// Package spannerstore implements access.Store over Cloud Spanner.
//
// Its sibling github.com/cccteam/access/postgresstore serves
// PostgreSQL-backed deployments through the application's pgx pool.
//
// Each Store owns three tables named {Prefix}{Store}{Roles|UserRoles|
// RoleGrants} — defaults yield AccessRoles, AccessUserRoles, AccessRoleGrants.
// Rows are partitioned by scope, persisted as the structural column pair
// (IsGlobal, Domain): the global partition is a flag, never a distinguished
// domain value.
// Separate tables per store make cross-store leakage structurally impossible:
// there is no store-key WHERE clause to forget. DDL returns the tables'
// canonical schema rendered with the configured names; apps copy it into a
// migration file (the library never runs DDL — Spanner schema changes are
// slow admin-API operations and apps own their schema lifecycle).
package spannerstore

import (
	"context"
	"fmt"
	"regexp"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/access"
	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
)

var _ access.Store = (*Store)(nil)

const defaultPrefix = "Access"

// Column and query-parameter names shared by the prepared statements and
// mutations.
const (
	colIsGlobal   = "IsGlobal"
	colDomain     = "Domain"
	colRole       = "Role"
	colUser       = "User"
	colPermission = "Permission"
	colResource   = "Resource"
	colField      = "Field"
	colCondition  = "Condition"
	colCreatedAt  = "CreatedAt"
	colUpdatedAt  = "UpdatedAt"

	paramIsGlobal = "isGlobal"
	paramDomain   = "domain"
	paramRole     = "role"
	paramUser     = "user"
)

var (
	// prefixPattern keeps concatenated table names valid Spanner identifiers;
	// the same rule applies in postgresstore so both stores accept the same
	// naming options.
	prefixPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	storePattern  = regexp.MustCompile(`^[A-Za-z0-9]*$`)
)

// Option configures a Store.
type Option func(*config)

type config struct {
	store  string
	prefix string
}

// WithStore names the policy store this client owns; it becomes part of the
// table names ({Prefix}{Store}Roles, ...). Apps with several independent
// permission stores in one database give each its own name; the default is
// the empty name.
func WithStore(store string) Option {
	return func(c *config) { c.store = store }
}

// WithPrefix overrides the shared leading table-name prefix (default
// "Access"), which keeps every access table contiguous in a sorted listing.
func WithPrefix(prefix string) Option {
	return func(c *config) { c.prefix = prefix }
}

type tableNames struct {
	roles      string
	userRoles  string
	roleGrants string
	userIndex  string
}

func resolveNames(opts []Option) (tableNames, error) {
	c := config{prefix: defaultPrefix}
	for _, opt := range opts {
		opt(&c)
	}

	if !prefixPattern.MatchString(c.prefix) {
		return tableNames{}, errors.Newf("invalid table prefix %q: must match %s", c.prefix, prefixPattern)
	}
	if !storePattern.MatchString(c.store) {
		return tableNames{}, errors.Newf("invalid store name %q: must match %s", c.store, storePattern)
	}

	base := c.prefix + c.store

	return tableNames{
		roles:      base + "Roles",
		userRoles:  base + "UserRoles",
		roleGrants: base + "RoleGrants",
		userIndex:  base + "UserRolesByScopeUser",
	}, nil
}

// Store implements access.Store over a Spanner client.
type Store struct {
	client *spanner.Client
	names  tableNames

	// Statements are built once here — table names are identifiers, not bind
	// parameters — so no query text is assembled at call sites.
	sqlDeleteRole      string
	sqlRoleExists      string
	sqlListRoles       string
	sqlListUserRoles   string
	sqlListRoleUsers   string
	sqlListRoleGrants  string
	sqlReadGrants      string
	sqlReadMemberships string
}

// New creates a Store on the given Spanner client. It validates the naming
// options and prepares statement text; it does not touch the database.
func New(client *spanner.Client, opts ...Option) (*Store, error) {
	names, err := resolveNames(opts)
	if err != nil {
		return nil, err
	}

	return &Store{
		client: client,
		names:  names,

		sqlDeleteRole:      fmt.Sprintf("DELETE FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain AND Role = @role", names.roles),
		sqlRoleExists:      fmt.Sprintf("SELECT 1 FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain AND Role = @role", names.roles),
		sqlListRoles:       fmt.Sprintf("SELECT Role FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain ORDER BY Role", names.roles),
		sqlListUserRoles:   fmt.Sprintf("SELECT Role FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain AND User = @user ORDER BY Role", names.userRoles),
		sqlListRoleUsers:   fmt.Sprintf("SELECT User FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain AND Role = @role ORDER BY User", names.userRoles),
		sqlListRoleGrants:  fmt.Sprintf("SELECT Permission, Resource, Field, Condition FROM %s WHERE IsGlobal = @isGlobal AND Domain = @domain AND Role = @role ORDER BY Permission, Resource, Field, Condition", names.roleGrants),
		sqlReadGrants:      fmt.Sprintf("SELECT IsGlobal, Domain, Role, Permission, Resource, Field, Condition FROM %s", names.roleGrants),
		sqlReadMemberships: fmt.Sprintf("SELECT IsGlobal, Domain, User, Role FROM %s", names.userRoles),
	}, nil
}

// DDL returns the canonical schema statements for this Store's tables,
// rendered with the configured names. Copy them into the application's
// migration file; the tests execute exactly these statements, so the shipped
// DDL is the tested DDL.
func (s *Store) DDL() []string {
	n := s.names

	return []string{
		fmt.Sprintf(`CREATE TABLE %s (
  IsGlobal BOOL NOT NULL,
  Domain STRING(128) NOT NULL,
  Role STRING(128) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
) PRIMARY KEY (IsGlobal, Domain, Role)`, n.roles),
		fmt.Sprintf(`CREATE TABLE %s (
  IsGlobal BOOL NOT NULL,
  Domain STRING(128) NOT NULL,
  Role STRING(128) NOT NULL,
  User STRING(320) NOT NULL,
  CreatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
) PRIMARY KEY (IsGlobal, Domain, Role, User),
  INTERLEAVE IN PARENT %s ON DELETE NO ACTION`, n.userRoles, n.roles),
		fmt.Sprintf(`CREATE INDEX %s ON %s (IsGlobal, Domain, User)`, n.userIndex, n.userRoles),
		fmt.Sprintf(`CREATE TABLE %s (
  IsGlobal BOOL NOT NULL,
  Domain STRING(128) NOT NULL,
  Role STRING(128) NOT NULL,
  Permission STRING(64) NOT NULL,
  Resource STRING(128) NOT NULL,
  Field STRING(128) NOT NULL,
  Condition STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp = true),
) PRIMARY KEY (IsGlobal, Domain, Role, Permission, Resource, Field, Condition),
  INTERLEAVE IN PARENT %s ON DELETE CASCADE`, n.roleGrants, n.roles),
	}
}

// ReadPolicy reads grants and memberships inside one read-only transaction,
// so both row sets observe the same store state.
func (s *Store) ReadPolicy(ctx context.Context) (*policy.Records, error) {
	txn := s.client.ReadOnlyTransaction()
	defer txn.Close()

	records := &policy.Records{}

	err := txn.Query(ctx, spanner.Statement{SQL: s.sqlReadGrants}).Do(func(row *spanner.Row) error {
		var global bool
		var domain, role, perm, resource, field, condition string
		if err := row.Columns(&global, &domain, &role, &perm, &resource, &field, &condition); err != nil {
			return errors.Wrap(err, "spanner.Row.Columns()")
		}
		records.Grants = append(records.Grants, policy.Grant{
			Scope:     policy.ScopeFromColumns(global, domain),
			Subject:   policy.Subject{Kind: policy.SubjectRole, Name: role},
			Perm:      accesstypes.Permission(perm),
			Resource:  resource,
			Field:     field,
			Condition: condition,
		})

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.ReadOnlyTransaction.Query() grants")
	}

	err = txn.Query(ctx, spanner.Statement{SQL: s.sqlReadMemberships}).Do(func(row *spanner.Row) error {
		var global bool
		var domain, user, role string
		if err := row.Columns(&global, &domain, &user, &role); err != nil {
			return errors.Wrap(err, "spanner.Row.Columns()")
		}
		records.Memberships = append(records.Memberships, policy.Membership{
			Scope:  policy.ScopeFromColumns(global, domain),
			Member: policy.Subject{Kind: policy.SubjectUser, Name: user},
			Role:   accesstypes.Role(role),
		})

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.ReadOnlyTransaction.Query() memberships")
	}

	return records, nil
}

// insertIgnoreExists applies an insert mutation, treating "row already
// exists" as the documented no-op.
func (s *Store) insertIgnoreExists(ctx context.Context, m *spanner.Mutation, wrap string) error {
	if _, err := s.client.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return nil
		}

		return errors.Wrap(err, wrap)
	}

	return nil
}

// InsertUserRole adds one user-role membership; adding an existing membership
// is a no-op. The (domain, role) parent row must exist.
func (s *Store) InsertUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Insert(s.names.userRoles,
		[]string{colIsGlobal, colDomain, colRole, colUser, colCreatedAt},
		[]any{global, domain, string(role), string(user), spanner.CommitTimestamp})

	return s.insertIgnoreExists(ctx, m, "spanner.Client.Apply() insert user role")
}

// DeleteUserRole removes one user-role membership; removing an absent
// membership is a no-op.
func (s *Store) DeleteUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Delete(s.names.userRoles, spanner.Key{global, domain, string(role), string(user)})
	if _, err := s.client.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply() delete user role")
	}

	return nil
}

// ListUserRoles returns the user's roles in scope, sorted.
func (s *Store) ListUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error) {
	global, domain := policy.ScopeColumns(scope)
	stmt := spanner.Statement{SQL: s.sqlListUserRoles, Params: map[string]any{paramIsGlobal: global, paramDomain: domain, paramUser: string(user)}}
	values, err := s.queryStrings(ctx, stmt)
	if err != nil {
		return nil, errors.Wrap(err, "user roles")
	}
	roles := make([]accesstypes.Role, 0, len(values))
	for _, v := range values {
		roles = append(roles, accesstypes.Role(v))
	}

	return roles, nil
}

// ListRoleUsers returns the role's members in scope, sorted.
func (s *Store) ListRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error) {
	global, domain := policy.ScopeColumns(scope)
	stmt := spanner.Statement{SQL: s.sqlListRoleUsers, Params: map[string]any{paramIsGlobal: global, paramDomain: domain, paramRole: string(role)}}
	values, err := s.queryStrings(ctx, stmt)
	if err != nil {
		return nil, errors.Wrap(err, "role users")
	}
	users := make([]accesstypes.User, 0, len(values))
	for _, v := range values {
		users = append(users, accesstypes.User(v))
	}

	return users, nil
}

// InsertRole creates the (scope, role) row; re-inserting an existing role is
// a no-op.
func (s *Store) InsertRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Insert(s.names.roles,
		[]string{colIsGlobal, colDomain, colRole, colUpdatedAt},
		[]any{global, domain, string(role), spanner.CommitTimestamp})

	return s.insertIgnoreExists(ctx, m, "spanner.Client.Apply() insert role")
}

// ListRoles returns the scope's roles, sorted.
func (s *Store) ListRoles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error) {
	global, domain := policy.ScopeColumns(scope)
	stmt := spanner.Statement{SQL: s.sqlListRoles, Params: map[string]any{paramIsGlobal: global, paramDomain: domain}}
	values, err := s.queryStrings(ctx, stmt)
	if err != nil {
		return nil, errors.Wrap(err, "roles")
	}
	roles := make([]accesstypes.Role, 0, len(values))
	for _, v := range values {
		roles = append(roles, accesstypes.Role(v))
	}

	return roles, nil
}

// DeleteRole deletes the (scope, role) row through DML so the affected count
// is known. Its grants cascade (interleaved ON DELETE CASCADE); memberships
// block the delete (interleaved ON DELETE NO ACTION), so a role with members
// refuses deletion.
func (s *Store) DeleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	global, domain := policy.ScopeColumns(scope)
	var deleted bool
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		count, err := txn.Update(ctx, spanner.Statement{
			SQL:    s.sqlDeleteRole,
			Params: map[string]any{paramIsGlobal: global, paramDomain: domain, paramRole: string(role)},
		})
		if err != nil {
			return errors.Wrap(err, "spanner.ReadWriteTransaction.Update()")
		}
		deleted = count > 0

		return nil
	})
	if err != nil {
		return false, errors.Wrap(err, "spanner.Client.ReadWriteTransaction() delete role")
	}

	return deleted, nil
}

// RoleExists reports whether the (scope, role) row exists.
func (s *Store) RoleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	global, domain := policy.ScopeColumns(scope)
	stmt := spanner.Statement{SQL: s.sqlRoleExists, Params: map[string]any{paramIsGlobal: global, paramDomain: domain, paramRole: string(role)}}
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	if _, err := iter.Next(); err != nil {
		if errors.Is(err, iterator.Done) {
			return false, nil
		}

		return false, errors.Wrap(err, "spanner.RowIterator.Next() role exists")
	}

	return true, nil
}

// InsertGrant adds one grant row; the condition is part of the row's identity
// ("" = unconditional), so re-inserting an existing row is a no-op and a
// different condition on the same (permission, resource, field) is a second
// row. The (scope, role) parent row must exist.
func (s *Store) InsertGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Insert(s.names.roleGrants,
		[]string{colIsGlobal, colDomain, colRole, colPermission, colResource, colField, colCondition, colUpdatedAt},
		[]any{global, domain, string(role), string(perm), resource, field, condition, spanner.CommitTimestamp})

	return s.insertIgnoreExists(ctx, m, "insert grant")
}

// DeleteGrant removes one grant row; removing an absent grant is a no-op.
func (s *Store) DeleteGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Delete(s.names.roleGrants, spanner.Key{global, domain, string(role), string(perm), resource, field, condition})
	if _, err := s.client.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply() delete grant")
	}

	return nil
}

// DeleteGrants removes every condition's row for the (permission, resource,
// field); removing absent rows is a no-op.
func (s *Store) DeleteGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field string) error {
	global, domain := policy.ScopeColumns(scope)
	m := spanner.Delete(s.names.roleGrants, spanner.Key{global, domain, string(role), string(perm), resource, field}.AsPrefix())
	if _, err := s.client.Apply(ctx, []*spanner.Mutation{m}); err != nil {
		return errors.Wrap(err, "spanner.Client.Apply() delete grants")
	}

	return nil
}

// ListRoleGrants returns the role's grant rows in scope, sorted.
func (s *Store) ListRoleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]policy.RoleGrant, error) {
	global, domain := policy.ScopeColumns(scope)
	stmt := spanner.Statement{SQL: s.sqlListRoleGrants, Params: map[string]any{paramIsGlobal: global, paramDomain: domain, paramRole: string(role)}}
	grants := make([]policy.RoleGrant, 0)
	err := s.client.Single().Query(ctx, stmt).Do(func(row *spanner.Row) error {
		var perm, resource, field, condition string
		if err := row.Columns(&perm, &resource, &field, &condition); err != nil {
			return errors.Wrap(err, "spanner.Row.Columns()")
		}
		grants = append(grants, policy.RoleGrant{Perm: accesstypes.Permission(perm), Resource: resource, Field: field, Condition: condition})

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.Client.Single().Query() role grants")
	}

	return grants, nil
}

// queryStrings runs a single-column string query.
func (s *Store) queryStrings(ctx context.Context, stmt spanner.Statement) ([]string, error) {
	values := make([]string, 0)
	err := s.client.Single().Query(ctx, stmt).Do(func(row *spanner.Row) error {
		var v string
		if err := row.Columns(&v); err != nil {
			return errors.Wrap(err, "spanner.Row.Columns()")
		}
		values = append(values, v)

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "spanner.Client.Single().Query()")
	}

	return values, nil
}
