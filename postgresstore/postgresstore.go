// Package postgresstore implements access.Store over PostgreSQL, riding the
// application's existing connection pool.
//
// Its sibling github.com/cccteam/access/spannerstore serves Cloud
// Spanner-backed deployments.
//
// Each Store owns three tables named {Prefix}{Store}{Roles|UserRoles|
// RoleGrants} — defaults yield AccessRoles, AccessUserRoles, AccessRoleGrants.
// Rows are partitioned by scope, persisted as the structural column triple
// ("IsGlobal", "Axis", "Domain"): the global partition is a flag, never a
// distinguished domain value, and the axis is the name of the axis the domain
// belongs to — "" for the default axis, which is every scope today.
// Separate tables per store make cross-store leakage structurally impossible:
// there is no store-key WHERE clause to forget. DDL returns the tables'
// canonical schema rendered with the configured names; apps copy it into a
// migration file (the library never runs DDL — apps own their schema
// lifecycle).
package postgresstore

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cccteam/access"
	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ access.Store = (*Store)(nil)

const defaultPrefix = "Access"

var (
	// prefixPattern keeps concatenated table names valid identifiers in both
	// supported stores without quoting gymnastics (Spanner cannot quote its
	// way around invalid identifiers, and the two stores must accept the same
	// naming options).
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

// tableNames holds the three quoted table identifiers plus the raw (unquoted)
// names for DDL object naming.
type tableNames struct {
	roles      string
	userRoles  string
	roleGrants string

	rawRoles      string
	rawUserRoles  string
	rawRoleGrants string
	rawUserIndex  string
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
	n := tableNames{
		rawRoles:      base + "Roles",
		rawUserRoles:  base + "UserRoles",
		rawRoleGrants: base + "RoleGrants",
		rawUserIndex:  base + "UserRolesByScopeUser",
	}
	n.roles = pgx.Identifier{n.rawRoles}.Sanitize()
	n.userRoles = pgx.Identifier{n.rawUserRoles}.Sanitize()
	n.roleGrants = pgx.Identifier{n.rawRoleGrants}.Sanitize()

	return n, nil
}

// Store implements access.Store over the application's pgx pool.
type Store struct {
	pool  *pgxpool.Pool
	names tableNames

	// Statements are built once here — table names are identifiers, not bind
	// parameters — so no query text is assembled at call sites.
	sqlInsertRole      string
	sqlDeleteRole      string
	sqlRoleExists      string
	sqlListRoles       string
	sqlInsertUserRole  string
	sqlDeleteUserRole  string
	sqlListUserRoles   string
	sqlListRoleUsers   string
	sqlInsertGrant     string
	sqlDeleteGrant     string
	sqlDeleteGrants    string
	sqlListRoleGrants  string
	sqlReadGrants      string
	sqlReadMemberships string
}

// New creates a Store on the application's existing pool. It validates the
// naming options and prepares statement text; it does not touch the database.
func New(pool *pgxpool.Pool, opts ...Option) (*Store, error) {
	names, err := resolveNames(opts)
	if err != nil {
		return nil, err
	}

	return &Store{
		pool:  pool,
		names: names,

		sqlInsertRole:     fmt.Sprintf(`insert into %s ("IsGlobal", "Axis", "Domain", "Role") values ($1, $2, $3, $4) on conflict do nothing`, names.roles),
		sqlDeleteRole:     fmt.Sprintf(`delete from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4`, names.roles),
		sqlRoleExists:     fmt.Sprintf(`select exists(select 1 from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4)`, names.roles),
		sqlListRoles:      fmt.Sprintf(`select "Role" from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 order by "Role"`, names.roles),
		sqlInsertUserRole: fmt.Sprintf(`insert into %s ("IsGlobal", "Axis", "Domain", "Role", "User") values ($1, $2, $3, $4, $5) on conflict do nothing`, names.userRoles),
		sqlDeleteUserRole: fmt.Sprintf(`delete from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4 and "User" = $5`, names.userRoles),
		sqlListUserRoles:  fmt.Sprintf(`select "Role" from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "User" = $4 order by "Role"`, names.userRoles),
		sqlListRoleUsers:  fmt.Sprintf(`select "User" from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4 order by "User"`, names.userRoles),
		sqlInsertGrant: fmt.Sprintf(
			`insert into %s ("IsGlobal", "Axis", "Domain", "Role", "Permission", "Resource", "Field", "Condition") values ($1, $2, $3, $4, $5, $6, $7, $8) on conflict do nothing`, names.roleGrants),
		sqlDeleteGrant: fmt.Sprintf(
			`delete from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4 and "Permission" = $5 and "Resource" = $6 and "Field" = $7 and "Condition" = $8`, names.roleGrants),
		sqlDeleteGrants: fmt.Sprintf(
			`delete from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4 and "Permission" = $5 and "Resource" = $6 and "Field" = $7`, names.roleGrants),
		sqlListRoleGrants: fmt.Sprintf(
			`select "Permission", "Resource", "Field", "Condition" from %s where "IsGlobal" = $1 and "Axis" = $2 and "Domain" = $3 and "Role" = $4 order by "Permission", "Resource", "Field", "Condition"`, names.roleGrants),
		sqlReadGrants:      fmt.Sprintf(`select "IsGlobal", "Axis", "Domain", "Role", "Permission", "Resource", "Field", "Condition" from %s`, names.roleGrants),
		sqlReadMemberships: fmt.Sprintf(`select "IsGlobal", "Axis", "Domain", "User", "Role" from %s`, names.userRoles),
	}, nil
}

// DDL returns the canonical schema statements for this Store's tables,
// rendered with the configured names. Copy them into the application's
// migration file; the tests execute exactly these statements, so the shipped
// DDL is the tested DDL.
func (s *Store) DDL() []string {
	n := s.names
	quote := func(name string) string { return pgx.Identifier{name}.Sanitize() }

	return []string{
		fmt.Sprintf(`CREATE TABLE %s (
  "IsGlobal" BOOLEAN NOT NULL,
  "Axis" TEXT NOT NULL,
  "Domain" TEXT NOT NULL,
  "Role" TEXT NOT NULL,
  "UpdatedAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY ("IsGlobal", "Axis", "Domain", "Role")
)`, n.roles),
		fmt.Sprintf(`CREATE TABLE %s (
  "IsGlobal" BOOLEAN NOT NULL,
  "Axis" TEXT NOT NULL,
  "Domain" TEXT NOT NULL,
  "Role" TEXT NOT NULL,
  "User" TEXT NOT NULL,
  "CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY ("IsGlobal", "Axis", "Domain", "Role", "User"),
  FOREIGN KEY ("IsGlobal", "Axis", "Domain", "Role") REFERENCES %s ("IsGlobal", "Axis", "Domain", "Role")
)`, n.userRoles, n.roles),
		fmt.Sprintf(`CREATE INDEX %s ON %s ("IsGlobal", "Axis", "Domain", "User")`, quote(n.rawUserIndex), n.userRoles),
		fmt.Sprintf(`CREATE TABLE %s (
  "IsGlobal" BOOLEAN NOT NULL,
  "Axis" TEXT NOT NULL,
  "Domain" TEXT NOT NULL,
  "Role" TEXT NOT NULL,
  "Permission" TEXT NOT NULL,
  "Resource" TEXT NOT NULL,
  "Field" TEXT NOT NULL,
  "Condition" TEXT NOT NULL,
  "UpdatedAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY ("IsGlobal", "Axis", "Domain", "Role", "Permission", "Resource", "Field", "Condition"),
  FOREIGN KEY ("IsGlobal", "Axis", "Domain", "Role") REFERENCES %s ("IsGlobal", "Axis", "Domain", "Role") ON DELETE CASCADE
)`, n.roleGrants, n.roles),
	}
}

// ReadPolicy reads grants and memberships inside one repeatable-read
// transaction, so both row sets observe the same store state.
func (s *Store) ReadPolicy(ctx context.Context) (*policy.Records, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, errors.Wrap(err, "pgxpool.Pool.BeginTx()")
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // rollback after commit is a no-op

	records := &policy.Records{}

	grantRows, err := tx.Query(ctx, s.sqlReadGrants)
	if err != nil {
		return nil, errors.Wrap(err, "pgx.Tx.Query() grants")
	}
	records.Grants, err = pgx.CollectRows(grantRows, func(row pgx.CollectableRow) (policy.Grant, error) {
		var g policy.Grant
		var global bool
		var axis, domain, role string
		if err := row.Scan(&global, &axis, &domain, &role, &g.Perm, &g.Resource, &g.Field, &g.Condition); err != nil {
			return policy.Grant{}, errors.Wrap(err, "pgx.CollectableRow.Scan()")
		}
		scope, err := policy.ScopeFromColumns(global, axis, domain)
		if err != nil {
			return policy.Grant{}, errors.Wrap(err, "policy.ScopeFromColumns()")
		}
		g.Scope = scope
		g.Subject = policy.Subject{Kind: policy.SubjectRole, Name: role}

		return g, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() grants")
	}

	memberRows, err := tx.Query(ctx, s.sqlReadMemberships)
	if err != nil {
		return nil, errors.Wrap(err, "pgx.Tx.Query() memberships")
	}
	records.Memberships, err = pgx.CollectRows(memberRows, func(row pgx.CollectableRow) (policy.Membership, error) {
		var m policy.Membership
		var global bool
		var axis, domain, user string
		if err := row.Scan(&global, &axis, &domain, &user, &m.Role); err != nil {
			return policy.Membership{}, errors.Wrap(err, "pgx.CollectableRow.Scan()")
		}
		scope, err := policy.ScopeFromColumns(global, axis, domain)
		if err != nil {
			return policy.Membership{}, errors.Wrap(err, "policy.ScopeFromColumns()")
		}
		m.Scope = scope
		m.Member = policy.Subject{Kind: policy.SubjectUser, Name: user}

		return m, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() memberships")
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, errors.Wrap(err, "pgx.Tx.Commit()")
	}

	return records, nil
}

// InsertUserRole adds one user-role membership; adding an existing membership
// is a no-op. The (scope, role) parent row must exist.
func (s *Store) InsertUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlInsertUserRole, global, axis, domain, role, user); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() insert user role")
	}

	return nil
}

// DeleteUserRole removes one user-role membership; removing an absent
// membership is a no-op.
func (s *Store) DeleteUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlDeleteUserRole, global, axis, domain, role, user); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() delete user role")
	}

	return nil
}

// ListUserRoles returns the user's roles in scope, sorted.
func (s *Store) ListUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	rows, err := s.pool.Query(ctx, s.sqlListUserRoles, global, axis, domain, user)
	if err != nil {
		return nil, errors.Wrap(err, "pgxpool.Pool.Query() user roles")
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[accesstypes.Role])
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() user roles")
	}

	return roles, nil
}

// ListRoleUsers returns the role's members in scope, sorted.
func (s *Store) ListRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	rows, err := s.pool.Query(ctx, s.sqlListRoleUsers, global, axis, domain, role)
	if err != nil {
		return nil, errors.Wrap(err, "pgxpool.Pool.Query() role users")
	}
	users, err := pgx.CollectRows(rows, pgx.RowTo[accesstypes.User])
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() role users")
	}

	return users, nil
}

// InsertRole creates the (scope, role) row; re-inserting an existing role is
// a no-op.
func (s *Store) InsertRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlInsertRole, global, axis, domain, role); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() insert role")
	}

	return nil
}

// ListRoles returns the scope's roles, sorted.
func (s *Store) ListRoles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	rows, err := s.pool.Query(ctx, s.sqlListRoles, global, axis, domain)
	if err != nil {
		return nil, errors.Wrap(err, "pgxpool.Pool.Query() roles")
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[accesstypes.Role])
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() roles")
	}

	return roles, nil
}

// DeleteRole deletes the (scope, role) row. Its grants cascade in the
// database; memberships block the delete through the userRoles foreign key
// (NO ACTION), so a role with members refuses deletion.
func (s *Store) DeleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	tag, err := s.pool.Exec(ctx, s.sqlDeleteRole, global, axis, domain, role)
	if err != nil {
		return false, errors.Wrap(err, "pgxpool.Pool.Exec() delete role")
	}

	return tag.RowsAffected() > 0, nil
}

// RoleExists reports whether the (scope, role) row exists.
func (s *Store) RoleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	var exists bool
	if err := s.pool.QueryRow(ctx, s.sqlRoleExists, global, axis, domain, role).Scan(&exists); err != nil {
		return false, errors.Wrap(err, "pgxpool.Pool.QueryRow() role exists")
	}

	return exists, nil
}

// InsertGrant adds one grant row; the condition is part of the row's identity
// ("" = unconditional), so re-inserting an existing row is a no-op and a
// different condition on the same (permission, resource, field) is a second
// row. The (scope, role) parent row must exist.
func (s *Store) InsertGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlInsertGrant, global, axis, domain, role, perm, resource, field, condition); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() insert grant")
	}

	return nil
}

// InsertGrants adds the role's grant rows in one batched round trip; each row's
// insert ignores a conflict, so present rows are untouched and the call is
// idempotent like InsertGrant. The (scope, role) parent row must exist.
func (s *Store) InsertGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, grants []policy.RoleGrant) error {
	if len(grants) == 0 {
		return nil
	}

	global, axis, domain := policy.ScopeColumns(scope)
	batch := &pgx.Batch{}
	for _, g := range grants {
		batch.Queue(s.sqlInsertGrant, global, axis, domain, role, g.Perm, g.Resource, g.Field, g.Condition)
	}

	results := s.pool.SendBatch(ctx, batch)
	for range grants {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()

			return errors.Wrap(err, "pgx.BatchResults.Exec() insert grant")
		}
	}
	if err := results.Close(); err != nil {
		return errors.Wrap(err, "pgx.BatchResults.Close() insert grants")
	}

	return nil
}

// DeleteGrant removes one grant row; removing an absent grant is a no-op.
func (s *Store) DeleteGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlDeleteGrant, global, axis, domain, role, perm, resource, field, condition); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() delete grant")
	}

	return nil
}

// DeleteGrants removes every condition's row for the (permission, resource,
// field); removing absent rows is a no-op.
func (s *Store) DeleteGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field string) error {
	global, axis, domain := policy.ScopeColumns(scope)
	if _, err := s.pool.Exec(ctx, s.sqlDeleteGrants, global, axis, domain, role, perm, resource, field); err != nil {
		return errors.Wrap(err, "pgxpool.Pool.Exec() delete grants")
	}

	return nil
}

// ListRoleGrants returns the role's grant rows in scope, sorted.
func (s *Store) ListRoleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]policy.RoleGrant, error) {
	global, axis, domain := policy.ScopeColumns(scope)
	rows, err := s.pool.Query(ctx, s.sqlListRoleGrants, global, axis, domain, role)
	if err != nil {
		return nil, errors.Wrap(err, "pgxpool.Pool.Query() role grants")
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (policy.RoleGrant, error) {
		var g policy.RoleGrant
		if err := row.Scan(&g.Perm, &g.Resource, &g.Field, &g.Condition); err != nil {
			return policy.RoleGrant{}, errors.Wrap(err, "pgx.CollectableRow.Scan()")
		}

		return g, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "pgx.CollectRows() role grants")
	}

	return grants, nil
}
