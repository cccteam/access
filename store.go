package access

import (
	"context"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
)

// Store is the persistence seam for policy data: three typed tables (roles,
// user-role memberships, role grants) partitioned by scope — the global
// partition or one tenant domain, persisted as the structural column pair
// (IsGlobal, Domain) — plus one normalized read feeding the snapshot
// compiler. Implementations are thin —
// each method is one SQL statement against one store's tables; everything
// smarter (validation, resource/field splitting, change signaling, snapshot
// compilation) lives in the access package, one shared code path for every
// store.
//
// The interface is sealed by construction: ReadPolicy's signature references
// this module's internal/policy package, so only packages inside this module
// can implement it. Use the provided implementations:
//
//	spannerstore.New(client, opts...)   // Cloud Spanner
//	postgresstore.New(pool, opts...)    // PostgreSQL, rides the app's pgx pool
//
// Store values hold bare names only — no marshal prefixes, no sentinel
// values. All values are opaque labels to the store: referential validity of
// domains, users, and resources belongs to the callers that write them.
// Scope is stored structurally: the global partition is a column flag, never
// a distinguished domain value, so any domain string is ordinary tenant data.
//
// Contracts every implementation provides:
//   - Inserts are idempotent: re-inserting an existing row is a no-op, not an
//     error. Deletes of absent rows are no-ops.
//   - DeleteRole is scoped to (domain, role): it cascades the role's grants,
//     refuses with an error while memberships still reference the role
//     (DB-enforced), and reports whether a row was actually deleted.
//   - InsertUserRole and InsertGrant require the (domain, role) row to exist
//     (DB-enforced foreign key / parent interleave).
//   - List results are sorted for deterministic output.
//   - ReadPolicy reads grants and memberships with snapshot consistency: both
//     row sets observe the same store state.
type Store interface {
	// ReadPolicy returns the store's complete policy content as normalized
	// records for the snapshot compiler.
	ReadPolicy(ctx context.Context) (*policy.Records, error)

	// Membership
	InsertUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error
	DeleteUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error
	ListUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error)
	ListRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error)

	// Roles
	InsertRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error
	ListRoles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error)
	DeleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)
	RoleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)

	// Grants. resource and field are stored as separate columns: field "" is
	// an endpoint grant, "*" an all-fields wildcard, anything else one field.
	// resource "" (with field "") is a scope-wide grant — the permission held
	// with no resource attachment; real resource names are validated non-empty
	// above this seam, so "" is structurally unreachable from data.
	// condition is the grant's condition as opaque expression text, "" when
	// unconditional, and is part of the row's identity: one (role,
	// permission, resource, field) holds one row per condition, so a role may
	// grant the same permission on one resource under several conditions.
	// InsertGrant is idempotent per row. DeleteGrant removes exactly one row;
	// DeleteGrants removes every condition's row for the (permission,
	// resource, field).
	InsertGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error
	DeleteGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error
	DeleteGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field string) error
	ListRoleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]policy.RoleGrant, error)
}
