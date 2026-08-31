package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// evaluator answers permission checks on the request path; the snapshot
// engine implements it. Implementations must be safe for concurrent use.
type evaluator interface {
	// checkUser returns user's scope-wide (no resource attachment) decision
	// within scope: granted on any unconditional cover, the covering
	// conditions when only conditional grants cover it — always row-free,
	// enforced at load — denied otherwise.
	checkUser(ctx context.Context, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission) (resourceDecision, error)

	// checkUserResources returns user's decision for each resource within
	// scope, aligned with the input order: granted on any unconditional
	// cover, the covering conditions when only conditional grants cover it,
	// denied otherwise.
	checkUserResources(
		ctx context.Context, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) ([]resourceDecision, error)

	// checkRole reports whether role holds perm scope-wide within scope.
	checkRole(ctx context.Context, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission) (bool, error)

	// checkRoleResources returns the subset of resources that role does NOT
	// hold perm on within scope. An empty result means all resources passed.
	checkRoleResources(
		ctx context.Context, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (missing []accesstypes.Resource, err error)
}

// policyStore is the management surface for role membership, role existence, and
// grants. Validation (role existence, empty-input checks) belongs to the
// callers; implementations only persist and query policy.
type policyStore interface {
	// Membership
	addUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error
	deleteUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error
	userRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error)
	userPermissions(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) (accesstypes.UserScopePermissions, error)

	// Roles
	addRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error
	roles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error)
	// deleteRole removes the role and its grants, scoped to (scope, role).
	deleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)
	roleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)
	roleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error)

	// Grants. A scope-wide grant attaches a permission to no resource; it is a
	// separate write, never a distinguished resource value.
	addGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error
	removeGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error
	addScopeWideGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission) error
	removeScopeWideGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission) error
	roleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (accesstypes.RolePermissionCollection, error)
}
