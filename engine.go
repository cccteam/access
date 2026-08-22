package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// evaluator answers permission checks on the request path. It is the seam the
// snapshot engine will implement; the casbin path is the first implementation.
// Implementations must be safe for concurrent use.
type evaluator interface {
	// checkUser returns the subset of resources that user does NOT hold perm on
	// within domain. An empty result means all resources passed.
	checkUser(
		ctx context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (missing []accesstypes.Resource, err error)

	// checkRole returns the subset of resources that role does NOT hold perm on
	// within domain. An empty result means all resources passed.
	checkRole(
		ctx context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (missing []accesstypes.Resource, err error)
}

// policyStore is the management surface for role membership, role existence, and
// grants. Validation (domain/role existence, empty-input checks) belongs to the
// callers; implementations only persist and query policy.
type policyStore interface {
	// Membership
	addUserRole(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error
	deleteUserRole(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error
	users(ctx context.Context) ([]accesstypes.User, error)
	userRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User) ([]accesstypes.Role, error)
	userPermissions(ctx context.Context, domain accesstypes.Domain, user accesstypes.User) (map[accesstypes.Resource][]accesstypes.Permission, error)

	// Roles
	addRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error
	roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error)
	// deleteRole removes the role and its grants from domain. The casbin
	// implementation ignores domain and removes the role across ALL domains
	// (legacy behavior, preserved until casbin's deletion); the typed stores
	// scope the delete to (domain, role).
	deleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)
	roleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)
	roleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error)

	// Grants
	addGrant(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error
	removeGrant(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error
	roleGrants(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error)
}
