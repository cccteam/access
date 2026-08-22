package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

var _ Controller = &Client{}

// Controller is the main interface for access control operations.
type Controller interface {
	// CheckUser returns the subset of resources that user does NOT hold perm on
	// within domain, preserving input order; empty means everything passed.
	CheckUser(
		ctx context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (missing []accesstypes.Resource, err error)

	// CheckRole returns the subset of resources that role does NOT hold perm on
	// within domain, preserving input order; empty means everything passed.
	CheckRole(
		ctx context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (missing []accesstypes.Resource, err error)

	// UserManager returns the UserManager for managing users, roles, and permissions.
	UserManager() UserManager

	// Handlers returns HTTP handlers for access management with validation and logging.
	Handlers(handler LogHandler) Handlers
}

var _ UserManager = &userManager{}

// UserManager manages RBAC users, roles, and permissions. Domains are opaque
// partition labels: no method validates domain existence — the application
// owns its tenant list and validates domains at its own boundaries.
type UserManager interface {
	// AddRoleUsers assigns role to users in domain. Errors if role doesn't exist.
	AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error

	// AddUserRoles assigns roles to user in domain. Errors if any role doesn't exist.
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error

	// DeleteRoleUsers removes users from role in domain. Errors if role doesn't exist.
	DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error

	// DeleteUserRoles removes role assignments from user in domain.
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error

	// UserRoles returns user's roles for the given domains. At least one domain
	// is required: access holds no domain list of its own to enumerate.
	UserRoles(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.RoleCollection, error)

	// UserPermissions returns user's effective permissions for the given
	// domains. At least one domain is required.
	UserPermissions(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)

	// AddRole creates role in domain. Errors if role already exists.
	AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error

	// RoleExists reports whether role exists in domain.
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)

	// Roles returns all roles in domain.
	Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error)

	// DeleteRole removes role from domain. Returns false with error if role has
	// users assigned. The delete is scoped to the given domain.
	DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)

	// AddRolePermissionResources grants permissions on resources to role in
	// domain. Errors if role doesn't exist. A domain-wide permission (not tied
	// to a specific resource) is a grant on accesstypes.GlobalResource.
	AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// DeleteRolePermissionResources removes resource-specific permissions from role in domain. Errors if role doesn't exist.
	DeleteRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// DeleteAllRolePermissions removes all permissions from role in domain.
	DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error

	// RoleUsers returns users assigned to role in domain.
	RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error)

	// RolePermissions returns permissions for role in domain as map of permissions to resources. Errors if role doesn't exist.
	RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error)
}
