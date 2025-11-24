package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

var _ Controller = &Client{}

// Controller is the main interface for access control operations.
type Controller interface {
	// RequireAll checks if user has all specified permissions in domain.
	RequireAll(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, permissions ...accesstypes.Permission) error

	// RequireResources checks if user has permission for resources in domain.
	// Returns ok=true if all resources are accessible, ok=false with missing resources otherwise.
	RequireResources(
		ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (ok bool, missing []accesstypes.Resource, err error)

	// UserManager returns the UserManager for managing users, roles, and permissions.
	UserManager() UserManager

	// Handlers returns HTTP handlers for access management with validation and logging.
	Handlers(handler LogHandler) Handlers
}

var _ UserManager = &userManager{}

// UserManager manages RBAC users, roles, permissions, and domains.
type UserManager interface {
	// AddRoleUsers assigns role to users in domain. Errors if role doesn't exist.
	AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error

	// AddUserRoles assigns roles to user in domain. Errors if any role doesn't exist.
	AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error

	// DeleteRoleUsers removes users from role in domain. Errors if role doesn't exist.
	DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error

	// DeleteUserRoles removes role assignments from user in domain.
	DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error

	// User returns user's roles and permissions. If domains unspecified, returns all domains.
	User(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (*UserAccess, error)

	// Users returns all users with roles and permissions. If domains unspecified, returns all domains.
	Users(ctx context.Context, domain ...accesstypes.Domain) ([]*UserAccess, error)

	// UserRoles returns user's roles. If domains unspecified, returns all domains.
	UserRoles(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.RoleCollection, error)

	// UserPermissions returns user's effective permissions. If domains unspecified, returns all domains.
	UserPermissions(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error)

	// AddRole creates role in domain. Errors if domain doesn't exist or role already exists.
	//
	// Note: Adds internal "noop" user to role for casbin enumeration.
	AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error

	// RoleExists returns true if role exists in domain.
	RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool

	// Roles returns all roles in domain. Errors if domain doesn't exist.
	Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error)

	// DeleteRole removes role from domain. Returns false with error if role has users assigned.
	DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error)

	// AddRolePermissions grants global permissions to role in domain. Errors if role doesn't exist.
	AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error

	// AddRolePermissionResources grants resource-specific permissions to role in domain. Errors if role doesn't exist.
	AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// DeleteRolePermissions removes global permissions from role in domain. Errors if role doesn't exist.
	DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error

	// DeleteRolePermissionResources removes resource-specific permissions from role in domain. Errors if role doesn't exist.
	DeleteRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// DeleteAllRolePermissions removes all permissions from role in domain.
	DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error

	// RoleUsers returns users assigned to role in domain. Excludes internal "noop" user.
	RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error)

	// RolePermissions returns permissions for role in domain as map of permissions to resources. Errors if role doesn't exist.
	RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error)

	// Domains returns all domains including global domain.
	Domains(ctx context.Context) ([]accesstypes.Domain, error)

	// DomainExists returns true if domain exists. Always true for global domain.
	DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error)
}

// Domains manages domain queries and validation.
type Domains interface {
	// DomainIDs returns all domain IDs.
	DomainIDs(ctx context.Context) ([]string, error)

	// DomainExists returns true if domain ID exists.
	DomainExists(ctx context.Context, guarantorID string) (bool, error)
}
