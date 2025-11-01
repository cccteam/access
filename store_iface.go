package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

// Store defines the interface for database operations.
type Store interface {
	// Users
	CreateUser(ctx context.Context, user *accesstypes.User) (int64, error)
	UserByName(ctx context.Context, name string) (*accesstypes.User, error)
	DeleteUser(ctx context.Context, name string) error

	// Roles
	CreateRole(ctx context.Context, role *accesstypes.Role) (int64, error)
	RoleByName(ctx context.Context, name string) (*accesstypes.Role, error)
	DeleteRole(ctx context.Context, name string) error

	// Permissions
	CreatePermission(ctx context.Context, permission *accesstypes.Permission) (int64, error)
	PermissionByName(ctx context.Context, name string) (*accesstypes.Permission, error)
	DeletePermission(ctx context.Context, name string) error

	// Resources
	CreateResource(ctx context.Context, resource *accesstypes.Resource) (int64, error)
	ResourceByName(ctx context.Context, name string) (*accesstypes.Resource, error)
	DeleteResource(ctx context.Context, name string) error

	// Mappings
	CreateUserRoleMap(ctx context.Context, userID, roleID int64, domain string) error
	CreatePermissionResourceMap(ctx context.Context, permissionID, resourceID int64) error
	CreateRoleMap(ctx context.Context, roleID, permResID int64) error

	// Conditions
	CreateCondition(ctx context.Context, roleMapID int64, condition string) error

	// Query
	CheckPermission(ctx context.Context, user, domain, resource, permission string) (bool, string, error)
}