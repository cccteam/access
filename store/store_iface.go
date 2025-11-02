package store

import (
	"context"
)

// Store defines the interface for database operations.
type Store interface {
	// Users
	CreateUser(ctx context.Context, user *User) (int64, error)
	UserByName(ctx context.Context, name string) (*User, error)
	DeleteUser(ctx context.Context, name string) error
	ListUsers(ctx context.Context) ([]*User, error)

	// Roles
	CreateRole(ctx context.Context, role *Role) (int64, error)
	RoleByName(ctx context.Context, name string) (*Role, error)
	DeleteRole(ctx context.Context, name string) error
	ListRoles(ctx context.Context) ([]*Role, error)
	ListRoleUsers(ctx context.Context, roleID int64, domain string) ([]*User, error)
	ListUserRoles(ctx context.Context, userID int64, domain string) ([]*Role, error)

	// Permissions
	CreatePermission(ctx context.Context, permission *Permission) (int64, error)
	PermissionByName(ctx context.Context, name string) (*Permission, error)
	DeletePermission(ctx context.Context, name string) error
	ListRolePermissions(ctx context.Context, roleID int64, domain string) ([]*Permission, error)
	ListUserPermissions(ctx context.Context, userID int64, domain string) ([]*Permission, error)

	// Resources
	CreateResource(ctx context.Context, resource *Resource) (int64, error)
	ResourceByName(ctx context.Context, name string) (*Resource, error)
	DeleteResource(ctx context.Context, name string) error
	ListRolePermissionResources(ctx context.Context, roleID, permissionID int64, domain string) ([]*Resource, error)
	ListUserPermissionResources(ctx context.Context, userID, permissionID int64, domain string) ([]*Resource, error)

	// Mappings
	CreateUserRoleMap(ctx context.Context, userID, roleID int64, domain string) error
	DeleteUserRoleMap(ctx context.Context, userID, roleID int64, domain string) error
	CreatePermissionResourceMap(ctx context.Context, permissionID, resourceID int64) (int64, error)
	CreateRoleMap(ctx context.Context, roleID, permResID int64) (int64, error)
	DeleteRolePermissionMap(ctx context.Context, roleID, permResID int64) error

	// Conditions
	CreateCondition(ctx context.Context, roleMapID int64, condition string) error

	// Query
	CheckPermission(ctx context.Context, user, domain, resource, permission string) (bool, string, error)
}
