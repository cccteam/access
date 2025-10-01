package access

import "github.com/cccteam/ccc/accesstypes"

// PermissionsListFunc returns available permissions.
type PermissionsListFunc func() []accesstypes.Permission

// UserAccess contains user's name, roles by domain, and effective permissions by domain and resource.
type UserAccess struct {
	Name        string
	Roles       accesstypes.RoleCollection
	Permissions accesstypes.UserPermissionCollection
}
