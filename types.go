package access

import "github.com/cccteam/ccc/accesstypes"

// PermissionsListFunc is a function that provides the list of app permissions for the users client
type PermissionsListFunc func() []accesstypes.Permission

// UserAccess struct contains the name and role mappings for a user
type UserAccess struct {
	Name        string
	Roles       accesstypes.RoleCollection
	Permissions accesstypes.UserPermissionCollection
}
