package access

import "github.com/cccteam/ccc/accesstypes"

// UserAccess struct contains the name and role mappings for a user
type UserAccess struct {
	Name        string
	Roles       accesstypes.RoleCollection
	Permissions accesstypes.UserPermissionCollection
}
