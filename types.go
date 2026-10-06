package access

import "github.com/cccteam/ccc/accesstypes"

// PermissionsListFunc returns available permissions.
type PermissionsListFunc func() []accesstypes.Permission

// GrantRow is one grant as the store holds it: Permission on Resource — a bare
// resource name, or Resource.field for one field — limited by Condition, ""
// being unconditional. AddRoleGrants takes rows; the role file's authored
// Grants expand into the same shape.
type GrantRow struct {
	Permission accesstypes.Permission
	Resource   accesstypes.Resource
	Condition  string
}
