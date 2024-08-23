package access

// PermissionsListFunc is a function that provides the list of app permissions for the users client
type PermissionsListFunc func() []Permission

// UserAccess struct contains the name and role mappings for a user
type UserAccess struct {
	Name        string
	Roles       map[Domain][]Role
	Permissions map[Domain][]Permission
}
