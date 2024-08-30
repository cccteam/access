package access

import (
	"context"

	"github.com/cccteam/access/accesstypes"
	"github.com/go-playground/validator/v10"
)

var _ Controller = &Client{}

type Controller interface {
	// CheckPermissions checks if a user has the given permissions in a domain
	RequireAll(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, permissions ...accesstypes.Permission) error

	// UserManager returns the UserManager interface for managing users, roles, and permissions
	UserManager() UserManager

	// Handlers returns the http.HandlerFunc for the access package
	Handlers(validate *validator.Validate, handler LogHandler) Handlers
}

var _ UserManager = &userManager{}

// UserManager is the interface for managing RBAC including the management of roles and permissions for users
type UserManager interface {
	// AddRoleUsers assigns a given role to a slice of users if the role exists
	AddRoleUsers(ctx context.Context, users []accesstypes.User, role accesstypes.Role, domain accesstypes.Domain) error

	// AddUserRoles assigns a list of roles to a user if the role exists
	AddUserRoles(ctx context.Context, user accesstypes.User, roles []accesstypes.Role, domain accesstypes.Domain) error

	// DeleteRoleUsers removes users from a given role
	DeleteRoleUsers(ctx context.Context, users []accesstypes.User, role accesstypes.Role, domain accesstypes.Domain) error

	// DeleteUserRole deletes the role assignment for a user in a specific domain.
	// Behavior is the same whether or not the role exists for the user.
	DeleteUserRole(ctx context.Context, username accesstypes.User, role accesstypes.Role, domain accesstypes.Domain) error

	// User returns a User by the given username with the roles that have been assigned.
	User(ctx context.Context, username accesstypes.User, domain ...accesstypes.Domain) (*UserAccess, error)

	// Users gets a list of users with their assigned roles
	Users(ctx context.Context, domain ...accesstypes.Domain) ([]*UserAccess, error)

	// UserRoles returns a map of the domain
	UserRoles(ctx context.Context, username accesstypes.User, domain ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Role, error)

	// UserPermissions returns a map of domains with a slice of permissions for each
	UserPermissions(ctx context.Context, username accesstypes.User, domain ...accesstypes.Domain) (map[accesstypes.Domain][]accesstypes.Permission, error)

	// AddRole adds a new role to a domain without assigning it to a user
	//
	// Note: due to the design of casbin, we must add a "noop" user to the role to enumerate it without permissions.
	AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error

	// RoleExists determines if the given Role exists for Domain
	RoleExists(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) bool

	// Roles returns the full list of roles for a given domain
	Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error)

	// DeleteRole deletes a role from the system.
	// If there are users assigned, it will not be deleted.
	DeleteRole(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) (bool, error)

	// AddRolePermissions adds a list of permissions to a role in a given domain
	AddRolePermissions(ctx context.Context, permissions []accesstypes.Permission, role accesstypes.Role, domain accesstypes.Domain) error

	// DeleteRolePermissions removes a list of permissions to a role in a given domain
	DeleteRolePermissions(ctx context.Context, permissions []accesstypes.Permission, role accesstypes.Role, domain accesstypes.Domain) error

	// DeleteAllRolePermissions removes all permissions for a given role in a domain
	DeleteAllRolePermissions(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) error

	// RoleUsers returns the list of users attached to a role in a given domain
	RoleUsers(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) ([]accesstypes.User, error)

	// RolePermissions returns the list of permissions attached to a role in a given domain
	RolePermissions(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain) ([]accesstypes.Permission, error)

	// Domains returns the full list of domains
	Domains(ctx context.Context) ([]accesstypes.Domain, error)

	// DomainExists returns true if the domain provided is a valid
	DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error)
}

type Domains interface {
	DomainIDs(ctx context.Context) ([]string, error)

	DomainExists(ctx context.Context, guarantorID string) (bool, error)
}
