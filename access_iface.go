package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
)

var _ Controller = &Client{}

// Controller is the main interface for access control operations.
type Controller interface {
	// CheckUser returns the Decision for whether user holds perm scope-wide
	// (attached to no resource) within scope. env is the request's decision
	// context; the check folds environment-referencing conditions against it
	// and fails loudly when a referenced attribute is absent.
	CheckUser(
		ctx context.Context, env accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission,
	) (accesstypes.Decision, error)

	// CheckUserResources returns the Decision for each resource for whether
	// user holds perm on it within scope, all answered from one policy
	// snapshot. env is the request's decision context; the check folds
	// environment-referencing conditions against it and fails loudly when a
	// referenced attribute is absent.
	CheckUserResources(
		ctx context.Context, env accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (accesstypes.Decisions, error)

	// CheckRole returns the Decision for whether role holds perm scope-wide
	// within scope: what CheckUser answers a member holding only that role,
	// minus the membership lookup. env is the request's decision context;
	// the check folds environment-referencing conditions against it and
	// fails loudly when a referenced attribute is absent.
	CheckRole(
		ctx context.Context, env accesstypes.Environment, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission,
	) (accesstypes.Decision, error)

	// CheckRoleResources returns the Decision for each resource for whether
	// role holds perm on it within scope, all answered from one policy
	// snapshot — the role twin of CheckUserResources, with the same
	// Environment, grouping, and fail-closed semantics.
	CheckRoleResources(
		ctx context.Context, env accesstypes.Environment, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (accesstypes.Decisions, error)

	// UserHasGrants reports whether user holds at least one grant in scope,
	// answered from the in-memory policy snapshot — the visibility question
	// concealed tenancy asks (see Client.UserHasGrants).
	UserHasGrants(ctx context.Context, user accesstypes.User, scope accesstypes.Scope) (bool, error)

	// UserDomains lists the domains where user holds at least one grant,
	// sorted — the tenant picker's membership question, answered with the
	// UserHasGrants foothold predicate (see Client.UserDomains).
	UserDomains(ctx context.Context, user accesstypes.User) ([]accesstypes.Domain, error)

	// UserPermissionDigest returns user's structural grant enumeration within
	// scope — the frontend digest payload: resource → permission → granted or
	// conditional, denied targets absent, nothing folded (see
	// Client.UserPermissionDigest).
	UserPermissionDigest(ctx context.Context, user accesstypes.User, scope accesstypes.Scope) (accesstypes.PermissionDigest, error)

	// ForUser returns the request-bound permission checker for user, whose
	// method set structurally satisfies the resource package's UserPermissions
	// seam. Test doubles implement it in one line over NewUserChecker.
	ForUser(user accesstypes.User) *UserChecker

	// RoleHasGrants reports whether role holds at least one grant in scope —
	// the foothold a session operating as the role has there (see
	// Client.RoleHasGrants).
	RoleHasGrants(ctx context.Context, role accesstypes.Role, scope accesstypes.Scope) (bool, error)

	// RoleDomains lists the domains where role holds at least one grant,
	// sorted — the tenant picker's membership question for a session
	// operating as the role (see Client.RoleDomains).
	RoleDomains(ctx context.Context, role accesstypes.Role) ([]accesstypes.Domain, error)

	// RolePermissionDigest returns role's structural grant enumeration within
	// scope — the frontend digest payload for a session operating as the role
	// (see Client.RolePermissionDigest).
	RolePermissionDigest(ctx context.Context, role accesstypes.Role, scope accesstypes.Scope) (accesstypes.PermissionDigest, error)

	// ForRole returns the request-bound permission checker for role, whose
	// method set structurally satisfies the resource package's
	// RolePermissions seam. Test doubles implement it in one line over
	// NewRoleChecker.
	ForRole(role accesstypes.Role) *RoleChecker

	// UserManager returns the UserManager for managing users, roles, and permissions.
	UserManager() UserManager

	// Handlers returns HTTP handlers for access management with validation and logging.
	Handlers(handler LogHandler) Handlers
}

var _ UserManager = &userManager{}

// UserManager manages RBAC users, roles, and permissions. Scopes are opaque
// partition labels: no method validates tenant existence — the application
// owns its tenant list and validates tenants at its own boundaries.
//
// The base-name/Resources-suffix pairing is the API's naming standard: the
// base method addresses a permission held scope-wide (attached to no
// resource); the Resources variant addresses specific resources.
type UserManager interface {
	// AddRoleUsers assigns role to users in scope. Errors if role doesn't exist.
	AddRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, users ...accesstypes.User) error

	// AddUserRoles assigns roles to user in scope. Errors if any role doesn't exist.
	AddUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, roles ...accesstypes.Role) error

	// DeleteRoleUsers removes users from role in scope. Errors if role doesn't exist.
	DeleteRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, users ...accesstypes.User) error

	// DeleteUserRoles removes role assignments from user in scope.
	DeleteUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, roles ...accesstypes.Role) error

	// UserRoles returns user's roles for the given scopes. At least one scope
	// is required: access holds no scope list of its own to enumerate.
	UserRoles(ctx context.Context, user accesstypes.User, scopes ...accesstypes.Scope) (accesstypes.RoleCollection, error)

	// UserPermissions returns user's effective permissions for the given
	// scopes. At least one scope is required.
	UserPermissions(ctx context.Context, user accesstypes.User, scopes ...accesstypes.Scope) (accesstypes.UserPermissionCollection, error)

	// AddRole creates role in scope. Errors if role already exists.
	AddRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error

	// RoleExists reports whether role exists in scope.
	RoleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)

	// Roles returns all roles in scope.
	Roles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error)

	// DeleteRole removes role from scope. Returns false with error if role has
	// users assigned. The delete is scoped to the given scope.
	DeleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error)

	// AddRolePermission grants permission to role scope-wide: the permission is
	// held with no resource attachment. Errors if role doesn't exist.
	AddRolePermission(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission) error

	// DeleteRolePermission removes a scope-wide permission from role in scope.
	// Errors if role doesn't exist.
	DeleteRolePermission(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission) error

	// AddRolePermissionResources grants permission on resources to role in
	// scope. Errors if role doesn't exist.
	AddRolePermissionResources(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// AddRoleGrant grants permission on one resource to role in scope, limited
	// by condition ("" is unconditional). Errors if role doesn't exist.
	AddRoleGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resource accesstypes.Resource, condition string) error

	// DeleteRolePermissionResources removes every grant of permission on the
	// resources from role in scope, whatever their conditions. Errors if role
	// doesn't exist.
	DeleteRolePermissionResources(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error

	// DeleteRoleGrant removes one grant: permission on resource under
	// condition ("" is the unconditional grant); other conditions on the
	// resource stay. Errors if role doesn't exist.
	DeleteRoleGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resource accesstypes.Resource, condition string) error

	// DeleteAllRolePermissions removes all permissions from role in scope,
	// scope-wide and resource-specific alike.
	DeleteAllRolePermissions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error

	// RoleUsers returns users assigned to role in scope.
	RoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error)

	// RolePermissions returns the permissions role holds in scope and how each
	// is granted (scope-wide, on resources, or both). Errors if role doesn't exist.
	RolePermissions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (accesstypes.RolePermissionCollection, error)

	// RoleGrants returns the role's resource grants in scope, keyed by
	// permission and resource, with the conditions each resource is granted
	// under (sorted; "" is the unconditional grant). Scope-wide grants are not
	// included. Errors if role doesn't exist.
	RoleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (map[accesstypes.Permission]map[accesstypes.Resource][]string, error)
}
