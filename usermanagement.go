package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ UserManager = &userManager{}

// userManager implements UserManager on top of the policyStore seam.
// Validation (role existence, empty-input checks) lives here; the store only
// persists and queries policy. Scopes are opaque partition labels — nothing
// here validates tenant existence, and no operation enumerates scopes: the
// application owns its tenant list.
type userManager struct {
	store policyStore
}

// newUserManager creates userManager backed by the given policy store.
func newUserManager(store policyStore) *userManager {
	return &userManager{
		store: store,
	}
}

// AddRoleUsers assigns a specified role to multiple users within a scope.
// Returns an error if the role doesn't exist in the domain.
func (u *userManager) AddRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		if user == "" {
			return httpio.NewBadRequestMessage("user cannot be empty string")
		}

		if err := u.store.addUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// AddUserRoles assigns multiple roles to a user within a scope.
// Returns an error if any of the roles don't exist in the domain.
func (u *userManager) AddUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		roleFound, err := u.RoleExists(ctx, scope, role)
		if err != nil {
			return err
		}
		if !roleFound {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
	}

	if user == "" {
		return httpio.NewBadRequestMessage("user cannot be empty string")
	}

	for _, role := range roles {
		if err := u.store.addUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRoleUsers removes multiple users from a specified role within a scope.
// Returns an error if the role doesn't exist.
func (u *userManager) DeleteRoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		if err := u.store.deleteUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteAllRolePermissions removes all permissions from a role within a
// scope, scope-wide and resource-specific alike.
func (u *userManager) DeleteAllRolePermissions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	perms, err := u.RolePermissions(ctx, scope, role)
	if err != nil {
		return errors.Wrap(err, "client.RolePermissions()")
	}

	for permission, grants := range perms {
		if grants.ScopeWide {
			if err := u.DeleteRolePermission(ctx, scope, role, permission); err != nil {
				return errors.Wrap(err, "client.DeleteRolePermission()")
			}
		}
		if len(grants.Resources) > 0 {
			if err := u.DeleteRolePermissionResources(ctx, scope, role, permission, grants.Resources...); err != nil {
				return errors.Wrap(err, "client.DeleteRolePermissionResources()")
			}
		}
	}

	return nil
}

// DeleteUserRoles removes multiple role assignments from a user within a scope.
// The operation succeeds regardless of whether the roles were previously assigned to the user.
func (u *userManager) DeleteUserRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		if err := u.store.deleteUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// UserRoles returns the roles assigned to a user across the given scopes.
// At least one scope is required: access holds no scope list of its own.
func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, scopes ...accesstypes.Scope) (accesstypes.RoleCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(scopes) == 0 {
		return nil, httpio.NewBadRequestMessage("at least one scope is required")
	}

	userRoles := make(accesstypes.RoleCollection)
	for _, scope := range scopes {
		roles, err := u.store.userRoles(ctx, scope, user)
		if err != nil {
			return nil, err
		}

		userRoles[scope] = roles
	}

	return userRoles, nil
}

// UserPermissions returns the effective permissions for a user across the
// given domains. At least one domain is required: access holds no domain list
// of its own.
func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, scopes ...accesstypes.Scope) (accesstypes.UserPermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(scopes) == 0 {
		return nil, httpio.NewBadRequestMessage("at least one scope is required")
	}

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, scope := range scopes {
		permissions, err := u.store.userPermissions(ctx, scope, user)
		if err != nil {
			return nil, err
		}

		userPermissions[scope] = permissions
	}

	return userPermissions, nil
}

// AddRole creates role in scope. The scope is an opaque partition label:
// its validity is the caller's business.
func (u *userManager) AddRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleDoesExist, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if roleDoesExist {
		return httpio.NewConflictMessagef("role %q already exists", string(role))
	}

	if role == "" {
		return httpio.NewBadRequestMessage("role cannot be empty string")
	}

	if err := u.store.addRole(ctx, scope, role); err != nil {
		return err
	}

	return nil
}

// Roles returns all roles in scope.
func (u *userManager) Roles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roles, err := u.store.roles(ctx, scope)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// DeleteRole removes role from domain, scoped to that domain. It refuses when
// users are still assigned to the role in the domain.
func (u *userManager) DeleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if hasUsers, err := u.hasUsersAssigned(ctx, scope, role); err != nil {
		return false, errors.Wrap(err, "client.hasUsersAssigned()")
	} else if hasUsers {
		return false, httpio.NewBadRequestMessagef("Users assigned to the role. You cannot delete a role that has users assigned")
	}

	deleted, err := u.store.deleteRole(ctx, scope, role)
	if err != nil {
		return false, err
	}

	return deleted, nil
}

// AddRolePermission grants permission to role scope-wide: the permission is
// held with no resource attachment.
func (u *userManager) AddRolePermission(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	if err := u.store.addScopeWideGrant(ctx, scope, role, permission); err != nil {
		return err
	}

	return nil
}

// DeleteRolePermission removes a scope-wide permission from role in scope.
func (u *userManager) DeleteRolePermission(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	if err := u.store.removeScopeWideGrant(ctx, scope, role, permission); err != nil {
		return err
	}

	return nil
}

// AddRolePermissionResources grants resource-specific permissions to role in scope.
func (u *userManager) AddRolePermissionResources(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	for _, resource := range resources {
		if resource == "" {
			return httpio.NewBadRequestMessage("resource cannot be empty string")
		}

		if err := u.store.addGrant(ctx, scope, role, permission, resource, ""); err != nil {
			return err
		}
	}

	return nil
}

// AddRoleGrant grants permission on one resource to role in scope, limited by
// condition ("" is unconditional).
func (u *userManager) AddRoleGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resource accesstypes.Resource, condition string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}
	if resource == "" {
		return httpio.NewBadRequestMessage("resource cannot be empty string")
	}

	if err := u.store.addGrant(ctx, scope, role, permission, resource, condition); err != nil {
		return err
	}

	return nil
}

// DeleteRolePermissionResources removes resource-specific permissions from role in scope.
func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	for _, resource := range resources {
		if err := u.store.removeGrant(ctx, scope, role, permission, resource); err != nil {
			return err
		}
	}

	return nil
}

// RoleUsers returns the users assigned to role in scope.
func (u *userManager) RoleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, scope, role)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// RolePermissions returns the permissions held by role in scope.
func (u *userManager) RolePermissions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return nil, err
	}
	if !roleFound {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	permissions, err := u.store.roleGrants(ctx, scope, role)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// RoleGrants returns the role's resource grants in scope with each grant's
// condition text ("" is unconditional), keyed by permission.
func (u *userManager) RoleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (map[accesstypes.Permission]map[accesstypes.Resource]string, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return nil, err
	}
	if !roleFound {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	grants, err := u.store.roleGrantConditions(ctx, scope, role)
	if err != nil {
		return nil, err
	}

	return grants, nil
}

// RoleExists reports whether role exists in scope.
func (u *userManager) RoleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	exists, err := u.store.roleExists(ctx, scope, role)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// requireRole errors with notFoundMsg when role does not exist in scope.
func (u *userManager) requireRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, notFoundMsg string) error {
	exists, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !exists {
		return httpio.NewNotFoundMessage(notFoundMsg)
	}

	return nil
}

func (u *userManager) hasUsersAssigned(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, scope, role)
	if err != nil {
		return false, errors.Wrap(err, "roleUsers()")
	}

	return len(users) > 0, nil
}
