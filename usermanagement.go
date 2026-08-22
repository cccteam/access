package access

import (
	"context"
	"maps"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ UserManager = &userManager{}

// userManager implements UserManager on top of the policyStore seam.
// Validation (role existence, empty-input checks) lives here; the store only
// persists and queries policy. Domains are opaque partition labels — nothing
// here validates domain existence, and no operation enumerates domains: the
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

// AddRoleUsers assigns a specified role to multiple users within a domain.
// Returns an error if the role doesn't exist in the domain.
func (u *userManager) AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, domain, role)
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

		if err := u.store.addUserRole(ctx, domain, user, role); err != nil {
			return err
		}
	}

	return nil
}

// AddUserRoles assigns multiple roles to a user within a domain.
// Returns an error if any of the roles don't exist in the domain.
func (u *userManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		roleFound, err := u.RoleExists(ctx, domain, role)
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
		if err := u.store.addUserRole(ctx, domain, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRoleUsers removes multiple users from a specified role within a domain.
// Returns an error if the role doesn't exist.
func (u *userManager) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, domain, role)
	if err != nil {
		return err
	}
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		if err := u.store.deleteUserRole(ctx, domain, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteAllRolePermissions removes all permissions (both global and resource-specific) from a role within a domain.
func (u *userManager) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	perms, err := u.RolePermissions(ctx, domain, role)
	if err != nil {
		return errors.Wrap(err, "client.RolePermissions()")
	}

	if err := u.DeleteRolePermissions(ctx, domain, role, slices.Collect(maps.Keys(perms))...); err != nil {
		return errors.Wrap(err, "client.DeleteRolePermissions()")
	}

	return nil
}

// DeleteUserRoles removes multiple role assignments from a user within a domain.
// The operation succeeds regardless of whether the roles were previously assigned to the user.
func (u *userManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		if err := u.store.deleteUserRole(ctx, domain, user, role); err != nil {
			return err
		}
	}

	return nil
}

// UserRoles returns the roles assigned to a user across the given domains.
// At least one domain is required: access holds no domain list of its own.
func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(domains) == 0 {
		return nil, httpio.NewBadRequestMessage("at least one domain is required")
	}

	userRoles := make(accesstypes.RoleCollection)
	for _, domain := range domains {
		roles, err := u.store.userRoles(ctx, domain, user)
		if err != nil {
			return nil, err
		}

		userRoles[domain] = roles
	}

	return userRoles, nil
}

// UserPermissions returns the effective permissions for a user across the
// given domains. At least one domain is required: access holds no domain list
// of its own.
func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(domains) == 0 {
		return nil, httpio.NewBadRequestMessage("at least one domain is required")
	}

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, domain := range domains {
		permissions, err := u.store.userPermissions(ctx, domain, user)
		if err != nil {
			return nil, err
		}

		userPermissions[domain] = permissions
	}

	return userPermissions, nil
}

// AddRole creates role in domain. The domain is an opaque partition label:
// its validity is the caller's business.
func (u *userManager) AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleDoesExist, err := u.RoleExists(ctx, domain, role)
	if err != nil {
		return err
	}
	if roleDoesExist {
		return httpio.NewConflictMessagef("role %q already exists", string(role))
	}

	if role == "" {
		return httpio.NewBadRequestMessage("role cannot be empty string")
	}

	if err := u.store.addRole(ctx, domain, role); err != nil {
		return err
	}

	return nil
}

// Roles returns all roles in domain.
func (u *userManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roles, err := u.store.roles(ctx, domain)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// DeleteRole removes role from domain, scoped to that domain. It refuses when
// users are still assigned to the role in the domain.
func (u *userManager) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if hasUsers, err := u.hasUsersAssigned(ctx, domain, role); err != nil {
		return false, errors.Wrap(err, "client.hasUsersAssigned()")
	} else if hasUsers {
		return false, httpio.NewBadRequestMessagef("Users assigned to the role. You cannot delete a role that has users assigned")
	}

	deleted, err := u.store.deleteRole(ctx, domain, role)
	if err != nil {
		return false, err
	}

	return deleted, nil
}

// AddRolePermissions grants global permissions to role in domain.
func (u *userManager) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, domain, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	for _, permission := range permissions {
		if permission == "" {
			return httpio.NewBadRequestMessage("permission cannot be empty string")
		}

		if err := u.store.addGrant(ctx, domain, role, permission, accesstypes.GlobalResource); err != nil {
			return err
		}
	}

	return nil
}

// AddRolePermissionResources grants resource-specific permissions to role in domain.
func (u *userManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, domain, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	for _, resource := range resources {
		if resource == "" {
			return httpio.NewBadRequestMessage("resource cannot be empty string")
		}

		if err := u.store.addGrant(ctx, domain, role, permission, resource); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRolePermissions removes global permissions from role in domain.
func (u *userManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, domain, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	for _, permission := range permissions {
		if err := u.store.removeGrant(ctx, domain, role, permission, accesstypes.GlobalResource); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRolePermissionResources removes resource-specific permissions from role in domain.
func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireRole(ctx, domain, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	for _, resource := range resources {
		if err := u.store.removeGrant(ctx, domain, role, permission, resource); err != nil {
			return err
		}
	}

	return nil
}

// RoleUsers returns the users assigned to role in domain.
func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, domain, role)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// RolePermissions returns the permissions held by role in domain.
func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, domain, role)
	if err != nil {
		return nil, err
	}
	if !roleFound {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	permissions, err := u.store.roleGrants(ctx, domain, role)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// RoleExists reports whether role exists in domain.
func (u *userManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	exists, err := u.store.roleExists(ctx, domain, role)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// requireRole errors with notFoundMsg when role does not exist in domain.
func (u *userManager) requireRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, notFoundMsg string) error {
	exists, err := u.RoleExists(ctx, domain, role)
	if err != nil {
		return err
	}
	if !exists {
		return httpio.NewNotFoundMessage(notFoundMsg)
	}

	return nil
}

func (u *userManager) hasUsersAssigned(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, domain, role)
	if err != nil {
		return false, errors.Wrap(err, "roleUsers()")
	}

	return len(users) > 0, nil
}
