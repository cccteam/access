package access

import (
	"context"
	"maps"
	"slices"
	"sort"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ UserManager = &userManager{}

// userManager implements UserManager on top of the policyStore seam.
// Validation (domain/role existence, empty-input checks) lives here; the store
// only persists and queries policy.
type userManager struct {
	store   policyStore
	domains Domains
}

// newUserManager creates userManager backed by the given policy store.
func newUserManager(domains Domains, store policyStore) *userManager {
	return &userManager{
		store:   store,
		domains: domains,
	}
}

// AddRoleUsers assigns a specified role to multiple users within a domain.
// Returns an error if the role doesn't exist in the domain.
func (u *userManager) AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound := u.RoleExists(ctx, domain, role)
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
		if roleFound := u.RoleExists(ctx, domain, role); !roleFound {
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

	if roleFound := u.RoleExists(ctx, domain, role); !roleFound {
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

// User retrieves a user's access information including roles and permissions.
// If no domains are specified, returns information for all domains the user has access to.
func (u *userManager) User(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (*UserAccess, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	return u.user(ctx, user, domains)
}

func (u *userManager) user(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (*UserAccess, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roles, err := u.userRoles(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	permissions, err := u.userPermissions(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	return &UserAccess{
		Name:        string(user),
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

// Users retrieves access information for all users in the system.
// If no domains are specified, returns information across all domains.
func (u *userManager) Users(ctx context.Context, domains ...accesstypes.Domain) ([]*UserAccess, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	users, err := u.users(ctx, domains)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *userManager) users(ctx context.Context, domains []accesstypes.Domain) ([]*UserAccess, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	userIDs, err := u.store.users(ctx)
	if err != nil {
		return nil, err
	}

	var users []*UserAccess
	for _, user := range userIDs {
		accessUser, err := u.user(ctx, user, domains)
		if err != nil {
			return nil, err
		}

		users = append(users, accessUser)
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})

	return users, nil
}

// UserRoles returns the roles assigned to a user across specified domains.
// If no domains are specified, returns roles across all domains.
func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userRoles, err := u.userRoles(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	return userRoles, nil
}

func (u *userManager) userRoles(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (accesstypes.RoleCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

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

// UserPermissions returns the effective permissions for a user across specified domains.
// If no domains are specified, returns permissions across all domains.
func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userPermissions, err := u.userPermissions(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	return userPermissions, nil
}

func (u *userManager) userPermissions(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

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

func (u *userManager) AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if exists, err := u.DomainExists(ctx, domain); err != nil {
		return errors.Wrap(err, "domainExists()")
	} else if !exists {
		return httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	if roleDoesExist := u.RoleExists(ctx, domain, role); roleDoesExist {
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

func (u *userManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if exists, err := u.DomainExists(ctx, domain); err != nil {
		return nil, errors.Wrap(err, "domainExists()")
	} else if !exists {
		return nil, httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	roles, err := u.store.roles(ctx, domain)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

func (u *userManager) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if hasUsers, err := u.hasUsersAssigned(ctx, domain, role); err != nil {
		return false, errors.Wrap(err, "client.hasUsersAssigned()")
	} else if hasUsers {
		return false, httpio.NewBadRequestMessagef("Users assigned to the role. You cannot delete a role that has users assigned")
	}

	deleted, err := u.store.deleteRole(ctx, role)
	if err != nil {
		return false, err
	}

	return deleted, nil
}

func (u *userManager) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return httpio.NewNotFoundMessagef("Permissions cannot be added to a role that doesn't exist")
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

func (u *userManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return httpio.NewNotFoundMessagef("Permissions cannot be added to a role that doesn't exist")
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

func (u *userManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return httpio.NewNotFoundMessagef("Permissions cannot be removed from a role that doesn't exist")
	}

	for _, permission := range permissions {
		if err := u.store.removeGrant(ctx, domain, role, permission, accesstypes.GlobalResource); err != nil {
			return err
		}
	}

	return nil
}

func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return httpio.NewNotFoundMessagef("Permissions cannot be removed from a role that doesn't exist")
	}

	for _, resource := range resources {
		if err := u.store.removeGrant(ctx, domain, role, permission, resource); err != nil {
			return err
		}
	}

	return nil
}

func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, domain, role)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	permissions, err := u.store.roleGrants(ctx, domain, role)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (u *userManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return u.store.roleExists(ctx, domain, role)
}

func (u *userManager) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	ids, err := u.domains.DomainIDs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.GuarantorIDs()")
	}

	domains := make([]accesstypes.Domain, 1, len(ids)+1)
	domains[0] = accesstypes.GlobalDomain
	for _, v := range ids {
		domains = append(domains, accesstypes.Domain(v))
	}

	return domains, nil
}

func (u *userManager) hasUsersAssigned(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	// roleUsers excludes the internal noop sentinel, so any user counts.
	users, err := u.store.roleUsers(ctx, domain, role)
	if err != nil {
		return false, errors.Wrap(err, "roleUsers()")
	}

	return len(users) > 0, nil
}

// DomainExists checks if the domain exists in the application.
func (u *userManager) DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if domain == accesstypes.GlobalDomain {
		return true, nil
	}
	exists, err := u.domains.DomainExists(ctx, string(domain))
	if err != nil {
		return false, errors.Wrap(err, "dbx.DB.GuarantorExists()")
	}

	return exists, nil
}
