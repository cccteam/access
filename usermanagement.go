package access

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ UserManager = &userManager{}

// userManager implements UserManager with casbin enforcement and thread-safe operations.
type userManager struct {
	Enforcer func() casbin.IEnforcer // Exposed for testing
	domains  Domains
	adapter  Adapter

	policyMu     sync.RWMutex
	policyLoaded bool

	enforcerMu          sync.RWMutex
	enforcer            casbin.IEnforcer
	enforcerInitialized bool
}

// newUserManager creates userManager. Errors if casbin enforcer creation fails.
func newUserManager(domains Domains, adapter Adapter) (*userManager, error) {
	enforcer, err := createEnforcer(rbacModel())
	if err != nil {
		return nil, err
	}

	u := &userManager{
		adapter:  adapter,
		enforcer: enforcer,
		domains:  domains,
	}

	u.Enforcer = u.refreshEnforcer

	return u, nil
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

		if _, err := u.Enforcer().AddRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role.Marshal(), user)
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
		if _, err := u.Enforcer().AddRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role, user)
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
		if _, err := u.Enforcer().DeleteRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role.Marshal(), user)
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
	_, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		if _, err := u.Enforcer().DeleteRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.DeleteRoleForUser(): role %q to %q", role.Marshal(), user)
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

	var users []*UserAccess
	userMap := make(map[string]bool)
	roles, err := u.Enforcer().GetAllRoles()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetAllRoles()")
	}

	subjects, err := u.Enforcer().GetAllSubjects()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetAllSubjects()")
	}
SUB:
	// loop through the subjects (containing both roles and usernames)
	// and if it is a a role, skip it, otherwise add user to the map
	for _, user := range subjects {
		for _, role := range roles {
			if role == user || user == accesstypes.NoopUser {
				continue SUB
			}
		}

		accessUser, err := u.user(ctx, accesstypes.UnmarshalUser(user), domains)
		if err != nil {
			return nil, err
		}

		users = append(users, accessUser)
		userMap[user] = true
	}
	// now get the grouping policy and look for users in there
	groupingPolicy, err := u.Enforcer().GetGroupingPolicy()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetGroupingPolicy()")
	}
GP:
	for _, gp := range groupingPolicy {
		user := gp[0]
		if userMap[user] || user == accesstypes.NoopUser {
			continue
		}

		for _, role := range roles {
			if role == user {
				continue GP
			}
		}

		accessUser, err := u.user(ctx, accesstypes.UnmarshalUser(user), domains)
		if err != nil {
			return nil, err
		}

		users = append(users, accessUser)
		userMap[user] = true
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
	_, span := tracer.Start(ctx)
	defer span.End()

	userRoles := make(accesstypes.RoleCollection)
	for _, domain := range domains {
		strRoles, err := u.Enforcer().GetRolesForUser(user.Marshal(), domain.Marshal())
		if err != nil {
			return nil, errors.Wrapf(err, "casbin.SyncedEnforcer.GetRolesForUser(): user: %q", user)
		}

		roles := make([]accesstypes.Role, 0, len(strRoles))
		for _, role := range strRoles {
			roles = append(roles, accesstypes.UnmarshalRole(role))
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
	_, span := tracer.Start(ctx)
	defer span.End()

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, domain := range domains {
		userPermissions[domain] = make(map[accesstypes.Resource][]accesstypes.Permission)

		strPerms, err := u.Enforcer().GetImplicitPermissionsForUser(user.Marshal(), domain.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "enforcer.GetImplicitPermissionsForUser()")
		}

		for _, perm := range strPerms {
			if slices.Contains(userPermissions[domain][accesstypes.UnmarshalResource(perm[2])], accesstypes.UnmarshalPermission(perm[3])) {
				continue
			}
			userPermissions[domain][accesstypes.UnmarshalResource(perm[2])] = append(userPermissions[domain][accesstypes.UnmarshalResource(perm[2])], accesstypes.UnmarshalPermission(perm[3]))
		}
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

	if _, err := u.Enforcer().AddGroupingPolicy(accesstypes.NoopUser, role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrap(err, "enforcer.AddGroupingPolicy()")
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

	// filter by domain
	grouping, err := u.Enforcer().GetFilteredGroupingPolicy(2, domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetFilteredGroupingPolicy()")
	}

	roleMap := map[accesstypes.Role]bool{}
	for _, group := range grouping {
		roleMap[accesstypes.UnmarshalRole(group[1])] = true
	}

	roles := make([]accesstypes.Role, 0, len(roleMap))

	for role := range roleMap {
		roles = append(roles, role)
	}

	// ensures the list is always returned in the same order as casbin doesn't handle this
	sort.Slice(roles, func(i int, j int) bool {
		return string(roles[i]) < string(roles[j])
	})

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

	deleted, err := u.Enforcer().DeleteRole(role.Marshal())
	if err != nil {
		return false, errors.Wrap(err, "enforcer.DeleteRole()")
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

		if _, err := u.Enforcer().AddPolicy(role.Marshal(), domain.Marshal(), accesstypes.GlobalResource.Marshal(), permission.Marshal(), "allow"); err != nil {
			return errors.Wrap(err, "enforcer.AddPolicy()")
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

		if _, err := u.Enforcer().AddPolicy(role.Marshal(), domain.Marshal(), resource.Marshal(), permission.Marshal(), "allow"); err != nil {
			return errors.Wrap(err, "enforcer.AddPolicy()")
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
		if _, err := u.Enforcer().RemoveFilteredPolicy(0, role.Marshal(), domain.Marshal(), accesstypes.GlobalResource.Marshal(), permission.Marshal()); err != nil {
			return errors.Wrapf(err, "enforcer.RemoveFilteredPolicy() role=%q, domain=%q", role, domain)
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
		if _, err := u.Enforcer().RemoveFilteredPolicy(0, role.Marshal(), domain.Marshal(), resource.Marshal(), permission.Marshal()); err != nil {
			return errors.Wrapf(err, "enforcer.RemoveFilteredPolicy() role=%q, domain=%q", role, domain)
		}
	}

	return nil
}

func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	_, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.Enforcer().GetUsersForRole(role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetUsersForRole()")
	}

	actualUsers := make([]accesstypes.User, 0, len(users))
	for _, u := range users {
		if u == accesstypes.NoopUser {
			continue
		}
		actualUsers = append(actualUsers, accesstypes.UnmarshalUser(u))
	}

	return actualUsers, nil
}

func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if !u.RoleExists(ctx, domain, role) {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	policies, err := u.Enforcer().GetFilteredPolicy(0, role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetFilteredPolicy()")
	}

	permissions := make(accesstypes.RolePermissionCollection, len(policies))
	for _, p := range policies {
		permissions[accesstypes.UnmarshalPermission(p[3])] = append(permissions[accesstypes.UnmarshalPermission(p[3])], accesstypes.UnmarshalResource(p[2]))
	}

	return permissions, nil
}

func (u *userManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	_, span := tracer.Start(ctx)
	defer span.End()

	roles := u.Enforcer().GetRolesForUserInDomain(accesstypes.NoopUser, domain.Marshal())

	return slices.Contains(roles, role.Marshal())
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
	_, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.Enforcer().GetUsersForRole(role.Marshal(), domain.Marshal())
	if err != nil {
		return false, errors.Wrap(err, "enforcer.GetUsersForRole()")
	}

	// We aren't checking the single user to be someone else as it should always be noop if length is 1.
	// Do we need to throw an error if it is someone other than noop?
	if len(users) <= 1 {
		return false, nil
	}

	return true, nil
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
