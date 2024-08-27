package access

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
)

var _ UserManager = &userManager{}

type userManager struct {
	Enforcer   func() casbin.IEnforcer // Testing purpose only
	domains    Domains
	connConfig *pgx.ConnConfig

	policyMu     sync.RWMutex
	policyLoaded bool

	enforcerMu          sync.RWMutex
	enforcer            casbin.IEnforcer
	enforcerInitialized bool
}

func newUserManager(domains Domains, connConfig *pgx.ConnConfig) (*userManager, error) {
	enforcer, err := createEnforcer(rbacModel())
	if err != nil {
		return nil, err
	}

	u := &userManager{
		connConfig: connConfig,
		enforcer:   enforcer,
		domains:    domains,
	}

	u.Enforcer = u.refreshEnforcer

	return u, nil
}

func (c *userManager) AddRoleUsers(ctx context.Context, users []User, role Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRoleUsers()")
	defer span.End()

	roleFound := c.RoleExists(ctx, role, domain)
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, username := range users {
		if _, err := c.Enforcer().AddRoleForUser(username.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role.Marshal(), username)
		}
	}

	return nil
}

func (c *userManager) AddUserRoles(ctx context.Context, user User, roles []Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddUserRoles()")
	defer span.End()

	for _, role := range roles {
		if roleFound := c.RoleExists(ctx, role, domain); !roleFound {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
	}

	for _, role := range roles {
		if _, err := c.Enforcer().AddRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role, user)
		}
	}

	return nil
}

func (c *userManager) DeleteRoleUsers(ctx context.Context, users []User, role Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRoleUsers()")
	defer span.End()

	if roleFound := c.RoleExists(ctx, role, domain); !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, username := range users {
		if _, err := c.Enforcer().DeleteRoleForUser(username.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
			return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role.Marshal(), username)
		}
	}

	return nil
}

func (c *userManager) DeleteAllRolePermissions(ctx context.Context, role Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteAllRolePermissions()")
	defer span.End()

	perms, err := c.RolePermissions(ctx, role, domain)
	if err != nil {
		return errors.Wrap(err, "client.RolePermissions()")
	}

	if err := c.DeleteRolePermissions(ctx, perms, role, domain); err != nil {
		return errors.Wrap(err, "client.DeleteRolePermissions()")
	}

	return nil
}

func (c *userManager) DeleteUserRole(ctx context.Context, username User, role Role, domain Domain) error {
	_, span := otel.Tracer(name).Start(ctx, "client.DeleteUserRole()")
	defer span.End()

	if _, err := c.Enforcer().DeleteRoleForUser(username.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrapf(err, "casbin.SyncedEnforcer.DeleteRoleForUser(): role %q to %q", role.Marshal(), username)
	}

	return nil
}

func (c *userManager) User(ctx context.Context, username User, domain ...Domain) (*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.User()")
	defer span.End()

	if domain == nil {
		var err error
		domain, err = c.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	user, err := c.user(ctx, username, domain)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *userManager) user(ctx context.Context, username User, domains []Domain) (*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.user()")
	defer span.End()

	roles, err := c.userRoles(ctx, username, domains)
	if err != nil {
		return nil, err
	}

	permissions, err := c.userPermissions(ctx, username, domains)
	if err != nil {
		return nil, err
	}

	return &UserAccess{
		Name:        string(username),
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

func (c *userManager) Users(ctx context.Context, domain ...Domain) ([]*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Users()")
	defer span.End()

	if domain == nil {
		var err error
		domain, err = c.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	users, err := c.users(ctx, domain)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (c *userManager) users(ctx context.Context, domains []Domain) ([]*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.users()")
	defer span.End()

	var users []*UserAccess
	userMap := make(map[string]bool)
	roles, err := c.Enforcer().GetAllRoles()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetAllRoles()")
	}

	subjects, err := c.Enforcer().GetAllSubjects()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetAllSubjects()")
	}
SUB:
	// loop through the subjects (containing both roles and usernames)
	// and if it is a a role, skip it, otherwise add user to the map
	for _, username := range subjects {
		for _, role := range roles {
			if role == username || username == NoopUser {
				continue SUB
			}
		}

		user, err := c.user(ctx, unmarshalUser(username), domains)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
		userMap[username] = true
	}
	// now get the grouping policy and look for users in there
	groupingPolicy, err := c.Enforcer().GetGroupingPolicy()
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetGroupingPolicy()")
	}
GP:
	for _, gp := range groupingPolicy {
		username := gp[0]
		if userMap[username] || username == NoopUser {
			continue
		}

		for _, role := range roles {
			if role == username {
				continue GP
			}
		}

		user, err := c.user(ctx, unmarshalUser(username), domains)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
		userMap[username] = true
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})

	return users, nil
}

// UserRoles gets the roles assigned to a user separated by domain
func (c *userManager) UserRoles(ctx context.Context, username User, domain ...Domain) (map[Domain][]Role, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserRoles()")
	defer span.End()

	if domain == nil {
		var err error
		domain, err = c.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userRoles, err := c.userRoles(ctx, username, domain)
	if err != nil {
		return nil, err
	}

	return userRoles, nil
}

func (c *userManager) userRoles(ctx context.Context, username User, domains []Domain) (map[Domain][]Role, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.userRoles()")
	defer span.End()

	userRoles := make(map[Domain][]Role)
	for _, domain := range domains {
		strRoles, err := c.Enforcer().GetRolesForUser(username.Marshal(), domain.Marshal())
		if err != nil {
			return nil, errors.Wrapf(err, "casbin.SyncedEnforcer.GetRolesForUser(): user: %q", username)
		}

		roles := make([]Role, 0, len(strRoles))
		for _, role := range strRoles {
			roles = append(roles, unmarshalRole(role))
		}
		userRoles[domain] = roles
	}

	return userRoles, nil
}

func (c *userManager) UserPermissions(ctx context.Context, username User, domain ...Domain) (map[Domain][]Permission, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserPermissions()")
	defer span.End()

	if domain == nil {
		var err error
		domain, err = c.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userPermissions, err := c.userPermissions(ctx, username, domain)
	if err != nil {
		return nil, err
	}

	return userPermissions, nil
}

func (c *userManager) userPermissions(ctx context.Context, username User, domains []Domain) (map[Domain][]Permission, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.userPermissions()")
	defer span.End()

	userPermissions := make(map[Domain][]Permission)
	for _, domain := range domains {
		strPerms, err := c.Enforcer().GetImplicitPermissionsForUser(username.Marshal(), domain.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "enforcer.GetImplicitPermissionsForUser()")
		}
		perms := make([]Permission, 0, len(strPerms))
		for _, perm := range strPerms {
			perms = append(perms, unmarshalPermission(perm[3]))
		}

		sort.Slice(perms, func(i, j int) bool {
			return perms[i] < perms[j]
		})

		userPermissions[domain] = perms
	}

	return userPermissions, nil
}

func (c *userManager) AddRole(ctx context.Context, domain Domain, role Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRole()")
	defer span.End()

	if exists, err := c.DomainExists(ctx, domain); err != nil {
		return errors.Wrap(err, "domainExists()")
	} else if !exists {
		return httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	if roleDoesExist := c.RoleExists(ctx, role, domain); roleDoesExist {
		return httpio.NewConflictMessagef("role %q already exists", string(role))
	}

	if _, err := c.Enforcer().AddGroupingPolicy(NoopUser, role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrap(err, "enforcer.AddGroupingPolicy()")
	}

	return nil
}

func (c *userManager) Roles(ctx context.Context, domain Domain) ([]Role, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Roles()")
	defer span.End()

	if exists, err := c.DomainExists(ctx, domain); err != nil {
		return nil, errors.Wrap(err, "domainExists()")
	} else if !exists {
		return nil, httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	// filter by domain
	grouping, err := c.Enforcer().GetFilteredGroupingPolicy(2, domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetFilteredGroupingPolicy()")
	}

	roleMap := map[Role]bool{}
	for _, group := range grouping {
		roleMap[unmarshalRole(group[1])] = true
	}

	roles := make([]Role, 0, len(roleMap))

	for role := range roleMap {
		roles = append(roles, role)
	}

	// ensures the list is always returned in the same order as casbin doesn't handle this
	sort.Slice(roles, func(i int, j int) bool {
		return string(roles[i]) < string(roles[j])
	})

	return roles, nil
}

func (c *userManager) DeleteRole(ctx context.Context, role Role, domain Domain) (bool, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRole()")
	defer span.End()

	if hasUsers, err := c.hasUsersAssigned(ctx, role, domain); err != nil {
		return false, errors.Wrap(err, "client.hasUsersAssigned()")
	} else if hasUsers {
		return false, httpio.NewBadRequestMessagef("Users assigned to the role. You cannot delete a role that has users assigned")
	}

	deleted, err := c.Enforcer().DeleteRole(role.Marshal())
	if err != nil {
		return false, errors.Wrap(err, "enforcer.DeleteRole()")
	}

	return deleted, nil
}

func (c *userManager) AddRolePermissions(ctx context.Context, permissions []Permission, role Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRolePermissions()")
	defer span.End()

	if !c.RoleExists(ctx, role, domain) {
		return httpio.NewNotFoundMessagef("Permissions cannot be added to a role that doesn't exist")
	}

	for _, permission := range permissions {
		if err := c.addPolicy(ctx, permission, role, domain); err != nil {
			return errors.Wrap(err, "users.addPolicy()")
		}
	}

	return nil
}

func (c *userManager) DeleteRolePermissions(ctx context.Context, permissions []Permission, role Role, domain Domain) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRolePermissions()")
	defer span.End()

	if !c.RoleExists(ctx, role, domain) {
		return httpio.NewNotFoundMessagef("Permissions cannot be removed from a role that doesn't exist")
	}

	for _, permission := range permissions {
		if _, err := c.Enforcer().RemoveFilteredPolicy(0, role.Marshal(), domain.Marshal(), "*", permission.Marshal()); err != nil {
			return errors.Wrapf(err, "enforcer.RemoveFilteredPolicy() role=%q, domain=%q", role, domain)
		}
	}

	return nil
}

func (c *userManager) RoleUsers(ctx context.Context, role Role, domain Domain) ([]User, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.RoleUsers()")
	defer span.End()

	users, err := c.Enforcer().GetUsersForRole(role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetUsersForRole()")
	}

	actualUsers := make([]User, 0, len(users))
	for _, u := range users {
		if u == NoopUser {
			continue
		}
		actualUsers = append(actualUsers, unmarshalUser(u))
	}

	return actualUsers, nil
}

func (c *userManager) RolePermissions(ctx context.Context, role Role, domain Domain) ([]Permission, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.RolePermissions()")
	defer span.End()

	if !c.RoleExists(ctx, role, domain) {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	policies, err := c.Enforcer().GetFilteredPolicy(0, role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetFilteredPolicy()")
	}

	permissions := make([]Permission, 0, len(policies))
	for _, p := range policies {
		permissions = append(permissions, unmarshalPermission(p[3]))
	}

	return permissions, nil
}

func (c *userManager) addPolicy(ctx context.Context, permission Permission, role Role, domain Domain) error {
	_, span := otel.Tracer(name).Start(ctx, "client.addPolicy()")
	defer span.End()

	if _, err := c.Enforcer().AddPolicy(role.Marshal(), domain.Marshal(), "*", permission.Marshal(), "allow"); err != nil {
		return errors.Wrap(err, "enforcer.AddPolicy()")
	}

	return nil
}

func (c *userManager) RoleExists(ctx context.Context, role Role, domain Domain) bool {
	_, span := otel.Tracer(name).Start(ctx, "client.RoleExists()")
	defer span.End()

	roles := c.Enforcer().GetRolesForUserInDomain(NoopUser, domain.Marshal())

	return slices.Contains(roles, role.Marshal())
}

func (c *userManager) Domains(ctx context.Context) ([]Domain, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Domains()")
	defer span.End()

	ids, err := c.domains.DomainIDs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.GuarantorIDs()")
	}

	domains := make([]Domain, 1, len(ids)+1)
	domains[0] = GlobalDomain
	for _, v := range ids {
		domains = append(domains, Domain(v))
	}

	return domains, nil
}

func (c *userManager) hasUsersAssigned(ctx context.Context, role Role, domain Domain) (bool, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.hasUsersAssigned()")
	defer span.End()

	users, err := c.Enforcer().GetUsersForRole(role.Marshal(), domain.Marshal())
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
func (c *userManager) DomainExists(ctx context.Context, domain Domain) (bool, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DomainExists()")
	defer span.End()

	if domain == GlobalDomain {
		return true, nil
	}
	exists, err := c.domains.DomainExists(ctx, string(domain))
	if err != nil {
		return false, errors.Wrap(err, "dbx.DB.GuarantorExists()")
	}

	return exists, nil
}
