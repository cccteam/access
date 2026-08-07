package access

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

func createEnforcer(rbacModel string) (*casbin.SyncedEnforcer, error) {
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, errors.Wrap(err, "model.NewModelFromString()")
	}

	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, errors.Wrapf(err, "casbin.NewSyncedEnforcer()")
	}

	e.EnableAutoSave(true)

	return e, nil
}

var (
	_ evaluator   = &casbinEngine{}
	_ policyStore = &casbinEngine{}
)

// casbinEngine implements the evaluator and policyStore seams on the casbin path.
// All casbin-specific concerns live here: the enforcer lifecycle, the
// user:/role:/resource:/perm: Marshal prefixes, and the noop sentinel user that
// makes empty roles enumerable.
type casbinEngine struct {
	Enforcer func() casbin.IEnforcer // Exposed for testing

	adapter Adapter

	policyMu     sync.RWMutex
	policyLoaded bool

	enforcerMu          sync.RWMutex
	enforcer            casbin.IEnforcer
	enforcerInitialized bool
}

// newCasbinEngine creates the casbin-backed engine. Errors if enforcer creation fails.
func newCasbinEngine(adapter Adapter) (*casbinEngine, error) {
	enforcer, err := createEnforcer(rbacModel())
	if err != nil {
		return nil, err
	}

	e := &casbinEngine{
		adapter:  adapter,
		enforcer: enforcer,
	}
	e.Enforcer = e.refreshEnforcer

	return e, nil
}

func (c *casbinEngine) refreshEnforcer() casbin.IEnforcer {
	c.initEnforcer()

	return c.loadPolicy()
}

func (c *casbinEngine) initEnforcer() {
	c.enforcerMu.RLock()
	if c.enforcerInitialized {
		c.enforcerMu.RUnlock()

		return
	}
	c.enforcerMu.RUnlock()

	c.enforcerMu.Lock()
	defer c.enforcerMu.Unlock()

	if c.enforcerInitialized {
		// lost race for lock
		return
	}
	// won race for lock

	a, err := c.adapter.NewAdapter()
	if err != nil {
		panic(errors.Wrapf(err, "pgxadapter.NewAdapter(): failed to create casbin adapter with db"))
	}

	c.enforcer.SetAdapter(a)

	c.enforcerInitialized = true
}

func (c *casbinEngine) loadPolicy() casbin.IEnforcer {
	c.policyMu.RLock()
	if c.policyLoaded {
		defer c.policyMu.RUnlock()

		return c.enforcer
	}
	c.policyMu.RUnlock()

	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	if c.policyLoaded {
		return c.enforcer
	}

	if err := c.enforcer.LoadPolicy(); err != nil {
		panic(errors.Wrapf(err, "casbin.SyncedEnforcer.LoadPolicy()"))
	}

	c.policyLoaded = true

	go func() {
		time.Sleep(time.Minute)
		c.policyMu.Lock()
		c.policyLoaded = false
		c.policyMu.Unlock()
	}()

	return c.enforcer
}

func (c *casbinEngine) checkUser(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) ([]accesstypes.Resource, error) {
	return c.check(ctx, user.Marshal(), domain, perm, resources...)
}

func (c *casbinEngine) checkRole(ctx context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) ([]accesstypes.Resource, error) {
	return c.check(ctx, role.Marshal(), domain, perm, resources...)
}

func (c *casbinEngine) check(_ context.Context, subject string, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) ([]accesstypes.Resource, error) {
	missing := make([]accesstypes.Resource, 0)
	for _, resource := range resources {
		authorized, err := c.Enforcer().Enforce(subject, domain.Marshal(), resource.Marshal(), perm.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "casbin.IEnforcer Enforce()")
		}
		if !authorized {
			missing = append(missing, resource)
		}
	}

	return missing, nil
}

func (c *casbinEngine) addUserRole(_ context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error {
	if _, err := c.Enforcer().AddRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrapf(err, "casbin.SyncedEnforcer.AddRoleForUser(): role %q to %q", role.Marshal(), user)
	}

	return nil
}

func (c *casbinEngine) deleteUserRole(_ context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error {
	if _, err := c.Enforcer().DeleteRoleForUser(user.Marshal(), role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrapf(err, "casbin.SyncedEnforcer.DeleteRoleForUser(): role %q to %q", role.Marshal(), user)
	}

	return nil
}

func (c *casbinEngine) users(_ context.Context) ([]accesstypes.User, error) {
	var users []accesstypes.User
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
	for _, user := range subjects {
		for _, role := range roles {
			if role == user || user == accesstypes.NoopUser {
				continue SUB
			}
		}

		users = append(users, accesstypes.UnmarshalUser(user))
		userMap[user] = true
	}
	// now get the grouping policy and look for users in there
	groupingPolicy, err := c.Enforcer().GetGroupingPolicy()
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

		users = append(users, accesstypes.UnmarshalUser(user))
		userMap[user] = true
	}

	return users, nil
}

func (c *casbinEngine) userRoles(_ context.Context, domain accesstypes.Domain, user accesstypes.User) ([]accesstypes.Role, error) {
	strRoles, err := c.Enforcer().GetRolesForUser(user.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrapf(err, "casbin.SyncedEnforcer.GetRolesForUser(): user: %q", user)
	}

	roles := make([]accesstypes.Role, 0, len(strRoles))
	for _, role := range strRoles {
		roles = append(roles, accesstypes.UnmarshalRole(role))
	}

	return roles, nil
}

func (c *casbinEngine) userPermissions(_ context.Context, domain accesstypes.Domain, user accesstypes.User) (map[accesstypes.Resource][]accesstypes.Permission, error) {
	strPerms, err := c.Enforcer().GetImplicitPermissionsForUser(user.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetImplicitPermissionsForUser()")
	}

	permissions := make(map[accesstypes.Resource][]accesstypes.Permission)
	for _, perm := range strPerms {
		if slices.Contains(permissions[accesstypes.UnmarshalResource(perm[2])], accesstypes.UnmarshalPermission(perm[3])) {
			continue
		}
		permissions[accesstypes.UnmarshalResource(perm[2])] = append(permissions[accesstypes.UnmarshalResource(perm[2])], accesstypes.UnmarshalPermission(perm[3]))
	}

	return permissions, nil
}

func (c *casbinEngine) addRole(_ context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	if _, err := c.Enforcer().AddGroupingPolicy(accesstypes.NoopUser, role.Marshal(), domain.Marshal()); err != nil {
		return errors.Wrap(err, "enforcer.AddGroupingPolicy()")
	}

	return nil
}

func (c *casbinEngine) roles(_ context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	// filter by domain
	grouping, err := c.Enforcer().GetFilteredGroupingPolicy(2, domain.Marshal())
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

func (c *casbinEngine) deleteRole(_ context.Context, role accesstypes.Role) (bool, error) {
	deleted, err := c.Enforcer().DeleteRole(role.Marshal())
	if err != nil {
		return false, errors.Wrap(err, "enforcer.DeleteRole()")
	}

	return deleted, nil
}

func (c *casbinEngine) roleExists(_ context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	roles := c.Enforcer().GetRolesForUserInDomain(accesstypes.NoopUser, domain.Marshal())

	return slices.Contains(roles, role.Marshal())
}

func (c *casbinEngine) roleUsers(_ context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	users, err := c.Enforcer().GetUsersForRole(role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetUsersForRole()")
	}

	actualUsers := make([]accesstypes.User, 0, len(users))
	for _, user := range users {
		if user == accesstypes.NoopUser {
			continue
		}
		actualUsers = append(actualUsers, accesstypes.UnmarshalUser(user))
	}

	return actualUsers, nil
}

func (c *casbinEngine) addGrant(_ context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error {
	if _, err := c.Enforcer().AddPolicy(role.Marshal(), domain.Marshal(), resource.Marshal(), perm.Marshal(), "allow"); err != nil {
		return errors.Wrap(err, "enforcer.AddPolicy()")
	}

	return nil
}

func (c *casbinEngine) removeGrant(_ context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error {
	if _, err := c.Enforcer().RemoveFilteredPolicy(0, role.Marshal(), domain.Marshal(), resource.Marshal(), perm.Marshal()); err != nil {
		return errors.Wrapf(err, "enforcer.RemoveFilteredPolicy() role=%q, domain=%q", role, domain)
	}

	return nil
}

func (c *casbinEngine) roleGrants(_ context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	policies, err := c.Enforcer().GetFilteredPolicy(0, role.Marshal(), domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "enforcer.GetFilteredPolicy()")
	}

	permissions := make(accesstypes.RolePermissionCollection, len(policies))
	for _, p := range policies {
		permissions[accesstypes.UnmarshalPermission(p[3])] = append(permissions[accesstypes.UnmarshalPermission(p[3])], accesstypes.UnmarshalResource(p[2]))
	}

	return permissions, nil
}
