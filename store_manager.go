package access

import (
	"context"
	"slices"
	"strings"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

var _ policyStore = (*storeManager)(nil)

// storeManager implements the policyStore seam over a typed Store. It is the
// one shared code path between store implementations and the management API:
// it owns resource/field splitting and the dot invariant, composes derived
// queries from the store's primitives, and fires the policy-change signal
// after every successful write.
type storeManager struct {
	store Store

	// onPolicyChange, when set, is called after every successful policy write
	// so the snapshot evaluator can refresh without waiting out the heartbeat.
	onPolicyChange func()
}

func newStoreManager(store Store) *storeManager {
	return &storeManager{store: store}
}

func (m *storeManager) notifyPolicyChange() {
	if m.onPolicyChange != nil {
		m.onPolicyChange()
	}
}

func (m *storeManager) addUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	if err := m.store.InsertUserRole(ctx, scope, user, role); err != nil {
		return errors.Wrapf(err, "access.Store.InsertUserRole(): role %q to %q", role, user)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) deleteUserRole(ctx context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	if err := m.store.DeleteUserRole(ctx, scope, user, role); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteUserRole(): role %q from %q", role, user)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) userRoles(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error) {
	roles, err := m.store.ListUserRoles(ctx, scope, user)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListUserRoles(): user %q", user)
	}

	return roles, nil
}

// userPermissions composes the user's effective permissions from membership
// and role grants. The typed stores hold no user-direct grants and no role
// inheritance, so one membership hop is the whole resolution.
func (m *storeManager) userPermissions(ctx context.Context, scope accesstypes.Scope, user accesstypes.User) (accesstypes.UserScopePermissions, error) {
	roles, err := m.store.ListUserRoles(ctx, scope, user)
	if err != nil {
		return accesstypes.UserScopePermissions{}, errors.Wrapf(err, "access.Store.ListUserRoles(): user %q", user)
	}

	permissions := accesstypes.UserScopePermissions{Resources: make(map[accesstypes.Resource][]accesstypes.Permission)}
	for _, role := range roles {
		grants, err := m.store.ListRoleGrants(ctx, scope, role)
		if err != nil {
			return accesstypes.UserScopePermissions{}, errors.Wrapf(err, "access.Store.ListRoleGrants(): role %q", role)
		}
		for _, g := range grants {
			if g.Resource == "" {
				if !slices.Contains(permissions.ScopeWide, g.Perm) {
					permissions.ScopeWide = append(permissions.ScopeWide, g.Perm)
				}

				continue
			}
			resource := joinResourceField(g.Resource, g.Field)
			if !slices.Contains(permissions.Resources[resource], g.Perm) {
				permissions.Resources[resource] = append(permissions.Resources[resource], g.Perm)
			}
		}
	}

	return permissions, nil
}

func (m *storeManager) addRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	if err := m.store.InsertRole(ctx, scope, role); err != nil {
		return errors.Wrapf(err, "access.Store.InsertRole(): role %q in scope %q", role, scope)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) roles(ctx context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error) {
	roles, err := m.store.ListRoles(ctx, scope)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoles(): scope %q", scope)
	}

	return roles, nil
}

// deleteRole is scoped to (scope, role) — the typed stores fix casbin's
// domain-blind delete. Grants cascade in the store; memberships block the
// delete (DB-enforced), backstopping the caller's has-users guard.
func (m *storeManager) deleteRole(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	deleted, err := m.store.DeleteRole(ctx, scope, role)
	if err != nil {
		return false, errors.Wrapf(err, "access.Store.DeleteRole(): role %q in scope %q", role, scope)
	}
	if deleted {
		m.notifyPolicyChange()
	}

	return deleted, nil
}

func (m *storeManager) roleExists(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	exists, err := m.store.RoleExists(ctx, scope, role)
	if err != nil {
		return false, errors.Wrapf(err, "access.Store.RoleExists(): role %q in scope %q", role, scope)
	}

	return exists, nil
}

func (m *storeManager) roleUsers(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error) {
	users, err := m.store.ListRoleUsers(ctx, scope, role)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoleUsers(): role %q", role)
	}

	return users, nil
}

func (m *storeManager) addGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource, condition string) error {
	base, field, err := splitGrantResource(resource)
	if err != nil {
		return err
	}
	if err := m.store.InsertGrant(ctx, scope, role, perm, base, field, condition); err != nil {
		return errors.Wrapf(err, "access.Store.InsertGrant(): %q on %q for role %q", perm, resource, role)
	}
	m.notifyPolicyChange()

	return nil
}

// removeGrant removes exactly one grant row: the resource's row under the
// given condition ("" = the unconditional row).
func (m *storeManager) removeGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource, condition string) error {
	base, field, err := splitGrantResource(resource)
	if err != nil {
		return err
	}
	if err := m.store.DeleteGrant(ctx, scope, role, perm, base, field, condition); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteGrant(): %q on %q for role %q", perm, resource, role)
	}
	m.notifyPolicyChange()

	return nil
}

// removeGrants removes every grant row on the resource, whatever its
// condition.
func (m *storeManager) removeGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error {
	base, field, err := splitGrantResource(resource)
	if err != nil {
		return err
	}
	if err := m.store.DeleteGrants(ctx, scope, role, perm, base, field); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteGrants(): %q on %q for role %q", perm, resource, role)
	}
	m.notifyPolicyChange()

	return nil
}

// addScopeWideGrant persists a permission attached to no resource: the store
// row carries empty resource and field columns, a spot real resources can
// never occupy (their names are validated non-empty in splitGrantResource).
func (m *storeManager) addScopeWideGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission) error {
	if err := m.store.InsertGrant(ctx, scope, role, perm, "", "", ""); err != nil {
		return errors.Wrapf(err, "access.Store.InsertGrant(): scope-wide %q for role %q", perm, role)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) removeScopeWideGrant(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission) error {
	if err := m.store.DeleteGrant(ctx, scope, role, perm, "", "", ""); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteGrant(): scope-wide %q for role %q", perm, role)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) roleGrants(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	grants, err := m.store.ListRoleGrants(ctx, scope, role)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoleGrants(): role %q", role)
	}

	permissions := make(accesstypes.RolePermissionCollection, len(grants))
	for _, g := range grants {
		pg := permissions[g.Perm]
		if g.Resource == "" {
			pg.ScopeWide = true
		} else {
			pg.Resources = append(pg.Resources, joinResourceField(g.Resource, g.Field))
		}
		permissions[g.Perm] = pg
	}

	return permissions, nil
}

// roleGrantConditions returns the role's resource grants with the conditions
// each resource is granted under (sorted; "" is the unconditional grant),
// keyed by permission; scope-wide grants are structural (no resource) and not
// included.
func (m *storeManager) roleGrantConditions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (map[accesstypes.Permission]map[accesstypes.Resource][]string, error) {
	grants, err := m.store.ListRoleGrants(ctx, scope, role)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoleGrants(): role %q", role)
	}

	out := make(map[accesstypes.Permission]map[accesstypes.Resource][]string)
	for _, g := range grants {
		if g.Resource == "" {
			continue
		}
		if out[g.Perm] == nil {
			out[g.Perm] = make(map[accesstypes.Resource][]string)
		}
		res := joinResourceField(g.Resource, g.Field)
		out[g.Perm][res] = append(out[g.Perm][res], g.Condition)
	}
	for _, resources := range out {
		for _, conditions := range resources {
			slices.Sort(conditions)
		}
	}

	return out, nil
}

// splitGrantResource splits a declared resource into its stored (base, field)
// columns and enforces the dot invariant, fail-closed at declaration time: a
// Resource has at most one dot — 0 dots is a parent resource, 1 dot is a
// field on a parent — and both segments are non-empty and dot-free. '.' is
// reserved as the structural separator. The non-empty rule also keeps the
// stores' empty-resource encoding of scope-wide grants unreachable from data.
//
// A resource whose real name violates the rule must translate at declaration,
// never be stored ambiguous.
func splitGrantResource(resource accesstypes.Resource) (base, field string, err error) {
	s := string(resource)
	base, field = splitResourceField(s)
	switch {
	case base == "":
		return "", "", errors.Newf("invalid resource %q: empty parent segment", s)
	case strings.ContainsRune(base, '.'):
		return "", "", errors.Newf("invalid resource %q: at most one '.' is allowed (parent or parent.field)", s)
	case field == "" && strings.ContainsRune(s, '.'):
		return "", "", errors.Newf("invalid resource %q: empty field segment", s)
	}

	return base, field, nil
}

// joinResourceField reassembles a stored (base, field) pair into the dotted
// resource name the public API speaks.
func joinResourceField(base, field string) accesstypes.Resource {
	if field == "" {
		return accesstypes.Resource(base)
	}

	return accesstypes.Resource(base + "." + field)
}
