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

func (m *storeManager) addUserRole(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error {
	if err := m.store.InsertUserRole(ctx, domain, user, role); err != nil {
		return errors.Wrapf(err, "access.Store.InsertUserRole(): role %q to %q", role, user)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) deleteUserRole(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, role accesstypes.Role) error {
	if err := m.store.DeleteUserRole(ctx, domain, user, role); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteUserRole(): role %q from %q", role, user)
	}
	m.notifyPolicyChange()

	return nil
}

// users dies with the cross-domain Users API in the cutover stage: the typed
// stores deliberately have no store-wide user enumeration (it disclosed every
// username across every tenant). Nothing routes here — userManager stays on
// the casbin path until the cutover removes both together.
func (m *storeManager) users(_ context.Context) ([]accesstypes.User, error) {
	return nil, errors.New("access: store-wide user enumeration is not supported by the typed policy store")
}

func (m *storeManager) userRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User) ([]accesstypes.Role, error) {
	roles, err := m.store.ListUserRoles(ctx, domain, user)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListUserRoles(): user %q", user)
	}

	return roles, nil
}

// userPermissions composes the user's effective permissions from membership
// and role grants. The typed stores hold no user-direct grants and no role
// inheritance, so one membership hop is the whole resolution.
func (m *storeManager) userPermissions(ctx context.Context, domain accesstypes.Domain, user accesstypes.User) (map[accesstypes.Resource][]accesstypes.Permission, error) {
	roles, err := m.store.ListUserRoles(ctx, domain, user)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListUserRoles(): user %q", user)
	}

	permissions := make(map[accesstypes.Resource][]accesstypes.Permission)
	for _, role := range roles {
		grants, err := m.store.ListRoleGrants(ctx, domain, role)
		if err != nil {
			return nil, errors.Wrapf(err, "access.Store.ListRoleGrants(): role %q", role)
		}
		for _, g := range grants {
			resource := joinResourceField(g.Resource, g.Field)
			if !slices.Contains(permissions[resource], g.Perm) {
				permissions[resource] = append(permissions[resource], g.Perm)
			}
		}
	}

	return permissions, nil
}

func (m *storeManager) addRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	if err := m.store.InsertRole(ctx, domain, role); err != nil {
		return errors.Wrapf(err, "access.Store.InsertRole(): role %q in domain %q", role, domain)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	roles, err := m.store.ListRoles(ctx, domain)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoles(): domain %q", domain)
	}

	return roles, nil
}

// deleteRole is scoped to (domain, role) — the typed stores fix casbin's
// domain-blind delete. Grants cascade in the store; memberships block the
// delete (DB-enforced), backstopping the caller's has-users guard.
func (m *storeManager) deleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	deleted, err := m.store.DeleteRole(ctx, domain, role)
	if err != nil {
		return false, errors.Wrapf(err, "access.Store.DeleteRole(): role %q in domain %q", role, domain)
	}
	if deleted {
		m.notifyPolicyChange()
	}

	return deleted, nil
}

func (m *storeManager) roleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	exists, err := m.store.RoleExists(ctx, domain, role)
	if err != nil {
		return false, errors.Wrapf(err, "access.Store.RoleExists(): role %q in domain %q", role, domain)
	}

	return exists, nil
}

func (m *storeManager) roleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	users, err := m.store.ListRoleUsers(ctx, domain, role)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoleUsers(): role %q", role)
	}

	return users, nil
}

func (m *storeManager) addGrant(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error {
	base, field, err := splitGrantResource(resource)
	if err != nil {
		return err
	}
	if err := m.store.InsertGrant(ctx, domain, role, perm, base, field); err != nil {
		return errors.Wrapf(err, "access.Store.InsertGrant(): %q on %q for role %q", perm, resource, role)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) removeGrant(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) error {
	base, field, err := splitGrantResource(resource)
	if err != nil {
		return err
	}
	if err := m.store.DeleteGrant(ctx, domain, role, perm, base, field); err != nil {
		return errors.Wrapf(err, "access.Store.DeleteGrant(): %q on %q for role %q", perm, resource, role)
	}
	m.notifyPolicyChange()

	return nil
}

func (m *storeManager) roleGrants(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	grants, err := m.store.ListRoleGrants(ctx, domain, role)
	if err != nil {
		return nil, errors.Wrapf(err, "access.Store.ListRoleGrants(): role %q", role)
	}

	permissions := make(accesstypes.RolePermissionCollection, len(grants))
	for _, g := range grants {
		permissions[g.Perm] = append(permissions[g.Perm], joinResourceField(g.Resource, g.Field))
	}

	return permissions, nil
}

// splitGrantResource splits a declared resource into its stored (base, field)
// columns and enforces the dot invariant, fail-closed at declaration time: a
// Resource has at most one dot — 0 dots is a parent resource, 1 dot is a
// field on a parent — and both segments are non-empty and dot-free. '.' is
// reserved as the structural separator; a resource whose real name contains
// dots must translate at declaration, never be stored ambiguous.
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
