package access

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

var _ Store = (*fakeStore)(nil)

type fakeRoleKey struct {
	scope accesstypes.Scope
	role  accesstypes.Role
}

type fakeMembership struct {
	scope accesstypes.Scope
	user  accesstypes.User
	role  accesstypes.Role
}

type fakeGrant struct {
	scope     accesstypes.Scope
	role      accesstypes.Role
	perm      accesstypes.Permission
	resource  string
	field     string
	condition string
}

// fakeStore is an in-memory Store honoring the documented contract: idempotent
// inserts, no-op deletes of absent rows, FK-style enforcement of the role
// parent, member-blocked cascade-granted role deletes, and sorted listings.
// A grant's condition is part of the grant row's identity, matching the
// stores' contract.
type fakeStore struct {
	mu          sync.Mutex
	roles       map[fakeRoleKey]bool
	memberships map[fakeMembership]bool
	grants      map[fakeGrant]bool

	// failWith, when set, makes every method return this error.
	failWith error
}

// setFail makes every subsequent method call return err (nil restores
// normal operation). Safe to call concurrently with engine goroutines.
func (f *fakeStore) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = err
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		roles:       make(map[fakeRoleKey]bool),
		memberships: make(map[fakeMembership]bool),
		grants:      make(map[fakeGrant]bool),
	}
}

func (f *fakeStore) ReadPolicy(_ context.Context) (*policy.Records, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}

	records := &policy.Records{}
	for g := range f.grants {
		records.Grants = append(records.Grants, policy.Grant{
			Scope:     g.scope,
			Subject:   policy.Subject{Kind: policy.SubjectRole, Name: string(g.role)},
			Perm:      g.perm,
			Resource:  g.resource,
			Field:     g.field,
			Condition: g.condition,
		})
	}
	for m := range f.memberships {
		records.Memberships = append(records.Memberships, policy.Membership{
			Scope:  m.scope,
			Member: policy.Subject{Kind: policy.SubjectUser, Name: string(m.user)},
			Role:   m.role,
		})
	}

	return records, nil
}

func (f *fakeStore) InsertUserRole(_ context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	if !f.roles[fakeRoleKey{scope, role}] {
		return errors.Newf("role %q does not exist in scope %q", role, scope)
	}
	f.memberships[fakeMembership{scope, user, role}] = true

	return nil
}

func (f *fakeStore) DeleteUserRole(_ context.Context, scope accesstypes.Scope, user accesstypes.User, role accesstypes.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	delete(f.memberships, fakeMembership{scope, user, role})

	return nil
}

func (f *fakeStore) ListUserRoles(_ context.Context, scope accesstypes.Scope, user accesstypes.User) ([]accesstypes.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	roles := make([]accesstypes.Role, 0)
	for m := range f.memberships {
		if m.scope == scope && m.user == user {
			roles = append(roles, m.role)
		}
	}
	slices.Sort(roles)

	return roles, nil
}

func (f *fakeStore) ListRoleUsers(_ context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]accesstypes.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	users := make([]accesstypes.User, 0)
	for m := range f.memberships {
		if m.scope == scope && m.role == role {
			users = append(users, m.user)
		}
	}
	slices.Sort(users)

	return users, nil
}

func (f *fakeStore) InsertRole(_ context.Context, scope accesstypes.Scope, role accesstypes.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	f.roles[fakeRoleKey{scope, role}] = true

	return nil
}

func (f *fakeStore) ListRoles(_ context.Context, scope accesstypes.Scope) ([]accesstypes.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	roles := make([]accesstypes.Role, 0)
	for k := range f.roles {
		if k.scope == scope {
			roles = append(roles, k.role)
		}
	}
	slices.Sort(roles)

	return roles, nil
}

func (f *fakeStore) DeleteRole(_ context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return false, f.failWith
	}
	if !f.roles[fakeRoleKey{scope, role}] {
		return false, nil
	}
	for m := range f.memberships {
		if m.scope == scope && m.role == role {
			return false, errors.Newf("role %q in scope %q still has members", role, scope)
		}
	}
	delete(f.roles, fakeRoleKey{scope, role})
	for g := range f.grants {
		if g.scope == scope && g.role == role {
			delete(f.grants, g)
		}
	}

	return true, nil
}

func (f *fakeStore) RoleExists(_ context.Context, scope accesstypes.Scope, role accesstypes.Role) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return false, f.failWith
	}

	return f.roles[fakeRoleKey{scope, role}], nil
}

func (f *fakeStore) InsertGrant(_ context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	if !f.roles[fakeRoleKey{scope, role}] {
		return errors.Newf("role %q does not exist in scope %q", role, scope)
	}
	f.grants[fakeGrant{scope, role, perm, resource, field, condition}] = true

	return nil
}

func (f *fakeStore) DeleteGrant(_ context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field, condition string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	delete(f.grants, fakeGrant{scope, role, perm, resource, field, condition})

	return nil
}

func (f *fakeStore) DeleteGrants(_ context.Context, scope accesstypes.Scope, role accesstypes.Role, perm accesstypes.Permission, resource, field string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	for g := range f.grants {
		if g.scope == scope && g.role == role && g.perm == perm && g.resource == resource && g.field == field {
			delete(f.grants, g)
		}
	}

	return nil
}

func (f *fakeStore) ListRoleGrants(_ context.Context, scope accesstypes.Scope, role accesstypes.Role) ([]policy.RoleGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	grants := make([]policy.RoleGrant, 0)
	for g := range f.grants {
		if g.scope == scope && g.role == role {
			grants = append(grants, policy.RoleGrant{Perm: g.perm, Resource: g.resource, Field: g.field, Condition: g.condition})
		}
	}
	slices.SortFunc(grants, func(a, b policy.RoleGrant) int {
		if c := strings.Compare(string(a.Perm), string(b.Perm)); c != 0 {
			return c
		}
		if c := strings.Compare(a.Resource, b.Resource); c != 0 {
			return c
		}
		if c := strings.Compare(a.Field, b.Field); c != 0 {
			return c
		}

		return strings.Compare(a.Condition, b.Condition)
	})

	return grants, nil
}
