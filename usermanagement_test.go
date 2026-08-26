package access

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// seededManager returns a userManager over a fresh fake store, pre-seeded
// with roles, grants, and memberships through the manager's own write path.
func seededManager(t *testing.T) (*userManager, *fakeStore) {
	t.Helper()
	ctx := context.Background()

	store := newFakeStore()
	m := newUserManager(newStoreManager(store))

	for _, seed := range []struct {
		scope accesstypes.Scope
		role  accesstypes.Role
	}{
		{tenant1Scope, "Editor"},
		{tenant1Scope, "Viewer"},
		{tenant2Scope, "Viewer"},
		{accesstypes.GlobalScope(), "Auditor"},
	} {
		if err := m.AddRole(ctx, seed.scope, seed.role); err != nil {
			t.Fatalf("AddRole(%q, %q) error = %v", seed.scope, seed.role, err)
		}
	}
	if err := m.AddRolePermissionResources(ctx, tenant1Scope, "Editor", "Read", "employees", "employees.name"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := m.AddRolePermission(ctx, accesstypes.GlobalScope(), "Auditor", "ViewUsers"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := m.AddRoleUsers(ctx, tenant1Scope, "Editor", "alice"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}
	if err := m.AddUserRoles(ctx, tenant2Scope, "alice", "Viewer"); err != nil {
		t.Fatalf("AddUserRoles() error = %v", err)
	}

	return m, store
}

func Test_userManager_membership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		op      func(ctx context.Context, m *userManager) error
		wantErr bool
		// verify runs after a successful op.
		verify func(ctx context.Context, t *testing.T, m *userManager)
	}{
		{
			name: "AddRoleUsers assigns members",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Scope, "Editor", "bob", "carol")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				users, err := m.RoleUsers(ctx, tenant1Scope, "Editor")
				if err != nil {
					t.Fatalf("RoleUsers() error = %v", err)
				}
				if diff := cmp.Diff([]accesstypes.User{"alice", "bob", "carol"}, users); diff != "" {
					t.Errorf("RoleUsers() (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "AddRoleUsers rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Scope, "Ghost", "bob")
			},
			wantErr: true,
		},
		{
			name: "AddRoleUsers is scope-scoped on role existence",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant2Scope, "Editor", "bob") // Editor exists only in tenant1
			},
			wantErr: true,
		},
		{
			name: "AddRoleUsers rejects empty user",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Scope, "Editor", "")
			},
			wantErr: true,
		},
		{
			name: "AddUserRoles assigns roles",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, tenant1Scope, "bob", "Editor", "Viewer")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				roles, err := m.UserRoles(ctx, "bob", tenant1Scope)
				if err != nil {
					t.Fatalf("UserRoles() error = %v", err)
				}
				want := accesstypes.RoleCollection{tenant1Scope: {"Editor", "Viewer"}}
				if diff := cmp.Diff(want, roles); diff != "" {
					t.Errorf("UserRoles() (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "AddUserRoles rejects any missing role before writing",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, tenant1Scope, "bob", "Editor", "Ghost")
			},
			wantErr: true,
		},
		{
			name: "AddUserRoles rejects empty user",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, tenant1Scope, "", "Editor")
			},
			wantErr: true,
		},
		{
			name: "DeleteRoleUsers removes membership",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRoleUsers(ctx, tenant1Scope, "Editor", "alice")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				users, err := m.RoleUsers(ctx, tenant1Scope, "Editor")
				if err != nil {
					t.Fatalf("RoleUsers() error = %v", err)
				}
				if len(users) != 0 {
					t.Errorf("RoleUsers() = %v, want empty", users)
				}
			},
		},
		{
			name: "DeleteRoleUsers rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRoleUsers(ctx, tenant1Scope, "Ghost", "alice")
			},
			wantErr: true,
		},
		{
			name: "DeleteUserRoles succeeds for roles never held",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteUserRoles(ctx, tenant1Scope, "alice", "Viewer")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				roles, err := m.UserRoles(ctx, "alice", tenant1Scope)
				if err != nil {
					t.Fatalf("UserRoles() error = %v", err)
				}
				want := accesstypes.RoleCollection{tenant1Scope: {"Editor"}}
				if diff := cmp.Diff(want, roles); diff != "" {
					t.Errorf("UserRoles() (-want +got):\n%s", diff)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, _ := seededManager(t)

			err := tt.op(ctx, m)
			if (err != nil) != tt.wantErr {
				t.Fatalf("op error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.verify != nil {
				tt.verify(ctx, t, m)
			}
		})
	}
}

func Test_userManager_UserRoles_UserPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		user      accesstypes.User
		scopes    []accesstypes.Scope
		wantErr   bool
		wantRoles accesstypes.RoleCollection
		wantPerms accesstypes.UserPermissionCollection
	}{
		{
			name:   "multi-scope collection",
			user:   "alice",
			scopes: []accesstypes.Scope{tenant1Scope, tenant2Scope},
			wantRoles: accesstypes.RoleCollection{
				tenant1Scope: {"Editor"},
				tenant2Scope: {"Viewer"},
			},
			wantPerms: accesstypes.UserPermissionCollection{
				tenant1Scope: {Resources: map[accesstypes.Resource][]accesstypes.Permission{"employees": {"Read"}, "employees.name": {"Read"}}},
				tenant2Scope: {Resources: map[accesstypes.Resource][]accesstypes.Permission{}},
			},
		},
		{
			name:   "unknown tenant yields empty entries",
			user:   "alice",
			scopes: []accesstypes.Scope{accesstypes.DomainScope("no-such-tenant")},
			wantRoles: accesstypes.RoleCollection{
				accesstypes.DomainScope("no-such-tenant"): {},
			},
			wantPerms: accesstypes.UserPermissionCollection{
				accesstypes.DomainScope("no-such-tenant"): {Resources: map[accesstypes.Resource][]accesstypes.Permission{}},
			},
		},
		{
			name:    "no scopes is an error",
			user:    "alice",
			scopes:  nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, _ := seededManager(t)

			roles, err := m.UserRoles(ctx, tt.user, tt.scopes...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UserRoles() error = %v, wantErr %v", err, tt.wantErr)
			}
			perms, err := m.UserPermissions(ctx, tt.user, tt.scopes...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UserPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.wantRoles, roles); diff != "" {
				t.Errorf("UserRoles() (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPerms, perms); diff != "" {
				t.Errorf("UserPermissions() (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_userManager_roles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		op      func(ctx context.Context, m *userManager) error
		wantErr bool
		verify  func(ctx context.Context, t *testing.T, m *userManager)
	}{
		{
			name: "AddRole creates the role in its domain only",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRole(ctx, tenant2Scope, "Editor")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				for scope, want := range map[accesstypes.Scope][]accesstypes.Role{
					tenant1Scope: {"Editor", "Viewer"},
					tenant2Scope: {"Editor", "Viewer"},
				} {
					roles, err := m.Roles(ctx, scope)
					if err != nil {
						t.Fatalf("Roles(%q) error = %v", scope, err)
					}
					if diff := cmp.Diff(want, roles); diff != "" {
						t.Errorf("Roles(%q) (-want +got):\n%s", scope, diff)
					}
				}
			},
		},
		{
			name: "AddRole rejects duplicates",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRole(ctx, tenant1Scope, "Editor")
			},
			wantErr: true,
		},
		{
			name: "AddRole rejects empty role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRole(ctx, tenant1Scope, "")
			},
			wantErr: true,
		},
		{
			name: "DeleteRole refuses while users are assigned",
			op: func(ctx context.Context, m *userManager) error {
				_, err := m.DeleteRole(ctx, tenant1Scope, "Editor")

				return err
			},
			wantErr: true,
		},
		{
			name: "DeleteRole removes an unassigned role and its grants, scoped to the domain",
			op: func(ctx context.Context, m *userManager) error {
				if err := m.DeleteRoleUsers(ctx, tenant1Scope, "Editor", "alice"); err != nil {
					return err
				}
				deleted, err := m.DeleteRole(ctx, tenant1Scope, "Editor")
				if err != nil {
					return err
				}
				if !deleted {
					return errors.New("DeleteRole() reported nothing deleted")
				}

				return nil
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				exists, err := m.RoleExists(ctx, tenant1Scope, "Editor")
				if err != nil || exists {
					t.Errorf("RoleExists() after delete = (%v, %v), want (false, nil)", exists, err)
				}
				// Viewer in tenant2 is untouched (delete is domain-scoped).
				if exists, err := m.RoleExists(ctx, tenant2Scope, "Viewer"); err != nil || !exists {
					t.Errorf("RoleExists(tenant2, Viewer) = (%v, %v), want (true, nil)", exists, err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, _ := seededManager(t)

			err := tt.op(ctx, m)
			if (err != nil) != tt.wantErr {
				t.Fatalf("op error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.verify != nil {
				tt.verify(ctx, t, m)
			}
		})
	}
}

func Test_userManager_permissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		op      func(ctx context.Context, m *userManager) error
		wantErr bool
		// wantPerms, when set, is compared against RolePermissions for the
		// (scope, role) below after a successful op.
		scope     accesstypes.Scope
		role      accesstypes.Role
		wantPerms accesstypes.RolePermissionCollection
	}{
		{
			// A scope-wide permission is a resource-less grant through the
			// dedicated method — there is no resource value that means it.
			name: "scope-wide permission via AddRolePermission",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermission(ctx, tenant1Scope, "Viewer", "ViewReports")
			},
			scope: tenant1Scope,
			role:  "Viewer",
			wantPerms: accesstypes.RolePermissionCollection{
				"ViewReports": {ScopeWide: true},
			},
		},
		{
			name: "AddRolePermission rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermission(ctx, tenant1Scope, "Ghost", "ViewReports")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources adds resource and field grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, tenant1Scope, "Viewer", "Read", "widgets", "widgets.*")
			},
			scope: tenant1Scope,
			role:  "Viewer",
			wantPerms: accesstypes.RolePermissionCollection{
				"Read": {Resources: []accesstypes.Resource{"widgets", "widgets.*"}},
			},
		},
		{
			name: "AddRolePermissionResources rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, tenant1Scope, "Ghost", "Read", "widgets")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources rejects empty resource",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, tenant1Scope, "Viewer", "Read", "")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources enforces the dot invariant",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, tenant1Scope, "Viewer", "Read", "a.b.c")
			},
			wantErr: true,
		},
		{
			name: "DeleteRolePermissionResources removes grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermissionResources(ctx, tenant1Scope, "Editor", "Read", "employees.name")
			},
			scope: tenant1Scope,
			role:  "Editor",
			wantPerms: accesstypes.RolePermissionCollection{
				"Read": {Resources: []accesstypes.Resource{"employees"}},
			},
		},
		{
			name: "DeleteRolePermission removes the scope-wide permission",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermission(ctx, accesstypes.GlobalScope(), "Auditor", "ViewUsers")
			},
			scope:     accesstypes.GlobalScope(),
			role:      "Auditor",
			wantPerms: accesstypes.RolePermissionCollection{},
		},
		{
			name: "DeleteAllRolePermissions clears scope-wide grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteAllRolePermissions(ctx, accesstypes.GlobalScope(), "Auditor")
			},
			scope:     accesstypes.GlobalScope(),
			role:      "Auditor",
			wantPerms: accesstypes.RolePermissionCollection{},
		},
		{
			// Regression: the casbin-era implementation only removed each
			// permission's global-resource grant, contradicting the method's
			// contract — resource and field grants silently survived.
			name: "DeleteAllRolePermissions clears resource-specific grants too",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteAllRolePermissions(ctx, tenant1Scope, "Editor")
			},
			scope:     tenant1Scope,
			role:      "Editor",
			wantPerms: accesstypes.RolePermissionCollection{},
		},
		{
			name: "DeleteRolePermissionResources rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermissionResources(ctx, tenant1Scope, "Ghost", "Read", "employees")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, _ := seededManager(t)

			err := tt.op(ctx, m)
			if (err != nil) != tt.wantErr {
				t.Fatalf("op error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil || tt.wantPerms == nil {
				return
			}
			got, err := m.RolePermissions(ctx, tt.scope, tt.role)
			if err != nil {
				t.Fatalf("RolePermissions() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantPerms, got); diff != "" {
				t.Errorf("RolePermissions() (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_userManager_RolePermissions_missingRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	m, _ := seededManager(t)
	if _, err := m.RolePermissions(ctx, tenant1Scope, "Ghost"); err == nil {
		t.Fatal("RolePermissions() expected error for missing role, got nil")
	}
}

// Test_userManager_storeErrorsPropagate pins the honest error path: a store
// failure surfaces as an error instead of reading as "role missing".
func Test_userManager_storeErrorsPropagate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	m, store := seededManager(t)
	store.setFail(errors.New("store down"))

	if _, err := m.RoleExists(ctx, tenant1Scope, "Editor"); err == nil {
		t.Error("RoleExists() expected error, got nil")
	}
	if err := m.AddRoleUsers(ctx, tenant1Scope, "Editor", "bob"); err == nil {
		t.Error("AddRoleUsers() expected error, got nil")
	}
	if _, err := m.UserRoles(ctx, "alice", tenant1Scope); err == nil {
		t.Error("UserRoles() expected error, got nil")
	}
}
