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
		domain accesstypes.Domain
		role   accesstypes.Role
	}{
		{"tenant1", "Editor"},
		{"tenant1", "Viewer"},
		{"tenant2", "Viewer"},
		{accesstypes.GlobalDomain, "Auditor"},
	} {
		if err := m.AddRole(ctx, seed.domain, seed.role); err != nil {
			t.Fatalf("AddRole(%q, %q) error = %v", seed.domain, seed.role, err)
		}
	}
	if err := m.AddRolePermissionResources(ctx, "tenant1", "Editor", "Read", "employees", "employees.name"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := m.AddRolePermissions(ctx, accesstypes.GlobalDomain, "Auditor", "ViewUsers"); err != nil {
		t.Fatalf("AddRolePermissions() error = %v", err)
	}
	if err := m.AddRoleUsers(ctx, "tenant1", "Editor", "alice"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}
	if err := m.AddUserRoles(ctx, "tenant2", "alice", "Viewer"); err != nil {
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
				return m.AddRoleUsers(ctx, "tenant1", "Editor", "bob", "carol")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				users, err := m.RoleUsers(ctx, "tenant1", "Editor")
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
				return m.AddRoleUsers(ctx, "tenant1", "Ghost", "bob")
			},
			wantErr: true,
		},
		{
			name: "AddRoleUsers is domain-scoped on role existence",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, "tenant2", "Editor", "bob") // Editor exists only in tenant1
			},
			wantErr: true,
		},
		{
			name: "AddRoleUsers rejects empty user",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, "tenant1", "Editor", "")
			},
			wantErr: true,
		},
		{
			name: "AddUserRoles assigns roles",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, "tenant1", "bob", "Editor", "Viewer")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				roles, err := m.UserRoles(ctx, "bob", "tenant1")
				if err != nil {
					t.Fatalf("UserRoles() error = %v", err)
				}
				want := accesstypes.RoleCollection{"tenant1": {"Editor", "Viewer"}}
				if diff := cmp.Diff(want, roles); diff != "" {
					t.Errorf("UserRoles() (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "AddUserRoles rejects any missing role before writing",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, "tenant1", "bob", "Editor", "Ghost")
			},
			wantErr: true,
		},
		{
			name: "AddUserRoles rejects empty user",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, "tenant1", "", "Editor")
			},
			wantErr: true,
		},
		{
			name: "DeleteRoleUsers removes membership",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRoleUsers(ctx, "tenant1", "Editor", "alice")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				users, err := m.RoleUsers(ctx, "tenant1", "Editor")
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
				return m.DeleteRoleUsers(ctx, "tenant1", "Ghost", "alice")
			},
			wantErr: true,
		},
		{
			name: "DeleteUserRoles succeeds for roles never held",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteUserRoles(ctx, "tenant1", "alice", "Viewer")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				roles, err := m.UserRoles(ctx, "alice", "tenant1")
				if err != nil {
					t.Fatalf("UserRoles() error = %v", err)
				}
				want := accesstypes.RoleCollection{"tenant1": {"Editor"}}
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
		domains   []accesstypes.Domain
		wantErr   bool
		wantRoles accesstypes.RoleCollection
		wantPerms accesstypes.UserPermissionCollection
	}{
		{
			name:    "multi-domain collection",
			user:    "alice",
			domains: []accesstypes.Domain{"tenant1", "tenant2"},
			wantRoles: accesstypes.RoleCollection{
				"tenant1": {"Editor"},
				"tenant2": {"Viewer"},
			},
			wantPerms: accesstypes.UserPermissionCollection{
				"tenant1": {"employees": {"Read"}, "employees.name": {"Read"}},
				"tenant2": {},
			},
		},
		{
			name:    "unknown domain yields empty entries",
			user:    "alice",
			domains: []accesstypes.Domain{"no-such-tenant"},
			wantRoles: accesstypes.RoleCollection{
				"no-such-tenant": {},
			},
			wantPerms: accesstypes.UserPermissionCollection{
				"no-such-tenant": {},
			},
		},
		{
			name:    "no domains is an error",
			user:    "alice",
			domains: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m, _ := seededManager(t)

			roles, err := m.UserRoles(ctx, tt.user, tt.domains...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UserRoles() error = %v, wantErr %v", err, tt.wantErr)
			}
			perms, err := m.UserPermissions(ctx, tt.user, tt.domains...)
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
				return m.AddRole(ctx, "tenant2", "Editor")
			},
			verify: func(ctx context.Context, t *testing.T, m *userManager) {
				t.Helper()
				for domain, want := range map[accesstypes.Domain][]accesstypes.Role{
					"tenant1": {"Editor", "Viewer"},
					"tenant2": {"Editor", "Viewer"},
				} {
					roles, err := m.Roles(ctx, domain)
					if err != nil {
						t.Fatalf("Roles(%q) error = %v", domain, err)
					}
					if diff := cmp.Diff(want, roles); diff != "" {
						t.Errorf("Roles(%q) (-want +got):\n%s", domain, diff)
					}
				}
			},
		},
		{
			name: "AddRole rejects duplicates",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRole(ctx, "tenant1", "Editor")
			},
			wantErr: true,
		},
		{
			name: "AddRole rejects empty role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRole(ctx, "tenant1", "")
			},
			wantErr: true,
		},
		{
			name: "DeleteRole refuses while users are assigned",
			op: func(ctx context.Context, m *userManager) error {
				_, err := m.DeleteRole(ctx, "tenant1", "Editor")

				return err
			},
			wantErr: true,
		},
		{
			name: "DeleteRole removes an unassigned role and its grants, scoped to the domain",
			op: func(ctx context.Context, m *userManager) error {
				if err := m.DeleteRoleUsers(ctx, "tenant1", "Editor", "alice"); err != nil {
					return err
				}
				deleted, err := m.DeleteRole(ctx, "tenant1", "Editor")
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
				exists, err := m.RoleExists(ctx, "tenant1", "Editor")
				if err != nil || exists {
					t.Errorf("RoleExists() after delete = (%v, %v), want (false, nil)", exists, err)
				}
				// Viewer in tenant2 is untouched (delete is domain-scoped).
				if exists, err := m.RoleExists(ctx, "tenant2", "Viewer"); err != nil || !exists {
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
		// (domain, role) below after a successful op.
		domain    accesstypes.Domain
		role      accesstypes.Role
		wantPerms accesstypes.RolePermissionCollection
	}{
		{
			name: "AddRolePermissions writes global-resource grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissions(ctx, "tenant1", "Viewer", "ViewReports")
			},
			domain: "tenant1",
			role:   "Viewer",
			wantPerms: accesstypes.RolePermissionCollection{
				"ViewReports": {accesstypes.GlobalResource},
			},
		},
		{
			name: "AddRolePermissions rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissions(ctx, "tenant1", "Ghost", "ViewReports")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissions rejects empty permission",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissions(ctx, "tenant1", "Viewer", "")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources adds resource and field grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, "tenant1", "Viewer", "Read", "widgets", "widgets.*")
			},
			domain: "tenant1",
			role:   "Viewer",
			wantPerms: accesstypes.RolePermissionCollection{
				"Read": {"widgets", "widgets.*"},
			},
		},
		{
			name: "AddRolePermissionResources rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, "tenant1", "Ghost", "Read", "widgets")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources rejects empty resource",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, "tenant1", "Viewer", "Read", "")
			},
			wantErr: true,
		},
		{
			name: "AddRolePermissionResources enforces the dot invariant",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRolePermissionResources(ctx, "tenant1", "Viewer", "Read", "a.b.c")
			},
			wantErr: true,
		},
		{
			name: "DeleteRolePermissionResources removes grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermissionResources(ctx, "tenant1", "Editor", "Read", "employees.name")
			},
			domain: "tenant1",
			role:   "Editor",
			wantPerms: accesstypes.RolePermissionCollection{
				"Read": {"employees"},
			},
		},
		{
			name: "DeleteRolePermissions removes global grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermissions(ctx, accesstypes.GlobalDomain, "Auditor", "ViewUsers")
			},
			domain:    accesstypes.GlobalDomain,
			role:      "Auditor",
			wantPerms: accesstypes.RolePermissionCollection{},
		},
		{
			// DeleteAllRolePermissions clears each permission's GLOBAL-resource
			// grant only — preserved casbin-era behavior: it feeds
			// DeleteRolePermissions, which targets accesstypes.GlobalResource.
			name: "DeleteAllRolePermissions clears global-resource grants",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteAllRolePermissions(ctx, accesstypes.GlobalDomain, "Auditor")
			},
			domain:    accesstypes.GlobalDomain,
			role:      "Auditor",
			wantPerms: accesstypes.RolePermissionCollection{},
		},
		{
			name: "DeleteAllRolePermissions leaves resource-specific grants (preserved casbin-era behavior)",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteAllRolePermissions(ctx, "tenant1", "Editor")
			},
			domain: "tenant1",
			role:   "Editor",
			wantPerms: accesstypes.RolePermissionCollection{
				"Read": {"employees", "employees.name"},
			},
		},
		{
			name: "DeleteRolePermissions rejects missing role",
			op: func(ctx context.Context, m *userManager) error {
				return m.DeleteRolePermissions(ctx, "tenant1", "Ghost", "Read")
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
			got, err := m.RolePermissions(ctx, tt.domain, tt.role)
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
	if _, err := m.RolePermissions(ctx, "tenant1", "Ghost"); err == nil {
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

	if _, err := m.RoleExists(ctx, "tenant1", "Editor"); err == nil {
		t.Error("RoleExists() expected error, got nil")
	}
	if err := m.AddRoleUsers(ctx, "tenant1", "Editor", "bob"); err == nil {
		t.Error("AddRoleUsers() expected error, got nil")
	}
	if _, err := m.UserRoles(ctx, "alice", "tenant1"); err == nil {
		t.Error("UserRoles() expected error, got nil")
	}
}
