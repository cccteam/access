package access

import (
	"context"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

func Test_splitGrantResource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  accesstypes.Resource
		wantBase  string
		wantField string
		wantErr   bool
	}{
		{name: "parent resource", resource: "employees", wantBase: "employees", wantField: ""},
		{name: "global resource", resource: accesstypes.GlobalResource, wantBase: string(accesstypes.GlobalResource), wantField: ""},
		{name: "field on parent", resource: "employees.name", wantBase: "employees", wantField: "name"},
		{name: "all-fields wildcard", resource: "employees.*", wantBase: "employees", wantField: "*"},
		{name: "two dots rejected", resource: "a.b.c", wantErr: true},
		{name: "empty parent segment rejected", resource: ".name", wantErr: true},
		{name: "empty field segment rejected", resource: "employees.", wantErr: true},
		{name: "empty resource rejected", resource: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base, field, err := splitGrantResource(tt.resource)
			if (err != nil) != tt.wantErr {
				t.Fatalf("splitGrantResource(%q) error = %v, wantErr %v", tt.resource, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if base != tt.wantBase || field != tt.wantField {
				t.Errorf("splitGrantResource(%q) = (%q, %q), want (%q, %q)", tt.resource, base, field, tt.wantBase, tt.wantField)
			}
		})
	}
}

func Test_storeManager_grants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name       string
		grant      accesstypes.Resource
		wantStored fakeGrant
		wantErr    bool
	}{
		{
			name:       "endpoint grant stores empty field",
			grant:      "employees",
			wantStored: fakeGrant{domain: "tenant1", role: "Editor", perm: "Read", resource: "employees", field: ""},
		},
		{
			name:       "field grant stores split columns",
			grant:      "employees.name",
			wantStored: fakeGrant{domain: "tenant1", role: "Editor", perm: "Read", resource: "employees", field: "name"},
		},
		{
			name:       "wildcard grant stores star field",
			grant:      "employees.*",
			wantStored: fakeGrant{domain: "tenant1", role: "Editor", perm: "Read", resource: "employees", field: "*"},
		},
		{
			name:    "dot invariant rejected at declaration",
			grant:   "a.b.c",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore()
			manager := newStoreManager(store)
			notified := 0
			manager.onPolicyChange = func() { notified++ }

			if err := manager.addRole(ctx, "tenant1", "Editor"); err != nil {
				t.Fatalf("addRole() error = %v", err)
			}

			err := manager.addGrant(ctx, "tenant1", "Editor", "Read", tt.grant)
			if (err != nil) != tt.wantErr {
				t.Fatalf("addGrant() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if notified != 1 { // only the addRole write
					t.Errorf("onPolicyChange fired %d times on a rejected grant, want 1", notified)
				}

				return
			}
			if !store.grants[tt.wantStored] {
				t.Errorf("addGrant(%q) stored %v, want %v", tt.grant, store.grants, tt.wantStored)
			}
			if notified != 2 {
				t.Errorf("onPolicyChange fired %d times, want 2 (addRole + addGrant)", notified)
			}

			if err := manager.removeGrant(ctx, "tenant1", "Editor", "Read", tt.grant); err != nil {
				t.Fatalf("removeGrant() error = %v", err)
			}
			if len(store.grants) != 0 {
				t.Errorf("removeGrant(%q) left grants %v, want none", tt.grant, store.grants)
			}
			if notified != 3 {
				t.Errorf("onPolicyChange fired %d times, want 3", notified)
			}
		})
	}
}

func Test_storeManager_roleGrants_reassembly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := newFakeStore()
	manager := newStoreManager(store)
	if err := manager.addRole(ctx, "tenant1", "Editor"); err != nil {
		t.Fatalf("addRole() error = %v", err)
	}
	for _, resource := range []accesstypes.Resource{"employees", "employees.name", "employees.*", "widgets"} {
		if err := manager.addGrant(ctx, "tenant1", "Editor", "Read", resource); err != nil {
			t.Fatalf("addGrant(%q) error = %v", resource, err)
		}
	}
	if err := manager.addGrant(ctx, "tenant1", "Editor", "Update", "employees"); err != nil {
		t.Fatalf("addGrant() error = %v", err)
	}

	got, err := manager.roleGrants(ctx, "tenant1", "Editor")
	if err != nil {
		t.Fatalf("roleGrants() error = %v", err)
	}
	want := accesstypes.RolePermissionCollection{
		"Read":   {"employees", "employees.*", "employees.name", "widgets"},
		"Update": {"employees"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("roleGrants() mismatch (-want +got):\n%s", diff)
	}
}

func Test_storeManager_userPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name  string
		setup func(t *testing.T, m *storeManager)
		user  accesstypes.User
		want  map[accesstypes.Resource][]accesstypes.Permission
	}{
		{
			name: "permissions merge across roles and dedupe",
			setup: func(t *testing.T, m *storeManager) {
				t.Helper()
				mustAddRole(t, m, "tenant1", "Editor")
				mustAddRole(t, m, "tenant1", "Viewer")
				mustAddGrant(t, m, "Editor", "Read", "employees")
				mustAddGrant(t, m, "Editor", "Update", "employees.name")
				mustAddGrant(t, m, "Viewer", "Read", "employees") // duplicate of Editor's
				mustAddGrant(t, m, "Viewer", "Read", "widgets")
				if err := m.addUserRole(ctx, "tenant1", "alice", "Editor"); err != nil {
					t.Fatal(err)
				}
				if err := m.addUserRole(ctx, "tenant1", "alice", "Viewer"); err != nil {
					t.Fatal(err)
				}
			},
			user: "alice",
			want: map[accesstypes.Resource][]accesstypes.Permission{
				"employees":      {"Read"},
				"employees.name": {"Update"},
				"widgets":        {"Read"},
			},
		},
		{
			name:  "user with no roles has no permissions",
			setup: func(t *testing.T, _ *storeManager) { t.Helper() },
			user:  "nobody",
			want:  map[accesstypes.Resource][]accesstypes.Permission{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager := newStoreManager(newFakeStore())
			tt.setup(t, manager)

			got, err := manager.userPermissions(ctx, "tenant1", tt.user)
			if err != nil {
				t.Fatalf("userPermissions() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("userPermissions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_storeManager_deleteRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name        string
		setup       func(t *testing.T, m *storeManager)
		domain      accesstypes.Domain
		role        accesstypes.Role
		wantDeleted bool
		wantErr     bool
		wantNotify  int
	}{
		{
			name: "delete scoped to domain leaves other domains intact",
			setup: func(t *testing.T, m *storeManager) {
				t.Helper()
				mustAddRole(t, m, "tenant1", "Editor")
				mustAddRole(t, m, "tenant2", "Editor")
				mustAddGrant(t, m, "Editor", "Read", "employees")
			},
			domain:      "tenant1",
			role:        "Editor",
			wantDeleted: true,
			wantNotify:  1,
		},
		{
			name:        "absent role deletes nothing and does not notify",
			setup:       func(t *testing.T, _ *storeManager) { t.Helper() },
			domain:      "tenant1",
			role:        "Ghost",
			wantDeleted: false,
			wantNotify:  0,
		},
		{
			name: "role with members refuses deletion",
			setup: func(t *testing.T, m *storeManager) {
				t.Helper()
				mustAddRole(t, m, "tenant1", "Editor")
				if err := m.addUserRole(ctx, "tenant1", "alice", "Editor"); err != nil {
					t.Fatal(err)
				}
			},
			domain:     "tenant1",
			role:       "Editor",
			wantErr:    true,
			wantNotify: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore()
			manager := newStoreManager(store)
			tt.setup(t, manager)

			notified := 0
			manager.onPolicyChange = func() { notified++ }

			deleted, err := manager.deleteRole(ctx, tt.domain, tt.role)
			if (err != nil) != tt.wantErr {
				t.Fatalf("deleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}
			if deleted != tt.wantDeleted {
				t.Errorf("deleteRole() deleted = %v, want %v", deleted, tt.wantDeleted)
			}
			if notified != tt.wantNotify {
				t.Errorf("onPolicyChange fired %d times, want %d", notified, tt.wantNotify)
			}
			if tt.wantDeleted {
				if exists, err := manager.roleExists(ctx, tt.domain, tt.role); err != nil || exists {
					t.Errorf("roleExists() after delete = (%v, %v), want (false, nil)", exists, err)
				}
				grants, err := manager.roleGrants(ctx, tt.domain, tt.role)
				if err != nil {
					t.Fatalf("roleGrants() error = %v", err)
				}
				if len(grants) != 0 {
					t.Errorf("grants survived role delete: %v", grants)
				}
			}
		})
	}
}

func Test_storeManager_users_unsupported(t *testing.T) {
	t.Parallel()

	manager := newStoreManager(newFakeStore())
	if _, err := manager.users(context.Background()); err == nil {
		t.Fatal("users() expected error, got nil")
	}
}

func mustAddRole(t *testing.T, m *storeManager, domain accesstypes.Domain, role accesstypes.Role) {
	t.Helper()
	if err := m.addRole(context.Background(), domain, role); err != nil {
		t.Fatalf("addRole(%q, %q) error = %v", domain, role, err)
	}
}

func mustAddGrant(t *testing.T, m *storeManager, role accesstypes.Role, perm accesstypes.Permission, resource accesstypes.Resource) {
	t.Helper()
	if err := m.addGrant(context.Background(), "tenant1", role, perm, resource); err != nil {
		t.Fatalf("addGrant(%q, %q, %q) error = %v", role, perm, resource, err)
	}
}
