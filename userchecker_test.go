package access

import (
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

// TestClient_ForUser pins the user-context seam: ForUser binds exactly the
// user, and Check is a pure delegate to CheckUserResources — the same grants
// answer both, from the bound user's point of view.
func TestClient_ForUser(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	client, err := New(newFakeStore())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Client.Close() error = %v", err)
		}
	})

	tenant1 := accesstypes.DomainScope("tenant1")
	manager := client.UserManager()
	if err := manager.AddRole(ctx, tenant1, "Editor"); err != nil {
		t.Fatalf("AddRole() error = %v", err)
	}
	if err := manager.AddRolePermissionResources(ctx, tenant1, "Editor", "Read", "employees"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := manager.AddRoleUsers(ctx, tenant1, "Editor", "erin"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}

	tests := []struct {
		name      string
		user      accesstypes.User
		perm      accesstypes.Permission
		resources []accesstypes.Resource
		want      accesstypes.Decisions
	}{
		{
			name:      "bound user's grant is granted",
			user:      "erin",
			perm:      "Read",
			resources: []accesstypes.Resource{"employees"},
			want:      accesstypes.Decisions{"employees": accesstypes.Granted()},
		},
		{
			name:      "unheld permission fails closed to denied",
			user:      "erin",
			perm:      "Delete",
			resources: []accesstypes.Resource{"employees"},
			want:      accesstypes.Decisions{"employees": accesstypes.Denied()},
		},
		{
			name:      "unknown bound user fails closed to denied",
			user:      "sam",
			perm:      "Read",
			resources: []accesstypes.Resource{"employees"},
			want:      accesstypes.Decisions{"employees": accesstypes.Denied()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := client.ForUser(tt.user)
			if got := checker.User(); got != tt.user {
				t.Errorf("UserChecker.User() = %v, want %v", got, tt.user)
			}

			got, err := checker.Check(t.Context(), accesstypes.NewEnvironment(), tenant1, tt.perm, tt.resources...)
			if err != nil {
				t.Fatalf("UserChecker.Check() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
				t.Errorf("UserChecker.Check() (-want +got):\n%s", diff)
			}
		})
	}
}
