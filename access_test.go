package access

import (
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{name: "new"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(newFakeStore())
			if err != nil {
				t.Error(err)
			}
			t.Cleanup(func() {
				if err := got.Close(); err != nil {
					t.Errorf("Client.Close() error = %v", err)
				}
			})

			if got.userManager == nil {
				t.Error("userManager is nil")
			}
		})
	}
}

// TestClient_CheckUser_unknownDomainFailsClosed pins the Domains decoupling:
// there is no domain validation on the check path — an unknown domain holds
// no grants, so everything comes back missing, without an error.
func TestClient_CheckUser_unknownDomainFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	store := newFakeStore()
	client, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Client.Close() error = %v", err)
		}
	})

	manager := client.UserManager()
	if err := manager.AddRole(ctx, "tenant1", "Editor"); err != nil {
		t.Fatalf("AddRole() error = %v", err)
	}
	if err := manager.AddRolePermissionResources(ctx, "tenant1", "Editor", "Read", "employees"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := manager.AddRoleUsers(ctx, "tenant1", "Editor", "erin"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}

	missing, err := client.CheckUser(ctx, "erin", "tenant1", "Read", "employees")
	if err != nil {
		t.Fatalf("CheckUser() error = %v", err)
	}
	if diff := cmp.Diff([]accesstypes.Resource{}, missing); diff != "" {
		t.Errorf("CheckUser() in known domain (-want +got):\n%s", diff)
	}

	missing, err = client.CheckUser(ctx, "erin", "no-such-tenant", "Read", "employees")
	if err != nil {
		t.Fatalf("CheckUser() unknown domain error = %v, want fail-closed missing, not an error", err)
	}
	if diff := cmp.Diff([]accesstypes.Resource{"employees"}, missing); diff != "" {
		t.Errorf("CheckUser() in unknown domain (-want +got):\n%s", diff)
	}
}
