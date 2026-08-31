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

// TestClient_CheckUser_returnsDecision pins the ABAC-ready seam translation:
// the RBAC snapshot evaluator answers a bare allow/deny, and the re-signed
// seam surfaces it as a Granted/Denied Decision. Conditional cannot occur
// until the engine holds conditions.
func TestClient_CheckUser_returnsDecision(t *testing.T) {
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
	if err := manager.AddRolePermission(ctx, tenant1, "Editor", "Read"); err != nil {
		t.Fatalf("AddRolePermission() error = %v", err)
	}
	if err := manager.AddRoleUsers(ctx, tenant1, "Editor", "erin"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}

	tests := []struct {
		name string
		user accesstypes.User
		perm accesstypes.Permission
		want accesstypes.Decision
	}{
		{
			name: "scope-wide grant is granted",
			user: "erin",
			perm: "Read",
			want: accesstypes.Granted(),
		},
		{
			name: "unheld permission fails closed to denied",
			user: "erin",
			perm: "Delete",
			want: accesstypes.Denied(),
		},
		{
			name: "unknown user fails closed to denied",
			user: "sam",
			perm: "Read",
			want: accesstypes.Denied(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := client.CheckUser(t.Context(), accesstypes.NewEnvironment(), tt.user, tenant1, tt.perm)
			if err != nil {
				t.Fatalf("CheckUser() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
				t.Errorf("CheckUser() (-want +got):\n%s", diff)
			}
		})
	}
}

// TestClient_CheckUserResources_returnsDecisions pins the per-resource
// Decision translation: every checked resource gets an answer from one
// snapshot — Granted where a grant covers it, Denied otherwise.
func TestClient_CheckUserResources_returnsDecisions(t *testing.T) {
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
	if err := manager.AddRolePermissionResources(ctx, tenant1, "Editor", "Read", "employees", "employees.name"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := manager.AddRoleUsers(ctx, tenant1, "Editor", "erin"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}

	tests := []struct {
		name      string
		resources []accesstypes.Resource
		want      accesstypes.Decisions
	}{
		{
			name:      "granted resources",
			resources: []accesstypes.Resource{"employees", "employees.name"},
			want: accesstypes.Decisions{
				"employees":      accesstypes.Granted(),
				"employees.name": accesstypes.Granted(),
			},
		},
		{
			name:      "mixed grants answer per resource",
			resources: []accesstypes.Resource{"employees", "secrets"},
			want: accesstypes.Decisions{
				"employees": accesstypes.Granted(),
				"secrets":   accesstypes.Denied(),
			},
		},
		{
			name:      "uncovered resource fails closed to denied",
			resources: []accesstypes.Resource{"secrets"},
			want: accesstypes.Decisions{
				"secrets": accesstypes.Denied(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := client.CheckUserResources(t.Context(), accesstypes.NewEnvironment(), "erin", tenant1, "Read", tt.resources...)
			if err != nil {
				t.Fatalf("CheckUserResources() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
				t.Errorf("CheckUserResources() (-want +got):\n%s", diff)
			}
		})
	}
}

// TestClient_CheckUserResources_conditionalDecision pins the Conditional leg
// of the public seam, including the shared-group emission: resources covered
// only by conditional grants surface as Conditional Decisions, and the ones
// sharing a covering set share ONE ConditionGroup listing every member —
// the same group value in each member's Decision — while a distinct set is
// its own group; an unconditional cover stays Granted regardless of other
// conditional grants, and no cover stays Denied. The groups' Condition
// payloads are the accesstypes placeholder until the expression language
// lands. Grants are seeded through the store directly: nothing on the
// management surface authors conditions yet.
func TestClient_CheckUserResources_conditionalDecision(t *testing.T) {
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

	tenant1 := accesstypes.DomainScope("tenant1")
	if err := store.InsertRole(ctx, tenant1, "Editor"); err != nil {
		t.Fatalf("InsertRole() error = %v", err)
	}
	for _, g := range []struct {
		resource, field, condition string
	}{
		{resource: "employees", field: ""},
		{resource: "employees", field: "name", condition: "owner = @subject"},
		{resource: "employees", field: "email", condition: "owner = @subject"},
		{resource: "employees", field: "salary", condition: "state = 'new'"},
		{resource: "widgets", field: "*"},
		{resource: "widgets", field: "name", condition: "owner = @subject"},
	} {
		if err := store.InsertGrant(ctx, tenant1, "Editor", "Update", g.resource, g.field, g.condition); err != nil {
			t.Fatalf("InsertGrant(%v) error = %v", g, err)
		}
	}
	if err := store.InsertUserRole(ctx, tenant1, "erin", "Editor"); err != nil {
		t.Fatalf("InsertUserRole() error = %v", err)
	}

	got, err := client.CheckUserResources(ctx, accesstypes.NewEnvironment(), "erin", tenant1, "Update",
		"employees", "employees.name", "employees.email", "employees.salary", "widgets.name", "secrets")
	if err != nil {
		t.Fatalf("CheckUserResources() error = %v", err)
	}
	sharedGroup := accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"employees.name", "employees.email"}}
	want := accesstypes.Decisions{
		"employees":        accesstypes.Granted(),
		"employees.name":   accesstypes.Conditional(sharedGroup),
		"employees.email":  accesstypes.Conditional(sharedGroup),
		"employees.salary": accesstypes.Conditional(accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"employees.salary"}}),
		"widgets.name":     accesstypes.Granted(),
		"secrets":          accesstypes.Denied(),
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
		t.Errorf("CheckUserResources() (-want +got):\n%s", diff)
	}
}

// TestClient_CheckUserResources_unknownTenantFailsClosed pins the Domains
// decoupling: there is no tenant validation on the check path — an unknown
// tenant scope holds no grants, so everything comes back missing, without an
// error.
func TestClient_CheckUserResources_unknownTenantFailsClosed(t *testing.T) {
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

	env := accesstypes.NewEnvironment()

	decisions, err := client.CheckUserResources(ctx, env, "erin", tenant1, "Read", "employees")
	if err != nil {
		t.Fatalf("CheckUserResources() error = %v", err)
	}
	want := accesstypes.Decisions{"employees": accesstypes.Granted()}
	if diff := cmp.Diff(want, decisions, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
		t.Errorf("CheckUserResources() in known tenant (-want +got):\n%s", diff)
	}

	decisions, err = client.CheckUserResources(ctx, env, "erin", accesstypes.DomainScope("no-such-tenant"), "Read", "employees")
	if err != nil {
		t.Fatalf("CheckUserResources() unknown tenant error = %v, want fail-closed denial, not an error", err)
	}
	want = accesstypes.Decisions{"employees": accesstypes.Denied()}
	if diff := cmp.Diff(want, decisions, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
		t.Errorf("CheckUserResources() in unknown tenant (-want +got):\n%s", diff)
	}
}
