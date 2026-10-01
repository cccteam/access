// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_diffGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  grantSet
		exclude grantSet
		want    grantSet
	}{
		{
			name:    "matching rows drop out",
			source:  rows("List", "Widgets", "", "List", "Widgets.name", ""),
			exclude: rows("List", "Widgets", ""),
			want:    rows("List", "Widgets.name", ""),
		},
		{
			name:    "a changed condition is not a match",
			source:  rows("Read", "Widgets", "owner = subject"),
			exclude: rows("Read", "Widgets", ""),
			want:    rows("Read", "Widgets", "owner = subject"),
		},
		{
			name:    "one of two conditions on a resource drops out",
			source:  rows("Read", "Widgets", "owner = subject", "Read", "Widgets", "price < 10"),
			exclude: rows("Read", "Widgets", "price < 10"),
			want:    rows("Read", "Widgets", "owner = subject"),
		},
		{
			name:    "complete overlap yields nothing",
			source:  rows("Read", "Widgets", "owner = subject"),
			exclude: rows("Read", "Widgets", "owner = subject"),
			want:    grantSet{},
		},
		{
			name:    "no overlap keeps everything",
			source:  rows("Read", "Widgets", ""),
			exclude: rows("List", "Widgets", ""),
			want:    rows("Read", "Widgets", ""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := diffGrants(tt.source, tt.exclude); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("diffGrants() = %v, want %v", got, tt.want)
			}
		})
	}
}

// rows builds a grantSet from (permission, resource, condition) triples.
func rows(triples ...string) grantSet {
	if len(triples)%3 != 0 {
		panic("rows takes (permission, resource, condition) triples")
	}
	set := make(grantSet)
	for len(triples) >= 3 {
		perm, res, condition := triples[0], triples[1], triples[2]
		set.add(accesstypes.Permission(perm), accesstypes.Resource(res), condition)
		triples = triples[3:]
	}

	return set
}

// Test_MigrateRoles_tenantNamesArePureData pins the structural-scope model:
// any string is a legal tenant name — including "global" and the retired
// sentinel spelling "access:global" — and every tenant lands in its own
// tenant scope, never the global partition, which MigrateRoles adds
// structurally itself. Each partition holds exactly the roles the file
// declares for it: the global list in the global scope, the domain list in
// every tenant scope, and nothing the file does not name.
func Test_MigrateRoles_tenantNamesArePureData(t *testing.T) {
	t.Parallel()

	config := &RoleConfig{Roles: ScopedRoles{
		Global: []*Role{{
			Name:        "VendorManager",
			Permissions: map[accesstypes.Permission][]Grant{"Execute": {{Resource: "DoThing"}}},
		}},
		Domain: []*Role{{
			Name:        "Reader",
			Permissions: map[accesstypes.Permission][]Grant{"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}}},
		}},
	}}

	tests := []struct {
		name    string
		domains []accesstypes.Domain
	}{
		{name: "plain tenant domains", domains: []accesstypes.Domain{"tenant1", "tenant2"}},
		{name: "no domains is global-only", domains: nil},
		{name: "sentinel-shaped names are ordinary tenants", domains: []accesstypes.Domain{"global", "access:global"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			manager := newUserManager(newStoreManager(newFakeStore()))

			if err := MigrateRoles(ctx, manager, grammarCollection{}, config, tt.domains...); err != nil {
				t.Fatalf("MigrateRoles() error = %v", err)
			}

			// The global role lands in the global scope alone; the domain role
			// in each tenant's own scope — no folding of sentinel-shaped tenant
			// names into the global partition, and no role the file does not
			// name anywhere.
			want := map[accesstypes.Scope][]accesstypes.Role{accesstypes.GlobalScope(): {"VendorManager"}}
			for _, d := range tt.domains {
				want[accesstypes.DomainScope(d)] = []accesstypes.Role{"Reader"}
			}
			for scope, wantRoles := range want {
				got, err := manager.Roles(ctx, scope)
				if err != nil {
					t.Fatalf("Roles(%v) error = %v", scope, err)
				}
				if diff := cmp.Diff(wantRoles, got); diff != "" {
					t.Errorf("Roles(%v) mismatch (-want +got):\n%s", scope, diff)
				}
			}
		})
	}
}

// Test_MigrateRoles_anyNameIsOrdinary pins that the configuration is the
// complete statement of the store's roles: no name is reserved or provisioned
// outside it, and a role declared with no grants is created and holds
// nothing.
func Test_MigrateRoles_anyNameIsOrdinary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		role       *Role
		wantGrants map[accesstypes.Permission]map[accesstypes.Resource][]string
	}{
		{
			name: "a role declared with no grants is created and holds nothing",
			role: &Role{Name: "Auditor"},
		},
		{
			name: "Administrator is an ordinary name, authored like any other",
			role: &Role{
				Name:        "Administrator",
				Permissions: map[accesstypes.Permission][]Grant{"Execute": {{Resource: "DoThing"}}},
			},
			wantGrants: map[accesstypes.Permission]map[accesstypes.Resource][]string{"Execute": {"DoThing": {""}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			manager := newUserManager(newStoreManager(newFakeStore()))
			global := accesstypes.GlobalScope()

			config := &RoleConfig{Roles: ScopedRoles{Global: []*Role{tt.role}}}
			if err := MigrateRoles(ctx, manager, grammarCollection{}, config); err != nil {
				t.Fatalf("MigrateRoles() error = %v", err)
			}

			gotRoles, err := manager.Roles(ctx, global)
			if err != nil {
				t.Fatalf("Roles() error = %v", err)
			}
			if diff := cmp.Diff([]accesstypes.Role{tt.role.Name}, gotRoles); diff != "" {
				t.Errorf("Roles() mismatch (-want +got):\n%s", diff)
			}
			gotGrants, err := manager.RoleGrants(ctx, global, tt.role.Name)
			if err != nil {
				t.Fatalf("RoleGrants() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantGrants, gotGrants, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("RoleGrants() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_MigrateRoles_rolesLiveAtTheirDeclaredScope pins the scoped-role model:
// a global role exists in the global partition only, a domain role in every
// tenant partition only, and a stale copy in the wrong partition — the shape
// the old create-everywhere behavior left behind — is reconciled away.
func Test_MigrateRoles_rolesLiveAtTheirDeclaredScope(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	manager := newUserManager(newStoreManager(newFakeStore()))

	global := accesstypes.GlobalScope()
	tenant := accesstypes.DomainScope("tenant1")

	// A phantom copy of each role in the partition its declaration does not
	// name, as the old behavior provisioned.
	if err := manager.AddRole(ctx, tenant, "VendorManager"); err != nil {
		t.Fatalf("AddRole() error = %v", err)
	}
	if err := manager.AddRole(ctx, global, "Reader"); err != nil {
		t.Fatalf("AddRole() error = %v", err)
	}

	config := &RoleConfig{Roles: ScopedRoles{
		Global: []*Role{{
			Name:        "VendorManager",
			Permissions: map[accesstypes.Permission][]Grant{"Execute": {{Resource: "DoThing"}}},
		}},
		Domain: []*Role{{
			Name:        "Reader",
			Permissions: map[accesstypes.Permission][]Grant{"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}}},
		}},
	}}
	if err := MigrateRoles(ctx, manager, grammarCollection{}, config, "tenant1"); err != nil {
		t.Fatalf("MigrateRoles() error = %v", err)
	}

	tests := []struct {
		scope accesstypes.Scope
		role  accesstypes.Role
		want  bool
	}{
		{global, "VendorManager", true},
		{tenant, "VendorManager", false},
		{tenant, "Reader", true},
		{global, "Reader", false},
	}
	for _, tt := range tests {
		exists, err := manager.RoleExists(ctx, tt.scope, tt.role)
		if err != nil {
			t.Fatalf("RoleExists(%v, %s) error = %v", tt.scope, tt.role, err)
		}
		if exists != tt.want {
			t.Errorf("RoleExists(%v, %s) = %v, want %v", tt.scope, tt.role, exists, tt.want)
		}
	}
}

func Test_validateRoleNames(t *testing.T) {
	t.Parallel()

	role := func(name accesstypes.Role) *Role { return &Role{Name: name} }

	tests := []struct {
		name    string
		roles   ScopedRoles
		wantErr string
	}{
		{
			name:  "distinct names at each scope pass",
			roles: ScopedRoles{Global: []*Role{role("VendorManager")}, Domain: []*Role{role("Reader")}},
		},
		{
			name:    "a name declared twice in one list is rejected",
			roles:   ScopedRoles{Domain: []*Role{role("Reader"), role("Reader")}},
			wantErr: "declared twice",
		},
		{
			name:    "a name declared at both scopes is rejected",
			roles:   ScopedRoles{Global: []*Role{role("Reader")}, Domain: []*Role{role("Reader")}},
			wantErr: "exactly one scope",
		},
		{
			name:  "Administrator is an ordinary name and passes",
			roles: ScopedRoles{Global: []*Role{role("Administrator")}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateRoleNames(tt.roles)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRoleNames() error = %v, want nil", err)
				}

				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRoleNames() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// Test_MigrateRoles_writesEachRoleOnce pins that reconciliation adds a role's
// missing grants as one store write per role and scope, not one per grant row,
// and that a role already at its desired state writes nothing.
func Test_MigrateRoles_writesEachRoleOnce(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newFakeStore()
	manager := newUserManager(newStoreManager(store))

	config := &RoleConfig{Roles: ScopedRoles{
		Global: []*Role{{
			Name:        "VendorManager",
			Permissions: map[accesstypes.Permission][]Grant{"Execute": {{Resource: "DoThing"}}},
		}},
		Domain: []*Role{{
			Name: "Reader",
			Permissions: map[accesstypes.Permission][]Grant{
				"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name", "price"}}},
			},
		}},
	}}

	// The global scope holds the one global role, each tenant scope the one
	// domain role.
	tests := []struct {
		name       string
		domains    []accesstypes.Domain
		wantWrites int
	}{
		{name: "first run: one write per role per scope", domains: []accesstypes.Domain{"tenant1", "tenant2"}, wantWrites: 3},
		{name: "second run: nothing to add, nothing written", domains: []accesstypes.Domain{"tenant1", "tenant2"}, wantWrites: 0},
		{name: "a new domain: one write per role in it", domains: []accesstypes.Domain{"tenant1", "tenant2", "tenant3"}, wantWrites: 1},
	}
	for _, tt := range tests {
		before := store.changeWrites
		if err := MigrateRoles(ctx, manager, grammarCollection{}, config, tt.domains...); err != nil {
			t.Fatalf("%s: MigrateRoles() error = %v", tt.name, err)
		}
		if got := store.changeWrites - before; got != tt.wantWrites {
			t.Errorf("%s: ChangeGrants called %d times, want %d", tt.name, got, tt.wantWrites)
		}
	}
	if store.deleteCalls != 0 || store.batchWrites != 0 {
		t.Errorf("DeleteGrant called %d times and InsertGrants %d times, want 0 and 0: a role's grants change through ChangeGrants alone", store.deleteCalls, store.batchWrites)
	}
}

// Test_MigrateRoles_changesEachRoleInOneWrite pins that a role's removals and
// additions reach the store as one ChangeGrants call: a condition edit is one
// row removed and one added together, a dropped grant is one removal, and no
// DeleteGrant call is ever made.
func Test_MigrateRoles_changesEachRoleInOneWrite(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newFakeStore()
	manager := newUserManager(newStoreManager(store))
	reader := func(condition string, fields ...accesstypes.Tag) *RoleConfig {
		return &RoleConfig{Roles: ScopedRoles{Domain: []*Role{{
			Name:        "Reader",
			Permissions: map[accesstypes.Permission][]Grant{"Read": {{Resource: "Widgets", Fields: fields, Condition: condition}}},
		}}}}
	}

	tests := []struct {
		name          string
		config        *RoleConfig
		wantRemovals  []policy.RoleGrant
		wantAdditions []policy.RoleGrant
		wantGrants    []policy.RoleGrant
	}{
		{
			name:          "first run adds the grant",
			config:        reader("price < 100"),
			wantAdditions: []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 100"}},
			wantGrants:    []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 100"}},
		},
		{
			name:          "a condition edit removes the old row and adds the new one together",
			config:        reader("price < 200"),
			wantRemovals:  []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 100"}},
			wantAdditions: []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 200"}},
			wantGrants:    []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 200"}},
		},
		{
			name:          "a field added is one addition",
			config:        reader("price < 200", "name"),
			wantAdditions: []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Field: "name", Condition: "price < 200"}},
			wantGrants: []policy.RoleGrant{
				{Perm: "Read", Resource: "Widgets", Condition: "price < 200"},
				{Perm: "Read", Resource: "Widgets", Field: "name", Condition: "price < 200"},
			},
		},
		{
			name:         "a field dropped is one removal",
			config:       reader("price < 200"),
			wantRemovals: []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Field: "name", Condition: "price < 200"}},
			wantGrants:   []policy.RoleGrant{{Perm: "Read", Resource: "Widgets", Condition: "price < 200"}},
		},
	}
	for _, tt := range tests {
		before := store.changeWrites
		if err := MigrateRoles(ctx, manager, grammarCollection{}, tt.config, "tenant1"); err != nil {
			t.Fatalf("%s: MigrateRoles() error = %v", tt.name, err)
		}
		if got := store.changeWrites - before; got != 1 {
			t.Errorf("%s: ChangeGrants called %d times, want 1", tt.name, got)
		}
		if diff := cmp.Diff(tt.wantRemovals, store.lastChange.removals, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("%s: removals mismatch (-want +got):\n%s", tt.name, diff)
		}
		if diff := cmp.Diff(tt.wantAdditions, store.lastChange.additions, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("%s: additions mismatch (-want +got):\n%s", tt.name, diff)
		}
		got, err := store.ListRoleGrants(ctx, accesstypes.DomainScope("tenant1"), "Reader")
		if err != nil {
			t.Fatalf("%s: ListRoleGrants() error = %v", tt.name, err)
		}
		if diff := cmp.Diff(tt.wantGrants, got); diff != "" {
			t.Errorf("%s: grants after the run (-want +got):\n%s", tt.name, diff)
		}
	}
	if store.deleteCalls != 0 {
		t.Errorf("DeleteGrant called %d times, want 0", store.deleteCalls)
	}
}
