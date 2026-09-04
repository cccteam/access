// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
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

// emptyCollection is a minimal PermissionCollection for migration tests.
type emptyCollection struct{}

func (emptyCollection) List() map[accesstypes.Permission][]accesstypes.Resource {
	return map[accesstypes.Permission][]accesstypes.Resource{}
}

func (emptyCollection) Scope(accesstypes.Resource) accesstypes.PermissionScope {
	return accesstypes.DomainPermissionScope
}

func (emptyCollection) IsResourceImmutable(accesstypes.PermissionScope, accesstypes.Resource) bool {
	return false
}

func (emptyCollection) AttributeComparisonType(accesstypes.PermissionScope, accesstypes.Resource, string) (accesstypes.AttributeType, bool) {
	return "", false
}

func (emptyCollection) AttributeIsColumn(accesstypes.PermissionScope, accesstypes.Resource, string) bool {
	return false
}

func (emptyCollection) DeclaresSubjectSet(string) bool { return false }

func (emptyCollection) DeclaresSubjectValue(string) bool { return false }

func (emptyCollection) IsComputedResource(accesstypes.PermissionScope, accesstypes.Resource) bool {
	return false
}

func (emptyCollection) MethodTarget(accesstypes.PermissionScope, accesstypes.Resource) (accesstypes.Resource, bool) {
	return "", false
}

// Test_MigrateRoles_tenantNamesArePureData pins the structural-scope model:
// any string is a legal tenant name — including "global" and the retired
// sentinel spelling "access:global" — and every tenant lands in its own
// tenant scope, never the global partition, which MigrateRoles adds
// structurally itself.
func Test_MigrateRoles_tenantNamesArePureData(t *testing.T) {
	t.Parallel()

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

			if err := MigrateRoles(ctx, manager, emptyCollection{}, &RoleConfig{}, tt.domains...); err != nil {
				t.Fatalf("MigrateRoles() error = %v", err)
			}

			// The Administrator role lands in the global scope and in each
			// tenant's own scope — one row per scope, no folding of
			// sentinel-shaped tenant names into the global partition.
			scopes := []accesstypes.Scope{accesstypes.GlobalScope()}
			for _, d := range tt.domains {
				scopes = append(scopes, accesstypes.DomainScope(d))
			}
			for _, scope := range scopes {
				exists, err := manager.RoleExists(ctx, scope, "Administrator")
				if err != nil {
					t.Fatalf("RoleExists(%v) error = %v", scope, err)
				}
				if !exists {
					t.Errorf("RoleExists(%v) = false, want the Administrator role reconciled into this scope", scope)
				}
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
			name:    "the Administrator role cannot be authored",
			roles:   ScopedRoles{Global: []*Role{role("Administrator")}},
			wantErr: "provisioned automatically",
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
