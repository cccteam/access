// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"reflect"
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
			name:    "matching pairs drop out",
			source:  grantSet{"List": {"Widgets": "", "Widgets.name": ""}},
			exclude: grantSet{"List": {"Widgets": ""}},
			want:    grantSet{"List": {"Widgets.name": ""}},
		},
		{
			name:    "a changed condition is not a match",
			source:  grantSet{"Read": {"Widgets": "owner = subject"}},
			exclude: grantSet{"Read": {"Widgets": ""}},
			want:    grantSet{"Read": {"Widgets": "owner = subject"}},
		},
		{
			name:    "complete overlap yields nothing",
			source:  grantSet{"Read": {"Widgets": "owner = subject"}},
			exclude: grantSet{"Read": {"Widgets": "owner = subject"}},
			want:    grantSet{},
		},
		{
			name:    "no overlap keeps everything",
			source:  grantSet{"Read": {"Widgets": ""}},
			exclude: grantSet{"List": {"Widgets": ""}},
			want:    grantSet{"Read": {"Widgets": ""}},
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
