// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"reflect"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
)

func Test_exclude(t *testing.T) {
	t.Parallel()

	type args struct {
		source  map[accesstypes.Permission][]accesstypes.Resource
		exclude map[accesstypes.Permission][]accesstypes.Resource
	}
	tests := []struct {
		name string
		args args
		want map[accesstypes.Permission][]accesstypes.Resource
	}{
		{
			name: "has intersection",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("2"), accesstypes.Resource("4")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("3")}},
		},
		{
			name: "has no intersection",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("5"), accesstypes.Resource("6")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
		},
		{
			name: "complete overlap",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := exclude(tt.args.source, tt.args.exclude); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Exclude() = %v, want %v", got, tt.want)
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
