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

// Test_MigrateRoles_tenantOnlyDomains pins the tenant-only position: the
// variadic never legitimately carries a ':'-bearing value — the global domain
// is added by MigrateRoles itself — so marker-shaped entries are rejected,
// closing the hole where a tenant list entry equal to the global marker would
// silently be treated as the global domain.
func Test_MigrateRoles_tenantOnlyDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domains []accesstypes.Domain
		wantErr bool
	}{
		{name: "plain tenant domains pass", domains: []accesstypes.Domain{"tenant1", "tenant2"}},
		{name: "no domains is global-only", domains: nil},
		{name: "marker-shaped tenant rejected", domains: []accesstypes.Domain{"tenant1", "acme:west"}, wantErr: true},
		// Stable across the accesstypes marker flip: pre-flip "access:global"
		// is an ordinary ':'-value; post-flip it is the marker itself — both
		// are illegitimate in a tenant position.
		{name: "global marker rejected in tenant position", domains: []accesstypes.Domain{"access:global"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager := newUserManager(newStoreManager(newFakeStore()))

			err := MigrateRoles(t.Context(), manager, emptyCollection{}, &RoleConfig{}, tt.domains...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MigrateRoles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
