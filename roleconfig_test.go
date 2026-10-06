// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
)

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
