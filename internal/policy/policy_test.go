package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
)

func Test_Records_Hash(t *testing.T) {
	t.Parallel()

	base := &Records{
		Grants: []Grant{
			{Scope: accesstypes.DomainScope("tenant1"), Subject: Subject{Kind: SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: Subject{Kind: SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees", Field: "name"},
			{Scope: accesstypes.DomainScope("tenant2"), Subject: Subject{Kind: SubjectUser, Name: "alice"}, Perm: "List", Resource: "widgets"},
		},
		Memberships: []Membership{
			{Scope: accesstypes.DomainScope("tenant1"), Member: Subject{Kind: SubjectUser, Name: "erin"}, Role: "Editor"},
			{Scope: accesstypes.DomainScope("tenant2"), Member: Subject{Kind: SubjectUser, Name: "bob"}, Role: "Viewer"},
		},
	}

	tests := []struct {
		name string
		// variant builds the records to compare against base.
		variant func() *Records
		// wantSameHash: row order must not matter; any content change must.
		wantSameHash bool
	}{
		{
			name: "row order does not change the hash",
			variant: func() *Records {
				return &Records{
					Grants:      []Grant{base.Grants[2], base.Grants[0], base.Grants[1]},
					Memberships: []Membership{base.Memberships[1], base.Memberships[0]},
				}
			},
			wantSameHash: true,
		},
		{
			name: "changed grant field changes the hash",
			variant: func() *Records {
				grants := slices.Clone(base.Grants)
				grants[2].Field = "name"

				return &Records{Grants: grants, Memberships: base.Memberships}
			},
			wantSameHash: false,
		},
		{
			name: "added grant condition changes the hash",
			variant: func() *Records {
				grants := slices.Clone(base.Grants)
				grants[2].Condition = "owner = @subject"

				return &Records{Grants: grants, Memberships: base.Memberships}
			},
			wantSameHash: false,
		},
		{
			name: "removed membership changes the hash",
			variant: func() *Records {
				return &Records{Grants: base.Grants, Memberships: base.Memberships[:1]}
			},
			wantSameHash: false,
		},
		{
			name: "global scope hashes differently from a tenant scope",
			variant: func() *Records {
				grants := slices.Clone(base.Grants)
				grants[2].Scope = accesstypes.GlobalScope()

				return &Records{Grants: grants, Memberships: base.Memberships}
			},
			wantSameHash: false,
		},
		{
			name: "a tenant literally named global is not the global scope",
			variant: func() *Records {
				grants := slices.Clone(base.Grants)
				grants[2].Scope = accesstypes.DomainScope("global")

				return &Records{Grants: grants, Memberships: base.Memberships}
			},
			wantSameHash: false,
		},
		{
			name: "changed subject kind changes the hash",
			variant: func() *Records {
				grants := slices.Clone(base.Grants)
				grants[2].Subject.Kind = SubjectRole

				return &Records{Grants: grants, Memberships: base.Memberships}
			},
			wantSameHash: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotSame := tt.variant().Hash() == base.Hash()
			if gotSame != tt.wantSameHash {
				t.Errorf("Hash() same as base = %v, want %v", gotSame, tt.wantSameHash)
			}
		})
	}
}

func Test_ScopeColumns_roundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scope      accesstypes.Scope
		wantGlobal bool
		wantDomain string
	}{
		{name: "global", scope: accesstypes.GlobalScope(), wantGlobal: true},
		{name: "tenant", scope: accesstypes.DomainScope("tenant1"), wantDomain: "tenant1"},
		{name: "tenant named global", scope: accesstypes.DomainScope("global"), wantDomain: "global"},
		{name: "zero scope is the zero domain's tenant scope", scope: accesstypes.Scope{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Every constructible scope belongs to the default axis, stored as "".
			global, axis, domain := ScopeColumns(tt.scope)
			if global != tt.wantGlobal || axis != "" || domain != tt.wantDomain {
				t.Errorf("ScopeColumns() = (%v, %q, %q), want (%v, %q, %q)", global, axis, domain, tt.wantGlobal, "", tt.wantDomain)
			}
			got, err := ScopeFromColumns(global, axis, domain)
			if err != nil {
				t.Fatalf("ScopeFromColumns() error = %v", err)
			}
			if got != tt.scope {
				t.Errorf("ScopeFromColumns() = %v, want %v", got, tt.scope)
			}
		})
	}
}

// Test_ScopeFromColumns_refusesNamedAxis pins the fail-closed posture: a stored
// row under an axis this build cannot name is refused rather than folded into
// the default axis, whatever its other columns say.
func Test_ScopeFromColumns_refusesNamedAxis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		global bool
		axis   string
		domain string
	}{
		{name: "tenant row under a named axis", axis: "region", domain: "tenant1"},
		{name: "global row under a named axis", global: true, axis: "region"},
		{name: "named axis with an empty domain", axis: "region"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ScopeFromColumns(tt.global, tt.axis, tt.domain)
			if err == nil {
				t.Fatalf("ScopeFromColumns(%v, %q, %q) = %v, want an error", tt.global, tt.axis, tt.domain, got)
			}
			if !strings.Contains(err.Error(), tt.axis) {
				t.Errorf("ScopeFromColumns() error = %q, want it to name the axis %q", err, tt.axis)
			}
		})
	}
}
