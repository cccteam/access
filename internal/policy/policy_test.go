package policy

import (
	"slices"
	"testing"
)

func Test_Records_Hash(t *testing.T) {
	t.Parallel()

	base := &Records{
		Grants: []Grant{
			{Domain: "tenant1", Subject: Subject{Kind: SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees"},
			{Domain: "tenant1", Subject: Subject{Kind: SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees", Field: "name"},
			{Domain: "tenant2", Subject: Subject{Kind: SubjectUser, Name: "alice"}, Perm: "List", Resource: "widgets"},
		},
		Memberships: []Membership{
			{Domain: "tenant1", Member: Subject{Kind: SubjectUser, Name: "erin"}, Role: "Editor"},
			{Domain: "tenant2", Member: Subject{Kind: SubjectUser, Name: "bob"}, Role: "Viewer"},
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
			name: "removed membership changes the hash",
			variant: func() *Records {
				return &Records{Grants: base.Grants, Memberships: base.Memberships[:1]}
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
