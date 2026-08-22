package access

import (
	"slices"
	"testing"

	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/google/go-cmp/cmp"
)

func Test_normalizeGrant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		row     []string
		want    grantRecord
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "endpoint grant on role",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees", "perm:Read", "allow"},
			want:   grantRecord{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees"},
			wantOK: true,
		},
		{
			name:   "field grant",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees.name", "perm:Read", "allow"},
			want:   grantRecord{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees", field: "name"},
			wantOK: true,
		},
		{
			name:   "wildcard field grant",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees.*", "perm:Update", "allow"},
			want:   grantRecord{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Update", resource: "employees", field: "*"},
			wantOK: true,
		},
		{
			name:   "direct user grant",
			row:    []string{"user:alice", "domain:tenant2", "resource:global", "perm:ViewUsers", "allow"},
			want:   grantRecord{domain: "tenant2", subject: subject{kind: subjectUser, name: "alice"}, perm: "ViewUsers", resource: "global"},
			wantOK: true,
		},
		{
			name:   "unprefixed subject is inert",
			row:    []string{"alice", "domain:tenant2", "resource:global", "perm:ViewUsers", "allow"},
			wantOK: false,
		},
		{
			name:   "missing effect defaults to allow",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees", "perm:Read"},
			want:   grantRecord{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees"},
			wantOK: true,
		},
		{
			name:   "noop subject is inert",
			row:    []string{"noop", "domain:tenant1", "resource:employees", "perm:Read", "allow"},
			wantOK: false,
		},
		{
			name:    "deny violates the additive-only invariant",
			row:     []string{"role:Editor", "domain:tenant1", "resource:employees", "perm:Read", "deny"},
			wantErr: true,
		},
		{
			name:    "malformed short row",
			row:     []string{"role:Editor", "domain:tenant1"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok, err := normalizeGrant(tt.row)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeGrant() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ok != tt.wantOK {
				t.Fatalf("normalizeGrant() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(grantRecord{}, subject{})); diff != "" {
				t.Errorf("normalizeGrant() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_normalizeMembership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		row     []string
		want    membershipRecord
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "user membership",
			row:    []string{"user:charlie", "role:Administrator", "domain:tenant1"},
			want:   membershipRecord{domain: "tenant1", member: subject{kind: subjectUser, name: "charlie"}, role: "Administrator"},
			wantOK: true,
		},
		{
			name:   "role inheritance",
			row:    []string{"role:Administrator", "role:Editor", "domain:tenant1"},
			want:   membershipRecord{domain: "tenant1", member: subject{kind: subjectRole, name: "Administrator"}, role: "Editor"},
			wantOK: true,
		},
		{
			name:   "noop sentinel is skipped",
			row:    []string{"noop", "role:Editor", "domain:tenant1"},
			wantOK: false,
		},
		{
			name:    "malformed short row",
			row:     []string{"user:charlie", "role:Administrator"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok, err := normalizeMembership(tt.row)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeMembership() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ok != tt.wantOK {
				t.Fatalf("normalizeMembership() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(membershipRecord{}, subject{})); diff != "" {
				t.Errorf("normalizeMembership() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_splitResourceField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		obj          string
		wantResource string
		wantField    string
	}{
		{name: "no field", obj: "employees", wantResource: "employees", wantField: ""},
		{name: "named field", obj: "employees.name", wantResource: "employees", wantField: "name"},
		{name: "wildcard field", obj: "employees.*", wantResource: "employees", wantField: "*"},
		{name: "splits on last dot", obj: "a.b.c", wantResource: "a.b", wantField: "c"},
		{name: "global resource", obj: "global", wantResource: "global", wantField: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resource, field := splitResourceField(tt.obj)
			if resource != tt.wantResource || field != tt.wantField {
				t.Errorf("splitResourceField(%q) = (%q, %q), want (%q, %q)", tt.obj, resource, field, tt.wantResource, tt.wantField)
			}
		})
	}
}

func Test_readCasbinPolicy(t *testing.T) {
	t.Parallel()

	records, err := readCasbinPolicy(fileadapter.NewAdapter("testdata/policy_reader.csv"))
	if err != nil {
		t.Fatalf("readCasbinPolicy() error = %v", err)
	}

	wantGrants := []grantRecord{
		{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees"},
		{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees", field: "name"},
		{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Update", resource: "employees", field: "*"},
		{domain: "tenant2", subject: subject{kind: subjectUser, name: "alice"}, perm: "ViewUsers", resource: "global"},
	}
	wantMemberships := []membershipRecord{
		{domain: "tenant1", member: subject{kind: subjectUser, name: "charlie"}, role: "Administrator"},
		{domain: "tenant1", member: subject{kind: subjectRole, name: "Administrator"}, role: "Editor"},
	}

	if diff := cmp.Diff(wantGrants, records.grants, cmp.AllowUnexported(grantRecord{}, subject{})); diff != "" {
		t.Errorf("readCasbinPolicy() grants mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantMemberships, records.memberships, cmp.AllowUnexported(membershipRecord{}, subject{})); diff != "" {
		t.Errorf("readCasbinPolicy() memberships mismatch (-want +got):\n%s", diff)
	}
}

func Test_policyRecords_hash(t *testing.T) {
	t.Parallel()

	base := &policyRecords{
		grants: []grantRecord{
			{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees"},
			{domain: "tenant1", subject: subject{kind: subjectRole, name: "Editor"}, perm: "Read", resource: "employees", field: "name"},
			{domain: "tenant2", subject: subject{kind: subjectUser, name: "alice"}, perm: "List", resource: "widgets"},
		},
		memberships: []membershipRecord{
			{domain: "tenant1", member: subject{kind: subjectUser, name: "erin"}, role: "Editor"},
			{domain: "tenant2", member: subject{kind: subjectUser, name: "bob"}, role: "Viewer"},
		},
	}

	tests := []struct {
		name string
		// variant builds the records to compare against base.
		variant func() *policyRecords
		// wantSameHash: row order must not matter; any content change must.
		wantSameHash bool
	}{
		{
			name: "row order does not change the hash",
			variant: func() *policyRecords {
				return &policyRecords{
					grants:      []grantRecord{base.grants[2], base.grants[0], base.grants[1]},
					memberships: []membershipRecord{base.memberships[1], base.memberships[0]},
				}
			},
			wantSameHash: true,
		},
		{
			name: "changed grant field changes the hash",
			variant: func() *policyRecords {
				grants := slices.Clone(base.grants)
				grants[2].field = "name"

				return &policyRecords{grants: grants, memberships: base.memberships}
			},
			wantSameHash: false,
		},
		{
			name: "removed membership changes the hash",
			variant: func() *policyRecords {
				return &policyRecords{grants: base.grants, memberships: base.memberships[:1]}
			},
			wantSameHash: false,
		},
		{
			name: "changed subject kind changes the hash",
			variant: func() *policyRecords {
				grants := slices.Clone(base.grants)
				grants[2].subject.kind = subjectRole

				return &policyRecords{grants: grants, memberships: base.memberships}
			},
			wantSameHash: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotSame := tt.variant().hash() == base.hash()
			if gotSame != tt.wantSameHash {
				t.Errorf("hash() same as base = %v, want %v", gotSame, tt.wantSameHash)
			}
		})
	}
}

func Test_readCasbinPolicy_denyFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/deny.csv"
	writeTestPolicy(t, path, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, deny\n")

	if _, err := readCasbinPolicy(fileadapter.NewAdapter(path)); err == nil {
		t.Fatal("readCasbinPolicy() expected error for deny row, got nil")
	}
}
