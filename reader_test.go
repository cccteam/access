package access

import (
	"testing"

	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/cccteam/access/internal/policy"
	"github.com/google/go-cmp/cmp"
)

func Test_normalizeGrant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		row     []string
		want    policy.Grant
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "endpoint grant on role",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees", "perm:Read", "allow"},
			want:   policy.Grant{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees"},
			wantOK: true,
		},
		{
			name:   "field grant",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees.name", "perm:Read", "allow"},
			want:   policy.Grant{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees", Field: "name"},
			wantOK: true,
		},
		{
			name:   "wildcard field grant",
			row:    []string{"role:Editor", "domain:tenant1", "resource:employees.*", "perm:Update", "allow"},
			want:   policy.Grant{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Update", Resource: "employees", Field: "*"},
			wantOK: true,
		},
		{
			name:   "direct user grant",
			row:    []string{"user:alice", "domain:tenant2", "resource:global", "perm:ViewUsers", "allow"},
			want:   policy.Grant{Domain: "tenant2", Subject: policy.Subject{Kind: policy.SubjectUser, Name: "alice"}, Perm: "ViewUsers", Resource: "global"},
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
			want:   policy.Grant{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees"},
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
			if diff := cmp.Diff(tt.want, got); diff != "" {
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
		want    policy.Membership
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "user membership",
			row:    []string{"user:charlie", "role:Administrator", "domain:tenant1"},
			want:   policy.Membership{Domain: "tenant1", Member: policy.Subject{Kind: policy.SubjectUser, Name: "charlie"}, Role: "Administrator"},
			wantOK: true,
		},
		{
			name:   "role inheritance",
			row:    []string{"role:Administrator", "role:Editor", "domain:tenant1"},
			want:   policy.Membership{Domain: "tenant1", Member: policy.Subject{Kind: policy.SubjectRole, Name: "Administrator"}, Role: "Editor"},
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
			if diff := cmp.Diff(tt.want, got); diff != "" {
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

	wantGrants := []policy.Grant{
		{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees"},
		{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Read", Resource: "employees", Field: "name"},
		{Domain: "tenant1", Subject: policy.Subject{Kind: policy.SubjectRole, Name: "Editor"}, Perm: "Update", Resource: "employees", Field: "*"},
		{Domain: "tenant2", Subject: policy.Subject{Kind: policy.SubjectUser, Name: "alice"}, Perm: "ViewUsers", Resource: "global"},
	}
	wantMemberships := []policy.Membership{
		{Domain: "tenant1", Member: policy.Subject{Kind: policy.SubjectUser, Name: "charlie"}, Role: "Administrator"},
		{Domain: "tenant1", Member: policy.Subject{Kind: policy.SubjectRole, Name: "Administrator"}, Role: "Editor"},
	}

	if diff := cmp.Diff(wantGrants, records.Grants); diff != "" {
		t.Errorf("readCasbinPolicy() grants mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantMemberships, records.Memberships); diff != "" {
		t.Errorf("readCasbinPolicy() memberships mismatch (-want +got):\n%s", diff)
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
