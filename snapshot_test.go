package access

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

func writeTestPolicy(t *testing.T, path, policy string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
}

// snapshotFromCSV compiles a snapshot from a casbin CSV fixture through the
// real reader path.
func snapshotFromCSV(t *testing.T, path string) *snapshot {
	t.Helper()
	records, err := readCasbinPolicy(fileadapter.NewAdapter(path))
	if err != nil {
		t.Fatalf("readCasbinPolicy() error = %v", err)
	}

	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		t.Fatalf("newSnapshot() error = %v", err)
	}

	return snap
}

func Test_snapshot_checkUser(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/policy.csv"
	writeTestPolicy(t, path, `
p, role:Editor,  domain:tenant1, resource:employees,        perm:Read,   allow
p, role:Editor,  domain:tenant1, resource:employees.name,   perm:Read,   allow
p, role:Editor,  domain:tenant1, resource:documents.*,      perm:Read,   allow
p, role:Auditor, domain:tenant1, resource:widgets,          perm:List,   allow
p, role:Chief,   domain:tenant1, resource:budgets,          perm:Read,   allow
p, user:dana,    domain:tenant1, resource:widgets,          perm:List,   allow
g, user:erin,    role:Editor,    domain:tenant1
g, user:erin,    role:Auditor,   domain:tenant1
g, role:Editor,  role:Chief,     domain:tenant1
g, noop,         role:Editor,    domain:tenant1
`)
	snap := snapshotFromCSV(t, path)

	type args struct {
		user      accesstypes.User
		domain    accesstypes.Domain
		perm      accesstypes.Permission
		resources []accesstypes.Resource
	}
	tests := []struct {
		name        string
		args        args
		wantMissing []accesstypes.Resource
	}{
		{
			name:        "endpoint grant through role",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "named field grant",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees.name"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "endpoint grant gives no field visibility",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees.salary"}},
			wantMissing: []accesstypes.Resource{"employees.salary"},
		},
		{
			name:        "wildcard grant covers unknown fields by implication",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"documents.title", "documents.body"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "wildcard grant does not grant the endpoint",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"documents"}},
			wantMissing: []accesstypes.Resource{"documents"},
		},
		{
			name:        "grants combine across roles",
			args:        args{user: "erin", domain: "tenant1", perm: "List", resources: []accesstypes.Resource{"widgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "role inheritance is folded transitively",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"budgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "direct user grant without membership",
			args:        args{user: "dana", domain: "tenant1", perm: "List", resources: []accesstypes.Resource{"widgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "grants stay inside their domain",
			args:        args{user: "erin", domain: "tenant2", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown user",
			args:        args{user: "stranger", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown permission",
			args:        args{user: "erin", domain: "tenant1", perm: "Fly", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown resource",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"spaceships"}},
			wantMissing: []accesstypes.Resource{"spaceships"},
		},
		{
			name:        "missing preserves input order",
			args:        args{user: "erin", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"spaceships", "employees", "employees.salary"}},
			wantMissing: []accesstypes.Resource{"spaceships", "employees.salary"},
		},
		{
			name:        "no resources yields empty missing",
			args:        args{user: "erin", domain: "tenant1", perm: "Read"},
			wantMissing: []accesstypes.Resource{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing := snap.checkUser(tt.args.user, tt.args.domain, tt.args.perm, tt.args.resources...)
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("snapshot.checkUser() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_snapshot_checkRole(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/policy.csv"
	writeTestPolicy(t, path, `
p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow
p, role:Chief,  domain:tenant1, resource:budgets,   perm:Read, allow
g, role:Editor, role:Chief,     domain:tenant1
g, role:Loop1,  role:Loop2,     domain:tenant1
g, role:Loop2,  role:Loop1,     domain:tenant1
`)
	snap := snapshotFromCSV(t, path)

	type args struct {
		role      accesstypes.Role
		domain    accesstypes.Domain
		perm      accesstypes.Permission
		resources []accesstypes.Resource
	}
	tests := []struct {
		name        string
		args        args
		wantMissing []accesstypes.Resource
	}{
		{
			name:        "own grant",
			args:        args{role: "Editor", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "inherited grant",
			args:        args{role: "Editor", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"budgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "inheritance is one-way",
			args:        args{role: "Chief", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "inheritance cycle compiles and denies safely",
			args:        args{role: "Loop1", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown role",
			args:        args{role: "Ghost", domain: "tenant1", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "wrong domain",
			args:        args{role: "Editor", domain: "tenant2", perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing := snap.checkRole(tt.args.role, tt.args.domain, tt.args.perm, tt.args.resources...)
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("snapshot.checkRole() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// fakeAdapterFactory hands out a persist.Adapter for a policy file, optionally
// failing to simulate store outages.
type fakeAdapterFactory struct {
	path    string
	failNew bool
}

func (f *fakeAdapterFactory) NewAdapter() (persist.Adapter, error) {
	if f.failNew {
		return nil, errors.New("adapter unavailable")
	}

	return fileadapter.NewAdapter(f.path), nil
}

func Test_snapshotEngine(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/policy.csv"
	writeTestPolicy(t, path, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n")

	t.Run("first load failure returns an error", func(t *testing.T) {
		t.Parallel()
		e := newSnapshotEngine(&fakeAdapterFactory{path: path, failNew: true})
		if _, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees"); err == nil {
			t.Fatal("checkUser() expected error when first load fails, got nil")
		}
	})

	t.Run("check served from snapshot", func(t *testing.T) {
		t.Parallel()
		e := newSnapshotEngine(&fakeAdapterFactory{path: path})
		missing, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees")
		if err != nil {
			t.Fatalf("checkUser() error = %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("checkUser() missing = %v, want none", missing)
		}
	})

	t.Run("invalidate reloads on next check", func(t *testing.T) {
		t.Parallel()
		grownPath := dir + "/policy_grow.csv"
		writeTestPolicy(t, grownPath, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n")
		e := newSnapshotEngine(&fakeAdapterFactory{path: grownPath})

		if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 1 {
			t.Fatalf("checkUser() = (%v, %v), want widgets missing before the write", missing, err)
		}

		writeTestPolicy(t, grownPath, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\np, role:Editor, domain:tenant1, resource:widgets, perm:List, allow\ng, user:erin, role:Editor, domain:tenant1\n")

		if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 1 {
			t.Fatalf("checkUser() = (%v, %v), want stale answer before invalidate", missing, err)
		}

		e.invalidate()

		if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 0 {
			t.Fatalf("checkUser() = (%v, %v), want widgets granted after invalidate", missing, err)
		}
	})

	t.Run("reload failure serves the last good snapshot", func(t *testing.T) {
		t.Parallel()
		gonePath := dir + "/policy_gone.csv"
		writeTestPolicy(t, gonePath, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n")
		e := newSnapshotEngine(&fakeAdapterFactory{path: gonePath})

		if _, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees"); err != nil {
			t.Fatalf("checkUser() error = %v", err)
		}

		// Break the store, then force a reload attempt.
		if err := os.Remove(gonePath); err != nil {
			t.Fatalf("os.Remove() error = %v", err)
		}
		e.invalidate()

		missing, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees")
		if err != nil {
			t.Fatalf("checkUser() error = %v, want stale snapshot served", err)
		}
		if len(missing) != 0 {
			t.Fatalf("checkUser() missing = %v, want none from stale snapshot", missing)
		}
	})
}
