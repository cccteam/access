package access

import (
	"context"
	"os"
	"slices"
	"sync"
	"sync/atomic"
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

// fakeDomains is a Domains implementation with a fixed ID list.
type fakeDomains struct {
	ids []string
}

func (f *fakeDomains) DomainIDs(_ context.Context) ([]string, error) {
	return f.ids, nil
}

func (f *fakeDomains) DomainExists(_ context.Context, id string) (bool, error) {
	return slices.Contains(f.ids, id), nil
}

// testEngine builds a snapshotEngine whose background loop is effectively
// inert (1h heartbeat) so tests drive reloads deterministically, and whose
// goroutines stop at test end.
func testEngine(t *testing.T, factory Adapter, opts *clientOptions) *snapshotEngine {
	t.Helper()
	if opts == nil {
		opts = defaultClientOptions()
	}
	opts.heartbeatInterval = time.Hour
	e := newSnapshotEngine(factory, opts)
	t.Cleanup(func() {
		if err := e.close(); err != nil {
			t.Errorf("snapshotEngine.close() error = %v", err)
		}
	})

	return e
}

// settle waits until the background loop's in-flight reload (if any) has
// finished, so subsequent fixture mutations cannot race it.
func settle(e *snapshotEngine) {
	e.tryReload()
}

// testPolicy is the fixture used by the engine lifecycle tests.
const testPolicy = "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n"

func writeEnginePolicy(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/policy.csv"
	writeTestPolicy(t, path, testPolicy)

	return path
}

func Test_snapshotEngine_checkUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		storeDown   bool
		wantErr     bool
		wantMissing []accesstypes.Resource
	}{
		{
			name:        "served from snapshot",
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:      "first load failure returns an error",
			storeDown: true,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := testEngine(t, &fakeAdapterFactory{path: writeEnginePolicy(t), failNew: tt.storeDown}, nil)

			gotMissing, err := e.checkUser(context.Background(), "erin", "tenant1", "Read", "employees")
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("checkUser() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_snapshotEngine_waitReady(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		storeDown bool
		timeout   time.Duration
		wantErr   bool
	}{
		{
			name:    "ready after first load",
			timeout: 5 * time.Second,
		},
		{
			name:      "times out while the store is down",
			storeDown: true,
			timeout:   50 * time.Millisecond,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := testEngine(t, &fakeAdapterFactory{path: writeEnginePolicy(t), failNew: tt.storeDown}, nil)

			readyCtx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()
			if err := e.waitReady(readyCtx); (err != nil) != tt.wantErr {
				t.Fatalf("waitReady() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && e.peek() == nil {
				t.Fatal("peek() = nil after waitReady")
			}
		})
	}
}

func Test_snapshotEngine_invalidateReloadsOnNextCheck(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := writeEnginePolicy(t)
	e := testEngine(t, &fakeAdapterFactory{path: path}, nil)

	if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 1 {
		t.Fatalf("checkUser() = (%v, %v), want widgets missing before the write", missing, err)
	}
	settle(e)

	writeTestPolicy(t, path, testPolicy+"p, role:Editor, domain:tenant1, resource:widgets, perm:List, allow\n")

	if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 1 {
		t.Fatalf("checkUser() = (%v, %v), want stale answer before invalidate", missing, err)
	}

	e.invalidate()

	if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 0 {
		t.Fatalf("checkUser() = (%v, %v), want widgets granted after invalidate", missing, err)
	}
}

func Test_snapshotEngine_reloadFailureServesLastGoodSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := writeEnginePolicy(t)
	var reloadErrs atomic.Int64
	opts := defaultClientOptions()
	opts.onReloadError = func(error) { reloadErrs.Add(1) }
	e := testEngine(t, &fakeAdapterFactory{path: path}, opts)

	if _, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees"); err != nil {
		t.Fatalf("checkUser() error = %v", err)
	}
	settle(e)

	// Break the store, then force a reload attempt.
	if err := os.Remove(path); err != nil {
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
}

func Test_snapshotEngine_closeIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := testEngine(t, &fakeAdapterFactory{path: writeEnginePolicy(t)}, nil)

	if _, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees"); err != nil {
		t.Fatalf("checkUser() error = %v", err)
	}
	if err := e.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if err := e.close(); err != nil {
		t.Fatalf("second close() error = %v", err)
	}
	if missing, err := e.checkUser(ctx, "erin", "tenant1", "Read", "employees"); err != nil || len(missing) != 0 {
		t.Fatalf("checkUser() after close = (%v, %v), want served from last snapshot", missing, err)
	}
}

// fakeSignal is an in-process ChangeSignal for tests.
type fakeSignal struct {
	mu           sync.Mutex
	announces    atomic.Int64
	onChange     func()
	watchStarted chan struct{}
	startedOnce  sync.Once
}

func newFakeSignal() *fakeSignal {
	return &fakeSignal{watchStarted: make(chan struct{})}
}

func (f *fakeSignal) Announce(_ context.Context) error {
	f.announces.Add(1)

	return nil
}

func (f *fakeSignal) Watch(ctx context.Context, onChange func()) error {
	f.mu.Lock()
	f.onChange = onChange
	f.mu.Unlock()
	f.startedOnce.Do(func() { close(f.watchStarted) })
	<-ctx.Done()

	return nil
}

func (f *fakeSignal) trigger() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onChange != nil {
		f.onChange()
	}
}

func Test_snapshotEngine_changeSignal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/policy.csv"
	writeTestPolicy(t, path, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n")

	sig := newFakeSignal()
	opts := defaultClientOptions()
	opts.signal = sig
	e := testEngine(t, &fakeAdapterFactory{path: path}, opts)

	if missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets"); err != nil || len(missing) != 1 {
		t.Fatalf("checkUser() = (%v, %v), want widgets missing before the change", missing, err)
	}
	settle(e)

	select {
	case <-sig.watchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("ChangeSignal.Watch was never started")
	}

	// A hint (not a local invalidate) must reload through the background loop.
	writeTestPolicy(t, path, "p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow\np, role:Editor, domain:tenant1, resource:widgets, perm:List, allow\ng, user:erin, role:Editor, domain:tenant1\n")
	sig.trigger()

	deadline := time.Now().Add(5 * time.Second)
	for {
		missing, err := e.checkUser(ctx, "erin", "tenant1", "List", "widgets")
		if err != nil {
			t.Fatalf("checkUser() error = %v", err)
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hint did not propagate a policy change within the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A local policy write announces to other instances.
	e.policyChanged()
	deadline = time.Now().Add(5 * time.Second)
	for sig.announces.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("policyChanged did not announce within the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Domain validation is a live Domains lookup on every check — deliberately
// not cached: domain writes do not flow through access, so a snapshot cache
// could serve a deleted domain until the next reload.
func Test_Client_domainValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domain  accesstypes.Domain
		wantErr bool
	}{
		{
			name:    "known domain passes validation",
			domain:  "tenant1",
			wantErr: false,
		},
		{
			name:    "unknown domain is rejected",
			domain:  "no-such-tenant",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			path := t.TempDir() + "/policy.csv"
			writeTestPolicy(t, path, "p, role:Editor, domain:tenant1, resource:global, perm:Read, allow\ng, user:erin, role:Editor, domain:tenant1\n")

			client, err := New(&fakeDomains{ids: []string{"tenant1"}}, &fakeAdapterFactory{path: path}, WithHeartbeatInterval(time.Hour))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("Client.Close() error = %v", err)
				}
			})

			if err := client.RequireAll(ctx, "erin", tt.domain, "Read"); (err != nil) != tt.wantErr {
				t.Fatalf("RequireAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
