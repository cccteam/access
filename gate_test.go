package access

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/cccteam/ccc/accesstypes"
)

// gateClient builds a Client over a policy file with an inert heartbeat.
func gateClient(t *testing.T, path string, domainIDs []string) *Client {
	t.Helper()
	client, err := New(&fakeDomains{ids: domainIDs}, &fakeAdapterFactory{path: path}, WithHeartbeatInterval(time.Hour))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Client.Close() error = %v", err)
		}
	})

	return client
}

func Test_Client_ValidateEngineEquivalence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// path names a testdata fixture; policy is an inline alternative
		// written to a temp file when set.
		path    string
		policy  string
		domains []string
	}{
		{
			name:    "user policies",
			path:    "testdata/policy_users.csv",
			domains: []string{"tenant1", "tenant2"},
		},
		{
			name:    "field policies",
			path:    "testdata/policy_fields.csv",
			domains: []string{"tenant1", "tenant2"},
		},
		{
			name:    "reader fixture with inheritance",
			path:    "testdata/policy_reader.csv",
			domains: []string{"tenant1", "tenant2"},
		},
		{
			// The `.*` wildcard is the one designed divergence (snapshot
			// interprets it, old casbin exact-matches it inert); the gate
			// must not trip on it.
			name: "wildcard grants do not trip the gate",
			policy: `
p, role:Editor, domain:tenant1, resource:employees.*,    perm:Read, allow
p, role:Editor, domain:tenant1, resource:employees.name, perm:Read, allow
p, role:Editor, domain:tenant1, resource:employees,      perm:Read, allow
g, user:erin,   role:Editor,    domain:tenant1
`,
			domains: []string{"tenant1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path
			if tt.policy != "" {
				path = t.TempDir() + "/policy.csv"
				writeTestPolicy(t, path, tt.policy)
			}

			client := gateClient(t, path, tt.domains)
			if err := client.ValidateEngineEquivalence(context.Background()); err != nil {
				t.Errorf("ValidateEngineEquivalence() error = %v, want nil", err)
			}
		})
	}
}

// A snapshot compiled from different rows than casbin serves must fail the
// gate: this drives the comparison internals with mismatched inputs, which
// cannot be produced through the public API.
func Test_gate_detectsDivergence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	casbinPath := dir + "/casbin.csv"
	writeTestPolicy(t, casbinPath, `
p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow
g, user:erin,   role:Editor,    domain:tenant1
`)
	divergedPath := dir + "/diverged.csv"
	writeTestPolicy(t, divergedPath, `
p, role:Editor, domain:tenant1, resource:employees, perm:Read, allow
p, role:Editor, domain:tenant1, resource:widgets,   perm:List, allow
g, user:erin,   role:Editor,    domain:tenant1
g, user:zoe,    role:Editor,    domain:tenant1
`)

	enforcer, err := mockEnforcer(casbinPath)
	if err != nil {
		t.Fatalf("mockEnforcer() error = %v", err)
	}
	ce := &casbinEngine{Enforcer: func() casbin.IEnforcer { return enforcer }}

	records, err := readCasbinPolicy(fileadapter.NewAdapter(divergedPath))
	if err != nil {
		t.Fatalf("readCasbinPolicy() error = %v", err)
	}
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		t.Fatalf("newSnapshot() error = %v", err)
	}

	universe, err := buildGateUniverse(ce, records, []accesstypes.Domain{"tenant1"})
	if err != nil {
		t.Fatalf("buildGateUniverse() error = %v", err)
	}

	g := &gate{ctx: context.Background(), casbin: ce, snap: snap, enum: newSnapshotEnumerator(snap)}
	g.compareStructure(universe)
	g.compareBehavior(universe)

	if g.mismatchCount == 0 {
		t.Fatal("gate detected no mismatches between diverged engines")
	}
	joined := strings.Join(g.mismatches, "\n")
	if !strings.Contains(joined, "widgets") {
		t.Errorf("mismatches do not mention the diverged grant:\n%s", joined)
	}
	if !strings.Contains(joined, "zoe") {
		t.Errorf("mismatches do not mention the diverged membership:\n%s", joined)
	}
}
