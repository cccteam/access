package access

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

// The differential suite is the v0.10 correctness argument: the casbin
// evaluator and the snapshot evaluator answer every check identically over the
// same casbin_rule rows (two engines, one store). Fixtures cover curated
// cases; the seeded property test and fuzz target sweep generated policies.
// Wildcard (.*) grants are excluded from generation: old casbin exact-matches
// them to nothing while the snapshot interprets them, which is the one
// designed divergence.

// policyUniverse is everything mentioned by a policy, plus probes for values
// nothing mentions, so the comparison matrix covers unknown subjects,
// domains, permissions, resources, and fields.
type policyUniverse struct {
	domains   []accesstypes.Domain
	users     []accesstypes.User
	roles     []accesstypes.Role
	perms     []accesstypes.Permission
	resources []accesstypes.Resource
}

// universeFromCSV derives the comparison universe from a casbin CSV fixture.
func universeFromCSV(t *testing.T, path string) *policyUniverse {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	domains := map[accesstypes.Domain]bool{}
	users := map[accesstypes.User]bool{}
	roles := map[accesstypes.Role]bool{}
	perms := map[accesstypes.Permission]bool{}
	resources := map[accesstypes.Resource]bool{}

	for line := range strings.Lines(string(data)) {
		tokens := strings.Split(strings.TrimSpace(line), ",")
		for i, tok := range tokens {
			tokens[i] = strings.TrimSpace(tok)
		}
		switch {
		case len(tokens) >= 5 && tokens[0] == "p":
			if user, ok := strings.CutPrefix(tokens[1], "user:"); ok {
				users[accesstypes.User(user)] = true
			}
			if role, ok := strings.CutPrefix(tokens[1], "role:"); ok {
				roles[accesstypes.Role(role)] = true
			}
			domains[accesstypes.Domain(strings.TrimPrefix(tokens[2], "domain:"))] = true
			res := accesstypes.Resource(strings.TrimPrefix(tokens[3], "resource:"))
			resources[res] = true
			if base, _ := splitResourceField(string(res)); base != string(res) {
				resources[accesstypes.Resource(base)] = true
			} else {
				resources[accesstypes.Resource(base+".probe")] = true
			}
			perms[accesstypes.Permission(strings.TrimPrefix(tokens[4], "perm:"))] = true
		case len(tokens) >= 4 && tokens[0] == "g":
			if user, ok := strings.CutPrefix(tokens[1], "user:"); ok {
				users[accesstypes.User(user)] = true
			}
			if role, ok := strings.CutPrefix(tokens[1], "role:"); ok {
				roles[accesstypes.Role(role)] = true
			}
			roles[accesstypes.Role(strings.TrimPrefix(tokens[2], "role:"))] = true
			domains[accesstypes.Domain(strings.TrimPrefix(tokens[3], "domain:"))] = true
		}
	}

	u := &policyUniverse{
		domains: []accesstypes.Domain{"unknown-domain"},
		users:   []accesstypes.User{"unknown-user", accesstypes.NoopUser},
		roles:   []accesstypes.Role{"unknown-role"},
		perms:   []accesstypes.Permission{"UnknownPerm"},
		resources: []accesstypes.Resource{
			"unknown-resource", "unknown-resource.field", accesstypes.GlobalResource,
		},
	}
	for d := range domains {
		u.domains = append(u.domains, d)
	}
	for user := range users {
		u.users = append(u.users, user)
	}
	for r := range roles {
		u.roles = append(u.roles, r)
	}
	for p := range perms {
		u.perms = append(u.perms, p)
	}
	for r := range resources {
		u.resources = append(u.resources, r)
	}

	return u
}

// diffEngines builds both evaluators over the same CSV rows.
func diffEngines(t *testing.T, path string) (*casbinEngine, *snapshot) {
	t.Helper()

	enforcer, err := mockEnforcer(path)
	if err != nil {
		t.Fatalf("mockEnforcer() error = %v", err)
	}
	ce := &casbinEngine{Enforcer: func() casbin.IEnforcer { return enforcer }}

	records, err := readCasbinPolicy(fileadapter.NewAdapter(path))
	if err != nil {
		t.Fatalf("readCasbinPolicy() error = %v", err)
	}
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		t.Fatalf("newSnapshot() error = %v", err)
	}

	return ce, snap
}

// assertEngineEquivalence compares both engines over the full
// domain x subject x permission x resource matrix of the universe, checking
// resources one at a time and as one batch.
func assertEngineEquivalence(t *testing.T, path string, u *policyUniverse) {
	t.Helper()

	ctx := context.Background()
	ce, snap := diffEngines(t, path)

	for _, domain := range u.domains {
		for _, perm := range u.perms {
			for _, user := range u.users {
				want, err := ce.checkUser(ctx, user, domain, perm, u.resources...)
				if err != nil {
					t.Fatalf("casbinEngine.checkUser() error = %v", err)
				}
				got := snap.checkUser(user, domain, perm, u.resources...)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("checkUser(%q, %q, %q) casbin vs snapshot (-casbin +snapshot):\n%s", user, domain, perm, diff)
				}
			}
			for _, role := range u.roles {
				want, err := ce.checkRole(ctx, role, domain, perm, u.resources...)
				if err != nil {
					t.Fatalf("casbinEngine.checkRole() error = %v", err)
				}
				got := snap.checkRole(role, domain, perm, u.resources...)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("checkRole(%q, %q, %q) casbin vs snapshot (-casbin +snapshot):\n%s", role, domain, perm, diff)
				}
			}
		}
	}
}

func Test_engineEquivalence_fixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "user policies", path: "testdata/policy_users.csv"},
		{name: "field policies", path: "testdata/policy_fields.csv"},
		{name: "base policy", path: "testdata/policy.csv"},
		{name: "add delete", path: "testdata/policy_add_delete.csv"},
		{name: "add permissions to role", path: "testdata/policy_addpermissionstorole.csv"},
		{name: "add role", path: "testdata/policy_addrole.csv"},
		{name: "add user roles", path: "testdata/policy_adduserroles.csv"},
		{name: "delete permissions from role", path: "testdata/policy_deletepermissionsfromrole.csv"},
		{name: "delete role", path: "testdata/policy_deleterole.csv"},
		{name: "delete users from role", path: "testdata/policy_deleteusersfromrole.csv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertEngineEquivalence(t, tt.path, universeFromCSV(t, tt.path))
		})
	}
}

// generatePolicy writes a random casbin CSV (no wildcard rows) and returns its
// path with the universe used to generate it.
func generatePolicy(t *testing.T, rng *rand.Rand) (string, *policyUniverse) {
	t.Helper()

	domains := []accesstypes.Domain{"tenant1", "tenant2"}
	users := []accesstypes.User{"u1", "u2", "u3"}
	roles := []accesstypes.Role{"r1", "r2", "r3"}
	perms := []accesstypes.Permission{"Read", "Update", "List"}
	bases := []string{"global", "employees", "widgets"}
	fields := []string{"a", "b"}

	pick := func(n int) int { return rng.IntN(n) }

	var b strings.Builder
	for range pick(20) + 1 {
		var sub string
		switch pick(12) {
		case 0:
			sub = accesstypes.NoopUser // inert on both engines
		case 1:
			sub = string(users[pick(len(users))]) // unprefixed: inert on both engines
		case 2, 3:
			sub = "user:" + string(users[pick(len(users))])
		default:
			sub = "role:" + string(roles[pick(len(roles))])
		}
		obj := bases[pick(len(bases))]
		if pick(2) == 0 {
			obj += "." + fields[pick(len(fields))]
		}
		fmt.Fprintf(&b, "p, %s, domain:%s, resource:%s, perm:%s, allow\n", sub, domains[pick(len(domains))], obj, perms[pick(len(perms))])
	}
	for range pick(10) + 1 {
		var member string
		switch pick(12) {
		case 0:
			member = accesstypes.NoopUser
		case 1:
			member = string(users[pick(len(users))]) // unprefixed: inert on both engines
		case 2, 3:
			member = "role:" + string(roles[pick(len(roles))]) // inheritance
		default:
			member = "user:" + string(users[pick(len(users))])
		}
		fmt.Fprintf(&b, "g, %s, role:%s, domain:%s\n", member, roles[pick(len(roles))], domains[pick(len(domains))])
	}

	path := t.TempDir() + "/policy.csv"
	writeTestPolicy(t, path, b.String())

	u := &policyUniverse{
		domains: slices.Concat(domains, []accesstypes.Domain{"unknown-domain"}),
		users:   slices.Concat(users, []accesstypes.User{"unknown-user", accesstypes.NoopUser}),
		roles:   slices.Concat(roles, []accesstypes.Role{"unknown-role"}),
		perms:   slices.Concat(perms, []accesstypes.Permission{"UnknownPerm"}),
	}
	for _, base := range bases {
		u.resources = append(u.resources, accesstypes.Resource(base))
		for _, f := range fields {
			u.resources = append(u.resources, accesstypes.Resource(base+"."+f))
		}
		u.resources = append(u.resources, accesstypes.Resource(base+".zz"))
	}
	u.resources = append(u.resources, "unknown-resource")

	return path, u
}

func runEquivalenceProperty(t *testing.T, seed uint64) {
	t.Helper()

	rng := rand.New(rand.NewPCG(seed, 0)) //nolint:gosec // deterministic seeded generation for a reproducible property test
	path, u := generatePolicy(t, rng)
	assertEngineEquivalence(t, path, u)
	if t.Failed() {
		data, _ := os.ReadFile(path)
		t.Logf("seed %d policy:\n%s", seed, data)
	}
}

func Test_engineEquivalence_property(t *testing.T) {
	t.Parallel()

	for seed := uint64(1); seed <= 64; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			t.Parallel()
			runEquivalenceProperty(t, seed)
		})
	}
}

func Fuzz_engineEquivalence(f *testing.F) {
	for seed := uint64(1); seed <= 8; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		runEquivalenceProperty(t, seed)
	})
}

// benchmarkPolicy builds a mid-size policy: 3 domains, 10 roles with 60
// grants each, 100 users with 3 roles each.
func benchmarkPolicy(b *testing.B) string {
	b.Helper()

	var sb strings.Builder
	for d := range 3 {
		for r := range 10 {
			for g := range 60 {
				res := fmt.Sprintf("res%d", g%20)
				if g%3 != 0 {
					res += fmt.Sprintf(".f%d", g%7)
				}
				fmt.Fprintf(&sb, "p, role:r%d, domain:d%d, resource:%s, perm:P%d, allow\n", r, d, res, g%6)
			}
		}
		for u := range 100 {
			for r := range 3 {
				fmt.Fprintf(&sb, "g, user:u%d, role:r%d, domain:d%d\n", u, (u+r)%10, d)
			}
		}
	}

	path := b.TempDir() + "/policy.csv"
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatalf("os.WriteFile() error = %v", err)
	}

	return path
}

func Benchmark_snapshot_checkUser(b *testing.B) {
	path := benchmarkPolicy(b)
	records, err := readCasbinPolicy(fileadapter.NewAdapter(path))
	if err != nil {
		b.Fatalf("readCasbinPolicy() error = %v", err)
	}
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		b.Fatalf("newSnapshot() error = %v", err)
	}

	resources := []accesstypes.Resource{"res1", "res1.f1", "res5.f3", "res19", "nosuch"}
	b.ResetTimer()
	for range b.N {
		snap.checkUser("u42", "d1", "P2", resources...)
	}
}

func Benchmark_casbin_checkUser(b *testing.B) {
	path := benchmarkPolicy(b)
	enforcer, err := mockEnforcer(path)
	if err != nil {
		b.Fatalf("mockEnforcer() error = %v", err)
	}
	ce := &casbinEngine{Enforcer: func() casbin.IEnforcer { return enforcer }}

	ctx := context.Background()
	resources := []accesstypes.Resource{"res1", "res1.f1", "res5.f3", "res19", "nosuch"}
	b.ResetTimer()
	for range b.N {
		if _, err := ce.checkUser(ctx, "u42", "d1", "P2", resources...); err != nil {
			b.Fatalf("checkUser() error = %v", err)
		}
	}
}
