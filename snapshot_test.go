package access

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"github.com/google/go-cmp/cmp"
)

// roleSubject and userSubject are fixture shorthands.
func roleSubject(name string) policy.Subject {
	return policy.Subject{Kind: policy.SubjectRole, Name: name}
}

func userSubject(name string) policy.Subject {
	return policy.Subject{Kind: policy.SubjectUser, Name: name}
}

// compileSnapshot compiles fixture records through the shared compiler.
func compileSnapshot(t *testing.T, records *policy.Records) *snapshot {
	t.Helper()
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		t.Fatalf("newSnapshot() error = %v", err)
	}

	return snap
}

// Test_splitResourceField pins the shared splitting rule: checked resources
// and stored grants split identically, on the LAST dot.
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

// missingFromDecisions derives the legacy missing list from per-resource
// decisions: every resource whose decision is denied, in input order. The
// fixtures here carry no conditions, so it also asserts nothing came back
// conditional.
func missingFromDecisions(t *testing.T, resources []accesstypes.Resource, decisions []resourceDecision) []accesstypes.Resource {
	t.Helper()
	if len(decisions) != len(resources) {
		t.Fatalf("decideUserResources() returned %d decisions for %d resources", len(decisions), len(resources))
	}
	missing := make([]accesstypes.Resource, 0)
	for i, d := range decisions {
		if len(d.conditions) > 0 {
			t.Fatalf("decideUserResources()[%d] = conditional %v, want unconditional decisions from a condition-free store", i, d.conditions)
		}
		if !d.granted {
			missing = append(missing, resources[i])
		}
	}

	return missing
}

func Test_snapshot_decideUserResources(t *testing.T) {
	t.Parallel()

	snap := compileSnapshot(t, &policy.Records{
		Grants: []policy.Grant{
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees", Field: "name"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Editor"), Perm: "Read", Resource: "documents", Field: "*"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Auditor"), Perm: "List", Resource: "widgets"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Chief"), Perm: "Read", Resource: "budgets"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: userSubject("dana"), Perm: "List", Resource: "widgets"},
		},
		Memberships: []policy.Membership{
			{Scope: accesstypes.DomainScope("tenant1"), Member: userSubject("erin"), Role: "Editor"},
			{Scope: accesstypes.DomainScope("tenant1"), Member: userSubject("erin"), Role: "Auditor"},
			{Scope: accesstypes.DomainScope("tenant1"), Member: roleSubject("Editor"), Role: "Chief"},
		},
	})

	type args struct {
		user      accesstypes.User
		scope     accesstypes.Scope
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
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "named field grant",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees.name"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "endpoint grant gives no field visibility",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees.salary"}},
			wantMissing: []accesstypes.Resource{"employees.salary"},
		},
		{
			name:        "wildcard grant covers unknown fields by implication",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"documents.title", "documents.body"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "wildcard grant does not grant the endpoint",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"documents"}},
			wantMissing: []accesstypes.Resource{"documents"},
		},
		{
			name:        "grants combine across roles",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "List", resources: []accesstypes.Resource{"widgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "role inheritance is folded transitively",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"budgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "direct user grant without membership",
			args:        args{user: "dana", scope: accesstypes.DomainScope("tenant1"), perm: "List", resources: []accesstypes.Resource{"widgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "grants stay inside their domain",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant2"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown user",
			args:        args{user: "stranger", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown permission",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Fly", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown resource",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"spaceships"}},
			wantMissing: []accesstypes.Resource{"spaceships"},
		},
		{
			name:        "missing preserves input order",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"spaceships", "employees", "employees.salary"}},
			wantMissing: []accesstypes.Resource{"spaceships", "employees.salary"},
		},
		{
			name:        "no resources yields empty missing",
			args:        args{user: "erin", scope: accesstypes.DomainScope("tenant1"), perm: "Read"},
			wantMissing: []accesstypes.Resource{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decisions := snap.decideUserResources(tt.args.user, tt.args.scope, tt.args.perm, tt.args.resources...)
			gotMissing := missingFromDecisions(t, tt.args.resources, decisions)
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("snapshot.decideUserResources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_snapshot_decideUserResources_conditions pins conditional coverage: a
// resource covered only by conditional grants decides Conditional carrying
// the covering grants' condition texts (OR semantics, canonically ordered,
// deduplicated); any unconditional cover settles the decision as Granted; no
// cover at all stays Denied. The texts are opaque — nothing here parses or
// evaluates them.
func Test_snapshot_decideUserResources_conditions(t *testing.T) {
	t.Parallel()

	snap := compileSnapshot(t, &policy.Records{
		Grants: []policy.Grant{
			{Scope: tenant1Scope, Subject: roleSubject("DraftEditor"), Perm: "Update", Resource: "loans", Field: "*", Condition: "state = 'new'"},
			{Scope: tenant1Scope, Subject: roleSubject("ServicingAgent"), Perm: "Update", Resource: "loans", Field: "phone", Condition: "state IN ('new', 'approved')"},
			{Scope: tenant1Scope, Subject: roleSubject("Auditor"), Perm: "Read", Resource: "reports", Condition: "region = @subject"},
			{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Read", Resource: "reports"},
			{Scope: tenant1Scope, Subject: roleSubject("Owner"), Perm: "Update", Resource: "notes", Field: "body", Condition: "owner = @subject"},
			{Scope: tenant1Scope, Subject: roleSubject("CoOwner"), Perm: "Update", Resource: "notes", Field: "body", Condition: "owner = @subject"},
			{Scope: tenant1Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "docs", Field: "*"},
			{Scope: tenant1Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "docs", Field: "title", Condition: "unpublished = false"},
			{Scope: tenant1Scope, Subject: userSubject("hank"), Perm: "Update", Resource: "notes", Field: "body", Condition: "owner = @subject"},
		},
		Memberships: []policy.Membership{
			{Scope: tenant1Scope, Member: userSubject("dana"), Role: "DraftEditor"},
			{Scope: tenant1Scope, Member: userSubject("dana"), Role: "ServicingAgent"},
			{Scope: tenant1Scope, Member: userSubject("erin"), Role: "Auditor"},
			{Scope: tenant1Scope, Member: userSubject("frank"), Role: "Auditor"},
			{Scope: tenant1Scope, Member: userSubject("frank"), Role: "Chief"},
			{Scope: tenant1Scope, Member: userSubject("gina"), Role: "Owner"},
			{Scope: tenant1Scope, Member: userSubject("gina"), Role: "CoOwner"},
			{Scope: tenant1Scope, Member: userSubject("carol"), Role: "Editor"},
		},
	})

	type args struct {
		user      accesstypes.User
		scope     accesstypes.Scope
		perm      accesstypes.Permission
		resources []accesstypes.Resource
	}
	tests := []struct {
		name string
		args args
		want []resourceDecision
	}{
		{
			name: "conditional covering set combines across roles in text order",
			args: args{user: "dana", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"loans.phone"}},
			want: []resourceDecision{{conditions: []string{"state = 'new'", "state IN ('new', 'approved')"}}},
		},
		{
			name: "conditional wildcard covers unknown fields by implication",
			args: args{user: "dana", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"loans.term"}},
			want: []resourceDecision{{conditions: []string{"state = 'new'"}}},
		},
		{
			name: "conditional wildcard does not cover the endpoint",
			args: args{user: "dana", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"loans"}},
			want: []resourceDecision{{}},
		},
		{
			name: "wildcard check answers from wildcard coverage only",
			args: args{user: "dana", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"loans.*"}},
			want: []resourceDecision{{conditions: []string{"state = 'new'"}}},
		},
		{
			name: "conditional endpoint grant",
			args: args{user: "erin", scope: tenant1Scope, perm: "Read", resources: []accesstypes.Resource{"reports"}},
			want: []resourceDecision{{conditions: []string{"region = @subject"}}},
		},
		{
			name: "any unconditional cover settles as granted across roles",
			args: args{user: "frank", scope: tenant1Scope, perm: "Read", resources: []accesstypes.Resource{"reports"}},
			want: []resourceDecision{{granted: true}},
		},
		{
			name: "identical condition texts deduplicate",
			args: args{user: "gina", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"notes.body"}},
			want: []resourceDecision{{conditions: []string{"owner = @subject"}}},
		},
		{
			name: "direct user grant carries its condition",
			args: args{user: "hank", scope: tenant1Scope, perm: "Update", resources: []accesstypes.Resource{"notes.body"}},
			want: []resourceDecision{{conditions: []string{"owner = @subject"}}},
		},
		{
			name: "unconditional wildcard settles a conditionally granted field",
			args: args{user: "carol", scope: tenant1Scope, perm: "Read", resources: []accesstypes.Resource{"docs.title", "docs.other"}},
			want: []resourceDecision{{granted: true}, {granted: true}},
		},
		{
			name: "conditional grants stay inside their scope",
			args: args{user: "dana", scope: tenant2Scope, perm: "Update", resources: []accesstypes.Resource{"loans.phone"}},
			want: []resourceDecision{{}},
		},
		{
			name: "uncovered resource stays denied",
			args: args{user: "erin", scope: tenant1Scope, perm: "Read", resources: []accesstypes.Resource{"employees"}},
			want: []resourceDecision{{}},
		},
		{
			name: "unknown permission fails closed",
			args: args{user: "dana", scope: tenant1Scope, perm: "Fly", resources: []accesstypes.Resource{"loans.phone"}},
			want: []resourceDecision{{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := snap.decideUserResources(tt.args.user, tt.args.scope, tt.args.perm, tt.args.resources...)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(resourceDecision{})); diff != "" {
				t.Errorf("snapshot.decideUserResources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_snapshot_zeroConditionsMatchesRBAC pins the "no conditions ⇒ pure
// RBAC" invariant: over a full sweep of a condition-free store, the decision
// path grants exactly where the untouched unconditional path (allowed, via
// missingResources) grants, and nothing is ever Conditional.
func Test_snapshot_zeroConditionsMatchesRBAC(t *testing.T) {
	t.Parallel()

	snap := compileSnapshot(t, &policy.Records{
		Grants: []policy.Grant{
			{Scope: tenant1Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees"},
			{Scope: tenant1Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees", Field: "name"},
			{Scope: tenant1Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "documents", Field: "*"},
			{Scope: tenant1Scope, Subject: roleSubject("Auditor"), Perm: "List", Resource: "widgets"},
			{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Read", Resource: "budgets"},
			{Scope: tenant2Scope, Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees", Field: "*"},
			{Scope: tenant1Scope, Subject: userSubject("dana"), Perm: "List", Resource: "widgets"},
		},
		Memberships: []policy.Membership{
			{Scope: tenant1Scope, Member: userSubject("erin"), Role: "Editor"},
			{Scope: tenant1Scope, Member: userSubject("erin"), Role: "Auditor"},
			{Scope: tenant1Scope, Member: roleSubject("Editor"), Role: "Chief"},
			{Scope: tenant2Scope, Member: userSubject("dana"), Role: "Editor"},
		},
	})

	users := []accesstypes.User{"erin", "dana", "stranger"}
	scopes := []accesstypes.Scope{tenant1Scope, tenant2Scope, accesstypes.GlobalScope()}
	perms := []accesstypes.Permission{"Read", "List", "Fly"}
	resources := []accesstypes.Resource{
		"employees", "employees.name", "employees.salary", "employees.*",
		"documents", "documents.title", "documents.*",
		"widgets", "budgets", "spaceships", "spaceships.crew",
	}

	for _, user := range users {
		for _, scope := range scopes {
			for _, perm := range perms {
				decisions := snap.decideUserResources(user, scope, perm, resources...)
				missing := snap.missingResources(snap.userGrants(scope, user), perm, resources)
				for i, resource := range resources {
					wantGranted := !slices.Contains(missing, resource)
					if decisions[i].granted != wantGranted {
						t.Errorf("decide(%s, %s, %s, %s).granted = %v, want %v", user, scope, perm, resource, decisions[i].granted, wantGranted)
					}
					if len(decisions[i].conditions) != 0 {
						t.Errorf("decide(%s, %s, %s, %s) = conditional %v, want unconditional from a condition-free store", user, scope, perm, resource, decisions[i].conditions)
					}
				}
			}
		}
	}
}

// Test_newSnapshot_conditionValidation pins the one structural rule that is
// already decided: a condition never attaches to a scope-wide grant — there
// is no row for it to evaluate against — and such a record fails the load.
// No other validation exists (syntax needs the expression language).
func Test_newSnapshot_conditionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		grant   policy.Grant
		wantErr bool
	}{
		{
			name:    "conditional scope-wide grant in a tenant scope fails the load",
			grant:   policy.Grant{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Approve", Resource: "", Condition: "state = 'new'"},
			wantErr: true,
		},
		{
			name:    "conditional scope-wide grant in the global scope fails the load",
			grant:   policy.Grant{Scope: accesstypes.GlobalScope(), Subject: roleSubject("Admin"), Perm: "Export", Resource: "", Condition: "state = 'new'"},
			wantErr: true,
		},
		{
			name:  "unconditional scope-wide grant compiles",
			grant: policy.Grant{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Approve", Resource: ""},
		},
		{
			name:  "conditional resource grant compiles",
			grant: policy.Grant{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Read", Resource: "budgets", Condition: "state = 'new'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newSnapshot(&policy.Records{Grants: []policy.Grant{tt.grant}}, time.Now())
			if (err != nil) != tt.wantErr {
				t.Errorf("newSnapshot() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test_newDecisions pins the translation to the public Decisions, including
// the shared-group emission: resources sharing a covering condition set get
// ONE ConditionGroup listing every member (first-appearance input order,
// deduplicated), the same group value reachable from each member's Decision;
// a distinct set is its own group. The group's Condition payload is the
// accesstypes placeholder until the expression language lands, so the texts
// do not cross the seam yet.
func Test_newDecisions(t *testing.T) {
	t.Parallel()

	sharedGroup := accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"loans.phone", "loans.term"}}

	tests := []struct {
		name      string
		resources []accesstypes.Resource
		decisions []resourceDecision
		want      accesstypes.Decisions
	}{
		{
			name:      "granted",
			resources: []accesstypes.Resource{"employees.name"},
			decisions: []resourceDecision{{granted: true}},
			want:      accesstypes.Decisions{"employees.name": accesstypes.Granted()},
		},
		{
			name:      "denied",
			resources: []accesstypes.Resource{"employees.name"},
			decisions: []resourceDecision{{}},
			want:      accesstypes.Decisions{"employees.name": accesstypes.Denied()},
		},
		{
			name:      "lone conditional carries one group naming the resource",
			resources: []accesstypes.Resource{"employees.name"},
			decisions: []resourceDecision{{conditions: []string{"owner = @subject"}}},
			want: accesstypes.Decisions{
				"employees.name": accesstypes.Conditional(accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"employees.name"}}),
			},
		},
		{
			name:      "identical covering sets share one group in each member's decision",
			resources: []accesstypes.Resource{"loans.phone", "loans.term"},
			decisions: []resourceDecision{
				{conditions: []string{"state = 'new'"}},
				{conditions: []string{"state = 'new'"}},
			},
			want: accesstypes.Decisions{
				"loans.phone": accesstypes.Conditional(sharedGroup),
				"loans.term":  accesstypes.Conditional(sharedGroup),
			},
		},
		{
			name:      "distinct covering sets get distinct groups",
			resources: []accesstypes.Resource{"loans.phone", "loans.notes"},
			decisions: []resourceDecision{
				{conditions: []string{"crew IN subject.crews", "state = 'open'"}},
				{conditions: []string{"crew IN subject.crews"}},
			},
			want: accesstypes.Decisions{
				"loans.phone": accesstypes.Conditional(accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"loans.phone"}}),
				"loans.notes": accesstypes.Conditional(accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"loans.notes"}}),
			},
		},
		{
			name:      "grouping never absorbs granted or denied members",
			resources: []accesstypes.Resource{"loans", "loans.phone", "loans.term", "secrets"},
			decisions: []resourceDecision{
				{granted: true},
				{conditions: []string{"state = 'new'"}},
				{conditions: []string{"state = 'new'"}},
				{},
			},
			want: accesstypes.Decisions{
				"loans":       accesstypes.Granted(),
				"loans.phone": accesstypes.Conditional(sharedGroup),
				"loans.term":  accesstypes.Conditional(sharedGroup),
				"secrets":     accesstypes.Denied(),
			},
		},
		{
			name:      "duplicate checked resource appears once in its group",
			resources: []accesstypes.Resource{"loans.phone", "loans.phone"},
			decisions: []resourceDecision{
				{conditions: []string{"state = 'new'"}},
				{conditions: []string{"state = 'new'"}},
			},
			want: accesstypes.Decisions{
				"loans.phone": accesstypes.Conditional(accesstypes.ConditionGroup{Resources: []accesstypes.Resource{"loans.phone"}}),
			},
		},
		{
			name:      "empty batch",
			resources: []accesstypes.Resource{},
			decisions: []resourceDecision{},
			want:      accesstypes.Decisions{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := newDecisions(tt.resources, tt.decisions)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(accesstypes.Decision{}, accesstypes.Condition{})); diff != "" {
				t.Errorf("newDecisions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_snapshot_scopeWideChecks pins the resource-less check path: a
// scope-wide grant compiles under the empty resource name — unreachable from
// data, since every write boundary validates resource names non-empty — and
// is answered by the base-name check methods. Resource grants never satisfy a
// scope-wide check and vice versa.
func Test_snapshot_scopeWideChecks(t *testing.T) {
	t.Parallel()

	globalScope := accesstypes.GlobalScope()
	records := &policy.Records{
		Grants: []policy.Grant{
			{Scope: globalScope, Subject: roleSubject("Admin"), Perm: "Export", Resource: ""},
			{Scope: globalScope, Subject: roleSubject("Admin"), Perm: "Read", Resource: "employees"},
			{Scope: tenant1Scope, Subject: roleSubject("Chief"), Perm: "Approve", Resource: ""},
		},
		Memberships: []policy.Membership{
			{Scope: globalScope, Member: userSubject("alice"), Role: "Admin"},
			{Scope: tenant1Scope, Member: userSubject("carol"), Role: "Chief"},
		},
	}
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		t.Fatalf("newSnapshot() error = %v", err)
	}

	tests := []struct {
		name  string
		check func() bool
		want  bool
	}{
		{name: "user holds scope-wide perm through role", check: func() bool { return snap.checkUser("alice", globalScope, "Export") }, want: true},
		{name: "role holds its scope-wide perm", check: func() bool { return snap.checkRole("Admin", globalScope, "Export") }, want: true},
		{name: "resource grant does not satisfy a scope-wide check", check: func() bool { return snap.checkUser("alice", globalScope, "Read") }},
		{name: "scope-wide grant is partitioned by scope", check: func() bool { return snap.checkUser("alice", tenant1Scope, "Export") }},
		{name: "tenant scope-wide grant works in its scope", check: func() bool { return snap.checkUser("carol", tenant1Scope, "Approve") }, want: true},
		{name: "a tenant named global is not the global scope", check: func() bool { return snap.checkUser("alice", accesstypes.DomainScope("global"), "Export") }},
		{name: "unknown perm fails closed", check: func() bool { return snap.checkUser("alice", globalScope, "Fly") }},
		{name: "unknown user fails closed", check: func() bool { return snap.checkUser("stranger", globalScope, "Export") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.check(); got != tt.want {
				t.Errorf("scope-wide check = %v, want %v", got, tt.want)
			}
		})
	}

	// The scope-wide grant does not leak into the resource batch path either:
	// checking the empty-string resource through decideUserResources is not a
	// public spelling, and real resources stay ungranted.
	if decisions := snap.decideUserResources("alice", globalScope, "Export", "employees"); decisions[0].granted {
		t.Errorf("decideUserResources() = %v, want employees denied: scope-wide grants must not satisfy resource checks", decisions)
	}
}

func Test_snapshot_checkRoleResources(t *testing.T) {
	t.Parallel()

	snap := compileSnapshot(t, &policy.Records{
		Grants: []policy.Grant{
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Editor"), Perm: "Read", Resource: "employees"},
			{Scope: accesstypes.DomainScope("tenant1"), Subject: roleSubject("Chief"), Perm: "Read", Resource: "budgets"},
		},
		Memberships: []policy.Membership{
			{Scope: accesstypes.DomainScope("tenant1"), Member: roleSubject("Editor"), Role: "Chief"},
			{Scope: accesstypes.DomainScope("tenant1"), Member: roleSubject("Loop1"), Role: "Loop2"},
			{Scope: accesstypes.DomainScope("tenant1"), Member: roleSubject("Loop2"), Role: "Loop1"},
		},
	})

	type args struct {
		role      accesstypes.Role
		scope     accesstypes.Scope
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
			args:        args{role: "Editor", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "inherited grant",
			args:        args{role: "Editor", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"budgets"}},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name:        "inheritance is one-way",
			args:        args{role: "Chief", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "inheritance cycle compiles and denies safely",
			args:        args{role: "Loop1", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "unknown role",
			args:        args{role: "Ghost", scope: accesstypes.DomainScope("tenant1"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
		{
			name:        "wrong domain",
			args:        args{role: "Editor", scope: accesstypes.DomainScope("tenant2"), perm: "Read", resources: []accesstypes.Resource{"employees"}},
			wantMissing: []accesstypes.Resource{"employees"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing := snap.checkRoleResources(tt.args.role, tt.args.scope, tt.args.perm, tt.args.resources...)
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("snapshot.checkRoleResources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Shared tenant scopes for the package's test fixtures.
var (
	tenant1Scope = accesstypes.DomainScope("tenant1")
	tenant2Scope = accesstypes.DomainScope("tenant2")
)

// engineFakeStore returns a fakeStore seeded with the engine lifecycle
// fixture: Editor holds Read on employees in tenant1, erin is an Editor.
func engineFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	ctx := context.Background()
	store := newFakeStore()
	for _, err := range []error{
		store.InsertRole(ctx, tenant1Scope, "Editor"),
		store.InsertGrant(ctx, tenant1Scope, "Editor", "Read", "employees", "", ""),
		store.InsertUserRole(ctx, tenant1Scope, "erin", "Editor"),
	} {
		if err != nil {
			t.Fatalf("seeding fake store: %v", err)
		}
	}

	return store
}

// grantWidgets simulates another instance's policy write: it lands in the
// store without notifying this instance's engine.
func grantWidgets(t *testing.T, store *fakeStore) {
	t.Helper()
	if err := store.InsertGrant(context.Background(), tenant1Scope, "Editor", "List", "widgets", "", ""); err != nil {
		t.Fatalf("InsertGrant() error = %v", err)
	}
}

// testEngine builds a snapshotEngine whose background loop is effectively
// inert (1h heartbeat) so tests drive reloads deterministically, and whose
// goroutines stop at test end.
func testEngine(t *testing.T, store Store, opts *clientOptions) *snapshotEngine {
	t.Helper()
	if opts == nil {
		opts = defaultClientOptions()
	}
	opts.heartbeatInterval = time.Hour
	e := newSnapshotEngine(store, opts)
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
	e.tryReload(context.Background())
}

func Test_snapshotEngine_checkUserResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		storeDown bool
		wantErr   bool
	}{
		{
			name: "served from snapshot",
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
			store := engineFakeStore(t)
			if tt.storeDown {
				store.setFail(errors.New("store down"))
			}
			e := testEngine(t, store, nil)

			got, err := e.checkUserResources(context.Background(), "erin", tenant1Scope, "Read", "employees")
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != 1 || !got[0].granted {
				t.Errorf("checkUserResources() = %v, want employees granted", got)
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
			store := engineFakeStore(t)
			if tt.storeDown {
				store.setFail(errors.New("store down"))
			}
			e := testEngine(t, store, nil)

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
	store := engineFakeStore(t)
	e := testEngine(t, store, nil)

	if got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "List", "widgets"); err != nil || got[0].granted {
		t.Fatalf("checkUser() = (%v, %v), want widgets denied before the write", got, err)
	}
	settle(e)

	grantWidgets(t, store)

	if got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "List", "widgets"); err != nil || got[0].granted {
		t.Fatalf("checkUser() = (%v, %v), want stale answer before invalidate", got, err)
	}

	e.invalidate()

	if got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "List", "widgets"); err != nil || !got[0].granted {
		t.Fatalf("checkUser() = (%v, %v), want widgets granted after invalidate", got, err)
	}
}

func Test_snapshotEngine_reloadFailureServesLastGoodSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := engineFakeStore(t)
	var reloadErrs atomic.Int64
	opts := defaultClientOptions()
	opts.onReloadError = func(error) { reloadErrs.Add(1) }
	e := testEngine(t, store, opts)

	if _, err := e.checkUserResources(ctx, "erin", tenant1Scope, "Read", "employees"); err != nil {
		t.Fatalf("checkUser() error = %v", err)
	}
	settle(e)

	// Break the store, then force a reload attempt.
	store.setFail(errors.New("store down"))
	e.invalidate()

	got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "Read", "employees")
	if err != nil {
		t.Fatalf("checkUser() error = %v, want stale snapshot served", err)
	}
	if !got[0].granted {
		t.Fatalf("checkUser() = %v, want granted from stale snapshot", got)
	}
}

func Test_snapshotEngine_closeIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := testEngine(t, engineFakeStore(t), nil)

	if _, err := e.checkUserResources(ctx, "erin", tenant1Scope, "Read", "employees"); err != nil {
		t.Fatalf("checkUser() error = %v", err)
	}
	if err := e.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if err := e.close(); err != nil {
		t.Fatalf("second close() error = %v", err)
	}
	if got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "Read", "employees"); err != nil || !got[0].granted {
		t.Fatalf("checkUser() after close = (%v, %v), want served from last snapshot", got, err)
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
	store := engineFakeStore(t)

	sig := newFakeSignal()
	opts := defaultClientOptions()
	opts.signal = sig
	e := testEngine(t, store, opts)

	if got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "List", "widgets"); err != nil || got[0].granted {
		t.Fatalf("checkUser() = (%v, %v), want widgets denied before the change", got, err)
	}
	settle(e)

	select {
	case <-sig.watchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("ChangeSignal.Watch was never started")
	}

	// A hint (not a local invalidate) must reload through the background loop.
	grantWidgets(t, store)
	sig.trigger()

	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := e.checkUserResources(ctx, "erin", tenant1Scope, "List", "widgets")
		if err != nil {
			t.Fatalf("checkUser() error = %v", err)
		}
		if got[0].granted {
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

// convoyStore instruments ReadPolicy to reproduce the write-storm race: while
// armed, every store read lands another local policy write (onLoad), so the
// write counter is always one ahead of the read in flight. The first armed
// read additionally parks on gate so the test can queue checks behind the
// reload mutex before letting anything finish.
type convoyStore struct {
	*fakeStore
	onLoad  func() // lands a write during every armed read; set before the engine starts
	loads   atomic.Int64
	armed   atomic.Bool
	started chan struct{} // closed when the first armed read is in flight
	gate    chan struct{} // first armed read blocks until this closes
	gateSeq sync.Once
}

func (c *convoyStore) ReadPolicy(ctx context.Context) (*policy.Records, error) {
	c.loads.Add(1)
	if c.armed.Load() {
		c.onLoad()
		c.gateSeq.Do(func() {
			close(c.started)
			<-c.gate
		})
	}

	return c.fakeStore.ReadPolicy(ctx)
}

// Test_snapshotEngine_syncReloadDedup pins the sync-reload dedup semantics:
// a check queued behind an in-flight reload is satisfied by any snapshot
// covering the writes that preceded the check's own entry. Regression for the
// convoy where the wake-up recheck chased the live write counter, sending
// every queued check into its own serial reload under sustained writes
// (loads grew with check count, not write count).
func Test_snapshotEngine_syncReloadDedup(t *testing.T) {
	t.Parallel()

	const checks = 50

	tests := []struct {
		name string
		// writeDuringRead lands another local write during every store read,
		// keeping the write counter permanently ahead of the read in flight —
		// the moving-target condition that caused the convoy.
		writeDuringRead bool
		// wantMaxLoads bounds store reads after the checks are queued; slack
		// covers stragglers that enter after a mid-read write. The convoy
		// regression produced one read per queued check (checks+1).
		wantMaxLoads int64
	}{
		{
			name:         "one write, queued checks share one reload",
			wantMaxLoads: 1,
		},
		{
			name:            "write storm, reloads scale with writes not checks",
			writeDuringRead: true,
			wantMaxLoads:    3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &convoyStore{
				fakeStore: engineFakeStore(t),
				started:   make(chan struct{}),
				gate:      make(chan struct{}),
			}
			e := testEngine(t, store, nil)
			store.onLoad = func() {}
			if tt.writeDuringRead {
				store.onLoad = e.invalidate
			}

			if err := e.waitReady(context.Background()); err != nil {
				t.Fatalf("waitReady() error = %v", err)
			}
			settle(e)
			baseline := store.loads.Load()

			store.armed.Store(true)
			e.invalidate() // send checks into the sync-reload path

			errs := make(chan error, checks)
			var wg sync.WaitGroup
			for range checks {
				wg.Go(func() {
					_, err := e.checkUserResources(context.Background(), "erin", tenant1Scope, "Read", "employees")
					errs <- err
				})
			}

			// Wait for the first sync reload to hold the store read open,
			// then give the remaining checks time to record their entry
			// generation and queue on the reload mutex before any reload
			// completes.
			<-store.started
			time.Sleep(50 * time.Millisecond)
			close(store.gate)

			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("checkUser() error = %v", err)
				}
			}

			if extra := store.loads.Load() - baseline; extra > tt.wantMaxLoads {
				t.Errorf("store loads with checks queued = %d, want at most %d", extra, tt.wantMaxLoads)
			}
		})
	}
}
