package access

import (
	"crypto/sha256"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// snapshot is an immutable, fully-compiled view of the policy store. It is
// built once per load and shared by reference; evaluation is lock-free and
// allocation-free. Subtraction never happens at evaluation time (additive-only
// invariant): a snapshot only encodes what is granted.
type snapshot struct {
	perms     map[accesstypes.Permission]uint16
	resources map[string]uint16   // base resource name -> dense ID ("" = scope-wide)
	fields    []map[string]uint16 // by resource ID: field name -> bit position
	scopes    map[accesstypes.Scope]*scopePolicy
	loadedAt  time.Time

	// conditions interns the distinct condition texts, sorted so a term set
	// resolves to canonically ordered texts. The texts are opaque: the
	// compiler never parses or evaluates them (the expression language is
	// undesigned); it only carries them to Conditional decisions.
	conditions []string
	condIDs    map[string]uint16

	// recordsHash identifies the snapshot's source content; the heartbeat
	// skips recompiling when a fresh read matches it.
	recordsHash [sha256.Size]byte

	// writeGen is the engine's local write generation observed BEFORE the
	// store read this snapshot was compiled from: any local write up to and
	// including that generation is guaranteed to be reflected here.
	writeGen int64
}

// scopePolicy holds one scope's fully-resolved grants. The scope is the
// partition grants live in: nothing in here is ever consulted for another
// scope. Role inheritance and per-user role combination are folded at
// compile time, so a check is a single subject lookup.
type scopePolicy struct {
	roleGrants map[accesstypes.Role]grantMap
	userGrants map[accesstypes.User]grantMap
}

// grantKey packs (permission ID, resource ID) into one map key.
type grantKey uint32

func packGrantKey(permID, resID uint16) grantKey {
	return grantKey(permID)<<16 | grantKey(resID)
}

// grantMap is a subject's complete effective grants: everything it holds
// directly, through role membership, and through role inheritance.
type grantMap map[grantKey]*fieldSet

// condTerms is a sorted, deduplicated set of interned condition IDs with OR
// semantics: the target is covered when any one condition holds. Methods
// never mutate their receiver in place after building — merges replace
// slices — so term sets alias safely across merged grant maps.
type condTerms []uint16

// with returns the terms with id included, keeping the set sorted.
func (t condTerms) with(id uint16) condTerms {
	i, ok := slices.BinarySearch(t, id)
	if ok {
		return t
	}

	return slices.Insert(t, i, id)
}

// union returns the sorted union of t and other, aliasing when either side
// is empty.
func (t condTerms) union(other condTerms) condTerms {
	switch {
	case len(other) == 0:
		return t
	case len(t) == 0:
		return other
	}

	merged := slices.Clone(t)
	for _, id := range other {
		merged = merged.with(id)
	}

	return merged
}

// condSet is a fieldSet's conditional coverage: for each target an endpoint,
// all-fields, or single-field grant can occupy, the conditions of the
// conditional grants covering it. It records coverage only — settling (an
// unconditional cover making conditions moot) happens at evaluation, which
// consults conditional coverage only after the unconditional check missed.
// Stores without conditions never allocate one.
type condSet struct {
	endpoint condTerms
	all      condTerms
	fields   map[uint16]condTerms // by field bit position
}

func (c *condSet) clone() *condSet {
	if c == nil {
		return nil
	}
	out := &condSet{endpoint: c.endpoint, all: c.all}
	if c.fields != nil {
		out.fields = maps.Clone(c.fields)
	}

	return out
}

// orIn merges src's coverage into c.
func (c *condSet) orIn(src *condSet) {
	c.endpoint = c.endpoint.union(src.endpoint)
	c.all = c.all.union(src.all)
	for i, terms := range src.fields {
		if c.fields == nil {
			c.fields = make(map[uint16]condTerms, len(src.fields))
		}
		c.fields[i] = c.fields[i].union(terms)
	}
}

// fieldSet is what one subject holds on one (permission, resource) pair.
// endpoint and field grants are distinct: an endpoint grant alone gives no
// field visibility, and field grants alone do not grant the endpoint.
// all is an implication flag, never materialized bits: it covers fields that
// did not exist when the grant was written.
// endpoint/all/bits encode unconditional grants only; conditional grants
// land in cond, nil unless one exists.
type fieldSet struct {
	endpoint bool
	all      bool
	bits     []uint64
	cond     *condSet
}

func (f *fieldSet) setBit(i uint16) {
	f.bits[i/64] |= 1 << (i % 64)
}

func (f *fieldSet) bit(i uint16) bool {
	return f.bits[i/64]&(1<<(i%64)) != 0
}

// ensureCond returns f's condSet, allocating it on first use.
func (f *fieldSet) ensureCond() *condSet {
	if f.cond == nil {
		f.cond = &condSet{}
	}

	return f.cond
}

// orIn merges src into f. Both bitsets are sized by the resource's field
// count, so lengths always match.
func (f *fieldSet) orIn(src *fieldSet) {
	f.endpoint = f.endpoint || src.endpoint
	f.all = f.all || src.all
	for i, w := range src.bits {
		f.bits[i] |= w
	}
	if src.cond != nil {
		if f.cond == nil {
			f.cond = src.cond.clone()
		} else {
			f.cond.orIn(src.cond)
		}
	}
}

func (f *fieldSet) clone() *fieldSet {
	return &fieldSet{
		endpoint: f.endpoint,
		all:      f.all,
		bits:     slices.Clone(f.bits),
		cond:     f.cond.clone(),
	}
}

// resourceDecision is the engine-internal decision for one checked resource.
// The zero value is denied (fail closed); granted marks an unconditional
// cover; conditions carries the covering conditional grants' condition texts
// (OR semantics, canonically ordered) when only conditional grants cover the
// resource.
type resourceDecision struct {
	granted    bool
	conditions []string
}

// newDecisions assembles the public Decisions for one checked batch, aligned
// by input order. Grouping is the engine's job — only the engine owns
// grant-set identity: a Conditional decision carries one ConditionGroup whose
// Resources lists every checked resource in the batch sharing that covering
// condition set (first-appearance input order, deduplicated), and every
// member's Decision carries the same group value, so callers deduplicate by
// sorted-Resources equality. The group's Condition payload is the accesstypes
// placeholder: until the expression language lands the type cannot carry the
// condition texts, which stay engine-internal.
//
// The group key is the canonically ordered condition-text set of the covering
// grants. Covering-grant sets whose texts are identical produce identical OR
// expressions, so collapsing them is pure deduplication: their group booleans
// could never differ.
func newDecisions(resources []accesstypes.Resource, decisions []resourceDecision) accesstypes.Decisions {
	// Pass 1: collect each distinct covering set's members in input order, so
	// every member's group names the complete set before decisions build.
	groups := make(map[string]accesstypes.ConditionGroup)
	for i, d := range decisions {
		if d.granted || len(d.conditions) == 0 {
			continue
		}
		key := joinConditions(d.conditions)
		group := groups[key]
		if !slices.Contains(group.Resources, resources[i]) {
			group.Resources = append(group.Resources, resources[i])
		}
		groups[key] = group
	}

	out := make(accesstypes.Decisions, len(resources))
	for i, d := range decisions {
		switch {
		case d.granted:
			out[resources[i]] = accesstypes.Granted()
		case len(d.conditions) > 0:
			out[resources[i]] = accesstypes.Conditional(groups[joinConditions(d.conditions)])
		default:
			out[resources[i]] = accesstypes.Denied()
		}
	}

	return out
}

// joinConditions builds the grouping key for one covering condition set: the
// canonically ordered texts, NUL-joined (the joinRoles idiom). Equal keys mean
// the covering sets' any-of combinations render as the same expression.
func joinConditions(conditions []string) string {
	var b strings.Builder
	for _, c := range conditions {
		b.WriteString(c)
		b.WriteByte(0)
	}

	return b.String()
}

// checkUser reports whether user holds perm scope-wide within scope. Grants
// reach a user through role membership or records written directly against
// the user, both folded into one lookup at compile time.
func (s *snapshot) checkUser(user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission) bool {
	return s.scopeWide(s.userGrants(scope, user), perm)
}

// decideUserResources returns user's decision for each resource within
// scope, aligned with the input order.
func (s *snapshot) decideUserResources(user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource) []resourceDecision {
	grants := s.userGrants(scope, user)
	decisions := make([]resourceDecision, len(resources))
	permID, permKnown := s.perms[perm]
	if !permKnown {
		return decisions
	}
	for i, resource := range resources {
		decisions[i] = s.decide(grants, permID, resource)
	}

	return decisions
}

// checkRole reports whether role holds perm scope-wide within scope.
func (s *snapshot) checkRole(role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission) bool {
	return s.scopeWide(s.roleGrants(scope, role), perm)
}

// checkRoleResources returns the resources role does NOT hold perm on within
// scope, preserving input order.
func (s *snapshot) checkRoleResources(role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource) []accesstypes.Resource {
	return s.missingResources(s.roleGrants(scope, role), perm, resources)
}

func (s *snapshot) userGrants(scope accesstypes.Scope, user accesstypes.User) grantMap {
	if sp := s.scopes[scope]; sp != nil {
		return sp.userGrants[user]
	}

	return nil
}

func (s *snapshot) roleGrants(scope accesstypes.Scope, role accesstypes.Role) grantMap {
	if sp := s.scopes[scope]; sp != nil {
		return sp.roleGrants[role]
	}

	return nil
}

// scopeWide reports whether the subject holds perm with no resource
// attachment: a grant compiled under the empty resource name, which real
// resources can never occupy (validated non-empty at every write boundary).
func (s *snapshot) scopeWide(grants grantMap, perm accesstypes.Permission) bool {
	if grants == nil {
		return false
	}
	permID, ok := s.perms[perm]
	if !ok {
		return false
	}
	resID, ok := s.resources[""]
	if !ok {
		return false
	}
	fs := grants[packGrantKey(permID, resID)]

	return fs != nil && fs.endpoint
}

func (s *snapshot) missingResources(grants grantMap, perm accesstypes.Permission, resources []accesstypes.Resource) []accesstypes.Resource {
	missing := make([]accesstypes.Resource, 0)
	permID, permKnown := s.perms[perm]
	for _, resource := range resources {
		if !permKnown || !s.allowed(grants, permID, resource) {
			missing = append(missing, resource)
		}
	}

	return missing
}

func (s *snapshot) allowed(grants grantMap, permID uint16, resource accesstypes.Resource) bool {
	if grants == nil {
		return false
	}

	base, field := splitResourceField(string(resource))
	resID, ok := s.resources[base]
	if !ok {
		return false
	}

	fs := grants[packGrantKey(permID, resID)]
	if fs == nil {
		return false
	}

	switch field {
	case "":
		return fs.endpoint
	case "*":
		return fs.all
	default:
		if fs.all {
			// Implication: an all-fields grant covers fields unknown to the
			// snapshot, including ones generated after the grant was written.
			return true
		}
		i, ok := s.fields[resID][field]

		return ok && fs.bit(i)
	}
}

// decide answers one resource against a subject's grants. Any unconditional
// cover settles the decision as granted — conditions on other covering
// grants are moot — so conditional coverage is consulted only after the
// unconditional check (the allowed rules, verbatim) missed. A conditional
// field cover is the union of the single-field terms and the all-fields
// terms; a field unknown to the snapshot is covered only by all-fields
// grants, mirroring the unconditional implication rule.
func (s *snapshot) decide(grants grantMap, permID uint16, resource accesstypes.Resource) resourceDecision {
	if grants == nil {
		return resourceDecision{}
	}

	base, field := splitResourceField(string(resource))
	resID, ok := s.resources[base]
	if !ok {
		return resourceDecision{}
	}

	fs := grants[packGrantKey(permID, resID)]
	if fs == nil {
		return resourceDecision{}
	}

	var terms condTerms
	switch field {
	case "":
		if fs.endpoint {
			return resourceDecision{granted: true}
		}
		if fs.cond != nil {
			terms = fs.cond.endpoint
		}
	case "*":
		if fs.all {
			return resourceDecision{granted: true}
		}
		if fs.cond != nil {
			terms = fs.cond.all
		}
	default:
		if fs.all {
			return resourceDecision{granted: true}
		}
		i, known := s.fields[resID][field]
		if known && fs.bit(i) {
			return resourceDecision{granted: true}
		}
		if fs.cond != nil {
			terms = fs.cond.all
			if known {
				terms = terms.union(fs.cond.fields[i])
			}
		}
	}
	if len(terms) == 0 {
		return resourceDecision{}
	}

	conditions := make([]string, len(terms))
	for i, id := range terms {
		conditions[i] = s.conditions[id]
	}

	return resourceDecision{conditions: conditions}
}

// newSnapshot compiles normalized policy records into an immutable snapshot.
func newSnapshot(records *policy.Records, loadedAt time.Time) (*snapshot, error) {
	s := &snapshot{
		perms:       make(map[accesstypes.Permission]uint16),
		resources:   make(map[string]uint16),
		condIDs:     make(map[string]uint16),
		scopes:      make(map[accesstypes.Scope]*scopePolicy),
		loadedAt:    loadedAt,
		recordsHash: records.Hash(),
	}

	if err := s.intern(records.Grants); err != nil {
		return nil, err
	}

	// Pass 2: group records by scope and compile each scope independently.
	type scopeRecords struct {
		grants      []policy.Grant
		memberships []policy.Membership
	}
	byScope := make(map[accesstypes.Scope]*scopeRecords)
	recordsFor := func(scope accesstypes.Scope) *scopeRecords {
		sr := byScope[scope]
		if sr == nil {
			sr = &scopeRecords{}
			byScope[scope] = sr
		}

		return sr
	}
	for _, g := range records.Grants {
		sr := recordsFor(g.Scope)
		sr.grants = append(sr.grants, g)
	}
	for _, m := range records.Memberships {
		sr := recordsFor(m.Scope)
		sr.memberships = append(sr.memberships, m)
	}

	for scope, sr := range byScope {
		s.scopes[scope] = s.compileScope(sr.grants, sr.memberships)
	}

	return s, nil
}

// intern assigns dense IDs to permissions and resources and bit positions to
// each resource's named fields, and interns the distinct condition texts. IDs
// are uint16 by design; overflowing one would silently truncate and grant the
// wrong permissions, so it fails the load instead.
//
// Conditions on scope-wide grants fail the load too: a condition limits its
// grant per row, and a grant attached to no resource has no row context to
// evaluate against. This blanket rejection is interim: once the condition
// package can parse expressions, it narrows to row-referencing conditions
// only (a binding-name attribute or new. reference) — row-free conditions
// over environment and subject attributes are valid on scope-wide grants and
// fold at check time (design plan §05, revised 2026-08-31).
func (s *snapshot) intern(grants []policy.Grant) error {
	for _, g := range grants {
		if g.Condition != "" {
			if g.Resource == "" {
				return errors.Newf("conditional scope-wide grant for subject %q in scope %s: a condition requires a resource row context", g.Subject.Name, g.Scope)
			}
			if _, ok := s.condIDs[g.Condition]; !ok {
				if len(s.condIDs) >= math.MaxUint16 {
					return errors.Newf("too many distinct conditions to compile: limit %d", math.MaxUint16)
				}
				s.condIDs[g.Condition] = 0 // placeholder; canonical IDs assigned below
			}
		}
		if _, ok := s.perms[g.Perm]; !ok {
			if len(s.perms) >= math.MaxUint16 {
				return errors.Newf("too many permissions to compile: limit %d", math.MaxUint16)
			}
			s.perms[g.Perm] = uint16(len(s.perms)) //nolint:gosec // bounded by the guard above
		}
		resID, ok := s.resources[g.Resource]
		if !ok {
			if len(s.resources) >= math.MaxUint16 {
				return errors.Newf("too many resources to compile: limit %d", math.MaxUint16)
			}
			resID = uint16(len(s.resources)) //nolint:gosec // bounded by the guard above
			s.resources[g.Resource] = resID
			s.fields = append(s.fields, make(map[string]uint16))
		}
		if g.Field != "" && g.Field != "*" {
			if _, ok := s.fields[resID][g.Field]; !ok {
				if len(s.fields[resID]) >= math.MaxUint16 {
					return errors.Newf("too many fields on resource %q to compile: limit %d", g.Resource, math.MaxUint16)
				}
				s.fields[resID][g.Field] = uint16(len(s.fields[resID])) //nolint:gosec // bounded by the guard above
			}
		}
	}

	// Condition IDs sort by text so term sets — and the texts a decision
	// carries — are canonically ordered regardless of record order.
	s.conditions = slices.Sorted(maps.Keys(s.condIDs))
	for i, text := range s.conditions {
		s.condIDs[text] = uint16(i)
	}

	return nil
}

func (s *snapshot) compileScope(grants []policy.Grant, memberships []policy.Membership) *scopePolicy {
	roleOwn, userDirect := s.compileSubjectGrants(grants)
	inherits, userRoles := splitMemberships(memberships)

	// Fold inheritance: every role referenced anywhere gets its effective
	// grants (its own plus its transitive parents').
	roleSet := make(map[accesstypes.Role]bool)
	for role := range roleOwn {
		roleSet[role] = true
	}
	for member, parents := range inherits {
		roleSet[member] = true
		for _, p := range parents {
			roleSet[p] = true
		}
	}
	for _, roles := range userRoles {
		for _, r := range roles {
			roleSet[r] = true
		}
	}

	dp := &scopePolicy{
		roleGrants: make(map[accesstypes.Role]grantMap, len(roleSet)),
		userGrants: make(map[accesstypes.User]grantMap, len(userRoles)+len(userDirect)),
	}
	for role := range roleSet {
		dp.roleGrants[role] = mergeGrants(collectRoleGrants(role, roleOwn, inherits))
	}

	// Per-user effective grants, deduplicated by role set so users sharing a
	// role combination share one merged map.
	combos := make(map[string]grantMap)
	for user, roles := range userRoles {
		slices.Sort(roles)
		if direct := userDirect[user]; direct != nil {
			sources := make([]grantMap, 0, len(roles)+1)
			for _, r := range roles {
				sources = append(sources, dp.roleGrants[r])
			}
			sources = append(sources, direct)
			dp.userGrants[user] = mergeGrants(sources)

			continue
		}

		key := joinRoles(roles)
		combined, ok := combos[key]
		if !ok {
			sources := make([]grantMap, 0, len(roles))
			for _, r := range roles {
				sources = append(sources, dp.roleGrants[r])
			}
			combined = mergeGrants(sources)
			combos[key] = combined
		}
		dp.userGrants[user] = combined
	}
	for user, direct := range userDirect {
		if _, ok := dp.userGrants[user]; !ok {
			dp.userGrants[user] = direct
		}
	}

	return dp
}

// compileSubjectGrants builds each subject's raw grant map from one scope's
// grant records.
func (s *snapshot) compileSubjectGrants(grants []policy.Grant) (roleOwn map[accesstypes.Role]grantMap, userDirect map[accesstypes.User]grantMap) {
	roleOwn = make(map[accesstypes.Role]grantMap)
	userDirect = make(map[accesstypes.User]grantMap)
	for _, g := range grants {
		var gm grantMap
		switch g.Subject.Kind {
		case policy.SubjectRole:
			role := accesstypes.Role(g.Subject.Name)
			if roleOwn[role] == nil {
				roleOwn[role] = make(grantMap)
			}
			gm = roleOwn[role]
		case policy.SubjectUser:
			user := accesstypes.User(g.Subject.Name)
			if userDirect[user] == nil {
				userDirect[user] = make(grantMap)
			}
			gm = userDirect[user]
		}

		resID := s.resources[g.Resource]
		key := packGrantKey(s.perms[g.Perm], resID)
		fs := gm[key]
		if fs == nil {
			fs = &fieldSet{bits: make([]uint64, (len(s.fields[resID])+63)/64)}
			gm[key] = fs
		}
		if g.Condition != "" {
			cond := fs.ensureCond()
			id := s.condIDs[g.Condition]
			switch g.Field {
			case "":
				cond.endpoint = cond.endpoint.with(id)
			case "*":
				cond.all = cond.all.with(id)
			default:
				if cond.fields == nil {
					cond.fields = make(map[uint16]condTerms)
				}
				i := s.fields[resID][g.Field]
				cond.fields[i] = cond.fields[i].with(id)
			}

			continue
		}
		switch g.Field {
		case "":
			fs.endpoint = true
		case "*":
			fs.all = true
		default:
			fs.setBit(s.fields[resID][g.Field])
		}
	}

	return roleOwn, userDirect
}

// splitMemberships separates one scope's membership records into user role
// assignments and role-to-role inheritance edges. Casbin resolves inheritance
// transitively at evaluation time; the compiler folds it at load time.
func splitMemberships(memberships []policy.Membership) (inherits map[accesstypes.Role][]accesstypes.Role, userRoles map[accesstypes.User][]accesstypes.Role) {
	inherits = make(map[accesstypes.Role][]accesstypes.Role)
	userRoles = make(map[accesstypes.User][]accesstypes.Role)
	for _, m := range memberships {
		switch m.Member.Kind {
		case policy.SubjectRole:
			member := accesstypes.Role(m.Member.Name)
			if !slices.Contains(inherits[member], m.Role) {
				inherits[member] = append(inherits[member], m.Role)
			}
		case policy.SubjectUser:
			user := accesstypes.User(m.Member.Name)
			if !slices.Contains(userRoles[user], m.Role) {
				userRoles[user] = append(userRoles[user], m.Role)
			}
		}
	}

	return inherits, userRoles
}

// collectRoleGrants returns the grant maps contributing to role's effective
// grants: its own and, transitively, every role it inherits (cycle-safe).
func collectRoleGrants(role accesstypes.Role, roleOwn map[accesstypes.Role]grantMap, inherits map[accesstypes.Role][]accesstypes.Role) []grantMap {
	var sources []grantMap
	visited := make(map[accesstypes.Role]bool)
	stack := []accesstypes.Role{role}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[r] {
			continue
		}
		visited[r] = true
		if own := roleOwn[r]; own != nil {
			sources = append(sources, own)
		}
		stack = append(stack, inherits[r]...)
	}

	return sources
}

// mergeGrants ORs the sources into one grantMap. With zero or one source it
// aliases rather than copies; snapshots are immutable so sharing is safe.
func mergeGrants(sources []grantMap) grantMap {
	sources = slices.DeleteFunc(sources, func(g grantMap) bool { return len(g) == 0 })
	switch len(sources) {
	case 0:
		return grantMap{}
	case 1:
		return sources[0]
	}

	merged := make(grantMap)
	for _, src := range sources {
		for key, fs := range src {
			if existing := merged[key]; existing != nil {
				existing.orIn(fs)
			} else {
				merged[key] = fs.clone()
			}
		}
	}

	return merged
}

func joinRoles(roles []accesstypes.Role) string {
	var b strings.Builder
	for _, r := range roles {
		b.WriteString(string(r))
		b.WriteByte(0)
	}

	return b.String()
}

// splitResourceField splits a resource name on its last '.' into the base
// resource and field. Checked resources and stored grants split with the same
// rule, so field matching is exact.
func splitResourceField(obj string) (resource, field string) {
	i := strings.LastIndexByte(obj, '.')
	if i < 0 {
		return obj, ""
	}

	return obj[:i], obj[i+1:]
}
