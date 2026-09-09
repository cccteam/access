package access

import (
	"crypto/sha256"
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

// fieldSet is what one subject holds on one (permission, resource) pair.
// endpoint and field grants are distinct: an endpoint grant alone gives no
// field visibility, and field grants alone do not grant the endpoint.
// all is an implication flag, never materialized bits: it covers fields that
// did not exist when the grant was written.
type fieldSet struct {
	endpoint bool
	all      bool
	bits     []uint64
}

func (f *fieldSet) setBit(i uint16) {
	f.bits[i/64] |= 1 << (i % 64)
}

func (f *fieldSet) bit(i uint16) bool {
	return f.bits[i/64]&(1<<(i%64)) != 0
}

// orIn merges src into f. Both bitsets are sized by the resource's field
// count, so lengths always match.
func (f *fieldSet) orIn(src *fieldSet) {
	f.endpoint = f.endpoint || src.endpoint
	f.all = f.all || src.all
	for i, w := range src.bits {
		f.bits[i] |= w
	}
}

func (f *fieldSet) clone() *fieldSet {
	return &fieldSet{
		endpoint: f.endpoint,
		all:      f.all,
		bits:     slices.Clone(f.bits),
	}
}

// checkUser reports whether user holds perm scope-wide within scope. Grants
// reach a user through role membership or records written directly against
// the user, both folded into one lookup at compile time.
func (s *snapshot) checkUser(user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission) bool {
	return s.scopeWide(s.userGrants(scope, user), perm)
}

// checkUserResources returns the resources user does NOT hold perm on within
// scope, preserving input order.
func (s *snapshot) checkUserResources(user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource) []accesstypes.Resource {
	return s.missingResources(s.userGrants(scope, user), perm, resources)
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

// newSnapshot compiles normalized policy records into an immutable snapshot.
func newSnapshot(records *policy.Records, loadedAt time.Time) (*snapshot, error) {
	s := &snapshot{
		perms:       make(map[accesstypes.Permission]uint16),
		resources:   make(map[string]uint16),
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
// each resource's named fields. IDs are uint16 by design; overflowing one
// would silently truncate and grant the wrong permissions, so it fails the
// load instead.
func (s *snapshot) intern(grants []policy.Grant) error {
	for _, g := range grants {
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
