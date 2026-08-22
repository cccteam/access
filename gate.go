package access

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// Probe values that exist in no real policy, used to compare denial behavior.
const (
	gateProbeDomain   = accesstypes.Domain("zz-gate-probe-domain")
	gateProbeUser     = accesstypes.User("zz-gate-probe-user")
	gateProbeRole     = accesstypes.Role("ZzGateProbeRole")
	gateProbePerm     = accesstypes.Permission("ZzGateProbePerm")
	gateProbeResource = accesstypes.Resource("zzgateproberesource")
	gateProbeField    = "zzgateprobefield"
)

// gateMismatchCap bounds how many divergences are reported before aborting.
const gateMismatchCap = 20

// ValidateEngineEquivalence compares the casbin evaluator and the snapshot
// evaluator over the live policy store. Run it in the migrate job BEFORE
// MigrateRoles; a non-nil error means the engines disagree and the deploy
// must abort (traffic never moves to the new revision).
//
// Two layers:
//   - Structural (exhaustive): for every domain and subject present in the
//     store, the effective grant set casbin reports (implicit permissions)
//     must equal the snapshot's compiled grant set, and every user's role
//     memberships must match.
//   - Behavioral (sampled): checkUser/checkRole answers are compared
//     engine-to-engine over every granted (subject, permission) group plus
//     unknown-domain/subject/permission/resource/field probes. Field probes
//     skip (permission, resource) pairs holding a `.*` wildcard grant: the
//     snapshot interpreting wildcards by implication while old casbin
//     exact-matches them inert is the one designed divergence.
func (c *Client) ValidateEngineEquivalence(ctx context.Context) error {
	adapter, err := c.snapEngine.adapterFactory.NewAdapter()
	if err != nil {
		return errors.Wrap(err, "access.Adapter.NewAdapter()")
	}

	records, err := readCasbinPolicy(adapter)
	if err != nil {
		return errors.Wrap(err, "readCasbinPolicy()")
	}

	appDomains, err := c.userManager.Domains(ctx)
	if err != nil {
		return errors.Wrap(err, "UserManager.Domains()")
	}

	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		return errors.Wrap(err, "newSnapshot()")
	}

	universe, err := buildGateUniverse(c.casbin, records, appDomains)
	if err != nil {
		return err
	}

	g := &gate{ctx: ctx, casbin: c.casbin, snap: snap, enum: newSnapshotEnumerator(snap)}
	g.compareStructure(universe)
	g.compareBehavior(universe)

	if len(g.mismatches) > 0 {
		return errors.Newf(
			"engine equivalence validation failed: %d mismatch(es) (showing up to %d):\n%s",
			g.mismatchCount, gateMismatchCap, strings.Join(g.mismatches, "\n"),
		)
	}

	return nil
}

// gateUniverse is everything to compare, derived from the casbin enforcer's
// raw rows (so a reader bug cannot hide a subject from the comparison), the
// normalized records, and the app's domain list.
type gateUniverse struct {
	domains   []accesstypes.Domain
	domainSet map[accesstypes.Domain]bool
	roles     map[accesstypes.Domain]map[accesstypes.Role]bool
	users     map[accesstypes.Domain]map[accesstypes.User]bool
	userRoles map[accesstypes.Domain]map[accesstypes.User][]accesstypes.Role // from records (reader view)
}

func buildGateUniverse(ce *casbinEngine, records *policy.Records, appDomains []accesstypes.Domain) (*gateUniverse, error) {
	u := &gateUniverse{
		domainSet: map[accesstypes.Domain]bool{accesstypes.GlobalDomain: true},
		roles:     make(map[accesstypes.Domain]map[accesstypes.Role]bool),
		users:     make(map[accesstypes.Domain]map[accesstypes.User]bool),
		userRoles: make(map[accesstypes.Domain]map[accesstypes.User][]accesstypes.Role),
	}
	for _, d := range appDomains {
		u.domainSet[d] = true
	}

	if err := u.addEnforcerSubjects(ce); err != nil {
		return nil, err
	}
	u.addRecordSubjects(records)

	u.domains = make([]accesstypes.Domain, 0, len(u.domainSet))
	for d := range u.domainSet {
		u.domains = append(u.domains, d)
	}
	slices.Sort(u.domains)

	return u, nil
}

func (u *gateUniverse) addRole(d accesstypes.Domain, r accesstypes.Role) {
	u.domainSet[d] = true
	if u.roles[d] == nil {
		u.roles[d] = make(map[accesstypes.Role]bool)
	}
	u.roles[d][r] = true
}

func (u *gateUniverse) addUser(d accesstypes.Domain, user accesstypes.User) {
	u.domainSet[d] = true
	if u.users[d] == nil {
		u.users[d] = make(map[accesstypes.User]bool)
	}
	u.users[d][user] = true
}

// addEnforcerSubjects collects subjects straight from the enforcer's rows,
// independent of the reader — a reader bug cannot hide a subject from the
// comparison.
func (u *gateUniverse) addEnforcerSubjects(ce *casbinEngine) error {
	policies, err := ce.Enforcer().GetPolicy()
	if err != nil {
		return errors.Wrap(err, "casbin.IEnforcer.GetPolicy()")
	}
	for _, p := range policies {
		if len(p) < 4 {
			continue
		}
		d := accesstypes.Domain(strings.TrimPrefix(p[1], "domain:"))
		if role, ok := strings.CutPrefix(p[0], "role:"); ok {
			u.addRole(d, accesstypes.Role(role))
		}
		if user, ok := strings.CutPrefix(p[0], "user:"); ok {
			u.addUser(d, accesstypes.User(user))
		}
	}

	groupings, err := ce.Enforcer().GetGroupingPolicy()
	if err != nil {
		return errors.Wrap(err, "casbin.IEnforcer.GetGroupingPolicy()")
	}
	for _, g := range groupings {
		if len(g) < 3 {
			continue
		}
		d := accesstypes.Domain(strings.TrimPrefix(g[2], "domain:"))
		u.addRole(d, accesstypes.Role(strings.TrimPrefix(g[1], "role:")))
		if user, ok := strings.CutPrefix(g[0], "user:"); ok {
			u.addUser(d, accesstypes.User(user))
		}
		if role, ok := strings.CutPrefix(g[0], "role:"); ok {
			u.addRole(d, accesstypes.Role(role))
		}
	}

	return nil
}

// addRecordSubjects collects subjects and memberships as the reader saw them.
func (u *gateUniverse) addRecordSubjects(records *policy.Records) {
	for _, g := range records.Grants {
		switch g.Subject.Kind {
		case policy.SubjectRole:
			u.addRole(g.Domain, accesstypes.Role(g.Subject.Name))
		case policy.SubjectUser:
			u.addUser(g.Domain, accesstypes.User(g.Subject.Name))
		}
	}
	for _, m := range records.Memberships {
		switch m.Member.Kind {
		case policy.SubjectRole:
			u.addRole(m.Domain, accesstypes.Role(m.Member.Name))
		case policy.SubjectUser:
			user := accesstypes.User(m.Member.Name)
			u.addUser(m.Domain, user)
			u.addRole(m.Domain, m.Role)
			if u.userRoles[m.Domain] == nil {
				u.userRoles[m.Domain] = make(map[accesstypes.User][]accesstypes.Role)
			}
			if !slices.Contains(u.userRoles[m.Domain][user], m.Role) {
				u.userRoles[m.Domain][user] = append(u.userRoles[m.Domain][user], m.Role)
			}
		}
	}
}

// gate accumulates comparison mismatches up to gateMismatchCap.
type gate struct {
	ctx           context.Context //nolint:containedctx // scoped to one validation run
	casbin        *casbinEngine
	snap          *snapshot
	enum          *snapshotEnumerator
	mismatches    []string
	mismatchCount int
}

func (g *gate) reportf(format string, args ...any) {
	g.mismatchCount++
	if len(g.mismatches) < gateMismatchCap {
		g.mismatches = append(g.mismatches, fmt.Sprintf(format, args...))
	}
}

// compareStructure exhaustively compares effective grant sets and user
// memberships for every subject in every domain.
func (g *gate) compareStructure(u *gateUniverse) {
	for _, domain := range u.domains {
		for _, role := range sortedKeys(u.roles[domain]) {
			casbinPairs, err := g.casbinImplicitPairs(role.Marshal(), domain)
			if err != nil {
				g.reportf("casbin implicit permissions for role %q in %q: %v", role, domain, err)

				continue
			}
			g.comparePairs("role "+string(role), domain, casbinPairs, g.enum.rolePairs(domain, role))
		}

		for _, user := range sortedKeys(u.users[domain]) {
			casbinPairs, err := g.casbinImplicitPairs(user.Marshal(), domain)
			if err != nil {
				g.reportf("casbin implicit permissions for user %q in %q: %v", user, domain, err)

				continue
			}
			g.comparePairs("user "+string(user), domain, casbinPairs, g.enum.userPairs(domain, user))

			casbinRoles, err := g.casbin.userRoles(g.ctx, domain, user)
			if err != nil {
				g.reportf("casbin roles for user %q in %q: %v", user, domain, err)

				continue
			}
			slices.Sort(casbinRoles)
			readerRoles := slices.Clone(u.userRoles[domain][user])
			slices.Sort(readerRoles)
			if !slices.Equal(casbinRoles, readerRoles) {
				g.reportf("user %q roles in %q: casbin=%v reader=%v", user, domain, casbinRoles, readerRoles)
			}
		}
	}
}

// compareBehavior compares actual check answers engine-to-engine: positive
// sweeps over every granted (permission, resource) group, plus probes for
// values nothing grants.
func (g *gate) compareBehavior(u *gateUniverse) {
	for _, domain := range u.domains {
		for _, role := range sortedKeys(u.roles[domain]) {
			g.sweepSubject(domain, policy.Subject{Kind: policy.SubjectRole, Name: string(role)}, g.enum.rolePairs(domain, role))
		}
		for _, user := range sortedKeys(u.users[domain]) {
			g.sweepSubject(domain, policy.Subject{Kind: policy.SubjectUser, Name: string(user)}, g.enum.userPairs(domain, user))
		}

		// Unknown subjects must be denied identically.
		g.compareCheck(domain, policy.Subject{Kind: policy.SubjectUser, Name: string(gateProbeUser)}, gateProbePerm, []accesstypes.Resource{accesstypes.GlobalResource, gateProbeResource})
		g.compareCheck(domain, policy.Subject{Kind: policy.SubjectRole, Name: string(gateProbeRole)}, gateProbePerm, []accesstypes.Resource{accesstypes.GlobalResource, gateProbeResource})
	}

	// Unknown domain must be denied identically for a sample of subjects.
	for _, domain := range u.domains {
		for _, role := range sortedKeys(u.roles[domain])[:min(len(u.roles[domain]), 3)] {
			for perm, resources := range pairsByPerm(g.enum.rolePairs(domain, role)) {
				g.compareCheck(gateProbeDomain, policy.Subject{Kind: policy.SubjectRole, Name: string(role)}, perm, resources[:min(len(resources), 3)])
			}
		}
	}
}

// sweepSubject compares check answers over everything the subject holds
// (expected to pass on both engines) and over targeted unknowns (expected to
// fail on both engines).
func (g *gate) sweepSubject(domain accesstypes.Domain, sub policy.Subject, pairs map[string]bool) {
	byPerm := pairsByPerm(pairs)
	perms := make([]accesstypes.Permission, 0, len(byPerm))
	for perm := range byPerm {
		perms = append(perms, perm)
	}
	slices.Sort(perms)

	for _, perm := range perms {
		resources := byPerm[perm]
		// Positive: everything granted answers identically.
		g.compareCheck(domain, sub, perm, resources)

		// Negative: unknown base resource, and an unknown field on each
		// granted base UNLESS that (perm, base) holds a wildcard grant (the
		// designed divergence: snapshot allows by implication, casbin does
		// not).
		probes := []accesstypes.Resource{gateProbeResource}
		seenBase := map[string]bool{}
		for _, res := range resources {
			base, _ := splitResourceField(string(res))
			if seenBase[base] || pairs[pairKey(perm, base+".*")] {
				continue
			}
			seenBase[base] = true
			probes = append(probes, accesstypes.Resource(base+"."+gateProbeField))
		}
		g.compareCheck(domain, sub, perm, probes)
	}

	// Unknown permission must be denied identically.
	g.compareCheck(domain, sub, gateProbePerm, []accesstypes.Resource{accesstypes.GlobalResource})
}

// compareCheck runs one batched check through both engines and reports any
// difference in the missing sets.
func (g *gate) compareCheck(domain accesstypes.Domain, sub policy.Subject, perm accesstypes.Permission, resources []accesstypes.Resource) {
	if len(resources) == 0 {
		return
	}

	var casbinMissing, snapMissing []accesstypes.Resource
	var err error
	switch sub.Kind {
	case policy.SubjectRole:
		casbinMissing, err = g.casbin.checkRole(g.ctx, accesstypes.Role(sub.Name), domain, perm, resources...)
		snapMissing = g.snap.checkRole(accesstypes.Role(sub.Name), domain, perm, resources...)
	case policy.SubjectUser:
		casbinMissing, err = g.casbin.checkUser(g.ctx, accesstypes.User(sub.Name), domain, perm, resources...)
		snapMissing = g.snap.checkUser(accesstypes.User(sub.Name), domain, perm, resources...)
	}
	if err != nil {
		g.reportf("casbin check for %s %q in %q perm %q: %v", kindName(sub), sub.Name, domain, perm, err)

		return
	}

	if !slices.Equal(casbinMissing, snapMissing) {
		g.reportf("check mismatch: %s %q domain %q perm %q resources %v: casbin missing %v, snapshot missing %v",
			kindName(sub), sub.Name, domain, perm, resources, casbinMissing, snapMissing)
	}
}

func kindName(s policy.Subject) string {
	if s.Kind == policy.SubjectRole {
		return "role"
	}

	return "user"
}

// casbinImplicitPairs returns the deduplicated (permission, object) pairs
// casbin reports as the subject's effective grants in domain.
func (g *gate) casbinImplicitPairs(marshaledSubject string, domain accesstypes.Domain) (map[string]bool, error) {
	rows, err := g.casbin.Enforcer().GetImplicitPermissionsForUser(marshaledSubject, domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "casbin.IEnforcer.GetImplicitPermissionsForUser()")
	}

	pairs := make(map[string]bool, len(rows))
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		perm := accesstypes.Permission(strings.TrimPrefix(row[3], "perm:"))
		pairs[pairKey(perm, strings.TrimPrefix(row[2], "resource:"))] = true
	}

	return pairs, nil
}

func (g *gate) comparePairs(subjectDesc string, domain accesstypes.Domain, casbinPairs, snapPairs map[string]bool) {
	for _, pair := range sortedKeys(casbinPairs) {
		if !snapPairs[pair] {
			g.reportf("%s in %q: casbin grants %q, snapshot does not", subjectDesc, domain, pair)
		}
	}
	for _, pair := range sortedKeys(snapPairs) {
		if !casbinPairs[pair] {
			g.reportf("%s in %q: snapshot grants %q, casbin does not", subjectDesc, domain, pair)
		}
	}
}

// pairKey formats one (permission, object) grant as a comparable string.
func pairKey(perm accesstypes.Permission, obj string) string {
	return string(perm) + " " + obj
}

func pairsByPerm(pairs map[string]bool) map[accesstypes.Permission][]accesstypes.Resource {
	byPerm := make(map[accesstypes.Permission][]accesstypes.Resource)
	for _, pair := range sortedKeys(pairs) {
		perm, obj, _ := strings.Cut(pair, " ")
		byPerm[accesstypes.Permission(perm)] = append(byPerm[accesstypes.Permission(perm)], accesstypes.Resource(obj))
	}

	return byPerm
}

func sortedKeys[K ~string](m map[K]bool) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	return keys
}

// snapshotEnumerator inverts a snapshot's interning so its compiled grants
// can be compared to casbin's row-shaped view.
type snapshotEnumerator struct {
	snap      *snapshot
	permName  []accesstypes.Permission
	resName   []string
	fieldName [][]string // by resource ID, by bit position
}

func newSnapshotEnumerator(snap *snapshot) *snapshotEnumerator {
	en := &snapshotEnumerator{
		snap:      snap,
		permName:  make([]accesstypes.Permission, len(snap.perms)),
		resName:   make([]string, len(snap.resources)),
		fieldName: make([][]string, len(snap.resources)),
	}
	for perm, id := range snap.perms {
		en.permName[id] = perm
	}
	for res, id := range snap.resources {
		en.resName[id] = res
		en.fieldName[id] = make([]string, len(snap.fields[id]))
		for field, bit := range snap.fields[id] {
			en.fieldName[id][bit] = field
		}
	}

	return en
}

func (en *snapshotEnumerator) rolePairs(domain accesstypes.Domain, role accesstypes.Role) map[string]bool {
	if dp := en.snap.domains[domain]; dp != nil {
		return en.pairs(dp.roleGrants[role])
	}

	return map[string]bool{}
}

func (en *snapshotEnumerator) userPairs(domain accesstypes.Domain, user accesstypes.User) map[string]bool {
	if dp := en.snap.domains[domain]; dp != nil {
		return en.pairs(dp.userGrants[user])
	}

	return map[string]bool{}
}

func (en *snapshotEnumerator) pairs(gm grantMap) map[string]bool {
	pairs := make(map[string]bool, len(gm))
	for key, fs := range gm {
		perm := en.permName[key>>16]
		res := en.resName[key&0xffff]
		if fs.endpoint {
			pairs[pairKey(perm, res)] = true
		}
		if fs.all {
			pairs[pairKey(perm, res+".*")] = true
		}
		for _, field := range en.fieldName[key&0xffff] {
			if fs.bit(en.snap.fields[key&0xffff][field]) {
				pairs[pairKey(perm, res+"."+field)] = true
			}
		}
	}

	return pairs
}
