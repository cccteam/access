package access

import (
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// Normalized policy records are the seam between store readers and the snapshot
// compiler: a reader turns a store into records; everything after (interning,
// bitsets, caches) is one shared code path. The casbin_rule reader below is the
// first reader; the new-tables reader arrives with the storage swap, and reader
// equivalence is testable as read_casbin(rows) == read_newtables(migrate(rows)).

// allowEffect is the only policy effect ever written or evaluated
// (additive-only invariant: there is no evaluation-time deny).
const allowEffect = "allow"

// subjectKind discriminates who a grant or membership row refers to.
type subjectKind uint8

const (
	subjectRole subjectKind = iota
	subjectUser
)

// subject is a grant target: normally a role, but casbin also honors policy
// rows written directly against a user, so the evaluator must too.
type subject struct {
	kind subjectKind
	name string // bare (unprefixed) role or user name
}

// grantRecord is one normalized permission grant.
//   - field == "" is an endpoint grant on the resource itself.
//   - field == "*" grants all fields by implication (compiles to an all-flag,
//     never materialized bits, so newly generated fields are covered).
//   - otherwise it grants the single named field.
type grantRecord struct {
	domain   accesstypes.Domain
	subject  subject
	perm     accesstypes.Permission
	resource string // bare base resource name
	field    string
}

// membershipRecord is one normalized role membership. member is usually a
// user; a role member expresses role inheritance, which casbin resolves
// transitively and the compiler folds at load time.
type membershipRecord struct {
	domain accesstypes.Domain
	member subject
	role   accesstypes.Role
}

// policyRecords is a reader's complete, store-agnostic output.
type policyRecords struct {
	grants      []grantRecord
	memberships []membershipRecord
}

// readCasbinPolicy loads every rule from a casbin_rule store and normalizes it.
// It reads through the same persist.Adapter load path casbin itself uses, so
// row parsing stays byte-identical to the write path's view of the store.
func readCasbinPolicy(adapter persist.Adapter) (*policyRecords, error) {
	m, err := model.NewModelFromString(rbacModel())
	if err != nil {
		return nil, errors.Wrap(err, "model.NewModelFromString()")
	}

	if err := adapter.LoadPolicy(m); err != nil {
		return nil, errors.Wrap(err, "persist.Adapter.LoadPolicy()")
	}

	policies, err := m.GetPolicy("p", "p")
	if err != nil {
		return nil, errors.Wrap(err, "model.Model.GetPolicy(p)")
	}
	groupings, err := m.GetPolicy("g", "g")
	if err != nil {
		return nil, errors.Wrap(err, "model.Model.GetPolicy(g)")
	}

	records := &policyRecords{
		grants:      make([]grantRecord, 0, len(policies)),
		memberships: make([]membershipRecord, 0, len(groupings)),
	}

	for _, p := range policies {
		grant, ok, err := normalizeGrant(p)
		if err != nil {
			return nil, err
		}
		if ok {
			records.grants = append(records.grants, grant)
		}
	}

	for _, g := range groupings {
		membership, ok, err := normalizeMembership(g)
		if err != nil {
			return nil, err
		}
		if ok {
			records.memberships = append(records.memberships, membership)
		}
	}

	return records, nil
}

// normalizeGrant transforms one casbin p row [sub, dom, obj, act, eft].
// Returns ok=false for rows that can never take effect (noop subject).
func normalizeGrant(row []string) (grantRecord, bool, error) {
	if len(row) < 4 {
		return grantRecord{}, false, errors.Newf("malformed policy row %q: want at least [sub, dom, obj, act]", row)
	}
	if len(row) >= 5 && row[4] != "" && row[4] != allowEffect {
		// Additive-only evaluation is a named invariant: nothing writes deny and
		// the snapshot engine has no evaluation-time deny. A deny row appearing
		// means the store violated the invariant; refuse to compile a snapshot
		// that would silently diverge from it.
		return grantRecord{}, false, errors.Newf("policy row %q has effect %q: only allow is supported", row, row[4])
	}

	sub, ok := normalizeSubject(row[0])
	if !ok {
		return grantRecord{}, false, nil
	}

	resource, field := splitResourceField(strings.TrimPrefix(row[2], "resource:"))

	return grantRecord{
		domain:   accesstypes.Domain(strings.TrimPrefix(row[1], "domain:")),
		subject:  sub,
		perm:     accesstypes.Permission(strings.TrimPrefix(row[3], "perm:")),
		resource: resource,
		field:    field,
	}, true, nil
}

// normalizeMembership transforms one casbin g row [member, role, dom].
// Returns ok=false for the noop sentinel, which exists only to make empty
// roles enumerable and is excluded from evaluation by the casbin matcher.
func normalizeMembership(row []string) (membershipRecord, bool, error) {
	if len(row) < 3 {
		return membershipRecord{}, false, errors.Newf("malformed grouping row %q: want [member, role, dom]", row)
	}

	member, ok := normalizeSubject(row[0])
	if !ok {
		return membershipRecord{}, false, nil
	}

	return membershipRecord{
		domain: accesstypes.Domain(strings.TrimPrefix(row[2], "domain:")),
		member: member,
		role:   accesstypes.Role(strings.TrimPrefix(row[1], "role:")),
	}, true, nil
}

// normalizeSubject classifies a marshaled casbin subject by its prefix.
// Returns ok=false for subjects that can never take effect: the noop sentinel
// (excluded by the casbin matcher) and unprefixed names (request subjects
// always arrive Marshal-prefixed, so casbin can never match such rows;
// treating them as users would grant what casbin denies).
func normalizeSubject(s string) (subject, bool) {
	if role, ok := strings.CutPrefix(s, "role:"); ok {
		return subject{kind: subjectRole, name: role}, true
	}
	if user, ok := strings.CutPrefix(s, "user:"); ok {
		return subject{kind: subjectUser, name: user}, true
	}

	return subject{}, false
}

// splitResourceField splits a stored object name on its last '.' into the base
// resource and field. Splitting both grant rows and checked resources with the
// same rule preserves casbin's exact-string-match semantics for named fields.
func splitResourceField(obj string) (resource, field string) {
	i := strings.LastIndexByte(obj, '.')
	if i < 0 {
		return obj, ""
	}

	return obj[:i], obj[i+1:]
}
