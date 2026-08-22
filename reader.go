package access

import (
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// Normalized policy records (internal/policy) are the seam between store
// readers and the snapshot compiler: a reader turns a store into records;
// everything after (interning, bitsets, caches) is one shared code path. The
// casbin_rule reader below is the first reader; the new-tables stores carry
// their own readers behind the Store interface.

// allowEffect is the only policy effect ever written or evaluated
// (additive-only invariant: there is no evaluation-time deny).
const allowEffect = "allow"

// readCasbinPolicy loads every rule from a casbin_rule store and normalizes it.
// It reads through the same persist.Adapter load path casbin itself uses, so
// row parsing stays byte-identical to the write path's view of the store.
func readCasbinPolicy(adapter persist.Adapter) (*policy.Records, error) {
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

	records := &policy.Records{
		Grants:      make([]policy.Grant, 0, len(policies)),
		Memberships: make([]policy.Membership, 0, len(groupings)),
	}

	for _, p := range policies {
		grant, ok, err := normalizeGrant(p)
		if err != nil {
			return nil, err
		}
		if ok {
			records.Grants = append(records.Grants, grant)
		}
	}

	for _, g := range groupings {
		membership, ok, err := normalizeMembership(g)
		if err != nil {
			return nil, err
		}
		if ok {
			records.Memberships = append(records.Memberships, membership)
		}
	}

	return records, nil
}

// normalizeGrant transforms one casbin p row [sub, dom, obj, act, eft].
// Returns ok=false for rows that can never take effect (noop subject).
func normalizeGrant(row []string) (policy.Grant, bool, error) {
	if len(row) < 4 {
		return policy.Grant{}, false, errors.Newf("malformed policy row %q: want at least [sub, dom, obj, act]", row)
	}
	if len(row) >= 5 && row[4] != "" && row[4] != allowEffect {
		// Additive-only evaluation is a named invariant: nothing writes deny and
		// the snapshot engine has no evaluation-time deny. A deny row appearing
		// means the store violated the invariant; refuse to compile a snapshot
		// that would silently diverge from it.
		return policy.Grant{}, false, errors.Newf("policy row %q has effect %q: only allow is supported", row, row[4])
	}

	sub, ok := normalizeSubject(row[0])
	if !ok {
		return policy.Grant{}, false, nil
	}

	resource, field := splitResourceField(strings.TrimPrefix(row[2], "resource:"))

	return policy.Grant{
		Domain:   accesstypes.Domain(strings.TrimPrefix(row[1], "domain:")),
		Subject:  sub,
		Perm:     accesstypes.Permission(strings.TrimPrefix(row[3], "perm:")),
		Resource: resource,
		Field:    field,
	}, true, nil
}

// normalizeMembership transforms one casbin g row [member, role, dom].
// Returns ok=false for the noop sentinel, which exists only to make empty
// roles enumerable and is excluded from evaluation by the casbin matcher.
func normalizeMembership(row []string) (policy.Membership, bool, error) {
	if len(row) < 3 {
		return policy.Membership{}, false, errors.Newf("malformed grouping row %q: want [member, role, dom]", row)
	}

	member, ok := normalizeSubject(row[0])
	if !ok {
		return policy.Membership{}, false, nil
	}

	return policy.Membership{
		Domain: accesstypes.Domain(strings.TrimPrefix(row[2], "domain:")),
		Member: member,
		Role:   accesstypes.Role(strings.TrimPrefix(row[1], "role:")),
	}, true, nil
}

// normalizeSubject classifies a marshaled casbin subject by its prefix.
// Returns ok=false for subjects that can never take effect: the noop sentinel
// (excluded by the casbin matcher) and unprefixed names (request subjects
// always arrive Marshal-prefixed, so casbin can never match such rows;
// treating them as users would grant what casbin denies).
func normalizeSubject(s string) (policy.Subject, bool) {
	if role, ok := strings.CutPrefix(s, "role:"); ok {
		return policy.Subject{Kind: policy.SubjectRole, Name: role}, true
	}
	if user, ok := strings.CutPrefix(s, "user:"); ok {
		return policy.Subject{Kind: policy.SubjectUser, Name: user}, true
	}

	return policy.Subject{}, false
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
