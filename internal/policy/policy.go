// Package policy defines the normalized policy records that flow between a
// policy store and the snapshot compiler: a store reader turns rows into
// records; everything after (interning, bitsets, caches) is one shared code
// path in the access package. The package is internal by design — the public
// access.Store interface references these types in its method signatures, so
// only packages inside this module can implement a store.
package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"
	"strings"

	"github.com/cccteam/ccc/accesstypes"
)

// SubjectKind discriminates who a grant or membership row refers to.
type SubjectKind uint8

// The two subject kinds: a role or a user.
const (
	SubjectRole SubjectKind = iota
	SubjectUser
)

// Subject is a grant target or membership holder. The typed stores only ever
// produce role grant subjects and user members; the compiler additionally
// supports user-direct grants and role-to-role membership (inheritance), so
// the record model does too.
type Subject struct {
	Kind SubjectKind
	Name string // bare (unprefixed) role or user name
}

// Grant is one normalized permission grant.
//   - Resource == "" (with Field == "") is a scope-wide grant: the permission
//     is held with no resource attachment. Real resource names are validated
//     non-empty at every write boundary, so "" is structurally unreachable
//     from data — it is the store-level encoding of absence, the same idiom
//     as Field == "".
//   - Field == "" is an endpoint grant on the resource itself.
//   - Field == "*" grants all fields by implication (compiles to an all-flag,
//     never materialized bits, so newly generated fields are covered).
//   - otherwise it grants the single named field.
//   - Condition == "" is an unconditional grant (a NULL store column);
//     otherwise it is the grant's condition as opaque expression text. The
//     records carry the text verbatim — nothing below the snapshot compiler
//     interprets it, and the compiler only interns it (the expression
//     language is undesigned).
type Grant struct {
	Scope     accesstypes.Scope
	Subject   Subject
	Perm      accesstypes.Permission
	Resource  string // bare base resource name; "" = scope-wide
	Field     string
	Condition string // opaque expression text; "" = unconditional
}

// Membership is one normalized role membership. Member is usually a user; a
// role member expresses role inheritance, which the compiler folds at load
// time. The typed stores only ever produce user members.
type Membership struct {
	Scope  accesstypes.Scope
	Member Subject
	Role   accesstypes.Role
}

// Records is a reader's complete, store-agnostic output.
type Records struct {
	Grants      []Grant
	Memberships []Membership
}

// RoleGrant is one stored grant row scoped to an already-known (domain, role):
// the shape a store returns for role-grant listings.
type RoleGrant struct {
	Perm      accesstypes.Permission
	Resource  string // bare base resource name
	Field     string // '' endpoint · '*' all fields · field name
	Condition string // opaque expression text; "" = unconditional
}

// Hash returns a canonical content hash of the records: independent of row
// order (stores return rows in arbitrary order) but sensitive to any change
// in effective policy. The heartbeat compares it to decide whether a fresh
// read needs a recompile and snapshot swap.
func (r *Records) Hash() [sha256.Size]byte {
	grants := slices.Clone(r.Grants)
	slices.SortFunc(grants, compareGrants)
	memberships := slices.Clone(r.Memberships)
	slices.SortFunc(memberships, compareMemberships)

	h := sha256.New()
	for _, g := range grants {
		hashString(h, "g")
		hashScope(h, g.Scope)
		hashByte(h, byte(g.Subject.Kind))
		hashString(h, g.Subject.Name)
		hashString(h, string(g.Perm))
		hashString(h, g.Resource)
		hashString(h, g.Field)
		hashString(h, g.Condition)
	}
	for _, m := range memberships {
		hashString(h, "m")
		hashScope(h, m.Scope)
		hashByte(h, byte(m.Member.Kind))
		hashString(h, m.Member.Name)
		hashString(h, string(m.Role))
	}

	return [sha256.Size]byte(h.Sum(nil))
}

//nolint:gocritic // slices.SortFunc requires value-typed comparators
func compareGrants(a, b Grant) int {
	return cmpChain(
		compareScopes(a.Scope, b.Scope),
		int(a.Subject.Kind)-int(b.Subject.Kind),
		strings.Compare(a.Subject.Name, b.Subject.Name),
		strings.Compare(string(a.Perm), string(b.Perm)),
		strings.Compare(a.Resource, b.Resource),
		strings.Compare(a.Field, b.Field),
		strings.Compare(a.Condition, b.Condition),
	)
}

func compareMemberships(a, b Membership) int {
	return cmpChain(
		compareScopes(a.Scope, b.Scope),
		int(a.Member.Kind)-int(b.Member.Kind),
		strings.Compare(a.Member.Name, b.Member.Name),
		strings.Compare(string(a.Role), string(b.Role)),
	)
}

func compareScopes(a, b accesstypes.Scope) int {
	ag, ad := ScopeColumns(a)
	bg, bd := ScopeColumns(b)

	return cmpChain(boolCompare(ag, bg), strings.Compare(ad, bd))
}

func boolCompare(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}

// ScopeColumns decomposes a Scope into the structural column pair the stores
// persist: (global, domain), with domain "" when global. ScopeFromColumns is
// its inverse.
func ScopeColumns(s accesstypes.Scope) (global bool, domain string) {
	if s.IsGlobal() {
		return true, ""
	}
	d, _ := s.Domain()

	return false, string(d)
}

// ScopeFromColumns reassembles a Scope from its stored column pair.
func ScopeFromColumns(global bool, domain string) accesstypes.Scope {
	if global {
		return accesstypes.GlobalScope()
	}

	return accesstypes.DomainScope(accesstypes.Domain(domain))
}

// cmpChain returns the first non-zero comparison result.
func cmpChain(results ...int) int {
	for _, r := range results {
		if r != 0 {
			return r
		}
	}

	return 0
}

// hashString writes a length-prefixed string so no delimiter collision can
// make two different record sequences hash identically.
func hashString(h hash.Hash, s string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(s)))
	h.Write(length[:])
	h.Write([]byte(s))
}

func hashByte(h hash.Hash, b byte) {
	h.Write([]byte{b})
}

// hashScope writes a scope's structural pair (global flag, domain).
func hashScope(h hash.Hash, s accesstypes.Scope) {
	global, domain := ScopeColumns(s)
	var b byte
	if global {
		b = 1
	}
	hashByte(h, b)
	hashString(h, domain)
}
