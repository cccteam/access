package access

import (
	"fmt"
	"slices"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// SkippedGrant reports a grant the policy store holds that the running release
// cannot use: its condition does not parse, a row-referencing condition sits
// on a scope-wide grant, or, when the Client was given its PermissionCollection
// (WithPermissionCollection), it names a permission, resource or field the
// release does not declare. The snapshot loaded without the grant, so the
// permission it would grant is denied and the rest of the policy is in force.
// One report per such grant reaches the reload-error hook
// (WithReloadErrorHandler) each time a snapshot compiles; the default hook
// writes it to the log. Test for it with errors.As.
type SkippedGrant struct {
	Scope accesstypes.Scope
	// Subject is the grant's holder: "role Chief" or "user dana".
	Subject    string
	Permission accesstypes.Permission
	// Resource is the dotted resource name ("Widgets", "Widgets.price"); it is
	// empty for a scope-wide grant.
	Resource  accesstypes.Resource
	Condition string
	Reason    error
}

// Error prints the grant and the reason in one sentence.
func (e *SkippedGrant) Error() string {
	target := "scope-wide"
	if e.Resource != "" {
		target = "on " + string(e.Resource)
	}
	condition := ""
	if e.Condition != "" {
		condition = fmt.Sprintf(" under condition %q", e.Condition)
	}

	return fmt.Sprintf("skipped a grant this release cannot use, so it is denied: %s in scope %s, %s %s%s: %v", e.Subject, e.Scope, e.Permission, target, condition, e.Reason)
}

// Unwrap returns the reason.
func (e *SkippedGrant) Unwrap() error {
	return e.Reason
}

// newSkippedGrant builds the report for a grant record.
func newSkippedGrant(g *policy.Grant, reason error) *SkippedGrant {
	return &SkippedGrant{
		Scope:      g.Scope,
		Subject:    subjectLabel(g.Subject),
		Permission: g.Perm,
		Resource:   grantResourceName(g),
		Condition:  g.Condition,
		Reason:     reason,
	}
}

// subjectLabel names a grant's holder for a report.
func subjectLabel(s policy.Subject) string {
	if s.Kind == policy.SubjectRole {
		return "role " + s.Name
	}

	return "user " + s.Name
}

// grantResourceName is the dotted name a grant record addresses: the base
// resource for an endpoint or all-fields grant, base.field for a field grant,
// empty for a scope-wide grant.
func grantResourceName(g *policy.Grant) accesstypes.Resource {
	if g.Resource == "" {
		return ""
	}
	if g.Field == "" || g.Field == "*" {
		return accesstypes.Resource(g.Resource)
	}

	return joinResourceField(g.Resource, g.Field)
}

// unusableName says why a resource grant names a permission, resource or field
// the collection does not declare, or nil when it does. The rule is
// MigrateRoles' own: the dotted resource must be listed under the permission.
// A scope-wide grant is not checked: the collection lists the permissions
// resources require, which is not every permission a role may hold.
func unusableName(collection PermissionCollection, g *policy.Grant) error {
	if g.Resource == "" {
		return nil
	}

	resources, known := collection.List()[g.Perm]
	if !known {
		return errors.Newf("this release has no permission %s", g.Perm)
	}
	name := grantResourceName(g)
	if !slices.Contains(resources, name) {
		return errors.Newf("this release declares no %s on %s", g.Perm, name)
	}

	return nil
}
