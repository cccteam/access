package access

import (
	"fmt"
	"strings"

	"github.com/cccteam/ccc/accesstypes"
)

// This file flags the existence probe a role configuration can open. A
// Delete, an Update, and a targeted Execute locate their row first and answer
// NotFound when it is absent, then evaluate the grant's condition and answer
// Forbidden when it fails. A read hides a row its condition does not select
// behind the same NotFound. So a role holding a conditional write on a
// resource it can neither Read nor List learns, from the response code alone,
// that a row exists — without changing it. MigrateRoles provisions the grant
// as written and says so: the combination can be legitimate, and the check is
// a heuristic (a Read whose condition is narrower than the write's leaks the
// same way). An unconditional write reveals existence only by succeeding,
// which is what the grant permits, so it is not flagged.

// GrantWarning is one grant MigrateRoles provisions as written but flags: a
// conditional Delete, Update, or targeted Execute in a role that holds neither
// Read nor List on the row resource the grant checks.
type GrantWarning struct {
	// Role holds the grant; Scope is the scope the role is declared at.
	Role  accesstypes.Role
	Scope accesstypes.PermissionScope

	// Permission and Resource name the grant: the row resource for Delete and
	// Update, the method for Execute.
	Permission accesstypes.Permission
	Resource   accesstypes.Resource

	// Row is the row resource whose existence the response code reveals: the
	// grant's own resource, or the method's @target.
	Row accesstypes.Resource

	// Condition is the grant's condition text.
	Condition string
}

// String renders the warning as one line: what is granted, what the answer
// reveals, and what closes it.
func (w GrantWarning) String() string {
	row := string(w.Row)
	if w.Row != w.Resource {
		row = fmt.Sprintf("its @target %s", w.Row)
	}

	return fmt.Sprintf("role %s: %s on %s is granted under %q without Read or List on %s: a Forbidden answer tells the caller a %s row exists where a read would answer NotFound. Grant Read or List on %s in this role or in a role assigned with it, or accept the disclosure; a Read whose condition is narrower than this one leaks the same way.",
		w.Role, w.Permission, w.Resource, w.Condition, row, w.Row, w.Row)
}

// grantWarnings flags the role's conditional Delete, Update, and targeted
// Execute grants whose row resource the role can neither Read nor List, in
// permission, resource, condition order. It reads the expanded grant set, so a
// grant carrying fields is one warning for its base row, not one per field.
func grantWarnings(store PermissionCollection, role *Role, scope accesstypes.PermissionScope, set grantSet) []GrantWarning {
	var warnings []GrantWarning
	for _, perm := range []accesstypes.Permission{accesstypes.Delete, accesstypes.Execute, accesstypes.Update} {
		for _, res := range sortedResources(set[perm]) {
			if strings.ContainsRune(string(res), '.') {
				continue
			}

			row := res
			if perm == accesstypes.Execute {
				// A method without a @target locates no row: its conditions
				// are row-free and settle at decode time.
				target, targeted := store.MethodTarget(scope, res)
				if !targeted {
					continue
				}
				row = target
			}
			if set.reads(row) {
				continue
			}

			for _, condition := range sortedConditions(set[perm][res]) {
				if condition == "" {
					continue
				}
				warnings = append(warnings, GrantWarning{
					Role:       role.Name,
					Scope:      scope,
					Permission: perm,
					Resource:   res,
					Row:        row,
					Condition:  condition,
				})
			}
		}
	}

	return warnings
}
