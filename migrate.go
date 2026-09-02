package access

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/go-playground/errors/v5"
)

// PermissionCollection is the set of permission-registry and condition-vocabulary
// operations MigrateRoles draws on. *resource.GeneratedCollection satisfies this
// interface.
type PermissionCollection interface {
	List() map[accesstypes.Permission][]accesstypes.Resource
	Scope(res accesstypes.Resource) accesstypes.PermissionScope
	IsResourceImmutable(scope accesstypes.PermissionScope, res accesstypes.Resource) bool

	// The condition vocabulary: attribute names with their comparison types,
	// and the application-wide subject namespace. Grant conditions validate
	// against these at deploy time.
	AttributeComparisonType(scope accesstypes.PermissionScope, res accesstypes.Resource, name string) (accesstypes.AttributeType, bool)
	AttributeIsColumn(scope accesstypes.PermissionScope, res accesstypes.Resource, name string) bool
	DeclaresSubjectSet(name string) bool
	DeclaresSubjectValue(name string) bool

	// IsComputedResource reports whether res is a computed resource: a
	// hand-written query surface whose permission checks run at decode time,
	// where no row exists — so its grants accept only row-free conditions,
	// exactly as Execute grants do.
	IsComputedResource(scope accesstypes.PermissionScope, res accesstypes.Resource) bool
}

// administratorRole is the default role granted all permissions by MigrateRoles.
const administratorRole accesstypes.Role = "Administrator"

// RoleConfig contains the roles to migrate, declared by scope.
type RoleConfig struct {
	Roles ScopedRoles `json:"roles"`
}

// ScopedRoles declares every role at exactly one scope, structurally — each
// scope its own JSON key, mirroring how accesstypes.Scope and role assignments
// express the global partition. A role describes powers at one scope: a global
// role carries grants on global-scoped resources and is reconciled into the
// global partition only; a domain role carries grants on domain-scoped
// resources and is reconciled into every tenant partition. A grant whose
// resource's scope contradicts the role's declared scope fails the migration —
// it would otherwise be provisioned into a partition the role's holders never
// look in. A job function needing both kinds of powers is two roles assigned
// to one user, never one mixed role.
type ScopedRoles struct {
	Global []*Role `json:"global"`
	Domain []*Role `json:"domain"`
}

// Role defines role name and permissions granted.
type Role struct {
	Name        accesstypes.Role                   `json:"name"`
	Permissions map[accesstypes.Permission][]Grant `json:"permissions"`
}

// Grant is one authored unit of a role's configuration: a permission (the map
// key above) on one resource, covering a field set, optionally limited by one
// condition. MigrateRoles expands it into the stored base and field grant
// rows, all carrying the same condition — the construction invariant the
// check seams and the read gate lean on: a conditional base decision's
// payload is always exactly the union its field decisions deliver.
type Grant struct {
	// Resource is the base resource name. A dotted field resource is legal
	// only as a bare mechanical grant (no Fields, no Condition) — fields
	// belong in Fields, and conditions are authored per grant, never per
	// field (the pairing invariant).
	Resource accesstypes.Resource `json:"resource"`

	// Fields is the field set the grant covers, spelled as the fields' wire
	// tags; each expands to a Resource.field grant row.
	Fields []accesstypes.Tag `json:"fields,omitempty"`

	// Condition is the grant's limiting condition in the condition expression
	// language; empty is unconditional. One condition scopes exactly this
	// grant's field set.
	Condition string `json:"condition,omitempty"`
}

// expand returns the grant's stored resource rows: the base resource plus one
// dotted resource per field.
func (g Grant) expand() []accesstypes.Resource {
	resources := make([]accesstypes.Resource, 0, len(g.Fields)+1)
	resources = append(resources, g.Resource)
	for _, field := range g.Fields {
		resources = append(resources, g.Resource.ResourceWithTag(field))
	}

	return resources
}

// MigrateRoles applies role configuration across the given tenant domains:
// adds missing roles, grants, and conditions, removes extras, and includes an
// Administrator role at each scope carrying every permission registered there.
//
// Roles are declared at exactly one scope (see ScopedRoles): global roles are
// reconciled into the global partition only, domain roles into every tenant
// partition, and a role whose grants contradict its declared scope fails the
// migration.
//
// The caller states its tenant universe explicitly; the global scope is
// always included structurally (global-scoped grants live there), so
// global-only applications pass no domains at all. Domains are opaque tenant
// labels — any string is a legal tenant name, their validity is the caller's
// business, and a domain not listed here is never reconciled.
func MigrateRoles(ctx context.Context, client UserManager, store PermissionCollection, roleConfig *RoleConfig, domains ...accesstypes.Domain) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := validateRoleNames(roleConfig.Roles); err != nil {
		return err
	}

	// The default Administrator role holds every permission its scope
	// registers — one copy per scope, like any other role.
	globalRoles := append(slices.Clone(roleConfig.Roles.Global), &Role{
		Name:        administratorRole,
		Permissions: adminGrants(store, accesstypes.GlobalPermissionScope),
	})
	domainRoles := append(slices.Clone(roleConfig.Roles.Domain), &Role{
		Name:        administratorRole,
		Permissions: adminGrants(store, accesstypes.DomainPermissionScope),
	})

	scopes := make([]accesstypes.Scope, 0, len(domains)+1)
	scopes = append(scopes, accesstypes.GlobalScope())
	for _, d := range domains {
		scopes = append(scopes, accesstypes.DomainScope(d))
	}

	if err := bootstrapRoles(ctx, client, store, globalRoles, domainRoles, scopes); err != nil {
		return errors.Wrap(err, "bootstrapRoles()")
	}

	return nil
}

// validateRoleNames enforces the declaration grammar: every role name is
// declared once, at exactly one scope, and Administrator is never authored —
// it is provisioned automatically at both scopes.
func validateRoleNames(roles ScopedRoles) error {
	seen := make(map[accesstypes.Role]string)
	check := func(list []*Role, kind string) error {
		for _, r := range list {
			if r.Name == administratorRole {
				return errors.Newf("role %q is provisioned automatically with every permission at each scope; do not declare it", administratorRole)
			}
			if prev, taken := seen[r.Name]; taken {
				if prev == kind {
					return errors.Newf("role %s is declared twice in the %s roles", r.Name, kind)
				}

				return errors.Newf("role %s is declared in both the global and domain roles — a role describes powers at exactly one scope; declare two roles with distinct names", r.Name)
			}
			seen[r.Name] = kind
		}

		return nil
	}
	if err := check(roles.Global, "global"); err != nil {
		return err
	}

	return check(roles.Domain, "domain")
}

// grantSet is one permission scope's desired grants: for each permission,
// each stored resource row with its condition text ("" = unconditional).
type grantSet map[accesstypes.Permission]map[accesstypes.Resource]string

func (s grantSet) add(perm accesstypes.Permission, res accesstypes.Resource, condition string) {
	if s[perm] == nil {
		s[perm] = make(map[accesstypes.Resource]string)
	}
	s[perm][res] = condition
}

func bootstrapRoles(ctx context.Context, client UserManager, store PermissionCollection, globalRoles, domainRoles []*Role, scopes []accesstypes.Scope) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := removeUnusedRoles(ctx, scopes, client, globalRoles, domainRoles); err != nil {
		return err
	}

	// Expansion validates a role's grants against its declared scope, so it
	// runs once per role, not once per tenant partition.
	globalGrants, err := expandAllRoleGrants(store, globalRoles, accesstypes.GlobalPermissionScope)
	if err != nil {
		return err
	}
	domainGrants, err := expandAllRoleGrants(store, domainRoles, accesstypes.DomainPermissionScope)
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		roles, grants := domainRoles, domainGrants
		if scope.IsGlobal() {
			roles, grants = globalRoles, globalGrants
		}

		for i, r := range roles {
			if err := reconcileRole(ctx, client, scope, r.Name, grants[i]); err != nil {
				return err
			}
		}
	}

	return nil
}

// reconcileRole brings one role in one scope partition to its desired grant
// set: the role row is created if missing, extra grants are removed, and
// missing grants are added.
func reconcileRole(ctx context.Context, client UserManager, scope accesstypes.Scope, role accesstypes.Role, desired grantSet) error {
	roleFound, err := client.RoleExists(ctx, scope, role)
	if err != nil {
		return errors.Wrapf(err, "role %q in scope %s", role, scope)
	}
	if !roleFound {
		if err := client.AddRole(ctx, scope, role); err != nil {
			return errors.Wrapf(err, "role %q to scope %s", role, scope)
		}
		fmt.Printf("Added role %q to scope %s\n", role, scope)
	}

	existing, err := client.RoleGrants(ctx, scope, role)
	if err != nil {
		return errors.Wrapf(err, "role %q to scope %s", role, scope)
	}

	// A grant whose condition changed appears in both sets: removed
	// first, then re-added with the new condition.
	removals := diffGrants(existing, desired)
	for _, perm := range sortedPermissions(removals) {
		resources := sortedResources(removals[perm])
		if err := client.DeleteRolePermissionResources(ctx, scope, role, perm, resources...); err != nil {
			return errors.Wrapf(err, "removing %s grants from role %s", perm, role)
		}
		fmt.Printf("Removed %s on %v from role %s in scope %s\n", perm, resources, role, scope)
	}

	additions := diffGrants(desired, existing)
	for _, perm := range sortedPermissions(additions) {
		for _, res := range sortedResources(additions[perm]) {
			if err := client.AddRoleGrant(ctx, scope, role, perm, res, additions[perm][res]); err != nil {
				return errors.Wrapf(err, "adding %s on %s to role %s", perm, res, role)
			}
		}
		fmt.Printf("Added %s on %v to role %s in scope %s\n", perm, sortedResources(additions[perm]), role, scope)
	}

	return nil
}

// expandAllRoleGrants expands each role's grants, indexed like the input slice.
func expandAllRoleGrants(store PermissionCollection, roles []*Role, declared accesstypes.PermissionScope) ([]grantSet, error) {
	sets := make([]grantSet, 0, len(roles))
	for _, r := range roles {
		set, err := expandRoleGrants(store, r, declared)
		if err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}

	return sets, nil
}

// expandRoleGrants validates one role's authored grants against its declared
// scope and expands them into the grant set MigrateRoles reconciles. A grant on
// a resource whose scope contradicts the declaration is rejected: it would be
// provisioned into a partition the role's holders never look in.
func expandRoleGrants(store PermissionCollection, r *Role, declared accesstypes.PermissionScope) (grantSet, error) {
	storePermissions := store.List()
	desired := make(grantSet)
	seen := make(map[accesstypes.Permission]map[accesstypes.Resource]struct{})

	for perm, grants := range r.Permissions {
		for _, grant := range grants {
			if strings.ContainsRune(string(grant.Resource), '.') && (len(grant.Fields) > 0 || grant.Condition != "") {
				return nil, errors.Newf("role %s: grant on %s: a dotted field resource takes no Fields or Condition — name the base resource and put fields in Fields", r.Name, grant.Resource)
			}
			if seen[perm] == nil {
				seen[perm] = make(map[accesstypes.Resource]struct{})
			}
			if _, dup := seen[perm][grant.Resource]; dup {
				return nil, errors.Newf("role %s: two %s grants on %s — a role grants one permission on a resource exactly once; different condition and field-set combinations are separate roles", r.Name, perm, grant.Resource)
			}
			seen[perm][grant.Resource] = struct{}{}

			if grant.Condition != "" {
				if err := validateGrantCondition(store, r.Name, perm, grant); err != nil {
					return nil, err
				}
			}

			for _, res := range grant.expand() {
				scope := store.Scope(res)
				if scope == "" {
					return nil, errors.Newf("resource %s does not require a permission or does not exist", res)
				}
				if !slices.Contains(storePermissions[perm], res) {
					return nil, errors.Newf("resource %s does not require permission %s", res, perm)
				}
				if perm == accesstypes.Update && store.IsResourceImmutable(scope, res) {
					return nil, errors.Newf("role %s cannot have update permission on immutable resource %s", r.Name, res)
				}
				if scope != declared {
					return nil, errors.Newf("role %s is a %s role but grants %s on %s, a %s-scoped resource — a role's grants live at its declared scope; move the grant to a %s role", r.Name, declared, perm, res, scope, scope)
				}

				desired.add(perm, res, grant.Condition)
			}
		}
	}

	return desired, nil
}

// removeUnusedRoles deletes every role a scope partition holds that its
// declared role list no longer names — the global list for the global scope,
// the domain list for every tenant scope.
func removeUnusedRoles(ctx context.Context, scopes []accesstypes.Scope, client UserManager, globalRoles, domainRoles []*Role) error {
	for _, scope := range scopes {
		declared := domainRoles
		if scope.IsGlobal() {
			declared = globalRoles
		}

		existingRoles, err := client.Roles(ctx, scope)
		if err != nil {
			return errors.Wrap(err, "client.Roles()")
		}

	EXISTING:
		for _, er := range existingRoles {
			for _, nr := range declared {
				if nr.Name == er {
					continue EXISTING
				}
			}
			if _, err := client.DeleteRole(ctx, scope, er); err != nil {
				return errors.Wrap(err, "client.DeleteRole()")
			}
			fmt.Printf("Removed old Role %s from scope %s\n", er, scope)
		}
	}

	return nil
}

// diffGrants returns the grants present in source whose (resource, condition)
// pair is absent from exclude — a grant with a changed condition counts as
// absent, so it lands in both the removal and addition halves of a
// reconciliation.
func diffGrants(source, exclude grantSet) grantSet {
	out := make(grantSet)
	for perm, resources := range source {
		for res, condition := range resources {
			if other, ok := exclude[perm][res]; ok && other == condition {
				continue
			}
			out.add(perm, res, condition)
		}
	}

	return out
}

func sortedPermissions(s grantSet) []accesstypes.Permission {
	perms := make([]accesstypes.Permission, 0, len(s))
	for perm := range s {
		perms = append(perms, perm)
	}
	slices.Sort(perms)

	return perms
}

func sortedResources(m map[accesstypes.Resource]string) []accesstypes.Resource {
	resources := make([]accesstypes.Resource, 0, len(m))
	for res := range m {
		resources = append(resources, res)
	}
	slices.Sort(resources)

	return resources
}

// adminGrants grants the scope's Administrator every permission registered at
// that scope, unconditionally, withholding update on immutable resources. Each
// registered resource row becomes its own mechanical grant.
func adminGrants(store PermissionCollection, scope accesstypes.PermissionScope) map[accesstypes.Permission][]Grant {
	grants := make(map[accesstypes.Permission][]Grant)
	for perm, resources := range store.List() {
		for _, res := range resources {
			if store.Scope(res) != scope {
				continue
			}
			if perm == accesstypes.Update && store.IsResourceImmutable(scope, res) {
				continue
			}
			grants[perm] = append(grants[perm], Grant{Resource: res})
		}
	}

	return grants
}
