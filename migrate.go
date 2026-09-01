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
}

// administratorRole is the default role granted all permissions by MigrateRoles.
const administratorRole accesstypes.Role = "Administrator"

// RoleConfig contains roles for migration.
type RoleConfig struct {
	Roles []*Role `json:"roles"`
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
// adds missing roles, grants, and conditions, removes extras, and includes
// the Administrator role with all permissions.
//
// The caller states its tenant universe explicitly; the global scope is
// always included structurally (global-scoped grants live there), so
// global-only applications pass no domains at all. Domains are opaque tenant
// labels — any string is a legal tenant name, their validity is the caller's
// business, and a domain not listed here is never reconciled.
func MigrateRoles(ctx context.Context, client UserManager, store PermissionCollection, roleConfig *RoleConfig, domains ...accesstypes.Domain) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	// Default Administrator role has all permissions
	roleConfig.Roles = append(roleConfig.Roles, &Role{
		Name:        administratorRole,
		Permissions: adminGrants(store),
	})

	scopes := make([]accesstypes.Scope, 0, len(domains)+1)
	scopes = append(scopes, accesstypes.GlobalScope())
	for _, d := range domains {
		scopes = append(scopes, accesstypes.DomainScope(d))
	}

	if err := bootstrapRoles(ctx, client, store, roleConfig.Roles, scopes); err != nil {
		return errors.Wrap(err, "bootstrapRoles()")
	}

	return nil
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

func bootstrapRoles(ctx context.Context, client UserManager, store PermissionCollection, roles []*Role, scopes []accesstypes.Scope) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := removeUnusedRoles(ctx, scopes, client, roles); err != nil {
		return err
	}

	for _, r := range roles {
		global, domain, err := expandRoleGrants(store, r)
		if err != nil {
			return err
		}

		for _, scope := range scopes {
			roleFound, err := client.RoleExists(ctx, scope, r.Name)
			if err != nil {
				return errors.Wrapf(err, "role %q in scope %s", r.Name, scope)
			}
			if !roleFound {
				if err := client.AddRole(ctx, scope, r.Name); err != nil {
					return errors.Wrapf(err, "role %q to scope %s", r.Name, scope)
				}
				fmt.Printf("Added role %q to scope %s\n", r.Name, scope)
			}

			desired := global
			if !scope.IsGlobal() {
				desired = domain
			}

			existing, err := client.RoleGrants(ctx, scope, r.Name)
			if err != nil {
				return errors.Wrapf(err, "role %q to scope %s", r.Name, scope)
			}

			// A grant whose condition changed appears in both sets: removed
			// first, then re-added with the new condition.
			removals := diffGrants(existing, desired)
			for _, perm := range sortedPermissions(removals) {
				resources := sortedResources(removals[perm])
				if err := client.DeleteRolePermissionResources(ctx, scope, r.Name, perm, resources...); err != nil {
					return errors.Wrapf(err, "removing %s grants from role %s", perm, r.Name)
				}
				fmt.Printf("Removed %s on %v from role %s in scope %s\n", perm, resources, r.Name, scope)
			}

			additions := diffGrants(desired, existing)
			for _, perm := range sortedPermissions(additions) {
				for _, res := range sortedResources(additions[perm]) {
					if err := client.AddRoleGrant(ctx, scope, r.Name, perm, res, additions[perm][res]); err != nil {
						return errors.Wrapf(err, "adding %s on %s to role %s", perm, res, r.Name)
					}
				}
				fmt.Printf("Added %s on %v to role %s in scope %s\n", perm, sortedResources(additions[perm]), r.Name, scope)
			}
		}
	}

	return nil
}

// expandRoleGrants validates one role's authored grants and expands them into
// the global- and domain-scope grant sets MigrateRoles reconciles.
func expandRoleGrants(store PermissionCollection, r *Role) (global, domain grantSet, err error) {
	storePermissions := store.List()
	global, domain = make(grantSet), make(grantSet)
	seen := make(map[accesstypes.Permission]map[accesstypes.Resource]struct{})

	for perm, grants := range r.Permissions {
		for _, grant := range grants {
			if strings.ContainsRune(string(grant.Resource), '.') && (len(grant.Fields) > 0 || grant.Condition != "") {
				return nil, nil, errors.Newf("role %s: grant on %s: a dotted field resource takes no Fields or Condition — name the base resource and put fields in Fields", r.Name, grant.Resource)
			}
			if seen[perm] == nil {
				seen[perm] = make(map[accesstypes.Resource]struct{})
			}
			if _, dup := seen[perm][grant.Resource]; dup {
				return nil, nil, errors.Newf("role %s: two %s grants on %s — a role grants one permission on a resource exactly once; different condition and field-set combinations are separate roles", r.Name, perm, grant.Resource)
			}
			seen[perm][grant.Resource] = struct{}{}

			if grant.Condition != "" {
				if err := validateGrantCondition(store, r.Name, perm, grant); err != nil {
					return nil, nil, err
				}
			}

			for _, res := range grant.expand() {
				scope := store.Scope(res)
				if scope == "" {
					return nil, nil, errors.Newf("resource %s does not require a permission or does not exist", res)
				}
				if !slices.Contains(storePermissions[perm], res) {
					return nil, nil, errors.Newf("resource %s does not require permission %s", res, perm)
				}
				if perm == accesstypes.Update && store.IsResourceImmutable(scope, res) {
					return nil, nil, errors.Newf("role %s cannot have update permission on immutable resource %s", r.Name, res)
				}

				if scope == accesstypes.GlobalPermissionScope {
					global.add(perm, res, grant.Condition)
				} else {
					domain.add(perm, res, grant.Condition)
				}
			}
		}
	}

	return global, domain, nil
}

func removeUnusedRoles(ctx context.Context, scopes []accesstypes.Scope, client UserManager, newRoles []*Role) error {
	for _, scope := range scopes {
		existingRoles, err := client.Roles(ctx, scope)
		if err != nil {
			return errors.Wrap(err, "client.Roles()")
		}

	EXISTING:
		for _, er := range existingRoles {
			for _, nr := range newRoles {
				if nr.Name == er {
					continue EXISTING
				}
			}
			if _, err := client.DeleteRole(ctx, scope, er); err != nil {
				return errors.Wrap(err, "client.DeleteRole()")
			}
			fmt.Printf("Removed old Role %s\n", er)
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

// adminGrants grants the Administrator every registered permission,
// unconditionally, withholding update on immutable resources. Each registered
// resource row becomes its own mechanical grant.
func adminGrants(store PermissionCollection) map[accesstypes.Permission][]Grant {
	grants := make(map[accesstypes.Permission][]Grant)
	for perm, resources := range store.List() {
		for _, res := range resources {
			if perm == accesstypes.Update && store.IsResourceImmutable(store.Scope(res), res) {
				continue
			}
			grants[perm] = append(grants[perm], Grant{Resource: res})
		}
	}

	return grants
}
