package access

import (
	"context"
	"fmt"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/go-playground/errors/v5"
)

// PermissionCollection is the set of permission registry operations required by MigrateRoles.
// *resource.GeneratedCollection satisfies this interface.
type PermissionCollection interface {
	List() map[accesstypes.Permission][]accesstypes.Resource
	Scope(res accesstypes.Resource) accesstypes.PermissionScope
	IsResourceImmutable(scope accesstypes.PermissionScope, res accesstypes.Resource) bool
}

// administratorRole is the default role granted all permissions by MigrateRoles.
const administratorRole accesstypes.Role = "Administrator"

// RoleConfig contains roles for migration.
type RoleConfig struct {
	Roles []*Role `json:"roles"`
}

// Role defines role name and permissions mapped to resources.
type Role struct {
	Name        accesstypes.Role
	Permissions map[accesstypes.Permission][]accesstypes.Resource
}

// MigrateRoles applies role configuration across the given tenant domains:
// adds missing roles and permissions, removes extras, and includes the
// Administrator role with all permissions.
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
		Permissions: adminPermissions(store),
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

func bootstrapRoles(ctx context.Context, client UserManager, store PermissionCollection, roles []*Role, scopes []accesstypes.Scope) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := removeUnusedRoles(ctx, scopes, client, roles); err != nil {
		return err
	}

	storePermissions := store.List()

	for _, r := range roles {
		globalPermResources := make(map[accesstypes.Permission][]accesstypes.Resource)
		domainPermResources := make(map[accesstypes.Permission][]accesstypes.Resource)
		for perm, resources := range r.Permissions {
			for _, resource := range resources {
				if r := store.Scope(resource); r == "" {
					return errors.Newf("resource %s does not require a permission or does not exist", resource)
				} else if r == accesstypes.GlobalPermissionScope {
					globalPermResources[perm] = append(globalPermResources[perm], resource)
				} else {
					domainPermResources[perm] = append(domainPermResources[perm], resource)
				}

				if !slices.Contains(storePermissions[perm], resource) {
					return errors.Newf("resource %s does not require permission %s", resource, perm)
				}

				if perm == accesstypes.Update && store.IsResourceImmutable(store.Scope(resource), resource) {
					return errors.Newf("role %s cannot have update permission on immutable resource %s", r.Name, resource)
				}
			}
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

			perms := globalPermResources
			if !scope.IsGlobal() {
				perms = domainPermResources
			}

			existingPermissions, err := client.RolePermissions(ctx, scope, r.Name)
			if err != nil {
				return errors.Wrapf(err, "role %q to scope %s", r.Name, scope)
			}

			newPermissions := exclude(perms, resourceGrants(existingPermissions))
			for permission, resources := range newPermissions {
				if err := client.AddRolePermissionResources(ctx, scope, r.Name, permission, resources...); err != nil {
					return errors.Wrapf(err, "permissions %v, role %s", perms, r.Name)
				}
			}
			if len(newPermissions) > 0 {
				fmt.Printf("Added Permissions %v to role %s and scope %s\n", newPermissions, r.Name, scope)
			}

			removePermissions := exclude(resourceGrants(existingPermissions), perms)
			for permission, resources := range removePermissions {
				if err := client.DeleteRolePermissionResources(ctx, scope, r.Name, permission, resources...); err != nil {
					return errors.Wrapf(err, "permissions %v, role %s", perms, r.Name)
				}
			}
			if len(removePermissions) > 0 {
				fmt.Printf("Removed Permissions %v from role %s and scope %s\n", removePermissions, r.Name, scope)
			}
		}
	}

	return nil
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

// exclude returns all elements that exist in source but not exclude
func exclude(source, exclude map[accesstypes.Permission][]accesstypes.Resource) map[accesstypes.Permission][]accesstypes.Resource {
	list := make(map[accesstypes.Permission][]accesstypes.Resource)

	for sk, sv := range source {
		ev := exclude[sk]
		for _, item := range sv {
			if slices.Contains(ev, item) {
				continue
			}
			list[sk] = append(list[sk], item)
		}
	}

	return list
}

// resourceGrants projects a RolePermissionCollection onto its resource-grant
// half. MigrateRoles reconciles resource grants only: scope-wide grants have
// no writer here (RoleConfig entries are Collection-validated resource
// names), so they are ignored rather than deleted.
func resourceGrants(perms accesstypes.RolePermissionCollection) map[accesstypes.Permission][]accesstypes.Resource {
	list := make(map[accesstypes.Permission][]accesstypes.Resource, len(perms))
	for perm, grants := range perms {
		if len(grants.Resources) > 0 {
			list[perm] = grants.Resources
		}
	}

	return list
}

// The Administrator should have all legal permissions, this function will prevent any updates to immutable resources
func adminPermissions(store PermissionCollection) map[accesstypes.Permission][]accesstypes.Resource {
	list := store.List()
	list[accesstypes.Update] = slices.DeleteFunc(list[accesstypes.Update], func(res accesstypes.Resource) bool {
		return store.IsResourceImmutable(store.Scope(res), res)
	})

	return list
}
