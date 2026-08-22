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

// MigrateRoles applies role configuration across the given domains: adds
// missing roles and permissions, removes extras, and includes the
// Administrator role with all permissions.
//
// The caller states its domain universe explicitly; accesstypes.GlobalDomain
// is always included (global-scoped grants live there), so global-only
// applications pass no domains at all. Domains are opaque labels — their
// validity is the caller's business, and a domain not listed here is never
// reconciled.
func MigrateRoles(ctx context.Context, client UserManager, store PermissionCollection, roleConfig *RoleConfig, domains ...accesstypes.Domain) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	// Default Administrator role has all permissions
	roleConfig.Roles = append(roleConfig.Roles, &Role{
		Name:        administratorRole,
		Permissions: adminPermissions(store),
	})

	allDomains := make([]accesstypes.Domain, 0, len(domains)+1)
	allDomains = append(allDomains, accesstypes.GlobalDomain)
	for _, d := range domains {
		if d != accesstypes.GlobalDomain {
			allDomains = append(allDomains, d)
		}
	}

	if err := bootstrapRoles(ctx, client, store, roleConfig.Roles, allDomains); err != nil {
		return errors.Wrap(err, "bootstrapRoles()")
	}

	return nil
}

func bootstrapRoles(ctx context.Context, client UserManager, store PermissionCollection, roles []*Role, domains []accesstypes.Domain) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := removeUnusedRoles(ctx, domains, client, roles); err != nil {
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

		for _, domain := range domains {
			roleFound, err := client.RoleExists(ctx, domain, r.Name)
			if err != nil {
				return errors.Wrapf(err, "role %q in domain %s", r.Name, domain)
			}
			if !roleFound {
				if err := client.AddRole(ctx, domain, r.Name); err != nil {
					return errors.Wrapf(err, "role %q to domain %s", r.Name, domain)
				}
				fmt.Printf("Added role %q to domain %s\n", r.Name, domain)
			}

			perms := globalPermResources
			if domain != accesstypes.GlobalDomain {
				perms = domainPermResources
			}

			existingPermissions, err := client.RolePermissions(ctx, domain, r.Name)
			if err != nil {
				return errors.Wrapf(err, "role %q to domain %s", r.Name, domain)
			}

			newPermissions := exclude(perms, existingPermissions)
			for permission, resources := range newPermissions {
				if err := client.AddRolePermissionResources(ctx, domain, r.Name, permission, resources...); err != nil {
					return errors.Wrapf(err, "permissions %v, role %s", perms, r.Name)
				}
			}
			if len(newPermissions) > 0 {
				fmt.Printf("Added Permissions %v to role %s and domain %s\n", newPermissions, r.Name, domain)
			}

			removePermissions := exclude(existingPermissions, perms)
			for permission, resources := range removePermissions {
				if err := client.DeleteRolePermissionResources(ctx, domain, r.Name, permission, resources...); err != nil {
					return errors.Wrapf(err, "permissions %v, role %s", perms, r.Name)
				}
			}
			if len(removePermissions) > 0 {
				fmt.Printf("Removed Permissions %v from role %s and domain %s\n", removePermissions, r.Name, domain)
			}
		}
	}

	return nil
}

func removeUnusedRoles(ctx context.Context, domains []accesstypes.Domain, client UserManager, newRoles []*Role) error {
	for _, domain := range domains {
		existingRoles, err := client.Roles(ctx, domain)
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
			if _, err := client.DeleteRole(ctx, domain, er); err != nil {
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

// The Administrator should have all legal permissions, this function will prevent any updates to immutable resources
func adminPermissions(store PermissionCollection) map[accesstypes.Permission][]accesstypes.Resource {
	list := store.List()
	list[accesstypes.Update] = slices.DeleteFunc(list[accesstypes.Update], func(res accesstypes.Resource) bool {
		return store.IsResourceImmutable(store.Scope(res), res)
	})

	return list
}
