// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"context"
	"fmt"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/resource"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

type RoleConfig struct {
	Roles []*Role `json:"roles"`
}

type Role struct {
	Name        accesstypes.Role
	Permissions map[accesstypes.Permission][]accesstypes.Resource
}

// MigrateRoles runs through and adds the specified roles with specific permissions to the application
func MigrateRoles(ctx context.Context, client UserManager, store *resource.Collection, roleConfig *RoleConfig) error {
	ctx, span := otel.Tracer(name).Start(ctx, "MigrateRoles()")
	defer span.End()

	// Default Administrator role has all permissions
	roleConfig.Roles = append(roleConfig.Roles, &Role{
		Name:        "Administrator",
		Permissions: store.List(),
	})

	if err := bootstrapRoles(ctx, client, store, roleConfig.Roles); err != nil {
		return errors.Wrap(err, "bootstrapRoles()")
	}

	return nil
}

func bootstrapRoles(ctx context.Context, client UserManager, store *resource.Collection, roles []*Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "bootstrapRoles()")
	defer span.End()

	domains, err := client.Domains(ctx)
	if err != nil {
		return errors.Wrap(err, "UserManager.Domains()")
	}

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
					if r.Name != "Administrator" {
						return errors.Newf("role %s cannot have update permission on immutable resource %s", r.Name, resource)
					}
				}
			}
		}

		for _, domain := range domains {
			if !client.RoleExists(ctx, domain, r.Name) {
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
