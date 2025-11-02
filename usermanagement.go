package access

import (
	"context"

	"github.com/cccteam/access/store"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

var _ UserManager = &userManager{}

type userManager struct {
	enforcer *Enforcer
	domains  Domains
	store    store.Store
}

func newUserManager(domains Domains, store store.Store) (*userManager, error) {
	enforcer := NewEnforcer(store)

	u := &userManager{
		store:    store,
		enforcer: enforcer,
		domains:  domains,
	}

	return u, nil
}

func (u *userManager) AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRoleUsers()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		dbUser, err := u.store.UserByName(ctx, user.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.UserByName()")
		}
		if dbUser == nil {
			// Create the user if they don't exist.
			newUser := &store.User{Name: user.Marshal()}
			userID, err := u.store.CreateUser(ctx, newUser)
			if err != nil {
				return errors.Wrap(err, "store.CreateUser()")
			}
			dbUser = newUser
			dbUser.ID = userID
		}
		if err := u.store.CreateUserRoleMap(ctx, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
			return errors.Wrap(err, "store.CreateUserRoleMap()")
		}
	}

	return nil
}

func (u *userManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddUserRoles()")
	defer span.End()

	dbUser, err := u.store.UserByName(ctx, user.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.UserByName()")
	}
	if dbUser == nil {
		// Create the user if they don't exist.
		newUser := &store.User{Name: user.Marshal()}
		userID, err := u.store.CreateUser(ctx, newUser)
		if err != nil {
			return errors.Wrap(err, "store.CreateUser()")
		}
		dbUser = newUser
		dbUser.ID = userID
	}

	for _, role := range roles {
		dbRole, err := u.store.RoleByName(ctx, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
		if err := u.store.CreateUserRoleMap(ctx, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
			return errors.Wrap(err, "store.CreateUserRoleMap()")
		}
	}

	return nil
}

func (u *userManager) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRoleUsers()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		dbUser, err := u.store.UserByName(ctx, user.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.UserByName()")
		}
		if dbUser == nil {
			return httpio.NewNotFoundMessagef("user %q is not a valid user. Please check that the user exists.", string(user))
		}
		if err := u.store.DeleteUserRoleMap(ctx, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
			return errors.Wrap(err, "store.DeleteUserRoleMap()")
		}
	}

	return nil
}

func (u *userManager) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	return nil
}

func (u *userManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteUserRoles()")
	defer span.End()

	dbUser, err := u.store.UserByName(ctx, user.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.UserByName()")
	}
	if dbUser == nil {
		return httpio.NewNotFoundMessagef("user %q is not a valid user. Please check that the user exists.", string(user))
	}

	for _, role := range roles {
		dbRole, err := u.store.RoleByName(ctx, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
		if err := u.store.DeleteUserRoleMap(ctx, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
			return errors.Wrap(err, "store.DeleteUserRoleMap()")
		}
	}

	return nil
}

func (u *userManager) User(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.User()")
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	return u.user(ctx, user, domains)
}

func (u *userManager) user(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.user()")
	defer span.End()

	roles, err := u.UserRoles(ctx, user, domains...)
	if err != nil {
		return nil, err
	}

	permissions, err := u.UserPermissions(ctx, user, domains...)
	if err != nil {
		return nil, err
	}

	return &UserAccess{
		Name:        string(user),
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

func (u *userManager) Users(ctx context.Context, domains ...accesstypes.Domain) ([]*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Users()")
	defer span.End()

	dbUsers, err := u.store.ListUsers(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "store.ListUsers()")
	}

	users := make([]*UserAccess, len(dbUsers))
	for i, dbUser := range dbUsers {
		user, err := u.user(ctx, accesstypes.User(dbUser.Name), domains)
		if err != nil {
			return nil, err
		}
		users[i] = user
	}

	return users, nil
}

func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserRoles()")
	defer span.End()

	dbUser, err := u.store.UserByName(ctx, user.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.UserByName()")
	}
	if dbUser == nil {
		return nil, httpio.NewNotFoundMessagef("user %q is not a valid user. Please check that the user exists.", string(user))
	}

	userRoles := make(accesstypes.RoleCollection)
	for _, domain := range domains {
		dbRoles, err := u.store.ListUserRoles(ctx, dbUser.ID, domain.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "store.ListUserRoles()")
		}

		roles := make([]accesstypes.Role, len(dbRoles))
		for i, r := range dbRoles {
			roles[i] = accesstypes.Role(r.Name)
		}
		userRoles[domain] = roles
	}

	return userRoles, nil
}

func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserPermissions()")
	defer span.End()

	dbUser, err := u.store.UserByName(ctx, user.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.UserByName()")
	}
	if dbUser == nil {
		return nil, httpio.NewNotFoundMessagef("user %q is not a valid user. Please check that the user exists.", string(user))
	}

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, domain := range domains {
		dbPerms, err := u.store.ListUserPermissions(ctx, dbUser.ID, domain.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "store.ListUserPermissions()")
		}

		perms := make(map[accesstypes.Resource][]accesstypes.Permission)
		for _, p := range dbPerms {
			dbResources, err := u.store.ListUserPermissionResources(ctx, dbUser.ID, p.ID, domain.Marshal())
			if err != nil {
				return nil, errors.Wrap(err, "store.ListUserPermissionResources()")
			}

			for _, r := range dbResources {
				perms[accesstypes.Resource(r.Name)] = append(perms[accesstypes.Resource(r.Name)], accesstypes.Permission(p.Name))
			}
		}
		userPermissions[domain] = perms
	}

	return userPermissions, nil
}

func (u *userManager) AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRole()")
	defer span.End()

	if exists, err := u.DomainExists(ctx, domain); err != nil {
		return errors.Wrap(err, "domainExists()")
	} else if !exists {
		return httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	roleDoesExist, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleDoesExist != nil {
		return httpio.NewConflictMessagef("role %q already exists", string(role))
	}

	_, err = u.store.CreateRole(ctx, &store.Role{Name: role.Marshal()})
	if err != nil {
		return errors.Wrap(err, "store.CreateRole()")
	}

	return nil
}

func (u *userManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Roles()")
	defer span.End()

	dbRoles, err := u.store.ListRoles(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "store.ListRoles()")
	}

	roles := make([]accesstypes.Role, len(dbRoles))
	for i, r := range dbRoles {
		roles[i] = accesstypes.Role(r.Name)
	}

	return roles, nil
}

func (u *userManager) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRole()")
	defer span.End()

	if err := u.store.DeleteRole(ctx, role.Marshal()); err != nil {
		return false, errors.Wrap(err, "store.DeleteRole()")
	}

	return true, nil
}

func (u *userManager) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRolePermissions()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, p := range permissions {
		dbPerm, err := u.store.PermissionByName(ctx, p.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.PermissionByName()")
		}
		if dbPerm == nil {
			return httpio.NewNotFoundMessagef("permission %q is not a valid permission. Please check that the permission exists.", string(p))
		}

		permResID, err := u.store.CreatePermissionResourceMap(ctx, dbPerm.ID, 0)
		if err != nil {
			return errors.Wrap(err, "store.CreatePermissionResourceMap()")
		}

		if _, err := u.store.CreateRoleMap(ctx, dbRole.ID, permResID); err != nil {
			return errors.Wrap(err, "store.CreateRoleMap()")
		}
	}

	return nil
}

func (u *userManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRolePermissionResources()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	dbPerm, err := u.store.PermissionByName(ctx, permission.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.PermissionByName()")
	}
	if dbPerm == nil {
		return httpio.NewNotFoundMessagef("permission %q is not a valid permission. Please check that the permission exists.", string(permission))
	}

	for _, r := range resources {
		dbRes, err := u.store.ResourceByName(ctx, r.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.ResourceByName()")
		}
		if dbRes == nil {
			return httpio.NewNotFoundMessagef("resource %q is not a valid resource. Please check that the resource exists.", string(r))
		}

		permResID, err := u.store.CreatePermissionResourceMap(ctx, dbPerm.ID, dbRes.ID)
		if err != nil {
			return errors.Wrap(err, "store.CreatePermissionResourceMap()")
		}

		if _, err := u.store.CreateRoleMap(ctx, dbRole.ID, permResID); err != nil {
			return errors.Wrap(err, "store.CreateRoleMap()")
		}
	}

	return nil
}

func (u *userManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRolePermissions()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, p := range permissions {
		dbPerm, err := u.store.PermissionByName(ctx, p.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.PermissionByName()")
		}
		if dbPerm == nil {
			return httpio.NewNotFoundMessagef("permission %q is not a valid permission. Please check that the permission exists.", string(p))
		}

		permResID, err := u.store.CreatePermissionResourceMap(ctx, dbPerm.ID, 0)
		if err != nil {
			return errors.Wrap(err, "store.CreatePermissionResourceMap()")
		}

		if err := u.store.DeleteRolePermissionMap(ctx, dbRole.ID, permResID); err != nil {
			return errors.Wrap(err, "store.DeleteRolePermissionMap()")
		}
	}

	return nil
}

func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRolePermissionResources()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	dbPerm, err := u.store.PermissionByName(ctx, permission.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.PermissionByName()")
	}
	if dbPerm == nil {
		return httpio.NewNotFoundMessagef("permission %q is not a valid permission. Please check that the permission exists.", string(permission))
	}

	for _, r := range resources {
		dbRes, err := u.store.ResourceByName(ctx, r.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.ResourceByName()")
		}
		if dbRes == nil {
			return httpio.NewNotFoundMessagef("resource %q is not a valid resource. Please check that the resource exists.", string(r))
		}

		permResID, err := u.store.CreatePermissionResourceMap(ctx, dbPerm.ID, dbRes.ID)
		if err != nil {
			return errors.Wrap(err, "store.CreatePermissionResourceMap()")
		}

		if err := u.store.DeleteRolePermissionMap(ctx, dbRole.ID, permResID); err != nil {
			return errors.Wrap(err, "store.DeleteRolePermissionMap()")
		}
	}

	return nil
}

func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.RoleUsers()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return nil, httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	dbUsers, err := u.store.ListRoleUsers(ctx, dbRole.ID, domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.ListRoleUsers()")
	}

	users := make([]accesstypes.User, len(dbUsers))
	for i, u := range dbUsers {
		users[i] = accesstypes.User(u.Name)
	}

	return users, nil
}

func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.RolePermissions()")
	defer span.End()

	dbRole, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.RoleByName()")
	}
	if dbRole == nil {
		return nil, httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	dbPerms, err := u.store.ListRolePermissions(ctx, dbRole.ID, domain.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.ListRolePermissions()")
	}

	perms := make(accesstypes.RolePermissionCollection)
	for _, p := range dbPerms {
		dbResources, err := u.store.ListRolePermissionResources(ctx, dbRole.ID, p.ID, domain.Marshal())
		if err != nil {
			return nil, errors.Wrap(err, "store.ListRolePermissionResources()")
		}

		resources := make([]accesstypes.Resource, len(dbResources))
		for i, r := range dbResources {
			resources[i] = accesstypes.Resource(r.Name)
		}
		perms[accesstypes.Permission(p.Name)] = resources
	}

	return perms, nil
}

func (u *userManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	_, span := otel.Tracer(name).Start(ctx, "client.RoleExists()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return false
	}

	return roleExists != nil
}

func (u *userManager) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Domains()")
	defer span.End()

	ids, err := u.domains.DomainIDs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.GuarantorIDs()")
	}

	domains := make([]accesstypes.Domain, 1, len(ids)+1)
	domains[0] = accesstypes.GlobalDomain
	for _, v := range ids {
		domains = append(domains, accesstypes.Domain(v))
	}

	return domains, nil
}

func (u *userManager) hasUsersAssigned(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	return false, nil
}

// DomainExists checks if the domain exists in the application.
func (u *userManager) DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DomainExists()")
	defer span.End()

	if domain == accesstypes.GlobalDomain {
		return true, nil
	}
	exists, err := u.domains.DomainExists(ctx, string(domain))
	if err != nil {
		return false, errors.Wrap(err, "dbx.DB.GuarantorExists()")
	}

	return exists, nil
}