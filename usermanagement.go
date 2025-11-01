package access

import (
	"context"
	"maps"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

var _ UserManager = &userManager{}

type userManager struct {
	enforcer *Enforcer
	domains  Domains
	store    Store
}

func newUserManager(domains Domains, store Store) (*userManager, error) {
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

	roleFound, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleFound == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		_ = user
		// TODO: Implement
	}

	return nil
}

func (u *userManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddUserRoles()")
	defer span.End()

	for _, role := range roles {
		roleFound, err := u.store.RoleByName(ctx, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if roleFound == nil {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
	}

	for _, role := range roles {
		_ = role
		// TODO: Implement
	}

	return nil
}

func (u *userManager) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRoleUsers()")
	defer span.End()

	roleFound, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleFound == nil {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		_ = user
		// TODO: Implement
	}

	return nil
}

func (u *userManager) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteAllRolePermissions()")
	defer span.End()

	perms, err := u.RolePermissions(ctx, domain, role)
	if err != nil {
		return errors.Wrap(err, "client.RolePermissions()")
	}

	if err := u.DeleteRolePermissions(ctx, domain, role, slices.Collect(maps.Keys(perms))...); err != nil {
		return errors.Wrap(err, "client.DeleteRolePermissions()")
	}

	return nil
}

func (u *userManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	_, span := otel.Tracer(name).Start(ctx, "client.DeleteUserRoles()")
	defer span.End()

	for _, role := range roles {
		_ = role
		// TODO: Implement
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

	roles, err := u.userRoles(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	permissions, err := u.userPermissions(ctx, user, domains)
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

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	users, err := u.users(ctx, domains)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *userManager) users(ctx context.Context, domains []accesstypes.Domain) ([]*UserAccess, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.users()")
	defer span.End()

	// TODO: Implement
	return nil, nil
}

// UserRoles gets the roles assigned to a user separated by domain
func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserRoles()")
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userRoles, err := u.userRoles(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	return userRoles, nil
}

func (u *userManager) userRoles(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (accesstypes.RoleCollection, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.userRoles()")
	defer span.End()

	// TODO: Implement
	return nil, nil
}

func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.UserPermissions()")
	defer span.End()

	if domains == nil {
		var err error
		domains, err = u.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	userPermissions, err := u.userPermissions(ctx, user, domains)
	if err != nil {
		return nil, err
	}

	return userPermissions, nil
}

func (u *userManager) userPermissions(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.userPermissions()")
	defer span.End()

	// TODO: Implement
	return nil, nil
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

	if err := u.store.CreateRole(ctx, &role); err != nil {
		return errors.Wrap(err, "store.CreateRole()")
	}

	return nil
}

func (u *userManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.Roles()")
	defer span.End()

	if exists, err := u.DomainExists(ctx, domain); err != nil {
		return nil, errors.Wrap(err, "domainExists()")
	} else if !exists {
		return nil, httpio.NewNotFoundMessagef("domain %q does not exist", string(domain))
	}

	// TODO: Implement
	return nil, nil
}

func (u *userManager) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRole()")
	defer span.End()

	// TODO: Implement
	return false, nil
}

func (u *userManager) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRolePermissions()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleExists == nil {
		return httpio.NewNotFoundMessagef("Permissions cannot be added to a role that doesn't exist")
	}

	for _, permission := range permissions {
		_ = permission
		// TODO: Implement
	}

	return nil
}

func (u *userManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.AddRolePermissions()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleExists == nil {
		return httpio.NewNotFoundMessagef("Permissions cannot be added to a role that doesn't exist")
	}

	for _, resource := range resources {
		_ = resource
		// TODO: Implement
	}

	return nil
}

func (u *userManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRolePermissions()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleExists == nil {
		return httpio.NewNotFoundMessagef("Permissions cannot be removed from a role that doesn't exist")
	}

	for _, permission := range permissions {
		_ = permission
		// TODO: Implement
	}

	return nil
}

func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := otel.Tracer(name).Start(ctx, "client.DeleteRolePermissionResourcess()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return errors.Wrap(err, "store.RoleByName()")
	}
	if roleExists == nil {
		return httpio.NewNotFoundMessagef("Permissions cannot be removed from a role that doesn't exist")
	}

	for _, resource := range resources {
		_ = resource
		// TODO: Implement
	}

	return nil
}

func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.RoleUsers()")
	defer span.End()

	// TODO: Implement
	return nil, nil
}

func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := otel.Tracer(name).Start(ctx, "client.RolePermissions()")
	defer span.End()

	roleExists, err := u.store.RoleByName(ctx, role.Marshal())
	if err != nil {
		return nil, errors.Wrap(err, "store.RoleByName()")
	}
	if roleExists == nil {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	// TODO: Implement
	return nil, nil
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
	_, span := otel.Tracer(name).Start(ctx, "client.hasUsersAssigned()")
	defer span.End()

	// TODO: Implement
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
