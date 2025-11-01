package access

import (
	"context"

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
		if err := u.store.CreateUserRoleMap(ctx, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
			return errors.Wrap(err, "store.CreateUserRoleMap()")
		}
	}

	return nil
}

func (u *userManager) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	return nil
}

func (u *userManager) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	return nil
}

func (u *userManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
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
	return nil, nil
}

func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, domains ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	_, span := otel.Tracer(name).Start(ctx, "client.userRoles()")
	defer span.End()

	userRoles := make(accesstypes.RoleCollection)
	for _, domain := range domains {
		userRoles[domain] = []accesstypes.Role{}
	}
	return userRoles, nil
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

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, domain := range domains {
		userPermissions[domain] = make(map[accesstypes.Resource][]accesstypes.Permission)
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

	_, err = u.store.CreateRole(ctx, &Role{Name: role.Marshal()})
	if err != nil {
		return errors.Wrap(err, "store.CreateRole()")
	}

	return nil
}

func (u *userManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	return nil, nil
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
	return nil
}

func (u *userManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	return nil
}

func (u *userManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	return nil
}

func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	return nil
}

func (u *userManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	return nil, nil
}

func (u *userManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
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
