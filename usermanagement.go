package access

import (
	"context"
	"slices"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ UserManager = &userManager{}

// userManager implements UserManager on top of the policyStore seam, the
// release's default roles and the evaluator. Validation (role existence,
// empty-input checks, the default roles' read-only rule) lives here; the
// store only persists and queries policy. Scopes are opaque partition labels
// — nothing here validates tenant existence, and no operation enumerates
// tenants: the application owns its tenant list.
type userManager struct {
	store     policyStore
	defaults  *defaultRoles
	evaluator evaluator
}

// newUserManager creates a userManager over the policy store, the release's
// default roles (nil for none) and the evaluator the effective-permission
// listings answer from.
func newUserManager(store policyStore, defaults *defaultRoles, evaluator evaluator) *userManager {
	return &userManager{
		store:     store,
		defaults:  defaults,
		evaluator: evaluator,
	}
}

// AddRoleUsers assigns role to users, the memberships held in scope. Errors
// if role doesn't exist in scope.
func (u *userManager) AddRoleUsers(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		if user == "" {
			return httpio.NewBadRequestMessage("user cannot be empty string")
		}

		if err := u.store.addUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// AddUserRoles assigns roles to user, the memberships held in scope. Errors
// if any role doesn't exist in scope.
func (u *userManager) AddUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		roleFound, err := u.RoleExists(ctx, scope, role)
		if err != nil {
			return err
		}
		if !roleFound {
			return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", role)
		}
	}

	if user == "" {
		return httpio.NewBadRequestMessage("user cannot be empty string")
	}

	for _, role := range roles {
		if err := u.store.addUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRoleUsers removes users from role, the memberships held in scope.
// Errors if role doesn't exist.
func (u *userManager) DeleteRoleUsers(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, users ...accesstypes.User) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !roleFound {
		return httpio.NewNotFoundMessagef("role %q is not a valid role. Please check that the role exists.", string(role))
	}

	for _, user := range users {
		if err := u.store.deleteUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// DeleteAllRolePermissions removes all permissions from a custom role held in
// scope, scope-wide and resource-specific alike.
func (u *userManager) DeleteAllRolePermissions(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	perms, err := u.store.roleGrants(ctx, scope, role)
	if err != nil {
		return errors.Wrap(err, "roleGrants()")
	}

	for permission, grants := range perms {
		if grants.ScopeWide {
			if err := u.store.removeScopeWideGrant(ctx, scope, role, permission); err != nil {
				return err
			}
		}
		for _, resource := range grants.Resources {
			if err := u.store.removeGrants(ctx, scope, role, permission, resource); err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteUserRoles removes user's memberships of roles held in scope. The
// operation succeeds regardless of whether the roles were previously assigned
// to the user.
func (u *userManager) DeleteUserRoles(ctx context.Context, scope accesstypes.PolicyScope, user accesstypes.User, roles ...accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	for _, role := range roles {
		if err := u.store.deleteUserRole(ctx, scope, user, role); err != nil {
			return err
		}
	}

	return nil
}

// UserRoles returns user's memberships as stored, keyed by where each is
// held: every membership with no scopes given, the memberships held in each
// given scope otherwise.
func (u *userManager) UserRoles(ctx context.Context, user accesstypes.User, scopes ...accesstypes.PolicyScope) (accesstypes.RoleCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	userRoles := make(accesstypes.RoleCollection)
	if len(scopes) == 0 {
		memberships, err := u.store.userMemberships(ctx, user)
		if err != nil {
			return nil, err
		}
		for _, m := range memberships {
			userRoles[m.Scope] = append(userRoles[m.Scope], m.Role)
		}

		return userRoles, nil
	}

	for _, scope := range scopes {
		roles, err := u.store.userRoles(ctx, scope, user)
		if err != nil {
			return nil, err
		}

		userRoles[scope] = roles
	}

	return userRoles, nil
}

// UserPermissions returns user's effective permissions in each scope,
// answered from the policy snapshot. At least one scope is required: access
// holds no tenant list of its own.
func (u *userManager) UserPermissions(ctx context.Context, user accesstypes.User, scopes ...accesstypes.Scope) (accesstypes.UserPermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if len(scopes) == 0 {
		return nil, httpio.NewBadRequestMessage("at least one scope is required")
	}

	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, scope := range scopes {
		permissions, err := u.evaluator.userPermissions(ctx, user, scope)
		if err != nil {
			return nil, err
		}

		userPermissions[scope] = permissions
	}

	return userPermissions, nil
}

// AddRole creates a custom role held in scope. The scope is an opaque
// partition label: its validity is the caller's business. A default role's
// name is taken.
func (u *userManager) AddRole(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if role == "" {
		return httpio.NewBadRequestMessage("role cannot be empty string")
	}
	if u.defaults.exists(scope, role) {
		return httpio.NewConflictMessagef("role %q is one of the release's default roles; a custom role cannot take its name", string(role))
	}

	roleDoesExist, err := u.RoleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if roleDoesExist {
		return httpio.NewConflictMessagef("role %q already exists", string(role))
	}

	if err := u.store.addRole(ctx, scope, role); err != nil {
		return err
	}

	return nil
}

// Roles returns the roles that exist in scope, sorted: the default roles of
// scope's kind and the custom roles held in scope, and in every domain for
// one domain.
func (u *userManager) Roles(ctx context.Context, scope accesstypes.PolicyScope) ([]accesstypes.Role, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roles := u.defaults.names(scope)
	customs, err := u.store.roles(ctx, scope)
	if err != nil {
		return nil, err
	}
	roles = append(roles, customs...)
	if _, oneDomain := scope.Domain(); oneDomain {
		everywhere, err := u.store.roles(ctx, accesstypes.EveryDomainPolicyScope())
		if err != nil {
			return nil, err
		}
		roles = append(roles, everywhere...)
	}
	slices.Sort(roles)

	return slices.Compact(roles), nil
}

// DeleteRole removes a custom role held in scope with its grants. It refuses
// a default role, and a role users are still assigned to in scope.
func (u *userManager) DeleteRole(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if u.defaults.exists(scope, role) {
		return false, httpio.NewBadRequestMessagef("role %q is one of the release's default roles; it cannot be deleted", string(role))
	}

	if hasUsers, err := u.hasUsersAssigned(ctx, scope, role); err != nil {
		return false, errors.Wrap(err, "client.hasUsersAssigned()")
	} else if hasUsers {
		return false, httpio.NewBadRequestMessagef("Users assigned to the role. You cannot delete a role that has users assigned")
	}

	deleted, err := u.store.deleteRole(ctx, scope, role)
	if err != nil {
		return false, err
	}

	return deleted, nil
}

// AddRolePermission grants permission to role scope-wide: the permission is
// held with no resource attachment.
func (u *userManager) AddRolePermission(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	if err := u.store.addScopeWideGrant(ctx, scope, role, permission); err != nil {
		return err
	}

	return nil
}

// DeleteRolePermission removes a scope-wide permission from role.
func (u *userManager) DeleteRolePermission(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	if err := u.store.removeScopeWideGrant(ctx, scope, role, permission); err != nil {
		return err
	}

	return nil
}

// AddRolePermissionResources grants resource-specific permissions to role.
func (u *userManager) AddRolePermissionResources(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	rows := make([]GrantRow, 0, len(resources))
	for _, resource := range resources {
		rows = append(rows, GrantRow{Permission: permission, Resource: resource})
	}

	return u.addGrantRows(ctx, scope, role, rows)
}

// AddRoleGrants writes the grants to role as one store write.
func (u *userManager) AddRoleGrants(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, grants ...GrantRow) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}

	return u.addGrantRows(ctx, scope, role, grants)
}

// addGrantRows validates the rows and hands them to the store as one write.
func (u *userManager) addGrantRows(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, rows []GrantRow) error {
	if err := requireResources(rows); err != nil {
		return err
	}

	if err := u.store.addGrants(ctx, scope, role, rows); err != nil {
		return err
	}

	return nil
}

// ChangeRoleGrants removes the removals from role and adds the additions to it
// as one store write.
func (u *userManager) ChangeRoleGrants(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, removals, additions []GrantRow) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be changed on a role that doesn't exist"); err != nil {
		return err
	}
	if err := requireResources(removals); err != nil {
		return err
	}
	if err := requireResources(additions); err != nil {
		return err
	}

	if err := u.store.changeGrants(ctx, scope, role, removals, additions); err != nil {
		return err
	}

	return nil
}

// requireResources refuses a grant row that names no resource.
func requireResources(rows []GrantRow) error {
	for _, row := range rows {
		if row.Resource == "" {
			return httpio.NewBadRequestMessage("resource cannot be empty string")
		}
	}

	return nil
}

// AddRoleGrant grants permission on one resource to role, limited by
// condition ("" is unconditional).
func (u *userManager) AddRoleGrant(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission, resource accesstypes.Resource, condition string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be added to a role that doesn't exist"); err != nil {
		return err
	}
	if resource == "" {
		return httpio.NewBadRequestMessage("resource cannot be empty string")
	}

	if err := u.store.addGrant(ctx, scope, role, permission, resource, condition); err != nil {
		return err
	}

	return nil
}

// DeleteRolePermissionResources removes resource-specific permissions from role.
func (u *userManager) DeleteRolePermissionResources(
	ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource,
) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	for _, resource := range resources {
		if err := u.store.removeGrants(ctx, scope, role, permission, resource); err != nil {
			return err
		}
	}

	return nil
}

// DeleteRoleGrant removes one grant: permission on resource under condition
// ("" is the unconditional grant). Other conditions on the resource stay.
func (u *userManager) DeleteRoleGrant(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, permission accesstypes.Permission, resource accesstypes.Resource, condition string) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if err := u.requireCustomRole(ctx, scope, role, "Permissions cannot be removed from a role that doesn't exist"); err != nil {
		return err
	}

	if err := u.store.removeGrant(ctx, scope, role, permission, resource, condition); err != nil {
		return err
	}

	return nil
}

// RoleUsers returns the users whose membership of role is held in scope.
func (u *userManager) RoleUsers(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) ([]accesstypes.User, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, scope, role)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// RolePermissions returns the permissions role holds in scope, answered from
// the policy snapshot.
func (u *userManager) RolePermissions(ctx context.Context, scope accesstypes.Scope, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	roleFound, err := u.RoleExists(ctx, scope.PolicyScope(), role)
	if err != nil {
		return nil, err
	}
	if !roleFound {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	permissions, err := u.evaluator.rolePermissions(ctx, role, scope)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// RoleGrants returns the role's resource grants as held, keyed by permission
// and resource, with the conditions each resource is granted under (sorted;
// "" is the unconditional grant).
func (u *userManager) RoleGrants(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (map[accesstypes.Permission]map[accesstypes.Resource][]string, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if set, ok := u.defaults.grantsOf(scope, role); ok {
		return set.listed(), nil
	}

	held, err := u.customRoleScope(ctx, scope, role)
	if err != nil {
		return nil, err
	}
	if held == nil {
		return nil, httpio.NewNotFoundMessagef("role %s doesn't exist", role)
	}

	grants, err := u.store.roleGrantConditions(ctx, *held, role)
	if err != nil {
		return nil, err
	}

	return grants, nil
}

// RoleExists reports whether role exists in scope: a default role of scope's
// kind, a custom role held in scope, or — for one domain — a custom role held
// in every domain.
func (u *userManager) RoleExists(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if u.defaults.exists(scope, role) {
		return true, nil
	}

	held, err := u.customRoleScope(ctx, scope, role)
	if err != nil {
		return false, err
	}

	return held != nil, nil
}

// customRoleScope finds where the custom role a request in scope would see is
// held: scope itself, or every domain when scope is one domain; nil when no
// custom role of that name is held in either.
func (u *userManager) customRoleScope(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (*accesstypes.PolicyScope, error) {
	exists, err := u.store.roleExists(ctx, scope, role)
	if err != nil {
		return nil, err
	}
	if exists {
		return &scope, nil
	}
	if _, oneDomain := scope.Domain(); !oneDomain {
		return nil, nil
	}
	everywhere := accesstypes.EveryDomainPolicyScope()
	exists, err = u.store.roleExists(ctx, everywhere, role)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	return &everywhere, nil
}

// requireCustomRole errors unless role is a custom role held in scope itself:
// a default role's grants are the release's, and a custom role held in every
// domain is changed where it is held, not through one domain.
func (u *userManager) requireCustomRole(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role, notFoundMsg string) error {
	if u.defaults.exists(scope, role) {
		return httpio.NewBadRequestMessagef("role %q is one of the release's default roles; its grants are the release's. Copy them into a custom role to change them", string(role))
	}

	exists, err := u.store.roleExists(ctx, scope, role)
	if err != nil {
		return err
	}
	if !exists {
		return httpio.NewNotFoundMessage(notFoundMsg)
	}

	return nil
}

func (u *userManager) hasUsersAssigned(ctx context.Context, scope accesstypes.PolicyScope, role accesstypes.Role) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	users, err := u.store.roleUsers(ctx, scope, role)
	if err != nil {
		return false, errors.Wrap(err, "roleUsers()")
	}

	return len(users) > 0, nil
}
