package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// RoleResourceChecker is the engine surface a RoleChecker delegates to: the
// check call that answers enforcement, and the digest and domain calls that
// answer the frontend's advisory questions — the role twin of
// UserResourceChecker. *Client satisfies it; test doubles satisfy it with the
// role check they already script plus digest and domain stubs.
type RoleResourceChecker interface {
	CheckRoleResources(
		ctx context.Context, env accesstypes.Environment, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (accesstypes.Decisions, error)

	RolePermissionDigest(ctx context.Context, role accesstypes.Role, scope accesstypes.Scope) (accesstypes.PermissionDigest, error)

	RoleDomains(ctx context.Context, role accesstypes.Role) ([]accesstypes.Domain, error)
}

// RoleChecker is the request-bound permission checker for one role: what a
// session operating as a role principal checks against, and the canonical
// implementation of the resource package's RolePermissions seam. Its method
// set is UserChecker's without User(): a role has no identity of its own. The
// session's effective identity — the actor who established it — is the
// resource layer's to supply where a row condition names the subject, so
// nothing here can be mistaken for a user.
//
// A RoleChecker binds the role only. Scope and Environment arrive per check
// from the caller, so one value serves every check in a request.
type RoleChecker struct {
	checker RoleResourceChecker
	role    accesstypes.Role
}

// NewRoleChecker returns a RoleChecker for role over checker. Applications
// use Client.ForRole (or Controller.ForRole); this constructor exists so test
// doubles implementing RoleResourceChecker can satisfy Controller.ForRole in
// one line.
func NewRoleChecker(checker RoleResourceChecker, role accesstypes.Role) *RoleChecker {
	return &RoleChecker{checker: checker, role: role}
}

// Check returns the Decision for perm on each of resources within scope for
// the bound role. It is a pure delegate to CheckRoleResources — see there for
// the Decision, grouping, Environment, and scope semantics.
func (r *RoleChecker) Check(
	ctx context.Context, env accesstypes.Environment, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (accesstypes.Decisions, error) {
	decisions, err := r.checker.CheckRoleResources(ctx, env, r.role, scope, perm, resources...)
	if err != nil {
		return nil, errors.Wrap(err, "access.RoleResourceChecker.CheckRoleResources()")
	}

	return decisions, nil
}

// PermissionDigest returns the bound role's structural grant enumeration
// within scope — the frontend digest payload. It is a pure delegate to
// RolePermissionDigest; see Client.RolePermissionDigest for the non-folding
// semantics.
func (r *RoleChecker) PermissionDigest(ctx context.Context, scope accesstypes.Scope) (accesstypes.PermissionDigest, error) {
	digest, err := r.checker.RolePermissionDigest(ctx, r.role, scope)
	if err != nil {
		return nil, errors.Wrap(err, "access.RoleResourceChecker.RolePermissionDigest()")
	}

	return digest, nil
}

// Domains lists the domains where the bound role holds at least one grant,
// sorted — the tenant picker's membership question. It is a pure delegate to
// RoleDomains; see Client.RoleDomains for the foothold semantics.
func (r *RoleChecker) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	domains, err := r.checker.RoleDomains(ctx, r.role)
	if err != nil {
		return nil, errors.Wrap(err, "access.RoleResourceChecker.RoleDomains()")
	}

	return domains, nil
}

// Role returns the bound role.
func (r *RoleChecker) Role() accesstypes.Role {
	return r.role
}
