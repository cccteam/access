package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// UserResourceChecker is the single engine call a UserChecker delegates to.
// *Client satisfies it; test doubles that script permission checks satisfy it
// with the same method they already fake.
type UserResourceChecker interface {
	CheckUserResources(
		ctx context.Context, env accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (accesstypes.Decisions, error)
}

// UserChecker is the request-bound permission checker for one user: the
// canonical implementation of the resource package's UserPermissions seam.
// Its method set structurally satisfies that interface without either package
// importing the other; an application's per-request accessor is one line —
// return client.ForUser(user).
//
// A UserChecker binds the user only. Scope and Environment arrive per check
// from the caller, so one value serves every check in a request.
type UserChecker struct {
	checker UserResourceChecker
	user    accesstypes.User
}

// NewUserChecker returns a UserChecker for user over checker. Applications
// use Client.ForUser (or Controller.ForUser); this constructor exists so test
// doubles implementing UserResourceChecker can satisfy Controller.ForUser in
// one line.
func NewUserChecker(checker UserResourceChecker, user accesstypes.User) *UserChecker {
	return &UserChecker{checker: checker, user: user}
}

// Check returns the Decision for perm on each of resources within scope for
// the bound user. It is a pure delegate to CheckUserResources — see there for
// the Decision, grouping, Environment, and scope semantics.
func (u *UserChecker) Check(
	ctx context.Context, env accesstypes.Environment, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (accesstypes.Decisions, error) {
	decisions, err := u.checker.CheckUserResources(ctx, env, u.user, scope, perm, resources...)
	if err != nil {
		return nil, errors.Wrap(err, "access.UserResourceChecker.CheckUserResources()")
	}

	return decisions, nil
}

// User returns the bound user.
func (u *UserChecker) User() accesstypes.User {
	return u.user
}
