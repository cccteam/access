// Package access implements tools to manage access to resources.
package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
)

var _ Controller = &Client{}

// Client is the main access control client for permission checking and user management.
type Client struct {
	evaluator   evaluator
	snapEngine  *snapshotEngine
	userManager *userManager
}

// New creates a new Client over a policy store built by one of the store
// subpackages (spannerstore, postgresstore).
//
// Permission checks are answered by the snapshot engine, compiled in-memory
// from the policy store and kept fresh by a background heartbeat plus an
// optional push hint (see WithChangeSignal). All policy writes (user
// management, MigrateRoles) go through the same store and refresh the
// snapshot immediately on this instance.
//
// The store's values — domains, users, resources — are opaque labels to
// access: referential validity belongs to the callers that write them, and
// checks fail closed on anything unknown. Whether an operation addresses a
// tenant domain or the global partition is expressed by accesstypes.Scope,
// never by a distinguished value.
func New(store Store, opts ...Option) (*Client, error) {
	options := defaultClientOptions()
	for _, opt := range opts {
		opt(options)
	}

	manager := newStoreManager(store)
	snapEngine := newSnapshotEngine(store, options)
	manager.onPolicyChange = snapEngine.policyChanged

	return &Client{
		evaluator:   snapEngine,
		snapEngine:  snapEngine,
		userManager: newUserManager(manager),
	}, nil
}

// WaitReady blocks until the first policy snapshot has loaded (or ctx
// expires). Wire it into readiness probes so instances receive traffic only
// once permission checks can be answered.
func (c *Client) WaitReady(ctx context.Context) error {
	return c.snapEngine.waitReady(ctx)
}

// Close stops the Client's background policy reloading and change-signal
// watch. Permission checks keep answering from the last loaded snapshot.
func (c *Client) Close() error {
	return c.snapEngine.close()
}

// Handlers returns the Handlers for enforcing access control
func (c *Client) Handlers(logHandler LogHandler) Handlers {
	return newHandler(c, logHandler)
}

// CheckUser returns the Decision for whether user holds perm scope-wide —
// attached to no resource — within scope.
//
// The Environment is the per-request decision context (sampled once per
// request). The engine folds environment-referencing conditions against it
// at check time; a condition referencing an attribute the Environment does
// not carry is a check error, never a silent allow or deny. Today's snapshot
// evaluator holds no conditions, so the parameter is deliberately unused and
// the answer is always Granted or Denied — the seam is ABAC-ready ahead of
// the condition vocabulary.
//
// There is no scope validation: an unknown tenant simply holds no grants, so
// the check fails closed. Callers wanting to distinguish "invalid tenant"
// from "no permission" validate the tenant in their own guard, against the
// source that owns tenants.
func (c *Client) CheckUser(ctx context.Context, _ accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission) (accesstypes.Decision, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	ok, err := c.evaluator.checkUser(ctx, user, scope, perm)
	if err != nil {
		return accesstypes.Denied(), err
	}
	if !ok {
		return accesstypes.Denied(), nil
	}

	return accesstypes.Granted(), nil
}

// CheckUserResources returns the Decision for each resource for whether user
// holds perm on it within scope — all answered from a single policy
// snapshot, so a revocation can never land between two answers of the same
// call. A resource is either a parent name ("employees") or a single field
// on a parent ("employees.name"). See CheckUser for the Environment and
// scope semantics.
func (c *Client) CheckUserResources(
	ctx context.Context, _ accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (accesstypes.Decisions, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	missing, err := c.evaluator.checkUserResources(ctx, user, scope, perm, resources...)
	if err != nil {
		return nil, err
	}

	denied := make(map[accesstypes.Resource]struct{}, len(missing))
	for _, resource := range missing {
		denied[resource] = struct{}{}
	}

	decisions := make(accesstypes.Decisions, len(resources))
	for _, resource := range resources {
		if _, ok := denied[resource]; ok {
			decisions[resource] = accesstypes.Denied()
		} else {
			decisions[resource] = accesstypes.Granted()
		}
	}

	return decisions, nil
}

// CheckRole reports whether role holds perm scope-wide within scope. See
// CheckUser for the scope semantics.
func (c *Client) CheckRole(ctx context.Context, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.checkRole(ctx, role, scope, perm)
}

// CheckRoleResources returns the subset of resources that role does NOT hold
// perm on within scope, preserving input order; an empty result means
// everything passed. See CheckUserResources for the resource shape.
func (c *Client) CheckRoleResources(
	ctx context.Context, role accesstypes.Role, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (missing []accesstypes.Resource, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.checkRoleResources(ctx, role, scope, perm, resources...)
}

// UserManager returns the UserManager for managing users, roles, and permissions.
func (c *Client) UserManager() UserManager {
	return c.userManager
}
