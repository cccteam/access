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
// checks fail closed on anything unknown.
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

// CheckUser returns the subset of resources that user does NOT hold perm on
// within domain, preserving input order; an empty result means everything
// passed. A resource is either a parent name ("employees") or a single field
// on a parent ("employees.name"); accesstypes.GlobalResource checks the
// domain-wide permission itself.
//
// There is no domain validation: an unknown domain simply holds no grants, so
// everything comes back missing (fail closed). Callers wanting to distinguish
// "invalid tenant" from "no permission" validate the domain in their own
// guard, against the source that owns tenants.
func (c *Client) CheckUser(
	ctx context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (missing []accesstypes.Resource, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.checkUser(ctx, user, domain, perm, resources...)
}

// CheckRole returns the subset of resources that role does NOT hold perm on
// within domain, preserving input order; an empty result means everything
// passed. See CheckUser for the resource shape and domain semantics.
func (c *Client) CheckRole(
	ctx context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (missing []accesstypes.Resource, err error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.checkRole(ctx, role, domain, perm, resources...)
}

// UserManager returns the UserManager for managing users, roles, and permissions.
func (c *Client) UserManager() UserManager {
	return c.userManager
}
