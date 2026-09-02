// Package access implements tools to manage access to resources.
package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/accesstypes/condition"
	"github.com/cccteam/ccc/tracer"
	"github.com/go-playground/errors/v5"
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
// request). The engine folds condition facts against it at check time; a
// condition referencing an attribute the Environment does not carry is a
// check error, never a silent allow or deny. The answer here is always
// Granted or Denied: a scope-wide grant carries only row-free conditions
// (row-referencing ones are rejected at snapshot load — no row exists for
// them to see), and row-free conditions fold to a definite answer. A
// condition folding leaves unsettled — a subject-attribute reference, which
// is data only the database can compare — is a check error too: there is no
// place to evaluate it on this path.
//
// There is no scope validation: an unknown tenant simply holds no grants, so
// the check fails closed. Callers wanting to distinguish "invalid tenant"
// from "no permission" validate the tenant in their own guard, against the
// source that owns tenants.
func (c *Client) CheckUser(ctx context.Context, env accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission) (accesstypes.Decision, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	decision, err := c.evaluator.checkUser(ctx, user, scope, perm)
	if err != nil {
		return accesstypes.Denied(), err
	}
	switch {
	case decision.granted:
		return accesstypes.Granted(), nil
	case len(decision.conditions) == 0:
		return accesstypes.Denied(), nil
	}

	result, err := condition.Fold(anyOf(decision.exprs), factsFor(env, user))
	if err != nil {
		return accesstypes.Denied(), errors.Wrapf(err, "folding the scope-wide conditions for user %q in scope %s", user, scope)
	}
	truth, settled := result.(condition.Truth)
	if !settled {
		return accesstypes.Denied(), errors.Newf("scope-wide conditions for user %q in scope %s did not fold to a definite answer: %q needs data no scope-wide check can reach", user, scope, result)
	}
	if !truth.Value {
		return accesstypes.Denied(), nil
	}

	return accesstypes.Granted(), nil
}

// CheckUserResources returns the Decision for each resource for whether user
// holds perm on it within scope — all answered from a single policy
// snapshot, so a revocation can never land between two answers of the same
// call. A resource is either a parent name ("employees") or a single field
// on a parent ("employees.name"). Per resource: Denied when no grant covers
// it, Granted when at least one unconditional grant covers it (conditions on
// other grants are moot), Conditional when only conditional grants cover it.
//
// Condition facts fold before the Decisions build: each covering set's
// any-of combination is evaluated against the environment's instant and the
// user's identity, so a set folding TRUE answers Granted, one folding FALSE
// answers Denied, and a Conditional decision carries only what the database
// must still evaluate — the engine folds facts, and never renders SQL. A
// condition referencing an attribute the Environment does not carry is a
// check error, never a silent allow or deny.
//
// Grouping is the engine's job — only the engine owns grant-set identity: a
// Conditional decision carries one ConditionGroup whose Resources lists
// every resource checked in this call sharing that covering-grant set, and
// the same group value appears in each member's Decision, so callers
// deduplicate by sorted-Resources equality. The distinct groups are exactly
// a write check's boolean list — OR across a group's grants inside its
// Condition, AND across groups computed by the caller — and a denial names
// the failing group's Resources. See CheckUser for the Environment and scope
// semantics.
func (c *Client) CheckUserResources(
	ctx context.Context, env accesstypes.Environment, user accesstypes.User, scope accesstypes.Scope, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (accesstypes.Decisions, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	resourceDecisions, err := c.evaluator.checkUserResources(ctx, user, scope, perm, resources...)
	if err != nil {
		return nil, err
	}

	decisions, err := newDecisions(resources, resourceDecisions, factsFor(env, user))
	if err != nil {
		return nil, errors.Wrapf(err, "conditions for user %q in scope %s", user, scope)
	}

	return decisions, nil
}

// factsFor builds the condition-folding facts for one check: the checked
// user's identity, plus the request's instant when the environment carries
// one. Absence stays absent — a condition referencing a missing fact fails
// the fold loudly, which is the designed posture.
func factsFor(env accesstypes.Environment, user accesstypes.User) condition.Facts {
	facts := condition.NewFacts().WithSubject(string(user))
	if now, ok := env.Now(); ok {
		facts = facts.WithNow(now)
	}

	return facts
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

// UserHasGrants reports whether user holds at least one grant in scope,
// answered from the in-memory policy snapshot (safe inside transactions; no
// store read). It is the visibility question concealed tenancy asks: an
// application hiding tenant existence answers a caller with no grants in a
// domain exactly as if the domain did not exist, while a caller with any
// foothold proceeds to ordinary permission checks. Role membership that
// resolves to no grants is not a foothold.
func (c *Client) UserHasGrants(ctx context.Context, user accesstypes.User, scope accesstypes.Scope) (bool, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.userHasGrants(ctx, user, scope)
}

// UserDomains lists the domains where user holds at least one grant, sorted
// — the membership question a tenant picker asks, answered from the
// in-memory policy snapshot with the same foothold predicate as
// UserHasGrants: a domain is listed exactly when its routes would answer
// user with ordinary 403s rather than a concealing 404, so a picker built on
// it can never disagree with concealed tenancy. The global scope is not a
// domain and is never listed.
//
// The answer reports grants, not tenants: a domain the application has since
// removed still lists while grants in it remain, and tenant existence stays
// the application's DomainExists seam. Like the digest it is structural and
// non-folding — no environment, no row data — so it caches cleanly per user
// for the life of a policy snapshot.
func (c *Client) UserDomains(ctx context.Context, user accesstypes.User) ([]accesstypes.Domain, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.userDomains(ctx, user)
}

// UserPermissionDigest returns user's structural grant enumeration within
// scope: every resource and field the user's grants reach, each mapping
// permission → granted (an unconditional cover exists) or conditional (only
// conditional grants cover it), with denied targets absent — fail-closed by
// construction. It is the payload of the frontend's per-scope permission
// digest and is advisory only; enforcement stays with the Check seams.
//
// Unlike the Check seams the digest never folds: it reports grant structure
// with no environment instant and no row data, so a payload is stable for
// the life of a policy snapshot and caches cleanly per scope. Scope-wide
// grants attach to no resource and are not enumerated. See CheckUser for the
// scope semantics — an unknown tenant simply holds no grants, so its digest
// is empty.
func (c *Client) UserPermissionDigest(ctx context.Context, user accesstypes.User, scope accesstypes.Scope) (accesstypes.PermissionDigest, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	return c.evaluator.userDigest(ctx, user, scope)
}

// ForUser returns the request-bound permission checker for user — the
// canonical implementation of the resource package's UserPermissions seam.
// See UserChecker.
func (c *Client) ForUser(user accesstypes.User) *UserChecker {
	return NewUserChecker(c, user)
}

// UserManager returns the UserManager for managing users, roles, and permissions.
func (c *Client) UserManager() UserManager {
	return c.userManager
}
