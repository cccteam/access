// Package access implements tools to manage access to resources.
package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
)

var _ Controller = &Client{}

// Client is the main access control client for permission checking and user management.
type Client struct {
	evaluator   evaluator
	userManager *userManager
}

// New creates a new Client with specified domains and adapter. Errors if engine initialization fails.
//
// Permission checks are answered by the snapshot engine, compiled in-memory
// from the policy store. All policy writes (user management, MigrateRoles)
// stay on the casbin path against the same store, so storage semantics are
// unchanged.
func New(domains Domains, adapter Adapter) (*Client, error) {
	engine, err := newCasbinEngine(adapter)
	if err != nil {
		return nil, errors.Wrap(err, "newCasbinEngine()")
	}

	snapEngine := newSnapshotEngine(adapter)
	engine.onPolicyChange = snapEngine.invalidate

	return &Client{
		evaluator:   snapEngine,
		userManager: newUserManager(domains, engine),
	}, nil
}

// Handlers returns the Handlers for enforcing access control
func (c *Client) Handlers(logHandler LogHandler) Handlers {
	return newHandler(c, logHandler)
}

// RequireAll checks if user has all permissions in domain. Errors if domain invalid or user lacks permissions.
func (c *Client) RequireAll(ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perms ...accesstypes.Permission) error {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return err
	} else if !exists {
		return httpio.NewBadRequestMessage("Invalid Domain")
	}

	for _, perm := range perms {
		missing, err := c.evaluator.checkUser(ctx, username, domain, perm, accesstypes.GlobalResource)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			return httpio.NewForbiddenMessagef("user %s does not have %s", username, perm)
		}
	}

	return nil
}

// RequireResources checks if user has permission for resources in domain.
// Returns ok=true if all accessible, ok=false with missing resources otherwise. Errors if domain invalid.
func (c *Client) RequireResources(
	ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (bool, []accesstypes.Resource, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return false, nil, err
	} else if !exists {
		return false, nil, httpio.NewBadRequestMessage("Invalid Domain")
	}

	missing, err := c.evaluator.checkUser(ctx, username, domain, perm, resources...)
	if err != nil {
		return false, nil, err
	}

	if len(missing) > 0 {
		return false, missing, nil
	}

	return true, nil, nil
}

// RoleRequireResources checks if role has permission for resources in domain.
// Returns ok=true if all resources are accessible, ok=false with missing resources otherwise.
func (c *Client) RoleRequireResources(
	ctx context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (bool, []accesstypes.Resource, error) {
	ctx, span := tracer.Start(ctx)
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return false, nil, err
	} else if !exists {
		return false, nil, httpio.NewBadRequestMessage("Invalid Domain")
	}

	missing, err := c.evaluator.checkRole(ctx, role, domain, perm, resources...)
	if err != nil {
		return false, nil, err
	}

	if len(missing) > 0 {
		return false, missing, nil
	}

	return true, nil, nil
}

// UserManager returns the UserManager for managing users, roles, and permissions.
func (c *Client) UserManager() UserManager {
	return c.userManager
}
