// Package access implements tools to manage access to resources.
package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"go.opentelemetry.io/otel"
)

const name = "github.com/cccteam/access"

var _ Controller = &Client{}

// Client is the main access control client for permission checking and user management.
type Client struct {
	userManager *userManager
}

// New creates a new Client with specified domains and adapter. Errors if user manager initialization fails.
func New(domains Domains, adapter Adapter) (*Client, error) {
	userManager, err := newUserManager(domains, adapter)
	if err != nil {
		return nil, errors.Wrap(err, "newUserManager()")
	}

	return &Client{
		userManager: userManager,
	}, nil
}

// Handlers returns the Handlers for enforcing access control
func (c *Client) Handlers(logHandler LogHandler) Handlers {
	return newHandler(c, logHandler)
}

// RequireAll checks if user has all permissions in domain. Errors if domain invalid or user lacks permissions.
func (c *Client) RequireAll(ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perms ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "App.RequireAll()")
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return err
	} else if !exists {
		return httpio.NewBadRequestMessage("Invalid Domain")
	}

	for _, perm := range perms {
		authorized, err := c.userManager.Enforcer().Enforce(username.Marshal(), domain.Marshal(), accesstypes.GlobalResource.Marshal(), perm.Marshal())
		if err != nil {
			return errors.Wrap(err, "casbin.IEnforcer Enforce()")
		}
		if !authorized {
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
	ctx, span := otel.Tracer(name).Start(ctx, "App.RequireResources()")
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return false, nil, err
	} else if !exists {
		return false, nil, httpio.NewBadRequestMessage("Invalid Domain")
	}

	missing := make([]accesstypes.Resource, 0)
	for _, resource := range resources {
		authorized, err := c.userManager.Enforcer().Enforce(username.Marshal(), domain.Marshal(), resource.Marshal(), perm.Marshal())
		if err != nil {
			return false, nil, errors.Wrap(err, "casbin.IEnforcer Enforce()")
		}
		if !authorized {
			missing = append(missing, resource)
		}
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
