// package access implements tools to manage access to resources. It is a wrapper around casbin using an rbac model.
package access

import (
	"context"

	"github.com/cccteam/access/store"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel"
)

const name = "github.com/cccteam/access"

var _ Access = &Client{}

// Client is the users client
type Client struct {
	userManager *userManager
}

// New creates a new user client
func New(domains Domains, store store.Store) (*Client, error) {
	userManager, err := newUserManager(domains, store)
	if err != nil {
		return nil, errors.Wrap(err, "newUserManager()")
	}

	return &Client{
		userManager: userManager,
	}, nil
}

func (c *Client) Handlers(validate *validator.Validate, logHandler LogHandler) Handlers {
	return newHandler(c, validate, logHandler)
}

func (c *Client) RequireAll(ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perms ...accesstypes.Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "App.RequireAll()")
	defer span.End()

	if exists, err := c.userManager.DomainExists(ctx, domain); err != nil {
		return err
	} else if !exists {
		return httpio.NewBadRequestMessage("Invalid Domain")
	}

	for _, perm := range perms {
		authorized, err := c.userManager.enforcer.Enforce(ctx, username.Marshal(), domain.Marshal(), accesstypes.GlobalResource.Marshal(), perm.Marshal())
		if err != nil {
			return errors.Wrap(err, "enforcer.Enforce()")
		}
		if !authorized {
			return httpio.NewForbiddenMessagef("user %s does not have %s", username, perm)
		}
	}

	return nil
}

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
		authorized, err := c.userManager.enforcer.Enforce(ctx, username.Marshal(), domain.Marshal(), resource.Marshal(), perm.Marshal())
		if err != nil {
			return false, nil, errors.Wrap(err, "enforcer.Enforce()")
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

func (c *Client) UserManager() UserManager {
	return c.userManager
}
