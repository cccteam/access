// package access implements tools to manage access to resources. It is a wrapper around casbin using an rbac model.
package access

import (
	"context"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/cccteam/httpio"
	"github.com/go-playground/errors/v5"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
)

const name = "github.com/cccteam/access"

// Client is the users client
type Client struct {
	connConfig *pgx.ConnConfig
	domains    Domains
	Enforcer   func() casbin.IEnforcer

	policyMu     sync.RWMutex
	policyLoaded bool

	enforcerMu          sync.RWMutex
	enforcer            casbin.IEnforcer
	enforcerInitialized bool
}

// New creates a new user client
func New(domains Domains, connConfig *pgx.ConnConfig) (*Client, error) {
	enforcer, err := createEnforcer(rbacModel())
	if err != nil {
		return nil, err
	}

	c := &Client{
		domains:    domains,
		connConfig: connConfig,
		enforcer:   enforcer,
	}

	c.Enforcer = c.refreshEnforcer

	return c, nil
}

func (c *Client) Handlers(validate *validator.Validate, logHandler LogHandler) Handlers {
	return newHandler(c, validate, logHandler)
}

func (c *Client) RequireAll(ctx context.Context, username User, domain Domain, perms ...Permission) error {
	ctx, span := otel.Tracer(name).Start(ctx, "App.Require()")
	defer span.End()

	if exists, err := c.DomainExists(ctx, domain); err != nil {
		return err
	} else if !exists {
		return httpio.NewBadRequestMessage("Invalid Domain")
	}

	for _, perm := range perms {
		authorized, err := c.Enforcer().Enforce(username.Marshal(), domain.Marshal(), "*", perm.Marshal())
		if err != nil {
			return errors.Wrap(err, "casbin.IEnforcer Enforce()")
		}
		if !authorized {
			return httpio.NewForbiddenMessagef("user %s does not have %s", username, perm)
		}
	}

	return nil
}
