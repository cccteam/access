package access

import (
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/go-playground/errors/v5"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

func (c *Client) refreshEnforcer() casbin.IEnforcer {
	if err := c.initEnforcer(); err != nil {
		panic(err)
	}

	return c.loadPolicy()
}

func (c *Client) initEnforcer() error {
	c.enforcerMu.RLock()
	if c.enforcerInitialized {
		defer c.enforcerMu.RUnlock()

		return nil
	}
	c.enforcerMu.RUnlock()

	c.enforcerMu.Lock()
	defer c.enforcerMu.Unlock()

	if c.enforcerInitialized {
		// lost race for lock
		return nil
	}
	// won race for lock

	a, err := pgxadapter.NewAdapter(c.connConfig, pgxadapter.WithDatabase(c.connConfig.Database), pgxadapter.WithTableName("AccessPolicies"))
	if err != nil {
		return errors.Wrapf(err, "pgxadapter.NewAdapter(): failed to create casbin adapter with db")
	}

	c.enforcer.SetAdapter(a)

	c.enforcerInitialized = true

	return nil
}

func (c *Client) loadPolicy() casbin.IEnforcer {
	c.policyMu.RLock()
	if c.policyLoaded {
		defer c.policyMu.RUnlock()

		return c.enforcer
	}
	c.policyMu.RUnlock()

	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	if c.policyLoaded {
		return c.enforcer
	}

	if err := c.enforcer.LoadPolicy(); err != nil {
		panic(errors.Wrapf(err, "casbin.SyncedEnforcer.LoadPolicy()"))
	}

	c.policyLoaded = true

	go func() {
		time.Sleep(time.Minute)
		c.policyMu.Lock()
		c.policyLoaded = false
		c.policyMu.Unlock()
	}()

	return c.enforcer
}

func createEnforcer(rbacModel string) (*casbin.SyncedEnforcer, error) {
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, errors.Wrap(err, "model.NewModelFromString()")
	}

	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, errors.Wrapf(err, "casbin.NewSyncedEnforcer()")
	}

	e.EnableAutoSave(true)

	return e, nil
}
