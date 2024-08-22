package access

import (
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

func (c *Client) e() casbin.IEnforcer {
	c.enforcerMu.RLock()
	if c.adapterLoaded {
		defer c.enforcerMu.RUnlock()

		return c.enforcer
	}
	c.enforcerMu.RUnlock()

	// adapter needs to be loaded
	c.enforcerMu.Lock()
	defer c.enforcerMu.Unlock()

	if c.adapterLoaded {
		return c.enforcer
	}

	if err := loadAdapter(c.enforcer, c.connConfig, c.connConfig.Database); err != nil {
		panic(err)
	}
	c.adapterLoaded = true

	go func() {
		time.Sleep(time.Minute)
		c.enforcerMu.Lock()
		c.adapterLoaded = false
		c.enforcerMu.Unlock()
	}()

	return c.enforcer
}

func loadAdapter(enforcer casbin.IEnforcer, config *pgx.ConnConfig, dbName string) error {
	a, err := pgxadapter.NewAdapter(config, pgxadapter.WithDatabase(dbName), pgxadapter.WithTableName("AccessPolicies"))
	if err != nil {
		return errors.Wrapf(err, "pgxadapter.NewAdapter(): failed to create casbin adapter with db")
	}

	// FIXME: The previous adapter is not closed, which is a resource leak.
	//		we should not load the adapter more then once...
	enforcer.SetAdapter(a)

	if err := enforcer.LoadPolicy(); err != nil {
		return errors.Wrapf(err, "casbin.SyncedEnforcer.LoadPolicy()")
	}

	return nil
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
