package access

import (
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/go-playground/errors/v5"
)

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

func (u *userManager) refreshEnforcer() casbin.IEnforcer {
	u.initEnforcer()

	return u.loadPolicy()
}

func (u *userManager) initEnforcer() {
	u.enforcerMu.RLock()
	if u.enforcerInitialized {
		u.enforcerMu.RUnlock()

		return
	}
	u.enforcerMu.RUnlock()

	u.enforcerMu.Lock()
	defer u.enforcerMu.Unlock()

	if u.enforcerInitialized {
		// lost race for lock
		return
	}
	// won race for lock

	a, err := u.adapter.NewAdapter()
	if err != nil {
		panic(errors.Wrapf(err, "pgxadapter.NewAdapter(): failed to create casbin adapter with db"))
	}

	u.enforcer.SetAdapter(a)

	u.enforcerInitialized = true
}

func (u *userManager) loadPolicy() casbin.IEnforcer {
	u.policyMu.RLock()
	if u.policyLoaded {
		defer u.policyMu.RUnlock()

		return u.enforcer
	}
	u.policyMu.RUnlock()

	u.policyMu.Lock()
	defer u.policyMu.Unlock()

	if u.policyLoaded {
		return u.enforcer
	}

	if err := u.enforcer.LoadPolicy(); err != nil {
		panic(errors.Wrapf(err, "casbin.SyncedEnforcer.LoadPolicy()"))
	}

	u.policyLoaded = true

	go func() {
		time.Sleep(time.Minute)
		u.policyMu.Lock()
		u.policyLoaded = false
		u.policyMu.Unlock()
	}()

	return u.enforcer
}
