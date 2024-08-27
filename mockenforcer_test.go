package access

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/go-playground/errors/v5"
)

func mockEnforcer(path string) (casbin.IEnforcer, error) {
	m, err := model.NewModelFromString(rbacModel())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load model")
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, fileadapter.NewAdapter(path))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load policies")
	}

	return enforcer, nil
}
