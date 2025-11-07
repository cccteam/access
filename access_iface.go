package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/validator/v10"
)

type Access interface {
	UserManager
	Handlers(validate *validator.Validate, handler LogHandler) Handlers
	RequireAll(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, permissions ...accesstypes.Permission) error
	RequireResources(
		ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (ok bool, missing []accesstypes.Resource, err error)
}

type Domains interface {
	DomainIDs(ctx context.Context) ([]string, error)
	DomainExists(ctx context.Context, guarantorID string) (bool, error)
}
