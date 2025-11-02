package access

import (
	"context"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/validator/v10"
)

var _ Access = &Client{}

type Access interface {
	// CheckPermissions checks if a user has the given permissions in a domain
	RequireAll(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, permissions ...accesstypes.Permission) error

	// RequireResource checks if a user has the given permission for a list of resources in a domain
	RequireResources(
		ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
	) (ok bool, missing []accesstypes.Resource, err error)

	// UserManager returns the UserManager interface for managing users, roles, and permissions
	UserManager() UserManager

	// Handlers returns the http.HandlerFunc for the access package
	Handlers(validate *validator.Validate, handler LogHandler) Handlers
}

type Domains interface {
	DomainIDs(ctx context.Context) ([]string, error)

	DomainExists(ctx context.Context, guarantorID string) (bool, error)
}
