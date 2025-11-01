package access

import (
	"context"
)

// Enforcer is responsible for checking permissions against the database.
type Enforcer struct {
	store Store
}

// NewEnforcer creates a new Enforcer with the given store.
func NewEnforcer(store Store) *Enforcer {
	return &Enforcer{store: store}
}

// Enforce checks if a user has the required permission for a resource in a domain.
func (e *Enforcer) Enforce(ctx context.Context, user, domain, resource, permission string) (bool, error) {
	ok, condition, err := e.store.CheckPermission(ctx, user, domain, resource, permission)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	// TODO: Evaluate the condition here.
	_ = condition

	return true, nil
}
