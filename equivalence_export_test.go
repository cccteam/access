package access

import (
	"context"
	"time"

	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

// Test-only exports for the config-equivalence suite (equivalence_test.go,
// package access_test), which anchors the typed-store write path to the
// casbin-validated baseline while both write paths exist in-tree. This file
// is deleted together with the casbin path.

// NewCasbinUserManagerForTest returns a UserManager over the casbin write
// path, which the public constructor no longer wires.
func NewCasbinUserManagerForTest(adapter Adapter) (UserManager, error) {
	engine, err := newCasbinEngine(adapter)
	if err != nil {
		return nil, err
	}

	return newUserManager(engine), nil
}

// NewTypedStoreUserManagerForTest returns a UserManager over the typed-store
// write path (storeManager), without a Client's snapshot machinery.
func NewTypedStoreUserManagerForTest(store Store) UserManager {
	return newUserManager(newStoreManager(store))
}

// ReadCasbinRecordsForTest reads a casbin_rule store into normalized records
// through the casbin reader.
func ReadCasbinRecordsForTest(adapter Adapter) (*policy.Records, error) {
	a, err := adapter.NewAdapter()
	if err != nil {
		return nil, errors.Wrap(err, "access.Adapter.NewAdapter()")
	}

	return readCasbinPolicy(a)
}

// SnapshotCheckerForTest compiles records with the shared snapshot compiler
// and answers checks with the evaluator's exact semantics.
type SnapshotCheckerForTest struct {
	snap *snapshot
}

// CompileSnapshotForTest compiles normalized records into a checker.
func CompileSnapshotForTest(records *policy.Records) (*SnapshotCheckerForTest, error) {
	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		return nil, err
	}

	return &SnapshotCheckerForTest{snap: snap}, nil
}

// CheckUser returns the resources user does NOT hold perm on within domain.
func (s *SnapshotCheckerForTest) CheckUser(_ context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) []accesstypes.Resource {
	return s.snap.checkUser(user, domain, perm, resources...)
}

// CheckRole returns the resources role does NOT hold perm on within domain.
func (s *SnapshotCheckerForTest) CheckRole(_ context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) []accesstypes.Resource {
	return s.snap.checkRole(role, domain, perm, resources...)
}
