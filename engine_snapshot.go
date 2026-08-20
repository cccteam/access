package access

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v2/persist"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
)

var _ evaluator = &snapshotEngine{}

// snapshotTTL bounds staleness when no policy-change signal arrives, matching
// the at-most-every-minute reload the casbin evaluator had. The signaling
// release (PolicyVersion heartbeat + push hint) replaces this as the reload
// trigger.
const snapshotTTL = time.Minute

// snapshotEngine answers permission checks from a compiled snapshot of the
// policy store. It is the request-path replacement for casbin evaluation:
// checks never take a lock or touch the database. The policy store is read
// through the same persist.Adapter casbin writes through; the write path is
// untouched.
//
// Failure semantics: the first load must succeed before checks are served
// (errors are returned, never panicked); once a snapshot exists, a failed
// reload serves the last good snapshot rather than failing checks.
type snapshotEngine struct {
	adapterFactory Adapter

	// invalidated is set by the policy write path so the next check reloads
	// immediately instead of waiting out the TTL, preserving the
	// read-your-writes behavior the shared casbin enforcer had.
	invalidated atomic.Bool

	snap atomic.Pointer[snapshot]

	mu      sync.Mutex // guards adapter and reloads
	adapter persist.Adapter
}

func newSnapshotEngine(adapterFactory Adapter) *snapshotEngine {
	return &snapshotEngine{adapterFactory: adapterFactory}
}

// invalidate marks the current snapshot stale. Safe to call concurrently.
func (s *snapshotEngine) invalidate() {
	s.invalidated.Store(true)
}

func (s *snapshotEngine) checkUser(_ context.Context, user accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) ([]accesstypes.Resource, error) {
	snap, err := s.currentSnapshot()
	if err != nil {
		return nil, err
	}

	return snap.checkUser(user, domain, perm, resources...), nil
}

func (s *snapshotEngine) checkRole(_ context.Context, role accesstypes.Role, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) ([]accesstypes.Resource, error) {
	snap, err := s.currentSnapshot()
	if err != nil {
		return nil, err
	}

	return snap.checkRole(role, domain, perm, resources...), nil
}

func (s *snapshotEngine) currentSnapshot() (*snapshot, error) {
	snap := s.snap.Load()
	if snap == nil {
		// No snapshot yet: everyone blocks on the first load, and its failure
		// is a check failure.
		s.mu.Lock()
		defer s.mu.Unlock()
		if snap = s.snap.Load(); snap != nil && !s.stale(snap) {
			return snap, nil
		}

		return s.reload()
	}

	if s.stale(snap) && s.mu.TryLock() {
		// One goroutine refreshes; concurrent checks keep serving the current
		// snapshot instead of queueing behind the load.
		defer s.mu.Unlock()
		if cur := s.snap.Load(); cur != nil && !s.stale(cur) {
			return cur, nil
		}
		if fresh, err := s.reload(); err == nil {
			return fresh, nil
		}
		// Reload failed: serve the last good snapshot, never an empty one.
		// The signaling release adds alerting on persistent reload failure.
	}

	return s.snap.Load(), nil
}

func (s *snapshotEngine) stale(snap *snapshot) bool {
	return s.invalidated.Load() || time.Since(snap.loadedAt) > snapshotTTL
}

// reload reads the store and swaps in a freshly compiled snapshot.
// The caller must hold mu.
func (s *snapshotEngine) reload() (*snapshot, error) {
	if s.adapter == nil {
		a, err := s.adapterFactory.NewAdapter()
		if err != nil {
			return nil, errors.Wrap(err, "access.Adapter.NewAdapter()")
		}
		s.adapter = a
	}

	// Clear before reading so a write racing the read re-marks the new
	// snapshot stale instead of the signal being lost.
	s.invalidated.Store(false)

	records, err := readCasbinPolicy(s.adapter)
	if err != nil {
		return nil, errors.Wrap(err, "readCasbinPolicy()")
	}

	snap, err := newSnapshot(records, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, "newSnapshot()")
	}
	s.snap.Store(snap)

	return snap, nil
}
