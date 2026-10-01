package access

import (
	"log"
	"time"
)

// Option configures optional Client behavior.
type Option func(*clientOptions)

type clientOptions struct {
	signal            ChangeSignal
	heartbeatInterval time.Duration
	onReloadError     func(error)
	collection        PermissionCollection
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		heartbeatInterval: defaultHeartbeatInterval,
		onReloadError:     logReloadError,
	}
}

// logReloadError is the default reload-error hook: every background failure
// and every skipped grant reaches the log, so neither is silent.
func logReloadError(err error) {
	log.Printf("access: %v", err)
}

// WithChangeSignal wires a push hint that propagates policy changes between
// instances in near-realtime. This is the intended configuration (see the
// postgressignal and firebasesignal subpackages); without it, changes
// propagate within one heartbeat interval.
func WithChangeSignal(s ChangeSignal) Option {
	return func(o *clientOptions) {
		o.signal = s
	}
}

// WithHeartbeatInterval overrides how often the policy store is re-read for
// changes (default 1m). It bounds cross-instance staleness when no
// ChangeSignal is configured, and otherwise backstops a broken signal.
// Non-positive values keep the default.
func WithHeartbeatInterval(d time.Duration) Option {
	return func(o *clientOptions) {
		if d > 0 {
			o.heartbeatInterval = d
		}
	}
}

// WithReloadErrorHandler replaces the hook that receives background failures
// (policy reloads and change-signal announce/watch errors) and the grants a
// load skipped because this release cannot use them (*SkippedGrant). While
// reloads fail the Client keeps serving the last good policy snapshot, so this
// hook is where persistent staleness and skipped grants become visible. The
// default writes each one to the standard log; wire alerting here when the log
// is not enough.
func WithReloadErrorHandler(f func(error)) Option {
	return func(o *clientOptions) {
		if f != nil {
			o.onReloadError = f
		}
	}
}

// WithPermissionCollection tells the Client what the running release declares:
// its permissions, resources and fields. A stored grant naming one the release
// does not declare (after a rollback, or once a release drops a resource) is
// then left out of the snapshot and reported as a SkippedGrant instead of
// being carried as a grant nothing can check. Without it, names are not
// checked; conditions are checked either way.
func WithPermissionCollection(c PermissionCollection) Option {
	return func(o *clientOptions) {
		o.collection = c
	}
}
