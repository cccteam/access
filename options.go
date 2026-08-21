package access

import "time"

// Option configures optional Client behavior.
type Option func(*clientOptions)

type clientOptions struct {
	signal            ChangeSignal
	heartbeatInterval time.Duration
	onReloadError     func(error)
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		heartbeatInterval: defaultHeartbeatInterval,
		onReloadError:     func(error) {},
	}
}

// WithChangeSignal wires a push hint that propagates policy changes between
// instances ahead of the heartbeat. Optional: without it, changes propagate
// within one heartbeat interval.
func WithChangeSignal(s ChangeSignal) Option {
	return func(o *clientOptions) {
		o.signal = s
	}
}

// WithHeartbeatInterval overrides how often the policy store is re-read for
// changes (default 15s). It bounds cross-instance staleness. Non-positive
// values keep the default.
func WithHeartbeatInterval(d time.Duration) Option {
	return func(o *clientOptions) {
		if d > 0 {
			o.heartbeatInterval = d
		}
	}
}

// WithReloadErrorHandler installs an alerting hook for background failures:
// policy reloads and change-signal announce/watch errors. While reloads fail
// the Client keeps serving the last good policy snapshot, so this handler is
// the only place persistent staleness becomes visible — wire it to logging or
// alerting in production.
func WithReloadErrorHandler(f func(error)) Option {
	return func(o *clientOptions) {
		if f != nil {
			o.onReloadError = f
		}
	}
}
