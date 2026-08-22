package access

import "context"

// ChangeSignal propagates best-effort policy-change hints between instances.
// Correctness never depends on it: the heartbeat re-reads the policy store on
// a fixed interval regardless, so a broken signal only costs propagation
// latency, never accuracy.
//
// Implementations:
//   - github.com/cccteam/access/postgressignal (Postgres LISTEN/NOTIFY)
//   - github.com/cccteam/access/firebasesignal (Firestore document watch)
type ChangeSignal interface {
	// Announce broadcasts that policy may have changed. The Client calls it
	// after successful policy writes; failures are reported through the
	// reload error handler and never fail the write.
	Announce(ctx context.Context) error

	// Watch delivers received hints by invoking onChange, blocking until ctx
	// ends or the subscription fails. If Watch returns early the Client
	// re-invokes it after a delay, so implementations may either reconnect
	// internally or simply return on connection loss.
	Watch(ctx context.Context, onChange func()) error
}
