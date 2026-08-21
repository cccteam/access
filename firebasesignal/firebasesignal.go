// Package firebasesignal implements access.ChangeSignal over a Firestore
// document watch, for deployments (e.g. Spanner-backed) where Postgres
// LISTEN/NOTIFY is unavailable.
//
// Its sibling github.com/cccteam/access/postgressignal serves
// Postgres-backed deployments through LISTEN/NOTIFY.
package firebasesignal

import (
	"context"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/cccteam/access"
	"github.com/go-playground/errors/v5"
)

var _ access.ChangeSignal = &Signal{}

// defaultResubscribeInterval is how often Watch tears down and recreates its
// snapshot stream. Streams can die silently; periodic resubscription heals
// them, and the fresh stream's initial snapshot re-delivers anything missed.
const defaultResubscribeInterval = time.Minute

// Signal propagates policy-change hints through writes to a single Firestore
// document. Announce writes the document; Watch streams its snapshots.
//
// The signal is a latency optimization only — access's heartbeat remains the
// correctness guarantee — so delivery here is deliberately best-effort.
type Signal struct {
	doc                 *firestore.DocumentRef
	resubscribeInterval time.Duration
}

// New creates a Signal on the document at docPath (e.g. "access/policy"),
// which all instances of an app must share. The caller owns the client's
// lifecycle.
func New(client *firestore.Client, docPath string) (*Signal, error) {
	segments := strings.Split(docPath, "/")
	if len(segments) < 2 || len(segments)%2 != 0 {
		return nil, errors.Newf("docPath %q must have an even number of segments (collection/document)", docPath)
	}
	doc := client.Doc(docPath)
	if doc == nil {
		return nil, errors.Newf("invalid document path %q", docPath)
	}

	return &Signal{
		doc:                 doc,
		resubscribeInterval: defaultResubscribeInterval,
	}, nil
}

// Announce broadcasts a change hint by overwriting the signal document. Any
// write fires every watcher's snapshot stream.
func (s *Signal) Announce(ctx context.Context) error {
	if _, err := s.doc.Set(ctx, map[string]any{
		"announcedAt": firestore.ServerTimestamp,
	}); err != nil {
		return errors.Wrap(err, "firestore.DocumentRef.Set()")
	}

	return nil
}

// Watch invokes onChange whenever the signal document changes, until ctx
// ends. The stream is resubscribed periodically to heal silently dead
// connections. Every (re)subscription replays the document's current state as
// its first event; onChange fires only when that state differs from the last
// one delivered, so routine resubscription stays silent while an announce
// that landed during a dead stream is still caught up on reconnect. A stream
// failure returns an error and the access engine re-invokes Watch after a
// delay.
func (s *Signal) Watch(ctx context.Context, onChange func()) error {
	// Zero until the first delivered state; a nonexistent document also
	// carries a zero UpdateTime, so a never-announced document fires nothing.
	var lastDelivered time.Time
	for ctx.Err() == nil {
		if err := s.watchOnce(ctx, &lastDelivered, onChange); err != nil {
			return err
		}
	}

	return nil // clean shutdown
}

// watchOnce streams snapshots for one resubscribe interval. It returns nil
// when the interval elapsed or ctx ended, and an error on stream failure.
func (s *Signal) watchOnce(ctx context.Context, lastDelivered *time.Time, onChange func()) error {
	subCtx, cancel := context.WithTimeout(ctx, s.resubscribeInterval)
	defer cancel()

	snapshots := s.doc.Snapshots(subCtx)
	defer snapshots.Stop()

	for {
		snap, err := snapshots.Next()
		if err != nil {
			if subCtx.Err() != nil {
				return nil // interval elapsed or parent ctx done: resubscription, not failure
			}

			return errors.Wrap(err, "firestore.DocumentSnapshotIterator.Next()")
		}
		if snap.UpdateTime.Equal(*lastDelivered) {
			continue // replay of a state already delivered (e.g. a resubscription's initial snapshot)
		}
		*lastDelivered = snap.UpdateTime
		onChange()
	}
}
