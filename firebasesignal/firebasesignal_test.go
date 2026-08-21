package firebasesignal

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
)

func newTestClient(ctx context.Context, t *testing.T) *firestore.Client {
	t.Helper()
	client, err := firestore.NewClient(ctx, "firebasesignal-test")
	if err != nil {
		t.Fatalf("firestore.NewClient() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("firestore.Client.Close() error = %v", err)
		}
	})

	return client
}

// testDocPath isolates each test on its own signal document.
func testDocPath(t *testing.T) string {
	t.Helper()

	return "access-signal/" + strings.ReplaceAll(t.Name(), "/", "-")
}

// watchInBackground runs Watch and returns a hint counter and a stop function
// that cancels the watch and asserts it exits cleanly.
func watchInBackground(ctx context.Context, t *testing.T, s *Signal) (hints *atomic.Int64, stop func()) {
	t.Helper()

	watchCtx, cancel := context.WithCancel(ctx)
	hints = &atomic.Int64{}
	done := make(chan error, 1)
	go func() {
		done <- s.Watch(watchCtx, func() { hints.Add(1) })
	}()

	return hints, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Watch() error = %v, want nil on context cancel", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Watch() did not return after context cancel")
		}
	}
}

// waitForHints polls until the counter reaches want or the deadline passes.
func waitForHints(t *testing.T, hints *atomic.Int64, want int64, msg string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for hints.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: got %d hints, want at least %d", msg, hints.Load(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Test_Signal_Watch covers hint delivery and replay suppression. Every new
// snapshot stream replays the document's current state; replaying an
// already-delivered state must not fire a hint — otherwise every instance
// would reload once per resubscribe interval forever — while announces must
// always be delivered, including across stream resubscriptions.
func Test_Signal_Watch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// resubscribeInterval overrides the stream lifetime; 0 keeps the
		// default (a single long subscription for the whole test).
		resubscribeInterval time.Duration
		// settle is idle time letting resubscription replays occur before
		// each hint-count assertion.
		settle time.Duration
	}{
		{
			name: "announce delivers hints",
		},
		{
			name:                "resubscription replays are suppressed",
			resubscribeInterval: 200 * time.Millisecond,
			settle:              700 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			client := newTestClient(ctx, t)

			signal, err := New(client, testDocPath(t))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if tt.resubscribeInterval > 0 {
				signal.resubscribeInterval = tt.resubscribeInterval
			}

			hints, stop := watchInBackground(ctx, t, signal)
			defer stop()

			// Never-announced document: no hints, no matter how many
			// subscriptions have replayed its (nonexistent) state.
			time.Sleep(tt.settle)
			if got := hints.Load(); got != 0 {
				t.Fatalf("got %d hints before any announce, want 0", got)
			}

			// No race with subscription setup: if the announce lands first,
			// the stream's initial snapshot carries it and still fires.
			if err := signal.Announce(ctx); err != nil {
				t.Fatalf("Announce() error = %v", err)
			}
			waitForHints(t, hints, 1, "hint after first announce")

			// The announced state is replayed by every subsequent
			// resubscription and must not fire again.
			time.Sleep(tt.settle)
			if got := hints.Load(); got != 1 {
				t.Fatalf("got %d hints after one announce, want exactly 1", got)
			}

			if err := signal.Announce(ctx); err != nil {
				t.Fatalf("Announce() error = %v", err)
			}
			waitForHints(t, hints, 2, "hint after second announce")
		})
	}
}

func Test_New_rejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := newTestClient(ctx, t)

	tests := []struct {
		name    string
		docPath string
		wantErr bool
	}{
		{name: "collection and document", docPath: "access/policy", wantErr: false},
		{name: "nested document", docPath: "apps/myapp/access/policy", wantErr: false},
		{name: "collection only", docPath: "access", wantErr: true},
		{name: "odd segments", docPath: "access/policy/extra", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(client, tt.docPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("New(%q) error = %v, wantErr %v", tt.docPath, err, tt.wantErr)
			}
		})
	}
}
