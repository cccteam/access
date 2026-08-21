package postgressignal

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	dbinitiator "github.com/cccteam/db-initiator"
)

const testChannel = "access_policy_changed"

// waitForListeners polls until n LISTEN backends are connected, so a NOTIFY
// sent afterwards cannot be lost to subscription racing.
func waitForListeners(ctx context.Context, t *testing.T, db *dbinitiator.PostgresDatabase, n int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var count int64
		// pg_stat_activity is cluster-wide; scope to this test's database so
		// parallel tests cannot satisfy (or disturb) each other's waits.
		if err := db.QueryRow(ctx,
			"select count(*) from pg_stat_activity where datname = current_database() and query ilike 'listen%'",
		).Scan(&count); err != nil {
			t.Fatalf("pgx.Row.Scan(): %v", err)
		}
		if count >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("wanted %d LISTEN backends, have %d", n, count)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startWatch runs signal.Watch in the background, delivering hints into the
// returned counter. The done channel receives Watch's return value once.
func startWatch(ctx context.Context, signal *Signal, hints *atomic.Int64) (done chan error, cancel context.CancelFunc) {
	watchCtx, cancel := context.WithCancel(ctx)
	done = make(chan error, 1)
	go func() {
		done <- signal.Watch(watchCtx, func() { hints.Add(1) })
	}()

	return done, cancel
}

func Test_Signal_Watch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		disruptConnection bool
	}{
		{
			name: "announce delivers a hint",
		},
		{
			name:              "announce delivers after connection loss and re-watch",
			disruptConnection: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			db, err := prepareDatabase(ctx, t)
			if err != nil {
				t.Fatalf("prepareDatabase() error = %v", err)
			}

			signal := New(db.Pool, testChannel)

			var hints atomic.Int64
			done, cancel := startWatch(ctx, signal, &hints)
			defer cancel()
			waitForListeners(ctx, t, db, 1)

			if tt.disruptConnection {
				// Kill the LISTEN backend out from under the watch.
				if _, err := db.Exec(ctx,
					"select pg_terminate_backend(pid) from pg_stat_activity where datname = current_database() and pid <> pg_backend_pid() and query ilike 'listen%'",
				); err != nil {
					t.Fatalf("pg_terminate_backend: %v", err)
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("Watch() returned nil after connection loss, want error so the caller re-invokes it")
					}
				case <-time.After(15 * time.Second):
					t.Fatal("Watch() did not return after its connection was terminated")
				}

				// The contract: the caller re-invokes Watch, restoring delivery.
				done, cancel = startWatch(ctx, signal, &hints)
				defer cancel()
				waitForListeners(ctx, t, db, 1)
			}

			if err := signal.Announce(ctx); err != nil {
				t.Fatalf("Announce() error = %v", err)
			}
			deadline := time.Now().Add(15 * time.Second)
			for hints.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("hint not delivered after Announce")
				}
				time.Sleep(20 * time.Millisecond)
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Watch() error = %v, want nil on context cancel", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("Watch() did not return after context cancel")
			}
		})
	}
}
