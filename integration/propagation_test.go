package integration

import (
	"context"
	"testing"
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/access/postgressignal"
	"github.com/cccteam/access/postgresstore"
	dbinitiator "github.com/cccteam/db-initiator"
)

const signalChannel = "access_policy_changed"

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

// waitFor polls until check passes or the deadline expires.
func waitFor(t *testing.T, timeout time.Duration, msg string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newTestClient builds a Client instance over the shared typed-store tables.
func newTestClient(t *testing.T, db *dbinitiator.PostgresDatabase, name string, withSignal bool, heartbeat time.Duration) *access.Client {
	t.Helper()

	opts := []access.Option{
		access.WithHeartbeatInterval(heartbeat),
		access.WithReloadErrorHandler(func(err error) { t.Logf("%s reload error: %v", name, err) }),
	}
	if withSignal {
		// The signal rides the application's existing pool.
		opts = append(opts, access.WithChangeSignal(postgressignal.New(db.Pool, signalChannel)))
	}
	store, err := postgresstore.New(db.Pool)
	if err != nil {
		t.Fatalf("postgresstore.New() error = %v", err)
	}
	client, err := access.New(store, opts...)
	if err != nil {
		t.Fatalf("access.New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Client.Close() error = %v", err)
		}
	})

	return client
}

// Test_Client_policyPropagation proves the full chain on a real store: a
// policy write on one client instance reaches another instance's snapshot
// through the typed policy tables, via each of the two propagation paths —
// the change signal (heartbeat pinned out of the picture) and the heartbeat
// alone (poll-only deployments, no signal configured).
func Test_Client_policyPropagation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		withSignal        bool
		heartbeatInterval time.Duration
	}{
		{
			name:              "through the change signal",
			withSignal:        true,
			heartbeatInterval: time.Hour,
		},
		{
			name:              "through the heartbeat alone",
			withSignal:        false,
			heartbeatInterval: 500 * time.Millisecond,
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

			// One store schema, shared by both client instances — the app's
			// migration applies the store's own DDL.
			schemaStore, err := postgresstore.New(db.Pool)
			if err != nil {
				t.Fatalf("postgresstore.New() error = %v", err)
			}
			for _, stmt := range schemaStore.DDL() {
				if _, err := db.Exec(ctx, stmt); err != nil {
					t.Fatalf("executing DDL: %v", err)
				}
			}

			writer := newTestClient(t, db, "writer", tt.withSignal, tt.heartbeatInterval)
			reader := newTestClient(t, db, "reader", tt.withSignal, tt.heartbeatInterval)

			readyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := writer.WaitReady(readyCtx); err != nil {
				t.Fatalf("writer WaitReady() error = %v", err)
			}
			if err := reader.WaitReady(readyCtx); err != nil {
				t.Fatalf("reader WaitReady() error = %v", err)
			}
			if tt.withSignal {
				// Both clients' watches must be listening before the writes,
				// or the announces could be lost (and the pinned heartbeat
				// would hide them).
				waitForListeners(ctx, t, db, 2)
			}

			mgr := writer.UserManager()
			if err := mgr.AddRole(ctx, "tenant1", "Editor"); err != nil {
				t.Fatalf("AddRole() error = %v", err)
			}
			if err := mgr.AddRolePermissionResources(ctx, "tenant1", "Editor", "Read", "employees"); err != nil {
				t.Fatalf("AddRolePermissionResources() error = %v", err)
			}
			if err := mgr.AddRoleUsers(ctx, "tenant1", "Editor", "erin"); err != nil {
				t.Fatalf("AddRoleUsers() error = %v", err)
			}

			// Read-your-writes on the writing instance.
			if missing, err := writer.CheckUser(ctx, "erin", "tenant1", "Read", "employees"); err != nil || len(missing) != 0 {
				t.Fatalf("writer CheckUser() = (%v, %v), want granted immediately", missing, err)
			}

			// Cross-instance propagation.
			waitFor(t, 15*time.Second, "policy change never reached the reader instance", func() bool {
				missing, err := reader.CheckUser(ctx, "erin", "tenant1", "Read", "employees")
				if err != nil {
					t.Fatalf("reader CheckUser() error = %v", err)
				}

				return len(missing) == 0
			})
		})
	}
}
