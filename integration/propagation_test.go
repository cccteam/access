package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/cccteam/access"
	"github.com/cccteam/access/postgressignal"
	dbinitiator "github.com/cccteam/db-initiator"
)

const signalChannel = "access_policy_changed"

// staticDomains is a Domains implementation with a fixed tenant list.
type staticDomains struct {
	ids []string
}

func (s *staticDomains) DomainIDs(_ context.Context) ([]string, error) {
	return s.ids, nil
}

func (s *staticDomains) DomainExists(_ context.Context, id string) (bool, error) {
	return slices.Contains(s.ids, id), nil
}

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

// Test_Client_policyPropagation proves the full v0.10 chain on a real store:
// a policy write on one client instance reaches another instance's snapshot
// through casbin_rule, via each of the two propagation paths — the change
// signal (heartbeat pinned out of the picture) and the heartbeat alone
// (poll-only deployments, no signal configured).
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
			connConfig := db.Config().ConnConfig
			domains := &staticDomains{ids: []string{"tenant1"}}

			newClient := func(name string) *access.Client {
				opts := []access.Option{
					access.WithHeartbeatInterval(tt.heartbeatInterval),
					access.WithReloadErrorHandler(func(err error) { t.Logf("%s reload error: %v", name, err) }),
				}
				if tt.withSignal {
					// The signal rides the application's existing pool.
					opts = append(opts, access.WithChangeSignal(postgressignal.New(db.Pool, signalChannel)))
				}
				client, err := access.New(domains, access.NewPostgresAdapter(connConfig, connConfig.Database, "casbin_rule"), opts...)
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

			writer := newClient("writer")
			reader := newClient("reader")

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
			if ok, missing, err := writer.RequireResources(ctx, "erin", "tenant1", "Read", "employees"); err != nil || !ok {
				t.Fatalf("writer RequireResources() = (%v, %v, %v), want granted immediately", ok, missing, err)
			}

			// Cross-instance propagation.
			waitFor(t, 15*time.Second, "policy change never reached the reader instance", func() bool {
				ok, _, err := reader.RequireResources(ctx, "erin", "tenant1", "Read", "employees")
				if err != nil {
					t.Fatalf("reader RequireResources() error = %v", err)
				}

				return ok
			})

			// The deploy gate passes over the live store.
			if err := writer.ValidateEngineEquivalence(ctx); err != nil {
				t.Errorf("ValidateEngineEquivalence() error = %v, want nil", err)
			}
		})
	}
}
