package spannerstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/go-playground/errors/v5"
)

var container *dbinitiator.SpannerContainer

// TestMain is a wrapper for the test suite. It creates a Cloud Spanner
// emulator container and runs the test suite.
func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	ctx := context.Background()
	c, err := dbinitiator.NewSpannerContainer(ctx, "latest")
	if err != nil {
		fmt.Println(err)

		return 2
	}
	container = c
	defer func() {
		if err := c.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	return m.Run()
}

// prepareStore creates a database for the test, applies the store's DDL
// through the same migration tooling apps use, and returns the ready store —
// so the shipped DDL is exactly what the suite runs against.
//
// NOTE: db-initiator's migrations require the jtwatson/migrate fork (see the
// replace directive in go.mod): upstream golang-migrate closes the spanner
// clients handed to it, which are db-initiator's shared container clients.
func prepareStore(ctx context.Context, t *testing.T, opts ...Option) (*Store, *dbinitiator.SpannerDB) {
	t.Helper()

	db, err := container.CreateDatabase(ctx, strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")))
	if err != nil {
		t.Fatalf("dbinitiator.SpannerContainer.CreateDatabase(): %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("dbinitiator.SpannerDB.Close(): %v", err)
		}
	})

	store, err := New(db.Client, opts...)
	if err != nil {
		t.Fatalf("spannerstore.New(): %v", err)
	}
	if err := applyDDL(t, db, store); err != nil {
		t.Fatalf("applying DDL: %v", err)
	}

	return store, db
}

func applyDDL(t *testing.T, db *dbinitiator.SpannerDB, store *Store) error {
	t.Helper()

	dir := t.TempDir()
	migration := strings.Join(store.DDL(), ";\n") + ";\n"
	if err := os.WriteFile(filepath.Join(dir, "000001_access.up.sql"), []byte(migration), 0o600); err != nil {
		return errors.Wrap(err, "os.WriteFile()")
	}

	if err := db.MigrateUp("file://" + dir); err != nil {
		return errors.Wrap(err, "dbinitiator.SpannerDB.MigrateUp()")
	}

	return nil
}
