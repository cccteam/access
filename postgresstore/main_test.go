package postgresstore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/go-playground/errors/v5"
)

var container *dbinitiator.PostgresContainer

// TestMain is a wrapper for the test suite. It creates a new PostgresContainer and runs the test suite.
func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := dbinitiator.NewPostgresContainer(ctx, "latest")
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	container = c

	exitCode := m.Run()

	c.Close()
	if err := c.Terminate(ctx); err != nil {
		fmt.Println(err)
	}

	os.Exit(exitCode)
}

// prepareStore creates a database for the test, applies the store's DDL, and
// returns the ready store — so the shipped DDL is exactly what the suite runs
// against.
func prepareStore(ctx context.Context, t *testing.T, opts ...Option) (*Store, *dbinitiator.PostgresDatabase) {
	t.Helper()

	db, err := container.CreateDatabase(ctx, strings.ReplaceAll(t.Name(), "/", "_"))
	if err != nil {
		t.Fatalf("dbinitiator.PostgresContainer.CreateDatabase(): %v", err)
	}
	t.Cleanup(db.Close)

	store, err := New(db.Pool, opts...)
	if err != nil {
		t.Fatalf("postgresstore.New(): %v", err)
	}
	if err := applyDDL(ctx, db, store); err != nil {
		t.Fatalf("applying DDL: %v", err)
	}

	return store, db
}

func applyDDL(ctx context.Context, db *dbinitiator.PostgresDatabase, store *Store) error {
	for _, stmt := range store.DDL() {
		if _, err := db.Exec(ctx, stmt); err != nil {
			return errors.Wrapf(err, "executing DDL statement %q", stmt)
		}
	}

	return nil
}
