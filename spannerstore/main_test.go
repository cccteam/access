package spannerstore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/go-playground/errors/v5"
)

var (
	container *dbinitiator.SpannerContainer
	admin     *database.DatabaseAdminClient
)

// TestMain is a wrapper for the test suite. It creates a Cloud Spanner
// emulator container plus one admin client for schema changes, and runs the
// test suite.
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

	host, err := c.Host(ctx)
	if err != nil {
		fmt.Println(err)

		return 2
	}
	port, err := c.MappedPort(ctx, "9010/tcp")
	if err != nil {
		fmt.Println(err)

		return 2
	}
	// The admin client (and anything else the tests dial) targets the
	// emulator through the standard env var.
	if err := os.Setenv("SPANNER_EMULATOR_HOST", fmt.Sprintf("%s:%s", host, port.Port())); err != nil {
		fmt.Println(err)

		return 2
	}

	a, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		fmt.Println(err)

		return 2
	}
	admin = a
	defer func() {
		if err := a.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	return m.Run()
}

// prepareStore creates a database for the test, applies the store's DDL, and
// returns the ready store — so the shipped DDL is exactly what the suite runs
// against.
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
	if err := applyDDL(ctx, db, store); err != nil {
		t.Fatalf("applying DDL: %v", err)
	}

	return store, db
}

func applyDDL(ctx context.Context, db *dbinitiator.SpannerDB, store *Store) error {
	op, err := admin.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Database:   db.DatabaseName(),
		Statements: store.DDL(),
	})
	if err != nil {
		return errors.Wrap(err, "database.DatabaseAdminClient.UpdateDatabaseDdl()")
	}
	if err := op.Wait(ctx); err != nil {
		return errors.Wrap(err, "database.UpdateDatabaseDdlOperation.Wait()")
	}

	return nil
}
