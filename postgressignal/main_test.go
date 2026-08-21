package postgressignal

import (
	"context"
	"fmt"
	"os"
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

// prepareDatabase creates a new empty database for the test; the signal needs
// no schema.
func prepareDatabase(ctx context.Context, t *testing.T) (*dbinitiator.PostgresDatabase, error) {
	t.Helper()

	db, err := container.CreateDatabase(ctx, t.Name())
	if err != nil {
		return nil, errors.Wrapf(err, "dbinitiator.PostgresContainer.CreateDatabase()")
	}

	t.Cleanup(db.Close)

	return db, nil
}
