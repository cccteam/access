package access

import (
	"github.com/casbin/casbin/v2/persist"
	spanneradapter "github.com/flowerinthenight/casbin-spanner-adapter"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

// Adapter is an interface for creating a new casbin adapter
type Adapter interface {
	NewAdapter() (persist.Adapter, error)
}

// PostgresAdapter is the adapter for connecting to a Postgres database
type PostgresAdapter struct {
	connConfig   *pgx.ConnConfig
	databaseName string
	tableName    string
}

// NewPostgresAdapter creates a new PostgresAdapter
func NewPostgresAdapter(connConfig *pgx.ConnConfig, databaseName, tableName string) *PostgresAdapter {
	return &PostgresAdapter{
		connConfig:   connConfig,
		databaseName: databaseName,
		tableName:    tableName,
	}
}

// NewAdapter creates a new casbin adapter for postgres
func (p *PostgresAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := pgxadapter.NewAdapter(p.connConfig, pgxadapter.WithDatabase(p.databaseName), pgxadapter.WithTableName(p.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "pgxadapter.NewAdapter()")
	}

	return a, nil
}

// SpannerAdapter is the adapter for connecting to a Spanner database
type SpannerAdapter struct {
	connConfig   *pgx.ConnConfig
	databaseName string
	tableName    string
}

// NewSpannerAdapter creates a new SpannerAdapter
func NewSpannerAdapter(databaseName, tableName string) *SpannerAdapter {
	return &SpannerAdapter{
		databaseName: databaseName,
		tableName:    tableName,
	}
}

// NewAdapter creates a new casbin adapter for spanner
func (s *SpannerAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := spanneradapter.NewAdapter(s.databaseName, spanneradapter.WithSkipDatabaseCreation(true), spanneradapter.WithTableName(s.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "spanneradapter.NewAdapter()")
	}

	return a, nil
}
