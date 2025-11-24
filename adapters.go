package access

import (
	"github.com/casbin/casbin/v2/persist"
	spanneradapter "github.com/flowerinthenight/casbin-spanner-adapter"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

// Adapter creates casbin persistence adapters.
type Adapter interface {
	// NewAdapter returns a casbin persistence adapter.
	NewAdapter() (persist.Adapter, error)
}

// PostgresAdapter provides PostgreSQL persistence for casbin policies.
type PostgresAdapter struct {
	connConfig   *pgx.ConnConfig
	databaseName string
	tableName    string
}

// NewPostgresAdapter creates PostgreSQL adapter for storing casbin policies.
func NewPostgresAdapter(connConfig *pgx.ConnConfig, databaseName, tableName string) *PostgresAdapter {
	return &PostgresAdapter{
		connConfig:   connConfig,
		databaseName: databaseName,
		tableName:    tableName,
	}
}

// NewAdapter creates PostgreSQL casbin adapter.
func (p *PostgresAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := pgxadapter.NewAdapter(p.connConfig, pgxadapter.WithDatabase(p.databaseName), pgxadapter.WithTableName(p.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "pgxadapter.NewAdapter()")
	}

	return a, nil
}

// SpannerAdapter provides Spanner persistence for casbin policies.
type SpannerAdapter struct {
	databaseName string
	tableName    string
}

// NewSpannerAdapter creates Spanner adapter for storing casbin policies.
func NewSpannerAdapter(databaseName, tableName string) *SpannerAdapter {
	return &SpannerAdapter{
		databaseName: databaseName,
		tableName:    tableName,
	}
}

// NewAdapter creates Spanner casbin adapter. Skips database creation.
func (s *SpannerAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := spanneradapter.NewAdapter(s.databaseName, spanneradapter.WithSkipDatabaseCreation(true), spanneradapter.WithTableName(s.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "spanneradapter.NewAdapter()")
	}

	return a, nil
}
