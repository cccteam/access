package access

import (
	"github.com/casbin/casbin/v2/persist"
	spanneradapter "github.com/flowerinthenight/casbin-spanner-adapter"
	"github.com/go-playground/errors/v5"
	"github.com/jackc/pgx/v5"
	pgxadapter "github.com/pckhoi/casbin-pgx-adapter/v3"
)

type Adapter interface {
	NewAdapter() (persist.Adapter, error)
}

type PostgresAdapter struct {
	connConfig   *pgx.ConnConfig
	databaseName string
	tableName    string
}

func NewPostgresAdapter(connConfig *pgx.ConnConfig, databaseName, tableName string) *PostgresAdapter {
	return &PostgresAdapter{
		connConfig:   connConfig,
		databaseName: databaseName,
		tableName:    tableName,
	}
}

func (p *PostgresAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := pgxadapter.NewAdapter(p.connConfig, pgxadapter.WithDatabase(p.databaseName), pgxadapter.WithTableName(p.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "pgxadapter.NewAdapter()")
	}

	return a, nil
}

type SpannerAdapter struct {
	connConfig   *pgx.ConnConfig
	databaseName string
	tableName    string
}

func NewSpannerAdapter(databaseName, tableName string) *SpannerAdapter {
	return &SpannerAdapter{
		databaseName: databaseName,
		tableName:    tableName,
	}
}

func (s *SpannerAdapter) NewAdapter() (persist.Adapter, error) {
	a, err := spanneradapter.NewAdapter(s.databaseName, spanneradapter.WithSkipDatabaseCreation(true), spanneradapter.WithTableName(s.tableName))
	if err != nil {
		return nil, errors.Wrap(err, "spanneradapter.NewAdapter()")
	}

	return a, nil
}
