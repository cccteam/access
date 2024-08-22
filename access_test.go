package access

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestNew(t *testing.T) {
	t.Parallel()

	type args struct {
		domains    *MockDomains
		connConfig *pgx.ConnConfig
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "new",
			args: args{
				domains:    &MockDomains{},
				connConfig: &pgx.ConnConfig{},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(tt.args.domains, tt.args.connConfig)
			if err != nil {
				t.Error(err)
			}

			if got.enforcer == nil {
				t.Error("enforcer is nil")
			}

			if got.domains == nil {
				t.Error("domains is nil")
			}

			if got.connConfig == nil {
				t.Error("connConfig is nil")
			}
		})
	}
}
