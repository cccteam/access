package access

import (
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	type args struct {
		domains    *MockDomains
		connConfig Adapter
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "new",
			args: args{
				domains:    &MockDomains{},
				connConfig: &PostgresAdapter{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(tt.args.domains, tt.args.connConfig)
			if err != nil {
				t.Error(err)
			}

			if got.userManager == nil {
				t.Error("connConfig is nil")
			}
		})
	}
}
