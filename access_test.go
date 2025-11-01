package access

import (
	"reflect"
	"testing"

	"go.uber.org/mock/gomock"
)

var mockStore *MockStore

func TestMain(m *testing.M) {
	ctrl := gomock.NewController(&testing.T{})
	defer ctrl.Finish()

	mockStore = NewMockStore(ctrl)
	m.Run()
}
func TestNew(t *testing.T) {
	t.Parallel()

	type args struct {
		domains *MockDomains
		store   Store
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "new",
			args: args{
				domains: &MockDomains{},
				store:   mockStore,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(tt.args.domains, tt.args.store)
			if err != nil {
				t.Error(err)
			}

			if got.userManager == nil {
				t.Error("userManager is nil")
			}
			if got.userManager.enforcer == nil {
				t.Error("enforcer is nil")
			}
		})
	}
}
