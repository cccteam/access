// deployment provides the utilities to bootstrap the application with preset configuration
package access

import (
	"reflect"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
)

func Test_exclude(t *testing.T) {
	t.Parallel()

	type args struct {
		source  map[accesstypes.Permission][]accesstypes.Resource
		exclude map[accesstypes.Permission][]accesstypes.Resource
	}
	tests := []struct {
		name string
		args args
		want map[accesstypes.Permission][]accesstypes.Resource
	}{
		{
			name: "has intersection",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("2"), accesstypes.Resource("4")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("3")}},
		},
		{
			name: "has no intersection",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("5"), accesstypes.Resource("6")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2"), accesstypes.Resource("3"), accesstypes.Resource("4")}},
		},
		{
			name: "complete overlap",
			args: args{
				source:  map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2")}},
				exclude: map[accesstypes.Permission][]accesstypes.Resource{accesstypes.Permission("1"): {accesstypes.Resource("1"), accesstypes.Resource("2")}},
			},
			want: map[accesstypes.Permission][]accesstypes.Resource{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := exclude(tt.args.source, tt.args.exclude); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Exclude() = %v, want %v", got, tt.want)
			}
		})
	}
}
