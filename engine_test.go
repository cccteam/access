package access

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

func Test_casbinEngine_checkUser(t *testing.T) {
	t.Parallel()

	enforcer, err := mockEnforcer("testdata/policy_users.csv")
	if err != nil {
		t.Fatalf("failed to load policies. err=%s", err)
	}
	e := &casbinEngine{
		Enforcer: func() casbin.IEnforcer {
			return enforcer
		},
	}

	type args struct {
		user      accesstypes.User
		domain    accesstypes.Domain
		perm      accesstypes.Permission
		resources []accesstypes.Resource
	}
	tests := []struct {
		name        string
		args        args
		wantMissing []accesstypes.Resource
	}{
		{
			name: "user with permission through role",
			args: args{
				user:      "charlie",
				domain:    "tenant1",
				perm:      "DeleteUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name: "user with direct permission",
			args: args{
				user:      "alice",
				domain:    "tenant2",
				perm:      "ViewUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name: "user without permission in domain",
			args: args{
				user:      "alice",
				domain:    "tenant1",
				perm:      "ViewUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{accesstypes.GlobalResource},
		},
		{
			name: "role grant does not apply in another domain",
			args: args{
				user:      "bob",
				domain:    "tenant2",
				perm:      "ViewUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{accesstypes.GlobalResource},
		},
		{
			name: "partially missing resources",
			args: args{
				user:      "charlie",
				domain:    "tenant1",
				perm:      "DeleteUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource, "Widgets"},
			},
			wantMissing: []accesstypes.Resource{"Widgets"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing, err := e.checkUser(context.Background(), tt.args.user, tt.args.domain, tt.args.perm, tt.args.resources...)
			if err != nil {
				t.Fatalf("casbinEngine.checkUser() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("casbinEngine.checkUser() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_casbinEngine_checkRole(t *testing.T) {
	t.Parallel()

	enforcer, err := mockEnforcer("testdata/policy_users.csv")
	if err != nil {
		t.Fatalf("failed to load policies. err=%s", err)
	}
	e := &casbinEngine{
		Enforcer: func() casbin.IEnforcer {
			return enforcer
		},
	}

	type args struct {
		role      accesstypes.Role
		domain    accesstypes.Domain
		perm      accesstypes.Permission
		resources []accesstypes.Resource
	}
	tests := []struct {
		name        string
		args        args
		wantMissing []accesstypes.Resource
	}{
		{
			name: "role with permission",
			args: args{
				role:      "Administrator",
				domain:    "tenant1",
				perm:      "DeleteUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{},
		},
		{
			name: "role without permission",
			args: args{
				role:      "Editor",
				domain:    "tenant1",
				perm:      "DeleteUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{accesstypes.GlobalResource},
		},
		{
			name: "role grant scoped to its domain",
			args: args{
				role:      "Editor",
				domain:    "tenant2",
				perm:      "ViewUsers",
				resources: []accesstypes.Resource{accesstypes.GlobalResource},
			},
			wantMissing: []accesstypes.Resource{accesstypes.GlobalResource},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMissing, err := e.checkRole(context.Background(), tt.args.role, tt.args.domain, tt.args.perm, tt.args.resources...)
			if err != nil {
				t.Fatalf("casbinEngine.checkRole() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantMissing, gotMissing); diff != "" {
				t.Errorf("casbinEngine.checkRole() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
