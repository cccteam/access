package access

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

// TestClient_User_Add_Delete tests adding and deleting roles from a user. It also tests the User method.
// This ties all  three methods together, but it is the easiest way to check the results of Add/Delete.
func TestClient_User_Add_Delete(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_add_delete.csv"

	type args struct {
		ctx      context.Context
		username accesstypes.User
		role     accesstypes.Role
		domain   accesstypes.Domain
	}
	tests := []struct {
		name     string
		args     args
		want     *UserAccess
		wantAdd  *UserAccess
		wantErr  bool
		want2Err bool
		prepare  func(db *MockDomains)
	}{
		{
			name: "Charlie",
			args: args{
				ctx:      context.Background(),
				username: "charlie",
				role:     "Viewer",
				domain:   accesstypes.Domain("tenant2"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"tenant2", "tenant1"}, nil).Times(3)
			},
			want: &UserAccess{
				Name: "charlie",
				Roles: accesstypes.RoleCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {},
				},
				Permissions: accesstypes.UserPermissionCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {},
				},
			},
			wantAdd: &UserAccess{
				Name: "charlie",
				Roles: accesstypes.RoleCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {"Viewer"},
				},
				Permissions: accesstypes.UserPermissionCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {},
				},
			},
		},
		{
			name: "Charlie error",
			args: args{
				ctx:      context.Background(),
				username: "charlie",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("I failed")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "returns error when role doesn't exist",
			args: args{
				ctx:      context.Background(),
				username: "bill",
				role:     accesstypes.Role("Non-Existent"),
				domain:   accesstypes.Domain("tenant2"),
			},
			want: &UserAccess{
				Name: "bill",
				Roles: accesstypes.RoleCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {},
				},
				Permissions: accesstypes.UserPermissionCollection{
					"global":  {},
					"tenant1": {},
					"tenant2": {},
				},
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"tenant2", "tenant1"}, nil).MaxTimes(3)
			},
			want2Err: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}
			if tt.prepare != nil {
				tt.prepare(domains)
			}
			c := &userManager{
				domains: domains,
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}
			got, err := c.User(tt.args.ctx, tt.args.username)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("Client.User() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Client.User() mismatch (-want +got):\n%s", diff)
			}
			if err := c.AddRoleUsers(ctx, tt.args.domain, tt.args.role, tt.args.username); err != nil {
				if tt.want2Err {
					return
				}
				t.Errorf("Client.AddRoleUsers() error = %v, want2Err %v", err, tt.want2Err)
			}

			got, err = c.User(tt.args.ctx, tt.args.username)
			if (err != nil) != tt.want2Err {
				t.Fatalf("Client.User() error = %v, want2Err %v", err, tt.want2Err)
			}
			if !reflect.DeepEqual(got, tt.wantAdd) {
				t.Fatalf("Client.User() = %v, want %v", got, tt.wantAdd)
			}
			if err := c.DeleteUserRoles(ctx, tt.args.domain, tt.args.username, tt.args.role); (err != nil) != tt.want2Err {
				t.Errorf("Client.DeleteUserRoles() error = %v, want2Err %v", err, tt.want2Err)
			}
			got, err = c.User(tt.args.ctx, tt.args.username)
			if (err != nil) != tt.want2Err {
				t.Fatalf("Client.User() error = %v, want2Err %v", err, tt.want2Err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Client.User() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Users(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_users.csv"

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    []*UserAccess
		wantErr bool
		prepare func(db *MockDomains)
	}{
		{
			name: "All users",
			args: args{
				ctx: context.Background(),
			},
			want: []*UserAccess{
				{
					Name: "alice",
					Roles: accesstypes.RoleCollection{
						"global":  {},
						"tenant2": {},
						"tenant1": {},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global":  {},
						"tenant2": {"global": {"ViewUsers"}},
						"tenant1": {},
					},
				},
				{
					Name: "bob",
					Roles: accesstypes.RoleCollection{
						"global":  {},
						"tenant2": {"Editor"},
						"tenant1": {},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global":  {},
						"tenant2": {},
						"tenant1": {},
					},
				},
				{
					Name: "charlie",
					Roles: accesstypes.RoleCollection{
						"global":  {},
						"tenant2": {},
						"tenant1": {"Administrator"},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global":  {},
						"tenant2": {},
						"tenant1": {"global": {"DeleteUsers", "AddUsers"}},
					},
				},
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"tenant2", "tenant1"}, nil).Times(1)
			},
		},
		{
			name: "Users Error",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("I failed")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}
			if tt.prepare != nil {
				tt.prepare(domains)
			}

			c := &userManager{
				domains: domains,
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.Users(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Client.Users() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Client.Users() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClient_RolePermissions(t *testing.T) {
	t.Parallel()

	enforcer, err := mockEnforcer("testdata/policy_users.csv")
	if err != nil {
		t.Fatalf("failed to load policies. err=%s", err)
	}

	type fields struct {
		e casbin.IEnforcer
	}
	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    accesstypes.RolePermissionCollection
		wantErr bool
	}{
		{
			name:    "ReturnsListOfPermissions",
			fields:  fields{e: enforcer},
			args:    args{role: "Administrator", domain: "tenant1"},
			want:    accesstypes.RolePermissionCollection{"DeleteUsers": {"global"}, "AddUsers": {"global"}},
			wantErr: false,
		},
		{
			name:    "No Permissions Found",
			fields:  fields{e: enforcer},
			args:    args{role: "Administrator", domain: "tenant2"},
			want:    accesstypes.RolePermissionCollection{},
			wantErr: false,
		},
		{
			name:    "Bad role",
			fields:  fields{e: enforcer},
			args:    args{role: "asdvsdb", domain: "tenant2"},
			want:    accesstypes.RolePermissionCollection{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.RolePermissions(ctx, tt.args.domain, tt.args.role)
			if err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.RolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Client.RolePermissions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClient_RoleUsers(t *testing.T) {
	t.Parallel()
	policyPath := "testdata/policy_users.csv"

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		want    []accesstypes.User
		wantErr bool
	}{
		{
			name:    "Filters Noop User",
			args:    args{role: "Administrator", domain: "tenant1"},
			want:    []accesstypes.User{"charlie"},
			wantErr: false,
		},
		{
			name:    "No users found",
			args:    args{role: "Administrator", domain: "tenant2"},
			want:    []accesstypes.User{},
			wantErr: false,
		},
		{
			name:    "No users found in given roll",
			args:    args{role: "Admin", domain: "tenant1"},
			want:    []accesstypes.User{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.RoleUsers(ctx, tt.args.domain, tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Client.RoleUsers() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("Client.RoleUsers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClient_DeleteRoleUsers(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_deleteusersfromrole.csv"

	type args struct {
		users  []accesstypes.User
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func()
	}{
		{
			name: "Charlie",
			args: args{
				users:  []accesstypes.User{"charlie"},
				role:   "Administrator",
				domain: accesstypes.Domain("tenant1"),
			},
			wantErr: false,
		},
		{
			name: "Charlie fails",
			args: args{
				users:  []accesstypes.User{"charlie"},
				role:   "Viewer",
				domain: accesstypes.Domain("tenant1"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.DeleteRoleUsers(ctx, tt.args.domain, tt.args.role, tt.args.users...); (err != nil) != tt.wantErr {
				t.Errorf("Client.DeleteRoleUsers() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_AddRole(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_addrole.csv"

	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
		role   accesstypes.Role
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(db *MockDomains)
	}{
		{
			name: "Successfully add a new role",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant1"),
				role:   accesstypes.Role("AddUser"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "tenant1").Return(true, nil)
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("733"),
				role:   accesstypes.Role("AddUser"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "Error getting domain",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("733"),
				role:   accesstypes.Role("AddUser"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "733").Return(false, errors.New("failed to get domain"))
			},
			wantErr: true,
		},
		{
			name: "Role Already Exists",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant1"),
				role:   accesstypes.Role("Viewer"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "tenant1").Return(true, nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			if tt.prepare != nil {
				tt.prepare(domains)
			}

			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				domains: domains,
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.AddRole(tt.args.ctx, tt.args.domain, tt.args.role); (err != nil) != tt.wantErr {
				t.Errorf("Client.AddRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_AddUserRoles(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_adduserroles.csv"

	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
		roles  []accesstypes.Role
		user   accesstypes.User
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(db *MockDomains)
	}{
		{
			name: "Successfully add roles to a user",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant2"),
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"tenant1", "tenant2"}, nil)
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant2"),
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"tenant1", "tenant2"}, nil)
			},
			wantErr: false,
		},
		{
			name: "Error getting domain",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant2"),
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"tenant1", "tenant2"}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			if tt.prepare != nil {
				tt.prepare(domains)
			}

			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				domains: domains,
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.AddUserRoles(ctx, tt.args.domain, tt.args.user, tt.args.roles...); (err != nil) != tt.wantErr {
				t.Errorf("Client.AddUserRoles() error = %v, wantErr %v", err, tt.wantErr)
			}

			user, err := c.User(context.Background(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Fatalf("failed to get user. err=%s", err)
			}
			if !reflect.DeepEqual(tt.args.roles, user.Roles[tt.args.domain]) {
				t.Errorf("Client.AddUserRoles() got=%v, want=%v", tt.args.roles, user.Roles[tt.args.domain])
			}
		})
	}
}

func TestClient_Roles(t *testing.T) {
	t.Parallel()

	enforcer, err := mockEnforcer("testdata/policy.csv")
	if err != nil {
		t.Fatalf("failed to load policies. err=%s", err)
	}

	type fields struct {
		e casbin.IEnforcer
	}
	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []accesstypes.Role
		prepare func(db *MockDomains)
		wantErr bool
	}{
		{
			name: "Domain doesn't exist",
			fields: fields{
				e: enforcer,
			},
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("733"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "returns error checking if domain exists ",
			fields: fields{
				e: enforcer,
			},
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("733"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "733").Return(false, errors.New("failed to get DomainIDs"))
			},
			wantErr: true,
		},
		{
			name: "Returns list of roles",
			fields: fields{
				e: enforcer,
			},
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant2"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "tenant2").Return(true, nil)
			},
			wantErr: false,
			want: []accesstypes.Role{
				accesstypes.Role("Administrator"),
				accesstypes.Role("Auditor"),
				accesstypes.Role("Editor"),
				accesstypes.Role("Viewer"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)

			if tt.prepare != nil {
				tt.prepare(domains)
			}

			c := &userManager{
				domains: domains,
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.Roles(tt.args.ctx, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Roles() = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.Roles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_DomainIDs(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    []accesstypes.Domain
		prepare func(db *MockDomains)
		wantErr bool
	}{
		{
			name: "Successfully gets DomainIDs",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"tenant1", "tenant2"}, nil)
			},
			want:    []accesstypes.Domain{accesstypes.GlobalDomain, accesstypes.Domain("tenant1"), accesstypes.Domain("tenant2")},
			wantErr: false,
		},
		{
			name: "returns error checking if domain exists ",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("failed to get DomainIDs"))
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)

			if tt.prepare != nil {
				tt.prepare(domains)
			}

			c := &userManager{
				domains: domains,
			}

			got, err := c.Domains(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Domains() = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.Domains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_DeleteRole(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_deleterole.csv"

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name      string
		args      args
		want      bool
		wantErr   bool
		wantExist bool
	}{
		{
			name: "Success",
			args: args{
				role:   accesstypes.Role("Viewer"),
				domain: accesstypes.Domain("tenant1"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when noop exists",
			args: args{
				role:   accesstypes.Role("Writer"),
				domain: accesstypes.Domain("tenant2"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when it doesn't exist already",
			args: args{
				role:   accesstypes.Role("Viewer"),
				domain: accesstypes.Domain("tenant2"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Fails when users are assigned",
			args: args{
				role:   accesstypes.Role("Administrator"),
				domain: accesstypes.Domain("tenant1"),
			},
			want:      false,
			wantErr:   true,
			wantExist: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.DeleteRole(ctx, tt.args.domain, tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Client.DeleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("Client.DeleteRole() = %v, want %v", got, tt.want)
			}

			exists := c.RoleExists(ctx, tt.args.domain, tt.args.role)
			if exists != tt.wantExist {
				t.Errorf("Client.roleExists() = %v, want %v", exists, tt.wantExist)
			}
		})
	}
}

func TestClient_DeleteRolePermissions(t *testing.T) {
	t.Parallel()
	policyPath := "testdata/policy_deletepermissionsfromrole.csv"

	type args struct {
		permissions []accesstypes.Permission
		role        accesstypes.Role
		domain      accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    accesstypes.RolePermissionCollection
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				permissions: []accesstypes.Permission{"AddUsers"},
				role:        "Administrator",
				domain:      "tenant1",
			},
			wantErr: false,
			want: accesstypes.RolePermissionCollection{
				"DeleteUsers": {"global"},
			},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				permissions: []accesstypes.Permission{"DELETE * FROM accesspolicies"},
				role:        "Administrator123",
				domain:      "tenant1",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection(nil),
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				permissions: []accesstypes.Permission{"DELETE * FROM accesspolicies"},
				role:        "Viewer",
				domain:      "701",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.DeleteRolePermissions(ctx, tt.args.domain, tt.args.role, tt.args.permissions...); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.DeleteRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permsAfter, err := c.RolePermissions(ctx, tt.args.domain, tt.args.role)
			if err != nil {
				t.Errorf("Client.RolePermissions() error= %v", err)
			}

			if !reflect.DeepEqual(tt.want, permsAfter) {
				t.Fatalf("Client.DeleteRolePermissions() got= %v, want= %v", permsAfter, tt.want)
			}
		})
	}
}

func TestClient_DeleteAllRolePermissions(t *testing.T) {
	t.Parallel()
	policyPath := "testdata/policy_deletepermissionsfromrole.csv"

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    accesstypes.RolePermissionCollection
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				role:   accesstypes.Role("Administrator"),
				domain: accesstypes.Domain("tenant1"),
			},
			wantErr: false,
			want:    accesstypes.RolePermissionCollection{},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				role:   accesstypes.Role("Administrator123"),
				domain: accesstypes.Domain("tenant1"),
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection(nil),
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				role:   accesstypes.Role("Viewer"),
				domain: accesstypes.Domain("701"),
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.DeleteAllRolePermissions(ctx, tt.args.domain, tt.args.role); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.DeleteRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permsAfter, err := c.RolePermissions(ctx, tt.args.domain, tt.args.role)
			if err != nil {
				t.Errorf("Client.RolePermissions() error= %v", err)
			}
			if diff := cmp.Diff(tt.want, permsAfter); diff != "" {
				t.Fatalf("Client.DeleteRolePermissions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClient_AddRolePermissions(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_addpermissionstorole.csv"

	type args struct {
		permissions []accesstypes.Permission
		role        accesstypes.Role
		domain      accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    accesstypes.RolePermissionCollection
	}{
		{
			name: "Adds permissions successfully",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "tenant2",
			},
			wantErr: false,
			want:    accesstypes.RolePermissionCollection{"AddUser": {"global"}, "ViewUser": {"global"}, "AddName": {"global"}},
		},
		{
			name: "fails due to missing role",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Administrator",
				domain:      "tenant2",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection{},
		},
		{
			name: "fails due to wrong domain",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "tenant1",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			enforcer, err := mockEnforcer(policyPath)
			if err != nil {
				t.Fatalf("failed to load policies. err=%s", err)
			}

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			if err := c.AddRolePermissions(ctx, tt.args.domain, tt.args.role, tt.args.permissions...); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.AddRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permissionsAfter, err := c.RolePermissions(ctx, tt.args.domain, tt.args.role)
			if err != nil {
				t.Errorf("Client.RolePermissions() error = %s", err.Error())
			}

			if !reflect.DeepEqual(tt.want, permissionsAfter) {
				t.Errorf("Client.AddRolePermissions got = %v, want = %v", permissionsAfter, tt.want)
			}
		})
	}
}

func TestClient_DomainExists(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		prepare func(db *MockDomains)
		wantErr bool
	}{
		{
			name: "Domain found",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant1"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "tenant1").Return(true, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Domain not found",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("733"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "error returned",
			args: args{
				ctx:    context.Background(),
				domain: accesstypes.Domain("tenant1"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "tenant1").Return(false, errors.New("error returned"))
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)

			if tt.prepare != nil {
				tt.prepare(domains)
			}

			c := &userManager{
				domains: domains,
			}

			got, err := c.DomainExists(tt.args.ctx, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.DomainExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.DomainExists() = %v, want %v", got, tt.want)
			}
		})
	}
}
