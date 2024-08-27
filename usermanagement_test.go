package access

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

func TestClient_User_Add_Delete(t *testing.T) {
	t.Parallel()

	policyPath := "testdata/policy_add_delete.csv"

	type args struct {
		ctx      context.Context
		username User
		role     Role
		domain   Domain
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
				domain:   Domain("712"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).Times(3)
			},
			want: &UserAccess{
				Name: "charlie",
				Roles: map[Domain][]Role{
					"global": {},
					"755":    {},
					"712":    {},
				},
				Permissions: map[Domain][]Permission{
					"global": {},
					"755":    {},
					"712":    {},
				},
			},
			wantAdd: &UserAccess{
				Name: "charlie",
				Roles: map[Domain][]Role{
					"global": {},
					"755":    {},
					"712":    {"Viewer"},
				},
				Permissions: map[Domain][]Permission{
					"global": {},
					"755":    {},
					"712":    {},
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
				role:     Role("Non-Existent"),
				domain:   Domain("712"),
			},
			want: &UserAccess{
				Name: "bill",
				Roles: map[Domain][]Role{
					"global": {},
					"755":    {},
					"712":    {},
				},
				Permissions: map[Domain][]Permission{
					"global": {},
					"755":    {},
					"712":    {},
				},
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).MaxTimes(3)
			},
			want2Err: true,
		},
	}
	for _, tt := range tests {
		tt := tt
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
			if err := c.AddRoleUsers(ctx, []User{tt.args.username}, tt.args.role, tt.args.domain); err != nil {
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
			if err := c.DeleteUserRole(ctx, tt.args.username, tt.args.role, tt.args.domain); (err != nil) != tt.want2Err {
				t.Errorf("Client.DeleteUserRole() error = %v, want2Err %v", err, tt.want2Err)
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
					Roles: map[Domain][]Role{
						"global": {},
						"712":    {},
						"755":    {},
					},
					Permissions: map[Domain][]Permission{
						"global": {},
						"712":    {"ViewUsers"},
						"755":    {},
					},
				},
				{
					Name: "bob",
					Roles: map[Domain][]Role{
						"global": {},
						"712":    {"Editor"},
						"755":    {},
					},
					Permissions: map[Domain][]Permission{
						"global": {},
						"712":    {},
						"755":    {},
					},
				},
				{
					Name: "charlie",
					Roles: map[Domain][]Role{
						"global": {},
						"712":    {},
						"755":    {"Administrator"},
					},
					Permissions: map[Domain][]Permission{
						"global": {},
						"712":    {},
						"755":    {"AddUsers", "DeleteUsers"},
					},
				},
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).Times(1)
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
		tt := tt
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
		role   Role
		domain Domain
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []Permission
		wantErr bool
	}{
		{
			name:    "ReturnsListOfPermissions",
			fields:  fields{e: enforcer},
			args:    args{role: "Administrator", domain: "755"},
			want:    []Permission{"DeleteUsers", "AddUsers"},
			wantErr: false,
		},
		{
			name:    "No Permissions Found",
			fields:  fields{e: enforcer},
			args:    args{role: "Administrator", domain: "712"},
			want:    []Permission{},
			wantErr: false,
		},
		{
			name:    "Bad role",
			fields:  fields{e: enforcer},
			args:    args{role: "asdvsdb", domain: "712"},
			want:    []Permission{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			c := &userManager{
				Enforcer: func() casbin.IEnforcer {
					return enforcer
				},
			}

			got, err := c.RolePermissions(ctx, tt.args.role, tt.args.domain)
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
		role   Role
		domain Domain
	}
	tests := []struct {
		name    string
		args    args
		want    []User
		wantErr bool
	}{
		{
			name:    "Filters Noop User",
			args:    args{role: "Administrator", domain: "755"},
			want:    []User{"charlie"},
			wantErr: false,
		},
		{
			name:    "No users found",
			args:    args{role: "Administrator", domain: "712"},
			want:    []User{},
			wantErr: false,
		},
		{
			name:    "No users found in given roll",
			args:    args{role: "Admin", domain: "755"},
			want:    []User{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
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

			got, err := c.RoleUsers(ctx, tt.args.role, tt.args.domain)
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
		users  []User
		role   Role
		domain Domain
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
				users:  []User{"charlie"},
				role:   "Administrator",
				domain: Domain("755"),
			},
			wantErr: false,
		},
		{
			name: "Charlie fails",
			args: args{
				users:  []User{"charlie"},
				role:   "Viewer",
				domain: Domain("755"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt

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

			if err := c.DeleteRoleUsers(ctx, tt.args.users, tt.args.role, tt.args.domain); (err != nil) != tt.wantErr {
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
		domain Domain
		role   Role
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
				domain: Domain("755"),
				role:   Role("AddUser"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: Domain("733"),
				role:   Role("AddUser"),
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
				domain: Domain("733"),
				role:   Role("AddUser"),
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
				domain: Domain("755"),
				role:   Role("Viewer"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
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
		domain Domain
		roles  []Role
		user   User
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
				domain: Domain("712"),
				roles:  []Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: Domain("712"),
				roles:  []Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
			},
			wantErr: false,
		},
		{
			name: "Error getting domain",
			args: args{
				ctx:    context.Background(),
				domain: Domain("712"),
				roles:  []Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
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

			if err := c.AddUserRoles(ctx, tt.args.user, tt.args.roles, tt.args.domain); (err != nil) != tt.wantErr {
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
		domain Domain
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []Role
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
				domain: Domain("733"),
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
				domain: Domain("733"),
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
				domain: Domain("712"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "712").Return(true, nil)
			},
			wantErr: false,
			want: []Role{
				Role("Administrator"),
				Role("Auditor"),
				Role("Editor"),
				Role("Viewer"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
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
		want    []Domain
		prepare func(db *MockDomains)
		wantErr bool
	}{
		{
			name: "Successfully gets DomainIDs",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainIDs(gomock.Any()).Return([]string{"755", "712"}, nil)
			},
			want:    []Domain{GlobalDomain, Domain("755"), Domain("712")},
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
		tt := tt
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
		role   Role
		domain Domain
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
				role:   Role("Viewer"),
				domain: Domain("755"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when noop exists",
			args: args{
				role:   Role("Writer"),
				domain: Domain("712"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when it doesn't exist already",
			args: args{
				role:   Role("Viewer"),
				domain: Domain("712"),
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Fails when users are assigned",
			args: args{
				role:   Role("Administrator"),
				domain: Domain("755"),
			},
			want:      false,
			wantErr:   true,
			wantExist: true,
		},
	}
	for _, tt := range tests {
		tt := tt
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

			got, err := c.DeleteRole(ctx, tt.args.role, tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Client.DeleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("Client.DeleteRole() = %v, want %v", got, tt.want)
			}

			exists := c.RoleExists(ctx, tt.args.role, tt.args.domain)
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
		permissions []Permission
		role        Role
		domain      Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []Permission
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				permissions: []Permission{"AddUsers"},
				role:        "Administrator",
				domain:      "755",
			},
			wantErr: false,
			want: []Permission{
				"DeleteUsers",
			},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				permissions: []Permission{"DELETE * FROM accesspolicies"},
				role:        "Administrator123",
				domain:      "755",
			},
			wantErr: true,
			want:    []Permission(nil),
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				permissions: []Permission{"DELETE * FROM accesspolicies"},
				role:        "Viewer",
				domain:      "701",
			},
			wantErr: true,
			want:    []Permission(nil),
		},
	}
	for _, tt := range tests {
		tt := tt
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

			if err := c.DeleteRolePermissions(ctx, tt.args.permissions, tt.args.role, tt.args.domain); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.DeleteRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permsAfter, err := c.RolePermissions(ctx, tt.args.role, tt.args.domain)
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
		role   Role
		domain Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []Permission
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				role:   Role("Administrator"),
				domain: Domain("755"),
			},
			wantErr: false,
			want:    []Permission{},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				role:   Role("Administrator123"),
				domain: Domain("755"),
			},
			wantErr: true,
			want:    []Permission(nil),
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				role:   Role("Viewer"),
				domain: Domain("701"),
			},
			wantErr: true,
			want:    []Permission(nil),
		},
	}
	for _, tt := range tests {
		tt := tt
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

			if err := c.DeleteAllRolePermissions(ctx, tt.args.role, tt.args.domain); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.DeleteRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permsAfter, err := c.RolePermissions(ctx, tt.args.role, tt.args.domain)
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
		permissions []Permission
		role        Role
		domain      Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []Permission
	}{
		{
			name: "Adds permissions successfully",
			args: args{
				permissions: []Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "712",
			},
			wantErr: false,
			want:    []Permission{"AddUser", "ViewUser", "AddName"},
		},
		{
			name: "fails due to missing role",
			args: args{
				permissions: []Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Administrator",
				domain:      "712",
			},
			wantErr: true,
			want:    []Permission{},
		},
		{
			name: "fails due to wrong domain",
			args: args{
				permissions: []Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "755",
			},
			wantErr: true,
			want:    []Permission{},
		},
	}
	for _, tt := range tests {
		tt := tt
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

			if err := c.AddRolePermissions(ctx, tt.args.permissions, tt.args.role, tt.args.domain); err != nil {
				if tt.wantErr {
					return
				}

				t.Errorf("Client.AddRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}

			permissionsAfter, err := c.RolePermissions(ctx, tt.args.role, tt.args.domain)
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
		domain Domain
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
				domain: Domain("755"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Domain not found",
			args: args{
				ctx:    context.Background(),
				domain: Domain("733"),
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
				domain: Domain("755"),
			},
			prepare: func(db *MockDomains) {
				db.EXPECT().DomainExists(gomock.Any(), "755").Return(false, errors.New("error returned"))
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
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
