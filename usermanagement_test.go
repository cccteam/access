package access

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
)

// TestClient_User_Add_Delete tests adding and deleting roles from a user. It also tests the User method.
// This ties all  three methods together, but it is the easiest way to check the results of Add/Delete.
func TestClient_User_Add_Delete(t *testing.T) {
	t.Parallel()

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
		prepare  func(store *MockStore, domains *MockDomains)
	}{
		{
			name: "Charlie",
			args: args{
				ctx:      context.Background(),
				username: "charlie",
				role:     "Viewer",
				domain:   "712",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).AnyTimes()
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
			want: &UserAccess{
				Name: "charlie",
				Roles: accesstypes.RoleCollection{
					"global": {},
					"755":    {},
					"712":    {},
				},
				Permissions: accesstypes.UserPermissionCollection{
					"global": {},
					"755":    {},
					"712":    {},
				},
			},
			wantAdd: &UserAccess{
				Name: "charlie",
				Roles: accesstypes.RoleCollection{
					"global": {},
					"755":    {},
					"712":    {"Viewer"},
				},
				Permissions: accesstypes.UserPermissionCollection{
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
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("I failed")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "returns error when role doesn't exist",
			args: args{
				ctx:      context.Background(),
				username: "bill",
				role:     "Non-Existent",
				domain:   "712",
			},
			want: &UserAccess{
				Name: "bill",
				Roles: accesstypes.RoleCollection{
					"global": {},
					"755":    {},
					"712":    {},
				},
				Permissions: accesstypes.UserPermissionCollection{
					"global": {},
					"755":    {},
					"712":    {},
				},
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).AnyTimes()
				store.EXPECT().RoleByName(gomock.Any(), "Non-Existent").Return(nil, nil).AnyTimes()
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
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store, domains)
			}
			c, err := newUserManager(domains, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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
				t.Errorf("Client.DeleteUserRoles() error = %v, wantErr %v", err, tt.want2Err)
			}
			got, err = c.User(tt.args.ctx, tt.args.username)
			if (err != nil) != tt.want2Err {
				t.Fatalf("Client.User() error = %v, wantErr %v", err, tt.want2Err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Client.User() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Users(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    []*UserAccess
		wantErr bool
		prepare func(store *MockStore, domains *MockDomains)
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
						"global": {},
						"712":    {},
						"755":    {},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global": {},
						"712":    {"global": {"ViewUsers"}},
						"755":    {},
					},
				},
				{
					Name: "bob",
					Roles: accesstypes.RoleCollection{
						"global": {},
						"712":    {"Editor"},
						"755":    {},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global": {},
						"712":    {},
						"755":    {},
					},
				},
				{
					Name: "charlie",
					Roles: accesstypes.RoleCollection{
						"global": {},
						"712":    {},
						"755":    {"Administrator"},
					},
					Permissions: accesstypes.UserPermissionCollection{
						"global": {},
						"712":    {},
						"755":    {"global": {"DeleteUsers", "AddUsers"}},
					},
				},
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return([]string{"712", "755"}, nil).Times(1)
			},
		},
		{
			name: "Users Error",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("I failed")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store, domains)
			}

			c, err := newUserManager(domains, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		want    accesstypes.RolePermissionCollection
		wantErr bool
		prepare func(store *MockStore)
	}{
		{
			name:    "ReturnsListOfPermissions",
			args:    args{role: "Administrator", domain: "755"},
			want:    accesstypes.RolePermissionCollection{"DeleteUsers": {"global"}, "AddUsers": {"global"}},
			wantErr: false,
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Administrator"
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(&r, nil).AnyTimes()
			},
		},
		{
			name:    "No Permissions Found",
			args:    args{role: "Administrator", domain: "712"},
			want:    accesstypes.RolePermissionCollection{},
			wantErr: false,
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Administrator"
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(&r, nil).AnyTimes()
			},
		},
		{
			name:    "Bad role",
			args:    args{role: "asdvsdb", domain: "712"},
			want:    nil,
			wantErr: true,
			prepare: func(store *MockStore) {
				store.EXPECT().RoleByName(gomock.Any(), "asdvsdb").Return(nil, nil).AnyTimes()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		want    []accesstypes.User
		wantErr bool
		prepare func(store *MockStore)
	}{
		{
			name:    "Filters Noop User",
			args:    args{role: "Administrator", domain: "755"},
			want:    []accesstypes.User{"charlie"},
			wantErr: false,
		},
		{
			name:    "No users found",
			args:    args{role: "Administrator", domain: "712"},
			want:    []accesstypes.User{},
			wantErr: false,
		},
		{
			name:    "No users found in given roll",
			args:    args{role: "Admin", domain: "755"},
			want:    []accesstypes.User{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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

	type args struct {
		users  []accesstypes.User
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(store *MockStore)
	}{
		{
			name: "Charlie",
			args: args{
				users:  []accesstypes.User{"charlie"},
				role:   "Administrator",
				domain: "755",
			},
			wantErr: false,
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Administrator"
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(&r, nil).AnyTimes()
			},
		},
		{
			name: "Charlie fails",
			args: args{
				users:  []accesstypes.User{"charlie"},
				role:   "Viewer",
				domain: "755",
			},
			wantErr: true,
			prepare: func(store *MockStore) {
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(nil, nil).AnyTimes()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
			}

			if err := c.DeleteRoleUsers(ctx, tt.args.domain, tt.args.role, tt.args.users...); (err != nil) != tt.wantErr {
				t.Errorf("Client.DeleteRoleUsers() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_AddRole(t *testing.T) {
	t.Parallel()

	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
		role   accesstypes.Role
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(store *MockStore, domains *MockDomains)
	}{
		{
			name: "Successfully add a new role",
			args: args{
				ctx:    context.Background(),
				domain: "755",
				role:   "AddUser",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
				store.EXPECT().RoleByName(gomock.Any(), "AddUser").Return(nil, nil).AnyTimes()
				store.EXPECT().CreateRole(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: "733",
				role:   "AddUser",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "Error getting domain",
			args: args{
				ctx:    context.Background(),
				domain: "733",
				role:   "AddUser",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "733").Return(false, errors.New("failed to get domain"))
			},
			wantErr: true,
		},
		{
			name: "Role Already Exists",
			args: args{
				ctx:    context.Background(),
				domain: "755",
				role:   "Viewer",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store, domains)
			}

			c, err := newUserManager(domains, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
			}

			if err := c.AddRole(tt.args.ctx, tt.args.domain, tt.args.role); (err != nil) != tt.wantErr {
				t.Errorf("Client.AddRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_AddUserRoles(t *testing.T) {
	t.Parallel()

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
		prepare func(store *MockStore, domains *MockDomains)
	}{
		{
			name: "Successfully add roles to a user",
			args: args{
				ctx:    context.Background(),
				domain: "712",
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
		},
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: "712",
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
			wantErr: false,
		},
		{
			name: "Error getting domain",
			args: args{
				ctx:    context.Background(),
				domain: "712",
				roles:  []accesstypes.Role{"Viewer"},
				user:   "Bill",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).AnyTimes().Return([]string{"755", "712"}, nil)
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
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
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store, domains)
			}

			c, err := newUserManager(domains, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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

	type args struct {
		ctx    context.Context
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		want    []accesstypes.Role
		prepare func(store *MockStore, domains *MockDomains)
		wantErr bool
	}{
		{
			name: "Domain doesn't exist",
			args: args{
				ctx:    context.Background(),
				domain: "733",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			wantErr: true,
		},
		{
			name: "returns error checking if domain exists ",
			args: args{
				ctx:    context.Background(),
				domain: "733",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "733").Return(false, errors.New("failed to get DomainIDs"))
			},
			wantErr: true,
		},
		{
			name: "Returns list of roles",
			args: args{
				ctx:    context.Background(),
				domain: "712",
			},
			prepare: func(store *MockStore, domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "712").Return(true, nil)
			},
			wantErr: false,
			want: []accesstypes.Role{
				"Administrator",
				"Auditor",
				"Editor",
				"Viewer",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			domains := NewMockDomains(ctrl)
			store := NewMockStore(ctrl)

			if tt.prepare != nil {
				tt.prepare(store, domains)
			}

			c, err := newUserManager(domains, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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
		prepare func(domains *MockDomains)
		wantErr bool
	}{
		{
			name: "Successfully gets DomainIDs",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return([]string{"755", "712"}, nil)
			},
			want:    []accesstypes.Domain{accesstypes.GlobalDomain, "755", "712"},
			wantErr: false,
		},
		{
			name: "returns error checking if domain exists ",
			args: args{
				ctx: context.Background(),
			},
			prepare: func(domains *MockDomains) {
				domains.EXPECT().DomainIDs(gomock.Any()).Return(nil, errors.New("failed to get DomainIDs"))
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
		prepare   func(store *MockStore)
	}{
		{
			name: "Success",
			args: args{
				role:   "Viewer",
				domain: "755",
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when noop exists",
			args: args{
				role:   "Writer",
				domain: "712",
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Success when it doesn't exist already",
			args: args{
				role:   "Viewer",
				domain: "712",
			},
			want:      true,
			wantErr:   false,
			wantExist: false,
		},
		{
			name: "Fails when users are assigned",
			args: args{
				role:   "Administrator",
				domain: "755",
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
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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
		prepare func(store *MockStore)
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				permissions: []accesstypes.Permission{"AddUsers"},
				role:        "Administrator",
				domain:      "755",
			},
			wantErr: false,
			want: accesstypes.RolePermissionCollection{
				"DeleteUsers": {"global"},
			},
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Administrator"
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(&r, nil).AnyTimes()
			},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				permissions: []accesstypes.Permission{"DELETE * FROM accesspolicies"},
				role:        "Administrator123",
				domain:      "755",
			},
			wantErr: true,
			want:    nil,
			prepare: func(store *MockStore) {
				store.EXPECT().RoleByName(gomock.Any(), "Administrator123").Return(nil, nil).AnyTimes()
			},
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				permissions: []accesstypes.Permission{"DELETE * FROM accesspolicies"},
				role:        "Viewer",
				domain:      "701",
			},
			wantErr: true,
			want:    nil,
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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

	type args struct {
		role   accesstypes.Role
		domain accesstypes.Domain
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    accesstypes.RolePermissionCollection
		prepare func(store *MockStore)
	}{
		{
			name: "Successfully removes permissions from a role",
			args: args{
				role:   "Administrator",
				domain: "755",
			},
			wantErr: false,
			want:    accesstypes.RolePermissionCollection{},
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Administrator"
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(&r, nil).AnyTimes()
			},
		},
		{
			name: "fails to delete permissions from non-existent role",
			args: args{
				role:   "Administrator123",
				domain: "755",
			},
			wantErr: true,
			want:    nil,
			prepare: func(store *MockStore) {
				store.EXPECT().RoleByName(gomock.Any(), "Administrator123").Return(nil, nil).AnyTimes()
			},
		},
		{
			name: "fails to delete permissions due to wrong domain",
			args: args{
				role:   "Viewer",
				domain: "701",
			},
			wantErr: true,
			want:    nil,
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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
		prepare func(store *MockStore)
	}{
		{
			name: "Adds permissions successfully",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "712",
			},
			wantErr: false,
			want:    accesstypes.RolePermissionCollection{"AddUser": {"global"}, "ViewUser": {"global"}, "AddName": {"global"}},
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
		},
		{
			name: "fails due to missing role",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Administrator",
				domain:      "712",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection{},
			prepare: func(store *MockStore) {
				store.EXPECT().RoleByName(gomock.Any(), "Administrator").Return(nil, nil).AnyTimes()
			},
		},
		{
			name: "fails due to wrong domain",
			args: args{
				permissions: []accesstypes.Permission{"AddUser", "ViewUser", "AddName"},
				role:        "Viewer",
				domain:      "755",
			},
			wantErr: true,
			want:    accesstypes.RolePermissionCollection{},
			prepare: func(store *MockStore) {
				var r accesstypes.Role = "Viewer"
				store.EXPECT().RoleByName(gomock.Any(), "Viewer").Return(&r, nil).AnyTimes()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			c, err := newUserManager(nil, store)
			if err != nil {
				t.Fatalf("failed to create userManager. err=%s", err)
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
		prepare func(domains *MockDomains)
		wantErr bool
	}{
		{
			name: "Domain found",
			args: args{
				ctx:    context.Background(),
				domain: "755",
			},
			prepare: func(domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "755").Return(true, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Domain not found",
			args: args{
				ctx:    context.Background(),
				domain: "733",
			},
			prepare: func(domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "733").Return(false, nil)
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "error returned",
			args: args{
				ctx:    context.Background(),
				domain: "755",
			},
			prepare: func(domains *MockDomains) {
				domains.EXPECT().DomainExists(gomock.Any(), "755").Return(false, errors.New("error returned"))
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
