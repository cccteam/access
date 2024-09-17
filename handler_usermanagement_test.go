package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/go-playground/validator/v10"
	"go.uber.org/mock/gomock"
)

const ViewRolePermissions accesstypes.Permission = "ViewRolePermissions"

func TestHandlerClient_Users(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		want    []UserAccess
		prepare func(accessManager *MockUserManager)
		wantErr bool
	}{
		{
			name: "gets a list of users",
			want: []UserAccess{{
				Name:        "zach",
				Roles:       accesstypes.RoleCollection{accesstypes.Domain("755"): {"Administrator"}},
				Permissions: accesstypes.UserPermissionCollection{accesstypes.Domain("755"): {ViewRolePermissions: {accesstypes.GlobalResource}}},
			}},
			prepare: func(accessManager *MockUserManager) {
				// configuring the mock to expect a call to accessManager.Users and to return a list of users. This is set to only be called once
				accessManager.EXPECT().Users(gomock.Any()).Return(
					[]*UserAccess{{
						Name:        "zach",
						Roles:       accesstypes.RoleCollection{accesstypes.Domain("755"): {"Administrator"}},
						Permissions: accesstypes.UserPermissionCollection{accesstypes.Domain("755"): {ViewRolePermissions: {accesstypes.GlobalResource}}},
					}}, nil).Times(1)
			},
		},
		{
			name: "fails to get users and returns a 500",
			prepare: func(accessManager *MockUserManager) {
				// configuring the mock to expect a call to accessManager.Users and to return an error. This is set to only be called once
				accessManager.EXPECT().Users(gomock.Any()).Return(nil, errors.New("Failed to get a list of users")).Times(1)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, nil)
			if err != nil {
				t.Error(err)
			}

			tt.prepare(accessManager)
			rr := httptest.NewRecorder()

			h.Users().ServeHTTP(rr, req)

			// Check what the response code is. For 500 errors, execute this block
			if rr.Code == http.StatusInternalServerError {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.Users() error = %v, wantErr = %v", got, tt.wantErr)
			}

			// parse the response body
			var got []UserAccess
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}

			// check if the response is what we expected by comparing the two
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.Users() = %v, want %v", &got, tt.want)
			}
		})
	}
}

func TestHandlerClient_User(t *testing.T) {
	t.Parallel()

	type args struct {
		username string
	}
	tests := []struct {
		name    string
		want    *UserAccess
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name: "Gets Zach",
			want: &UserAccess{
				Name:        "zach",
				Roles:       accesstypes.RoleCollection{accesstypes.Domain("755"): {"Viewer"}},
				Permissions: accesstypes.UserPermissionCollection{},
			},
			args: args{username: "zach"},
			prepare: func(user *MockUserManager) {
				user.EXPECT().User(gomock.Any(), accesstypes.User("zach")).Return(&UserAccess{
					Name:        "zach",
					Roles:       accesstypes.RoleCollection{accesstypes.Domain("755"): {"Viewer"}},
					Permissions: accesstypes.UserPermissionCollection{},
				}, nil).Times(1)
			},
		},
		{
			name: "gets the wrong user",
			want: &UserAccess{
				Name:        "billy",
				Roles:       accesstypes.RoleCollection{},
				Permissions: accesstypes.UserPermissionCollection{},
			},
			wantErr: true,
			args: args{
				username: "zach",
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().User(gomock.Any(), accesstypes.User("zach")).Return(&UserAccess{
					Name:        "zach",
					Roles:       accesstypes.RoleCollection{},
					Permissions: accesstypes.UserPermissionCollection{},
				}, nil).Times(1)
			},
		},
		{
			name: "fails validation",
			want: &UserAccess{
				Name:        "billy",
				Roles:       accesstypes.RoleCollection{},
				Permissions: accesstypes.UserPermissionCollection{},
			},
			wantErr: true,
			args: args{
				username: "",
			},
		},
		{
			name:    "fails to get user",
			wantErr: true,
			args: args{
				username: "zach",
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().User(gomock.Any(), accesstypes.User("zach")).Return(nil, errors.New("failed to get the user")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramUser: tt.args.username})
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.User()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.Users() error = %v, wantErr = %v", got.Message, tt.wantErr)
			}

			var got *UserAccess
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}

			if !reflect.DeepEqual(got, tt.want) != tt.wantErr {
				t.Errorf("App.getUser = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandlerClient_AddRole(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "Adds Viewer Role",
			wantErr: false,
			args:    args{guarantorID: "755", body: `{"roleName" : "Viewer" }`},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRole(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Viewer")).Return(nil).Times(1)
			},
		},
		{
			name:    "fail to parse body",
			wantErr: true,
			args: args{
				guarantorID: "755",
			},
		},
		{
			name:    "fail to validate domain",
			args:    args{body: `{"roleName" : "Viewer" }`},
			wantErr: true,
		},
		{
			name:    "fails to add a role",
			wantErr: true,
			args: args{
				guarantorID: "755",
				body:        `{"roleName" : "Viewer" }`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRole(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Viewer")).Return(errors.New("Failed to add the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost, strings.NewReader(tt.args.body), map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID})
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.AddRole()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.AddRole() error = %v, wantErr = %v", got, tt.wantErr)
			}

			type response struct {
				Role string
			}

			var got *response

			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}
		})
	}
}

func TestHandlerClient_DeleteRole(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "deletes Viewer Role",
			wantErr: false,
			args:    args{guarantorID: "755", role: "Viewer"},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRole(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Viewer")).Return(true, nil).Times(1)
			},
		},
		{
			name:    "fail to validate domain",
			args:    args{guarantorID: "", role: "Viewer"},
			wantErr: true,
		},
		{
			name:    "fail to validate role",
			args:    args{guarantorID: "755", role: ""},
			wantErr: true,
		},
		{
			name:    "fails to delete a role",
			wantErr: true,
			args:    args{guarantorID: "755", role: "Viewer"},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRole(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Viewer")).Return(false, errors.New("Failed to add the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost,
				http.NoBody,
				map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role},
			)
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.DeleteRole()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.AddRole() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestHandlerClient_AddRolePermissions(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "successfully adds permissions",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions" : ["AddUser", "RemoveUser"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.Permission("AddUser"), accesstypes.Permission("RemoveUser")).Return(nil).Times(1)
			},
		},
		{
			name:    "successfully adds permissions empty",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{ "permissions" : [] }`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin")).Return(nil).Times(1)
			},
		},
		{
			name:    "fails to parse the request body",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"permissions": {abc}`,
			},
		},
		{
			name:    "fails on domain",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"permissions": []}`,
			},
		},
		{
			name:    "fails on role",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "",
				body:        `{"permissions": []}`,
			},
		},
		{
			name:    "fails to add the permissions",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions": ["AddUser"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.Permission("AddUser")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost,
				strings.NewReader(tt.args.body),
				map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role},
			)
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.AddRolePermissions()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.AddRolePermissions() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestHandlerClient_AddRoleUsers(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "successfully adds users",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users" : ["Daddy", "Bob"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.User("Daddy"), accesstypes.User("Bob")).Return(nil).Times(1)
			},
		},
		{
			name:    "successfully adds users empty",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{ "users" : [] }`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin")).Return(nil).Times(1)
			},
		},
		{
			name:    "fails to parse the request body",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"users": {abc}`,
			},
		},
		{
			name:    "fails on domain",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"users": []}`,
			},
		},
		{
			name:    "fails on role",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "",
				body:        `{"users": []}`,
			},
		},
		{
			name:    "fails to add the users",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users": ["Johnny"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.User("Johnny")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost,
				strings.NewReader(tt.args.body),
				map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role},
			)
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.AddRoleUsers()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.AddRoleUsers() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestHandlerClient_DeleteRoleUsers(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "successfully adds users",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users" : ["Daddy", "Bob"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.User("Daddy"), accesstypes.User("Bob")).Return(nil).Times(1)
			},
		},
		{
			name:    "successfully adds users empty",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{ "users" : [] }`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin")).Return(nil).Times(1)
			},
		},
		{
			name:    "fails to parse the request body",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"users": {abc}`,
			},
		},
		{
			name:    "fails on domain",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"users": []}`,
			},
		},
		{
			name:    "fails on role",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "",
				body:        `{"users": []}`,
			},
		},
		{
			name:    "fails to delete the users",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users": ["Johnny"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.User("Johnny")).Return(errors.New("failed to remove users from role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost,
				strings.NewReader(tt.args.body),
				map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role},
			)
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.DeleteRoleUsers()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.DeleteRoleUsers() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestHandlerClient_DeleteRolePermissions(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockUserManager)
	}{
		{
			name:    "successfully deletes permissions",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions" : ["AddUser", "RemoveUser"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.Permission("AddUser"), accesstypes.Permission("RemoveUser")).Return(nil).Times(1)
			},
		},
		{
			name:    "fails to delete permissions empty",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{ "permissions" : [] }`,
			},
		},
		{
			name:    "fails to parse the request body",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"permissions": {abc}`,
			},
		},
		{
			name:    "fails on domain",
			wantErr: true,
			args: args{
				guarantorID: "",
				role:        "Admin",
				body:        `{"permissions": ["KillUser"]}`,
			},
		},
		{
			name:    "fails on role",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "",
				body:        `{"permissions": ["KillUser"]}`,
			},
		},
		{
			name:    "fails to delete the permissions",
			wantErr: true,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions": ["AddUser"]}`,
			},
			prepare: func(user *MockUserManager) {
				user.EXPECT().DeleteRolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin"), accesstypes.Permission("AddUser")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost,
				strings.NewReader(tt.args.body),
				map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role},
			)
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(h.DeleteRolePermissions()).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.DeleteRolePermissions() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestHandlerClient_Roles(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		prepare func(accessManager *MockUserManager)
		wantErr bool
	}{
		{
			name: "gets a list of roles",
			want: []string{"this", "is", "a", "test"},
			args: args{
				guarantorID: "755",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().Roles(gomock.Any(), accesstypes.Domain("755")).Return([]accesstypes.Role{accesstypes.Role("this"), accesstypes.Role("is"), accesstypes.Role("a"), accesstypes.Role("test")}, nil)
			},
		},
		{
			name: "fails to get roles and returns a 500",
			args: args{
				guarantorID: "755",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().Roles(gomock.Any(), accesstypes.Domain("755")).Return(nil, errors.New("Failed to get a list of roles")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "fails on domain",
			args: args{
				guarantorID: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(h.Roles()).ServeHTTP(rr, req)

			// Check what the response code is. For 500 errors, execute this block
			if rr.Code == http.StatusInternalServerError {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.Roles() error = %v, wantErr = %v", got, tt.wantErr)
			}

			// parse the response body
			type response struct {
				Roles []string
			}

			var got response
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}

			// check if the response is what we expected by comparing the two
			if !reflect.DeepEqual(got.Roles, tt.want) {
				t.Errorf("App.Roles() = %v, want %v", &got, tt.want)
			}
		})
	}
}

func TestHandlerClient_RoleUsers(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		prepare func(accessManager *MockUserManager)
		wantErr bool
	}{
		{
			name: "gets a list of users for role",
			want: []string{"daddy"},
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().RoleUsers(gomock.Any(), accesstypes.Domain("755"), gomock.Any()).Return([]accesstypes.User{"daddy"}, nil)
			},
		},
		{
			name: "fails to get roles and returns a 500",
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().RoleUsers(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin")).Return(nil, errors.New("Failed to get a list of roles")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "fails on domain",
			args: args{
				guarantorID: "",
				role:        "Admin",
			},
			wantErr: true,
		},
		{
			name: "fails on role",
			args: args{
				guarantorID: "755",
				role:        "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(h.RoleUsers()).ServeHTTP(rr, req)

			// Check what the response code is. For 500 errors, execute this block
			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.RoleUsers() error = %v, wantErr = %v", got, tt.wantErr)
			}

			var got []string
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}

			// check if the response is what we expected by comparing the two
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.RoleUsers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandlerClient_RolePermissions(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		args    args
		want    accesstypes.RolePermissionCollection
		prepare func(accessManager *MockUserManager)
		wantErr bool
	}{
		{
			name: "gets a list of permissions for role",
			want: accesstypes.RolePermissionCollection{"daddy": {"resource:global"}},
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().RolePermissions(gomock.Any(), accesstypes.Domain("755"), gomock.Any()).Return(accesstypes.RolePermissionCollection{"daddy": {"resource:global"}}, nil)
			},
		},
		{
			name: "fails to get permissions and returns a 500",
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockUserManager) {
				accessManager.EXPECT().RolePermissions(gomock.Any(), accesstypes.Domain("755"), accesstypes.Role("Admin")).Return(nil, errors.New("Failed to get a list of permissions")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "fails on domain",
			args: args{
				guarantorID: "",
				role:        "Admin",
			},
			wantErr: true,
		},
		{
			name: "fails on role",
			args: args{
				guarantorID: "755",
				role:        "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockUserManager(ctrl)

			h := &HandlerClient{
				manager:  accessManager,
				validate: validator.New(),
				handler: func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						if err := handler(w, r); err != nil {
							_ = httpio.NewEncoder(w).ClientMessage(r.Context(), err)
						}
					}
				},
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(h.RolePermissions()).ServeHTTP(rr, req)

			// Check what the response code is. For 500 errors, execute this block
			if rr.Code != http.StatusOK {
				if tt.wantErr {
					return
				}
				var got httpio.MessageResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
					t.Errorf("json.Unmarshal() error=%v", err)
				}
				t.Errorf("App.RolePermissions() error = %v, wantErr = %v", got, tt.wantErr)
			}

			var got accesstypes.RolePermissionCollection
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("json.Unmarshal() error=%v", err)
			}

			// check if the response is what we expected by comparing the two
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("App.RolePermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func createHTTPRequest(method string, body io.Reader, urlParams map[httpio.ParamType]string) (*http.Request, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, method, "", body)
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequestWithContext()")
	}
	rctx := chi.NewRouteContext()
	for key, val := range urlParams {
		rctx.URLParams.Add(string(key), val)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req, nil
}
