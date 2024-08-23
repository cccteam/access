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

	"github.com/cccteam/httpio"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/errors/v5"
	"github.com/go-playground/validator/v10"
	"go.uber.org/mock/gomock"
)

const ViewRolePermissions Permission = "ViewRolePermissions"

func NewMockHandlerClient(accessManager Manager) *HandlerClient {
	a := &HandlerClient{
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

	return a
}

// calls the Users() handler and returns a slice of users
//
// use this for reference purposes
func TestAppUsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		want    []UserAccess
		prepare func(accessManager *MockManager)
		wantErr bool
	}{
		{
			name: "gets a list of users",
			want: []UserAccess{{
				Name:        "zach",
				Roles:       map[Domain][]Role{Domain("755"): {"Administrator"}},
				Permissions: map[Domain][]Permission{Domain("755"): {ViewRolePermissions}},
			}},
			prepare: func(accessManager *MockManager) {
				// configuring the mock to expect a call to accessManager.Users and to return a list of users. This is set to only be called once
				accessManager.EXPECT().Users(gomock.Any()).Return(
					[]*UserAccess{{
						Name:        "zach",
						Roles:       map[Domain][]Role{Domain("755"): {"Administrator"}},
						Permissions: map[Domain][]Permission{Domain("755"): {ViewRolePermissions}},
					}}, nil).Times(1)
			},
		},
		{
			name: "fails to get users and returns a 500",
			prepare: func(accessManager *MockManager) {
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
			accessManager := NewMockManager(ctrl)
			a := NewMockHandlerClient(accessManager)

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, nil)
			if err != nil {
				t.Error(err)
			}

			tt.prepare(accessManager)
			rr := httptest.NewRecorder()

			a.Users().ServeHTTP(rr, req)

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

func TestAppUser(t *testing.T) {
	t.Parallel()

	type args struct {
		username string
	}
	tests := []struct {
		name    string
		want    *UserAccess
		wantErr bool
		args    args
		prepare func(user *MockManager)
	}{
		{
			name: "Gets Zach",
			want: &UserAccess{
				Name:        "zach",
				Roles:       map[Domain][]Role{Domain("755"): {"Viewer"}},
				Permissions: map[Domain][]Permission{},
			},
			args: args{username: "zach"},
			prepare: func(user *MockManager) {
				user.EXPECT().User(gomock.Any(), User("zach")).Return(&UserAccess{
					Name:        "zach",
					Roles:       map[Domain][]Role{Domain("755"): {"Viewer"}},
					Permissions: map[Domain][]Permission{},
				}, nil).Times(1)
			},
		},
		{
			name: "gets the wrong user",
			want: &UserAccess{
				Name:        "billy",
				Roles:       map[Domain][]Role{},
				Permissions: map[Domain][]Permission{},
			},
			wantErr: true,
			args: args{
				username: "zach",
			},
			prepare: func(user *MockManager) {
				user.EXPECT().User(gomock.Any(), User("zach")).Return(&UserAccess{
					Name:        "zach",
					Roles:       map[Domain][]Role{},
					Permissions: map[Domain][]Permission{},
				}, nil).Times(1)
			},
		},
		{
			name: "fails validation",
			want: &UserAccess{
				Name:        "billy",
				Roles:       map[Domain][]Role{},
				Permissions: map[Domain][]Permission{},
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
			prepare: func(user *MockManager) {
				user.EXPECT().User(gomock.Any(), User("zach")).Return(nil, errors.New("failed to get the user")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)
			a := NewMockHandlerClient(accessManager)

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramUser: tt.args.username})
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(a.User()).ServeHTTP(rr, req)

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

func TestApp_AddRole(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		body        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockManager)
	}{
		{
			name:    "Adds Viewer Role",
			wantErr: false,
			args:    args{guarantorID: "755", body: `{"roleName" : "Viewer" }`},
			prepare: func(user *MockManager) {
				user.EXPECT().AddRole(gomock.Any(), Domain("755"), Role("Viewer")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().AddRole(gomock.Any(), Domain("755"), Role("Viewer")).Return(errors.New("Failed to add the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			req, err := createHTTPRequest(http.MethodPost, strings.NewReader(tt.args.body), map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID})
			if err != nil {
				t.Error(err)
			}

			rr := httptest.NewRecorder()
			httpio.WithParams(a.AddRole()).ServeHTTP(rr, req)

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

func TestApp_DeleteRole(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		prepare func(user *MockManager)
	}{
		{
			name:    "deletes Viewer Role",
			wantErr: false,
			args:    args{guarantorID: "755", role: "Viewer"},
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRole(gomock.Any(), Role("Viewer"), Domain("755")).Return(true, nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRole(gomock.Any(), Role("Viewer"), Domain("755")).Return(false, errors.New("Failed to add the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

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
			httpio.WithParams(a.DeleteRole()).ServeHTTP(rr, req)

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

func TestAppAddRolePermissions(t *testing.T) {
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
		prepare func(user *MockManager)
	}{
		{
			name:    "successfully adds permissions",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions" : ["AddUser", "RemoveUser"]}`,
			},
			prepare: func(user *MockManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), []Permission{"AddUser", "RemoveUser"}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), []Permission{}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().AddRolePermissions(gomock.Any(), []Permission{"AddUser"}, Role("Admin"), Domain("755")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

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
			httpio.WithParams(a.AddRolePermissions()).ServeHTTP(rr, req)

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

func TestAppAddRoleUsers(t *testing.T) {
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
		prepare func(user *MockManager)
	}{
		{
			name:    "successfully adds users",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users" : ["Daddy", "Bob"]}`,
			},
			prepare: func(user *MockManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), []User{"Daddy", "Bob"}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), []User{}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().AddRoleUsers(gomock.Any(), []User{"Johnny"}, Role("Admin"), Domain("755")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

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
			httpio.WithParams(a.AddRoleUsers()).ServeHTTP(rr, req)

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

func TestApp_DeleteRoleUsers(t *testing.T) {
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
		prepare func(user *MockManager)
	}{
		{
			name:    "successfully adds users",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"users" : ["Daddy", "Bob"]}`,
			},
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), []User{"Daddy", "Bob"}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), []User{}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRoleUsers(gomock.Any(), []User{"Johnny"}, Role("Admin"), Domain("755")).Return(errors.New("failed to remove users from role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

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
			httpio.WithParams(a.DeleteRoleUsers()).ServeHTTP(rr, req)

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

func TestApp_DeleteRolePermissions(t *testing.T) {
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
		prepare func(user *MockManager)
	}{
		{
			name:    "successfully deletes permissions",
			wantErr: false,
			args: args{
				guarantorID: "755",
				role:        "Admin",
				body:        `{"permissions" : ["AddUser", "RemoveUser"]}`,
			},
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRolePermissions(gomock.Any(), []Permission{"AddUser", "RemoveUser"}, Role("Admin"), Domain("755")).Return(nil).Times(1)
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
			prepare: func(user *MockManager) {
				user.EXPECT().DeleteRolePermissions(gomock.Any(), []Permission{"AddUser"}, Role("Admin"), Domain("755")).Return(errors.New("failed to add the user to the role")).Times(1)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			accessManager := NewMockManager(ctrl)

			a := NewMockHandlerClient(accessManager)

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
			httpio.WithParams(a.DeleteRolePermissions()).ServeHTTP(rr, req)

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

func TestApp_Roles(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		prepare func(accessManager *MockManager)
		wantErr bool
	}{
		{
			name: "gets a list of roles",
			want: []string{"this", "is", "a", "test"},
			args: args{
				guarantorID: "755",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().Roles(gomock.Any(), Domain("755")).Return([]Role{Role("this"), Role("is"), Role("a"), Role("test")}, nil)
			},
		},
		{
			name: "fails to get roles and returns a 500",
			args: args{
				guarantorID: "755",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().Roles(gomock.Any(), Domain("755")).Return(nil, errors.New("Failed to get a list of roles")).Times(1)
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
			accessManager := NewMockManager(ctrl)
			a := NewMockHandlerClient(accessManager)

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(a.Roles()).ServeHTTP(rr, req)

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

func TestApp_RoleUsers(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		prepare func(accessManager *MockManager)
		wantErr bool
	}{
		{
			name: "gets a list of users for role",
			want: []string{"daddy"},
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().RoleUsers(gomock.Any(), gomock.Any(), Domain("755")).Return([]User{"daddy"}, nil)
			},
		},
		{
			name: "fails to get roles and returns a 500",
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().RoleUsers(gomock.Any(), Role("Admin"), Domain("755")).Return(nil, errors.New("Failed to get a list of roles")).Times(1)
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
			accessManager := NewMockManager(ctrl)
			a := NewMockHandlerClient(accessManager)

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(a.RoleUsers()).ServeHTTP(rr, req)

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

func TestApp_RolePermissions(t *testing.T) {
	t.Parallel()

	type args struct {
		guarantorID string
		role        string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		prepare func(accessManager *MockManager)
		wantErr bool
	}{
		{
			name: "gets a list of permissions for role",
			want: []string{"daddy"},
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().RolePermissions(gomock.Any(), gomock.Any(), Domain("755")).Return([]Permission{"daddy"}, nil)
			},
		},
		{
			name: "fails to get permissions and returns a 500",
			args: args{
				guarantorID: "755",
				role:        "Admin",
			},
			prepare: func(accessManager *MockManager) {
				accessManager.EXPECT().RolePermissions(gomock.Any(), Role("Admin"), Domain("755")).Return(nil, errors.New("Failed to get a list of permissions")).Times(1)
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
			accessManager := NewMockManager(ctrl)
			a := NewMockHandlerClient(accessManager)

			req, err := createHTTPRequest(http.MethodGet, http.NoBody, map[httpio.ParamType]string{paramGuarantorID: tt.args.guarantorID, paramRole: tt.args.role})
			if err != nil {
				t.Error(err)
			}

			if tt.prepare != nil {
				tt.prepare(accessManager)
			}

			rr := httptest.NewRecorder()

			httpio.WithParams(a.RolePermissions()).ServeHTTP(rr, req)

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

			var got []string
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
