// Code generated by MockGen. DO NOT EDIT.
// Source: ../access_iface.go
//
// Generated by this command:
//
//	mockgen -package access -source ../access_iface.go -destination ../mock_access_iface.go
//

// Package access is a generated GoMock package.
package access

import (
	context "context"
	reflect "reflect"

	accesstypes "github.com/cccteam/ccc/accesstypes"
	validator "github.com/go-playground/validator/v10"
	gomock "go.uber.org/mock/gomock"
)

// MockController is a mock of Controller interface.
type MockController struct {
	ctrl     *gomock.Controller
	recorder *MockControllerMockRecorder
	isgomock struct{}
}

// MockControllerMockRecorder is the mock recorder for MockController.
type MockControllerMockRecorder struct {
	mock *MockController
}

// NewMockController creates a new mock instance.
func NewMockController(ctrl *gomock.Controller) *MockController {
	mock := &MockController{ctrl: ctrl}
	mock.recorder = &MockControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockController) EXPECT() *MockControllerMockRecorder {
	return m.recorder
}

// Handlers mocks base method.
func (m *MockController) Handlers(validate *validator.Validate, handler LogHandler) Handlers {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Handlers", validate, handler)
	ret0, _ := ret[0].(Handlers)
	return ret0
}

// Handlers indicates an expected call of Handlers.
func (mr *MockControllerMockRecorder) Handlers(validate, handler any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Handlers", reflect.TypeOf((*MockController)(nil).Handlers), validate, handler)
}

// RequireAll mocks base method.
func (m *MockController) RequireAll(ctx context.Context, user accesstypes.User, domain accesstypes.Domain, permissions ...accesstypes.Permission) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user, domain}
	for _, a := range permissions {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RequireAll", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// RequireAll indicates an expected call of RequireAll.
func (mr *MockControllerMockRecorder) RequireAll(ctx, user, domain any, permissions ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user, domain}, permissions...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireAll", reflect.TypeOf((*MockController)(nil).RequireAll), varargs...)
}

// RequireResources mocks base method.
func (m *MockController) RequireResources(ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource) (bool, []accesstypes.Resource, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, username, domain, perm}
	for _, a := range resources {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RequireResources", varargs...)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].([]accesstypes.Resource)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// RequireResources indicates an expected call of RequireResources.
func (mr *MockControllerMockRecorder) RequireResources(ctx, username, domain, perm any, resources ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, username, domain, perm}, resources...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequireResources", reflect.TypeOf((*MockController)(nil).RequireResources), varargs...)
}

// UserManager mocks base method.
func (m *MockController) UserManager() UserManager {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserManager")
	ret0, _ := ret[0].(UserManager)
	return ret0
}

// UserManager indicates an expected call of UserManager.
func (mr *MockControllerMockRecorder) UserManager() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserManager", reflect.TypeOf((*MockController)(nil).UserManager))
}

// MockUserManager is a mock of UserManager interface.
type MockUserManager struct {
	ctrl     *gomock.Controller
	recorder *MockUserManagerMockRecorder
	isgomock struct{}
}

// MockUserManagerMockRecorder is the mock recorder for MockUserManager.
type MockUserManagerMockRecorder struct {
	mock *MockUserManager
}

// NewMockUserManager creates a new mock instance.
func NewMockUserManager(ctrl *gomock.Controller) *MockUserManager {
	mock := &MockUserManager{ctrl: ctrl}
	mock.recorder = &MockUserManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserManager) EXPECT() *MockUserManagerMockRecorder {
	return m.recorder
}

// AddRole mocks base method.
func (m *MockUserManager) AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRole", ctx, domain, role)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRole indicates an expected call of AddRole.
func (mr *MockUserManagerMockRecorder) AddRole(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRole", reflect.TypeOf((*MockUserManager)(nil).AddRole), ctx, domain, role)
}

// AddRolePermissionResources mocks base method.
func (m *MockUserManager) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role, permission}
	for _, a := range resources {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddRolePermissionResources", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRolePermissionResources indicates an expected call of AddRolePermissionResources.
func (mr *MockUserManagerMockRecorder) AddRolePermissionResources(ctx, domain, role, permission any, resources ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role, permission}, resources...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRolePermissionResources", reflect.TypeOf((*MockUserManager)(nil).AddRolePermissionResources), varargs...)
}

// AddRolePermissions mocks base method.
func (m *MockUserManager) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role}
	for _, a := range permissions {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddRolePermissions", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRolePermissions indicates an expected call of AddRolePermissions.
func (mr *MockUserManagerMockRecorder) AddRolePermissions(ctx, domain, role any, permissions ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role}, permissions...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRolePermissions", reflect.TypeOf((*MockUserManager)(nil).AddRolePermissions), varargs...)
}

// AddRoleUsers mocks base method.
func (m *MockUserManager) AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role}
	for _, a := range users {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddRoleUsers", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRoleUsers indicates an expected call of AddRoleUsers.
func (mr *MockUserManagerMockRecorder) AddRoleUsers(ctx, domain, role any, users ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role}, users...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRoleUsers", reflect.TypeOf((*MockUserManager)(nil).AddRoleUsers), varargs...)
}

// AddUserRoles mocks base method.
func (m *MockUserManager) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, user}
	for _, a := range roles {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AddUserRoles", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddUserRoles indicates an expected call of AddUserRoles.
func (mr *MockUserManagerMockRecorder) AddUserRoles(ctx, domain, user any, roles ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, user}, roles...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddUserRoles", reflect.TypeOf((*MockUserManager)(nil).AddUserRoles), varargs...)
}

// DeleteAllRolePermissions mocks base method.
func (m *MockUserManager) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAllRolePermissions", ctx, domain, role)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllRolePermissions indicates an expected call of DeleteAllRolePermissions.
func (mr *MockUserManagerMockRecorder) DeleteAllRolePermissions(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllRolePermissions", reflect.TypeOf((*MockUserManager)(nil).DeleteAllRolePermissions), ctx, domain, role)
}

// DeleteRole mocks base method.
func (m *MockUserManager) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRole", ctx, domain, role)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteRole indicates an expected call of DeleteRole.
func (mr *MockUserManagerMockRecorder) DeleteRole(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRole", reflect.TypeOf((*MockUserManager)(nil).DeleteRole), ctx, domain, role)
}

// DeleteRolePermissionResources mocks base method.
func (m *MockUserManager) DeleteRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role, permission}
	for _, a := range resources {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteRolePermissionResources", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRolePermissionResources indicates an expected call of DeleteRolePermissionResources.
func (mr *MockUserManagerMockRecorder) DeleteRolePermissionResources(ctx, domain, role, permission any, resources ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role, permission}, resources...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRolePermissionResources", reflect.TypeOf((*MockUserManager)(nil).DeleteRolePermissionResources), varargs...)
}

// DeleteRolePermissions mocks base method.
func (m *MockUserManager) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role}
	for _, a := range permissions {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteRolePermissions", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRolePermissions indicates an expected call of DeleteRolePermissions.
func (mr *MockUserManagerMockRecorder) DeleteRolePermissions(ctx, domain, role any, permissions ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role}, permissions...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRolePermissions", reflect.TypeOf((*MockUserManager)(nil).DeleteRolePermissions), varargs...)
}

// DeleteRoleUsers mocks base method.
func (m *MockUserManager) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, role}
	for _, a := range users {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteRoleUsers", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRoleUsers indicates an expected call of DeleteRoleUsers.
func (mr *MockUserManagerMockRecorder) DeleteRoleUsers(ctx, domain, role any, users ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, role}, users...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRoleUsers", reflect.TypeOf((*MockUserManager)(nil).DeleteRoleUsers), varargs...)
}

// DeleteUserRoles mocks base method.
func (m *MockUserManager) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx, domain, user}
	for _, a := range roles {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUserRoles", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserRoles indicates an expected call of DeleteUserRoles.
func (mr *MockUserManagerMockRecorder) DeleteUserRoles(ctx, domain, user any, roles ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, domain, user}, roles...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserRoles", reflect.TypeOf((*MockUserManager)(nil).DeleteUserRoles), varargs...)
}

// DomainExists mocks base method.
func (m *MockUserManager) DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DomainExists", ctx, domain)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DomainExists indicates an expected call of DomainExists.
func (mr *MockUserManagerMockRecorder) DomainExists(ctx, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DomainExists", reflect.TypeOf((*MockUserManager)(nil).DomainExists), ctx, domain)
}

// Domains mocks base method.
func (m *MockUserManager) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Domains", ctx)
	ret0, _ := ret[0].([]accesstypes.Domain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Domains indicates an expected call of Domains.
func (mr *MockUserManagerMockRecorder) Domains(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Domains", reflect.TypeOf((*MockUserManager)(nil).Domains), ctx)
}

// RoleExists mocks base method.
func (m *MockUserManager) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleExists", ctx, domain, role)
	ret0, _ := ret[0].(bool)
	return ret0
}

// RoleExists indicates an expected call of RoleExists.
func (mr *MockUserManagerMockRecorder) RoleExists(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleExists", reflect.TypeOf((*MockUserManager)(nil).RoleExists), ctx, domain, role)
}

// RolePermissions mocks base method.
func (m *MockUserManager) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RolePermissions", ctx, domain, role)
	ret0, _ := ret[0].(accesstypes.RolePermissionCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RolePermissions indicates an expected call of RolePermissions.
func (mr *MockUserManagerMockRecorder) RolePermissions(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RolePermissions", reflect.TypeOf((*MockUserManager)(nil).RolePermissions), ctx, domain, role)
}

// RoleUsers mocks base method.
func (m *MockUserManager) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleUsers", ctx, domain, role)
	ret0, _ := ret[0].([]accesstypes.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RoleUsers indicates an expected call of RoleUsers.
func (mr *MockUserManagerMockRecorder) RoleUsers(ctx, domain, role any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleUsers", reflect.TypeOf((*MockUserManager)(nil).RoleUsers), ctx, domain, role)
}

// Roles mocks base method.
func (m *MockUserManager) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Roles", ctx, domain)
	ret0, _ := ret[0].([]accesstypes.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Roles indicates an expected call of Roles.
func (mr *MockUserManagerMockRecorder) Roles(ctx, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Roles", reflect.TypeOf((*MockUserManager)(nil).Roles), ctx, domain)
}

// User mocks base method.
func (m *MockUserManager) User(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (*UserAccess, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "User", varargs...)
	ret0, _ := ret[0].(*UserAccess)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// User indicates an expected call of User.
func (mr *MockUserManagerMockRecorder) User(ctx, user any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "User", reflect.TypeOf((*MockUserManager)(nil).User), varargs...)
}

// UserPermissions mocks base method.
func (m *MockUserManager) UserPermissions(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserPermissions", varargs...)
	ret0, _ := ret[0].(accesstypes.UserPermissionCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserPermissions indicates an expected call of UserPermissions.
func (mr *MockUserManagerMockRecorder) UserPermissions(ctx, user any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserPermissions", reflect.TypeOf((*MockUserManager)(nil).UserPermissions), varargs...)
}

// UserRoles mocks base method.
func (m *MockUserManager) UserRoles(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, user}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserRoles", varargs...)
	ret0, _ := ret[0].(accesstypes.RoleCollection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserRoles indicates an expected call of UserRoles.
func (mr *MockUserManagerMockRecorder) UserRoles(ctx, user any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, user}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserRoles", reflect.TypeOf((*MockUserManager)(nil).UserRoles), varargs...)
}

// Users mocks base method.
func (m *MockUserManager) Users(ctx context.Context, domain ...accesstypes.Domain) ([]*UserAccess, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Users", varargs...)
	ret0, _ := ret[0].([]*UserAccess)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Users indicates an expected call of Users.
func (mr *MockUserManagerMockRecorder) Users(ctx any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Users", reflect.TypeOf((*MockUserManager)(nil).Users), varargs...)
}

// MockDomains is a mock of Domains interface.
type MockDomains struct {
	ctrl     *gomock.Controller
	recorder *MockDomainsMockRecorder
	isgomock struct{}
}

// MockDomainsMockRecorder is the mock recorder for MockDomains.
type MockDomainsMockRecorder struct {
	mock *MockDomains
}

// NewMockDomains creates a new mock instance.
func NewMockDomains(ctrl *gomock.Controller) *MockDomains {
	mock := &MockDomains{ctrl: ctrl}
	mock.recorder = &MockDomainsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDomains) EXPECT() *MockDomainsMockRecorder {
	return m.recorder
}

// DomainExists mocks base method.
func (m *MockDomains) DomainExists(ctx context.Context, guarantorID string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DomainExists", ctx, guarantorID)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DomainExists indicates an expected call of DomainExists.
func (mr *MockDomainsMockRecorder) DomainExists(ctx, guarantorID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DomainExists", reflect.TypeOf((*MockDomains)(nil).DomainExists), ctx, guarantorID)
}

// DomainIDs mocks base method.
func (m *MockDomains) DomainIDs(ctx context.Context) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DomainIDs", ctx)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DomainIDs indicates an expected call of DomainIDs.
func (mr *MockDomainsMockRecorder) DomainIDs(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DomainIDs", reflect.TypeOf((*MockDomains)(nil).DomainIDs), ctx)
}
