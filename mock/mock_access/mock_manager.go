// Code generated by MockGen. DO NOT EDIT.
// Source: ../access_iface.go
//
// Generated by this command:
//
//	mockgen -source ../access_iface.go -destination mock_access/mock_manager.go
//

// Package mock_access is a generated GoMock package.
package mock_access

import (
	context "context"
	reflect "reflect"

	access "github.com/cccteam/access"
	validator "github.com/go-playground/validator/v10"
	gomock "go.uber.org/mock/gomock"
)

// MockController is a mock of Controller interface.
type MockController struct {
	ctrl     *gomock.Controller
	recorder *MockControllerMockRecorder
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
func (m *MockController) Handlers(validate *validator.Validate, handler access.LogHandler) access.Handlers {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Handlers", validate, handler)
	ret0, _ := ret[0].(access.Handlers)
	return ret0
}

// Handlers indicates an expected call of Handlers.
func (mr *MockControllerMockRecorder) Handlers(validate, handler any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Handlers", reflect.TypeOf((*MockController)(nil).Handlers), validate, handler)
}

// RequireAll mocks base method.
func (m *MockController) RequireAll(ctx context.Context, user access.User, domain access.Domain, permissions ...access.Permission) error {
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

// UserManager mocks base method.
func (m *MockController) UserManager() access.UserManager {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserManager")
	ret0, _ := ret[0].(access.UserManager)
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
func (m *MockUserManager) AddRole(ctx context.Context, domain access.Domain, role access.Role) error {
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

// AddRolePermissions mocks base method.
func (m *MockUserManager) AddRolePermissions(ctx context.Context, permissions []access.Permission, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRolePermissions", ctx, permissions, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRolePermissions indicates an expected call of AddRolePermissions.
func (mr *MockUserManagerMockRecorder) AddRolePermissions(ctx, permissions, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRolePermissions", reflect.TypeOf((*MockUserManager)(nil).AddRolePermissions), ctx, permissions, role, domain)
}

// AddRoleUsers mocks base method.
func (m *MockUserManager) AddRoleUsers(ctx context.Context, users []access.User, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRoleUsers", ctx, users, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRoleUsers indicates an expected call of AddRoleUsers.
func (mr *MockUserManagerMockRecorder) AddRoleUsers(ctx, users, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRoleUsers", reflect.TypeOf((*MockUserManager)(nil).AddRoleUsers), ctx, users, role, domain)
}

// AddUserRoles mocks base method.
func (m *MockUserManager) AddUserRoles(ctx context.Context, user access.User, roles []access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddUserRoles", ctx, user, roles, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddUserRoles indicates an expected call of AddUserRoles.
func (mr *MockUserManagerMockRecorder) AddUserRoles(ctx, user, roles, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddUserRoles", reflect.TypeOf((*MockUserManager)(nil).AddUserRoles), ctx, user, roles, domain)
}

// DeleteAllRolePermissions mocks base method.
func (m *MockUserManager) DeleteAllRolePermissions(ctx context.Context, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAllRolePermissions", ctx, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllRolePermissions indicates an expected call of DeleteAllRolePermissions.
func (mr *MockUserManagerMockRecorder) DeleteAllRolePermissions(ctx, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllRolePermissions", reflect.TypeOf((*MockUserManager)(nil).DeleteAllRolePermissions), ctx, role, domain)
}

// DeleteRole mocks base method.
func (m *MockUserManager) DeleteRole(ctx context.Context, role access.Role, domain access.Domain) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRole", ctx, role, domain)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteRole indicates an expected call of DeleteRole.
func (mr *MockUserManagerMockRecorder) DeleteRole(ctx, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRole", reflect.TypeOf((*MockUserManager)(nil).DeleteRole), ctx, role, domain)
}

// DeleteRolePermissions mocks base method.
func (m *MockUserManager) DeleteRolePermissions(ctx context.Context, permissions []access.Permission, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRolePermissions", ctx, permissions, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRolePermissions indicates an expected call of DeleteRolePermissions.
func (mr *MockUserManagerMockRecorder) DeleteRolePermissions(ctx, permissions, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRolePermissions", reflect.TypeOf((*MockUserManager)(nil).DeleteRolePermissions), ctx, permissions, role, domain)
}

// DeleteRoleUsers mocks base method.
func (m *MockUserManager) DeleteRoleUsers(ctx context.Context, users []access.User, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRoleUsers", ctx, users, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRoleUsers indicates an expected call of DeleteRoleUsers.
func (mr *MockUserManagerMockRecorder) DeleteRoleUsers(ctx, users, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRoleUsers", reflect.TypeOf((*MockUserManager)(nil).DeleteRoleUsers), ctx, users, role, domain)
}

// DeleteUserRole mocks base method.
func (m *MockUserManager) DeleteUserRole(ctx context.Context, username access.User, role access.Role, domain access.Domain) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUserRole", ctx, username, role, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserRole indicates an expected call of DeleteUserRole.
func (mr *MockUserManagerMockRecorder) DeleteUserRole(ctx, username, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserRole", reflect.TypeOf((*MockUserManager)(nil).DeleteUserRole), ctx, username, role, domain)
}

// DomainExists mocks base method.
func (m *MockUserManager) DomainExists(ctx context.Context, domain access.Domain) (bool, error) {
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
func (m *MockUserManager) Domains(ctx context.Context) ([]access.Domain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Domains", ctx)
	ret0, _ := ret[0].([]access.Domain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Domains indicates an expected call of Domains.
func (mr *MockUserManagerMockRecorder) Domains(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Domains", reflect.TypeOf((*MockUserManager)(nil).Domains), ctx)
}

// RoleExists mocks base method.
func (m *MockUserManager) RoleExists(ctx context.Context, role access.Role, domain access.Domain) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleExists", ctx, role, domain)
	ret0, _ := ret[0].(bool)
	return ret0
}

// RoleExists indicates an expected call of RoleExists.
func (mr *MockUserManagerMockRecorder) RoleExists(ctx, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleExists", reflect.TypeOf((*MockUserManager)(nil).RoleExists), ctx, role, domain)
}

// RolePermissions mocks base method.
func (m *MockUserManager) RolePermissions(ctx context.Context, role access.Role, domain access.Domain) ([]access.Permission, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RolePermissions", ctx, role, domain)
	ret0, _ := ret[0].([]access.Permission)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RolePermissions indicates an expected call of RolePermissions.
func (mr *MockUserManagerMockRecorder) RolePermissions(ctx, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RolePermissions", reflect.TypeOf((*MockUserManager)(nil).RolePermissions), ctx, role, domain)
}

// RoleUsers mocks base method.
func (m *MockUserManager) RoleUsers(ctx context.Context, role access.Role, domain access.Domain) ([]access.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleUsers", ctx, role, domain)
	ret0, _ := ret[0].([]access.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RoleUsers indicates an expected call of RoleUsers.
func (mr *MockUserManagerMockRecorder) RoleUsers(ctx, role, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleUsers", reflect.TypeOf((*MockUserManager)(nil).RoleUsers), ctx, role, domain)
}

// Roles mocks base method.
func (m *MockUserManager) Roles(ctx context.Context, domain access.Domain) ([]access.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Roles", ctx, domain)
	ret0, _ := ret[0].([]access.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Roles indicates an expected call of Roles.
func (mr *MockUserManagerMockRecorder) Roles(ctx, domain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Roles", reflect.TypeOf((*MockUserManager)(nil).Roles), ctx, domain)
}

// User mocks base method.
func (m *MockUserManager) User(ctx context.Context, username access.User, domain ...access.Domain) (*access.UserAccess, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, username}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "User", varargs...)
	ret0, _ := ret[0].(*access.UserAccess)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// User indicates an expected call of User.
func (mr *MockUserManagerMockRecorder) User(ctx, username any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, username}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "User", reflect.TypeOf((*MockUserManager)(nil).User), varargs...)
}

// UserPermissions mocks base method.
func (m *MockUserManager) UserPermissions(ctx context.Context, username access.User, domain ...access.Domain) (map[access.Domain][]access.Permission, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, username}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserPermissions", varargs...)
	ret0, _ := ret[0].(map[access.Domain][]access.Permission)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserPermissions indicates an expected call of UserPermissions.
func (mr *MockUserManagerMockRecorder) UserPermissions(ctx, username any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, username}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserPermissions", reflect.TypeOf((*MockUserManager)(nil).UserPermissions), varargs...)
}

// UserRoles mocks base method.
func (m *MockUserManager) UserRoles(ctx context.Context, username access.User, domain ...access.Domain) (map[access.Domain][]access.Role, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, username}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UserRoles", varargs...)
	ret0, _ := ret[0].(map[access.Domain][]access.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserRoles indicates an expected call of UserRoles.
func (mr *MockUserManagerMockRecorder) UserRoles(ctx, username any, domain ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, username}, domain...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserRoles", reflect.TypeOf((*MockUserManager)(nil).UserRoles), varargs...)
}

// Users mocks base method.
func (m *MockUserManager) Users(ctx context.Context, domain ...access.Domain) ([]*access.UserAccess, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range domain {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Users", varargs...)
	ret0, _ := ret[0].([]*access.UserAccess)
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
