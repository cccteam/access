package access

import (
	"context"
	reflect "reflect"

	"github.com/cccteam/ccc/accesstypes"
	"go.uber.org/mock/gomock"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// CreateUser mocks base method.
func (m *MockStore) CreateUser(ctx context.Context, user *accesstypes.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockStoreMockRecorder) CreateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockStore)(nil).CreateUser), ctx, user)
}

// UserByName mocks base method.
func (m *MockStore) UserByName(ctx context.Context, name string) (*accesstypes.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserByName", ctx, name)
	ret0, _ := ret[0].(*accesstypes.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UserByName indicates an expected call of UserByName.
func (mr *MockStoreMockRecorder) UserByName(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserByName", reflect.TypeOf((*MockStore)(nil).UserByName), ctx, name)
}

// DeleteUser mocks base method.
func (m *MockStore) DeleteUser(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockStoreMockRecorder) DeleteUser(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockStore)(nil).DeleteUser), ctx, name)
}

// CreateRole mocks base method.
func (m *MockStore) CreateRole(ctx context.Context, role *accesstypes.Role) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRole", ctx, role)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRole indicates an expected call of CreateRole.
func (mr *MockStoreMockRecorder) CreateRole(ctx, role interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRole", reflect.TypeOf((*MockStore)(nil).CreateRole), ctx, role)
}

// RoleByName mocks base method.
func (m *MockStore) RoleByName(ctx context.Context, name string) (*accesstypes.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RoleByName", ctx, name)
	ret0, _ := ret[0].(*accesstypes.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RoleByName indicates an expected call of RoleByName.
func (mr *MockStoreMockRecorder) RoleByName(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RoleByName", reflect.TypeOf((*MockStore)(nil).RoleByName), ctx, name)
}

// DeleteRole mocks base method.
func (m *MockStore) DeleteRole(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRole", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRole indicates an expected call of DeleteRole.
func (mr *MockStoreMockRecorder) DeleteRole(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRole", reflect.TypeOf((*MockStore)(nil).DeleteRole), ctx, name)
}

// CreatePermission mocks base method.
func (m *MockStore) CreatePermission(ctx context.Context, permission *accesstypes.Permission) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePermission", ctx, permission)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreatePermission indicates an expected call of CreatePermission.
func (mr *MockStoreMockRecorder) CreatePermission(ctx, permission interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePermission", reflect.TypeOf((*MockStore)(nil).CreatePermission), ctx, permission)
}

// PermissionByName mocks base method.
func (m *MockStore) PermissionByName(ctx context.Context, name string) (*accesstypes.Permission, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PermissionByName", ctx, name)
	ret0, _ := ret[0].(*accesstypes.Permission)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PermissionByName indicates an expected call of PermissionByName.
func (mr *MockStoreMockRecorder) PermissionByName(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PermissionByName", reflect.TypeOf((*MockStore)(nil).PermissionByName), ctx, name)
}

// DeletePermission mocks base method.
func (m *MockStore) DeletePermission(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeletePermission", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeletePermission indicates an expected call of DeletePermission.
func (mr *MockStoreMockRecorder) DeletePermission(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePermission", reflect.TypeOf((*MockStore)(nil).DeletePermission), ctx, name)
}

// CreateResource mocks base method.
func (m *MockStore) CreateResource(ctx context.Context, resource *accesstypes.Resource) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateResource", ctx, resource)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateResource indicates an expected call of CreateResource.
func (mr *MockStoreMockRecorder) CreateResource(ctx, resource interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateResource", reflect.TypeOf((*MockStore)(nil).CreateResource), ctx, resource)
}

// ResourceByName mocks base method.
func (m *MockStore) ResourceByName(ctx context.Context, name string) (*accesstypes.Resource, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResourceByName", ctx, name)
	ret0, _ := ret[0].(*accesstypes.Resource)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResourceByName indicates an expected call of ResourceByName.
func (mr *MockStoreMockRecorder) ResourceByName(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResourceByName", reflect.TypeOf((*MockStore)(nil).ResourceByName), ctx, name)
}

// DeleteResource mocks base method.
func (m *MockStore) DeleteResource(ctx context.Context, name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteResource", ctx, name)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteResource indicates an expected call of DeleteResource.
func (mr *MockStoreMockRecorder) DeleteResource(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteResource", reflect.TypeOf((*MockStore)(nil).DeleteResource), ctx, name)
}

// CreateUserRoleMap mocks base method.
func (m *MockStore) CreateUserRoleMap(ctx context.Context, userID, roleID int64, domain string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUserRoleMap", ctx, userID, roleID, domain)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateUserRoleMap indicates an expected call of CreateUserRoleMap.
func (mr *MockStoreMockRecorder) CreateUserRoleMap(ctx, userID, roleID, domain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUserRoleMap", reflect.TypeOf((*MockStore)(nil).CreateUserRoleMap), ctx, userID, roleID, domain)
}

// CreatePermissionResourceMap mocks base method.
func (m *MockStore) CreatePermissionResourceMap(ctx context.Context, permissionID, resourceID int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePermissionResourceMap", ctx, permissionID, resourceID)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreatePermissionResourceMap indicates an expected call of CreatePermissionResourceMap.
func (mr *MockStoreMockRecorder) CreatePermissionResourceMap(ctx, permissionID, resourceID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePermissionResourceMap", reflect.TypeOf((*MockStore)(nil).CreatePermissionResourceMap), ctx, permissionID, resourceID)
}

// CreateRoleMap mocks base method.
func (m *MockStore) CreateRoleMap(ctx context.Context, roleID, permResID int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRoleMap", ctx, roleID, permResID)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRoleMap indicates an expected call of CreateRoleMap.
func (mr *MockStoreMockRecorder) CreateRoleMap(ctx, roleID, permResID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRoleMap", reflect.TypeOf((*MockStore)(nil).CreateRoleMap), ctx, roleID, permResID)
}

// CreateCondition mocks base method.
func (m *MockStore) CreateCondition(ctx context.Context, roleMapID int64, condition string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateCondition", ctx, roleMapID, condition)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateCondition indicates an expected call of CreateCondition.
func (mr *MockStoreMockRecorder) CreateCondition(ctx, roleMapID, condition interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateCondition", reflect.TypeOf((*MockStore)(nil).CreateCondition), ctx, roleMapID, condition)
}

// CheckPermission mocks base method.
func (m *MockStore) CheckPermission(ctx context.Context, user, domain, resource, permission string) (bool, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckPermission", ctx, user, domain, resource, permission)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CheckPermission indicates an expected call of CheckPermission.
func (mr *MockStoreMockRecorder) CheckPermission(ctx, user, domain, resource, permission interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckPermission", reflect.TypeOf((*MockStore)(nil).CheckPermission), ctx, user, domain, resource, permission)
}
