package access

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/ccc/accesstypes"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
)

var _ Store = &SpannerStore{}

// SpannerStore implements the Store interface for Google Cloud Spanner.
type SpannerStore struct {
	client *spanner.Client
}

// NewSpannerStore creates a new SpannerStore.
func NewSpannerStore(client *spanner.Client) *SpannerStore {
	return &SpannerStore{client: client}
}

// Users
func (s *SpannerStore) CreateUser(ctx context.Context, user *accesstypes.User) error {
	m := spanner.Insert("Users", []string{"Name"}, []interface{}{user.Marshal()})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

func (s *SpannerStore) UserByName(ctx context.Context, name string) (*accesstypes.User, error) {
	row, err := s.client.Single().ReadRow(ctx, "Users", spanner.Key{name}, []string{"Name"})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, nil // Or a specific not found error
		}
		return nil, err
	}
	var userName string
	if err := row.Column(0, &userName); err != nil {
		return nil, err
	}
	user := accesstypes.User(userName)
	return &user, nil
}

func (s *SpannerStore) DeleteUser(ctx context.Context, name string) error {
	m := spanner.Delete("Users", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Roles
func (s *SpannerStore) CreateRole(ctx context.Context, role *accesstypes.Role) error {
	m := spanner.Insert("Roles", []string{"Name"}, []interface{}{role.Marshal()})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

func (s *SpannerStore) RoleByName(ctx context.Context, name string) (*accesstypes.Role, error) {
	row, err := s.client.Single().ReadRow(ctx, "Roles", spanner.Key{name}, []string{"Name"})
	if err != nil {
		if spanner.ErrCode(err) == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	var roleName string
	if err := row.Column(0, &roleName); err != nil {
		return nil, err
	}
	role := accesstypes.Role(roleName)
	return &role, nil
}

func (s *SpannerStore) DeleteRole(ctx context.Context, name string) error {
	m := spanner.Delete("Roles", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Permissions
func (s *SpannerStore) CreatePermission(ctx context.Context, permission *accesstypes.Permission) error {
	m := spanner.Insert("Permissions", []string{"Name"}, []interface{}{permission.Marshal()})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

func (s *SpannerStore) PermissionByName(ctx context.Context, name string) (*accesstypes.Permission, error) {
	// ... implementation similar to UserByName/RoleByName
	return nil, nil
}

func (s *SpannerStore) DeletePermission(ctx context.Context, name string) error {
	// ... implementation similar to DeleteUser/DeleteRole
	return nil
}

// Resources
func (s *SpannerStore) CreateResource(ctx context.Context, resource *accesstypes.Resource) error {
	m := spanner.Insert("Resources", []string{"Name"}, []interface{}{resource.Marshal()})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

func (s *SpannerStore) ResourceByName(ctx context.Context, name string) (*accesstypes.Resource, error) {
	// ... implementation similar to UserByName/RoleByName
	return nil, nil
}

func (s *SpannerStore) DeleteResource(ctx context.Context, name string) error {
	// ... implementation similar to DeleteUser/DeleteRole
	return nil
}

// Mappings
func (s *SpannerStore) CreateUserRoleMap(ctx context.Context, userID, roleID int64, domain string) error {
	m := spanner.Insert("UserRoleMaps", []string{"UserId", "RoleId", "Domain"}, []interface{}{userID, roleID, domain})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

func (s *SpannerStore) CreatePermissionResourceMap(ctx context.Context, permissionID, resourceID int64) error {
	m := spanner.Insert("PermissionResourceMaps", []string{"PermissionId", "ResourceId"}, []interface{}{permissionID, resourceID})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err.Error
}

func (s *SpannerStore) CreateRoleMap(ctx context.Context, roleID, permResID int64) error {
	m := spanner.Insert("RoleMaps", []string{"RoleId", "PermResId"}, []interface{}{roleID, permResID})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Conditions
func (s *SpannerStore) CreateCondition(ctx context.Context, roleMapID int64, condition string) error {
	m := spanner.Insert("Conditions", []string{"RoleMapId", "Condition"}, []interface{}{roleMapID, condition})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Query
func (s *SpannerStore) CheckPermission(ctx context.Context, user, domain, resource, permission string) (bool, string, error) {
	stmt := spanner.NewStatement(`
        SELECT
            rm.Id, c.Condition
        FROM Users u
        JOIN UserRoleMaps ur ON ur.UserId = u.Id
        JOIN Roles r ON r.Id = ur.RoleId
        JOIN RoleMaps rm ON rm.RoleId = r.Id
        JOIN PermissionResourceMaps prm ON prm.Id = rm.PermResId
        JOIN Resources res ON res.Id = prm.ResId
        JOIN Permissions p ON p.Id = prm.PermId
        LEFT JOIN Conditions c ON c.RoleMapId = rm.Id
        WHERE u.Name = @user AND
            ur.Domain = @domain AND
            res.Name = @resource AND
            p.Name = @permission
    `)
	stmt.Params["user"] = user
	stmt.Params["domain"] = domain
	stmt.Params["resource"] = resource
	stmt.Params["permission"] = permission

	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	var roleMapID int64
	var condition spanner.NullString
	if err := row.Columns(&roleMapID, &condition); err != nil {
		return false, "", err
	}

	return true, condition.StringValue, nil
}
