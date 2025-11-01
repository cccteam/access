package access

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
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
func (s *SpannerStore) CreateUser(ctx context.Context, user *User) (int64, error) {
	user.ID = int64(uuid.New().ID())
	m := spanner.Insert("Users", []string{"Id", "Name"}, []interface{}{user.ID, user.Name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return user.ID, err
}

func (s *SpannerStore) UserByName(ctx context.Context, name string) (*User, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Users WHERE Name = @name")
	stmt.Params["name"] = name
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var user User
	if err := row.ToStruct(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *SpannerStore) DeleteUser(ctx context.Context, name string) error {
	m := spanner.Delete("Users", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Roles
func (s *SpannerStore) CreateRole(ctx context.Context, role *Role) (int64, error) {
	role.ID = int64(uuid.New().ID())
	m := spanner.Insert("Roles", []string{"Id", "Name"}, []interface{}{role.ID, role.Name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return role.ID, err
}

func (s *SpannerStore) RoleByName(ctx context.Context, name string) (*Role, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Roles WHERE Name = @name")
	stmt.Params["name"] = name
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var role Role
	if err := row.ToStruct(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (s *SpannerStore) DeleteRole(ctx context.Context, name string) error {
	m := spanner.Delete("Roles", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Permissions
func (s *SpannerStore) CreatePermission(ctx context.Context, permission *Permission) (int64, error) {
	permission.ID = int64(uuid.New().ID())
	m := spanner.Insert("Permissions", []string{"Id", "Name"}, []interface{}{permission.ID, permission.Name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return permission.ID, err
}

func (s *SpannerStore) PermissionByName(ctx context.Context, name string) (*Permission, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Permissions WHERE Name = @name")
	stmt.Params["name"] = name
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var perm Permission
	if err := row.ToStruct(&perm); err != nil {
		return nil, err
	}

	return &perm, nil
}

func (s *SpannerStore) DeletePermission(ctx context.Context, name string) error {
	m := spanner.Delete("Permissions", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Resources
func (s *SpannerStore) CreateResource(ctx context.Context, resource *Resource) (int64, error) {
	resource.ID = int64(uuid.New().ID())
	m := spanner.Insert("Resources", []string{"Id", "Name"}, []interface{}{resource.ID, resource.Name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return resource.ID, err
}

func (s *SpannerStore) ResourceByName(ctx context.Context, name string) (*Resource, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Resources WHERE Name = @name")
	stmt.Params["name"] = name
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var res Resource
	if err := row.ToStruct(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (s *SpannerStore) DeleteResource(ctx context.Context, name string) error {
	m := spanner.Delete("Resources", spanner.Key{name})
	_, err := s.client.Apply(ctx, []*spanner.Mutation{m})
	return err
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
	return err
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

	return true, condition.String(), nil
}
