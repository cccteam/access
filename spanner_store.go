package access

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/cccteam/access/store"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/go-playground/errors/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

var _ Access = &SpannerStore{}

// SpannerStore implements the UserManager interface for Google Cloud Spanner.
type SpannerStore struct {
	client  *spanner.Client
	domains Domains
}

// NewSpannerStore creates a new SpannerStore.
func NewSpannerStore(client *spanner.Client, domains Domains) *SpannerStore {
	return &SpannerStore{client: client, domains: domains}
}

func (s *SpannerStore) AddRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		for _, user := range users {
			dbUser, err := s.userByName(ctx, txn, user.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.UserByName()")
			}
			if dbUser == nil {
				// Create the user if they don't exist.
				if err := s.createUser(ctx, txn, user.Marshal()); err != nil {
					return errors.Wrap(err, "store.CreateUser()")
				}
				dbUser, err = s.userByName(ctx, txn, user.Marshal())
				if err != nil {
					return errors.Wrap(err, "store.UserByName()")
				}
			}
			if err := s.createUserRoleMap(ctx, txn, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
				return errors.Wrap(err, "store.CreateUserRoleMap()")
			}
		}
		return nil
	})
	return err
}

// Private methods for database operations within a transaction
func (s *SpannerStore) userByName(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) (*store.User, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Users WHERE Name = @name")
	stmt.Params["name"] = name
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var user store.User
	if err := row.ToStruct(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *SpannerStore) createUser(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) error {
	m := spanner.Insert("Users", []string{"Name"}, []interface{}{name})
	return txn.BufferWrite([]*spanner.Mutation{m})
}

func (s *SpannerStore) roleByName(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) (*store.Role, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Roles WHERE Name = @name")
	stmt.Params["name"] = name
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var role store.Role
	if err := row.ToStruct(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (s *SpannerStore) createUserRoleMap(ctx context.Context, txn *spanner.ReadWriteTransaction, userID, roleID int64, domain string) error {
	m := spanner.Insert("UserRoleMaps", []string{"UserId", "RoleId", "Domain"}, []interface{}{userID, roleID, domain})
	return txn.BufferWrite([]*spanner.Mutation{m})
}

func (s *SpannerStore) AddUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbUser, err := s.userByName(ctx, txn, user.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.UserByName()")
		}
		if dbUser == nil {
			// Create the user if they don't exist.
			if err := s.createUser(ctx, txn, user.Marshal()); err != nil {
				return errors.Wrap(err, "store.CreateUser()")
			}
			dbUser, err = s.userByName(ctx, txn, user.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.UserByName()")
			}
		}

		for _, role := range roles {
			dbRole, err := s.roleByName(ctx, txn, role.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.RoleByName()")
			}
			if dbRole == nil {
				return errors.New("role not found")
			}
			if err := s.createUserRoleMap(ctx, txn, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
				return errors.Wrap(err, "store.CreateUserRoleMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) DeleteRoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, users ...accesstypes.User) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		for _, user := range users {
			dbUser, err := s.userByName(ctx, txn, user.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.UserByName()")
			}
			if dbUser == nil {
				return errors.New("user not found")
			}
			if err := s.deleteUserRoleMap(ctx, txn, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
				return errors.Wrap(err, "store.DeleteUserRoleMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) DeleteUserRoles(ctx context.Context, domain accesstypes.Domain, user accesstypes.User, roles ...accesstypes.Role) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbUser, err := s.userByName(ctx, txn, user.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.UserByName()")
		}
		if dbUser == nil {
			return errors.New("user not found")
		}

		for _, role := range roles {
			dbRole, err := s.roleByName(ctx, txn, role.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.RoleByName()")
			}
			if dbRole == nil {
				return errors.New("role not found")
			}
			if err := s.deleteUserRoleMap(ctx, txn, dbUser.ID, dbRole.ID, domain.Marshal()); err != nil {
				return errors.Wrap(err, "store.DeleteUserRoleMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) deleteUserRoleMap(ctx context.Context, txn *spanner.ReadWriteTransaction, userID, roleID int64, domain string) error {
	m := spanner.Delete("UserRoleMaps", spanner.Key{userID, roleID, domain})
	return txn.BufferWrite([]*spanner.Mutation{m})
}

func (s *SpannerStore) User(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (*UserAccess, error) {
	if domain == nil {
		var err error
		domain, err = s.Domains(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Guarantor IDs")
		}
	}

	return s.user(ctx, user, domain)
}

func (s *SpannerStore) user(ctx context.Context, user accesstypes.User, domains []accesstypes.Domain) (*UserAccess, error) {
	roles, err := s.UserRoles(ctx, user, domains...)
	if err != nil {
		return nil, err
	}

	permissions, err := s.UserPermissions(ctx, user, domains...)
	if err != nil {
		return nil, err
	}

	return &UserAccess{
		Name:        string(user),
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

func (s *SpannerStore) Users(ctx context.Context, domain ...accesstypes.Domain) ([]*UserAccess, error) {
	stmt := spanner.NewStatement("SELECT Name FROM Users")
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	var users []*UserAccess
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var userName string
		if err := row.Column(0, &userName); err != nil {
			return nil, err
		}

		user, err := s.user(ctx, accesstypes.User(userName), domain)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (s *SpannerStore) UserRoles(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.RoleCollection, error) {
	userRoles := make(accesstypes.RoleCollection)
	for _, d := range domain {
		stmt := spanner.NewStatement(`
			SELECT r.Name
			FROM Roles r
			JOIN UserRoleMaps ur ON ur.RoleId = r.Id
			JOIN Users u ON u.Id = ur.UserId
			WHERE u.Name = @userName AND ur.Domain = @domain
		`)
		stmt.Params["userName"] = user.Marshal()
		stmt.Params["domain"] = d.Marshal()

		iter := s.client.Single().Query(ctx, stmt)
		defer iter.Stop()

		var roles []accesstypes.Role
		for {
			row, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			var roleName string
			if err := row.Column(0, &roleName); err != nil {
				return nil, err
			}
			roles = append(roles, accesstypes.Role(roleName))
		}
		userRoles[d] = roles
	}

	return userRoles, nil
}

func (s *SpannerStore) UserPermissions(ctx context.Context, user accesstypes.User, domain ...accesstypes.Domain) (accesstypes.UserPermissionCollection, error) {
	userPermissions := make(accesstypes.UserPermissionCollection)
	for _, d := range domain {
		stmt := spanner.NewStatement(`
			SELECT p.Name, r.Name
			FROM Permissions p
			JOIN PermissionResourceMaps prm ON prm.PermissionId = p.Id
			JOIN Resources r ON r.Id = prm.ResourceId
			JOIN RolePermissionResourceMaps rprm ON rprm.PermissionResourceMapId = prm.Id
			JOIN UserRoleMaps ur ON ur.RoleId = rprm.RoleId
			JOIN Users u ON u.Id = ur.UserId
			WHERE u.Name = @userName AND ur.Domain = @domain
		`)
		stmt.Params["userName"] = user.Marshal()
		stmt.Params["domain"] = d.Marshal()

		iter := s.client.Single().Query(ctx, stmt)
		defer iter.Stop()

		permissions := make(map[accesstypes.Resource][]accesstypes.Permission)
		for {
			row, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			var permName, resName string
			if err := row.Columns(&permName, &resName); err != nil {
				return nil, err
			}
			permissions[accesstypes.Resource(resName)] = append(permissions[accesstypes.Resource(resName)], accesstypes.Permission(permName))
		}
		userPermissions[d] = permissions
	}

	return userPermissions, nil
}

func (s *SpannerStore) AddRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		exists, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return err
		}
		if exists != nil {
			return errors.New("role already exists")
		}
		return s.createRole(ctx, txn, role.Marshal())
	})
	return err
}

func (s *SpannerStore) createRole(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) error {
	m := spanner.Insert("Roles", []string{"Name"}, []interface{}{name})
	return txn.BufferWrite([]*spanner.Mutation{m})
}

func (s *SpannerStore) RoleExists(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) bool {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		role, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return err
		}
		if role == nil {
			return errors.New("role not found")
		}
		return nil
	})
	return err == nil
}

func (s *SpannerStore) Roles(ctx context.Context, domain accesstypes.Domain) ([]accesstypes.Role, error) {
	stmt := spanner.NewStatement("SELECT Name FROM Roles")
	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	var roles []accesstypes.Role
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var roleName string
		if err := row.Column(0, &roleName); err != nil {
			return nil, err
		}
		roles = append(roles, accesstypes.Role(roleName))
	}

	return roles, nil
}

func (s *SpannerStore) DeleteRole(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (bool, error) {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return err
		}
		if dbRole == nil {
			return errors.New("role not found")
		}
		return s.deleteRole(ctx, txn, dbRole.ID)
	})
	return err == nil, err
}

func (s *SpannerStore) deleteRole(ctx context.Context, txn *spanner.ReadWriteTransaction, roleID int64) error {
	m := spanner.Delete("Roles", spanner.Key{roleID})
	return txn.BufferWrite([]*spanner.Mutation{m})
}

func (s *SpannerStore) AddRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		for _, p := range permissions {
			dbPerm, err := s.permissionByName(ctx, txn, p.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.PermissionByName()")
			}
			if dbPerm == nil {
				return errors.New("permission not found")
			}

			permResID, err := s.createPermissionResourceMap(ctx, txn, dbPerm.ID, 0)
			if err != nil {
				return errors.Wrap(err, "store.CreatePermissionResourceMap()")
			}

			if _, err := s.createRoleMap(ctx, txn, dbRole.ID, permResID); err != nil {
				return errors.Wrap(err, "store.CreateRoleMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) AddRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		dbPerm, err := s.permissionByName(ctx, txn, permission.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.PermissionByName()")
		}
		if dbPerm == nil {
			return errors.New("permission not found")
		}

		for _, r := range resources {
			dbRes, err := s.resourceByName(ctx, txn, r.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.ResourceByName()")
			}
			if dbRes == nil {
				return errors.New("resource not found")
			}

			permResID, err := s.createPermissionResourceMap(ctx, txn, dbPerm.ID, dbRes.ID)
			if err != nil {
				return errors.Wrap(err, "store.CreatePermissionResourceMap()")
			}

			if _, err := s.createRoleMap(ctx, txn, dbRole.ID, permResID); err != nil {
				return errors.Wrap(err, "store.CreateRoleMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) permissionByName(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) (*store.Permission, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Permissions WHERE Name = @name")
	stmt.Params["name"] = name
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var perm store.Permission
	if err := row.ToStruct(&perm); err != nil {
		return nil, err
	}

	return &perm, nil
}

func (s *SpannerStore) resourceByName(ctx context.Context, txn *spanner.ReadWriteTransaction, name string) (*store.Resource, error) {
	stmt := spanner.NewStatement("SELECT Id, Name FROM Resources WHERE Name = @name")
	stmt.Params["name"] = name
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var res store.Resource
	if err := row.ToStruct(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (s *SpannerStore) createPermissionResourceMap(ctx context.Context, txn *spanner.ReadWriteTransaction, permissionID, resourceID int64) (int64, error) {
	var id int64
	stmt := spanner.NewStatement("SELECT Id FROM PermissionResourceMaps WHERE PermissionId = @permissionId AND ResourceId = @resourceId")
	stmt.Params["permissionId"] = permissionID
	stmt.Params["resourceId"] = resourceID
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		id = int64(uuid.New().ID())
		m := spanner.Insert("PermissionResourceMaps", []string{"Id", "PermissionId", "ResourceId"}, []interface{}{id, permissionID, resourceID})
		if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return 0, err
		}
		return id, nil
	}
	if err != nil {
		return 0, err
	}

	if err := row.Column(0, &id); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SpannerStore) createRoleMap(ctx context.Context, txn *spanner.ReadWriteTransaction, roleID, permResID int64) (int64, error) {
	var id int64
	stmt := spanner.NewStatement("SELECT Id FROM RolePermissionResourceMaps WHERE RoleId = @roleId AND PermissionResourceMapId = @permResId")
	stmt.Params["roleId"] = roleID
	stmt.Params["permResId"] = permResID
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		id = int64(uuid.New().ID())
		m := spanner.Insert("RolePermissionResourceMaps", []string{"Id", "RoleId", "PermissionResourceMapId"}, []interface{}{id, roleID, permResID})
		if err := txn.BufferWrite([]*spanner.Mutation{m}); err != nil {
			return 0, err
		}
		return id, nil
	}
	if err != nil {
		return 0, err
	}

	if err := row.Column(0, &id); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SpannerStore) DeleteRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permissions ...accesstypes.Permission) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		for _, p := range permissions {
			dbPerm, err := s.permissionByName(ctx, txn, p.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.PermissionByName()")
			}
			if dbPerm == nil {
				return errors.New("permission not found")
			}

			permResID, err := s.createPermissionResourceMap(ctx, txn, dbPerm.ID, 0)
			if err != nil {
				return errors.Wrap(err, "store.CreatePermissionResourceMap()")
			}

			if err := s.deleteRolePermissionMap(ctx, txn, dbRole.ID, permResID); err != nil {
				return errors.Wrap(err, "store.DeleteRolePermissionMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) DeleteRolePermissionResources(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role, permission accesstypes.Permission, resources ...accesstypes.Resource) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		dbPerm, err := s.permissionByName(ctx, txn, permission.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.PermissionByName()")
		}
		if dbPerm == nil {
			return errors.New("permission not found")
		}

		for _, r := range resources {
			dbRes, err := s.resourceByName(ctx, txn, r.Marshal())
			if err != nil {
				return errors.Wrap(err, "store.ResourceByName()")
			}
			if dbRes == nil {
				return errors.New("resource not found")
			}

			permResID, err := s.createPermissionResourceMap(ctx, txn, dbPerm.ID, dbRes.ID)
			if err != nil {
				return errors.Wrap(err, "store.CreatePermissionResourceMap()")
			}

			if err := s.deleteRolePermissionMap(ctx, txn, dbRole.ID, permResID); err != nil {
				return errors.Wrap(err, "store.DeleteRolePermissionMap()")
			}
		}
		return nil
	})
	return err
}

func (s *SpannerStore) deleteRolePermissionMap(ctx context.Context, txn *spanner.ReadWriteTransaction, roleID, permResID int64) error {
	stmt := spanner.NewStatement("SELECT Id FROM RolePermissionResourceMaps WHERE RoleId = @roleId AND PermissionResourceMapId = @permResId")
	stmt.Params["roleId"] = roleID
	stmt.Params["permResId"] = permResID
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	var mutations []*spanner.Mutation
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var id int64
		if err := row.Column(0, &id); err != nil {
			return err
		}
		mutations = append(mutations, spanner.Delete("RolePermissionResourceMaps", spanner.Key{id}))
	}

	if len(mutations) > 0 {
		return txn.BufferWrite(mutations)
	}

	return nil
}

func (s *SpannerStore) DeleteAllRolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) error {
	_, err := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		dbRole, err := s.roleByName(ctx, txn, role.Marshal())
		if err != nil {
			return errors.Wrap(err, "store.RoleByName()")
		}
		if dbRole == nil {
			return errors.New("role not found")
		}

		stmt := spanner.NewStatement("SELECT Id FROM RolePermissionResourceMaps WHERE RoleId = @roleId")
		stmt.Params["roleId"] = dbRole.ID
		iter := txn.Query(ctx, stmt)
		defer iter.Stop()

		var mutations []*spanner.Mutation
		for {
			row, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			var id int64
			if err := row.Column(0, &id); err != nil {
				return err
			}
			mutations = append(mutations, spanner.Delete("RolePermissionResourceMaps", spanner.Key{id}))
		}

		if len(mutations) > 0 {
			return txn.BufferWrite(mutations)
		}

		return nil
	})
	return err
}

func (s *SpannerStore) RoleUsers(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) ([]accesstypes.User, error) {
	stmt := spanner.NewStatement(`
		SELECT u.Name
		FROM Users u
		JOIN UserRoleMaps ur ON ur.UserId = u.Id
		JOIN Roles r ON r.Id = ur.RoleId
		WHERE r.Name = @roleName AND ur.Domain = @domain
	`)
	stmt.Params["roleName"] = role.Marshal()
	stmt.Params["domain"] = domain.Marshal()

	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	var users []accesstypes.User
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var userName string
		if err := row.Column(0, &userName); err != nil {
			return nil, err
		}
		users = append(users, accesstypes.User(userName))
	}

	return users, nil
}

func (s *SpannerStore) RolePermissions(ctx context.Context, domain accesstypes.Domain, role accesstypes.Role) (accesstypes.RolePermissionCollection, error) {
	stmt := spanner.NewStatement(`
		SELECT p.Name, r.Name
		FROM Permissions p
		JOIN PermissionResourceMaps prm ON prm.PermissionId = p.Id
		JOIN Resources r ON r.Id = prm.ResourceId
		JOIN RolePermissionResourceMaps rprm ON rprm.PermissionResourceMapId = prm.Id
		JOIN Roles ro ON ro.Id = rprm.RoleId
		WHERE ro.Name = @roleName
	`)
	stmt.Params["roleName"] = role.Marshal()

	iter := s.client.Single().Query(ctx, stmt)
	defer iter.Stop()

	permissions := make(accesstypes.RolePermissionCollection)
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var permName, resName string
		if err := row.Columns(&permName, &resName); err != nil {
			return nil, err
		}
		permissions[accesstypes.Permission(permName)] = append(permissions[accesstypes.Permission(permName)], accesstypes.Resource(resName))
	}

	return permissions, nil
}

func (s *SpannerStore) Domains(ctx context.Context) ([]accesstypes.Domain, error) {
	ids, err := s.domains.DomainIDs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "dbx.DB.GuarantorIDs()")
	}

	domains := make([]accesstypes.Domain, 1, len(ids)+1)
	domains[0] = accesstypes.GlobalDomain
	for _, v := range ids {
		domains = append(domains, accesstypes.Domain(v))
	}

	return domains, nil
}

func (s *SpannerStore) DomainExists(ctx context.Context, domain accesstypes.Domain) (bool, error) {
	if domain == accesstypes.GlobalDomain {
		return true, nil
	}
	exists, err := s.domains.DomainExists(ctx, string(domain))
	if err != nil {
		return false, errors.Wrap(err, "dbx.DB.GuarantorExists()")
	}

	return exists, nil
}

func (s *SpannerStore) Handlers(validate *validator.Validate, logHandler LogHandler) Handlers {
	return newHandler(s, validate, logHandler)
}

func (s *SpannerStore) RequireAll(ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perms ...accesstypes.Permission) error {
	for _, perm := range perms {
		authorized, err := s.checkPermission(ctx, username.Marshal(), domain.Marshal(), accesstypes.GlobalResource.Marshal(), perm.Marshal())
		if err != nil {
			return errors.Wrap(err, "checkPermission()")
		}
		if !authorized {
			return errors.New("forbidden")
		}
	}

	return nil
}

func (s *SpannerStore) RequireResources(
	ctx context.Context, username accesstypes.User, domain accesstypes.Domain, perm accesstypes.Permission, resources ...accesstypes.Resource,
) (bool, []accesstypes.Resource, error) {
	missing := make([]accesstypes.Resource, 0)
	for _, resource := range resources {
		authorized, err := s.checkPermission(ctx, username.Marshal(), domain.Marshal(), resource.Marshal(), perm.Marshal())
		if err != nil {
			return false, nil, errors.Wrap(err, "checkPermission()")
		}
		if !authorized {
			missing = append(missing, resource)
		}
	}

	if len(missing) > 0 {
		return false, missing, nil
	}

	return true, nil, nil
}

func (s *SpannerStore) checkPermission(ctx context.Context, user, domain, resource, permission string) (bool, error) {
	stmt := spanner.NewStatement(`
		SELECT
			count(1)
		FROM Users u
		JOIN UserRoleMaps ur ON ur.UserId = u.Id
		JOIN Roles r ON r.Id = ur.RoleId
		JOIN RolePermissionResourceMaps rm ON rm.RoleId = r.Id
		JOIN PermissionResourceMaps prm ON prm.Id = rm.PermissionResourceMapId
		JOIN Resources res ON res.Id = prm.ResourceId
		JOIN Permissions p ON p.Id = prm.PermissionId
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
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var count int64
	if err := row.Column(0, &count); err != nil {
		return false, err
	}

	return count > 0, nil
}
