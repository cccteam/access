# access

Go library for role-based access control (RBAC) with domain-specific permission management. Built on [Casbin](https://casbin.org/).

## Overview

Manages user permissions and roles across multiple domains or tenants. Supports PostgreSQL and Google Cloud Spanner as persistence backends.

## Features

- Role-based access control (RBAC)
- Multi-domain/tenant support with global domain option
- Resource-specific permissions
- User, role, and permission management APIs
- HTTP handlers for REST endpoints
- Role migration and bootstrapping

## Installation

```bash
go get github.com/cccteam/access
```

## Core Concepts

- **Domain**: Tenant or organizational unit for permission isolation
- **User**: Individual with assigned roles
- **Role**: Named collection of permissions
- **Permission**: Action that can be performed (create, read, update, delete)
- **Resource**: Object or entity that permissions apply to

## Database Adapters

### PostgreSQL

```go
connConfig, _ := pgx.ParseConfig("postgresql://user:pass@localhost/db")
adapter := access.NewPostgresAdapter(connConfig, "database_name", "casbin_rule")
```

### Google Cloud Spanner

```go
adapter := access.NewSpannerAdapter("projects/myproject/instances/myinstance/databases/mydb", "casbin_rule")
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/cccteam/access"
    "github.com/cccteam/ccc/accesstypes"
    "github.com/jackc/pgx/v5"
)

func main() {
    // Configure PostgreSQL connection
    connConfig, _ := pgx.ParseConfig("postgresql://user:pass@localhost/db")
    
    // Create adapters and domains implementation
    adapter := access.NewPostgresAdapter(connConfig, "mydb", "casbin_rule")
    domains := &MyDomainsImpl{} // Implement the Domains interface
    
    client, err := access.New(domains, adapter)
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    mgr := client.UserManager()
    
    // Create role and grant permissions
    mgr.AddRole(ctx, "tenant1", "admin")
    mgr.AddRolePermissions(ctx, "tenant1", "admin", "create", "read", "update", "delete")
    
    // Assign role to user
    mgr.AddUserRoles(ctx, "tenant1", "john.doe", "admin")
    
    // Check permissions
    err = client.RequireAll(ctx, "john.doe", "tenant1", "read", "write")
}
```

### Implementing Domains Interface

Implement the `Domains` interface for domain validation:

```go
type MyDomainsImpl struct {}

func (d *MyDomainsImpl) DomainIDs(ctx context.Context) ([]string, error) {
    return []string{"tenant1", "tenant2", "tenant3"}, nil
}

func (d *MyDomainsImpl) DomainExists(ctx context.Context, domainID string) (bool, error) {
    // Check domain existence in your system
    return true, nil
}
```

## API Usage

### Permission Checking

```go
// Check all permissions
err := client.RequireAll(ctx, user, domain, "read", "write", "delete")

// Check resource-specific permissions
ok, missing, err := client.RequireResources(ctx, user, domain, "read", "resource1", "resource2")
```

### User Management

```go
mgr := client.UserManager()

userAccess, err := mgr.User(ctx, "john.doe", "tenant1")
allUsers, err := mgr.Users(ctx, "tenant1")
roles, err := mgr.UserRoles(ctx, "john.doe", "tenant1")
permissions, err := mgr.UserPermissions(ctx, "john.doe", "tenant1")

mgr.AddUserRoles(ctx, "tenant1", "john.doe", "admin", "editor")
mgr.DeleteUserRoles(ctx, "tenant1", "john.doe", "editor")
```

### Role Management

```go
mgr.AddRole(ctx, "tenant1", "moderator")
deleted, err := mgr.DeleteRole(ctx, "tenant1", "moderator")

roles, err := mgr.Roles(ctx, "tenant1")
exists := mgr.RoleExists(ctx, "tenant1", "admin")

users, err := mgr.RoleUsers(ctx, "tenant1", "admin")
mgr.AddRoleUsers(ctx, "tenant1", "admin", "user1", "user2")
mgr.DeleteRoleUsers(ctx, "tenant1", "admin", "user1")
```

### Permission Management

```go
// Domain-specific permissions
mgr.AddRolePermissions(ctx, "tenant1", "admin", "create", "delete")
mgr.DeleteRolePermissions(ctx, "tenant1", "admin", "delete")
mgr.DeleteAllRolePermissions(ctx, "tenant1", "admin")

// Resource-specific permissions
mgr.AddRolePermissionResources(ctx, "tenant1", "editor", "read", "document1", "document2")
mgr.DeleteRolePermissionResources(ctx, "tenant1", "editor", "read", "document1")

permissions, err := mgr.RolePermissions(ctx, "tenant1", "admin")
```

## HTTP Handlers

```go
import "github.com/go-playground/validator/v10"

validate := validator.New()
logHandler := func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := handler(w, r); err != nil {
            // Handle error
        }
    }
}

handlers := client.Handlers(validate, logHandler)

http.HandleFunc("/roles", handlers.Roles())
http.HandleFunc("/roles/add", handlers.AddRole())
http.HandleFunc("/users", handlers.Users())
http.HandleFunc("/user", handlers.User())
```

## Role Migration

`MigrateRoles` automates role and permission setup across all domains. Use for initial setup, deployment automation, and permission updates.

### Usage

```go
import (
    "context"
    
    "github.com/cccteam/access"
    "github.com/cccteam/ccc/accesstypes"
    "github.com/cccteam/ccc/resource"
)

func migrateRoles(client *access.Client, store *resource.Collection) error {
    ctx := context.Background()
    
    roleConfig := &access.RoleConfig{
        Roles: []*access.Role{
            {
                Name: "Editor",
                Permissions: map[accesstypes.Permission][]accesstypes.Resource{
                    "read":   {"documents", "images", "files"},
                    "create": {"documents", "images"},
                    "update": {"documents", "images"},
                },
            },
            {
                Name: "Viewer",
                Permissions: map[accesstypes.Permission][]accesstypes.Resource{
                    "read": {"documents", "images", "files"},
                },
            },
            {
                Name: "Moderator",
                Permissions: map[accesstypes.Permission][]accesstypes.Resource{
                    "read":   {"documents", "images", "files", "users"},
                    "update": {"documents", "users"},
                    "delete": {"documents"},
                },
            },
        },
    }
    
    return access.MigrateRoles(ctx, client.UserManager(), store, roleConfig)
}
```

### Behavior

- Automatically adds "Administrator" role with all permissions
- Applies roles across all domains (global and domain-specific)
- Creates missing roles and adds missing permissions
- Removes permissions not in configuration
- Removes roles not in configuration
- Validates resources and permissions against resource store
- Prevents update permissions on immutable resources

**Note**: Safe to run multiple times - applies changes only when state differs from configuration. Modifies input config by appending Administrator role.

### JSON Configuration

```json
{
  "roles": [
    {
      "Name": "Editor",
      "Permissions": {
        "read": ["documents", "images"],
        "create": ["documents", "images"],
        "update": ["documents", "images"]
      }
    },
    {
      "Name": "Viewer",
      "Permissions": {
        "read": ["documents", "images"]
      }
    }
  ]
}
```

```go
data, _ := os.ReadFile("roles.json")
var config access.RoleConfig
json.Unmarshal(data, &config)
access.MigrateRoles(ctx, client.UserManager(), store, &config)
```

## License

See LICENSE file.

---

Created and maintained by the CCC team.
