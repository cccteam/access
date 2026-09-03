# access

Go library for role-based access control (RBAC) with domain-partitioned permission management. Policy lives in typed tables owned by this library; permission checks are answered by an immutable in-memory snapshot compiled from those tables — lock-free, allocation-free, and never touching the database on the request path.

## Overview

Manages user permissions and roles across multiple domains or tenants. Supports PostgreSQL and Google Cloud Spanner as persistence backends through the `postgresstore` and `spannerstore` subpackages.

## Features

- Role-based access control (RBAC)
- Multi-tenant support with a structural global scope
- Resource- and field-level permissions (`employees`, `employees.name`, `employees.*`)
- Compiled in-memory snapshot evaluation with near-realtime change propagation
- User, role, and permission management APIs
- HTTP handlers for REST endpoints
- Role migration and bootstrapping

## Installation

```bash
go get github.com/cccteam/access
```

## Core Concepts

- **Scope**: The partition an operation applies to — the global partition (`accesstypes.GlobalScope()`) or one tenant domain (`accesstypes.DomainScope(domain)`). Global-ness is structural: no domain string means "global", so any tenant name is legal data (a tenant literally named "global" is an ordinary tenant). Scopes are opaque labels to access — the application owns its tenant list, and checks fail closed on unknown tenants.
- **User**: Individual with assigned roles
- **Role**: Named collection of permissions, scoped to a scope — role identity is `(scope, role)`
- **Permission**: Action that can be performed (List, Read, Create, Update, Delete, ...)
- **Resource**: What a permission applies to. A resource name has at most one dot: `employees` is a parent resource, `employees.name` is one field on it, and `employees.*` grants all fields by implication (covering fields that don't exist yet). An endpoint grant (`employees`) gives no field visibility, and field grants don't grant the endpoint — that separation is the point of field-level control.

## Policy Stores

Each store owns three tables named `{Prefix}{Store}{Roles|UserRoles|RoleGrants}` — defaults yield `AccessRoles`, `AccessUserRoles`, `AccessRoleGrants`. Applications with several independent permission stores in one database give each a store name (`WithStore("AdminPortal")` → `AccessAdminPortalRoles`, ...); separate tables make cross-store leakage structurally impossible.

The library never runs DDL — applications own their schema lifecycle. `DDL()` returns the canonical schema rendered with the configured names; copy it into your migration file. The library's own test suites execute exactly these statements, so the shipped DDL is the tested DDL.

### PostgreSQL

```go
import "github.com/cccteam/access/postgresstore"

// Rides the application's existing pgx pool.
store, err := postgresstore.New(pool /* *pgxpool.Pool */)

// Or a named store with a custom prefix:
store, err := postgresstore.New(pool, postgresstore.WithStore("AdminPortal"))

// Schema for your migration file:
for _, stmt := range store.DDL() { ... }
```

### Google Cloud Spanner

```go
import "github.com/cccteam/access/spannerstore"

store, err := spannerstore.New(client /* *spanner.Client */)

// Or a named store:
store, err := spannerstore.New(client, spannerstore.WithStore("AdminPortal"))
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/cccteam/access"
    "github.com/cccteam/access/postgresstore"
    "github.com/jackc/pgx/v5/pgxpool"
)

func main() {
    ctx := context.Background()

    pool, _ := pgxpool.New(ctx, "postgresql://user:pass@localhost/db")

    store, err := postgresstore.New(pool)
    if err != nil {
        log.Fatal(err)
    }

    client, err := access.New(store)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    mgr := client.UserManager()

    tenant1 := accesstypes.DomainScope("tenant1")

    // Create role and grant permissions
    mgr.AddRole(ctx, tenant1, "admin")
    mgr.AddRolePermissionResources(ctx, tenant1, "admin", "Read", "documents", "documents.*")

    // Assign role to user
    mgr.AddUserRoles(ctx, tenant1, "john.doe", "admin")

    // Check permissions: one Decision per resource, from one policy snapshot.
    env := accesstypes.NewEnvironment() // per-request decision context
    decisions, err := client.CheckUserResources(ctx, env, "john.doe", tenant1, "Read", "documents", "documents.title")
    if err != nil {
        log.Fatal(err)
    }
    if denied := decisions.DeniedResources(); len(denied) > 0 {
        // deny: shape your own Forbidden response
    }
}
```

## Policy Snapshot, Freshness, and Lifecycle

Permission checks are served from an immutable in-memory snapshot: lock-free,
allocation-free, and never touching the database on the request path. Policy
changes propagate between instances in near-realtime through a change signal
(recommended — see below), with a background heartbeat as the correctness
backstop: it re-reads the policy store (default every 1m) and swaps in a new
snapshot only when the content changed, so cross-instance staleness is bounded
by the heartbeat interval even if the signal breaks. Writes made through this
client are visible to its own checks immediately.

```go
import "github.com/cccteam/access/postgressignal"

client, err := access.New(store,
    // Recommended: propagate changes between instances in near-realtime.
    // Rides the app's existing pgx pool.
    access.WithChangeSignal(postgressignal.New(pool, "access_policy_changed")),
    // Optional: tune the heartbeat backstop (default 1m).
    access.WithHeartbeatInterval(30*time.Second),
    // Optional: alerting hook for background reload/signal failures. While
    // reloads fail, checks keep serving the last good snapshot.
    access.WithReloadErrorHandler(func(err error) { log.Printf("access: %v", err) }),
)

// Readiness: block until the first policy snapshot has loaded.
if err := client.WaitReady(ctx); err != nil { ... }

// Shutdown: stop background reloading (checks keep serving the last snapshot).
defer client.Close()
```

The push signal is a latency optimization only — correctness never depends on
it. For Spanner environments (no LISTEN/NOTIFY), the `firebasesignal`
subpackage provides the equivalent over a Firestore document watch:

```go
import "github.com/cccteam/access/firebasesignal"

fsClient, _ := firestore.NewClient(ctx, projectID)
signal, err := firebasesignal.New(fsClient, "access/policy")
client, err := access.New(store, access.WithChangeSignal(signal))
```

## API Usage

### Permission Checking

The base name / `Resources` suffix pairing is the API's naming standard: the
base method checks a permission held scope-wide (attached to no resource);
the `Resources` variant checks specific resources.

The checks — for users and for roles alike — are the request-path seams and
are ABAC-ready: they take the per-request decision context
(`accesstypes.Environment`, immediately after `ctx`) and answer with
Decisions (`Denied` / `Granted` / `Conditional`).
`CheckUserResources` returns one Decision per resource, all from a single
policy snapshot; `Decisions.DeniedResources()` lists what was denied — empty
means everything passed. One permission per call; batch as many resources as
you like. `CheckUser` returns the Decision for a permission held scope-wide.
A grant may carry a condition — opaque expression text on its store row
(`Condition`, NULL = unconditional) — and a resource covered only by
conditional grants answers `Conditional`; any unconditional cover answers
`Granted` outright. Grouping is the engine's job: within one
`CheckUserResources` call, a Conditional decision's
`ConditionGroup.Resources` lists every checked resource sharing that
covering-grant set, the same group appearing in each member's Decision —
deduplicate by sorted-Resources equality. Conditions never attach to
scope-wide grants (there is no row for them to see — rejected at snapshot
load; interim — this narrows to row-referencing conditions once the
condition package classifies row-free, with environment/subject-only
conditions folding at check time), so `CheckUser` never answers
`Conditional`. Nothing authors
conditions yet (the expression language is undesigned), so in practice every
Decision is `Granted` or `Denied` and an empty `Environment` is the normal
argument.

The role checks are the same seams evaluated against a role's effective
grants — its own and, transitively, every role it inherits — with no member
involved: `CheckRole` and `CheckRoleResources` answer exactly what
`CheckUser` and `CheckUserResources` answer a user holding only that role.
They serve sessions that operate *as a role* (an administrator working a
partner portal under a role chosen for the session — the session library's
impersonated sessions) as well as policy introspection. A role has no
identity of its own: a `subject` term in a row condition is bound by the
resource layer to the session's effective identity at render time, and a
scope-wide condition that needs a subject is a check error, as it is for a
user. `RoleHasGrants`, `RoleDomains` and `RolePermissionDigest` are the role
twins of the user foothold, tenant-picker and digest questions.

```go
env := accesstypes.NewEnvironment()

decisions, err := client.CheckUserResources(ctx, env, user, scope, "Read", "documents", "documents.title", "images")
decision, err := client.CheckUser(ctx, env, user, scope, "ExportReports") // scope-wide

decisions, err = client.CheckRoleResources(ctx, env, role, scope, "Update", "documents")
decision, err = client.CheckRole(ctx, env, role, scope, "ExportReports")
```

A request binds its principal once: `client.ForUser(user)` returns a
`*UserChecker` and `client.ForRole(role)` a `*RoleChecker`, each carrying
`Check`, `PermissionDigest` and `Domains` over the bound subject — the
canonical implementations of the resource package's `UserPermissions` and
`RolePermissions` seams. Only the `UserChecker` has `User()`: a role is not
anyone, and the session's effective identity is the resource layer's to
supply.

There is no tenant validation on the check path: an unknown tenant scope
holds no grants, so everything comes back denied (fail closed). If your API
wants to answer 400 for an invalid tenant rather than 403, validate the
tenant in your own guard — your application owns the tenant table.

### User Management

```go
mgr := client.UserManager()
tenant1 := accesstypes.DomainScope("tenant1")
tenant2 := accesstypes.DomainScope("tenant2")

// Enumeration is scope-explicit: access holds no tenant list of its own.
roles, err := mgr.UserRoles(ctx, "john.doe", tenant1, tenant2)
permissions, err := mgr.UserPermissions(ctx, "john.doe", tenant1)

mgr.AddUserRoles(ctx, tenant1, "john.doe", "admin", "editor")
mgr.DeleteUserRoles(ctx, tenant1, "john.doe", "editor")
```

### Role Management

```go
mgr.AddRole(ctx, tenant1, "moderator")
deleted, err := mgr.DeleteRole(ctx, tenant1, "moderator") // scoped to tenant1

roles, err := mgr.Roles(ctx, tenant1)
exists, err := mgr.RoleExists(ctx, tenant1, "admin")

users, err := mgr.RoleUsers(ctx, tenant1, "admin")
mgr.AddRoleUsers(ctx, tenant1, "admin", "user1", "user2")
mgr.DeleteRoleUsers(ctx, tenant1, "admin", "user1")

// Global-scope roles live in their own partition.
mgr.AddRole(ctx, accesstypes.GlobalScope(), "SystemAdmin")
```

### Permission Management

```go
// Resource- and field-specific permissions
mgr.AddRolePermissionResources(ctx, tenant1, "editor", "Read", "documents", "documents.*")
mgr.DeleteRolePermissionResources(ctx, tenant1, "editor", "Read", "documents.*")

// A scope-wide permission (not tied to any resource) is granted through the
// base-name method — there is no resource value that means it.
mgr.AddRolePermission(ctx, tenant1, "admin", "CreateUsers")
mgr.DeleteRolePermission(ctx, tenant1, "admin", "CreateUsers")

permissions, err := mgr.RolePermissions(ctx, tenant1, "admin")
```

Grant writes enforce the resource shape fail-closed: at most one dot, both
segments non-empty (`a.b.c`, `.name`, and `employees.` are rejected at
declaration time).

## HTTP Handlers

```go
logHandler := func(handler func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := handler(w, r); err != nil {
            // Handle error
        }
    }
}

handlers := client.Handlers(logHandler)

http.HandleFunc("/roles", handlers.Roles())
http.HandleFunc("/roles/add", handlers.AddRole())
```

## Role Migration

`MigrateRoles` reconciles role and permission configuration across the given
domains: it creates missing roles and grants, removes extras, and adds an
"Administrator" role with all permissions. Run it from your migrate job on
every deploy.

The caller states its tenant universe explicitly as plain domain names — any
string is a legal tenant name; the global scope is always included
structurally, so global-only applications pass no domains at all. Construct the
migrate job's client with a change signal so running instances pick up the new
configuration immediately.

### Usage

```go
import (
    "context"

    "github.com/cccteam/access"
    "github.com/cccteam/ccc/accesstypes"
    "github.com/cccteam/ccc/resource"
)

func migrateRoles(ctx context.Context, client *access.Client, store *resource.GeneratedCollection, tenants []accesstypes.Domain) error {
    roleConfig := &access.RoleConfig{
        Roles: []*access.Role{
            {
                Name: "Editor",
                Permissions: map[accesstypes.Permission][]accesstypes.Resource{
                    "Read":   {"documents", "documents.*", "images"},
                    "Create": {"documents", "images"},
                    "Update": {"documents"},
                },
            },
            {
                Name: "Viewer",
                Permissions: map[accesstypes.Permission][]accesstypes.Resource{
                    "Read": {"documents", "images"},
                },
            },
        },
    }

    return access.MigrateRoles(ctx, client.UserManager(), store, roleConfig, tenants...)
}
```

### Behavior

- Automatically adds "Administrator" role with all permissions
- Applies roles across the global scope plus a tenant scope for every domain passed in
- Creates missing roles and adds missing permissions
- Removes permissions not in configuration
- Removes roles not in configuration
- Validates resources and permissions against the resource store
- Prevents update permissions on immutable resources

**Note**: Safe to run multiple times — applies changes only when state differs from configuration, and a rollback that re-runs an older release's migrate job converges the store back to that release's defaults. Modifies input config by appending the Administrator role.

### JSON Configuration

```json
{
  "roles": [
    {
      "Name": "Editor",
      "Permissions": {
        "Read": ["documents", "images"],
        "Create": ["documents", "images"],
        "Update": ["documents", "images"]
      }
    },
    {
      "Name": "Viewer",
      "Permissions": {
        "Read": ["documents", "images"]
      }
    }
  ]
}
```

```go
data, _ := os.ReadFile("roles.json")
var config access.RoleConfig
json.Unmarshal(data, &config)
access.MigrateRoles(ctx, client.UserManager(), store, &config, tenants...)
```

## License

See LICENSE file.

---

Created and maintained by the CCC team.
