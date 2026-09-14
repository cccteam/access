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
(`Condition`, empty = unconditional, and part of the row's identity) — and a
resource covered only by conditional grants answers `Conditional`; any
unconditional cover answers `Granted` outright. A role may hold several grants
on one resource for one permission, each under its own condition, stored as
one row per condition, so the engine sees them exactly as it would from
separate roles. Grouping is the engine's job: within one
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
domains: it creates missing roles and grants and removes extras. The
configuration is the complete statement of the store's roles: every role a
login can hold is declared in it, so the warnings below and `ValidateRoles` see
every grant the store will carry. Run it from your migrate job on every deploy.

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
        Roles: access.ScopedRoles{
            Domain: []*access.Role{
                {
                    Name: "Editor",
                    Permissions: map[accesstypes.Permission][]access.Grant{
                        accesstypes.List:   {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "author"}}},
                        accesstypes.Read:   {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "author", "body"}}},
                        accesstypes.Create: {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "body"}}},
                        accesstypes.Update: {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "body"}, Condition: "author = subject"}},
                    },
                },
                {
                    Name: "Viewer",
                    Permissions: map[accesstypes.Permission][]access.Grant{
                        accesstypes.List: {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "author"}}},
                        accesstypes.Read: {{Resource: "Documents", Fields: []accesstypes.Tag{"title", "author", "body"}}},
                    },
                },
            },
        },
    }

    return access.MigrateRoles(ctx, client.UserManager(), store, roleConfig, tenants...)
}
```

### Behavior

- Applies roles across the global scope plus a tenant scope for every domain passed in
- Creates missing roles and adds missing permissions
- Removes permissions not in configuration
- Removes roles not in configuration. A role a user still holds cannot be removed, so the migration fails naming it; remove the memberships, or author the role under that name in the configuration
- Creates a role whose configuration entry has no grants; it holds nothing until a grant is authored
- Validates resources, permissions, and conditions against the resource store before touching it
- Prevents update permissions on immutable resources
- Warns, without rejecting, when a role holds a conditional Delete, Update, or targeted Execute on a row it can neither Read nor List, or a conditional List on a concealing field the resource sorts or filters by (see Warnings)

**Note**: Safe to run multiple times — applies changes only when state differs from configuration, and a rollback that re-runs an older release's migrate job converges the store back to that release's defaults. The input configuration is not modified.

### Warnings

A Delete, an Update, and an Execute on a method with a `@target` row locate the row first
and answer NotFound when it is absent, then evaluate the grant's condition and answer
Forbidden when it fails. A read hides a row its condition does not select behind the same
NotFound. So a role holding a conditional write on a row it can neither Read nor List
learns, from the response code alone, that a row exists in its tenant, without changing
it. `MigrateRoles` provisions such a grant as written and prints one line for it beside
its Added and Removed lines:

```
Warning: role Paymaster: Delete on Missions is granted under "state = 'open'" without Read or List on Missions: a Forbidden answer tells the caller a Missions row exists where a read would answer NotFound. Grant Read or List on Missions in this role or in a role assigned with it, or accept the disclosure; a Read whose condition is narrower than this one leaks the same way.
```

The check is per role. A reader role meant to be assigned alongside the writer role does
not silence it, because `MigrateRoles` never sees assignments; the line tells the role's
author which role to change. Unconditional writes are not flagged: they reveal existence
only by succeeding, which is what the grant permits. The check is a heuristic. Holding
Read does not close the channel when the Read condition is narrower than the write's.

The second warning is about cost, not disclosure. A sort or filter on a conditionally
visible field runs over the visible projection, `CASE WHEN <condition> THEN column END`,
so a masked cell is `NULL` wherever the query looks at it and nothing about a hidden value
leaks through order or match. No index serves that expression: every such page sorts the
tenant's whole partition. The query drops the `CASE` when the row filter has already
proven the field's condition on every surviving row, which is the case when every field
the role lists on the resource is granted under a condition that implies the field's own;
it keeps the `CASE` when the role lists another field unconditionally, or under a
condition the field's condition does not cover. `MigrateRoles` warns exactly there, for a
field the resource orders by (`@order`, so every page pays) or admits as a sort or filter
key (an indexed or `allow_filter` field, so a page sorted or filtered by it pays), and
only where the field's masked cells conceal. The resource package's `masking:"positional"`
struct tag declares the other behaviour: the cell stays hidden but the query runs on the
real column, the index serves the page, and where the hidden values fall is disclosed; the
generated collection leaves such a field out of the check.

```
Warning: role Archivist: List on Missions.fee is granted under "state = 'completed'", and fee is a sort or filter key of Missions whose masked cells conceal; this role also lists Missions fields under "state IN ('completed', 'failed', 'stood_down')", which the field's condition does not cover, so the row filter does not prove the field's condition and a page this role sorts or filters by fee orders on CASE WHEN <condition> THEN column END, which no index serves: it sorts the tenant's whole partition. Grant fee unconditionally in this role, tag the field masking:"positional" and disclose where its hidden values fall, or accept the cost for a table that never pages at volume.
```

The covering test admits implication on one attribute under a closed rule set: a
condition covers another that spells it the same way, an equality or `IN` list whose
values all sit inside its own `IN` list, a `!=` or `NOT IN` whose values include all of its
own, and a conjunction any one of whose terms it covers; every other shape (another
attribute, a range, a subject set, `1` against `1.0`) must be spelled the same. So the
archivist's row fields, granted on the closed states, are silent, because her completed
grant implies them (`state = 'completed'` is one of `state IN ('completed', 'failed',
'stood_down')`); her fee, granted on completed alone, is the one warning above, because
the closed-states grant admits rows the fee's condition does not select.

`ValidateRoles` runs the same validation and returns the warnings as `[]access.Warning`
with no store client involved, so a project test or a tool gets the answer the deploy
would. Every warning prints as one line; a consumer that wants the fields switches on the
kind, `access.GrantWarning` or `access.ConcealingKeyWarning`:

```go
warnings, err := access.ValidateRoles(store, roleConfig)
if err != nil {
    return err // the refusals MigrateRoles would answer
}
for _, w := range warnings {
    fmt.Println(w)
}
```

### Several Sites, One Policy Store

A deployment whose sites each generate their own collection over one schema shares one
policy store: a login is one identity and a role is one set of powers across the
application. `UnionCollection` presents the sites' collections as one registry for
`MigrateRoles`: the registries merge, the subject namespace is the union of the sites'
declarations, and every other question about a resource is answered by the first
collection registering it. A resource several sites serve must be declared identically
in each; `UnionCollection` refuses collections that disagree on a shared resource's
permissions (fields included), scope, immutability, computed marking, or method target.

```go
store, err := access.UnionCollection(consolerouter.Collection(), portalrouter.Collection())
if err != nil {
    return err
}

return access.MigrateRoles(ctx, client.UserManager(), store, roleConfig, tenants...)
```

### JSON Configuration

```json
{
  "roles": {
    "global": [],
    "domain": [
      {
        "name": "Editor",
        "permissions": {
          "List":   [{"resource": "Documents", "fields": ["title", "author"]}],
          "Read":   [{"resource": "Documents", "fields": ["title", "author", "body"]}],
          "Create": [{"resource": "Documents", "fields": ["title", "body"]}],
          "Update": [{"resource": "Documents", "fields": ["title", "body"], "condition": "author = subject"}]
        }
      },
      {
        "name": "Viewer",
        "permissions": {
          "List": [{"resource": "Documents", "fields": ["title", "author"]}],
          "Read": [{"resource": "Documents", "fields": ["title", "author", "body"]}]
        }
      }
    ]
  }
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
