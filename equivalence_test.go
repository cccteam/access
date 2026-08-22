package access_test

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/cccteam/access"
	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/access/postgresstore"
	"github.com/cccteam/ccc/accesstypes"
	dbinitiator "github.com/cccteam/db-initiator"
	"github.com/google/go-cmp/cmp"
)

// TestConfigEquivalence anchors the typed-store write path to the
// casbin-validated baseline while both write paths exist in-tree: the same
// RoleConfig runs through MigrateRoles into a live casbin_rule store AND into
// the typed tables; the same membership operations run through both
// UserManager paths. Then the two stores must be equivalent three ways:
//  1. canonical records — both readers normalize to the same policy content;
//  2. compiled decisions — a full domain × subject × perm × resource sweep
//     (including unknowns, fields, and wildcards) answers identically;
//  3. the management query surface (roles, role users, role permissions,
//     user roles, user permissions) answers identically.
//
// The one designed divergence — casbin's domain-blind DeleteRole versus the
// typed stores' per-domain delete — is deliberately not exercised: the
// reconcile pass only removes roles that are unassigned in every domain,
// which is also the only shape MigrateRoles can complete on either path.
func TestConfigEquivalence(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	container, err := dbinitiator.NewPostgresContainer(ctx, "latest")
	if err != nil {
		t.Fatalf("dbinitiator.NewPostgresContainer(): %v", err)
	}
	t.Cleanup(func() {
		container.Close()
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminating container: %v", err)
		}
	})

	db, err := container.CreateDatabase(ctx, t.Name())
	if err != nil {
		t.Fatalf("dbinitiator.PostgresContainer.CreateDatabase(): %v", err)
	}
	t.Cleanup(db.Close)

	domains := &staticDomains{ids: []string{"tenant1", "tenant2"}}

	// Casbin path: the public constructor still wires it.
	connConfig := db.Config().ConnConfig
	adapter := access.NewPostgresAdapter(connConfig, connConfig.Database, "casbin_rule")
	client, err := access.New(domains, adapter)
	if err != nil {
		t.Fatalf("access.New(): %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("closing client: %v", err)
		}
	})
	casbinManager := client.UserManager()

	// Typed-store path: same database, its own tables.
	store, err := postgresstore.New(db.Pool)
	if err != nil {
		t.Fatalf("postgresstore.New(): %v", err)
	}
	for _, stmt := range store.DDL() {
		if _, err := db.Exec(ctx, stmt); err != nil {
			t.Fatalf("executing DDL: %v", err)
		}
	}
	storeManager := access.NewTypedStoreUserManagerForTest(domains, store)

	collection := newEquivCollection()

	// Pass 1: initial config through both write paths, then membership.
	for _, manager := range []access.UserManager{casbinManager, storeManager} {
		if err := access.MigrateRoles(ctx, manager, collection, initialRoleConfig()); err != nil {
			t.Fatalf("MigrateRoles() pass 1: %v", err)
		}
	}
	applyMembership(ctx, t, casbinManager)
	applyMembership(ctx, t, storeManager)

	assertStoresEquivalent(ctx, t, "after initial config + membership", adapter, store, casbinManager, storeManager)

	// Pass 2: reconcile-with-delete — Temp dropped (unassigned everywhere),
	// Editor loses Read on widgets, gains Delete on employees.
	for _, manager := range []access.UserManager{casbinManager, storeManager} {
		if err := access.MigrateRoles(ctx, manager, collection, reconciledRoleConfig()); err != nil {
			t.Fatalf("MigrateRoles() pass 2: %v", err)
		}
	}

	assertStoresEquivalent(ctx, t, "after reconcile pass", adapter, store, casbinManager, storeManager)
}

// staticDomains is a Domains implementation with a fixed tenant list.
type staticDomains struct {
	ids []string
}

func (s *staticDomains) DomainIDs(_ context.Context) ([]string, error) {
	return s.ids, nil
}

func (s *staticDomains) DomainExists(_ context.Context, id string) (bool, error) {
	return slices.Contains(s.ids, id), nil
}

// equivCollection is a PermissionCollection fixture: the permission registry
// MigrateRoles validates configs against.
type equivCollection struct {
	list      map[accesstypes.Permission][]accesstypes.Resource
	scopes    map[accesstypes.Resource]accesstypes.PermissionScope
	immutable map[accesstypes.Resource]bool
}

func newEquivCollection() *equivCollection {
	return &equivCollection{
		list: map[accesstypes.Permission][]accesstypes.Resource{
			"Read":      {"employees", "employees.*", "employees.name", "employees.salary", "widgets"},
			"Update":    {"employees", "widgets"},
			"Delete":    {"employees"},
			"ViewUsers": {accesstypes.GlobalResource},
		},
		scopes: map[accesstypes.Resource]accesstypes.PermissionScope{
			"employees":                accesstypes.DomainPermissionScope,
			"employees.*":              accesstypes.DomainPermissionScope,
			"employees.name":           accesstypes.DomainPermissionScope,
			"employees.salary":         accesstypes.DomainPermissionScope,
			"widgets":                  accesstypes.DomainPermissionScope,
			accesstypes.GlobalResource: accesstypes.GlobalPermissionScope,
		},
		// widgets is immutable: adminPermissions must exclude it from the
		// Administrator's Update grants.
		immutable: map[accesstypes.Resource]bool{"widgets": true},
	}
}

// List returns a fresh copy: MigrateRoles mutates the returned map when
// computing Administrator permissions, as the generated collection allows.
func (c *equivCollection) List() map[accesstypes.Permission][]accesstypes.Resource {
	list := make(map[accesstypes.Permission][]accesstypes.Resource, len(c.list))
	for perm, resources := range c.list {
		list[perm] = slices.Clone(resources)
	}

	return list
}

func (c *equivCollection) Scope(res accesstypes.Resource) accesstypes.PermissionScope {
	return c.scopes[res]
}

func (c *equivCollection) IsResourceImmutable(_ accesstypes.PermissionScope, res accesstypes.Resource) bool {
	return c.immutable[res]
}

func initialRoleConfig() *access.RoleConfig {
	return &access.RoleConfig{Roles: []*access.Role{
		{
			Name: "Editor",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"Read":   {"employees", "employees.*", "employees.name", "widgets"},
				"Update": {"employees"},
			},
		},
		{
			Name: "Viewer",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"Read": {"employees", "employees.name"},
			},
		},
		{
			Name: "Auditor",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"ViewUsers": {accesstypes.GlobalResource},
			},
		},
		{
			Name: "Temp",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"Read": {"widgets"},
			},
		},
	}}
}

func reconciledRoleConfig() *access.RoleConfig {
	return &access.RoleConfig{Roles: []*access.Role{
		{
			Name: "Editor",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"Read":   {"employees", "employees.*", "employees.name"},
				"Update": {"employees"},
				"Delete": {"employees"},
			},
		},
		{
			Name: "Viewer",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"Read": {"employees", "employees.name"},
			},
		},
		{
			Name: "Auditor",
			Permissions: map[accesstypes.Permission][]accesstypes.Resource{
				"ViewUsers": {accesstypes.GlobalResource},
			},
		},
	}}
}

// applyMembership drives the same membership operations through one manager:
// plain adds, an idempotent re-add, a global-domain assignment, a removal,
// and a removal of a role never held.
func applyMembership(ctx context.Context, t *testing.T, manager access.UserManager) {
	t.Helper()

	if err := manager.AddRoleUsers(ctx, "tenant1", "Editor", "alice", "bob"); err != nil {
		t.Fatalf("AddRoleUsers() error = %v", err)
	}
	if err := manager.AddUserRoles(ctx, "tenant2", "alice", "Viewer"); err != nil {
		t.Fatalf("AddUserRoles() error = %v", err)
	}
	if err := manager.AddRoleUsers(ctx, accesstypes.GlobalDomain, "Auditor", "carol"); err != nil {
		t.Fatalf("AddRoleUsers() global error = %v", err)
	}
	if err := manager.AddUserRoles(ctx, "tenant1", "alice", "Editor"); err != nil {
		t.Fatalf("AddUserRoles() re-add error = %v", err)
	}
	if err := manager.DeleteRoleUsers(ctx, "tenant1", "Editor", "bob"); err != nil {
		t.Fatalf("DeleteRoleUsers() error = %v", err)
	}
	if err := manager.DeleteUserRoles(ctx, "tenant1", "carol", "Viewer"); err != nil {
		t.Fatalf("DeleteUserRoles() of role never held error = %v", err)
	}
}

// Sweep universe: everything either store could know about, plus unknowns.
var (
	sweepDomains = []accesstypes.Domain{accesstypes.GlobalDomain, "tenant1", "tenant2", "zz-unknown-domain"}
	sweepUsers   = []accesstypes.User{"alice", "bob", "carol", "zz-unknown-user"}
	sweepRoles   = []accesstypes.Role{"Editor", "Viewer", "Auditor", "Temp", "Administrator", "ZzUnknownRole"}
	sweepPerms   = []accesstypes.Permission{"Read", "Update", "Delete", "ViewUsers", "ZzUnknownPerm"}

	sweepResources = []accesstypes.Resource{
		accesstypes.GlobalResource,
		"employees", "employees.*", "employees.name", "employees.salary", "employees.zzunknown",
		"widgets", "widgets.*", "widgets.zzunknown",
		"zzunknownresource", "zzunknownresource.field",
	}
)

func assertStoresEquivalent(
	ctx context.Context, t *testing.T, stage string,
	adapter access.Adapter, store access.Store,
	casbinManager, storeManager access.UserManager,
) {
	t.Helper()

	// 1. Canonical records: both readers normalize to the same content.
	casbinRecords, err := access.ReadCasbinRecordsForTest(adapter)
	if err != nil {
		t.Fatalf("[%s] ReadCasbinRecordsForTest(): %v", stage, err)
	}
	storeRecords, err := store.ReadPolicy(ctx)
	if err != nil {
		t.Fatalf("[%s] Store.ReadPolicy(): %v", stage, err)
	}
	if len(casbinRecords.Grants) == 0 || len(casbinRecords.Memberships) == 0 {
		t.Fatalf("[%s] casbin store is empty (%d grants, %d memberships): the equivalence would be vacuous",
			stage, len(casbinRecords.Grants), len(casbinRecords.Memberships))
	}
	sortRecords(casbinRecords)
	sortRecords(storeRecords)
	if diff := cmp.Diff(casbinRecords, storeRecords); diff != "" {
		t.Errorf("[%s] canonical records diverge (-casbin +store):\n%s", stage, diff)
	}

	// 2. Compiled decisions over the full sweep.
	casbinSnap, err := access.CompileSnapshotForTest(casbinRecords)
	if err != nil {
		t.Fatalf("[%s] compiling casbin-side snapshot: %v", stage, err)
	}
	storeSnap, err := access.CompileSnapshotForTest(storeRecords)
	if err != nil {
		t.Fatalf("[%s] compiling store-side snapshot: %v", stage, err)
	}
	for _, domain := range sweepDomains {
		for _, perm := range sweepPerms {
			for _, user := range sweepUsers {
				a := casbinSnap.CheckUser(ctx, user, domain, perm, sweepResources...)
				b := storeSnap.CheckUser(ctx, user, domain, perm, sweepResources...)
				if !slices.Equal(a, b) {
					t.Errorf("[%s] CheckUser(%s, %s, %s) diverges: casbin missing %v, store missing %v", stage, user, domain, perm, a, b)
				}
			}
			for _, role := range sweepRoles {
				a := casbinSnap.CheckRole(ctx, role, domain, perm, sweepResources...)
				b := storeSnap.CheckRole(ctx, role, domain, perm, sweepResources...)
				if !slices.Equal(a, b) {
					t.Errorf("[%s] CheckRole(%s, %s, %s) diverges: casbin missing %v, store missing %v", stage, role, domain, perm, a, b)
				}
			}
		}
	}

	// 3. Management query surface.
	assertManagersEquivalent(ctx, t, stage, casbinManager, storeManager)
}

func assertManagersEquivalent(ctx context.Context, t *testing.T, stage string, casbinManager, storeManager access.UserManager) {
	t.Helper()

	allDomains, err := casbinManager.Domains(ctx)
	if err != nil {
		t.Fatalf("[%s] Domains(): %v", stage, err)
	}

	for _, domain := range allDomains {
		casbinRoles, err := casbinManager.Roles(ctx, domain)
		if err != nil {
			t.Fatalf("[%s] casbin Roles(%s): %v", stage, domain, err)
		}
		storeRoles, err := storeManager.Roles(ctx, domain)
		if err != nil {
			t.Fatalf("[%s] store Roles(%s): %v", stage, domain, err)
		}
		if diff := cmp.Diff(casbinRoles, storeRoles); diff != "" {
			t.Errorf("[%s] Roles(%s) diverge (-casbin +store):\n%s", stage, domain, diff)
		}

		for _, role := range casbinRoles {
			casbinUsers, err := casbinManager.RoleUsers(ctx, domain, role)
			if err != nil {
				t.Fatalf("[%s] casbin RoleUsers(%s, %s): %v", stage, domain, role, err)
			}
			storeUsers, err := storeManager.RoleUsers(ctx, domain, role)
			if err != nil {
				t.Fatalf("[%s] store RoleUsers(%s, %s): %v", stage, domain, role, err)
			}
			slices.Sort(casbinUsers)
			slices.Sort(storeUsers)
			if diff := cmp.Diff(casbinUsers, storeUsers); diff != "" {
				t.Errorf("[%s] RoleUsers(%s, %s) diverge (-casbin +store):\n%s", stage, domain, role, diff)
			}

			casbinPerms, err := casbinManager.RolePermissions(ctx, domain, role)
			if err != nil {
				t.Fatalf("[%s] casbin RolePermissions(%s, %s): %v", stage, domain, role, err)
			}
			storePerms, err := storeManager.RolePermissions(ctx, domain, role)
			if err != nil {
				t.Fatalf("[%s] store RolePermissions(%s, %s): %v", stage, domain, role, err)
			}
			if diff := cmp.Diff(sortedRolePermissions(casbinPerms), sortedRolePermissions(storePerms)); diff != "" {
				t.Errorf("[%s] RolePermissions(%s, %s) diverge (-casbin +store):\n%s", stage, domain, role, diff)
			}
		}

		for _, user := range sweepUsers {
			casbinUserRoles, err := casbinManager.UserRoles(ctx, user, domain)
			if err != nil {
				t.Fatalf("[%s] casbin UserRoles(%s, %s): %v", stage, user, domain, err)
			}
			storeUserRoles, err := storeManager.UserRoles(ctx, user, domain)
			if err != nil {
				t.Fatalf("[%s] store UserRoles(%s, %s): %v", stage, user, domain, err)
			}
			if diff := cmp.Diff(sortedRoleCollection(casbinUserRoles), sortedRoleCollection(storeUserRoles)); diff != "" {
				t.Errorf("[%s] UserRoles(%s, %s) diverge (-casbin +store):\n%s", stage, user, domain, diff)
			}

			casbinUserPerms, err := casbinManager.UserPermissions(ctx, user, domain)
			if err != nil {
				t.Fatalf("[%s] casbin UserPermissions(%s, %s): %v", stage, user, domain, err)
			}
			storeUserPerms, err := storeManager.UserPermissions(ctx, user, domain)
			if err != nil {
				t.Fatalf("[%s] store UserPermissions(%s, %s): %v", stage, user, domain, err)
			}
			if diff := cmp.Diff(sortedUserPermissions(casbinUserPerms), sortedUserPermissions(storeUserPerms)); diff != "" {
				t.Errorf("[%s] UserPermissions(%s, %s) diverge (-casbin +store):\n%s", stage, user, domain, diff)
			}
		}
	}
}

func sortedRolePermissions(c accesstypes.RolePermissionCollection) accesstypes.RolePermissionCollection {
	out := make(accesstypes.RolePermissionCollection, len(c))
	for perm, resources := range c {
		r := slices.Clone(resources)
		slices.Sort(r)
		out[perm] = r
	}

	return out
}

func sortedRoleCollection(c accesstypes.RoleCollection) accesstypes.RoleCollection {
	out := make(accesstypes.RoleCollection, len(c))
	for domain, roles := range c {
		r := slices.Clone(roles)
		slices.Sort(r)
		out[domain] = r
	}

	return out
}

func sortedUserPermissions(c accesstypes.UserPermissionCollection) accesstypes.UserPermissionCollection {
	out := make(accesstypes.UserPermissionCollection, len(c))
	for domain, byResource := range c {
		res := make(map[accesstypes.Resource][]accesstypes.Permission, len(byResource))
		for resource := range maps.Keys(byResource) {
			perms := slices.Clone(byResource[resource])
			slices.Sort(perms)
			res[resource] = perms
		}
		out[domain] = res
	}

	return out
}

// sortRecords orders records canonically so the two readers' outputs compare
// as sets.
func sortRecords(r *policy.Records) {
	compareSubjects := func(a, b policy.Subject) int {
		if c := int(a.Kind) - int(b.Kind); c != 0 {
			return c
		}

		return strings.Compare(a.Name, b.Name)
	}
	cmpChain := func(results ...int) int {
		for _, c := range results {
			if c != 0 {
				return c
			}
		}

		return 0
	}

	slices.SortFunc(r.Grants, func(a, b policy.Grant) int {
		return cmpChain(
			strings.Compare(string(a.Domain), string(b.Domain)),
			compareSubjects(a.Subject, b.Subject),
			strings.Compare(string(a.Perm), string(b.Perm)),
			strings.Compare(a.Resource, b.Resource),
			strings.Compare(a.Field, b.Field),
		)
	})
	slices.SortFunc(r.Memberships, func(a, b policy.Membership) int {
		return cmpChain(
			strings.Compare(string(a.Domain), string(b.Domain)),
			compareSubjects(a.Member, b.Member),
			strings.Compare(string(a.Role), string(b.Role)),
		)
	})
}
