// Package storetest is the shared conformance suite for access.Store
// implementations. Each store package owns its containers and schema setup
// and hands a ready store to Run; the contract assertions live here once, so
// every store is held to exactly the same behavior.
package storetest

import (
	"slices"
	"strings"
	"testing"

	"github.com/cccteam/access"
	"github.com/cccteam/access/internal/policy"
	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Fixture names shared by the suite's ordered phases. Scopes are variables
// because accesstypes.Scope is a struct.
var (
	tenant1     = accesstypes.DomainScope("tenant1")
	tenant2     = accesstypes.DomainScope("tenant2")
	globalScope = accesstypes.GlobalScope()
)

const (
	editor = accesstypes.Role("Editor")
	admin  = accesstypes.Role("Admin")
	viewer = accesstypes.Role("Viewer")

	alice = accesstypes.User("alice")
	bob   = accesstypes.User("bob")

	readPerm = accesstypes.Permission("Read")

	employees = "employees"
	widgets   = "widgets"
)

// Run exercises the full access.Store contract against an empty, ready store.
// The suite is one ordered scenario: later phases build on earlier writes.
func Run(t *testing.T, store access.Store) {
	t.Helper()

	t.Run("roles", func(t *testing.T) { runRoles(t, store) })
	t.Run("memberships", func(t *testing.T) { runMemberships(t, store) })
	t.Run("grants", func(t *testing.T) { runGrants(t, store) })
	t.Run("global scope", func(t *testing.T) { runGlobalScope(t, store) })
	t.Run("delete role", func(t *testing.T) { runDeleteRole(t, store) })
	t.Run("read policy", func(t *testing.T) { runReadPolicy(t, store) })
}

func runRoles(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	if exists, err := store.RoleExists(ctx, tenant1, editor); err != nil || exists {
		t.Fatalf("RoleExists() on empty store = (%v, %v), want (false, nil)", exists, err)
	}

	for _, role := range []accesstypes.Role{editor, admin, viewer} {
		if err := store.InsertRole(ctx, tenant1, role); err != nil {
			t.Fatalf("InsertRole(%q) error = %v", role, err)
		}
	}
	if err := store.InsertRole(ctx, tenant1, editor); err != nil {
		t.Fatalf("InsertRole() re-insert must be a no-op, got error = %v", err)
	}
	if err := store.InsertRole(ctx, tenant2, editor); err != nil {
		t.Fatalf("InsertRole(tenant2) error = %v", err)
	}

	if exists, err := store.RoleExists(ctx, tenant1, editor); err != nil || !exists {
		t.Fatalf("RoleExists() = (%v, %v), want (true, nil)", exists, err)
	}
	if exists, err := store.RoleExists(ctx, tenant2, admin); err != nil || exists {
		t.Fatalf("RoleExists() must be domain-scoped: got (%v, %v), want (false, nil)", exists, err)
	}

	roles, err := store.ListRoles(ctx, tenant1)
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	if diff := cmp.Diff([]accesstypes.Role{admin, editor, viewer}, roles); diff != "" {
		t.Errorf("ListRoles() must be sorted and domain-scoped (-want +got):\n%s", diff)
	}
}

func runMemberships(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	if err := store.InsertUserRole(ctx, tenant1, alice, "Ghost"); err == nil {
		t.Fatal("InsertUserRole() with absent role must fail (parent enforcement), got nil")
	}

	for _, m := range []struct {
		user accesstypes.User
		role accesstypes.Role
	}{
		{alice, editor},
		{alice, viewer},
		{bob, editor},
	} {
		if err := store.InsertUserRole(ctx, tenant1, m.user, m.role); err != nil {
			t.Fatalf("InsertUserRole(%q, %q) error = %v", m.user, m.role, err)
		}
	}
	if err := store.InsertUserRole(ctx, tenant1, alice, editor); err != nil {
		t.Fatalf("InsertUserRole() re-insert must be a no-op, got error = %v", err)
	}

	userRoles, err := store.ListUserRoles(ctx, tenant1, alice)
	if err != nil {
		t.Fatalf("ListUserRoles() error = %v", err)
	}
	if diff := cmp.Diff([]accesstypes.Role{editor, viewer}, userRoles); diff != "" {
		t.Errorf("ListUserRoles() (-want +got):\n%s", diff)
	}
	if roles, err := store.ListUserRoles(ctx, tenant2, alice); err != nil || len(roles) != 0 {
		t.Errorf("ListUserRoles() must be domain-scoped: got (%v, %v)", roles, err)
	}

	roleUsers, err := store.ListRoleUsers(ctx, tenant1, editor)
	if err != nil {
		t.Fatalf("ListRoleUsers() error = %v", err)
	}
	if diff := cmp.Diff([]accesstypes.User{alice, bob}, roleUsers); diff != "" {
		t.Errorf("ListRoleUsers() (-want +got):\n%s", diff)
	}

	if err := store.DeleteUserRole(ctx, tenant1, bob, editor); err != nil {
		t.Fatalf("DeleteUserRole() error = %v", err)
	}
	if err := store.DeleteUserRole(ctx, tenant1, bob, editor); err != nil {
		t.Fatalf("DeleteUserRole() of absent row must be a no-op, got error = %v", err)
	}
	if users, err := store.ListRoleUsers(ctx, tenant1, editor); err != nil || len(users) != 1 || users[0] != alice {
		t.Errorf("ListRoleUsers() after delete = (%v, %v), want ([%s], nil)", users, err, alice)
	}
}

func runGrants(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	if err := store.InsertGrant(ctx, tenant1, "Ghost", readPerm, employees, "", ""); err == nil {
		t.Fatal("InsertGrant() with absent role must fail (parent enforcement), got nil")
	}

	// Condition is opaque expression text and part of the row's identity: the
	// same (permission, resource, field) holds one row per condition, "" being
	// the unconditional row. The store never interprets the text.
	grants := []policy.RoleGrant{
		{Perm: readPerm, Resource: employees, Field: ""},
		{Perm: readPerm, Resource: employees, Field: "*"},
		{Perm: readPerm, Resource: employees, Field: "name"},
		{Perm: readPerm, Resource: employees, Field: "salary", Condition: "owner = @subject"},
		{Perm: readPerm, Resource: employees, Field: "salary", Condition: "region = 'west'"},
		{Perm: "Update", Resource: widgets, Field: ""},
	}
	for _, g := range grants {
		if err := store.InsertGrant(ctx, tenant1, editor, g.Perm, g.Resource, g.Field, g.Condition); err != nil {
			t.Fatalf("InsertGrant(%v) error = %v", g, err)
		}
	}
	if err := store.InsertGrant(ctx, tenant1, editor, readPerm, employees, "", ""); err != nil {
		t.Fatalf("InsertGrant() re-insert must be a no-op, got error = %v", err)
	}
	if err := store.InsertGrant(ctx, tenant1, editor, readPerm, employees, "salary", "owner = @subject"); err != nil {
		t.Fatalf("InsertGrant() re-insert with the same condition must be a no-op, got error = %v", err)
	}

	got, err := store.ListRoleGrants(ctx, tenant1, editor)
	if err != nil {
		t.Fatalf("ListRoleGrants() error = %v", err)
	}
	if diff := cmp.Diff(grants, got); diff != "" {
		t.Errorf("ListRoleGrants() must be sorted with one row per condition (-want +got):\n%s", diff)
	}

	// DeleteGrant addresses exactly one row: the other condition on the same
	// (permission, resource, field) survives.
	if err := store.DeleteGrant(ctx, tenant1, editor, readPerm, employees, "salary", "region = 'west'"); err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if err := store.DeleteGrant(ctx, tenant1, editor, readPerm, employees, "salary", "region = 'west'"); err != nil {
		t.Fatalf("DeleteGrant() of absent row must be a no-op, got error = %v", err)
	}
	got, err = store.ListRoleGrants(ctx, tenant1, editor)
	if err != nil {
		t.Fatalf("ListRoleGrants() error = %v", err)
	}
	want := append(append([]policy.RoleGrant{}, grants[:4]...), grants[5])
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ListRoleGrants() after deleting one condition's row (-want +got):\n%s", diff)
	}

	// DeleteGrants removes every condition's row for the (permission,
	// resource, field), and only those.
	if err := store.InsertGrant(ctx, tenant1, editor, readPerm, employees, "salary", "region = 'west'"); err != nil {
		t.Fatalf("InsertGrant() error = %v", err)
	}
	if err := store.DeleteGrants(ctx, tenant1, editor, readPerm, employees, "salary"); err != nil {
		t.Fatalf("DeleteGrants() error = %v", err)
	}
	if err := store.DeleteGrants(ctx, tenant1, editor, "Update", widgets, ""); err != nil {
		t.Fatalf("DeleteGrants() error = %v", err)
	}
	if err := store.DeleteGrants(ctx, tenant1, editor, "Update", widgets, ""); err != nil {
		t.Fatalf("DeleteGrants() of absent rows must be a no-op, got error = %v", err)
	}
	got, err = store.ListRoleGrants(ctx, tenant1, editor)
	if err != nil {
		t.Fatalf("ListRoleGrants() error = %v", err)
	}
	if diff := cmp.Diff(grants[:3], got); diff != "" {
		t.Errorf("ListRoleGrants() after DeleteGrants (-want +got):\n%s", diff)
	}
}

func runGlobalScope(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	tenantNamedGlobal := accesstypes.DomainScope("global")

	if err := store.InsertRole(ctx, globalScope, admin); err != nil {
		t.Fatalf("InsertRole(global scope) error = %v", err)
	}
	if err := store.InsertRole(ctx, tenantNamedGlobal, admin); err != nil {
		t.Fatalf("InsertRole(tenant named global) error = %v", err)
	}

	// The global partition and a tenant literally named "global" are distinct
	// rows: scope is structural, never a domain value.
	if exists, err := store.RoleExists(ctx, globalScope, admin); err != nil || !exists {
		t.Fatalf("RoleExists(global scope) = (%v, %v), want (true, nil)", exists, err)
	}
	if exists, err := store.RoleExists(ctx, tenantNamedGlobal, admin); err != nil || !exists {
		t.Fatalf("RoleExists(tenant named global) = (%v, %v), want (true, nil)", exists, err)
	}
	if deleted, err := store.DeleteRole(ctx, tenantNamedGlobal, admin); err != nil || !deleted {
		t.Fatalf("DeleteRole(tenant named global) = (%v, %v), want (true, nil)", deleted, err)
	}
	if exists, err := store.RoleExists(ctx, globalScope, admin); err != nil || !exists {
		t.Fatalf("RoleExists(global scope) after tenant delete = (%v, %v), want (true, nil): deleting the tenant row must not touch the global partition", exists, err)
	}

	// A scope-wide grant is stored as an empty resource+field row — a spot no
	// real resource can occupy — and lists back exactly that way.
	if err := store.InsertGrant(ctx, globalScope, admin, "Export", "", "", ""); err != nil {
		t.Fatalf("InsertGrant(scope-wide) error = %v", err)
	}
	grants, err := store.ListRoleGrants(ctx, globalScope, admin)
	if err != nil {
		t.Fatalf("ListRoleGrants(global scope) error = %v", err)
	}
	want := []policy.RoleGrant{{Perm: "Export", Resource: "", Field: ""}}
	if diff := cmp.Diff(want, grants); diff != "" {
		t.Errorf("ListRoleGrants(global scope) (-want +got):\n%s", diff)
	}
}

func runDeleteRole(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	// alice still holds Editor: memberships must block the delete.
	if _, err := store.DeleteRole(ctx, tenant1, editor); err == nil {
		t.Fatal("DeleteRole() with members must fail, got nil")
	}
	if exists, err := store.RoleExists(ctx, tenant1, editor); err != nil || !exists {
		t.Fatalf("RoleExists() after blocked delete = (%v, %v), want (true, nil)", exists, err)
	}

	if err := store.DeleteUserRole(ctx, tenant1, alice, editor); err != nil {
		t.Fatalf("DeleteUserRole() error = %v", err)
	}
	deleted, err := store.DeleteRole(ctx, tenant1, editor)
	if err != nil || !deleted {
		t.Fatalf("DeleteRole() = (%v, %v), want (true, nil)", deleted, err)
	}

	// Grants cascaded with the role; the same role name in another domain is
	// untouched (the delete is domain-scoped).
	if grants, err := store.ListRoleGrants(ctx, tenant1, editor); err != nil || len(grants) != 0 {
		t.Errorf("ListRoleGrants() after role delete = (%v, %v), want no grants", grants, err)
	}
	if exists, err := store.RoleExists(ctx, tenant2, editor); err != nil || !exists {
		t.Errorf("RoleExists(tenant2) after tenant1 delete = (%v, %v), want (true, nil)", exists, err)
	}

	deleted, err = store.DeleteRole(ctx, tenant1, editor)
	if err != nil || deleted {
		t.Fatalf("DeleteRole() of absent role = (%v, %v), want (false, nil)", deleted, err)
	}
}

func runReadPolicy(t *testing.T, store access.Store) {
	t.Helper()
	ctx := t.Context()

	// State accumulated above: roles tenant1/{Admin,Viewer}, tenant2/Editor,
	// global/Admin with a scope-wide Export grant; membership alice->Viewer in
	// tenant1. Add grants to a surviving role so the read covers grants too,
	// one of them conditional.
	if err := store.InsertGrant(ctx, tenant1, viewer, "List", widgets, "*", ""); err != nil {
		t.Fatalf("InsertGrant() error = %v", err)
	}
	if err := store.InsertGrant(ctx, tenant1, viewer, readPerm, widgets, "name", "owner = @subject"); err != nil {
		t.Fatalf("InsertGrant() error = %v", err)
	}

	records, err := store.ReadPolicy(ctx)
	if err != nil {
		t.Fatalf("ReadPolicy() error = %v", err)
	}

	want := &policy.Records{
		Grants: []policy.Grant{
			{Scope: tenant1, Subject: policy.Subject{Kind: policy.SubjectRole, Name: string(viewer)}, Perm: "List", Resource: widgets, Field: "*"},
			{Scope: tenant1, Subject: policy.Subject{Kind: policy.SubjectRole, Name: string(viewer)}, Perm: readPerm, Resource: widgets, Field: "name", Condition: "owner = @subject"},
			{Scope: globalScope, Subject: policy.Subject{Kind: policy.SubjectRole, Name: string(admin)}, Perm: "Export", Resource: "", Field: ""},
		},
		Memberships: []policy.Membership{
			{Scope: tenant1, Member: policy.Subject{Kind: policy.SubjectUser, Name: string(alice)}, Role: viewer},
		},
	}
	sortRecords(records)
	sortRecords(want)
	// Scope is comparable with unexported fields; compare it by ==.
	if diff := cmp.Diff(want, records, cmpopts.EquateComparable(accesstypes.Scope{})); diff != "" {
		t.Errorf("ReadPolicy() (-want +got):\n%s", diff)
	}
}

// sortRecords orders records canonically so set comparisons are stable
// regardless of row order.
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
	compareScopes := func(a, b accesstypes.Scope) int {
		ag, ad := policy.ScopeColumns(a)
		bg, bd := policy.ScopeColumns(b)
		gi := func(g bool) int {
			if g {
				return 1
			}

			return 0
		}

		return cmpChain(gi(ag)-gi(bg), strings.Compare(ad, bd))
	}

	slices.SortFunc(r.Grants, func(a, b policy.Grant) int {
		return cmpChain(
			compareScopes(a.Scope, b.Scope),
			compareSubjects(a.Subject, b.Subject),
			strings.Compare(string(a.Perm), string(b.Perm)),
			strings.Compare(a.Resource, b.Resource),
			strings.Compare(a.Field, b.Field),
		)
	})
	slices.SortFunc(r.Memberships, func(a, b policy.Membership) int {
		return cmpChain(
			compareScopes(a.Scope, b.Scope),
			compareSubjects(a.Member, b.Member),
			strings.Compare(string(a.Role), string(b.Role)),
		)
	})
}
