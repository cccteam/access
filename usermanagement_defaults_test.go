package access

// These tests pin the management surface over the release's default roles: a
// default exists without a store row — a global role in the global partition,
// a domain role in one domain and in every domain; a membership names it by
// name; its grants are the file's and are read here, never written; and a
// custom role is held where it was created, reaching one domain from every
// domain but changed only where it is held.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/cccteam/httpio"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// The release's default roles the tests run against: a global role and a
// domain role, each granting what grammarCollection declares at its scope.
const (
	globalDefault accesstypes.Role = "Steward"
	domainDefault accesstypes.Role = "Reader"
)

// neverSeenScope is a request in a domain the store holds no row in: a tenant
// created after the policy was written.
var neverSeenScope = accesstypes.DomainScope("never-seen")

// defaultsRoleConfig declares the two default roles: Steward executes the
// global method, Reader reads Widgets and its name field.
func defaultsRoleConfig() *RoleConfig {
	return &RoleConfig{Roles: ScopedRoles{
		Global: []*Role{{Name: globalDefault, Permissions: map[accesstypes.Permission][]Grant{
			"Execute": {{Resource: "DoThing"}},
		}}},
		Domain: []*Role{{Name: domainDefault, Permissions: map[accesstypes.Permission][]Grant{
			"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}},
		}}},
	}}
}

// defaultsTestEngine builds a snapshotEngine over store that compiles the
// release's default roles into its snapshot, inert like testEngine (1h
// heartbeat) and stopped at test end.
func defaultsTestEngine(t *testing.T, store Store, defaults *defaultRoles) *snapshotEngine {
	t.Helper()
	opts := defaultClientOptions()
	opts.heartbeatInterval = time.Hour
	e := newSnapshotEngine(store, defaults, opts)
	t.Cleanup(func() {
		if err := e.close(); err != nil {
			t.Errorf("snapshotEngine.close() error = %v", err)
		}
	})

	return e
}

// defaultsManager returns a userManager over a fresh fake store with the
// release's default roles compiled in and custom roles seeded through the
// manager's own write path: Zed held in tenant1 with Read on Widgets,
// Everywhere held in every domain with a conditional Read on Widgets, Dup held
// both in tenant1 and in every domain, and Gob held in the global partition.
// The store manager's change hook is wired to the engine, so a write is seen
// by the next evaluator answer.
func defaultsManager(t *testing.T) (*userManager, *fakeStore) {
	t.Helper()
	ctx := context.Background()

	defaults, err := compileDefaultRoles(grammarCollection{}, defaultsRoleConfig())
	if err != nil {
		t.Fatalf("compileDefaultRoles() error = %v", err)
	}
	store := newFakeStore()
	manager := newStoreManager(store)
	engine := defaultsTestEngine(t, store, defaults)
	manager.onPolicyChange = engine.policyChanged
	m := newUserManager(manager, defaults, engine)

	for _, seed := range []struct {
		scope accesstypes.PolicyScope
		role  accesstypes.Role
	}{
		{tenant1Policy, "Zed"},
		{everyDomainPolicy, "Everywhere"},
		{tenant1Policy, "Dup"},
		{everyDomainPolicy, "Dup"},
		{globalPolicy, "Gob"},
	} {
		if err := m.AddRole(ctx, seed.scope, seed.role); err != nil {
			t.Fatalf("AddRole(%q, %q) error = %v", seed.scope, seed.role, err)
		}
	}
	if err := m.AddRolePermissionResources(ctx, tenant1Policy, "Zed", "Read", "Widgets"); err != nil {
		t.Fatalf("AddRolePermissionResources() error = %v", err)
	}
	if err := m.AddRoleGrant(ctx, everyDomainPolicy, "Everywhere", "Read", "Widgets", "price < 10"); err != nil {
		t.Fatalf("AddRoleGrant() error = %v", err)
	}

	return m, store
}

// Test_userManager_defaults_RoleExists pins where each kind of role exists: a
// default of a scope's kind everywhere that kind reaches, a custom role where
// it is held — and, held in every domain, in any one domain.
func Test_userManager_defaults_RoleExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope accesstypes.PolicyScope
		role  accesstypes.Role
		want  bool
	}{
		{name: "a global default exists in the global partition", scope: globalPolicy, role: globalDefault, want: true},
		{name: "a global default does not exist in one domain", scope: tenant1Policy, role: globalDefault},
		{name: "a global default does not exist in every domain", scope: everyDomainPolicy, role: globalDefault},
		{name: "a domain default exists in one domain", scope: tenant1Policy, role: domainDefault, want: true},
		{name: "a domain default exists in a domain the store holds no row in", scope: neverSeenScope.PolicyScope(), role: domainDefault, want: true},
		{name: "a domain default exists in every domain", scope: everyDomainPolicy, role: domainDefault, want: true},
		{name: "a domain default does not exist in the global partition", scope: globalPolicy, role: domainDefault},
		{name: "a custom role held in every domain exists there", scope: everyDomainPolicy, role: "Everywhere", want: true},
		{name: "a custom role held in every domain exists in any one domain", scope: tenant2Policy, role: "Everywhere", want: true},
		{name: "a custom role held in every domain does not exist in the global partition", scope: globalPolicy, role: "Everywhere"},
		{name: "a custom role held in one domain exists there", scope: tenant1Policy, role: "Zed", want: true},
		{name: "a custom role held in one domain does not exist in another", scope: tenant2Policy, role: "Zed"},
		{name: "a custom role held in one domain does not exist in every domain", scope: everyDomainPolicy, role: "Zed"},
		{name: "a custom role held in the global partition exists there", scope: globalPolicy, role: "Gob", want: true},
		{name: "a role nothing defines does not exist", scope: tenant1Policy, role: "Ghost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, _ := defaultsManager(t)

			got, err := m.RoleExists(t.Context(), tt.scope, tt.role)
			if err != nil {
				t.Fatalf("RoleExists() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("RoleExists(%s, %s) = %v, want %v", tt.scope, tt.role, got, tt.want)
			}
		})
	}
}

// Test_userManager_defaults_Roles pins the listing: the defaults of the
// scope's kind, the custom roles held in the scope and, for one domain, the
// custom roles held in every domain — sorted, a name once however many places
// hold it.
func Test_userManager_defaults_Roles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope accesstypes.PolicyScope
		want  []accesstypes.Role
	}{
		{name: "the global partition lists the global default and the global customs", scope: globalPolicy, want: []accesstypes.Role{"Gob", globalDefault}},
		{name: "one domain lists the domain default, its own customs and the every-domain customs once", scope: tenant1Policy, want: []accesstypes.Role{"Dup", "Everywhere", domainDefault, "Zed"}},
		{name: "another domain does not see a custom role held in the first", scope: tenant2Policy, want: []accesstypes.Role{"Dup", "Everywhere", domainDefault}},
		{name: "a domain the store holds no row in lists the defaults and the every-domain customs", scope: neverSeenScope.PolicyScope(), want: []accesstypes.Role{"Dup", "Everywhere", domainDefault}},
		{name: "every domain lists the domain default and the every-domain customs", scope: everyDomainPolicy, want: []accesstypes.Role{"Dup", "Everywhere", domainDefault}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, _ := defaultsManager(t)

			got, err := m.Roles(t.Context(), tt.scope)
			if err != nil {
				t.Fatalf("Roles() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Roles(%s) (-want +got):\n%s", tt.scope, diff)
			}
		})
	}
}

// Test_userManager_defaults_AddRole pins the names a custom role cannot take:
// a default's of the scope's kind (a conflict), a name a custom role held in
// every domain already answers to in one domain, and the empty name.
func Test_userManager_defaults_AddRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		scope   accesstypes.PolicyScope
		role    accesstypes.Role
		wantErr func(error) bool
	}{
		{name: "a domain default's name is refused in one domain", scope: tenant1Policy, role: domainDefault, wantErr: httpio.HasConflict},
		{name: "a domain default's name is refused in every domain", scope: everyDomainPolicy, role: domainDefault, wantErr: httpio.HasConflict},
		{name: "a global default's name is refused in the global partition", scope: globalPolicy, role: globalDefault, wantErr: httpio.HasConflict},
		{name: "a name held in every domain is refused in one domain", scope: tenant2Policy, role: "Everywhere", wantErr: httpio.HasConflict},
		{name: "the empty name is refused", scope: tenant1Policy, role: "", wantErr: httpio.HasBadRequest},
		{name: "a name held in another domain only is free", scope: tenant2Policy, role: "Zed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			m, store := defaultsManager(t)
			rolesBefore := len(store.roles)

			err := m.AddRole(ctx, tt.scope, tt.role)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("AddRole() error = %v", err)
				}
				if exists, err := m.RoleExists(ctx, tt.scope, tt.role); err != nil || !exists {
					t.Errorf("RoleExists() after AddRole = (%v, %v), want (true, nil)", exists, err)
				}

				return
			}
			if err == nil || !tt.wantErr(err) {
				t.Fatalf("AddRole() error = %v, want a refusal of the expected kind", err)
			}
			if len(store.roles) != rolesBefore {
				t.Errorf("AddRole() wrote a role row on a refused call")
			}
		})
	}
}

// Test_userManager_defaults_DeleteRole pins what DeleteRole refuses — a
// default role, which has no row to delete, and a custom role with members in
// the scope — and that a custom role is deleted where it is held.
func Test_userManager_defaults_DeleteRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prepare     func(ctx context.Context, m *userManager) error
		scope       accesstypes.PolicyScope
		role        accesstypes.Role
		wantErr     bool
		wantDeleted bool
		// wantExists is asked of RoleExists in scope after the call.
		wantExists bool
	}{
		{name: "a domain default is refused in one domain", scope: tenant1Policy, role: domainDefault, wantErr: true, wantExists: true},
		{name: "a domain default is refused in every domain", scope: everyDomainPolicy, role: domainDefault, wantErr: true, wantExists: true},
		{name: "a global default is refused", scope: globalPolicy, role: globalDefault, wantErr: true, wantExists: true},
		{
			name: "a custom role with members in the scope is refused",
			prepare: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Policy, "Zed", "alice")
			},
			scope: tenant1Policy, role: "Zed", wantErr: true, wantExists: true,
		},
		{name: "a custom role is deleted where it is held", scope: tenant1Policy, role: "Zed", wantDeleted: true},
		{name: "a custom role held in every domain is deleted there", scope: everyDomainPolicy, role: "Everywhere", wantDeleted: true},
		{name: "a custom role held in every domain is not deleted through one domain", scope: tenant1Policy, role: "Everywhere", wantExists: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			m, store := defaultsManager(t)
			if tt.prepare != nil {
				if err := tt.prepare(ctx, m); err != nil {
					t.Fatalf("prepare error = %v", err)
				}
			}
			rolesBefore := len(store.roles)

			deleted, err := m.DeleteRole(ctx, tt.scope, tt.role)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}
			if deleted != tt.wantDeleted {
				t.Errorf("DeleteRole() deleted = %v, want %v", deleted, tt.wantDeleted)
			}
			if !tt.wantDeleted && len(store.roles) != rolesBefore {
				t.Errorf("DeleteRole() removed a role row on a call that deleted nothing")
			}
			exists, err := m.RoleExists(ctx, tt.scope, tt.role)
			if err != nil {
				t.Fatalf("RoleExists() error = %v", err)
			}
			if exists != tt.wantExists {
				t.Errorf("RoleExists() after DeleteRole = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

// Test_userManager_defaults_grantWrites pins that every grant write is refused
// on a default role, whose grants are the release's; is not found on a custom
// role held in every domain when addressed through one domain, since the row
// is not held there; and succeeds on a custom role in the scope that holds it.
func Test_userManager_defaults_grantWrites(t *testing.T) {
	t.Parallel()

	writes := []struct {
		name  string
		write func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error
	}{
		{name: "AddRolePermission", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.AddRolePermission(ctx, scope, role, "Read")
		}},
		{name: "AddRolePermissionResources", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.AddRolePermissionResources(ctx, scope, role, "Read", "Widgets")
		}},
		{name: "AddRoleGrant", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.AddRoleGrant(ctx, scope, role, "Read", "Widgets", "")
		}},
		{name: "AddRoleGrants", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.AddRoleGrants(ctx, scope, role, GrantRow{Permission: "Read", Resource: "Widgets"})
		}},
		{name: "ChangeRoleGrants", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.ChangeRoleGrants(ctx, scope, role, nil, []GrantRow{{Permission: "Read", Resource: "Widgets"}})
		}},
		{name: "DeleteRolePermission", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.DeleteRolePermission(ctx, scope, role, "Read")
		}},
		{name: "DeleteRolePermissionResources", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.DeleteRolePermissionResources(ctx, scope, role, "Read", "Widgets")
		}},
		{name: "DeleteRoleGrant", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.DeleteRoleGrant(ctx, scope, role, "Read", "Widgets", "")
		}},
		{name: "DeleteAllRolePermissions", write: func(ctx context.Context, m *userManager, scope accesstypes.PolicyScope, role accesstypes.Role) error {
			return m.DeleteAllRolePermissions(ctx, scope, role)
		}},
	}
	targets := []struct {
		name  string
		scope accesstypes.PolicyScope
		role  accesstypes.Role
		// wantErr is nil for a write that succeeds; a refused write leaves
		// the store's grant rows as they were.
		wantErr func(error) bool
	}{
		{name: "a domain default is refused as the release's", scope: tenant1Policy, role: domainDefault, wantErr: mentionsRelease},
		{name: "a domain default is refused in every domain too", scope: everyDomainPolicy, role: domainDefault, wantErr: mentionsRelease},
		{name: "a global default is refused as the release's", scope: globalPolicy, role: globalDefault, wantErr: mentionsRelease},
		{name: "a custom role held in every domain is not found through one domain", scope: tenant1Policy, role: "Everywhere", wantErr: httpio.HasNotFound},
		{name: "a custom role succeeds in the scope that holds it", scope: tenant1Policy, role: "Zed"},
		{name: "a custom role held in every domain succeeds there", scope: everyDomainPolicy, role: "Everywhere"},
	}
	for _, write := range writes {
		t.Run(write.name, func(t *testing.T) {
			t.Parallel()
			for _, target := range targets {
				t.Run(target.name, func(t *testing.T) {
					t.Parallel()
					ctx := t.Context()
					m, store := defaultsManager(t)
					grantsBefore := len(store.grants)

					err := write.write(ctx, m, target.scope, target.role)
					if target.wantErr == nil {
						if err != nil {
							t.Fatalf("%s() error = %v", write.name, err)
						}

						return
					}
					if err == nil || !target.wantErr(err) {
						t.Fatalf("%s() error = %v, want a refusal of the expected kind", write.name, err)
					}
					if len(store.grants) != grantsBefore {
						t.Errorf("%s() changed the store's grants on a refused call", write.name)
					}
				})
			}
		})
	}
}

// mentionsRelease reports whether a refusal says the role is the release's.
func mentionsRelease(err error) bool {
	return httpio.HasBadRequest(err) && strings.Contains(err.Error(), "release")
}

// Test_userManager_defaults_membership pins where a membership of each kind
// of role can be held — a domain default in one domain and in every domain, a
// global default in the global partition, a custom role where it is held or,
// from every domain, in one domain — and that UserRoles lists memberships
// keyed by where each is held, as stored.
func Test_userManager_defaults_membership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		op      func(ctx context.Context, m *userManager) error
		wantErr func(error) bool
		// wantAll is UserRoles with no scopes after op; askScopes and
		// wantByScope are UserRoles asked with scopes.
		wantAll     accesstypes.RoleCollection
		askScopes   []accesstypes.PolicyScope
		wantByScope accesstypes.RoleCollection
	}{
		{
			name: "AddRoleUsers holds a domain default's membership in one domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Policy, domainDefault, "dana")
			},
			wantAll:     accesstypes.RoleCollection{tenant1Policy: {domainDefault}},
			askScopes:   []accesstypes.PolicyScope{tenant1Policy, tenant2Policy},
			wantByScope: accesstypes.RoleCollection{tenant1Policy: {domainDefault}, tenant2Policy: {}},
		},
		{
			name: "AddRoleUsers holds a domain default's membership in every domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, everyDomainPolicy, domainDefault, "dana")
			},
			wantAll:     accesstypes.RoleCollection{everyDomainPolicy: {domainDefault}},
			askScopes:   []accesstypes.PolicyScope{everyDomainPolicy, tenant1Policy},
			wantByScope: accesstypes.RoleCollection{everyDomainPolicy: {domainDefault}, tenant1Policy: {}},
		},
		{
			name: "AddUserRoles holds a global default's membership in the global partition",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, globalPolicy, "dana", globalDefault)
			},
			wantAll:     accesstypes.RoleCollection{globalPolicy: {globalDefault}},
			askScopes:   []accesstypes.PolicyScope{globalPolicy},
			wantByScope: accesstypes.RoleCollection{globalPolicy: {globalDefault}},
		},
		{
			name: "AddUserRoles holds a domain default and an every-domain custom role together in every domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, everyDomainPolicy, "dana", domainDefault, "Everywhere")
			},
			wantAll:     accesstypes.RoleCollection{everyDomainPolicy: {"Everywhere", domainDefault}},
			askScopes:   []accesstypes.PolicyScope{everyDomainPolicy},
			wantByScope: accesstypes.RoleCollection{everyDomainPolicy: {"Everywhere", domainDefault}},
		},
		{
			name: "AddRoleUsers holds an every-domain custom role's membership in one domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant2Policy, "Everywhere", "dana")
			},
			wantAll:     accesstypes.RoleCollection{tenant2Policy: {"Everywhere"}},
			askScopes:   []accesstypes.PolicyScope{tenant2Policy},
			wantByScope: accesstypes.RoleCollection{tenant2Policy: {"Everywhere"}},
		},
		{
			name: "AddRoleUsers refuses an every-domain membership of a custom role held in one domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, everyDomainPolicy, "Zed", "dana")
			},
			wantErr: httpio.HasNotFound,
			wantAll: accesstypes.RoleCollection{},
		},
		{
			name: "AddUserRoles refuses it before writing any of the roles",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddUserRoles(ctx, everyDomainPolicy, "dana", domainDefault, "Zed")
			},
			wantErr: httpio.HasNotFound,
			wantAll: accesstypes.RoleCollection{},
		},
		{
			name: "AddRoleUsers refuses a global default in one domain",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, tenant1Policy, globalDefault, "dana")
			},
			wantErr: httpio.HasNotFound,
			wantAll: accesstypes.RoleCollection{},
		},
		{
			name: "AddRoleUsers refuses a domain default in the global partition",
			op: func(ctx context.Context, m *userManager) error {
				return m.AddRoleUsers(ctx, globalPolicy, domainDefault, "dana")
			},
			wantErr: httpio.HasNotFound,
			wantAll: accesstypes.RoleCollection{},
		},
		{
			name: "memberships held in several places list keyed by where each is held",
			op: func(ctx context.Context, m *userManager) error {
				if err := m.AddRoleUsers(ctx, tenant1Policy, "Zed", "dana"); err != nil {
					return err
				}
				if err := m.AddRoleUsers(ctx, everyDomainPolicy, domainDefault, "dana"); err != nil {
					return err
				}

				return m.AddUserRoles(ctx, globalPolicy, "dana", globalDefault)
			},
			wantAll: accesstypes.RoleCollection{
				tenant1Policy:     {"Zed"},
				everyDomainPolicy: {domainDefault},
				globalPolicy:      {globalDefault},
			},
			askScopes: []accesstypes.PolicyScope{tenant1Policy, tenant2Policy, everyDomainPolicy, globalPolicy},
			wantByScope: accesstypes.RoleCollection{
				tenant1Policy:     {"Zed"},
				tenant2Policy:     {},
				everyDomainPolicy: {domainDefault},
				globalPolicy:      {globalDefault},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			m, _ := defaultsManager(t)

			err := tt.op(ctx, m)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("op error = %v", err)
			case tt.wantErr != nil && (err == nil || !tt.wantErr(err)):
				t.Fatalf("op error = %v, want a refusal of the expected kind", err)
			}

			all, err := m.UserRoles(ctx, "dana")
			if err != nil {
				t.Fatalf("UserRoles() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantAll, all, cmpopts.EquateComparable(accesstypes.PolicyScope{})); diff != "" {
				t.Errorf("UserRoles() with no scopes (-want +got):\n%s", diff)
			}
			if tt.askScopes == nil {
				return
			}
			byScope, err := m.UserRoles(ctx, "dana", tt.askScopes...)
			if err != nil {
				t.Fatalf("UserRoles(scopes...) error = %v", err)
			}
			if diff := cmp.Diff(tt.wantByScope, byScope, cmpopts.EquateComparable(accesstypes.PolicyScope{})); diff != "" {
				t.Errorf("UserRoles(scopes...) (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_userManager_defaults_UserPermissions pins the effective listing: a
// membership of a domain default held in every domain reaches every tenant
// scope, one the store holds no row in included; one held in one domain
// reaches that domain alone; a global default reaches the global scope; and
// a request scope is required.
func Test_userManager_defaults_UserPermissions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	m, _ := defaultsManager(t)
	for _, seed := range []struct {
		scope accesstypes.PolicyScope
		user  accesstypes.User
		role  accesstypes.Role
	}{
		{everyDomainPolicy, "dana", domainDefault},
		{tenant1Policy, "erin", domainDefault},
		{globalPolicy, "gus", globalDefault},
	} {
		if err := m.AddUserRoles(ctx, seed.scope, seed.user, seed.role); err != nil {
			t.Fatalf("AddUserRoles(%q, %q, %q) error = %v", seed.scope, seed.user, seed.role, err)
		}
	}

	readsWidgets := accesstypes.UserScopePermissions{Resources: map[accesstypes.Resource][]accesstypes.Permission{
		"Widgets":      {"Read"},
		"Widgets.name": {"Read"},
	}}
	nothing := accesstypes.UserScopePermissions{Resources: map[accesstypes.Resource][]accesstypes.Permission{}}

	tests := []struct {
		name    string
		user    accesstypes.User
		scopes  []accesstypes.Scope
		want    accesstypes.UserPermissionCollection
		wantErr bool
	}{
		{
			name:   "a domain default held in every domain reaches every tenant scope",
			user:   "dana",
			scopes: []accesstypes.Scope{tenant1Scope, tenant2Scope, neverSeenScope},
			want: accesstypes.UserPermissionCollection{
				tenant1Scope:   readsWidgets,
				tenant2Scope:   readsWidgets,
				neverSeenScope: readsWidgets,
			},
		},
		{
			name:   "a domain default held in one domain reaches that domain alone",
			user:   "erin",
			scopes: []accesstypes.Scope{tenant1Scope, tenant2Scope},
			want: accesstypes.UserPermissionCollection{
				tenant1Scope: readsWidgets,
				tenant2Scope: nothing,
			},
		},
		{
			name:   "a global default held globally reaches the global scope and no tenant scope",
			user:   "gus",
			scopes: []accesstypes.Scope{accesstypes.GlobalScope(), tenant1Scope},
			want: accesstypes.UserPermissionCollection{
				accesstypes.GlobalScope(): {Resources: map[accesstypes.Resource][]accesstypes.Permission{"DoThing": {"Execute"}}},
				tenant1Scope:              nothing,
			},
		},
		{
			name:   "a user holding nothing is answered with empty entries",
			user:   "nobody",
			scopes: []accesstypes.Scope{tenant1Scope},
			want:   accesstypes.UserPermissionCollection{tenant1Scope: nothing},
		},
		{
			name:    "no request scope is an error",
			user:    "dana",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := m.UserPermissions(t.Context(), tt.user, tt.scopes...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UserPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateComparable(accesstypes.Scope{})); diff != "" {
				t.Errorf("UserPermissions() (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_userManager_defaults_RolePermissions pins the per-role listing in a
// request scope: a default role answers from the file where its kind reaches,
// a custom role answers its store grants where it is held or from every
// domain, and a role that does not exist in the scope is not found.
func Test_userManager_defaults_RolePermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		scope   accesstypes.Scope
		role    accesstypes.Role
		want    accesstypes.RolePermissionCollection
		wantErr func(error) bool
	}{
		{
			name:  "a domain default answers from the file in one domain",
			scope: tenant1Scope,
			role:  domainDefault,
			want:  accesstypes.RolePermissionCollection{"Read": {Resources: []accesstypes.Resource{"Widgets", "Widgets.name"}}},
		},
		{
			name:  "a domain default answers in a domain the store holds no row in",
			scope: neverSeenScope,
			role:  domainDefault,
			want:  accesstypes.RolePermissionCollection{"Read": {Resources: []accesstypes.Resource{"Widgets", "Widgets.name"}}},
		},
		{
			name:  "a global default answers from the file in the global scope",
			scope: accesstypes.GlobalScope(),
			role:  globalDefault,
			want:  accesstypes.RolePermissionCollection{"Execute": {Resources: []accesstypes.Resource{"DoThing"}}},
		},
		{
			name:  "a custom role answers its store grants where it is held",
			scope: tenant1Scope,
			role:  "Zed",
			want:  accesstypes.RolePermissionCollection{"Read": {Resources: []accesstypes.Resource{"Widgets"}}},
		},
		{
			name:  "a custom role held in every domain answers in any one domain",
			scope: tenant2Scope,
			role:  "Everywhere",
			want:  accesstypes.RolePermissionCollection{"Read": {Resources: []accesstypes.Resource{"Widgets"}}},
		},
		{name: "a role nothing defines is not found", scope: tenant1Scope, role: "Ghost", wantErr: httpio.HasNotFound},
		{name: "a domain default asked in the global scope is not found", scope: accesstypes.GlobalScope(), role: domainDefault, wantErr: httpio.HasNotFound},
		{name: "a global default asked in a domain is not found", scope: tenant1Scope, role: globalDefault, wantErr: httpio.HasNotFound},
		{name: "a custom role held in one domain is not found in another", scope: tenant2Scope, role: "Zed", wantErr: httpio.HasNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, _ := defaultsManager(t)

			got, err := m.RolePermissions(t.Context(), tt.scope, tt.role)
			if tt.wantErr != nil {
				if err == nil || !tt.wantErr(err) {
					t.Fatalf("RolePermissions() error = %v, want a refusal of the expected kind", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("RolePermissions() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RolePermissions() (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_userManager_defaults_RoleGrants pins the as-held listing with
// conditions: a default role's grants come from the file, unconditional rows
// under the empty condition; a custom role's come from the store where it is
// held, reachable through one domain when held in every domain; a role that
// does not exist in the scope is not found.
func Test_userManager_defaults_RoleGrants(t *testing.T) {
	t.Parallel()

	fileGrants := map[accesstypes.Permission]map[accesstypes.Resource][]string{
		"Read": {"Widgets": {""}, "Widgets.name": {""}},
	}
	tests := []struct {
		name    string
		scope   accesstypes.PolicyScope
		role    accesstypes.Role
		want    map[accesstypes.Permission]map[accesstypes.Resource][]string
		wantErr func(error) bool
	}{
		{name: "a domain default's grants are the file's in one domain", scope: tenant1Policy, role: domainDefault, want: fileGrants},
		{name: "a domain default's grants are the file's in every domain", scope: everyDomainPolicy, role: domainDefault, want: fileGrants},
		{
			name:  "a global default's grants are the file's in the global partition",
			scope: globalPolicy,
			role:  globalDefault,
			want:  map[accesstypes.Permission]map[accesstypes.Resource][]string{"Execute": {"DoThing": {""}}},
		},
		{
			name:  "a custom role answers its own rows with their conditions",
			scope: tenant1Policy,
			role:  "Zed",
			want:  map[accesstypes.Permission]map[accesstypes.Resource][]string{"Read": {"Widgets": {""}}},
		},
		{
			name:  "a custom role held in every domain answers through one domain",
			scope: tenant1Policy,
			role:  "Everywhere",
			want:  map[accesstypes.Permission]map[accesstypes.Resource][]string{"Read": {"Widgets": {"price < 10"}}},
		},
		{
			name:  "a custom role held in every domain answers there",
			scope: everyDomainPolicy,
			role:  "Everywhere",
			want:  map[accesstypes.Permission]map[accesstypes.Resource][]string{"Read": {"Widgets": {"price < 10"}}},
		},
		{name: "a role nothing defines is not found", scope: tenant1Policy, role: "Ghost", wantErr: httpio.HasNotFound},
		{name: "a domain default in the global partition is not found", scope: globalPolicy, role: domainDefault, wantErr: httpio.HasNotFound},
		{name: "a custom role held in one domain is not found in every domain", scope: everyDomainPolicy, role: "Zed", wantErr: httpio.HasNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, _ := defaultsManager(t)

			got, err := m.RoleGrants(t.Context(), tt.scope, tt.role)
			if tt.wantErr != nil {
				if err == nil || !tt.wantErr(err) {
					t.Fatalf("RoleGrants() error = %v, want a refusal of the expected kind", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("RoleGrants() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RoleGrants() (-want +got):\n%s", diff)
			}
		})
	}
}
