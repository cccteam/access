package access

// These tests pin the conditional-grant RoleConfig grammar: the grant object
// (resource + field set + one condition) as the authoring unit, its expansion
// into base and field grant rows sharing the condition (the construction
// invariant), deploy-time condition validation against the Collection's
// vocabulary, and condition-aware reconciliation (a changed condition text is
// remove + re-add).

import (
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
	"github.com/google/go-cmp/cmp"
)

// grammarCollection is the fixture vocabulary: one domain-scoped resource
// with typed attributes, and one global execute-only method.
type grammarCollection struct{}

func (grammarCollection) List() map[accesstypes.Permission][]accesstypes.Resource {
	return map[accesstypes.Permission][]accesstypes.Resource{
		"Read":    {"Widgets", "Widgets.name", "Widgets.price"},
		"Update":  {"Widgets", "Widgets.price"},
		"Delete":  {"Widgets"},
		"Execute": {"DoThing"},
	}
}

func (grammarCollection) Scope(res accesstypes.Resource) accesstypes.PermissionScope {
	switch {
	case res == "DoThing":
		return accesstypes.GlobalPermissionScope
	case strings.HasPrefix(string(res), "Widgets"):
		return accesstypes.DomainPermissionScope
	default:
		return ""
	}
}

func (grammarCollection) IsResourceImmutable(accesstypes.PermissionScope, accesstypes.Resource) bool {
	return false
}

func (grammarCollection) AttributeComparisonType(_ accesstypes.PermissionScope, res accesstypes.Resource, name string) (accesstypes.AttributeType, bool) {
	if res != "Widgets" {
		return "", false
	}
	switch name {
	case "owner", "shipClass":
		return accesstypes.AttributeTypeString, true
	case "price":
		return accesstypes.AttributeTypeNumber, true
	case "expires":
		return accesstypes.AttributeTypeTimestamp, true
	case "archived":
		return accesstypes.AttributeTypeBool, true
	case "released":
		return accesstypes.AttributeTypeDate, true
	default:
		return "", false
	}
}

func (grammarCollection) AttributeIsColumn(_ accesstypes.PermissionScope, res accesstypes.Resource, name string) bool {
	// shipClass is the fixture's join-path attribute; everything else is a
	// column on the row.
	return res == "Widgets" && name != "shipClass"
}

func (grammarCollection) DeclaresSubjectSet(name string) bool { return name == "crews" }

func (grammarCollection) DeclaresSubjectValue(name string) bool { return name == "approvalLimit" }

func TestExpandRoleGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		perm       accesstypes.Permission
		grants     []Grant
		wantDomain grantSet
		wantErr    string
	}{
		{
			name:   "a grant expands into base and field rows sharing the condition",
			perm:   "Read",
			grants: []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name", "price"}, Condition: "owner = subject"}},
			wantDomain: grantSet{"Read": {
				"Widgets":       "owner = subject",
				"Widgets.name":  "owner = subject",
				"Widgets.price": "owner = subject",
			}},
		},
		{
			name:       "an unconditional grant expands with empty conditions",
			perm:       "Read",
			grants:     []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}},
			wantDomain: grantSet{"Read": {"Widgets": "", "Widgets.name": ""}},
		},
		{
			name:    "two grants on one resource are rejected",
			perm:    "Read",
			grants:  []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}, {Resource: "Widgets", Fields: []accesstypes.Tag{"price"}}},
			wantErr: "exactly once",
		},
		{
			name:    "a dotted resource takes no fields or condition",
			perm:    "Read",
			grants:  []Grant{{Resource: "Widgets.name", Condition: "owner = subject"}},
			wantErr: "dotted field resource",
		},
		{
			name:       "a bare dotted resource is a legal mechanical grant",
			perm:       "Read",
			grants:     []Grant{{Resource: "Widgets.name"}},
			wantDomain: grantSet{"Read": {"Widgets.name": ""}},
		},
		{
			name:    "an unregistered field is rejected",
			perm:    "Read",
			grants:  []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"nope"}}},
			wantErr: "does not require permission",
		},
		{
			name:    "a field outside the permission's registrations is rejected",
			perm:    "Update",
			grants:  []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}},
			wantErr: "does not require permission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			role := &Role{Name: "Tester", Permissions: map[accesstypes.Permission][]Grant{tt.perm: tt.grants}}
			_, domain, err := expandRoleGrants(grammarCollection{}, role)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expandRoleGrants() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("expandRoleGrants() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantDomain, domain); diff != "" {
				t.Errorf("expandRoleGrants() domain mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateGrantCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		perm      accesstypes.Permission
		condition string
		wantErr   string
	}{
		{name: "subject fact against a string attribute", perm: "Read", condition: "owner = subject"},
		{name: "typed literals across the vocabulary", perm: "Read", condition: "price < 10 AND archived = FALSE AND expires > '2026-01-01T00:00:00Z' AND released >= '2026-01-01'"},
		{name: "now against a timestamp attribute", perm: "Read", condition: "expires > now"},
		{name: "now against a timestamp literal", perm: "Read", condition: "now < '2027-01-01T00:00:00Z'"},
		{name: "subject set and subject value", perm: "Read", condition: "owner IN subject.crews AND price <= subject.approvalLimit"},
		{name: "post-image on update", perm: "Update", condition: "new.price <= 100"},
		{name: "literal list on a number attribute", perm: "Read", condition: "price IN (1, 2, 3)"},

		{name: "unparseable condition", perm: "Read", condition: "owner = = subject", wantErr: "expected an operand"},
		{name: "unknown attribute", perm: "Read", condition: "ghost = subject", wantErr: "not an attribute"},
		{name: "unknown subject set", perm: "Read", condition: "owner IN subject.ghosts", wantErr: "not a declared subject set"},
		{name: "unknown subject value", perm: "Read", condition: "price <= subject.ghostLimit", wantErr: "not a declared subject value"},
		{name: "post-image on read", perm: "Read", condition: "new.price <= 100", wantErr: "post-image"},
		{name: "post-image of a join-path attribute", perm: "Update", condition: "new.shipClass = 'Freighter'", wantErr: "join-path"},
		{name: "string literal against a number attribute", perm: "Read", condition: "price = 'cheap'", wantErr: "cannot compare against the string"},
		{name: "number literal against a string attribute", perm: "Read", condition: "owner = 3", wantErr: "cannot compare against the number"},
		{name: "malformed timestamp literal", perm: "Read", condition: "expires > 'yesterday'", wantErr: "RFC 3339"},
		{name: "malformed date literal", perm: "Read", condition: "released = '2026-99-99'", wantErr: "YYYY-MM-DD"},
		{name: "boolean literal against a string attribute", perm: "Read", condition: "owner = TRUE", wantErr: "boolean"},
		{name: "subject against a number attribute", perm: "Read", condition: "price = subject", wantErr: "user id"},
		{name: "now against a string attribute", perm: "Read", condition: "owner < now", wantErr: "timestamp"},
		{name: "malformed timestamp against now", perm: "Read", condition: "now < 'soon'", wantErr: "RFC 3339"},
		{name: "list literal type mismatch", perm: "Read", condition: "price IN (1, 'two')", wantErr: "cannot compare against the string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			grant := Grant{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}, Condition: tt.condition}
			err := validateGrantCondition(grammarCollection{}, "Tester", tt.perm, grant)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateGrantCondition() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("validateGrantCondition() error = %v", err)
			}
		})
	}
}

func TestValidateGrantCondition_executeIsDecodeTime(t *testing.T) {
	t.Parallel()

	// Row-referencing conditions cannot evaluate at decode; row-free
	// conditions fold against the environment facts and are permitted.
	rowBound := Grant{Resource: "DoThing", Condition: "owner = subject"}
	err := validateGrantCondition(grammarCollection{}, "Tester", "Execute", rowBound)
	if err == nil || !strings.Contains(err.Error(), "decode time") {
		t.Fatalf("validateGrantCondition(row-referencing) error = %v, want the decode-time rejection", err)
	}

	rowFree := Grant{Resource: "DoThing", Condition: "now < '2027-01-01T00:00:00Z'"}
	if err := validateGrantCondition(grammarCollection{}, "Tester", "Execute", rowFree); err != nil {
		t.Fatalf("validateGrantCondition(row-free) error = %v, want nil", err)
	}
}

// TestMigrateRoles_conditionReconciliation runs the full migration against the
// fake store: conditions land on every expanded row, an unchanged
// configuration is a no-op, a changed condition text re-lands, and dropping
// the condition clears it.
func TestMigrateRoles_conditionReconciliation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	manager := newUserManager(newStoreManager(newFakeStore()))

	migrate := func(condition string) {
		t.Helper()
		config := &RoleConfig{Roles: []*Role{{
			Name: "Reader",
			Permissions: map[accesstypes.Permission][]Grant{
				"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}, Condition: condition}},
			},
		}}}
		if err := MigrateRoles(ctx, manager, grammarCollection{}, config, "tenant1"); err != nil {
			t.Fatalf("MigrateRoles() error = %v", err)
		}
	}

	scope := accesstypes.DomainScope("tenant1")

	migrate("owner = subject")
	grants, err := manager.RoleGrants(ctx, scope, "Reader")
	if err != nil {
		t.Fatalf("RoleGrants() error = %v", err)
	}
	want := map[accesstypes.Permission]map[accesstypes.Resource]string{
		"Read": {"Widgets": "owner = subject", "Widgets.name": "owner = subject"},
	}
	if diff := cmp.Diff(want, grants); diff != "" {
		t.Errorf("RoleGrants() after first migration mismatch (-want +got):\n%s", diff)
	}

	migrate("price < 10")
	grants, err = manager.RoleGrants(ctx, scope, "Reader")
	if err != nil {
		t.Fatalf("RoleGrants() error = %v", err)
	}
	want = map[accesstypes.Permission]map[accesstypes.Resource]string{
		"Read": {"Widgets": "price < 10", "Widgets.name": "price < 10"},
	}
	if diff := cmp.Diff(want, grants); diff != "" {
		t.Errorf("RoleGrants() after condition change mismatch (-want +got):\n%s", diff)
	}

	migrate("")
	grants, err = manager.RoleGrants(ctx, scope, "Reader")
	if err != nil {
		t.Fatalf("RoleGrants() error = %v", err)
	}
	want = map[accesstypes.Permission]map[accesstypes.Resource]string{
		"Read": {"Widgets": "", "Widgets.name": ""},
	}
	if diff := cmp.Diff(want, grants); diff != "" {
		t.Errorf("RoleGrants() after dropping the condition mismatch (-want +got):\n%s", diff)
	}
}
