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

func (grammarCollection) IsComputedResource(accesstypes.PermissionScope, accesstypes.Resource) bool {
	return false
}

func (grammarCollection) MethodTarget(accesstypes.PermissionScope, accesstypes.Resource) (accesstypes.Resource, bool) {
	return "", false
}

// computedGrammarCollection is grammarCollection with Widgets reported as a
// computed resource, so the decode-time condition rules can be exercised
// against the same attribute vocabulary.
type computedGrammarCollection struct{ grammarCollection }

func (computedGrammarCollection) IsComputedResource(_ accesstypes.PermissionScope, res accesstypes.Resource) bool {
	return res == "Widgets"
}

// targetedGrammarCollection is grammarCollection with DoThing reporting a
// @target row (Widgets), so the targeted-Execute condition rules can be
// exercised against the target's attribute vocabulary.
type targetedGrammarCollection struct{ grammarCollection }

func (targetedGrammarCollection) MethodTarget(_ accesstypes.PermissionScope, method accesstypes.Resource) (accesstypes.Resource, bool) {
	if method == "DoThing" {
		return "Widgets", true
	}

	return "", false
}

func TestExpandRoleGrants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		perm     accesstypes.Permission
		grants   []Grant
		declared accesstypes.PermissionScope
		want     grantSet
		wantErr  string
	}{
		{
			name:   "a grant expands into base and field rows sharing the condition",
			perm:   "Read",
			grants: []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name", "price"}, Condition: "owner = subject"}},
			want: grantSet{"Read": {
				"Widgets":       "owner = subject",
				"Widgets.name":  "owner = subject",
				"Widgets.price": "owner = subject",
			}},
		},
		{
			name:   "an unconditional grant expands with empty conditions",
			perm:   "Read",
			grants: []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}},
			want:   grantSet{"Read": {"Widgets": "", "Widgets.name": ""}},
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
			name:   "a bare dotted resource is a legal mechanical grant",
			perm:   "Read",
			grants: []Grant{{Resource: "Widgets.name"}},
			want:   grantSet{"Read": {"Widgets.name": ""}},
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
		{
			name:     "a global-resource grant in a domain role is rejected",
			perm:     "Execute",
			grants:   []Grant{{Resource: "DoThing"}},
			declared: accesstypes.DomainPermissionScope,
			wantErr:  "a role's grants live at its declared scope",
		},
		{
			name:     "a domain-resource grant in a global role is rejected",
			perm:     "Read",
			grants:   []Grant{{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}}},
			declared: accesstypes.GlobalPermissionScope,
			wantErr:  "a role's grants live at its declared scope",
		},
		{
			name:     "a global-resource grant in a global role expands",
			perm:     "Execute",
			grants:   []Grant{{Resource: "DoThing"}},
			declared: accesstypes.GlobalPermissionScope,
			want:     grantSet{"Execute": {"DoThing": ""}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			declared := tt.declared
			if declared == "" {
				declared = accesstypes.DomainPermissionScope
			}
			role := &Role{Name: "Tester", Permissions: map[accesstypes.Permission][]Grant{tt.perm: tt.grants}}
			got, err := expandRoleGrants(grammarCollection{}, role, declared)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expandRoleGrants() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("expandRoleGrants() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("expandRoleGrants() mismatch (-want +got):\n%s", diff)
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

func TestValidateGrantCondition_targetedExecute(t *testing.T) {
	t.Parallel()

	// A @target-bearing method's generated handler locates its row inside the
	// transaction (design plan §12), so its Execute grants may reference the
	// row — bindings, subject values, and literal types all validate against
	// the TARGET resource's vocabulary, never the method's.
	tests := []struct {
		name      string
		condition string
		wantErr   string
	}{
		{name: "row-referencing condition is permitted", condition: "owner = subject"},
		{name: "subject-value threshold is permitted", condition: "price <= subject.approvalLimit"},
		{name: "row-free condition still folds at decode", condition: "now < '2027-01-01T00:00:00Z'"},
		{name: "unknown attribute names the target resource", condition: "ghost = subject", wantErr: "not an attribute of Widgets"},
		{name: "literal types validate against the target", condition: "price = 'cheap'", wantErr: "cannot compare against the string"},
		{name: "post-image stays rejected on Execute", condition: "new.price <= 100", wantErr: "post-image"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			grant := Grant{Resource: "DoThing", Condition: tt.condition}
			err := validateGrantCondition(targetedGrammarCollection{}, "Tester", "Execute", grant)
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

func TestValidateGrantCondition_computedIsDecodeTime(t *testing.T) {
	t.Parallel()

	// A computed resource's checks run at decode, exactly like Execute: only
	// row-free conditions can settle there, whatever the permission.
	tests := []struct {
		name      string
		condition string
		wantErr   bool
	}{
		{name: "row-referencing condition is rejected", condition: "owner = subject", wantErr: true},
		{name: "subject-value condition is rejected", condition: "price <= subject.approvalLimit", wantErr: true},
		{name: "row-free condition is permitted", condition: "now < '2027-01-01T00:00:00Z'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			grant := Grant{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}, Condition: tt.condition}
			err := validateGrantCondition(computedGrammarCollection{}, "Tester", "Read", grant)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "decode time") {
					t.Fatalf("validateGrantCondition() error = %v, want the decode-time rejection", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("validateGrantCondition() error = %v", err)
			}
		})
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
		config := &RoleConfig{Roles: ScopedRoles{Domain: []*Role{{
			Name: "Reader",
			Permissions: map[accesstypes.Permission][]Grant{
				"Read": {{Resource: "Widgets", Fields: []accesstypes.Tag{"name"}, Condition: condition}},
			},
		}}}}
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
