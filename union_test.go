package access

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cccteam/ccc/accesstypes"
)

// stubCollection is a PermissionCollection whose every answer is table data: the
// registry, per-resource scopes (Domain when unlisted), and the resources marked
// immutable or computed or given a method target, plus a vocabulary keyed
// "Resource.attribute".
type stubCollection struct {
	list          map[accesstypes.Permission][]accesstypes.Resource
	scopes        map[accesstypes.Resource]accesstypes.PermissionScope
	immutable     []accesstypes.Resource
	computed      []accesstypes.Resource
	targets       map[accesstypes.Resource]accesstypes.Resource
	attributes    map[string]accesstypes.AttributeType
	columns       []string
	subjectSets   []string
	subjectValues []string
}

func (s *stubCollection) List() map[accesstypes.Permission][]accesstypes.Resource {
	return s.list
}

func (s *stubCollection) Scope(res accesstypes.Resource) accesstypes.PermissionScope {
	if scope, ok := s.scopes[res]; ok {
		return scope
	}

	return accesstypes.DomainPermissionScope
}

func (s *stubCollection) IsResourceImmutable(_ accesstypes.PermissionScope, res accesstypes.Resource) bool {
	return slices.Contains(s.immutable, res)
}

func (s *stubCollection) IsComputedResource(_ accesstypes.PermissionScope, res accesstypes.Resource) bool {
	return slices.Contains(s.computed, res)
}

func (s *stubCollection) MethodTarget(_ accesstypes.PermissionScope, method accesstypes.Resource) (accesstypes.Resource, bool) {
	target, ok := s.targets[method]

	return target, ok
}

func (s *stubCollection) AttributeComparisonType(_ accesstypes.PermissionScope, res accesstypes.Resource, name string) (accesstypes.AttributeType, bool) {
	typ, ok := s.attributes[string(res)+"."+name]

	return typ, ok
}

func (s *stubCollection) AttributeIsColumn(_ accesstypes.PermissionScope, res accesstypes.Resource, name string) bool {
	return slices.Contains(s.columns, string(res)+"."+name)
}

func (s *stubCollection) DeclaresSubjectSet(name string) bool {
	return slices.Contains(s.subjectSets, name)
}

func (s *stubCollection) DeclaresSubjectValue(name string) bool {
	return slices.Contains(s.subjectValues, name)
}

// registry spells a List result from (permission, resource) pairs.
func registry(pairs ...string) map[accesstypes.Permission][]accesstypes.Resource {
	if len(pairs)%2 != 0 {
		panic("registry takes (permission, resource) pairs")
	}
	list := make(map[accesstypes.Permission][]accesstypes.Resource)
	for len(pairs) >= 2 {
		perm, res := accesstypes.Permission(pairs[0]), accesstypes.Resource(pairs[1])
		list[perm] = append(list[perm], res)
		pairs = pairs[2:]
	}

	return list
}

func Test_UnionCollection(t *testing.T) {
	t.Parallel()

	console := &stubCollection{
		list:      registry("Read", "Widgets", "List", "Widgets", "Read", "Widgets.name", "Update", "Widgets.name", "Read", "Widgets.id", "Execute", "LaunchWidget"),
		immutable: []accesstypes.Resource{"Widgets.id"},
		targets:   map[accesstypes.Resource]accesstypes.Resource{"LaunchWidget": "Widgets"},
	}
	portal := &stubCollection{
		list:     registry("Read", "Gadgets", "Read", "Gadgets.label"),
		computed: []accesstypes.Resource{"Gadgets"},
	}
	// consoleAgain declares Widgets exactly as console does, with extra resources of its own.
	consoleAgain := &stubCollection{
		list:      registry("List", "Widgets", "Read", "Widgets", "Update", "Widgets.name", "Read", "Widgets.name", "Read", "Widgets.id", "Execute", "LaunchWidget", "Read", "Sprockets"),
		immutable: []accesstypes.Resource{"Widgets.id"},
		targets:   map[accesstypes.Resource]accesstypes.Resource{"LaunchWidget": "Widgets"},
	}
	withDifferent := func(change func(*stubCollection)) *stubCollection {
		c := &stubCollection{
			list:      registry("Read", "Widgets", "List", "Widgets", "Read", "Widgets.name", "Update", "Widgets.name", "Read", "Widgets.id", "Execute", "LaunchWidget"),
			immutable: []accesstypes.Resource{"Widgets.id"},
			targets:   map[accesstypes.Resource]accesstypes.Resource{"LaunchWidget": "Widgets"},
		}
		change(c)

		return c
	}

	tests := []struct {
		name        string
		collections []PermissionCollection
		wantList    map[accesstypes.Permission][]accesstypes.Resource
		wantErr     string
	}{
		{
			name:    "no collections",
			wantErr: "at least one collection is required",
		},
		{
			name:        "one collection lists as itself, sorted",
			collections: []PermissionCollection{console},
			wantList: map[accesstypes.Permission][]accesstypes.Resource{
				"Read":    {"Widgets", "Widgets.id", "Widgets.name"},
				"List":    {"Widgets"},
				"Update":  {"Widgets.name"},
				"Execute": {"LaunchWidget"},
			},
		},
		{
			name:        "disjoint collections merge",
			collections: []PermissionCollection{console, portal},
			wantList: map[accesstypes.Permission][]accesstypes.Resource{
				"Read":    {"Gadgets", "Gadgets.label", "Widgets", "Widgets.id", "Widgets.name"},
				"List":    {"Widgets"},
				"Update":  {"Widgets.name"},
				"Execute": {"LaunchWidget"},
			},
		},
		{
			name:        "a resource declared identically twice appears once",
			collections: []PermissionCollection{console, consoleAgain},
			wantList: map[accesstypes.Permission][]accesstypes.Resource{
				"Read":    {"Sprockets", "Widgets", "Widgets.id", "Widgets.name"},
				"List":    {"Widgets"},
				"Update":  {"Widgets.name"},
				"Execute": {"LaunchWidget"},
			},
		},
		{
			name: "different permissions on a shared resource",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.list = registry("Read", "Widgets", "Read", "Widgets.name", "Update", "Widgets.name", "Read", "Widgets.id", "Execute", "LaunchWidget")
			})},
			wantErr: `collections 1 and 2 (in argument order) both register resource "Widgets" and disagree on its permissions: [List Read] vs [Read]`,
		},
		{
			name: "a field only one collection declares is a permissions disagreement on the field",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.list = registry("Read", "Widgets", "List", "Widgets", "Read", "Widgets.name", "Read", "Widgets.id", "Execute", "LaunchWidget")
			})},
			wantErr: `resource "Widgets.name" and disagree on its permissions: [Read Update] vs [Read]`,
		},
		{
			name: "different scope",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.scopes = map[accesstypes.Resource]accesstypes.PermissionScope{"Widgets": accesstypes.GlobalPermissionScope}
			})},
			wantErr: `resource "Widgets" and disagree on its scope: "domain" vs "global"`,
		},
		{
			name: "different immutability on a field",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.immutable = nil
			})},
			wantErr: `resource "Widgets.id" and disagree on its immutability: true vs false`,
		},
		{
			name: "different computed marking",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.computed = []accesstypes.Resource{"Widgets"}
			})},
			wantErr: `resource "Widgets" and disagree on its computed marking: false vs true`,
		},
		{
			name: "different method target",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.targets = map[accesstypes.Resource]accesstypes.Resource{"LaunchWidget": "Gadgets"}
			})},
			wantErr: `resource "LaunchWidget" and disagree on its method target: "Widgets" vs "Gadgets"`,
		},
		{
			name: "a target only one collection declares",
			collections: []PermissionCollection{console, withDifferent(func(c *stubCollection) {
				c.targets = nil
			})},
			wantErr: `resource "LaunchWidget" and disagree on its method target: "Widgets" vs none`,
		},
		{
			name:        "the disagreeing collections are named by position, not by adjacency",
			collections: []PermissionCollection{portal, console, withDifferent(func(c *stubCollection) { c.immutable = nil })},
			wantErr:     `collections 2 and 3 (in argument order) both register resource "Widgets.id"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := UnionCollection(tt.collections...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnionCollection() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("UnionCollection() error = %v", err)
			}
			if list := got.List(); !reflect.DeepEqual(list, tt.wantList) {
				t.Errorf("List() = %v, want %v", list, tt.wantList)
			}
		})
	}
}

func Test_unionCollection_answers(t *testing.T) {
	t.Parallel()

	console := &stubCollection{
		list:          registry("Read", "Widgets", "Read", "Widgets.id", "Execute", "LaunchWidget"),
		immutable:     []accesstypes.Resource{"Widgets.id"},
		targets:       map[accesstypes.Resource]accesstypes.Resource{"LaunchWidget": "Widgets"},
		attributes:    map[string]accesstypes.AttributeType{"Widgets.owner": "string"},
		columns:       []string{"Widgets.owner"},
		subjectSets:   []string{"crew"},
		subjectValues: []string{"login"},
	}
	portal := &stubCollection{
		list:          registry("Read", "Gadgets", "Read", "Gadgets.label"),
		scopes:        map[accesstypes.Resource]accesstypes.PermissionScope{"Gadgets": accesstypes.GlobalPermissionScope},
		computed:      []accesstypes.Resource{"Gadgets"},
		attributes:    map[string]accesstypes.AttributeType{"Gadgets.size": "int"},
		columns:       []string{"Gadgets.size"},
		subjectSets:   []string{"clients"},
		subjectValues: []string{"tenant"},
	}
	union, err := UnionCollection(console, portal)
	if err != nil {
		t.Fatalf("UnionCollection() error = %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "scope from the owner", got: union.Scope("Gadgets"), want: accesstypes.GlobalPermissionScope},
		{name: "scope of an unregistered resource from the first collection", got: union.Scope("Nothing"), want: accesstypes.DomainPermissionScope},
		{name: "immutability from the owner", got: union.IsResourceImmutable(accesstypes.DomainPermissionScope, "Widgets.id"), want: true},
		{name: "computed marking from the owner", got: union.IsComputedResource(accesstypes.GlobalPermissionScope, "Gadgets"), want: true},
		{name: "not computed when the owner says so", got: union.IsComputedResource(accesstypes.DomainPermissionScope, "Widgets"), want: false},
		{name: "attribute type from the owner", got: attributeType(union, "Gadgets", "size"), want: "int"},
		{name: "attribute unknown outside the owner", got: attributeType(union, "Widgets", "size"), want: ""},
		{name: "attribute column from the owner", got: union.AttributeIsColumn(accesstypes.DomainPermissionScope, "Widgets", "owner"), want: true},
		{name: "subject set from any collection", got: union.DeclaresSubjectSet("clients") && union.DeclaresSubjectSet("crew"), want: true},
		{name: "subject set none declares", got: union.DeclaresSubjectSet("visitors"), want: false},
		{name: "subject value from any collection", got: union.DeclaresSubjectValue("tenant") && union.DeclaresSubjectValue("login"), want: true},
		{name: "method target from the owner", got: methodTarget(union, "LaunchWidget"), want: "Widgets"},
		{name: "no target for a plain resource", got: methodTarget(union, "Widgets"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

// attributeType reads a union's attribute type as a plain string, "" when unknown.
func attributeType(c PermissionCollection, res accesstypes.Resource, name string) string {
	typ, _ := c.AttributeComparisonType(c.Scope(res), res, name)

	return string(typ)
}

// methodTarget reads a union's method target as a plain string, "" when undeclared.
func methodTarget(c PermissionCollection, method accesstypes.Resource) string {
	target, _ := c.MethodTarget(c.Scope(method), method)

	return string(target)
}

// Test_unionCollection_ListIsACopy pins that a caller mutating the listed registry does
// not reach into the union.
func Test_unionCollection_ListIsACopy(t *testing.T) {
	t.Parallel()

	union, err := UnionCollection(&stubCollection{list: registry("Read", "Widgets")})
	if err != nil {
		t.Fatalf("UnionCollection() error = %v", err)
	}
	first := union.List()
	first["Read"][0] = "Changed"
	first["Write"] = []accesstypes.Resource{"Widgets"}
	if got := union.List(); !reflect.DeepEqual(got, registry("Read", "Widgets")) {
		t.Errorf("List() after mutation = %v, want the original registry", got)
	}
}
