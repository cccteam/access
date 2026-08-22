package postgresstore

import (
	"context"
	"strings"
	"testing"

	"github.com/cccteam/access/internal/storetest"
)

func TestNew_naming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      []Option
		wantTable string
		wantErr   bool
	}{
		{name: "defaults", wantTable: `"AccessRoles"`},
		{name: "store name", opts: []Option{WithStore("AdminPortal")}, wantTable: `"AccessAdminPortalRoles"`},
		{name: "prefix override", opts: []Option{WithPrefix("Acl"), WithStore("Portal")}, wantTable: `"AclPortalRoles"`},
		{name: "invalid prefix", opts: []Option{WithPrefix("bad prefix")}, wantErr: true},
		{name: "empty prefix", opts: []Option{WithPrefix("")}, wantErr: true},
		{name: "invalid store name", opts: []Option{WithStore("drop table")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, err := New(nil, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			ddl := strings.Join(store.DDL(), "\n")
			if !strings.Contains(ddl, "CREATE TABLE "+tt.wantTable+" (") {
				t.Errorf("DDL() does not create table %s:\n%s", tt.wantTable, ddl)
			}
		})
	}
}

func TestStore_conformance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store, _ := prepareStore(ctx, t)
	storetest.Run(t, store)
}

func TestStore_conformance_namedStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store, _ := prepareStore(ctx, t, WithStore("AdminPortal"))
	storetest.Run(t, store)
}

// TestStore_isolation proves separate stores in one database cannot see each
// other's rows: cross-store leakage is structurally impossible, not filtered.
func TestStore_isolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	adminStore, db := prepareStore(ctx, t, WithStore("AdminPortal"))
	partnerStore, err := New(db.Pool, WithStore("PartnerPortal"))
	if err != nil {
		t.Fatalf("postgresstore.New(): %v", err)
	}
	if err := applyDDL(ctx, db, partnerStore); err != nil {
		t.Fatalf("applying DDL: %v", err)
	}

	if err := adminStore.InsertRole(ctx, "tenant1", "Editor"); err != nil {
		t.Fatalf("InsertRole() error = %v", err)
	}
	if err := adminStore.InsertUserRole(ctx, "tenant1", "alice", "Editor"); err != nil {
		t.Fatalf("InsertUserRole() error = %v", err)
	}

	if exists, err := partnerStore.RoleExists(ctx, "tenant1", "Editor"); err != nil || exists {
		t.Errorf("RoleExists() on sibling store = (%v, %v), want (false, nil)", exists, err)
	}
	records, err := partnerStore.ReadPolicy(ctx)
	if err != nil {
		t.Fatalf("ReadPolicy() error = %v", err)
	}
	if len(records.Grants) != 0 || len(records.Memberships) != 0 {
		t.Errorf("ReadPolicy() on sibling store returned rows: %+v", records)
	}
}
