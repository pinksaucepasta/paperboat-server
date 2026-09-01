package environment

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPostgresScopeInventoryIncludesRetiredScopesInCanonicalOrder(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the ENV scope inventory proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	accountID := "envinventoryuser_" + suffix
	defer store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID) //nolint:errcheck -- test cleanup
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, accountID, "workos_"+suffix, suffix+"@inventory.invalid"); err != nil {
		t.Fatal(err)
	}
	for _, machineID := range []string{"machine_a_" + suffix, "machine_z_" + suffix} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles) VALUES($1,$2,$3,$4,'linux','amd64','/inventory','offline','released','host',ARRAY['host'])`, machineID, accountID, "environment_"+machineID, "ENV inventory "+machineID); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	scopes := []struct {
		id, scope, machineID, state, manifestID string
		version, epoch                          int64
	}{
		{"scope_global_" + suffix, ScopeGlobal, "", "active", digest("1"), 8, 3},
		{"scope_z_" + suffix, ScopeMachine, "machine_z_" + suffix, "retired", digest("2"), 11, 6},
		{"scope_a_" + suffix, ScopeMachine, "machine_a_" + suffix, "active", digest("3"), 4, 2},
	}
	for _, scope := range scopes {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scopes(id,account_id,scope,machine_id,scope_state,version,key_epoch,authority_generation,authority_id,manifest_id) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,1,$8,$9)`, scope.id, accountID, scope.scope, scope.machineID, scope.state, scope.version, scope.epoch, digest("a"), scope.manifestID); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ZETA", "ALPHA"} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scope_names(scope_id,name) VALUES($1,$2)`, scopes[0].id, name); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err := NewService(store, nil, nil).ListScopes(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Schema != "paperboat.environment-scope-inventory/v1" || len(inventory.Scopes) != 3 {
		t.Fatalf("inventory=%+v", inventory)
	}
	if inventory.Scopes[0].Scope != ScopeGlobal || inventory.Scopes[1].MachineID != "machine_a_"+suffix || inventory.Scopes[2].MachineID != "machine_z_"+suffix || inventory.Scopes[2].ScopeState != "retired" {
		t.Fatalf("inventory order/state=%+v", inventory.Scopes)
	}
	if !reflect.DeepEqual(inventory.Scopes[0].Names, []string{"ALPHA", "ZETA"}) || inventory.Scopes[1].Names == nil || inventory.Scopes[2].Names == nil {
		t.Fatalf("inventory names=%+v", inventory.Scopes)
	}
}
