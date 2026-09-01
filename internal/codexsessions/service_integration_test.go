package codexsessions

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestCreateSelectsAdmittedRuntimeConnector(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Codex-session integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_")) + time.Now().UTC().Format("150405000000000")
	userID := "codex_user_" + suffix
	clientID := "codex_cli_" + suffix
	environmentID := "codex_env_" + suffix
	machineID := "codex_machine_" + suffix
	nodeID := "codex_edge_" + suffix
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_environments WHERE id=$1`, environmentID)
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, userID)
	})

	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, []any{userID, "workos_" + userID, userID + "@example.test"}},
		{`INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,'Codex test','desktop','test',ARRAY['account:read'],'active',$4,$4)`, []any{clientID, userID, "client_" + suffix, time.Now().UTC()}},
		{`INSERT INTO paperboat.control_environments (id,workspace_id,owner_user_id) VALUES ($1,$2,$3)`, []any{environmentID, "workspace_" + suffix, userID}},
		{`INSERT INTO paperboat.control_tunnel_nodes (id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES ($1,'test','v1',$2,'ready',true,now())`, []any{nodeID, "epoch_" + suffix}},
		{`INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation,configured_capabilities,observed_capabilities) VALUES ($1,$2,$3,'Codex machine','linux','amd64','/workspace','online','occupied',true,7,ARRAY['terminal_host','codex_host'],ARRAY['terminal_host','codex_host'])`, []any{machineID, userID, environmentID}},
		{`INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,connector_id,generation,edge_pool,state) VALUES ($1,$2,'000-preview',99,'test','pending')`, []any{environmentID, machineID}},
		{`INSERT INTO paperboat.control_connector_generations (environment_id,machine_id,connector_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,'runtime',3,'test',$3,'admitted')`, []any{environmentID, machineID, nodeID}},
		{`INSERT INTO paperboat.control_routes (id,environment_id,connector_id,kind,public_host,target_host,target_port,desired_state) VALUES ($1,$2,'runtime','runtime_https_wss',$3,'127.0.0.1',8080,'attached')`, []any{"codex_route_" + suffix, environmentID, "codex-" + suffix + ".example.test"}},
	}
	for _, statement := range statements {
		if _, err := store.SQL().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	service := New(store, nil, "", 4)
	service.now = func() time.Time { return time.Unix(2_000, 0).UTC() }
	created, err := service.Create(ctx, userID, clientID, environmentID, "codex-create-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.Queries().GetOwnedCodexSession(ctx, dbsqlc.GetOwnedCodexSessionParams{ID: created.ID, UserID: userID, CLIClientSessionID: clientID})
	if err != nil {
		t.Fatal(err)
	}
	if row.MachineID != machineID || row.InstallationGeneration != 7 || row.ConnectorID != "runtime" || row.ConnectorGeneration != 3 || row.EdgeNodeID != nodeID {
		t.Fatalf("created Codex authority = %+v", row)
	}
}
