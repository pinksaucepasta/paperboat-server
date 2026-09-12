package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestInspectorRemoteAccessPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	suffix := fmt.Sprint(now.UnixNano())
	owner, mate, lease, tunnel, route, node := inspectorHTTPFixture(t, ctx, database, now, suffix)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := database.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`UPDATE paperboat.control_tunnel_nodes SET registry_expires_at=$1,region='test',failure_domain='test',roles=ARRAY['edge'],transports=ARRAY['http3','http2'],capacity_limit=10,capacity_observed_at=now() WHERE id=$2`, now.Add(time.Hour), node)
	cli := "cli_ir_" + suffix
	exec(`INSERT INTO paperboat.cli_client_sessions(id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES($1,$2,$3,'inspector remote','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, cli, mate, "client_ir_"+suffix, now)
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.cli_client_sessions WHERE id=$1`, cli)
	})
	service := inspectaccess.NewService(database)
	grant, err := service.Issue(ctx, inspectaccess.IssueRequest{AccountID: mate, ResourceKind: "preview", ResourceID: lease, RouteID: lease, Action: "inspect", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	input := inspectaccess.AccessRequest{AccountID: mate, CLIClientSessionID: cli, Token: grant.Token, ResourceKind: "preview", ResourceID: lease, RouteID: lease, Action: "inspect", Transport: "native"}
	access, err := service.ResolveAccess(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if access.OwnerAccountID != owner || access.MachineID != "mch_ih_"+suffix {
		t.Fatalf("incorrect owner routing: %+v", access)
	}
	exec(`UPDATE paperboat.control_tunnel_nodes SET ready=false WHERE id=$1`, node)
	if _, err = service.ResolveAccess(ctx, input); err != nil {
		t.Fatalf("native inspector depended on ready edge: %v", err)
	}
	exec(`UPDATE paperboat.control_tunnel_nodes SET ready=true WHERE id=$1`, node)
	var count int
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.inspector_native_admissions WHERE credential_id=$1`, grant.CredentialID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("inspector network admission count=%d err=%v", count, err)
	}
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.user_machine_access_sessions WHERE cli_client_session_id=$1`, cli).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unexpected machine access count=%d err=%v", count, err)
	}

	exec(`UPDATE paperboat.tunnels SET created_by_host_id=$1 WHERE id=$2`, access.MachineID, tunnel)
	ownerCLI := "cli_ir_owner_" + suffix
	exec(`INSERT INTO paperboat.cli_client_sessions(id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES($1,$2,$3,'inspector owner','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, ownerCLI, owner, "client_ir_owner_"+suffix, now)
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.cli_client_sessions WHERE id=$1`, ownerCLI)
	})
	durableGrant, e := service.Issue(ctx, inspectaccess.IssueRequest{AccountID: owner, ResourceKind: "tunnel", ResourceID: tunnel, RouteID: route, Action: "inspect", TTL: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	durable, e := service.ResolveAccess(ctx, inspectaccess.AccessRequest{AccountID: owner, CLIClientSessionID: ownerCLI, Token: durableGrant.Token, ResourceKind: "tunnel", ResourceID: tunnel, RouteID: route, Action: "inspect", Transport: "native"})
	if e != nil || durable.MachineID != access.MachineID {
		t.Fatalf("durable native routing: %v", e)
	}

	hash := sha256.Sum256([]byte(`{}`))
	connector := "con_ir_" + suffix
	carrierSession := "ses_ir_" + suffix
	assignment := "asg_ir_" + suffix
	exec(`INSERT INTO paperboat.tunnel_config_generations(tunnel_id,generation,content_hash,snapshot,activation_state,created_by_actor_id,activated_at,retained_until) VALUES($1,1,$2,$3,'active',$4,now(),now()+interval '1 hour')`, tunnel, hash[:], []byte(`{}`), owner)
	exec(`INSERT INTO paperboat.tunnel_connectors(id,tunnel_id,host_id,credential_reference,credential_thumbprint,protocol_version,last_session_id,last_applied_config_generation) VALUES($1,$2,$3,$4,$4,'1.0',$5,1)`, connector, tunnel, access.MachineID, "ref_ir_"+suffix, carrierSession)
	exec(`INSERT INTO paperboat.tunnel_connector_sessions(id,connector_id,process_generation,protocol_version,state,lease_deadline,retained_until,applied_config_generation) VALUES($1,$2,1,'1.0','ready',now()+interval '1 hour',now()+interval '1 hour',1)`, carrierSession, connector)
	exec(`INSERT INTO paperboat.tunnel_edge_route_assignments(assignment_id,route_id,assignment_generation,account_id,tunnel_id,connector_id,host_id,machine_identity_public_key,machine_identity_thumbprint,connector_generation,connector_session_id,connector_process_generation,config_generation,config_content_hash,access_mode,route_generation,route_revision,edge_node_id,edge_process_epoch,edge_failure_domain,state,observed_state) SELECT $1,$2,1,$3,$4,$5,m.id,m.public_identity_key,m.public_identity_key,1,$6,1,1,$7,'team',7,7,$8,$9,'test','active','ready' FROM paperboat.user_machines m WHERE m.id=$10`, assignment, route, owner, tunnel, connector, carrierSession, hash[:], node, "epoch-ih-"+suffix, access.MachineID)
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.tunnel_edge_route_assignments WHERE assignment_id=$1`, assignment)
	})
	edgeDurable, e := service.ResolveAccess(ctx, inspectaccess.AccessRequest{AccountID: owner, Token: durableGrant.Token, ResourceKind: "tunnel", ResourceID: tunnel, RouteID: route, Action: "inspect", Transport: "edge", EdgeNodeID: node, EdgeProcessEpoch: "epoch-ih-" + suffix})
	if e != nil || edgeDurable.Carrier.AssignmentID != assignment || edgeDurable.Carrier.ConfigContentHash != fmt.Sprintf("sha256:%x", hash) {
		t.Fatalf("durable edge routing: %v", e)
	}
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation) VALUES($1,'tunnel',$2,$3,true,1)`, "team_ih_"+suffix, tunnel, owner)
	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,'tunnel',$3,'inspect',1,true)`, "team_ih_"+suffix, mate, tunnel)
	targets, e := service.Targets(ctx, mate, tunnel, "inspect")
	if e != nil || len(targets) != 1 || targets[0].ResourceID != tunnel || targets[0].RouteID != route {
		t.Fatalf("inspect-only target discovery: %v", e)
	}
	if _, e = service.Targets(ctx, mate, tunnel, "replay"); e == nil {
		t.Fatal("inspect-only target discovery admitted replay")
	}
	handlers := &InspectorHandlers{Access: service}
	body, _ := json.Marshal(map[string]any{"credential_token": grant.Token, "resource_kind": "preview", "resource_id": lease, "route_id": lease, "action": "inspect", "transport": "edge"})
	response := inspectorHTTPRequest(t, handlers.ResolveAccess, http.MethodPost, "/v1/inspector/access", string(body), mate)
	if response.Code != http.StatusOK {
		t.Fatalf("edge route status=%d", response.Code)
	}
	denied := input
	denied.Action = "replay"
	if _, err = service.ResolveAccess(ctx, denied); err == nil {
		t.Fatal("inspect credential admitted replay")
	}
	denied = input
	denied.Transport = "edge"
	denied.EdgeNodeID = "different-edge"
	denied.EdgeProcessEpoch = "different-epoch"
	if _, err = service.ResolveAccess(ctx, denied); err == nil {
		t.Fatal("different edge admitted")
	}

	exec(`UPDATE paperboat.tunnel_routes SET desired_state='deleted',deleted_at=now(),generation=generation+1 WHERE id=$1`, route)
	if _, e = service.Authorize(ctx, inspectaccess.AuthorizeRequest{MachineAccount: owner, Token: durableGrant.Token, ResourceKind: "tunnel", ResourceID: tunnel, RouteID: route, Action: "inspect"}); e == nil {
		t.Fatal("deleted route remained authorized")
	}
	if _, e = service.Targets(ctx, mate, tunnel, "inspect"); e == nil {
		t.Fatal("deleted route remained discoverable")
	}
	exec(`UPDATE paperboat.team_resource_grants SET active=false,generation=generation+1 WHERE resource_id=$1 AND account_id=$2 AND permission='inspect'`, lease, mate)
	if _, err = service.ResolveAccess(ctx, input); err == nil {
		t.Fatal("revoked inspect grant admitted")
	}
	if err = database.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.inspector_native_admissions WHERE credential_id=$1`, grant.CredentialID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("revoked network admission count=%d err=%v", count, err)
	}
}
