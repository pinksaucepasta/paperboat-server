package connectorprotocol

import (
	"context"
	"testing"
	"time"
)

func TestTask24IngressProjectionPostgres(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()
	c := f.connectors[0]
	now := f.clock.now
	nodeID := "edge_task24_" + f.suffix
	epoch := "epoch_task24_" + f.suffix
	routeID := "route_task24_" + f.suffix
	environmentID := "env_" + c.hostID
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.database.SQL().ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Clean foreign-key owners in order, even when an assertion fails. The
	// existing fixture subsequently deletes the account and closes its database.
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM tunnel_edge_route_assignments WHERE edge_node_id=$1`,
			`DELETE FROM control_tunnel_nodes WHERE id=$1`,
		} {
			if _, err := f.database.SQL().ExecContext(ctx, q, nodeID); err != nil {
				t.Error(err)
			}
		}
		if _, err := f.database.SQL().ExecContext(ctx, `DELETE FROM machine_control_sessions WHERE machine_id=$1`, c.hostID); err != nil {
			t.Error(err)
		}
		if _, err := f.database.SQL().ExecContext(ctx, `DELETE FROM control_environments WHERE id=$1`, environmentID); err != nil {
			t.Error(err)
		}
	})
	exec(`INSERT INTO control_environments(id,workspace_id,owner_user_id,desired_state) VALUES($1,$2,$3,'active')`, environmentID, c.hostID, f.accountID)
	exec(`INSERT INTO control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES($1,'task24','1.0',$2,'ready',true,$3)`, nodeID, epoch, now)
	exec(`INSERT INTO tunnel_routes(id,tunnel_id,name,protocol,match_type,match_hostname,path_prefix,origin_scheme,origin_address,tls_verification,created_by_actor_id,updated_by_actor_id) VALUES($1,$2,'task24','http','exact','task24.example.test','/','http','127.0.0.1:3000','not_applicable',$3,$3)`, routeID, f.tunnelID, f.accountID)
	exec(`INSERT INTO machine_control_renewals(operation_id,machine_id,installation_generation,credential_jti,issued_at,expires_at,session_generation) SELECT $1,id,installation_generation,$1,$3,$4,1 FROM user_machines WHERE id=$2`, "renew_task24_"+f.suffix, c.hostID, now.Add(-time.Minute), now.Add(time.Hour))
	exec(`INSERT INTO machine_control_sessions(machine_id,installation_generation,session_generation,operation_id,credential_jti,issued_at,expires_at) SELECT machine_id,installation_generation,session_generation,operation_id,credential_jti,issued_at,expires_at FROM machine_control_renewals WHERE operation_id=$1`, "renew_task24_"+f.suffix)
	exec(`INSERT INTO tunnel_edge_route_assignments(assignment_id,route_id,assignment_generation,account_id,tunnel_id,connector_id,host_id,machine_identity_public_key,machine_identity_thumbprint,connector_generation,connector_session_id,connector_process_generation,config_generation,config_content_hash,access_mode,route_generation,route_revision,edge_node_id,edge_process_epoch,edge_failure_domain,state,observed_state)
 SELECT $1,$2,1,t.account_id,t.id,c.id,c.host_id,m.public_identity_key,$3,c.generation,c.last_session_id,1,1,g.content_hash,'public',1,1,$4,$5,'task24','active','ready' FROM tunnels t JOIN tunnel_connectors c ON c.tunnel_id=t.id JOIN user_machines m ON m.id=c.host_id JOIN tunnel_config_generations g ON g.tunnel_id=t.id AND g.generation=1 WHERE c.id=$6`, "assignment_task24_"+f.suffix, routeID, c.oldThumbprint, nodeID, epoch, c.id)
	exec(`UPDATE control_tunnel_nodes SET region='task24',failure_domain='task24',roles=ARRAY['edge'],transports=ARRAY['http3','http2'],capacity_limit=100,capacity_used=0,capacity_observed_at=$2,registry_expires_at=$2::timestamptz+interval '1 hour' WHERE id=$1`, nodeID, now)
	source := SQLIngressSource{DB: f.database, Clock: f.clock}
	active := ActiveControlSession{AccountID: f.accountID, TunnelID: f.tunnelID, ConnectorID: c.id, HostID: c.hostID, SessionID: c.oldSessionID, IdentityKeyID: c.oldIdentityKeyID, IdentityKeyThumbprint: c.oldThumbprint, ProcessGeneration: 1, CredentialGeneration: 1, ConfigGeneration: 1, ConfigContentHash: f.config.ContentHash}
	check := func(t *testing.T, want int) {
		t.Helper()
		for _, read := range []func() ([]IngressDecision, error){func() ([]IngressDecision, error) { return source.Edge(ctx, nodeID, epoch) }, func() ([]IngressDecision, error) { return source.Daemon(ctx, active) }} {
			got, err := read()
			if err != nil || len(got) != want {
				t.Fatalf("projection count=%d want=%d err=%v", len(got), want, err)
			}
			if want == 1 {
				d := got[0]
				if d.Binding.EnvironmentID != environmentID || d.Binding.RouteID != routeID || d.Binding.HostID != c.hostID || d.Binding.OriginAddress != "127.0.0.1:3000" || d.Validate(now) != nil || !d.ExpiresAt.Equal(now.Add(IngressAuthorityLifetime)) {
					t.Fatal("incorrect current binding")
				}
			}
		}
	}
	check(t, 1)
	for _, tc := range []struct {
		name, change, restore string
		id                    string
	}{
		{"quota suspension", `UPDATE control_environments SET desired_state='suspended' WHERE id=$1`, `UPDATE control_environments SET desired_state='active' WHERE id=$1`, environmentID},
		{"revoked environment", `UPDATE control_environments SET revoked_at=now() WHERE id=$1`, `UPDATE control_environments SET revoked_at=NULL WHERE id=$1`, environmentID},
		{"wrong environment workspace", `UPDATE control_environments SET workspace_id='wrong-machine' WHERE id=$1`, `UPDATE control_environments SET workspace_id=substring(id from 5) WHERE id=$1`, environmentID},
		{"stale route", `UPDATE tunnel_routes SET generation=2 WHERE id=$1`, `UPDATE tunnel_routes SET generation=1 WHERE id=$1`, routeID},
		{"paused publication", `UPDATE tunnels SET desired_state='paused' WHERE id=$1`, `UPDATE tunnels SET desired_state='active' WHERE id=$1`, f.tunnelID},
		{"restricted publication", `UPDATE tunnels SET access_mode='private' WHERE id=$1`, `UPDATE tunnels SET access_mode='public' WHERE id=$1`, f.tunnelID},
		{"revoked machine", `UPDATE user_machines SET revoked_at=now() WHERE id=$1`, `UPDATE user_machines SET revoked_at=NULL WHERE id=$1`, c.hostID},
		{"wrong installation", `UPDATE user_machines SET installation_generation=installation_generation+1 WHERE id=$1`, `UPDATE user_machines SET installation_generation=installation_generation-1 WHERE id=$1`, c.hostID},
		{"expired credential", `UPDATE tunnel_connector_credential_generations SET created_at=now()-interval '1 hour',valid_until=now()-interval '1 minute' WHERE connector_id=$1`, `UPDATE tunnel_connector_credential_generations SET valid_until=now()+interval '4 hours' WHERE connector_id=$1`, c.id},
		{"revoked credential", `UPDATE tunnel_connector_credential_generations SET state='revoked',revoked_at=now() WHERE connector_id=$1`, `UPDATE tunnel_connector_credential_generations SET state='active',revoked_at=NULL WHERE connector_id=$1`, c.id},
		{"expired session", `UPDATE tunnel_connector_sessions SET created_at=now()-interval '1 hour',lease_deadline=now()-interval '1 minute' WHERE id=$1`, `UPDATE tunnel_connector_sessions SET lease_deadline=now()+interval '20 minutes' WHERE id=$1`, c.oldSessionID},
		{"stale edge heartbeat", `UPDATE control_tunnel_nodes SET last_heartbeat_at=now()-interval '3 minutes' WHERE id=$1`, `UPDATE control_tunnel_nodes SET last_heartbeat_at=now() WHERE id=$1`, nodeID},
		{"stale connector heartbeat", `UPDATE tunnel_connector_sessions SET last_heartbeat_at=now()-interval '3 minutes' WHERE id=$1`, `UPDATE tunnel_connector_sessions SET last_heartbeat_at=now() WHERE id=$1`, c.oldSessionID},
		{"expired machine identity", `UPDATE machine_control_sessions SET expires_at=issued_at+interval '1 second' WHERE machine_id=$1`, `UPDATE machine_control_sessions SET expires_at=now()+interval '1 hour' WHERE machine_id=$1`, c.hostID},
	} {
		t.Run(tc.name, func(t *testing.T) { exec(tc.change, tc.id); t.Cleanup(func() { exec(tc.restore, tc.id) }); check(t, 0) })
		check(t, 1)
	}
	wrong := active
	wrong.HostID = f.connectors[1].hostID
	if got, err := source.Daemon(ctx, wrong); err != nil || len(got) != 0 {
		t.Fatalf("wrong host authority count=%d err=%v", len(got), err)
	}
	if got, err := source.Edge(ctx, nodeID, epoch+"_old"); err != nil || len(got) != 0 {
		t.Fatalf("wrong edge epoch count=%d err=%v", len(got), err)
	}
	// Restricted selection must remain separate from anonymous projections and
	// cannot turn a route or edge selector into viewer authority.
	for _, mode := range []string{"private", "team"} {
		exec(`UPDATE tunnels SET access_mode=$2 WHERE id=$1`, f.tunnelID, mode)
		exec(`UPDATE tunnel_edge_route_assignments SET access_mode=$2 WHERE route_id=$1`, routeID, mode)
		check(t, 0)
		d, err := source.RestrictedRoute(ctx, nodeID, epoch, mode, routeID)
		if err != nil || d.Binding.Audience != mode || d.Binding.RouteID != routeID || d.Binding.HostID != c.hostID {
			t.Fatalf("restricted %s projection: %v", mode, err)
		}
		if d.Validate(now) == nil {
			t.Fatal("connector projection must not itself grant viewer access")
		}
		if _, err := source.RestrictedRoute(ctx, nodeID, epoch+"_old", mode, routeID); err == nil {
			t.Fatal("stale edge received restricted projection")
		}
		if _, err := source.RestrictedRoute(ctx, nodeID, epoch, mode, routeID+"_wrong"); err == nil {
			t.Fatal("wrong route received restricted projection")
		}
	}
	exec(`UPDATE tunnels SET access_mode='public' WHERE id=$1`, f.tunnelID)
	exec(`UPDATE tunnel_edge_route_assignments SET access_mode='public' WHERE route_id=$1`, routeID)
	exec(`UPDATE tunnel_routes SET protocol='tcp',match_type='managed',path_prefix=NULL,origin_scheme='tcp',origin_address='127.0.0.1:5432',preserve_host=false,public_tcp_listener_id=$2,public_tcp_port=24568 WHERE id=$1`, routeID, "listener_task28_"+f.suffix)
	decisions, err := source.Edge(ctx, nodeID, epoch)
	if err != nil || len(decisions) != 1 {
		t.Fatalf("public TCP projection count=%d err=%v", len(decisions), err)
	}
	binding := decisions[0].Binding
	if binding.Protocol != "tcp" || binding.ListenerID != "listener_task28_"+f.suffix || binding.PublicPort != 24568 || binding.PathPrefix != "" || binding.OriginAddress != "127.0.0.1:5432" || decisions[0].Validate(now) != nil {
		t.Fatalf("public TCP binding = %+v", decisions[0])
	}
}
