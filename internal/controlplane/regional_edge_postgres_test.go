package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestRegionalEdgeAssignmentsOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
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
	if err = db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := newTunnelEdgeAcceptanceFixture(fmt.Sprintf("regional_%d", time.Now().UnixNano()), now)
	f.insertBase(t, database)
	t.Cleanup(func() {
		database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, f.accountID)
		database.SQL().ExecContext(ctx, `DELETE FROM paperboat.control_tunnel_nodes WHERE id LIKE $1`, f.nodeID+"%")
	})
	f.insertConnector(t, database, f.connectorOne, f.hostOne, f.sessionOne, 11)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.SQL().ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Same pool does not imply same failure domain. Each region must retain its
	// own immutable assignment; promotion of one cannot drain its healthy peer.
	exec(`INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at,region,failure_domain,roles,transports,capacity_limit,capacity_used,capacity_observed_at,registry_expires_at)
 VALUES($1,'trk15-zone-a','1.0',$2,'ready',true,$3,'region-b','domain-b',ARRAY['edge'],ARRAY['http3','http2'],100,0,$3,$3::timestamptz+interval '1 hour')`, f.nodeID+"b", f.epoch+"b", now)
	svc := &EdgeService{store: database, clock: func() time.Time { return now }}
	if n, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil || n != 2 {
		t.Fatalf("two regions stage: %d %v", n, err)
	}
	a, b := f.loadAssignment(t, database, 1), f.loadAssignment(t, database, 2)
	for _, row := range []tunnelEdgeAcceptanceRow{a, b} {
		if err := svc.ObserveRoutes(ctx, row.nodeID, []RouteObservation{f.observation(row, "ready")}); err != nil {
			t.Fatal(err)
		}
	}
	assertState := func(g int64, want string) {
		t.Helper()
		if got := f.loadAssignment(t, database, g); got.state != want {
			t.Fatalf("generation %d state %s want %s", g, got.state, want)
		}
	}
	assertState(1, "active")
	assertState(2, "active")
	if n, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil || n != 0 {
		t.Fatalf("idempotent: %d %v", n, err)
	}
	// A stale edge loses serving authority before a replacement can be selected.
	exec(`UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=$2 WHERE id=$1`, a.nodeID, now.Add(-16*time.Second))
	if _, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertState(a.generation, "draining")
	assertState(b.generation, "active")
	// Excluded nodes remain unavailable even after heartbeat recovery.
	exec(`UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=$2,allowed_account_ids=ARRAY['another_account'] WHERE id=$1`, a.nodeID, now)
	if n, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil || n != 0 {
		t.Fatalf("excluded edge selected: %d %v", n, err)
	}
	exec(`UPDATE paperboat.control_tunnel_nodes SET allowed_account_ids=NULL WHERE id=$1`, a.nodeID)
	if n, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil || n != 1 {
		t.Fatalf("recovered standby: %d %v", n, err)
	}
	replacement := f.loadAssignment(t, database, 3)
	if replacement.nodeID != a.nodeID || replacement.assignmentID == a.assignmentID {
		t.Fatal("recovery reused obsolete authority")
	}
	if err := svc.ObserveRoutes(ctx, a.nodeID, []RouteObservation{f.observation(a, "ready")}); err == nil {
		t.Fatal("stale generation promoted")
	}
	if err := svc.ObserveRoutes(ctx, replacement.nodeID, []RouteObservation{f.observation(replacement, "ready")}); err != nil {
		t.Fatal(err)
	}
	assertState(b.generation, "active")
	assertState(3, "active")
	exec(`UPDATE paperboat.control_tunnel_nodes SET state='draining',ready=false,drain_deadline=$2 WHERE id=$1`, replacement.nodeID, now.Add(30*time.Second))
	if _, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil {
		t.Fatal(err)
	}
	assertState(3, "draining")
	assertState(b.generation, "active")
	// Public address metadata alone is not readiness. HTTP also needs its
	// certificate on this exact process; TCP must acknowledge its new route.
	exec(`UPDATE paperboat.control_tunnel_nodes SET public_ingress_ipv4='8.8.8.8',public_ingress_verified_at=$2 WHERE id=$1`, b.nodeID, now)
	addresses := func(want int) {
		t.Helper()
		rows, err := database.Queries().ListReadyEdgeDNSAddressesV1(ctx, dbsqlc.ListReadyEdgeDNSAddressesV1Params{TunnelID: f.tunnelID, Hostname: "regional.example.test", Now: sql.NullTime{Time: now, Valid: true}})
		if err != nil || len(rows) != want {
			t.Fatalf("public readiness got %d want %d: %v", len(rows), want, err)
		}
	}
	addresses(0)
	exec(`UPDATE paperboat.tunnel_routes SET protocol='tcp',origin_scheme='tcp',match_type='managed',path_prefix=NULL,public_tcp_listener_id='listener_regional_01',public_tcp_port=25001,generation=generation+1 WHERE id=$1`, f.routeID)
	if n, err := svc.ReconcileTunnelEdgeRouteAssignments(ctx, 10); err != nil || n != 1 {
		t.Fatalf("TCP generation stage: %d %v", n, err)
	}
	addresses(0)
	tcp := f.loadAssignment(t, database, 4)
	if err := svc.ObserveRoutes(ctx, tcp.nodeID, []RouteObservation{f.observation(tcp, "ready")}); err != nil {
		t.Fatal(err)
	}
	addresses(1)
	// Verified withdrawal can transfer a reserved name to its current resource,
	// but a delayed old owner cannot reclaim it or reset publication generation.
	names, err := database.Queries().ListEdgeDNSPublicationNamesV1(ctx, f.tunnelID)
	if err != nil || len(names) == 0 {
		t.Fatalf("managed name: %v", err)
	}
	hostname := names[0]
	exec(`INSERT INTO paperboat.edge_dns_publications(hostname,owner_id,resource_generation,readiness_version,observed_at,publication_generation,desired_addresses,provider_records,state,created_at,updated_at,verified_at)
 VALUES($1,'previous_owner',3,'previous',$2,9,'[]','[]','verified',$2,$2,$2)`, hostname, now.Add(-time.Second))
	t.Cleanup(func() {
		database.SQL().ExecContext(ctx, `DELETE FROM paperboat.edge_dns_publications WHERE hostname=$1`, hostname)
	})
	if n, err := database.Queries().TransferWithdrawnEdgeDNSNameV1(ctx, dbsqlc.TransferWithdrawnEdgeDNSNameV1Params{Hostname: hostname, OwnerID: f.tunnelID, ResourceGeneration: 1, ObservedAt: now}); err != nil || n != 1 {
		t.Fatalf("reserved ownership transfer: %d %v", n, err)
	}
	var publicationGeneration int64
	if err := database.SQL().QueryRowContext(ctx, `SELECT publication_generation FROM paperboat.edge_dns_publications WHERE hostname=$1 AND owner_id=$2`, hostname, f.tunnelID).Scan(&publicationGeneration); err != nil || publicationGeneration != 10 {
		t.Fatalf("publication fence reset: %d %v", publicationGeneration, err)
	}
	if n, err := database.Queries().TransferWithdrawnEdgeDNSNameV1(ctx, dbsqlc.TransferWithdrawnEdgeDNSNameV1Params{Hostname: hostname, OwnerID: "previous_owner", ResourceGeneration: 3, ObservedAt: now.Add(time.Second)}); err != nil || n != 0 {
		t.Fatalf("old owner reclaimed namespace: %d %v", n, err)
	}
	exec(`UPDATE paperboat.tunnels SET desired_state='paused' WHERE id=$1`, f.tunnelID)
	addresses(0)

}
