package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReconcileStaleNodesFencesConnectorAndAdvancesRoute(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='offline',ready=false WHERE state IN ('registered','ready')`); err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().Format("150405.000000000")
	seedUsageScope(t, store, suffix)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	environmentID, nodeID, routeID, helperID := "env_"+suffix, "node_"+suffix, "route_"+suffix, "hlp_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='ready',ready=true,last_heartbeat_at=$2 WHERE id=$1`, nodeID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,key_thumbprint,public_key,state) VALUES ($1,$2,'sha256:test',$3,'active')`, helperID, environmentID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,edge_node_id,state,admission_jti_hash,expires_at) VALUES ($1,$2,1,'default',$3,'admitted',$4,$5)`, environmentID, helperID, nodeID, []byte("admission-hash"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_routes SET applied_revision=1,applied_node_id=$2,applied_generation=1 WHERE id=$1`, routeID, nodeID); err != nil {
		t.Fatal(err)
	}
	service := NewEdgeService(store, "test")
	service.SetClock(func() time.Time { return now })
	count, err := service.ReconcileStaleNodes(ctx, now.Add(-30*time.Second), 10)
	if err != nil || count != 1 {
		t.Fatalf("reconcile count=%d err=%v", count, err)
	}
	var nodeState, connectorState string
	var ready bool
	var generation, desiredRevision, appliedRevision int64
	var assigned bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,ready FROM paperboat.control_tunnel_nodes WHERE id=$1`, nodeID).Scan(&nodeState, &ready); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,generation,edge_node_id IS NOT NULL FROM paperboat.control_connector_generations WHERE environment_id=$1`, environmentID).Scan(&connectorState, &generation, &assigned); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_revision,applied_revision FROM paperboat.control_routes WHERE id=$1`, routeID).Scan(&desiredRevision, &appliedRevision); err != nil {
		t.Fatal(err)
	}
	if nodeState != "offline" || ready || connectorState != "pending" || generation != 2 || assigned || desiredRevision != 2 || appliedRevision != 0 {
		t.Fatalf("node=%s/%v connector=%s gen=%d assigned=%v route=%d/%d", nodeState, ready, connectorState, generation, assigned, desiredRevision, appliedRevision)
	}
	count, err = service.ReconcileStaleNodes(ctx, now.Add(-30*time.Second), 10)
	if err != nil || count != 0 {
		t.Fatalf("repeat reconcile count=%d err=%v", count, err)
	}
}

func TestObserveRoutesFencesRevisionNodeAndGeneration(t *testing.T) {
	store := openControlPlaneTestDB(t)
	ctx := context.Background()
	suffix := "observe_" + time.Now().Format("150405.000000000")
	seedUsageScope(t, store, suffix)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	environmentID, nodeID, routeID, helperID := "env_"+suffix, "node_"+suffix, "route_"+suffix, "hlp_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='ready',ready=true,last_heartbeat_at=$2 WHERE id=$1`, nodeID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_helpers (id,environment_id,key_thumbprint,public_key,state) VALUES ($1,$2,'sha256:test',$3,'active')`, helperID, environmentID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.control_connector_generations (environment_id,helper_id,generation,edge_pool,edge_node_id,state) VALUES ($1,$2,4,'default',$3,'admitted')`, environmentID, helperID, nodeID); err != nil {
		t.Fatal(err)
	}
	service := NewEdgeService(store, "test")
	service.SetClock(func() time.Time { return now })
	valid := []RouteObservation{{RouteID: routeID, RouteRevision: 1, EdgeNodeID: nodeID, ConnectorGeneration: 4}}
	if err := service.ObserveRoutes(ctx, nodeID, valid); err != nil {
		t.Fatal(err)
	}
	var revision, generation int64
	var appliedNode string
	if err := store.SQL().QueryRowContext(ctx, `SELECT applied_revision,applied_node_id,applied_generation FROM paperboat.control_routes WHERE id=$1`, routeID).Scan(&revision, &appliedNode, &generation); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || appliedNode != nodeID || generation != 4 {
		t.Fatalf("applied route = %d/%s/%d", revision, appliedNode, generation)
	}
	for _, invalid := range [][]RouteObservation{
		{{RouteID: routeID, RouteRevision: 2, EdgeNodeID: nodeID, ConnectorGeneration: 4}},
		{{RouteID: routeID, RouteRevision: 1, EdgeNodeID: "other-node", ConnectorGeneration: 4}},
		{{RouteID: routeID, RouteRevision: 1, EdgeNodeID: nodeID, ConnectorGeneration: 3}},
	} {
		if err := service.ObserveRoutes(ctx, nodeID, invalid); !errors.Is(err, ErrAssignmentConflict) && !errors.Is(err, ErrInvalidUsageReport) {
			t.Fatalf("invalid observation error = %v", err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_routes SET desired_state='detaching',desired_revision=2 WHERE id=$1`, routeID); err != nil {
		t.Fatal(err)
	}
	if err := service.ObserveRoutes(ctx, nodeID, nil); err != nil {
		t.Fatal(err)
	}
	var state string
	var appliedRevision int64
	var stillAssigned bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT desired_state,applied_revision,applied_node_id IS NOT NULL FROM paperboat.control_routes WHERE id=$1`, routeID).Scan(&state, &appliedRevision, &stillAssigned); err != nil {
		t.Fatal(err)
	}
	if state != "detached" || appliedRevision != 2 || stillAssigned {
		t.Fatalf("detached route = %s/%d assigned=%v", state, appliedRevision, stillAssigned)
	}
}
