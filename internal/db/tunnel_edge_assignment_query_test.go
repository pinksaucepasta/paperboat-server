package db

import (
	"bytes"
	"os"
	"testing"
)

func TestTunnelEdgeAssignmentQueriesSerializeAndFenceGeneration(t *testing.T) {
	body, err := os.ReadFile("queries/control_plane.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(body, []byte("-- name: NextTunnelEdgeRouteAssignmentGenerationV1 :one"))
	if start < 0 {
		t.Fatal("generation query is missing")
	}
	end := bytes.Index(body[start+1:], []byte("-- name:"))
	if end < 0 {
		t.Fatal("generation query is missing")
	}
	generation := body[start : start+1+end]
	for _, required := range [][]byte{
		[]byte("FROM tunnel_routes"),
		[]byte("FOR UPDATE"),
		[]byte("MAX(assignment_generation)"),
	} {
		if !bytes.Contains(generation, required) {
			t.Fatalf("generation query is missing %q: %s", required, generation)
		}
	}
	stage := bytes.Index(body, []byte("-- name: StageTunnelEdgeRouteAssignmentV1 :one"))
	if stage < 0 {
		t.Fatal("stage query is missing")
	}
	stageEnd := bytes.Index(body[stage+1:], []byte("-- name:"))
	if stageEnd < 0 {
		t.Fatal("stage query has no end")
	}
	stageQuery := body[stage : stage+1+stageEnd]
	for _, required := range [][]byte{
		[]byte("prior.assignment_generation >= sqlc.arg(assignment_generation)"),
		[]byte("state = 'staged'"),
		[]byte("config.content_hash = sqlc.arg(config_content_hash)"),
		[]byte("session.state IN ('authenticating','ready')"),
		[]byte("session.applied_config_generation = config.generation"),
	} {
		if !bytes.Contains(stageQuery, required) {
			t.Fatalf("stage query is missing %q", required)
		}
	}
}

func TestTunnelEdgeAssignmentQueriesStageAfterConfigAckBeforeConnectorReady(t *testing.T) {
	body, err := os.ReadFile("queries/control_plane.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := func(name string) []byte {
		start := bytes.Index(body, []byte("-- name: "+name))
		if start < 0 {
			t.Fatalf("query %s is missing", name)
		}
		end := bytes.Index(body[start+1:], []byte("-- name:"))
		if end < 0 {
			return body[start:]
		}
		return body[start : start+1+end]
	}
	for _, name := range []string{"StageTunnelEdgeRouteAssignmentV1", "ListReadyTunnelEdgeRouteCandidatesV1"} {
		queryText := query(name)
		if !bytes.Contains(queryText, []byte("session.state IN ('authenticating','ready')")) {
			t.Fatalf("%s must admit an authenticated pre-ready session: %s", name, queryText)
		}
		if !bytes.Contains(queryText, []byte("session.applied_config_generation = config.generation")) {
			t.Fatalf("%s must require the exact acknowledged config generation: %s", name, queryText)
		}
		if !bytes.Contains(queryText, []byte("c.last_applied_config_generation = config.generation")) {
			t.Fatalf("%s must require the connector's exact acknowledged config generation: %s", name, queryText)
		}
		if !bytes.Contains(queryText, []byte("session.last_heartbeat_at >")) {
			t.Fatalf("%s must require a live session heartbeat: %s", name, queryText)
		}
	}
	activation := query("ApplyTunnelEdgeRouteObservationV1")
	if !bytes.Contains(activation, []byte("session.state = 'ready'")) {
		t.Fatalf("ready activation must remain connector-ready gated: %s", activation)
	}
}

func TestTunnelEdgeAssignmentQueriesRetainAllConnectorReplicas(t *testing.T) {
	body, err := os.ReadFile("queries/control_plane.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := func(name string) []byte {
		start := bytes.Index(body, []byte("-- name: "+name))
		if start < 0 {
			t.Fatalf("query %s is missing", name)
		}
		end := bytes.Index(body[start+1:], []byte("-- name:"))
		if end < 0 {
			return body[start:]
		}
		return body[start : start+1+end]
	}
	candidates := query("ListReadyTunnelEdgeRouteCandidatesV1")
	if bytes.Contains(candidates, []byte("FROM tunnel_connectors AS candidate")) || !bytes.Contains(candidates, []byte("JOIN tunnel_connectors AS c ON c.tunnel_id = t.id")) || !bytes.Contains(candidates, []byte("ORDER BY r.id, c.id")) {
		t.Fatalf("candidate query must return every deterministic ready connector: %s", candidates)
	}
	activate := query("ActivateTunnelEdgeRouteAssignmentV1")
	if !bytes.Contains(activate, []byte("a.connector_id = c.connector_id")) {
		t.Fatalf("activation must drain only the replaced connector session: %s", activate)
	}
	migration, err := os.ReadFile("migrations/134_tunnel_edge_route_replicas.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{[]byte("route_connector_staged"), []byte("route_connector_active"), []byte("route_id, connector_id")} {
		if !bytes.Contains(migration, required) {
			t.Fatalf("replica migration is missing %q", required)
		}
	}
}
