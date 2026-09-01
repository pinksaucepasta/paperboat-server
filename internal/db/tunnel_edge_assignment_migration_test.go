package db

import (
	"bytes"
	"testing"
)

func TestTunnelEdgeRouteAssignmentMigrationIsGenerationFenced(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/133_tunnel_edge_route_assignments.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("tunnel edge assignment migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE tunnel_edge_route_assignments"),
		[]byte("assignment_generation bigint NOT NULL"),
		[]byte("config_content_hash bytea NOT NULL"),
		[]byte("host_id text NOT NULL"),
		[]byte("access_mode text NOT NULL DEFAULT 'public'"),
		[]byte("connector_session_id text NOT NULL"),
		[]byte("connector_process_generation bigint NOT NULL"),
		[]byte("edge_process_epoch text NOT NULL"),
		[]byte("FOREIGN KEY (tunnel_id, account_id)"),
		[]byte("FOREIGN KEY (route_id, tunnel_id)"),
		[]byte("FOREIGN KEY (connector_session_id, connector_id)"),
		[]byte("FOREIGN KEY (connector_id, tunnel_id, host_id)"),
		[]byte("FOREIGN KEY (edge_node_id)"),
		[]byte("CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_generation"),
		[]byte("CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_staged"),
		[]byte("CREATE UNIQUE INDEX tunnel_edge_route_assignments_route_active"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("tunnel edge assignment migration is missing %q", required)
		}
	}
	if bytes.Contains(up, []byte("origin_address")) {
		t.Fatal("edge assignment migration must not persist host-local origin addresses")
	}
	if bytes.Count(down, []byte("-- +goose StatementBegin")) != 1 || bytes.Count(down, []byte("-- +goose StatementEnd")) != 1 {
		t.Fatal("guarded assignment rollback must wrap its procedural statement")
	}
	for _, required := range [][]byte{
		[]byte("cannot roll back tunnel edge assignments while live assignments exist"),
		[]byte("DROP TABLE IF EXISTS tunnel_edge_route_assignments"),
		[]byte("DROP CONSTRAINT IF EXISTS tunnel_connector_sessions_id_connector_unique"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("tunnel edge assignment migration down path is missing %q", required)
		}
	}
}
