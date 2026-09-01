package db

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPreviewCarrierAttachmentMigrationIsEphemeralAndSecretFree(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/130_preview_lease_carrier_attachments.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("attachment migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE preview_lease_carrier_attachments"),
		[]byte("carrier_kind text NOT NULL DEFAULT 'preview_ephemeral'"),
		[]byte("CHECK (carrier_kind = 'preview_ephemeral')"),
		[]byte("request_hash bytea NOT NULL"),
		[]byte("request_id text NOT NULL"),
		[]byte("correlation_id text NOT NULL"),
		[]byte("host_id text NOT NULL"),
		[]byte("lease_generation bigint NOT NULL"),
		[]byte("connector_session_id text NOT NULL"),
		[]byte("process_generation bigint NOT NULL"),
		[]byte("config_generation bigint NOT NULL"),
		[]byte("route_generation bigint NOT NULL"),
		[]byte("config_content_hash text NOT NULL"),
		[]byte("edge_endpoints text[] NOT NULL"),
		[]byte("CHECK (cardinality(edge_endpoints) = 2)"),
		[]byte("CREATE UNIQUE INDEX preview_lease_carrier_attachments_live_preview"),
		[]byte("CREATE UNIQUE INDEX preview_lease_carrier_attachments_idempotency"),
		[]byte("FOREIGN KEY (preview_id, account_id)"),
		[]byte("FOREIGN KEY (operation_id, account_id)"),
		[]byte("CREATE TABLE preview_lease_create_operations"),
		[]byte("PRIMARY KEY (account_id, preview_id)"),
		[]byte("CREATE TABLE preview_carrier_attachment_outbox"),
		[]byte("action IN ('admit','detach')"),
		[]byte("access_mode text NOT NULL"),
		[]byte("machine_identity_public_key"),
		[]byte("machine_identity_thumbprint"),
		[]byte("edge_node_id text NOT NULL REFERENCES control_tunnel_nodes"),
		[]byte("CREATE TRIGGER preview_lease_carrier_attachment_guard"),
		[]byte("DROP TABLE IF EXISTS preview_lease_carrier_attachments"),
	} {
		if !bytes.Contains(up, required) && !bytes.Contains(down, required) {
			t.Fatalf("attachment migration is missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(" token text"), []byte("bearer_token"), []byte("password text"), []byte("private_key"), []byte("credential text"), []byte("credential_ciphertext"),
	} {
		if bytes.Contains(up, forbidden) {
			t.Fatalf("attachment migration contains forbidden material field %q", forbidden)
		}
	}
	if bytes.Count(up, []byte("-- +goose StatementBegin")) < 2 || bytes.Count(up, []byte("-- +goose StatementEnd")) < 2 {
		t.Fatal("attachment migration PL/pgSQL functions must be protected by goose statement guards")
	}
}

func TestPreviewCarrierEndpointMigrationSeparatesLegacyConnectorPorts(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/131_preview_carrier_endpoints.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok || !bytes.Contains(up, []byte("-- +goose Up")) {
		t.Fatal("carrier endpoint migration must have explicit goose up/down sections")
	}
	for _, required := range [][]byte{
		[]byte("carrier_endpoint_host text"),
		[]byte("carrier_endpoint_tcp_port integer"),
		[]byte("carrier_endpoint_quic_port integer"),
		[]byte("control_tunnel_nodes_carrier_endpoint_check"),
		[]byte("carrier_endpoint_tcp_port <> carrier_endpoint_quic_port"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("carrier endpoint migration is missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("DROP COLUMN IF EXISTS carrier_endpoint_host"),
		[]byte("DROP COLUMN IF EXISTS carrier_endpoint_tcp_port"),
		[]byte("DROP COLUMN IF EXISTS carrier_endpoint_quic_port"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("carrier endpoint migration down path is missing %q", required)
		}
	}
	if bytes.Contains(up, []byte("ADD COLUMN endpoint_tcp_port")) || bytes.Contains(up, []byte("ADD COLUMN endpoint_quic_port")) {
		t.Fatal("carrier endpoint migration must not alter legacy connector endpoint columns")
	}
}

func TestPreviewCarrierEdgeProcessEpochMigrationFencesOverlappingEdgeProcesses(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/132_preview_carrier_edge_process_epoch.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok || !bytes.Contains(up, []byte("-- +goose Up")) {
		t.Fatal("edge process epoch migration must have explicit goose up/down sections")
	}
	for _, required := range [][]byte{
		[]byte("ADD COLUMN edge_process_epoch text"),
		[]byte("SET edge_process_epoch = node.process_epoch"),
		[]byte("ALTER COLUMN edge_process_epoch SET NOT NULL"),
		[]byte("preview_lease_carrier_attachments_edge_process_epoch_check"),
		[]byte("preview_carrier_attachment_outbox_edge_process_epoch_check"),
		[]byte("length(edge_process_epoch) BETWEEN 8 AND 128"),
		[]byte("^[A-Za-z0-9_-]+$"),
		[]byte("preview_lease_carrier_attachment_edge_epoch_guard_v1"),
		[]byte("node.process_epoch = NEW.edge_process_epoch"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("edge process epoch migration is missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("DROP COLUMN IF EXISTS edge_process_epoch"),
		[]byte("DROP CONSTRAINT IF EXISTS preview_carrier_attachment_outbox_edge_process_epoch_check"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("edge process epoch migration down path is missing %q", required)
		}
	}
	if !bytes.Contains(up, []byte("-- +goose StatementBegin")) || !bytes.Contains(up, []byte("-- +goose StatementEnd")) {
		t.Fatal("edge process epoch trigger function must be protected by goose statement guards")
	}
}

func TestPreviewLeaseCreateOperationLookupUsesImmutableRelation(t *testing.T) {
	body, err := os.ReadFile("queries/preview_lease_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "JOIN preview_lease_create_operations") {
		t.Fatal("preview create-operation lookup does not use immutable relation")
	}
	if strings.Contains(text, "ORDER BY candidate.created_at DESC") || strings.Contains(text, "ORDER BY created_at DESC, id DESC") {
		t.Fatal("preview create-operation lookup still chooses latest operation")
	}
}
