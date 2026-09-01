package db

import (
	"bytes"
	"testing"
)

func TestConnectorActivationMigrationPersistsOperationBoundGenerations(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/140_connector_activation_generation.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("connector activation migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE tunnel_connector_activations"),
		[]byte("operation_id text PRIMARY KEY"),
		[]byte("credential_generation bigint NOT NULL"),
		[]byte("process_generation bigint NOT NULL"),
		[]byte("REFERENCES operations(id, account_id) ON DELETE RESTRICT"),
		[]byte("REFERENCES tunnel_connectors(id, tunnel_id, host_id) ON DELETE CASCADE"),
		[]byte("UNIQUE (connector_id, process_generation)"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("connector activation migration missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte("private_key"), []byte("bearer"), []byte("enrollment_token")} {
		if bytes.Contains(up, forbidden) {
			t.Fatalf("connector activation migration contains secret field %q", forbidden)
		}
	}
	if !bytes.Contains(down, []byte("DROP TABLE IF EXISTS tunnel_connector_activations")) {
		t.Fatal("connector activation down migration must remove its table")
	}
}
