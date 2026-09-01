package db

import (
	"bytes"
	"testing"
)

func TestConnectorRotationMigrationDefinesDurableImmutablePlan(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/129_connector_rotation.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("connector rotation migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("credential_generation bigint NOT NULL DEFAULT 1"),
		[]byte("last_heartbeat_sent_at timestamptz"),
		[]byte("source_operation_id text REFERENCES operations(id)"),
		[]byte("CREATE TABLE tunnel_connector_rotation_targets"),
		[]byte("PRIMARY KEY (operation_id, connector_id)"),
		[]byte("target_set_hash text NOT NULL"),
		[]byte("new_credential_valid_until timestamptz"),
		[]byte("new_public_key bytea"),
		[]byte("replacement_session_id text"),
		[]byte("revoke_session_id text"),
		[]byte("revoke_process_generation bigint"),
		[]byte("revoked_at timestamptz"),
		[]byte("validate_connector_rotation_target_scope"),
		[]byte("target identity and policy are immutable"),
		[]byte("NEW.overlap_until IS DISTINCT FROM OLD.overlap_until"),
		[]byte("NEW.new_credential_valid_until IS DISTINCT FROM OLD.new_credential_valid_until"),
		[]byte("state = 'revoked') = (revoked_at IS NOT NULL)"),
		[]byte("ALTER TABLE connector_proof_replays"),
		[]byte("connector_proof_replays_proof_kind_check"),
		[]byte("proof_kind IN ('auth', 'renew', 'rotation')"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("migration is missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("private_key"), []byte("bearer_token"), []byte("credential_ciphertext"),
	} {
		if bytes.Contains(up, forbidden) {
			t.Fatalf("migration contains forbidden secret field %q", forbidden)
		}
	}
	if !bytes.Contains(down, []byte("cannot roll back connector rotation state with retained targets")) {
		t.Fatal("down migration must refuse destructive rollback while targets remain")
	}
	if bytes.Count(down, []byte("-- +goose StatementBegin")) != 1 || bytes.Count(down, []byte("-- +goose StatementEnd")) != 1 {
		t.Fatal("down migration must keep its guarded DO block intact for Goose")
	}
	if !bytes.Contains(down, []byte("proof_kind IN ('auth', 'renew')")) {
		t.Fatal("down migration must restore the authentication/renewal proof-kind constraint")
	}
	if bytes.Index(down, []byte("DROP TABLE tunnel_connector_rotation_targets")) < bytes.Index(down, []byte("DROP TRIGGER tunnel_connector_rotation_target_scope")) {
		t.Fatal("down migration must drop trigger before target table")
	}
}
