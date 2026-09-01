package db

import (
	"bytes"
	"testing"
)

func TestConnectorProofReplayMigrationIsDedicatedAndScoped(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/127_connector_proof_replay.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("connector proof replay migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE connector_proof_replays"),
		[]byte("account_id text NOT NULL REFERENCES users(id)"),
		[]byte("tunnel_id text NOT NULL"),
		[]byte("connector_id text NOT NULL"),
		[]byte("credential_generation bigint NOT NULL"),
		[]byte("proof_kind text NOT NULL"),
		[]byte("nonce text NOT NULL"),
		[]byte("proof_digest bytea NOT NULL"),
		[]byte("PRIMARY KEY (account_id, tunnel_id, connector_id, proof_kind, nonce)"),
		[]byte("UNIQUE (account_id, tunnel_id, connector_id, proof_digest)"),
		[]byte("CHECK (proof_kind IN ('auth', 'renew'))"),
		[]byte("CHECK (octet_length(proof_digest) = 32)"),
		[]byte("connector_proof_replays_expiry"),
	} {
		if !bytes.Contains(up, required) {
			t.Errorf("replay migration is missing %q", required)
		}
	}
	if bytes.Contains(up, []byte("CREATE TABLE operations")) || bytes.Contains(up, []byte("INSERT INTO operations")) {
		t.Fatal("proof replay migration must not use the user-visible operations ledger")
	}
	for _, required := range [][]byte{
		[]byte("cannot roll back connector proof replay ledger with retained rows"),
		[]byte("DROP TABLE connector_proof_replays"),
	} {
		if !bytes.Contains(down, required) {
			t.Errorf("replay migration down path is missing %q", required)
		}
	}
}
