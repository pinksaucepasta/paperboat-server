package db

import (
	"bytes"
	"os"
	"testing"
)

func TestTunnelCertificateEdgeRevocationMigrationIsTerminalAndGuarded(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/142_tunnel_certificate_edge_revocation.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("edge revocation migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("DROP CONSTRAINT IF EXISTS tunnel_certificate_edge_distributions_state_check"),
		[]byte("state IN ('staged','ready','active','retired','revoked','failed')"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("edge revocation migration missing %q", required)
		}
	}
	if !bytes.Contains(down, []byte("WHERE state = 'revoked'")) || !bytes.Contains(down, []byte("RAISE EXCEPTION")) {
		t.Fatal("edge revocation migration down path is not guarded")
	}
}

func TestTunnelCertificateEdgeStateQueryAcceptsOnlyBoundTerminalRevocation(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificates_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("state IN ('staged','ready','active','retired','revoked','failed')"),
		[]byte("sqlc.arg(state) = 'revoked'"),
		[]byte("state = 'revoked'"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("certificate edge state query missing %q", required)
		}
	}
}
