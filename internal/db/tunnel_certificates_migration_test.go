package db

import (
	"bytes"
	"os"
	"testing"
)

func TestTunnelCertificateMigrationUsesEncryptedRecordsAndGenerationFences(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/136_tunnel_certificates.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("certificate migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE tunnel_certificate_records"),
		[]byte("certificate_ciphertext bytea NOT NULL"),
		[]byte("private_key_ciphertext bytea NOT NULL"),
		[]byte("master_key_reference text NOT NULL"),
		[]byte("certificate_generation bigint NOT NULL"),
		[]byte("CREATE TABLE tunnel_certificate_issuance_locks"),
		[]byte("lease_until timestamptz NOT NULL"),
		[]byte("CREATE TABLE tunnel_certificate_edge_distributions"),
		[]byte("edge_process_epoch text NOT NULL"),
		[]byte("edge_assignment_generation bigint NOT NULL"),
		[]byte("PRIMARY KEY (certificate_id, edge_node_id, edge_process_epoch)"),
		[]byte("state IN ('staged','ready','active','retired','failed')"),
		[]byte("cannot roll back tunnel certificates while live distribution exists"),
	} {
		if !bytes.Contains(up, required) && !bytes.Contains(down, required) {
			t.Fatalf("certificate migration missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("private_key text"),
		[]byte("bearer_token"),
		[]byte("api_token"),
	} {
		if bytes.Contains(up, forbidden) {
			t.Fatalf("certificate migration stores forbidden plaintext field %q", forbidden)
		}
	}
}

func TestTunnelCertificateQueriesCompleteCreateOnlyAfterActiveCertificate(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificates_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("AcquireTunnelCertificateIssuanceLockV1"),
		[]byte("lease_until <= sqlc.arg(now)"),
		[]byte("edge_process_epoch = sqlc.arg(edge_process_epoch)"),
		[]byte("edge_assignment_generation = sqlc.arg(edge_assignment_generation)"),
		[]byte("edge_assignment_generation <= EXCLUDED.edge_assignment_generation"),
		[]byte("prior.edge_assignment_generation >= sqlc.arg(edge_assignment_generation)"),
		[]byte("state = 'active'"),
		[]byte("operation_type = 'domain.create'"),
		[]byte("certificate_generation = sqlc.arg(certificate_generation)"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("certificate query missing %q", required)
		}
	}
}

func TestTunnelCertificateDueQueriesCastNowBeforeAddingRenewalInterval(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificate_domains_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte("sqlc.arg(now)::timestamptz + sqlc.arg(renew_before)::interval")
	if count := bytes.Count(body, needle); count != 2 {
		t.Fatalf("certificate due queries have %d explicit timestamp casts, want 2", count)
	}
}
