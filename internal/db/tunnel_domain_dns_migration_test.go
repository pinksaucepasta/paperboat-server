package db

import (
	"bytes"
	"os"
	"testing"
)

func TestTunnelDomainDNSMigrationHasBoundedQuarantineAndDueIndexes(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/135_tunnel_domain_dns_tls.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("domain DNS migration has no down section")
	}
	for _, required := range [][]byte{
		[]byte("dns_provider text NOT NULL"),
		[]byte("expected_records jsonb NOT NULL"),
		[]byte("dns_next_check_at timestamptz NOT NULL"),
		[]byte("verification_attempts integer NOT NULL"),
		[]byte("quarantine_until timestamptz"),
		[]byte("interval '7 days'"),
		[]byte("CREATE UNIQUE INDEX tunnel_domains_live_hostname_unique"),
		[]byte("CREATE INDEX tunnel_domains_dns_due"),
		[]byte("CREATE INDEX tunnel_domains_quarantine_due"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("domain DNS migration is missing %q", required)
		}
	}
	if !bytes.Contains(down, []byte("cannot restore global hostname uniqueness")) {
		t.Fatal("domain DNS down path must fail closed when historical claims coexist")
	}
}

func TestTunnelEdgeDomainProjectionRequiresVerifiedOwnershipAndReadyTLS(t *testing.T) {
	body, err := os.ReadFile("queries/control_plane.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("AS domain_bindings"),
		[]byte("d.route_id = r.id"),
		[]byte("d.ownership_state = 'verified'"),
		[]byte("d.certificate_state = 'ready'"),
		[]byte("d.conflict_state = 'clear'"),
		[]byte("ORDER BY d.hostname, d.id"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("edge domain projection is missing %q", required)
		}
	}
}

func TestTunnelDomainReconciliationSeparatesDNSAndCertificateOperationBoundaries(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_domain_reconciliation.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("ownership_state IN ('pending','failed','verified')"),
		[]byte("observation_verified"),
		[]byte("operation_type = 'domain.verify'"),
		[]byte("operation_type = 'domain.create'"),
		[]byte("phase = 'issuing_certificate'"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("domain reconciliation query is missing %q", required)
		}
	}
	if bytes.Contains(body, []byte("operation_type IN ('domain.create','domain.verify')")) {
		t.Fatal("DNS ownership still completes create and verify operations together")
	}
}
