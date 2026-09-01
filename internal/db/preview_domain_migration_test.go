package db

import (
	"bytes"
	"testing"
)

func TestPreviewCustomDomainMigrationBindsLeaseAndGlobalHostname(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/145_preview_custom_domains.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("preview custom-domain migration has no down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE preview_domains"),
		[]byte("FOREIGN KEY (preview_id, account_id)"),
		[]byte("REFERENCES preview_leases(id, account_id) ON DELETE CASCADE"),
		[]byte("preview_generation bigint NOT NULL"),
		[]byte("CREATE UNIQUE INDEX preview_domains_live_hostname_unique"),
		[]byte("ownership_state IN ('pending','failed','verified')"),
		[]byte("pg_advisory_xact_lock(hashtextextended(candidate, 145))"),
		[]byte("domain_bindings_live_hostname_unique"),
		[]byte("CREATE TRIGGER preview_domains_global_hostname_claim_v1"),
		[]byte("CREATE TRIGGER tunnel_domains_global_hostname_claim_v1"),
		[]byte("FROM preview_domains AS other"),
		[]byte("FROM tunnel_domains AS other"),
		[]byte("other.id <> NEW.id"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("preview custom-domain migration missing %q", required)
		}
	}
	if !bytes.Contains(down, []byte("cannot remove preview custom domains while bindings exist")) {
		t.Fatal("preview custom-domain migration down path must fail closed with live or historical bindings")
	}
	if bytes.Contains(up, []byte("ADD CONSTRAINT preview_leases_id_account_unique")) || bytes.Contains(down, []byte("DROP CONSTRAINT IF EXISTS preview_leases_id_account_unique")) {
		t.Fatal("preview custom-domain migration must not recreate or drop migration-125-owned preview lease scope constraint")
	}
}
