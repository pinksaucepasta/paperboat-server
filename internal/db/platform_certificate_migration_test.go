package db

import (
	"bytes"
	"os"
	"testing"
)

func TestPlatformCertificateMigrationPreservesTargetGuardsAndOwnerCascade(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/150_tunnel_platform_certificate_targets.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("platform certificate migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE TABLE tunnel_platform_certificate_targets"),
		[]byte("account_id = 'platform_system_v1'"),
		[]byte("platform_wildcard"),
		[]byte("user_account_id text REFERENCES users(id) ON DELETE CASCADE"),
		[]byte("tunnel_certificate_records_user_account_match_check"),
		[]byte("tunnel_certificate_target_guard_v1"),
		[]byte("tunnel_certificate_issuance_lock_target_guard_v1"),
		[]byte("cannot remove platform certificate targets while platform certificate rows or locks exist"),
	} {
		if !bytes.Contains(up, required) && !bytes.Contains(down, required) {
			t.Fatalf("platform certificate migration missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("target_kind IN ('durable_route','preview_lease')"),
		[]byte("strategy IN ('delegated_dns01','provided_reference','on_demand_leaf','wildcard_fallback')"),
		[]byte("DROP CONSTRAINT IF EXISTS tunnel_certificate_records_target_strategy_check"),
		[]byte("target_kind = 'durable_route'"),
		[]byte("target_kind = 'preview_lease'"),
		[]byte("FOREIGN KEY (account_id) REFERENCES users(id) ON DELETE CASCADE"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("platform migration Down does not restore %q", required)
		}
	}
	if bytes.Contains(down, []byte("ALTER COLUMN domain_id SET NOT NULL")) || bytes.Contains(down, []byte("ALTER COLUMN tunnel_id SET NOT NULL")) {
		t.Fatal("platform migration Down incorrectly restores pre-preview non-null target columns")
	}
	if bytes.Contains(down, []byte("FROM tunnel_certificate_records WHERE target_kind = 'preview_lease'")) || bytes.Contains(down, []byte("cannot remove platform certificate targets while platform or preview")) {
		t.Fatal("platform migration Down incorrectly blocks preview-domain rows")
	}
}

func TestPlatformTargetIdentityUpsertDoesNotAdvanceLifecycleTime(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificates_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(body, []byte("-- name: UpsertTunnelPlatformCertificateTargetV1"))
	end := bytes.Index(body, []byte("-- name: ListTunnelPlatformCertificateTargetsV1"))
	if start < 0 || end <= start {
		t.Fatal("platform target upsert query was not found")
	}
	query := body[start:end]
	if !bytes.Contains(query, []byte("SET id = tunnel_platform_certificate_targets.id")) {
		t.Fatal("platform target identity replay is not an explicit lifecycle no-op")
	}
	if bytes.Contains(query, []byte("SET updated_at = EXCLUDED.updated_at")) {
		t.Fatal("platform target identity replay advances updated_at while retaining retry state")
	}
}

func TestPlatformCertificateReplayIsPayloadFencedBeforeRestaging(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificates_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(body, []byte("-- name: CreateTunnelPlatformCertificateRecordV1"))
	end := bytes.Index(body, []byte("-- name: SupersedeOlderTunnelPlatformCertificatesV1"))
	if start < 0 || end <= start {
		t.Fatal("platform certificate create query was not found")
	}
	query := body[start:end]
	for _, field := range []string{
		"strategy", "certificate_reference", "master_key_reference",
		"certificate_ciphertext", "private_key_ciphertext", "fingerprint",
		"issuer", "not_before", "expires_at", "renewal_at",
	} {
		fence := []byte("tunnel_certificate_records." + field + " = EXCLUDED." + field)
		if !bytes.Contains(query, fence) {
			t.Fatalf("platform certificate replay can mutate state before checking %s", field)
		}
	}
}
