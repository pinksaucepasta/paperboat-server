package db

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEmbeddedMigrationVersionsAreUnique(t *testing.T) {
	entries, err := migrationsFS.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}

	versions := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			t.Fatalf("migration %q has no numeric version prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration %q has an invalid version prefix: %v", entry.Name(), err)
		}
		if existing, exists := versions[version]; exists {
			t.Fatalf("migration version %d is duplicated by %q and %q", version, existing, entry.Name())
		}
		versions[version] = entry.Name()
	}
}

func TestClientSetupModeMigrationDropsConstraintBeforeRenamingValues(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/111_client_setup_mode.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range bytes.Split(body, []byte("-- +goose Down")) {
		drop := bytes.Index(section, []byte("DROP CONSTRAINT user_machines_setup_mode_check"))
		update := bytes.Index(section, []byte("UPDATE user_machines SET setup_mode"))
		if drop < 0 || update < 0 || drop > update {
			t.Fatalf("setup-mode migration must drop the old check constraint before updating constrained values: %s", section)
		}
	}
}

func TestMachineSetupModeMigrationsOnlyPermitHostAndClient(t *testing.T) {
	fresh, err := migrationsFS.ReadFile("migrations/077_machine_setup_modes.sql")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fresh, []byte("'session'")) {
		t.Fatal("fresh machine setup schema must not contain the obsolete session mode")
	}

	forward, err := migrationsFS.ReadFile("migrations/112_remove_session_setup_mode.sql")
	if err != nil {
		t.Fatal(err)
	}
	drop := bytes.Index(forward, []byte("DROP CONSTRAINT user_machines_setup_mode_check"))
	convert := bytes.Index(forward, []byte("WHERE setup_mode = 'session'"))
	constraint := bytes.LastIndex(forward, []byte("CHECK (setup_mode IN ('client','host'))"))
	if drop < 0 || convert < 0 || constraint < 0 || !(drop < convert && convert < constraint) {
		t.Fatalf("forward setup-mode migration must remove the old check, convert session rows, then enforce host/client only: %s", forward)
	}
}

func TestCLIEndpointEnrollmentLifecycleMigrationsAreClosedWorld(t *testing.T) {
	role, err := migrationsFS.ReadFile("migrations/114_peer_endpoint_enrollment_role_check.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_role_check"),
		[]byte("CHECK (role IN ('machine','cli')) NOT VALID"),
		[]byte("VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_role_check"),
	} {
		if !bytes.Contains(role, required) {
			t.Fatalf("role compatibility migration missing %q: %s", required, role)
		}
	}

	lifecycle, err := migrationsFS.ReadFile("migrations/115_cli_endpoint_enrollment_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("CHECK (state IN ('pending','fulfilled','expired','denied','revoked')) NOT VALID"),
		[]byte("CREATE TABLE peer_endpoint_enrollment_denials"),
		[]byte("request_id text NOT NULL UNIQUE REFERENCES peer_endpoint_enrollment_requests(id) ON DELETE CASCADE"),
		[]byte("'client_revoked'"),
		[]byte("VALIDATE CONSTRAINT peer_endpoint_certificates_revocation_reason_check"),
		[]byte("CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_on_session_revocation()"),
		[]byte("trg_cli_client_sessions_revoke_peer_endpoint"),
	} {
		if !bytes.Contains(lifecycle, required) {
			t.Fatalf("CLI lifecycle migration missing %q: %s", required, lifecycle)
		}
	}

	repair, err := migrationsFS.ReadFile("migrations/116_cli_endpoint_revocation_repair.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("CREATE OR REPLACE FUNCTION revoke_cli_peer_endpoint_for_session("),
		[]byte("ON CONFLICT (user_id, certificate_fingerprint) DO NOTHING"),
		[]byte("AFTER UPDATE OF state, revoked_at, revocation_reason ON cli_client_sessions"),
		[]byte("WHERE session.state = 'revoked'"),
		[]byte("'client_revoked','account_revoked'"),
	} {
		if !bytes.Contains(repair, required) {
			t.Fatalf("CLI revocation repair migration missing %q: %s", required, repair)
		}
	}
}
