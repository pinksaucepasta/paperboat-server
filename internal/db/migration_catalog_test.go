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

func TestPeerEndpointRoleCompatibilityMigrationRestoresFreshSchemaInvariant(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/114_peer_endpoint_enrollment_role_check.sql")
	if err != nil {
		t.Fatal(err)
	}

	drop := []byte("DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_role_check")
	constraint := []byte("ADD CONSTRAINT peer_endpoint_enrollment_requests_role_check")
	check := []byte("CHECK (role IN ('machine','cli')) NOT VALID")
	validate := []byte("VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_role_check")
	if bytes.Index(body, drop) < 0 || bytes.Index(body, constraint) < bytes.Index(body, drop) || bytes.Index(body, check) < bytes.Index(body, constraint) || bytes.Index(body, validate) < bytes.Index(body, check) {
		t.Fatalf("CLI endpoint role compatibility migration does not add and validate the fresh-schema invariant: %s", body)
	}
}

func TestAuthenticatedHostSetupMigrationBindsSessionOperationGenerationAndMode(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/115_authenticated_host_setup_installations.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("authenticated_setup_cli_session_id text REFERENCES cli_client_sessions(id) ON DELETE CASCADE"),
		[]byte("authenticated_setup_operation_id text"),
		[]byte("authenticated_setup_generation bigint"),
		[]byte("authenticated_setup_mode text"),
		[]byte("authenticated_setup_helper_enrollment_id text REFERENCES control_helper_enrollments(id) ON DELETE SET NULL"),
		[]byte("authenticated_setup_operation_id IS NOT NULL"),
		[]byte("authenticated_setup_generation IS NOT NULL"),
		[]byte("authenticated_setup_mode IS NOT NULL"),
		[]byte("authenticated_setup_mode = 'host'"),
		[]byte("approved_by_user_id IS NOT NULL"),
		[]byte("user_machine_id IS NOT NULL"),
		[]byte("CREATE UNIQUE INDEX user_machine_pairings_authenticated_setup_operation"),
		[]byte("authenticated_setup_cli_session_id, authenticated_setup_operation_id"),
		[]byte("CREATE UNIQUE INDEX user_machine_pairings_authenticated_setup_helper_enrollment"),
		[]byte("ON user_machine_pairings(authenticated_setup_helper_enrollment_id)"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("authenticated Host setup migration is missing %q: %s", required, body)
		}
	}
}
