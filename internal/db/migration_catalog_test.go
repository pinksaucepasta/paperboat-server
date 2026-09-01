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

func TestEnvironmentTransitionOperationMigrationAllowsAtomicMultiScopeStaging(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/148_environment_transition_shared_operation.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("DROP CONSTRAINT IF EXISTS environment_transition_manifests_transition_id_operation_id_key")) ||
		bytes.Contains(bytes.ToUpper(body), []byte("ADD CONSTRAINT")) {
		t.Fatalf("ENV transition operation migration must only remove the invalid per-transition operation uniqueness: %s", body)
	}
}

func TestEdgeCarrierServerTrustMigrationIsBoundedAndReversible(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/138_edge_carrier_server_spki.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("carrier_server_spki_sha256"),
		[]byte("carrier_server_certificate_chain_pem"),
		[]byte("edge_carrier_server_spki_sha256"),
		[]byte("edge_carrier_server_certificate_chain_pem"),
		[]byte("^sha256:[0-9a-f]{64}$"),
		[]byte("65536"),
		[]byte("-- +goose Down"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("edge carrier trust migration missing %q", required)
		}
	}
}

func TestMachineEnvironmentCapabilityMigrationWidenedOnlyForHosts(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/141_machine_environment_capability.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("machine capability migration has no goose down section")
	}
	if !bytes.Contains(up, []byte("DROP CONSTRAINT user_machines_observed_capabilities_check")) || !bytes.Contains(up, []byte("DROP CONSTRAINT user_machines_configured_capabilities_check")) {
		t.Fatalf("machine capability migration must replace the old capability constraints: %s", up)
	}
	if !bytes.Contains(up, []byte("WHERE setup_mode = 'host'")) || !bytes.Contains(up, []byte("environment_injection")) {
		t.Fatalf("machine capability migration must add environment injection only to host defaults: %s", up)
	}
	if !bytes.Contains(up, []byte("observed_capabilities <@ configured_capabilities")) || !bytes.Contains(up, []byte("configured_capabilities SET DEFAULT")) {
		t.Fatalf("machine capability migration must retain observed/configured invariants: %s", up)
	}
	if !bytes.Contains(down, []byte("array_remove(configured_capabilities, 'environment_injection')")) || !bytes.Contains(down, []byte("array_remove(observed_capabilities, 'environment_injection')")) {
		t.Fatalf("machine capability migration down path must remove the widened capability: %s", down)
	}
}

func TestEnvironmentE2EESchemaStoresOnlyOpaqueDocuments(t *testing.T) {
	fresh, err := migrationsFS.ReadFile("migrations/139_environment_variables.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("value_bytes"), []byte("encryption_nonce"), []byte("content_hash"), []byte("wrapped_dek")} {
		if bytes.Contains(fresh, forbidden) {
			t.Fatalf("fresh ENV E2EE schema contains server-decryptable/plaintext-derived field %q", forbidden)
		}
	}
	for _, required := range [][]byte{[]byte("environment_authorities"), []byte("environment_scope_manifests"), []byte("environment_host_bootstraps"), []byte("envelope bytea"), []byte("recipient_public_key bytea")} {
		if !bytes.Contains(fresh, required) {
			t.Fatalf("fresh ENV E2EE schema missing %q", required)
		}
	}

	cutover, err := migrationsFS.ReadFile("migrations/143_environment_e2ee_cutover.sql")
	if err != nil {
		t.Fatal(err)
	}
	drop := bytes.Index(cutover, []byte("DROP TABLE IF EXISTS environment_variables"))
	create := bytes.Index(cutover, []byte("CREATE TABLE IF NOT EXISTS environment_authority_heads"))
	if drop < 0 || create < 0 || drop > create {
		t.Fatal("ENV cutover must discard the unreleased server-decryptable tables before creating opaque state")
	}
	beforeCreate := bytes.ToLower(cutover[:create])
	for _, legacyTable := range []string{"environment_variable_observations", "environment_variables", "environment_variable_scopes"} {
		statement := []byte("drop table if exists " + legacyTable)
		if bytes.Count(beforeCreate, statement) != 1 {
			t.Fatalf("ENV cutover must unconditionally drop legacy table %q exactly once", legacyTable)
		}
	}
	if bytes.Contains(beforeCreate, []byte("information_schema.columns")) {
		t.Fatal("ENV cutover must not gate legacy cleanup on a legacy column name")
	}
	for _, unsafeRead := range [][]byte{[]byte("select value_bytes"), []byte("select encryption_nonce"), []byte("select wrapped_dek")} {
		if bytes.Contains(beforeCreate, unsafeRead) {
			t.Fatal("ENV cutover must not read or transform old plaintext values")
		}
	}

	cleanup, err := migrationsFS.ReadFile("migrations/147_environment_e2ee_legacy_cleanup.sql")
	if err != nil {
		t.Fatal(err)
	}
	cleanupUp, _, ok := bytes.Cut(cleanup, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("ENV legacy cleanup migration has no goose down section")
	}
	for _, legacyTable := range []string{"environment_variable_observations", "environment_variables", "environment_variable_scopes"} {
		if bytes.Count(bytes.ToLower(cleanupUp), []byte("drop table if exists "+legacyTable)) != 1 {
			t.Fatalf("ENV legacy cleanup must unconditionally drop legacy table %q exactly once", legacyTable)
		}
	}
	if bytes.Contains(bytes.ToLower(cleanupUp), []byte("information_schema")) {
		t.Fatal("ENV legacy cleanup must not inspect legacy columns before dropping them")
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
	if !bytes.Contains(body, drop) || bytes.Index(body, constraint) < bytes.Index(body, drop) || bytes.Index(body, check) < bytes.Index(body, constraint) || bytes.Index(body, validate) < bytes.Index(body, check) {
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

func TestPreviewTunnelV1MigrationIsAdditiveAndSecretFree(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/122_preview_tunnel_v1_persistence.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"tunnels", "tunnel_routes", "tunnel_domains", "tunnel_connectors",
		"tunnel_connector_sessions", "preview_leases", "tunnel_config_generations", "operations",
	} {
		if !bytes.Contains(body, []byte("CREATE TABLE "+table+" (")) {
			t.Errorf("preview/tunnel v1 migration is missing table %s", table)
		}
	}
	for _, required := range [][]byte{
		[]byte("UNIQUE (account_id, name)"),
		[]byte("UNIQUE (account_id, idempotency_key)"),
		[]byte("UNIQUE (tunnel_id, host_id)"),
		[]byte("FOREIGN KEY (tunnel_id, previous_generation)"),
		[]byte("CREATE TRIGGER tunnel_config_generations_immutable"),
		[]byte("CREATE TRIGGER audit_events_append_only"),
		[]byte("credential_reference text NOT NULL"),
		[]byte("-- Non-destructive on purpose."),
	} {
		if !bytes.Contains(body, required) {
			t.Errorf("preview/tunnel v1 migration is missing %q", required)
		}
	}
	up, _, _ := bytes.Cut(body, []byte("-- +goose Down"))
	for _, legacy := range [][]byte{
		[]byte("DROP TABLE control_previews"),
		[]byte("DROP TABLE control_routes"),
		[]byte("DROP TABLE control_connector_generations"),
	} {
		if bytes.Contains(up, legacy) {
			t.Errorf("TRK-03 migration removes legacy state before TRK-29: %q", legacy)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("credential_ciphertext"),
		[]byte("private_key"),
		[]byte(" bearer_token"),
		[]byte(" reusable_token"),
	} {
		if bytes.Contains(up, forbidden) {
			t.Errorf("preview/tunnel v1 schema contains forbidden reusable credential field %q", forbidden)
		}
	}
}

func TestTunnelResourcesMigrationDownIsGuardedAndReversible(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/125_tunnel_resources_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("TRK-07 resource migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("UNIQUE (id, tunnel_id)"),
		[]byte("UNIQUE (id, tunnel_id, host_id)"),
		[]byte("FOREIGN KEY (connector_id, tunnel_id)"),
		[]byte("FOREIGN KEY (connector_id, tunnel_id, host_id)"),
		[]byte("FOREIGN KEY (route_id, tunnel_id)"),
		[]byte("FOREIGN KEY (tunnel_id, account_id)"),
		[]byte("verifier_public_key bytea NOT NULL"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("TRK-07 resource migration is missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("origin_scheme = 'unix'"),
		[]byte("cannot roll back tunnel resources: unix origins require a forward migration"),
		[]byte("SET origin_scheme = 'http'"),
		[]byte("SET drain_state = 'drained'"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("TRK-07 resource migration down path is missing guarded normalization %q", required)
		}
	}

	hardening, err := migrationsFS.ReadFile("migrations/126_tunnel_resource_scope_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("operations_id_account_unique"),
		[]byte("tunnel_connector_enrollments_operation_account_fk"),
		[]byte("tunnel_connector_enrollments_consumed_connector_check"),
	} {
		if !bytes.Contains(hardening, required) {
			t.Fatalf("TRK-07 scope hardening migration is missing %q", required)
		}
	}
}

func TestTunnelConfigSnapshotBytesMigrationPreservesHashInvariant(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/128_tunnel_config_snapshot_bytes.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := bytes.Cut(body, []byte("-- +goose Down"))
	if !ok {
		t.Fatal("snapshot byte migration has no goose down section")
	}
	for _, required := range [][]byte{
		[]byte("CREATE EXTENSION IF NOT EXISTS pgcrypto"),
		[]byte("DROP TRIGGER IF EXISTS tunnel_config_generations_immutable ON tunnel_config_generations"),
		[]byte("DROP CONSTRAINT IF EXISTS tunnel_config_generations_snapshot_check"),
		[]byte("CREATE FUNCTION canonical_config_snapshot_string(value text)"),
		[]byte("chr(8232), chr(92) || 'u2028'"),
		[]byte("chr(8233), chr(92) || 'u2029'"),
		[]byte("SQL canonical bytes do not match stored content hash"),
		[]byte("ALTER COLUMN snapshot TYPE bytea"),
		[]byte("USING convert_to(canonical_config_snapshot_jsonb(snapshot), 'UTF8')"),
		[]byte("SET content_hash = digest(snapshot, 'sha256')"),
		[]byte("tunnel_config_generations_snapshot_bytes_check"),
		[]byte("CREATE TRIGGER tunnel_config_generations_immutable"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("snapshot byte migration is missing %q: %s", required, up)
		}
	}
	for _, required := range [][]byte{
		[]byte("payload is not valid UTF-8 JSON"),
		[]byte("payload is not a JSON object"),
		[]byte("ALTER COLUMN snapshot TYPE jsonb"),
		[]byte("ADD CONSTRAINT tunnel_config_generations_snapshot_check"),
		[]byte("SET content_hash = digest(convert_to(canonical_config_snapshot_jsonb(snapshot), 'UTF8'), 'sha256')"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("snapshot byte migration down path is missing guard/recompute %q: %s", required, down)
		}
	}
}
