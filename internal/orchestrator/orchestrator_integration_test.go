package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

func TestProvisionProjectIsIdempotentAndReachesReady(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_create", 20)

	projectService := projects.NewService(store, audit.NewWriter(store), orchestratorTestConfig())
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_create",
		IdempotencyKey:  "orch-create",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       10,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	service := NewService(store, fakeFly, orchestratorTestConfig())
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	ready, err := projectService.Get(ctx, "usr_orch_create", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != "ready" || ready.PendingRestartApply {
		t.Fatalf("project after provisioning = %#v, want ready with applied config", ready)
	}
	if len(fakeFly.Volumes) != 1 || len(fakeFly.Machines) != 1 {
		t.Fatalf("fake Fly resources = %d volumes, %d machines; want one each", len(fakeFly.Volumes), len(fakeFly.Machines))
	}
	if err := service.provisionProject(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	if len(fakeFly.Volumes) != 1 || len(fakeFly.Machines) != 1 {
		t.Fatalf("idempotent reprovision duplicated resources: %d volumes, %d machines", len(fakeFly.Volumes), len(fakeFly.Machines))
	}
}

func TestProvisionAdoptsExistingProviderResourcesBeforeCreate(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_adopt", 20)

	cfg := orchestratorTestConfig()
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_adopt",
		IdempotencyKey:  "orch-adopt",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	fakeFly.Volumes["vol_existing"] = fly.Volume{ID: "vol_existing", Name: "pbvol-" + strings.ReplaceAll(project.ID, "_", "-"), SizeGB: 8, Region: "iad", State: "created"}
	fakeFly.Machines["mach_existing"] = fly.Machine{ID: "mach_existing", Name: "pbvm-" + strings.ReplaceAll(project.ID, "_", "-"), State: "stopped", Region: "iad", Tags: map[string]string{"paperboat_project_id": project.ID, "managed_by": "paperboat-server"}}

	service := NewService(store, fakeFly, cfg)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := countCalls(fakeFly.Calls, "CreateVolume:"); calls != 0 {
		t.Fatalf("adoption created duplicate volume, calls=%d", calls)
	}
	if calls := countCalls(fakeFly.Calls, "CreateMachine:"); calls != 0 {
		t.Fatalf("adoption created duplicate machine, calls=%d", calls)
	}
	var volumeID, machineID string
	if err := store.SQL().QueryRowContext(ctx, `SELECT fly_volume_id FROM paperboat.fly_volumes WHERE project_id = $1`, project.ID).Scan(&volumeID); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT fly_machine_id FROM paperboat.fly_machines WHERE project_id = $1`, project.ID).Scan(&machineID); err != nil {
		t.Fatal(err)
	}
	if volumeID != "vol_existing" || machineID != "mach_existing" {
		t.Fatalf("adopted ids = volume %q machine %q", volumeID, machineID)
	}
}

func TestRestartAppliesPendingConfigExactlyOnce(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_restart", 20)

	cfg := orchestratorTestConfig()
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_restart",
		IdempotencyKey:  "orch-restart",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	service := NewService(store, fakeFly, cfg)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	machineType := "standard-2x"
	if _, err := projectService.Update(ctx, projects.UpdateInput{UserID: "usr_orch_restart", ProjectID: project.ID, MachineTypeCode: &machineType}); err != nil {
		t.Fatal(err)
	}
	if err := service.restartProject(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	after, err := projectService.Get(ctx, "usr_orch_restart", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.PendingRestartApply || after.CurrentConfig.MachineTypeCode != "standard-2x" {
		t.Fatalf("restart did not apply desired config: %#v", after)
	}
	firstUpdateCalls := countCalls(fakeFly.Calls, "UpdateMachine:")
	if firstUpdateCalls != 1 {
		t.Fatalf("UpdateMachine calls after first restart = %d, want 1", firstUpdateCalls)
	}
	for machineID, spec := range fakeFly.MachineSpecs {
		if spec.VolumeID == "" {
			t.Fatalf("updated machine %s lost volume mount in spec: %#v", machineID, spec)
		}
	}
	if err := service.restartProject(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	if calls := countCalls(fakeFly.Calls, "UpdateMachine:"); calls != 1 {
		t.Fatalf("second restart re-applied unchanged config, update calls = %d", calls)
	}
}

func TestDeleteReleasesStorageAfterProviderCleanup(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_delete", 20)
	insertGitHubToken(t, store, "usr_orch_delete", "github-delete-token")

	cfg := orchestratorTestConfig()
	cfg.Secrets.AgentunnelMachineToken = "agentunnel-delete-token"
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_delete",
		IdempotencyKey:  "orch-delete",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	service := NewService(store, fakeFly, cfg)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := projectService.Delete(ctx, "usr_orch_delete", project.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_orch_delete").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 0 {
		t.Fatalf("allocated storage after delete = %d, want 0", allocated)
	}
	if len(fakeFly.Volumes) != 0 || len(fakeFly.Machines) != 0 {
		t.Fatalf("provider resources remain after delete: volumes=%d machines=%d", len(fakeFly.Volumes), len(fakeFly.Machines))
	}
	if calls := countCalls(fakeFly.Calls, "DeleteSecret:"); calls != 2 {
		t.Fatalf("DeleteSecret calls = %d, want 2; calls=%#v", calls, fakeFly.Calls)
	}
}

func TestProvisionInjectsConfiguredMachineSecrets(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_secrets", 20)
	insertGitHubToken(t, store, "usr_orch_secrets", "github-config-token")

	cfg := orchestratorTestConfig()
	cfg.Secrets.AgentunnelMachineToken = "agentunnel-machine-token"
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_secrets",
		IdempotencyKey:  "orch-secrets",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFly := fly.NewFakeClient()
	service := NewService(store, fakeFly, cfg)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var spec fly.MachineSpec
	for _, value := range fakeFly.MachineSpecs {
		spec = value
	}
	if !hasSecret(spec.Secrets, cfg.Fly.AgentunnelSecret, "agentunnel-machine-token") {
		t.Fatalf("agentunnel secret was not injected: %#v", spec.Secrets)
	}
	if !hasSecret(spec.Secrets, cfg.Fly.GitHubSecret, "github-config-token") {
		t.Fatalf("github config token was not injected: %#v", spec.Secrets)
	}
	events, err := projectService.Events(ctx, "usr_orch_secrets", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(fmt.Sprint(event.Metadata), "github-config-token") || strings.Contains(fmt.Sprint(event.Metadata), "agentunnel-machine-token") {
			t.Fatalf("project event leaked secret metadata: %#v", event)
		}
	}
}

func TestRestartBlocksPendingStorageResizeUntilPolicyApproved(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	seedOrchestratorCatalogs(t, store)
	insertOrchestratorUser(t, store, "usr_orch_resize", 20)

	cfg := orchestratorTestConfig()
	projectService := projects.NewService(store, audit.NewWriter(store), cfg)
	project, _, err := projectService.Create(ctx, projects.CreateInput{
		UserID:          "usr_orch_resize",
		IdempotencyKey:  "orch-resize",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, fly.NewFakeClient(), cfg)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	nextStorage := 10
	if _, err := projectService.Update(ctx, projects.UpdateInput{UserID: "usr_orch_resize", ProjectID: project.ID, StorageGB: &nextStorage}); err != nil {
		t.Fatal(err)
	}
	if err := service.restartProject(ctx, project.ID); !errors.Is(err, ErrVolumeResizeRequiresApproval) {
		t.Fatalf("resize restart error = %v, want ErrVolumeResizeRequiresApproval", err)
	}
	after, err := projectService.Get(ctx, "usr_orch_resize", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.PendingRestartApply || after.CurrentConfig.StorageGB != 8 || after.DesiredConfig.StorageGB != 10 {
		t.Fatalf("resize block should preserve pending config: %#v", after)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.projects SET state = 'running' WHERE id = $1`, project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.credit_accounts (id, user_id, balance) VALUES ('cred_orch_resize', 'usr_orch_resize', 0.1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := projectService.Restart(ctx, "usr_orch_resize", project.ID); err != nil {
		t.Fatal(err)
	}
	var restartEventType string
	if err := store.SQL().QueryRowContext(ctx, `SELECT event_type FROM paperboat.project_events WHERE project_id = $1 AND event_type = 'project.restart_queued'`, project.ID).Scan(&restartEventType); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(ctx); !errors.Is(err, ErrVolumeResizeRequiresApproval) {
		t.Fatalf("queued resize restart error = %v, want ErrVolumeResizeRequiresApproval", err)
	}
	var jobState, projectState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.orchestration_jobs WHERE job_type = 'project.restart' AND aggregate_id = $1`, project.ID).Scan(&jobState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.projects WHERE id = $1`, project.ID).Scan(&projectState); err != nil {
		t.Fatal(err)
	}
	if jobState != "blocked" || projectState != "running" {
		t.Fatalf("resize block states = job %q project %q, want blocked/running", jobState, projectState)
	}
}

func TestReconcileQueuesOrphanMachineForReview(t *testing.T) {
	store := newOrchestratorTestDB(t)
	ctx := context.Background()
	fakeFly := fly.NewFakeClient()
	fakeFly.Machines["mach_orphan"] = fly.Machine{
		ID: "mach_orphan", Name: "pbvm-orphan", State: "stopped", Region: "iad",
		Tags: map[string]string{"managed_by": "paperboat-server", "paperboat_project_id": "prj_missing"},
	}
	service := NewService(store, fakeFly, orchestratorTestConfig())
	run, err := service.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Findings) != 1 || !strings.Contains(run.Findings[0].Message, "orphan") {
		t.Fatalf("reconcile findings = %#v, want orphan finding", run.Findings)
	}
	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.orchestration_jobs WHERE job_type = 'fly.orphan.remediate' AND aggregate_id = 'mach_orphan'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "needs_review" {
		t.Fatalf("orphan job state = %q, want needs_review", state)
	}
}

func countCalls(calls []string, prefix string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func hasSecret(secrets []fly.MachineSecret, envVar, value string) bool {
	for _, secret := range secrets {
		if secret.EnvVar == envVar && secret.Value == value && secret.Name != "" {
			return true
		}
	}
	return false
}

func insertGitHubToken(t *testing.T, store *db.DB, userID, token string) {
	t.Helper()
	ciphertext, err := secrets.Encrypt(orchestratorTestConfig().Secrets.EncryptionKey, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.github_oauth_tokens (id, user_id, token_ciphertext, scopes, provider_account_login, last_validated_at)
VALUES ($1, $2, $3, ARRAY['repo'], $4, now())`, "ght_"+userID, userID, ciphertext, "gh_"+userID); err != nil {
		t.Fatal(err)
	}
}

func newOrchestratorTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run orchestrator integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	resetOrchestratorTestTables(t, store)
	return store
}

func resetOrchestratorTestTables(t *testing.T, store *db.DB) {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if !safeOrchestratorTestDSN(dsn) && os.Getenv("PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET") != "true" {
		t.Fatalf("refusing to truncate paperboat schema for unsafe PAPERBOAT_TEST_DATABASE_DSN")
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
DO $$
DECLARE
	tables text;
BEGIN
	SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
	INTO tables
	FROM pg_tables
	WHERE schemaname = 'paperboat'
	  AND tablename <> 'schema_migrations';

	IF tables IS NOT NULL THEN
		EXECUTE 'TRUNCATE TABLE ' || tables || ' CASCADE';
	END IF;
END $$;`); err != nil {
		t.Fatal(err)
	}
}

func safeOrchestratorTestDSN(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	name := strings.ToLower(strings.Trim(strings.TrimSpace(u.Path), "/"))
	return strings.Contains(name, "test") || strings.Contains(name, "dev") || strings.Contains(name, "local")
}

func insertOrchestratorUser(t *testing.T, store *db.DB, userID string, includedGB int) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, $3, 'active')`, userID, "workos_"+userID, userID+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb) VALUES ($1, $2, $3)`, "stor_"+userID, userID, includedGB); err != nil {
		t.Fatal(err)
	}
}

func seedOrchestratorCatalogs(t *testing.T, store *db.DB) {
	t.Helper()
	ctx := context.Background()
	for _, row := range []struct {
		code     string
		name     string
		vcpu     int
		memoryMB int
		weight   string
	}{
		{"standard-1x", "Standard 1x", 4, 8192, "1"},
		{"standard-2x", "Standard 2x", 8, 16384, "2"},
	} {
		versionID := "mtv_" + row.code
		if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id)
VALUES ($1, $2, $3, $4, $5, $6, true, $7)
ON CONFLICT (code) DO UPDATE SET current_version_id = EXCLUDED.current_version_id, active = true`,
			"mt_"+row.code, row.code, row.name, row.vcpu, row.memoryMB, row.weight, versionID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight)
VALUES ($1, $2, 1, $3, $4, $5)
ON CONFLICT DO NOTHING`, versionID, "mt_"+row.code, row.vcpu, row.memoryMB, row.weight); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ('reg_iad', 'iad', 'IAD', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.idle_timeout_options (id, code, duration_seconds, active) VALUES ('ito_15m', '15m', 900, true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_presets (id, code, name, active, current_version_id) VALUES ('preset_codex', 'codex', 'Codex', true, 'presetv_codex')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_preset_versions (id, preset_id, version_number, manifest) VALUES ('presetv_codex', 'preset_codex', 1, '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
}

func orchestratorTestConfig() config.Config {
	cfg := config.Default()
	cfg.Secrets.EncryptionKey = "orchestrator-test-encryption-key"
	cfg.Fly.AppName = "paperboat-test"
	cfg.Fly.ImageRef = "registry.example.invalid/paperboat/project-vm:test"
	return cfg
}
