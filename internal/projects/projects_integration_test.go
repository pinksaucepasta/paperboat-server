package projects

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestCreateProjectPersistsIntentAllocatesStorageAndIsIdempotent(t *testing.T) {
	store := newProjectTestDB(t)
	ctx := context.Background()
	seedProjectCatalogs(t, store)
	insertProjectUser(t, store, "usr_project_create", 12)

	service := NewService(store, audit.NewWriter(store), projectTestConfig())
	input := CreateInput{
		UserID:          "usr_project_create",
		IdempotencyKey:  "create-project-key",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       8,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"codex"},
		IdleTimeoutCode: "15m",
		SetupScript:     "echo setup",
	}
	project, existed, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("first create reported existing project")
	}
	if project.State != "provisioning_storage" || !project.PendingRestartApply {
		t.Fatalf("unexpected project state: %#v", project)
	}
	if project.DesiredConfig.StorageGB != 8 || project.DesiredConfig.MachineTypeCode != "standard-1x" {
		t.Fatalf("unexpected desired config: %#v", project.DesiredConfig)
	}
	var ciphertext []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT script_ciphertext FROM paperboat.project_setup_script_revisions WHERE project_id = $1`, project.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), input.SetupScript) {
		t.Fatal("setup script was stored in plaintext")
	}

	retry, existed, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !existed || retry.ID != project.ID {
		t.Fatalf("idempotent retry = (%q,%v), want (%q,true)", retry.ID, existed, project.ID)
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, input.UserID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 8 {
		t.Fatalf("allocated storage = %d, want 8", allocated)
	}

	conflicting := input
	conflicting.StorageGB = 9
	if _, _, err := service.Create(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting idempotent retry error = %v, want ErrIdempotencyConflict", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, input.UserID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 8 {
		t.Fatalf("allocated storage after idempotency conflict = %d, want 8", allocated)
	}

	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.project_runtime_configs
SET applied_config_hash = desired_config_hash,
    applied_storage_gb = $2,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    pending_restart_apply = false
WHERE project_id = $1`, project.ID, input.StorageGB); err != nil {
		t.Fatal(err)
	}
	applied, err := service.Get(ctx, input.UserID, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if applied.PendingRestartApply || applied.RestartRequired {
		t.Fatalf("applied project still reports pending restart: %#v", applied)
	}
	if applied.CurrentConfig.StorageGB != applied.DesiredConfig.StorageGB ||
		applied.CurrentConfig.MachineTypeCode != applied.DesiredConfig.MachineTypeCode ||
		applied.CurrentConfig.RegionCode != applied.DesiredConfig.RegionCode ||
		applied.CurrentConfig.IdleTimeoutCode != applied.DesiredConfig.IdleTimeoutCode ||
		strings.Join(applied.CurrentConfig.PresetCodes, ",") != strings.Join(applied.DesiredConfig.PresetCodes, ",") {
		t.Fatalf("current config was not hydrated from applied desired config: current=%#v desired=%#v", applied.CurrentConfig, applied.DesiredConfig)
	}

	trimmedInput := input
	trimmedInput.IdempotencyKey = "create-project-trimmed-url-key"
	trimmedInput.Name = ""
	trimmedInput.RepositoryURL = " https://github.com/paperboat/spaced.git "
	trimmedInput.StorageGB = 4
	trimmedProject, _, err := service.Create(ctx, trimmedInput)
	if err != nil {
		t.Fatal(err)
	}
	if trimmedProject.Name != "spaced" || trimmedProject.Repository.SourceURL != "https://github.com/paperboat/spaced.git" {
		t.Fatalf("trimmed url project = name %q url %q, want spaced and trimmed source", trimmedProject.Name, trimmedProject.Repository.SourceURL)
	}
}

func TestCreateProjectRejectsDisabledCatalogAndOverAllocation(t *testing.T) {
	store := newProjectTestDB(t)
	ctx := context.Background()
	seedProjectCatalogs(t, store)
	insertProjectUser(t, store, "usr_project_validation", 5)
	service := NewService(store, audit.NewWriter(store), projectTestConfig())

	input := CreateInput{
		UserID:          "usr_project_validation",
		IdempotencyKey:  "disabled-preset-key",
		RepositoryURL:   "https://github.com/paperboat/example.git",
		StorageGB:       2,
		MachineTypeCode: "standard-1x",
		RegionCode:      "iad",
		PresetCodes:     []string{"disabled"},
		IdleTimeoutCode: "15m",
	}
	if _, _, err := service.Create(ctx, input); !errors.Is(err, ErrCatalogUnavailable) {
		t.Fatalf("disabled catalog error = %v, want ErrCatalogUnavailable", err)
	}

	input.IdempotencyKey = "overallocate-key"
	input.PresetCodes = []string{"codex"}
	input.StorageGB = 6
	if _, _, err := service.Create(ctx, input); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("over allocation error = %v, want ErrInsufficientStorage", err)
	}
}

func TestUpdateDesiredConfigMarksRestartRequiredAndDeleteQueuesIntent(t *testing.T) {
	store := newProjectTestDB(t)
	ctx := context.Background()
	seedProjectCatalogs(t, store)
	insertProjectUser(t, store, "usr_project_update", 20)
	service := NewService(store, audit.NewWriter(store), projectTestConfig())

	project, _, err := service.Create(ctx, CreateInput{
		UserID:          "usr_project_update",
		IdempotencyKey:  "update-create-key",
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
	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.project_runtime_configs
SET applied_config_hash = desired_config_hash,
    applied_storage_gb = $2,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    pending_restart_apply = false
WHERE project_id = $1`, project.ID, 8); err != nil {
		t.Fatal(err)
	}
	machine := "standard-2x"
	storageGB := 12
	updated, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, MachineTypeCode: &machine, StorageGB: &storageGB})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DesiredConfig.MachineTypeCode != "standard-2x" || updated.DesiredConfig.StorageGB != 12 || !updated.RestartRequired {
		t.Fatalf("update did not mark desired restart config: %#v", updated)
	}
	if updated.CurrentConfig.MachineTypeCode != "standard-1x" || updated.CurrentConfig.StorageGB != 8 || updated.CurrentConfig.RegionCode != "iad" {
		t.Fatalf("pending update did not preserve applied current config: current=%#v desired=%#v", updated.CurrentConfig, updated.DesiredConfig)
	}
	staleVersion := project.Version
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, ExpectedVersion: &staleVersion, StorageGB: &storageGB}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version update error = %v, want ErrVersionConflict", err)
	}
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, ExpectedVersion: &staleVersion, MachineTypeCode: &machine, StorageGB: &storageGB}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version noop update error = %v, want ErrVersionConflict", err)
	}
	eventsBeforeNoop, err := service.Events(ctx, "usr_project_update", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, MachineTypeCode: &machine, StorageGB: &storageGB})
	if err != nil {
		t.Fatal(err)
	}
	if noop.DesiredConfig.ConfigHash != updated.DesiredConfig.ConfigHash {
		t.Fatalf("noop update changed config hash: %q != %q", noop.DesiredConfig.ConfigHash, updated.DesiredConfig.ConfigHash)
	}
	eventsAfterNoop, err := service.Events(ctx, "usr_project_update", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsAfterNoop) != len(eventsBeforeNoop) {
		t.Fatalf("noop update appended events: before=%d after=%d", len(eventsBeforeNoop), len(eventsAfterNoop))
	}
	var allocated int
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_project_update").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 12 {
		t.Fatalf("allocated after grow = %d, want 12", allocated)
	}
	tooLarge := 30
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &tooLarge}); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("overlarge storage update error = %v, want ErrInsufficientStorage", err)
	}
	var assigned int
	if err := store.SQL().QueryRowContext(ctx, `SELECT assigned_gb FROM paperboat.project_storage_allocations WHERE project_id = $1`, project.ID).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if assigned != 12 {
		t.Fatalf("assigned storage after failed resize = %d, want 12", assigned)
	}
	smaller := 10
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &smaller}); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_project_update").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 10 {
		t.Fatalf("allocated after shrink = %d, want 10", allocated)
	}
	backToTwelve := 12
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &backToTwelve}); err != nil {
		t.Fatalf("grow back to previously used target failed: %v", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_project_update").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 12 {
		t.Fatalf("allocated after grow back = %d, want 12", allocated)
	}
	backToEight := 8
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &backToEight}); err != nil {
		t.Fatalf("shrink back to original size failed: %v", err)
	}
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &backToTwelve}); err != nil {
		t.Fatalf("repeated grow transition failed: %v", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id = $1`, "usr_project_update").Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 12 {
		t.Fatalf("allocated after repeated grow transition = %d, want 12", allocated)
	}
	var machineRows int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.fly_machines WHERE project_id = $1`, project.ID).Scan(&machineRows); err != nil {
		t.Fatal(err)
	}
	if machineRows != 0 {
		t.Fatalf("phase 6 update mutated provider machine rows, count = %d", machineRows)
	}
	deleting, err := service.Delete(ctx, "usr_project_update", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleting.State != "deleting" {
		t.Fatalf("delete state = %q, want deleting", deleting.State)
	}
	afterDeleteSize := 14
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_update", ProjectID: project.ID, StorageGB: &afterDeleteSize}); !errors.Is(err, ErrDeleted) {
		t.Fatalf("update after delete request error = %v, want ErrDeleted", err)
	}
	events, err := service.Events(ctx, "usr_project_update", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 {
		t.Fatalf("events = %#v, want create/update/delete events", events)
	}
}

func TestStartRequiresMinimumCreditsAndRecordsActivity(t *testing.T) {
	store := newProjectTestDB(t)
	ctx := context.Background()
	seedProjectCatalogs(t, store)
	insertProjectUser(t, store, "usr_project_start_credits", 20)
	cfg := projectTestConfig()
	cfg.Metering.MinimumStartCreditWindow = 5 * time.Minute
	service := NewService(store, audit.NewWriter(store), cfg)

	project, _, err := service.Create(ctx, CreateInput{
		UserID:          "usr_project_start_credits",
		IdempotencyKey:  "start-credit-create-key",
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
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.projects SET state = 'stopped' WHERE id = $1`, project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.project_runtime_configs
SET applied_config_hash = desired_config_hash,
    applied_storage_gb = $2,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    pending_restart_apply = false
WHERE project_id = $1`, project.ID, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(ctx, "usr_project_start_credits", project.ID); !errors.Is(err, ErrInsufficientCredits) {
		t.Fatalf("start without credits error = %v, want ErrInsufficientCredits", err)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.orchestration_jobs WHERE job_type = 'project.start' AND aggregate_id = $1 AND state = 'queued'`, project.ID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("queued start jobs without credits = %d, want 0", jobs)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.credit_accounts (id, user_id, balance) VALUES ('cred_start_guard', 'usr_project_start_credits', 0.1)`); err != nil {
		t.Fatal(err)
	}
	started, err := service.Start(ctx, "usr_project_start_credits", project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started.State != "starting" {
		t.Fatalf("started state = %q, want starting", started.State)
	}
	var source string
	if err := store.SQL().QueryRowContext(ctx, `SELECT source FROM paperboat.project_activity_markers WHERE project_id = $1`, project.ID).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if source != "connect_session" {
		t.Fatalf("activity source = %q, want connect_session", source)
	}
}

func TestRestartRequiresCreditsForDesiredMachineType(t *testing.T) {
	store := newProjectTestDB(t)
	ctx := context.Background()
	seedProjectCatalogs(t, store)
	insertProjectUser(t, store, "usr_project_restart_credits", 20)
	cfg := projectTestConfig()
	cfg.Metering.MinimumStartCreditWindow = 5 * time.Minute
	service := NewService(store, audit.NewWriter(store), cfg)

	project, _, err := service.Create(ctx, CreateInput{
		UserID:          "usr_project_restart_credits",
		IdempotencyKey:  "restart-credit-create-key",
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
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.projects SET state = 'running' WHERE id = $1`, project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.project_runtime_configs
SET applied_config_hash = desired_config_hash,
    applied_storage_gb = $2,
    applied_machine_type_version_id = machine_type_version_id,
    applied_preset_version_ids = preset_version_ids,
    applied_setup_script_ref = setup_script_ref,
    applied_idle_timeout_option_id = idle_timeout_option_id,
    applied_region_id = region_id,
    pending_restart_apply = false
WHERE project_id = $1`, project.ID, 8); err != nil {
		t.Fatal(err)
	}
	nextMachineType := "standard-2x"
	if _, err := service.Update(ctx, UpdateInput{UserID: "usr_project_restart_credits", ProjectID: project.ID, MachineTypeCode: &nextMachineType}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.credit_accounts (id, user_id, balance) VALUES ('cred_restart_guard', 'usr_project_restart_credits', 0.1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Restart(ctx, "usr_project_restart_credits", project.ID); !errors.Is(err, ErrInsufficientCredits) {
		t.Fatalf("restart with insufficient desired credits error = %v, want ErrInsufficientCredits", err)
	}
	var jobs int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.orchestration_jobs WHERE job_type = 'project.restart' AND aggregate_id = $1 AND state = 'queued'`, project.ID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("queued restart jobs with insufficient desired credits = %d, want 0", jobs)
	}
}

func newProjectTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run project integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	resetProjectTestTables(t, store)
	return store
}

func resetProjectTestTables(t *testing.T, store *db.DB) {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if !safeProjectTestDSN(dsn) && os.Getenv("PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET") != "true" {
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

func safeProjectTestDSN(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	name := strings.ToLower(strings.Trim(strings.TrimSpace(u.Path), "/"))
	return strings.Contains(name, "test") || strings.Contains(name, "dev") || strings.Contains(name, "local")
}

func insertProjectUser(t *testing.T, store *db.DB, userID string, includedGB int) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, $3, 'active')`, userID, "workos_"+userID, userID+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb) VALUES ($1, $2, $3)`, "stor_"+userID, userID, includedGB); err != nil {
		t.Fatal(err)
	}
}

func seedProjectCatalogs(t *testing.T, store *db.DB) {
	t.Helper()
	ctx := context.Background()
	for _, row := range []struct {
		code   string
		name   string
		vcpu   int
		memory int
		weight string
	}{
		{"standard-1x", "Standard 1x", 4, 8192, "1"},
		{"standard-2x", "Standard 2x", 8, 16384, "2"},
	} {
		id := "mt_" + row.code
		versionID := "mtv_" + row.code
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id) VALUES ($1, $2, $3, $4, $5, $6::numeric, true, $7)`, id, row.code, row.name, row.vcpu, row.memory, row.weight, versionID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight) VALUES ($1, $2, 1, $3, $4, $5::numeric)`, versionID, id, row.vcpu, row.memory, row.weight); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		code   string
		active bool
	}{
		{"codex", true},
		{"disabled", false},
	} {
		id := "preset_" + row.code
		versionID := "presetv_" + row.code
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_presets (id, code, name, active, current_version_id) VALUES ($1, $2, $2, $3, $4)`, id, row.code, row.active, versionID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.vm_preset_versions (id, preset_id, version_number, manifest) VALUES ($1, $2, 1, '{}'::jsonb)`, versionID, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ('region_iad', 'iad', 'Ashburn', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.idle_timeout_options (id, code, duration_seconds, active) VALUES ('idle_15m', '15m', 900, true)`); err != nil {
		t.Fatal(err)
	}
}

func projectTestConfig() config.Config {
	cfg := config.Default()
	cfg.Secrets.EncryptionKey = "test-project-encryption-key-for-phase-six"
	return cfg
}
