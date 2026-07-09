package metering_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

func TestRuntimeMeteringDebitsWeightedConcurrentMachines(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "a", "mach_a_"+suffix, "standard-1x", "1", 3600)
	seedMeteredProjectForUser(t, store, suffix, userID, "b", "mach_b_"+suffix, "standard-2x", "2", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_"+suffix, "grant-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_a_"+suffix] = fly.Machine{ID: "mach_a_" + suffix, State: "running"}
	flyClient.Machines["mach_b_"+suffix] = fly.Machine{ID: "mach_b_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(time.Hour) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "7.000000" {
		t.Fatalf("balance = %s, want 7.000000", balance)
	}
	var checkpoints int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.metering_checkpoints WHERE user_id = $1 AND state = 'processed'`, userID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 2 {
		t.Fatalf("processed checkpoints = %d, want 2", checkpoints)
	}
}

func TestRuntimeMeteringTreatsFlyStartedAsRunning(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "started", "mach_started_"+suffix, "standard-1x", "1", 7200)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_started_"+suffix, "grant-started-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_started_"+suffix] = fly.Machine{ID: "mach_started_" + suffix, State: "started"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(time.Hour) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var balance, providerState, projectState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.fly_machines WHERE project_id = $1`, "prj_started_"+suffix).Scan(&providerState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.projects WHERE id = $1`, "prj_started_"+suffix).Scan(&projectState); err != nil {
		t.Fatal(err)
	}
	if balance != "9.000000" || providerState != "started" || projectState != "running" {
		t.Fatalf("started state metering = balance %s provider %s project %s", balance, providerState, projectState)
	}
}

func TestRuntimeMeteringCheckpointIsIdempotent(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "idem", "mach_idem_"+suffix, "standard-1x", "1", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_idem_"+suffix, "grant-idem-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_idem_"+suffix] = fly.Machine{ID: "mach_idem_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(time.Hour) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "9.000000" {
		t.Fatalf("balance = %s, want 9.000000", balance)
	}
}

func TestRuntimeMeteringRecoversCreatedCheckpointWithoutOverlap(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "recover", "mach_recover_"+suffix, "standard-1x", "1", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_recover_"+suffix, "grant-recover-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_recover_"+suffix] = fly.Machine{ID: "mach_recover_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var intervalID string
	if err := store.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.machine_runtime_intervals WHERE project_id = $1`, "prj_recover_"+suffix).Scan(&intervalID); err != nil {
		t.Fatal(err)
	}
	checkpointID := "mchk_recover_" + suffix
	checkpointKey := "metering.runtime:" + intervalID + ":recover"
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.metering_checkpoints
	(id, runtime_interval_id, project_id, user_id, period_start, period_end, runtime_seconds, credit_weight, credits_debited, idempotency_key, state)
VALUES ($1, $2, $3, $4, $5, $6, 3600, 1, 1, $7, 'created')`,
		checkpointID, intervalID, "prj_recover_"+suffix, userID, start, start.Add(time.Hour), checkpointKey); err != nil {
		t.Fatal(err)
	}
	if err := billingRepo.DebitCredits(ctx, userID, "cled_recover_"+suffix, checkpointKey, "metering", checkpointID, "1", nil); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(2 * time.Hour) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "8.000000" {
		t.Fatalf("balance = %s, want 8.000000", balance)
	}
	var checkpointCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.metering_checkpoints WHERE runtime_interval_id = $1`, intervalID).Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if checkpointCount != 2 {
		t.Fatalf("checkpoint count = %d, want 2", checkpointCount)
	}
}

func TestRuntimeMeteringQueuesStopOnCreditExhaustion(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "poor", "mach_poor_"+suffix, "standard-2x", "2", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_poor_"+suffix, "grant-poor-"+suffix, "test", suffix, "1", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_poor_"+suffix] = fly.Machine{ID: "mach_poor_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(time.Hour) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertQueuedStop(t, store, "prj_poor_"+suffix, "project.stop.credit_exhausted:prj_poor_"+suffix)
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.project_events WHERE project_id = $1 AND event_type = 'project.stop_queued.credit_exhausted'`, "prj_poor_"+suffix).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("credit exhaustion stop events = %d, want 1", events)
	}
	var projectState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.projects WHERE id = $1`, "prj_poor_"+suffix).Scan(&projectState); err != nil {
		t.Fatal(err)
	}
	if projectState != "stopping" {
		t.Fatalf("project state = %s, want stopping", projectState)
	}
}

func TestRuntimeMeteringClosesIntervalOnStoppedProviderState(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "state", "mach_state_"+suffix, "standard-1x", "1", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_state_"+suffix, "grant-state-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_state_"+suffix] = fly.Machine{ID: "mach_state_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	flyClient.Machines["mach_state_"+suffix] = fly.Machine{ID: "mach_state_" + suffix, State: "stopped"}
	service.SetClock(func() time.Time { return start.Add(5 * time.Minute) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var stoppedAt time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT stopped_at FROM paperboat.machine_runtime_intervals WHERE project_id = $1`, "prj_state_"+suffix).Scan(&stoppedAt); err != nil {
		t.Fatal(err)
	}
	if !stoppedAt.Equal(start.Add(5 * time.Minute)) {
		t.Fatalf("stopped_at = %s, want %s", stoppedAt, start.Add(5*time.Minute))
	}
	var projectState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.projects WHERE id = $1`, "prj_state_"+suffix).Scan(&projectState); err != nil {
		t.Fatal(err)
	}
	if projectState != "stopped" {
		t.Fatalf("project state = %s, want stopped", projectState)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "9.916667" {
		t.Fatalf("balance = %s, want 9.916667", balance)
	}
}

func TestRuntimeMeteringCreatesTailCheckpointWhenPendingIntervalStops(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "tail", "mach_tail_"+suffix, "standard-1x", "1", 3600)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_tail_"+suffix, "grant-tail-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_tail_"+suffix] = fly.Machine{ID: "mach_tail_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var intervalID string
	if err := store.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.machine_runtime_intervals WHERE project_id = $1`, "prj_tail_"+suffix).Scan(&intervalID); err != nil {
		t.Fatal(err)
	}
	checkpointID := "mchk_tail_" + suffix
	checkpointKey := "metering.runtime:" + intervalID + ":tail"
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.metering_checkpoints
	(id, runtime_interval_id, project_id, user_id, period_start, period_end, runtime_seconds, credit_weight, credits_debited, idempotency_key, state)
VALUES ($1, $2, $3, $4, $5, $6, 3600, 1, 1, $7, 'created')`,
		checkpointID, intervalID, "prj_tail_"+suffix, userID, start, start.Add(time.Hour), checkpointKey); err != nil {
		t.Fatal(err)
	}
	if err := billingRepo.DebitCredits(ctx, userID, "cled_tail_"+suffix, checkpointKey, "metering", checkpointID, "1", nil); err != nil {
		t.Fatal(err)
	}
	flyClient.Machines["mach_tail_"+suffix] = fly.Machine{ID: "mach_tail_" + suffix, State: "stopped"}
	service.SetClock(func() time.Time { return start.Add(65 * time.Minute) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::numeric(18,6)::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "8.916667" {
		t.Fatalf("balance = %s, want 8.916667", balance)
	}
	var checkpointCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.metering_checkpoints WHERE runtime_interval_id = $1 AND state = 'processed'`, intervalID).Scan(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if checkpointCount != 2 {
		t.Fatalf("processed checkpoint count = %d, want 2", checkpointCount)
	}
}

func TestRuntimeMeteringQueuesIdleStop(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "idle", "mach_idle_"+suffix, "standard-1x", "1", 60)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_idle_"+suffix, "grant-idle-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_idle_"+suffix] = fly.Machine{ID: "mach_idle_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(61 * time.Second) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertQueuedStop(t, store, "prj_idle_"+suffix, "project.stop.idle_timeout:prj_idle_"+suffix)
}

func TestRuntimeMeteringIdleWarningWithoutMarkerIsEmittedOnce(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "warn", "mach_warn_"+suffix, "standard-1x", "1", 60)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_warn_"+suffix, "grant-warn-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_warn_"+suffix] = fly.Machine{ID: "mach_warn_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	service.SetEnforcementConfig(metering.EnforcementConfig{IdleWarningLead: 30 * time.Second})
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	warningAt := start.Add(31 * time.Second)
	service.SetClock(func() time.Time { return warningAt })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var warningEvents int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT count(*) FROM paperboat.project_events
WHERE project_id = $1 AND event_type = 'project.idle_stop_warning'`, "prj_warn_"+suffix).Scan(&warningEvents); err != nil {
		t.Fatal(err)
	}
	if warningEvents != 1 {
		t.Fatalf("idle warning events = %d, want 1", warningEvents)
	}
	var markerWarnings int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.project_activity_markers WHERE project_id = $1 AND idle_warning_sent_at IS NOT NULL`, "prj_warn_"+suffix).Scan(&markerWarnings); err != nil {
		t.Fatal(err)
	}
	if markerWarnings != 1 {
		t.Fatalf("warning marker rows = %d, want 1", markerWarnings)
	}
}

func TestRuntimeMeteringKeepAliveSuppressesIdleStopUntilExpiry(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "pin", "mach_pin_"+suffix, "standard-1x", "1", 60)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_pin_"+suffix, "grant-pin-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_pin_"+suffix] = fly.Machine{ID: "mach_pin_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := metering.NewRuntimeRepository(store, "").RecordActivity(ctx, "prj_pin_"+suffix, start, "vm_heartbeat", nil); err != nil {
		t.Fatal(err)
	}
	keepAliveUntil := start.Add(10 * time.Minute)
	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.project_activity_markers
SET keep_alive_until = $2
WHERE project_id = $1`, "prj_pin_"+suffix, keepAliveUntil); err != nil {
		t.Fatal(err)
	}
	service.SetClock(func() time.Time { return start.Add(2 * time.Minute) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.orchestration_jobs WHERE idempotency_key = $1`, "project.stop.idle_timeout:prj_pin_"+suffix).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("idle stop queued while keep-alive pin active")
	}
	service.SetClock(func() time.Time { return keepAliveUntil.Add(time.Second) })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertQueuedStop(t, store, "prj_pin_"+suffix, "project.stop.idle_timeout:prj_pin_"+suffix)
}

func TestRuntimeMeteringQueuesStopOnEntitlementLoss(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "entitlement", "mach_entitlement_"+suffix, "standard-1x", "1", 600)
	if _, err := store.SQL().ExecContext(ctx, `
UPDATE paperboat.subscriptions SET state = 'canceled', current_period_end = $2 WHERE user_id = $1`, userID, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, userID, "grant_entitlement_"+suffix, "grant-entitlement-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.access_sessions (id, user_id, project_id, session_type, state, descriptor, expires_at, idempotency_key)
VALUES ($1, $2, $3, 'papercode', 'active', '{}'::jsonb, $4, $5)`,
		"acs_entitlement_"+suffix, userID, "prj_entitlement_"+suffix, nowPlusHour(), "access-entitlement-"+suffix); err != nil {
		t.Fatal(err)
	}
	flyClient := fly.NewFakeClient()
	flyClient.Machines["mach_entitlement_"+suffix] = fly.Machine{ID: "mach_entitlement_" + suffix, State: "running"}
	service := metering.NewRuntimeService(store, flyClient, billingRepo)
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return now })
	if err := service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertQueuedStop(t, store, "prj_entitlement_"+suffix, "project.stop.entitlement_lost:prj_entitlement_"+suffix)
	assertRuntimeAccessSessionRevoked(t, store, "acs_entitlement_"+suffix, "entitlement_lost")
}

func openRuntimeTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres repository integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}

func nowPlusHour() time.Time {
	return time.Now().UTC().Add(time.Hour)
}

func assertRuntimeAccessSessionRevoked(t *testing.T, store *db.DB, sessionID, reason string) {
	t.Helper()
	var state string
	var revoked bool
	var descriptor string
	if err := store.SQL().QueryRowContext(context.Background(), `
SELECT state, revoked_at IS NOT NULL, descriptor::text
FROM paperboat.access_sessions
WHERE id = $1`, sessionID).Scan(&state, &revoked, &descriptor); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || !revoked || !strings.Contains(descriptor, `"revocation_reason": "`+reason+`"`) {
		t.Fatalf("session state=%q revoked=%v descriptor=%s, want revoked with reason %q", state, revoked, descriptor, reason)
	}
}

func seedMeteredProject(t *testing.T, store *db.DB, suffix, label, machineID, machineCode, weight string, idleSeconds int) string {
	t.Helper()
	userID := "usr_meter_" + suffix
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.users (id, workos_subject, primary_email, status) VALUES ($1, $2, $3, 'active')`, userID, "workos_meter_"+suffix, "meter-"+suffix+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.subscriptions (id, user_id, provider, provider_subscription_id, state, current_period_end)
VALUES ($1, $2, 'polar', $3, 'active', NULL)`, "sub_seed_"+label+"_"+suffix, userID, "sub-seed-"+label+"-"+suffix); err != nil {
		t.Fatal(err)
	}
	seedMeteredProjectForUser(t, store, suffix, userID, label, machineID, machineCode, weight, idleSeconds)
	return userID
}

func seedMeteredProjectForUser(t *testing.T, store *db.DB, suffix, userID, label, machineID, machineCode, weight string, idleSeconds int) {
	t.Helper()
	ctx := context.Background()
	projectID := "prj_" + label + "_" + suffix
	machineTypeID := "mt_" + label + "_" + suffix
	machineTypeVersionID := "mtv_" + label + "_" + suffix
	idleID := "idle_" + label + "_" + suffix
	regionID := "reg_" + label + "_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id) VALUES ($1, $2, $3, 4, 8192, $4::numeric, true, $5)`, machineTypeID, machineCode+"-"+label+"-"+suffix, machineCode, weight, machineTypeVersionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight) VALUES ($1, $2, 1, 4, 8192, $3::numeric)`, machineTypeVersionID, machineTypeID, weight); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.idle_timeout_options (id, code, duration_seconds, active) VALUES ($1, $2, $3, true)`, idleID, "idle-"+label+"-"+suffix, idleSeconds); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ($1, $2, 'Test Region', true)`, regionID, "iad-"+label+"-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, $3, 'running', $4)`, projectID, userID, "Meter "+label, "idem-"+label+"-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.project_repositories (project_id, provider, source_url) VALUES ($1, 'github', 'https://github.com/example/repo')`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.storage_accounts (id, user_id, included_gb) VALUES ($1, $2, 100) ON CONFLICT (user_id) DO NOTHING`, "stor_"+label+"_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	var storageAccountID string
	if err := store.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.storage_accounts WHERE user_id = $1`, userID).Scan(&storageAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.project_storage_allocations (project_id, storage_account_id, assigned_gb) VALUES ($1, $2, 10)`, projectID, storageAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.project_runtime_configs
	(project_id, machine_type_version_id, idle_timeout_option_id, region_id, desired_config_hash, applied_storage_gb, applied_machine_type_version_id, applied_idle_timeout_option_id, applied_region_id, applied_config_hash)
VALUES ($1, $2, $3, $4, 'hash', 10, $2, $3, $4, 'hash')`, projectID, machineTypeVersionID, idleID, regionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.fly_machines (id, project_id, fly_machine_id, state, image_ref, region) VALUES ($1, $2, $3, 'running', 'image', 'iad')`, "flm_"+label+"_"+suffix, projectID, machineID); err != nil {
		t.Fatal(err)
	}
}

func assertQueuedStop(t *testing.T, store *db.DB, projectID, key string) {
	t.Helper()
	var state, projectState string
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.orchestration_jobs WHERE idempotency_key = $1`, key).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "queued" {
		t.Fatalf("job state = %s, want queued", state)
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.projects WHERE id = $1`, projectID).Scan(&projectState); err != nil {
		t.Fatal(err)
	}
	if projectState != "stopping" {
		t.Fatalf("project state = %s, want stopping", projectState)
	}
}
