package metering_test

import (
	"context"
	"errors"
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
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
)

func TestUserMachineRuntimeObservationCommitsServerReceiptTime(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_heartbeat_"+suffix, "um_heartbeat_"+suffix, "env_heartbeat_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "heartbeat-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Heartbeat','linux','amd64','/home/test','offline','occupied',false)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-time.Second)
	if err := metering.NewRuntimeRepository(store, "").RecordRuntimeObservation(ctx, metering.RuntimeObservation{ProjectID: environmentID, MachineID: machineID, ObservedAt: time.Unix(1, 0), ReporterVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	var state string
	var online bool
	var lastSeen time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,online,last_seen_at FROM paperboat.user_machines WHERE id=$1`, machineID).Scan(&state, &online, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if state != "online" || !online || lastSeen.Before(started) {
		t.Fatalf("heartbeat state=%s online=%v last_seen_at=%s", state, online, lastSeen)
	}
}

func TestUserMachineRuntimeObservationRejectsConcurrentCopiedIdentity(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_duplicate_"+suffix, "um_duplicate_"+suffix, "env_duplicate_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "duplicate-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Duplicate','linux','amd64','/home/test','offline','occupied',false)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	repository := metering.NewRuntimeRepository(store, "", 2*time.Minute)
	observation := metering.RuntimeObservation{ProjectID: environmentID, MachineID: machineID, ObservedAt: time.Now().UTC(), ReporterVersion: "test", WorkerGeneration: 1, OSBootID: "boot-a", WorkerServiceScope: "user", ConnectorState: "ready", ConnectorGeneration: 1, DiagnosticsObservedAt: time.Now().UTC()}
	if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
		t.Fatal(err)
	}
	observation.OSBootID = "boot-b"
	observation.DiagnosticsObservedAt = observation.DiagnosticsObservedAt.Add(time.Second)
	if err := repository.RecordRuntimeObservation(ctx, observation); !errors.Is(err, metering.ErrDuplicateMachineIdentity) {
		t.Fatalf("concurrent copied identity error = %v", err)
	}
	observation.WorkerGeneration = 2
	if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
		t.Fatalf("new generation after reboot: %v", err)
	}
	observation.WorkerGeneration = 1
	observation.OSBootID = "boot-c"
	if err := repository.RecordRuntimeObservation(ctx, observation); !errors.Is(err, metering.ErrDuplicateMachineIdentity) {
		t.Fatalf("older copied identity error = %v", err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET last_seen_at=now()-interval '3 minutes' WHERE id=$1`, machineID); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
		t.Fatalf("stale identity takeover: %v", err)
	}
}

func TestRuntimeRelayLatencyVectorIsWorkerAndGenerationFenced(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_latency_"+suffix, "um_latency_"+suffix, "env_latency_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "latency-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online) VALUES ($1,$2,$3,'Latency','linux','amd64','/home/test','offline','occupied',false)`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	repository := metering.NewRuntimeRepository(store, "")
	now := time.Now().UTC()
	record := func(worker, generation uint64, region string) {
		t.Helper()
		observation := metering.RuntimeObservation{ProjectID: environmentID, MachineID: machineID, ObservedAt: now, ReporterVersion: "test", WorkerGeneration: worker, OSBootID: "boot-current", WorkerServiceScope: "system", ConnectorState: "ready", ConnectorGeneration: worker, DiagnosticsObservedAt: now, RelayLatency: &metering.RelayLatencyVector{Generation: generation, ObservedAt: now, Samples: []metering.RelayLatencySample{{Region: region, RTTMS: 20}}}}
		if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
			t.Fatal(err)
		}
	}
	record(2, 3, "fsn1")
	record(2, 2, "hel1")
	var worker, generation int64
	var encoded string
	if err := store.SQL().QueryRowContext(ctx, `SELECT relay_latency_worker_generation,relay_latency_generation,relay_latency_vector::text FROM paperboat.user_machines WHERE id=$1`, machineID).Scan(&worker, &generation, &encoded); err != nil {
		t.Fatal(err)
	}
	if worker != 2 || generation != 3 || !strings.Contains(encoded, `"fsn1"`) || strings.Contains(encoded, `"hel1"`) {
		t.Fatalf("worker=%d generation=%d vector=%s", worker, generation, encoded)
	}
	record(3, 1, "hel1")
	if err := store.SQL().QueryRowContext(ctx, `SELECT relay_latency_worker_generation,relay_latency_generation,relay_latency_vector::text FROM paperboat.user_machines WHERE id=$1`, machineID).Scan(&worker, &generation, &encoded); err != nil {
		t.Fatal(err)
	}
	if worker != 3 || generation != 1 || !strings.Contains(encoded, `"hel1"`) {
		t.Fatalf("replacement worker=%d generation=%d vector=%s", worker, generation, encoded)
	}
}

func TestRuntimeMeteringDebitsWeightedConcurrentMachines(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "a", "mach_a_"+suffix, "standard-1x", "1")
	seedMeteredProjectForUser(t, store, suffix, userID, "b", "mach_b_"+suffix, "standard-2x", "2")
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
	userID := seedMeteredProject(t, store, suffix, "started", "mach_started_"+suffix, "standard-1x", "1")
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
	userID := seedMeteredProject(t, store, suffix, "idem", "mach_idem_"+suffix, "standard-1x", "1")
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
	userID := seedMeteredProject(t, store, suffix, "recover", "mach_recover_"+suffix, "standard-1x", "1")
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
	userID := seedMeteredProject(t, store, suffix, "poor", "mach_poor_"+suffix, "standard-2x", "2")
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
	processMeteringStop(t, store, flyClient, "prj_poor_"+suffix)
	assertProjectStateAndStorage(t, store, "prj_poor_"+suffix, userID, "stopped", 10)
}

func TestRuntimeMeteringClosesIntervalOnStoppedProviderState(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "state", "mach_state_"+suffix, "standard-1x", "1")
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
	if projectState != "running" {
		t.Fatalf("provider observation changed product state = %s, want running", projectState)
	}
	var machineState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.fly_machines WHERE project_id = $1`, "prj_state_"+suffix).Scan(&machineState); err != nil {
		t.Fatal(err)
	}
	if machineState != "stopped" {
		t.Fatalf("observed machine state = %s, want stopped", machineState)
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
	userID := seedMeteredProject(t, store, suffix, "tail", "mach_tail_"+suffix, "standard-1x", "1")
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

func TestRuntimeMeteringQueuesStopOnEntitlementLoss(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := seedMeteredProject(t, store, suffix, "entitlement", "mach_entitlement_"+suffix, "standard-1x", "1")
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
VALUES ($1, $2, $3, 'helper', 'active', '{}'::jsonb, $4, $5)`,
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
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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

func seedMeteredProject(t *testing.T, store *db.DB, suffix, label, machineID, machineCode, weight string) string {
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
	seedMeteredProjectForUser(t, store, suffix, userID, label, machineID, machineCode, weight)
	return userID
}

func seedMeteredProjectForUser(t *testing.T, store *db.DB, suffix, userID, label, machineID, machineCode, weight string) {
	t.Helper()
	ctx := context.Background()
	projectID := "prj_" + label + "_" + suffix
	machineTypeID := "mt_" + label + "_" + suffix
	machineTypeVersionID := "mtv_" + label + "_" + suffix
	regionID := "reg_" + label + "_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_types (id, code, name, vcpu, memory_mb, credit_weight, active, current_version_id) VALUES ($1, $2, $3, 4, 8192, $4::numeric, true, $5)`, machineTypeID, machineCode+"-"+label+"-"+suffix, machineCode, weight, machineTypeVersionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.machine_type_versions (id, machine_type_id, version_number, vcpu, memory_mb, credit_weight) VALUES ($1, $2, 1, 4, 8192, $3::numeric)`, machineTypeVersionID, machineTypeID, weight); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.regions (id, code, name, enabled) VALUES ($1, $2, 'Test Region', true)`, regionID, "iad-"+label+"-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.projects (id, user_id, name, state, idempotency_key) VALUES ($1, $2, $3, 'running', $4)`, projectID, userID, "Meter "+label, "idem-"+label+"-"+suffix); err != nil {
		t.Fatal(err)
	}
	canonicalMachineID := "mch_" + label + "_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_roles,machine_kind) VALUES ($1,$2,$3,$4,'linux','unknown','/workspace','online','occupied',ARRAY['host']::text[],'hosted')`, canonicalMachineID, userID, projectID, "Meter "+label); err != nil {
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
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.storage_accounts SET allocated_gb=allocated_gb+10 WHERE id=$1`, storageAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.project_runtime_configs
	(project_id, machine_type_version_id, region_id, desired_config_hash, applied_storage_gb, applied_machine_type_version_id, applied_region_id, applied_config_hash)
VALUES ($1, $2, $3, 'hash', 10, $2, $3, 'hash')`, projectID, machineTypeVersionID, regionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.fly_machines (id, project_id, user_machine_id, fly_machine_id, state, image_ref, region) VALUES ($1, $2, $3, $4, 'running', 'image', 'iad')`, "flm_"+label+"_"+suffix, projectID, canonicalMachineID, machineID); err != nil {
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

func processMeteringStop(t *testing.T, store *db.DB, flyClient *fly.FakeClient, projectID string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `UPDATE paperboat.orchestration_jobs SET state='succeeded', updated_at=now() WHERE state='queued' AND aggregate_id<>$1`, projectID); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Secrets.EncryptionKey = "metering-lifecycle-test-key"
	if err := orchestrator.NewService(store, flyClient, cfg).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, machine := range flyClient.Machines {
		if machine.State != "stopped" {
			t.Fatalf("provider machine state = %q, want stopped", machine.State)
		}
	}
	var jobs int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM paperboat.orchestration_jobs WHERE aggregate_id=$1 AND job_type='project.stop' AND state='succeeded'`, projectID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("succeeded stop jobs = %d, want 1", jobs)
	}
}

func assertProjectStateAndStorage(t *testing.T, store *db.DB, projectID, userID, wantState string, wantAllocated int) {
	t.Helper()
	var state string
	var allocated int
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT state FROM paperboat.projects WHERE id=$1`, projectID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(context.Background(), `SELECT allocated_gb FROM paperboat.storage_accounts WHERE user_id=$1`, userID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if state != wantState || allocated != wantAllocated {
		t.Fatalf("project state/storage = %s/%d, want %s/%d", state, allocated, wantState, wantAllocated)
	}
}
