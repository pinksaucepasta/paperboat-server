package metering

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type RuntimeService struct {
	repo    *RuntimeRepository
	fly     fly.Client
	billing *billing.Repository
	now     func() time.Time
	cfg     EnforcementConfig
}

type EnforcementConfig struct {
	HeartbeatGrace        time.Duration
	ReporterLostStopGrace time.Duration
	IdleWarningLead       time.Duration
}

var ErrInvalidHeartbeatCredential = errors.New("invalid heartbeat credential")

func NewRuntimeService(store *db.DB, flyClient fly.Client, billingRepo *billing.Repository) *RuntimeService {
	return &RuntimeService{
		repo:    NewRuntimeRepository(store, ""),
		fly:     flyClient,
		billing: billingRepo,
		now:     func() time.Time { return time.Now().UTC() },
		cfg: EnforcementConfig{
			HeartbeatGrace:        2 * time.Minute,
			ReporterLostStopGrace: 10 * time.Minute,
			IdleWarningLead:       5 * time.Minute,
		},
	}
}

func (s *RuntimeService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *RuntimeService) SetEnforcementConfig(cfg EnforcementConfig) {
	if cfg.HeartbeatGrace > 0 {
		s.cfg.HeartbeatGrace = cfg.HeartbeatGrace
	}
	if cfg.ReporterLostStopGrace > 0 {
		s.cfg.ReporterLostStopGrace = cfg.ReporterLostStopGrace
	}
	if cfg.IdleWarningLead > 0 {
		s.cfg.IdleWarningLead = cfg.IdleWarningLead
	}
}

func (s *RuntimeService) RunOnce(ctx context.Context) error {
	now := s.now().UTC()
	if err := s.processPendingCheckpoints(ctx); err != nil {
		return err
	}
	machines, err := s.repo.MeterableMachines(ctx)
	if err != nil {
		return err
	}
	for _, machine := range machines {
		observed, err := s.fly.GetMachine(ctx, machine.FlyMachineID)
		if errors.Is(err, fly.ErrNotFound) {
			if err := s.observeStopped(ctx, machine.ProjectID, now, "missing", "low"); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if isProviderRunning(observed.State) {
			if err := s.observeRunning(ctx, machine, now, observed.State); err != nil {
				return err
			}
			continue
		}
		if err := s.observeStopped(ctx, machine.ProjectID, now, observed.State, "high"); err != nil {
			return err
		}
	}
	return s.repo.EnforceIdleAndReporterState(ctx, now, s.cfg)
}

func (s *RuntimeService) Worker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := s.RunOnce(ctx); err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *RuntimeService) processPendingCheckpoints(ctx context.Context) error {
	checkpoints, err := s.repo.PendingCheckpoints(ctx)
	if err != nil {
		return err
	}
	for _, checkpoint := range checkpoints {
		if err := s.processCheckpoint(ctx, checkpoint); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeService) observeRunning(ctx context.Context, machine MeterableMachine, now time.Time, providerState string) error {
	interval, opened, err := s.repo.EnsureOpenInterval(ctx, machine, now)
	if err != nil {
		return err
	}
	if opened {
		return s.repo.RecordObservedProjectState(ctx, machine.ProjectID, providerState, "running")
	}
	checkpoint, ok, err := s.repo.CreateCheckpoint(ctx, interval, now)
	if err != nil || !ok {
		return err
	}
	if err := s.processCheckpoint(ctx, checkpoint); err != nil {
		return err
	}
	return s.repo.RecordObservedProjectState(ctx, machine.ProjectID, providerState, "running")
}

func (s *RuntimeService) observeStopped(ctx context.Context, projectID string, now time.Time, observedState, confidence string) error {
	interval, ok, err := s.repo.OpenInterval(ctx, projectID)
	if err != nil {
		return err
	}
	if ok {
		checkpoint, checkpointOK, err := s.repo.EnsureFinalCheckpoint(ctx, interval, now)
		if err != nil {
			return err
		}
		if checkpointOK {
			if err := s.processCheckpoint(ctx, checkpoint); err != nil {
				return err
			}
		}
	}
	if err := s.repo.CloseOpenInterval(ctx, projectID, now, "fly_poll", confidence, observedState); err != nil {
		return err
	}
	return s.repo.RecordObservedProjectState(ctx, projectID, observedState, mapProviderState(observedState))
}

func (s *RuntimeService) processCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	err := s.billing.DebitCredits(ctx, checkpoint.UserID, newID("cled"), checkpoint.IdempotencyKey, "metering", checkpoint.ID, checkpoint.CreditsDebited, map[string]any{
		"project_id":          checkpoint.ProjectID,
		"runtime_interval_id": checkpoint.RuntimeIntervalID,
		"runtime_seconds":     checkpoint.RuntimeSeconds,
		"credit_weight":       checkpoint.CreditWeight,
	})
	if errors.Is(err, billing.ErrInsufficientCredits) {
		if markErr := s.repo.MarkCheckpointFailedAndQueueCreditStop(ctx, checkpoint, err); markErr != nil {
			return markErr
		}
		return nil
	}
	if err != nil {
		return s.repo.MarkCheckpointFailed(ctx, checkpoint.ID, err)
	}
	if err := s.repo.MarkCheckpointProcessed(ctx, checkpoint); err != nil {
		return err
	}
	return nil
}

type RuntimeRepository struct {
	db            *db.DB
	encryptionKey string
}

func NewRuntimeRepository(store *db.DB, encryptionKey string) *RuntimeRepository {
	return &RuntimeRepository{db: store, encryptionKey: encryptionKey}
}

type MeterableMachine struct {
	ProjectID            string
	UserID               string
	FlyMachineID         string
	MachineTypeVersionID string
	CreditWeight         string
	IdleTimeoutSeconds   int
}

type RuntimeInterval struct {
	ID             string
	ProjectID      string
	UserID         string
	FlyMachineID   string
	CreditWeight   string
	LastMeteredAt  time.Time
	ObservedState  string
	Confidence     string
	ObservationSrc string
}

type Checkpoint struct {
	ID                string
	RuntimeIntervalID string
	ProjectID         string
	UserID            string
	PeriodStart       time.Time
	PeriodEnd         time.Time
	RuntimeSeconds    int
	CreditWeight      string
	CreditsDebited    string
	IdempotencyKey    string
}

type ActivityHeartbeat struct {
	ProjectID       string
	MachineID       string
	LastActivityAt  time.Time
	LastHeartbeatAt time.Time
	ReporterVersion string
	Signals         map[string]string
}

func (r *RuntimeRepository) MeterableMachines(ctx context.Context) ([]MeterableMachine, error) {
	rows, err := r.db.SQL().QueryContext(ctx, `
SELECT p.id, p.user_id, fm.fly_machine_id, prc.applied_machine_type_version_id,
       mtv.credit_weight::text, ito.duration_seconds
FROM paperboat.projects p
JOIN paperboat.fly_machines fm ON fm.project_id = p.id
JOIN paperboat.project_runtime_configs prc ON prc.project_id = p.id
JOIN paperboat.machine_type_versions mtv ON mtv.id = prc.applied_machine_type_version_id
JOIN paperboat.idle_timeout_options ito ON ito.id = prc.applied_idle_timeout_option_id
WHERE p.state IN ('ready', 'running', 'starting', 'stopping', 'restarting', 'suspended')
  AND prc.applied_machine_type_version_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MeterableMachine
	for rows.Next() {
		var machine MeterableMachine
		if err := rows.Scan(&machine.ProjectID, &machine.UserID, &machine.FlyMachineID, &machine.MachineTypeVersionID, &machine.CreditWeight, &machine.IdleTimeoutSeconds); err != nil {
			return nil, err
		}
		out = append(out, machine)
	}
	return out, rows.Err()
}

func (r *RuntimeRepository) OpenInterval(ctx context.Context, projectID string) (RuntimeInterval, bool, error) {
	var interval RuntimeInterval
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT id, project_id, user_id, fly_machine_id, credit_weight::text, last_metered_at, observed_state, confidence, observation_source
FROM paperboat.machine_runtime_intervals
WHERE project_id = $1 AND stopped_at IS NULL`, projectID).Scan(&interval.ID, &interval.ProjectID, &interval.UserID, &interval.FlyMachineID, &interval.CreditWeight, &interval.LastMeteredAt, &interval.ObservedState, &interval.Confidence, &interval.ObservationSrc)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeInterval{}, false, nil
	}
	return interval, err == nil, err
}

func (r *RuntimeRepository) PendingCheckpoints(ctx context.Context) ([]Checkpoint, error) {
	rows, err := r.db.SQL().QueryContext(ctx, `
SELECT id, runtime_interval_id, project_id, user_id, period_start, period_end,
       runtime_seconds, credit_weight::text, credits_debited::text, idempotency_key
FROM paperboat.metering_checkpoints
WHERE state IN ('created', 'failed')
ORDER BY period_end ASC, created_at ASC
LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var checkpoint Checkpoint
		if err := rows.Scan(&checkpoint.ID, &checkpoint.RuntimeIntervalID, &checkpoint.ProjectID, &checkpoint.UserID, &checkpoint.PeriodStart, &checkpoint.PeriodEnd, &checkpoint.RuntimeSeconds, &checkpoint.CreditWeight, &checkpoint.CreditsDebited, &checkpoint.IdempotencyKey); err != nil {
			return nil, err
		}
		out = append(out, checkpoint)
	}
	return out, rows.Err()
}

func (r *RuntimeRepository) EnsureOpenInterval(ctx context.Context, machine MeterableMachine, now time.Time) (RuntimeInterval, bool, error) {
	var interval RuntimeInterval
	opened := false
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		err := tx.QueryRow(ctx, `
SELECT id, project_id, user_id, fly_machine_id, credit_weight::text, last_metered_at, observed_state, confidence, observation_source
FROM machine_runtime_intervals
WHERE project_id = $1 AND stopped_at IS NULL
FOR UPDATE`, machine.ProjectID).Scan(&interval.ID, &interval.ProjectID, &interval.UserID, &interval.FlyMachineID, &interval.CreditWeight, &interval.LastMeteredAt, &interval.ObservedState, &interval.Confidence, &interval.ObservationSrc)
		if err == nil {
			_, err = tx.Exec(ctx, `
UPDATE machine_runtime_intervals
SET observed_state = 'running', observation_source = 'fly_poll', confidence = 'high', updated_at = now()
WHERE id = $1`, interval.ID)
			interval.ObservedState = "running"
			interval.ObservationSrc = "fly_poll"
			interval.Confidence = "high"
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		opened = true
		interval = RuntimeInterval{
			ID:             newID("rti"),
			ProjectID:      machine.ProjectID,
			UserID:         machine.UserID,
			FlyMachineID:   machine.FlyMachineID,
			CreditWeight:   machine.CreditWeight,
			LastMeteredAt:  now,
			ObservedState:  "running",
			ObservationSrc: "fly_poll",
			Confidence:     "high",
		}
		_, err = tx.Exec(ctx, `
INSERT INTO machine_runtime_intervals
	(id, project_id, user_id, fly_machine_id, machine_type_version_id, credit_weight, started_at, last_metered_at, observed_state, observation_source, confidence)
VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $7, 'running', 'fly_poll', 'high')`,
			interval.ID, machine.ProjectID, machine.UserID, machine.FlyMachineID, machine.MachineTypeVersionID, machine.CreditWeight, now)
		return err
	})
	return interval, opened, err
}

func (r *RuntimeRepository) CreateCheckpoint(ctx context.Context, interval RuntimeInterval, now time.Time) (Checkpoint, bool, error) {
	if !now.After(interval.LastMeteredAt) {
		return Checkpoint{}, false, nil
	}
	var checkpoint Checkpoint
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := tx.QueryRow(ctx, `
SELECT id, project_id, user_id, fly_machine_id, credit_weight::text, last_metered_at
FROM machine_runtime_intervals
WHERE id = $1 AND stopped_at IS NULL
FOR UPDATE`, interval.ID).Scan(&interval.ID, &interval.ProjectID, &interval.UserID, &interval.FlyMachineID, &interval.CreditWeight, &interval.LastMeteredAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		existing, ok, err := pendingCheckpointTx(ctx, tx, interval.ID)
		if err != nil || ok {
			checkpoint = existing
			return err
		}
		if !now.After(interval.LastMeteredAt) {
			return nil
		}
		seconds := int(now.Sub(interval.LastMeteredAt).Seconds())
		if seconds <= 0 {
			return nil
		}
		checkpoint = Checkpoint{
			ID:                newID("mchk"),
			RuntimeIntervalID: interval.ID,
			ProjectID:         interval.ProjectID,
			UserID:            interval.UserID,
			PeriodStart:       interval.LastMeteredAt,
			PeriodEnd:         now,
			RuntimeSeconds:    seconds,
			CreditWeight:      interval.CreditWeight,
			IdempotencyKey:    fmt.Sprintf("metering.runtime:%s:%d:%d", interval.ID, interval.LastMeteredAt.UnixNano(), now.UnixNano()),
		}
		if err := tx.QueryRow(ctx, `SELECT (($1::numeric / 3600.0) * $2::numeric)::numeric(18,6)::text`, seconds, interval.CreditWeight).Scan(&checkpoint.CreditsDebited); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO metering_checkpoints
	(id, runtime_interval_id, project_id, user_id, period_start, period_end, runtime_seconds, credit_weight, credits_debited, idempotency_key, state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::numeric, $10, 'created')
ON CONFLICT (idempotency_key) DO NOTHING`,
			checkpoint.ID, checkpoint.RuntimeIntervalID, checkpoint.ProjectID, checkpoint.UserID, checkpoint.PeriodStart, checkpoint.PeriodEnd, checkpoint.RuntimeSeconds, checkpoint.CreditWeight, checkpoint.CreditsDebited, checkpoint.IdempotencyKey)
		return err
	})
	if err != nil || checkpoint.ID == "" {
		return Checkpoint{}, false, err
	}
	return checkpoint, true, nil
}

func (r *RuntimeRepository) EnsureFinalCheckpoint(ctx context.Context, interval RuntimeInterval, stoppedAt time.Time) (Checkpoint, bool, error) {
	var checkpoint Checkpoint
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := tx.QueryRow(ctx, `
SELECT id, project_id, user_id, fly_machine_id, credit_weight::text, last_metered_at
FROM machine_runtime_intervals
WHERE id = $1
FOR UPDATE`, interval.ID).Scan(&interval.ID, &interval.ProjectID, &interval.UserID, &interval.FlyMachineID, &interval.CreditWeight, &interval.LastMeteredAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		periodStart := interval.LastMeteredAt
		var maxEnd sql.NullTime
		if err := tx.QueryRow(ctx, `SELECT max(period_end) FROM metering_checkpoints WHERE runtime_interval_id = $1`, interval.ID).Scan(&maxEnd); err != nil {
			return err
		}
		if maxEnd.Valid && maxEnd.Time.After(periodStart) {
			periodStart = maxEnd.Time
		}
		seconds := int(stoppedAt.Sub(periodStart).Seconds())
		if seconds > 0 {
			tail := Checkpoint{
				ID:                newID("mchk"),
				RuntimeIntervalID: interval.ID,
				ProjectID:         interval.ProjectID,
				UserID:            interval.UserID,
				PeriodStart:       periodStart,
				PeriodEnd:         stoppedAt,
				RuntimeSeconds:    seconds,
				CreditWeight:      interval.CreditWeight,
				IdempotencyKey:    fmt.Sprintf("metering.runtime:%s:%d:%d", interval.ID, periodStart.UnixNano(), stoppedAt.UnixNano()),
			}
			if err := tx.QueryRow(ctx, `SELECT (($1::numeric / 3600.0) * $2::numeric)::numeric(18,6)::text`, seconds, interval.CreditWeight).Scan(&tail.CreditsDebited); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO metering_checkpoints
	(id, runtime_interval_id, project_id, user_id, period_start, period_end, runtime_seconds, credit_weight, credits_debited, idempotency_key, state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::numeric, $10, 'created')
ON CONFLICT (idempotency_key) DO NOTHING`,
				tail.ID, tail.RuntimeIntervalID, tail.ProjectID, tail.UserID, tail.PeriodStart, tail.PeriodEnd, tail.RuntimeSeconds, tail.CreditWeight, tail.CreditsDebited, tail.IdempotencyKey); err != nil {
				return err
			}
		}
		existing, ok, err := pendingCheckpointTx(ctx, tx, interval.ID)
		if err != nil || ok {
			checkpoint = existing
			return err
		}
		return nil
	})
	if err != nil || checkpoint.ID == "" {
		return Checkpoint{}, false, err
	}
	return checkpoint, true, nil
}

func pendingCheckpointTx(ctx context.Context, tx *db.Tx, intervalID string) (Checkpoint, bool, error) {
	var checkpoint Checkpoint
	err := tx.QueryRow(ctx, `
SELECT id, runtime_interval_id, project_id, user_id, period_start, period_end,
       runtime_seconds, credit_weight::text, credits_debited::text, idempotency_key
FROM metering_checkpoints
WHERE runtime_interval_id = $1 AND state IN ('created', 'failed')
ORDER BY period_end ASC, created_at ASC
LIMIT 1
FOR UPDATE`, intervalID).Scan(&checkpoint.ID, &checkpoint.RuntimeIntervalID, &checkpoint.ProjectID, &checkpoint.UserID, &checkpoint.PeriodStart, &checkpoint.PeriodEnd, &checkpoint.RuntimeSeconds, &checkpoint.CreditWeight, &checkpoint.CreditsDebited, &checkpoint.IdempotencyKey)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, false, nil
	}
	return checkpoint, err == nil, err
}

func (r *RuntimeRepository) MarkCheckpointProcessed(ctx context.Context, checkpoint Checkpoint) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE metering_checkpoints SET state = 'processed', processed_at = now() WHERE id = $1`, checkpoint.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
UPDATE machine_runtime_intervals
SET last_metered_at = $2, updated_at = now()
WHERE id = $1 AND last_metered_at = $3`, checkpoint.RuntimeIntervalID, checkpoint.PeriodEnd, checkpoint.PeriodStart)
		return err
	})
}

func (r *RuntimeRepository) MarkCheckpointFailed(ctx context.Context, checkpointID string, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE metering_checkpoints SET state = 'failed', last_error = $2 WHERE id = $1`, checkpointID, cause.Error())
		return err
	})
}

func (r *RuntimeRepository) MarkCheckpointFailedAndQueueCreditStop(ctx context.Context, checkpoint Checkpoint, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE metering_checkpoints SET state = 'failed', last_error = $2 WHERE id = $1`, checkpoint.ID, cause.Error()); err != nil {
			return err
		}
		return queueSystemStopTx(ctx, tx, checkpoint.ProjectID, "credit_exhausted", map[string]any{
			"checkpoint_id":   checkpoint.ID,
			"credits_needed":  checkpoint.CreditsDebited,
			"runtime_seconds": checkpoint.RuntimeSeconds,
		})
	})
}

func (r *RuntimeRepository) CloseOpenInterval(ctx context.Context, projectID string, stoppedAt time.Time, source, confidence, observedState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
UPDATE machine_runtime_intervals
SET stopped_at = $2, observed_state = $3, observation_source = $4, confidence = $5, updated_at = now()
WHERE project_id = $1 AND stopped_at IS NULL`, projectID, stoppedAt, observedState, source, confidence)
		return err
	})
}

func (r *RuntimeRepository) RecordObservedProjectState(ctx context.Context, projectID, providerState, projectState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE fly_machines SET state = $2, version = version + 1, updated_at = now() WHERE project_id = $1`, projectID, providerState); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE projects SET state = $2, version = version + 1, updated_at = now() WHERE id = $1 AND state NOT IN ('deleted', 'deleting', 'provisioning_storage', 'provisioning_machine', 'stopping', 'restarting', 'suspended')`, projectID, projectState)
		return err
	})
}

func (r *RuntimeRepository) EnforceIdleAndReporterState(ctx context.Context, now time.Time, cfg EnforcementConfig) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT p.id, coalesce(pam.last_activity_at, mri.started_at), ito.duration_seconds, pam.keep_alive_until
FROM projects p
JOIN machine_runtime_intervals mri ON mri.project_id = p.id AND mri.stopped_at IS NULL
JOIN project_runtime_configs prc ON prc.project_id = p.id
JOIN idle_timeout_options ito ON ito.id = prc.applied_idle_timeout_option_id
LEFT JOIN project_activity_markers pam ON pam.project_id = p.id
WHERE p.state = 'running'
  AND (pam.keep_alive_until IS NULL OR pam.keep_alive_until <= $1)
FOR UPDATE OF p SKIP LOCKED`, now)
		if err != nil {
			return err
		}
		type idleStop struct {
			projectID      string
			lastActivity   time.Time
			timeoutSeconds int
			keepAliveUntil sql.NullTime
		}
		var stops []idleStop
		for rows.Next() {
			var stop idleStop
			if err := rows.Scan(&stop.projectID, &stop.lastActivity, &stop.timeoutSeconds, &stop.keepAliveUntil); err != nil {
				rows.Close()
				return err
			}
			stops = append(stops, stop)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, stop := range stops {
			deadline := stop.lastActivity.Add(time.Duration(stop.timeoutSeconds) * time.Second)
			if cfg.IdleWarningLead > 0 && now.Before(deadline) && !now.Before(deadline.Add(-cfg.IdleWarningLead)) {
				if err := emitIdleWarningTx(ctx, tx, stop.projectID, stop.lastActivity, deadline); err != nil {
					return err
				}
				continue
			}
			if now.Before(deadline) {
				continue
			}
			if err := queueSystemStopTx(ctx, tx, stop.projectID, "idle_timeout", map[string]any{
				"last_activity_at":     stop.lastActivity.UTC().Format(time.RFC3339Nano),
				"idle_timeout_seconds": stop.timeoutSeconds,
			}); err != nil {
				return err
			}
		}
		if cfg.HeartbeatGrace > 0 && cfg.ReporterLostStopGrace > 0 {
			if err := r.enforceReporterLossTx(ctx, tx, now, cfg); err != nil {
				return err
			}
		}
		if err := r.enforceEntitlementLossTx(ctx, tx, now); err != nil {
			return err
		}
		return nil
	})
}

func (r *RuntimeRepository) enforceEntitlementLossTx(ctx context.Context, tx *db.Tx, now time.Time) error {
	rows, err := tx.Query(ctx, `
SELECT p.id, p.user_id
FROM projects p
WHERE p.state = 'running'
  AND EXISTS (
    SELECT 1 FROM machine_runtime_intervals mri
    WHERE mri.project_id = p.id AND mri.stopped_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1 FROM subscriptions s
    WHERE s.user_id = p.user_id
      AND s.state IN ('active', 'trialing')
      AND (s.current_period_end IS NULL OR s.current_period_end > $1)
  )
FOR UPDATE OF p SKIP LOCKED`, now)
	if err != nil {
		return err
	}
	defer rows.Close()
	type stop struct {
		projectID string
		userID    string
	}
	var stops []stop
	for rows.Next() {
		var item stop
		if err := rows.Scan(&item.projectID, &item.userID); err != nil {
			return err
		}
		stops = append(stops, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range stops {
		if err := queueSystemStopTx(ctx, tx, item.projectID, "entitlement_lost", map[string]any{
			"user_id": item.userID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *RuntimeRepository) enforceReporterLossTx(ctx context.Context, tx *db.Tx, now time.Time, cfg EnforcementConfig) error {
	rows, err := tx.Query(ctx, `
SELECT p.id, pam.last_heartbeat_at, pam.reporter_lost_since
FROM projects p
JOIN machine_runtime_intervals mri ON mri.project_id = p.id AND mri.stopped_at IS NULL
LEFT JOIN project_activity_markers pam ON pam.project_id = p.id
WHERE p.state = 'running'
  AND pam.last_heartbeat_at IS NOT NULL
  AND pam.last_heartbeat_at <= $1::timestamptz
FOR UPDATE OF p SKIP LOCKED`, now.Add(-cfg.HeartbeatGrace))
	if err != nil {
		return err
	}
	defer rows.Close()
	type lost struct {
		projectID string
		heartbeat time.Time
		lostSince sql.NullTime
	}
	var lostRows []lost
	for rows.Next() {
		var item lost
		if err := rows.Scan(&item.projectID, &item.heartbeat, &item.lostSince); err != nil {
			return err
		}
		lostRows = append(lostRows, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range lostRows {
		lostSince := item.heartbeat.Add(cfg.HeartbeatGrace)
		if item.lostSince.Valid {
			lostSince = item.lostSince.Time
		} else if _, err := tx.Exec(ctx, `UPDATE project_activity_markers SET reporter_lost_since = $2, updated_at = now() WHERE project_id = $1`, item.projectID, lostSince); err != nil {
			return err
		}
		if !now.Before(lostSince.Add(cfg.ReporterLostStopGrace)) {
			if err := queueSystemStopTx(ctx, tx, item.projectID, "activity_reporter_lost", map[string]any{
				"last_heartbeat_at": item.heartbeat.UTC().Format(time.RFC3339Nano),
				"lost_since":        lostSince.UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(ctx, `
UPDATE project_activity_markers
SET reporter_lost_since = NULL, updated_at = now()
WHERE reporter_lost_since IS NOT NULL
  AND last_heartbeat_at > $1::timestamptz`, now.Add(-cfg.HeartbeatGrace))
	return err
}

func (r *RuntimeRepository) RecordActivity(ctx context.Context, projectID string, at time.Time, source string, metadata map[string]any) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("activity source is required")
	}
	if !validActivitySource(source) {
		return fmt.Errorf("activity source %q is not accepted", source)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project_activity_markers (project_id, last_activity_at, source, metadata)
VALUES ($1, $2, $3, coalesce($4::jsonb, '{}'::jsonb))
ON CONFLICT (project_id) DO UPDATE
SET last_activity_at = greatest(project_activity_markers.last_activity_at, EXCLUDED.last_activity_at),
    source = EXCLUDED.source,
    metadata = EXCLUDED.metadata,
    updated_at = now()`, projectID, at, source, string(b))
		return err
	})
}

func validActivitySource(source string) bool {
	switch source {
	case "connect_session", "agentunnel_connection", "papercode_activity", "cli_activity", "vm_heartbeat":
		return true
	default:
		return false
	}
}

func (r *RuntimeRepository) RecordHeartbeat(ctx context.Context, heartbeat ActivityHeartbeat) error {
	if heartbeat.LastHeartbeatAt.IsZero() {
		heartbeat.LastHeartbeatAt = time.Now().UTC()
	}
	if heartbeat.LastActivityAt.IsZero() {
		heartbeat.LastActivityAt = heartbeat.LastHeartbeatAt
	}
	signals := heartbeat.Signals
	if signals == nil {
		signals = map[string]string{}
	}
	b, err := json.Marshal(signals)
	if err != nil {
		return err
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO project_activity_markers
	(project_id, machine_id, last_activity_at, source, metadata, last_heartbeat_at, reporter_version, signals)
VALUES ($1, $2, $3, 'vm_heartbeat', '{}'::jsonb, $4, $5, $6::jsonb)
ON CONFLICT (project_id) DO UPDATE
SET machine_id = EXCLUDED.machine_id,
    last_activity_at = greatest(project_activity_markers.last_activity_at, EXCLUDED.last_activity_at),
    source = EXCLUDED.source,
    last_heartbeat_at = greatest(coalesce(project_activity_markers.last_heartbeat_at, '-infinity'::timestamptz), EXCLUDED.last_heartbeat_at),
    reporter_version = EXCLUDED.reporter_version,
    signals = EXCLUDED.signals,
    reporter_lost_since = NULL,
    idle_warning_sent_at = CASE
      WHEN EXCLUDED.last_activity_at > project_activity_markers.last_activity_at THEN NULL
      ELSE project_activity_markers.idle_warning_sent_at
    END,
    updated_at = now()`,
			heartbeat.ProjectID, heartbeat.MachineID, heartbeat.LastActivityAt, heartbeat.LastHeartbeatAt, heartbeat.ReporterVersion, string(b))
		return err
	})
}

func (r *RuntimeRepository) VerifyHeartbeatCredential(ctx context.Context, projectID, machineID, token string) error {
	if projectID == "" || machineID == "" || token == "" || r.encryptionKey == "" {
		return ErrInvalidHeartbeatCredential
	}
	var encoded string
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT ar.metadata->>'machine_token_ciphertext'
FROM paperboat.fly_machines fm
JOIN paperboat.agentunnel_resources ar ON ar.project_id = fm.project_id
WHERE fm.project_id = $1 AND fm.fly_machine_id = $2`, projectID, machineID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidHeartbeatCredential
	}
	if err != nil {
		return err
	}
	if encoded == "" {
		return ErrInvalidHeartbeatCredential
	}
	ciphertext, err := hex.DecodeString(encoded)
	if err != nil {
		return ErrInvalidHeartbeatCredential
	}
	expected, err := secrets.Decrypt(r.encryptionKey, ciphertext)
	if err != nil {
		return ErrInvalidHeartbeatCredential
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return ErrInvalidHeartbeatCredential
	}
	return nil
}

func emitIdleWarningTx(ctx context.Context, tx *db.Tx, projectID string, lastActivity, deadline time.Time) error {
	result, err := tx.Exec(ctx, `
INSERT INTO project_activity_markers (project_id, last_activity_at, source, metadata, idle_warning_sent_at)
VALUES ($1, $2, 'server', '{}'::jsonb, now())
ON CONFLICT (project_id) DO UPDATE
SET idle_warning_sent_at = now(), updated_at = now()
WHERE project_activity_markers.idle_warning_sent_at IS NULL`, projectID, lastActivity)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return nil
	}
	return insertEvent(ctx, tx, projectID, "project.idle_stop_warning", "Project is approaching its configured idle timeout.", map[string]any{
		"last_activity_at": lastActivity.UTC().Format(time.RFC3339Nano),
		"idle_deadline":    deadline.UTC().Format(time.RFC3339Nano),
	})
}

func queueSystemStopTx(ctx context.Context, tx *db.Tx, projectID, reason string, metadata map[string]any) error {
	if _, err := tx.Exec(ctx, `UPDATE projects SET state = 'stopping', version = version + 1, updated_at = now() WHERE id = $1 AND state NOT IN ('deleted', 'deleting', 'stopping', 'stopped')`, projectID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE access_sessions
SET state = 'revoked',
    revoked_at = now(),
    updated_at = now(),
    version = version + 1,
    descriptor = jsonb_set(descriptor, '{revocation_reason}', to_jsonb($2::text), true)
WHERE project_id = $1
  AND state = 'active'
  AND revoked_at IS NULL`, projectID, reason); err != nil {
		return err
	}
	payload := fmt.Sprintf(`{"previous_state":"running","reason":%q}`, reason)
	key := "project.stop." + reason + ":" + projectID
	jobID := newID("job")
	err := tx.QueryRow(ctx, `
INSERT INTO orchestration_jobs (id, job_type, aggregate_type, aggregate_id, idempotency_key, state, payload)
VALUES ($1, 'project.stop', 'project', $2, $3, 'queued', $4::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING id`, jobID, projectID, key, payload).Scan(&jobID)
	inserted := err == nil
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE orchestration_jobs
SET state = 'queued', next_run_at = now(), payload = $2::jsonb, updated_at = now()
WHERE idempotency_key = $1`, key, payload); err != nil {
			return err
		}
	}
	if !inserted {
		return nil
	}
	message := "Project stop was queued by metering enforcement."
	if reason == "idle_timeout" {
		message = "Project was idle past its configured timeout; stop was queued."
	}
	if reason == "credit_exhausted" {
		message = "Project credits were exhausted; stop was queued."
	}
	if reason == "activity_reporter_lost" {
		message = "Project activity reporter stopped heartbeating; stop was queued."
	}
	if reason == "entitlement_lost" {
		message = "Project entitlement is inactive; stop was queued."
	}
	return insertEvent(ctx, tx, projectID, "project.stop_queued."+reason, message, metadata)
}

func insertEvent(ctx context.Context, tx *db.Tx, projectID, eventType, message string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO project_events (id, project_id, event_type, message, metadata) VALUES ($1, $2, $3, $4, $5::jsonb)`, newID("pevt"), projectID, eventType, message, string(b))
	return err
}

func mapProviderState(state string) string {
	if isProviderRunning(state) {
		return "running"
	}
	return "stopped"
}

func isProviderRunning(state string) bool {
	return state == "running" || state == "started"
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
