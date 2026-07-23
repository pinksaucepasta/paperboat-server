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
	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type RuntimeService struct {
	repo       *RuntimeRepository
	fly        fly.Client
	billing    *billing.Repository
	now        func() time.Time
	cfg        EnforcementConfig
	downstream ProjectSessionRevoker
}

type ProjectSessionRevoker interface {
	RetryPendingPapercodeRevocations(context.Context) error
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

func (s *RuntimeService) SetDownstreamRevoker(revoker ProjectSessionRevoker) {
	s.downstream = revoker
}

func (s *RuntimeService) RunOnce(ctx context.Context) (runErr error) {
	defer func() {
		runErr = errors.Join(runErr, s.propagatePapercodeRevocations(ctx))
	}()
	now := s.now().UTC()
	if err := s.processPendingCheckpoints(ctx); err != nil {
		return err
	}
	machines, err := s.repo.MeterableMachines(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, machine := range machines {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			return errors.Join(errs...)
		}
		// A single machine's poll/observe failure (e.g. a transient Fly API
		// error) must not abort the run: idle and reporter-loss enforcement
		// below still has to happen for every other project, or idle machines
		// would never be stopped. Collect the error and keep going.
		if err := s.observeMachine(ctx, machine, now); err != nil {
			errs = append(errs, fmt.Errorf("observe machine %s: %w", machine.FlyMachineID, err))
		}
	}
	if err := s.repo.EnforceIdleAndReporterState(ctx, now, s.cfg); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *RuntimeService) observeMachine(ctx context.Context, machine MeterableMachine, now time.Time) error {
	observed, err := s.fly.GetMachine(ctx, machine.FlyMachineID)
	if errors.Is(err, fly.ErrNotFound) {
		return s.observeStopped(ctx, machine.ProjectID, now, "missing", "low")
	}
	if err != nil {
		return err
	}
	if isProviderRunning(observed.State) {
		return s.observeRunning(ctx, machine, now, observed.State)
	}
	return s.observeStopped(ctx, machine.ProjectID, now, observed.State, "high")
}

func (s *RuntimeService) propagatePapercodeRevocations(ctx context.Context) error {
	if s.downstream == nil {
		return nil
	}
	return s.downstream.RetryPendingPapercodeRevocations(ctx)
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
	ProjectID            string
	MachineID            string
	LastActivityAt       time.Time
	LastHeartbeatAt      time.Time
	ReporterVersion      string
	Signals              map[string]string
	ConfigSync           *configsync.Status
	ConfigSyncObservedAt time.Time
}

func runtimeIntervalFromOpenRow(row dbsqlc.GetOpenRuntimeIntervalRow) RuntimeInterval {
	return RuntimeInterval{ID: row.ID, ProjectID: row.ProjectID, UserID: row.UserID, FlyMachineID: row.FlyMachineID, CreditWeight: row.CreditWeight, LastMeteredAt: row.LastMeteredAt, ObservedState: row.ObservedState, Confidence: row.Confidence, ObservationSrc: row.ObservationSource}
}

func checkpointFromPendingRow(row dbsqlc.ListPendingMeteringCheckpointsRow) Checkpoint {
	return Checkpoint{ID: row.ID, RuntimeIntervalID: row.RuntimeIntervalID, ProjectID: row.ProjectID, UserID: row.UserID, PeriodStart: row.PeriodStart, PeriodEnd: row.PeriodEnd, RuntimeSeconds: int(row.RuntimeSeconds), CreditWeight: row.CreditWeight, CreditsDebited: row.CreditsDebited, IdempotencyKey: row.IdempotencyKey}
}

func meteringCheckpointParams(checkpoint Checkpoint) dbsqlc.InsertMeteringCheckpointParams {
	return dbsqlc.InsertMeteringCheckpointParams{ID: checkpoint.ID, RuntimeIntervalID: checkpoint.RuntimeIntervalID, ProjectID: checkpoint.ProjectID, UserID: checkpoint.UserID, PeriodStart: checkpoint.PeriodStart, PeriodEnd: checkpoint.PeriodEnd, RuntimeSeconds: int32(checkpoint.RuntimeSeconds), CreditWeight: checkpoint.CreditWeight, CreditsDebited: checkpoint.CreditsDebited, IdempotencyKey: checkpoint.IdempotencyKey}
}

func (r *RuntimeRepository) MeterableMachines(ctx context.Context) ([]MeterableMachine, error) {
	rows, err := r.db.Queries().ListMeterableMachines(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]MeterableMachine, 0, len(rows))
	for _, row := range rows {
		out = append(out, MeterableMachine{ProjectID: row.ProjectID, UserID: row.UserID, FlyMachineID: row.FlyMachineID, MachineTypeVersionID: row.AppliedMachineTypeVersionID.String, CreditWeight: row.CreditWeight, IdleTimeoutSeconds: int(row.DurationSeconds)})
	}
	return out, nil
}

func (r *RuntimeRepository) OpenInterval(ctx context.Context, projectID string) (RuntimeInterval, bool, error) {
	row, err := r.db.Queries().GetOpenRuntimeInterval(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeInterval{}, false, nil
	}
	return runtimeIntervalFromOpenRow(row), err == nil, err
}

func (r *RuntimeRepository) PendingCheckpoints(ctx context.Context) ([]Checkpoint, error) {
	rows, err := r.db.Queries().ListPendingMeteringCheckpoints(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Checkpoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, checkpointFromPendingRow(row))
	}
	return out, nil
}

func (r *RuntimeRepository) EnsureOpenInterval(ctx context.Context, machine MeterableMachine, now time.Time) (RuntimeInterval, bool, error) {
	var interval RuntimeInterval
	opened := false
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		row, err := q.GetOpenRuntimeIntervalForUpdate(ctx, machine.ProjectID)
		if err == nil {
			interval = RuntimeInterval{ID: row.ID, ProjectID: row.ProjectID, UserID: row.UserID, FlyMachineID: row.FlyMachineID, CreditWeight: row.CreditWeight, LastMeteredAt: row.LastMeteredAt, ObservedState: row.ObservedState, Confidence: row.Confidence, ObservationSrc: row.ObservationSource}
			err = q.MarkRuntimeIntervalRunning(ctx, interval.ID)
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
		return q.InsertRuntimeInterval(ctx, dbsqlc.InsertRuntimeIntervalParams{ID: interval.ID, ProjectID: machine.ProjectID, UserID: machine.UserID, FlyMachineID: machine.FlyMachineID, MachineTypeVersionID: machine.MachineTypeVersionID, CreditWeight: machine.CreditWeight, StartedAt: now})
	})
	return interval, opened, err
}

func (r *RuntimeRepository) CreateCheckpoint(ctx context.Context, interval RuntimeInterval, now time.Time) (Checkpoint, bool, error) {
	if !now.After(interval.LastMeteredAt) {
		return Checkpoint{}, false, nil
	}
	var checkpoint Checkpoint
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		row, err := q.GetRuntimeIntervalForCheckpoint(ctx, interval.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		interval = RuntimeInterval{ID: row.ID, ProjectID: row.ProjectID, UserID: row.UserID, FlyMachineID: row.FlyMachineID, CreditWeight: row.CreditWeight, LastMeteredAt: row.LastMeteredAt}
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
		checkpoint.CreditsDebited, err = q.CalculateRuntimeCredits(ctx, dbsqlc.CalculateRuntimeCreditsParams{RuntimeSeconds: int64(seconds), CreditWeight: interval.CreditWeight})
		if err != nil {
			return err
		}
		return q.InsertMeteringCheckpoint(ctx, meteringCheckpointParams(checkpoint))
	})
	if err != nil || checkpoint.ID == "" {
		return Checkpoint{}, false, err
	}
	return checkpoint, true, nil
}

func (r *RuntimeRepository) EnsureFinalCheckpoint(ctx context.Context, interval RuntimeInterval, stoppedAt time.Time) (Checkpoint, bool, error) {
	var checkpoint Checkpoint
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		row, err := q.GetRuntimeIntervalForFinalCheckpoint(ctx, interval.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		interval = RuntimeInterval{ID: row.ID, ProjectID: row.ProjectID, UserID: row.UserID, FlyMachineID: row.FlyMachineID, CreditWeight: row.CreditWeight, LastMeteredAt: row.LastMeteredAt}
		periodStart := interval.LastMeteredAt
		latestEnd, err := q.GetLatestCheckpointEnd(ctx, interval.ID)
		if err == nil && latestEnd.After(periodStart) {
			periodStart = latestEnd
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
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
			tail.CreditsDebited, err = q.CalculateRuntimeCredits(ctx, dbsqlc.CalculateRuntimeCreditsParams{RuntimeSeconds: int64(seconds), CreditWeight: interval.CreditWeight})
			if err != nil {
				return err
			}
			if err := q.InsertMeteringCheckpoint(ctx, meteringCheckpointParams(tail)); err != nil {
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
	row, err := tx.Queries().GetPendingCheckpointForUpdate(ctx, intervalID)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, false, nil
	}
	checkpoint := Checkpoint{ID: row.ID, RuntimeIntervalID: row.RuntimeIntervalID, ProjectID: row.ProjectID, UserID: row.UserID, PeriodStart: row.PeriodStart, PeriodEnd: row.PeriodEnd, RuntimeSeconds: int(row.RuntimeSeconds), CreditWeight: row.CreditWeight, CreditsDebited: row.CreditsDebited, IdempotencyKey: row.IdempotencyKey}
	return checkpoint, err == nil, err
}

func (r *RuntimeRepository) MarkCheckpointProcessed(ctx context.Context, checkpoint Checkpoint) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if err := q.MarkMeteringCheckpointProcessed(ctx, checkpoint.ID); err != nil {
			return err
		}
		return q.AdvanceRuntimeIntervalMetering(ctx, dbsqlc.AdvanceRuntimeIntervalMeteringParams{ID: checkpoint.RuntimeIntervalID, LastMeteredAt: checkpoint.PeriodEnd, LastMeteredAt_2: checkpoint.PeriodStart})
	})
}

func (r *RuntimeRepository) MarkCheckpointFailed(ctx context.Context, checkpointID string, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().MarkMeteringCheckpointFailed(ctx, dbsqlc.MarkMeteringCheckpointFailedParams{ID: checkpointID, LastError: cause.Error()})
	})
}

func (r *RuntimeRepository) MarkCheckpointFailedAndQueueCreditStop(ctx context.Context, checkpoint Checkpoint, cause error) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := tx.Queries().MarkMeteringCheckpointFailed(ctx, dbsqlc.MarkMeteringCheckpointFailedParams{ID: checkpoint.ID, LastError: cause.Error()}); err != nil {
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
		return tx.Queries().CloseRuntimeInterval(ctx, dbsqlc.CloseRuntimeIntervalParams{ProjectID: projectID, StoppedAt: sql.NullTime{Time: stoppedAt, Valid: true}, ObservedState: observedState, ObservationSource: source, Confidence: confidence})
	})
}

func (r *RuntimeRepository) RecordObservedProjectState(ctx context.Context, projectID, providerState, projectState string) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		// Provider state is an observation only. Lifecycle jobs own product state,
		// including readiness-gated starts and deliberate stops.
		return tx.Queries().UpdateObservedFlyMachineState(ctx, dbsqlc.UpdateObservedFlyMachineStateParams{ProjectID: projectID, State: providerState})
	})
}

func (r *RuntimeRepository) EnforceIdleAndReporterState(ctx context.Context, now time.Time, cfg EnforcementConfig) error {
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Queries().ListIdleProjectsForUpdate(ctx, sql.NullTime{Time: now, Valid: true})
		if err != nil {
			return err
		}
		for _, stop := range rows {
			deadline := stop.LastActivityAt.Add(time.Duration(stop.DurationSeconds) * time.Second)
			if cfg.IdleWarningLead > 0 && now.Before(deadline) && !now.Before(deadline.Add(-cfg.IdleWarningLead)) {
				if err := emitIdleWarningTx(ctx, tx, stop.ProjectID, stop.LastActivityAt, deadline); err != nil {
					return err
				}
				continue
			}
			if now.Before(deadline) {
				continue
			}
			if err := queueSystemStopTx(ctx, tx, stop.ProjectID, "idle_timeout", map[string]any{
				"last_activity_at":     stop.LastActivityAt.UTC().Format(time.RFC3339Nano),
				"idle_timeout_seconds": int(stop.DurationSeconds),
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
	rows, err := tx.Queries().ListEntitlementLostProjectsForUpdate(ctx, sql.NullTime{Time: now, Valid: true})
	if err != nil {
		return err
	}
	for _, item := range rows {
		if err := queueSystemStopTx(ctx, tx, item.ProjectID, "entitlement_lost", map[string]any{
			"user_id": item.UserID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *RuntimeRepository) enforceReporterLossTx(ctx context.Context, tx *db.Tx, now time.Time, cfg EnforcementConfig) error {
	q := tx.Queries()
	rows, err := q.ListReporterLostProjectsForUpdate(ctx, sql.NullTime{Time: now.Add(-cfg.HeartbeatGrace), Valid: true})
	if err != nil {
		return err
	}
	for _, item := range rows {
		heartbeat := item.LastHeartbeatAt.Time
		lostSince := heartbeat.Add(cfg.HeartbeatGrace)
		if item.ReporterLostSince.Valid {
			lostSince = item.ReporterLostSince.Time
		} else if err := q.SetReporterLostSince(ctx, dbsqlc.SetReporterLostSinceParams{ProjectID: item.ProjectID, ReporterLostSince: sql.NullTime{Time: lostSince, Valid: true}}); err != nil {
			return err
		}
		if !now.Before(lostSince.Add(cfg.ReporterLostStopGrace)) {
			if err := queueSystemStopTx(ctx, tx, item.ProjectID, "activity_reporter_lost", map[string]any{
				"last_heartbeat_at": heartbeat.UTC().Format(time.RFC3339Nano),
				"lost_since":        lostSince.UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return err
			}
		}
	}
	return q.ClearRecoveredReporterLoss(ctx, sql.NullTime{Time: now.Add(-cfg.HeartbeatGrace), Valid: true})
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
		return tx.Queries().UpsertMeteringActivity(ctx, dbsqlc.UpsertMeteringActivityParams{ProjectID: projectID, LastActivityAt: at, Source: source, Metadata: b})
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
		updated, err := tx.Queries().MarkConnectedMachineOnlineFromHelper(ctx, dbsqlc.MarkConnectedMachineOnlineFromHelperParams{ID: heartbeat.MachineID, EnvironmentID: heartbeat.ProjectID})
		if err != nil {
			return err
		}
		if updated == 1 {
			_, err = tx.Queries().MarkConnectedMachineEnrollmentReady(ctx, sql.NullString{String: heartbeat.MachineID, Valid: true})
			return err
		}
		if err := tx.Queries().UpsertActivityHeartbeat(ctx, dbsqlc.UpsertActivityHeartbeatParams{ProjectID: heartbeat.ProjectID, MachineID: heartbeat.MachineID, LastActivityAt: heartbeat.LastActivityAt, LastHeartbeatAt: sql.NullTime{Time: heartbeat.LastHeartbeatAt, Valid: true}, ReporterVersion: heartbeat.ReporterVersion, Signals: b}); err != nil {
			return err
		}
		if heartbeat.ConfigSync == nil {
			return nil
		}
		if heartbeat.ConfigSyncObservedAt.IsZero() {
			heartbeat.ConfigSyncObservedAt = heartbeat.ConfigSync.UpdatedAt.UTC()
		}
		skipped, err := json.Marshal(heartbeat.ConfigSync.Skipped)
		if err != nil {
			return err
		}
		conflicts, err := json.Marshal(heartbeat.ConfigSync.Conflicts)
		if err != nil {
			return err
		}
		classifierPending, err := json.Marshal(heartbeat.ConfigSync.ClassifierPending)
		if err != nil {
			return err
		}
		if err := tx.Queries().UpsertConfigSyncStatus(ctx, dbsqlc.UpsertConfigSyncStatusParams{
			ProjectID: heartbeat.ProjectID, MachineID: heartbeat.MachineID, State: heartbeat.ConfigSync.State,
			LastAttemptAt: nullableTime(heartbeat.ConfigSync.LastAttemptAt), LastSuccessfulSyncAt: nullableTime(heartbeat.ConfigSync.LastSuccessfulAt),
			RemoteCommit: heartbeat.ConfigSync.RemoteCommit, PendingPathCount: int32(heartbeat.ConfigSync.PendingPathCount),
			Skipped: skipped, Conflicts: conflicts, ClassifierPending: classifierPending, ErrorCode: heartbeat.ConfigSync.ErrorCode, ErrorMessage: heartbeat.ConfigSync.ErrorMessage,
			MaxFileBytes: heartbeat.ConfigSync.MaxFileBytes, MaxBatchBytes: heartbeat.ConfigSync.MaxBatchBytes,
			PolicyRevision: heartbeat.ConfigSync.PolicyRevision, ClassifierPolicyRevision: heartbeat.ConfigSync.ClassifierPolicyRevision,
			ClassifierModelRevision: heartbeat.ConfigSync.ClassifierModelRevision, ClassifierHealth: heartbeat.ConfigSync.ClassifierHealth, StatusUpdatedAt: heartbeat.ConfigSync.UpdatedAt.UTC(),
			EncryptionKeyVersion: int32(heartbeat.ConfigSync.EncryptionKeyVersion),
			StatusObservedAt:     heartbeat.ConfigSyncObservedAt.UTC(), HeartbeatAt: heartbeat.LastHeartbeatAt,
		}); err != nil {
			return err
		}
		return tx.Queries().TouchConfigSyncStatusReceipt(ctx, dbsqlc.TouchConfigSyncStatusReceiptParams{
			HeartbeatAt: heartbeat.LastHeartbeatAt,
			ProjectID:   heartbeat.ProjectID,
			MachineID:   heartbeat.MachineID,
		})
	})
}

func nullableTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func (r *RuntimeRepository) VerifyHeartbeatCredential(ctx context.Context, projectID, machineID, token string) error {
	if projectID == "" || machineID == "" || token == "" || r.encryptionKey == "" {
		return ErrInvalidHeartbeatCredential
	}
	encoded, err := r.db.Queries().GetHeartbeatMachineTokenCiphertext(ctx, dbsqlc.GetHeartbeatMachineTokenCiphertextParams{ProjectID: projectID, FlyMachineID: machineID})
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
	rows, err := tx.Queries().EmitIdleWarning(ctx, dbsqlc.EmitIdleWarningParams{ProjectID: projectID, LastActivityAt: lastActivity})
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
	q := tx.Queries()
	if err := q.MarkProjectStoppingForEnforcement(ctx, projectID); err != nil {
		return err
	}
	if err := q.RevokeProjectSessionsForEnforcement(ctx, dbsqlc.RevokeProjectSessionsForEnforcementParams{ProjectID: projectID, Reason: reason}); err != nil {
		return err
	}
	payload := fmt.Sprintf(`{"previous_state":"running","reason":%q}`, reason)
	key := "project.stop." + reason + ":" + projectID
	jobID := newID("job")
	insertedID, err := q.InsertEnforcementStopJob(ctx, dbsqlc.InsertEnforcementStopJobParams{ID: jobID, ProjectID: projectID, IdempotencyKey: key, Payload: json.RawMessage(payload)})
	jobID = insertedID
	inserted := err == nil
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := q.RequeueEnforcementStopJob(ctx, dbsqlc.RequeueEnforcementStopJobParams{IdempotencyKey: key, Payload: json.RawMessage(payload)}); err != nil {
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
	return tx.Queries().InsertMeteringProjectEvent(ctx, dbsqlc.InsertMeteringProjectEventParams{ID: newID("pevt"), ProjectID: projectID, EventType: eventType, Message: message, Metadata: b})
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
