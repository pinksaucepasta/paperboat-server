package tunnelv1

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

var (
	ErrPlatformCertificateUnavailable = errors.New("platform certificate lifecycle is unavailable")
	ErrPlatformCertificateNoEdges     = errors.New("platform certificate has no ready edge targets")
)

const defaultPlatformEdgeStaleAfter = 2 * time.Minute

// PlatformEdgeTargetResolver supplies the exact current node/process and
// assignment generations. Platform wildcards are distributed to every target
// returned by this resolver; the worker never discovers edge DNS credentials
// or falls back to Caddy.
type PlatformEdgeTargetResolver func(context.Context) ([]tunnelcert.EdgeTarget, error)

// SQLPlatformEdgeTargetResolver selects the exact ready edge process set for
// a platform distribution pass. The node process_epoch is the process fence;
// platform certificates have no route assignment, so their assignment
// generation is the stable value one. Heartbeats must not manufacture a new
// certificate distribution generation on every reconciliation tick.
type SQLPlatformEdgeTargetResolver struct {
	db         *db.DB
	staleAfter time.Duration
	now        func() time.Time
}

func NewSQLPlatformEdgeTargetResolver(database *db.DB, staleAfter time.Duration, now func() time.Time) (*SQLPlatformEdgeTargetResolver, error) {
	if database == nil || database.SQL() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrPlatformCertificateUnavailable)
	}
	if staleAfter <= 0 || staleAfter > 15*time.Minute {
		staleAfter = defaultPlatformEdgeStaleAfter
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SQLPlatformEdgeTargetResolver{db: database, staleAfter: staleAfter, now: now}, nil
}

func (r *SQLPlatformEdgeTargetResolver) Resolve(ctx context.Context) ([]tunnelcert.EdgeTarget, error) {
	if r == nil || r.db == nil || r.db.SQL() == nil {
		return nil, ErrPlatformCertificateUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := r.now().UTC()
	if now.IsZero() {
		return nil, ErrPlatformCertificateUnavailable
	}
	rows, err := r.db.Queries().ListReadyPlatformEdgeTargetsV1(ctx, sql.NullTime{Time: now.Add(-r.staleAfter), Valid: true})
	if err != nil {
		return nil, err
	}
	result := make([]tunnelcert.EdgeTarget, 0, 8)
	seen := make(map[string]struct{})
	for _, row := range rows {
		nodeID, processEpoch := row.ID, row.ProcessEpoch
		edge := tunnelcert.EdgeTarget{NodeID: nodeID, ProcessEpoch: processEpoch, Generation: 1}
		key := nodeID + "\x00" + processEpoch
		if _, exists := seen[key]; exists {
			continue
		}
		if err := (tunnelcert.Domain{ID: "platform_edge_probe_v1", AccountID: "platform_edge_probe_v1", TargetKind: tunnelcert.TargetPlatformWildcard, Hostname: "*.edge.example.test", Generation: 1, Strategy: tunnelcert.StrategyPlatformDNS01, OwnershipState: "verified", EdgeTargets: []tunnelcert.EdgeTarget{edge}}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: edge node %s returned invalid identity: %v", ErrPlatformCertificateUnavailable, nodeID, err)
		}
		seen[key] = struct{}{}
		result = append(result, edge)
	}
	return tunnelcert.SortEdgeTargets(result), nil
}

type PlatformCertificateWorkerConfig struct {
	Database               *db.DB
	Bases                  tunnelcert.PlatformCertificateBases
	EdgeTargets            PlatformEdgeTargetResolver
	Issuer                 tunnelcert.Issuer
	CAA                    tunnelcert.CAAInspector
	Keys                   tunnelcert.MasterKeySource
	MasterKeyReference     string
	IssuerName             string
	OwnerID                string
	Distributor            tunnelcert.CertificateDistributor
	RenewBefore            time.Duration
	LockTTL                time.Duration
	DistributionTimeout    time.Duration
	ExpiryAlertWindow      time.Duration
	MaxCertificateLifetime time.Duration
	Now                    func() time.Time
}

// PlatformCertificateWorker reconciles the two built-in wildcard targets.
// The coordinator remains the only code that issues, encrypts, stages,
// activates, supersedes, distributes, or revokes certificate material.
type PlatformCertificateWorker struct {
	store       *tunnelcert.PlatformCertificateStore
	targets     []tunnelcert.PlatformCertificateTargetDefinition
	coordinator *tunnelcert.Coordinator
	edgeTargets PlatformEdgeTargetResolver
	renewBefore time.Duration
	issuerName  string
	now         func() time.Time

	mu        sync.Mutex
	lastErr   error
	observeMu sync.RWMutex
	observe   func(context.Context, CertificateTelemetryEvent)
}

func NewPlatformCertificateWorker(config PlatformCertificateWorkerConfig) (*PlatformCertificateWorker, error) {
	if config.Database == nil || config.Issuer == nil || config.CAA == nil || config.Keys == nil || config.MasterKeyReference == "" || config.OwnerID == "" || config.EdgeTargets == nil || config.Distributor == nil {
		return nil, fmt.Errorf("%w: database, issuer, CAA, key source, references, owner, edge resolver, and distributor are required", ErrPlatformCertificateUnavailable)
	}
	definitions, err := tunnelcert.PlatformCertificateTargetDefinitions(config.Bases)
	if err != nil {
		return nil, fmt.Errorf("%w: target definitions: %v", ErrPlatformCertificateUnavailable, err)
	}
	store, err := tunnelcert.NewPlatformCertificateStore(config.Database)
	if err != nil {
		return nil, fmt.Errorf("%w: target store: %v", ErrPlatformCertificateUnavailable, err)
	}
	locks, err := tunnelcert.NewSQLIssuanceLock(config.Database)
	if err != nil {
		return nil, fmt.Errorf("%w: issuance lock: %v", ErrPlatformCertificateUnavailable, err)
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	issuerName := config.IssuerName
	if issuerName == "" {
		issuerName = "letsencrypt"
	}
	coordinator, err := tunnelcert.NewCoordinator(tunnelcert.Config{
		Store:                  store,
		Locks:                  locks,
		Keys:                   config.Keys,
		Issuer:                 config.Issuer,
		CAA:                    config.CAA,
		Distributor:            config.Distributor,
		MasterKeyReference:     config.MasterKeyReference,
		IssuerName:             issuerName,
		OwnerID:                config.OwnerID,
		LockTTL:                config.LockTTL,
		RenewBefore:            config.RenewBefore,
		DistributionTimeout:    config.DistributionTimeout,
		ExpiryAlertWindow:      config.ExpiryAlertWindow,
		MaxCertificateLifetime: config.MaxCertificateLifetime,
		Now:                    now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: coordinator: %v", ErrPlatformCertificateUnavailable, err)
	}
	renewBefore := config.RenewBefore
	if renewBefore <= 0 || renewBefore >= 365*24*time.Hour {
		renewBefore = 30 * 24 * time.Hour
	}
	return &PlatformCertificateWorker{store: store, targets: definitions, coordinator: coordinator, edgeTargets: config.EdgeTargets, renewBefore: renewBefore, issuerName: issuerName, now: now}, nil
}

func (w *PlatformCertificateWorker) LastError() error {
	if w == nil {
		return ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

// SetTelemetryObserver installs the same process-owned lifecycle adapter used
// by user and preview certificate workers. Platform target IDs are emitted as
// DomainID so existing certificate health and diagnostics retain one schema.
func (w *PlatformCertificateWorker) SetTelemetryObserver(observer func(context.Context, CertificateTelemetryEvent)) error {
	if w == nil || observer == nil {
		return ErrInvalidInput
	}
	w.observeMu.Lock()
	w.observe = observer
	w.observeMu.Unlock()
	return nil
}

func (w *PlatformCertificateWorker) emitTelemetry(ctx context.Context, targetID, certificateID, operation, outcome string, nextRetryAt time.Time) {
	if w == nil {
		return
	}
	w.observeMu.RLock()
	observer := w.observe
	w.observeMu.RUnlock()
	if observer != nil {
		observer(ctx, CertificateTelemetryEvent{DomainID: targetID, CertificateID: certificateID, Operation: operation, Outcome: outcome, NextRetryAt: nextRetryAt})
	}
}

func (w *PlatformCertificateWorker) setLastError(err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

// Reconcile creates the durable target rows before reading them, then runs a
// bounded coordinator pass. A failed renewal records a capped retry deadline
// while leaving any active certificate and edge copies untouched.
func (w *PlatformCertificateWorker) Reconcile(ctx context.Context, limit int) (int, error) {
	if w == nil || w.store == nil || w.coordinator == nil || w.edgeTargets == nil || limit < 1 || limit > 500 {
		return 0, ErrInvalidInput
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := w.now().UTC()
	if err := w.store.EnsurePlatformTargets(ctx, w.targets, now); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	edges, err := w.edgeTargets(ctx)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	edges = tunnelcert.SortEdgeTargets(edges)
	if len(edges) == 0 {
		return 0, ErrPlatformCertificateNoEdges
	}
	for _, edge := range edges {
		if err := (tunnelcert.Domain{ID: "platform_edge_probe_v1", AccountID: "platform_edge_probe_v1", TargetKind: tunnelcert.TargetPlatformWildcard, Hostname: "*.edge.example.test", Generation: 1, Strategy: tunnelcert.StrategyPlatformDNS01, OwnershipState: "verified", EdgeTargets: []tunnelcert.EdgeTarget{edge}}).Validate(); err != nil {
			return 0, fmt.Errorf("%w: edge resolver returned invalid target: %v", ErrPlatformCertificateUnavailable, err)
		}
	}
	platformTargets, err := w.store.ListPlatformTargets(ctx, limit)
	if err != nil {
		return 0, err
	}
	changed := 0
	retryFailure := false
	for _, target := range platformTargets {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		if target.DesiredState != "active" {
			continue
		}
		current, found, err := w.coordinator.CurrentCertificate(ctx, target.ID)
		if err != nil {
			return changed, err
		}
		// A failed attempt is durable. Do not hammer the issuer while an active
		// LKG remains usable, but still call Ensure with RenewalDue=false so a
		// newly replaced edge can receive that LKG immediately.
		if target.NextRetryAt.After(now) && (!found || current.ExpiresAt.After(now)) {
			if !found {
				retryFailure = true
				w.setLastError(platformRetryError(target.CertificateFailureCode))
				continue
			}
		}
		domain := platformDomain(target, edges, now, w.renewBefore, w.issuerName)
		if found {
			domain.CertificateReference = current.CertificateReference
			domain.CertificateGeneration = current.CertificateGeneration
			domain.RenewalDue = !current.RenewalAt.After(now) || !current.ExpiresAt.After(now)
			if target.NextRetryAt.After(now) && current.ExpiresAt.After(now) {
				domain.RenewalDue = false
			}
		} else {
			domain.RenewalDue = true
		}
		hadCurrent := found
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		result, ensureErr := w.coordinator.Ensure(ctx, domain)
		if ensureErr != nil {
			operation := platformCertificateOperation(hadCurrent)
			if !platformRetryable(ensureErr) {
				w.emitTelemetry(ctx, target.ID, "", operation, "failed", time.Time{})
				return changed, ensureErr
			}
			next := now.Add(platformRetryDelay(target.RetryCount + 1))
			if err := w.store.MarkPlatformCertificateFailure(ctx, target.ID, platformFailureCode(ensureErr), next, now); err != nil {
				w.emitTelemetry(ctx, target.ID, "", operation, "failed", next)
				return changed, err
			}
			retryFailure = true
			w.setLastError(ensureErr)
			w.emitTelemetry(ctx, target.ID, "", operation, "failed", next)
			continue
		}
		certificate, found, err := w.coordinator.CurrentCertificate(ctx, target.ID)
		if err != nil {
			return changed, err
		}
		if !found || certificate.State != tunnelcert.StateActive || certificate.TargetKind != tunnelcert.TargetPlatformWildcard || certificate.Hostname != target.Hostname {
			w.emitTelemetry(ctx, target.ID, "", platformCertificateOperation(hadCurrent), "failed", now.Add(time.Minute))
			return changed, tunnelcert.ErrGenerationConflict
		}
		if err := w.store.MarkPlatformCertificateReady(ctx, target.ID, certificate.CertificateReference, certificate.ExpiresAt, now); err != nil {
			w.emitTelemetry(ctx, target.ID, certificate.ID, platformCertificateOperation(hadCurrent), "failed", now.Add(time.Minute))
			return changed, err
		}
		w.emitTelemetry(ctx, target.ID, certificate.ID, platformCertificateOperation(hadCurrent), "success", time.Time{})
		if result.Issued {
			changed++
		}
	}
	if !retryFailure {
		// A pass is complete only after every target was visited and its
		// projection was marked ready. A later success therefore clears a
		// transient error, while a partial pass with a retryable target leaves
		// the failure visible to health and diagnostics.
		w.setLastError(nil)
	}
	return changed, nil
}

func platformCertificateOperation(hadCurrent bool) string {
	if hadCurrent {
		return "renew"
	}
	return "issue"
}

func platformDomain(target tunnelcert.PlatformCertificateTarget, edges []tunnelcert.EdgeTarget, now time.Time, renewBefore time.Duration, issuerName string) tunnelcert.Domain {
	return tunnelcert.Domain{
		ID: target.ID, AccountID: target.AccountID, TargetKind: tunnelcert.TargetPlatformWildcard,
		Hostname: target.Hostname, ChallengeReference: target.ChallengeReference,
		Generation: target.Generation, Strategy: tunnelcert.StrategyPlatformDNS01,
		OwnershipState: "verified", CAAState: "unknown", CertificateReference: target.CertificateReference,
		RenewalDue: target.CertificateExpiresAt.IsZero() || !target.CertificateExpiresAt.After(now.Add(renewBefore)),
		Issuer:     issuerName, EdgeTargets: append([]tunnelcert.EdgeTarget(nil), edges...),
	}
}

func platformRetryable(err error) bool {
	return errors.Is(err, tunnelcert.ErrIssuerUnavailable) || errors.Is(err, tunnelcert.ErrIssuerRateLimited) || errors.Is(err, tunnelcert.ErrCAAUnavailable) || errors.Is(err, tunnelcert.ErrCAABlocked) || errors.Is(err, tunnelcert.ErrDNSChallengeUnavailable) || errors.Is(err, tunnelcert.ErrDNSChallengePending) || errors.Is(err, tunnelcert.ErrCertificateNotReady) || errors.Is(err, tunnelcert.ErrDistributionUnavailable) || errors.Is(err, tunnelcert.ErrIssuanceLocked)
}

func platformFailureCode(err error) string {
	switch {
	case errors.Is(err, tunnelcert.ErrIssuerRateLimited):
		return "issuer_rate_limited"
	case errors.Is(err, tunnelcert.ErrIssuerUnavailable):
		return "issuer_unavailable"
	case errors.Is(err, tunnelcert.ErrCAABlocked):
		return "caa_blocked"
	case errors.Is(err, tunnelcert.ErrCAAUnavailable):
		return "caa_unavailable"
	case errors.Is(err, tunnelcert.ErrDNSChallengePending):
		return "dns_challenge_pending"
	case errors.Is(err, tunnelcert.ErrDNSChallengeUnavailable):
		return "dns_challenge_unavailable"
	case errors.Is(err, tunnelcert.ErrCertificateNotReady):
		return "edge_not_ready"
	case errors.Is(err, tunnelcert.ErrIssuanceLocked):
		return "issuance_locked"
	default:
		return "distribution_unavailable"
	}
}

func platformRetryError(code string) error {
	switch code {
	case "issuer_rate_limited":
		return tunnelcert.ErrIssuerRateLimited
	case "issuer_unavailable":
		return tunnelcert.ErrIssuerUnavailable
	case "caa_blocked":
		return tunnelcert.ErrCAABlocked
	case "caa_unavailable":
		return tunnelcert.ErrCAAUnavailable
	case "dns_challenge_pending":
		return tunnelcert.ErrDNSChallengePending
	case "dns_challenge_unavailable":
		return tunnelcert.ErrDNSChallengeUnavailable
	case "edge_not_ready":
		return tunnelcert.ErrCertificateNotReady
	case "issuance_locked":
		return tunnelcert.ErrIssuanceLocked
	case "distribution_unavailable":
		return tunnelcert.ErrDistributionUnavailable
	default:
		return ErrPlatformCertificateUnavailable
	}
}

func platformRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 10 {
		attempt = 10
	}
	delay := time.Minute
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

// Revoke performs durable local/edge/authority revocation through the same
// coordinator path as user certificates, then terminally disables the target
// so a background renewal cannot resurrect it.
func (w *PlatformCertificateWorker) Revoke(ctx context.Context, targetID, reason string) error {
	if w == nil || w.store == nil || w.coordinator == nil || !validPlatformTargetID(targetID) {
		return ErrInvalidInput
	}
	now := w.now().UTC()
	if reason == "" {
		reason = "platform_certificate_revoked"
	}
	if _, err := w.coordinator.Revoke(ctx, targetID, reason); err != nil {
		_ = w.store.MarkPlatformTargetRevoked(ctx, targetID, reason, now)
		return err
	}
	return w.store.MarkPlatformTargetRevoked(ctx, targetID, reason, now)
}

func validPlatformTargetID(id string) bool {
	return id == tunnelcert.PlatformPreviewTargetID || id == tunnelcert.PlatformTunnelTargetID
}

func (w *PlatformCertificateWorker) Worker(interval time.Duration, limit int) workers.Worker {
	return func(ctx context.Context) error {
		if w == nil || w.store == nil || w.coordinator == nil || w.edgeTargets == nil || interval <= 0 || limit < 1 || limit > 500 {
			return ErrInvalidInput
		}
		if ctx == nil {
			ctx = context.Background()
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := w.coordinator.ReconcileRevocations(ctx, limit); err != nil && !errors.Is(err, context.Canceled) {
				w.setLastError(err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := w.coordinator.ReconcileDistributionCleanup(ctx, limit); err != nil && !errors.Is(err, context.Canceled) {
				w.setLastError(err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := w.Reconcile(ctx, limit); err != nil && !errors.Is(err, context.Canceled) {
				w.setLastError(err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

var _ func(*PlatformCertificateWorker, time.Duration, int) workers.Worker = (*PlatformCertificateWorker).Worker
