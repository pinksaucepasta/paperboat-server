package tunnelv1

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
)

// CertificateWorker is the durable boundary between verified tunnel_domains
// and the server-owned certificate coordinator.  It is intentionally created
// only when an issuer, envelope key source, and authenticated edge distributor
// are supplied by deployment composition.
type CertificateWorker struct {
	db          *db.DB
	coordinator *tunnelcert.Coordinator
	renewBefore time.Duration
	issuerName  string
	now         func() time.Time
	mu          sync.Mutex
	lastErr     error
	observe     func(context.Context, CertificateTelemetryEvent)
}

type CertificateTelemetryEvent struct {
	DomainID      string
	CertificateID string
	Operation     string
	Outcome       string
	NextRetryAt   time.Time
}

func (w *CertificateWorker) SetTelemetryObserver(observer func(context.Context, CertificateTelemetryEvent)) error {
	if w == nil || observer == nil {
		return ErrInvalidInput
	}
	w.observe = observer
	return nil
}

// LastError exposes the most recent retryable authority/cleanup failure to
// health and diagnostics without making the worker itself exit and abandon
// unrelated certificate domains.
func (w *CertificateWorker) LastError() error {
	if w == nil {
		return ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func NewCertificateWorker(database *db.DB, coordinator *tunnelcert.Coordinator, renewBefore time.Duration, now func() time.Time, issuerName ...string) (*CertificateWorker, error) {
	if database == nil || coordinator == nil {
		return nil, fmt.Errorf("%w: certificate database and coordinator are required", ErrInvalidInput)
	}
	if renewBefore <= 0 || renewBefore >= 365*24*time.Hour {
		renewBefore = 30 * 24 * time.Hour
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	configuredIssuer := "letsencrypt"
	if len(issuerName) > 0 && issuerName[0] != "" {
		configuredIssuer = issuerName[0]
	}
	return &CertificateWorker{db: database, coordinator: coordinator, renewBefore: renewBefore, issuerName: configuredIssuer, now: now}, nil
}

func (w *CertificateWorker) Reconcile(ctx context.Context, limit int) (int, error) {
	if w == nil || w.db == nil || w.coordinator == nil || limit < 1 || limit > 500 {
		return 0, ErrInvalidInput
	}
	now := w.now().UTC()
	interval := pgtype.Interval{Microseconds: renewBeforeMicros(w.renewBefore)}
	rows, err := w.db.Queries().ListDueTunnelCertificateDomainsV1(ctx, dbsqlc.ListDueTunnelCertificateDomainsV1Params{Now: now, RenewBefore: interval, RowLimit: int32(limit)})
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		edges, err := w.db.Queries().ListReadyTunnelCertificateEdgesV1(ctx, row.ID)
		if err != nil {
			return changed, err
		}
		domain, err := certificateDomainWithConfig(row, edges, now, w.renewBefore, w.issuerName)
		if err != nil {
			return changed, err
		}
		result, ensureErr := w.coordinator.Ensure(ctx, domain)
		if ensureErr != nil {
			failureCode := certificateFailureCode(ensureErr)
			if failureCode == "" {
				w.emitTelemetry(ctx, row.ID, "", certificateOperation(row.CertificateReference.Valid), "failed", now.Add(time.Minute))
				return changed, ensureErr
			}
			_, markErr := w.db.Queries().MarkTunnelDomainCertificateFailureV1(ctx, dbsqlc.MarkTunnelDomainCertificateFailureV1Params{Now: sql.NullTime{Time: now, Valid: true}, FailureCode: sql.NullString{String: failureCode, Valid: true}, DomainID: row.ID, ExpectedGeneration: row.Generation})
			if markErr != nil && !errors.Is(markErr, pgx.ErrNoRows) {
				return changed, markErr
			}
			changed++
			w.emitTelemetry(ctx, row.ID, "", certificateOperation(row.CertificateReference.Valid), "failed", now.Add(time.Minute))
			continue
		}
		certificate, found, currentErr := w.coordinator.CurrentCertificate(ctx, row.ID)
		if currentErr != nil {
			return changed, currentErr
		}
		if !found || certificate.State != tunnelcert.StateActive || certificate.CertificateReference != result.Certificate.Reference || certificate.CertificateGeneration == 0 {
			return changed, tunnelcert.ErrGenerationConflict
		}
		// A successful Ensure may only have reconciled an already-active
		// certificate to a late/replaced edge. That path must not bump the
		// domain generation or complete a domain.create operation again. The
		// durable domain projection is committed only for a newly issued
		// certificate; late-edge work is already durable in the distributor.
		if result.Issued {
			err = w.coordinator.CommitDomainCertificateReady(ctx, row.AccountID, row.ID, uint64(row.Generation), certificate, now)
			if errors.Is(err, pgx.ErrNoRows) {
				return changed, ErrGenerationConflict
			}
			if err != nil {
				return changed, err
			}
		}
		w.emitTelemetry(ctx, row.ID, certificate.ID, certificateOperation(row.CertificateReference.Valid), "success", time.Time{})
		changed++
	}
	remaining := limit - changed
	if remaining <= 0 {
		return changed, nil
	}
	previewRows, err := w.db.Queries().ListDuePreviewCertificateDomainsV1(ctx, dbsqlc.ListDuePreviewCertificateDomainsV1Params{Now: now, RenewBefore: interval, RowLimit: int32(remaining)})
	if err != nil {
		return changed, err
	}
	for _, row := range previewRows {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		lease, err := w.db.Queries().GetPreviewLeaseForReconciliationV1(ctx, row.PreviewID)
		if err != nil {
			return changed, err
		}
		edges, err := w.db.Queries().ListReadyPreviewCertificateEdgesV1(ctx, dbsqlc.ListReadyPreviewCertificateEdgesV1Params{DomainID: row.ID, Now: now})
		if err != nil {
			return changed, err
		}
		domain, err := previewCertificateDomainWithConfig(row, lease, edges, now, w.renewBefore, w.issuerName)
		if err != nil {
			return changed, err
		}
		if rebound, err := w.coordinator.RebindPreviewCertificate(ctx, domain, now); err != nil {
			return changed, err
		} else if rebound {
			w.emitTelemetry(ctx, row.ID, "", "replace", "success", time.Time{})
			changed++
			continue
		}
		result, ensureErr := w.coordinator.Ensure(ctx, domain)
		if ensureErr != nil {
			w.emitTelemetry(ctx, row.ID, "", certificateOperation(row.CertificateReference.Valid), "failed", now.Add(time.Minute))
			return changed, ensureErr
		}
		certificate, found, currentErr := w.coordinator.CurrentCertificateForDomain(ctx, domain)
		if currentErr != nil {
			return changed, currentErr
		}
		if !found || certificate.State != tunnelcert.StateActive || certificate.CertificateReference != result.Certificate.Reference || certificate.CertificateGeneration == 0 || certificate.Target().Key() != domain.Target().Key() {
			return changed, tunnelcert.ErrGenerationConflict
		}
		if result.Issued {
			err = w.coordinator.CommitPreviewDomainCertificateReady(ctx, row.AccountID, row.ID, row.PreviewID, uint64(row.PreviewGeneration), uint64(row.Generation), certificate, now)
			if errors.Is(err, pgx.ErrNoRows) {
				return changed, tunnelcert.ErrGenerationConflict
			}
			if err != nil {
				return changed, err
			}
		}
		w.emitTelemetry(ctx, row.ID, certificate.ID, certificateOperation(row.CertificateReference.Valid), "success", time.Time{})
		changed++
	}
	return changed, nil
}

func certificateOperation(hasCurrent bool) string {
	if hasCurrent {
		return "renew"
	}
	return "issue"
}

func (w *CertificateWorker) emitTelemetry(ctx context.Context, domainID, certificateID, operation, outcome string, nextRetryAt time.Time) {
	if w != nil && w.observe != nil {
		w.observe(ctx, CertificateTelemetryEvent{DomainID: domainID, CertificateID: certificateID, Operation: operation, Outcome: outcome, NextRetryAt: nextRetryAt})
	}
}

// RequestExactLeaf handles one authenticated first-SNI request. The caller
// supplies only the already authenticated edge process identity and exact
// hostname; the worker resolves the verified wildcard policy, current edge
// assignment, and parent certificate from durable state before invoking the
// coordinator. Exact leaves use the hostname-aware store path and therefore
// never mutate the wildcard parent's projection or generation.
func (w *CertificateWorker) RequestExactLeaf(ctx context.Context, nodeID, processEpoch, hostname string) error {
	if w == nil || w.db == nil || w.coordinator == nil || nodeID == "" || processEpoch == "" {
		return ErrInvalidInput
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	host, wildcard, err := tunnelcert.NormalizeHostname(hostname)
	if err != nil || wildcard || host != hostname {
		return fmt.Errorf("%w: exact hostname is not canonical", tunnelcert.ErrInvalid)
	}
	rows, err := w.db.Queries().ListOnDemandWildcardDomainsForEdgeV1(ctx, dbsqlc.ListOnDemandWildcardDomainsForEdgeV1Params{EdgeNodeID: nodeID, EdgeProcessEpoch: processEpoch, RowLimit: 256})
	if err != nil {
		return err
	}
	now := w.now().UTC()
	for _, row := range rows {
		parent, parentWildcard, normalizeErr := tunnelcert.NormalizeHostname(row.Hostname)
		if normalizeErr != nil || !parentWildcard || parent != row.Hostname || !tunnelcert.OneLabelUnderWildcard(host, parent) {
			continue
		}
		edges, edgeErr := w.db.Queries().ListReadyTunnelCertificateEdgesV1(ctx, row.ID)
		if edgeErr != nil {
			return edgeErr
		}
		var target dbsqlc.ListReadyTunnelCertificateEdgesV1Row
		foundTarget := false
		for _, edge := range edges {
			if edge.EdgeNodeID == nodeID && edge.EdgeProcessEpoch == processEpoch {
				target = edge
				foundTarget = true
				break
			}
		}
		if !foundTarget {
			continue
		}
		domain, domainErr := certificateDomainWithConfig(row, []dbsqlc.ListReadyTunnelCertificateEdgesV1Row{target}, now, w.renewBefore, w.issuerName)
		if domainErr != nil {
			return domainErr
		}
		domain.LeafHostname = host
		domain.AllowOnDemandFallback = false
		active, activeErr := w.db.Queries().GetActiveTunnelCertificateByHostnameV1(ctx, dbsqlc.GetActiveTunnelCertificateByHostnameV1Params{DomainID: sql.NullString{String: row.ID, Valid: true}, Hostname: host})
		if errors.Is(activeErr, pgx.ErrNoRows) {
			domain.RenewalDue = true
		} else if activeErr != nil {
			return activeErr
		} else {
			domain.RenewalDue = !active.RenewalAt.After(now) || !active.ExpiresAt.After(now)
		}
		if _, ensureErr := w.coordinator.Ensure(ctx, domain); ensureErr != nil {
			return ensureErr
		}
		return nil
	}
	previewRows, err := w.db.Queries().ListOnDemandPreviewDomainsForEdgeV1(ctx, dbsqlc.ListOnDemandPreviewDomainsForEdgeV1Params{Now: now, EdgeNodeID: nodeID, EdgeProcessEpoch: processEpoch, RowLimit: 256})
	if err != nil {
		return err
	}
	for _, row := range previewRows {
		parent, parentWildcard, normalizeErr := tunnelcert.NormalizeHostname(row.Hostname)
		if normalizeErr != nil || !parentWildcard || parent != row.Hostname || !tunnelcert.OneLabelUnderWildcard(host, parent) {
			continue
		}
		lease, leaseErr := w.db.Queries().GetPreviewLeaseForReconciliationV1(ctx, row.PreviewID)
		if leaseErr != nil {
			return leaseErr
		}
		edge, edgeErr := w.db.Queries().ListReadyPreviewCertificateEdgesV1(ctx, dbsqlc.ListReadyPreviewCertificateEdgesV1Params{DomainID: row.ID, Now: now})
		if edgeErr != nil {
			return edgeErr
		}
		var target dbsqlc.ListReadyPreviewCertificateEdgesV1Row
		foundTarget := false
		for _, candidate := range edge {
			if candidate.EdgeNodeID == nodeID && candidate.EdgeProcessEpoch == processEpoch {
				target = candidate
				foundTarget = true
				break
			}
		}
		if !foundTarget {
			continue
		}
		domain, domainErr := previewCertificateDomainWithConfig(row, lease, []dbsqlc.ListReadyPreviewCertificateEdgesV1Row{target}, now, w.renewBefore, w.issuerName)
		if domainErr != nil {
			return domainErr
		}
		domain.LeafHostname = host
		domain.AllowOnDemandFallback = false
		if rebound, rebindErr := w.coordinator.RebindPreviewCertificate(ctx, domain, now); rebindErr != nil {
			return rebindErr
		} else if rebound {
			return nil
		}
		active, activeFound, activeErr := w.coordinator.CurrentCertificateForDomain(ctx, domain)
		if activeErr != nil {
			return activeErr
		}
		domain.RenewalDue = !activeFound || !active.RenewalAt.After(now) || !active.ExpiresAt.After(now)
		if _, ensureErr := w.coordinator.Ensure(ctx, domain); ensureErr != nil {
			return ensureErr
		}
		return nil
	}
	return tunnelcert.ErrCertificateNotReady
}

func (w *CertificateWorker) Worker(interval time.Duration, limit int) workers.Worker {
	return func(ctx context.Context) error {
		if interval <= 0 {
			return ErrInvalidInput
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, revokeErr := w.coordinator.ReconcileRevocations(ctx, limit); revokeErr != nil && !errors.Is(revokeErr, context.Canceled) {
				// Authority outages are durable retry states, not reasons to
				// stop renewal for every other domain. Keep the last error for
				// diagnostics and continue at the next bounded tick.
				w.mu.Lock()
				w.lastErr = revokeErr
				w.mu.Unlock()
			}
			// Cleanup is deliberately independent from issuance. An unavailable
			// old edge must not stop the worker; its durable row remains eligible
			// and is retried on the next tick.
			if _, cleanupErr := w.coordinator.ReconcileDistributionCleanup(ctx, limit); cleanupErr != nil && errors.Is(cleanupErr, context.Canceled) {
				return cleanupErr
			}
			if _, err := w.Reconcile(ctx, limit); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func certificateDomainWithConfig(row dbsqlc.TunnelDomain, edges []dbsqlc.ListReadyTunnelCertificateEdgesV1Row, now time.Time, renewBefore time.Duration, issuerName string) (tunnelcert.Domain, error) {
	strategy, err := certificateStrategy(row.CertificateStrategy)
	if err != nil {
		return tunnelcert.Domain{}, err
	}
	// An on-demand policy row represents a verified wildcard binding. The
	// background worker issues that parent wildcard certificate first; exact
	// one-label leaves are created later by the SNI-bound on-demand path. Keep
	// the strategy on the domain so distribution can tell the edge to suppress
	// silent wildcard fallback while the parent policy is active.
	onDemandPolicy := strategy == tunnelcert.StrategyOnDemandLeaf
	targets := make([]tunnelcert.EdgeTarget, 0, len(edges))
	for _, edge := range edges {
		targets = append(targets, tunnelcert.EdgeTarget{NodeID: edge.EdgeNodeID, ProcessEpoch: edge.EdgeProcessEpoch, Generation: uint64(edge.AssignmentGeneration)})
	}
	if renewBefore <= 0 || renewBefore >= 365*24*time.Hour {
		renewBefore = 30 * 24 * time.Hour
	}
	if issuerName == "" {
		issuerName = "letsencrypt"
	}
	return tunnelcert.Domain{ID: row.ID, AccountID: row.AccountID, TunnelID: row.TunnelID, TargetKind: tunnelcert.TargetDurableRoute, RouteID: row.RouteID, Hostname: row.Hostname, ChallengeReference: row.OwnershipChallengeReference, Generation: uint64(row.Generation), Strategy: strategy, OwnershipState: row.OwnershipState, CAAState: row.CaaState, CertificateReference: row.CertificateReference.String, CertificateGeneration: 0, RenewalDue: row.CertificateState != "ready" || !row.CertificateExpiresAt.Valid || !row.CertificateExpiresAt.Time.After(now.Add(renewBefore)), AllowOnDemandFallback: onDemandPolicy, EdgeTargets: targets, Issuer: issuerName}, nil
}

func previewCertificateDomainWithConfig(row dbsqlc.PreviewDomain, lease dbsqlc.PreviewLease, edges []dbsqlc.ListReadyPreviewCertificateEdgesV1Row, now time.Time, renewBefore time.Duration, issuerName string) (tunnelcert.Domain, error) {
	strategy, err := certificateStrategy(row.CertificateStrategy)
	if err != nil {
		return tunnelcert.Domain{}, err
	}
	if row.PreviewGeneration <= 0 || row.Generation <= 0 || lease.ID != row.PreviewID || lease.AccountID != row.AccountID || lease.Generation != row.PreviewGeneration || lease.TerminalState != "active" {
		return tunnelcert.Domain{}, fmt.Errorf("%w: preview lease generation is stale", tunnelcert.ErrGenerationConflict)
	}
	expiresAt := lease.LeaseDeadline
	if lease.UserDeadline.Valid && lease.UserDeadline.Time.Before(expiresAt) {
		expiresAt = lease.UserDeadline.Time
	}
	if !expiresAt.After(now) {
		return tunnelcert.Domain{}, tunnelcert.ErrCertificateRevoked
	}
	targets := make([]tunnelcert.EdgeTarget, 0, len(edges))
	for _, edge := range edges {
		targets = append(targets, tunnelcert.EdgeTarget{NodeID: edge.EdgeNodeID, ProcessEpoch: edge.EdgeProcessEpoch, Generation: uint64(edge.AttachmentGeneration)})
	}
	if renewBefore <= 0 || renewBefore >= 365*24*time.Hour {
		renewBefore = 30 * 24 * time.Hour
	}
	if issuerName == "" {
		issuerName = "letsencrypt"
	}
	return tunnelcert.Domain{ID: row.ID, AccountID: row.AccountID, TargetKind: tunnelcert.TargetPreviewLease, PreviewID: row.PreviewID, PreviewGeneration: uint64(row.PreviewGeneration), PreviewState: "active", PreviewExpiresAt: expiresAt.UTC(), Hostname: row.Hostname, ChallengeReference: row.OwnershipChallengeReference, Generation: uint64(row.Generation), Strategy: strategy, OwnershipState: row.OwnershipState, CAAState: row.CaaState, CertificateReference: row.CertificateReference.String, RenewalDue: row.CertificateState != "ready" || !row.CertificateExpiresAt.Valid || !row.CertificateExpiresAt.Time.After(now.Add(renewBefore)), AllowOnDemandFallback: strategy == tunnelcert.StrategyOnDemandLeaf, EdgeTargets: targets, Issuer: issuerName}, nil
}

func certificateStrategy(value string) (tunnelcert.Strategy, error) {
	switch value {
	case "managed", string(tunnelcert.StrategyDelegatedDNS01):
		return tunnelcert.StrategyDelegatedDNS01, nil
	case "provided_reference":
		return tunnelcert.StrategyProvided, nil
	case "on_demand_leaf":
		return tunnelcert.StrategyOnDemandLeaf, nil
	default:
		return "", fmt.Errorf("%w: unsupported certificate strategy", ErrInvalidInput)
	}
}

func certificateFailureCode(err error) string {
	switch {
	case errors.Is(err, tunnelcert.ErrCAAUnavailable):
		return "caa_unavailable"
	case errors.Is(err, tunnelcert.ErrCAABlocked):
		return "caa_blocked"
	case errors.Is(err, tunnelcert.ErrDNSChallengePending):
		return "dns_challenge_pending"
	case errors.Is(err, tunnelcert.ErrDNSChallengeUnavailable):
		return "dns_challenge_unavailable"
	case errors.Is(err, tunnelcert.ErrIssuerRateLimited):
		return "issuer_rate_limited"
	case errors.Is(err, tunnelcert.ErrIssuerUnavailable):
		return "issuer_unavailable"
	case errors.Is(err, tunnelcert.ErrCertificateInvalid):
		return "certificate_invalid"
	case errors.Is(err, tunnelcert.ErrCertificateNotReady):
		return "edge_certificate_not_ready"
	case errors.Is(err, tunnelcert.ErrDistributionUnavailable):
		return "edge_certificate_distribution_unavailable"
	default:
		return ""
	}
}

func renewBeforeMicros(value time.Duration) int64 {
	return value.Microseconds()
}
