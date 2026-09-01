package previewdomain

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
	"github.com/pinksaucepasta/paperboat-server/internal/workers"
	"golang.org/x/net/publicsuffix"
)

const (
	previewDNSMinimumRetry          = 30 * time.Second
	previewDNSMaximumRetry          = 30 * time.Minute
	previewDNSDefaultTTL            = 5 * time.Minute
	previewDNSMaximumTTL            = 24 * time.Hour
	previewDNSTransientFailureGrace = 3
	previewDNSObservationTimeout    = 5 * time.Second
	previewDNSMaximumBatch          = 500
)

// DNSReconciliationRepository is the narrow persistence boundary used by the
// worker. ListDue must return only non-deleted domains whose preview lease is
// active and whose preview generation is current. ApplyDNSObservation must
// recheck those conditions while holding the lease row lock before its CAS.
// This prevents a delayed DNS response from updating a renewed or stopped
// preview.
type DNSReconciliationRepository interface {
	ListDue(context.Context, time.Time, int) ([]dbsqlc.PreviewDomain, error)
	ApplyDNSObservationForReconciliation(context.Context, DNSReconciliationObservation) (dbsqlc.PreviewDomain, error)
}

// DNSQuarantineReleaser is optional. SQLRepository implements it so normal
// reconciliation also releases expired seven-day hostname quarantines. It is
// kept separate to make the worker easy to exercise with deterministic fakes.
type DNSQuarantineReleaser interface {
	ReleaseExpiredPreviewDomainQuarantines(context.Context, time.Time) (int64, error)
}

// DNSReconciliationObservation contains only the state needed for the
// generation-fenced observation CAS. It deliberately carries no origin or
// credential material.
type DNSReconciliationObservation struct {
	DomainID           string
	AccountID          string
	PreviewID          string
	PreviewGeneration  int64
	ExpectedGeneration int64
	ObservedRecords    []byte
	OwnershipState     string
	ConflictState      string
	NextCheckAt        time.Time
	TTLSeconds         int32
	Verified           bool
	Now                time.Time
}

// DNSReconcileEvent is a safe structured log projection. It contains stable
// identifiers and typed state only, never hostnames, origins, DNS answers, or
// credentials.
type DNSReconcileEvent struct {
	DomainID       string
	PreviewID      string
	Code           string
	OwnershipState string
	ConflictState  string
	Verified       bool
	NextCheckAt    time.Time
}

type DNSReconcileEventSink interface {
	EmitDNSReconcileEvent(context.Context, DNSReconcileEvent)
}

type DNSReconcileEventSinkFunc func(context.Context, DNSReconcileEvent)

func (f DNSReconcileEventSinkFunc) EmitDNSReconcileEvent(ctx context.Context, event DNSReconcileEvent) {
	if f != nil {
		f(ctx, event)
	}
}

// RetryJitter returns a bounded retry delay. The default is deterministic per
// domain and attempt, which spreads domains without making tests or recovery
// scheduling dependent on process-global randomness.
type RetryJitter func(domainID string, attempt int32, base time.Duration) time.Duration

type ReconcilerConfig struct {
	Now                   func() time.Time
	ObservationTimeout    time.Duration
	MinimumRetry          time.Duration
	MaximumRetry          time.Duration
	DefaultTTL            time.Duration
	MaximumTTL            time.Duration
	TransientFailureGrace int32
	Jitter                RetryJitter
	EventSink             DNSReconcileEventSink
}

func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		ObservationTimeout:    previewDNSObservationTimeout,
		MinimumRetry:          previewDNSMinimumRetry,
		MaximumRetry:          previewDNSMaximumRetry,
		DefaultTTL:            previewDNSDefaultTTL,
		MaximumTTL:            previewDNSMaximumTTL,
		TransientFailureGrace: previewDNSTransientFailureGrace,
		Jitter:                deterministicDNSJitter,
	}
}

type Reconciler struct {
	repository DNSReconciliationRepository
	resolver   tunnelv1.DomainDNSResolver
	now        func() time.Time
	config     ReconcilerConfig
}

// SetEventSink installs the process-owned telemetry adapter before Worker is
// started. Runtime replacement is intentionally unsupported so one reconcile
// pass cannot split its observations across sinks.
func (r *Reconciler) SetEventSink(sink DNSReconcileEventSink) error {
	if r == nil || sink == nil {
		return ErrInvalidInput
	}
	r.config.EventSink = sink
	return nil
}

func NewReconciler(repository DNSReconciliationRepository, resolver tunnelv1.DomainDNSResolver, config ReconcilerConfig) (*Reconciler, error) {
	if repository == nil || resolver == nil {
		return nil, fmt.Errorf("%w: DNS repository and resolver are required", ErrInvalidInput)
	}
	defaults := DefaultReconcilerConfig()
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.ObservationTimeout == 0 {
		config.ObservationTimeout = defaults.ObservationTimeout
	}
	if config.MinimumRetry == 0 {
		config.MinimumRetry = defaults.MinimumRetry
	}
	if config.MaximumRetry == 0 {
		config.MaximumRetry = defaults.MaximumRetry
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = defaults.DefaultTTL
	}
	if config.MaximumTTL == 0 {
		config.MaximumTTL = defaults.MaximumTTL
	}
	if config.TransientFailureGrace == 0 {
		config.TransientFailureGrace = defaults.TransientFailureGrace
	}
	if config.Jitter == nil {
		config.Jitter = defaults.Jitter
	}
	if config.ObservationTimeout < 0 || config.MinimumRetry <= 0 || config.MaximumRetry < config.MinimumRetry ||
		config.DefaultTTL <= 0 || config.MaximumTTL < config.DefaultTTL || config.MaximumTTL < config.MinimumRetry || config.TransientFailureGrace < 1 {
		return nil, fmt.Errorf("%w: invalid DNS reconciliation policy", ErrInvalidInput)
	}
	return &Reconciler{repository: repository, resolver: resolver, now: config.Now, config: config}, nil
}

// NewDNSReconciler is an explicit alias for callers that want to distinguish
// this worker from the preview-domain API service.
func NewDNSReconciler(repository DNSReconciliationRepository, resolver tunnelv1.DomainDNSResolver, config ReconcilerConfig) (*Reconciler, error) {
	return NewReconciler(repository, resolver, config)
}

// Reconcile performs at most limit DNS observations. A stale row caused by a
// renewal, stop, or owner-loss race is skipped because the durable lease/CAS
// fence has already made it harmless. Database failures remain fatal so the
// supervisor retries rather than silently dropping work.
func (r *Reconciler) Reconcile(ctx context.Context, limit int) (int, error) {
	if r == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	if limit < 1 || limit > previewDNSMaximumBatch {
		return 0, fmt.Errorf("%w: DNS reconciliation batch is invalid", ErrInvalidInput)
	}
	now := r.now().UTC()
	if now.IsZero() {
		return 0, ErrInvalidInput
	}
	if releaser, ok := r.repository.(DNSQuarantineReleaser); ok {
		if _, err := releaser.ReleaseExpiredPreviewDomainQuarantines(ctx, now); err != nil {
			return 0, err
		}
	}
	rows, err := r.repository.ListDue(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		if err := r.reconcileOne(ctx, row, now); err != nil {
			if errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrLeaseNotActive) || errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (r *Reconciler) reconcileOne(ctx context.Context, row dbsqlc.PreviewDomain, now time.Time) error {
	if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.AccountID) == "" || strings.TrimSpace(row.PreviewID) == "" || row.PreviewGeneration < 1 || row.Generation < 1 {
		return ErrInvalidInput
	}
	recordType := reconciliationDNSRecordType(row)
	observeCtx := ctx
	var cancel context.CancelFunc
	if r.config.ObservationTimeout > 0 {
		observeCtx, cancel = context.WithTimeout(ctx, r.config.ObservationTimeout)
		defer cancel()
	}
	observation, lookupErr := r.resolver.Observe(observeCtx, row.Hostname, recordType, row.DnsTarget, row.OwnershipChallengeReference)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	code, verified := classifyDNSObservation(row, observation, recordType, lookupErr)
	state, conflict := dnsObservationState(row, code, r.config.TransientFailureGrace)
	observed := marshalObservedRecords(observation.Records)
	if state == "verified" && !verified {
		// A transient resolver failure inside the grace window must preserve the
		// last authoritative answer, not replace it with an empty/error payload.
		observed = append([]byte(nil), row.ObservedRecords...)
	}
	if observed == nil {
		observed = []byte("[]")
	}
	delay := r.retryDelay(row.ID, row.VerificationAttempts, observation.TTL, verified)
	next := now.Add(delay)
	updated, err := r.repository.ApplyDNSObservationForReconciliation(ctx, DNSReconciliationObservation{
		DomainID: row.ID, AccountID: row.AccountID, PreviewID: row.PreviewID,
		PreviewGeneration: row.PreviewGeneration, ExpectedGeneration: row.Generation,
		ObservedRecords: observed, OwnershipState: state, ConflictState: conflict,
		NextCheckAt: next, TTLSeconds: int32(r.boundTTL(observation.TTL) / time.Second),
		Verified: verified, Now: now,
	})
	if err != nil {
		return err
	}
	r.emit(ctx, DNSReconcileEvent{DomainID: updated.ID, PreviewID: updated.PreviewID, Code: code,
		OwnershipState: updated.OwnershipState, ConflictState: updated.ConflictState,
		Verified: verified, NextCheckAt: updated.DnsNextCheckAt})
	return nil
}

func classifyDNSObservation(row dbsqlc.PreviewDomain, observation tunnelv1.DNSObservation, recordType string, lookupErr error) (string, bool) {
	if lookupErr == nil && observation.FailureCode == "" && dnsObservationMatches(row, observation, recordType) {
		return "dns_verified", true
	}
	if observation.FailureCode != "" {
		return normalizeDNSFailureCode(observation.FailureCode), false
	}
	if lookupErr != nil {
		return classifyDNSLookupError(lookupErr), false
	}
	return "dns_wrong_record", false
}

func normalizeDNSFailureCode(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "wrong_record", "dns_wrong_record":
		return "dns_wrong_record"
	case "dns_not_found", "not_found":
		return "dns_not_found"
	case "dns_unavailable", "timeout", "temporary":
		return "dns_unavailable"
	default:
		return "dns_error"
	}
}

func classifyDNSLookupError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "dns_not_found"
		}
		if dnsErr.IsTimeout || dnsErr.IsTemporary {
			return "dns_unavailable"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "dns_unavailable"
	}
	return "dns_error"
}

func dnsObservationState(row dbsqlc.PreviewDomain, code string, grace int32) (string, string) {
	if code == "dns_verified" {
		return "verified", "clear"
	}
	if code == "dns_wrong_record" {
		return "failed", "conflicted"
	}
	if code == "dns_not_found" {
		return "failed", "clear"
	}
	if row.OwnershipState == "verified" && row.VerificationAttempts+1 < grace {
		return "verified", "clear"
	}
	if row.OwnershipState == "failed" || row.OwnershipState == "verified" {
		return "failed", "clear"
	}
	return "pending", "clear"
}

func dnsObservationMatches(row dbsqlc.PreviewDomain, observation tunnelv1.DNSObservation, recordType string) bool {
	if len(observation.Records) == 0 {
		return false
	}
	if strings.ToUpper(recordType) != "CNAME" {
		// NetDomainDNSResolver already compared the authoritative A/AAAA answer
		// set with the target for ANAME/ALIAS/apex policies.
		return true
	}
	want := "CNAME " + normalizeObservedDNSValue(row.DnsTarget)
	for _, record := range observation.Records {
		if strings.EqualFold(strings.TrimSpace(record), want) {
			return true
		}
	}
	return false
}

// reconciliationDNSRecordType mirrors tunnelv1's provider-aware policy. The
// preview API's instruction type is intentionally retained for display, while
// an apex Cloudflare record is observed as flattened addresses (ALIAS) just
// like a durable tunnel domain. Wildcard and non-apex records remain CNAME.
func reconciliationDNSRecordType(row dbsqlc.PreviewDomain) string {
	recordType := strings.ToUpper(DNSRecordType(row.Hostname, row.DnsProvider))
	base := strings.TrimPrefix(row.Hostname, "*.")
	if !strings.HasPrefix(row.Hostname, "*.") {
		if registrable, err := publicsuffix.EffectiveTLDPlusOne(base); err == nil && registrable == base && strings.EqualFold(row.DnsProvider, "cloudflare") {
			return "ALIAS"
		}
	}
	return recordType
}

func normalizeObservedDNSValue(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func marshalObservedRecords(records []string) []byte {
	if len(records) == 0 {
		return []byte("[]")
	}
	copyRecords := append([]string(nil), records...)
	for i := range copyRecords {
		copyRecords[i] = strings.TrimSpace(copyRecords[i])
	}
	// Resolver output is normally sorted. Sorting again makes injected or
	// alternate resolver implementations produce stable persisted JSON.
	sortStrings(copyRecords)
	encoded, err := json.Marshal(copyRecords)
	if err != nil {
		return []byte("[]")
	}
	return encoded
}

func (r *Reconciler) boundTTL(value time.Duration) time.Duration {
	if value <= 0 {
		value = r.config.DefaultTTL
	}
	if value < r.config.MinimumRetry {
		value = r.config.MinimumRetry
	}
	if value > r.config.MaximumTTL {
		value = r.config.MaximumTTL
	}
	return value
}

func (r *Reconciler) retryDelay(domainID string, attempt int32, observedTTL time.Duration, verified bool) time.Duration {
	base := r.config.MinimumRetry
	if verified {
		base = r.boundTTL(observedTTL)
	} else {
		for i := int32(0); i < attempt && base < r.config.MaximumRetry; i++ {
			if base > r.config.MaximumRetry/2 {
				base = r.config.MaximumRetry
				break
			}
			base *= 2
		}
		if base > r.config.MaximumRetry {
			base = r.config.MaximumRetry
		}
	}
	delay := r.config.Jitter(domainID, attempt, base)
	if delay < r.config.MinimumRetry {
		return r.config.MinimumRetry
	}
	maximum := r.config.MaximumRetry
	if maximum > r.config.MaximumTTL {
		maximum = r.config.MaximumTTL
	}
	if verified {
		maximum = r.config.MaximumTTL
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func deterministicDNSJitter(domainID string, attempt int32, base time.Duration) time.Duration {
	if base <= time.Second {
		return base
	}
	digest := sha256.Sum256([]byte(domainID + "\x00" + strconv.FormatInt(int64(attempt), 10)))
	span := base / 10
	if span < time.Second {
		span = time.Second
	}
	// Offset is in [-10%, +10%] (subject to duration rounding).
	width := uint64(span*2 + 1)
	offset := time.Duration(uint64(digest[0])<<8|uint64(digest[1])) % time.Duration(width)
	offset -= span
	return base + offset
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		value := values[i]
		j := i - 1
		for ; j >= 0 && values[j] > value; j-- {
			values[j+1] = values[j]
		}
		values[j+1] = value
	}
}

func (r *Reconciler) emit(ctx context.Context, event DNSReconcileEvent) {
	if r.config.EventSink != nil {
		r.config.EventSink.EmitDNSReconcileEvent(ctx, event)
	}
}

// Worker runs an initial pass immediately and then polls at interval. It
// returns transient/database failures to the supervisor, while cancellation is
// propagated without wrapping so shutdown remains prompt.
func (r *Reconciler) Worker(interval time.Duration, limit int) workers.Worker {
	return func(ctx context.Context) error {
		if interval <= 0 || limit < 1 || limit > previewDNSMaximumBatch {
			return fmt.Errorf("%w: DNS reconciliation worker policy is invalid", ErrInvalidInput)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := r.Reconcile(ctx, limit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
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

// ListDue and ApplyDNSObservationForReconciliation are the SQLRepository
// implementation of the worker boundary. They live here so the reconciler's
// persistence contract remains visible beside its fencing logic.
func (r *SQLRepository) ListDue(ctx context.Context, now time.Time, limit int) ([]dbsqlc.PreviewDomain, error) {
	if r == nil || r.db == nil || ctx == nil || now.IsZero() || limit < 1 || limit > previewDNSMaximumBatch {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.Queries().ListDuePreviewDomainsV1(ctx, dbsqlc.ListDuePreviewDomainsV1Params{Now: now.UTC(), RowLimit: int32(limit)})
	return rows, translate(err)
}

func (r *SQLRepository) ReleaseExpiredPreviewDomainQuarantines(ctx context.Context, now time.Time) (int64, error) {
	if r == nil || r.db == nil || ctx == nil || now.IsZero() {
		return 0, ErrInvalidInput
	}
	count, err := r.db.Queries().ReleaseExpiredPreviewDomainQuarantinesV1(ctx, now.UTC())
	return count, translate(err)
}

func (r *SQLRepository) ApplyDNSObservationForReconciliation(ctx context.Context, input DNSReconciliationObservation) (dbsqlc.PreviewDomain, error) {
	if r == nil || r.db == nil || ctx == nil || strings.TrimSpace(input.DomainID) == "" || !validScope(input.AccountID, input.PreviewID) ||
		input.PreviewGeneration < 1 || input.ExpectedGeneration < 1 || input.Now.IsZero() || input.NextCheckAt.IsZero() || len(input.ObservedRecords) == 0 {
		return dbsqlc.PreviewDomain{}, ErrInvalidInput
	}
	var updated dbsqlc.PreviewDomain
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		lease, err := tx.Queries().GetPreviewDomainLeaseContextV1(ctx, dbsqlc.GetPreviewDomainLeaseContextV1Params{
			PreviewID: input.PreviewID, AccountID: input.AccountID, DomainID: input.DomainID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if lease.Generation != input.PreviewGeneration || lease.TerminalState != "active" || !lease.LeaseDeadline.After(input.Now) || (lease.UserDeadline.Valid && !lease.UserDeadline.Time.After(input.Now)) {
			return ErrGenerationConflict
		}
		updated, err = tx.Queries().ApplyPreviewDomainDNSObservationV1(ctx, dbsqlc.ApplyPreviewDomainDNSObservationV1Params{
			ObservedRecords: input.ObservedRecords, OwnershipState: input.OwnershipState, ConflictState: input.ConflictState,
			Now: sql.NullTime{Time: input.Now.UTC(), Valid: true}, NextCheckAt: input.NextCheckAt.UTC(),
			TtlSeconds: sql.NullInt32{Int32: input.TTLSeconds, Valid: input.TTLSeconds > 0}, ObservationVerified: input.Verified,
			DomainID: input.DomainID, AccountID: input.AccountID, PreviewID: input.PreviewID, ExpectedGeneration: input.ExpectedGeneration,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return err
		}
		// Only authoritative DNS proof may move the operation state. Keep the
		// verification completion and create progression in this transaction so
		// a generation race cannot publish a ready-looking operation alone.
		if input.Verified && updated.OwnershipState == "verified" && updated.ConflictState == "clear" {
			if _, err := tx.Queries().CompletePreviewDomainVerificationOperationsV1(ctx, dbsqlc.CompletePreviewDomainVerificationOperationsV1Params{
				Now: sql.NullTime{Time: input.Now.UTC(), Valid: true}, AccountID: input.AccountID,
				DomainID: sql.NullString{String: input.DomainID, Valid: true},
			}); err != nil {
				return err
			}
			if _, err := tx.Queries().AdvancePreviewDomainCreateOperationsV1(ctx, dbsqlc.AdvancePreviewDomainCreateOperationsV1Params{
				Now: input.Now.UTC(), AccountID: input.AccountID,
				DomainID: sql.NullString{String: input.DomainID, Valid: true},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return updated, translate(err)
}
