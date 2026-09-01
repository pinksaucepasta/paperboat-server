package previewdomain

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type SQLRepository struct {
	db    *db.DB
	now   func() time.Time
	newID func(string) (string, error)
}

func NewSQLRepository(database *db.DB, config Config) (*SQLRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalidInput)
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	newID := config.NewID
	if newID == nil {
		newID = defaultID
	}
	return &SQLRepository{db: database, now: now, newID: newID}, nil
}

func (r *SQLRepository) List(ctx context.Context, accountID, previewID string, after *ListPosition, limit int) ([]dbsqlc.PreviewDomain, error) {
	if !validScope(accountID, previewID) || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	var createdAt sql.NullTime
	var afterID sql.NullString
	if after != nil {
		createdAt = sql.NullTime{Time: after.CreatedAt.UTC(), Valid: true}
		afterID = sql.NullString{String: after.ID, Valid: true}
	}
	rows, err := r.db.Queries().ListPreviewDomainsV1(ctx, dbsqlc.ListPreviewDomainsV1Params{AccountID: accountID, PreviewID: previewID, AfterCreatedAt: createdAt, AfterID: afterID, RowLimit: int32(limit)})
	return rows, translate(err)
}

// ListProjection returns the bounded historical alias set embedded in a
// preview resource. Unlike the mutable domain collection, it retains terminal
// released/quarantined rows so a stopped or expired preview can explain which
// custom hostnames were withdrawn.
func (r *SQLRepository) ListProjection(ctx context.Context, accountID, previewID string, limit int) ([]dbsqlc.PreviewDomain, error) {
	if !validScope(accountID, previewID) || limit < 1 || limit > MaxDomains+1 {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.Queries().ListPreviewDomainProjectionV1(ctx, dbsqlc.ListPreviewDomainProjectionV1Params{
		AccountID: accountID, PreviewID: previewID, RowLimit: int32(limit),
	})
	return rows, translate(err)
}

func (r *SQLRepository) Get(ctx context.Context, accountID, previewID, domainID string) (dbsqlc.PreviewDomain, error) {
	if !validScope(accountID, previewID) || strings.TrimSpace(domainID) == "" {
		return dbsqlc.PreviewDomain{}, ErrInvalidInput
	}
	row, err := r.db.Queries().GetPreviewDomainV1(ctx, dbsqlc.GetPreviewDomainV1Params{DomainID: domainID, AccountID: accountID, PreviewID: previewID})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.PreviewDomain{}, ErrNotFound
	}
	return row, translate(err)
}

func (r *SQLRepository) Lease(ctx context.Context, accountID, previewID string) (LeaseContext, error) {
	if !validScope(accountID, previewID) {
		return LeaseContext{}, ErrInvalidInput
	}
	row, err := r.db.Queries().GetPreviewDomainLeaseViewV1(ctx, dbsqlc.GetPreviewDomainLeaseViewV1Params{PreviewID: previewID, AccountID: accountID})
	if errors.Is(err, pgx.ErrNoRows) {
		return LeaseContext{}, ErrNotFound
	}
	if err != nil {
		return LeaseContext{}, translate(err)
	}
	return LeaseContext{ID: row.ID, AccountID: row.AccountID, Generation: row.Generation, LeaseDeadline: row.LeaseDeadline,
		UserDeadline: row.UserDeadline, AllocationState: row.AllocationState, EdgeState: row.EdgeState,
		OriginState: row.OriginState, TerminalState: row.TerminalState, OwnerDeviceID: row.OwnerDeviceID,
		OwnerSessionID: row.OwnerSessionID, Endpoint: row.Endpoint}, nil
}

func (r *SQLRepository) Create(ctx context.Context, input CreateRecord) (RepositoryMutation, error) {
	if err := validateCreateRecord(input); err != nil {
		return RepositoryMutation{}, err
	}
	var result RepositoryMutation
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		lease, err := lockLease(ctx, tx, input.AccountID, input.PreviewID)
		if err != nil {
			return err
		}
		if err := requireActiveLease(lease, input.Now); err != nil {
			return err
		}
		if input.PreviewGeneration != lease.Generation {
			return ErrGenerationConflict
		}
		op, replayed, err := beginOperation(ctx, q, operationRecord{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "preview.domain.create", ResourceID: input.DomainID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		if replayed {
			domain, getErr := getAnyDomain(ctx, tx, input.AccountID, input.PreviewID, input.DomainID)
			if errors.Is(getErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if getErr != nil {
				return translate(getErr)
			}
			result = RepositoryMutation{Domain: domain, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		domain, err := q.CreatePreviewDomainV1(ctx, dbsqlc.CreatePreviewDomainV1Params{
			ID: input.DomainID, AccountID: input.AccountID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration,
			Hostname: input.Hostname, MatchType: input.MatchType, OwnershipChallengeReference: input.ChallengeReference,
			DnsTarget: input.DNSTarget, DnsProvider: input.DNSProvider, ExpectedRecords: input.ExpectedRecords, Now: input.Now.UTC(), CertificateStrategy: input.CertificateStrategy,
		})
		if err != nil {
			return mapDatabaseError(err)
		}
		op, err = advanceOperation(ctx, q, op.ID, domain.ID, "waiting_for_dns", 35, input.Now)
		if err != nil {
			return err
		}
		if err := recordAudit(ctx, q, input.AuditEventID, input.AccountID, input.ActorID, input.ActorType, "preview.domain.created", domain.ID, input.IdempotencyKey, input.RequestID, input.CorrelationID, input.SourceDeviceID, input.Now, map[string]any{"hostname": input.Hostname, "state": "waiting_dns"}); err != nil {
			return err
		}
		result = RepositoryMutation{Domain: domain, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) Verify(ctx context.Context, input MutationRecord) (RepositoryMutation, error) {
	return r.mutate(ctx, input, true)
}

func (r *SQLRepository) Delete(ctx context.Context, input MutationRecord) (RepositoryMutation, error) {
	return r.mutate(ctx, input, false)
}

func (r *SQLRepository) mutate(ctx context.Context, input MutationRecord, verify bool) (RepositoryMutation, error) {
	if err := validateMutationRecord(input); err != nil {
		return RepositoryMutation{}, err
	}
	var result RepositoryMutation
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		lease, err := lockLease(ctx, tx, input.AccountID, input.PreviewID)
		if err != nil {
			return err
		}
		if err := requireActiveLease(lease, input.Now); err != nil {
			return err
		}
		opType := "preview.domain.delete"
		if verify {
			opType = "preview.domain.verify"
		}
		op, replayed, err := beginOperation(ctx, q, operationRecord{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: opType, ResourceID: input.DomainID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		current, err := getAnyDomain(ctx, tx, input.AccountID, input.PreviewID, input.DomainID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = RepositoryMutation{Domain: current, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if current.DeletedAt.Valid {
			return ErrNotFound
		}
		if current.PreviewGeneration != lease.Generation {
			return ErrGenerationConflict
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		if verify {
			current, err = q.BeginPreviewDomainVerificationV1(ctx, dbsqlc.BeginPreviewDomainVerificationV1Params{Now: input.Now.UTC(), DomainID: input.DomainID, AccountID: input.AccountID, PreviewID: input.PreviewID, ExpectedGeneration: input.ExpectedGeneration})
		} else {
			current, err = q.DeletePreviewDomainV1(ctx, dbsqlc.DeletePreviewDomainV1Params{QuarantineUntil: sql.NullTime{Time: input.Now.UTC().Add(Quarantine), Valid: true}, Now: sql.NullTime{Time: input.Now.UTC(), Valid: true}, DomainID: input.DomainID, AccountID: input.AccountID, PreviewID: input.PreviewID, ExpectedGeneration: input.ExpectedGeneration})
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return mapDatabaseError(err)
		}
		phase, progress, event := "waiting_for_dns", int16(35), "preview.domain.verification_requested"
		if !verify {
			phase, progress, event = "ready", 100, "preview.domain.deleted"
		}
		if progress == 100 {
			op, err = completeOperation(ctx, q, op.ID, current.ID, phase, "changed", input.Now)
		} else {
			op, err = advanceOperation(ctx, q, op.ID, current.ID, phase, progress, input.Now)
		}
		if err != nil {
			return err
		}
		if err := recordAudit(ctx, q, input.AuditEventID, input.AccountID, input.ActorID, input.ActorType, event, current.ID, input.IdempotencyKey, input.RequestID, input.CorrelationID, input.SourceDeviceID, input.Now, map[string]any{"hostname": current.Hostname, "state": wireState(current)}); err != nil {
			return err
		}
		result = RepositoryMutation{Domain: current, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) ApplyDNSObservation(ctx context.Context, input DNSObservationRecord) (RepositoryMutation, error) {
	if err := validateMutationRecord(input.MutationRecord); err != nil {
		return RepositoryMutation{}, err
	}
	if input.NextCheckAt.IsZero() || input.Now.IsZero() || input.OwnershipState == "" || input.ConflictState == "" || len(input.ObservedRecords) == 0 {
		return RepositoryMutation{}, ErrInvalidInput
	}
	var result RepositoryMutation
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		domain, err := tx.Queries().ApplyPreviewDomainDNSObservationV1(ctx, dbsqlc.ApplyPreviewDomainDNSObservationV1Params{
			ObservedRecords: input.ObservedRecords, OwnershipState: input.OwnershipState, ConflictState: input.ConflictState,
			Now: sql.NullTime{Time: input.Now.UTC(), Valid: true}, NextCheckAt: input.NextCheckAt.UTC(),
			TtlSeconds: nullableSQLInt32(input.TTLSeconds), ObservationVerified: input.Verified, DomainID: input.DomainID,
			AccountID: input.AccountID, PreviewID: input.PreviewID, ExpectedGeneration: input.ExpectedGeneration,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return translate(err)
		}
		result = RepositoryMutation{Domain: domain, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) ApplyCertificateObservation(ctx context.Context, input CertificateObservationRecord) (RepositoryMutation, error) {
	if err := validateMutationRecord(input.MutationRecord); err != nil {
		return RepositoryMutation{}, err
	}
	if input.CertificateState == "" || input.CAAState == "" || input.Now.IsZero() {
		return RepositoryMutation{}, ErrInvalidInput
	}
	var result RepositoryMutation
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		domain, err := tx.Queries().ApplyPreviewDomainCertificateObservationV1(ctx, dbsqlc.ApplyPreviewDomainCertificateObservationV1Params{
			CertificateState: input.CertificateState, CertificateReference: nullableSQLString(input.CertificateReference),
			CertificateExpiresAt: nullableSQLTime(input.CertificateExpiresAt), Now: sql.NullTime{Time: input.Now.UTC(), Valid: true},
			FailureCode: nullableSQLString(input.FailureCode), CaaState: input.CAAState, DomainID: input.DomainID,
			AccountID: input.AccountID, PreviewID: input.PreviewID, ExpectedGeneration: input.ExpectedGeneration,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			return translate(err)
		}
		result = RepositoryMutation{Domain: domain, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) ReadyAliases(ctx context.Context, accountID, previewID string, now time.Time) ([]ReadyAliasRecord, error) {
	if !validScope(accountID, previewID) || now.IsZero() {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.Queries().ListReadyPreviewDomainAliasesV1(ctx, dbsqlc.ListReadyPreviewDomainAliasesV1Params{
		Now: now.UTC(), AccountID: accountID, PreviewID: previewID,
	})
	if err != nil {
		return nil, translate(err)
	}
	result := make([]ReadyAliasRecord, 0, len(rows))
	for _, row := range rows {
		if row.ActiveCertificateGeneration < 1 || row.ActiveCertificateReference == "" {
			return nil, ErrCertificatePending
		}
		result = append(result, ReadyAliasRecord{Domain: previewDomainFromAliasRow(row), CertificateReference: row.ActiveCertificateReference, CertificateGeneration: row.ActiveCertificateGeneration})
	}
	return result, nil
}

func previewDomainFromAliasRow(row dbsqlc.ListReadyPreviewDomainAliasesV1Row) dbsqlc.PreviewDomain {
	return dbsqlc.PreviewDomain{ID: row.ID, AccountID: row.AccountID, PreviewID: row.PreviewID, PreviewGeneration: row.PreviewGeneration,
		Hostname: row.Hostname, MatchType: row.MatchType, OwnershipChallengeReference: row.OwnershipChallengeReference,
		OwnershipState: row.OwnershipState, DnsTarget: row.DnsTarget, ObservedRecords: row.ObservedRecords,
		DnsProvider: row.DnsProvider, ExpectedRecords: row.ExpectedRecords, DnsLastCheckedAt: row.DnsLastCheckedAt,
		DnsNextCheckAt: row.DnsNextCheckAt, DnsTtlSeconds: row.DnsTtlSeconds, VerificationAttempts: row.VerificationAttempts,
		CertificateStrategy: row.CertificateStrategy, CertificateReference: row.CertificateReference, CertificateState: row.CertificateState,
		CertificateExpiresAt: row.CertificateExpiresAt, CertificateRenewalAttemptedAt: row.CertificateRenewalAttemptedAt,
		CertificateFailureCode: row.CertificateFailureCode, CaaState: row.CaaState, ConflictState: row.ConflictState,
		LastVerifiedAt: row.LastVerifiedAt, Generation: row.Generation, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		DeletedAt: row.DeletedAt, QuarantineUntil: row.QuarantineUntil}
}

// CreateForPreviewTx atomically inserts all preview aliases into a caller's
// existing lease-create transaction.  It does not create child operations:
// the caller's preview.create operation is the durable idempotency record for
// the batch.  Every domain is validated and allocated before the first insert.
func (r *SQLRepository) CreateForPreviewTx(ctx context.Context, tx *db.Tx, input BatchCreateRequest) ([]dbsqlc.PreviewDomain, error) {
	if tx == nil || !validScope(input.AccountID, input.PreviewID) || input.PreviewGeneration < 1 || input.Now.IsZero() || len(input.Domains) > MaxDomains {
		return nil, ErrInvalidInput
	}
	lease, err := lockLease(ctx, tx, input.AccountID, input.PreviewID)
	if err != nil {
		return nil, err
	}
	if err := requireActiveLease(lease, input.Now); err != nil {
		return nil, err
	}
	if lease.Generation != input.PreviewGeneration {
		return nil, ErrGenerationConflict
	}
	target, err := StableTargetHostname(input.StableEndpoint)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id, hostname, matchType, challenge, provider, strategy string
		expected                                               []byte
	}
	candidates := make([]candidate, 0, len(input.Domains))
	seen := make(map[string]struct{}, len(input.Domains))
	for _, request := range input.Domains {
		hostname, matchType, normalizeErr := NormalizeHostname(request.Hostname)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		if _, ok := seen[hostname]; ok {
			return nil, ErrDomainConflict
		}
		seen[hostname] = struct{}{}
		provider, providerErr := ValidateProvider(request.Provider)
		if providerErr != nil {
			return nil, providerErr
		}
		strategy, strategyErr := ValidateCertificateStrategy(request.CertificateStrategy, matchType)
		if strategyErr != nil {
			return nil, strategyErr
		}
		domainID, idErr := r.newID("pdom")
		if idErr != nil {
			return nil, idErr
		}
		challengeID, idErr := r.newID("dns")
		if idErr != nil {
			return nil, idErr
		}
		recordType := DNSRecordType(hostname, provider)
		expected, marshalErr := json.Marshal([]DNSRecord{{Name: hostname, Type: recordType, Value: target, TTL: 300}})
		if marshalErr != nil {
			return nil, marshalErr
		}
		candidates = append(candidates, candidate{id: domainID, hostname: hostname, matchType: matchType, challenge: "dns-challenge://" + challengeID, provider: provider, strategy: strategy, expected: expected})
	}
	rows := make([]dbsqlc.PreviewDomain, 0, len(candidates))
	for _, candidate := range candidates {
		row, createErr := tx.Queries().CreatePreviewDomainV1(ctx, dbsqlc.CreatePreviewDomainV1Params{ID: candidate.id, AccountID: input.AccountID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration, Hostname: candidate.hostname, MatchType: candidate.matchType, OwnershipChallengeReference: candidate.challenge, DnsTarget: target, DnsProvider: candidate.provider, ExpectedRecords: candidate.expected, Now: input.Now.UTC(), CertificateStrategy: candidate.strategy})
		if createErr != nil {
			return nil, mapDatabaseError(createErr)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func lockLease(ctx context.Context, tx *db.Tx, accountID, previewID string) (LeaseContext, error) {
	row, err := tx.Queries().GetPreviewLeaseOwnerContextV1(ctx, dbsqlc.GetPreviewLeaseOwnerContextV1Params{PreviewID: previewID, AccountID: accountID})
	if errors.Is(err, pgx.ErrNoRows) {
		return LeaseContext{}, ErrNotFound
	}
	if err != nil {
		return LeaseContext{}, translate(err)
	}
	return LeaseContext{ID: row.ID, AccountID: row.AccountID, Generation: row.Generation, LeaseDeadline: row.LeaseDeadline,
		UserDeadline: row.UserDeadline, AllocationState: row.AllocationState, EdgeState: row.EdgeState,
		OriginState: row.OriginState, TerminalState: row.TerminalState, OwnerDeviceID: row.OwnerDeviceID,
		OwnerSessionID: row.OwnerSessionID, Endpoint: row.Endpoint}, nil
}

func getAnyDomain(ctx context.Context, tx *db.Tx, accountID, previewID, domainID string) (dbsqlc.PreviewDomain, error) {
	return tx.Queries().GetPreviewDomainAnyV1(ctx, dbsqlc.GetPreviewDomainAnyV1Params{DomainID: domainID, AccountID: accountID, PreviewID: previewID})
}

type operationRecord struct {
	ID, AccountID, IdempotencyKey            string
	RequestHash                              [32]byte
	OperationType, ResourceID, CorrelationID string
}

func beginOperation(ctx context.Context, q *dbsqlc.Queries, input operationRecord) (dbsqlc.Operation, bool, error) {
	op, err := q.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{ID: input.ID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash[:], OperationType: input.OperationType, ResourceKind: Kind, ResourceID: sql.NullString{String: input.ResourceID, Valid: true}, Phase: "persisting", State: "running", Progress: 20, Outcome: "unchanged", CorrelationID: input.CorrelationID})
	if err == nil {
		return op, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.Operation{}, false, mapDatabaseError(err)
	}
	existing, getErr := q.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey})
	if getErr != nil {
		return dbsqlc.Operation{}, false, translate(getErr)
	}
	if existing.OperationType != input.OperationType || existing.ResourceKind != Kind || !existing.ResourceID.Valid || existing.ResourceID.String != input.ResourceID || !bytes.Equal(existing.RequestHash, input.RequestHash[:]) {
		return dbsqlc.Operation{}, false, ErrIdempotencyConflict
	}
	return existing, true, nil
}

func advanceOperation(ctx context.Context, q *dbsqlc.Queries, id, resourceID, phase string, progress int16, now time.Time) (dbsqlc.Operation, error) {
	op, err := q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{ResourceID: sql.NullString{String: resourceID, Valid: true}, Phase: phase, State: "running", Progress: progress, Outcome: "changed", ResultReference: sql.NullString{}, UpdatedAt: now.UTC(), CompletedAt: sql.NullTime{}, ID: id})
	return op, translate(err)
}

func completeOperation(ctx context.Context, q *dbsqlc.Queries, id, resourceID, phase, outcome string, now time.Time) (dbsqlc.Operation, error) {
	op, err := q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{ResourceID: sql.NullString{String: resourceID, Valid: true}, Phase: phase, State: "succeeded", Progress: 100, Outcome: outcome, ResultReference: sql.NullString{String: resourceID, Valid: true}, UpdatedAt: now.UTC(), CompletedAt: sql.NullTime{Time: now.UTC(), Valid: true}, ID: id})
	return op, translate(err)
}

func recordAudit(ctx context.Context, q *dbsqlc.Queries, id, accountID, actorID, actorType, eventType, resourceID, idempotencyKey, requestID, correlationID, sourceDeviceID string, now time.Time, metadata map[string]any) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if _, err := q.InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{ID: id, AccountID: sql.NullString{String: accountID, Valid: true}, ActorID: sql.NullString{String: actorID, Valid: actorID != ""}, ActorUserID: sql.NullString{String: actorID, Valid: actorType != "host" && actorID != ""}, ActorType: actorType, EventType: eventType, ChangeType: "update", Outcome: "changed", ResourceType: Kind, ResourceID: resourceID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: idempotencyKey != ""}, RequestID: sql.NullString{String: requestID, Valid: requestID != ""}, CorrelationID: sql.NullString{String: correlationID, Valid: correlationID != ""}, SourceDeviceID: sql.NullString{String: sourceDeviceID, Valid: sourceDeviceID != ""}, Metadata: encoded, CreatedAt: now.UTC()}); err != nil {
		return translate(err)
	}
	return nil
}

func validateCreateRecord(input CreateRecord) error {
	if !validScope(input.AccountID, input.PreviewID) || strings.TrimSpace(input.DomainID) == "" || strings.TrimSpace(input.OperationID) == "" || strings.TrimSpace(input.AuditEventID) == "" || strings.TrimSpace(input.IdempotencyKey) == "" || input.PreviewGeneration < 1 || input.RequestHash == ([32]byte{}) || input.Now.IsZero() {
		return ErrInvalidInput
	}
	if input.Hostname == "" || input.MatchType == "" || input.ChallengeReference == "" || input.DNSTarget == "" || input.DNSProvider == "" || input.CertificateStrategy == "" || len(input.ExpectedRecords) == 0 {
		return ErrInvalidInput
	}
	return nil
}

func validateMutationRecord(input MutationRecord) error {
	if !validScope(input.AccountID, input.PreviewID) || strings.TrimSpace(input.DomainID) == "" || strings.TrimSpace(input.OperationID) == "" || strings.TrimSpace(input.AuditEventID) == "" || strings.TrimSpace(input.IdempotencyKey) == "" || input.ExpectedGeneration < 1 || input.RequestHash == ([32]byte{}) || input.Now.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

func validScope(accountID, previewID string) bool {
	return strings.TrimSpace(accountID) != "" && strings.TrimSpace(previewID) != ""
}

func requireActiveLease(lease LeaseContext, now time.Time) error {
	if lease.TerminalState != "active" || !lease.LeaseDeadline.After(now) || (lease.UserDeadline.Valid && !lease.UserDeadline.Time.After(now)) {
		return ErrLeaseNotActive
	}
	return nil
}

func mapDatabaseError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			if pgErr.ConstraintName == "domain_bindings_live_hostname_unique" || strings.Contains(pgErr.Message, "custom domain hostname") {
				return ErrDomainConflict
			}
		case "23514":
			return ErrInvalidInput
		}
	}
	return translate(err)
}

func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func nullableSQLString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func nullableSQLTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func nullableSQLInt32(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: *value, Valid: true}
}

func defaultID(prefix string) (string, error) {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()), nil
}
