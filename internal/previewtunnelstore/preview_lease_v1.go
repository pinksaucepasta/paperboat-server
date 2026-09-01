package previewtunnelstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
)

var (
	ErrPreviewLeaseOperationInProgress = errors.New("preview lease operation is already in progress")
	ErrPreviewLeaseTerminal            = errors.New("preview lease is already terminal")
	ErrPreviewLeaseExpired             = errors.New("preview lease deadline has passed")
	ErrPreviewLeaseDeadlineExceeded    = errors.New("preview lease deadline exceeds user deadline")
	ErrOwnerNotFound                   = errors.New("preview lease owner is not owned by this account")
	ErrEndpointConflict                = errors.New("preview lease endpoint conflict")
)

const previewDomainQuarantine = 7 * 24 * time.Hour

// PreviewLeaseRecord combines the stable lease row with its lifecycle sidecar.
// Generation is deliberately not exposed by the v1 resource schema, but is
// required for strong HTTP ETags and all lease mutations.
type PreviewLeaseRecord struct {
	dbsqlc.PreviewLease
}

type CreatePreviewLeaseV1Input struct {
	OperationID    string
	LeaseID        string
	AuditEventID   string
	AccountID      string
	ActorID        string
	ActorType      string
	OwnerDeviceID  string
	OwnerSessionID string
	TargetScheme   string
	TargetAddress  string
	AccessMode     string
	EndpointID     string
	Endpoint       string
	LeaseDeadline  time.Time
	UserDeadline   sql.NullTime
	RequestHash    []byte
	IdempotencyKey string
	CorrelationID  string
	RequestID      string
	SourceDeviceID string
	Now            time.Time
	Domains        []PreviewDomainCreateRequest
}

type CreatePreviewLeaseV1Result struct {
	Lease     PreviewLeaseRecord
	Operation dbsqlc.Operation
	Replayed  bool
}

type RenewPreviewLeaseV1Input struct {
	OperationID        string
	AuditEventID       string
	AccountID          string
	ActorID            string
	ActorType          string
	PreviewID          string
	OwnerDeviceID      string
	OwnerSessionID     string
	ExpectedGeneration int64
	LeaseDeadline      time.Time
	RequestHash        []byte
	IdempotencyKey     string
	CorrelationID      string
	RequestID          string
	SourceDeviceID     string
	Now                time.Time
}

type RenewPreviewLeaseV1Result struct {
	Lease     PreviewLeaseRecord
	Operation dbsqlc.Operation
	Replayed  bool
}

type StopPreviewLeaseV1Input struct {
	OperationID        string
	AuditEventID       string
	AccountID          string
	ActorID            string
	ActorType          string
	PreviewID          string
	OwnerDeviceID      string
	OwnerSessionID     string
	ExpectedGeneration int64
	RequestHash        []byte
	IdempotencyKey     string
	CorrelationID      string
	RequestID          string
	SourceDeviceID     string
	Now                time.Time
}

type StopPreviewLeaseV1Result struct {
	Lease    PreviewLeaseRecord
	Replayed bool
}

type MarkPreviewLeaseReadyV1Input struct {
	AuditEventID       string
	AccountID          string
	ActorID            string
	ActorType          string
	PreviewID          string
	ExpectedGeneration int64
	AllocationState    string
	EdgeState          string
	OriginState        string
	CorrelationID      string
	RequestID          string
	SourceDeviceID     string
	Now                time.Time
}

// MarkPreviewLeaseDispatchUncertainV1Input records that the server could not
// determine whether the host received the one-shot dispatch. The lease stays
// active and pending so a replay can reuse the same operation and lease.
type MarkPreviewLeaseDispatchUncertainV1Input struct {
	AuditEventID   string
	AccountID      string
	ActorID        string
	ActorType      string
	PreviewID      string
	ErrorCode      string
	CorrelationID  string
	RequestID      string
	SourceDeviceID string
	Now            time.Time
}

type ReconcilePreviewLeasesV1Input struct {
	ActorID       string
	ActorType     string
	CorrelationID string
	RequestID     string
	Now           time.Time
	OwnerGrace    time.Duration
	Limit         int32
}

type ReconcilePreviewLeasesV1Result struct {
	Expired   []PreviewLeaseRecord
	OwnerLost []PreviewLeaseRecord
	HasMore   bool
}

func (s *Store) VerifyPreviewLeaseOwnerV1(ctx context.Context, accountID, ownerDeviceID string) error {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(ownerDeviceID) == "" {
		return ErrInvalidInput
	}
	_, err := s.db.Queries().VerifyPreviewLeaseOwnerV1(ctx, dbsqlc.VerifyPreviewLeaseOwnerV1Params{
		AccountID: accountID, OwnerDeviceID: ownerDeviceID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrOwnerNotFound
	}
	return translate(err)
}

// GetPreviewLeaseV1 returns only the account-scoped row. A missing row and a
// row belonging to another account intentionally have the same error.
func (s *Store) GetPreviewLeaseV1(ctx context.Context, accountID, previewID string) (PreviewLeaseRecord, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(previewID) == "" {
		return PreviewLeaseRecord{}, fmt.Errorf("%w: account and preview IDs are required", ErrInvalidInput)
	}
	row, err := s.db.Queries().GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: previewID, AccountID: accountID})
	if err != nil {
		return PreviewLeaseRecord{}, translate(err)
	}
	return previewLeaseRecordFromRow(row), nil
}

type ListPreviewLeasesV1Input struct {
	AccountID      string
	AfterCreatedAt sql.NullTime
	AfterID        sql.NullString
	Limit          int32
}

func (s *Store) ListPreviewLeasesV1(ctx context.Context, input ListPreviewLeasesV1Input) ([]PreviewLeaseRecord, error) {
	if strings.TrimSpace(input.AccountID) == "" || input.Limit < 1 || input.Limit > 201 {
		return nil, ErrInvalidInput
	}
	if input.AfterCreatedAt.Valid != input.AfterID.Valid {
		return nil, fmt.Errorf("%w: list cursor must contain both timestamp and ID", ErrInvalidInput)
	}
	rows, err := s.db.Queries().ListPreviewLeasesV1(ctx, dbsqlc.ListPreviewLeasesV1Params{
		AccountID: input.AccountID, AfterCreatedAt: input.AfterCreatedAt, AfterID: input.AfterID, RowLimit: input.Limit,
	})
	if err != nil {
		return nil, translate(err)
	}
	items := make([]PreviewLeaseRecord, 0, len(rows))
	for _, row := range rows {
		items = append(items, previewLeaseRecordFromRow(row))
	}
	return items, nil
}

func (s *Store) CreatePreviewLeaseV1(ctx context.Context, input CreatePreviewLeaseV1Input) (CreatePreviewLeaseV1Result, error) {
	if err := validateCreatePreviewLeaseV1(input); err != nil {
		return CreatePreviewLeaseV1Result{}, err
	}
	now := input.Now.UTC()
	var result CreatePreviewLeaseV1Result
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		operation, err := q.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "preview.create", ResourceKind: "preview_lease",
			Phase: "persisting", State: "running", Progress: 15, Outcome: "unchanged",
			CorrelationID: input.CorrelationID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := q.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{
				AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			})
			if getErr != nil {
				return translate(getErr)
			}
			if existing.OperationType != "preview.create" || existing.ResourceKind != "preview_lease" || !equalBytes(existing.RequestHash, input.RequestHash) {
				return ErrIdempotencyConflict
			}
			if !existing.ResourceID.Valid {
				return ErrPreviewLeaseOperationInProgress
			}
			lease, getErr := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: existing.ResourceID.String, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = CreatePreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(lease), Operation: existing, Replayed: true}
			return nil
		}
		if err != nil {
			return translate(err)
		}

		_, err = q.CreatePreviewLease(ctx, dbsqlc.CreatePreviewLeaseParams{
			ID: input.LeaseID, EndpointID: input.EndpointID, Endpoint: input.Endpoint,
			AccountID: input.AccountID, ActorID: input.ActorID, OwnerDeviceID: input.OwnerDeviceID,
			OwnerSessionID: input.OwnerSessionID, TargetScheme: input.TargetScheme,
			TargetAddress: input.TargetAddress, AccessMode: input.AccessMode,
			LeaseDeadline: input.LeaseDeadline, UserDeadline: input.UserDeadline,
			AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", Now: now,
		})
		if err != nil {
			return translatePreviewLeaseCreateError(err)
		}
		lease, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.LeaseID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if len(input.Domains) > 0 {
			if s.previewDomains == nil {
				return fmt.Errorf("%w: preview domain persistence is unavailable", ErrInvalidInput)
			}
			if err := s.previewDomains.CreateForPreviewTx(ctx, tx, PreviewDomainBatchInput{
				AccountID: input.AccountID, PreviewID: input.LeaseID, PreviewGeneration: lease.Generation,
				StableEndpoint: input.Endpoint, Domains: append([]PreviewDomainCreateRequest(nil), input.Domains...),
				ActorID: input.ActorID, ActorType: input.ActorType, RequestID: input.RequestID,
				CorrelationID: input.CorrelationID, Now: now,
			}); err != nil {
				return err
			}
		}
		operation, err = q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
			ResourceID: sql.NullString{String: input.LeaseID, Valid: true}, Phase: "connecting", State: "running",
			Progress: 60, Outcome: "changed", ResultReference: sql.NullString{String: input.LeaseID, Valid: true},
			UpdatedAt: now, CompletedAt: sql.NullTime{}, ID: operation.ID,
		})
		if err != nil {
			return translate(err)
		}
		if err := insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
			ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
			EventType: "preview.created", ChangeType: "create", Outcome: "changed", ResourceID: input.LeaseID,
			IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
			SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{
				"access_mode": input.AccessMode, "allocation_state": "pending", "persistent": false,
			}, CreatedAt: now,
		}); err != nil {
			return err
		}
		result = CreatePreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(lease), Operation: operation}
		return nil
	})
	return result, err
}

func (s *Store) RenewPreviewLeaseV1(ctx context.Context, input RenewPreviewLeaseV1Input) (RenewPreviewLeaseV1Result, error) {
	if err := validateRenewPreviewLeaseV1(input); err != nil {
		return RenewPreviewLeaseV1Result{}, err
	}
	now := input.Now.UTC()
	var result RenewPreviewLeaseV1Result
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		operation, err := q.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "preview.renew", ResourceKind: "preview_lease",
			ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "persisting", State: "running",
			Progress: 20, Outcome: "unchanged", CorrelationID: input.CorrelationID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := q.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{
				AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			})
			if getErr != nil {
				return translate(getErr)
			}
			if existing.OperationType != "preview.renew" || existing.ResourceKind != "preview_lease" || !existing.ResourceID.Valid || existing.ResourceID.String != input.PreviewID || !equalBytes(existing.RequestHash, input.RequestHash) {
				return ErrIdempotencyConflict
			}
			lease, getErr := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = RenewPreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(lease), Operation: existing, Replayed: true}
			return nil
		}
		if err != nil {
			return translate(err)
		}
		current, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if current.TerminalState != "active" {
			return ErrPreviewLeaseTerminal
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		if !input.LeaseDeadline.After(now) {
			return ErrPreviewLeaseExpired
		}
		if current.UserDeadline.Valid && input.LeaseDeadline.After(current.UserDeadline.Time) {
			return ErrPreviewLeaseDeadlineExceeded
		}
		if _, err := q.AdvancePreviewLeaseLifecycleV1(ctx, dbsqlc.AdvancePreviewLeaseLifecycleV1Params{
			OwnerLastSeenAt: now, PreviewID: input.PreviewID, AccountID: input.AccountID,
			OwnerDeviceID: input.OwnerDeviceID, OwnerSessionID: input.OwnerSessionID,
			ExpectedGeneration: input.ExpectedGeneration,
		}); errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		} else if err != nil {
			return translate(err)
		}
		if err := q.RenewPreviewLeaseV1(ctx, dbsqlc.RenewPreviewLeaseV1Params{
			LeaseDeadline: input.LeaseDeadline, Now: now, ID: input.PreviewID, AccountID: input.AccountID,
		}); err != nil {
			return translate(err)
		}
		lease, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if _, err := q.AdvancePreviewDomainTargetGenerationV1(ctx, dbsqlc.AdvancePreviewDomainTargetGenerationV1Params{
			NewPreviewGeneration: lease.Generation, Now: now, PreviewID: input.PreviewID,
			AccountID: input.AccountID, PreviousPreviewGeneration: current.Generation,
		}); err != nil {
			return translate(err)
		}
		expiresAt := lease.LeaseDeadline
		if lease.UserDeadline.Valid && lease.UserDeadline.Time.Before(expiresAt) {
			expiresAt = lease.UserDeadline.Time
		}
		if _, err := tunnelcert.RebindPreviewCertificatesTx(ctx, tx, input.AccountID, input.PreviewID, uint64(current.Generation), uint64(lease.Generation), expiresAt, now); err != nil {
			return translate(err)
		}
		operation, err = q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
			ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "ready", State: "succeeded",
			Progress: 100, Outcome: "changed", ResultReference: sql.NullString{String: input.PreviewID, Valid: true},
			UpdatedAt: now, CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operation.ID,
		})
		if err != nil {
			return translate(err)
		}
		if err := insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
			ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
			EventType: "preview.lease_renewed", ChangeType: "renew", Outcome: "changed", ResourceID: input.PreviewID,
			IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
			SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{"lease_deadline": input.LeaseDeadline.UTC()}, CreatedAt: now,
		}); err != nil {
			return err
		}
		result = RenewPreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(lease), Operation: operation}
		return nil
	})
	return result, err
}

func (s *Store) StopPreviewLeaseV1(ctx context.Context, input StopPreviewLeaseV1Input) (StopPreviewLeaseV1Result, error) {
	if err := validateStopPreviewLeaseV1(input); err != nil {
		return StopPreviewLeaseV1Result{}, err
	}
	now := input.Now.UTC()
	var result StopPreviewLeaseV1Result
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		operation, err := q.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "preview.stop", ResourceKind: "preview_lease",
			ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "persisting", State: "running",
			Progress: 50, Outcome: "unchanged", CorrelationID: input.CorrelationID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := q.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{
				AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			})
			if getErr != nil {
				return translate(getErr)
			}
			if existing.OperationType != "preview.stop" || existing.ResourceKind != "preview_lease" || !existing.ResourceID.Valid || existing.ResourceID.String != input.PreviewID || !equalBytes(existing.RequestHash, input.RequestHash) {
				return ErrIdempotencyConflict
			}
			current, getErr := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = StopPreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(current), Replayed: true}
			return nil
		}
		if err != nil {
			return translate(err)
		}
		current, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if current.TerminalState != "active" {
			operation, err = q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
				ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "ready", State: "succeeded",
				Progress: 100, Outcome: "unchanged", ResultReference: sql.NullString{String: input.PreviewID, Valid: true},
				UpdatedAt: now, CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operation.ID,
			})
			if err != nil {
				return translate(err)
			}
			result = StopPreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(current), Replayed: true}
			return nil
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		if _, err := q.AdvancePreviewLeaseLifecycleV1(ctx, dbsqlc.AdvancePreviewLeaseLifecycleV1Params{
			OwnerLastSeenAt: current.OwnerLastSeenAt, PreviewID: input.PreviewID, AccountID: input.AccountID,
			OwnerDeviceID: input.OwnerDeviceID, OwnerSessionID: input.OwnerSessionID,
			ExpectedGeneration: input.ExpectedGeneration,
		}); errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		} else if err != nil {
			return translate(err)
		}
		if err := q.StopPreviewLeaseV1(ctx, dbsqlc.StopPreviewLeaseV1Params{
			Now: sql.NullTime{Time: now, Valid: true}, ID: input.PreviewID, AccountID: input.AccountID,
		}); err != nil {
			return translate(err)
		}
		stopped, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if _, err := q.WithdrawPreviewDomainsV1(ctx, dbsqlc.WithdrawPreviewDomainsV1Params{
			QuarantineUntil: sql.NullTime{Time: now.Add(previewDomainQuarantine), Valid: true},
			Now:             sql.NullTime{Time: now, Valid: true}, PreviewID: input.PreviewID, AccountID: input.AccountID,
			TerminalPreviewGeneration: stopped.Generation,
		}); err != nil {
			return translate(err)
		}
		if _, err := tunnelcert.RevokePreviewCertificatesTx(ctx, tx, input.AccountID, input.PreviewID, "preview_lease_terminal", now); err != nil {
			return translate(err)
		}
		key := input.IdempotencyKey
		if key == "" {
			key = "preview.stop:" + input.PreviewID
		}
		if err := insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
			ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
			EventType: "preview.stopped", ChangeType: "stop", Outcome: "changed", ResourceID: input.PreviewID,
			IdempotencyKey: key, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
			SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{"endpoint_released": true}, CreatedAt: now,
		}); err != nil {
			return err
		}
		if _, err = q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
			ResourceID: sql.NullString{String: input.PreviewID, Valid: true}, Phase: "ready", State: "succeeded",
			Progress: 100, Outcome: "changed", ResultReference: sql.NullString{String: input.PreviewID, Valid: true},
			UpdatedAt: now, CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operation.ID,
		}); err != nil {
			return translate(err)
		}
		result = StopPreviewLeaseV1Result{Lease: previewLeaseRecordFromRow(stopped)}
		return nil
	})
	return result, err
}

func (s *Store) MarkPreviewLeaseReadyV1(ctx context.Context, input MarkPreviewLeaseReadyV1Input) (PreviewLeaseRecord, error) {
	if err := validateMarkPreviewLeaseReadyV1(input); err != nil {
		return PreviewLeaseRecord{}, err
	}
	now := input.Now.UTC()
	var result PreviewLeaseRecord
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		current, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if current.TerminalState != "active" {
			result = previewLeaseRecordFromRow(current)
			return nil
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		rows, err := q.AdvancePreviewLeaseReadinessV1(ctx, dbsqlc.AdvancePreviewLeaseReadinessV1Params{
			PreviewID: input.PreviewID, AccountID: input.AccountID, ExpectedGeneration: input.ExpectedGeneration,
		})
		if err != nil {
			return translate(err)
		}
		if rows != 1 {
			return ErrGenerationConflict
		}
		if err := q.MarkPreviewLeaseReadyV1(ctx, dbsqlc.MarkPreviewLeaseReadyV1Params{
			AllocationState: input.AllocationState, EdgeState: input.EdgeState, OriginState: input.OriginState,
			Now: sql.NullTime{Time: now, Valid: true}, ID: input.PreviewID, AccountID: input.AccountID,
		}); err != nil {
			return translate(err)
		}
		updated, err := q.GetPreviewLeaseV1(ctx, dbsqlc.GetPreviewLeaseV1Params{ID: input.PreviewID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		result = previewLeaseRecordFromRow(updated)
		if updated.AllocationState == "failed" {
			if err := failPreviewLeaseCreateOperation(ctx, q, input.AccountID, input.PreviewID, "preview_allocation_failed", now); err != nil {
				return err
			}
			return insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
				ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
				EventType: "preview.failed", ChangeType: "state", Outcome: "changed", ResourceID: input.PreviewID,
				IdempotencyKey: "preview.failed:" + input.PreviewID, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
				SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{"allocation_state": "failed"}, CreatedAt: now,
			})
		}
		if updated.AllocationState == "ready" && updated.EdgeState == "ready" && updated.OriginState == "ready" {
			if err := completePreviewLeaseCreateOperation(ctx, q, input.AccountID, input.PreviewID, now); err != nil {
				return err
			}
			return insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
				ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
				EventType: "preview.ready", ChangeType: "state", Outcome: "changed", ResourceID: input.PreviewID,
				IdempotencyKey: "preview.ready:" + input.PreviewID, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
				SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{"allocation_state": "ready", "edge_state": "ready", "origin_state": "ready"}, CreatedAt: now,
			})
		}
		return nil
	})
	return result, err
}

// MarkPreviewLeaseDispatchUncertainV1 is deliberately separate from
// readiness. A transport timeout is not evidence of edge/origin readiness and
// must never advance the lease generation or complete the create operation.
func (s *Store) MarkPreviewLeaseDispatchUncertainV1(ctx context.Context, input MarkPreviewLeaseDispatchUncertainV1Input) error {
	if strings.TrimSpace(input.AuditEventID) == "" || strings.TrimSpace(input.AccountID) == "" || strings.TrimSpace(input.ActorID) == "" || !validActorType(input.ActorType) || strings.TrimSpace(input.PreviewID) == "" || strings.TrimSpace(input.ErrorCode) == "" || strings.TrimSpace(input.CorrelationID) == "" || strings.TrimSpace(input.RequestID) == "" || input.Now.IsZero() {
		return ErrInvalidInput
	}
	now := input.Now.UTC()
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().MarkPreviewLeaseCreateOperationUncertainV1(ctx, dbsqlc.MarkPreviewLeaseCreateOperationUncertainV1Params{
			ErrorCode: sql.NullString{String: input.ErrorCode, Valid: true}, UpdatedAt: now,
			AccountID: input.AccountID, ResourceID: input.PreviewID,
		}); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return translate(err)
		}
		return insertPreviewLeaseAudit(ctx, tx.Queries(), previewLeaseAuditInput{
			ID: input.AuditEventID, AccountID: input.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
			EventType: "preview.dispatch_uncertain", ChangeType: "dispatch", Outcome: "uncertain", ResourceID: input.PreviewID,
			IdempotencyKey: "preview.dispatch_uncertain:" + input.PreviewID, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
			SourceDeviceID: input.SourceDeviceID, Metadata: map[string]any{"error_code": input.ErrorCode}, CreatedAt: now,
		})
	})
}

func (s *Store) ReconcilePreviewLeasesV1(ctx context.Context, input ReconcilePreviewLeasesV1Input) (ReconcilePreviewLeasesV1Result, error) {
	if strings.TrimSpace(input.ActorID) == "" || !validActorType(input.ActorType) || strings.TrimSpace(input.CorrelationID) == "" || strings.TrimSpace(input.RequestID) == "" || input.OwnerGrace <= 0 || input.Now.IsZero() || input.Limit < 1 || input.Limit > 500 {
		return ReconcilePreviewLeasesV1Result{}, ErrInvalidInput
	}
	now := input.Now.UTC()
	var result ReconcilePreviewLeasesV1Result
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		expiredIDs, err := q.ExpirePreviewLeasesV1(ctx, dbsqlc.ExpirePreviewLeasesV1Params{Now: sql.NullTime{Time: now, Valid: true}, RowLimit: input.Limit})
		if err != nil {
			return translate(err)
		}
		result.HasMore = len(expiredIDs) == int(input.Limit)
		for _, id := range expiredIDs {
			lease, err := q.GetPreviewLeaseForReconciliationV1(ctx, id)
			if err != nil {
				return translate(err)
			}
			record := previewLeaseRecordFromRow(lease)
			if _, err := q.WithdrawPreviewDomainsV1(ctx, dbsqlc.WithdrawPreviewDomainsV1Params{
				QuarantineUntil: sql.NullTime{Time: now.Add(previewDomainQuarantine), Valid: true}, Now: sql.NullTime{Time: now, Valid: true},
				PreviewID: record.ID, AccountID: record.AccountID, TerminalPreviewGeneration: record.Generation,
			}); err != nil {
				return translate(err)
			}
			if _, err := tunnelcert.RevokePreviewCertificatesTx(ctx, tx, record.AccountID, record.ID, "preview_lease_terminal", now); err != nil {
				return translate(err)
			}
			result.Expired = append(result.Expired, record)
			if err := insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
				ID: previewLeaseAuditID("preview.expired", record.ID, input.RequestID, input.CorrelationID), AccountID: record.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
				EventType: "preview.expired", ChangeType: "expire", Outcome: "changed", ResourceID: record.ID,
				IdempotencyKey: "preview.expired:" + record.ID, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
				Metadata: map[string]any{"endpoint_released": true}, CreatedAt: now,
			}); err != nil {
				return err
			}
		}
		ownerLostIDs, err := q.MarkLostPreviewLeasesV1(ctx, dbsqlc.MarkLostPreviewLeasesV1Params{
			Now: sql.NullTime{Time: now, Valid: true}, OwnerCutoff: now.Add(-input.OwnerGrace), RowLimit: input.Limit,
		})
		if err != nil {
			return translate(err)
		}
		result.HasMore = result.HasMore || len(ownerLostIDs) == int(input.Limit)
		for _, id := range ownerLostIDs {
			lease, err := q.GetPreviewLeaseForReconciliationV1(ctx, id)
			if err != nil {
				return translate(err)
			}
			record := previewLeaseRecordFromRow(lease)
			if _, err := q.WithdrawPreviewDomainsV1(ctx, dbsqlc.WithdrawPreviewDomainsV1Params{
				QuarantineUntil: sql.NullTime{Time: now.Add(previewDomainQuarantine), Valid: true}, Now: sql.NullTime{Time: now, Valid: true},
				PreviewID: record.ID, AccountID: record.AccountID, TerminalPreviewGeneration: record.Generation,
			}); err != nil {
				return translate(err)
			}
			if _, err := tunnelcert.RevokePreviewCertificatesTx(ctx, tx, record.AccountID, record.ID, "preview_lease_terminal", now); err != nil {
				return translate(err)
			}
			result.OwnerLost = append(result.OwnerLost, record)
			if err := insertPreviewLeaseAudit(ctx, q, previewLeaseAuditInput{
				ID: previewLeaseAuditID("preview.owner_lost", record.ID, input.RequestID, input.CorrelationID), AccountID: record.AccountID, ActorID: input.ActorID, ActorType: input.ActorType,
				EventType: "preview.owner_lost", ChangeType: "expire", Outcome: "changed", ResourceID: record.ID,
				IdempotencyKey: "preview.owner_lost:" + record.ID, RequestID: input.RequestID, CorrelationID: input.CorrelationID,
				Metadata: map[string]any{"endpoint_released": true, "owner_grace_seconds": int(input.OwnerGrace / time.Second)}, CreatedAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

type previewLeaseAuditInput struct {
	ID             string
	AccountID      string
	ActorID        string
	ActorType      string
	EventType      string
	ChangeType     string
	Outcome        string
	ResourceID     string
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
	SourceDeviceID string
	Metadata       map[string]any
	CreatedAt      time.Time
}

func insertPreviewLeaseAudit(ctx context.Context, q *dbsqlc.Queries, input previewLeaseAuditInput) error {
	if input.ID == "" || input.AccountID == "" || input.ActorID == "" || input.EventType == "" || input.ResourceID == "" || input.IdempotencyKey == "" || input.RequestID == "" || input.CorrelationID == "" || !validActorType(input.ActorType) {
		return fmt.Errorf("%w: incomplete preview lease audit event", ErrInvalidInput)
	}
	metadata, err := json.Marshal(input.Metadata)
	if err != nil {
		return err
	}
	metadata, err = canonicalSafeJSON(metadata)
	if err != nil {
		return err
	}
	_, err = q.InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{
		ID: input.ID, AccountID: nullString(input.AccountID), ActorID: nullString(input.ActorID),
		ActorUserID: actorUserID(input.ActorType, input.ActorID), ActorType: input.ActorType, EventType: input.EventType,
		ChangeType: input.ChangeType, Outcome: input.Outcome, ResourceType: "preview_lease", ResourceID: input.ResourceID,
		IdempotencyKey: nullString(input.IdempotencyKey), RequestID: nullString(input.RequestID),
		CorrelationID: nullString(input.CorrelationID), SourceDeviceID: nullString(input.SourceDeviceID),
		Metadata: metadata, CreatedAt: input.CreatedAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return translate(err)
}

func previewLeaseRecordFromRow(row dbsqlc.PreviewLease) PreviewLeaseRecord {
	return PreviewLeaseRecord{PreviewLease: row}
}

func validateCreatePreviewLeaseV1(input CreatePreviewLeaseV1Input) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "lease_id": input.LeaseID, "audit_event_id": input.AuditEventID,
		"account_id": input.AccountID, "actor_id": input.ActorID, "actor_type": input.ActorType,
		"owner_device_id": input.OwnerDeviceID, "owner_session_id": input.OwnerSessionID,
		"target_scheme": input.TargetScheme, "target_address": input.TargetAddress,
		"endpoint_id": input.EndpointID, "endpoint": input.Endpoint, "idempotency_key": input.IdempotencyKey,
		"request_id": input.RequestID, "correlation_id": input.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if len(input.RequestHash) != 32 || !validActorType(input.ActorType) {
		return ErrInvalidInput
	}
	if input.AccessMode != "public" && input.AccessMode != "private" {
		return ErrInvalidInput
	}
	if !ValidPreviewTargetV1(input.TargetScheme, input.TargetAddress, input.AccessMode) {
		return ErrInvalidInput
	}
	if !validPreviewEndpoint(input.Endpoint) || input.LeaseDeadline.IsZero() || input.Now.IsZero() || !input.LeaseDeadline.After(input.Now) {
		return ErrInvalidInput
	}
	if input.UserDeadline.Valid && (input.UserDeadline.Time.IsZero() || input.UserDeadline.Time.Before(input.Now) || input.LeaseDeadline.After(input.UserDeadline.Time)) {
		return ErrInvalidInput
	}
	if len(input.Domains) > 8 {
		return ErrInvalidInput
	}
	seenDomains := make(map[string]struct{}, len(input.Domains))
	for _, domain := range input.Domains {
		hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain.Hostname), "."))
		if hostname == "" || strings.ContainsAny(hostname, "\r\n\x00") {
			return ErrInvalidInput
		}
		if _, duplicate := seenDomains[hostname]; duplicate {
			return ErrInvalidInput
		}
		seenDomains[hostname] = struct{}{}
	}
	return nil
}

func validateRenewPreviewLeaseV1(input RenewPreviewLeaseV1Input) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID,
		"actor_id": input.ActorID, "actor_type": input.ActorType, "preview_id": input.PreviewID,
		"owner_device_id": input.OwnerDeviceID, "owner_session_id": input.OwnerSessionID,
		"idempotency_key": input.IdempotencyKey, "request_id": input.RequestID, "correlation_id": input.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || len(input.RequestHash) != 32 || input.LeaseDeadline.IsZero() || input.Now.IsZero() || !validActorType(input.ActorType) {
		return ErrInvalidInput
	}
	return nil
}

func validateStopPreviewLeaseV1(input StopPreviewLeaseV1Input) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "actor_id": input.ActorID,
		"actor_type": input.ActorType, "preview_id": input.PreviewID, "owner_device_id": input.OwnerDeviceID,
		"owner_session_id": input.OwnerSessionID, "request_id": input.RequestID, "correlation_id": input.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || len(input.RequestHash) != 32 || input.Now.IsZero() || !validActorType(input.ActorType) {
		return ErrInvalidInput
	}
	return nil
}

func validateMarkPreviewLeaseReadyV1(input MarkPreviewLeaseReadyV1Input) error {
	for name, value := range map[string]string{
		"audit_event_id": input.AuditEventID, "account_id": input.AccountID, "actor_id": input.ActorID,
		"actor_type": input.ActorType, "preview_id": input.PreviewID, "request_id": input.RequestID, "correlation_id": input.CorrelationID,
		"allocation_state": input.AllocationState, "edge_state": input.EdgeState, "origin_state": input.OriginState,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || input.Now.IsZero() || !validActorType(input.ActorType) {
		return ErrInvalidInput
	}
	if input.AllocationState != "pending" && input.AllocationState != "ready" && input.AllocationState != "failed" && input.AllocationState != "released" {
		return ErrInvalidInput
	}
	if input.EdgeState != "pending" && input.EdgeState != "ready" && input.EdgeState != "degraded" && input.EdgeState != "down" {
		return ErrInvalidInput
	}
	if input.OriginState != "unknown" && input.OriginState != "ready" && input.OriginState != "degraded" && input.OriginState != "down" {
		return ErrInvalidInput
	}
	return nil
}

func validPreviewEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" || parsed.Port() != "" {
		return false
	}
	host := parsed.Hostname()
	labels := strings.Split(host, ".")
	if len(labels) < 2 || strings.HasPrefix(labels[0], "preview-") {
		return false
	}
	for _, label := range labels {
		if !validPreviewDNSLabel(label) {
			return false
		}
	}
	return true
}

func validPreviewDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// ValidPreviewTargetV1 accepts only local origins. HTTP-family targets are
// loopback host:port values, Unix targets are absolute socket paths, and raw
// TCP is deliberately private-only and may address only loopback or RFC1918/
// RFC4193 IP space. The server never turns a public preview into an arbitrary
// network proxy.
func ValidPreviewTargetV1(scheme, raw, accessMode string) bool {
	if strings.TrimSpace(scheme) != scheme || strings.TrimSpace(accessMode) != accessMode {
		return false
	}
	switch scheme {
	case "http", "https", "h2c":
		return validPreviewHostPort(raw, false)
	case "unix":
		return validPreviewUnixPath(raw)
	case "tcp":
		return accessMode == "private" && validPreviewHostPort(raw, true)
	default:
		return false
	}
}

// validPreviewTargetAddress is retained as the HTTP-family test helper used
// by this package's focused validation tests.
func validPreviewTargetAddress(raw string) bool {
	return ValidPreviewTargetV1("http", raw, "public")
}

func validPreviewHostPort(raw string, allowPrivate bool) bool {
	if len(raw) == 0 || len(raw) > 512 || strings.ContainsAny(raw, "\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	return ip.IsLoopback() || allowPrivate && ip.IsPrivate()
}

func validPreviewUnixPath(raw string) bool {
	if len(raw) == 0 || len(raw) > 512 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n") {
		return false
	}
	return path.IsAbs(raw) && path.Clean(raw) == raw
}

func completePreviewLeaseCreateOperation(ctx context.Context, q *dbsqlc.Queries, accountID, previewID string, now time.Time) error {
	operation, err := q.GetPreviewLeaseCreateOperationV1(ctx, dbsqlc.GetPreviewLeaseCreateOperationV1Params{AccountID: accountID, ResourceID: sql.NullString{String: previewID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return translate(err)
	}
	if operation.State != "pending" && operation.State != "running" {
		return nil
	}
	_, err = q.CompletePreviewLeaseCreateOperationV1(ctx, dbsqlc.CompletePreviewLeaseCreateOperationV1Params{
		UpdatedAt: now, CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operation.ID, AccountID: accountID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return translate(err)
}

func failPreviewLeaseCreateOperation(ctx context.Context, q *dbsqlc.Queries, accountID, previewID, code string, now time.Time) error {
	operation, err := q.GetPreviewLeaseCreateOperationV1(ctx, dbsqlc.GetPreviewLeaseCreateOperationV1Params{AccountID: accountID, ResourceID: sql.NullString{String: previewID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return translate(err)
	}
	if operation.State != "pending" && operation.State != "running" {
		return nil
	}
	_, err = q.FailPreviewLeaseCreateOperationV1(ctx, dbsqlc.FailPreviewLeaseCreateOperationV1Params{
		ErrorCode: sql.NullString{String: code, Valid: true}, UpdatedAt: now,
		CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operation.ID, AccountID: accountID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return translate(err)
}

func translatePreviewLeaseCreateError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "preview_leases_endpoint_key" {
		return ErrEndpointConflict
	}
	return translate(err)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func previewLeaseAuditID(eventType, resourceID, requestID, correlationID string) string {
	digest := sha256.Sum256([]byte(eventType + "\x00" + resourceID + "\x00" + requestID + "\x00" + correlationID))
	return "aud_preview_" + fmt.Sprintf("%x", digest[:16])
}
