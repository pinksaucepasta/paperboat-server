package diagnosticuploads

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type SQLRepository struct {
	store *db.DB
	audit *audit.Writer
}

func NewSQLRepository(store *db.DB, writer *audit.Writer) (*SQLRepository, error) {
	if store == nil || writer == nil {
		return nil, ErrInvalid
	}
	return &SQLRepository{store: store, audit: writer}, nil
}

func (r *SQLRepository) Reserve(ctx context.Context, request CreateRequest, hash [32]byte, proposed Intent) (Intent, error) {
	var result Intent
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, err := tx.Queries().GetDiagnosticUploadIntentByOperationForUpdate(ctx, dbsqlc.GetDiagnosticUploadIntentByOperationForUpdateParams{UserID: request.UserID, OperationKey: request.OperationKey})
		if err == nil {
			if !bytes.Equal(existing.RequestHash, hash[:]) {
				return ErrIdempotencyConflict
			}
			result = intentFromRow(existing)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := tx.Queries().CreateDiagnosticUploadIntent(ctx, dbsqlc.CreateDiagnosticUploadIntentParams{
			ID: proposed.ID, UserID: proposed.UserID, CLIClientSessionID: proposed.CLIClientSessionID,
			OperationKey: proposed.OperationKey, RequestHash: hash[:], CorrelationID: proposed.CorrelationID,
			ObjectKey: proposed.ObjectKey, ExpectedBytes: proposed.Bytes, Sha256: proposed.SHA256[:],
			Categories: proposed.Categories, ExpiresAt: proposed.ExpiresAt, RetainUntil: proposed.RetainUntil, CreatedAt: proposed.CreatedAt,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: proposed.UserID, ActorType: audit.ActorUser,
			EventType: "diagnostic_upload.authorized", ResourceType: "diagnostic_upload", ResourceID: proposed.ID,
			IdempotencyKey: proposed.OperationKey, Metadata: map[string]any{"bytes": proposed.Bytes, "correlation_id": proposed.CorrelationID, "expires_at": proposed.ExpiresAt}}); err != nil {
			return err
		}
		result = intentFromRow(row)
		return nil
	})
	return result, err
}

func (r *SQLRepository) Get(ctx context.Context, userID, intentID string) (Intent, error) {
	var result Intent
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := tx.Queries().GetDiagnosticUploadIntentForUserForUpdate(ctx, dbsqlc.GetDiagnosticUploadIntentForUserForUpdateParams{ID: intentID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		result = intentFromRow(row)
		return nil
	})
	return result, err
}

func (r *SQLRepository) Complete(ctx context.Context, userID, intentID string, metadata ObjectMetadata, now time.Time) (Intent, error) {
	var result Intent
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		current, err := tx.Queries().GetDiagnosticUploadIntentForUserForUpdate(ctx, dbsqlc.GetDiagnosticUploadIntentForUserForUpdateParams{ID: intentID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current.State == "uploaded" {
			result = intentFromRow(current)
			return nil
		}
		if current.State != "pending" || !current.ExpiresAt.After(now) {
			return ErrExpired
		}
		if current.ExpectedBytes != metadata.Bytes || !bytes.Equal(current.Sha256, metadata.SHA256[:]) {
			return ErrUploadMismatch
		}
		row, err := tx.Queries().CompleteDiagnosticUploadIntent(ctx, dbsqlc.CompleteDiagnosticUploadIntentParams{UploadedAt: sql.NullTime{Time: now, Valid: true}, ObjectEtag: sql.NullString{String: metadata.ETag, Valid: true}, ID: intentID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrExpired
		}
		if err != nil {
			return err
		}
		if err := r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser,
			EventType: "diagnostic_upload.completed", ResourceType: "diagnostic_upload", ResourceID: intentID,
			IdempotencyKey: current.OperationKey + ":completed", Metadata: map[string]any{"bytes": current.ExpectedBytes, "correlation_id": current.CorrelationID}}); err != nil {
			return err
		}
		result = intentFromRow(row)
		return nil
	})
	return result, err
}

func (r *SQLRepository) CleanupCandidates(ctx context.Context, now time.Time, limit int) ([]CleanupItem, error) {
	rows, err := r.store.Queries().ListDiagnosticUploadCleanupCandidates(ctx, dbsqlc.ListDiagnosticUploadCleanupCandidatesParams{Now: now, RowLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	result := make([]CleanupItem, 0, len(rows))
	for _, row := range rows {
		result = append(result, CleanupItem{ID: row.ID, ObjectKey: row.ObjectKey, State: row.State, ExpiresAt: row.ExpiresAt, RetainUntil: row.RetainUntil})
	}
	return result, nil
}

func (r *SQLRepository) MarkExpired(ctx context.Context, id string, now time.Time) error {
	_, err := r.store.Queries().MarkDiagnosticUploadIntentExpired(ctx, dbsqlc.MarkDiagnosticUploadIntentExpiredParams{ID: id, Now: now})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func (r *SQLRepository) DeleteRetained(ctx context.Context, id string, now time.Time) error {
	_, err := r.store.Queries().DeleteRetainedDiagnosticUploadIntent(ctx, dbsqlc.DeleteRetainedDiagnosticUploadIntentParams{ID: id, Now: now})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func intentFromRow(row dbsqlc.DiagnosticUploadIntent) Intent {
	result := Intent{ID: row.ID, UserID: row.UserID, CLIClientSessionID: row.CLIClientSessionID, OperationKey: row.OperationKey,
		CorrelationID: row.CorrelationID, ObjectKey: row.ObjectKey, Bytes: row.ExpectedBytes, Categories: append([]string(nil), row.Categories...),
		State: row.State, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, RetainUntil: row.RetainUntil}
	copy(result.RequestHash[:], row.RequestHash)
	copy(result.SHA256[:], row.Sha256)
	if row.UploadedAt.Valid {
		result.UploadedAt = row.UploadedAt.Time
	}
	if row.ObjectEtag.Valid {
		result.ObjectETag = row.ObjectEtag.String
	}
	return result
}
