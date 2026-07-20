package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var ErrOperationLeaseLost = errors.New("control operation lease lost")

// OperationRunner leases durable operations and runs provider work outside the
// database transaction. Callers classify timeout-after-mutation as uncertain.
type OperationRunner struct {
	store       *db.DB
	maxAttempts int32
	backoff     time.Duration
	lease       time.Duration
	now         func() time.Time
}

func NewOperationRunner(store *db.DB, maxAttempts int32, backoff, lease time.Duration) *OperationRunner {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if backoff <= 0 {
		backoff = time.Second
	}
	if lease <= 0 {
		lease = 30 * time.Second
	}
	return &OperationRunner{store: store, maxAttempts: maxAttempts, backoff: backoff, lease: lease, now: time.Now}
}

func (r *OperationRunner) Lease(ctx context.Context, batchSize int32) ([]dbsqlc.ControlOperation, error) {
	if batchSize < 1 {
		return nil, errors.New("operation batch size must be positive")
	}
	now := r.now()
	return r.store.Queries().LeaseControlOperations(ctx, dbsqlc.LeaseControlOperationsParams{
		Now: now, LeaseExpiresAt: sql.NullTime{Time: now.Add(r.lease), Valid: true}, BatchSize: batchSize,
	})
}

func (r *OperationRunner) Succeed(ctx context.Context, operation dbsqlc.ControlOperation, result []byte) error {
	now := r.now()
	updated, err := r.store.Queries().CompleteControlOperation(ctx, dbsqlc.CompleteControlOperationParams{
		ID: operation.ID, Result: result, Now: sql.NullTime{Time: now, Valid: true}, LeaseExpiresAt: operation.LeaseExpiresAt,
	})
	return operationUpdateResult(updated, err)
}

func (r *OperationRunner) Fail(ctx context.Context, operation dbsqlc.ControlOperation, message string) error {
	now := r.now()
	next := now.Add(r.backoff)
	updated, err := r.store.Queries().MarkControlOperationFailed(ctx, dbsqlc.MarkControlOperationFailedParams{
		ID: operation.ID, LastError: sql.NullString{String: message, Valid: true}, LeaseExpiresAt: operation.LeaseExpiresAt,
		NextAttemptAt: sql.NullTime{Time: next, Valid: true}, MaxAttempts: r.maxAttempts, Now: now,
	})
	return operationUpdateResult(updated, err)
}

func (r *OperationRunner) Uncertain(ctx context.Context, operation dbsqlc.ControlOperation, message string) error {
	now := r.now()
	next := now.Add(r.backoff)
	updated, err := r.store.Queries().MarkControlOperationUncertain(ctx, dbsqlc.MarkControlOperationUncertainParams{
		ID: operation.ID, LastError: sql.NullString{String: message, Valid: true}, LeaseExpiresAt: operation.LeaseExpiresAt,
		NextAttemptAt: sql.NullTime{Time: next, Valid: true}, Now: now,
	})
	return operationUpdateResult(updated, err)
}

func operationUpdateResult(updated int64, err error) error {
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrOperationLeaseLost
	}
	return nil
}
