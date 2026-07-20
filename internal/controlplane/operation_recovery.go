package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrRecoveryKeyConflict      = errors.New("operation recovery key conflict")
	ErrOperationNotDeadLettered = errors.New("operation is not dead-lettered")
)

type OperationRecoveryService struct {
	store *db.DB
	audit *audit.Writer
}

func NewOperationRecoveryService(store *db.DB, writer *audit.Writer) *OperationRecoveryService {
	return &OperationRecoveryService{store: store, audit: writer}
}

func (s *OperationRecoveryService) Recover(ctx context.Context, actorID, recoveryKey, operationID string, now time.Time) error {
	recoveryKey = strings.TrimSpace(recoveryKey)
	operationID = strings.TrimSpace(operationID)
	if recoveryKey == "" || operationID == "" || len(recoveryKey) > 256 {
		return fmt.Errorf("recovery key and operation id are required")
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().ReserveControlOperationRecovery(ctx, dbsqlc.ReserveControlOperationRecoveryParams{OperationKey: recoveryKey, OperationID: operationID, ActorUserID: sql.NullString{String: actorID, Valid: actorID != ""}})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetControlOperationRecovery(ctx, recoveryKey)
			if getErr != nil {
				return getErr
			}
			if existing.OperationID != operationID {
				return ErrRecoveryKeyConflict
			}
			return nil
		}
		updated, err := tx.Queries().RecoverDeadLetterControlOperation(ctx, dbsqlc.RecoverDeadLetterControlOperationParams{ID: operationID, Now: now.UTC()})
		if err != nil {
			return err
		}
		if updated == 0 {
			return ErrOperationNotDeadLettered
		}
		if s.audit != nil {
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "control.operation_recovered", ResourceType: "control_operation", ResourceID: operationID, IdempotencyKey: recoveryKey})
		}
		return nil
	})
}
