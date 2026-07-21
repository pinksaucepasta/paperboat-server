package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var ErrHostedProviderOperationNotRecoverable = errors.New("hosted provider operation is not recoverable")

type HostedProviderRecoveryService struct {
	store *db.DB
	audit *audit.Writer
}

func NewHostedProviderRecoveryService(store *db.DB, writer *audit.Writer) *HostedProviderRecoveryService {
	return &HostedProviderRecoveryService{store: store, audit: writer}
}

func (s *HostedProviderRecoveryService) Recover(ctx context.Context, actorID, operationKey, operationID, action, evidenceReference string) error {
	operationKey, operationID = strings.TrimSpace(operationKey), strings.TrimSpace(operationID)
	action, evidenceReference = strings.TrimSpace(action), strings.TrimSpace(evidenceReference)
	if operationKey == "" || operationID == "" || len(operationKey) > 256 || (action != "confirm_deleted" && action != "retry") || evidenceReference == "" || len(evidenceReference) > 512 {
		return fmt.Errorf("invalid hosted provider recovery request")
	}
	evidenceDigest := sha256.Sum256([]byte(evidenceReference))
	evidenceHash := hex.EncodeToString(evidenceDigest[:])
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().ReserveHostedProviderOperationRecovery(ctx, dbsqlc.ReserveHostedProviderOperationRecoveryParams{
			OperationKey: operationKey, ProviderOperationID: operationID,
			ActorUserID: sql.NullString{String: actorID, Valid: actorID != ""}, Action: action, EvidenceReference: evidenceHash,
		})
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetHostedProviderOperationRecovery(ctx, operationKey)
			if getErr != nil {
				return getErr
			}
			if existing.ProviderOperationID != operationID || existing.Action != action || existing.EvidenceReference != evidenceHash {
				return ErrRecoveryKeyConflict
			}
			return nil
		}
		if err != nil {
			return err
		}
		rows, err := tx.Queries().RecoverUncertainHostedProviderOperation(ctx, dbsqlc.RecoverUncertainHostedProviderOperationParams{ID: operationID, Action: action})
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrHostedProviderOperationNotRecoverable
		}
		if s.audit != nil {
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "hosted.provider_operation_recovered", ResourceType: "hosted_provider_operation", ResourceID: operationID, IdempotencyKey: operationKey, Metadata: map[string]any{"action": action, "evidence_sha256": evidenceHash}})
		}
		return nil
	})
}
