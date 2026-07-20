package billing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrBillingRecoveryInvalid       = errors.New("billing recovery request is invalid")
	ErrBillingRecoveryConflict      = errors.New("billing recovery idempotency conflict")
	ErrBillingOperationNotUncertain = errors.New("billing operation is not uncertain")
)

var evidenceReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{7,255}$`)

type RecoveryService struct {
	store *db.DB
	audit *audit.Writer
}

func NewRecoveryService(store *db.DB, writer *audit.Writer) *RecoveryService {
	return &RecoveryService{store: store, audit: writer}
}

func (s *RecoveryService) Recover(ctx context.Context, actorID, recoveryKey, kind, operationID, evidenceReference string) error {
	actorID, recoveryKey = strings.TrimSpace(actorID), strings.TrimSpace(recoveryKey)
	kind, operationID = strings.TrimSpace(kind), strings.TrimSpace(operationID)
	evidenceReference = strings.TrimSpace(evidenceReference)
	if s.store == nil || actorID == "" || len(recoveryKey) < 8 || len(recoveryKey) > 256 || operationID == "" || len(operationID) > 256 || !validRecoveryKind(kind) || !evidenceReferencePattern.MatchString(evidenceReference) {
		return ErrBillingRecoveryInvalid
	}
	evidenceHash := sha256.Sum256([]byte(evidenceReference))
	request, _ := json.Marshal([]string{kind, operationID, evidenceReference})
	requestHash := sha256.Sum256(request)
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().ReserveBillingUncertainRecovery(ctx, dbsqlc.ReserveBillingUncertainRecoveryParams{IdempotencyKey: recoveryKey, OperationKind: kind, OperationID: operationID, RequestHash: requestHash[:], ActorUserID: sql.NullString{String: actorID, Valid: true}})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetBillingUncertainRecovery(ctx, recoveryKey)
			if getErr != nil {
				return getErr
			}
			if existing.OperationKind != kind || existing.OperationID != operationID || !bytes.Equal(existing.RequestHash, requestHash[:]) {
				return ErrBillingRecoveryConflict
			}
			return nil
		}
		var updated int64
		switch kind {
		case "checkout":
			updated, err = tx.Queries().RecoverUncertainBillingCheckout(ctx, operationID)
		case "portal":
			updated, err = tx.Queries().RecoverUncertainBillingPortal(ctx, operationID)
		case "subscription_update":
			updated, err = tx.Queries().RecoverUncertainBillingSubscriptionUpdate(ctx, operationID)
		case "auto_topup":
			updated, err = tx.Queries().RecoverUncertainBillingAutoTopup(ctx, operationID)
		}
		if err != nil {
			return err
		}
		if updated != 1 {
			return ErrBillingOperationNotUncertain
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "billing.uncertain_operation_recovered", ResourceType: "billing_" + kind, ResourceID: operationID, IdempotencyKey: recoveryKey, Metadata: map[string]any{"evidence_sha256": hex.EncodeToString(evidenceHash[:])}})
	})
}

func validRecoveryKind(kind string) bool {
	return kind == "checkout" || kind == "portal" || kind == "subscription_update" || kind == "auto_topup"
}
