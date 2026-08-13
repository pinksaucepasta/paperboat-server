package managedssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

func (r *SQLRepository) RegisterClient(ctx context.Context, request RegisterClientRequest, proposed ClientKey) (ClientKey, error) {
	var result ClientKey
	requestHash := managedOperationHash(struct {
		SessionID string
		PublicKey string
	}{request.CLIClientSessionID, proposed.PublicKey})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveManagedSSHClientAuthorityForUpdate(ctx, dbsqlc.ResolveManagedSSHClientAuthorityForUpdateParams{CLIClientSessionID: request.CLIClientSessionID, UserID: request.UserID}); err != nil {
			return authorityError(err)
		}
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.UserID, "client_key_register", requestHash)
		if err != nil {
			return err
		}
		if operation != nil {
			row, getErr := q.GetManagedSSHClientKeyByFingerprint(ctx, proposed.Fingerprint[:])
			if getErr != nil || !sameClientKey(row, proposed) {
				return ErrConflict
			}
			result, err = clientKeyFromRow(row)
			return err
		}
		active, err := q.GetActiveManagedSSHClientKeyForUpdate(ctx, request.CLIClientSessionID)
		if err == nil {
			if !sameClientKey(active, proposed) {
				return ErrConflict
			}
			result, err = clientKeyFromRow(active)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.UserID, "client_key_register", requestHash, hex.EncodeToString(proposed.Fingerprint[:]), result.ReconciliationVersion, request.Now)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		existing, err := q.GetManagedSSHClientKeyByFingerprint(ctx, proposed.Fingerprint[:])
		if err == nil {
			if !sameClientKey(existing, proposed) {
				return ErrConflict
			}
			result, err = clientKeyFromRow(existing)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.UserID, "client_key_register", requestHash, hex.EncodeToString(proposed.Fingerprint[:]), result.ReconciliationVersion, request.Now)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		created, err := q.CreateManagedSSHClientKey(ctx, dbsqlc.CreateManagedSSHClientKeyParams{Fingerprint: proposed.Fingerprint[:], UserID: proposed.UserID, CLIClientSessionID: proposed.CLIClientSessionID, Algorithm: proposed.Algorithm, PublicKey: proposed.PublicKey, ReconciliationVersion: int64(proposed.ReconciliationVersion), CreatedAt: proposed.CreatedAt})
		if err != nil {
			return err
		}
		result, err = clientKeyFromRow(created)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.UserID, "client_key_register", requestHash, hex.EncodeToString(proposed.Fingerprint[:]), result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorUser, EventType: "managed_ssh.client_key_registered", ResourceType: "managed_ssh_client_key", ResourceID: hex.EncodeToString(proposed.Fingerprint[:]), IdempotencyKey: request.OperationID, Metadata: map[string]any{"cli_client_session_id": request.CLIClientSessionID, "algorithm": proposed.Algorithm, "reconciliation_version": proposed.ReconciliationVersion}})
	})
	return result, conflictOnUnique(err)
}

func (r *SQLRepository) RevokeClient(ctx context.Context, request RevokeClientRequest) (ClientKey, error) {
	var result ClientKey
	requestHash := managedOperationHash(struct {
		Fingerprint [32]byte
		Reason      string
	}{request.Fingerprint, request.Reason})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.ActorUserID, "client_key_revoke", requestHash)
		if err != nil {
			return err
		}
		row, err := q.GetManagedSSHClientKeyByFingerprint(ctx, request.Fingerprint[:])
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if row.UserID != request.ActorUserID {
			return ErrConflict
		}
		if row.State == "revoked" {
			if row.RevocationReason.String != request.Reason || operation == nil {
				return ErrConflict
			}
			result, err = clientKeyFromRow(row)
			return err
		}
		row, err = q.RevokeManagedSSHClientKey(ctx, dbsqlc.RevokeManagedSSHClientKeyParams{RevokedAt: sql.NullTime{Time: request.Now, Valid: true}, RevocationReason: sql.NullString{String: request.Reason, Valid: true}, Fingerprint: request.Fingerprint[:]})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		result, err = clientKeyFromRow(row)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "client_key_revoke", requestHash, hex.EncodeToString(request.Fingerprint[:]), result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.ActorUserID, ActorType: audit.ActorUser, EventType: "managed_ssh.client_key_revoked", ResourceType: "managed_ssh_client_key", ResourceID: hex.EncodeToString(request.Fingerprint[:]), IdempotencyKey: request.OperationID, Metadata: map[string]any{"reason": request.Reason, "reconciliation_version": result.ReconciliationVersion}})
	})
	return result, err
}

func (r *SQLRepository) ListClientKeys(ctx context.Context, request ListClientKeysRequest) (ClientKeySet, error) {
	result := ClientKeySet{UserMachineID: request.UserMachineID, MachineGeneration: request.MachineGeneration}
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		rows, err := tx.Queries().ListActiveManagedSSHClientKeysForUser(ctx, request.ActorUserID)
		if err != nil {
			return err
		}
		result.Keys = make([]ClientKey, 0, len(rows))
		for _, row := range rows {
			key, err := clientKeyFromRow(row)
			if err != nil {
				return err
			}
			result.Keys = append(result.Keys, key)
		}
		return nil
	})
	return result, err
}

func (r *SQLRepository) RegisterTarget(ctx context.Context, request RegisterTargetRequest) (MachineTarget, error) {
	var result MachineTarget
	requestHash := managedOperationHash(struct {
		MachineID  string
		Generation uint64
		OSUser     string
		Port       uint16
	}{request.UserMachineID, request.MachineGeneration, request.OSUser, request.TargetPort})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.ActorUserID, "target_register", requestHash)
		if err != nil {
			return err
		}
		row, err := q.GetMachineSSHTargetForUpdate(ctx, request.UserMachineID)
		if operation != nil {
			if err != nil || row.MachineGeneration != int64(request.MachineGeneration) || row.OsUser != request.OSUser || row.TargetPort != int32(request.TargetPort) {
				return ErrConflict
			}
			result, err = machineTargetFromRow(row)
			return err
		}
		eventType := "managed_ssh.machine_target_registered"
		if errors.Is(err, sql.ErrNoRows) {
			row, err = q.CreateMachineSSHTarget(ctx, dbsqlc.CreateMachineSSHTargetParams{UserMachineID: request.UserMachineID, MachineGeneration: int64(request.MachineGeneration), OsUser: request.OSUser, TargetPort: int32(request.TargetPort), Now: request.Now})
		} else if err == nil && row.MachineGeneration == int64(request.MachineGeneration) {
			if row.OsUser != request.OSUser || row.TargetPort != int32(request.TargetPort) {
				return ErrConflict
			}
			result, err = machineTargetFromRow(row)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "target_register", requestHash, request.UserMachineID, result.ReconciliationVersion, request.Now)
		} else if err == nil && row.MachineGeneration < int64(request.MachineGeneration) {
			eventType = "managed_ssh.machine_target_reenrolled"
			row, err = q.ReplaceMachineSSHTargetGeneration(ctx, dbsqlc.ReplaceMachineSSHTargetGenerationParams{MachineGeneration: int64(request.MachineGeneration), OsUser: request.OSUser, TargetPort: int32(request.TargetPort), Now: request.Now, UserMachineID: request.UserMachineID})
		} else if err == nil {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		result, err = machineTargetFromRow(row)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "target_register", requestHash, request.UserMachineID, result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.ActorUserID, ActorType: audit.ActorUser, EventType: eventType, ResourceType: "machine_ssh_target", ResourceID: request.UserMachineID, IdempotencyKey: request.OperationID, Metadata: map[string]any{"machine_generation": result.MachineGeneration, "target_port": result.TargetPort, "reconciliation_version": result.ReconciliationVersion}})
	})
	return result, conflictOnUnique(err)
}

func (r *SQLRepository) UpdateTargetPort(ctx context.Context, request UpdateTargetPortRequest) (MachineTarget, error) {
	var result MachineTarget
	requestHash := managedOperationHash(struct {
		MachineID       string
		Generation      uint64
		Port            uint16
		ExpectedVersion uint64
	}{request.UserMachineID, request.MachineGeneration, request.TargetPort, request.ExpectedReconciliationVersion})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.ActorUserID, "target_update", requestHash)
		if err != nil {
			return err
		}
		current, err := q.GetMachineSSHTargetForUpdate(ctx, request.UserMachineID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if operation != nil {
			if current.MachineGeneration != int64(request.MachineGeneration) || current.TargetPort != int32(request.TargetPort) || current.ReconciliationVersion <= int64(request.ExpectedReconciliationVersion) {
				return ErrConflict
			}
			result, err = machineTargetFromRow(current)
			return err
		}
		if current.MachineGeneration != int64(request.MachineGeneration) || current.ReconciliationVersion != int64(request.ExpectedReconciliationVersion) {
			return ErrConflict
		}
		if current.TargetPort == int32(request.TargetPort) {
			result, err = machineTargetFromRow(current)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "target_update", requestHash, request.UserMachineID, result.ReconciliationVersion, request.Now)
		}
		row, err := q.UpdateMachineSSHTargetPort(ctx, dbsqlc.UpdateMachineSSHTargetPortParams{TargetPort: int32(request.TargetPort), Now: request.Now, UserMachineID: request.UserMachineID, MachineGeneration: int64(request.MachineGeneration), ExpectedReconciliationVersion: int64(request.ExpectedReconciliationVersion)})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		result, err = machineTargetFromRow(row)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "target_update", requestHash, request.UserMachineID, result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.ActorUserID, ActorType: audit.ActorUser, EventType: "managed_ssh.machine_target_port_updated", ResourceType: "machine_ssh_target", ResourceID: request.UserMachineID, IdempotencyKey: request.OperationID, Metadata: map[string]any{"machine_generation": result.MachineGeneration, "target_port": result.TargetPort, "reconciliation_version": result.ReconciliationVersion}})
	})
	return result, err
}

func (r *SQLRepository) GetTarget(ctx context.Context, request GetTargetRequest) (MachineTarget, error) {
	var result MachineTarget
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		row, err := q.GetMachineSSHTargetForUpdate(ctx, request.UserMachineID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if row.MachineGeneration != int64(request.MachineGeneration) {
			return ErrUnavailable
		}
		result, err = machineTargetFromRow(row)
		return err
	})
	return result, err
}

func (r *SQLRepository) ObserveHost(ctx context.Context, request ObserveHostRequest, proposed HostKeySet) (HostKeySet, error) {
	var result HostKeySet
	requestHash := managedOperationHash(struct {
		SetID                 string
		MachineID             string
		MachineGeneration     uint64
		ObservationGeneration uint64
		Fingerprint           [32]byte
	}{request.SetID, request.UserMachineID, request.MachineGeneration, request.ObservationGeneration, proposed.Fingerprint})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		var supersededSetID, rejectedPendingSetID string
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.UserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.UserID, "host_keys_observe", requestHash)
		if err != nil {
			return err
		}
		if operation != nil {
			row, getErr := q.GetMachineSSHHostKeySetByID(ctx, operation.ResourceID)
			if getErr != nil || row.UserMachineID != request.UserMachineID || row.MachineGeneration != int64(request.MachineGeneration) || !bytes.Equal(row.SetFingerprint, proposed.Fingerprint[:]) {
				return ErrConflict
			}
			result, err = loadHostKeySet(ctx, q, row)
			return err
		}
		existing, err := q.GetMachineSSHHostKeySetByObservation(ctx, dbsqlc.GetMachineSSHHostKeySetByObservationParams{UserMachineID: request.UserMachineID, MachineGeneration: int64(request.MachineGeneration), ObservationGeneration: int64(request.ObservationGeneration)})
		if err == nil {
			if existing.ID != proposed.ID || !bytes.Equal(existing.SetFingerprint, proposed.Fingerprint[:]) {
				return ErrConflict
			}
			result, err = loadHostKeySet(ctx, q, existing)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.UserID, "host_keys_observe", requestHash, result.ID, result.ReconciliationVersion, request.Now)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		active, activeErr := q.GetActiveMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
		if activeErr == nil && active.MachineGeneration == int64(request.MachineGeneration) && bytes.Equal(active.SetFingerprint, proposed.Fingerprint[:]) {
			result, err = loadHostKeySet(ctx, q, active)
			if err != nil {
				return err
			}
			return createManagedOperation(ctx, q, request.OperationID, request.UserID, "host_keys_observe", requestHash, result.ID, result.ReconciliationVersion, request.Now)
		}
		if activeErr != nil && !errors.Is(activeErr, sql.ErrNoRows) {
			return activeErr
		}
		if activeErr == nil && active.MachineGeneration != int64(request.MachineGeneration) {
			pending, pendingErr := q.GetPendingMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
			if pendingErr == nil {
				rejected, err := q.RejectPendingMachineSSHHostKeySet(ctx, dbsqlc.RejectPendingMachineSSHHostKeySetParams{RejectedAt: sql.NullTime{Time: proposed.ObservedAt, Valid: true}, RejectionReason: sql.NullString{String: "machine_reenrolled", Valid: true}, ID: pending.ID})
				if err != nil {
					return err
				}
				rejectedPendingSetID = rejected.ID
			} else if !errors.Is(pendingErr, sql.ErrNoRows) {
				return pendingErr
			}
			superseded, err := q.SupersedeActiveMachineSSHHostKeySet(ctx, active.ID)
			if err != nil {
				return err
			}
			supersededSetID = superseded.ID
			activeErr = sql.ErrNoRows
		}
		state := "active"
		promotedAt := sql.NullTime{Time: proposed.ObservedAt, Valid: true}
		if activeErr == nil {
			state, promotedAt = "pending", sql.NullTime{}
			pending, pendingErr := q.GetPendingMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
			if pendingErr == nil && !bytes.Equal(pending.SetFingerprint, proposed.Fingerprint[:]) {
				return ErrConflict
			}
			if pendingErr == nil {
				result, err = loadHostKeySet(ctx, q, pending)
				if err != nil {
					return err
				}
				return createManagedOperation(ctx, q, request.OperationID, request.UserID, "host_keys_observe", requestHash, result.ID, result.ReconciliationVersion, request.Now)
			}
			if !errors.Is(pendingErr, sql.ErrNoRows) {
				return pendingErr
			}
		}
		for _, key := range proposed.Keys {
			owner, ownerErr := q.GetMachineSSHHostKeyOwner(ctx, key.Fingerprint[:])
			if ownerErr == nil {
				if owner.UserMachineID != request.UserMachineID || owner.Algorithm != key.Algorithm || owner.PublicKey != key.PublicKey {
					return ErrConflict
				}
				continue
			}
			if !errors.Is(ownerErr, sql.ErrNoRows) {
				return ownerErr
			}
			if _, err := q.CreateMachineSSHHostKeyOwner(ctx, dbsqlc.CreateMachineSSHHostKeyOwnerParams{Fingerprint: key.Fingerprint[:], UserMachineID: request.UserMachineID, Algorithm: key.Algorithm, PublicKey: key.PublicKey, FirstObservedAt: proposed.ObservedAt}); err != nil {
				return err
			}
		}
		created, err := q.CreateMachineSSHHostKeySet(ctx, dbsqlc.CreateMachineSSHHostKeySetParams{ID: proposed.ID, UserMachineID: proposed.UserMachineID, MachineGeneration: int64(proposed.MachineGeneration), ObservationGeneration: int64(proposed.ObservationGeneration), SetFingerprint: proposed.Fingerprint[:], State: state, ReconciliationVersion: int64(proposed.ReconciliationVersion), ObservedAt: proposed.ObservedAt, PromotedAt: promotedAt})
		if err != nil {
			return err
		}
		for ordinal, key := range proposed.Keys {
			if err := q.AddMachineSSHHostKeyToSet(ctx, dbsqlc.AddMachineSSHHostKeyToSetParams{SetID: proposed.ID, UserMachineID: proposed.UserMachineID, Fingerprint: key.Fingerprint[:], Ordinal: int16(ordinal)}); err != nil {
				return err
			}
		}
		result, err = loadHostKeySet(ctx, q, created)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.UserID, "host_keys_observe", requestHash, result.ID, result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		metadata := map[string]any{"user_machine_id": request.UserMachineID, "machine_generation": request.MachineGeneration, "observation_generation": request.ObservationGeneration, "set_fingerprint": hex.EncodeToString(result.Fingerprint[:]), "key_count": len(result.Keys), "state": result.State}
		if supersededSetID != "" {
			metadata["superseded_set_id"] = supersededSetID
		}
		if rejectedPendingSetID != "" {
			metadata["rejected_pending_set_id"] = rejectedPendingSetID
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorUser, EventType: "managed_ssh.host_key_set_observed", ResourceType: "machine_ssh_host_key_set", ResourceID: result.ID, IdempotencyKey: request.OperationID, Metadata: metadata})
	})
	return result, conflictOnUnique(err)
}

func (r *SQLRepository) PromoteHost(ctx context.Context, request PromoteHostRequest) (HostKeySet, error) {
	var result HostKeySet
	requestHash := managedOperationHash(struct {
		MachineID   string
		Generation  uint64
		SetID       string
		Fingerprint [32]byte
	}{request.UserMachineID, request.MachineGeneration, request.SetID, request.ExpectedFingerprint})
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		operation, err := managedOperationReplay(ctx, q, request.OperationID, request.ActorUserID, "host_keys_promote", requestHash)
		if err != nil {
			return err
		}
		if operation != nil {
			active, getErr := q.GetMachineSSHHostKeySetByID(ctx, operation.ResourceID)
			if getErr != nil || active.State != "active" || active.ID != request.SetID || active.MachineGeneration != int64(request.MachineGeneration) || !bytes.Equal(active.SetFingerprint, request.ExpectedFingerprint[:]) {
				return ErrConflict
			}
			result, err = loadHostKeySet(ctx, q, active)
			return err
		}
		pending, err := q.GetPendingMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if pending.ID != request.SetID || pending.MachineGeneration != int64(request.MachineGeneration) || !bytes.Equal(pending.SetFingerprint, request.ExpectedFingerprint[:]) {
			return ErrConflict
		}
		active, err := q.GetActiveMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if _, err := q.SupersedeActiveMachineSSHHostKeySet(ctx, active.ID); err != nil {
			return err
		}
		promoted, err := q.PromotePendingMachineSSHHostKeySet(ctx, dbsqlc.PromotePendingMachineSSHHostKeySetParams{PromotedAt: sql.NullTime{Time: request.Now, Valid: true}, ID: pending.ID})
		if err != nil {
			return err
		}
		result, err = loadHostKeySet(ctx, q, promoted)
		if err != nil {
			return err
		}
		if err := createManagedOperation(ctx, q, request.OperationID, request.ActorUserID, "host_keys_promote", requestHash, result.ID, result.ReconciliationVersion, request.Now); err != nil {
			return err
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.ActorUserID, ActorType: audit.ActorUser, EventType: "managed_ssh.host_key_set_promoted", ResourceType: "machine_ssh_host_key_set", ResourceID: result.ID, IdempotencyKey: request.OperationID, Metadata: map[string]any{"user_machine_id": request.UserMachineID, "old_set_id": active.ID, "new_set_id": result.ID, "set_fingerprint": hex.EncodeToString(result.Fingerprint[:]), "machine_generation": request.MachineGeneration}})
	})
	return result, err
}

func (r *SQLRepository) GetActiveHost(ctx context.Context, request GetHostKeySetRequest) (HostKeySet, error) {
	return r.getHost(ctx, request, false)
}

func (r *SQLRepository) GetPendingHost(ctx context.Context, request GetHostKeySetRequest) (HostKeySet, error) {
	return r.getHost(ctx, request, true)
}

func (r *SQLRepository) getHost(ctx context.Context, request GetHostKeySetRequest, pending bool) (HostKeySet, error) {
	var result HostKeySet
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.ResolveMachineSSHHostKeyAuthorityForUpdate(ctx, dbsqlc.ResolveMachineSSHHostKeyAuthorityForUpdateParams{UserMachineID: request.UserMachineID, UserID: request.ActorUserID, MachineGeneration: int64(request.MachineGeneration)}); err != nil {
			return authorityError(err)
		}
		var row dbsqlc.MachineSshHostKeySet
		var err error
		if pending {
			row, err = q.GetPendingMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
		} else {
			row, err = q.GetActiveMachineSSHHostKeySetForUpdate(ctx, request.UserMachineID)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		if row.MachineGeneration != int64(request.MachineGeneration) {
			return ErrUnavailable
		}
		result, err = loadHostKeySet(ctx, q, row)
		return err
	})
	return result, err
}

func loadHostKeySet(ctx context.Context, q *dbsqlc.Queries, row dbsqlc.MachineSshHostKeySet) (HostKeySet, error) {
	result, err := hostKeySetFromRow(row)
	if err != nil {
		return HostKeySet{}, err
	}
	members, err := q.ListMachineSSHHostKeysForSet(ctx, row.ID)
	if err != nil {
		return HostKeySet{}, err
	}
	result.Keys = make([]HostKey, 0, len(members))
	for _, member := range members {
		fingerprint, err := fingerprintFromBytes(member.Fingerprint)
		if err != nil {
			return HostKeySet{}, err
		}
		result.Keys = append(result.Keys, HostKey{Fingerprint: fingerprint, Algorithm: member.Algorithm, PublicKey: member.PublicKey})
	}
	return result, nil
}

func clientKeyFromRow(row dbsqlc.ManagedSshClientKey) (ClientKey, error) {
	fingerprint, err := fingerprintFromBytes(row.Fingerprint)
	if err != nil {
		return ClientKey{}, err
	}
	return ClientKey{Fingerprint: fingerprint, UserID: row.UserID, CLIClientSessionID: row.CLIClientSessionID, Algorithm: row.Algorithm, PublicKey: row.PublicKey, State: row.State, ReconciliationVersion: uint64(row.ReconciliationVersion), CreatedAt: row.CreatedAt, RevokedAt: nullTime(row.RevokedAt), RevocationReason: row.RevocationReason.String}, nil
}

func hostKeySetFromRow(row dbsqlc.MachineSshHostKeySet) (HostKeySet, error) {
	fingerprint, err := fingerprintFromBytes(row.SetFingerprint)
	if err != nil {
		return HostKeySet{}, err
	}
	return HostKeySet{ID: row.ID, UserMachineID: row.UserMachineID, MachineGeneration: uint64(row.MachineGeneration), ObservationGeneration: uint64(row.ObservationGeneration), Fingerprint: fingerprint, State: row.State, ReconciliationVersion: uint64(row.ReconciliationVersion), ObservedAt: row.ObservedAt, PromotedAt: nullTime(row.PromotedAt)}, nil
}

func machineTargetFromRow(row dbsqlc.MachineSshTarget) (MachineTarget, error) {
	if row.MachineGeneration <= 0 || row.TargetPort <= 0 || row.TargetPort > 65535 || row.ReconciliationVersion <= 0 || !validOSUser(row.OsUser) || row.CreatedAt.IsZero() || row.UpdatedAt.Before(row.CreatedAt) {
		return MachineTarget{}, ErrUnavailable
	}
	return MachineTarget{UserMachineID: row.UserMachineID, MachineGeneration: uint64(row.MachineGeneration), OSUser: row.OsUser, TargetPort: uint16(row.TargetPort), ReconciliationVersion: uint64(row.ReconciliationVersion), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

func fingerprintFromBytes(value []byte) ([32]byte, error) {
	var result [32]byte
	if len(value) != len(result) {
		return result, fmt.Errorf("managed SSH authority contains an invalid fingerprint")
	}
	copy(result[:], value)
	return result, nil
}

func sameClientKey(row dbsqlc.ManagedSshClientKey, proposed ClientKey) bool {
	return bytes.Equal(row.Fingerprint, proposed.Fingerprint[:]) && row.UserID == proposed.UserID && row.CLIClientSessionID == proposed.CLIClientSessionID && row.Algorithm == proposed.Algorithm && row.PublicKey == proposed.PublicKey
}

func authorityError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnavailable
	}
	return err
}

func conflictOnUnique(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

func managedOperationHash(value any) [sha256.Size]byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("managed SSH operation hash contains an unsupported value")
	}
	return sha256.Sum256(encoded)
}

func managedOperationReplay(ctx context.Context, q *dbsqlc.Queries, operationID, userID, kind string, requestHash [sha256.Size]byte) (*dbsqlc.ManagedSshOperation, error) {
	operation, err := q.GetManagedSSHOperationForUpdate(ctx, operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if operation.UserID != userID || operation.OperationKind != kind || !bytes.Equal(operation.RequestHash, requestHash[:]) {
		return nil, ErrConflict
	}
	return &operation, nil
}

func createManagedOperation(ctx context.Context, q *dbsqlc.Queries, operationID, userID, kind string, requestHash [sha256.Size]byte, resourceID string, revision uint64, now time.Time) error {
	if revision == 0 || revision > math.MaxInt64 {
		return ErrInvalid
	}
	_, err := q.CreateManagedSSHOperation(ctx, dbsqlc.CreateManagedSSHOperationParams{
		OperationID: operationID, UserID: userID, OperationKind: kind, RequestHash: requestHash[:],
		ResourceID: resourceID, ResultRevision: int64(revision), CreatedAt: now,
	})
	return conflictOnUnique(err)
}

func nullTime(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time
}
