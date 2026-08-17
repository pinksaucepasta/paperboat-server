package usermachines

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/releases"
)

const (
	UpdateObservationSchemaV1   = "paperboat.update-observation/v1"
	MaintenanceApprovalSchemaV1 = "paperboat.maintenance-approval/v1"
	DefaultMaintenanceTTL       = 15 * time.Minute
	MaxMaintenanceTTL           = 24 * time.Hour
)

var (
	ErrUpdateObservationInvalid    = errors.New("machine update observation is invalid")
	ErrUpdateObservationStale      = errors.New("machine update observation is stale")
	ErrUpdateObservationConflict   = errors.New("machine update observation operation conflicts with an earlier payload")
	ErrMaintenanceApprovalInvalid  = errors.New("maintenance approval is invalid")
	ErrMaintenanceApprovalNotFound = errors.New("maintenance approval not found")
	ErrMaintenanceApprovalConflict = errors.New("maintenance approval idempotency key was reused with different input")
	ErrMaintenanceApprovalState    = errors.New("maintenance approval is not actionable in its current state")
)

var (
	updateChannelPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	updateCodePattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	updateOperationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
)

// UpdateObservation is the machine-authenticated status of the local update
// supervisor. The machine proof authenticates the sender; ordering fields
// fence late packets from replacing newer state.
type UpdateObservation struct {
	Schema                 string    `json:"schema"`
	State                  string    `json:"state"`
	CurrentVersion         string    `json:"current_version"`
	TargetVersion          string    `json:"target_version,omitempty"`
	Channel                string    `json:"channel"`
	OperationID            string    `json:"operation_id"`
	InstallationGeneration uint64    `json:"installation_generation"`
	WorkerGeneration       uint64    `json:"worker_generation"`
	OSBootID               string    `json:"os_boot_id"`
	RollbackCount          uint64    `json:"rollback_count"`
	ErrorCode              string    `json:"error_code,omitempty"`
	ObservedAt             time.Time `json:"observed_at"`
}

// MaintenanceApproval is an explicit account-owner decision for a potentially
// disruptive maintenance action. Approval is scoped to one machine and one
// signed target version, and expires automatically.
type MaintenanceApproval struct {
	Schema          string     `json:"schema"`
	ID              string     `json:"id"`
	MachineID       string     `json:"machine_id"`
	Action          string     `json:"action"`
	TargetVersion   string     `json:"target_version"`
	Reason          string     `json:"reason,omitempty"`
	Status          string     `json:"status"`
	ExpiresAt       time.Time  `json:"expires_at"`
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	DecidedByUserID string     `json:"decided_by_user_id,omitempty"`
	Version         int64      `json:"version"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (o UpdateObservation) Validate(now time.Time) error {
	validStates := map[string]bool{
		"idle": true, "checking": true, "downloading": true, "staged": true,
		"activating": true, "deferred": true, "healthy": true, "failed": true,
		"rolled_back": true,
	}
	if o.Schema != UpdateObservationSchemaV1 || !validStates[o.State] || !releases.ValidVersion(o.CurrentVersion) || o.TargetVersion != "" && !releases.ValidVersion(o.TargetVersion) || !updateChannelPattern.MatchString(o.Channel) || !updateOperationPattern.MatchString(o.OperationID) || o.InstallationGeneration < 1 || o.WorkerGeneration < 1 || strings.TrimSpace(o.OSBootID) == "" || len(o.OSBootID) > 256 || strings.ContainsAny(o.OSBootID, "\x00\r\n") || o.ObservedAt.IsZero() || o.RollbackCount > 1_000_000 {
		return ErrUpdateObservationInvalid
	}
	if o.State != "idle" && o.State != "healthy" && o.TargetVersion == "" {
		return ErrUpdateObservationInvalid
	}
	if o.State == "failed" || o.State == "rolled_back" {
		if !updateCodePattern.MatchString(o.ErrorCode) {
			return ErrUpdateObservationInvalid
		}
	} else if o.ErrorCode != "" {
		return ErrUpdateObservationInvalid
	}
	if !now.IsZero() && o.ObservedAt.After(now.UTC().Add(5*time.Minute)) {
		return ErrUpdateObservationInvalid
	}
	return nil
}

func (s *Service) RecordUpdateObservation(ctx context.Context, environmentID, userMachineID string, observation UpdateObservation) error {
	environmentID, userMachineID = strings.TrimSpace(environmentID), strings.TrimSpace(userMachineID)
	if environmentID == "" || userMachineID == "" || observation.Validate(s.now().UTC()) != nil {
		return ErrUpdateObservationInvalid
	}
	payloadHash := hashUpdateObservation(observation)
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetUserMachineForEnvironmentBandwidthUpdate(ctx, environmentID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && machine.ID != userMachineID {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if machine.InstallationGeneration < int64(observation.InstallationGeneration) {
			return ErrUpdateObservationInvalid
		}
		if machine.InstallationGeneration != int64(observation.InstallationGeneration) {
			return ErrUpdateObservationStale
		}

		current, err := tx.Queries().GetUserMachineUpdateObservation(ctx, dbsqlc.GetUserMachineUpdateObservationParams{UserMachineID: userMachineID, EnvironmentID: environmentID})
		if errors.Is(err, sql.ErrNoRows) {
			_, createErr := tx.Queries().CreateUserMachineUpdateObservation(ctx, dbsqlc.CreateUserMachineUpdateObservationParams{
				UserMachineID: userMachineID, EnvironmentID: environmentID, Schema: observation.Schema,
				CurrentVersion: observation.CurrentVersion, TargetVersion: observation.TargetVersion,
				Channel: observation.Channel, State: observation.State, ErrorCode: observation.ErrorCode,
				OperationID: observation.OperationID, InstallationGeneration: int64(observation.InstallationGeneration),
				WorkerGeneration: int64(observation.WorkerGeneration), OsBootID: observation.OSBootID,
				RollbackCount: int64(observation.RollbackCount), ObservedAt: observation.ObservedAt.UTC(), PayloadHash: payloadHash,
			})
			return createErr
		}
		if err != nil {
			return err
		}
		if current.OperationID == observation.OperationID {
			if bytes.Equal(current.PayloadHash, payloadHash) {
				return nil
			}
			return ErrUpdateObservationConflict
		}
		if current.InstallationGeneration > int64(observation.InstallationGeneration) || current.InstallationGeneration == int64(observation.InstallationGeneration) && (observation.ObservedAt.Before(current.ObservedAt) || observation.ObservedAt.Equal(current.ObservedAt) && observation.WorkerGeneration < uint64(current.WorkerGeneration)) {
			return ErrUpdateObservationStale
		}
		_, err = tx.Queries().UpdateUserMachineUpdateObservation(ctx, dbsqlc.UpdateUserMachineUpdateObservationParams{
			UserMachineID: userMachineID, ExpectedEnvironmentID: environmentID, EnvironmentID: environmentID,
			Schema: observation.Schema, CurrentVersion: observation.CurrentVersion, TargetVersion: observation.TargetVersion,
			Channel: observation.Channel, State: observation.State, ErrorCode: observation.ErrorCode,
			OperationID: observation.OperationID, InstallationGeneration: int64(observation.InstallationGeneration),
			WorkerGeneration: int64(observation.WorkerGeneration), OsBootID: observation.OSBootID,
			RollbackCount: int64(observation.RollbackCount), ObservedAt: observation.ObservedAt.UTC(), PayloadHash: payloadHash,
		})
		return err
	})
}

func (s *Service) GetUpdateObservation(ctx context.Context, userID, userMachineID string) (UpdateObservation, error) {
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateObservation{}, ErrNotFound
	}
	if err != nil {
		return UpdateObservation{}, err
	}
	status, err := s.db.Queries().GetUserMachineUpdateObservation(ctx, dbsqlc.GetUserMachineUpdateObservationParams{UserMachineID: row.ID, EnvironmentID: row.EnvironmentID})
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateObservation{}, ErrNotFound
	}
	if err != nil {
		return UpdateObservation{}, err
	}
	return mapUpdateObservation(status), nil
}

func (s *Service) RequestMaintenanceApproval(ctx context.Context, userID, userMachineID, idempotencyKey, action, targetVersion, reason string, ttl time.Duration) (MaintenanceApproval, error) {
	userID, userMachineID, idempotencyKey = strings.TrimSpace(userID), strings.TrimSpace(userMachineID), strings.TrimSpace(idempotencyKey)
	action, targetVersion, reason = strings.TrimSpace(action), strings.TrimSpace(targetVersion), strings.TrimSpace(reason)
	if userID == "" || userMachineID == "" || len(idempotencyKey) < 8 || len(idempotencyKey) > 128 || !validMaintenanceAction(action) || !releases.ValidVersion(targetVersion) || len(reason) > 512 {
		return MaintenanceApproval{}, ErrMaintenanceApprovalInvalid
	}
	if ttl == 0 {
		ttl = DefaultMaintenanceTTL
	}
	if ttl < time.Minute || ttl > MaxMaintenanceTTL {
		return MaintenanceApproval{}, ErrMaintenanceApprovalInvalid
	}
	requestHash := hashMaintenanceRequest(action, targetVersion, reason)
	expiresAt := s.now().UTC().Add(ttl)
	var result MaintenanceApproval
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if existing, err := tx.Queries().GetUserMachineMaintenanceApprovalForIdempotency(ctx, dbsqlc.GetUserMachineMaintenanceApprovalForIdempotencyParams{UserID: userID, UserMachineID: userMachineID, IdempotencyKey: idempotencyKey}); err == nil {
			if !bytes.Equal(existing.RequestHash, requestHash) {
				return ErrMaintenanceApprovalConflict
			}
			result = mapMaintenanceApproval(existing)
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		machine, err := tx.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: userMachineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if machine.State == "revoked" || machine.State == "deleted" || machine.DeletedAt.Valid {
			return ErrMaintenanceApprovalState
		}
		row, err := tx.Queries().CreateUserMachineMaintenanceApproval(ctx, dbsqlc.CreateUserMachineMaintenanceApprovalParams{
			ID: newID("uma"), UserMachineID: userMachineID, UserID: userID, Schema: MaintenanceApprovalSchemaV1,
			Action: action, TargetVersion: targetVersion, Reason: reason, IdempotencyKey: idempotencyKey,
			RequestHash: requestHash, ExpiresAt: expiresAt,
		})
		if errors.Is(err, sql.ErrNoRows) {
			row, err = tx.Queries().GetUserMachineMaintenanceApprovalForIdempotency(ctx, dbsqlc.GetUserMachineMaintenanceApprovalForIdempotencyParams{UserID: userID, UserMachineID: userMachineID, IdempotencyKey: idempotencyKey})
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(row.RequestHash, requestHash) {
			return ErrMaintenanceApprovalConflict
		}
		result = mapMaintenanceApproval(row)
		if s.audit == nil {
			return nil
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.maintenance_approval_requested", ResourceType: "user_machine_maintenance_approval", ResourceID: row.ID, IdempotencyKey: "user_machine.maintenance_approval_requested:" + row.ID, Metadata: map[string]any{"machine_id": userMachineID, "action": action, "target_version": targetVersion}})
	})
	return result, err
}

func (s *Service) ListMaintenanceApprovals(ctx context.Context, userID, userMachineID string) ([]MaintenanceApproval, error) {
	if _, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID}); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if _, err := s.db.Queries().ExpireDueUserMachineMaintenanceApprovals(ctx, dbsqlc.ExpireDueUserMachineMaintenanceApprovalsParams{UserID: userID, UserMachineID: userMachineID}); err != nil {
		return nil, err
	}
	rows, err := s.db.Queries().ListUserMachineMaintenanceApprovals(ctx, dbsqlc.ListUserMachineMaintenanceApprovalsParams{UserID: userID, UserMachineID: userMachineID, PageLimit: 50})
	if err != nil {
		return nil, err
	}
	result := make([]MaintenanceApproval, 0, len(rows))
	for _, row := range rows {
		result = append(result, mapMaintenanceApproval(row))
	}
	return result, nil
}

func (s *Service) DecideMaintenanceApproval(ctx context.Context, userID, userMachineID, approvalID, decision string) (MaintenanceApproval, error) {
	userID, userMachineID, approvalID, decision = strings.TrimSpace(userID), strings.TrimSpace(userMachineID), strings.TrimSpace(approvalID), strings.TrimSpace(decision)
	if userID == "" || userMachineID == "" || approvalID == "" || decision != "approved" && decision != "rejected" {
		return MaintenanceApproval{}, ErrMaintenanceApprovalInvalid
	}
	var result MaintenanceApproval
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := tx.Queries().GetUserMachineMaintenanceApprovalForUpdate(ctx, dbsqlc.GetUserMachineMaintenanceApprovalForUpdateParams{ID: approvalID, UserID: userID, UserMachineID: userMachineID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMaintenanceApprovalNotFound
		}
		if err != nil {
			return err
		}
		if row.Status != "pending" {
			result = mapMaintenanceApproval(row)
			return ErrMaintenanceApprovalState
		}
		if !s.now().UTC().Before(row.ExpiresAt) {
			if expired, expireErr := tx.Queries().ExpireUserMachineMaintenanceApproval(ctx, dbsqlc.ExpireUserMachineMaintenanceApprovalParams{ID: row.ID, UserID: userID, UserMachineID: userMachineID}); expireErr == nil {
				result = mapMaintenanceApproval(expired)
			}
			return ErrMaintenanceApprovalState
		}
		decided, err := tx.Queries().DecideUserMachineMaintenanceApproval(ctx, dbsqlc.DecideUserMachineMaintenanceApprovalParams{Status: decision, DecidedByUserID: sql.NullString{String: userID, Valid: true}, ID: row.ID, UserID: userID, UserMachineID: userMachineID, ExpectedVersion: row.Version})
		if err != nil {
			return err
		}
		result = mapMaintenanceApproval(decided)
		if s.audit == nil {
			return nil
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.maintenance_approval_decided", ResourceType: "user_machine_maintenance_approval", ResourceID: row.ID, IdempotencyKey: "user_machine.maintenance_approval_decided:" + row.ID + ":" + decision, Metadata: map[string]any{"machine_id": userMachineID, "decision": decision, "target_version": row.TargetVersion}})
	})
	return result, err
}

func hashUpdateObservation(observation UpdateObservation) []byte {
	body, _ := json.Marshal(struct {
		Schema                 string    `json:"schema"`
		State                  string    `json:"state"`
		CurrentVersion         string    `json:"current_version"`
		TargetVersion          string    `json:"target_version"`
		Channel                string    `json:"channel"`
		OperationID            string    `json:"operation_id"`
		InstallationGeneration uint64    `json:"installation_generation"`
		WorkerGeneration       uint64    `json:"worker_generation"`
		OSBootID               string    `json:"os_boot_id"`
		RollbackCount          uint64    `json:"rollback_count"`
		ErrorCode              string    `json:"error_code"`
		ObservedAt             time.Time `json:"observed_at"`
	}{observation.Schema, observation.State, observation.CurrentVersion, observation.TargetVersion, observation.Channel, observation.OperationID, observation.InstallationGeneration, observation.WorkerGeneration, observation.OSBootID, observation.RollbackCount, observation.ErrorCode, observation.ObservedAt.UTC()})
	digest := sha256.Sum256(body)
	return digest[:]
}

func hashMaintenanceRequest(action, targetVersion, reason string) []byte {
	body, _ := json.Marshal(struct{ Action, TargetVersion, Reason string }{action, targetVersion, reason})
	digest := sha256.Sum256(body)
	return digest[:]
}

func mapUpdateObservation(row dbsqlc.UserMachineUpdateObservation) UpdateObservation {
	return UpdateObservation{Schema: row.Schema, State: row.State, CurrentVersion: row.CurrentVersion, TargetVersion: row.TargetVersion.String, Channel: row.Channel, OperationID: row.OperationID, InstallationGeneration: uint64(row.InstallationGeneration), WorkerGeneration: uint64(row.WorkerGeneration), OSBootID: row.OsBootID, RollbackCount: uint64(row.RollbackCount), ErrorCode: row.ErrorCode.String, ObservedAt: row.ObservedAt.UTC()}
}

func mapMaintenanceApproval(row dbsqlc.UserMachineMaintenanceApproval) MaintenanceApproval {
	result := MaintenanceApproval{Schema: row.Schema, ID: row.ID, MachineID: row.UserMachineID, Action: row.Action, TargetVersion: row.TargetVersion, Reason: row.Reason, Status: row.Status, ExpiresAt: row.ExpiresAt.UTC(), DecidedByUserID: row.DecidedByUserID.String, Version: row.Version, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
	if row.DecidedAt.Valid {
		decided := row.DecidedAt.Time.UTC()
		result.DecidedAt = &decided
	}
	return result
}

func validMaintenanceAction(action string) bool {
	return action == "update" || action == "restart" || action == "migration"
}
