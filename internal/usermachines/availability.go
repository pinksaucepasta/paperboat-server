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
)

const AvailabilityPolicySchemaV1 = "paperboat.availability-policy/v1"

var (
	ErrAvailabilityInvalid             = errors.New("availability policy is invalid")
	ErrAvailabilityIdempotencyConflict = errors.New("availability policy idempotency key was reused with different input")
	ErrAvailabilityVersionConflict     = errors.New("availability policy version conflict")
	ErrAvailabilityObservationStale    = errors.New("availability policy observation is stale")
)

var safeAvailabilityCode = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)

type AvailabilityPolicy struct {
	Schema             string     `json:"schema"`
	DesiredMode        string     `json:"desired_mode"`
	DesiredVersion     int64      `json:"desired_version"`
	ObservedMode       string     `json:"observed_mode,omitempty"`
	ObservedVersion    int64      `json:"observed_version"`
	ObservedAt         *time.Time `json:"observed_at,omitempty"`
	Status             string     `json:"status"`
	ErrorCode          string     `json:"error_code,omitempty"`
	HostServiceVersion string     `json:"host_service_version,omitempty"`
	HostServiceScope   string     `json:"host_service_scope,omitempty"`
	UpdateRollbacks    int64      `json:"update_rollbacks"`
	UpdateHealth       string     `json:"update_health"`
}

type AvailabilityObservation struct {
	Schema             string    `json:"schema"`
	Mode               string    `json:"mode"`
	Version            int64     `json:"version"`
	Status             string    `json:"status"`
	ObservedAt         time.Time `json:"observed_at"`
	ErrorCode          string    `json:"error_code,omitempty"`
	HostServiceVersion string    `json:"host_service_version"`
	HostServiceScope   string    `json:"host_service_scope"`
	UpdateRollbacks    int64     `json:"update_rollbacks"`
	UpdateHealth       string    `json:"update_health"`
}

type AvailabilityResolution struct {
	Schema        string `json:"schema"`
	UserMachineID string `json:"machine_id"`
	Mode          string `json:"mode"`
	Version       int64  `json:"version"`
}

type AvailabilityVersionError struct{ CurrentVersion int64 }

func (e *AvailabilityVersionError) Error() string { return ErrAvailabilityVersionConflict.Error() }
func (e *AvailabilityVersionError) Unwrap() error { return ErrAvailabilityVersionConflict }

func (s *Service) SetAvailabilityPolicy(ctx context.Context, userID, userMachineID, idempotencyKey, mode string, expectedVersion int64) (AvailabilityPolicy, error) {
	userID, userMachineID, idempotencyKey, mode = strings.TrimSpace(userID), strings.TrimSpace(userMachineID), strings.TrimSpace(idempotencyKey), strings.TrimSpace(mode)
	if userID == "" || userMachineID == "" || len(idempotencyKey) < 8 || len(idempotencyKey) > 128 || expectedVersion < 0 || !validAvailabilityMode(mode) {
		return AvailabilityPolicy{}, ErrAvailabilityInvalid
	}
	requestBody, _ := json.Marshal(struct {
		ExpectedVersion int64  `json:"expected_version"`
		Mode            string `json:"mode"`
	}{expectedVersion, mode})
	requestHash := sha256.Sum256(requestBody)
	var result AvailabilityPolicy
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		operation, err := tx.Queries().GetUserMachineAvailabilityOperation(ctx, dbsqlc.GetUserMachineAvailabilityOperationParams{UserID: userID, UserMachineID: userMachineID, IdempotencyKey: idempotencyKey})
		if err == nil {
			if !bytes.Equal(operation.RequestHash, requestHash[:]) || json.Unmarshal(operation.Result, &result) != nil {
				return ErrAvailabilityIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		machine, err := tx.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: userMachineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if machine.AvailabilityDesiredVersion != expectedVersion {
			return &AvailabilityVersionError{CurrentVersion: machine.AvailabilityDesiredVersion}
		}
		updated, err := tx.Queries().SetUserMachineAvailabilityPolicy(ctx, dbsqlc.SetUserMachineAvailabilityPolicyParams{Mode: mode, ID: userMachineID, UserID: userID, ExpectedVersion: expectedVersion})
		if err != nil {
			return err
		}
		if updated != 1 {
			return &AvailabilityVersionError{CurrentVersion: machine.AvailabilityDesiredVersion}
		}
		machine.AvailabilityMode, machine.AvailabilityDesiredVersion, machine.AvailabilityStatus, machine.AvailabilityErrorCode = mode, expectedVersion+1, "pending", sql.NullString{}
		result = mapAvailability(machine)
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Queries().CreateUserMachineAvailabilityOperation(ctx, dbsqlc.CreateUserMachineAvailabilityOperationParams{ID: newID("umao"), UserMachineID: userMachineID, UserID: userID, IdempotencyKey: idempotencyKey, RequestHash: requestHash[:], ExpectedVersion: expectedVersion, ResultingVersion: expectedVersion + 1, Mode: mode, Result: encoded})
		if err != nil {
			return err
		}
		if s.audit == nil {
			return nil
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.availability_policy_updated", ResourceType: "user_machine", ResourceID: userMachineID, IdempotencyKey: "user_machine.availability_policy_updated:" + userMachineID + ":" + idempotencyKey, Metadata: map[string]any{"mode": mode, "version": expectedVersion + 1}})
	})
	return result, err
}

func (s *Service) ResolveAvailabilityPolicy(ctx context.Context, helperID, environmentID string) (AvailabilityResolution, error) {
	if strings.TrimSpace(helperID) == "" || strings.TrimSpace(environmentID) == "" {
		return AvailabilityResolution{}, ErrAvailabilityInvalid
	}
	machine, err := s.db.Queries().GetUserMachineAvailabilityForHelper(ctx, dbsqlc.GetUserMachineAvailabilityForHelperParams{HelperID: helperID, EnvironmentID: environmentID})
	if errors.Is(err, sql.ErrNoRows) {
		return AvailabilityResolution{}, ErrNotFound
	}
	if err != nil {
		return AvailabilityResolution{}, err
	}
	return AvailabilityResolution{Schema: AvailabilityPolicySchemaV1, UserMachineID: machine.ID, Mode: machine.AvailabilityMode, Version: machine.AvailabilityDesiredVersion}, nil
}

func (s *Service) RecordAvailabilityObservation(ctx context.Context, environmentID, userMachineID string, observation AvailabilityObservation) error {
	if environmentID == "" || userMachineID == "" || observation.Schema != AvailabilityPolicySchemaV1 || !validAvailabilityMode(observation.Mode) || observation.Version < 0 || observation.UpdateRollbacks < 0 || !validUpdateHealth(observation.UpdateHealth) || !validAvailabilityStatus(observation.Status) || observation.ObservedAt.IsZero() || len(observation.HostServiceVersion) > 128 || observation.HostServiceVersion == "" || observation.HostServiceScope != "system" || (observation.ErrorCode != "" && !safeAvailabilityCode.MatchString(observation.ErrorCode)) || observation.Status == "applied" && observation.ErrorCode != "" || observation.Status != "applied" && observation.ErrorCode == "" {
		return ErrAvailabilityInvalid
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetUserMachineForEnvironmentBandwidthUpdate(ctx, environmentID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && machine.ID != userMachineID {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if observation.Version != machine.AvailabilityDesiredVersion || observation.Version < machine.AvailabilityObservedVersion {
			return ErrAvailabilityObservationStale
		}
		if observation.Version == machine.AvailabilityObservedVersion && machine.AvailabilityObservedAt.Valid {
			if machine.AvailabilityObservedMode.String != observation.Mode || observation.UpdateRollbacks < machine.HostUpdateRollbacks || observation.ObservedAt.Before(machine.AvailabilityObservedAt.Time) {
				return ErrAvailabilityObservationStale
			}
			if machine.AvailabilityStatus == observation.Status && machine.AvailabilityErrorCode.String == observation.ErrorCode && machine.HostServiceVersion.String == observation.HostServiceVersion && machine.HostServiceScope.String == observation.HostServiceScope && machine.HostUpdateRollbacks == observation.UpdateRollbacks && machine.UpdateHealth == observation.UpdateHealth {
				return nil
			}
		}
		rows, err := tx.Queries().RecordUserMachineAvailabilityObservation(ctx, dbsqlc.RecordUserMachineAvailabilityObservationParams{ObservedMode: sql.NullString{String: observation.Mode, Valid: true}, ObservedVersion: observation.Version, ObservedAt: sql.NullTime{Time: observation.ObservedAt.UTC(), Valid: true}, Status: observation.Status, ErrorCode: observation.ErrorCode, HostServiceVersion: observation.HostServiceVersion, HostServiceScope: observation.HostServiceScope, UpdateRollbacks: observation.UpdateRollbacks, UpdateHealth: observation.UpdateHealth, ID: userMachineID, EnvironmentID: environmentID})
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrAvailabilityObservationStale
		}
		return nil
	})
}

func mapAvailability(row dbsqlc.UserMachine) AvailabilityPolicy {
	status := row.AvailabilityStatus
	if !row.Online {
		status = "offline"
	}
	result := AvailabilityPolicy{Schema: AvailabilityPolicySchemaV1, DesiredMode: row.AvailabilityMode, DesiredVersion: row.AvailabilityDesiredVersion, ObservedMode: row.AvailabilityObservedMode.String, ObservedVersion: row.AvailabilityObservedVersion, Status: status, ErrorCode: row.AvailabilityErrorCode.String, HostServiceVersion: row.HostServiceVersion.String, HostServiceScope: row.HostServiceScope.String, UpdateRollbacks: row.HostUpdateRollbacks, UpdateHealth: row.UpdateHealth}
	if row.AvailabilityObservedAt.Valid {
		value := row.AvailabilityObservedAt.Time
		result.ObservedAt = &value
	}
	return result
}
func validAvailabilityMode(value string) bool { return value == "allow_sleep" || value == "keep_awake" }
func validAvailabilityStatus(value string) bool {
	return value == "applied" || value == "unsupported" || value == "error"
}
func validUpdateHealth(value string) bool {
	return value == "healthy" || value == "recovery_required"
}
