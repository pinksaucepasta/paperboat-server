package usermachines

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const DeviceCapabilitiesSchemaV1 = "paperboat.device-capabilities/v1"

var (
	ErrCapabilitiesInvalid             = errors.New("device capabilities are invalid")
	ErrCapabilitiesVersionConflict     = errors.New("device capabilities version conflict")
	ErrCapabilitiesIdempotencyConflict = errors.New("device capabilities idempotency conflict")
	ErrCapabilitiesObservationStale    = errors.New("device capabilities observation is stale")
)

type DeviceCapabilitySelection struct {
	Terminal      bool `json:"terminal"`
	ManagedSSH    bool `json:"managed_ssh"`
	FileReceive   bool `json:"file_receive"`
	PreviewTunnel bool `json:"preview_tunnel"`
	PeerRelay     bool `json:"peer_relay"`
}

type DeviceCapabilityPolicy struct {
	Schema         string                    `json:"schema"`
	Desired        DeviceCapabilitySelection `json:"desired"`
	DesiredVersion int64                     `json:"desired_version"`
	Applied        DeviceCapabilitySelection `json:"applied"`
	AppliedVersion int64                     `json:"applied_version"`
	Status         string                    `json:"status"`
	ErrorCode      string                    `json:"error_code,omitempty"`
}

type CapabilitiesVersionError struct{ CurrentVersion int64 }

func (e *CapabilitiesVersionError) Error() string { return ErrCapabilitiesVersionConflict.Error() }
func (e *CapabilitiesVersionError) Unwrap() error { return ErrCapabilitiesVersionConflict }

func (s *Service) DeviceCapabilitiesEnabled() bool { return s != nil && s.db != nil }

func (s *Service) SetDeviceCapabilities(ctx context.Context, userID, machineID, idempotencyKey string, desired DeviceCapabilitySelection, expectedVersion int64) (DeviceCapabilityPolicy, error) {
	userID, machineID, idempotencyKey = strings.TrimSpace(userID), strings.TrimSpace(machineID), strings.TrimSpace(idempotencyKey)
	if userID == "" || machineID == "" || len(idempotencyKey) < 8 || len(idempotencyKey) > 128 || expectedVersion < 1 {
		return DeviceCapabilityPolicy{}, ErrCapabilitiesInvalid
	}
	names := capabilityNames(desired)
	body, _ := json.Marshal(struct {
		ExpectedVersion int64                     `json:"expected_version"`
		Desired         DeviceCapabilitySelection `json:"desired"`
	}{expectedVersion, desired})
	hash := sha256.Sum256(body)
	var result DeviceCapabilityPolicy
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		op, err := tx.Queries().GetUserMachineCapabilityOperation(ctx, dbsqlc.GetUserMachineCapabilityOperationParams{UserID: userID, UserMachineID: machineID, IdempotencyKey: idempotencyKey})
		if err == nil {
			if !bytes.Equal(op.RequestHash, hash[:]) || json.Unmarshal(op.Result, &result) != nil {
				return ErrCapabilitiesIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		machine, err := tx.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: machineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if machine.CapabilitiesDesiredVersion != expectedVersion {
			return &CapabilitiesVersionError{CurrentVersion: machine.CapabilitiesDesiredVersion}
		}
		// Preserve capabilities owned by other tasks (ENV and availability).
		for _, name := range machine.ConfiguredCapabilities {
			if name == "environment_injection" || name == "keep_awake" {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		names = slices.Compact(names)
		rows, err := tx.Queries().SetUserMachineCapabilities(ctx, dbsqlc.SetUserMachineCapabilitiesParams{ConfiguredCapabilities: names, ID: machineID, UserID: userID, ExpectedVersion: expectedVersion})
		if err != nil {
			return err
		}
		if rows != 1 {
			return &CapabilitiesVersionError{CurrentVersion: machine.CapabilitiesDesiredVersion}
		}
		machine.ConfiguredCapabilities = names
		machine.CapabilitiesDesiredVersion++
		if machine.Online {
			machine.CapabilitiesStatus = "pending"
		} else {
			machine.CapabilitiesStatus = "offline"
		}
		machine.CapabilitiesErrorCode = sql.NullString{}
		result = mapDeviceCapabilityPolicy(machine)
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Queries().CreateUserMachineCapabilityOperation(ctx, dbsqlc.CreateUserMachineCapabilityOperationParams{ID: newID("umco"), UserMachineID: machineID, UserID: userID, IdempotencyKey: idempotencyKey, RequestHash: hash[:], ExpectedVersion: expectedVersion, ResultingVersion: expectedVersion + 1, ConfiguredCapabilities: names, Result: encoded})
		if err != nil {
			return err
		}
		if s.audit == nil {
			return nil
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.capabilities_updated", ResourceType: "user_machine", ResourceID: machineID, IdempotencyKey: "user_machine.capabilities_updated:" + machineID + ":" + idempotencyKey, Metadata: map[string]any{"version": expectedVersion + 1}})
	})
	return result, err
}

func (s *Service) ResolveDeviceCapabilities(ctx context.Context, machineID, environmentID string) (DeviceCapabilityPolicy, error) {
	machine, err := s.db.Queries().GetUserMachineForEnvironmentBandwidthUpdate(ctx, environmentID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && machine.ID != machineID {
		return DeviceCapabilityPolicy{}, ErrNotFound
	}
	if err != nil {
		return DeviceCapabilityPolicy{}, err
	}
	return mapDeviceCapabilityPolicy(machine), nil
}

type DeviceCapabilitiesObservation struct {
	Schema     string                    `json:"schema"`
	Version    int64                     `json:"version"`
	Applied    DeviceCapabilitySelection `json:"applied"`
	Status     string                    `json:"status"`
	ErrorCode  string                    `json:"error_code,omitempty"`
	ObservedAt time.Time                 `json:"observed_at"`
}

func (s *Service) RecordDeviceCapabilitiesObservation(ctx context.Context, machineID, environmentID string, in DeviceCapabilitiesObservation) error {
	if machineID == "" || environmentID == "" || in.Schema != DeviceCapabilitiesSchemaV1 || in.Version < 1 || in.ObservedAt.IsZero() || !slices.Contains([]string{"applied", "error"}, in.Status) || in.Status == "applied" && in.ErrorCode != "" || in.Status == "error" && !safeAvailabilityCode.MatchString(in.ErrorCode) {
		return ErrCapabilitiesInvalid
	}
	rows, err := s.db.Queries().RecordUserMachineCapabilitiesObservation(ctx, dbsqlc.RecordUserMachineCapabilitiesObservationParams{ObservedCapabilities: capabilityNames(in.Applied), ObservedVersion: in.Version, Status: in.Status, ErrorCode: sql.NullString{String: in.ErrorCode, Valid: in.ErrorCode != ""}, ID: machineID, EnvironmentID: environmentID})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrCapabilitiesObservationStale
	}
	return nil
}

func capabilityNames(value DeviceCapabilitySelection) []string {
	var result []string
	if value.FileReceive {
		result = append(result, "file_receive")
	}
	if value.PreviewTunnel {
		result = append(result, "preview_launch")
	}
	if value.Terminal {
		result = append(result, "terminal_host", "codex_host", "session_host")
	}
	if value.ManagedSSH {
		result = append(result, "ssh_host")
	}
	if value.PeerRelay {
		result = append(result, "peer_relay")
	}
	return result
}

func selectionFromNames(names []string) DeviceCapabilitySelection {
	return DeviceCapabilitySelection{Terminal: slices.Contains(names, "terminal_host"), ManagedSSH: slices.Contains(names, "ssh_host"), FileReceive: slices.Contains(names, "file_receive"), PreviewTunnel: slices.Contains(names, "preview_launch"), PeerRelay: slices.Contains(names, "peer_relay")}
}

func mapDeviceCapabilityPolicy(machine dbsqlc.UserMachine) DeviceCapabilityPolicy {
	return DeviceCapabilityPolicy{Schema: DeviceCapabilitiesSchemaV1, Desired: selectionFromNames(machine.ConfiguredCapabilities), DesiredVersion: machine.CapabilitiesDesiredVersion, Applied: selectionFromNames(machine.ObservedCapabilities), AppliedVersion: machine.CapabilitiesObservedVersion, Status: machine.CapabilitiesStatus, ErrorCode: machine.CapabilitiesErrorCode.String}
}
