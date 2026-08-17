package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

type runtimeObservationRepository interface {
	VerifyHeartbeatCredential(context.Context, string, string, string) error
	RecordRuntimeObservation(context.Context, metering.RuntimeObservation) error
}

type runtimeIdentityVerifier interface {
	VerifyRuntimeObservation(context.Context, string, []byte, []byte, string, string) error
}
type availabilityObservationRepository interface {
	RecordAvailabilityObservation(context.Context, string, string, usermachines.AvailabilityObservation) error
}

type updateObservationRepository interface {
	RecordUpdateObservation(context.Context, string, string, usermachines.UpdateObservation) error
}

func runtimeObservation(repo runtimeObservationRepository, identities runtimeIdentityVerifier, _ int, observationSinks ...any) http.HandlerFunc {
	var availability availabilityObservationRepository
	var updates updateObservationRepository
	for _, sink := range observationSinks {
		if candidate, ok := sink.(availabilityObservationRepository); ok {
			availability = candidate
		}
		if candidate, ok := sink.(updateObservationRepository); ok {
			updates = candidate
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EnvironmentID      string                                `json:"environment_id"`
			ResourceID         string                                `json:"resource_id"`
			ReporterVersion    string                                `json:"reporter_version"`
			SampledAt          time.Time                             `json:"sampled_at"`
			Availability       *usermachines.AvailabilityObservation `json:"availability"`
			RuntimeDiagnostics *struct {
				Capabilities        []string  `json:"capabilities"`
				WorkerGeneration    uint64    `json:"worker_generation"`
				OSBootID            string    `json:"os_boot_id"`
				WorkerServiceScope  string    `json:"worker_service_scope"`
				ConnectorState      string    `json:"connector_state"`
				ConnectorGeneration uint64    `json:"connector_generation"`
				ObservedAt          time.Time `json:"observed_at"`
			} `json:"runtime_diagnostics"`
			RelayLatency *metering.RelayLatencyVector    `json:"relay_latency,omitempty"`
			Update       *usermachines.UpdateObservation `json:"update,omitempty"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err != nil || len(body) > 1<<20 || decoder.Decode(&req) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Heartbeat payload is invalid JSON.")
			return
		}
		if req.EnvironmentID == "" || req.ResourceID == "" || req.SampledAt.IsZero() {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Runtime observation is missing required fields.")
			return
		}
		if req.RuntimeDiagnostics != nil && (req.RuntimeDiagnostics.WorkerGeneration < 1 || req.RuntimeDiagnostics.OSBootID == "" || len(req.RuntimeDiagnostics.OSBootID) > 256 || strings.ContainsAny(req.RuntimeDiagnostics.OSBootID, "\x00\r\n") || !validObservedCapabilities(req.RuntimeDiagnostics.Capabilities) || !slices.Contains([]string{"unknown", "user", "system"}, req.RuntimeDiagnostics.WorkerServiceScope) || !slices.Contains([]string{"ready", "degraded", "unavailable"}, req.RuntimeDiagnostics.ConnectorState) || req.RuntimeDiagnostics.ObservedAt.IsZero()) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Runtime diagnostics are invalid.")
			return
		}
		if req.RelayLatency != nil && (req.RuntimeDiagnostics == nil || !req.RelayLatency.Valid(req.SampledAt)) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Relay latency observation is invalid.")
			return
		}
		if req.Update != nil {
			if req.Update.Validate(time.Now().UTC()) != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Update observation is invalid.")
				return
			}
			if updates == nil {
				writeError(w, r, http.StatusServiceUnavailable, "update_observation_unavailable", "Update observation storage is temporarily unavailable.")
				return
			}
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		authErr := metering.ErrInvalidHeartbeatCredential
		if identities != nil && r.Header.Get("X-Paperboat-Machine-Proof") != "" {
			proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
			if proofErr == nil {
				authErr = identities.VerifyRuntimeObservation(r.Context(), got, proof, body, req.EnvironmentID, req.ResourceID)
			}
		} else {
			authErr = repo.VerifyHeartbeatCredential(r.Context(), req.EnvironmentID, req.ResourceID, got)
		}
		if authErr != nil {
			if errors.Is(authErr, metering.ErrInvalidHeartbeatCredential) || errors.Is(authErr, controlplane.ErrHelperProof) {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Runtime observation credential is invalid.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if req.Availability != nil {
			if availability == nil {
				writeError(w, r, http.StatusServiceUnavailable, "availability_unavailable", "Availability observation storage is unavailable.")
				return
			}
			normalized, _, validOrder := normalizeStatusTimestamps(req.Availability.ObservedAt, req.SampledAt, time.Now().UTC())
			if !validOrder {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Availability observation timestamp is invalid.")
				return
			}
			req.Availability.ObservedAt = normalized
			if err := availability.RecordAvailabilityObservation(r.Context(), req.EnvironmentID, req.ResourceID, *req.Availability); err != nil {
				if errors.Is(err, usermachines.ErrAvailabilityInvalid) {
					writeError(w, r, http.StatusBadRequest, "invalid_request", "Availability observation is invalid.")
				} else if errors.Is(err, usermachines.ErrAvailabilityObservationStale) {
					writeError(w, r, http.StatusConflict, "availability_observation_stale", "Availability observation does not match the current policy version.")
				} else {
					writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to record availability observation.")
				}
				return
			}
		}
		updateRecorded := false
		if req.Update != nil {
			if err := updates.RecordUpdateObservation(r.Context(), req.EnvironmentID, req.ResourceID, *req.Update); err != nil {
				switch {
				case errors.Is(err, usermachines.ErrUpdateObservationStale):
					// A late update packet must not make the machine heartbeat fail.
					// The durable status remains fenced by installation and worker
					// generations; the next heartbeat will carry current state.
				case errors.Is(err, usermachines.ErrUpdateObservationInvalid), errors.Is(err, usermachines.ErrUpdateObservationConflict):
					writeError(w, r, http.StatusConflict, "update_observation_rejected", "Update observation was rejected as stale or conflicting.")
					return
				case errors.Is(err, usermachines.ErrNotFound):
					writeError(w, r, http.StatusNotFound, "machine_not_found", "Machine was not found.")
					return
				default:
					writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to record update observation.")
					return
				}
			} else {
				updateRecorded = true
			}
		}
		observation := metering.RuntimeObservation{
			ProjectID:       req.EnvironmentID,
			MachineID:       req.ResourceID,
			ObservedAt:      req.SampledAt.UTC(),
			ReporterVersion: req.ReporterVersion,
		}
		if req.RuntimeDiagnostics != nil {
			observation.WorkerGeneration = req.RuntimeDiagnostics.WorkerGeneration
			observation.OSBootID = req.RuntimeDiagnostics.OSBootID
			observation.WorkerServiceScope = req.RuntimeDiagnostics.WorkerServiceScope
			observation.ConnectorState = req.RuntimeDiagnostics.ConnectorState
			observation.ConnectorGeneration = req.RuntimeDiagnostics.ConnectorGeneration
			observation.Capabilities = append([]string(nil), req.RuntimeDiagnostics.Capabilities...)
			observation.DiagnosticsObservedAt = req.RuntimeDiagnostics.ObservedAt.UTC()
		}
		observation.RelayLatency = req.RelayLatency
		if err := repo.RecordRuntimeObservation(r.Context(), observation); err != nil {
			if errors.Is(err, metering.ErrDuplicateMachineIdentity) {
				writeError(w, r, http.StatusConflict, "duplicate_machine_identity", "This machine identity is active on another installation. Run pb setup to create a distinct machine identity.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{"accepted": true, "update_observation_recorded": updateRecorded}})
	}
}

func validObservedCapabilities(capabilities []string) bool {
	if len(capabilities) > 6 {
		return false
	}
	allowed := []string{"file_receive", "preview_launch", "terminal_host", "codex_host", "session_host", "keep_awake"}
	for index, capability := range capabilities {
		if !slices.Contains(allowed, capability) || slices.Contains(capabilities[:index], capability) {
			return false
		}
	}
	return true
}

func normalizeStatusTimestamps(statusUpdated, sampledAt, serverNow time.Time) (time.Time, time.Time, bool) {
	statusUpdated = statusUpdated.UTC()
	sampledAt = sampledAt.UTC()
	serverNow = serverNow.UTC()
	if statusUpdated.After(sampledAt) {
		if sampledAt.After(serverNow) {
			return serverNow, serverNow, false
		}
		return sampledAt, serverNow, false
	}
	observed := serverNow.Add(-sampledAt.Sub(statusUpdated))
	if sampledAt.After(serverNow) {
		return observed, observed, true
	}
	return statusUpdated, observed, true
}
