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

func runtimeObservation(repo runtimeObservationRepository, identities runtimeIdentityVerifier, _ int, availabilityObservers ...availabilityObservationRepository) http.HandlerFunc {
	var availability availabilityObservationRepository
	if len(availabilityObservers) > 0 {
		availability = availabilityObservers[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EnvironmentID      string                                `json:"environment_id"`
			ResourceID         string                                `json:"resource_id"`
			ReporterVersion    string                                `json:"reporter_version"`
			SampledAt          time.Time                             `json:"sampled_at"`
			Availability       *usermachines.AvailabilityObservation `json:"availability"`
			RuntimeDiagnostics *struct {
				WorkerGeneration    uint64    `json:"worker_generation"`
				OSBootID            string    `json:"os_boot_id"`
				WorkerServiceScope  string    `json:"worker_service_scope"`
				ConnectorState      string    `json:"connector_state"`
				ConnectorGeneration uint64    `json:"connector_generation"`
				ObservedAt          time.Time `json:"observed_at"`
			} `json:"runtime_diagnostics"`
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
		if req.RuntimeDiagnostics != nil && (req.RuntimeDiagnostics.WorkerGeneration < 1 || req.RuntimeDiagnostics.OSBootID == "" || len(req.RuntimeDiagnostics.OSBootID) > 256 || strings.ContainsAny(req.RuntimeDiagnostics.OSBootID, "\x00\r\n") || !slices.Contains([]string{"unknown", "user", "system"}, req.RuntimeDiagnostics.WorkerServiceScope) || !slices.Contains([]string{"ready", "degraded", "unavailable"}, req.RuntimeDiagnostics.ConnectorState) || req.RuntimeDiagnostics.ObservedAt.IsZero()) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Runtime diagnostics are invalid.")
			return
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
			observation.DiagnosticsObservedAt = req.RuntimeDiagnostics.ObservedAt.UTC()
		}
		if err := repo.RecordRuntimeObservation(r.Context(), observation); err != nil {
			if errors.Is(err, metering.ErrDuplicateMachineIdentity) {
				writeError(w, r, http.StatusConflict, "duplicate_machine_identity", "This machine identity is active on another installation. Run pb setup to create a distinct machine identity.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{"accepted": true}})
	}
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
