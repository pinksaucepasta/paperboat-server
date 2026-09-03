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
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
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

type runtimeEnvironmentObservationRepository interface {
	RecordEnvironmentObservation(context.Context, string, string, *environment.Observation) (environment.RuntimeResult, error)
}

type runtimeAuxiliaryRejection struct {
	Observation string `json:"observation"`
	Code        string `json:"code"`
}

func runtimeObservation(repo runtimeObservationRepository, identities runtimeIdentityVerifier, _ int, observationSinks ...any) http.HandlerFunc {
	var availability availabilityObservationRepository
	var updates updateObservationRepository
	var environmentObservation runtimeEnvironmentObservationRepository
	for _, sink := range observationSinks {
		if candidate, ok := sink.(availabilityObservationRepository); ok {
			availability = candidate
		}
		if candidate, ok := sink.(updateObservationRepository); ok {
			updates = candidate
		}
		if candidate, ok := sink.(runtimeEnvironmentObservationRepository); ok {
			environmentObservation = candidate
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
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
			Environment  *environment.Observation        `json:"environment,omitempty"`
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
		hasEnvironmentCapability := req.RuntimeDiagnostics != nil && slices.Contains(req.RuntimeDiagnostics.Capabilities, "environment_injection")
		environmentMember, environmentMarshalErr := json.Marshal(req.Environment)
		if !validEnvironmentObservationShape(body, hasEnvironmentCapability, req.Environment) || environmentMarshalErr != nil || (req.Environment != nil && (len(environmentMember) > 4<<10 || environment.ValidateObservation(*req.Environment) != nil)) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Environment observation is invalid.")
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
		// Runtime presence is durable at this point. Optional observation storage
		// can be temporarily unavailable without making the heartbeat retry.
		auxiliaryRejections := make([]runtimeAuxiliaryRejection, 0, 3)
		var environmentResult environment.RuntimeResult
		if req.Environment != nil {
			if environmentObservation != nil {
				environmentResult, err = environmentObservation.RecordEnvironmentObservation(r.Context(), req.EnvironmentID, req.ResourceID, req.Environment)
				if err != nil {
					switch {
					case errors.Is(err, environment.ErrObservationInvalid):
						writeError(w, r, http.StatusBadRequest, "invalid_request", "Environment observation is invalid.")
						return
					case errors.Is(err, environment.ErrMachineNotHost):
						writeError(w, r, http.StatusUnprocessableEntity, "machine_not_host", "Environment variables are available only for host-capable machines.")
						return
					case errors.Is(err, environment.ErrMachineNotFound):
						writeError(w, r, http.StatusNotFound, "machine_not_found", "Machine was not found.")
						return
					default:
						auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "environment", Code: "environment_observation_unavailable"})
					}
				}
			}
		}
		if req.Availability != nil {
			if availability == nil {
				writeError(w, r, http.StatusServiceUnavailable, "availability_unavailable", "Availability observation storage is unavailable.")
				return
			}
			normalized, _, validOrder := normalizeStatusTimestamps(req.Availability.ObservedAt, req.SampledAt, time.Now().UTC())
			if !validOrder {
				auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "availability", Code: "availability_observation_invalid"})
			} else {
				req.Availability.ObservedAt = normalized
				if err := availability.RecordAvailabilityObservation(r.Context(), req.EnvironmentID, req.ResourceID, *req.Availability); err != nil {
					switch {
					case errors.Is(err, usermachines.ErrAvailabilityInvalid):
						auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "availability", Code: "availability_observation_invalid"})
					case errors.Is(err, usermachines.ErrAvailabilityObservationStale):
						auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "availability", Code: "availability_observation_stale"})
					default:
						auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "availability", Code: "availability_observation_unavailable"})
					}
				}
			}
		}
		updateRecorded := false
		if req.Update != nil {
			if req.Update.Validate(time.Now().UTC()) != nil {
				auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "update", Code: "update_observation_invalid"})
			} else if updates == nil {
				writeError(w, r, http.StatusServiceUnavailable, "update_observation_unavailable", "Update observation storage is temporarily unavailable.")
				return
			} else if err := updates.RecordUpdateObservation(r.Context(), req.EnvironmentID, req.ResourceID, *req.Update); err != nil {
				code := "update_observation_unavailable"
				switch {
				case errors.Is(err, usermachines.ErrUpdateObservationStale):
					code = "update_observation_stale"
				case errors.Is(err, usermachines.ErrUpdateObservationInvalid):
					code = "update_observation_invalid"
				case errors.Is(err, usermachines.ErrUpdateObservationConflict):
					code = "update_observation_conflict"
				case errors.Is(err, usermachines.ErrNotFound):
					writeError(w, r, http.StatusNotFound, "machine_not_found", "Machine was not found.")
					return
				}
				auxiliaryRejections = append(auxiliaryRejections, runtimeAuxiliaryRejection{Observation: "update", Code: code})
			} else {
				updateRecorded = true
			}
		}
		response := map[string]any{"accepted": true, "update_observation_recorded": updateRecorded}
		if len(auxiliaryRejections) > 0 {
			response["auxiliary_rejections"] = auxiliaryRejections
		}
		if environmentObservation != nil && req.Environment != nil && environmentResult.Bundle != nil {
			response["environment_bundle"] = environmentResult.Bundle
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: response})
	}
}

func validEnvironmentObservationShape(body []byte, capability bool, observation *environment.Observation) bool {
	var outer map[string]json.RawMessage
	if json.Unmarshal(body, &outer) != nil {
		return false
	}
	raw, present := outer["environment"]
	if present != capability {
		return false
	}
	if !capability || observation == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return !capability
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for _, name := range []string{"schema", "observation_seq", "host_recipient_key_id", "authority", "global", "machine", "state", "error_code", "observed_at"} {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func validObservedCapabilities(capabilities []string) bool {
	allowed := []string{"file_receive", "preview_launch", "terminal_host", "codex_host", "session_host", "keep_awake", "environment_injection"}
	if len(capabilities) > len(allowed) {
		return false
	}
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
