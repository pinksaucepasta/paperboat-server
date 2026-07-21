package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

type activityHeartbeatRepository interface {
	VerifyHeartbeatCredential(context.Context, string, string, string) error
	RecordHeartbeat(context.Context, metering.ActivityHeartbeat) error
}

type activityIdentityVerifier interface {
	VerifyActivityHeartbeat(context.Context, string, []byte, []byte, string, string) error
}

func activityHeartbeat(repo activityHeartbeatRepository, identities activityIdentityVerifier, summaryLimit int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProjectID            string             `json:"project_id"`
			MachineID            string             `json:"machine_id"`
			LastActivityAt       time.Time          `json:"last_activity_at"`
			Signals              map[string]string  `json:"signals"`
			ReporterVersion      string             `json:"reporter_version"`
			SampledAt            time.Time          `json:"sampled_at"`
			ConfigSync           *configsync.Status `json:"config_sync"`
			ConfigSyncObservedAt time.Time          `json:"-"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 || json.NewDecoder(bytes.NewReader(body)).Decode(&req) != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Heartbeat payload is invalid JSON.")
			return
		}
		if req.ProjectID == "" || req.MachineID == "" || req.LastActivityAt.IsZero() || req.SampledAt.IsZero() {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Heartbeat payload is missing required fields.")
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		authErr := metering.ErrInvalidHeartbeatCredential
		if identities != nil && r.Header.Get("X-Paperboat-Helper-Proof") != "" {
			proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
			if proofErr == nil {
				authErr = identities.VerifyActivityHeartbeat(r.Context(), got, proof, body, req.ProjectID, req.MachineID)
			}
		} else {
			authErr = repo.VerifyHeartbeatCredential(r.Context(), req.ProjectID, req.MachineID, got)
		}
		if authErr != nil {
			if errors.Is(authErr, metering.ErrInvalidHeartbeatCredential) || errors.Is(authErr, controlplane.ErrHelperProof) {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Machine activity credential is invalid.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if req.ConfigSync != nil {
			normalized, err := configsync.NormalizeStatus(*req.ConfigSync, summaryLimit)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_request", "Config sync status is invalid.")
				return
			}
			serverNow := time.Now().UTC()
			statusUpdated, statusObserved, validOrder := normalizeStatusTimestamps(normalized.UpdatedAt, req.SampledAt, serverNow)
			if !validOrder {
				normalized.State = "error"
				normalized.ErrorCode = "status_clock_invalid"
				normalized.ErrorMessage = "Config sync status timestamp is newer than its activity sample."
			}
			normalized.UpdatedAt = statusUpdated
			req.ConfigSync = &normalized
			req.ConfigSyncObservedAt = statusObserved
		}
		if err := repo.RecordHeartbeat(r.Context(), metering.ActivityHeartbeat{
			ProjectID:            req.ProjectID,
			MachineID:            req.MachineID,
			LastActivityAt:       req.LastActivityAt.UTC(),
			LastHeartbeatAt:      req.SampledAt.UTC(),
			ReporterVersion:      req.ReporterVersion,
			Signals:              req.Signals,
			ConfigSync:           req.ConfigSync,
			ConfigSyncObservedAt: req.ConfigSyncObservedAt,
		}); err != nil {
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
