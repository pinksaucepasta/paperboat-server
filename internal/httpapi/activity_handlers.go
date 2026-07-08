package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

func activityHeartbeat(repo *metering.RuntimeRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProjectID       string            `json:"project_id"`
			MachineID       string            `json:"machine_id"`
			LastActivityAt  time.Time         `json:"last_activity_at"`
			Signals         map[string]string `json:"signals"`
			ReporterVersion string            `json:"reporter_version"`
			SampledAt       time.Time         `json:"sampled_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Heartbeat payload is invalid JSON.")
			return
		}
		if req.ProjectID == "" || req.MachineID == "" || req.LastActivityAt.IsZero() || req.SampledAt.IsZero() {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Heartbeat payload is missing required fields.")
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err := repo.VerifyHeartbeatCredential(r.Context(), req.ProjectID, req.MachineID, got); err != nil {
			if errors.Is(err, metering.ErrInvalidHeartbeatCredential) {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Machine activity credential is invalid.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		if err := repo.RecordHeartbeat(r.Context(), metering.ActivityHeartbeat{
			ProjectID:       req.ProjectID,
			MachineID:       req.MachineID,
			LastActivityAt:  req.LastActivityAt.UTC(),
			LastHeartbeatAt: req.SampledAt.UTC(),
			ReporterVersion: req.ReporterVersion,
			Signals:         req.Signals,
		}); err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{"accepted": true}})
	}
}
