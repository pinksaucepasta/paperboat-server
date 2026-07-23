package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

type helperPreviewObservationInput struct {
	Identity      string `json:"identity"`
	EnvironmentID string `json:"environment_id"`
	LogicalName   string `json:"logical_name"`
	Target        struct {
		Host string `json:"host"`
		Port int32  `json:"port"`
	} `json:"target"`
	State     string    `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	Revision  uint64    `json:"revision"`
}

func helperPreviewObservation(previews *controlplane.PreviewService, identities *controlplane.EnrollmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview observation is invalid.")
			return
		}
		proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		claims, err := identities.VerifyPreviewRequest(r.Context(), r.Header.Get("X-Paperboat-Helper-Identity"), mustBearer(r), proof, body, r.Method, r.URL.Path)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Credential is invalid.")
			return
		}
		var input helperPreviewObservationInput
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || input.EnvironmentID != claims.EnvironmentID {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview observation is invalid.")
			return
		}
		helperReady, targetReady, valid := previewObservationReadiness(input.State)
		if !valid {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Preview observation state is invalid.")
			return
		}
		item, err := previews.ObserveForHelper(r.Context(), controlplane.PreviewObservation{EnvironmentID: claims.EnvironmentID, PreviewKey: input.Identity, LogicalName: input.LogicalName, TargetHost: input.Target.Host, TargetPort: input.Target.Port, Revision: input.Revision, HelperReady: helperReady, TargetReady: targetReady, ObservedAt: input.UpdatedAt})
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, r, http.StatusConflict, "observation_stale_or_unknown", "Preview observation is stale or unavailable.")
			return
		}
		if err != nil {
			previewHelperError(w, r, err)
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: newPreviewResponse(item)})
	}
}

func previewObservationReadiness(state string) (bool, bool, bool) {
	switch state {
	case "registering", "degraded":
		return true, false, true
	case "ready":
		return true, true, true
	case "offline", "expired", "removed":
		return false, false, true
	default:
		return false, false, false
	}
}
