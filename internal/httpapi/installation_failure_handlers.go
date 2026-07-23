package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/connectedmachines"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

func helperInstallationFailure(enrollments *controlplane.EnrollmentService, machines *connectedmachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		var input struct {
			EnrollmentID       string `json:"enrollment_id"`
			HelperID           string `json:"helper_id"`
			HelperEnrollmentID string `json:"helper_enrollment_id"`
			Stage              string `json:"stage"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF || strings.TrimSpace(input.EnrollmentID) == "" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || input.HelperID == "" {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
			return
		}
		var environmentID string
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if proofErr == nil && len(proof) > 0 {
			claims, verifyErr := enrollments.VerifyHelperRequest(r.Context(), parts[1], proof, r.Method, r.URL.Path, body)
			if verifyErr != nil || claims.HelperID != input.HelperID {
				writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
				return
			}
			environmentID = claims.EnvironmentID
		} else {
			claims, verifyErr := enrollments.VerifyEnrollmentCredential(parts[1])
			if verifyErr != nil || claims.EnrollmentID != input.HelperEnrollmentID {
				writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper enrollment is invalid.")
				return
			}
			environmentID = claims.EnvironmentID
		}
		if err := machines.FailInstallation(r.Context(), input.EnrollmentID, environmentID, input.HelperID, input.HelperEnrollmentID, input.Stage); err != nil {
			if errors.Is(err, connectedmachines.ErrEnrollmentState) {
				writeError(w, r, http.StatusConflict, "installation_failure_not_recorded", "The enrollment is no longer awaiting installation recovery.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to record installation failure.")
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]bool{"recorded": true}})
	}
}
