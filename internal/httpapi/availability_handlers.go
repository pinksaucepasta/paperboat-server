package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func userMachineAvailabilityPolicy(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var input struct {
			ExpectedVersion int64  `json:"expected_version"`
			Mode            string `json:"mode"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		result, err := service.SetAvailabilityPolicy(r.Context(), principal.User.ID, r.PathValue("user_machine_id"), r.Header.Get("Idempotency-Key"), input.Mode, input.ExpectedVersion)
		switch {
		case errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
		case errors.Is(err, usermachines.ErrAvailabilityInvalid):
			writeError(w, r, http.StatusBadRequest, "validation_failed", "A valid Idempotency-Key, expected_version, and mode are required.")
		case errors.Is(err, usermachines.ErrAvailabilityIdempotencyConflict):
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used with different availability policy input.")
		case errors.Is(err, usermachines.ErrAvailabilityVersionConflict):
			var conflict *usermachines.AvailabilityVersionError
			if errors.As(err, &conflict) {
				writeErrorDetails(w, r, http.StatusConflict, "availability_version_conflict", "Availability policy changed since it was loaded.", map[string]any{"current_version": conflict.CurrentVersion})
			} else {
				writeError(w, r, http.StatusConflict, "availability_version_conflict", "Availability policy changed since it was loaded.")
			}
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to update availability policy.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
		}
	}
}

func helperRuntimePolicyResolve(enrollments *controlplane.EnrollmentService, machines *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var input struct{}
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		proof, proofErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Helper-Proof"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || proofErr != nil || len(proof) == 0 {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
			return
		}
		claims, err := enrollments.VerifyHelperRequest(r.Context(), parts[1], proof, r.Method, r.URL.Path, body)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "credential_invalid", "Helper identity is invalid.")
			return
		}
		result, err := machines.ResolveAvailabilityPolicy(r.Context(), claims.HelperID, claims.EnvironmentID)
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusForbidden, "helper_machine_unavailable", "Helper is not assigned to an active user machine.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to resolve helper runtime policy.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}
