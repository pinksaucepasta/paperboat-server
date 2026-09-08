package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func userMachineCapabilities(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var input struct {
			ExpectedVersion int64                                  `json:"expected_version"`
			Desired         usermachines.DeviceCapabilitySelection `json:"desired"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		result, err := service.SetDeviceCapabilities(r.Context(), principal.User.ID, r.PathValue("machine_id"), r.Header.Get("Idempotency-Key"), input.Desired, input.ExpectedVersion)
		switch {
		case errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
		case errors.Is(err, usermachines.ErrCapabilitiesInvalid):
			writeError(w, r, http.StatusBadRequest, "validation_failed", "A valid Idempotency-Key and expected_version are required.")
		case errors.Is(err, usermachines.ErrCapabilitiesIdempotencyConflict):
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used with different device capabilities.")
		case errors.Is(err, usermachines.ErrCapabilitiesVersionConflict):
			var conflict *usermachines.CapabilitiesVersionError
			if errors.As(err, &conflict) {
				writeErrorDetails(w, r, http.StatusConflict, "capabilities_version_conflict", "Device capabilities changed since they were loaded.", map[string]any{"current_version": conflict.CurrentVersion})
			} else {
				writeError(w, r, http.StatusConflict, "capabilities_version_conflict", "Device capabilities changed since they were loaded.")
			}
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to update device capabilities.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
		}
	}
}
