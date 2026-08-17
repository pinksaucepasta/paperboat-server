package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func userMachineUpdateStatus(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.GetUpdateObservation(r.Context(), principal.User.ID, r.PathValue("machine_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_update_status_not_found", "Machine update status was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to read machine update status.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func userMachineUpdateSummary(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.FleetUpdateSummary(r.Context(), principal.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to read machine update status.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func userMachineMaintenanceApprovalsList(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.ListMaintenanceApprovals(r.Context(), principal.User.ID, r.PathValue("machine_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to list maintenance approvals.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"approvals": result}})
	}
}

func userMachineMaintenanceApprovalRequest(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var input struct {
			Action           string `json:"action"`
			TargetVersion    string `json:"target_version"`
			Reason           string `json:"reason"`
			ExpiresInSeconds int64  `json:"expires_in_seconds"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 8193))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&input) != nil || decoder.Decode(&extra) != io.EOF {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must match the documented schema.")
			return
		}
		var ttl time.Duration
		if input.ExpiresInSeconds != 0 {
			if input.ExpiresInSeconds < 60 || input.ExpiresInSeconds > int64(usermachines.MaxMaintenanceTTL/time.Second) {
				writeError(w, r, http.StatusBadRequest, "validation_failed", "expires_in_seconds must be between 60 and 86400.")
				return
			}
			ttl = time.Duration(input.ExpiresInSeconds) * time.Second
		}
		result, err := service.RequestMaintenanceApproval(r.Context(), principal.User.ID, r.PathValue("machine_id"), r.Header.Get("Idempotency-Key"), input.Action, input.TargetVersion, input.Reason, ttl)
		switch {
		case errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "Machine was not found.")
		case errors.Is(err, usermachines.ErrMaintenanceApprovalInvalid):
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Maintenance approval details are invalid.")
		case errors.Is(err, usermachines.ErrMaintenanceApprovalConflict):
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used with different maintenance approval input.")
		case errors.Is(err, usermachines.ErrMaintenanceApprovalState):
			writeError(w, r, http.StatusConflict, "maintenance_approval_unavailable", "This machine cannot accept maintenance approval in its current state.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to request maintenance approval.")
		default:
			writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
		}
	}
}

func userMachineMaintenanceApprovalDecision(service *usermachines.Service, decision string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.DecideMaintenanceApproval(r.Context(), principal.User.ID, r.PathValue("machine_id"), r.PathValue("approval_id"), decision)
		switch {
		case errors.Is(err, usermachines.ErrMaintenanceApprovalNotFound), errors.Is(err, usermachines.ErrNotFound):
			writeError(w, r, http.StatusNotFound, "maintenance_approval_not_found", "Maintenance approval was not found.")
		case errors.Is(err, usermachines.ErrMaintenanceApprovalInvalid):
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Maintenance approval decision is invalid.")
		case errors.Is(err, usermachines.ErrMaintenanceApprovalState):
			writeError(w, r, http.StatusConflict, "maintenance_approval_not_actionable", "Maintenance approval is expired or already decided.")
		case err != nil:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to decide maintenance approval.")
		default:
			writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
		}
	}
}
