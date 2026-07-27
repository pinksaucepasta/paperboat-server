package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func userMachinePairings(service *usermachines.Service) http.HandlerFunc {
	type request struct {
		Verifier        string          `json:"verifier"`
		EnrollmentToken string          `json:"enrollment_token"`
		DisplayName     string          `json:"display_name"`
		Platform        string          `json:"platform"`
		Architecture    string          `json:"architecture"`
		WorkspaceRoot   string          `json:"workspace_root"`
		RuntimeVersions json.RawMessage `json:"runtime_versions"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		pairing, err := service.CreatePairing(r.Context(), usermachines.PairingInput{Verifier: body.Verifier, EnrollmentToken: body.EnrollmentToken, DisplayName: body.DisplayName, Platform: body.Platform, Architecture: body.Architecture, WorkspaceRoot: body.WorkspaceRoot, RuntimeVersions: body.RuntimeVersions})
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_user_machine_pairing", "Pairing details are invalid or unsupported.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: pairing})
	}
}

func userMachineEnrollmentStart(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.StartEnrollment(r.Context(), p.User.ID, r.Header.Get("Idempotency-Key"))
		if err != nil {
			if errors.Is(err, usermachines.ErrIdempotencyKeyRequired) {
				writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "A valid Idempotency-Key header is required.")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "user_machine_enrollment_start_failed", "Unable to start user-machine enrollment.")
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: result})
	}
}

func userMachineEnrollmentStatus(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.Enrollment(r.Context(), p.User.ID, r.PathValue("enrollment_id"))
		if err != nil {
			writeError(w, r, http.StatusNotFound, "user_machine_enrollment_not_found", "User-machine enrollment was not found.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func userMachineEnrollmentCancel(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.CancelEnrollment(r.Context(), p.User.ID, r.PathValue("enrollment_id")); err != nil {
			writeError(w, r, http.StatusConflict, "user_machine_enrollment_not_cancellable", "User-machine enrollment cannot be cancelled in its current state.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"cancelled": true}})
	}
}

func userMachineEnrollmentRetry(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		result, err := service.RetryEnrollment(r.Context(), p.User.ID, r.PathValue("enrollment_id"))
		if err != nil {
			writeError(w, r, http.StatusConflict, "user_machine_enrollment_not_retryable", "User-machine enrollment cannot be retried in its current state.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result})
	}
}

func userMachineInstallationConsume(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Verifier string `json:"verifier"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		material, err := service.ConsumeInstallation(r.Context(), body.Verifier)
		if err != nil {
			switch {
			case errors.Is(err, usermachines.ErrInstallationPending):
				writeError(w, r, http.StatusConflict, "user_machine_approval_pending", "UserMachine approval is pending.")
			case errors.Is(err, usermachines.ErrInstallationDenied):
				writeError(w, r, http.StatusForbidden, "user_machine_pairing_denied", "UserMachine pairing was denied.")
			case errors.Is(err, usermachines.ErrInstallationExpired):
				writeError(w, r, http.StatusGone, "user_machine_pairing_expired", "UserMachine pairing expired.")
			default:
				writeError(w, r, http.StatusGone, "user_machine_installation_unavailable", "Installation material is unavailable or has already been used.")
			}
			return
		}
		var data any
		if err := json.Unmarshal(material, &data); err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: data})
	}
}

func userMachinesList(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		limit, offset := 50, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				limit = parsed
			}
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				offset = parsed
			}
		}
		items, total, err := service.List(r.Context(), p.User.ID, limit, offset)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to list user machines.")
			return
		}
		var next any
		if offset+len(items) < total {
			value := offset + len(items)
			next = value
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items, "pagination": map[string]any{"limit": limit, "offset": offset, "total": total, "next_offset": next}}})
	}
}

func userMachineOverview(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		overview, err := service.Overview(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Unable to load user-machine usage.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: overview})
	}
}

func userMachineGet(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		machine, err := service.Get(r.Context(), p.User.ID, r.PathValue("user_machine_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: machine})
	}
}

func userMachineConnectionDescriptor(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			TerminalSessionID string `json:"terminal_session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		response, err := service.ConnectTerminalSession(r.Context(), p.User.ID, r.PathValue("user_machine_id"), p.Client.SessionID, body.TerminalSessionID)
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "connector_unavailable", "User machine credentials are unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineConnectionReadiness(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		response, err := service.ConnectionReadinessForTerminalSession(r.Context(), p.User.ID, r.PathValue("user_machine_id"), r.URL.Query().Get("terminal_session_id"))
		if errors.Is(err, usermachines.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
			return
		}
		if errors.Is(err, usermachines.ErrTerminalSessionNotFound) {
			writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "connector_unavailable", "User machine status is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: response})
	}
}

func userMachineTerminalSessionsList(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.ListTerminalSessions(r.Context(), p.User.ID, r.PathValue("user_machine_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"items": items, "pagination": map[string]any{"limit": len(items), "offset": 0, "total": len(items), "next_offset": nil}}})
	}
}

func userMachineTerminalSessionsCreate(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Name         string `json:"name"`
			TerminalMode string `json:"terminal_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		item, err := service.CreateConfiguredTerminalSessionWithMode(r.Context(), p.User.ID, r.PathValue("user_machine_id"), body.Name, body.TerminalMode, r.Header.Get("Idempotency-Key"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: item})
	}
}

func userMachineTerminalSessionsRename(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		item, err := service.RenameTerminalSession(r.Context(), p.User.ID, r.PathValue("user_machine_id"), r.PathValue("session_id"), body.Name)
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: item})
	}
}

func userMachineTerminalSessionsClose(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := service.CloseTerminalSession(r.Context(), p.User.ID, r.PathValue("user_machine_id"), r.PathValue("session_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		if !applied {
			writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]string{"operation_state": "pending"}})
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"operation_state": "applied"}})
	}
}

func userMachineTerminalSessionsDelete(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := service.DeleteTerminalSession(r.Context(), p.User.ID, r.PathValue("user_machine_id"), r.PathValue("session_id"))
		if userMachineTerminalSessionError(w, r, err) {
			return
		}
		if !applied {
			writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]string{"purge_state": "pending"}})
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"purge_state": "purged"}})
	}
}

func userMachineTerminalSessionError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, usermachines.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
	case errors.Is(err, usermachines.ErrTerminalSessionNotFound):
		writeError(w, r, http.StatusNotFound, "terminal_session_not_found", "Terminal session was not found.")
	case errors.Is(err, usermachines.ErrTerminalSessionReserved):
		writeError(w, r, http.StatusConflict, "terminal_session_reserved", "The default terminal session cannot be changed this way.")
	case errors.Is(err, usermachines.ErrTerminalSessionLimit):
		writeError(w, r, http.StatusConflict, "terminal_session_limit_reached", "This user machine has reached its terminal session limit.")
	case errors.Is(err, usermachines.ErrTerminalSessionConflict):
		writeError(w, r, http.StatusConflict, "terminal_session_name_conflict", "A terminal session already uses that name.")
	case errors.Is(err, usermachines.ErrTerminalSessionInvalidName):
		writeError(w, r, http.StatusBadRequest, "invalid_terminal_session_name", "Terminal session name is invalid.")
	case errors.Is(err, usermachines.ErrTerminalSessionInvalidMode):
		writeError(w, r, http.StatusBadRequest, "invalid_terminal_mode", "Terminal mode must be herdr or shell.")
	case errors.Is(err, usermachines.ErrTerminalSessionIdempotency):
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}

func userMachinePairingApprove(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		machine, err := service.Approve(r.Context(), p.User.ID, r.PathValue("user_code"))
		if err != nil {
			switch {
			case errors.Is(err, usermachines.ErrSeatUnavailable), errors.Is(err, billing.ErrUserMachineSeatUnavailable):
				writeError(w, r, http.StatusConflict, "user_machine_seat_unavailable", "An active user-machine subscription with an available seat is required.")
			case errors.Is(err, usermachines.ErrPairingExpired):
				writeError(w, r, http.StatusGone, "user_machine_pairing_expired", "This pairing request has expired.")
			case errors.Is(err, usermachines.ErrPairingUsed):
				writeError(w, r, http.StatusConflict, "user_machine_pairing_used", "This pairing request has already been decided.")
			default:
				writeError(w, r, http.StatusNotFound, "user_machine_pairing_not_found", "Pairing request was not found.")
			}
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: machine})
	}
}

func userMachinePairingDeny(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.Deny(r.Context(), p.User.ID, r.PathValue("user_code")); err != nil {
			switch {
			case errors.Is(err, usermachines.ErrPairingExpired):
				writeError(w, r, http.StatusGone, "user_machine_pairing_expired", "This pairing request has expired.")
			case errors.Is(err, usermachines.ErrPairingUsed):
				writeError(w, r, http.StatusConflict, "user_machine_pairing_used", "This pairing request has already been decided.")
			default:
				writeError(w, r, http.StatusNotFound, "user_machine_pairing_not_found", "Pairing request was not found.")
			}
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"denied": true}})
	}
}

func userMachineDisconnect(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.Disconnect(r.Context(), p.User.ID, r.PathValue("user_machine_id")); err != nil {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"disconnected": true}})
	}
}

func userMachineDelete(service *usermachines.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if err := service.Delete(r.Context(), p.User.ID, r.PathValue("user_machine_id")); err != nil {
			writeError(w, r, http.StatusNotFound, "user_machine_not_found", "User machine was not found.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]bool{"deleted": true}})
	}
}
