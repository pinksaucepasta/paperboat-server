package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/codexsessions"
)

func codexSessionCreate(service *codexsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			EnvironmentID string `json:"environment_id"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		session, err := service.Create(r.Context(), p.User.ID, p.Client.SessionID, body.EnvironmentID, r.Header.Get("Idempotency-Key"))
		if writeCodexSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: session})
	}
}
func codexSessionDescriptor(service *codexsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		descriptor, err := service.Descriptor(r.Context(), p.User.ID, p.Client.SessionID, r.PathValue("session_id"))
		if writeCodexSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: descriptor})
	}
}
func codexSessionRenew(service *codexsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		session, err := service.Renew(r.Context(), p.User.ID, p.Client.SessionID, r.PathValue("session_id"))
		if writeCodexSessionError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: session})
	}
}
func codexSessionDelete(service *codexsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		if writeCodexSessionError(w, r, service.Stop(r.Context(), p.User.ID, p.Client.SessionID, r.PathValue("session_id"))) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
func writeCodexSessionError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, codexsessions.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "codex_session_not_found", "Codex session was not found.")
	case errors.Is(err, codexsessions.ErrLimitReached):
		writeError(w, r, http.StatusTooManyRequests, "limit_reached", "The active Codex session limit was reached.")
	case errors.Is(err, codexsessions.ErrIdempotencyConflict):
		writeError(w, r, http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for another request.")
	case errors.Is(err, codexsessions.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_request", "The Codex session request is invalid.")
	case errors.Is(err, codexsessions.ErrCapabilityUnavailable):
		writeError(w, r, http.StatusConflict, "machine_capability_unavailable", "The selected machine is not configured to host Codex sessions.")
	case errors.Is(err, codexsessions.ErrMachineOffline):
		writeError(w, r, http.StatusConflict, "machine_offline", "The selected machine is not currently available to host Codex sessions.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "The Codex session operation failed.")
	}
	return true
}
