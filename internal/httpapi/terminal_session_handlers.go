package httpapi

import (
	"encoding/json"
	"errors"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/terminalsessions"
	"net/http"
	"strconv"
)

func terminalSessionsList(s *terminalsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		out, err := s.List(r.Context(), p.User.ID, r.PathValue("project_id"))
		if terminalSessionError(w, r, err) {
			return
		}
		limit, offset := 50, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 1 || parsed > 200 {
				writeError(w, r, http.StatusBadRequest, "invalid_pagination", "limit must be between 1 and 200.")
				return
			}
			limit = parsed
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 0 {
				writeError(w, r, http.StatusBadRequest, "invalid_pagination", "offset must be non-negative.")
				return
			}
			offset = parsed
		}
		total := len(out)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		page := out[offset:end]
		var nextOffset any
		if end < total {
			nextOffset = end
		}
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"items": page, "pagination": map[string]any{"limit": limit, "offset": offset, "total": total, "next_offset": nextOffset}}})
	}
}
func terminalSessionsCreate(s *terminalsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var b struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeError(w, r, 400, "invalid_request", "Request body must be valid JSON.")
			return
		}
		out, err := s.Create(r.Context(), p.User.ID, r.PathValue("project_id"), b.Name, r.Header.Get("Idempotency-Key"))
		if terminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, 201, SuccessResponse{Data: out})
	}
}
func terminalSessionsRename(s *terminalsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var b struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeError(w, r, 400, "invalid_request", "Request body must be valid JSON.")
			return
		}
		out, err := s.Rename(r.Context(), p.User.ID, r.PathValue("project_id"), r.PathValue("session_id"), b.Name)
		if terminalSessionError(w, r, err) {
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: out})
	}
}
func terminalSessionsClose(s *terminalsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := s.Close(r.Context(), p.User.ID, r.PathValue("project_id"), r.PathValue("session_id"))
		if terminalSessionError(w, r, err) {
			return
		}
		if applied {
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"operation_state": "applied"}})
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]string{"operation_state": "pending"}})
	}
}
func terminalSessionsDelete(s *terminalsessions.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		applied, err := s.Delete(r.Context(), p.User.ID, r.PathValue("project_id"), r.PathValue("session_id"))
		if terminalSessionError(w, r, err) {
			return
		}
		if applied {
			writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]string{"purge_state": "purged"}})
			return
		}
		writeJSON(w, 202, SuccessResponse{Data: map[string]string{"purge_state": "pending"}})
	}
}
func terminalSessionError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, projects.ErrNotFound):
		writeError(w, r, 404, "project_not_found", "Project was not found.")
	case errors.Is(err, terminalsessions.ErrNotFound):
		writeError(w, r, 404, "terminal_session_not_found", "Terminal session was not found.")
	case errors.Is(err, terminalsessions.ErrReserved):
		writeError(w, r, 409, "terminal_session_reserved", "The default terminal session cannot be changed this way.")
	case errors.Is(err, terminalsessions.ErrLimit):
		writeError(w, r, 409, "terminal_session_limit_reached", "This project has reached its terminal session limit.")
	case errors.Is(err, terminalsessions.ErrConflict):
		writeError(w, r, 409, "terminal_session_name_conflict", "A terminal session already uses that name.")
	case errors.Is(err, terminalsessions.ErrInvalidName):
		writeError(w, r, 400, "invalid_terminal_session_name", "Terminal session name is invalid.")
	case errors.Is(err, terminalsessions.ErrIdempotencyKeyRequired):
		writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key is required.")
	default:
		writeError(w, r, 500, "internal_error", "Internal server error.")
	}
	return true
}
