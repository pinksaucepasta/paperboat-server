package httpapi

import (
	"encoding/json"
	"net/http"
	"time"
)

type ErrorResponse struct {
	Error APIError `json:"error"`
}

type APIError struct {
	Schema        string         `json:"schema,omitempty"`
	Kind          string         `json:"kind,omitempty"`
	Code          string         `json:"code"`
	Component     string         `json:"component,omitempty"`
	Message       string         `json:"message"`
	Outcome       string         `json:"outcome,omitempty"`
	Retryable     *bool          `json:"retryable,omitempty"`
	RetryAt       *time.Time     `json:"retry_at,omitempty"`
	RepairAction  string         `json:"repair_action,omitempty"`
	RequestID     string         `json:"request_id"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

type SuccessResponse struct {
	Data any `json:"data"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeErrorDetails(w, r, status, code, message, map[string]any{})
}

func writeErrorDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]any) {
	writeJSON(w, status, ErrorResponse{Error: APIError{
		Code:      code,
		Message:   message,
		RequestID: requestIDFromContext(r.Context()),
		Details:   details,
	}})
}
