package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/diagnosticuploads"
)

const maximumDiagnosticIntentRequestBytes = 2048

type diagnosticUploadIntentResponse struct {
	Schema        string            `json:"schema"`
	IntentID      string            `json:"intent_id"`
	CorrelationID string            `json:"correlation_id"`
	State         string            `json:"state"`
	ExpiresAt     string            `json:"expires_at"`
	UploadMethod  string            `json:"upload_method,omitempty"`
	UploadURL     string            `json:"upload_url,omitempty"`
	UploadHeaders map[string]string `json:"upload_headers,omitempty"`
}

func diagnosticUploadIntentCreate(service *diagnosticuploads.Service) http.HandlerFunc {
	type request struct {
		Schema        string   `json:"schema"`
		CorrelationID string   `json:"correlation_id"`
		Bytes         int64    `json:"bytes"`
		SHA256        string   `json:"sha256"`
		Categories    []string `json:"categories"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		if operationKey == "" {
			writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
			return
		}
		var body request
		if !decodeStrictDiagnosticJSON(w, r, &body, maximumDiagnosticIntentRequestBytes) {
			return
		}
		if body.Schema != "paperboat.diagnostic-upload-intent-request/v1" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Diagnostic upload intent is invalid.")
			return
		}
		intent, authority, err := service.Create(r.Context(), diagnosticuploads.CreateRequest{
			UserID: principal.User.ID, CLIClientSessionID: principal.Client.SessionID, OperationKey: operationKey,
			CorrelationID: body.CorrelationID, Bytes: body.Bytes, SHA256: body.SHA256, Categories: body.Categories,
		})
		if err != nil {
			writeDiagnosticUploadError(w, r, err)
			return
		}
		response := diagnosticUploadIntentResponse{Schema: "paperboat.diagnostic-upload-intent/v1", IntentID: intent.ID, CorrelationID: intent.CorrelationID, State: intent.State, ExpiresAt: intent.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00")}
		if intent.State == "pending" {
			response.UploadMethod, response.UploadURL, response.UploadHeaders = http.MethodPut, authority.URL, authority.Headers
		}
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: response})
	}
}

func diagnosticUploadIntentComplete(service *diagnosticuploads.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r.Context())
		if !ok || principal.Client == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct{}
		if !decodeStrictDiagnosticJSON(w, r, &body, 32) {
			return
		}
		intent, err := service.Complete(r.Context(), principal.User.ID, r.PathValue("intent_id"))
		if err != nil {
			writeDiagnosticUploadError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: diagnosticUploadIntentResponse{Schema: "paperboat.diagnostic-upload-intent/v1", IntentID: intent.ID, CorrelationID: intent.CorrelationID, State: intent.State, ExpiresAt: intent.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00")}})
	}
}

func decodeStrictDiagnosticJSON(w http.ResponseWriter, r *http.Request, output any, maximum int64) bool {
	if r.Header.Get("Content-Type") != "application/json" || r.URL.RawQuery != "" || r.ContentLength < 0 || r.ContentLength > maximum {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Request must contain bounded application/json.")
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, maximum+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must contain one JSON value.")
		return false
	}
	return true
}

func writeDiagnosticUploadError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, diagnosticuploads.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "validation_failed", "Diagnostic upload request is invalid.")
	case errors.Is(err, diagnosticuploads.ErrIdempotencyConflict):
		writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an earlier diagnostic upload.")
	case errors.Is(err, diagnosticuploads.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "diagnostic_upload_not_found", "Diagnostic upload intent was not found.")
	case errors.Is(err, diagnosticuploads.ErrExpired):
		writeError(w, r, http.StatusGone, "diagnostic_upload_expired", "Diagnostic upload intent expired; create a new intent.")
	case errors.Is(err, diagnosticuploads.ErrUploadMismatch):
		writeError(w, r, http.StatusUnprocessableEntity, "diagnostic_upload_mismatch", "Uploaded bundle does not match its authorized size and checksum.")
	default:
		writeError(w, r, http.StatusServiceUnavailable, "diagnostic_upload_unavailable", "Diagnostic upload service is temporarily unavailable.")
	}
}
