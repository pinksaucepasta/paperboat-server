package previewattachment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const (
	// AttachmentRenewPathSuffix, AttachmentReleasePathSuffix, and
	// AttachmentReadinessPathSuffix are intentionally subresources of the
	// attachment. The edge observation boundary is not registered here.
	AttachmentRenewPathSuffix     = "/renew"
	AttachmentReleasePathSuffix   = "/release"
	AttachmentReadinessPathSuffix = "/readiness"
)

// MachineProofVerifier is implemented by the control-plane enrollment
// service adapter. It must verify Authorization, X-Paperboat-Machine-
// Identity, X-Paperboat-Machine-Proof, method, path, and the exact raw body
// before returning these four proof fields.
type MachineProofVerifier interface {
	VerifyMachineRequest(context.Context, *http.Request, []byte) (MachineProof, error)
}

// LeasePreconditionChecker checks the exact current preview lease ETag. The
// callback belongs to the preview lease service because attachment rows do
// not own the lease generation. It is required for allocate, renew, and
// readiness; release deliberately does not invoke it so stop-first cleanup
// remains possible.
type LeasePreconditionChecker interface {
	CheckPreviewLeaseIfMatch(context.Context, MachineProof, string, string) error
}

// HTTPHandler exposes only the machine-proof control-plane operations. It is
// mountable by the parent router and has no dependency on browser/CLI auth.
// ObserveEdge remains a trusted edge transport callback on Service.
type HTTPHandler struct {
	service      *Service
	verifier     MachineProofVerifier
	precondition LeasePreconditionChecker
}

func NewHTTPHandler(service *Service, verifier MachineProofVerifier, precondition LeasePreconditionChecker) (*HTTPHandler, error) {
	if service == nil || verifier == nil || precondition == nil {
		return nil, fmt.Errorf("%w: attachment HTTP dependencies are incomplete", ErrInvalid)
	}
	return &HTTPHandler{service: service, verifier: verifier, precondition: precondition}, nil
}

// Register adds the complete host-facing attachment surface to a Go
// ServeMux. The edge callback is intentionally absent from this list.
func (h *HTTPHandler) Register(mux *http.ServeMux) error {
	if h == nil || mux == nil {
		return fmt.Errorf("%w: nil attachment HTTP handler or mux", ErrInvalid)
	}
	mux.Handle("POST "+AttachmentPathPrefix+"{preview_id}"+AttachmentPathSuffix, h)
	mux.Handle("POST "+AttachmentPathPrefix+"{preview_id}"+AttachmentPathSuffix+AttachmentRenewPathSuffix, h)
	mux.Handle("POST "+AttachmentPathPrefix+"{preview_id}"+AttachmentPathSuffix+AttachmentReadinessPathSuffix, h)
	mux.Handle("POST "+AttachmentPathPrefix+"{preview_id}"+AttachmentPathSuffix+AttachmentReleasePathSuffix, h)
	return nil
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.verifier == nil || h.precondition == nil {
		writeAttachmentError(w, http.StatusServiceUnavailable, "attachment_unavailable", "Preview carrier attachment is unavailable.", true)
		return
	}
	if r == nil || r.Method != http.MethodPost {
		writeAttachmentError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Preview carrier attachment mutations require POST.", false)
		return
	}
	previewID, action, ok := attachmentPath(r)
	if !ok {
		writeAttachmentError(w, http.StatusNotFound, "not_found", "Preview carrier attachment endpoint was not found.", false)
		return
	}
	if !requireMachineHeaders(r) {
		writeAttachmentError(w, http.StatusUnauthorized, "machine_identity_required", "A renewable machine identity is required.", false)
		return
	}
	raw, err := readAttachmentBody(r)
	if err != nil {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview carrier attachment request is invalid.", false)
		return
	}
	proof, err := h.verifier.VerifyMachineRequest(r.Context(), r, raw)
	if err != nil {
		writeAttachmentError(w, http.StatusUnauthorized, "machine_identity_invalid", "The signed machine request could not be verified.", false)
		return
	}
	if err := proof.Validate(); err != nil {
		writeAttachmentError(w, http.StatusUnauthorized, "machine_identity_invalid", "The signed machine request could not be verified.", false)
		return
	}
	if action != "release" {
		if err := h.precondition.CheckPreviewLeaseIfMatch(r.Context(), proof, previewID, r.Header.Get("If-Match")); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	key, err := singleHeader(r.Header, "Idempotency-Key")
	if err != nil {
		writeAttachmentError(w, http.StatusBadRequest, "idempotency_key_required", "Exactly one Idempotency-Key is required.", false)
		return
	}
	switch action {
	case "allocate":
		h.allocate(w, r, previewID, proof, key, raw)
	case "renew":
		h.renew(w, r, previewID, proof, key, raw)
	case "readiness":
		h.readiness(w, r, previewID, proof, key, raw)
	case "release":
		h.release(w, r, previewID, proof, key, raw)
	default:
		writeAttachmentError(w, http.StatusNotFound, "not_found", "Preview carrier attachment endpoint was not found.", false)
	}
}

func (h *HTTPHandler) allocate(w http.ResponseWriter, r *http.Request, previewID string, proof MachineProof, key string, raw []byte) {
	req, err := DecodeRequest(raw)
	if err != nil || req.PreviewID != previewID || req.IdempotencyKey != key || req.OperationID != key || proof.OperationID != key {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview carrier attachment request is invalid.", false)
		return
	}
	attachment, err := h.service.Allocate(r.Context(), proof, req)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	if attachment.State == StatePending {
		admitted, admitErr := h.service.Admit(r.Context(), proof, req, attachment.Binding, attachment.AttachmentGeneration)
		if admitErr == nil {
			attachment = admitted
		} else if !errors.Is(admitErr, ErrAdmissionUnavailable) {
			writeAttachmentServiceError(w, admitErr)
			return
		}
	}
	status := http.StatusOK
	if attachment.State == StatePending {
		status = http.StatusAccepted
		w.Header().Set("Retry-After", "2")
	}
	writeAttachmentStatus(w, attachment, status)
}

func (h *HTTPHandler) renew(w http.ResponseWriter, r *http.Request, previewID string, proof MachineProof, key string, raw []byte) {
	mutation, err := DecodeMutation(raw, false, false)
	if err != nil || mutation.Request.PreviewID != previewID || mutation.Request.IdempotencyKey != key || mutation.Request.OperationID != key || proof.OperationID != key {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview carrier renewal request is invalid.", false)
		return
	}
	attachment, err := h.service.Renew(r.Context(), proof, mutation.Request, mutation.AttachmentGeneration)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	writeAttachment(w, attachment)
}

func (h *HTTPHandler) readiness(w http.ResponseWriter, r *http.Request, previewID string, proof MachineProof, key string, raw []byte) {
	mutation, err := DecodeMutation(raw, true, true)
	if err != nil || mutation.Request.PreviewID != previewID || mutation.Request.IdempotencyKey != key || mutation.Request.OperationID != key || proof.OperationID != key || mutation.Binding.PreviewID != previewID {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview readiness request is invalid.", false)
		return
	}
	attachment, err := h.service.ObserveOrigin(r.Context(), proof, mutation.Request, mutation.Binding, mutation.AttachmentGeneration, *mutation.OriginReady)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	writeAttachment(w, attachment)
}

func (h *HTTPHandler) release(w http.ResponseWriter, r *http.Request, previewID string, proof MachineProof, key string, raw []byte) {
	mutation, err := DecodeMutation(raw, true, false)
	if err != nil || mutation.Request.PreviewID != previewID || mutation.Request.IdempotencyKey != key || mutation.Request.OperationID != key || proof.OperationID != key || mutation.Binding.PreviewID != previewID {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview release request is invalid.", false)
		return
	}
	// The binding is a server-issued handle. It is validated against the
	// stored row by Service/SQLRepository; the body is not an authorization
	// source merely because it is machine-proof signed.
	// Service needs the persisted request hash to authenticate the handle. Load
	// the complete row by its account and operation before invoking Release.
	persisted, getErr := h.service.Get(r.Context(), mutation.Binding.AccountID, mutation.Request.OperationID)
	if getErr != nil {
		writeAttachmentServiceError(w, getErr)
		return
	}
	if persisted.PreviewID != previewID || persisted.Binding != mutation.Binding {
		writeAttachmentError(w, http.StatusConflict, "stale_binding", "Preview carrier attachment binding is stale.", false)
		return
	}
	result, err := h.service.Release(r.Context(), proof, mutation.Request, persisted, mutation.AttachmentGeneration)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	writeAttachment(w, result)
}

func attachmentPath(r *http.Request) (previewID, action string, ok bool) {
	if r == nil || r.URL == nil {
		return "", "", false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if !strings.HasPrefix(path, AttachmentPathPrefix) || !strings.HasSuffix(path, AttachmentPathSuffix) && !strings.Contains(path, AttachmentPathSuffix+"/") {
		return "", "", false
	}
	remainder := strings.TrimPrefix(path, AttachmentPathPrefix)
	parts := strings.Split(remainder, "/")
	if len(parts) < 2 || parts[1] != strings.TrimPrefix(AttachmentPathSuffix, "/") || !validID(parts[0]) {
		return "", "", false
	}
	if len(parts) == 2 {
		return parts[0], "allocate", true
	}
	if len(parts) != 3 || parts[2] == "" {
		return "", "", false
	}
	switch parts[2] {
	case "renew", "release", "readiness":
		return parts[0], parts[2], true
	default:
		return "", "", false
	}
}

func requireMachineHeaders(r *http.Request) bool {
	return r != nil && strings.TrimSpace(r.Header.Get("Authorization")) != "" && strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity")) != "" && strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")) != ""
}

func readAttachmentBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("%w: request body is required", ErrInvalid)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil || len(body) > MaxRequestBytes {
		return nil, fmt.Errorf("%w: request body is too large or unreadable", ErrInvalid)
	}
	return body, nil
}

func singleHeader(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", ErrInvalid
	}
	return values[0], nil
}

func writeAttachment(w http.ResponseWriter, attachment Attachment) {
	writeAttachmentStatus(w, attachment, http.StatusOK)
}

func writeAttachmentStatus(w http.ResponseWriter, attachment Attachment, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", fmt.Sprintf(`"ptv1:preview_carrier_attachment:%s:%d"`, attachment.OperationID, attachment.AttachmentGeneration))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Data Attachment `json:"data"`
	}{Data: attachment})
}

func writeAttachmentError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Schema    string `json:"schema"`
			Kind      string `json:"kind"`
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}{Error: struct {
		Schema    string `json:"schema"`
		Kind      string `json:"kind"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}{Schema: Schema, Kind: "error", Code: code, Message: message, Retryable: retryable}})
}

func writeAttachmentServiceError(w http.ResponseWriter, err error) {
	slog.Warn("preview carrier attachment failed", "error", err)
	status, code, message, retryable := http.StatusInternalServerError, "internal_error", "Preview carrier attachment could not be completed.", true
	switch {
	case errors.Is(err, ErrInvalid):
		status, code, message, retryable = http.StatusBadRequest, "invalid_request", "Preview carrier attachment request is invalid.", false
	case errors.Is(err, ErrUnauthorized):
		status, code, message, retryable = http.StatusForbidden, "forbidden", "The machine is not the preview owner.", false
	case errors.Is(err, ErrNotFound):
		status, code, message, retryable = http.StatusNotFound, "not_found", "Preview carrier attachment was not found.", false
	case errors.Is(err, ErrIdempotencyConflict):
		status, code, message, retryable = http.StatusConflict, "idempotency_conflict", "Idempotency-Key conflicts with the original operation.", false
	case errors.Is(err, ErrStaleBinding):
		status, code, message, retryable = http.StatusPreconditionFailed, "stale_binding", "The preview carrier changed; refresh its attachment.", false
	case errors.Is(err, ErrConflict), errors.Is(err, ErrTerminal):
		status, code, message, retryable = http.StatusConflict, "attachment_conflict", "The preview carrier attachment is no longer mutable.", false
	case errors.Is(err, ErrExpired):
		status, code, message, retryable = http.StatusConflict, "attachment_expired", "The preview lease has expired.", false
	case errors.Is(err, ErrAdmissionUnavailable):
		status, code, message, retryable = http.StatusServiceUnavailable, "edge_admission_unavailable", "The edge has not accepted this preview carrier yet.", true
	}
	writeAttachmentError(w, status, code, message, retryable)
}
