package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

// The preview-domain handlers are intentionally exported as small route
// constructors. Router ownership stays in router.go, while this file owns
// strict decoding, request hashing, preconditions, and safe error mapping.
// All mutations are lease-owner operations and use the service's durable
// idempotency record.

func PreviewDomainListHandler(service previewdomain.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewDomainRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		if service == nil {
			writePreviewDomainError(w, r, previewdomain.ErrDNSUnavailable)
			return
		}
		page, err := service.List(r.Context(), request, previewDomainPreviewID(r), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: page})
	}
}

func PreviewDomainGetHandler(service previewdomain.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewDomainRequestContext(w, r)
		if !ok {
			return
		}
		if service == nil {
			writePreviewDomainError(w, r, previewdomain.ErrDNSUnavailable)
			return
		}
		value, err := service.Get(r.Context(), request, previewDomainPreviewID(r), previewDomainID(r))
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		w.Header().Set("ETag", value.ETag)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
	}
}

func PreviewDomainCreateHandler(service previewdomain.API) http.HandlerFunc {
	type document struct {
		Hostname            string `json:"hostname"`
		Provider            string `json:"provider"`
		CertificateStrategy string `json:"certificate_strategy"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := previewDomainBody(w, r, false)
		if !ok {
			return
		}
		var value document
		if !decodeTunnelJSON(body, &value) {
			writePreviewDomainError(w, r, fmt.Errorf("%w: invalid domain create document", previewdomain.ErrInvalidInput))
			return
		}
		key, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		request, ok := previewDomainRequestContext(w, r)
		if !ok {
			return
		}
		if service == nil {
			writePreviewDomainError(w, r, previewdomain.ErrDNSUnavailable)
			return
		}
		result, err := service.Create(r.Context(), request, previewDomainPreviewID(r), previewdomain.Request{
			Hostname: value.Hostname, Provider: value.Provider, CertificateStrategy: value.CertificateStrategy,
			Mutation: previewdomain.MutationInput{IdempotencyKey: key, RequestHash: hash},
		})
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		writePreviewDomainMutation(w, result, true)
	}
}

func PreviewDomainVerifyHandler(service previewdomain.API) http.HandlerFunc {
	return previewDomainMutationHandler(service, true)
}

func PreviewDomainDeleteHandler(service previewdomain.API) http.HandlerFunc {
	return previewDomainMutationHandler(service, false)
}

func previewDomainMutationHandler(service previewdomain.API, verify bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, hash, ok := previewDomainBody(w, r, true)
		if !ok {
			return
		}
		key, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		domainID := previewDomainID(r)
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, previewdomain.Kind, domainID)
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		request, ok := previewDomainRequestContext(w, r)
		if !ok {
			return
		}
		if service == nil {
			writePreviewDomainError(w, r, previewdomain.ErrDNSUnavailable)
			return
		}
		input := previewdomain.MutationInput{ExpectedGeneration: generation, IdempotencyKey: key, RequestHash: hash}
		var result previewdomain.MutationResult
		if verify {
			result, err = service.Verify(r.Context(), request, previewDomainPreviewID(r), domainID, input)
		} else {
			result, err = service.Delete(r.Context(), request, previewDomainPreviewID(r), domainID, input)
		}
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		writePreviewDomainMutation(w, result, false)
	}
}

func PreviewDomainInstructionsHandler(service previewdomain.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := previewDomainRequestContext(w, r)
		if !ok {
			return
		}
		if service == nil {
			writePreviewDomainError(w, r, previewdomain.ErrDNSUnavailable)
			return
		}
		instructions, err := service.Instructions(r.Context(), request, previewDomainPreviewID(r), previewDomainID(r))
		if err != nil {
			writePreviewDomainError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: instructions})
	}
}

// PreviewDomainList returns a short alias for the configured list handler.
// The Handler names document that the returned value is a fully configured
// http.HandlerFunc.
func PreviewDomainList(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainListHandler(service)
}

func PreviewDomainGet(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainGetHandler(service)
}

func PreviewDomainCreate(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainCreateHandler(service)
}

func PreviewDomainVerify(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainVerifyHandler(service)
}

func PreviewDomainDelete(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainDeleteHandler(service)
}

func PreviewDomainInstructions(service previewdomain.API) http.HandlerFunc {
	return PreviewDomainInstructionsHandler(service)
}

func previewDomainRequestContext(w http.ResponseWriter, r *http.Request) (previewtunnelapi.RequestContext, bool) {
	request, ok := previewTunnelRequestContext(w, r)
	return request, ok
}

func previewDomainPreviewID(r *http.Request) string {
	if value := strings.TrimSpace(r.PathValue("preview_id")); value != "" {
		return value
	}
	return strings.TrimSpace(r.PathValue("previewId"))
}

func previewDomainID(r *http.Request) string {
	if value := strings.TrimSpace(r.PathValue("domain_id")); value != "" {
		return value
	}
	return strings.TrimSpace(r.PathValue("domainId"))
}

func previewDomainBody(w http.ResponseWriter, r *http.Request, allowEmpty bool) ([]byte, [32]byte, bool) {
	body, ok := readTunnelRequestBody(w, r)
	if !ok {
		return nil, [32]byte{}, false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if !allowEmpty {
			writePreviewDomainError(w, r, fmt.Errorf("%w: JSON body is required", previewdomain.ErrInvalidInput))
			return nil, [32]byte{}, false
		}
		body = []byte("{}")
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		writePreviewDomainError(w, r, fmt.Errorf("%w: request body must be a JSON object", previewdomain.ErrInvalidInput))
		return nil, [32]byte{}, false
	}
	if allowEmpty && !isEmptyTunnelMutation(body) {
		writePreviewDomainError(w, r, fmt.Errorf("%w: mutation body must be an empty JSON object", previewdomain.ErrInvalidInput))
		return nil, [32]byte{}, false
	}
	hash, err := previewtunnelapi.RequestHash(body)
	if err != nil {
		writePreviewDomainError(w, r, fmt.Errorf("%w: invalid request JSON", previewdomain.ErrInvalidInput))
		return nil, [32]byte{}, false
	}
	return body, hash, true
}

func writePreviewDomainMutation(w http.ResponseWriter, result previewdomain.MutationResult, create bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", result.Domain.ETag)
	if result.Operation.State == "running" {
		w.Header().Set("Location", "/v1/operations/"+result.Operation.ID)
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: result.Operation})
		return
	}
	status := http.StatusOK
	if create && !result.Replayed {
		status = http.StatusCreated
	}
	writeJSON(w, status, SuccessResponse{Data: result.Domain})
}

func writePreviewDomainError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message, outcome, retryable, action := http.StatusInternalServerError, "internal_error", "Internal server error.", "uncertain", true, "retry"
	switch {
	case errors.Is(err, previewtunnelapi.ErrIfMatchRequired):
		status, code, message, outcome, retryable, action = http.StatusPreconditionRequired, "if_match_required", "If-Match is required for this preview domain mutation.", "unchanged", false, "fetch_current_domain"
	case errors.Is(err, previewtunnelapi.ErrInvalidETag):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_etag", "If-Match does not identify this preview domain.", "unchanged", false, "fetch_current_domain"
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_cursor", "The preview-domain cursor is invalid.", "unchanged", false, "restart_pagination"
	case errors.Is(err, previewtunnelapi.ErrIdempotencyRequired), errors.Is(err, previewtunnelapi.ErrInvalidIdempotency):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "idempotency_key_required", "A valid Idempotency-Key is required.", "unchanged", false, "retry_with_idempotency_key"
	case errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, previewdomain.ErrOwnerDenied):
		status, code, message, outcome, retryable, action = http.StatusForbidden, "forbidden", "You are not allowed to access this preview domain.", "unchanged", false, "authenticate_with_required_scope"
	case errors.Is(err, previewdomain.ErrNotFound):
		status, code, message, outcome, retryable, action = http.StatusNotFound, "domain_not_found", "The preview domain was not found.", "unchanged", false, "refresh_preview"
	case errors.Is(err, previewdomain.ErrGenerationConflict):
		status, code, message, outcome, retryable, action = http.StatusPreconditionFailed, "generation_conflict", "The preview domain changed; refresh it and retry.", "unchanged", false, "fetch_current_domain"
	case errors.Is(err, previewdomain.ErrDomainConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "domain_conflict", "The hostname is already claimed.", "unchanged", false, "choose_different_hostname"
	case errors.Is(err, previewdomain.ErrIdempotencyConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "idempotency_conflict", "The idempotency key conflicts with an earlier operation.", "unchanged", false, "retry_with_new_idempotency_key"
	case errors.Is(err, previewdomain.ErrLeaseNotActive):
		status, code, message, outcome, retryable, action = http.StatusConflict, "preview_not_active", "The preview lease is no longer active.", "unchanged", false, "create_new_preview"
	case errors.Is(err, previewdomain.ErrDNSUnavailable):
		status, code, message, outcome, retryable, action = http.StatusServiceUnavailable, "dns_unavailable", "DNS verification is temporarily unavailable.", "unchanged", true, "retry"
	case errors.Is(err, previewdomain.ErrCertificatePending):
		status, code, message, outcome, retryable, action = http.StatusConflict, "certificate_pending", "The preview domain certificate is not ready.", "unchanged", true, "retry"
	case errors.Is(err, previewdomain.ErrInvalidInput):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_request", "The preview-domain request is invalid.", "unchanged", false, "fix_request"
	}
	writePreviewTunnelError(w, r, status, code, message, outcome, retryable, action)
}
