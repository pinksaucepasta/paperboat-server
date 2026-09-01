package privateaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

const AuthorizePath = "/v1/edge/private-access/authorize"

type EdgeVerifier interface {
	VerifyEdgeRequest(context.Context, *http.Request, []byte) (EdgeIdentity, error)
}

// PreviewEdgeVerifierAdapter allows the canonical preview edge verifier to be
// reused for private access without introducing a second edge credential.
type PreviewEdgeVerifierAdapter struct {
	Verifier previewattachment.PreviewEdgeRequestVerifier
}

func (a PreviewEdgeVerifierAdapter) VerifyEdgeRequest(ctx context.Context, r *http.Request, body []byte) (EdgeIdentity, error) {
	if a.Verifier == nil {
		return EdgeIdentity{}, ErrIdentityUnavailable
	}
	identity, err := a.Verifier.VerifyPreviewEdgeRequest(ctx, r, body)
	if err != nil {
		return EdgeIdentity{}, err
	}
	return EdgeIdentity{NodeID: identity.NodeID, ProcessEpoch: identity.ProcessEpoch}, nil
}

type HTTPHandler struct {
	service *Service
	edge    EdgeVerifier
}

func NewHTTPHandler(service *Service, edge EdgeVerifier) (*HTTPHandler, error) {
	if service == nil || edge == nil {
		return nil, fmt.Errorf("%w: private access HTTP dependencies are incomplete", ErrInvalid)
	}
	return &HTTPHandler{service: service, edge: edge}, nil
}

func (h *HTTPHandler) Register(mux *http.ServeMux) error {
	if h == nil || mux == nil {
		return fmt.Errorf("%w: private access HTTP handler or mux is nil", ErrInvalid)
	}
	mux.Handle("POST "+AuthorizePath, h)
	return nil
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.edge == nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "private_access_unavailable", "Private access is unavailable.", true)
		return
	}
	if r == nil || r.Method != http.MethodPost || r.URL == nil || strings.TrimSuffix(r.URL.Path, "/") != AuthorizePath {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Private access authorization requires POST.", false)
		return
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		writeHTTPError(w, http.StatusUnsupportedMediaType, "content_type_required", "Private access authorization requires application/json.", false)
		return
	}
	raw, err := readBody(r)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "invalid_request", "Private access authorization request is invalid.", false)
		return
	}
	edgeIdentity, err := h.edge.VerifyEdgeRequest(r.Context(), r, raw)
	if err != nil {
		if auditErr := h.service.recordEdgeIdentityDenial(r.Context()); auditErr != nil {
			writeHTTPError(w, http.StatusServiceUnavailable, "authorization_unavailable", "Private access authorization is unavailable.", true)
			return
		}
		writeHTTPError(w, http.StatusUnauthorized, "edge_identity_invalid", "The edge identity could not be verified.", false)
		return
	}
	request, err := decodeRequest(raw)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "invalid_request", "Private access authorization request is invalid.", false)
		return
	}
	grant, err := singleHeader(r.Header, "X-Paperboat-Private-Access-Grant", false)
	if err != nil {
		writeHTTPError(w, http.StatusUnauthorized, "grant_required", "A signed private access grant is required.", false)
		return
	}
	decision, err := h.service.Authorize(r.Context(), AuthorizeInput{Request: request, Edge: edgeIdentity, Grant: grant})
	if err == nil {
		writeDecision(w, decision, nil)
		return
	}
	var denied *DeniedError
	if errors.As(err, &denied) {
		writeDecision(w, decision, denied)
		return
	}
	if errors.Is(err, ErrIdempotencyConflict) {
		writeHTTPError(w, http.StatusConflict, "idempotency_conflict", "The authorization retry does not match the original request.", false)
		return
	}
	writeHTTPError(w, http.StatusServiceUnavailable, "authorization_unavailable", "Private access authorization is unavailable.", true)
}

func writeDecision(w http.ResponseWriter, decision Decision, denied *DeniedError) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if denied != nil {
		switch denied.Reason {
		case ReasonUnauthenticated, ReasonDeviceRevoked, ReasonSessionExpired, ReasonIdentityInvalid:
			status = http.StatusUnauthorized
		case ReasonInternal, ReasonRoutePaused, ReasonRateLimited:
			status = http.StatusServiceUnavailable
		default:
			status = http.StatusForbidden
		}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decision)
}

func writeHTTPError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Schema    string `json:"schema"`
		Kind      string `json:"kind"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}{Schema: Schema, Kind: "error", Code: code, Message: message, Retryable: retryable})
}

func decodeRequest(raw []byte) (Request, error) {
	if len(raw) == 0 || len(raw) > MaximumRequestBody || canonicaljson.RejectDuplicateFields(raw) != nil {
		return Request{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Request{}, ErrInvalid
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

func readBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaximumRequestBody+1))
	if err != nil || len(raw) > MaximumRequestBody {
		return nil, ErrInvalid
	}
	return raw, nil
}

func singleHeader(header http.Header, name string, optional bool) (string, error) {
	values := header.Values(name)
	if len(values) == 0 && optional {
		return "", nil
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], "\r\n") {
		return "", ErrInvalid
	}
	return values[0], nil
}
