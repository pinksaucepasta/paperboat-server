package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

// PreviewLeaseAPI is kept separate from the common operation/event service so
// route wiring can be added without changing the shared router contract.
type PreviewLeaseAPI interface {
	Create(context.Context, previewtunnelapi.RequestContext, previewv1.CreateRequest) (previewv1.CreateResult, error)
	Get(context.Context, previewtunnelapi.RequestContext, string) (previewv1.PreviewResult, error)
	List(context.Context, previewtunnelapi.RequestContext, string, int) (previewv1.PreviewPage, error)
	Renew(context.Context, previewtunnelapi.RequestContext, string, previewv1.MutationRequest) (previewv1.RenewResult, error)
	Stop(context.Context, previewtunnelapi.RequestContext, string, previewv1.MutationRequest) (previewv1.StopResult, error)
}

// PreviewReadinessAPI is intentionally separate from PreviewLeaseAPI so the
// readiness mutation cannot accidentally be exposed through browser-auth
// handlers. Only a bearer-authenticated owner device may complete a create.
type PreviewReadinessAPI interface {
	ObserveDeviceReadiness(context.Context, previewtunnelapi.RequestContext, string, string, string, string, string, int64, string, string, string) (previewv1.PreviewResult, error)
}

func previewLeaseCreate(service PreviewLeaseAPI, machineIdentities ...machineRequestVerifier) http.HandlerFunc {
	type request struct {
		OwnerDeviceID  string           `json:"owner_device_id"`
		OwnerSessionID string           `json:"owner_session_id"`
		Target         previewv1.Target `json:"target"`
		AccessMode     string           `json:"access_mode,omitempty"`
		ExpiresAt      *time.Time       `json:"expires_at"`
		Domains        *[]string        `json:"domains"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		raw, hash, err := readPreviewLeaseJSON(r, true)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		_ = raw
		key, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		var body request
		if err := decodePreviewLeaseBody(raw, &body); err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		if body.Domains == nil {
			writePreviewLeaseError(w, r, fmt.Errorf("%w: domains is required and may be an empty array", previewv1.ErrInvalidInput))
			return
		}
		requestContext, ok := previewLeaseRequestContext(w, r, raw, key, machineIdentities...)
		if !ok {
			return
		}
		result, err := service.Create(r.Context(), requestContext, previewv1.CreateRequest{
			OwnerDeviceID: body.OwnerDeviceID, OwnerSessionID: body.OwnerSessionID, Target: body.Target,
			AccessMode: body.AccessMode, ExpiresAt: body.ExpiresAt, Domains: *body.Domains, IdempotencyKey: key, RequestHash: hash,
		})
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("ETag", result.ETag)
		// The operation ID is durable server metadata needed by a host to
		// resume its local carrier after an exact 200 replay. Keep it out of
		// the public preview resource and expose it on every create response.
		w.Header().Set("X-Paperboat-Operation-ID", result.Operation.ID)
		status := http.StatusAccepted
		var data any = result.Operation
		if result.Operation.State == "succeeded" {
			status = http.StatusOK
			data = result.Preview
		} else {
			w.Header().Set("Location", "/v1/operations/"+result.Operation.ID)
		}
		writeJSON(w, status, SuccessResponse{Data: data})
	}
}

// previewLeaseMutationAuth keeps the browser/CLI mutation contract while
// allowing a host with only its renewable machine identity to mutate its own
// lease. Machine-authenticated requests are verified by the handler after it
// has read the exact bounded body; this wrapper only avoids forcing them
// through DeviceService, which has no production host session to authenticate.
func previewLeaseMutationAuth(user *auth.Service, devices *auth.DeviceService, identities machineRequestVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity")) != "" || strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")) != "" {
			next.ServeHTTP(w, r)
			return
		}
		requireAnyAuth(user, devices, requireScope("previews:write", requireCSRF(user, next))).ServeHTTP(w, r)
	})
}

// previewLeaseCreateAuth is retained as the named create wrapper used by
// focused handler tests and callers; all preview mutations share the same
// machine-auth bypass and ordinary-auth fallback.
func previewLeaseCreateAuth(user *auth.Service, devices *auth.DeviceService, identities machineRequestVerifier, next http.Handler) http.Handler {
	return previewLeaseMutationAuth(user, devices, identities, next)
}

// previewLeaseRequestContext derives a host actor only from a verified proof.
// In particular, a CLI client session ID is never treated as a machine ID.
func previewLeaseRequestContext(w http.ResponseWriter, r *http.Request, body []byte, idempotencyKey string, machineIdentities ...machineRequestVerifier) (previewtunnelapi.RequestContext, bool) {
	identityHeader := strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity"))
	proofHeader := strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof"))
	if identityHeader == "" && proofHeader == "" {
		return previewTunnelRequestContext(w, r)
	}
	if len(machineIdentities) == 0 || machineIdentities[0] == nil {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_required", "A signed host identity is required.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	bearer, bearerOK := bearerToken(r)
	if !bearerOK {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "unauthenticated", "A machine identity is required.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	proof, err := base64.RawURLEncoding.Strict().DecodeString(proofHeader)
	if err != nil || len(proof) == 0 {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	identity := identityHeader
	if identity != "" && identity != bearer {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	if identity == "" {
		identity = bearer
	}
	claims, err := machineIdentities[0].VerifyMachineRequest(r.Context(), identity, proof, r.Method, r.URL.Path, body)
	if err != nil || claims.UserID == "" || claims.MachineID == "" || claims.InstallationGeneration < 1 || claims.OperationID != idempotencyKey {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	if principal, ok := principalFromContext(r.Context()); ok && principal.User.ID != "" && principal.User.ID != claims.UserID {
		writePreviewLeaseError(w, r, previewtunnelapi.ErrForbidden)
		return previewtunnelapi.RequestContext{}, false
	}
	return previewtunnelapi.RequestContext{
		Actor: previewtunnelapi.Actor{
			AccountID: claims.UserID, ActorID: claims.UserID, DeviceID: claims.MachineID, HostID: claims.MachineID,
			Role: "user", Scopes: []string{"previews:write"},
		},
		RequestID:     requestIDFromContext(r.Context()),
		CorrelationID: observability.CorrelationID(r.Context()),
	}, true
}

func previewLeaseList(service PreviewLeaseAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestContext, ok := previewTunnelRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		page, err := service.List(r.Context(), requestContext, r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: page})
	}
}

func previewLeaseGet(service PreviewLeaseAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestContext, ok := previewTunnelRequestContext(w, r)
		if !ok {
			return
		}
		result, err := service.Get(r.Context(), requestContext, r.PathValue("preview_id"))
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("ETag", result.ETag)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result.Preview})
	}
}

func previewLeaseReadiness(service PreviewReadinessAPI, identities machineRequestVerifier) http.HandlerFunc {
	type request struct {
		OwnerDeviceID   string `json:"owner_device_id"`
		OwnerSessionID  string `json:"owner_session_id"`
		AllocationState string `json:"allocation_state"`
		EdgeState       string `json:"edge_state"`
		OriginState     string `json:"origin_state"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// This route is authenticated by a renewable machine identity and its
		// request proof. It deliberately does not use the CLI DeviceService:
		// production hosts may have no browser/CLI client-session bearer at all.
		// A bearer is still required, and is either the machine identity itself
		// or the companion device token used by the host runtime.
		bearer, bearerOK := bearerToken(r)
		if !bearerOK {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "unauthenticated", "A machine identity is required.", "unchanged", false, "run_on_authorized_host")
			return
		}
		if identities == nil {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_required", "A signed host identity is required.", "unchanged", false, "run_on_authorized_host")
			return
		}
		idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		raw, _, err := readPreviewLeaseJSON(r, true)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		var body request
		if err := decodePreviewLeaseBody(raw, &body); err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		proof, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")))
		if err != nil || len(proof) == 0 {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
			return
		}
		identity := strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity"))
		if identity != "" && identity != bearer {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
			return
		}
		if identity == "" {
			identity = bearer
		}
		claims, err := identities.VerifyMachineRequest(r.Context(), identity, proof, r.Method, r.URL.Path, raw)
		if err != nil || claims.UserID == "" || claims.MachineID == "" || claims.InstallationGeneration < 1 || claims.OperationID != idempotencyKey {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
			return
		}
		if claims.MachineID != strings.TrimSpace(body.OwnerDeviceID) {
			writePreviewLeaseError(w, r, previewv1.ErrOwnerDenied)
			return
		}
		requestContext := previewtunnelapi.RequestContext{
			Actor: previewtunnelapi.Actor{
				AccountID: claims.UserID, ActorID: claims.UserID, DeviceID: claims.MachineID, HostID: claims.MachineID,
				Role: "user", Scopes: []string{"previews:write"},
			},
			RequestID: requestIDFromContext(r.Context()), CorrelationID: observability.CorrelationID(r.Context()),
		}
		previewID := r.PathValue("preview_id")
		expectedGeneration, err := previewtunnelapi.ParseIfMatch(r.Header, "preview_lease", previewID)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		result, err := service.ObserveDeviceReadiness(r.Context(), requestContext, previewID, idempotencyKey, body.OwnerDeviceID, body.OwnerSessionID, strings.TrimSpace(r.Header.Get(previewtunnelapi.IfMatchHeader)), expectedGeneration, body.AllocationState, body.EdgeState, body.OriginState)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("ETag", result.ETag)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result.Preview})
	}
}

func previewLeaseRenew(service PreviewLeaseAPI, machineIdentities ...machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		previewID := r.PathValue("preview_id")
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, "preview_lease", previewID)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		key, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		raw, hash, err := readPreviewLeaseMutationJSON(r)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		var body struct {
			OwnerSessionID string `json:"owner_session_id"`
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := decodePreviewLeaseBody(raw, &body); err != nil {
				writePreviewLeaseError(w, r, err)
				return
			}
		}
		requestContext, ok := previewLeaseRequestContext(w, r, raw, key, machineIdentities...)
		if !ok {
			return
		}
		result, err := service.Renew(r.Context(), requestContext, previewID, previewv1.MutationRequest{
			ExpectedGeneration: generation, OwnerSessionID: body.OwnerSessionID, IdempotencyKey: key, RequestHash: hash,
		})
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("ETag", result.ETag)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result.Preview})
	}
}

func previewLeaseStop(service PreviewLeaseAPI, machineIdentities ...machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		previewID := r.PathValue("preview_id")
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, "preview_lease", previewID)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		key, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		raw, hash, err := readPreviewLeaseMutationJSON(r)
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			var body struct{}
			if err := decodePreviewLeaseBody(raw, &body); err != nil {
				writePreviewLeaseError(w, r, err)
				return
			}
		}
		requestContext, ok := previewLeaseRequestContext(w, r, raw, key, machineIdentities...)
		if !ok {
			return
		}
		result, err := service.Stop(r.Context(), requestContext, previewID, previewv1.MutationRequest{
			ExpectedGeneration: generation, IdempotencyKey: key, RequestHash: hash,
		})
		if err != nil {
			writePreviewLeaseError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("ETag", result.ETag)
		writeJSON(w, http.StatusOK, SuccessResponse{Data: result.Preview})
	}
}

// readPreviewLeaseMutationJSON returns the exact bytes received on the wire
// for machine-proof verification while retaining the existing idempotency
// rule that an omitted body and an explicit {} have the same request hash.
func readPreviewLeaseMutationJSON(r *http.Request) ([]byte, [32]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, [32]byte{}, fmt.Errorf("%w: request body is too large or unreadable", previewv1.ErrInvalidInput)
	}
	hashBody := raw
	if len(bytes.TrimSpace(hashBody)) == 0 {
		hashBody = []byte("{}")
	}
	hash, err := previewtunnelapi.RequestHash(hashBody)
	if err != nil {
		return raw, [32]byte{}, fmt.Errorf("%w: request JSON is invalid", previewv1.ErrInvalidInput)
	}
	return raw, hash, nil
}

func readPreviewLeaseJSON(r *http.Request, required bool) ([]byte, [32]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, [32]byte{}, fmt.Errorf("%w: request body is too large or unreadable", previewv1.ErrInvalidInput)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if required {
			return nil, [32]byte{}, fmt.Errorf("%w: request body is required", previewv1.ErrInvalidInput)
		}
		// Optional mutation bodies have one semantic empty document. Hash the
		// canonical object so an omitted body and an explicit {} replay the
		// same durable idempotency record.
		raw = []byte("{}")
	}
	hash, err := previewtunnelapi.RequestHash(raw)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: request JSON is invalid", previewv1.ErrInvalidInput)
	}
	return raw, hash, nil
}

func decodePreviewLeaseBody(raw []byte, target any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%w: request body must be a JSON object", previewv1.ErrInvalidInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: request body must match the preview schema", previewv1.ErrInvalidInput)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: request body must contain one JSON value", previewv1.ErrInvalidInput)
	}
	return nil
}

func writePreviewLeaseError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Warn("preview request failed", "request_id", requestIDFromContext(r.Context()), "error", err)
	status := http.StatusInternalServerError
	code := "internal_error"
	message := "Internal server error."
	outcome := "uncertain"
	retryable := true
	action := "retry"
	switch {
	case errors.Is(err, previewtunnelapi.ErrIfMatchRequired):
		status, code, message, outcome, retryable, action = http.StatusPreconditionRequired, "if_match_required", "If-Match is required for this preview mutation.", "unchanged", false, "refresh_preview"
	case errors.Is(err, previewtunnelapi.ErrInvalidETag):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_precondition", "The preview precondition is invalid.", "unchanged", false, "refresh_preview"
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_cursor", "The preview pagination cursor is invalid.", "unchanged", false, "restart_pagination"
	case errors.Is(err, previewtunnelapi.ErrIdempotencyRequired), errors.Is(err, previewtunnelapi.ErrInvalidIdempotency):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "idempotency_key_required", "A valid Idempotency-Key is required.", "unchanged", false, "retry_with_idempotency_key"
	case errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, previewtunnelapi.ErrHostActorRequired), errors.Is(err, previewv1.ErrOwnerDenied), errors.Is(err, previewtunnelstore.ErrOwnerNotFound):
		status, code, message, outcome, retryable, action = http.StatusForbidden, "forbidden", "You are not allowed to access this preview.", "unchanged", false, "authenticate_with_required_scope"
	case errors.Is(err, previewtunnelstore.ErrNotFound):
		status, code, message, outcome, retryable, action = http.StatusNotFound, "preview_not_found", "The preview was not found.", "unchanged", false, "refresh"
	case errors.Is(err, previewtunnelstore.ErrGenerationConflict):
		status, code, message, outcome, retryable, action = http.StatusPreconditionFailed, "generation_conflict", "The preview changed; refresh it and retry.", "unchanged", false, "refresh_preview"
	case errors.Is(err, previewtunnelstore.ErrIdempotencyConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "idempotency_conflict", "Idempotency-Key conflicts with an earlier preview operation.", "unchanged", false, "retry_with_new_idempotency_key"
	case errors.Is(err, previewtunnelstore.ErrConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "preview_conflict", "The preview could not be allocated without a conflict.", "unchanged", true, "retry"
	case errors.Is(err, previewv1.ErrAttachmentNotReady):
		status, code, message, outcome, retryable, action = http.StatusConflict, "preview_attachment_not_ready", "The authenticated preview carrier is not ready yet.", "unchanged", true, "retry_readiness"
	case errors.Is(err, previewtunnelstore.ErrPreviewLeaseTerminal), errors.Is(err, previewtunnelstore.ErrPreviewLeaseExpired), errors.Is(err, previewtunnelstore.ErrPreviewLeaseDeadlineExceeded):
		status, code, message, outcome, retryable, action = http.StatusConflict, "preview_not_active", "The preview lease is no longer renewable.", "unchanged", false, "create_new_preview"
	case errors.Is(err, previewv1.ErrInvalidInput):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "validation_failed", "Preview request details are invalid.", "unchanged", false, "correct_request"
	}
	writePreviewTunnelErrorWithValues(w, r, status, code, message, outcome, retryable, action)
}

func writePreviewTunnelErrorWithValues(w http.ResponseWriter, r *http.Request, status int, code, message, outcome string, retryable bool, action string) {
	writeJSON(w, status, ErrorResponse{Error: APIError{
		Schema: "paperboat.preview-tunnel/v1", Kind: "error", Code: code, Component: "control", Message: message,
		Outcome: outcome, Retryable: &retryable, RepairAction: action,
		RequestID: requestIDFromContext(r.Context()), CorrelationID: observability.CorrelationID(r.Context()),
	}})
}
