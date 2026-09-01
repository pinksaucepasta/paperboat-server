package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

const maxTunnelRequest = 1 << 20

// tunnelCreate is intentionally separate from the ordinary account handlers.
// The only source of HostID is a successful signed machine proof. No body or
// caller-supplied host header is inspected for ownership.
func tunnelCreate(service tunnelv1.API, identities machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readTunnelRequestBody(w, r)
		if !ok {
			return
		}
		var document tunnelCreateDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelError(w, r, fmt.Errorf("%w: invalid tunnel create document", tunnelv1.ErrInvalidInput))
			return
		}
		hash, err := previewtunnelapi.RequestHash(body)
		if err != nil {
			writeTunnelError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		principal, ok := principalFromContext(r.Context())
		if !ok {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.", "unchanged", false, "authenticate")
			return
		}
		if identities == nil {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_required", "A signed host identity is required to create a tunnel.", "unchanged", false, "run_on_authorized_host")
			return
		}
		proof, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")))
		if err != nil || len(proof) == 0 {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
			return
		}
		claims, err := identities.VerifyMachineRequest(r.Context(), strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Identity")), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.UserID == "" || claims.MachineID == "" || claims.InstallationGeneration <= 0 || claims.UserID != principal.User.ID || claims.OperationID != idempotencyKey {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
			return
		}
		request := tunnelRequestContext(principal, r)
		// A machine proof is the structural identity. DeviceID and HostID are
		// both derived from the verified machine ID so RequireHost cannot be
		// satisfied by a CLI session ID or a caller header.
		request.Actor.DeviceID = claims.MachineID
		request.Actor.HostID = claims.MachineID
		result, err := service.CreateTunnel(r.Context(), request, tunnelv1.CreateTunnelRequest{
			Name: document.Name, AccessMode: document.AccessMode,
			Origin: tunnelv1.OriginRequest{
				Scheme: document.Origin.Scheme, Address: document.Origin.Address,
				PreserveHost: document.Origin.PreserveHost, HostOverride: document.Origin.HostOverride,
			},
			ExpiresAt:     document.ExpiresAt,
			MutationInput: tunnelv1.MutationInput{IdempotencyKey: idempotencyKey, RequestHash: hash},
		})
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		writeTunnelMutation(w, result, result.Replayed, true)
	}
}

func tunnelList(service tunnelv1.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := tunnelRequestFromHTTP(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListTunnels(r.Context(), request, r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: page})
	}
}

func tunnelGet(service tunnelv1.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := tunnelRequestFromHTTP(w, r)
		if !ok {
			return
		}
		value, err := service.GetTunnel(r.Context(), request, tunnelIDFromPath(r))
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		w.Header().Set("ETag", value.ETag)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: value})
	}
}

func tunnelPatch(service tunnelv1.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readTunnelRequestBody(w, r)
		if !ok {
			return
		}
		var document tunnelPatchDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelError(w, r, fmt.Errorf("%w: invalid tunnel patch document", tunnelv1.ErrInvalidInput))
			return
		}
		hash, err := previewtunnelapi.RequestHash(body)
		if err != nil {
			writeTunnelError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, "tunnel", tunnelIDFromPath(r))
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		patch, err := document.request()
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		request, ok := tunnelRequestFromHTTP(w, r)
		if !ok {
			return
		}
		patch.MutationInput = tunnelv1.MutationInput{ExpectedGeneration: generation, IdempotencyKey: idempotencyKey, RequestHash: hash}
		result, err := service.PatchTunnel(r.Context(), request, tunnelIDFromPath(r), patch)
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		writeTunnelMutation(w, result, result.Replayed, false)
	}
}

func tunnelPause(service tunnelv1.API) http.HandlerFunc {
	return tunnelStateMutationHandler(service, service.PauseTunnel)
}

func tunnelResume(service tunnelv1.API) http.HandlerFunc {
	return tunnelStateMutationHandler(service, service.ResumeTunnel)
}

func tunnelDelete(service tunnelv1.API) http.HandlerFunc {
	return tunnelStateMutationHandler(service, service.DeleteTunnel)
}

type tunnelStateMutationFunc func(context.Context, previewtunnelapi.RequestContext, string, tunnelv1.MutationInput) (tunnelv1.MutationResult, error)

func tunnelStateMutationHandler(service tunnelv1.API, mutate tunnelStateMutationFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readTunnelRequestBody(w, r)
		if !ok {
			return
		}
		if len(bytes.TrimSpace(body)) == 0 {
			body = []byte("{}")
		}
		if !isEmptyTunnelMutation(body) {
			writeTunnelError(w, r, fmt.Errorf("%w: state mutation body must be an empty JSON object", tunnelv1.ErrInvalidInput))
			return
		}
		hash, err := previewtunnelapi.RequestHash(body)
		if err != nil {
			writeTunnelError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, "tunnel", tunnelIDFromPath(r))
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		request, ok := tunnelRequestFromHTTP(w, r)
		if !ok {
			return
		}
		result, err := mutate(r.Context(), request, tunnelIDFromPath(r), tunnelv1.MutationInput{
			ExpectedGeneration: generation, IdempotencyKey: idempotencyKey, RequestHash: hash,
		})
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		writeTunnelMutation(w, result, result.Replayed, false)
	}
}

func tunnelStatus(service tunnelv1.API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := tunnelRequestFromHTTP(w, r)
		if !ok {
			return
		}
		status, err := service.Status(r.Context(), request, tunnelIDFromPath(r))
		if err != nil {
			writeTunnelError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, SuccessResponse{Data: status})
	}
}

type tunnelCreateDocument struct {
	Name       string               `json:"name"`
	AccessMode string               `json:"access_mode"`
	Origin     tunnelOriginDocument `json:"origin"`
	ExpiresAt  *time.Time           `json:"expires_at"`
}

type tunnelOriginDocument struct {
	Scheme       string  `json:"scheme"`
	Address      string  `json:"address"`
	PreserveHost *bool   `json:"preserve_host"`
	HostOverride *string `json:"host_override"`
}

type tunnelPatchDocument struct {
	Name       *string         `json:"name"`
	AccessMode *string         `json:"access_mode"`
	ExpiresAt  json.RawMessage `json:"expires_at"`
	raw        map[string]json.RawMessage
}

func (d *tunnelPatchDocument) UnmarshalJSON(data []byte) error {
	type alias tunnelPatchDocument
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("patch body must be a JSON object")
	}
	for key := range fields {
		switch key {
		case "name", "access_mode", "expires_at":
		default:
			return errors.New("unknown tunnel patch field")
		}
	}
	*d = tunnelPatchDocument(decoded)
	d.raw = fields
	return nil
}

func (d tunnelPatchDocument) request() (tunnelv1.PatchTunnelRequest, error) {
	var expiresAt *time.Time
	expirySet := false
	if raw, ok := d.raw["expires_at"]; ok {
		expirySet = true
		if string(bytes.TrimSpace(raw)) != "null" {
			var parsed time.Time
			if err := json.Unmarshal(raw, &parsed); err != nil {
				return tunnelv1.PatchTunnelRequest{}, fmt.Errorf("%w: expires_at must be RFC3339 or null", tunnelv1.ErrInvalidInput)
			}
			expiresAt = &parsed
		}
	}
	if raw, ok := d.raw["name"]; ok && string(bytes.TrimSpace(raw)) == "null" {
		return tunnelv1.PatchTunnelRequest{}, fmt.Errorf("%w: name cannot be null", tunnelv1.ErrInvalidInput)
	}
	if raw, ok := d.raw["access_mode"]; ok && string(bytes.TrimSpace(raw)) == "null" {
		return tunnelv1.PatchTunnelRequest{}, fmt.Errorf("%w: access_mode cannot be null", tunnelv1.ErrInvalidInput)
	}
	return tunnelv1.PatchTunnelRequest{Name: d.Name, AccessMode: d.AccessMode, ExpiresAt: expiresAt, ExpirySet: expirySet}, nil
}

func tunnelRequestFromHTTP(w http.ResponseWriter, r *http.Request) (previewtunnelapi.RequestContext, bool) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.", "unchanged", false, "authenticate")
		return previewtunnelapi.RequestContext{}, false
	}
	return tunnelRequestContext(principal, r), true
}

func tunnelRequestContext(principal principal, r *http.Request) previewtunnelapi.RequestContext {
	actor := previewtunnelapi.Actor{AccountID: principal.User.ID, ActorID: principal.User.ID, Role: string(principal.User.Role)}
	if principal.Client != nil {
		actor.DeviceID = principal.Client.SessionID
		actor.Scopes = append([]string(nil), principal.Client.Scopes...)
	}
	return previewtunnelapi.RequestContext{
		Actor: actor, RequestID: observability.RequestID(r.Context()), CorrelationID: observability.CorrelationID(r.Context()),
	}
}

func readTunnelRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTunnelRequest+1))
	if err != nil || len(body) > maxTunnelRequest {
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_request", "Tunnel request is invalid.", "unchanged", false, "fix_request")
		return nil, false
	}
	return body, true
}

func decodeTunnelJSON(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func isEmptyTunnelMutation(body []byte) bool {
	var fields map[string]json.RawMessage
	if !decodeTunnelJSON(body, &fields) || fields == nil {
		return false
	}
	return len(fields) == 0
}

func tunnelIDFromPath(r *http.Request) string {
	if value := strings.TrimSpace(r.PathValue("tunnel_id")); value != "" {
		return value
	}
	return strings.TrimSpace(r.PathValue("tunnelId"))
}

func writeTunnelMutation(w http.ResponseWriter, result tunnelv1.MutationResult, replayed, create bool) {
	w.Header().Set("ETag", result.Tunnel.ETag)
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if result.Operation.State == "running" {
		status = http.StatusAccepted
	} else if create && !replayed {
		status = http.StatusCreated
	}
	// The wire data is always one canonical v1 resource. Replay and changed
	// booleans are service-internal decisions and are intentionally not exposed
	// as an undocumented mutation envelope.
	if result.Operation.State == "running" {
		writeJSON(w, status, SuccessResponse{Data: result.Operation})
		return
	}
	writeJSON(w, status, SuccessResponse{Data: result.Tunnel})
}

func writeTunnelError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, previewtunnelapi.ErrIfMatchRequired):
		writePreviewTunnelError(w, r, http.StatusPreconditionRequired, "if_match_required", "If-Match is required for this tunnel mutation.", "unchanged", false, "fetch_current_tunnel")
	case errors.Is(err, previewtunnelapi.ErrInvalidETag):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_etag", "If-Match does not identify this tunnel.", "unchanged", false, "fetch_current_tunnel")
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_cursor", "The tunnel cursor is invalid.", "unchanged", false, "restart_pagination")
	case errors.Is(err, previewtunnelapi.ErrIdempotencyRequired):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "idempotency_required", "Idempotency-Key is required.", "unchanged", false, "retry_with_idempotency_key")
	case errors.Is(err, previewtunnelapi.ErrInvalidIdempotency):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key is invalid.", "unchanged", false, "send_valid_idempotency_key")
	case errors.Is(err, previewtunnelapi.ErrHostActorRequired), errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, tunnelv1.ErrHostNotFound):
		writePreviewTunnelError(w, r, http.StatusForbidden, "forbidden", "You are not allowed to perform this tunnel operation.", "unchanged", false, "authenticate_with_required_host")
	case errors.Is(err, tunnelv1.ErrNotFound):
		writePreviewTunnelError(w, r, http.StatusNotFound, "tunnel_not_found", "The tunnel was not found.", "unchanged", false, "refresh")
	case errors.Is(err, tunnelv1.ErrGenerationConflict):
		writePreviewTunnelError(w, r, http.StatusPreconditionFailed, "generation_conflict", "The tunnel changed before this update was applied.", "unchanged", false, "fetch_current_tunnel")
	case errors.Is(err, tunnelv1.ErrIdempotencyConflict):
		writePreviewTunnelError(w, r, http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for different tunnel input.", "unchanged", false, "retry_with_new_idempotency_key")
	case errors.Is(err, tunnelv1.ErrConflict):
		writePreviewTunnelError(w, r, http.StatusConflict, "tunnel_conflict", "The tunnel could not be changed because it conflicts with current state.", "unchanged", false, "refresh_and_retry")
	case errors.Is(err, tunnelv1.ErrNameConflict):
		writePreviewTunnelError(w, r, http.StatusConflict, "tunnel_name_conflict", "A tunnel with this name already exists in the account.", "unchanged", false, "choose_another_name")
	case errors.Is(err, tunnelv1.ErrTerminalState):
		writePreviewTunnelError(w, r, http.StatusConflict, "tunnel_deleted", "The tunnel is deleted and cannot be changed.", "unchanged", false, "create_new_tunnel")
	case errors.Is(err, tunnelv1.ErrOperationInProgress):
		writePreviewTunnelError(w, r, http.StatusConflict, "operation_in_progress", "An earlier tunnel operation is still in progress.", "uncertain", true, "inspect_operation")
	case errors.Is(err, tunnelv1.ErrInvalidInput):
		writePreviewTunnelError(w, r, http.StatusBadRequest, "invalid_request", "Tunnel request is invalid.", "unchanged", false, "fix_request")
	default:
		writePreviewTunnelError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.", "uncertain", true, "retry")
	}
}
