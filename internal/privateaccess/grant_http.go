package privateaccess

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

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
)

const GrantPath = "/v1/edge/private-access/grants"

// GrantIssueRequest deliberately omits account, device, and session fields.
// They are derived from the renewable identity proof and never accepted from
// the request body as authority.
type GrantIssueRequest struct {
	ResourceKind         string    `json:"resource_kind"`
	ResourceID           string    `json:"resource_id"`
	RouteID              string    `json:"route_id"`
	Audience             string    `json:"audience"`
	ExpiresAt            time.Time `json:"expires_at"`
	Nonce                string    `json:"nonce"`
	OperationID          string    `json:"operation_id,omitempty"`
	ConnectorID          string    `json:"connector_id,omitempty"`
	CarrierSessionID     string    `json:"carrier_session_id"`
	RouteGeneration      uint64    `json:"route_generation"`
	ProcessGeneration    uint64    `json:"process_generation"`
	ConfigGeneration     uint64    `json:"config_generation"`
	SessionGeneration    uint64    `json:"session_generation"`
	AssignmentGeneration uint64    `json:"assignment_generation"`
	EdgeNodeID           string    `json:"edge_node_id"`
	EdgeProcessEpoch     string    `json:"edge_process_epoch"`
	Protocol             string    `json:"protocol"`
	Method               string    `json:"method,omitempty"`
	Host                 string    `json:"host,omitempty"`
	Path                 string    `json:"path,omitempty"`
	IdempotencyKey       string    `json:"idempotency_key"`
	RequestID            string    `json:"request_id"`
	CorrelationID        string    `json:"correlation_id"`
}

func (r GrantIssueRequest) bind(identity Identity) Request {
	return Request{
		AccountID: identity.AccountID, ResourceKind: r.ResourceKind, ResourceID: r.ResourceID,
		RouteID: r.RouteID, Audience: r.Audience, DeviceID: identity.DeviceID,
		SessionID: identity.SessionID, InstallationGeneration: identity.InstallationGeneration, ExpiresAt: r.ExpiresAt, Nonce: r.Nonce,
		OperationID: r.OperationID, ConnectorID: r.ConnectorID, CarrierSessionID: r.CarrierSessionID,
		RouteGeneration: r.RouteGeneration, ProcessGeneration: r.ProcessGeneration,
		ConfigGeneration: r.ConfigGeneration, SessionGeneration: r.SessionGeneration,
		AssignmentGeneration: r.AssignmentGeneration, EdgeNodeID: r.EdgeNodeID, EdgeProcessEpoch: r.EdgeProcessEpoch,
		Protocol: r.Protocol, Method: r.Method,
		Host: r.Host, Path: r.Path, IdempotencyKey: r.IdempotencyKey,
		RequestID: r.RequestID, CorrelationID: r.CorrelationID,
	}
}

type GrantIssueResponse struct {
	Schema        string    `json:"schema"`
	Kind          string    `json:"kind"`
	Grant         string    `json:"grant"`
	ExpiresAt     time.Time `json:"expires_at"`
	RequestID     string    `json:"request_id"`
	CorrelationID string    `json:"correlation_id"`
	// Request is the server-normalized signed request. It contains only
	// binding metadata, never proof bytes or a private credential. Returning it
	// lets the edge perform the second authorize call without guessing the
	// accessor's renewable session identity.
	Request Request `json:"request"`
}

type GrantHTTPHandler struct {
	service *Service
	machine MachineRequestVerifier
}

type MachineRequestVerifier interface {
	VerifyMachineControlRequest(context.Context, string, []byte, string, string, []byte) (controlplane.MachineRequestClaims, error)
}

func NewGrantHTTPHandler(service *Service, machine MachineRequestVerifier) (*GrantHTTPHandler, error) {
	if service == nil || machine == nil {
		return nil, fmt.Errorf("%w: private access grant HTTP dependencies are incomplete", ErrInvalid)
	}
	return &GrantHTTPHandler{service: service, machine: machine}, nil
}

func (h *GrantHTTPHandler) Register(mux *http.ServeMux) error {
	if h == nil || mux == nil {
		return fmt.Errorf("%w: private access grant HTTP handler or mux is nil", ErrInvalid)
	}
	mux.Handle("POST "+GrantPath, h)
	return nil
}

func (h *GrantHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.machine == nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "private_access_unavailable", "Private access is unavailable.", true)
		return
	}
	if r == nil || r.Method != http.MethodPost || r.URL == nil || strings.TrimSuffix(r.URL.Path, "/") != GrantPath {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Private access grant issuance requires POST.", false)
		return
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		writeHTTPError(w, http.StatusUnsupportedMediaType, "content_type_required", "Private access grant issuance requires application/json.", false)
		return
	}
	raw, err := readBody(r)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "invalid_request", "Private access grant request is invalid.", false)
		return
	}
	issueRequest, err := decodeGrantIssueRequest(raw)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "invalid_request", "Private access grant request is invalid.", false)
		return
	}
	authorization, authErr := singleHeader(r.Header, "Authorization", false)
	machineIdentity, identityErr := singleHeader(r.Header, "X-Paperboat-Machine-Identity", false)
	proofText, proofErr := singleHeader(r.Header, "X-Paperboat-Machine-Proof", false)
	proof, decodeErr := base64.RawURLEncoding.Strict().DecodeString(proofText)
	if authErr != nil || identityErr != nil || proofErr != nil || decodeErr != nil || !strings.HasPrefix(authorization, "Bearer ") || strings.TrimPrefix(authorization, "Bearer ") != machineIdentity {
		writeHTTPError(w, http.StatusUnauthorized, "machine_identity_invalid", "The machine identity could not be verified.", false)
		return
	}
	claims, err := h.machine.VerifyMachineControlRequest(r.Context(), machineIdentity, proof, r.Method, r.URL.Path, raw)
	if err != nil || claims.UserID == "" || claims.MachineID == "" || claims.InstallationGeneration <= 0 || claims.CredentialJTI == "" || claims.SessionGeneration <= 0 || claims.OperationID != issueRequest.IdempotencyKey {
		writeHTTPError(w, http.StatusUnauthorized, "machine_identity_invalid", "The machine identity could not be verified.", false)
		return
	}
	identity := Identity{AccountID: claims.UserID, UserID: claims.UserID, DeviceID: claims.MachineID, SessionID: claims.CredentialJTI, InstallationGeneration: uint64(claims.InstallationGeneration), ExpiresAt: issueRequest.ExpiresAt, Method: "machine"}
	request := issueRequest.bind(identity)
	grant, err := h.service.IssueGrant(r.Context(), identity, EdgeIdentity{NodeID: request.EdgeNodeID, ProcessEpoch: request.EdgeProcessEpoch}, request)
	if err != nil {
		var denied *DeniedError
		if errors.As(err, &denied) {
			writeHTTPError(w, statusForDenied(denied.Reason), "private_access_denied", "Private access grant issuance was denied.", denied.Retryable)
			return
		}
		writeHTTPError(w, http.StatusServiceUnavailable, "authorization_unavailable", "Private access authorization is unavailable.", true)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(GrantIssueResponse{Schema: Schema, Kind: Kind, Grant: grant, ExpiresAt: request.ExpiresAt, RequestID: request.RequestID, CorrelationID: request.CorrelationID, Request: request})
}

func decodeGrantIssueRequest(raw []byte) (GrantIssueRequest, error) {
	if len(raw) == 0 || len(raw) > MaximumRequestBody || canonicaljson.RejectDuplicateFields(raw) != nil {
		return GrantIssueRequest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request GrantIssueRequest
	if err := decoder.Decode(&request); err != nil {
		return GrantIssueRequest{}, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return GrantIssueRequest{}, ErrInvalid
	}
	return request, nil
}

func statusForDenied(reason DenyReason) int {
	switch reason {
	case ReasonUnauthenticated, ReasonDeviceRevoked, ReasonSessionExpired, ReasonIdentityInvalid:
		return http.StatusUnauthorized
	case ReasonInternal, ReasonRoutePaused, ReasonRateLimited:
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}
