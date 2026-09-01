// Package privateaccess contains the server authority for private preview and
// tunnel requests.  It deliberately returns a short-lived decision, never a
// reusable bearer or connector credential.
package privateaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
)

const (
	Schema = "paperboat.preview-tunnel/v1"
	Kind   = "private_access_authorization"

	ResourcePreview = "preview"
	ResourceTunnel  = "tunnel"

	ProtocolHTTP = "http"
	ProtocolTCP  = "tcp"

	AudiencePreviewHTTP = "paperboat-preview-http"
	AudienceTunnelHTTP  = "paperboat-tunnel-http"
	AudienceTunnelTCP   = "paperboat-tunnel-tcp"

	DecisionAllowed = "allowed"

	// The edge must renew a decision instead of retaining it indefinitely.
	DefaultDecisionTTL = 45 * time.Second
	MaximumDecisionTTL = 2 * time.Minute
	MaximumRequestBody = 64 << 10
	MaximumPathBytes   = 4096
	MaximumHostBytes   = 512
)

var (
	ErrInvalid             = errors.New("invalid private access request")
	ErrDenied              = errors.New("private access denied")
	ErrResourceNotFound    = errors.New("private access resource not found")
	ErrRouteUnavailable    = errors.New("private access route unavailable")
	ErrIdentityUnavailable = errors.New("private access identity unavailable")
	ErrAuditUnavailable    = errors.New("private access audit unavailable")
	ErrIdempotencyConflict = errors.New("private access idempotency conflict")
)

// DenyReason is stable machine-readable policy output.  The associated
// message is intentionally generic so a caller cannot use this API to probe
// another account's resources.
type DenyReason string

const (
	ReasonUnauthenticated  DenyReason = "unauthenticated"
	ReasonAccountMismatch  DenyReason = "account_mismatch"
	ReasonDeviceRevoked    DenyReason = "device_revoked"
	ReasonSessionExpired   DenyReason = "session_expired"
	ReasonResourceNotFound DenyReason = "resource_not_found"
	ReasonRoutePaused      DenyReason = "route_paused"
	ReasonExpired          DenyReason = "expired"
	ReasonWrongRoute       DenyReason = "wrong_route"
	ReasonProtocolDenied   DenyReason = "protocol_denied"
	ReasonIdentityInvalid  DenyReason = "identity_invalid"
	ReasonRateLimited      DenyReason = "rate_limited"
	ReasonInternal         DenyReason = "authorization_unavailable"
)

func (r DenyReason) valid() bool {
	switch r {
	case DenyReason(DecisionAllowed), ReasonUnauthenticated, ReasonAccountMismatch, ReasonDeviceRevoked,
		ReasonSessionExpired, ReasonResourceNotFound, ReasonRoutePaused,
		ReasonExpired, ReasonWrongRoute, ReasonProtocolDenied,
		ReasonIdentityInvalid, ReasonRateLimited, ReasonInternal:
		return true
	default:
		return false
	}
}

func (r DenyReason) retryable() bool {
	return r == ReasonRoutePaused || r == ReasonRateLimited || r == ReasonInternal
}

// DeniedError is the typed policy failure returned by Authorize.  It contains
// no database text, credential, URL, or user-controlled value.
type DeniedError struct {
	Reason    DenyReason
	Retryable bool
}

func (e *DeniedError) Error() string {
	if e == nil {
		return ErrDenied.Error()
	}
	return "private access denied: " + string(e.Reason)
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

func newDenied(reason DenyReason) *DeniedError {
	if !reason.valid() {
		reason = ReasonInternal
	}
	return &DeniedError{Reason: reason, Retryable: reason.retryable()}
}

// Identity is produced by the renewable stable-host machine verifier.
// verifier.  AccountID is server-derived and must never be copied from the
// resource request.  Revoked and ExpiresAt are checked on every authorization
// call, including an idempotency replay.
type Identity struct {
	AccountID              string
	UserID                 string
	DeviceID               string
	SessionID              string
	ExpiresAt              time.Time
	Revoked                bool
	Method                 string
	InstallationGeneration uint64
}

func (i Identity) Validate(now time.Time) error {
	for name, value := range map[string]string{
		"account_id": i.AccountID, "user_id": i.UserID,
		"device_id": i.DeviceID, "session_id": i.SessionID,
	} {
		if !validID(value) {
			return fmt.Errorf("%w: invalid %s", ErrInvalid, name)
		}
	}
	if i.InstallationGeneration == 0 {
		return fmt.Errorf("%w: invalid installation_generation", ErrInvalid)
	}
	if i.Revoked {
		return newDenied(ReasonDeviceRevoked)
	}
	if i.ExpiresAt.IsZero() || (!now.IsZero() && !i.ExpiresAt.After(now)) {
		return newDenied(ReasonSessionExpired)
	}
	return nil
}

// EdgeIdentity is populated only after the existing edge mTLS/control
// verifier has authenticated the caller. It is kept outside Request because
// the edge must not be able to choose the node or process epoch it claims to
// represent.
type EdgeIdentity struct {
	NodeID       string
	ProcessEpoch string
}

func (e EdgeIdentity) Validate() error {
	if !validID(e.NodeID) || connectorprotocol.ValidateOpaqueEpoch(e.ProcessEpoch) != nil {
		return fmt.Errorf("%w: edge identity is invalid", ErrInvalid)
	}
	return nil
}

// Request contains the exact route and carrier fence supplied by the edge.
// Account identity comes exclusively from Identity and the server resolver.
type Request struct {
	// AccountID is copied into the signed grant, but it is never trusted until
	// it equals the verifier's server-derived identity and the resolver result.
	AccountID              string    `json:"account_id"`
	ResourceKind           string    `json:"resource_kind"`
	ResourceID             string    `json:"resource_id"`
	RouteID                string    `json:"route_id"`
	Audience               string    `json:"audience"`
	DeviceID               string    `json:"device_id"`
	SessionID              string    `json:"session_id"`
	InstallationGeneration uint64    `json:"installation_generation"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
	OperationID            string    `json:"operation_id,omitempty"`
	ConnectorID            string    `json:"connector_id,omitempty"`
	CarrierSessionID       string    `json:"carrier_session_id"`
	RouteGeneration        uint64    `json:"route_generation"`
	ProcessGeneration      uint64    `json:"process_generation"`
	ConfigGeneration       uint64    `json:"config_generation"`
	SessionGeneration      uint64    `json:"session_generation"`
	AssignmentGeneration   uint64    `json:"assignment_generation"`
	EdgeNodeID             string    `json:"edge_node_id"`
	EdgeProcessEpoch       string    `json:"edge_process_epoch"`
	Protocol               string    `json:"protocol"`
	Method                 string    `json:"method,omitempty"`
	Host                   string    `json:"host,omitempty"`
	Path                   string    `json:"path,omitempty"`
	IdempotencyKey         string    `json:"idempotency_key"`
	RequestID              string    `json:"request_id"`
	CorrelationID          string    `json:"correlation_id"`
}

func (r Request) Validate() error {
	if r.ResourceKind != ResourcePreview && r.ResourceKind != ResourceTunnel {
		return fmt.Errorf("%w: unsupported resource kind", ErrInvalid)
	}
	for name, value := range map[string]string{
		"account_id": r.AccountID, "resource_id": r.ResourceID, "route_id": r.RouteID,
		"audience": r.Audience, "device_id": r.DeviceID, "session_id": r.SessionID,
		"carrier_session_id": r.CarrierSessionID,
		"idempotency_key":    r.IdempotencyKey, "request_id": r.RequestID,
		"correlation_id": r.CorrelationID,
		"edge_node_id":   r.EdgeNodeID, "edge_process_epoch": r.EdgeProcessEpoch,
	} {
		if !validID(value) {
			return fmt.Errorf("%w: invalid %s", ErrInvalid, name)
		}
	}
	if r.ResourceKind == ResourcePreview && !validID(r.OperationID) {
		return fmt.Errorf("%w: preview operation_id is required", ErrInvalid)
	}
	if r.ResourceKind == ResourceTunnel && r.OperationID != "" && !validID(r.OperationID) {
		return fmt.Errorf("%w: invalid operation_id", ErrInvalid)
	}
	if r.ResourceKind == ResourceTunnel && !validID(r.ConnectorID) {
		return fmt.Errorf("%w: tunnel connector_id is required", ErrInvalid)
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(time.Unix(0, 0)) {
		return fmt.Errorf("%w: grant expiry is required", ErrInvalid)
	}
	if !validID(r.Nonce) {
		return fmt.Errorf("%w: grant nonce is required", ErrInvalid)
	}
	wantAudience := audienceFor(r.ResourceKind, r.Protocol)
	if r.Audience != wantAudience {
		return fmt.Errorf("%w: grant audience does not match protocol", ErrInvalid)
	}
	if r.Protocol != ProtocolHTTP && r.Protocol != ProtocolTCP {
		return fmt.Errorf("%w: unsupported protocol", ErrInvalid)
	}
	if r.InstallationGeneration == 0 || r.RouteGeneration == 0 || r.SessionGeneration == 0 || r.ProcessGeneration == 0 || r.ConfigGeneration == 0 || r.AssignmentGeneration == 0 {
		return fmt.Errorf("%w: carrier generations must be positive", ErrInvalid)
	}
	if len(r.IdempotencyKey) > 256 || len(r.RequestID) < 3 || len(r.RequestID) > 128 || len(r.CorrelationID) < 3 || len(r.CorrelationID) > 128 {
		return fmt.Errorf("%w: trace fields are out of bounds", ErrInvalid)
	}
	if hasControl(r.IdempotencyKey) || hasControl(r.RequestID) || hasControl(r.CorrelationID) {
		return fmt.Errorf("%w: trace fields contain control characters", ErrInvalid)
	}
	if r.Protocol == ProtocolHTTP {
		if len(r.Method) == 0 || len(r.Method) > 32 || hasControl(r.Method) || strings.ContainsAny(r.Method, " \t") {
			return fmt.Errorf("%w: invalid HTTP method", ErrInvalid)
		}
		if len(r.Host) == 0 || len(r.Host) > MaximumHostBytes || hasControl(r.Host) {
			return fmt.Errorf("%w: invalid HTTP host", ErrInvalid)
		}
		if len(r.Path) == 0 || len(r.Path) > MaximumPathBytes || !strings.HasPrefix(r.Path, "/") || hasControl(r.Path) {
			return fmt.Errorf("%w: invalid HTTP path", ErrInvalid)
		}
	} else if r.Method != "" || r.Host != "" || r.Path != "" {
		return fmt.Errorf("%w: HTTP fields are not valid for TCP", ErrInvalid)
	}
	return nil
}

func audienceFor(resourceKind, protocol string) string {
	switch {
	case resourceKind == ResourcePreview && protocol == ProtocolHTTP:
		return AudiencePreviewHTTP
	case resourceKind == ResourceTunnel && protocol == ProtocolHTTP:
		return AudienceTunnelHTTP
	case resourceKind == ResourceTunnel && protocol == ProtocolTCP:
		return AudienceTunnelTCP
	default:
		return ""
	}
}

// Lookup is the account-scoped query sent to the durable resolver.
type Lookup struct {
	AccountID string
	Request   Request
	Edge      EdgeIdentity
	Now       time.Time
}

// Binding is the authoritative resource/carrier state returned by a
// resolver.  It is not client input.  Preview bindings are derived from
// previewattachment.Attachment and tunnel bindings from tunnel resource and
// connector-session rows.
type Binding struct {
	AccountID        string
	ResourceKind     string
	ResourceID       string
	RouteID          string
	OperationID      string
	ConnectorID      string
	CarrierSessionID string

	OwnerDeviceID  string
	OwnerSessionID string

	RouteGeneration      uint64
	ProcessGeneration    uint64
	ConfigGeneration     uint64
	SessionGeneration    uint64
	AssignmentGeneration uint64
	Protocol             string
	AccessMode           string
	State                string
	ExpiresAt            time.Time
	Hostname             string
	PathPrefix           string
	EdgeNodeID           string
	EdgeProcessEpoch     string
}

func (b Binding) Validate(now time.Time) error {
	if b.ResourceKind != ResourcePreview && b.ResourceKind != ResourceTunnel {
		return fmt.Errorf("%w: binding resource kind is invalid", ErrInvalid)
	}
	for name, value := range map[string]string{
		"account_id": b.AccountID, "resource_id": b.ResourceID,
		"route_id": b.RouteID, "carrier_session_id": b.CarrierSessionID,
	} {
		if !validID(value) {
			return fmt.Errorf("%w: binding %s is invalid", ErrInvalid, name)
		}
	}
	if b.ResourceKind == ResourcePreview && (!validID(b.OperationID) || !validID(b.OwnerDeviceID) || !validID(b.OwnerSessionID)) {
		return fmt.Errorf("%w: preview binding owner or operation is invalid", ErrInvalid)
	}
	if b.ResourceKind == ResourceTunnel && !validID(b.ConnectorID) {
		return fmt.Errorf("%w: tunnel binding connector is invalid", ErrInvalid)
	}
	if b.Protocol != ProtocolHTTP && b.Protocol != ProtocolTCP {
		return fmt.Errorf("%w: binding protocol is invalid", ErrInvalid)
	}
	if b.AccessMode != "private" {
		return newDenied(ReasonProtocolDenied)
	}
	if b.RouteGeneration == 0 || b.SessionGeneration == 0 || b.ProcessGeneration == 0 || b.ConfigGeneration == 0 || b.AssignmentGeneration == 0 {
		return fmt.Errorf("%w: binding generations must be positive", ErrInvalid)
	}
	if b.ExpiresAt.IsZero() || (!now.IsZero() && !b.ExpiresAt.After(now)) {
		return newDenied(ReasonExpired)
	}
	if b.Protocol == ProtocolHTTP && (len(b.Hostname) == 0 || len(b.Hostname) > MaximumHostBytes || hasControl(b.Hostname)) {
		return fmt.Errorf("%w: binding host is invalid", ErrInvalid)
	}
	if (b.EdgeNodeID == "") != (b.EdgeProcessEpoch == "") {
		return fmt.Errorf("%w: binding edge identity is incomplete", ErrInvalid)
	}
	if b.EdgeNodeID != "" {
		if err := (EdgeIdentity{NodeID: b.EdgeNodeID, ProcessEpoch: b.EdgeProcessEpoch}).Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Decision is safe to send to an edge.  It carries no access token, bearer,
// credential, private key, or target secret.  The edge must ask again after
// ExpiresAt and must close active streams when its policy cache expires.
type Decision struct {
	Schema               string     `json:"schema"`
	Kind                 string     `json:"kind"`
	DecisionID           string     `json:"decision_id"`
	Allowed              bool       `json:"allowed"`
	Reason               DenyReason `json:"reason"`
	ExpiresAt            time.Time  `json:"expires_at"`
	RequestID            string     `json:"request_id"`
	CorrelationID        string     `json:"correlation_id"`
	ResourceKind         string     `json:"resource_kind,omitempty"`
	ResourceID           string     `json:"resource_id,omitempty"`
	RouteID              string     `json:"route_id,omitempty"`
	OperationID          string     `json:"operation_id,omitempty"`
	ConnectorID          string     `json:"connector_id,omitempty"`
	CarrierSessionID     string     `json:"carrier_session_id,omitempty"`
	RouteGeneration      uint64     `json:"route_generation,omitempty"`
	SessionGeneration    uint64     `json:"session_generation,omitempty"`
	ProcessGeneration    uint64     `json:"process_generation,omitempty"`
	ConfigGeneration     uint64     `json:"config_generation,omitempty"`
	AssignmentGeneration uint64     `json:"assignment_generation,omitempty"`
	Protocol             string     `json:"protocol,omitempty"`
}

func (d Decision) Validate(now time.Time) error {
	if d.Schema != Schema || d.Kind != Kind || !validID(d.DecisionID) || !d.Reason.valid() || d.ExpiresAt.IsZero() || (!now.IsZero() && !d.ExpiresAt.After(now)) {
		return fmt.Errorf("%w: malformed decision", ErrInvalid)
	}
	if d.Allowed != (d.Reason == DecisionAllowed) {
		return fmt.Errorf("%w: decision allow/reason mismatch", ErrInvalid)
	}
	if len(d.RequestID) < 3 || len(d.RequestID) > 128 || len(d.CorrelationID) < 3 || len(d.CorrelationID) > 128 {
		return fmt.Errorf("%w: malformed decision trace fields", ErrInvalid)
	}
	return nil
}

// ResourceResolver is the only place allowed to turn public IDs into an
// authoritative private route binding.
type ResourceResolver interface {
	ResolvePrivate(context.Context, Lookup) (Binding, error)
}

// MachineStateVerifier performs the fresh revocation and installation check
// used after a grant has been verified at the edge.
type MachineStateVerifier interface {
	VerifyCurrentMachine(context.Context, Identity, time.Time) error
}

// GrantVerifier validates a server-signed, short-lived route grant.  The
// verifier must return the signed request claims, not arbitrary caller input.
type GrantVerifier interface {
	VerifyGrant(context.Context, string, time.Time) (Request, error)
}

// AuditRecord is deliberately a safe projection.  Implementations must not
// add request headers, cookies, URLs with credentials, or proof bytes.
type AuditRecord struct {
	EventType        string
	Allowed          bool
	Reason           DenyReason
	AccountID        string
	UserID           string
	DeviceID         string
	SessionID        string
	ResourceKind     string
	ResourceID       string
	RouteID          string
	OperationID      string
	ConnectorID      string
	CarrierSessionID string
	Protocol         string
	RequestID        string
	CorrelationID    string
	IdempotencyKey   string
}

type AuditSink interface {
	Record(context.Context, AuditRecord) error
}

func requestFingerprint(in AuthorizeInput) (string, error) {
	// Identity is intentionally reduced to server-owned stable IDs. Proof bytes
	// never enter the replay key, audit record, or decision body.
	envelope := struct {
		AccountID string  `json:"account_id"`
		UserID    string  `json:"user_id"`
		DeviceID  string  `json:"device_id"`
		SessionID string  `json:"session_id"`
		Request   Request `json:"request"`
	}{in.Identity.AccountID, in.Identity.UserID, in.Identity.DeviceID, in.Identity.SessionID, in.Request}
	b, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Hash returns the canonical digest bound into a signed private-access grant.
// It includes route, identity, expiry, nonce, and trace fields but never any
// bearer or proof bytes.
func (r Request) Hash() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("%w: hash request", ErrInvalid)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func decisionID(fingerprint string) string {
	return "pad_" + fingerprint[:32]
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e || strings.ContainsRune("/\\?&=#", r) {
			return false
		}
	}
	return true
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func canonicalHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.TrimSuffix(value, ".")
}

func hostFromEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}
