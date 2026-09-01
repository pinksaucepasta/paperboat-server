// Package previewattachment contains the server-authoritative contract for
// attaching a preview lease to a canonical data carrier.
//
// An attachment is deliberately not a credential.  It is a short-lived,
// generation-fenced description of which canonical carrier session may serve
// one preview operation.  The carrier's renewable machine proof remains the
// only authentication material on the wire.
package previewattachment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
)

const (
	Schema = "paperboat.preview-tunnel/v1"
	Kind   = "preview_carrier_attachment"

	StatePending   = "pending"
	StateAdmitted  = "admitted"
	StateEdgeReady = "edge_ready"
	StateReady     = "ready"
	StateFailed    = "failed"
	StateReleased  = "released"
)

var (
	ErrInvalid              = errors.New("invalid preview carrier attachment")
	ErrNotFound             = errors.New("preview carrier attachment not found")
	ErrIdempotencyConflict  = errors.New("preview carrier attachment idempotency conflict")
	ErrConflict             = errors.New("preview carrier attachment conflict")
	ErrStaleBinding         = errors.New("stale preview carrier attachment binding")
	ErrExpired              = errors.New("preview carrier attachment expired")
	ErrTerminal             = errors.New("preview carrier attachment is terminal")
	ErrUnauthorized         = errors.New("preview carrier attachment machine proof does not authorize request")
	ErrAdmissionUnavailable = errors.New("preview carrier edge admission was not accepted")
)

// MachineProof is the result of VerifyMachineRequest.  The package never
// verifies signatures itself, and never accepts a caller-supplied account or
// machine identity as authority.  The HTTP adapter must populate this only
// after canonical proof verification.
type MachineProof struct {
	UserID                 string
	MachineID              string
	OperationID            string
	InstallationGeneration uint64
}

func (p MachineProof) Validate() error {
	if !validID(p.UserID) || !validID(p.MachineID) || !validID(p.OperationID) {
		return fmt.Errorf("%w: incomplete machine proof", ErrInvalid)
	}
	if p.InstallationGeneration == 0 {
		return fmt.Errorf("%w: installation generation must be positive", ErrInvalid)
	}
	return nil
}

// Request is the stable, signed-operation portion of an attachment request.
// AccountID is intentionally absent: it is derived from the authoritative
// machine/user mapping, not copied from an untrusted request body.
type Request struct {
	PreviewID      string `json:"preview_id"`
	OperationID    string `json:"operation_id"`
	OwnerDeviceID  string `json:"owner_device_id"`
	OwnerSessionID string `json:"owner_session_id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestID      string `json:"request_id"`
	CorrelationID  string `json:"correlation_id"`
}

func (r Request) Validate() error {
	if !validID(r.PreviewID) || !validID(r.OperationID) || !validID(r.OwnerDeviceID) || !validID(r.OwnerSessionID) {
		return fmt.Errorf("%w: incomplete attachment request", ErrInvalid)
	}
	if len(r.IdempotencyKey) < 1 || len(r.IdempotencyKey) > 256 {
		return fmt.Errorf("%w: idempotency key length must be 1..256", ErrInvalid)
	}
	if len(r.RequestID) < 3 || len(r.RequestID) > 128 || len(r.CorrelationID) < 3 || len(r.CorrelationID) > 128 {
		return fmt.Errorf("%w: request and correlation IDs must be 3..128 bytes", ErrInvalid)
	}
	if hasControl(r.IdempotencyKey) || hasControl(r.RequestID) || hasControl(r.CorrelationID) {
		return fmt.Errorf("%w: trace fields contain control characters", ErrInvalid)
	}
	return nil
}

// Hash returns the hash of the canonical request envelope.  It is suitable
// for operation replay checks and does not include mutable carrier state.
func (r Request) Hash(accountID string) (string, error) {
	if !validID(accountID) {
		return "", fmt.Errorf("%w: invalid account ID", ErrInvalid)
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	// Keep this declaration in wire order.  It is intentionally not a map.
	envelope := struct {
		AccountID      string `json:"account_id"`
		PreviewID      string `json:"preview_id"`
		OperationID    string `json:"operation_id"`
		OwnerDeviceID  string `json:"owner_device_id"`
		OwnerSessionID string `json:"owner_session_id"`
		IdempotencyKey string `json:"idempotency_key"`
		RequestID      string `json:"request_id"`
		CorrelationID  string `json:"correlation_id"`
	}{
		AccountID: accountID, PreviewID: r.PreviewID, OperationID: r.OperationID,
		OwnerDeviceID: r.OwnerDeviceID, OwnerSessionID: r.OwnerSessionID,
		IdempotencyKey: r.IdempotencyKey, RequestID: r.RequestID,
		CorrelationID: r.CorrelationID,
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("%w: canonical request: %v", ErrInvalid, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type Target struct {
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
}

func (t Target) Validate() error {
	if len(t.Scheme) == 0 || len(t.Scheme) > 32 || len(t.Address) == 0 || len(t.Address) > 2048 || hasControl(t.Scheme) || hasControl(t.Address) {
		return fmt.Errorf("%w: invalid target", ErrInvalid)
	}
	for _, allowed := range []string{"http", "https", "h2c", "tcp", "unix"} {
		if strings.EqualFold(t.Scheme, allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: unsupported target scheme %q", ErrInvalid, t.Scheme)
}

// LeaseSnapshot contains authoritative values returned by the server's lease,
// carrier, and route registries. A caller
// cannot construct these values through Request.
type LeaseSnapshot struct {
	AccountID      string
	ActorID        string
	PreviewID      string
	OperationID    string
	OwnerDeviceID  string
	OwnerSessionID string
	Endpoint       string
	Target         Target
	AccessMode     string
	Generation     uint64
	LeaseDeadline  time.Time
	State          string
	// Public verifier values copied from the authoritative user-machine row.
	// They let the edge bind the presented machine certificate to the exact
	// owner without receiving a private key or bearer token.
	MachineIdentityPublicKey  string
	MachineIdentityThumbprint string
}

type CarrierSnapshot struct {
	AccountID string
	HostID    string
	// Ephemeral must be true for preview attachments.  Preview allocation does
	// not require a durable tunnel resource; these canonical IDs identify a
	// short-lived carrier admission created for this operation.
	Ephemeral         bool
	TunnelID          string
	ConnectorID       string
	SessionID         string
	ProcessGeneration uint64
	ConfigGeneration  uint64
	ConfigContentHash string
	LeaseDeadline     time.Time
	// EdgeNodeID is the selected control_tunnel_nodes identity. Endpoint text
	// alone is never authority because an endpoint can be reused or drift.
	EdgeNodeID string
	// EdgeProcessEpoch fences an old edge process that briefly overlaps a
	// replacement while retaining the stable edge node ID.
	EdgeProcessEpoch                     string
	EdgeCarrierServerSPKISHA256          string
	EdgeCarrierServerCertificateChainPEM string
	MachineIdentityPublicKey             string
	MachineIdentityThumbprint            string
	// EdgeEndpoints are transport addresses only. They contain no credentials
	// and are safe to return to the host after machine-proof authentication.
	EdgeEndpoints []string
}

type RouteSnapshot struct {
	AccountID      string
	TunnelID       string
	RouteID        string
	Generation     uint64
	Protocol       string
	PublicEndpoint string
}

type Resolution struct {
	Lease   LeaseSnapshot
	Carrier CarrierSnapshot
	Route   RouteSnapshot
}

// ResolveRequest is passed to an Authority only after the request proof has
// been checked for structural validity.  Authority implementations must read
// current rows/registries and must not trust identity fields from the client.
type ResolveRequest struct {
	Proof   MachineProof
	Request Request
}

// AdmissionRequest is the write-only message sent by the server's edge
// publisher. It contains the exact ephemeral identity and route generation,
// but never a credential or private key. The edge must treat this as a
// single-use, generation-fenced admission and return Accepted or Already.
type AdmissionRequest struct {
	Schema               string    `json:"schema"`
	Kind                 string    `json:"kind"`
	Binding              Binding   `json:"binding"`
	AccessMode           string    `json:"access_mode"`
	IdempotencyKey       string    `json:"idempotency_key"`
	OperationID          string    `json:"operation_id"`
	AttachmentGeneration uint64    `json:"attachment_generation"`
	ConfigContentHash    string    `json:"config_content_hash"`
	EdgeEndpoints        []string  `json:"edge_endpoints"`
	Endpoint             string    `json:"endpoint"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func (a AdmissionRequest) Validate(now time.Time) error {
	if a.Schema != Schema || a.Kind != Kind {
		return fmt.Errorf("%w: invalid admission schema or kind", ErrInvalid)
	}
	if err := a.Binding.validate(); err != nil {
		return err
	}
	if err := validateAccessModeAndRoute(a.AccessMode, ""); err != nil {
		return err
	}
	if a.OperationID != a.Binding.OperationID || len(a.IdempotencyKey) == 0 || a.IdempotencyKey != a.OperationID || a.AttachmentGeneration == 0 {
		return fmt.Errorf("%w: admission operation binding is invalid", ErrInvalid)
	}
	if !validContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: invalid config content hash", ErrInvalid)
	}
	if err := validateEdgeEndpoints(a.EdgeEndpoints); err != nil {
		return err
	}
	if err := validateEndpoint(a.Endpoint); err != nil {
		return err
	}
	if a.ExpiresAt.IsZero() || (!now.IsZero() && !a.ExpiresAt.After(now)) {
		return fmt.Errorf("%w: admission expired", ErrExpired)
	}
	return nil
}

// AdmissionDeliveryStatus is intentionally explicit so a network timeout
// cannot be interpreted as successful edge admission.
type AdmissionDeliveryStatus string

const (
	AdmissionAccepted AdmissionDeliveryStatus = "accepted"
	AdmissionAlready  AdmissionDeliveryStatus = "already_accepted"
	AdmissionRetry    AdmissionDeliveryStatus = "retryable"
	AdmissionRejected AdmissionDeliveryStatus = "rejected"
)

type AdmissionDelivery struct {
	Status AdmissionDeliveryStatus
	Code   string
}

func (d AdmissionDelivery) Accepted() bool {
	return d.Status == AdmissionAccepted || d.Status == AdmissionAlready
}

type AdmissionPublisher interface {
	PublishPreviewCarrierAdmission(context.Context, AdmissionRequest) (AdmissionDelivery, error)
}

type Authority interface {
	ResolvePreviewAttachment(ctx context.Context, in ResolveRequest) (Resolution, error)
}

type Binding struct {
	AccountID                            string `json:"account_id"`
	PreviewID                            string `json:"preview_id"`
	OperationID                          string `json:"operation_id"`
	OwnerDeviceID                        string `json:"owner_device_id"`
	OwnerSessionID                       string `json:"owner_session_id"`
	HostID                               string `json:"host_id"`
	LeaseGeneration                      uint64 `json:"lease_generation"`
	TunnelID                             string `json:"tunnel_id"`
	ConnectorID                          string `json:"connector_id"`
	SessionID                            string `json:"session_id"`
	ProcessGeneration                    uint64 `json:"process_generation"`
	ConfigGeneration                     uint64 `json:"config_generation"`
	RouteID                              string `json:"route_id"`
	RouteGeneration                      uint64 `json:"route_generation"`
	EdgeNodeID                           string `json:"edge_node_id"`
	EdgeProcessEpoch                     string `json:"edge_process_epoch"`
	EdgeCarrierServerSPKISHA256          string `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string `json:"edge_carrier_server_certificate_chain_pem"`
	MachineIdentityPublicKey             string `json:"machine_identity_public_key"`
	MachineIdentityThumbprint            string `json:"machine_identity_thumbprint"`
}

func (b Binding) validate() error {
	for name, value := range map[string]string{
		"account_id": b.AccountID, "preview_id": b.PreviewID, "operation_id": b.OperationID,
		"owner_device_id": b.OwnerDeviceID, "owner_session_id": b.OwnerSessionID,
		"host_id":   b.HostID,
		"tunnel_id": b.TunnelID, "connector_id": b.ConnectorID, "session_id": b.SessionID,
		"route_id": b.RouteID, "edge_node_id": b.EdgeNodeID,
		"edge_process_epoch": b.EdgeProcessEpoch,
	} {
		if !validID(value) {
			return fmt.Errorf("%w: invalid %s", ErrInvalid, name)
		}
	}
	if b.LeaseGeneration == 0 || b.ProcessGeneration == 0 || b.ConfigGeneration == 0 || b.RouteGeneration == 0 {
		return fmt.Errorf("%w: carrier generations must be positive", ErrInvalid)
	}
	if b.HostID != b.OwnerDeviceID {
		return fmt.Errorf("%w: host and preview owner device must match", ErrInvalid)
	}
	if b.TunnelID == b.ConnectorID {
		return fmt.Errorf("%w: tunnel and connector identities must differ", ErrInvalid)
	}
	if connectorprotocol.ValidateOpaqueEpoch(b.EdgeProcessEpoch) != nil {
		return fmt.Errorf("%w: invalid edge process epoch", ErrInvalid)
	}
	if !validCarrierServerSPKISHA256(b.EdgeCarrierServerSPKISHA256) {
		return fmt.Errorf("%w: invalid edge carrier server SPKI pin", ErrInvalid)
	}
	if len(b.EdgeCarrierServerCertificateChainPEM) == 0 || len(b.EdgeCarrierServerCertificateChainPEM) > 64<<10 {
		return fmt.Errorf("%w: invalid edge carrier server certificate chain", ErrInvalid)
	}
	if !validMachineIdentityPublicKey(b.MachineIdentityPublicKey) {
		return fmt.Errorf("%w: invalid machine identity public key", ErrInvalid)
	}
	if !validMachineIdentityThumbprint(b.MachineIdentityThumbprint) {
		return fmt.Errorf("%w: invalid machine identity thumbprint", ErrInvalid)
	}
	return nil
}

// Attachment is the server response and the generation-fenced handle used by
// subsequent Admit, Observe, Renew, and Release calls.  It contains identity
// and routing metadata only.  In particular, it has no token, password,
// private key, bearer, or credential field.
type Attachment struct {
	Schema string `json:"schema"`
	Kind   string `json:"kind"`
	Binding
	IdempotencyKey       string     `json:"idempotency_key"`
	RequestID            string     `json:"request_id"`
	CorrelationID        string     `json:"correlation_id"`
	RequestHash          string     `json:"request_hash"`
	Endpoint             string     `json:"endpoint"`
	Target               Target     `json:"target"`
	AccessMode           string     `json:"access_mode"`
	ConfigContentHash    string     `json:"config_content_hash"`
	EdgeEndpoints        []string   `json:"edge_endpoints"`
	AttachmentGeneration uint64     `json:"attachment_generation"`
	IssuedAt             time.Time  `json:"issued_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	State                string     `json:"state"`
	EdgeReady            bool       `json:"edge_ready"`
	OriginReady          bool       `json:"origin_ready"`
	ReadyAt              *time.Time `json:"ready_at,omitempty"`
	ReleasedAt           *time.Time `json:"released_at,omitempty"`
}

// CarrierAdmission is the write-only result consumed by the edge/host
// carrier registry after it accepts a preview attachment.  It carries only
// canonical identity and generation values.  Machine mTLS/proof material is
// acquired through the existing renewable machine-identity path and is never
// returned by this package.
type CarrierAdmission struct {
	Schema               string         `json:"schema"`
	Kind                 string         `json:"kind"`
	Binding              Binding        `json:"binding"`
	AccessMode           string         `json:"access_mode"`
	AttachmentGeneration uint64         `json:"attachment_generation"`
	ConfigContentHash    string         `json:"config_content_hash"`
	EdgeEndpoints        []string       `json:"edge_endpoints"`
	Endpoint             string         `json:"endpoint"`
	ExpiresAt            time.Time      `json:"expires_at"`
	State                string         `json:"state,omitempty"`
	Hostname             string         `json:"hostname,omitempty"`
	RouteKind            string         `json:"route_kind,omitempty"`
	RouteRevision        uint64         `json:"route_revision,omitempty"`
	Aliases              []CarrierAlias `json:"aliases,omitempty"`
}

type CarrierAlias struct {
	DomainID              string `json:"domain_id"`
	Hostname              string `json:"hostname"`
	MatchType             string `json:"match_type"`
	WildcardLabels        *int   `json:"wildcard_labels,omitempty"`
	PreviewGeneration     uint64 `json:"preview_generation"`
	DomainGeneration      uint64 `json:"domain_generation"`
	CertificateGeneration uint64 `json:"certificate_generation"`
}

func (a CarrierAlias) Validate(previewGeneration uint64) error {
	if !validID(a.DomainID) || a.PreviewGeneration == 0 || a.PreviewGeneration != previewGeneration || a.DomainGeneration == 0 || a.CertificateGeneration == 0 {
		return fmt.Errorf("%w: invalid preview carrier alias binding", ErrInvalid)
	}
	hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Hostname), "."))
	switch a.MatchType {
	case "exact":
		if a.WildcardLabels != nil || strings.HasPrefix(hostname, "*.") || !validAliasDNSName(hostname) {
			return fmt.Errorf("%w: invalid exact preview carrier alias", ErrInvalid)
		}
	case "one_label_wildcard":
		if a.WildcardLabels == nil || *a.WildcardLabels != 1 || !strings.HasPrefix(hostname, "*.") || !validAliasDNSName(strings.TrimPrefix(hostname, "*.")) {
			return fmt.Errorf("%w: invalid wildcard preview carrier alias", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: invalid preview carrier alias match type", ErrInvalid)
	}
	return nil
}

func (a CarrierAdmission) Validate(now time.Time) error {
	if a.Schema != Schema || a.Kind != Kind || a.AttachmentGeneration == 0 {
		return fmt.Errorf("%w: invalid carrier admission", ErrInvalid)
	}
	// Edge ACKs must carry the state from the complete server snapshot.  Do
	// not accept an arbitrary state (or a terminal attachment state) from an
	// edge caller: that would make the wire contract diverge from the server
	// state machine and could turn a malformed admission into an installable
	// route.
	switch a.State {
	case StatePending, StateAdmitted, StateEdgeReady, StateReady:
	default:
		return fmt.Errorf("%w: invalid carrier admission state", ErrInvalid)
	}
	if err := a.Binding.validate(); err != nil {
		return err
	}
	if err := validateAccessModeAndRoute(a.AccessMode, a.RouteKind); err != nil {
		return err
	}
	if !validContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: invalid config content hash", ErrInvalid)
	}
	if err := validateEndpoint(a.Endpoint); err != nil {
		return err
	}
	if err := validateEdgeEndpoints(a.EdgeEndpoints); err != nil {
		return err
	}
	if a.Hostname == "" {
		a.Hostname = endpointHostname(a.Endpoint)
	}
	if a.RouteRevision == 0 {
		a.RouteRevision = a.Binding.RouteGeneration
	}
	if !validID(a.Hostname) || a.RouteRevision != a.Binding.RouteGeneration {
		return fmt.Errorf("%w: invalid route binding", ErrInvalid)
	}
	if len(a.Aliases) > 64 {
		return fmt.Errorf("%w: too many preview carrier aliases", ErrInvalid)
	}
	seenAliasIDs := make(map[string]struct{}, len(a.Aliases))
	seenAliasHosts := make(map[string]struct{}, len(a.Aliases))
	for _, alias := range a.Aliases {
		if err := alias.Validate(a.Binding.LeaseGeneration); err != nil {
			return err
		}
		hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(alias.Hostname), "."))
		if _, duplicate := seenAliasIDs[alias.DomainID]; duplicate {
			return fmt.Errorf("%w: duplicate preview carrier alias", ErrInvalid)
		}
		if _, duplicate := seenAliasHosts[hostname]; duplicate {
			return fmt.Errorf("%w: duplicate preview carrier alias hostname", ErrInvalid)
		}
		seenAliasIDs[alias.DomainID] = struct{}{}
		seenAliasHosts[hostname] = struct{}{}
	}
	if a.ExpiresAt.IsZero() || (!now.IsZero() && !a.ExpiresAt.After(now)) {
		return fmt.Errorf("%w: carrier admission expired", ErrExpired)
	}
	return nil
}

func (a Attachment) Admission() (CarrierAdmission, error) {
	if a.State == StatePending || a.State == StateFailed || a.State == StateReleased {
		return CarrierAdmission{}, fmt.Errorf("%w: attachment has not been edge-admitted", ErrConflict)
	}
	admission := CarrierAdmission{
		Schema: Schema, Kind: Kind, Binding: a.Binding,
		AccessMode:           a.AccessMode,
		AttachmentGeneration: a.AttachmentGeneration, ConfigContentHash: a.ConfigContentHash,
		EdgeEndpoints: append([]string(nil), a.EdgeEndpoints...),
		Endpoint:      a.Endpoint, ExpiresAt: a.ExpiresAt, State: a.State,
		Hostname: endpointHostname(a.Endpoint), RouteKind: routeKindForAccessMode(a.AccessMode), RouteRevision: a.Binding.RouteGeneration,
	}
	if err := admission.Validate(time.Time{}); err != nil {
		return CarrierAdmission{}, err
	}
	return admission, nil
}

func (a Attachment) AdmissionRequest() (AdmissionRequest, error) {
	request := AdmissionRequest{
		Schema: Schema, Kind: Kind, Binding: a.Binding,
		AccessMode:     a.AccessMode,
		IdempotencyKey: a.IdempotencyKey, OperationID: a.OperationID,
		AttachmentGeneration: a.AttachmentGeneration, ConfigContentHash: a.ConfigContentHash,
		EdgeEndpoints: append([]string(nil), a.EdgeEndpoints...), Endpoint: a.Endpoint, ExpiresAt: a.ExpiresAt,
	}
	if err := request.Validate(time.Time{}); err != nil {
		return AdmissionRequest{}, err
	}
	return request, nil
}

const (
	accessModePublic  = "public"
	accessModePrivate = "private"
	publicRouteKind   = "preview_public_https_wss"
	privateRouteKind  = "preview_private_https_wss"
)

func routeForAccessMode(accessMode string) (string, string) {
	switch accessMode {
	case accessModePublic:
		return accessModePublic, publicRouteKind
	case accessModePrivate:
		return accessModePrivate, privateRouteKind
	default:
		return "", ""
	}
}

func routeKindForAccessMode(accessMode string) string {
	_, kind := routeForAccessMode(accessMode)
	return kind
}

// validateAccessModeAndRoute keeps a private preview from being normalized to
// the public route. The current canonical edge admission policy has no private
// authorizer, so private admissions fail closed until that verifier exists.
func validateAccessModeAndRoute(accessMode, routeKind string) error {
	_, want := routeForAccessMode(accessMode)
	if want == "" {
		return fmt.Errorf("%w: access mode must be public or private", ErrInvalid)
	}
	if routeKind != "" && routeKind != want {
		return fmt.Errorf("%w: route kind does not match access mode", ErrInvalid)
	}
	if accessMode == accessModePrivate {
		return fmt.Errorf("%w: private preview route policy is unavailable", ErrAdmissionUnavailable)
	}
	return nil
}

func (a Attachment) Validate(now time.Time) error {
	if a.Schema != Schema || a.Kind != Kind {
		return fmt.Errorf("%w: invalid schema or kind", ErrInvalid)
	}
	if err := a.Binding.validate(); err != nil {
		return err
	}
	if len(a.IdempotencyKey) < 1 || len(a.IdempotencyKey) > 256 || len(a.RequestID) < 3 || len(a.RequestID) > 128 || len(a.CorrelationID) < 3 || len(a.CorrelationID) > 128 || hasControl(a.IdempotencyKey) || hasControl(a.RequestID) || hasControl(a.CorrelationID) {
		return fmt.Errorf("%w: invalid trace fields", ErrInvalid)
	}
	if len(a.RequestHash) != sha256.Size*2 {
		return fmt.Errorf("%w: invalid request hash", ErrInvalid)
	}
	if _, err := hex.DecodeString(a.RequestHash); err != nil {
		return fmt.Errorf("%w: invalid request hash encoding", ErrInvalid)
	}
	if err := a.Target.Validate(); err != nil {
		return err
	}
	if err := validateAccessModeAndRoute(a.AccessMode, ""); err != nil {
		return err
	}
	if err := validateEndpoint(a.Endpoint); err != nil {
		return err
	}
	if err := validateEdgeEndpoints(a.EdgeEndpoints); err != nil {
		return err
	}
	if !validContentHash(a.ConfigContentHash) {
		return fmt.Errorf("%w: invalid config content hash", ErrInvalid)
	}
	if a.AttachmentGeneration == 0 || a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return fmt.Errorf("%w: invalid attachment lifetime", ErrInvalid)
	}
	if !now.IsZero() && !a.ExpiresAt.After(now) && a.State != StateReleased && a.State != StateFailed {
		return fmt.Errorf("%w: attachment expired", ErrExpired)
	}
	switch a.State {
	case StatePending, StateAdmitted:
		if a.EdgeReady || a.OriginReady || a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: origin cannot be ready before edge", ErrInvalid)
		}
	case StateEdgeReady:
		if !a.EdgeReady || a.OriginReady || a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: invalid edge-ready state", ErrInvalid)
		}
	case StateReady:
		if !a.EdgeReady || !a.OriginReady || a.ReadyAt == nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: ready requires edge and origin", ErrInvalid)
		}
	case StateFailed:
		if a.ReadyAt != nil || a.ReleasedAt != nil {
			return fmt.Errorf("%w: failed attachment cannot be ready or released", ErrInvalid)
		}
	case StateReleased:
		if a.ReadyAt != nil || a.ReleasedAt == nil || a.EdgeReady || a.OriginReady {
			return fmt.Errorf("%w: released attachment must be terminal and not ready", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown state %q", ErrInvalid, a.State)
	}
	return nil
}

func validateResolution(now time.Time, r Resolution) error {
	l := r.Lease
	if !validID(l.AccountID) || !validID(l.ActorID) || !validID(l.PreviewID) || !validID(l.OperationID) || !validID(l.OwnerDeviceID) || !validID(l.OwnerSessionID) {
		return fmt.Errorf("%w: incomplete lease resolution", ErrInvalid)
	}
	if !validMachineIdentityPublicKey(l.MachineIdentityPublicKey) || !validMachineIdentityThumbprint(l.MachineIdentityThumbprint) {
		return fmt.Errorf("%w: lease has no valid machine verifier identity", ErrUnauthorized)
	}
	if l.Generation == 0 || l.LeaseDeadline.IsZero() || (!now.IsZero() && !l.LeaseDeadline.After(now)) {
		return fmt.Errorf("%w: lease is expired or has no generation", ErrExpired)
	}
	if l.State == StateReleased || l.State == StateFailed || strings.EqualFold(l.State, "stopped") || strings.EqualFold(l.State, "expired") {
		return fmt.Errorf("%w: lease is terminal", ErrTerminal)
	}
	if err := l.Target.Validate(); err != nil {
		return err
	}
	if err := validateAccessModeAndRoute(l.AccessMode, ""); err != nil {
		return err
	}
	if err := validateEndpoint(l.Endpoint); err != nil {
		return err
	}
	c := r.Carrier
	if c.AccountID != l.AccountID || c.HostID != l.OwnerDeviceID || !c.Ephemeral || !validID(c.TunnelID) || !validID(c.ConnectorID) || !validID(c.SessionID) || c.ProcessGeneration == 0 || c.ConfigGeneration == 0 || !validContentHash(c.ConfigContentHash) || !validID(c.EdgeNodeID) || connectorprotocol.ValidateOpaqueEpoch(c.EdgeProcessEpoch) != nil || !validCarrierServerSPKISHA256(c.EdgeCarrierServerSPKISHA256) {
		return fmt.Errorf("%w: carrier does not match lease owner or identity", ErrConflict)
	}
	if c.MachineIdentityPublicKey != l.MachineIdentityPublicKey || c.MachineIdentityThumbprint != l.MachineIdentityThumbprint {
		return fmt.Errorf("%w: carrier machine verifier identity does not match lease owner", ErrUnauthorized)
	}
	if !validMachineIdentityPublicKey(c.MachineIdentityPublicKey) || !validMachineIdentityThumbprint(c.MachineIdentityThumbprint) {
		return fmt.Errorf("%w: carrier has no valid machine verifier identity", ErrConflict)
	}
	if err := validateEdgeEndpoints(c.EdgeEndpoints); err != nil {
		return err
	}
	if c.LeaseDeadline.IsZero() || !c.LeaseDeadline.After(now) || c.LeaseDeadline.After(l.LeaseDeadline) {
		return fmt.Errorf("%w: carrier lifetime is outside lease lifetime", ErrConflict)
	}
	rt := r.Route
	if rt.AccountID != l.AccountID || rt.TunnelID != c.TunnelID || !validID(rt.RouteID) || rt.Generation == 0 || rt.Protocol == "" || rt.PublicEndpoint == "" {
		return fmt.Errorf("%w: route does not match carrier", ErrConflict)
	}
	if endpointHost(l.Endpoint) != endpointHost(rt.PublicEndpoint) {
		return fmt.Errorf("%w: route endpoint does not match lease endpoint", ErrConflict)
	}
	return nil
}

func bindingFromResolution(r Resolution) Binding {
	return Binding{
		AccountID: r.Lease.AccountID, PreviewID: r.Lease.PreviewID, OperationID: r.Lease.OperationID,
		OwnerDeviceID: r.Lease.OwnerDeviceID, OwnerSessionID: r.Lease.OwnerSessionID,
		HostID: r.Carrier.HostID, LeaseGeneration: r.Lease.Generation,
		TunnelID: r.Carrier.TunnelID, ConnectorID: r.Carrier.ConnectorID, SessionID: r.Carrier.SessionID,
		ProcessGeneration: r.Carrier.ProcessGeneration, ConfigGeneration: r.Carrier.ConfigGeneration,
		RouteID: r.Route.RouteID, RouteGeneration: r.Route.Generation,
		EdgeNodeID:                           r.Carrier.EdgeNodeID,
		EdgeProcessEpoch:                     r.Carrier.EdgeProcessEpoch,
		EdgeCarrierServerSPKISHA256:          r.Carrier.EdgeCarrierServerSPKISHA256,
		EdgeCarrierServerCertificateChainPEM: r.Carrier.EdgeCarrierServerCertificateChainPEM,
		MachineIdentityPublicKey:             r.Carrier.MachineIdentityPublicKey,
		MachineIdentityThumbprint:            r.Carrier.MachineIdentityThumbprint,
	}
}

func logicalBindingEqual(a, b Binding) bool {
	return a.AccountID == b.AccountID && a.PreviewID == b.PreviewID && a.OperationID == b.OperationID && a.OwnerDeviceID == b.OwnerDeviceID && a.OwnerSessionID == b.OwnerSessionID && a.HostID == b.HostID && a.TunnelID == b.TunnelID && a.ConnectorID == b.ConnectorID && a.RouteID == b.RouteID && a.EdgeNodeID == b.EdgeNodeID
}

func carrierBindingEqual(a, b Binding) bool {
	return logicalBindingEqual(a, b) && a.LeaseGeneration == b.LeaseGeneration && a.SessionID == b.SessionID && a.ProcessGeneration == b.ProcessGeneration && a.ConfigGeneration == b.ConfigGeneration && a.RouteGeneration == b.RouteGeneration && a.EdgeProcessEpoch == b.EdgeProcessEpoch && a.EdgeCarrierServerSPKISHA256 == b.EdgeCarrierServerSPKISHA256 && a.EdgeCarrierServerCertificateChainPEM == b.EdgeCarrierServerCertificateChainPEM && a.MachineIdentityPublicKey == b.MachineIdentityPublicKey && a.MachineIdentityThumbprint == b.MachineIdentityThumbprint
}

func dataCarrierBindingEqual(a, b Binding) bool {
	return logicalBindingEqual(a, b) && a.SessionID == b.SessionID && a.ProcessGeneration == b.ProcessGeneration && a.ConfigGeneration == b.ConfigGeneration && a.RouteGeneration == b.RouteGeneration && a.EdgeProcessEpoch == b.EdgeProcessEpoch && a.EdgeCarrierServerSPKISHA256 == b.EdgeCarrierServerSPKISHA256 && a.EdgeCarrierServerCertificateChainPEM == b.EdgeCarrierServerCertificateChainPEM && a.MachineIdentityPublicKey == b.MachineIdentityPublicKey && a.MachineIdentityThumbprint == b.MachineIdentityThumbprint
}

func validID(value string) bool {
	if len(value) < 3 || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validAliasDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@[] \t\r\n") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
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

func validContentHash(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validCarrierServerSPKISHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validMachineIdentityPublicKey(value string) bool {
	if len(value) < 40 || len(value) > 256 || hasControl(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validMachineIdentityThumbprint(value string) bool {
	if len(value) != len("sha256:")+43 || !strings.HasPrefix(value, "sha256:") || hasControl(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func machineIdentityThumbprint(publicKey string) (string, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(publicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return "", false
	}
	digest := sha256.Sum256(decoded)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:]), true
}

func validateEndpoint(value string) error {
	if len(value) == 0 || len(value) > 2048 || hasControl(value) {
		return fmt.Errorf("%w: invalid endpoint", ErrInvalid)
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: endpoint must be an absolute URL without credentials, query, or fragment", ErrInvalid)
	}
	if !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("%w: endpoint must use http or https", ErrInvalid)
	}
	return nil
}

func endpointHost(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func endpointHostname(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func validateEdgeEndpoints(endpoints []string) error {
	if len(endpoints) != 2 {
		return fmt.Errorf("%w: exactly one tls and one quic edge endpoint are required", ErrConflict)
	}
	seen := make(map[string]struct{}, len(endpoints))
	schemes := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if len(endpoint) == 0 || len(endpoint) > 2048 || hasControl(endpoint) {
			return fmt.Errorf("%w: invalid edge endpoint", ErrInvalid)
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Path != "" || u.Opaque != "" {
			return fmt.Errorf("%w: edge endpoint must be an absolute URL without credentials, query, or fragment", ErrInvalid)
		}
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "tls", "quic":
		default:
			return fmt.Errorf("%w: unsupported edge endpoint scheme %q", ErrInvalid, u.Scheme)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%w: edge endpoint must include a valid port", ErrInvalid)
		}
		if _, ok := seen[endpoint]; ok {
			return fmt.Errorf("%w: edge endpoints must be unique", ErrInvalid)
		}
		seen[endpoint] = struct{}{}
		schemes[scheme] = struct{}{}
	}
	if len(schemes) != 2 {
		return fmt.Errorf("%w: exactly one tls and one quic edge endpoint are required", ErrConflict)
	}
	return nil
}
