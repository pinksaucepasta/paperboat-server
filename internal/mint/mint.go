package mint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProofType            = "t3-cloud-mint+jwt"
	ProofScope           = "environment:connect"
	RevokeType           = "t3-cloud-revoke+jwt"
	RevokeScope          = "environment:revoke"
	HealthType           = "t3-cloud-health+jwt"
	HealthScope          = "environment:health"
	TerminalControlType  = "t3-cloud-terminal-control+jwt"
	TerminalControlScope = "environment:terminal-control"
	MaxProofTTL          = 5 * time.Minute
	defaultMaxAge        = 5 * time.Minute
)

type Key struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

type Provider struct {
	mu       sync.RWMutex
	activeID string
	keys     map[string]ed25519.PrivateKey
	maxAge   time.Duration
}

type ProofInput struct {
	Issuer             string
	EnvironmentID      string
	UserID             string
	CLIClientSessionID string
	JTI                string
	Nonce              string
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

type RevocationInput struct {
	ProofInput
	SessionIDs []string
	Reason     string
}

type TerminalControlInput struct {
	Issuer        string
	EnvironmentID string
	UserID        string
	JTI           string
	Nonce         string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	Operation     string
	ThreadID      string
	TerminalIDs   []string
}

type CredentialInput struct {
	Issuer          string
	Audience        string
	Subject         string
	JTI             string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	CredentialClass string
	Scopes          []string
	EnvironmentID   string
	// AccountID is the account/tenant binding for credentials that cross the
	// control-plane to a user-owned machine. It is intentionally separate from
	// EnvironmentID: an environment is an execution target, not an authority
	// boundary.
	AccountID              string
	EnrollmentID           string
	AssignmentID           string
	WarningRevision        string
	HelperID               string
	MachineID              string
	SourceMachineID        string
	UserID                 string
	ActorID                string
	CLIClientSessionID     string
	SessionID              string
	OperationID            string
	PreviewID              string
	OwnerSessionID         string
	IdempotencyKey         string
	RequestID              string
	CorrelationID          string
	TargetScheme           string
	TargetAddress          string
	AccessMode             string
	Endpoint               string
	LeaseDeadline          time.Time
	UserDeadline           *time.Time
	LeaseETag              string
	State                  string
	AllocationState        string
	EdgeState              string
	OriginState            string
	CreatedAt              time.Time
	LastRenewedAt          time.Time
	ExpectedGeneration     int64
	RequestHash            string
	KeyThumbprint          string
	ConnectorID            string
	ResourceKind           string
	ResourceID             string
	RouteID                string
	Protocol               string
	CarrierSessionID       string
	ProcessGeneration      int64
	ConfigGeneration       int64
	SessionGeneration      int64
	AssignmentGeneration   int64
	Method                 string
	Host                   string
	Path                   string
	ConnectorGeneration    int64
	InstallationGeneration int64
	EdgePool               string
	EdgeNodeID             string
	EdgeProcessEpoch       string
	RouteBinding           string
	IntentID               string
	EndpointID             string
	PeerEndpointID         string
	AttemptGeneration      int64
	NetworkGeneration      int64
	PeerRole               string
	RouteAllocation        string
	RouteGeneration        int64
	InitiatorEndpointID    string
	ResponderEndpointID    string
	RelayByteLimit         int64
	RelayCarriers          []string
	FileTransferPolicy     *FileTransferPolicy
}

type FileTransferPolicy struct {
	Revision               string `json:"revision"`
	MaxFileBytes           int64  `json:"max_file_bytes"`
	MaxBatchFiles          int    `json:"max_batch_files"`
	MaxBatchBytes          int64  `json:"max_batch_bytes"`
	MaxConcurrentTransfers int    `json:"max_concurrent_transfers"`
	RetentionSeconds       int64  `json:"retention_seconds"`
	DeliveryTimeoutSeconds int64  `json:"delivery_timeout_seconds"`
	MaxPendingSpoolBytes   int64  `json:"max_pending_spool_bytes"`
}

var DefaultFileTransferPolicy = FileTransferPolicy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}

type CredentialClaims struct {
	Issuer                 string              `json:"iss"`
	Audience               string              `json:"aud"`
	Subject                string              `json:"sub"`
	JTI                    string              `json:"jti"`
	IssuedAt               int64               `json:"iat"`
	ExpiresAt              int64               `json:"exp"`
	Scopes                 []string            `json:"scope"`
	CredentialClass        string              `json:"credential_class"`
	EnvironmentID          string              `json:"environment_id"`
	AccountID              string              `json:"account_id,omitempty"`
	EnrollmentID           string              `json:"enrollment_id,omitempty"`
	AssignmentID           string              `json:"assignment_id,omitempty"`
	WarningRevision        string              `json:"warning_revision,omitempty"`
	HelperID               string              `json:"helper_id,omitempty"`
	MachineID              string              `json:"machine_id,omitempty"`
	SourceMachineID        string              `json:"source_machine_id,omitempty"`
	UserID                 string              `json:"user_id,omitempty"`
	ActorID                string              `json:"actor_id,omitempty"`
	CLIClientSessionID     string              `json:"cli_client_session_id,omitempty"`
	SessionID              string              `json:"session_id,omitempty"`
	OperationID            string              `json:"operation_id,omitempty"`
	PreviewID              string              `json:"preview_id,omitempty"`
	OwnerSessionID         string              `json:"owner_session_id,omitempty"`
	IdempotencyKey         string              `json:"idempotency_key,omitempty"`
	RequestID              string              `json:"request_id,omitempty"`
	CorrelationID          string              `json:"correlation_id,omitempty"`
	TargetScheme           string              `json:"target_scheme,omitempty"`
	TargetAddress          string              `json:"target_address,omitempty"`
	AccessMode             string              `json:"access_mode,omitempty"`
	Endpoint               string              `json:"endpoint,omitempty"`
	LeaseDeadline          int64               `json:"lease_deadline,omitempty"`
	UserDeadline           *int64              `json:"user_deadline,omitempty"`
	LeaseETag              string              `json:"lease_etag,omitempty"`
	State                  string              `json:"state,omitempty"`
	AllocationState        string              `json:"allocation_state,omitempty"`
	EdgeState              string              `json:"edge_state,omitempty"`
	OriginState            string              `json:"origin_state,omitempty"`
	CreatedAt              int64               `json:"created_at,omitempty"`
	LastRenewedAt          int64               `json:"last_renewed_at,omitempty"`
	ExpectedGeneration     int64               `json:"expected_generation,omitempty"`
	RequestHash            string              `json:"request_hash,omitempty"`
	KeyThumbprint          string              `json:"key_thumbprint,omitempty"`
	ConnectorGeneration    int64               `json:"connector_generation,omitempty"`
	ConnectorID            string              `json:"connector_id,omitempty"`
	ResourceKind           string              `json:"resource_kind,omitempty"`
	ResourceID             string              `json:"resource_id,omitempty"`
	RouteID                string              `json:"route_id,omitempty"`
	Protocol               string              `json:"protocol,omitempty"`
	CarrierSessionID       string              `json:"carrier_session_id,omitempty"`
	ProcessGeneration      int64               `json:"process_generation,omitempty"`
	ConfigGeneration       int64               `json:"config_generation,omitempty"`
	SessionGeneration      int64               `json:"session_generation,omitempty"`
	AssignmentGeneration   int64               `json:"assignment_generation,omitempty"`
	Method                 string              `json:"method,omitempty"`
	Host                   string              `json:"host,omitempty"`
	Path                   string              `json:"path,omitempty"`
	InstallationGeneration int64               `json:"installation_generation,omitempty"`
	EdgePool               string              `json:"edge_pool,omitempty"`
	EdgeNodeID             string              `json:"edge_node_id,omitempty"`
	EdgeProcessEpoch       string              `json:"edge_process_epoch,omitempty"`
	RouteBinding           string              `json:"route_binding,omitempty"`
	IntentID               string              `json:"intent_id,omitempty"`
	EndpointID             string              `json:"endpoint_id,omitempty"`
	PeerEndpointID         string              `json:"peer_endpoint_id,omitempty"`
	AttemptGeneration      int64               `json:"attempt_generation,omitempty"`
	NetworkGeneration      int64               `json:"network_generation,omitempty"`
	PeerRole               string              `json:"peer_role,omitempty"`
	RouteAllocation        string              `json:"route_allocation,omitempty"`
	RouteGeneration        int64               `json:"route_generation,omitempty"`
	InitiatorEndpointID    string              `json:"initiator_endpoint_id,omitempty"`
	ResponderEndpointID    string              `json:"responder_endpoint_id,omitempty"`
	RelayByteLimit         int64               `json:"relay_byte_limit,omitempty"`
	RelayCarriers          []string            `json:"relay_carriers,omitempty"`
	FileTransferPolicy     *FileTransferPolicy `json:"file_transfer_policy,omitempty"`
}

var credentialPolicies = map[string]struct {
	audience string
	scopes   []string
	maxTTL   time.Duration
}{
	"helper_enrollment":   {audience: "paperboat-enrollment", scopes: []string{"helper:enroll"}, maxTTL: 10 * time.Minute},
	"helper_identity":     {audience: "paperboat-control", scopes: []string{"helper:connect", "helper:renew"}, maxTTL: time.Hour},
	"machine_control":     {audience: "paperboat-control", scopes: []string{"machine:connect", "machine:renew"}, maxTTL: time.Hour},
	"connector_admission": {audience: "paperboat-edge", scopes: []string{"connector:admit"}, maxTTL: 5 * time.Minute},
	"peer_signaling":      {audience: "paperboat-edge", scopes: []string{"peer:signal"}, maxTTL: 5 * time.Minute},
	"peer_relay":          {audience: "paperboat-edge", scopes: []string{"peer:relay"}, maxTTL: 5 * time.Minute},
	"peer_pmtu":           {audience: "paperboat-edge", scopes: []string{"peer:pmtu"}, maxTTL: 5 * time.Minute},
	"config_sync":         {audience: "paperboat-machine", scopes: []string{"config:pull", "config:apply", "config:report"}, maxTTL: 5 * time.Minute},
	"terminal_operation":  {audience: "paperboat-machine", scopes: []string{"terminal:operate"}, maxTTL: 5 * time.Minute},
	"exec_operation":      {audience: "paperboat-machine", scopes: []string{"exec:operate"}, maxTTL: 5 * time.Minute},
	"ssh_operation":       {audience: "paperboat-machine", scopes: []string{"ssh:operate"}, maxTTL: 5 * time.Minute},
	"preview_launch":      {audience: "paperboat-machine", scopes: []string{"preview:launch"}, maxTTL: 5 * time.Minute},
	"private_access":      {audience: "paperboat-edge", scopes: []string{"private:access"}, maxTTL: 2 * time.Minute},
	"file_transfer":       {audience: "paperboat-machine", scopes: []string{"file:transfer"}, maxTTL: 5 * time.Minute},
	"codex_manage":        {audience: "paperboat-machine", scopes: []string{"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}, maxTTL: 5 * time.Minute},
	"codex_connect":       {audience: "paperboat-machine", scopes: []string{"codex:connect"}, maxTTL: 5 * time.Minute},
}

// private_access grants use the audience for the concrete edge protocol. The
// class remains one policy so its scope and lifetime cannot drift, while the
// exact audience prevents an HTTP grant from being replayed for raw TCP (or a
// preview grant for a durable tunnel).
func credentialAudienceAllowed(class, audience, defaultAudience string) bool {
	if class != "private_access" {
		return audience == defaultAudience
	}
	switch audience {
	case "paperboat-preview-http", "paperboat-tunnel-http", "paperboat-tunnel-tcp":
		return true
	default:
		return false
	}
}

func New(keys []Key, activeID string, maxAge time.Duration) (*Provider, error) {
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	provider := &Provider{activeID: strings.TrimSpace(activeID), keys: make(map[string]ed25519.PrivateKey), maxAge: maxAge}
	for _, key := range keys {
		id := strings.TrimSpace(key.ID)
		if id == "" || len(key.PrivateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("mint keys require a non-empty id and Ed25519 private key")
		}
		if _, exists := provider.keys[id]; exists {
			return nil, fmt.Errorf("duplicate mint key id %q", id)
		}
		provider.keys[id] = append(ed25519.PrivateKey(nil), key.PrivateKey...)
	}
	if len(provider.keys) == 0 {
		return nil, errors.New("at least one mint key is required")
	}
	if _, ok := provider.keys[provider.activeID]; !ok {
		return nil, fmt.Errorf("active mint key %q is not published", provider.activeID)
	}
	return provider, nil
}

func NewEphemeral(maxAge time.Duration) (*Provider, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mint key: %w", err)
	}
	return New([]Key{{ID: "development-ephemeral", PrivateKey: privateKey}}, "development-ephemeral", maxAge)
}

// ParseKeys accepts entries in the form kid:base64url(ed25519-seed-or-private-key).
func ParseKeys(specs []string, activeID string, maxAge time.Duration) (*Provider, error) {
	keys := make([]Key, 0, len(specs))
	for _, spec := range specs {
		id, encoded, ok := strings.Cut(strings.TrimSpace(spec), ":")
		if !ok {
			return nil, errors.New("mint signing keys must use kid:base64url format")
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode mint key %q: %w", id, err)
		}
		if len(raw) == ed25519.SeedSize {
			raw = ed25519.NewKeyFromSeed(raw)
		}
		keys = append(keys, Key{ID: id, PrivateKey: ed25519.PrivateKey(raw)})
	}
	return New(keys, activeID, maxAge)
}

func (p *Provider) Sign(input ProofInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.CLIClientSessionID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" {
		return "", errors.New("mint proof claims are incomplete")
	}
	issuedAt := input.IssuedAt.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("mint proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(ProofType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"environmentId": input.EnvironmentID, "clientSessionId": input.CLIClientSessionID,
		"nonce": input.Nonce, "scope": []string{ProofScope},
	})
}

func (p *Provider) SignHealth(input ProofInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.CLIClientSessionID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" {
		return "", errors.New("health proof claims are incomplete")
	}
	issuedAt := input.IssuedAt.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("health proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(HealthType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"environmentId": input.EnvironmentID, "clientSessionId": input.CLIClientSessionID,
		"nonce": input.Nonce, "scope": []string{HealthScope},
	})
}

func (p *Provider) SignRevocation(input RevocationInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.CLIClientSessionID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" || strings.TrimSpace(input.Reason) == "" || len(input.SessionIDs) == 0 {
		return "", errors.New("revocation proof claims are incomplete")
	}
	issuedAt := input.IssuedAt.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("revocation proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(RevokeType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"environmentId": input.EnvironmentID, "clientSessionId": input.CLIClientSessionID,
		"nonce": input.Nonce, "scope": []string{RevokeScope}, "sessionIds": input.SessionIDs,
		"reason": input.Reason,
	})
}

func (p *Provider) SignTerminalControl(input TerminalControlInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" || strings.TrimSpace(input.ThreadID) == "" || len(input.TerminalIDs) == 0 {
		return "", errors.New("terminal control proof claims are incomplete")
	}
	if input.Operation != "snapshot" && input.Operation != "close" && input.Operation != "delete_history" {
		return "", errors.New("invalid terminal control operation")
	}
	issuedAt, expiresAt := input.IssuedAt.UTC(), input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("terminal control proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(TerminalControlType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(), "environmentId": input.EnvironmentID,
		"nonce": input.Nonce, "scope": []string{TerminalControlScope}, "operation": input.Operation,
		"threadId": input.ThreadID, "terminalIds": input.TerminalIDs,
	})
}

func (p *Provider) SignCredential(input CredentialInput) (string, error) {
	policy, ok := credentialPolicies[input.CredentialClass]
	issuedAt, expiresAt := input.IssuedAt.UTC(), input.ExpiresAt.UTC()
	if !ok || input.Issuer == "" || input.Subject == "" || input.JTI == "" || input.EnvironmentID == "" || !credentialAudienceAllowed(input.CredentialClass, input.Audience, policy.audience) || !slices.Equal(input.Scopes, policy.scopes) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > policy.maxTTL {
		return "", errors.New("credential claims are invalid")
	}
	claims := map[string]any{"iss": input.Issuer, "aud": input.Audience, "sub": input.Subject, "jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(), "scope": input.Scopes, "credential_class": input.CredentialClass, "environment_id": input.EnvironmentID}
	switch input.CredentialClass {
	case "helper_enrollment":
		if input.EnrollmentID == "" {
			return "", errors.New("enrollment binding is required")
		}
		claims["enrollment_id"] = input.EnrollmentID
	case "helper_identity":
		if input.HelperID == "" || input.MachineID == "" || input.KeyThumbprint == "" {
			return "", errors.New("helper identity bindings are required")
		}
		claims["helper_id"], claims["machine_id"], claims["key_thumbprint"] = input.HelperID, input.MachineID, input.KeyThumbprint
	case "machine_control":
		if input.UserID == "" || input.MachineID == "" || input.KeyThumbprint == "" || input.InstallationGeneration < 1 || input.SessionGeneration < 1 {
			return "", errors.New("machine control bindings are required")
		}
		claims["user_id"], claims["machine_id"], claims["key_thumbprint"], claims["installation_generation"], claims["session_generation"] = input.UserID, input.MachineID, input.KeyThumbprint, input.InstallationGeneration, input.SessionGeneration
	case "connector_admission":
		if input.FileTransferPolicy == nil {
			input.FileTransferPolicy = &DefaultFileTransferPolicy
		}
		binding, bindingErr := base64.RawURLEncoding.Strict().DecodeString(input.RouteBinding)
		if input.MachineID == "" || input.InstallationGeneration < 1 || input.ConnectorID == "" || input.ConnectorGeneration < 1 || input.EdgePool == "" || input.EdgeNodeID == "" || bindingErr != nil || len(binding) != 32 || base64.RawURLEncoding.EncodeToString(binding) != input.RouteBinding {
			return "", errors.New("connector admission bindings are required")
		}
		claims["machine_id"], claims["installation_generation"], claims["connector_id"], claims["connector_generation"], claims["edge_pool"], claims["edge_node_id"] = input.MachineID, input.InstallationGeneration, input.ConnectorID, input.ConnectorGeneration, input.EdgePool, input.EdgeNodeID
		claims["route_binding"] = input.RouteBinding
		claims["file_transfer_policy"] = input.FileTransferPolicy
	case "peer_signaling":
		if input.Subject != input.EndpointID || input.IntentID == "" || input.EndpointID == "" || input.PeerEndpointID == "" || input.EndpointID == input.PeerEndpointID || input.AttemptGeneration < 1 || input.NetworkGeneration < 1 || input.EdgeNodeID == "" || input.PeerRole != "controlling" && input.PeerRole != "controlled" {
			return "", errors.New("peer signaling bindings are required")
		}
		claims["intent_id"], claims["endpoint_id"], claims["peer_endpoint_id"] = input.IntentID, input.EndpointID, input.PeerEndpointID
		claims["attempt_generation"], claims["network_generation"], claims["peer_role"], claims["edge_node_id"] = input.AttemptGeneration, input.NetworkGeneration, input.PeerRole, input.EdgeNodeID
	case "peer_relay", "peer_pmtu":
		allocation, err := base64.RawURLEncoding.Strict().DecodeString(input.RouteAllocation)
		validCarriers := input.CredentialClass == "peer_pmtu" && len(input.RelayCarriers) == 0 || input.CredentialClass == "peer_relay" && slices.Equal(input.RelayCarriers, []string{"relay_quic", "relay_wss"})
		if err != nil || len(allocation) != 16 || base64.RawURLEncoding.EncodeToString(allocation) != input.RouteAllocation || input.Subject != input.IntentID || input.IntentID == "" || input.EdgeNodeID == "" || input.InitiatorEndpointID == "" || input.ResponderEndpointID == "" || input.InitiatorEndpointID == input.ResponderEndpointID || input.AttemptGeneration < 1 || input.NetworkGeneration < 1 || input.RouteGeneration < 1 || input.RelayByteLimit < 1 || input.RelayByteLimit > 1<<40 || !validCarriers {
			return "", errors.New("peer relay bindings are required")
		}
		claims["intent_id"], claims["edge_node_id"], claims["route_allocation"] = input.IntentID, input.EdgeNodeID, input.RouteAllocation
		claims["initiator_endpoint_id"], claims["responder_endpoint_id"] = input.InitiatorEndpointID, input.ResponderEndpointID
		claims["attempt_generation"], claims["network_generation"], claims["route_generation"], claims["relay_byte_limit"] = input.AttemptGeneration, input.NetworkGeneration, input.RouteGeneration, input.RelayByteLimit
		if input.CredentialClass == "peer_relay" {
			claims["relay_carriers"] = input.RelayCarriers
		}
	case "config_sync":
		if input.MachineID == "" || input.InstallationGeneration < 1 || input.AssignmentID == "" || input.WarningRevision == "" {
			return "", errors.New("config sync bindings are required")
		}
		claims["machine_id"], claims["installation_generation"], claims["assignment_id"], claims["warning_revision"] = input.MachineID, input.InstallationGeneration, input.AssignmentID, input.WarningRevision
	case "terminal_operation":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" || input.SessionID == "" {
			return "", errors.New("machine access bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"], claims["session_id"] = input.MachineID, input.UserID, input.CLIClientSessionID, input.SessionID
		if input.SourceMachineID != "" {
			claims["source_machine_id"] = input.SourceMachineID
		}
	case "exec_operation":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" || !validOperationID(input.OperationID) {
			return "", errors.New("exec operation bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"], claims["operation_id"] = input.MachineID, input.UserID, input.CLIClientSessionID, input.OperationID
	case "ssh_operation":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" || !validOperationID(input.OperationID) {
			return "", errors.New("ssh operation bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"], claims["operation_id"] = input.MachineID, input.UserID, input.CLIClientSessionID, input.OperationID
	case "codex_manage", "codex_connect":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" || input.SessionID == "" || input.InstallationGeneration < 1 || input.ConnectorID == "" || input.ConnectorGeneration < 1 || input.EdgePool == "" || input.EdgeNodeID == "" {
			return "", errors.New("codex session bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"], claims["session_id"] = input.MachineID, input.UserID, input.CLIClientSessionID, input.SessionID
		claims["installation_generation"], claims["connector_id"], claims["connector_generation"] = input.InstallationGeneration, input.ConnectorID, input.ConnectorGeneration
		claims["edge_pool"], claims["edge_node_id"] = input.EdgePool, input.EdgeNodeID
	case "preview_launch":
		if err := validatePreviewLaunchInput(input); err != nil {
			return "", errors.New("preview launch bindings are required")
		}
		claims["account_id"], claims["machine_id"], claims["user_id"], claims["actor_id"] = input.AccountID, input.MachineID, input.UserID, input.ActorID
		claims["preview_id"], claims["owner_session_id"], claims["operation_id"] = input.PreviewID, input.OwnerSessionID, input.OperationID
		claims["target_scheme"], claims["target_address"], claims["access_mode"] = input.TargetScheme, input.TargetAddress, input.AccessMode
		claims["endpoint"], claims["lease_deadline"], claims["lease_etag"] = input.Endpoint, input.LeaseDeadline.UTC().Unix(), input.LeaseETag
		claims["state"], claims["allocation_state"], claims["edge_state"], claims["origin_state"] = input.State, input.AllocationState, input.EdgeState, input.OriginState
		claims["created_at"], claims["last_renewed_at"] = input.CreatedAt.UTC().Unix(), input.LastRenewedAt.UTC().Unix()
		claims["expected_generation"], claims["request_hash"] = input.ExpectedGeneration, input.RequestHash
		claims["idempotency_key"], claims["request_id"], claims["correlation_id"] = input.IdempotencyKey, input.RequestID, input.CorrelationID
		if input.UserDeadline != nil {
			value := input.UserDeadline.UTC().Unix()
			claims["user_deadline"] = value
		}
	case "private_access":
		if err := validatePrivateAccessInput(input); err != nil {
			return "", errors.New("private access bindings are required")
		}
		claims["account_id"], claims["user_id"], claims["machine_id"], claims["session_id"] = input.AccountID, input.UserID, input.MachineID, input.SessionID
		claims["resource_kind"], claims["resource_id"], claims["route_id"], claims["protocol"] = input.ResourceKind, input.ResourceID, input.RouteID, input.Protocol
		claims["operation_id"], claims["connector_id"], claims["route_generation"] = input.OperationID, input.ConnectorID, input.RouteGeneration
		claims["carrier_session_id"], claims["process_generation"], claims["config_generation"] = input.CarrierSessionID, input.ProcessGeneration, input.ConfigGeneration
		claims["installation_generation"], claims["session_generation"], claims["assignment_generation"] = input.InstallationGeneration, input.SessionGeneration, input.AssignmentGeneration
		claims["edge_node_id"], claims["edge_process_epoch"] = input.EdgeNodeID, input.EdgeProcessEpoch
		claims["method"], claims["host"], claims["path"] = input.Method, input.Host, input.Path
		claims["idempotency_key"], claims["request_id"], claims["correlation_id"] = input.IdempotencyKey, input.RequestID, input.CorrelationID
		claims["access_mode"], claims["request_hash"] = input.AccessMode, input.RequestHash
	case "file_transfer":
		if input.MachineID == "" || input.SourceMachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" {
			return "", errors.New("machine transfer bindings are required")
		}
		claims["machine_id"], claims["source_machine_id"], claims["user_id"], claims["cli_client_session_id"] = input.MachineID, input.SourceMachineID, input.UserID, input.CLIClientSessionID
		if input.SessionID != "" {
			claims["session_id"] = input.SessionID
		}
	}
	return p.signClaims("paperboat-credential+jwt", claims)
}

func (p *Provider) VerifyCredential(token, expectedIssuer, expectedClass string, now time.Time) (CredentialClaims, error) {
	return p.verifyCredential(token, expectedIssuer, expectedClass, now, 0)
}

func (p *Provider) VerifyCredentialWithExpiryGrace(token, expectedIssuer, expectedClass string, now time.Time, expiryGrace time.Duration) (CredentialClaims, error) {
	if expiryGrace <= 0 {
		return CredentialClaims{}, errors.New("credential expiry grace is invalid")
	}
	return p.verifyCredential(token, expectedIssuer, expectedClass, now, expiryGrace)
}

func (p *Provider) verifyCredential(token, expectedIssuer, expectedClass string, now time.Time, expiryGrace time.Duration) (CredentialClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return CredentialClaims{}, errors.New("credential is malformed")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return CredentialClaims{}, errors.New("credential is malformed")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if strictCredentialJSON(headerBytes, &header) != nil || header.Algorithm != "EdDSA" || header.Type != "paperboat-credential+jwt" || header.KeyID == "" {
		return CredentialClaims{}, errors.New("credential header is invalid")
	}
	p.mu.RLock()
	privateKey, ok := p.keys[header.KeyID]
	p.mu.RUnlock()
	if !ok {
		return CredentialClaims{}, errors.New("credential key is unknown")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
		return CredentialClaims{}, errors.New("credential signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return CredentialClaims{}, errors.New("credential is malformed")
	}
	var claims CredentialClaims
	if strictCredentialJSON(payload, &claims) != nil {
		return CredentialClaims{}, errors.New("credential claims are invalid")
	}
	policy, ok := credentialPolicies[expectedClass]
	current := now.UTC().Unix()
	switch {
	case !ok:
		return CredentialClaims{}, errors.New("credential policy is invalid")
	case claims.CredentialClass != expectedClass:
		return CredentialClaims{}, errors.New("credential class is invalid")
	case claims.Issuer != expectedIssuer:
		return CredentialClaims{}, errors.New("credential issuer is invalid")
	case !credentialAudienceAllowed(expectedClass, claims.Audience, policy.audience):
		return CredentialClaims{}, errors.New("credential audience is invalid")
	case !slices.Equal(claims.Scopes, policy.scopes):
		return CredentialClaims{}, errors.New("credential scopes are invalid")
	case claims.Subject == "" || claims.JTI == "" || claims.EnvironmentID == "":
		return CredentialClaims{}, errors.New("credential base bindings are invalid")
	case claims.ExpiresAt <= current-int64(expiryGrace/time.Second):
		return CredentialClaims{}, errors.New("credential is expired")
	case claims.IssuedAt > current+60:
		return CredentialClaims{}, errors.New("credential issued-at is invalid")
	case claims.ExpiresAt <= claims.IssuedAt:
		return CredentialClaims{}, errors.New("credential time window is invalid")
	case time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > policy.maxTTL:
		return CredentialClaims{}, errors.New("credential ttl is invalid")
	}
	switch expectedClass {
	case "helper_enrollment":
		if claims.EnrollmentID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "helper_identity":
		if claims.HelperID == "" || claims.MachineID == "" || claims.KeyThumbprint == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "machine_control":
		if claims.UserID == "" || claims.MachineID == "" || claims.KeyThumbprint == "" || claims.InstallationGeneration < 1 || claims.SessionGeneration < 1 {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "connector_admission":
		binding, bindingErr := base64.RawURLEncoding.Strict().DecodeString(claims.RouteBinding)
		if claims.MachineID == "" || claims.InstallationGeneration < 1 || claims.ConnectorID == "" || claims.ConnectorGeneration < 1 || claims.EdgePool == "" || claims.EdgeNodeID == "" || bindingErr != nil || len(binding) != 32 || base64.RawURLEncoding.EncodeToString(binding) != claims.RouteBinding {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "peer_signaling":
		if claims.Subject != claims.EndpointID || claims.IntentID == "" || claims.EndpointID == "" || claims.PeerEndpointID == "" || claims.EndpointID == claims.PeerEndpointID || claims.AttemptGeneration < 1 || claims.NetworkGeneration < 1 || claims.EdgeNodeID == "" || claims.PeerRole != "controlling" && claims.PeerRole != "controlled" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "peer_relay", "peer_pmtu":
		allocation, err := base64.RawURLEncoding.Strict().DecodeString(claims.RouteAllocation)
		validCarriers := claims.CredentialClass == "peer_pmtu" && len(claims.RelayCarriers) == 0 || claims.CredentialClass == "peer_relay" && slices.Equal(claims.RelayCarriers, []string{"relay_quic", "relay_wss"})
		if err != nil || len(allocation) != 16 || base64.RawURLEncoding.EncodeToString(allocation) != claims.RouteAllocation || claims.Subject != claims.IntentID || claims.IntentID == "" || claims.EdgeNodeID == "" || claims.InitiatorEndpointID == "" || claims.ResponderEndpointID == "" || claims.InitiatorEndpointID == claims.ResponderEndpointID || claims.AttemptGeneration < 1 || claims.NetworkGeneration < 1 || claims.RouteGeneration < 1 || claims.RelayByteLimit < 1 || claims.RelayByteLimit > 1<<40 || !validCarriers {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "config_sync":
		if claims.MachineID == "" || claims.InstallationGeneration < 1 || claims.AssignmentID == "" || claims.WarningRevision == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "terminal_operation":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" || claims.SessionID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "exec_operation":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" || !validOperationID(claims.OperationID) {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "ssh_operation":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" || !validOperationID(claims.OperationID) {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "codex_manage", "codex_connect":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" || claims.SessionID == "" || claims.InstallationGeneration < 1 || claims.ConnectorID == "" || claims.ConnectorGeneration < 1 || claims.EdgePool == "" || claims.EdgeNodeID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "preview_launch":
		if err := validatePreviewLaunchClaims(claims); err != nil {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "private_access":
		if err := validatePrivateAccessClaims(claims); err != nil {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "file_transfer":
		if claims.MachineID == "" || claims.SourceMachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	}
	return claims, nil
}

func validatePreviewLaunchInput(input CredentialInput) error {
	if input.AccountID == "" || input.MachineID == "" || input.UserID == "" || input.ActorID == "" || input.PreviewID == "" || input.OwnerSessionID == "" || !validOperationID(input.OperationID) {
		return errors.New("identity bindings are incomplete")
	}
	if input.Subject != input.UserID || !validCredentialBindingID(input.AccountID) || !validCredentialBindingID(input.ActorID) || !validCredentialBindingID(input.MachineID) || !validCredentialBindingID(input.PreviewID) || !validCredentialBindingID(input.OwnerSessionID) {
		return errors.New("identity bindings are invalid")
	}
	if !validPreviewLaunchTrace(input.IdempotencyKey, 1, 256) || !validPreviewLaunchTrace(input.RequestID, 3, 128) || !validPreviewLaunchTrace(input.CorrelationID, 3, 128) {
		return errors.New("trace bindings are invalid")
	}
	if input.TargetScheme != "http" && input.TargetScheme != "https" && input.TargetScheme != "h2c" && input.TargetScheme != "unix" && input.TargetScheme != "tcp" {
		return errors.New("target scheme is invalid")
	}
	if input.TargetAddress == "" || len(input.TargetAddress) > 512 || strings.ContainsAny(input.TargetAddress, "\r\n") || (input.AccessMode != "public" && input.AccessMode != "private") {
		return errors.New("target binding is invalid")
	}
	if input.Endpoint == "" || !strings.HasPrefix(input.Endpoint, "https://") || strings.ContainsAny(input.Endpoint, "\r\n") {
		return errors.New("endpoint binding is invalid")
	}
	if input.LeaseDeadline.IsZero() || !input.LeaseDeadline.After(input.IssuedAt.UTC()) || input.UserDeadline != nil && (input.UserDeadline.IsZero() || input.UserDeadline.Before(input.IssuedAt.UTC()) || input.UserDeadline.After(input.LeaseDeadline)) {
		return errors.New("lease deadline binding is invalid")
	}
	if input.CreatedAt.IsZero() || input.LastRenewedAt.IsZero() || input.LastRenewedAt.Before(input.CreatedAt) || input.CreatedAt.After(input.LeaseDeadline) {
		return errors.New("lease timestamps are invalid")
	}
	if input.ExpectedGeneration < 1 || !validPreviewLaunchETag(input.LeaseETag, input.PreviewID, input.ExpectedGeneration) {
		return errors.New("lease generation binding is invalid")
	}
	if !validPreviewLaunchHash(input.RequestHash) {
		return errors.New("request hash binding is invalid")
	}
	if !validPreviewLaunchState(input.State, input.AllocationState, input.EdgeState, input.OriginState) {
		return errors.New("lease state binding is invalid")
	}
	return nil
}

func validatePreviewLaunchClaims(claims CredentialClaims) error {
	if claims.AccountID == "" || claims.MachineID == "" || claims.UserID == "" || claims.ActorID == "" || claims.PreviewID == "" || claims.OwnerSessionID == "" || !validOperationID(claims.OperationID) {
		return errors.New("identity bindings are incomplete")
	}
	if claims.Subject != claims.UserID || !validCredentialBindingID(claims.AccountID) || !validCredentialBindingID(claims.ActorID) || !validCredentialBindingID(claims.MachineID) || !validCredentialBindingID(claims.PreviewID) || !validCredentialBindingID(claims.OwnerSessionID) {
		return errors.New("identity bindings are invalid")
	}
	if !validPreviewLaunchTrace(claims.IdempotencyKey, 1, 256) || !validPreviewLaunchTrace(claims.RequestID, 3, 128) || !validPreviewLaunchTrace(claims.CorrelationID, 3, 128) {
		return errors.New("trace bindings are invalid")
	}
	if claims.TargetScheme != "http" && claims.TargetScheme != "https" && claims.TargetScheme != "h2c" && claims.TargetScheme != "unix" && claims.TargetScheme != "tcp" {
		return errors.New("target scheme is invalid")
	}
	if claims.TargetAddress == "" || len(claims.TargetAddress) > 512 || strings.ContainsAny(claims.TargetAddress, "\r\n") || (claims.AccessMode != "public" && claims.AccessMode != "private") {
		return errors.New("target binding is invalid")
	}
	if claims.Endpoint == "" || !strings.HasPrefix(claims.Endpoint, "https://") || strings.ContainsAny(claims.Endpoint, "\r\n") || claims.LeaseDeadline <= claims.IssuedAt || claims.UserDeadline != nil && (*claims.UserDeadline <= claims.IssuedAt || *claims.UserDeadline > claims.LeaseDeadline) {
		return errors.New("lease deadline binding is invalid")
	}
	if claims.CreatedAt <= 0 || claims.LastRenewedAt < claims.CreatedAt || claims.CreatedAt > claims.LeaseDeadline {
		return errors.New("lease timestamps are invalid")
	}
	if claims.ExpectedGeneration < 1 || !validPreviewLaunchETag(claims.LeaseETag, claims.PreviewID, claims.ExpectedGeneration) || !validPreviewLaunchHash(claims.RequestHash) {
		return errors.New("lease generation binding is invalid")
	}
	if !validPreviewLaunchState(claims.State, claims.AllocationState, claims.EdgeState, claims.OriginState) {
		return errors.New("lease state binding is invalid")
	}
	return nil
}

func validatePrivateAccessInput(input CredentialInput) error {
	if !validCredentialBindingID(input.AccountID) || !validCredentialBindingID(input.UserID) || !validCredentialBindingID(input.MachineID) || !validCredentialBindingID(input.SessionID) || !validCredentialBindingID(input.ResourceID) || !validCredentialBindingID(input.RouteID) || !validCredentialBindingID(input.CarrierSessionID) || !validCredentialBindingID(input.EdgeNodeID) || !validPrivateAccessEpoch(input.EdgeProcessEpoch) || input.JTI == "" || input.AccessMode != "private" || input.InstallationGeneration < 1 || input.RouteGeneration < 1 || input.SessionGeneration < 1 || input.ProcessGeneration < 1 || input.ConfigGeneration < 1 || input.AssignmentGeneration < 1 {
		return errors.New("private access identity bindings are incomplete")
	}
	if input.ResourceKind != "preview" && input.ResourceKind != "tunnel" {
		return errors.New("private access resource kind is invalid")
	}
	if input.Protocol != "http" && input.Protocol != "tcp" {
		return errors.New("private access protocol is invalid")
	}
	if input.ResourceKind == "preview" && !validOperationID(input.OperationID) {
		return errors.New("private preview operation binding is invalid")
	}
	if input.ResourceKind == "tunnel" && !validCredentialBindingID(input.ConnectorID) {
		return errors.New("private tunnel connector binding is invalid")
	}
	if input.Protocol == "tcp" && input.ResourceKind != "tunnel" {
		return errors.New("private TCP is only supported for tunnels")
	}
	if !validPreviewLaunchHash(input.RequestHash) {
		return errors.New("private access request hash is invalid")
	}
	if !validPreviewLaunchTrace(input.IdempotencyKey, 1, 256) || !validPreviewLaunchTrace(input.RequestID, 3, 128) || !validPreviewLaunchTrace(input.CorrelationID, 3, 128) {
		return errors.New("private access trace is invalid")
	}
	if input.Protocol == "http" {
		if !validPreviewLaunchTrace(input.Method, 1, 32) || !validPreviewLaunchTrace(input.Host, 1, 512) || len(input.Path) < 1 || len(input.Path) > 4096 || !strings.HasPrefix(input.Path, "/") {
			return errors.New("private access HTTP binding is invalid")
		}
	} else if input.Method != "" || input.Host != "" || input.Path != "" {
		return errors.New("private access TCP binding is invalid")
	}
	return nil
}

func validatePrivateAccessClaims(claims CredentialClaims) error {
	if !validCredentialBindingID(claims.AccountID) || !validCredentialBindingID(claims.UserID) || !validCredentialBindingID(claims.MachineID) || !validCredentialBindingID(claims.SessionID) || !validCredentialBindingID(claims.ResourceID) || !validCredentialBindingID(claims.RouteID) || !validCredentialBindingID(claims.CarrierSessionID) || !validCredentialBindingID(claims.EdgeNodeID) || !validPrivateAccessEpoch(claims.EdgeProcessEpoch) || claims.JTI == "" || claims.AccessMode != "private" || claims.InstallationGeneration < 1 || claims.RouteGeneration < 1 || claims.SessionGeneration < 1 || claims.ProcessGeneration < 1 || claims.ConfigGeneration < 1 || claims.AssignmentGeneration < 1 {
		return errors.New("private access identity bindings are incomplete")
	}
	if claims.ResourceKind != "preview" && claims.ResourceKind != "tunnel" {
		return errors.New("private access resource kind is invalid")
	}
	if claims.Protocol != "http" && claims.Protocol != "tcp" {
		return errors.New("private access protocol is invalid")
	}
	if claims.ResourceKind == "preview" && !validOperationID(claims.OperationID) {
		return errors.New("private preview operation binding is invalid")
	}
	if claims.ResourceKind == "tunnel" && !validCredentialBindingID(claims.ConnectorID) {
		return errors.New("private tunnel connector binding is invalid")
	}
	if claims.Protocol == "tcp" && claims.ResourceKind != "tunnel" {
		return errors.New("private TCP is only supported for tunnels")
	}
	if !validPreviewLaunchHash(claims.RequestHash) {
		return errors.New("private access request hash is invalid")
	}
	if !validPreviewLaunchTrace(claims.IdempotencyKey, 1, 256) || !validPreviewLaunchTrace(claims.RequestID, 3, 128) || !validPreviewLaunchTrace(claims.CorrelationID, 3, 128) {
		return errors.New("private access trace is invalid")
	}
	if claims.Protocol == "http" {
		if !validPreviewLaunchTrace(claims.Method, 1, 32) || !validPreviewLaunchTrace(claims.Host, 1, 512) || len(claims.Path) < 1 || len(claims.Path) > 4096 || !strings.HasPrefix(claims.Path, "/") {
			return errors.New("private access HTTP binding is invalid")
		}
	} else if claims.Method != "" || claims.Host != "" || claims.Path != "" {
		return errors.New("private access TCP binding is invalid")
	}
	return nil
}

func validPrivateAccessEpoch(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validCredentialBindingID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return false
		}
	}
	return true
}

func validPreviewLaunchTrace(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return false
		}
	}
	return true
}

func validPreviewLaunchHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func validPreviewLaunchETag(value, previewID string, expectedGeneration int64) bool {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	parts := strings.Split(strings.Trim(value, `"`), ":")
	if len(parts) != 4 || parts[0] != "ptv1" || parts[1] != "preview_lease" {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || string(decoded) != previewID || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] {
		return false
	}
	generation, err := strconv.ParseInt(parts[3], 10, 64)
	return err == nil && generation == expectedGeneration && generation > 0
}

func validPreviewLaunchState(state, allocation, edge, origin string) bool {
	validState := state == "allocating" || state == "connecting" || state == "ready"
	validAllocation := allocation == "pending" || allocation == "ready" || allocation == "failed" || allocation == "released"
	validEdge := edge == "pending" || edge == "ready" || edge == "degraded" || edge == "down"
	validOrigin := origin == "unknown" || origin == "ready" || origin == "unavailable" || origin == "degraded" || origin == "down"
	return validState && validAllocation && validEdge && validOrigin
}

func validOperationID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func strictCredentialJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing credential data")
	}
	return nil
}

func (p *Provider) signClaims(proofType string, claims map[string]any) (string, error) {
	p.mu.RLock()
	id := p.activeID
	privateKey := append(ed25519.PrivateKey(nil), p.keys[id]...)
	p.mu.RUnlock()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": proofType, "kid": id})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := encode(header) + "." + encode(payload)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned))), nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	keys := make([]map[string]string, 0, len(p.keys))
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		privateKey := p.keys[id]
		publicKey := privateKey.Public().(ed25519.PublicKey)
		keys = append(keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": id,
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		})
	}
	maxAge := int(p.maxAge.Seconds())
	p.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// ActivePublicKeyPEM returns the active Ed25519 verification key in the
// format required by the Helper relay-config contract.
func (p *Provider) ActivePublicKeyPEM() (string, error) {
	p.mu.RLock()
	key := append(ed25519.PrivateKey(nil), p.keys[p.activeID]...)
	p.mu.RUnlock()
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
}

func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
