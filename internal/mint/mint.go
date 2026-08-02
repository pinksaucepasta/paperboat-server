package mint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
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
	Issuer                 string
	Audience               string
	Subject                string
	JTI                    string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	CredentialClass        string
	Scopes                 []string
	EnvironmentID          string
	EnrollmentID           string
	AssignmentID           string
	WarningRevision        string
	HelperID               string
	MachineID              string
	SourceMachineID        string
	UserID                 string
	CLIClientSessionID     string
	SessionID              string
	KeyThumbprint          string
	ConnectorID            string
	ConnectorGeneration    int64
	InstallationGeneration int64
	EdgePool               string
	EdgeNodeID             string
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
	EnrollmentID           string              `json:"enrollment_id,omitempty"`
	AssignmentID           string              `json:"assignment_id,omitempty"`
	WarningRevision        string              `json:"warning_revision,omitempty"`
	HelperID               string              `json:"helper_id,omitempty"`
	MachineID              string              `json:"machine_id,omitempty"`
	SourceMachineID        string              `json:"source_machine_id,omitempty"`
	UserID                 string              `json:"user_id,omitempty"`
	CLIClientSessionID     string              `json:"cli_client_session_id,omitempty"`
	SessionID              string              `json:"session_id,omitempty"`
	KeyThumbprint          string              `json:"key_thumbprint,omitempty"`
	ConnectorGeneration    int64               `json:"connector_generation,omitempty"`
	ConnectorID            string              `json:"connector_id,omitempty"`
	InstallationGeneration int64               `json:"installation_generation,omitempty"`
	EdgePool               string              `json:"edge_pool,omitempty"`
	EdgeNodeID             string              `json:"edge_node_id,omitempty"`
	FileTransferPolicy     *FileTransferPolicy `json:"file_transfer_policy,omitempty"`
}

var credentialPolicies = map[string]struct {
	audience string
	scopes   []string
	maxTTL   time.Duration
}{
	"helper_enrollment":    {audience: "paperboat-enrollment", scopes: []string{"helper:enroll"}, maxTTL: 10 * time.Minute},
	"helper_identity":      {audience: "paperboat-control", scopes: []string{"helper:connect", "helper:renew"}, maxTTL: time.Hour},
	"machine_control":      {audience: "paperboat-control", scopes: []string{"machine:connect", "machine:renew"}, maxTTL: time.Hour},
	"preview_registration": {audience: "paperboat-control", scopes: []string{"preview:register"}, maxTTL: 5 * time.Minute},
	"connector_admission":  {audience: "paperboat-edge", scopes: []string{"connector:admit"}, maxTTL: 5 * time.Minute},
	"config_sync":          {audience: "paperboat-machine", scopes: []string{"config:pull", "config:apply", "config:report"}, maxTTL: 5 * time.Minute},
	"terminal_operation":   {audience: "paperboat-machine", scopes: []string{"terminal:operate"}, maxTTL: 5 * time.Minute},
	"preview_launch":       {audience: "paperboat-machine", scopes: []string{"preview:launch"}, maxTTL: 5 * time.Minute},
	"file_transfer":        {audience: "paperboat-machine", scopes: []string{"file:transfer"}, maxTTL: 5 * time.Minute},
	"codex_manage":         {audience: "paperboat-machine", scopes: []string{"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}, maxTTL: 5 * time.Minute},
	"codex_connect":        {audience: "paperboat-machine", scopes: []string{"codex:connect"}, maxTTL: 5 * time.Minute},
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
	if !ok || input.Issuer == "" || input.Subject == "" || input.JTI == "" || input.EnvironmentID == "" || input.Audience != policy.audience || !slices.Equal(input.Scopes, policy.scopes) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > policy.maxTTL {
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
		if input.UserID == "" || input.MachineID == "" || input.KeyThumbprint == "" || input.InstallationGeneration < 1 {
			return "", errors.New("machine control bindings are required")
		}
		claims["user_id"], claims["machine_id"], claims["key_thumbprint"], claims["installation_generation"] = input.UserID, input.MachineID, input.KeyThumbprint, input.InstallationGeneration
	case "preview_registration":
		if input.MachineID == "" || input.InstallationGeneration < 1 {
			return "", errors.New("preview registration binding is required")
		}
		claims["machine_id"], claims["installation_generation"] = input.MachineID, input.InstallationGeneration
	case "connector_admission":
		if input.FileTransferPolicy == nil {
			input.FileTransferPolicy = &DefaultFileTransferPolicy
		}
		if input.MachineID == "" || input.InstallationGeneration < 1 || input.ConnectorID == "" || input.ConnectorGeneration < 1 || input.EdgePool == "" || input.EdgeNodeID == "" {
			return "", errors.New("connector admission bindings are required")
		}
		claims["machine_id"], claims["installation_generation"], claims["connector_id"], claims["connector_generation"], claims["edge_pool"], claims["edge_node_id"] = input.MachineID, input.InstallationGeneration, input.ConnectorID, input.ConnectorGeneration, input.EdgePool, input.EdgeNodeID
		claims["file_transfer_policy"] = input.FileTransferPolicy
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
	case "codex_manage", "codex_connect":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" || input.SessionID == "" || input.InstallationGeneration < 1 || input.ConnectorID == "" || input.ConnectorGeneration < 1 || input.EdgePool == "" || input.EdgeNodeID == "" {
			return "", errors.New("codex session bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"], claims["session_id"] = input.MachineID, input.UserID, input.CLIClientSessionID, input.SessionID
		claims["installation_generation"], claims["connector_id"], claims["connector_generation"] = input.InstallationGeneration, input.ConnectorID, input.ConnectorGeneration
		claims["edge_pool"], claims["edge_node_id"] = input.EdgePool, input.EdgeNodeID
	case "preview_launch":
		if input.MachineID == "" || input.UserID == "" || input.CLIClientSessionID == "" {
			return "", errors.New("preview launch bindings are required")
		}
		claims["machine_id"], claims["user_id"], claims["cli_client_session_id"] = input.MachineID, input.UserID, input.CLIClientSessionID
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
	case claims.Audience != policy.audience:
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
		if claims.UserID == "" || claims.MachineID == "" || claims.KeyThumbprint == "" || claims.InstallationGeneration < 1 {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "preview_registration":
		if claims.MachineID == "" || claims.InstallationGeneration < 1 {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "connector_admission":
		if claims.MachineID == "" || claims.InstallationGeneration < 1 || claims.ConnectorID == "" || claims.ConnectorGeneration < 1 || claims.EdgePool == "" || claims.EdgeNodeID == "" {
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
	case "codex_manage", "codex_connect":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" || claims.SessionID == "" || claims.InstallationGeneration < 1 || claims.ConnectorID == "" || claims.ConnectorGeneration < 1 || claims.EdgePool == "" || claims.EdgeNodeID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "preview_launch":
		if claims.MachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	case "file_transfer":
		if claims.MachineID == "" || claims.SourceMachineID == "" || claims.UserID == "" || claims.CLIClientSessionID == "" {
			return CredentialClaims{}, errors.New("credential claims are invalid")
		}
	}
	return claims, nil
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
