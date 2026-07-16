package agentunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

const defaultAccessTTL = 5 * time.Minute
const providerCodeSubdomainInUse = "SUBDOMAIN_IN_USE"

var (
	ErrNotFound                        = projects.ErrNotFound
	ErrDeleted                         = projects.ErrDeleted
	ErrInvalidState                    = projects.ErrInvalidState
	ErrMachineFailed                   = errors.New("project machine failed")
	ErrInsufficientCredit              = projects.ErrInsufficientCredits
	ErrTunnelUnavailable               = errors.New("agentunnel resource is unavailable")
	ErrProvider                        = errors.New("agentunnel provider error")
	ErrCredentialIssuerUnavailable     = errors.New("papercode credential issuer is unavailable")
	ErrGitHubRequired                  = errors.New("github config is not ready")
	ErrTerminalSessionNotFound         = errors.New("terminal session not found")
	ErrTerminalSessionOperationPending = errors.New("terminal session operation pending")
	ErrTerminalRuntimeUnavailable      = errors.New("terminal runtime is unavailable")
)

type providerError struct {
	code    string
	message string
}

func (e providerError) Error() string {
	if e.code == "" {
		return ErrProvider.Error()
	}
	if e.message != "" {
		return ErrProvider.Error() + ": " + e.code + ": " + e.message
	}
	return ErrProvider.Error() + ": " + e.code
}

func (e providerError) Is(target error) bool {
	return target == ErrProvider
}

type Client interface {
	EnsureProjectResources(ctx context.Context, project ProjectRef) (ResourceDescriptor, error)
	ReattachProjectResources(ctx context.Context, project ProjectRef, resource ResourceDescriptor) (ResourceDescriptor, error)
	Status(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error)
	CleanupProjectResources(ctx context.Context, resource ResourceDescriptor, action, reason string) error
}

type ProjectRef struct {
	ID   string
	Name string
}

type ResourceDescriptor struct {
	ServerURL        string         `json:"server_url,omitempty"`
	TunnelID         string         `json:"tunnel_id"`
	ClientID         string         `json:"client_id,omitempty"`
	ResourceID       string         `json:"resource_id,omitempty"`
	HTTPBaseURL      string         `json:"http_base_url,omitempty"`
	WebSocketBaseURL string         `json:"websocket_base_url,omitempty"`
	MachineToken     string         `json:"-"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type TunnelStatus struct {
	Ready               bool   `json:"ready"`
	Status              string `json:"status"`
	Reason              string `json:"reason,omitempty"`
	HTTPBaseURL         string `json:"http_base_url,omitempty"`
	WebSocketBaseURL    string `json:"websocket_base_url,omitempty"`
	MaxRequestBodyBytes int64  `json:"max_request_body_bytes,omitempty"`
}

type CredentialIssuer interface {
	CheckCLI(ctx context.Context, input CredentialInput) error
	IssueCLI(ctx context.Context, input CredentialInput) (CLICredentials, error)
	RevokeCLI(ctx context.Context, input CredentialRevocationInput) error
}

type environmentHealthChecker interface {
	CheckHealth(ctx context.Context, input CredentialInput) error
}

type CredentialRevocationInput struct {
	UserID          string
	ProjectID       string
	EnvironmentID   string
	ClientSessionID string
	HTTPBaseURL     string
	SessionIDs      []string
	Reason          string
}

type CredentialInput struct {
	UserID          string
	ProjectID       string
	EnvironmentID   string
	ClientSessionID string
	HTTPBaseURL     string
	ExpiresAt       time.Time
}

type CLICredentials struct {
	TerminalAuth      map[string]any
	UploadAuth        map[string]any
	TerminalSessionID string
	FileSessionID     string
}

type DisabledCredentialIssuer struct{}

func (DisabledCredentialIssuer) CheckCLI(context.Context, CredentialInput) error {
	return ErrCredentialIssuerUnavailable
}

func (DisabledCredentialIssuer) CheckHealth(context.Context, CredentialInput) error {
	return ErrCredentialIssuerUnavailable
}

func (DisabledCredentialIssuer) IssueCLI(context.Context, CredentialInput) (CLICredentials, error) {
	return CLICredentials{}, ErrCredentialIssuerUnavailable
}

func (DisabledCredentialIssuer) RevokeCLI(context.Context, CredentialRevocationInput) error {
	return ErrCredentialIssuerUnavailable
}

type FakeCredentialIssuer struct{}

func (FakeCredentialIssuer) CheckCLI(context.Context, CredentialInput) error {
	return nil
}

func (FakeCredentialIssuer) CheckHealth(context.Context, CredentialInput) error { return nil }

func (FakeCredentialIssuer) IssueCLI(_ context.Context, input CredentialInput) (CLICredentials, error) {
	terminalScopes := []string{"terminal:operate"}
	fileScopes := []string{"file:stage"}
	return CLICredentials{
		TerminalAuth: map[string]any{
			"method":     "websocket_ticket",
			"ticket":     "pct_" + input.ProjectID,
			"expires_at": input.ExpiresAt,
			"scopes":     terminalScopes,
		},
		UploadAuth: map[string]any{
			"method":     "bearer",
			"token":      "pat_" + input.ProjectID,
			"expires_at": input.ExpiresAt,
			"scopes":     fileScopes,
		},
		TerminalSessionID: "fake-terminal-" + input.ProjectID + "-" + input.ClientSessionID,
		FileSessionID:     "fake-file-" + input.ProjectID + "-" + input.ClientSessionID,
	}, nil
}

func (FakeCredentialIssuer) RevokeCLI(context.Context, CredentialRevocationInput) error { return nil }

type FakeClient struct {
	BaseURL string
}

func (f FakeClient) EnsureProjectResources(_ context.Context, project ProjectRef) (ResourceDescriptor, error) {
	base := strings.TrimRight(f.BaseURL, "/")
	if base == "" {
		base = "https://agentunnel.local"
	}
	return ResourceDescriptor{
		ServerURL:        base,
		TunnelID:         "tun_" + project.ID,
		ClientID:         "cli_" + project.ID,
		ResourceID:       "res_" + project.ID,
		HTTPBaseURL:      base + "/projects/" + project.ID,
		WebSocketBaseURL: strings.Replace(base, "https://", "wss://", 1) + "/projects/" + project.ID,
		MachineToken:     "fake-agentunnel-token-" + project.ID,
		Metadata: map[string]any{
			"provider":       "fake",
			"resource_kind":  "http_tunnel",
			"preview_url":    base + "/projects/" + project.ID,
			"local_url":      "http://127.0.0.1:4099",
			"machine_secret": "external",
		},
	}, nil
}

func (f FakeClient) ReattachProjectResources(ctx context.Context, project ProjectRef, resource ResourceDescriptor) (ResourceDescriptor, error) {
	reattached, err := f.EnsureProjectResources(ctx, project)
	if err != nil {
		return ResourceDescriptor{}, err
	}
	reattached.TunnelID = resource.TunnelID
	reattached.ResourceID = resource.ResourceID
	reattached.HTTPBaseURL = resource.HTTPBaseURL
	reattached.WebSocketBaseURL = resource.WebSocketBaseURL
	return reattached, nil
}

func (FakeClient) Status(_ context.Context, _ ResourceDescriptor) (TunnelStatus, error) {
	return TunnelStatus{Ready: true, Status: "online"}, nil
}

func (FakeClient) CleanupProjectResources(context.Context, ResourceDescriptor, string, string) error {
	return nil
}

type DisabledClient struct{}

func (DisabledClient) EnsureProjectResources(context.Context, ProjectRef) (ResourceDescriptor, error) {
	return ResourceDescriptor{}, ErrTunnelUnavailable
}

func (DisabledClient) ReattachProjectResources(context.Context, ProjectRef, ResourceDescriptor) (ResourceDescriptor, error) {
	return ResourceDescriptor{}, ErrTunnelUnavailable
}

func (DisabledClient) Status(context.Context, ResourceDescriptor) (TunnelStatus, error) {
	return TunnelStatus{}, ErrTunnelUnavailable
}

func (DisabledClient) CleanupProjectResources(context.Context, ResourceDescriptor, string, string) error {
	return ErrTunnelUnavailable
}

type HTTPClient struct {
	BaseURL              string
	APIKey               string
	PapercodeLocalURL    string
	RouteExpiresIn       time.Duration
	RouteSubdomainPrefix string
	AccessPolicyID       string
	UploadMaxBytes       int64
	HTTPClient           *http.Client
}

func (c HTTPClient) EnsureProjectResources(ctx context.Context, project ProjectRef) (ResourceDescriptor, error) {
	clientID, machineToken, err := c.ensureClient(ctx, project)
	if err != nil {
		return ResourceDescriptor{}, err
	}
	if c.RouteExpiresIn <= 0 {
		return ResourceDescriptor{}, ErrTunnelUnavailable
	}
	fail := func(err error) (ResourceDescriptor, error) {
		cleanupErr := c.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: clientID}, "close", "provision_failed")
		if cleanupErr != nil {
			return ResourceDescriptor{}, errors.Join(err, cleanupErr)
		}
		return ResourceDescriptor{}, err
	}
	localURL := strings.TrimSpace(c.PapercodeLocalURL)
	if localURL == "" {
		return fail(ErrTunnelUnavailable)
	}
	var httpPayload struct {
		TunnelID   string     `json:"tunnel_id"`
		PreviewURL string     `json:"preview_url"`
		Status     string     `json:"status"`
		ExpiresAt  *time.Time `json:"expires_at"`
	}
	var lastHTTPErr error
	for _, subdomain := range projectSubdomainCandidates(c.RouteSubdomainPrefix, project.ID) {
		httpBody := map[string]any{
			"client_id":  clientID,
			"local_url":  localURL,
			"subdomain":  subdomain,
			"expires_in": "never",
		}
		if strings.TrimSpace(c.AccessPolicyID) != "" {
			httpBody["access_policy_id"] = c.AccessPolicyID
		}
		if err := c.post(ctx, "/api/http-tunnels", httpBody, &httpPayload); err != nil {
			lastHTTPErr = err
			if isSubdomainInUse(err) {
				continue
			}
			return fail(err)
		}
		lastHTTPErr = nil
		break
	}
	if lastHTTPErr != nil {
		return fail(lastHTTPErr)
	}
	httpURL, wsURL := routeURLs(httpPayload.PreviewURL)
	if httpPayload.TunnelID == "" || httpURL == "" || wsURL == "" {
		return fail(ErrTunnelUnavailable)
	}
	resource := ResourceDescriptor{
		ServerURL:        strings.TrimRight(c.BaseURL, "/"),
		TunnelID:         httpPayload.TunnelID,
		ClientID:         clientID,
		ResourceID:       httpPayload.TunnelID,
		HTTPBaseURL:      httpURL,
		WebSocketBaseURL: wsURL,
		MachineToken:     machineToken,
		Metadata: map[string]any{
			"provider":       "agentunnel",
			"resource_kind":  "http_tunnel",
			"http_tunnel_id": httpPayload.TunnelID,
			"local_url":      localURL,
			"route_status":   httpPayload.Status,
			"route_expires":  timeString(httpPayload.ExpiresAt),
			"preview_url":    httpPayload.PreviewURL,
			"machine_secret": "external",
		},
	}
	return resource, nil
}

func (c HTTPClient) ReattachProjectResources(ctx context.Context, project ProjectRef, resource ResourceDescriptor) (ResourceDescriptor, error) {
	if strings.TrimSpace(resource.TunnelID) == "" || resourceKind(resource) != "http_tunnel" {
		return ResourceDescriptor{}, ErrTunnelUnavailable
	}
	clientID, machineToken, err := c.ensureClient(ctx, project)
	if err != nil {
		return ResourceDescriptor{}, err
	}
	var payload struct {
		TunnelID   string `json:"tunnel_id"`
		PreviewURL string `json:"preview_url"`
		Status     string `json:"status"`
		ClientID   string `json:"client_id"`
	}
	if err := c.post(ctx, "/api/http-tunnels/"+url.PathEscape(resource.TunnelID)+"/reassign", map[string]any{"client_id": clientID, "expires_in": "never"}, &payload); err != nil {
		_ = c.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: clientID}, "close", "reattach_failed")
		return ResourceDescriptor{}, err
	}
	httpURL, wsURL := routeURLs(firstNonEmpty(payload.PreviewURL, resource.HTTPBaseURL))
	if payload.TunnelID != resource.TunnelID || payload.ClientID != clientID || httpURL == "" || wsURL == "" {
		_ = c.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: clientID}, "close", "reattach_invalid_response")
		return ResourceDescriptor{}, ErrTunnelUnavailable
	}
	oldClientID := strings.TrimSpace(resource.ClientID)
	metadata := cloneMetadata(resource.Metadata)
	metadata["route_status"] = payload.Status
	metadata["preview_url"] = httpURL
	metadata["machine_secret"] = "external"
	if oldClientID != "" && oldClientID != clientID {
		metadata["superseded_client_id"] = oldClientID
	}
	delete(metadata, "tcp_tunnel_id")
	delete(metadata, "tcp_status")
	delete(metadata, "tcp_lifecycle")
	delete(metadata, "tcp_forwarding_status")
	return ResourceDescriptor{
		ServerURL: strings.TrimRight(c.BaseURL, "/"), TunnelID: resource.TunnelID, ClientID: clientID, ResourceID: resource.ResourceID,
		HTTPBaseURL: httpURL, WebSocketBaseURL: wsURL, MachineToken: machineToken, Metadata: metadata,
	}, nil
}

func (c HTTPClient) Status(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	if strings.TrimSpace(resource.TunnelID) == "" {
		return TunnelStatus{}, ErrTunnelUnavailable
	}
	return c.httpTunnelStatus(ctx, resource)
}

func (c HTTPClient) httpTunnelStatus(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	var payload struct {
		TunnelID            string     `json:"tunnel_id"`
		PreviewURL          string     `json:"preview_url"`
		Status              string     `json:"status"`
		ForwardingStatus    string     `json:"forwarding_status"`
		ClientConnected     bool       `json:"client_connected"`
		MaxRequestBodyBytes int64      `json:"max_request_body_bytes"`
		ExpiresAt           *time.Time `json:"expires_at"`
	}
	if err := c.get(ctx, "/api/http-tunnels/"+url.PathEscape(resource.TunnelID), &payload); err != nil {
		return TunnelStatus{}, err
	}
	httpURL, wsURL := routeURLs(firstNonEmpty(payload.PreviewURL, resource.HTTPBaseURL))
	status := firstNonEmpty(payload.ForwardingStatus, payload.Status, "unknown")
	ready := payload.Status == "active" && payload.ClientConnected && status == "online" && httpURL != "" && wsURL != ""
	reason := ""
	if !ready {
		switch {
		case payload.Status != "active":
			reason = "HTTP_ROUTE_NOT_ACTIVE"
		case !payload.ClientConnected || status != "online":
			reason = "CLIENT_OFFLINE"
		default:
			reason = "HTTP_ROUTE_NOT_READY"
		}
	}
	if ready && c.UploadMaxBytes > 0 {
		const multipartEnvelopeMaxBytes int64 = 64 << 10
		requiredProxyBytes := c.UploadMaxBytes + multipartEnvelopeMaxBytes
		if requiredProxyBytes < c.UploadMaxBytes {
			ready = false
			status = "proxy_limit_incompatible"
			reason = "UPLOAD_LIMIT_OVERFLOW"
		} else if payload.MaxRequestBodyBytes <= 0 {
			ready = false
			status = "proxy_limit_incompatible"
			reason = "PROXY_BODY_LIMIT_UNKNOWN"
		} else if payload.MaxRequestBodyBytes < requiredProxyBytes {
			ready = false
			status = "proxy_limit_incompatible"
			reason = "PROXY_BODY_LIMIT_TOO_LOW"
		}
	}
	return TunnelStatus{
		Ready:               ready,
		Status:              status,
		Reason:              reason,
		HTTPBaseURL:         httpURL,
		WebSocketBaseURL:    wsURL,
		MaxRequestBodyBytes: payload.MaxRequestBodyBytes,
	}, nil
}

func (c HTTPClient) CleanupProjectResources(ctx context.Context, resource ResourceDescriptor, action, reason string) error {
	clientID := strings.TrimSpace(resource.ClientID)
	if clientID == "" {
		return ErrTunnelUnavailable
	}
	action = strings.TrimSpace(action)
	if action == "" {
		action = "suspend"
	}
	body := map[string]any{"action": action}
	if strings.TrimSpace(reason) != "" {
		body["reason"] = reason
	}
	var payload map[string]any
	if err := c.post(ctx, "/api/clients/"+url.PathEscape(clientID)+"/machine-cleanup", body, &payload); err != nil {
		return err
	}
	return nil
}

func (c HTTPClient) get(ctx context.Context, path string, target any) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, target)
}

func (c HTTPClient) post(ctx context.Context, path string, body any, target any) error {
	return c.doJSON(ctx, http.MethodPost, path, body, target)
}

func (c HTTPClient) doJSON(ctx context.Context, method, path string, body any, target any) error {
	base, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ErrTunnelUnavailable
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String(), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(c.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrTunnelUnavailable
	}
	defer resp.Body.Close()
	var envelope struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return ErrTunnelUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.OK {
		return providerError{code: envelope.Error.Code, message: envelope.Error.Message}
	}
	if len(envelope.Data) == 0 {
		return ErrTunnelUnavailable
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return ErrTunnelUnavailable
	}
	return nil
}

func (c HTTPClient) ensureClient(ctx context.Context, project ProjectRef) (string, string, error) {
	var payload struct {
		ClientID string `json:"client_id"`
		ID       string `json:"id"`
		Token    string `json:"client_token"`
	}
	body := map[string]any{"name": projectClientName(project)}
	if err := c.post(ctx, "/api/clients", body, &payload); err != nil {
		return "", "", err
	}
	clientID := firstNonEmpty(payload.ClientID, payload.ID)
	if clientID == "" {
		return "", "", ErrTunnelUnavailable
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", "", ErrTunnelUnavailable
	}
	return clientID, payload.Token, nil
}

func isSubdomainInUse(err error) bool {
	var providerErr providerError
	return errors.As(err, &providerErr) && providerErr.code == providerCodeSubdomainInUse
}

type Service struct {
	issuer                   string
	repo                     *Repository
	projects                 *projects.Service
	client                   Client
	credentials              CredentialIssuer
	audit                    *audit.Writer
	minimumStartCreditWindow time.Duration
	ttl                      time.Duration
	connectReadyTimeout      time.Duration
	connectPollInterval      time.Duration
	uploadMaxBytes           int64
	uploadAllowedMIMEs       []string
	uploadRetentionSeconds   int64
	beforeConnect            func(context.Context, string, string) error
}

// PapercodeHTTPBaseURL returns the canonical agentunnel route for an already
// provisioned project. It never starts a machine or creates a resource.
func (s *Service) PapercodeHTTPBaseURL(ctx context.Context, projectID string) (string, error) {
	resource, ok, err := s.repo.Resource(ctx, projectID)
	if err != nil {
		return "", err
	}
	if !ok || strings.TrimSpace(resource.HTTPBaseURL) == "" {
		return "", ErrTunnelUnavailable
	}
	return strings.TrimRight(resource.HTTPBaseURL, "/"), nil
}

// SetBeforeConnect configures control-plane reconciliation that must complete
// after Papercode is healthy and before a descriptor can be issued.
func (s *Service) SetBeforeConnect(fn func(context.Context, string, string) error) {
	s.beforeConnect = fn
}

func NewService(store *db.DB, projectService *projects.Service, client Client, auditWriter *audit.Writer, cfg config.Config) *Service {
	issuer := CredentialIssuer(DisabledCredentialIssuer{})
	if cfg.Providers.FakeMode {
		issuer = FakeCredentialIssuer{}
	}
	return NewServiceWithCredentials(store, projectService, client, issuer, auditWriter, cfg)
}

func NewServiceWithCredentials(store *db.DB, projectService *projects.Service, client Client, issuer CredentialIssuer, auditWriter *audit.Writer, cfg config.Config) *Service {
	if client == nil {
		client = FakeClient{BaseURL: cfg.Providers.Agentunnel.BaseURL}
	}
	if issuer == nil {
		issuer = DisabledCredentialIssuer{}
	}
	return &Service{
		issuer:                   config.NormalizeIssuer(cfg.HTTP.PublicBaseURL),
		repo:                     NewRepository(store, cfg.Secrets.EncryptionKey),
		projects:                 projectService,
		client:                   client,
		credentials:              issuer,
		audit:                    auditWriter,
		minimumStartCreditWindow: cfg.Metering.MinimumStartCreditWindow,
		ttl:                      defaultAccessTTL,
		connectReadyTimeout:      cfg.Providers.Agentunnel.ConnectReadyTimeout,
		connectPollInterval:      cfg.Providers.Agentunnel.ConnectPollInterval,
		uploadMaxBytes:           cfg.Providers.Agentunnel.UploadMaxBytes,
		uploadAllowedMIMEs:       slices.Clone(cfg.Providers.Agentunnel.UploadAllowedMIMEs),
		uploadRetentionSeconds:   int64(cfg.Providers.Agentunnel.UploadRetention / time.Second),
	}
}

type ConnectKind string

const (
	ConnectGeneric   ConnectKind = "generic"
	ConnectPapercode ConnectKind = "papercode"
	ConnectCLI       ConnectKind = "cli"
)

type ConnectInput struct {
	UserID            string
	ProjectID         string
	Kind              ConnectKind
	ClientSessionID   string
	TerminalSessionID string
}

type ConnectResponse struct {
	Issuer            string         `json:"issuer,omitempty"`
	ProjectID         string         `json:"project_id"`
	ProjectState      string         `json:"project_state"`
	Connectable       bool           `json:"connectable"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Descriptors       []any          `json:"descriptors,omitempty"`
	Environment       map[string]any `json:"environment,omitempty"`
	AccessEndpoint    map[string]any `json:"access_endpoint,omitempty"`
	Terminal          map[string]any `json:"terminal,omitempty"`
	PapercodeUpload   map[string]any `json:"upload,omitempty"`
	Status            string         `json:"status,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	RetryAfterSeconds int            `json:"retry_after_seconds"`
}

func (s *Service) Connect(ctx context.Context, input ConnectInput) (ConnectResponse, error) {
	observability.ConnectAttempted()
	if input.Kind == "" {
		input.Kind = ConnectGeneric
	}
	project, err := s.projects.Get(ctx, input.UserID, input.ProjectID)
	if err != nil {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "project_not_found", nil)
		return ConnectResponse{}, err
	}
	var terminalSession dbsqlc.ProjectTerminalSession
	if input.Kind == ConnectCLI {
		err = s.repo.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			q := tx.Queries()
			if _, err := q.LockProjectTerminalSessions(ctx, input.ProjectID); err != nil {
				return err
			}
			if input.TerminalSessionID == "" {
				terminalSession, err = q.GetDefaultTerminalSession(ctx, input.ProjectID)
			} else {
				terminalSession, err = q.GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: input.ProjectID, ID: input.TerminalSessionID})
			}
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTerminalSessionNotFound
			}
			if err != nil {
				return err
			}
			pending, err := q.TerminalSessionOperationPending(ctx, dbsqlc.TerminalSessionOperationPendingParams{ProjectID: input.ProjectID, TerminalSessionID: terminalSession.ID})
			if err != nil {
				return err
			}
			if pending {
				return ErrTerminalSessionOperationPending
			}
			// A completed close leaves a durable identity that can be attached again.
			// Mark the new attach intent so a subsequent close controls the restarted
			// PTY instead of treating the historical close as still authoritative.
			return q.ReopenTerminalSession(ctx, dbsqlc.ReopenTerminalSessionParams{ProjectID: input.ProjectID, ID: terminalSession.ID})
		})
		if err != nil {
			return ConnectResponse{}, err
		}
	}
	if terminalProjectState(project.State) {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "invalid_project_state", map[string]any{"project_state": project.State})
		if project.State == "deleted" || project.State == "deleting" {
			return ConnectResponse{}, ErrDeleted
		}
		if project.State == "failed" {
			return ConnectResponse{}, ErrMachineFailed
		}
		return ConnectResponse{}, ErrInvalidState
	}
	if err := s.repo.EnsureConnectCredits(ctx, input.UserID, input.ProjectID, s.minimumStartCreditWindow); err != nil {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credits_exhausted", nil)
		return ConnectResponse{}, err
	}
	expires := time.Now().UTC().Add(s.ttl)
	var credentials CLICredentials
	if input.Kind == ConnectCLI {
		if err := s.repo.EnsureGitHubConfigReady(ctx, input.UserID); err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "github_config_not_ready", nil)
			return ConnectResponse{}, err
		}
		credentialInput := CredentialInput{UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID, ClientSessionID: input.ClientSessionID, ExpiresAt: expires}
		if err := s.credentials.CheckCLI(ctx, credentialInput); err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credential_issuer_unavailable", nil)
			return ConnectResponse{}, fmt.Errorf("%w: %v", ErrCredentialIssuerUnavailable, err)
		}
	}
	resource, ok, err := s.repo.Resource(ctx, input.ProjectID)
	if err != nil {
		return ConnectResponse{}, err
	}
	resource, err = s.reconcileResource(ctx, project, resource, ok)
	if err != nil {
		return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
	}
	if project.State == "stopped" && ok {
		if oldClientID, _ := resource.Metadata["superseded_client_id"].(string); strings.TrimSpace(oldClientID) != "" {
			if err := s.client.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: oldClientID}, "suspend", "machine_replaced"); err != nil {
				return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
			}
			delete(resource.Metadata, "superseded_client_id")
			resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
			if err != nil {
				return ConnectResponse{}, err
			}
		}
		resource, err = s.client.ReattachProjectResources(ctx, ProjectRef{ID: project.ID, Name: project.Name}, resource)
		if err != nil {
			return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
		}
		resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
		if err != nil {
			return ConnectResponse{}, err
		}
		if oldClientID, _ := resource.Metadata["superseded_client_id"].(string); strings.TrimSpace(oldClientID) != "" {
			if err := s.client.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: oldClientID}, "suspend", "machine_replaced"); err != nil {
				return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
			}
			delete(resource.Metadata, "superseded_client_id")
			resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
			if err != nil {
				return ConnectResponse{}, err
			}
		}
	}
	resumeQueued := false
	if project.State == "stopped" || project.State == "ready" {
		project, err = s.projects.Start(ctx, input.UserID, input.ProjectID)
		if err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "start_failed", map[string]any{"project_state": project.State})
			return ConnectResponse{}, err
		}
		resumeQueued = true
	}
	status, err := s.waitForReady(ctx, resource)
	if err != nil {
		reconciled, reconcileErr := s.reconcileResource(ctx, project, resource, false)
		if reconcileErr != nil {
			if errors.Is(err, ErrProvider) {
				reconcileErr = ErrProvider
			}
			return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, reconcileErr)
		}
		resource = reconciled
		status, err = s.waitForReady(ctx, resource)
		if err != nil {
			return ConnectResponse{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
		}
	}
	resource = applyStatusResource(resource, status)
	if staleHTTPStatus(resource, status) {
		reconciled, reconcileErr := s.reconcileResource(ctx, project, resource, false)
		if reconcileErr == nil {
			resource = reconciled
			if refreshed, refreshErr := s.client.Status(ctx, resource); refreshErr == nil {
				status = refreshed
				resource = applyStatusResource(resource, status)
			}
		}
	}
	if !status.Ready {
		refreshedProject, refreshErr := s.projects.Get(ctx, input.UserID, input.ProjectID)
		if refreshErr != nil {
			return ConnectResponse{}, refreshErr
		}
		project = refreshedProject
		if project.State == "failed" {
			return ConnectResponse{}, ErrMachineFailed
		}
		response := ConnectResponse{Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires, Status: status.Status, Reason: status.Reason, RetryAfterSeconds: s.retryAfterSeconds()}
		if resumeQueued && project.State == "starting" {
			response.Status = "machine_starting"
			response.Reason = "machine_start_queued"
		} else if project.State == "starting" || project.State == "restarting" {
			response.Status = "machine_starting"
			response.Reason = "machine_not_running"
		} else if status.Reason == "CLIENT_OFFLINE" {
			response.Status = "tunnel_connecting"
			response.Reason = "tunnel_offline"
		}
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "tunnel_not_ready", map[string]any{
			"status": response.Status, "reason": response.Reason, "environment_id": project.ID,
			"agentunnel_tunnel_id": resource.TunnelID, "agentunnel_client_id": resource.ClientID,
		})
		return response, nil
	}
	healthClientSessionID := input.ClientSessionID
	if healthClientSessionID == "" {
		healthClientSessionID = "paperboat-control-plane"
	}
	healthInput := CredentialInput{
		UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
		ClientSessionID: healthClientSessionID, HTTPBaseURL: resource.HTTPBaseURL, ExpiresAt: expires,
	}
	healthErr := s.credentials.CheckCLI(ctx, healthInput)
	if checker, ok := s.credentials.(environmentHealthChecker); ok {
		healthErr = checker.CheckHealth(ctx, healthInput)
	}
	if healthErr != nil {
		response := ConnectResponse{
			Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires,
			Status: "papercode_starting", Reason: "papercode_unhealthy", RetryAfterSeconds: s.retryAfterSeconds(),
		}
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "papercode_unhealthy", map[string]any{
			"environment_id": project.ID, "agentunnel_tunnel_id": resource.TunnelID,
			"error": healthErr.Error(),
		})
		return response, nil
	}
	if s.beforeConnect != nil {
		if err := s.beforeConnect(ctx, input.UserID, input.ProjectID); err != nil {
			return ConnectResponse{}, fmt.Errorf("%w: %v", ErrTerminalRuntimeUnavailable, err)
		}
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.route_ready", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.route_ready:" + newID("attempt"), Metadata: map[string]any{"environment_id": project.ID, "agentunnel_tunnel_id": resource.TunnelID, "agentunnel_client_id": resource.ClientID, "status": status.Status}})
	observability.RouteReady()
	if input.Kind == ConnectCLI {
		credentialInput := CredentialInput{
			UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
			ClientSessionID: input.ClientSessionID, HTTPBaseURL: resource.HTTPBaseURL, ExpiresAt: expires,
		}
		credentials, err = s.credentials.IssueCLI(ctx, credentialInput)
		if err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credential_issuer_unavailable", nil)
			var outboxErr error
			sessionIDs := compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)
			if len(sessionIDs) > 0 {
				_, outboxErr = s.repo.CreatePapercodeRevocationOutbox(ctx, CredentialRevocationInput{
					UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
					ClientSessionID: input.ClientSessionID, HTTPBaseURL: resource.HTTPBaseURL,
					SessionIDs: sessionIDs, Reason: "partial_credential_issuance_failed",
				})
			}
			return ConnectResponse{}, errors.Join(fmt.Errorf("%w: %v", ErrCredentialIssuerUnavailable, err), outboxErr)
		}
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.credentials_minted", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.credentials_minted:" + credentials.TerminalSessionID, Metadata: map[string]any{"environment_id": input.ProjectID, "client_session_id": input.ClientSessionID, "terminal_session_id": credentials.TerminalSessionID, "file_session_id": credentials.FileSessionID}})
		observability.CredentialsMinted()
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "agentunnel_connection", map[string]any{
		"kind": input.Kind, "status": status.Status, "environment_id": project.ID,
		"agentunnel_tunnel_id": resource.TunnelID, "agentunnel_client_id": resource.ClientID,
	})
	response := buildResponse(input.Kind, project, resource, expires, credentials, s.uploadMaxBytes, s.uploadAllowedMIMEs, s.uploadRetentionSeconds, terminalSession.ThreadID, terminalSession.TerminalID, terminalSession.LaunchCwd)
	if input.Kind == ConnectCLI {
		response.Issuer = s.issuer
	}
	session, err := s.repo.CreateAccessSession(ctx, input.UserID, input.ProjectID, input.ClientSessionID, credentials.TerminalSessionID, credentials.FileSessionID, string(input.Kind), response, expires)
	if err != nil {
		if input.Kind == ConnectCLI {
			revocation := CredentialRevocationInput{
				UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
				ClientSessionID: input.ClientSessionID, HTTPBaseURL: resource.HTTPBaseURL,
				SessionIDs: []string{credentials.TerminalSessionID, credentials.FileSessionID},
				Reason:     "access_session_persistence_failed",
			}
			outboxID, outboxErr := s.repo.CreatePapercodeRevocationOutbox(ctx, revocation)
			cleanupErr := s.credentials.RevokeCLI(ctx, revocation)
			var markErr error
			if outboxErr == nil && cleanupErr == nil {
				markErr = s.repo.MarkPapercodeRevocationOutboxPropagated(ctx, outboxID)
			}
			return ConnectResponse{}, errors.Join(err, outboxErr, cleanupErr, markErr)
		}
		return ConnectResponse{}, err
	}
	correlation := map[string]any{
		"kind": input.Kind, "project_state": project.State, "environment_id": project.ID,
		"access_session_id": session.ID, "agentunnel_tunnel_id": resource.TunnelID,
		"agentunnel_client_id": resource.ClientID,
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "connect_session", correlation)
	_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, session.ID, "approved", "", correlation)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.connect_approved", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.connect_approved:" + session.ID, Metadata: correlation})
	observability.ConnectApproved()
	return response, nil
}

func compactSessionIDs(sessionIDs ...string) []string {
	out := make([]string, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		if sessionID != "" && !slices.Contains(out, sessionID) {
			out = append(out, sessionID)
		}
	}
	return out
}

func (s *Service) denyProviderFailure(ctx context.Context, userID, projectID string, err error) error {
	reason := "tunnel_unavailable"
	out := ErrTunnelUnavailable
	if errors.Is(err, ErrProvider) {
		reason = "provider_error"
		out = ErrProvider
	}
	s.recordConnectDenied(ctx, userID, projectID, reason, nil)
	return out
}

func (s *Service) recordConnectDenied(ctx context.Context, userID, projectID, reason string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	} else {
		metadata = maps.Clone(metadata)
	}
	metadata["reason"] = reason
	metadata["environment_id"] = projectID
	_ = s.repo.RecordConnectionEvent(ctx, userID, projectID, "", "denied", reason, metadata)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "access.connect_denied", ResourceType: "project", ResourceID: projectID, IdempotencyKey: "access.connect_denied:" + newID("attempt"), Metadata: metadata})
	observability.ConnectDenied()
}

func (s *Service) waitForReady(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	timeout := s.connectReadyTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	interval := s.connectPollInterval
	if interval <= 0 || interval > timeout {
		interval = timeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last TunnelStatus
	for {
		status, err := s.client.Status(waitCtx, resource)
		if err != nil {
			return TunnelStatus{}, err
		}
		last = status
		if status.Ready {
			return status, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return last, nil
		case <-timer.C:
		}
	}
}

func (s *Service) reconcileResource(ctx context.Context, project projects.Project, resource ResourceDescriptor, existing bool) (ResourceDescriptor, error) {
	if existing && resource.HTTPBaseURL != "" && resource.WebSocketBaseURL != "" {
		return resource, nil
	}
	reconciled, err := s.client.EnsureProjectResources(ctx, ProjectRef{ID: project.ID, Name: project.Name})
	if err != nil {
		return ResourceDescriptor{}, err
	}
	if existing {
		preserveMachineCredential(resource, &reconciled)
	}
	return s.repo.UpsertResource(ctx, project.ID, reconciled)
}

func preserveMachineCredential(existing ResourceDescriptor, reconciled *ResourceDescriptor) {
	if reconciled == nil {
		return
	}
	ciphertext, _ := existing.Metadata["machine_token_ciphertext"].(string)
	if strings.TrimSpace(ciphertext) == "" {
		return
	}
	if reconciled.Metadata == nil {
		reconciled.Metadata = map[string]any{}
	}
	reconciled.Metadata["machine_token_ciphertext"] = ciphertext
	reconciled.MachineToken = ""
}

func staleHTTPStatus(resource ResourceDescriptor, status TunnelStatus) bool {
	if resourceKind(resource) != "http_tunnel" {
		return false
	}
	// An offline client still owns a valid, stable route. Rotating its credential
	// here strands a booting VM on the previous token and causes every connect
	// retry to rotate the token again before the VM can reconnect.
	if status.Reason == "CLIENT_OFFLINE" {
		return false
	}
	switch status.Status {
	case "closed", "expired":
		return true
	default:
		return status.HTTPBaseURL == "" || status.WebSocketBaseURL == ""
	}
}

func (s *Service) Status(ctx context.Context, userID, projectID, terminalSessionID string) (ConnectResponse, error) {
	project, err := s.projects.Get(ctx, userID, projectID)
	if err != nil {
		return ConnectResponse{}, err
	}
	var terminalSession dbsqlc.ProjectTerminalSession
	if terminalSessionID == "" {
		terminalSession, err = s.repo.db.Queries().GetDefaultTerminalSession(ctx, projectID)
	} else {
		terminalSession, err = s.repo.db.Queries().GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: projectID, ID: terminalSessionID})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectResponse{}, ErrTerminalSessionNotFound
	}
	if err != nil {
		return ConnectResponse{}, err
	}
	pending, err := s.repo.db.Queries().TerminalSessionOperationPending(ctx, dbsqlc.TerminalSessionOperationPendingParams{ProjectID: projectID, TerminalSessionID: terminalSession.ID})
	if err != nil {
		return ConnectResponse{}, err
	}
	if pending {
		return ConnectResponse{}, ErrTerminalSessionOperationPending
	}
	resource, ok, err := s.repo.Resource(ctx, projectID)
	if err != nil {
		return ConnectResponse{}, err
	}
	response := ConnectResponse{Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: time.Now().UTC().Add(s.ttl), RetryAfterSeconds: s.retryAfterSeconds()}
	if !ok {
		response.Status = "missing"
		response.Reason = "agentunnel resources have not been provisioned"
		return response, nil
	}
	status, err := s.client.Status(ctx, resource)
	if err != nil {
		response.Status = "unknown"
		response.Reason = "agentunnel status is unavailable"
		return response, nil
	}
	response.Connectable = status.Ready && !terminalProjectState(project.State)
	response.Status = status.Status
	response.Reason = status.Reason
	if status.Ready {
		response.Status = "ready"
		response.Reason = "ready"
		response.RetryAfterSeconds = 0
	} else if project.State == "starting" || project.State == "restarting" {
		response.Status = "machine_starting"
		response.Reason = "machine_not_running"
	} else if status.Reason == "CLIENT_OFFLINE" {
		response.Status = "tunnel_connecting"
		response.Reason = "tunnel_offline"
	}
	if response.Connectable && s.beforeConnect != nil {
		if err := s.beforeConnect(ctx, userID, projectID); err != nil {
			// Reconciliation is durable and retryable. Keep this as a normal
			// readiness state so a CLI waits rather than receiving a transient
			// operational failure while a pending purge/close is applied.
			response.Connectable = false
			response.Status = "papercode_starting"
			response.Reason = "terminal_session_operation_pending"
			response.RetryAfterSeconds = s.retryAfterSeconds()
		}
	}
	response.Terminal = terminalStatusDescriptor(status, terminalSession)
	if terminalProjectState(project.State) {
		response.Connectable = false
		response.Reason = firstNonEmpty(response.Reason, "project_state_"+project.State)
	}
	if project.State == "stopping" || project.State == "stopped" {
		if reason, ok, reasonErr := s.repo.LatestStopReason(ctx, projectID); reasonErr == nil && ok {
			response.Connectable = false
			response.Reason = reason
		}
	}
	if err := s.repo.EnsureConnectCredits(ctx, userID, projectID, s.minimumStartCreditWindow); err != nil {
		response.Connectable = false
		response.Reason = "credits_exhausted"
	}
	return response, nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, userID, reason string) error {
	if err := s.repo.RevokeUserAccessSessions(ctx, userID, reason); err != nil {
		return err
	}
	rows, err := s.repo.UserPapercodeSessions(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.revokePapercodeSessions(ctx, rows, reason); err != nil {
		return err
	}
	if err := s.repo.MarkUserPapercodeRevocationPropagated(ctx, userID); err != nil {
		return err
	}
	s.recordRevocationPropagated(ctx, "user", userID, reason, "papercode", map[string]any{"user_id": userID})
	return nil
}

func (s *Service) RevokeClientSessions(ctx context.Context, clientSessionID, reason string) error {
	if err := s.repo.RevokeClientAccessSessions(ctx, clientSessionID, reason); err != nil {
		return err
	}
	rows, err := s.repo.ClientPapercodeSessions(ctx, clientSessionID)
	if err != nil {
		return err
	}
	if err := s.revokePapercodeSessions(ctx, rows, reason); err != nil {
		return err
	}
	if err := s.repo.MarkClientPapercodeRevocationPropagated(ctx, clientSessionID); err != nil {
		return err
	}
	s.recordRevocationPropagated(ctx, "client_session", clientSessionID, reason, "papercode", map[string]any{"client_session_id": clientSessionID})
	return nil
}

func (s *Service) RevokeProjectSessions(ctx context.Context, projectID, reason string) error {
	if err := s.repo.RevokeProjectAccessSessions(ctx, projectID, reason); err != nil {
		return err
	}
	var revokeErrors []error
	papercodePropagated := false
	rows, err := s.repo.ProjectPapercodeSessions(ctx, projectID)
	if err != nil {
		revokeErrors = append(revokeErrors, fmt.Errorf("list project papercode sessions: %w", err))
	} else if err := s.revokePapercodeSessions(ctx, rows, reason); err != nil {
		revokeErrors = append(revokeErrors, err)
	} else {
		papercodePropagated = true
	}
	if resource, ok, err := s.repo.Resource(ctx, projectID); err != nil {
		revokeErrors = append(revokeErrors, fmt.Errorf("load project tunnel resource: %w", err))
	} else if ok {
		action := "suspend"
		if reason == "project_delete" {
			action = "close"
		}
		outboxErr := s.repo.UpsertAgentunnelCleanupOutbox(ctx, projectID, action, reason)
		if outboxErr != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("persist project tunnel cleanup: %w", outboxErr))
		}
		if err := s.client.CleanupProjectResources(ctx, resource, action, reason); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("cleanup project tunnel resources: %w", err))
		} else if outboxErr == nil {
			if err := s.repo.MarkAgentunnelCleanupOutboxPropagated(ctx, projectID); err != nil {
				revokeErrors = append(revokeErrors, fmt.Errorf("mark project tunnel cleanup propagated: %w", err))
			} else {
				s.recordRevocationPropagated(ctx, "project", projectID, reason, "agentunnel", map[string]any{"environment_id": projectID})
			}
		}
	}
	if papercodePropagated {
		if err := s.repo.MarkProjectPapercodeRevocationPropagated(ctx, projectID); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("mark project papercode revocation propagated: %w", err))
		}
		s.recordRevocationPropagated(ctx, "project", projectID, reason, "papercode", map[string]any{"environment_id": projectID})
	}
	return errors.Join(revokeErrors...)
}

func (s *Service) RetryPendingPapercodeRevocations(ctx context.Context) error {
	var retryErrors []error
	rows, err := s.repo.PendingPapercodeRevocations(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list pending papercode revocations: %w", err))
	} else {
		for _, row := range rows {
			if err := s.revokePapercodeSessions(ctx, []PapercodeSessionLink{row}, row.Reason); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("retry access session %s: %w", row.AccessSessionID, err))
				continue
			}
			if err := s.repo.MarkAccessSessionPapercodeRevocationPropagated(ctx, row.AccessSessionID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark access session %s revocation propagated: %w", row.AccessSessionID, err))
			} else {
				s.recordRevocationPropagated(ctx, "access_session", row.AccessSessionID, row.Reason, "papercode", map[string]any{"access_session_id": row.AccessSessionID, "project_id": row.ProjectID, "environment_id": row.ProjectID, "client_session_id": row.ClientSessionID})
			}
		}
	}
	outbox, err := s.repo.PendingPapercodeRevocationOutbox(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list orphaned papercode revocations: %w", err))
	} else {
		for _, item := range outbox {
			if err := s.credentials.RevokeCLI(ctx, item.Revocation); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("retry orphaned papercode revocation %s: %w", item.ID, err))
				continue
			}
			if err := s.repo.MarkPapercodeRevocationOutboxPropagated(ctx, item.ID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark orphaned papercode revocation %s propagated: %w", item.ID, err))
			} else {
				s.recordRevocationPropagated(ctx, "project", item.Revocation.ProjectID, item.Revocation.Reason, "papercode", map[string]any{"environment_id": item.Revocation.EnvironmentID, "client_session_id": item.Revocation.ClientSessionID})
			}
		}
	}
	tunnelCleanups, err := s.repo.PendingAgentunnelCleanupOutbox(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list pending agentunnel cleanup: %w", err))
	} else {
		for _, cleanup := range tunnelCleanups {
			resource, ok, err := s.repo.Resource(ctx, cleanup.ProjectID)
			if err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("load tunnel cleanup project %s: %w", cleanup.ProjectID, err))
				continue
			}
			if !ok {
				retryErrors = append(retryErrors, fmt.Errorf("load tunnel cleanup project %s: resource is missing", cleanup.ProjectID))
				continue
			}
			if err := s.client.CleanupProjectResources(ctx, resource, cleanup.Action, cleanup.Reason); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("retry tunnel cleanup project %s: %w", cleanup.ProjectID, err))
				continue
			}
			if err := s.repo.MarkAgentunnelCleanupOutboxPropagated(ctx, cleanup.ProjectID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark tunnel cleanup project %s propagated: %w", cleanup.ProjectID, err))
			} else {
				s.recordRevocationPropagated(ctx, "project", cleanup.ProjectID, cleanup.Reason, "agentunnel", map[string]any{"environment_id": cleanup.ProjectID})
			}
		}
	}
	return errors.Join(retryErrors...)
}

func (s *Service) recordRevocationPropagated(ctx context.Context, resourceType, resourceID, reason, target string, metadata map[string]any) {
	metadata = maps.Clone(metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["reason"] = reason
	metadata["target"] = target
	_ = s.audit.Write(ctx, audit.Event{ActorType: audit.ActorSystem, EventType: "access.revocation_propagated", ResourceType: resourceType, ResourceID: resourceID, IdempotencyKey: "access.revocation_propagated:" + resourceType + ":" + resourceID + ":" + target + ":" + reason, Metadata: metadata})
	observability.RevocationPropagated()
}

func (s *Service) revokePapercodeSessions(ctx context.Context, rows []PapercodeSessionLink, reason string) error {
	var revokeErrors []error
	for _, row := range rows {
		sessionIDs := make([]string, 0, 2)
		if row.TerminalSessionID != "" {
			sessionIDs = append(sessionIDs, row.TerminalSessionID)
		}
		if row.FileSessionID != "" && row.FileSessionID != row.TerminalSessionID {
			sessionIDs = append(sessionIDs, row.FileSessionID)
		}
		if len(sessionIDs) == 0 {
			continue
		}
		if err := s.credentials.RevokeCLI(ctx, CredentialRevocationInput{
			UserID: row.UserID, ProjectID: row.ProjectID, EnvironmentID: row.ProjectID,
			ClientSessionID: row.ClientSessionID, HTTPBaseURL: row.HTTPBaseURL,
			SessionIDs: sessionIDs, Reason: reason,
		}); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("revoke papercode sessions for project %s: %w", row.ProjectID, err))
		}
	}
	return errors.Join(revokeErrors...)
}

func terminalProjectState(state string) bool {
	switch state {
	case "deleted", "deleting", "failed", "suspended", "creating", "provisioning_storage", "provisioning_machine":
		return true
	default:
		return false
	}
}

func buildResponse(kind ConnectKind, project projects.Project, resource ResourceDescriptor, expires time.Time, credentials CLICredentials, uploadMaxBytes int64, uploadAllowedMIMEs []string, uploadRetentionSeconds int64, threadID, terminalID, cwd string) ConnectResponse {
	base := ConnectResponse{ProjectID: project.ID, ProjectState: project.State, Connectable: true, ExpiresAt: expires, Status: "ready", Reason: "ready"}
	switch kind {
	case ConnectPapercode:
		base.Environment = map[string]any{
			"environment_id": project.ID,
			"project_id":     project.ID,
			"display_name":   project.Name,
			"repository_identity": map[string]any{
				"provider": project.Repository.Provider,
				"url":      project.Repository.SourceURL,
			},
		}
		base.AccessEndpoint = map[string]any{
			"kind":               "tunneled_websocket",
			"provider":           "agentunnel",
			"http_base_url":      resource.HTTPBaseURL,
			"websocket_base_url": resource.WebSocketBaseURL,
			"compatibility": map[string]bool{
				"hosted_https_web": true,
				"desktop":          true,
				"mobile":           true,
			},
			"expires_at": expires,
		}
	case ConnectCLI:
		if threadID == "" {
			threadID = "paperboat-cli"
		}
		if terminalID == "" {
			terminalID = "term-1"
		}
		if cwd == "" {
			cwd = "/workspace"
		}
		base.Terminal = map[string]any{
			"kind":               "papercode_websocket",
			"http_base_url":      resource.HTTPBaseURL,
			"websocket_base_url": resource.WebSocketBaseURL,
			"thread_id":          threadID,
			"terminal_id":        terminalID,
			"cwd":                cwd,
		}
		if credentials.TerminalAuth != nil {
			base.Terminal["auth"] = credentials.TerminalAuth
		}
		base.Environment = map[string]any{
			"environment_id": project.ID,
			"project_id":     project.ID,
			"display_name":   project.Name,
			"project_root":   "/workspace",
		}
		base.PapercodeUpload = map[string]any{
			"kind":               "papercode_staged_image",
			"http_base_url":      resource.HTTPBaseURL,
			"path":               uploadPath(resource.HTTPBaseURL),
			"max_bytes":          uploadMaxBytes,
			"allowed_mime_types": slices.Clone(uploadAllowedMIMEs),
			"retention_seconds":  uploadRetentionSeconds,
		}
		if credentials.UploadAuth != nil {
			base.PapercodeUpload["auth"] = credentials.UploadAuth
		}
	default:
		base.Descriptors = []any{map[string]any{
			"kind":       "agentunnel_resource",
			"provider":   "agentunnel",
			"expires_at": expires,
		}}
	}
	return base
}

func uploadPath(httpBaseURL string) string {
	u, err := url.Parse(httpBaseURL)
	if err != nil {
		return ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/files/staged-images"
	u.RawPath = ""
	return u.Path
}

func (s *Service) retryAfterSeconds() int {
	interval := s.connectPollInterval
	if interval <= 0 {
		return 1
	}
	seconds := int((interval + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func applyStatusResource(resource ResourceDescriptor, status TunnelStatus) ResourceDescriptor {
	resource.HTTPBaseURL = firstNonEmpty(status.HTTPBaseURL, resource.HTTPBaseURL)
	resource.WebSocketBaseURL = firstNonEmpty(status.WebSocketBaseURL, resource.WebSocketBaseURL)
	return resource
}

func resourceKind(resource ResourceDescriptor) string {
	if resource.Metadata == nil {
		return ""
	}
	kind, _ := resource.Metadata["resource_kind"].(string)
	return kind
}

func routeURLs(value string) (string, string) {
	httpURL := strings.TrimRight(value, "/")
	if httpURL == "" {
		return "", ""
	}
	u, err := url.Parse(httpURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", ""
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", ""
	}
	return httpURL, strings.TrimRight(u.String(), "/")
}

func projectSubdomain(prefix, projectID string) string {
	prefix = sanitizeSubdomainPart(firstNonEmpty(prefix, "pb"))
	projectID = sanitizeSubdomainPart(projectID)
	if projectID == "" {
		projectID = "project"
	}
	return prefix + "-" + projectID
}

func projectSubdomainCandidates(prefix, projectID string) []string {
	base := truncateSubdomain(projectSubdomain(prefix, projectID))
	sum := sha256.Sum256([]byte(projectID))
	hash := hex.EncodeToString(sum[:])
	return []string{
		base,
		truncateSubdomain(base + "-" + hash[:6]),
		truncateSubdomain(base + "-" + hash[6:12]),
		truncateSubdomain(base + "-" + hash[12:18]),
	}
}

func truncateSubdomain(value string) string {
	if len(value) <= 63 {
		return value
	}
	return strings.Trim(value[:63], "-")
}

func projectClientName(project ProjectRef) string {
	base := sanitizeSubdomainPart(firstNonEmpty(project.Name, project.ID))
	if base == "" {
		base = "project"
	}
	sum := sha256.Sum256([]byte(project.ID))
	suffix := hex.EncodeToString(sum[:])[:10]
	maxBaseLen := 48
	if len(base) > maxBaseLen {
		base = strings.Trim(base[:maxBaseLen], "-")
	}
	return "paperboat-" + base + "-" + suffix
}

func sanitizeSubdomainPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func timeString(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func terminalStatusDescriptor(status TunnelStatus, terminalSession dbsqlc.ProjectTerminalSession) map[string]any {
	if status.HTTPBaseURL == "" && status.WebSocketBaseURL == "" {
		return nil
	}
	return map[string]any{
		"kind":               "papercode_websocket",
		"http_base_url":      status.HTTPBaseURL,
		"websocket_base_url": status.WebSocketBaseURL,
		"thread_id":          terminalSession.ThreadID,
		"terminal_id":        terminalSession.TerminalID,
		"cwd":                terminalSession.LaunchCwd,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func cloneMetadata(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

type AccessSession struct {
	ID string
}

type PapercodeSessionLink struct {
	AccessSessionID   string
	UserID            string
	ProjectID         string
	ClientSessionID   string
	TerminalSessionID string
	FileSessionID     string
	HTTPBaseURL       string
	Reason            string
}

type PapercodeRevocationOutboxItem struct {
	ID         string
	Revocation CredentialRevocationInput
}

type AgentunnelCleanupOutboxItem struct {
	ProjectID string
	Action    string
	Reason    string
}

type Repository struct {
	db            *db.DB
	encryptionKey string
}

func NewRepository(store *db.DB, encryptionKey string) *Repository {
	return &Repository{db: store, encryptionKey: encryptionKey}
}

func (r *Repository) EnsureConnectCredits(ctx context.Context, userID, projectID string, window time.Duration) error {
	if window <= 0 {
		return fmt.Errorf("minimum start credit window must be positive")
	}
	enough, err := r.db.Queries().HasConnectCredits(ctx, dbsqlc.HasConnectCreditsParams{ProjectID: projectID, UserID: userID, WindowSeconds: int64(window.Seconds())})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enough {
		return ErrInsufficientCredit
	}
	return nil
}

func (r *Repository) EnsureGitHubConfigReady(ctx context.Context, userID string) error {
	ready, err := r.db.Queries().GitHubConfigReady(ctx, userID)
	if err != nil {
		return err
	}
	if !ready {
		return ErrGitHubRequired
	}
	return nil
}

func (r *Repository) UpsertResource(ctx context.Context, projectID string, resource ResourceDescriptor) (ResourceDescriptor, error) {
	if resource.Metadata == nil {
		resource.Metadata = map[string]any{}
	}
	if strings.TrimSpace(resource.MachineToken) != "" {
		ciphertext, err := secrets.Encrypt(r.encryptionKey, resource.MachineToken)
		if err != nil {
			return ResourceDescriptor{}, err
		}
		resource.Metadata["machine_token_ciphertext"] = hex.EncodeToString(ciphertext)
		resource.MachineToken = ""
	}
	resource.Metadata["http_base_url"] = resource.HTTPBaseURL
	resource.Metadata["websocket_base_url"] = resource.WebSocketBaseURL
	delete(resource.Metadata, "ssh_host")
	delete(resource.Metadata, "ssh_port")
	delete(resource.Metadata, "tcp_tunnel_id")
	delete(resource.Metadata, "tcp_status")
	delete(resource.Metadata, "tcp_lifecycle")
	delete(resource.Metadata, "tcp_forwarding_status")
	delete(resource.Metadata, "tcp_error_code")
	metadata, err := json.Marshal(resource.Metadata)
	if err != nil {
		return ResourceDescriptor{}, err
	}
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		err := q.UpsertAgentunnelResource(ctx, dbsqlc.UpsertAgentunnelResourceParams{ID: newID("agr"), ProjectID: projectID, TunnelID: resource.TunnelID, ClientID: resource.ClientID, ResourceID: resource.ResourceID, Metadata: metadata})
		if err != nil {
			return err
		}
		previewURL, _ := resource.Metadata["preview_url"].(string)
		localURL, _ := resource.Metadata["local_url"].(string)
		if strings.TrimSpace(previewURL) == "" || strings.TrimSpace(localURL) == "" {
			return nil
		}
		return q.UpsertPreviewURLRecord(ctx, dbsqlc.UpsertPreviewURLRecordParams{ID: newID("pvr"), ProjectID: projectID, TargetUrl: localURL, PublicUrl: previewURL})
	})
	return resource, err
}

func (r *Repository) Resource(ctx context.Context, projectID string) (ResourceDescriptor, bool, error) {
	row, err := r.db.Queries().GetAgentunnelResource(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return ResourceDescriptor{}, false, nil
	}
	if err != nil {
		return ResourceDescriptor{}, false, err
	}
	resource := ResourceDescriptor{TunnelID: row.TunnelID, ClientID: row.ClientID, ResourceID: row.ResourceID}
	_ = json.Unmarshal(row.Metadata, &resource.Metadata)
	if resource.Metadata == nil {
		resource.Metadata = map[string]any{}
	}
	resource.HTTPBaseURL, _ = resource.Metadata["http_base_url"].(string)
	resource.WebSocketBaseURL, _ = resource.Metadata["websocket_base_url"].(string)
	return resource, true, nil
}

func (r *Repository) LatestStopReason(ctx context.Context, projectID string) (string, bool, error) {
	eventType, err := r.db.Queries().GetLatestProjectStopEventType(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimPrefix(eventType, "project.stop_queued."), true, nil
}

func (r *Repository) CreateAccessSession(ctx context.Context, userID, projectID, clientSessionID, terminalSessionID, fileSessionID, sessionType string, descriptor ConnectResponse, expiresAt time.Time) (AccessSession, error) {
	id := newID("acs")
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		return AccessSession{}, err
	}
	key := "access.session:" + id
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().CreateAccessSession(ctx, dbsqlc.CreateAccessSessionParams{ID: id, UserID: userID, ProjectID: projectID, ClientSessionID: clientSessionID, PapercodeTerminalSessionID: terminalSessionID, PapercodeFileSessionID: fileSessionID, SessionType: sessionType, Descriptor: descriptorBytes, ExpiresAt: expiresAt, IdempotencyKey: key})
	})
	return AccessSession{ID: id}, err
}

func (r *Repository) RevokeClientAccessSessions(ctx context.Context, clientSessionID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeClientAccessSessions(ctx, dbsqlc.RevokeClientAccessSessionsParams{ClientSessionID: sql.NullString{String: clientSessionID, Valid: true}, Reason: reason})
}

func (r *Repository) RevokeUserAccessSessions(ctx context.Context, userID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeUserAccessSessions(ctx, dbsqlc.RevokeUserAccessSessionsParams{UserID: userID, Reason: reason})
}

func (r *Repository) RevokeProjectAccessSessions(ctx context.Context, projectID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeProjectAccessSessions(ctx, dbsqlc.RevokeProjectAccessSessionsParams{ProjectID: projectID, Reason: reason})
}

func (r *Repository) ClientPapercodeSessions(ctx context.Context, clientSessionID string) ([]PapercodeSessionLink, error) {
	rows, err := r.db.Queries().ListClientPapercodeSessions(ctx, sql.NullString{String: clientSessionID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]PapercodeSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, PapercodeSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, ClientSessionID: row.ClientSessionID, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) UserPapercodeSessions(ctx context.Context, userID string) ([]PapercodeSessionLink, error) {
	rows, err := r.db.Queries().ListUserPapercodeSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PapercodeSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, PapercodeSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, ClientSessionID: row.ClientSessionID, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) ProjectPapercodeSessions(ctx context.Context, projectID string) ([]PapercodeSessionLink, error) {
	rows, err := r.db.Queries().ListProjectPapercodeSessions(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]PapercodeSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, PapercodeSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, ClientSessionID: row.ClientSessionID, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) MarkClientPapercodeRevocationPropagated(ctx context.Context, clientSessionID string) error {
	return r.db.Queries().MarkClientPapercodeRevocationPropagated(ctx, sql.NullString{String: clientSessionID, Valid: true})
}

func (r *Repository) MarkUserPapercodeRevocationPropagated(ctx context.Context, userID string) error {
	return r.db.Queries().MarkUserPapercodeRevocationPropagated(ctx, userID)
}

func (r *Repository) MarkProjectPapercodeRevocationPropagated(ctx context.Context, projectID string) error {
	return r.db.Queries().MarkProjectPapercodeRevocationPropagated(ctx, projectID)
}

func (r *Repository) PendingPapercodeRevocations(ctx context.Context) ([]PapercodeSessionLink, error) {
	rows, err := r.db.Queries().ListPendingPapercodeRevocations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PapercodeSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, PapercodeSessionLink{AccessSessionID: row.ID, UserID: row.UserID, ProjectID: row.ProjectID, ClientSessionID: row.ClientSessionID, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl), Reason: fmt.Sprint(row.Reason)})
	}
	return out, nil
}

func (r *Repository) MarkAccessSessionPapercodeRevocationPropagated(ctx context.Context, accessSessionID string) error {
	return r.db.Queries().MarkAccessSessionPapercodeRevocationPropagated(ctx, accessSessionID)
}

func (r *Repository) CreatePapercodeRevocationOutbox(ctx context.Context, input CredentialRevocationInput) (string, error) {
	id := newID("pro")
	err := r.db.Queries().CreatePapercodeRevocationOutbox(ctx, dbsqlc.CreatePapercodeRevocationOutboxParams{
		ID: id, UserID: input.UserID, ProjectID: input.ProjectID, ClientSessionID: input.ClientSessionID,
		HttpBaseUrl: input.HTTPBaseURL, SessionIds: input.SessionIDs, Reason: input.Reason,
	})
	return id, err
}

func (r *Repository) PendingPapercodeRevocationOutbox(ctx context.Context) ([]PapercodeRevocationOutboxItem, error) {
	rows, err := r.db.Queries().ListPendingPapercodeRevocationOutbox(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PapercodeRevocationOutboxItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, PapercodeRevocationOutboxItem{ID: row.ID, Revocation: CredentialRevocationInput{
			UserID: row.UserID, ProjectID: row.ProjectID, EnvironmentID: row.ProjectID,
			ClientSessionID: row.ClientSessionID, HTTPBaseURL: row.HttpBaseUrl,
			SessionIDs: row.SessionIds, Reason: row.Reason,
		}})
	}
	return out, nil
}

func (r *Repository) MarkPapercodeRevocationOutboxPropagated(ctx context.Context, id string) error {
	return r.db.Queries().MarkPapercodeRevocationOutboxPropagated(ctx, id)
}

func (r *Repository) UpsertAgentunnelCleanupOutbox(ctx context.Context, projectID, action, reason string) error {
	return r.db.Queries().UpsertAgentunnelCleanupOutbox(ctx, dbsqlc.UpsertAgentunnelCleanupOutboxParams{
		ID: newID("aco"), ProjectID: projectID, Action: action, Reason: reason,
	})
}

func (r *Repository) PendingAgentunnelCleanupOutbox(ctx context.Context) ([]AgentunnelCleanupOutboxItem, error) {
	rows, err := r.db.Queries().ListPendingAgentunnelCleanupOutbox(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AgentunnelCleanupOutboxItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, AgentunnelCleanupOutboxItem{ProjectID: row.ProjectID, Action: row.Action, Reason: row.Reason})
	}
	return out, nil
}

func (r *Repository) MarkAgentunnelCleanupOutboxPropagated(ctx context.Context, projectID string) error {
	return r.db.Queries().MarkAgentunnelCleanupOutboxPropagated(ctx, projectID)
}

func revocationReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "revoked"
	}
	return reason
}

func (r *Repository) RecordConnectionEvent(ctx context.Context, userID, projectID, accessSessionID, result, reason string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return r.db.Queries().RecordConnectionEvent(ctx, dbsqlc.RecordConnectionEventParams{ID: newID("cev"), UserID: userID, ProjectID: projectID, AccessSessionID: accessSessionID, Result: result, FailureReason: reason, Metadata: b})
}

func (r *Repository) RecordActivity(ctx context.Context, projectID, source string, metadata map[string]any) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("activity source is required")
	}
	if !validActivitySource(source) {
		return fmt.Errorf("activity source %q is not accepted", source)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return r.db.Queries().UpsertProjectActivity(ctx, dbsqlc.UpsertProjectActivityParams{ProjectID: projectID, Source: source, Metadata: b})
}

func validActivitySource(source string) bool {
	switch source {
	case "connect_session", "agentunnel_connection", "papercode_activity", "cli_activity", "vm_heartbeat":
		return true
	default:
		return false
	}
}

func newID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
