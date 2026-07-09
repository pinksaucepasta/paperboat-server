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
	"hash/fnv"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

const defaultAccessTTL = 5 * time.Minute
const providerCodeRemotePortInUse = "REMOTE_PORT_IN_USE"
const providerCodeTCPTunnelsDisabled = "TCP_TUNNELS_DISABLED"
const providerCodeSubdomainInUse = "SUBDOMAIN_IN_USE"

var (
	ErrNotFound                    = projects.ErrNotFound
	ErrDeleted                     = projects.ErrDeleted
	ErrInvalidState                = projects.ErrInvalidState
	ErrInsufficientCredit          = projects.ErrInsufficientCredits
	ErrTunnelUnavailable           = errors.New("agentunnel resource is unavailable")
	ErrProvider                    = errors.New("agentunnel provider error")
	ErrCredentialIssuerUnavailable = errors.New("papercode credential issuer is unavailable")
	ErrGitHubRequired              = errors.New("github config is not ready")
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
	Status(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error)
	CleanupProjectResources(ctx context.Context, resource ResourceDescriptor, action, reason string) error
}

type ProjectRef struct {
	ID   string
	Name string
}

type ResourceDescriptor struct {
	TunnelID         string         `json:"tunnel_id"`
	ClientID         string         `json:"client_id,omitempty"`
	ResourceID       string         `json:"resource_id,omitempty"`
	HTTPBaseURL      string         `json:"http_base_url,omitempty"`
	WebSocketBaseURL string         `json:"websocket_base_url,omitempty"`
	SSHHost          string         `json:"ssh_host,omitempty"`
	SSHPort          int            `json:"ssh_port,omitempty"`
	MachineToken     string         `json:"-"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type TunnelStatus struct {
	Ready            bool   `json:"ready"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	SSHHost          string `json:"ssh_host,omitempty"`
	SSHPort          int    `json:"ssh_port,omitempty"`
	HTTPBaseURL      string `json:"http_base_url,omitempty"`
	WebSocketBaseURL string `json:"websocket_base_url,omitempty"`
}

type CredentialIssuer interface {
	CheckCLI(ctx context.Context, input CredentialInput) error
	IssueCLI(ctx context.Context, input CredentialInput) (CLICredentials, error)
}

type CredentialInput struct {
	UserID    string
	ProjectID string
	ExpiresAt time.Time
}

type CLICredentials struct {
	TerminalAuth map[string]any
	UploadAuth   map[string]any
}

type DisabledCredentialIssuer struct{}

func (DisabledCredentialIssuer) CheckCLI(context.Context, CredentialInput) error {
	return ErrCredentialIssuerUnavailable
}

func (DisabledCredentialIssuer) IssueCLI(context.Context, CredentialInput) (CLICredentials, error) {
	return CLICredentials{}, ErrCredentialIssuerUnavailable
}

type FakeCredentialIssuer struct{}

func (FakeCredentialIssuer) CheckCLI(context.Context, CredentialInput) error {
	return nil
}

func (FakeCredentialIssuer) IssueCLI(_ context.Context, input CredentialInput) (CLICredentials, error) {
	scopes := []string{"terminal:operate"}
	return CLICredentials{
		TerminalAuth: map[string]any{
			"method":     "websocket_ticket",
			"ticket":     "pct_" + input.ProjectID,
			"expires_at": input.ExpiresAt,
			"scopes":     scopes,
		},
		UploadAuth: map[string]any{
			"method":     "bearer",
			"token":      "pat_" + input.ProjectID,
			"expires_at": input.ExpiresAt,
			"scopes":     scopes,
		},
	}, nil
}

type FakeClient struct {
	BaseURL string
}

func (f FakeClient) EnsureProjectResources(_ context.Context, project ProjectRef) (ResourceDescriptor, error) {
	base := strings.TrimRight(f.BaseURL, "/")
	if base == "" {
		base = "https://agentunnel.local"
	}
	host := "ssh.agentunnel.local"
	if u, err := url.Parse(base); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return ResourceDescriptor{
		TunnelID:         "tun_" + project.ID,
		ClientID:         "cli_" + project.ID,
		ResourceID:       "res_" + project.ID,
		HTTPBaseURL:      base + "/projects/" + project.ID,
		WebSocketBaseURL: strings.Replace(base, "https://", "wss://", 1) + "/projects/" + project.ID,
		SSHHost:          host,
		SSHPort:          22,
		MachineToken:     "fake-agentunnel-token-" + project.ID,
		Metadata: map[string]any{
			"provider":       "fake",
			"resource_kind":  "http_tunnel",
			"preview_url":    base + "/projects/" + project.ID,
			"local_url":      "http://127.0.0.1:4099",
			"tcp_tunnel_id":  "res_" + project.ID,
			"machine_secret": "external",
		},
	}, nil
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
	SSHLocalHost         string
	SSHLocalPort         int
	SSHRemotePortStart   int
	SSHRemotePortEnd     int
	AccessPolicyID       string
	HTTPClient           *http.Client
}

func (c HTTPClient) EnsureProjectResources(ctx context.Context, project ProjectRef) (ResourceDescriptor, error) {
	clientID, machineToken, err := c.ensureClient(ctx, project)
	if err != nil {
		return ResourceDescriptor{}, err
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
	expires := c.RouteExpiresIn
	if expires <= 0 {
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
			"expires_in": expires.String(),
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
	sshResource, err := c.ensureSSHTunnel(ctx, project, clientID)
	if err != nil && !isTCPTunnelsDisabled(err) {
		return fail(err)
	}
	resource := ResourceDescriptor{
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
	if err != nil {
		resource.Metadata["tcp_status"] = "disabled"
		resource.Metadata["tcp_error_code"] = providerCodeTCPTunnelsDisabled
		return resource, nil
	}
	resource.SSHHost = sshResource.SSHHost
	resource.SSHPort = sshResource.SSHPort
	resource.Metadata["tcp_tunnel_id"] = sshResource.TunnelID
	resource.Metadata["tcp_status"] = sshResource.Metadata["tcp_status"]
	resource.Metadata["tcp_lifecycle"] = sshResource.Metadata["tcp_lifecycle"]
	resource.Metadata["tcp_forwarding_status"] = sshResource.Metadata["tcp_forwarding_status"]
	return resource, nil
}

func (c HTTPClient) Status(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	if strings.TrimSpace(resource.TunnelID) == "" {
		return TunnelStatus{}, ErrTunnelUnavailable
	}
	if resourceKind(resource) == "http_tunnel" {
		httpStatus, err := c.httpTunnelStatus(ctx, resource)
		if err != nil {
			return TunnelStatus{}, err
		}
		tcpTunnelID, _ := resource.Metadata["tcp_tunnel_id"].(string)
		if strings.TrimSpace(tcpTunnelID) == "" {
			httpStatus.Ready = false
			httpStatus.Reason = firstNonEmpty(httpStatus.Reason, "TCP_TUNNEL_MISSING")
			return httpStatus, nil
		}
		tcpResource := resource
		tcpResource.TunnelID = tcpTunnelID
		tcpStatus, err := c.tcpTunnelStatus(ctx, tcpResource)
		if err != nil {
			return TunnelStatus{}, err
		}
		combined := httpStatus
		combined.SSHHost = tcpStatus.SSHHost
		combined.SSHPort = tcpStatus.SSHPort
		combined.Ready = httpStatus.Ready && tcpStatus.Ready
		if !httpStatus.Ready {
			return combined, nil
		}
		combined.Status = firstNonEmpty(tcpStatus.Status, httpStatus.Status)
		combined.Reason = tcpStatus.Reason
		if !tcpStatus.Ready && combined.Reason == "" {
			combined.Reason = "TCP_TUNNEL_NOT_READY"
		}
		return combined, nil
	}
	return c.tcpTunnelStatus(ctx, resource)
}

func (c HTTPClient) httpTunnelStatus(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	var payload struct {
		TunnelID   string     `json:"tunnel_id"`
		PreviewURL string     `json:"preview_url"`
		Status     string     `json:"status"`
		ExpiresAt  *time.Time `json:"expires_at"`
	}
	if err := c.get(ctx, "/api/http-tunnels/"+url.PathEscape(resource.TunnelID), &payload); err != nil {
		return TunnelStatus{}, err
	}
	httpURL, wsURL := routeURLs(firstNonEmpty(payload.PreviewURL, resource.HTTPBaseURL))
	status := firstNonEmpty(payload.Status, "unknown")
	ready := status == "active" && httpURL != "" && wsURL != ""
	reason := ""
	if !ready {
		reason = "HTTP_ROUTE_NOT_ACTIVE"
	}
	return TunnelStatus{
		Ready:            ready,
		Status:           status,
		Reason:           reason,
		HTTPBaseURL:      httpURL,
		WebSocketBaseURL: wsURL,
	}, nil
}

func (c HTTPClient) tcpTunnelStatus(ctx context.Context, resource ResourceDescriptor) (TunnelStatus, error) {
	var payload struct {
		Type             string `json:"type"`
		Protocol         string `json:"protocol"`
		Host             string `json:"host"`
		Port             int    `json:"port"`
		TunnelID         string `json:"tunnel_id"`
		Status           string `json:"status"`
		Lifecycle        string `json:"lifecycle"`
		ForwardingStatus string `json:"forwarding_status"`
		CanConnect       bool   `json:"can_connect"`
		ReasonCode       string `json:"reason_code"`
		Message          string `json:"message"`
		Hint             string `json:"hint"`
	}
	if err := c.get(ctx, "/api/tcp-tunnels/"+url.PathEscape(resource.TunnelID)+"/connect-info", &payload); err != nil {
		return TunnelStatus{}, err
	}
	reason := payload.ReasonCode
	if reason == "" {
		reason = payload.Message
	}
	status := payload.ForwardingStatus
	if status == "" {
		status = payload.Status
	}
	return TunnelStatus{
		Ready:            payload.CanConnect,
		Status:           status,
		Reason:           reason,
		SSHHost:          firstNonEmpty(payload.Host, resource.SSHHost),
		SSHPort:          firstNonZero(payload.Port, resource.SSHPort),
		HTTPBaseURL:      resource.HTTPBaseURL,
		WebSocketBaseURL: resource.WebSocketBaseURL,
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

func (c HTTPClient) ensureSSHTunnel(ctx context.Context, project ProjectRef, clientID string) (ResourceDescriptor, error) {
	localHost := firstNonEmpty(c.SSHLocalHost, "127.0.0.1")
	localPort := firstNonZero(c.SSHLocalPort, 22)
	remotePorts := c.remotePortsForProject(project.ID)
	if len(remotePorts) == 0 {
		return ResourceDescriptor{}, ErrTunnelUnavailable
	}
	var lastErr error
	for _, remotePort := range remotePorts {
		var payload struct {
			TunnelID         string `json:"tunnel_id"`
			RemotePort       int    `json:"remote_port"`
			LocalPort        int    `json:"local_port"`
			Status           string `json:"status"`
			Lifecycle        string `json:"lifecycle"`
			ForwardingStatus string `json:"forwarding_status"`
		}
		body := map[string]any{
			"client_id":   clientID,
			"local_host":  localHost,
			"local_port":  localPort,
			"remote_port": remotePort,
			"expires_in":  "never",
		}
		if strings.TrimSpace(c.AccessPolicyID) != "" {
			body["access_policy_id"] = c.AccessPolicyID
		}
		if err := c.post(ctx, "/api/tcp-tunnels", body, &payload); err != nil {
			lastErr = err
			if isRemotePortInUse(err) {
				continue
			}
			return ResourceDescriptor{}, err
		}
		if payload.TunnelID == "" {
			lastErr = ErrTunnelUnavailable
			return ResourceDescriptor{}, lastErr
		}
		return ResourceDescriptor{
			TunnelID: payload.TunnelID,
			ClientID: clientID,
			SSHPort:  firstNonZero(payload.RemotePort, remotePort),
			Metadata: map[string]any{
				"tcp_status":            payload.Status,
				"tcp_lifecycle":         payload.Lifecycle,
				"tcp_forwarding_status": payload.ForwardingStatus,
			},
		}, nil
	}
	if lastErr != nil {
		return ResourceDescriptor{}, lastErr
	}
	return ResourceDescriptor{}, ErrTunnelUnavailable
}

func isRemotePortInUse(err error) bool {
	var providerErr providerError
	return errors.As(err, &providerErr) && providerErr.code == providerCodeRemotePortInUse
}

func isTCPTunnelsDisabled(err error) bool {
	var providerErr providerError
	return errors.As(err, &providerErr) && providerErr.code == providerCodeTCPTunnelsDisabled
}

func isSubdomainInUse(err error) bool {
	var providerErr providerError
	return errors.As(err, &providerErr) && providerErr.code == providerCodeSubdomainInUse
}

func (c HTTPClient) remotePortsForProject(projectID string) []int {
	start := c.SSHRemotePortStart
	end := c.SSHRemotePortEnd
	if start <= 0 || end < start || end > 65535 {
		return nil
	}
	size := end - start + 1
	h := fnv.New32a()
	_, _ = h.Write([]byte(projectID))
	offset := int(h.Sum32() % uint32(size))
	ports := make([]int, 0, size)
	for i := 0; i < size; i++ {
		ports = append(ports, start+((offset+i)%size))
	}
	return ports
}

type Service struct {
	repo                     *Repository
	projects                 *projects.Service
	client                   Client
	credentials              CredentialIssuer
	audit                    *audit.Writer
	minimumStartCreditWindow time.Duration
	ttl                      time.Duration
	connectReadyTimeout      time.Duration
	connectPollInterval      time.Duration
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
		repo:                     NewRepository(store, cfg.Secrets.EncryptionKey),
		projects:                 projectService,
		client:                   client,
		credentials:              issuer,
		audit:                    auditWriter,
		minimumStartCreditWindow: cfg.Metering.MinimumStartCreditWindow,
		ttl:                      defaultAccessTTL,
		connectReadyTimeout:      cfg.Providers.Agentunnel.ConnectReadyTimeout,
		connectPollInterval:      cfg.Providers.Agentunnel.ConnectPollInterval,
	}
}

type ConnectKind string

const (
	ConnectGeneric   ConnectKind = "generic"
	ConnectPapercode ConnectKind = "papercode"
	ConnectCLI       ConnectKind = "cli"
)

type ConnectInput struct {
	UserID    string
	ProjectID string
	Kind      ConnectKind
}

type ConnectResponse struct {
	ProjectID       string         `json:"project_id"`
	ProjectState    string         `json:"project_state"`
	Connectable     bool           `json:"connectable"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Descriptors     []any          `json:"descriptors,omitempty"`
	Environment     map[string]any `json:"environment,omitempty"`
	AccessEndpoint  map[string]any `json:"access_endpoint,omitempty"`
	Terminal        map[string]any `json:"terminal,omitempty"`
	PapercodeUpload map[string]any `json:"upload,omitempty"`
	Status          string         `json:"status,omitempty"`
	Reason          string         `json:"reason,omitempty"`
}

func (s *Service) Connect(ctx context.Context, input ConnectInput) (ConnectResponse, error) {
	if input.Kind == "" {
		input.Kind = ConnectGeneric
	}
	project, err := s.projects.Get(ctx, input.UserID, input.ProjectID)
	if err != nil {
		_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "project_not_found", nil)
		return ConnectResponse{}, err
	}
	if terminalProjectState(project.State) {
		_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "invalid_project_state", map[string]any{"project_state": project.State})
		if project.State == "deleted" || project.State == "deleting" {
			return ConnectResponse{}, ErrDeleted
		}
		return ConnectResponse{}, ErrInvalidState
	}
	if err := s.repo.EnsureConnectCredits(ctx, input.UserID, input.ProjectID, s.minimumStartCreditWindow); err != nil {
		_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "credits_exhausted", nil)
		return ConnectResponse{}, err
	}
	expires := time.Now().UTC().Add(s.ttl)
	var credentials CLICredentials
	if input.Kind == ConnectCLI {
		if err := s.repo.EnsureGitHubConfigReady(ctx, input.UserID); err != nil {
			_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "github_config_not_ready", nil)
			return ConnectResponse{}, err
		}
		credentialInput := CredentialInput{UserID: input.UserID, ProjectID: input.ProjectID, ExpiresAt: expires}
		if err := s.credentials.CheckCLI(ctx, credentialInput); err != nil {
			_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "credential_issuer_unavailable", nil)
			return ConnectResponse{}, fmt.Errorf("%w: %v", ErrCredentialIssuerUnavailable, err)
		}
		credentials, err = s.credentials.IssueCLI(ctx, credentialInput)
		if err != nil {
			_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "credential_issuer_unavailable", nil)
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
	resumeQueued := false
	if project.State == "stopped" || project.State == "ready" {
		project, err = s.projects.Start(ctx, input.UserID, input.ProjectID)
		if err != nil {
			_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "start_failed", map[string]any{"error": err.Error()})
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
		response := ConnectResponse{ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires, Status: status.Status, Reason: status.Reason}
		if resumeQueued {
			response.Status = firstNonEmpty(status.Status, "starting")
			response.Reason = firstNonEmpty(status.Reason, "machine_start_queued")
		}
		_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, "", "denied", "tunnel_not_ready", map[string]any{"status": status.Status, "reason": status.Reason})
		return response, nil
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "agentunnel_connection", map[string]any{"kind": input.Kind, "status": status.Status})
	response := buildResponse(input.Kind, project, resource, expires, credentials)
	session, err := s.repo.CreateAccessSession(ctx, input.UserID, input.ProjectID, string(input.Kind), response, expires)
	if err != nil {
		return ConnectResponse{}, err
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "connect_session", map[string]any{"access_session_id": session.ID, "kind": input.Kind})
	_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, session.ID, "approved", "", map[string]any{"kind": input.Kind, "project_state": project.State})
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.connect_approved", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.connect_approved:" + session.ID, Metadata: map[string]any{"kind": input.Kind}})
	return response, nil
}

func (s *Service) denyProviderFailure(ctx context.Context, userID, projectID string, err error) error {
	reason := "tunnel_unavailable"
	out := ErrTunnelUnavailable
	if errors.Is(err, ErrProvider) {
		reason = "provider_error"
		out = ErrProvider
	}
	_ = s.repo.RecordConnectionEvent(ctx, userID, projectID, "", "denied", reason, nil)
	return out
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
	return s.repo.UpsertResource(ctx, project.ID, reconciled)
}

func staleHTTPStatus(resource ResourceDescriptor, status TunnelStatus) bool {
	if resourceKind(resource) != "http_tunnel" {
		return false
	}
	switch status.Status {
	case "closed", "expired":
		return true
	default:
		return status.HTTPBaseURL == "" || status.WebSocketBaseURL == ""
	}
}

func (s *Service) Status(ctx context.Context, userID, projectID string) (ConnectResponse, error) {
	project, err := s.projects.Get(ctx, userID, projectID)
	if err != nil {
		return ConnectResponse{}, err
	}
	resource, ok, err := s.repo.Resource(ctx, projectID)
	if err != nil {
		return ConnectResponse{}, err
	}
	response := ConnectResponse{ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: time.Now().UTC().Add(s.ttl)}
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
	response.Terminal = terminalStatusDescriptor(status)
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
	return s.repo.RevokeUserAccessSessions(ctx, userID, reason)
}

func (s *Service) RevokeProjectSessions(ctx context.Context, projectID, reason string) error {
	if resource, ok, err := s.repo.Resource(ctx, projectID); err != nil {
		return err
	} else if ok {
		action := "suspend"
		if reason == "project_delete" {
			action = "close"
		}
		if err := s.client.CleanupProjectResources(ctx, resource, action, reason); err != nil {
			return err
		}
	}
	return s.repo.RevokeProjectAccessSessions(ctx, projectID, reason)
}

func terminalProjectState(state string) bool {
	switch state {
	case "deleted", "deleting", "failed", "suspended", "creating", "provisioning_storage", "provisioning_machine":
		return true
	default:
		return false
	}
}

func buildResponse(kind ConnectKind, project projects.Project, resource ResourceDescriptor, expires time.Time, credentials CLICredentials) ConnectResponse {
	base := ConnectResponse{ProjectID: project.ID, ProjectState: project.State, Connectable: true, ExpiresAt: expires}
	switch kind {
	case ConnectPapercode:
		base.Environment = map[string]any{
			"environment_id": project.ID,
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
		base.Terminal = map[string]any{
			"kind":               "papercode_websocket",
			"http_base_url":      resource.HTTPBaseURL,
			"websocket_base_url": resource.WebSocketBaseURL,
			"thread_id":          "paperboat-cli",
			"terminal_id":        "term-1",
			"cwd":                "/workspace",
		}
		if credentials.TerminalAuth != nil {
			base.Terminal["auth"] = credentials.TerminalAuth
		}
		base.Environment = map[string]any{
			"environment_id": project.ID,
			"display_name":   project.Name,
			"project_root":   "/workspace",
		}
		base.PapercodeUpload = map[string]any{
			"kind":               "papercode_file_upload",
			"http_base_url":      resource.HTTPBaseURL,
			"max_bytes":          10485760,
			"allowed_mime_types": []string{"image/png", "image/jpeg", "image/webp"},
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

func applyStatusResource(resource ResourceDescriptor, status TunnelStatus) ResourceDescriptor {
	resource.SSHHost = firstNonEmpty(status.SSHHost, resource.SSHHost)
	resource.SSHPort = firstNonZero(status.SSHPort, resource.SSHPort)
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

func terminalStatusDescriptor(status TunnelStatus) map[string]any {
	if status.HTTPBaseURL == "" && status.WebSocketBaseURL == "" {
		return nil
	}
	return map[string]any{
		"kind":               "papercode_websocket",
		"http_base_url":      status.HTTPBaseURL,
		"websocket_base_url": status.WebSocketBaseURL,
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

type AccessSession struct {
	ID string
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
	var enough bool
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT coalesce(ca.balance, 0)::numeric >= ((($3::numeric / 3600.0) * mtv.credit_weight)::numeric(18,6))
FROM paperboat.projects p
JOIN paperboat.project_runtime_configs prc ON prc.project_id = p.id
JOIN paperboat.machine_type_versions mtv ON mtv.id = prc.applied_machine_type_version_id
LEFT JOIN paperboat.credit_accounts ca ON ca.user_id = p.user_id
WHERE p.id = $1 AND p.user_id = $2`, projectID, userID, int(window.Seconds())).Scan(&enough)
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
	var ready bool
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1
	FROM paperboat.github_oauth_tokens t
	JOIN paperboat.github_config_repositories cr ON cr.user_id = t.user_id
	WHERE t.user_id = $1
	  AND t.revoked_at IS NULL
	  AND (t.expires_at IS NULL OR t.expires_at > now())
	  AND cr.provisioned_at IS NOT NULL
)`, userID).Scan(&ready)
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
	resource.Metadata["ssh_host"] = resource.SSHHost
	resource.Metadata["ssh_port"] = resource.SSHPort
	metadata, err := json.Marshal(resource.Metadata)
	if err != nil {
		return ResourceDescriptor{}, err
	}
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO agentunnel_resources (id, project_id, tunnel_id, client_id, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (project_id) DO UPDATE
SET tunnel_id = EXCLUDED.tunnel_id,
    client_id = EXCLUDED.client_id,
    resource_id = EXCLUDED.resource_id,
    metadata = EXCLUDED.metadata,
    version = agentunnel_resources.version + 1,
    updated_at = now()`, newID("agr"), projectID, resource.TunnelID, resource.ClientID, resource.ResourceID, string(metadata))
		if err != nil {
			return err
		}
		previewURL, _ := resource.Metadata["preview_url"].(string)
		localURL, _ := resource.Metadata["local_url"].(string)
		if strings.TrimSpace(previewURL) == "" || strings.TrimSpace(localURL) == "" {
			return nil
		}
		_, err = tx.Exec(ctx, `
INSERT INTO preview_url_records (id, project_id, preview_key, target_url, public_url, state)
VALUES ($1, $2, 'papercode', $3, $4, 'active')
ON CONFLICT (project_id, preview_key) DO UPDATE
SET target_url = EXCLUDED.target_url,
    public_url = EXCLUDED.public_url,
    state = 'active',
    version = preview_url_records.version + 1,
    updated_at = now()`, newID("pvr"), projectID, localURL, previewURL)
		return err
	})
	return resource, err
}

func (r *Repository) Resource(ctx context.Context, projectID string) (ResourceDescriptor, bool, error) {
	var resource ResourceDescriptor
	var metadata []byte
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT tunnel_id, client_id, resource_id, metadata
FROM paperboat.agentunnel_resources
WHERE project_id = $1`, projectID).Scan(&resource.TunnelID, &resource.ClientID, &resource.ResourceID, &metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return ResourceDescriptor{}, false, nil
	}
	if err != nil {
		return ResourceDescriptor{}, false, err
	}
	_ = json.Unmarshal(metadata, &resource.Metadata)
	if resource.Metadata == nil {
		resource.Metadata = map[string]any{}
	}
	resource.HTTPBaseURL, _ = resource.Metadata["http_base_url"].(string)
	resource.WebSocketBaseURL, _ = resource.Metadata["websocket_base_url"].(string)
	resource.SSHHost, _ = resource.Metadata["ssh_host"].(string)
	if port, ok := resource.Metadata["ssh_port"].(float64); ok {
		resource.SSHPort = int(port)
	}
	return resource, true, nil
}

func (r *Repository) LatestStopReason(ctx context.Context, projectID string) (string, bool, error) {
	var eventType string
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT event_type
FROM paperboat.project_events
WHERE project_id = $1
  AND event_type LIKE 'project.stop_queued.%'
ORDER BY created_at DESC
LIMIT 1`, projectID).Scan(&eventType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimPrefix(eventType, "project.stop_queued."), true, nil
}

func (r *Repository) CreateAccessSession(ctx context.Context, userID, projectID, sessionType string, descriptor ConnectResponse, expiresAt time.Time) (AccessSession, error) {
	id := newID("acs")
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		return AccessSession{}, err
	}
	key := "access.session:" + id
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO access_sessions (id, user_id, project_id, session_type, state, descriptor, expires_at, idempotency_key)
VALUES ($1, $2, $3, $4, 'active', $5::jsonb, $6, $7)`, id, userID, projectID, sessionType, string(descriptorBytes), expiresAt, key)
		return err
	})
	return AccessSession{ID: id}, err
}

func (r *Repository) RevokeUserAccessSessions(ctx context.Context, userID, reason string) error {
	reason = revocationReason(reason)
	_, err := r.db.SQL().ExecContext(ctx, `
UPDATE paperboat.access_sessions
SET state = 'revoked',
    revoked_at = now(),
    updated_at = now(),
    version = version + 1,
    descriptor = jsonb_set(descriptor, '{revocation_reason}', to_jsonb($2::text), true)
WHERE state = 'active'
  AND revoked_at IS NULL
  AND user_id = $1`, userID, reason)
	return err
}

func (r *Repository) RevokeProjectAccessSessions(ctx context.Context, projectID, reason string) error {
	reason = revocationReason(reason)
	_, err := r.db.SQL().ExecContext(ctx, `
UPDATE paperboat.access_sessions
SET state = 'revoked',
    revoked_at = now(),
    updated_at = now(),
    version = version + 1,
    descriptor = jsonb_set(descriptor, '{revocation_reason}', to_jsonb($2::text), true)
WHERE state = 'active'
  AND revoked_at IS NULL
  AND project_id = $1`, projectID, reason)
	return err
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
	if strings.TrimSpace(accessSessionID) == "" {
		_, err = r.db.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connection_events (id, user_id, project_id, result, failure_reason, metadata)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6::jsonb)`, newID("cev"), userID, projectID, result, reason, string(b))
		return err
	}
	_, err = r.db.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connection_events (id, user_id, project_id, access_session_id, result, failure_reason, metadata)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7::jsonb)`, newID("cev"), userID, projectID, accessSessionID, result, reason, string(b))
	return err
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
	_, err = r.db.SQL().ExecContext(ctx, `
INSERT INTO paperboat.project_activity_markers (project_id, last_activity_at, source, metadata)
VALUES ($1, now(), $2, $3::jsonb)
ON CONFLICT (project_id) DO UPDATE
SET last_activity_at = greatest(project_activity_markers.last_activity_at, EXCLUDED.last_activity_at),
    source = EXCLUDED.source,
    metadata = EXCLUDED.metadata,
    updated_at = now()`, projectID, source, string(b))
	return err
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
