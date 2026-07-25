package access

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

const defaultAccessTTL = 5 * time.Minute

var (
	ErrNotFound                        = projects.ErrNotFound
	ErrDeleted                         = projects.ErrDeleted
	ErrInvalidState                    = projects.ErrInvalidState
	ErrMachineFailed                   = errors.New("project machine failed")
	ErrInsufficientCredit              = projects.ErrInsufficientCredits
	ErrTunnelUnavailable               = errors.New("access route is unavailable")
	ErrProvider                        = errors.New("access provider error")
	ErrCredentialIssuerUnavailable     = errors.New("connection credential issuer is unavailable")
	ErrGitHubRequired                  = errors.New("github config is not ready")
	ErrTerminalSessionNotFound         = errors.New("terminal session not found")
	ErrTerminalSessionOperationPending = errors.New("terminal session operation pending")
	ErrTerminalRuntimeUnavailable      = errors.New("terminal runtime is unavailable")
)

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
	UserID             string
	ProjectID          string
	EnvironmentID      string
	CLIClientSessionID string
	HTTPBaseURL        string
	SessionIDs         []string
	Reason             string
}

type CredentialInput struct {
	UserID             string
	ProjectID          string
	EnvironmentID      string
	CLIClientSessionID string
	HTTPBaseURL        string
	ExpiresAt          time.Time
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
		TerminalSessionID: "fake-terminal-" + input.ProjectID + "-" + input.CLIClientSessionID,
		FileSessionID:     "fake-file-" + input.ProjectID + "-" + input.CLIClientSessionID,
	}, nil
}

func (FakeCredentialIssuer) RevokeCLI(context.Context, CredentialRevocationInput) error { return nil }

type FakeClient struct {
	BaseURL string
}

func (f FakeClient) EnsureProjectResources(_ context.Context, project ProjectRef) (ResourceDescriptor, error) {
	base := strings.TrimRight(f.BaseURL, "/")
	if base == "" {
		base = "https://access.local"
	}
	return ResourceDescriptor{
		ServerURL:        base,
		TunnelID:         "tun_" + project.ID,
		ClientID:         "cli_" + project.ID,
		ResourceID:       "res_" + project.ID,
		HTTPBaseURL:      base + "/projects/" + project.ID,
		WebSocketBaseURL: strings.Replace(base, "https://", "wss://", 1) + "/projects/" + project.ID,
		MachineToken:     "fake-provider_route-token-" + project.ID,
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
	controlSigner            *mint.Provider
	now                      func() time.Time
}

// HelperHTTPBaseURL returns the canonical provider_route route for an already
// provisioned project. It never starts a machine or creates a resource.
func (s *Service) HelperHTTPBaseURL(ctx context.Context, projectID string) (string, error) {
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
// after Helper is healthy and before a descriptor can be issued.
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
		client = DisabledClient{}
		if cfg.Providers.FakeMode {
			client = FakeClient{}
		}
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
		connectReadyTimeout:      cfg.Access.ConnectReadyTimeout,
		connectPollInterval:      cfg.Access.ConnectPollInterval,
		uploadMaxBytes:           cfg.Access.UploadMaxBytes,
		uploadAllowedMIMEs:       slices.Clone(cfg.Access.UploadAllowedMIMEs),
		uploadRetentionSeconds:   int64(cfg.Access.UploadRetention / time.Second),
		now:                      time.Now,
	}
}

// ConfigureCanonicalAccess enables direct hosted helper descriptors.
func (s *Service) ConfigureCanonicalAccess(signer *mint.Provider) {
	s.controlSigner = signer
}

type DescriptorKind string

const (
	DescriptorGeneric   DescriptorKind = "generic"
	DescriptorForHelper DescriptorKind = "helper"
	DescriptorForCLI    DescriptorKind = "cli"
)

type DescriptorRequest struct {
	UserID             string
	ProjectID          string
	Kind               DescriptorKind
	CLIClientSessionID string
	TerminalSessionID  string
}

type ConnectionDescriptor struct {
	Schema            string         `json:"schema,omitempty"`
	Capabilities      []string       `json:"capabilities,omitempty"`
	Issuer            string         `json:"issuer,omitempty"`
	ProjectID         string         `json:"project_id"`
	ProjectState      string         `json:"project_state"`
	Connectable       bool           `json:"connectable"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Descriptors       []any          `json:"descriptors,omitempty"`
	Environment       map[string]any `json:"environment,omitempty"`
	AccessEndpoint    map[string]any `json:"access_endpoint,omitempty"`
	Terminal          map[string]any `json:"terminal,omitempty"`
	HelperUpload      map[string]any `json:"upload,omitempty"`
	Status            string         `json:"status,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	RetryAfterSeconds int            `json:"retry_after_seconds"`
}

func (r ConnectionDescriptor) MarshalJSON() ([]byte, error) {
	if r.Schema != accessdescriptor.SchemaV1 {
		return nil, errors.New("connection descriptor schema is required")
	}
	descriptor, err := r.canonicalDescriptor()
	if err != nil {
		return nil, err
	}
	return json.Marshal(descriptor)
}

func (r ConnectionDescriptor) canonicalDescriptor() (accessdescriptor.Descriptor, error) {
	environment, err := canonicalEnvironment(r.Environment)
	if err != nil {
		return accessdescriptor.Descriptor{}, err
	}
	out := accessdescriptor.Descriptor{
		Schema: r.Schema, Issuer: r.Issuer, Connectable: r.Connectable, ExpiresAt: r.ExpiresAt,
		Environment: environment, Capabilities: slices.Clone(r.Capabilities), Status: r.Status,
		Reason: r.Reason, RetryAfterSeconds: r.RetryAfterSeconds,
	}
	if r.Terminal != nil && r.Terminal["auth"] != nil {
		terminal, err := decodeCanonical[accessdescriptor.Terminal](r.Terminal)
		if err != nil {
			return accessdescriptor.Descriptor{}, fmt.Errorf("canonical terminal descriptor: %w", err)
		}
		out.Terminal = &terminal
	}
	if r.HelperUpload != nil && r.HelperUpload["auth"] != nil {
		upload, err := decodeCanonical[accessdescriptor.Upload](r.HelperUpload)
		if err != nil {
			return accessdescriptor.Descriptor{}, fmt.Errorf("canonical upload descriptor: %w", err)
		}
		out.Upload = &upload
	}
	return out, nil
}

func canonicalEnvironment(value map[string]any) (accessdescriptor.Environment, error) {
	out := accessdescriptor.Environment{
		ID: stringValue(value, "id"), Kind: stringValue(value, "kind"), ResourceID: stringValue(value, "resource_id"),
		DisplayName: stringValue(value, "display_name"), State: stringValue(value, "state"), Root: stringValue(value, "root"),
	}
	if out.ID == "" || out.Kind == "" || out.ResourceID == "" || out.DisplayName == "" || out.State == "" {
		return accessdescriptor.Environment{}, errors.New("canonical environment descriptor is incomplete")
	}
	return out, nil
}

func decodeCanonical[T any](value any) (T, error) {
	var out T
	b, err := json.Marshal(value)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func connectionState(connectable bool, status, state string) string {
	if connectable || status == "ready" {
		return "ready"
	}
	switch state {
	case "deleted", "deleting":
		return "deleted"
	case "revoked", "suspended":
		return "revoked"
	case "starting", "restarting", "creating", "provisioning_storage", "provisioning_machine":
		return "starting"
	default:
		return "offline"
	}
}

func setCanonicalCLIIdentity(response *ConnectionDescriptor, project projects.Project) {
	response.Schema = accessdescriptor.SchemaV1
	response.Capabilities = []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityHerdr, accessdescriptor.CapabilityUpload, accessdescriptor.CapabilityPreview, accessdescriptor.CapabilityActivity}
	response.Environment = map[string]any{
		"id": project.ID, "kind": accessdescriptor.EnvironmentHosted, "resource_id": project.ID,
		"display_name": project.Name, "state": connectionState(response.Connectable, response.Status, project.State), "root": "/workspace",
	}
}

func (s *Service) Connect(ctx context.Context, input DescriptorRequest) (ConnectionDescriptor, error) {
	observability.ConnectAttempted()
	if input.Kind == "" {
		input.Kind = DescriptorGeneric
	}
	project, err := s.projects.Get(ctx, input.UserID, input.ProjectID)
	if err != nil {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "project_not_found", nil)
		return ConnectionDescriptor{}, err
	}
	var terminalSession dbsqlc.ProjectTerminalSession
	if input.Kind == DescriptorForCLI {
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
			return ConnectionDescriptor{}, err
		}
	}
	if terminalProjectState(project.State) {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "invalid_project_state", map[string]any{"project_state": project.State})
		if project.State == "deleted" || project.State == "deleting" {
			return ConnectionDescriptor{}, ErrDeleted
		}
		if project.State == "failed" {
			return ConnectionDescriptor{}, ErrMachineFailed
		}
		return ConnectionDescriptor{}, ErrInvalidState
	}
	if err := s.repo.EnsureConnectCredits(ctx, input.UserID, input.ProjectID, s.minimumStartCreditWindow); err != nil {
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credits_exhausted", nil)
		return ConnectionDescriptor{}, err
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	expires := now().UTC().Add(s.ttl)
	if s.controlSigner != nil && expires.After(now().UTC().Add(5*time.Minute)) {
		expires = now().UTC().Add(5 * time.Minute)
	}
	var credentials CLICredentials
	if input.Kind == DescriptorForCLI {
		if err := s.repo.EnsureGitHubConfigReady(ctx, input.UserID); err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "github_config_not_ready", nil)
			return ConnectionDescriptor{}, err
		}
		credentialInput := CredentialInput{UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID, CLIClientSessionID: input.CLIClientSessionID, ExpiresAt: expires}
		if s.controlSigner == nil {
			if err := s.credentials.CheckCLI(ctx, credentialInput); err != nil {
				s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credential_issuer_unavailable", nil)
				return ConnectionDescriptor{}, fmt.Errorf("%w: %v", ErrCredentialIssuerUnavailable, err)
			}
		}
	}
	if input.Kind == DescriptorForCLI && s.controlSigner != nil {
		return s.connectCanonicalHosted(ctx, input, project, terminalSession, expires)
	}
	resource, ok, err := s.repo.Resource(ctx, input.ProjectID)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	resource, err = s.reconcileResource(ctx, project, resource, ok)
	if err != nil {
		return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
	}
	if project.State == "stopped" && ok {
		if oldClientID, _ := resource.Metadata["superseded_client_id"].(string); strings.TrimSpace(oldClientID) != "" {
			if err := s.client.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: oldClientID}, "suspend", "machine_replaced"); err != nil {
				return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
			}
			delete(resource.Metadata, "superseded_client_id")
			resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
			if err != nil {
				return ConnectionDescriptor{}, err
			}
		}
		resource, err = s.client.ReattachProjectResources(ctx, ProjectRef{ID: project.ID, Name: project.Name}, resource)
		if err != nil {
			return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
		}
		resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
		if err != nil {
			return ConnectionDescriptor{}, err
		}
		if oldClientID, _ := resource.Metadata["superseded_client_id"].(string); strings.TrimSpace(oldClientID) != "" {
			if err := s.client.CleanupProjectResources(ctx, ResourceDescriptor{ClientID: oldClientID}, "suspend", "machine_replaced"); err != nil {
				return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
			}
			delete(resource.Metadata, "superseded_client_id")
			resource, err = s.repo.UpsertResource(ctx, project.ID, resource)
			if err != nil {
				return ConnectionDescriptor{}, err
			}
		}
	}
	resumeQueued := false
	if project.State == "stopped" || project.State == "ready" {
		project, err = s.projects.Start(ctx, input.UserID, input.ProjectID)
		if err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "start_failed", map[string]any{"project_state": project.State})
			return ConnectionDescriptor{}, err
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
			return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, reconcileErr)
		}
		resource = reconciled
		status, err = s.waitForReady(ctx, resource)
		if err != nil {
			return ConnectionDescriptor{}, s.denyProviderFailure(ctx, input.UserID, input.ProjectID, err)
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
			return ConnectionDescriptor{}, refreshErr
		}
		project = refreshedProject
		if project.State == "failed" {
			return ConnectionDescriptor{}, ErrMachineFailed
		}
		response := ConnectionDescriptor{Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires, Status: status.Status, Reason: status.Reason, RetryAfterSeconds: s.retryAfterSeconds()}
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
		if input.Kind == DescriptorForCLI {
			setCanonicalCLIIdentity(&response, project)
		}
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "tunnel_not_ready", map[string]any{
			"status": response.Status, "reason": response.Reason, "environment_id": project.ID,
			"provider_route_tunnel_id": resource.TunnelID, "provider_route_client_id": resource.ClientID,
		})
		return response, nil
	}
	healthCLIClientSessionID := input.CLIClientSessionID
	if healthCLIClientSessionID == "" {
		healthCLIClientSessionID = "paperboat-control-plane"
	}
	healthInput := CredentialInput{
		UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
		CLIClientSessionID: healthCLIClientSessionID, HTTPBaseURL: resource.HTTPBaseURL, ExpiresAt: expires,
	}
	healthErr := s.credentials.CheckCLI(ctx, healthInput)
	if checker, ok := s.credentials.(environmentHealthChecker); ok {
		healthErr = checker.CheckHealth(ctx, healthInput)
	}
	if healthErr != nil {
		response := ConnectionDescriptor{
			Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires,
			Status: "helper_starting", Reason: "helper_unhealthy", RetryAfterSeconds: s.retryAfterSeconds(),
		}
		if input.Kind == DescriptorForCLI {
			setCanonicalCLIIdentity(&response, project)
		}
		s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "helper_unhealthy", map[string]any{
			"environment_id": project.ID, "provider_route_tunnel_id": resource.TunnelID,
			"error": healthErr.Error(),
		})
		return response, nil
	}
	if s.beforeConnect != nil {
		if err := s.beforeConnect(ctx, input.UserID, input.ProjectID); err != nil {
			return ConnectionDescriptor{}, fmt.Errorf("%w: %v", ErrTerminalRuntimeUnavailable, err)
		}
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.route_ready", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.route_ready:" + newID("attempt"), Metadata: map[string]any{"environment_id": project.ID, "provider_route_tunnel_id": resource.TunnelID, "provider_route_client_id": resource.ClientID, "status": status.Status}})
	observability.RouteReady()
	if input.Kind == DescriptorForCLI {
		credentialInput := CredentialInput{
			UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
			CLIClientSessionID: input.CLIClientSessionID, HTTPBaseURL: resource.HTTPBaseURL, ExpiresAt: expires,
		}
		credentials, err = s.credentials.IssueCLI(ctx, credentialInput)
		if err != nil {
			s.recordConnectDenied(ctx, input.UserID, input.ProjectID, "credential_issuer_unavailable", nil)
			var outboxErr error
			sessionIDs := compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)
			if len(sessionIDs) > 0 {
				_, outboxErr = s.repo.CreateHelperRevocationOutbox(ctx, CredentialRevocationInput{
					UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
					CLIClientSessionID: input.CLIClientSessionID, HTTPBaseURL: resource.HTTPBaseURL,
					SessionIDs: sessionIDs, Reason: "partial_credential_issuance_failed",
				})
			}
			return ConnectionDescriptor{}, errors.Join(fmt.Errorf("%w: %v", ErrCredentialIssuerUnavailable, err), outboxErr)
		}
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.credentials_minted", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.credentials_minted:" + credentials.TerminalSessionID, Metadata: map[string]any{"environment_id": input.ProjectID, "cli_client_session_id": input.CLIClientSessionID, "terminal_session_id": credentials.TerminalSessionID, "file_session_id": credentials.FileSessionID}})
		observability.CredentialsMinted()
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "provider_route_connection", map[string]any{
		"kind": input.Kind, "status": status.Status, "environment_id": project.ID,
		"provider_route_tunnel_id": resource.TunnelID, "provider_route_client_id": resource.ClientID,
	})
	response := buildResponse(input.Kind, project, resource, expires, credentials, s.uploadMaxBytes, s.uploadAllowedMIMEs, s.uploadRetentionSeconds, terminalSession.ThreadID, terminalSession.TerminalID, terminalSession.LaunchCwd)
	if input.Kind == DescriptorForCLI {
		response.Issuer = s.issuer
	}
	session, err := s.repo.CreateAccessSession(ctx, input.UserID, input.ProjectID, input.CLIClientSessionID, credentials.TerminalSessionID, credentials.FileSessionID, string(input.Kind), response, expires)
	if err != nil {
		if input.Kind == DescriptorForCLI {
			revocation := CredentialRevocationInput{
				UserID: input.UserID, ProjectID: input.ProjectID, EnvironmentID: input.ProjectID,
				CLIClientSessionID: input.CLIClientSessionID, HTTPBaseURL: resource.HTTPBaseURL,
				SessionIDs: []string{credentials.TerminalSessionID, credentials.FileSessionID},
				Reason:     "access_session_persistence_failed",
			}
			outboxID, outboxErr := s.repo.CreateHelperRevocationOutbox(ctx, revocation)
			cleanupErr := s.credentials.RevokeCLI(ctx, revocation)
			var markErr error
			if outboxErr == nil && cleanupErr == nil {
				markErr = s.repo.MarkHelperRevocationOutboxPropagated(ctx, outboxID)
			}
			return ConnectionDescriptor{}, errors.Join(err, outboxErr, cleanupErr, markErr)
		}
		return ConnectionDescriptor{}, err
	}
	correlation := map[string]any{
		"kind": input.Kind, "project_state": project.State, "environment_id": project.ID,
		"access_session_id": session.ID, "provider_route_tunnel_id": resource.TunnelID,
		"provider_route_client_id": resource.ClientID,
	}
	_ = s.repo.RecordActivity(ctx, input.ProjectID, "connect_session", correlation)
	_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, session.ID, "approved", "", correlation)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.connect_approved", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.connect_approved:" + session.ID, Metadata: correlation})
	observability.ConnectApproved()
	return response, nil
}

func (s *Service) connectCanonicalHosted(ctx context.Context, input DescriptorRequest, project projects.Project, terminalSession dbsqlc.ProjectTerminalSession, expires time.Time) (ConnectionDescriptor, error) {
	if strings.TrimSpace(input.CLIClientSessionID) == "" {
		return ConnectionDescriptor{}, ErrCredentialIssuerUnavailable
	}
	if project.State == "stopped" || project.State == "ready" {
		started, err := s.projects.Start(ctx, input.UserID, input.ProjectID)
		if err != nil {
			return ConnectionDescriptor{}, err
		}
		project = started
	}
	response := ConnectionDescriptor{
		Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, ExpiresAt: expires,
		Status: "connector_connecting", Reason: "helper_route_not_ready", RetryAfterSeconds: s.retryAfterSeconds(),
	}
	setCanonicalCLIIdentity(&response, project)
	route, err := s.repo.db.Queries().GetActiveHelperRouteForEnvironment(ctx, project.ID)
	if errors.Is(err, sql.ErrNoRows) {
		if project.State == "starting" || project.State == "restarting" {
			response.Status, response.Reason = "machine_starting", "machine_not_running"
		}
		return response, nil
	}
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	if s.beforeConnect != nil {
		if err := s.beforeConnect(ctx, input.UserID, input.ProjectID); err != nil {
			return ConnectionDescriptor{}, fmt.Errorf("%w: %v", ErrTerminalRuntimeUnavailable, err)
		}
	}
	issuedAt := time.Now().UTC()
	if s.now != nil {
		issuedAt = s.now().UTC()
	}
	terminalJTI, uploadJTI := newID("jti_helper_terminal"), newID("jti_helper_upload")
	sign := func(class string, scopes []string, jti string) (string, error) {
		return s.controlSigner.SignCredential(mint.CredentialInput{
			Issuer: s.issuer, Audience: "paperboat-helper", Subject: input.UserID, JTI: jti,
			IssuedAt: issuedAt, ExpiresAt: expires, CredentialClass: class, Scopes: scopes,
			EnvironmentID: project.ID, UserID: input.UserID, CLIClientSessionID: input.CLIClientSessionID, SessionID: terminalSession.ID,
		})
	}
	terminalToken, err := sign("terminal_operation", []string{"terminal:operate"}, terminalJTI)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	uploadToken, err := sign("image_stage", []string{"file:stage"}, uploadJTI)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	httpBaseURL := "https://" + route.PublicHost
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	setCanonicalCLIIdentity(&response, project)
	response.Terminal = map[string]any{
		"endpoint": "wss://" + route.PublicHost + "/v1/runtime", "session_id": terminalSession.ID,
		"thread_id": terminalSession.ThreadID, "terminal_id": terminalSession.TerminalID, "cwd": terminalSession.LaunchCwd,
		"auth": map[string]any{"method": "bearer", "token": terminalToken, "expires_at": expires, "scopes": []string{"terminal:operate"}},
	}
	response.HelperUpload = map[string]any{
		"endpoint": httpBaseURL + "/v1/uploads", "max_bytes": s.uploadMaxBytes,
		"allowed_mime_types": s.uploadAllowedMIMEs, "retention_seconds": s.uploadRetentionSeconds,
		"auth": map[string]any{"method": "bearer", "token": uploadToken, "expires_at": expires, "scopes": []string{"file:stage"}},
	}
	session, err := s.repo.CreateAccessSession(ctx, input.UserID, input.ProjectID, input.CLIClientSessionID, terminalJTI, uploadJTI, string(input.Kind), response, expires)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	metadata := map[string]any{"kind": input.Kind, "environment_id": project.ID, "access_session_id": session.ID, "route_id": route.ID}
	_ = s.repo.RecordConnectionEvent(ctx, input.UserID, input.ProjectID, session.ID, "approved", "", metadata)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: input.UserID, ActorType: audit.ActorUser, EventType: "access.connect_approved", ResourceType: "project", ResourceID: input.ProjectID, IdempotencyKey: "access.connect_approved:" + session.ID, Metadata: metadata})
	observability.RouteReady()
	observability.CredentialsMinted()
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

func (s *Service) Status(ctx context.Context, userID, projectID, terminalSessionID string) (ConnectionDescriptor, error) {
	project, err := s.projects.Get(ctx, userID, projectID)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	var terminalSession dbsqlc.ProjectTerminalSession
	if terminalSessionID == "" {
		terminalSession, err = s.repo.db.Queries().GetDefaultTerminalSession(ctx, projectID)
	} else {
		terminalSession, err = s.repo.db.Queries().GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: projectID, ID: terminalSessionID})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectionDescriptor{}, ErrTerminalSessionNotFound
	}
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	pending, err := s.repo.db.Queries().TerminalSessionOperationPending(ctx, dbsqlc.TerminalSessionOperationPendingParams{ProjectID: projectID, TerminalSessionID: terminalSession.ID})
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	if pending {
		return ConnectionDescriptor{}, ErrTerminalSessionOperationPending
	}
	if s.controlSigner != nil {
		expires := time.Now().UTC().Add(s.ttl)
		if expires.After(time.Now().UTC().Add(5 * time.Minute)) {
			expires = time.Now().UTC().Add(5 * time.Minute)
		}
		response := ConnectionDescriptor{Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: expires, Status: "connector_connecting", Reason: "helper_route_not_ready", RetryAfterSeconds: s.retryAfterSeconds()}
		setCanonicalCLIIdentity(&response, project)
		_, routeErr := s.repo.db.Queries().GetActiveHelperRouteForEnvironment(ctx, projectID)
		if routeErr == nil {
			response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
		} else if !errors.Is(routeErr, sql.ErrNoRows) {
			return ConnectionDescriptor{}, routeErr
		}
		if terminalProjectState(project.State) {
			response.Connectable = false
			response.Status, response.Reason = "offline", "project_state_"+project.State
		}
		if err := s.repo.EnsureConnectCredits(ctx, userID, projectID, s.minimumStartCreditWindow); err != nil {
			response.Connectable = false
			response.Reason = "credits_exhausted"
		}
		response.Environment["state"] = connectionState(response.Connectable, response.Status, project.State)
		return response, nil
	}
	resource, ok, err := s.repo.Resource(ctx, projectID)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	response := ConnectionDescriptor{Issuer: s.issuer, ProjectID: project.ID, ProjectState: project.State, Connectable: false, ExpiresAt: time.Now().UTC().Add(s.ttl), RetryAfterSeconds: s.retryAfterSeconds()}
	setCanonicalCLIIdentity(&response, project)
	if !ok {
		response.Status = "missing"
		response.Reason = "provider_route resources have not been provisioned"
		return response, nil
	}
	status, err := s.client.Status(ctx, resource)
	if err != nil {
		response.Status = "unknown"
		response.Reason = "provider_route status is unavailable"
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
			response.Status = "helper_starting"
			response.Reason = "terminal_session_operation_pending"
			response.RetryAfterSeconds = s.retryAfterSeconds()
		}
	}
	status.HTTPBaseURL = firstNonEmpty(status.HTTPBaseURL, resource.HTTPBaseURL)
	status.WebSocketBaseURL = firstNonEmpty(status.WebSocketBaseURL, resource.WebSocketBaseURL)
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
	response.Environment["state"] = connectionState(response.Connectable, response.Status, project.State)
	return response, nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, userID, reason string) error {
	if err := s.repo.RevokeUserAccessSessions(ctx, userID, reason); err != nil {
		return err
	}
	if s.controlSigner != nil {
		s.recordRevocationPropagated(ctx, "user", userID, reason, "control_plane", map[string]any{"user_id": userID})
		return nil
	}
	rows, err := s.repo.UserHelperSessions(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.revokeHelperSessions(ctx, rows, reason); err != nil {
		return err
	}
	if err := s.repo.MarkUserHelperRevocationPropagated(ctx, userID); err != nil {
		return err
	}
	s.recordRevocationPropagated(ctx, "user", userID, reason, "helper", map[string]any{"user_id": userID})
	return nil
}

func (s *Service) RevokeClientSessions(ctx context.Context, cliClientSessionID, reason string) error {
	if err := s.repo.RevokeClientAccessSessions(ctx, cliClientSessionID, reason); err != nil {
		return err
	}
	if s.controlSigner != nil {
		s.recordRevocationPropagated(ctx, "client_session", cliClientSessionID, reason, "control_plane", map[string]any{"cli_client_session_id": cliClientSessionID})
		return nil
	}
	rows, err := s.repo.ClientHelperSessions(ctx, cliClientSessionID)
	if err != nil {
		return err
	}
	if err := s.revokeHelperSessions(ctx, rows, reason); err != nil {
		return err
	}
	if err := s.repo.MarkClientHelperRevocationPropagated(ctx, cliClientSessionID); err != nil {
		return err
	}
	s.recordRevocationPropagated(ctx, "client_session", cliClientSessionID, reason, "helper", map[string]any{"cli_client_session_id": cliClientSessionID})
	return nil
}

func (s *Service) RevokeProjectSessions(ctx context.Context, projectID, reason string) error {
	if err := s.repo.RevokeProjectAccessSessions(ctx, projectID, reason); err != nil {
		return err
	}
	if s.controlSigner != nil {
		s.recordRevocationPropagated(ctx, "project", projectID, reason, "control_plane", map[string]any{"project_id": projectID})
		return nil
	}
	var revokeErrors []error
	helperPropagated := false
	rows, err := s.repo.ProjectHelperSessions(ctx, projectID)
	if err != nil {
		revokeErrors = append(revokeErrors, fmt.Errorf("list project helper sessions: %w", err))
	} else if err := s.revokeHelperSessions(ctx, rows, reason); err != nil {
		revokeErrors = append(revokeErrors, err)
	} else {
		helperPropagated = true
	}
	if resource, ok, err := s.repo.Resource(ctx, projectID); err != nil {
		revokeErrors = append(revokeErrors, fmt.Errorf("load project tunnel resource: %w", err))
	} else if ok {
		action := "suspend"
		if reason == "project_delete" {
			action = "close"
		}
		outboxErr := s.repo.UpsertProviderRouteCleanupOutbox(ctx, projectID, action, reason)
		if outboxErr != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("persist project tunnel cleanup: %w", outboxErr))
		}
		if err := s.client.CleanupProjectResources(ctx, resource, action, reason); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("cleanup project tunnel resources: %w", err))
		} else if outboxErr == nil {
			if err := s.repo.MarkProviderRouteCleanupOutboxPropagated(ctx, projectID); err != nil {
				revokeErrors = append(revokeErrors, fmt.Errorf("mark project tunnel cleanup propagated: %w", err))
			} else {
				s.recordRevocationPropagated(ctx, "project", projectID, reason, "provider_route", map[string]any{"environment_id": projectID})
			}
		}
	}
	if helperPropagated {
		if err := s.repo.MarkProjectHelperRevocationPropagated(ctx, projectID); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("mark project helper revocation propagated: %w", err))
		}
		s.recordRevocationPropagated(ctx, "project", projectID, reason, "helper", map[string]any{"environment_id": projectID})
	}
	return errors.Join(revokeErrors...)
}

func (s *Service) RetryPendingHelperRevocations(ctx context.Context) error {
	var retryErrors []error
	rows, err := s.repo.PendingHelperRevocations(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list pending helper revocations: %w", err))
	} else {
		for _, row := range rows {
			if err := s.revokeHelperSessions(ctx, []HelperSessionLink{row}, row.Reason); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("retry access session %s: %w", row.AccessSessionID, err))
				continue
			}
			if err := s.repo.MarkAccessSessionHelperRevocationPropagated(ctx, row.AccessSessionID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark access session %s revocation propagated: %w", row.AccessSessionID, err))
			} else {
				s.recordRevocationPropagated(ctx, "access_session", row.AccessSessionID, row.Reason, "helper", map[string]any{"access_session_id": row.AccessSessionID, "project_id": row.ProjectID, "environment_id": row.ProjectID, "cli_client_session_id": row.CLIClientSessionID})
			}
		}
	}
	outbox, err := s.repo.PendingHelperRevocationOutbox(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list orphaned helper revocations: %w", err))
	} else {
		for _, item := range outbox {
			if err := s.credentials.RevokeCLI(ctx, item.Revocation); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("retry orphaned helper revocation %s: %w", item.ID, err))
				continue
			}
			if err := s.repo.MarkHelperRevocationOutboxPropagated(ctx, item.ID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark orphaned helper revocation %s propagated: %w", item.ID, err))
			} else {
				s.recordRevocationPropagated(ctx, "project", item.Revocation.ProjectID, item.Revocation.Reason, "helper", map[string]any{"environment_id": item.Revocation.EnvironmentID, "cli_client_session_id": item.Revocation.CLIClientSessionID})
			}
		}
	}
	tunnelCleanups, err := s.repo.PendingProviderRouteCleanupOutbox(ctx)
	if err != nil {
		retryErrors = append(retryErrors, fmt.Errorf("list pending provider_route cleanup: %w", err))
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
			if err := s.repo.MarkProviderRouteCleanupOutboxPropagated(ctx, cleanup.ProjectID); err != nil {
				retryErrors = append(retryErrors, fmt.Errorf("mark tunnel cleanup project %s propagated: %w", cleanup.ProjectID, err))
			} else {
				s.recordRevocationPropagated(ctx, "project", cleanup.ProjectID, cleanup.Reason, "provider_route", map[string]any{"environment_id": cleanup.ProjectID})
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

func (s *Service) revokeHelperSessions(ctx context.Context, rows []HelperSessionLink, reason string) error {
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
			CLIClientSessionID: row.CLIClientSessionID, HTTPBaseURL: row.HTTPBaseURL,
			SessionIDs: sessionIDs, Reason: reason,
		}); err != nil {
			revokeErrors = append(revokeErrors, fmt.Errorf("revoke helper sessions for project %s: %w", row.ProjectID, err))
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

func buildResponse(kind DescriptorKind, project projects.Project, resource ResourceDescriptor, expires time.Time, credentials CLICredentials, uploadMaxBytes int64, uploadAllowedMIMEs []string, uploadRetentionSeconds int64, threadID, terminalID, cwd string) ConnectionDescriptor {
	base := ConnectionDescriptor{ProjectID: project.ID, ProjectState: project.State, Connectable: true, ExpiresAt: expires, Status: "ready", Reason: "ready"}
	switch kind {
	case DescriptorForHelper:
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
			"provider":           "provider_route",
			"http_base_url":      resource.HTTPBaseURL,
			"websocket_base_url": resource.WebSocketBaseURL,
			"compatibility": map[string]bool{
				"hosted_https_web": true,
				"desktop":          true,
				"mobile":           true,
			},
			"expires_at": expires,
		}
	case DescriptorForCLI:
		setCanonicalCLIIdentity(&base, project)
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
			"endpoint":           resource.WebSocketBaseURL,
			"http_endpoint":      resource.HTTPBaseURL,
			"session_id":         threadID,
			"kind":               "paperboat_terminal_v1",
			"http_base_url":      resource.HTTPBaseURL,
			"websocket_base_url": resource.WebSocketBaseURL,
			"thread_id":          threadID,
			"terminal_id":        terminalID,
			"cwd":                cwd,
		}
		if credentials.TerminalAuth != nil {
			base.Terminal["auth"] = credentials.TerminalAuth
		}
		base.Environment["environment_id"] = project.ID
		base.Environment["project_id"] = project.ID
		base.Environment["project_root"] = "/workspace"
		base.Environment["repository_identity"] = map[string]any{
			"provider": project.Repository.Provider,
			"url":      project.Repository.SourceURL,
		}
		base.HelperUpload = map[string]any{
			"endpoint":           uploadEndpoint(resource.HTTPBaseURL),
			"kind":               "paperboat_staged_image_v1",
			"http_base_url":      resource.HTTPBaseURL,
			"path":               uploadPath(resource.HTTPBaseURL),
			"max_bytes":          uploadMaxBytes,
			"allowed_mime_types": slices.Clone(uploadAllowedMIMEs),
			"retention_seconds":  uploadRetentionSeconds,
		}
		if credentials.UploadAuth != nil {
			base.HelperUpload["auth"] = credentials.UploadAuth
		}
	default:
		base.Descriptors = []any{map[string]any{
			"kind":       "provider_route_resource",
			"provider":   "provider_route",
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
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/files/staged-images"
	u.RawPath = ""
	return u.Path
}

func uploadEndpoint(httpBaseURL string) string {
	u, err := url.Parse(httpBaseURL)
	if err != nil {
		return ""
	}
	u.Path = uploadPath(httpBaseURL)
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String()
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

func terminalStatusDescriptor(status TunnelStatus, terminalSession dbsqlc.ProjectTerminalSession) map[string]any {
	if status.HTTPBaseURL == "" && status.WebSocketBaseURL == "" {
		return nil
	}
	return map[string]any{
		"kind":               "paperboat_terminal_v1",
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

type AccessSession struct {
	ID string
}

type HelperSessionLink struct {
	AccessSessionID    string
	UserID             string
	ProjectID          string
	CLIClientSessionID string
	TerminalSessionID  string
	FileSessionID      string
	HTTPBaseURL        string
	Reason             string
}

type HelperRevocationOutboxItem struct {
	ID         string
	Revocation CredentialRevocationInput
}

type ProviderRouteCleanupOutboxItem struct {
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
		err := q.UpsertProviderRouteResource(ctx, dbsqlc.UpsertProviderRouteResourceParams{ID: newID("agr"), ProjectID: projectID, TunnelID: resource.TunnelID, ClientID: resource.ClientID, ResourceID: resource.ResourceID, Metadata: metadata})
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
	row, err := r.db.Queries().GetProviderRouteResource(ctx, projectID)
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

func (r *Repository) CreateAccessSession(ctx context.Context, userID, projectID, cliClientSessionID, terminalSessionID, fileSessionID, sessionType string, descriptor ConnectionDescriptor, expiresAt time.Time) (AccessSession, error) {
	id := newID("acs")
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		return AccessSession{}, err
	}
	key := "access.session:" + id
	err = r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.Queries().CreateAccessSession(ctx, dbsqlc.CreateAccessSessionParams{ID: id, UserID: userID, ProjectID: projectID, CLIClientSessionID: cliClientSessionID, HelperTerminalSessionID: terminalSessionID, HelperFileSessionID: fileSessionID, SessionType: sessionType, Descriptor: descriptorBytes, ExpiresAt: expiresAt, IdempotencyKey: key})
	})
	return AccessSession{ID: id}, err
}

func (r *Repository) RevokeClientAccessSessions(ctx context.Context, cliClientSessionID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeClientAccessSessions(ctx, dbsqlc.RevokeClientAccessSessionsParams{CLIClientSessionID: sql.NullString{String: cliClientSessionID, Valid: true}, Reason: reason})
}

func (r *Repository) RevokeUserAccessSessions(ctx context.Context, userID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeUserAccessSessions(ctx, dbsqlc.RevokeUserAccessSessionsParams{UserID: userID, Reason: reason})
}

func (r *Repository) RevokeProjectAccessSessions(ctx context.Context, projectID, reason string) error {
	reason = revocationReason(reason)
	return r.db.Queries().RevokeProjectAccessSessions(ctx, dbsqlc.RevokeProjectAccessSessionsParams{ProjectID: projectID, Reason: reason})
}

func (r *Repository) ClientHelperSessions(ctx context.Context, cliClientSessionID string) ([]HelperSessionLink, error) {
	rows, err := r.db.Queries().ListClientHelperSessions(ctx, sql.NullString{String: cliClientSessionID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]HelperSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, HelperSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, CLIClientSessionID: row.CLIClientSessionID, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) UserHelperSessions(ctx context.Context, userID string) ([]HelperSessionLink, error) {
	rows, err := r.db.Queries().ListUserHelperSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]HelperSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, HelperSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, CLIClientSessionID: row.CLIClientSessionID, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) ProjectHelperSessions(ctx context.Context, projectID string) ([]HelperSessionLink, error) {
	rows, err := r.db.Queries().ListProjectHelperSessions(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]HelperSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, HelperSessionLink{UserID: row.UserID, ProjectID: row.ProjectID, CLIClientSessionID: row.CLIClientSessionID, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl)})
	}
	return out, nil
}

func (r *Repository) MarkClientHelperRevocationPropagated(ctx context.Context, cliClientSessionID string) error {
	return r.db.Queries().MarkClientHelperRevocationPropagated(ctx, sql.NullString{String: cliClientSessionID, Valid: true})
}

func (r *Repository) MarkUserHelperRevocationPropagated(ctx context.Context, userID string) error {
	return r.db.Queries().MarkUserHelperRevocationPropagated(ctx, userID)
}

func (r *Repository) MarkProjectHelperRevocationPropagated(ctx context.Context, projectID string) error {
	return r.db.Queries().MarkProjectHelperRevocationPropagated(ctx, projectID)
}

func (r *Repository) PendingHelperRevocations(ctx context.Context) ([]HelperSessionLink, error) {
	rows, err := r.db.Queries().ListPendingHelperRevocations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]HelperSessionLink, 0, len(rows))
	for _, row := range rows {
		out = append(out, HelperSessionLink{AccessSessionID: row.ID, UserID: row.UserID, ProjectID: row.ProjectID, CLIClientSessionID: row.CLIClientSessionID, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID, HTTPBaseURL: fmt.Sprint(row.HttpBaseUrl), Reason: fmt.Sprint(row.Reason)})
	}
	return out, nil
}

func (r *Repository) MarkAccessSessionHelperRevocationPropagated(ctx context.Context, accessSessionID string) error {
	return r.db.Queries().MarkAccessSessionHelperRevocationPropagated(ctx, accessSessionID)
}

func (r *Repository) CreateHelperRevocationOutbox(ctx context.Context, input CredentialRevocationInput) (string, error) {
	id := newID("pro")
	err := r.db.Queries().CreateHelperRevocationOutbox(ctx, dbsqlc.CreateHelperRevocationOutboxParams{
		ID: id, UserID: input.UserID, ProjectID: input.ProjectID, CLIClientSessionID: input.CLIClientSessionID,
		HttpBaseUrl: input.HTTPBaseURL, SessionIds: input.SessionIDs, Reason: input.Reason,
	})
	return id, err
}

func (r *Repository) PendingHelperRevocationOutbox(ctx context.Context) ([]HelperRevocationOutboxItem, error) {
	rows, err := r.db.Queries().ListPendingHelperRevocationOutbox(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]HelperRevocationOutboxItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, HelperRevocationOutboxItem{ID: row.ID, Revocation: CredentialRevocationInput{
			UserID: row.UserID, ProjectID: row.ProjectID, EnvironmentID: row.ProjectID,
			CLIClientSessionID: row.CLIClientSessionID, HTTPBaseURL: row.HttpBaseUrl,
			SessionIDs: row.SessionIds, Reason: row.Reason,
		}})
	}
	return out, nil
}

func (r *Repository) MarkHelperRevocationOutboxPropagated(ctx context.Context, id string) error {
	return r.db.Queries().MarkHelperRevocationOutboxPropagated(ctx, id)
}

func (r *Repository) UpsertProviderRouteCleanupOutbox(ctx context.Context, projectID, action, reason string) error {
	return r.db.Queries().UpsertProviderRouteCleanupOutbox(ctx, dbsqlc.UpsertProviderRouteCleanupOutboxParams{
		ID: newID("aco"), ProjectID: projectID, Action: action, Reason: reason,
	})
}

func (r *Repository) PendingProviderRouteCleanupOutbox(ctx context.Context) ([]ProviderRouteCleanupOutboxItem, error) {
	rows, err := r.db.Queries().ListPendingProviderRouteCleanupOutbox(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ProviderRouteCleanupOutboxItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, ProviderRouteCleanupOutboxItem{ProjectID: row.ProjectID, Action: row.Action, Reason: row.Reason})
	}
	return out, nil
}

func (r *Repository) MarkProviderRouteCleanupOutboxPropagated(ctx context.Context, projectID string) error {
	return r.db.Queries().MarkProviderRouteCleanupOutboxPropagated(ctx, projectID)
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
	case "connect_session", "provider_route_connection", "helper_activity", "cli_activity", "vm_heartbeat":
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
