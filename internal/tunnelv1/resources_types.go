package tunnelv1

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

// ResourceConfig controls the resource service's deterministic dependencies.
// CursorKey is deliberately separate from the tunnel list key so a token from
// one resource family can never be replayed against another family.
type ResourceConfig struct {
	CursorKey []byte
	// ChallengeZone is the server-owned authoritative zone used for delegated
	// ACME DNS-01 TXT targets. It is never a customer-controlled hostname.
	ChallengeZone            string
	Now                      func() time.Time
	NewID                    func(string) (string, error)
	EnrollmentTTL            time.Duration
	RotationOverlap          time.Duration
	CredentialLifetime       time.Duration
	AllowInsecureDevelopment bool
}

type ResourceAPI interface {
	ListRoutes(context.Context, previewtunnelapi.RequestContext, string, string, int) (RoutePage, error)
	GetRoute(context.Context, previewtunnelapi.RequestContext, string, string) (RouteView, error)
	CreateRoute(context.Context, previewtunnelapi.RequestContext, string, RouteCreateRequest) (RouteMutationResult, error)
	PatchRoute(context.Context, previewtunnelapi.RequestContext, string, string, RoutePatchRequest) (RouteMutationResult, error)
	DeleteRoute(context.Context, previewtunnelapi.RequestContext, string, string, ResourceMutationInput) (RouteMutationResult, error)

	ListDomains(context.Context, previewtunnelapi.RequestContext, string, string, int) (DomainPage, error)
	GetDomain(context.Context, previewtunnelapi.RequestContext, string, string) (DomainView, error)
	CreateDomain(context.Context, previewtunnelapi.RequestContext, string, DomainCreateRequest) (DomainMutationResult, error)
	DeleteDomain(context.Context, previewtunnelapi.RequestContext, string, string, ResourceMutationInput) (DomainMutationResult, error)
	VerifyDomain(context.Context, previewtunnelapi.RequestContext, string, string, ResourceMutationInput) (DomainMutationResult, error)
	DomainInstructions(context.Context, previewtunnelapi.RequestContext, string, string) (DNSInstructions, error)

	ListConnectors(context.Context, previewtunnelapi.RequestContext, string, string, int) (ConnectorPage, error)
	GetConnector(context.Context, previewtunnelapi.RequestContext, string, string) (ConnectorView, error)
	IssueEnrollment(context.Context, previewtunnelapi.RequestContext, string, EnrollmentRequest) (EnrollmentResult, error)
	ExchangeEnrollment(context.Context, previewtunnelapi.RequestContext, EnrollmentExchangeRequest) (ConnectorMutationResult, error)
	DrainConnector(context.Context, previewtunnelapi.RequestContext, string, string, ResourceMutationInput) (ConnectorMutationResult, error)
	RevokeConnector(context.Context, previewtunnelapi.RequestContext, string, string, ResourceMutationInput) (ConnectorMutationResult, error)
	RotateCredentials(context.Context, previewtunnelapi.RequestContext, string, ResourceMutationInput) (previewtunnelapi.Operation, error)

	ListTunnelLogs(context.Context, previewtunnelapi.RequestContext, string, string, int) (LogPage, error)
	ListPreviewLogs(context.Context, previewtunnelapi.RequestContext, string, string, int) (LogPage, error)
}

// PreviewLogAPI is kept independent from the lifecycle PreviewTunnelAPI so a
// browser cannot accidentally gain access to enrollment or write-only data.
type PreviewLogAPI interface {
	ListPreviewLogs(context.Context, previewtunnelapi.RequestContext, string, string, int) (LogPage, error)
}

type ResourceMutationInput struct {
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
}

type RouteCreateRequest struct {
	Name                 string
	Protocol             string
	MatchType            string
	Hostname             string
	WildcardSuffix       string
	PathPrefix           *string
	Origin               RouteOriginRequest
	Priority             int32
	ConnectTimeoutMS     int32
	IdleTimeoutMS        int32
	MaxConcurrentStreams int32
	Mutation             ResourceMutationInput
}

type RoutePatchRequest struct {
	Name                 *string
	Protocol             *string
	MatchType            *string
	Hostname             *string
	WildcardSuffix       *string
	PathPrefix           *string
	PathPrefixSet        bool
	Origin               *RouteOriginRequest
	Priority             *int32
	ConnectTimeoutMS     *int32
	IdleTimeoutMS        *int32
	MaxConcurrentStreams *int32
	DesiredState         *string
	Mutation             ResourceMutationInput
}

type RouteTLSRequest struct {
	Verification              string
	ServerName                *string
	CAReference               *string
	ClientCredentialReference *string
}

type RouteOriginRequest struct {
	Scheme       string
	Address      string
	PreserveHost bool
	HostOverride *string
	TLS          *RouteTLSRequest
}

type DomainCreateRequest struct {
	Hostname            string
	RouteID             string
	Provider            string
	CertificateStrategy string
	Mutation            ResourceMutationInput
}

type EnrollmentRequest struct {
	HostID       string
	Capabilities []string
	TTL          time.Duration
	Mutation     ResourceMutationInput
}

type EnrollmentExchangeRequest struct {
	TunnelID                    string
	Token                       string
	HostID                      string
	ProtocolVersion             string
	SoftwareVersion             *string
	CredentialReference         string
	CredentialThumbprint        string
	CredentialVerifierAlgorithm string
	CredentialVerifierPublicKey []byte
	CredentialProof             []byte
	OperatingSystem             *string
	Architecture                *string
	Mutation                    ResourceMutationInput
}

type RouteHostMatch struct {
	Type           string `json:"type"`
	Hostname       string `json:"hostname,omitempty"`
	WildcardLabels *int   `json:"wildcard_labels,omitempty"`
}

type RouteTLS struct {
	Verification              string  `json:"verification"`
	ServerName                *string `json:"server_name,omitempty"`
	CAReference               *string `json:"ca_reference,omitempty"`
	ClientCredentialReference *string `json:"client_credential_reference,omitempty"`
}

type RouteOrigin struct {
	Scheme       string    `json:"scheme"`
	Address      string    `json:"address"`
	PreserveHost bool      `json:"preserve_host"`
	HostOverride *string   `json:"host_override,omitempty"`
	TLS          *RouteTLS `json:"tls,omitempty"`
}

type RouteView struct {
	Schema               string         `json:"schema"`
	Kind                 string         `json:"kind"`
	ID                   string         `json:"id"`
	TunnelID             string         `json:"tunnel_id"`
	Name                 string         `json:"name"`
	Protocol             string         `json:"protocol"`
	HostMatch            RouteHostMatch `json:"host_match"`
	PathPrefix           *string        `json:"path_prefix,omitempty"`
	Origin               RouteOrigin    `json:"origin"`
	Priority             int32          `json:"priority"`
	ConnectTimeoutMS     int32          `json:"connect_timeout_ms"`
	IdleTimeoutMS        int32          `json:"idle_timeout_ms"`
	MaxConcurrentStreams int32          `json:"max_concurrent_streams"`
	DesiredState         string         `json:"desired_state"`
	Generation           int64          `json:"generation"`
	ETag                 string         `json:"etag"`
}

type RoutePage struct {
	Items      []RouteView `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type DomainDNS struct {
	Target          string     `json:"target"`
	ObservedRecords []string   `json:"observed_records,omitempty"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
}

type DomainCertificate struct {
	State     string         `json:"state"`
	Reference string         `json:"reference,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Failure   map[string]any `json:"failure,omitempty"`
}

type DomainView struct {
	Schema              string            `json:"schema"`
	Kind                string            `json:"kind"`
	ID                  string            `json:"id"`
	AccountID           string            `json:"account_id"`
	TunnelID            string            `json:"tunnel_id"`
	RouteID             string            `json:"route_id"`
	Hostname            string            `json:"hostname"`
	MatchType           string            `json:"match_type"`
	WildcardLabels      *int              `json:"wildcard_labels,omitempty"`
	CertificateStrategy string            `json:"certificate_strategy"`
	State               string            `json:"state"`
	DNS                 DomainDNS         `json:"dns"`
	Certificate         DomainCertificate `json:"certificate"`
	Generation          int64             `json:"generation"`
	ETag                string            `json:"etag"`
}

type DomainPage struct {
	Items      []DomainView `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type ConnectorView struct {
	Schema                      string     `json:"schema"`
	Kind                        string     `json:"kind"`
	ID                          string     `json:"id"`
	TunnelID                    string     `json:"tunnel_id"`
	HostID                      string     `json:"host_id"`
	CredentialReference         string     `json:"credential_reference"`
	RotationGeneration          int64      `json:"rotation_generation"`
	DesiredState                string     `json:"desired_state"`
	SoftwareVersion             string     `json:"software_version,omitempty"`
	ProtocolVersion             string     `json:"protocol_version"`
	OperatingSystem             string     `json:"operating_system,omitempty"`
	Architecture                string     `json:"architecture,omitempty"`
	LastSessionID               string     `json:"last_session_id,omitempty"`
	LastHeartbeatAt             *time.Time `json:"last_heartbeat_at,omitempty"`
	ReadyAt                     *time.Time `json:"ready_at,omitempty"`
	LastAppliedConfigGeneration int64      `json:"last_applied_config_generation,omitempty"`
	DrainState                  string     `json:"drain_state"`
	Generation                  int64      `json:"generation"`
	ETag                        string     `json:"etag"`
}

type ConnectorPage struct {
	Items      []ConnectorView `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type EnrollmentResult struct {
	Schema       string                     `json:"schema"`
	Kind         string                     `json:"kind"`
	ID           string                     `json:"id"`
	TunnelID     string                     `json:"tunnel_id"`
	HostID       string                     `json:"host_id"`
	Operation    previewtunnelapi.Operation `json:"operation"`
	Token        string                     `json:"enrollment_token"`
	ExpiresAt    time.Time                  `json:"expires_at"`
	Capabilities []string                   `json:"capabilities"`
	Replayed     bool                       `json:"replayed"`
}

type ConnectorMutationResult struct {
	Connector  ConnectorView              `json:"connector"`
	Operation  previewtunnelapi.Operation `json:"operation"`
	Activation *ConnectorActivation       `json:"activation,omitempty"`
	Replayed   bool                       `json:"replayed"`
	Changed    bool                       `json:"changed"`
}

// ConnectorActivation is the secret-free, server-authoritative input needed
// before the first connector-v1 Hello. The stable endpoint identity and
// credential/process generations are read from or reserved by the same durable
// enrollment transaction and remain stable on an exact idempotent replay. The
// host must never guess or derive any of these values.
type ConnectorActivation struct {
	Schema               string                     `json:"schema"`
	Kind                 string                     `json:"kind"`
	AccountID            string                     `json:"account_id"`
	TunnelID             string                     `json:"tunnel_id"`
	ConnectorID          string                     `json:"connector_id"`
	HostID               string                     `json:"host_id"`
	StableEndpointID     string                     `json:"stable_endpoint_id"`
	CredentialGeneration int64                      `json:"credential_generation"`
	ProcessGeneration    int64                      `json:"process_generation"`
	Operation            previewtunnelapi.Operation `json:"operation"`
}

type RouteMutationResult struct {
	Route     RouteView                  `json:"route"`
	Operation previewtunnelapi.Operation `json:"operation"`
	Replayed  bool                       `json:"replayed"`
	Changed   bool                       `json:"changed"`
}

type DomainMutationResult struct {
	Domain    DomainView                 `json:"domain"`
	Operation previewtunnelapi.Operation `json:"operation"`
	Replayed  bool                       `json:"replayed"`
	Changed   bool                       `json:"changed"`
}

type LogEntry struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	TunnelID      string         `json:"tunnel_id,omitempty"`
	PreviewID     string         `json:"preview_id,omitempty"`
	RouteID       string         `json:"route_id,omitempty"`
	ConnectorID   string         `json:"connector_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	Level         string         `json:"level"`
	Component     string         `json:"component"`
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Metadata      map[string]any `json:"metadata"`
	CorrelationID string         `json:"correlation_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Cursor        string         `json:"cursor"`
}

type LogPage struct {
	Items      []LogEntry `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type DNSRecordInstruction struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

type DNSInstructions struct {
	Schema              string                 `json:"schema"`
	Kind                string                 `json:"kind"`
	TunnelID            string                 `json:"tunnel_id"`
	DomainID            string                 `json:"domain_id"`
	Hostname            string                 `json:"hostname"`
	Provider            string                 `json:"provider"`
	Records             []DNSRecordInstruction `json:"records"`
	CertificateStrategy string                 `json:"certificate_strategy"`
	VerificationState   string                 `json:"verification_state"`
	Note                string                 `json:"note"`
}

type ResourceMutationRecord struct {
	Route             dbsqlc.TunnelRoute
	Domain            dbsqlc.TunnelDomain
	Connector         dbsqlc.TunnelConnector
	Operation         dbsqlc.Operation
	StableEndpointID  string
	ProcessGeneration int64
	Replayed          bool
	Changed           bool
}

type EnrollmentRecord struct {
	Enrollment dbsqlc.TunnelConnectorEnrollment
	Operation  dbsqlc.Operation
	Token      string
	Replayed   bool
}

type ResourceRepository interface {
	VerifyHost(context.Context, string, string) error
	ListResourceRoutes(context.Context, string, string, *ListPosition, int) ([]dbsqlc.TunnelRoute, error)
	GetResourceRoute(context.Context, string, string, string) (dbsqlc.TunnelRoute, error)
	CreateResourceRoute(context.Context, RouteRecord) (ResourceMutationRecord, error)
	PatchResourceRoute(context.Context, RouteRecord) (ResourceMutationRecord, error)
	DeleteResourceRoute(context.Context, RouteRecord) (ResourceMutationRecord, error)
	ListResourceDomains(context.Context, string, string, *ListPosition, int) ([]dbsqlc.TunnelDomain, error)
	GetResourceDomain(context.Context, string, string, string) (dbsqlc.TunnelDomain, error)
	CreateResourceDomain(context.Context, DomainRecord) (ResourceMutationRecord, error)
	DeleteResourceDomain(context.Context, DomainRecord) (ResourceMutationRecord, error)
	BeginResourceDomainVerification(context.Context, DomainRecord) (ResourceMutationRecord, error)
	ListResourceConnectors(context.Context, string, string, *ListPosition, int) ([]dbsqlc.TunnelConnector, error)
	GetResourceConnector(context.Context, string, string, string) (dbsqlc.TunnelConnector, error)
	IssueConnectorEnrollment(context.Context, EnrollmentRecordInput) (EnrollmentRecord, error)
	ExchangeConnectorEnrollment(context.Context, EnrollmentExchangeRecord) (ResourceMutationRecord, error)
	DrainResourceConnector(context.Context, ConnectorRecord) (ResourceMutationRecord, error)
	RevokeResourceConnector(context.Context, ConnectorRecord) (ResourceMutationRecord, error)
	RotateResourceCredentials(context.Context, RotationRecord) (dbsqlc.Operation, error)
	ListResourceTunnelLogs(context.Context, string, string, int64, int) ([]dbsqlc.ListTunnelLogsV1Row, error)
	ListResourcePreviewLogs(context.Context, string, string, int64, int) ([]dbsqlc.TunnelLogEntry, error)
}

type RouteRecord struct {
	OperationID          string
	AuditEventID         string
	ParentAuditEventID   string
	AccountID            string
	TunnelID             string
	RouteID              string
	Name                 string
	Protocol             string
	MatchType            string
	Hostname             sql.NullString
	WildcardSuffix       sql.NullString
	PathPrefix           sql.NullString
	Origin               RouteOriginRequest
	Priority             int32
	ConnectTimeoutMS     int32
	IdleTimeoutMS        int32
	MaxConcurrentStreams int32
	DesiredState         string
	ExpectedGeneration   int64
	IdempotencyKey       string
	RequestHash          [sha256.Size]byte
	ActorID              string
	AuditActorID         string
	ActorType            string
	RequestID            string
	CorrelationID        string
	SourceDeviceID       string
	Now                  time.Time
	CredentialLifetime   time.Duration
	NameSet              bool
	ProtocolSet          bool
	MatchTypeSet         bool
	HostnameSet          bool
	WildcardSuffixSet    bool
	PathPrefixSet        bool
	OriginSet            bool
	PrioritySet          bool
	ConnectTimeoutSet    bool
	IdleTimeoutSet       bool
	MaxStreamsSet        bool
	DesiredStateSet      bool
}

type DomainRecord struct {
	OperationID         string
	AuditEventID        string
	ParentAuditEventID  string
	AccountID           string
	TunnelID            string
	DomainID            string
	RouteID             string
	Hostname            string
	MatchType           string
	CertificateStrategy string
	ChallengeReference  string
	DNSTarget           string
	DNSProvider         string
	ExpectedRecords     []byte
	ExpectedGeneration  int64
	IdempotencyKey      string
	RequestHash         [sha256.Size]byte
	ActorID             string
	AuditActorID        string
	ActorType           string
	RequestID           string
	CorrelationID       string
	SourceDeviceID      string
	Now                 time.Time
}

type ConnectorRecord struct {
	OperationID        string
	AuditEventID       string
	ParentAuditEventID string
	AccountID          string
	TunnelID           string
	ConnectorID        string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	AuditActorID       string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	Now                time.Time
}

type EnrollmentRecordInput struct {
	OperationID        string
	EnrollmentID       string
	AuditEventID       string
	ParentAuditEventID string
	AccountID          string
	TunnelID           string
	HostID             string
	TokenHash          []byte
	Token              string
	Capabilities       []string
	ExpiresAt          time.Time
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	AuditActorID       string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	Now                time.Time
	CredentialLifetime time.Duration
}

type EnrollmentExchangeRecord struct {
	OperationID                 string
	AuditEventID                string
	ParentAuditEventID          string
	AccountID                   string
	TunnelID                    string
	HostID                      string
	TokenHash                   []byte
	ProtocolVersion             string
	SoftwareVersion             sql.NullString
	OperatingSystem             sql.NullString
	Architecture                sql.NullString
	ConnectorID                 string
	CredentialReference         string
	CredentialThumbprint        string
	CredentialVerifierAlgorithm string
	CredentialVerifierPublicKey []byte
	CredentialGenerationID      string
	CredentialProof             []byte
	IdempotencyKey              string
	RequestHash                 [sha256.Size]byte
	ActorID                     string
	AuditActorID                string
	ActorType                   string
	RequestID                   string
	CorrelationID               string
	SourceDeviceID              string
	Now                         time.Time
	CredentialLifetime          time.Duration
	CredentialOverlap           time.Duration
}

type RotationRecord struct {
	OperationID        string
	AuditEventID       string
	ParentAuditEventID string
	AccountID          string
	TunnelID           string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	AuditActorID       string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	Now                time.Time
	OverlapUntil       time.Time
	// CredentialLifetime is supplied by the configured resource policy. The
	// repository persists the resulting absolute deadline in the immutable
	// rotation target rows so a retry or restart never has to reconstruct policy.
	CredentialLifetime time.Duration
	NewID              func(string) (string, error)
}
