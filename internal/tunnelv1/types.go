package tunnelv1

import (
	"crypto/sha256"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

// Schema is the public preview/tunnel resource family identifier.
const Schema = "paperboat.preview-tunnel/v1"

const (
	DesiredActive  = "active"
	DesiredPaused  = "paused"
	DesiredDeleted = "deleted"
	AccessPublic   = "public"
	AccessPrivate  = "private"
)

// OriginRequest is the initial route target supplied when a durable tunnel is
// created. Credentials are intentionally not accepted in this v1 request.
type OriginRequest struct {
	Scheme       string  `json:"scheme"`
	Address      string  `json:"address"`
	PreserveHost *bool   `json:"preserve_host,omitempty"`
	HostOverride *string `json:"host_override,omitempty"`
}

// MutationInput carries the common idempotency and optimistic-concurrency
// inputs for a tunnel mutation. RequestHash is computed from the exact
// canonical request body by the HTTP boundary.
type MutationInput struct {
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
}

type CreateTunnelRequest struct {
	Name       string
	AccessMode string
	Origin     OriginRequest
	ExpiresAt  *time.Time
	MutationInput
}

type PatchTunnelRequest struct {
	Name       *string
	AccessMode *string
	ExpiresAt  *time.Time
	// ExpirySet distinguishes an omitted expires_at field from an explicit
	// null, which removes an existing expiry.
	ExpirySet bool
	MutationInput
}

// TunnelView is the safe durable tunnel representation. It contains no
// reusable credential material.
type TunnelView struct {
	Schema           string     `json:"schema"`
	Kind             string     `json:"kind"`
	ID               string     `json:"id"`
	AccountID        string     `json:"account_id"`
	Name             string     `json:"name"`
	DesiredState     string     `json:"desired_state"`
	AccessMode       string     `json:"access_mode"`
	Generation       int64      `json:"generation"`
	ETag             string     `json:"etag"`
	StableEndpointID string     `json:"stable_endpoint_id"`
	StableEndpoint   string     `json:"stable_endpoint"`
	CreatedByHostID  string     `json:"created_by_host_id"`
	CreatedByActorID string     `json:"created_by_actor_id"`
	ExpiresAt        *time.Time `json:"expires_at"`
	SummaryCode      string     `json:"summary_code"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type MutationResult struct {
	Tunnel    TunnelView                 `json:"tunnel"`
	Operation previewtunnelapi.Operation `json:"operation"`
	Replayed  bool                       `json:"replayed"`
	Changed   bool                       `json:"changed"`
}

type TunnelPage struct {
	Items      []TunnelView `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type HealthDimension struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

type HealthDimensions struct {
	Service     HealthDimension `json:"service"`
	Edge        HealthDimension `json:"edge"`
	Config      HealthDimension `json:"config"`
	Route       HealthDimension `json:"route"`
	Origin      HealthDimension `json:"origin"`
	DNS         HealthDimension `json:"dns"`
	Certificate HealthDimension `json:"certificate"`
	Access      HealthDimension `json:"access"`
	Update      HealthDimension `json:"update"`
}

type HealthView struct {
	Schema        string           `json:"schema"`
	Kind          string           `json:"kind"`
	ResourceKind  string           `json:"resource_kind"`
	ResourceID    string           `json:"resource_id"`
	OverallCode   string           `json:"overall_code"`
	Dimensions    HealthDimensions `json:"dimensions"`
	Summary       string           `json:"summary"`
	Since         time.Time        `json:"since"`
	Retrying      bool             `json:"retrying"`
	NextRetryAt   *time.Time       `json:"next_retry_at,omitempty"`
	RepairAction  string           `json:"repair_action"`
	CorrelationID string           `json:"correlation_id"`
}

// EndpointBuilder allocates a user-facing stable endpoint from the immutable
// endpoint identity. The name argument is retained at this boundary so callers
// do not need a coordinated interface change, but endpoint implementations must
// not derive public hostnames from it.
type EndpointBuilder func(name, stableEndpointID string) (string, error)

type Config struct {
	EndpointBuilder EndpointBuilder
	CursorKey       []byte
	Now             func() time.Time
	NewID           func(prefix string) (string, error)
	// NewEndpointID allocates the opaque UUID used as the leftmost managed
	// tunnel hostname label. It is separate from internal resource IDs so
	// changing the tunnel name can never change the public endpoint.
	NewEndpointID func() (string, error)
}

type ExpiryReconcileRequest struct {
	Now           time.Time
	Limit         int
	ActorID       string
	ActorType     string
	RequestID     string
	CorrelationID string
}
