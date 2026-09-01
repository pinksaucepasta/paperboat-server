package previewv1

import (
	"context"
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

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

const PreviewDispatchKind = "preview_dispatch"

var (
	ErrDispatchInvalid     = errors.New("invalid preview dispatch")
	ErrDispatchMismatch    = errors.New("preview dispatch response mismatch")
	ErrDispatchUnavailable = errors.New("preview dispatch unavailable")
	ErrDispatchUncertain   = errors.New("preview dispatch outcome is uncertain")
	ErrDispatchRejected    = errors.New("preview dispatch rejected")
)

// DispatchRequest is the secret-free, operation-bound lease projection sent
// to the selected host. Its field order and canonical hash are part of the
// host/server protocol. RequestHash excludes itself and covers every other
// field, including LeaseETag.
type DispatchRequest struct {
	Schema             string     `json:"schema"`
	Kind               string     `json:"kind"`
	PreviewID          string     `json:"preview_id"`
	OperationID        string     `json:"operation_id"`
	AccountID          string     `json:"account_id"`
	ActorID            string     `json:"actor_id"`
	OwnerDeviceID      string     `json:"owner_device_id"`
	OwnerSessionID     string     `json:"owner_session_id"`
	Target             Target     `json:"target"`
	AccessMode         string     `json:"access_mode"`
	Endpoint           string     `json:"endpoint"`
	LeaseDeadline      time.Time  `json:"lease_deadline"`
	UserDeadline       *time.Time `json:"user_deadline,omitempty"`
	LeaseETag          string     `json:"lease_etag"`
	State              string     `json:"state"`
	AllocationState    string     `json:"allocation_state"`
	EdgeState          string     `json:"edge_state"`
	OriginState        string     `json:"origin_state"`
	CreatedAt          time.Time  `json:"created_at"`
	LastRenewedAt      time.Time  `json:"last_renewed_at"`
	ExpectedGeneration int64      `json:"expected_generation"`
	IdempotencyKey     string     `json:"idempotency_key"`
	RequestID          string     `json:"request_id"`
	CorrelationID      string     `json:"correlation_id"`
	RequestHash        string     `json:"request_hash"`
}

// DispatchOutcome is the only response data accepted from a host. A host may
// accept before readiness; the server's device-auth readiness observation is
// the authority that completes the create operation.
type DispatchOutcome struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	PreviewID   string `json:"preview_id"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Generation  int64  `json:"generation"`
}

// Dispatcher is deliberately narrow so the preview policy service can be
// tested without an HTTP server or database. Implementations must perform
// network I/O only after the lease/operation transaction has committed.
type Dispatcher interface {
	Dispatch(context.Context, DispatchRequest) (DispatchOutcome, error)
}

// ComputeRequestHash returns the lowercase SHA-256 hex digest used by the
// host. The request_hash member itself is intentionally not included.
func (r DispatchRequest) ComputeRequestHash() (string, error) {
	canonical, err := r.canonicalHashInput(r.OwnerDeviceID)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// Validate checks identity, lifecycle, generation, and exact request hash.
// now is optional for deterministic construction; a non-zero value also
// rejects expired lease/user deadlines.
func (r DispatchRequest) Validate(now time.Time) error {
	canonical, err := r.canonicalHashInput(r.OwnerDeviceID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	want := hex.EncodeToString(digest[:])
	if len(r.RequestHash) != sha256.Size*2 || r.RequestHash != want {
		return fmt.Errorf("%w: request hash mismatch", ErrDispatchInvalid)
	}
	if !now.IsZero() {
		when := now.UTC()
		if !r.LeaseDeadline.After(when) || r.UserDeadline != nil && !r.UserDeadline.After(when) {
			return fmt.Errorf("%w: lease deadline has passed", ErrDispatchInvalid)
		}
	}
	return nil
}

func (r DispatchRequest) canonicalHashInput(machineID string) ([]byte, error) {
	r.Schema = strings.TrimSpace(r.Schema)
	r.Kind = strings.TrimSpace(r.Kind)
	r.PreviewID = strings.TrimSpace(r.PreviewID)
	r.OperationID = strings.TrimSpace(r.OperationID)
	r.AccountID = strings.TrimSpace(r.AccountID)
	r.ActorID = strings.TrimSpace(r.ActorID)
	r.OwnerDeviceID = strings.TrimSpace(r.OwnerDeviceID)
	r.OwnerSessionID = strings.TrimSpace(r.OwnerSessionID)
	r.Target.Scheme = strings.ToLower(strings.TrimSpace(r.Target.Scheme))
	r.Target.Address = strings.TrimSpace(r.Target.Address)
	r.AccessMode = strings.ToLower(strings.TrimSpace(r.AccessMode))
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	r.LeaseETag = strings.TrimSpace(r.LeaseETag)
	r.IdempotencyKey = strings.TrimSpace(r.IdempotencyKey)
	r.RequestID = strings.TrimSpace(r.RequestID)
	r.CorrelationID = strings.TrimSpace(r.CorrelationID)
	if r.Schema != Schema || r.Kind != PreviewDispatchKind || !validDispatchID(r.PreviewID) || !validDispatchID(r.OperationID) || !validDispatchID(r.AccountID) || !validDispatchID(r.ActorID) || !validDispatchID(r.OwnerDeviceID) || r.OwnerDeviceID != strings.TrimSpace(machineID) || !validDispatchID(r.OwnerSessionID) || r.ExpectedGeneration < 1 {
		return nil, ErrDispatchInvalid
	}
	if !validDispatchTrace(r.IdempotencyKey, 1, 256) || !validDispatchTrace(r.RequestID, 3, 128) || !validDispatchTrace(r.CorrelationID, 3, 128) {
		return nil, ErrDispatchInvalid
	}
	if !previewtunnelstore.ValidPreviewTargetV1(r.Target.Scheme, r.Target.Address, r.AccessMode) {
		return nil, ErrDispatchInvalid
	}
	if r.AccessMode != "public" && r.AccessMode != "private" || !validDispatchEndpoint(r.Endpoint) {
		return nil, ErrDispatchInvalid
	}
	if r.LeaseDeadline.IsZero() || r.UserDeadline != nil && r.UserDeadline.IsZero() || r.CreatedAt.IsZero() || r.LastRenewedAt.IsZero() || r.LastRenewedAt.Before(r.CreatedAt) {
		return nil, ErrDispatchInvalid
	}
	if !validDispatchState(r.State, r.AllocationState, r.EdgeState, r.OriginState) || !validDispatchETag(r.LeaseETag, r.PreviewID, r.ExpectedGeneration) {
		return nil, ErrDispatchInvalid
	}
	return json.Marshal(struct {
		Schema             string     `json:"schema"`
		Kind               string     `json:"kind"`
		PreviewID          string     `json:"preview_id"`
		OperationID        string     `json:"operation_id"`
		AccountID          string     `json:"account_id"`
		ActorID            string     `json:"actor_id"`
		OwnerDeviceID      string     `json:"owner_device_id"`
		OwnerSessionID     string     `json:"owner_session_id"`
		Target             Target     `json:"target"`
		AccessMode         string     `json:"access_mode"`
		Endpoint           string     `json:"endpoint"`
		LeaseDeadline      time.Time  `json:"lease_deadline"`
		UserDeadline       *time.Time `json:"user_deadline,omitempty"`
		LeaseETag          string     `json:"lease_etag"`
		State              string     `json:"state"`
		AllocationState    string     `json:"allocation_state"`
		EdgeState          string     `json:"edge_state"`
		OriginState        string     `json:"origin_state"`
		CreatedAt          time.Time  `json:"created_at"`
		LastRenewedAt      time.Time  `json:"last_renewed_at"`
		ExpectedGeneration int64      `json:"expected_generation"`
		IdempotencyKey     string     `json:"idempotency_key"`
		RequestID          string     `json:"request_id"`
		CorrelationID      string     `json:"correlation_id"`
	}{r.Schema, r.Kind, r.PreviewID, r.OperationID, r.AccountID, r.ActorID, r.OwnerDeviceID, r.OwnerSessionID, r.Target, r.AccessMode, r.Endpoint, r.LeaseDeadline.UTC(), utcDispatchTime(r.UserDeadline), r.LeaseETag, r.State, r.AllocationState, r.EdgeState, r.OriginState, r.CreatedAt.UTC(), r.LastRenewedAt.UTC(), r.ExpectedGeneration, r.IdempotencyKey, r.RequestID, r.CorrelationID})
}

func utcDispatchTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func validDispatchID(value string) bool {
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

func validDispatchTrace(value string, minimum, maximum int) bool {
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

func validDispatchEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" && parsed.RawPath != "/" || parsed.Host == "" || parsed.Port() != "" {
		return false
	}
	labels := strings.Split(parsed.Hostname(), ".")
	if len(labels) < 2 || strings.HasPrefix(labels[0], "preview-") {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func validDispatchETag(raw, id string, expected int64) bool {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	parts := strings.Split(strings.Trim(raw, `"`), ":")
	if len(parts) != 4 || parts[0] != "ptv1" || parts[1] != Kind {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || string(decoded) != id || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] || strconv.FormatInt(expected, 10) != parts[3] {
		return false
	}
	return expected > 0
}

func validDispatchState(state, allocation, edge, origin string) bool {
	return (state == "allocating" || state == "connecting" || state == "ready") &&
		(allocation == "pending" || allocation == "ready" || allocation == "failed" || allocation == "released") &&
		(edge == "pending" || edge == "ready" || edge == "degraded" || edge == "down") &&
		(origin == "unknown" || origin == "ready" || origin == "unavailable")
}
