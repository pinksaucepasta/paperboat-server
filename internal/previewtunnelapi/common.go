package previewtunnelapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
)

const (
	IdempotencyHeader = "Idempotency-Key"
	IfMatchHeader     = "If-Match"
	DefaultPageLimit  = 50
	MaximumPageLimit  = 200
	maximumCursorSize = 2048
	maximumCursorBody = 512
)

var (
	ErrForbidden           = errors.New("preview tunnel authorization denied")
	ErrHostActorRequired   = errors.New("host-scoped actor required")
	ErrIdempotencyRequired = errors.New("idempotency key required")
	ErrInvalidIdempotency  = errors.New("invalid idempotency key")
	ErrIfMatchRequired     = errors.New("If-Match required")
	ErrInvalidETag         = errors.New("invalid ETag")
	ErrInvalidCursor       = errors.New("invalid cursor")
	ErrUnsafeMetadata      = errors.New("unsafe metadata")
)

// APIError is the shared error contract. Message is safe for users and all
// branching fields are typed so callers never inspect the message text.
type APIError struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	Code          string         `json:"code"`
	Component     string         `json:"component"`
	Message       string         `json:"message"`
	Outcome       string         `json:"outcome"`
	Retryable     bool           `json:"retryable"`
	RetryAt       *time.Time     `json:"retry_at,omitempty"`
	RepairAction  string         `json:"repair_action,omitempty"`
	RequestID     string         `json:"request_id"`
	CorrelationID string         `json:"correlation_id"`
	Details       map[string]any `json:"details,omitempty"`
}

type Actor struct {
	AccountID string
	ActorID   string
	DeviceID  string
	HostID    string
	Role      string
	Scopes    []string
}

type AccessRequest struct {
	AccountID   string
	Resource    string
	Action      string
	RequireHost bool
}

// Authorize applies account, actor, device, role, resource-scope, and host
// checks in one place. Browser users have no Scopes; bearer/device actors do.
func Authorize(actor Actor, request AccessRequest) error {
	if strings.TrimSpace(actor.ActorID) == "" || strings.TrimSpace(actor.AccountID) == "" || actor.AccountID != request.AccountID {
		return ErrForbidden
	}
	switch actor.Role {
	case "user", "support", "admin", "system_worker":
	default:
		return ErrForbidden
	}
	if request.RequireHost && (strings.TrimSpace(actor.DeviceID) == "" || strings.TrimSpace(actor.HostID) == "") {
		return ErrHostActorRequired
	}
	if actor.Role == "support" && request.Action != "read" {
		return ErrForbidden
	}
	if actor.Role == "admin" || actor.Role == "system_worker" || len(actor.Scopes) == 0 {
		return nil
	}
	required := request.Resource + ":" + request.Action
	for _, scope := range actor.Scopes {
		if scope == required {
			return nil
		}
	}
	return ErrForbidden
}

func ParseIdempotencyKey(header http.Header) (string, error) {
	values := header.Values(IdempotencyHeader)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", ErrIdempotencyRequired
	}
	if len(values) != 1 {
		return "", ErrInvalidIdempotency
	}
	key := strings.TrimSpace(values[0])
	if len(key) > 256 {
		return "", ErrInvalidIdempotency
	}
	for _, r := range key {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", ErrInvalidIdempotency
		}
	}
	return key, nil
}

// RequestHash canonicalizes JSON and rejects duplicate fields before hashing.
// Equal semantic JSON objects therefore produce the same idempotency hash.
func RequestHash(body []byte) ([sha256.Size]byte, error) {
	if err := canonicaljson.RejectDuplicateFields(body); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("invalid request JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("invalid request JSON: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("canonicalize request JSON: %w", err)
	}
	return sha256.Sum256(canonical), nil
}

func ETag(resourceKind, resourceID string, generation int64) string {
	id := base64.RawURLEncoding.EncodeToString([]byte(resourceID))
	return fmt.Sprintf(`"ptv1:%s:%s:%d"`, resourceKind, id, generation)
}

func ParseIfMatch(header http.Header, resourceKind, resourceID string) (int64, error) {
	values := header.Values(IfMatchHeader)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return 0, ErrIfMatchRequired
	}
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return 0, ErrInvalidETag
	}
	raw := strings.TrimSpace(values[0])
	if strings.HasPrefix(raw, "W/") || len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidETag
	}
	parts := strings.Split(strings.Trim(raw, `"`), ":")
	if len(parts) != 4 || parts[0] != "ptv1" || parts[1] != resourceKind {
		return 0, ErrInvalidETag
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(id, []byte(resourceID)) {
		return 0, ErrInvalidETag
	}
	generation, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || generation < 1 {
		return 0, ErrInvalidETag
	}
	return generation, nil
}

func PageLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultPageLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > MaximumPageLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", MaximumPageLimit)
	}
	return limit, nil
}

type EventPosition struct {
	AccountID    string `json:"account_id"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	Sequence     int64  `json:"sequence"`
}

type CursorCodec struct{ key []byte }

func NewCursorCodec(key []byte) (*CursorCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("cursor signing key must contain at least 32 bytes")
	}
	return &CursorCodec{key: append([]byte(nil), key...)}, nil
}

func (c *CursorCodec) Encode(position EventPosition) (string, error) {
	if position.AccountID == "" || position.ResourceKind == "" || position.ResourceID == "" || position.Sequence < 0 {
		return "", ErrInvalidCursor
	}
	payload, err := json.Marshal(position)
	if err != nil || len(payload) > maximumCursorBody {
		return "", ErrInvalidCursor
	}
	signature := c.sign(payload)
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) > maximumCursorSize {
		return "", ErrInvalidCursor
	}
	return encoded, nil
}

func (c *CursorCodec) Decode(raw string, expected EventPosition) (EventPosition, error) {
	if len(raw) == 0 || len(raw) > maximumCursorSize {
		return EventPosition{}, ErrInvalidCursor
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return EventPosition{}, ErrInvalidCursor
	}
	encoding := base64.RawURLEncoding.Strict()
	payload, err := encoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maximumCursorBody {
		return EventPosition{}, ErrInvalidCursor
	}
	signature, err := encoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, c.sign(payload)) {
		return EventPosition{}, ErrInvalidCursor
	}
	var position EventPosition
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&position); err != nil || decoder.Decode(&struct{}{}) != io.EOF || position.Sequence < 0 {
		return EventPosition{}, ErrInvalidCursor
	}
	if position.AccountID != expected.AccountID || position.ResourceKind != expected.ResourceKind || position.ResourceID != expected.ResourceID {
		return EventPosition{}, ErrInvalidCursor
	}
	return position, nil
}

func (c *CursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
