package previewtunnelapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

const schemaID = "paperboat.preview-tunnel/v1"

var ErrOperationNotCancellable = errors.New("operation cannot be cancelled safely")

type Service struct {
	store   *previewtunnelstore.Store
	cursors *CursorCodec
}

func NewService(store *previewtunnelstore.Store, cursorKey []byte) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("preview tunnel store is required")
	}
	cursors, err := NewCursorCodec(cursorKey)
	if err != nil {
		return nil, err
	}
	return &Service{store: store, cursors: cursors}, nil
}

type Operation struct {
	Schema        string     `json:"schema"`
	Kind          string     `json:"kind"`
	ID            string     `json:"id"`
	ResourceKind  string     `json:"resource_kind"`
	ResourceID    string     `json:"resource_id"`
	Phase         string     `json:"phase"`
	State         string     `json:"state"`
	Progress      int        `json:"progress"`
	Retrying      bool       `json:"retrying"`
	NextRetryAt   *time.Time `json:"next_retry_at,omitempty"`
	Error         *APIError  `json:"error,omitempty"`
	CorrelationID string     `json:"correlation_id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type RequestContext struct {
	Actor         Actor
	RequestID     string
	CorrelationID string
}

func (s *Service) GetOperation(ctx context.Context, request RequestContext, operationID string) (Operation, error) {
	if err := Authorize(request.Actor, AccessRequest{AccountID: request.Actor.AccountID, Resource: "operations", Action: "read"}); err != nil {
		return Operation{}, err
	}
	row, err := s.store.GetOperation(ctx, request.Actor.AccountID, operationID)
	if err != nil {
		return Operation{}, err
	}
	return operationView(row, request.RequestID), nil
}

func (s *Service) CancelOperation(ctx context.Context, request RequestContext, operationID string) (Operation, error) {
	if err := Authorize(request.Actor, AccessRequest{AccountID: request.Actor.AccountID, Resource: "operations", Action: "write"}); err != nil {
		return Operation{}, err
	}
	result, err := s.store.CancelOperation(ctx, previewtunnelstore.CancelOperationInput{
		OperationID: operationID, AccountID: request.Actor.AccountID, AuditEventID: newID("aud"),
		ActorID: request.Actor.ActorID, ActorType: actorType(request.Actor), RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, SourceDeviceID: request.Actor.DeviceID,
	})
	if errors.Is(err, previewtunnelstore.ErrOperationNotCancellable) {
		return Operation{}, ErrOperationNotCancellable
	}
	if err != nil {
		return Operation{}, err
	}
	return operationView(result.Operation, request.RequestID), nil
}

type EventActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Event struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	Cursor        string         `json:"cursor"`
	EventType     string         `json:"event_type"`
	ResourceKind  string         `json:"resource_kind"`
	ResourceID    string         `json:"resource_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Actor         EventActor     `json:"actor"`
	CorrelationID string         `json:"correlation_id"`
	SafeMetadata  map[string]any `json:"safe_metadata"`
}

type EventPage struct {
	Items      []Event `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

func (s *Service) ListEvents(ctx context.Context, request RequestContext, resourceKind, resourceID, rawCursor string, limit int) (EventPage, error) {
	scope := resourceScope(resourceKind)
	if scope == "" {
		return EventPage{}, previewtunnelstore.ErrInvalidInput
	}
	if err := Authorize(request.Actor, AccessRequest{AccountID: request.Actor.AccountID, Resource: scope, Action: "read"}); err != nil {
		return EventPage{}, err
	}
	after := int64(0)
	if rawCursor != "" {
		position, err := s.cursors.Decode(rawCursor, EventPosition{AccountID: request.Actor.AccountID, ResourceKind: resourceKind, ResourceID: resourceID})
		if err != nil {
			return EventPage{}, err
		}
		after = position.Sequence
	}
	if limit < 1 || limit > MaximumPageLimit {
		return EventPage{}, fmt.Errorf("limit must be between 1 and %d", MaximumPageLimit)
	}
	rows, err := s.store.ListEvents(ctx, previewtunnelstore.ListEventsInput{
		AccountID: request.Actor.AccountID, ResourceType: resourceKind, ResourceID: resourceID,
		AfterSequence: after, Limit: int32(limit + 1),
	})
	if err != nil {
		return EventPage{}, err
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	page := EventPage{Items: make([]Event, 0, len(rows))}
	for _, row := range rows {
		event, err := s.eventView(row)
		if err != nil {
			return EventPage{}, err
		}
		page.Items = append(page.Items, event)
	}
	if hasMore && len(page.Items) > 0 {
		page.NextCursor = page.Items[len(page.Items)-1].Cursor
	}
	return page, nil
}

func operationView(row dbsqlc.Operation, requestID string) Operation {
	view := Operation{
		Schema: schemaID, Kind: "operation", ID: row.ID, ResourceKind: row.ResourceKind,
		ResourceID: nullableString(row.ResourceID), Phase: row.Phase, State: row.State,
		Progress: int(row.Progress), Retrying: row.Retrying, CorrelationID: row.CorrelationID,
		CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC(),
	}
	if view.State == "cancelled" {
		view.State = "canceled"
	}
	if view.State == "uncertain" {
		view.State = "failed"
		if !row.ErrorCode.Valid {
			row.ErrorCode = sql.NullString{String: "operation_outcome_uncertain", Valid: true}
		}
	}
	if row.NextRetryAt.Valid {
		next := row.NextRetryAt.Time.UTC()
		view.NextRetryAt = &next
	}
	if row.ErrorCode.Valid {
		view.Error = &APIError{
			Schema: schemaID, Kind: "error", Code: row.ErrorCode.String, Component: "control", Message: "The operation did not complete.",
			Outcome: row.Outcome, Retryable: row.Retrying, RepairAction: "inspect_operation",
			RequestID: requestID, CorrelationID: row.CorrelationID,
		}
	}
	return view
}

// OperationView is the shared safe projection used by every preview and
// durable tunnel resource endpoint. Keeping the conversion here prevents
// uncertain outcomes and typed error details from drifting between services.
func OperationView(row dbsqlc.Operation, requestID string) Operation {
	return operationView(row, requestID)
}

func (s *Service) eventView(row dbsqlc.AuditEvent) (Event, error) {
	if !row.CursorSequence.Valid || !row.AccountID.Valid || !row.ActorID.Valid || !row.CorrelationID.Valid {
		return Event{}, fmt.Errorf("invalid v1 event row %q", row.ID)
	}
	var metadata map[string]any
	decoder := json.NewDecoder(bytes.NewReader(row.Metadata))
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return Event{}, fmt.Errorf("decode event metadata: %w", err)
	}
	safe, err := SafeMetadata(metadata)
	if err != nil {
		return Event{}, err
	}
	cursor, err := s.cursors.Encode(EventPosition{
		AccountID: row.AccountID.String, ResourceKind: row.ResourceType,
		ResourceID: row.ResourceID, Sequence: row.CursorSequence.Int64,
	})
	if err != nil {
		return Event{}, err
	}
	return Event{
		Schema: schemaID, Kind: "event", ID: row.ID, Cursor: cursor, EventType: row.EventType,
		ResourceKind: row.ResourceType, ResourceID: row.ResourceID, OccurredAt: row.CreatedAt.UTC(),
		Actor:         EventActor{Type: eventActorType(row.ActorType), ID: row.ActorID.String},
		CorrelationID: row.CorrelationID.String, SafeMetadata: safe,
	}, nil
}

func actorType(actor Actor) string {
	if actor.HostID != "" {
		return "host"
	}
	if actor.Role == "system_worker" {
		return "system"
	}
	return "user"
}

func eventActorType(value string) string {
	switch value {
	case "host", "system", "edge", "user":
		return value
	case "admin":
		return "user"
	default:
		return "system"
	}
}

func resourceScope(resourceKind string) string {
	switch resourceKind {
	case "preview_lease":
		return "previews"
	case "tunnel", "route", "domain_binding", "connector", "config_generation":
		return "tunnels"
	case "operation":
		return "operations"
	default:
		return ""
	}
}

func nullableString(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func newID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(value[:])
}
