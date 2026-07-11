package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorSystem ActorType = "system"
	ActorAdmin  ActorType = "admin"
)

type Event struct {
	ID             string
	ActorUserID    string
	ActorType      ActorType
	EventType      string
	ResourceType   string
	ResourceID     string
	IdempotencyKey string
	Metadata       map[string]any
	CreatedAt      time.Time
}

type Writer struct {
	db *db.DB
}

func NewWriter(store *db.DB) *Writer {
	return &Writer{db: store}
}

func (w *Writer) Write(ctx context.Context, event Event) error {
	if w == nil || w.db == nil {
		return nil
	}
	return write(ctx, w.db.Queries(), event)
}

func (w *Writer) WriteTx(ctx context.Context, tx *db.Tx, event Event) error {
	if w == nil || tx == nil {
		return nil
	}
	return write(ctx, tx.Queries(), event)
}

func write(ctx context.Context, q *dbsqlc.Queries, event Event) error {
	if event.ID == "" {
		event.ID = newID("aud")
	}
	if event.ActorType == "" {
		event.ActorType = ActorSystem
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	err = q.InsertAuditEvent(ctx, dbsqlc.InsertAuditEventParams{ID: event.ID, ActorUserID: event.ActorUserID, ActorType: string(event.ActorType), EventType: event.EventType, ResourceType: event.ResourceType, ResourceID: event.ResourceID, IdempotencyKey: event.IdempotencyKey, Metadata: metadata})
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

type Query struct {
	Limit        int
	ResourceType string
	ResourceID   string
	ActorUserID  string
}

func (w *Writer) List(ctx context.Context, query Query) ([]Event, error) {
	limit := query.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := w.db.Queries().ListAuditEvents(ctx, dbsqlc.ListAuditEventsParams{ResourceType: query.ResourceType, ResourceID: query.ResourceID, ActorUserID: query.ActorUserID, RowLimit: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	events := make([]Event, 0, len(rows))
	for _, row := range rows {
		event := Event{ID: row.ID, ActorUserID: row.ActorUserID, ActorType: ActorType(row.ActorType), EventType: row.EventType, ResourceType: row.ResourceType, ResourceID: row.ResourceID, IdempotencyKey: row.IdempotencyKey, CreatedAt: row.CreatedAt}
		if err := json.Unmarshal(row.Metadata, &event.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal audit metadata: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
