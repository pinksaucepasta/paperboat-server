package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
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
	return write(ctx, w.db.SQL().ExecContext, event)
}

type execContextFunc func(context.Context, string, ...any) (sql.Result, error)

func (w *Writer) WriteTx(ctx context.Context, tx *db.Tx, event Event) error {
	if w == nil || tx == nil {
		return nil
	}
	return write(ctx, tx.Exec, event)
}

func write(ctx context.Context, exec execContextFunc, event Event) error {
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
	_, err = exec(ctx, `
INSERT INTO paperboat.audit_events
	(id, actor_user_id, actor_type, event_type, resource_type, resource_id, idempotency_key, metadata, created_at)
VALUES
	($1, nullif($2, ''), $3, $4, $5, $6, nullif($7, ''), $8::jsonb, now())
ON CONFLICT (idempotency_key) DO NOTHING`,
		event.ID, event.ActorUserID, string(event.ActorType), event.EventType, event.ResourceType,
		event.ResourceID, event.IdempotencyKey, string(metadata))
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
	rows, err := w.db.SQL().QueryContext(ctx, `
SELECT id, coalesce(actor_user_id, ''), actor_type, event_type, resource_type, resource_id,
       coalesce(idempotency_key, ''), metadata, created_at
FROM paperboat.audit_events
WHERE ($1 = '' OR resource_type = $1)
  AND ($2 = '' OR resource_id = $2)
  AND ($3 = '' OR actor_user_id = $3)
ORDER BY created_at DESC
LIMIT $4`, query.ResourceType, query.ResourceID, query.ActorUserID, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var event Event
		var actorType string
		var metadata []byte
		if err := rows.Scan(&event.ID, &event.ActorUserID, &actorType, &event.EventType, &event.ResourceType, &event.ResourceID, &event.IdempotencyKey, &metadata, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		event.ActorType = ActorType(actorType)
		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal audit metadata: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
