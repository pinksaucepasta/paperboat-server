package teams

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// Team activity is administrative metadata. Retention is independent of resource lifetime.
const ActivityRetention = 90 * 24 * time.Hour
const DefaultActivityLimit = 50
const MaximumActivityLimit = 200
const MaximumActivityMetadataBytes = 4096

type ActivityItem struct {
	ID           string         `json:"id"`
	ActorAccount string         `json:"actor_account"`
	Action       string         `json:"action"`
	CreatedAt    time.Time      `json:"created_at"`
	Metadata     map[string]any `json:"metadata"`
}
type ActivityPage struct {
	Items      []ActivityItem `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

func activityCursor(team string, sequence int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(team + ":" + strconv.FormatInt(sequence, 10)))
}
func parseActivityCursor(team, cursor string) (int64, error) {
	if cursor == "" {
		return 0, nil
	}
	if len(cursor) > 512 {
		return 0, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrInvalid
	}
	prefix := team + ":"
	if !strings.HasPrefix(string(raw), prefix) {
		return 0, ErrInvalid
	}
	n, err := strconv.ParseInt(strings.TrimPrefix(string(raw), prefix), 10, 64)
	if err != nil || n <= 0 || activityCursor(team, n) != cursor {
		return 0, ErrInvalid
	}
	return n, nil
}

// activityMetadata projects known metadata only. Historical unknown keys are never returned.
func activityMetadata(input map[string]any, strict bool) (map[string]any, error) {
	out := make(map[string]any)
	for key, value := range input {
		switch key {
		case "generation", "target_account", "recipient_account", "sender_account", "role", "resource_kind", "resource_id", "permission", "active", "machine_id", "audience", "capabilities", "terminal_session_id", "action", "access_session_id", "attachment_id", "request_id", "source_machine_id", "destination_machine_id", "status", "decision", "repository_id", "version", "published_revision", "assignment_id", "default_version", "previous_owner", "new_owner", "adopted_version":
		default:
			if strict {
				return nil, ErrInvalid
			}
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > 1024 {
			return nil, ErrInvalid
		}
		switch v := value.(type) {
		case string:
			if len(v) > 512 || strings.ContainsAny(v, "\r\n\x00") {
				return nil, ErrInvalid
			}
		case bool, int, int32, int64, uint, uint32, uint64, float64, json.Number:
		case []string:
			if len(v) > 32 {
				return nil, ErrInvalid
			}
			for _, s := range v {
				if len(s) > 64 || strings.ContainsAny(s, "\r\n\x00") {
					return nil, ErrInvalid
				}
			}
		case []any:
			if key != "capabilities" || len(v) > 32 {
				return nil, ErrInvalid
			}
			for _, item := range v {
				s, ok := item.(string)
				if !ok || len(s) > 64 || strings.ContainsAny(s, "\r\n\x00") {
					return nil, ErrInvalid
				}
			}
		default:
			return nil, ErrInvalid
		}
		out[key] = value
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > MaximumActivityMetadataBytes {
		return nil, ErrInvalid
	}
	return out, nil
}

func (s *Service) Activity(ctx context.Context, account, team, cursor string, limit int) (ActivityPage, error) {
	out := ActivityPage{Items: []ActivityItem{}}
	if !validID(team) || limit < 0 || limit > MaximumActivityLimit {
		return out, ErrInvalid
	}
	if limit == 0 {
		limit = DefaultActivityLimit
	}
	before, err := parseActivityCursor(team, cursor)
	if err != nil {
		return out, err
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		// Serialize authorization with membership/deletion changes for every page.
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		t, err := ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if t.Deleted {
			return ErrNotFound
		}
		m, ok := member(t, account)
		if !ok || !m.Active {
			return ErrNotFound
		}
		if account != t.OwnerAccount && m.Role != "admin" {
			return ErrForbidden
		}
		rows, err := tx.Query(ctx, `SELECT id,coalesce(actor_user_id,''),event_type,created_at,metadata,cursor_sequence FROM audit_events WHERE resource_type='team' AND resource_id=$1 AND created_at>=now()-interval '90 days' AND ($2::bigint=0 OR cursor_sequence<$2) ORDER BY cursor_sequence DESC LIMIT $3`, team, before, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		var last int64
		for rows.Next() {
			if len(out.Items) == limit {
				out.NextCursor = activityCursor(team, last)
				break
			}
			var item ActivityItem
			var raw []byte
			if err := rows.Scan(&item.ID, &item.ActorAccount, &item.Action, &item.CreatedAt, &raw, &last); err != nil {
				return err
			}
			var metadata map[string]any
			if err := json.Unmarshal(raw, &metadata); err != nil {
				return err
			}
			item.Metadata, err = activityMetadata(metadata, false)
			if err != nil {
				return err
			}
			item.Action = strings.TrimPrefix(item.Action, "team.")
			out.Items = append(out.Items, item)
		}
		return rows.Err()
	})
	return out, err
}

// PruneActivity removes a bounded expired batch; the database trigger independently
// enforces the same retention boundary while rejecting all updates and fresh deletions.
func (s *Service) PruneActivity(ctx context.Context) (int64, error) {
	result, err := s.db.SQL().ExecContext(ctx, `DELETE FROM paperboat.audit_events WHERE id IN (SELECT id FROM paperboat.audit_events WHERE resource_type='team' AND created_at<now()-interval '90 days' ORDER BY created_at,id LIMIT 200 FOR UPDATE SKIP LOCKED)`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
