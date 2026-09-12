-- +goose Up
CREATE INDEX audit_events_team_activity_cursor ON audit_events(resource_id,cursor_sequence DESC) WHERE resource_type='team';
CREATE INDEX audit_events_team_activity_expiry ON audit_events(created_at,id) WHERE resource_type='team';

-- Team administrative metadata is retained for 90 days. Other audit streams
-- retain their existing append-only policy; no caller may update audit rows.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND OLD.resource_type = 'team'
     AND OLD.created_at < now() - interval '90 days' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit events are append-only within retention' USING ERRCODE = '55000';
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX audit_events_team_activity_cursor;
DROP INDEX audit_events_team_activity_expiry;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;
-- +goose StatementEnd
