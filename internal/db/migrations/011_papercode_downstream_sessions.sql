-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE access_sessions
ADD COLUMN IF NOT EXISTS papercode_terminal_session_id text,
ADD COLUMN IF NOT EXISTS papercode_file_session_id text,
ADD COLUMN IF NOT EXISTS papercode_revoked_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_access_sessions_papercode_terminal
ON access_sessions(papercode_terminal_session_id)
WHERE papercode_terminal_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_access_sessions_papercode_file
ON access_sessions(papercode_file_session_id)
WHERE papercode_file_session_id IS NOT NULL;

-- +goose Down
-- Forward-only migration.
