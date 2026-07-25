-- +goose Up

SET LOCAL search_path TO paperboat;

ALTER TABLE access_sessions
ADD COLUMN IF NOT EXISTS helper_terminal_session_id text,
ADD COLUMN IF NOT EXISTS helper_file_session_id text,
ADD COLUMN IF NOT EXISTS helper_revoked_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_access_sessions_helper_terminal
ON access_sessions(helper_terminal_session_id)
WHERE helper_terminal_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_access_sessions_helper_file
ON access_sessions(helper_file_session_id)
WHERE helper_file_session_id IS NOT NULL;

-- +goose Down
-- Forward-only migration.
