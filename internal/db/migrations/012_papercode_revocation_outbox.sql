-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE papercode_revocation_outbox (
    id text PRIMARY KEY,
    user_id text NOT NULL,
    project_id text NOT NULL,
    client_session_id text NOT NULL,
    http_base_url text NOT NULL,
    session_ids text[] NOT NULL CHECK (cardinality(session_ids) > 0),
    reason text NOT NULL,
    propagated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_papercode_revocation_outbox_pending
ON papercode_revocation_outbox(created_at)
WHERE propagated_at IS NULL;

-- +goose Down
-- Forward-only migration.
