-- +goose Up

SET LOCAL search_path TO paperboat;

CREATE TABLE agentunnel_cleanup_outbox (
    id text PRIMARY KEY,
    project_id text NOT NULL UNIQUE,
    action text NOT NULL,
    reason text NOT NULL,
    propagated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_agentunnel_cleanup_outbox_pending
ON agentunnel_cleanup_outbox(created_at)
WHERE propagated_at IS NULL;

-- +goose Down
-- Forward-only migration.
