-- +goose Up
CREATE TABLE control_config_sync_statuses (
  environment_id text PRIMARY KEY REFERENCES control_environments(id) ON DELETE CASCADE,
  repository_id text NOT NULL REFERENCES control_config_repositories(id) ON DELETE CASCADE,
  assignment_id text NOT NULL,
  helper_id text NOT NULL,
  helper_generation bigint NOT NULL CHECK (helper_generation > 0),
  warning_revision text NOT NULL,
  policy_revision text NOT NULL,
  key_version bigint NOT NULL CHECK (key_version >= 0),
  sync_revision bigint NOT NULL CHECK (sync_revision >= 0),
  state text NOT NULL,
  remote_revision text,
  lease_id text,
  fencing_token bigint,
  pending_path_count integer NOT NULL DEFAULT 0 CHECK (pending_path_count >= 0),
  classifier_pending jsonb NOT NULL DEFAULT '[]'::jsonb,
  skipped jsonb NOT NULL DEFAULT '[]'::jsonb,
  conflicts jsonb NOT NULL DEFAULT '[]'::jsonb,
  error_code text,
  recovery_actions jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_attempt_at timestamptz,
  last_successful_at timestamptz,
  helper_updated_at timestamptz NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  CHECK (state IN ('disabled','consent_required','restoring','watching','pending','syncing','healthy','warning','conflict','offline','revoked','error','sync_uncertain')),
  CHECK (fencing_token IS NULL OR (fencing_token > 0 AND lease_id IS NOT NULL)),
  CHECK (jsonb_typeof(classifier_pending) = 'array' AND jsonb_typeof(skipped) = 'array' AND jsonb_typeof(conflicts) = 'array' AND jsonb_typeof(recovery_actions) = 'array')
);
CREATE INDEX control_config_sync_statuses_repository_state
  ON control_config_sync_statuses(repository_id, state, observed_at);

CREATE TABLE control_config_sync_status_history (
  environment_id text NOT NULL REFERENCES control_environments(id) ON DELETE CASCADE,
  sync_revision bigint NOT NULL,
  repository_id text NOT NULL,
  assignment_id text NOT NULL,
  helper_id text NOT NULL,
  helper_generation bigint NOT NULL,
  state text NOT NULL,
  error_code text,
  remote_revision text,
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment_id, sync_revision)
);

-- +goose Down
DROP TABLE IF EXISTS control_config_sync_status_history;
DROP TABLE IF EXISTS control_config_sync_statuses;
