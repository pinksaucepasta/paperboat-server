-- +goose Up
SET LOCAL search_path TO paperboat;

CREATE TABLE account_config_keys (
  user_id text PRIMARY KEY REFERENCES users(id), key_version integer NOT NULL,
  recipient text NOT NULL, encrypted_identity bytea NOT NULL,
  previous_key_version integer, previous_recipient text, previous_encrypted_identity bytea,
  created_at timestamptz NOT NULL DEFAULT now(), rotated_at timestamptz
);
CREATE TABLE config_classification_overrides (
  user_id text NOT NULL REFERENCES users(id), normalized_path text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('portable','project_only','exclude')),
  created_by text NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, normalized_path)
);
CREATE TABLE config_classification_cache (
  user_id text NOT NULL REFERENCES users(id), normalized_path text NOT NULL, metadata_hash text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('portable','project_only','exclude','uncertain')),
  source text NOT NULL, confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1), reason_code text NOT NULL,
  policy_revision text NOT NULL, model_revision text NOT NULL, classifier_revision text NOT NULL,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, normalized_path, metadata_hash, policy_revision, model_revision, classifier_revision)
);
ALTER TABLE config_sync_statuses ADD COLUMN classifier_pending jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE config_sync_statuses ADD COLUMN classifier_policy_revision text NOT NULL DEFAULT '';
ALTER TABLE config_sync_statuses ADD COLUMN classifier_model_revision text NOT NULL DEFAULT '';
ALTER TABLE config_sync_statuses ADD COLUMN classifier_health text NOT NULL DEFAULT '';
ALTER TABLE config_sync_statuses ADD COLUMN encryption_key_version integer NOT NULL DEFAULT 0;

-- +goose Down
-- Forward-only migration.
