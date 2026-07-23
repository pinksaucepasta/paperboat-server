-- +goose Up
ALTER TABLE control_previews
  ADD COLUMN helper_observation_revision bigint NOT NULL DEFAULT 0 CHECK (helper_observation_revision >= 0),
  ADD COLUMN helper_observed_at timestamptz;

-- +goose Down
ALTER TABLE control_previews
  DROP COLUMN IF EXISTS helper_observed_at,
  DROP COLUMN IF EXISTS helper_observation_revision;
