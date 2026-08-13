-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN update_health text NOT NULL DEFAULT 'unknown'
    CHECK (update_health IN ('unknown','healthy','recovery_required'));

-- +goose Down
ALTER TABLE user_machines DROP COLUMN IF EXISTS update_health;
