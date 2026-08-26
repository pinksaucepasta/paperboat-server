-- +goose Up
-- Deleted machines are historical records and must not reserve a runtime
-- identity forever. A fresh dashboard enrollment may legitimately reuse the
-- same physical machine after the old record has been removed.
DROP INDEX IF EXISTS user_machines_public_identity_key;
CREATE UNIQUE INDEX user_machines_public_identity_key
  ON user_machines(public_identity_key)
  WHERE public_identity_key IS NOT NULL AND deleted_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS user_machines_public_identity_key;
CREATE UNIQUE INDEX user_machines_public_identity_key
  ON user_machines(public_identity_key)
  WHERE public_identity_key IS NOT NULL;
