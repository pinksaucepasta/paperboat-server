-- +goose Up
ALTER TABLE user_machines ADD COLUMN alias text;

-- +goose StatementBegin
CREATE FUNCTION assign_user_machine_fallback_alias() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.alias IS NULL THEN
    NEW.alias := 'machine-' || substr(md5(NEW.id), 1, 12);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER user_machines_assign_fallback_alias
BEFORE INSERT ON user_machines
FOR EACH ROW EXECUTE FUNCTION assign_user_machine_fallback_alias();

UPDATE user_machines
SET alias = 'machine-' || substr(md5(id), 1, 12)
WHERE alias IS NULL;

ALTER TABLE user_machines ALTER COLUMN alias SET NOT NULL;
ALTER TABLE user_machines ADD CONSTRAINT user_machines_alias_format CHECK (
  alias ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
);
CREATE UNIQUE INDEX user_machines_active_alias
  ON user_machines(user_id, lower(alias))
  WHERE deleted_at IS NULL;

-- +goose Down
DROP TRIGGER IF EXISTS user_machines_assign_fallback_alias ON user_machines;
DROP FUNCTION IF EXISTS assign_user_machine_fallback_alias();
DROP INDEX IF EXISTS user_machines_active_alias;
ALTER TABLE user_machines DROP CONSTRAINT IF EXISTS user_machines_alias_format;
ALTER TABLE user_machines DROP COLUMN alias;
