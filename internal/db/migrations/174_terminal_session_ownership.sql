-- +goose Up
ALTER TABLE user_machine_terminal_sessions ADD COLUMN owner_account text REFERENCES users(id);
UPDATE user_machine_terminal_sessions s SET owner_account=m.user_id FROM user_machines m WHERE m.id=s.user_machine_id;
ALTER TABLE user_machine_terminal_sessions ALTER COLUMN owner_account SET NOT NULL;
DROP INDEX user_machine_terminal_sessions_active_name;
DROP INDEX user_machine_terminal_sessions_one_default;
DROP INDEX user_machine_terminal_sessions_idempotency;
CREATE UNIQUE INDEX user_machine_terminal_sessions_active_name ON user_machine_terminal_sessions(user_machine_id,owner_account,lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX user_machine_terminal_sessions_one_default ON user_machine_terminal_sessions(user_machine_id,owner_account) WHERE is_default AND deleted_at IS NULL;
CREATE UNIQUE INDEX user_machine_terminal_sessions_idempotency ON user_machine_terminal_sessions(user_machine_id,owner_account,idempotency_key) WHERE idempotency_key IS NOT NULL;

-- +goose Down
DROP INDEX user_machine_terminal_sessions_active_name;
DROP INDEX user_machine_terminal_sessions_one_default;
DROP INDEX user_machine_terminal_sessions_idempotency;
CREATE UNIQUE INDEX user_machine_terminal_sessions_active_name ON user_machine_terminal_sessions(user_machine_id,lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX user_machine_terminal_sessions_one_default ON user_machine_terminal_sessions(user_machine_id) WHERE is_default AND deleted_at IS NULL;
CREATE UNIQUE INDEX user_machine_terminal_sessions_idempotency ON user_machine_terminal_sessions(user_machine_id,idempotency_key) WHERE idempotency_key IS NOT NULL;
ALTER TABLE user_machine_terminal_sessions DROP COLUMN owner_account;
