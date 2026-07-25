-- +goose Up
ALTER TABLE terminal_session_operations
  DROP CONSTRAINT IF EXISTS terminal_session_operations_terminal_session_id_operation_s_key;
ALTER TABLE terminal_session_operations
  DROP CONSTRAINT IF EXISTS terminal_session_ops_session_operation_state_key;
CREATE UNIQUE INDEX IF NOT EXISTS terminal_session_operations_one_pending
  ON terminal_session_operations (terminal_session_id, operation)
  WHERE state = 'pending';

ALTER TABLE user_machine_terminal_session_operations
  DROP CONSTRAINT IF EXISTS user_machine_terminal_se_terminal_session_id_operation_key;
ALTER TABLE user_machine_terminal_session_operations
  DROP CONSTRAINT IF EXISTS user_machine_terminal_ops_session_operation_state_key;
CREATE UNIQUE INDEX IF NOT EXISTS user_machine_terminal_session_operations_one_pending
  ON user_machine_terminal_session_operations (terminal_session_id, operation)
  WHERE state = 'pending';

-- +goose Down
-- Forward-only repair: restoring the stale constraints would break repeatable operations.
