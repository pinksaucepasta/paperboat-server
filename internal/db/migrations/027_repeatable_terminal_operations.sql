-- +goose Up
ALTER TABLE terminal_session_operations
  DROP CONSTRAINT terminal_session_operations_terminal_session_id_operation_s_key;
CREATE UNIQUE INDEX terminal_session_operations_one_pending
  ON terminal_session_operations (terminal_session_id, operation)
  WHERE state = 'pending';

ALTER TABLE user_machine_terminal_session_operations
  DROP CONSTRAINT user_machine_terminal_session_terminal_session_id_operation_key;
CREATE UNIQUE INDEX user_machine_terminal_session_operations_one_pending
  ON user_machine_terminal_session_operations (terminal_session_id, operation)
  WHERE state = 'pending';

-- +goose Down
DROP INDEX IF EXISTS user_machine_terminal_session_operations_one_pending;
ALTER TABLE user_machine_terminal_session_operations
  ADD CONSTRAINT user_machine_terminal_ops_session_operation_state_key
  UNIQUE (terminal_session_id, operation, state);

DROP INDEX IF EXISTS terminal_session_operations_one_pending;
ALTER TABLE terminal_session_operations
  ADD CONSTRAINT terminal_session_ops_session_operation_state_key
  UNIQUE (terminal_session_id, operation, state);
