-- +goose Up
ALTER TABLE user_machine_terminal_session_operations
  DROP CONSTRAINT user_machine_terminal_session_operations_state_check;
ALTER TABLE user_machine_terminal_session_operations
  ADD CONSTRAINT user_machine_terminal_session_operations_state_check
  CHECK (state IN ('pending','applied','failed','superseded'));

UPDATE terminal_session_operations operation
SET state='superseded',completed_at=now(),last_error='default terminal sessions retired',updated_at=now()
FROM project_terminal_sessions session
WHERE operation.terminal_session_id=session.id AND session.is_default AND operation.state='pending';

UPDATE user_machine_terminal_session_operations operation
SET state='superseded',completed_at=now(),last_error='default terminal sessions retired',updated_at=now()
FROM user_machine_terminal_sessions session
WHERE operation.terminal_session_id=session.id AND session.is_default AND operation.state='pending';

UPDATE project_terminal_sessions
SET desired_state='deleted',runtime_state='closed',deleted_at=coalesce(deleted_at,now()),updated_at=now()
WHERE is_default AND deleted_at IS NULL;

UPDATE user_machine_terminal_sessions
SET desired_state='deleted',deleted_at=coalesce(deleted_at,now()),updated_at=now()
WHERE is_default AND deleted_at IS NULL;

-- +goose Down
-- Retired runtime history cannot be recreated safely.
