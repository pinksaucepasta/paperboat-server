-- +goose Up
ALTER TABLE terminal_session_operations
  DROP CONSTRAINT terminal_session_operations_state_check;
ALTER TABLE terminal_session_operations
  ADD CONSTRAINT terminal_session_operations_state_check
  CHECK (state IN ('pending','applied','failed','superseded'));

-- +goose Down
UPDATE terminal_session_operations
SET state='failed',last_error=coalesce(last_error,'superseded before migration rollback')
WHERE state='superseded';
ALTER TABLE terminal_session_operations
  DROP CONSTRAINT terminal_session_operations_state_check;
ALTER TABLE terminal_session_operations
  ADD CONSTRAINT terminal_session_operations_state_check
  CHECK (state IN ('pending','applied','failed'));
