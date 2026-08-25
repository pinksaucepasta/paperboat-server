-- +goose Up
ALTER TABLE user_machine_pairings
  ADD COLUMN authenticated_setup_cli_session_id text REFERENCES cli_client_sessions(id) ON DELETE CASCADE,
  ADD COLUMN authenticated_setup_operation_id text,
  ADD COLUMN authenticated_setup_generation bigint,
  ADD COLUMN authenticated_setup_mode text,
  ADD COLUMN authenticated_setup_helper_enrollment_id text REFERENCES control_helper_enrollments(id) ON DELETE SET NULL;

ALTER TABLE user_machine_pairings
  ADD CONSTRAINT user_machine_pairings_authenticated_setup_check CHECK (
    (authenticated_setup_cli_session_id IS NULL
      AND authenticated_setup_operation_id IS NULL
      AND authenticated_setup_generation IS NULL
      AND authenticated_setup_mode IS NULL
      AND authenticated_setup_helper_enrollment_id IS NULL)
    OR
    (authenticated_setup_cli_session_id IS NOT NULL
      AND authenticated_setup_operation_id IS NOT NULL
      AND length(authenticated_setup_operation_id) BETWEEN 8 AND 128
      AND authenticated_setup_generation IS NOT NULL
      AND authenticated_setup_generation >= 1
      AND authenticated_setup_mode IS NOT NULL
      AND authenticated_setup_mode = 'host'
      AND approved_by_user_id IS NOT NULL
      AND user_machine_id IS NOT NULL
      AND state IN ('approved', 'consumed', 'expired'))
  );

CREATE UNIQUE INDEX user_machine_pairings_authenticated_setup_operation
  ON user_machine_pairings(authenticated_setup_cli_session_id, authenticated_setup_operation_id)
  WHERE authenticated_setup_cli_session_id IS NOT NULL;

CREATE UNIQUE INDEX user_machine_pairings_authenticated_setup_helper_enrollment
  ON user_machine_pairings(authenticated_setup_helper_enrollment_id)
  WHERE authenticated_setup_helper_enrollment_id IS NOT NULL
    AND state IN ('approved', 'consumed');

-- +goose Down
DROP INDEX IF EXISTS user_machine_pairings_authenticated_setup_helper_enrollment;
DROP INDEX IF EXISTS user_machine_pairings_authenticated_setup_operation;
ALTER TABLE user_machine_pairings DROP CONSTRAINT user_machine_pairings_authenticated_setup_check;
ALTER TABLE user_machine_pairings
  DROP COLUMN authenticated_setup_helper_enrollment_id,
  DROP COLUMN authenticated_setup_mode,
  DROP COLUMN authenticated_setup_generation,
  DROP COLUMN authenticated_setup_operation_id,
  DROP COLUMN authenticated_setup_cli_session_id;
