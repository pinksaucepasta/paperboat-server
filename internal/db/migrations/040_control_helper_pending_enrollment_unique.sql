-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM control_helper_enrollments
    WHERE state = 'pending' AND revoked_at IS NULL
    GROUP BY environment_id HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'cannot enforce pending helper enrollment uniqueness: duplicates exist';
  END IF;
END $$;
-- +goose StatementEnd

CREATE UNIQUE INDEX IF NOT EXISTS control_helper_enrollments_one_pending_per_environment
  ON control_helper_enrollments(environment_id)
  WHERE state = 'pending' AND revoked_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS control_helper_enrollments_one_pending_per_environment;
