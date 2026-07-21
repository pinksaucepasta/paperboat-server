-- +goose Up

-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM orchestration_jobs
    GROUP BY idempotency_key HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'orchestration_jobs contains duplicate idempotency keys';
  END IF;
END $$;
-- +goose StatementEnd

CREATE UNIQUE INDEX IF NOT EXISTS orchestration_jobs_idempotency
  ON orchestration_jobs(idempotency_key);

-- +goose Down
DROP INDEX IF EXISTS orchestration_jobs_idempotency;
