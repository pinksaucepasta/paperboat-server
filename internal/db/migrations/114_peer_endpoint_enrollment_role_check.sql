-- +goose Up
-- Migration 090 creates this constraint for fresh databases. Databases that
-- applied the original form of migration 090 receive the role column later in
-- migration 110, so add the same invariant without rewriting applied history.
ALTER TABLE peer_endpoint_enrollment_requests
  DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_role_check;

ALTER TABLE peer_endpoint_enrollment_requests
  ADD CONSTRAINT peer_endpoint_enrollment_requests_role_check
  CHECK (role IN ('machine','cli')) NOT VALID;

ALTER TABLE peer_endpoint_enrollment_requests
  VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_role_check;

-- +goose Down
-- This invariant is also part of the fresh schema in migration 090. Do not
-- remove it when rolling back only the compatibility migration.
SELECT 1;
