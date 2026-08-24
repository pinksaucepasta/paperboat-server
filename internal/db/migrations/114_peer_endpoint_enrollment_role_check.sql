-- +goose Up
-- Fresh databases receive this invariant from migration 090. Databases that
-- applied the original migration 090 received the role column in migration
-- 110, so enforce the same closed role set without rewriting applied history.
ALTER TABLE peer_endpoint_enrollment_requests
  DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_role_check;

ALTER TABLE peer_endpoint_enrollment_requests
  ADD CONSTRAINT peer_endpoint_enrollment_requests_role_check
  CHECK (role IN ('machine','cli')) NOT VALID;

ALTER TABLE peer_endpoint_enrollment_requests
  VALIDATE CONSTRAINT peer_endpoint_enrollment_requests_role_check;

-- +goose Down
SELECT 1;
