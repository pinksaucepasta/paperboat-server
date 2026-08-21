-- +goose Up
ALTER TABLE peer_endpoint_enrollment_requests
  ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'machine';

ALTER TABLE peer_endpoint_enrollment_requests
  DROP CONSTRAINT IF EXISTS peer_endpoint_enrollment_requests_endpoint_id_fkey;

-- +goose Down
SELECT 1;
