-- +goose Up
CREATE TABLE diagnostic_upload_intents (
  id text PRIMARY KEY CHECK (id ~ '^diag_[A-Za-z0-9_-]{16,128}$'),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cli_client_session_id text NOT NULL REFERENCES cli_client_sessions(id) ON DELETE CASCADE,
  operation_key text NOT NULL CHECK (octet_length(operation_key) BETWEEN 16 AND 200),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  correlation_id text NOT NULL UNIQUE CHECK (correlation_id ~ '^pb-[a-f0-9]{32}$'),
  object_key text NOT NULL UNIQUE CHECK (object_key ~ '^diagnostics/[A-Za-z0-9_-]{16,128}/[A-Za-z0-9_-]{16,128}\.zip$'),
  expected_bytes bigint NOT NULL CHECK (expected_bytes BETWEEN 1 AND 26214400),
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  categories text[] NOT NULL CHECK (
    cardinality(categories) BETWEEN 1 AND 16
    AND categories <@ ARRAY['manifest', 'recent_events', 'redacted_events', 'status']::text[]
  ),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'uploaded', 'expired')),
  expires_at timestamptz NOT NULL,
  retain_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  uploaded_at timestamptz,
  object_etag text CHECK (object_etag IS NULL OR octet_length(object_etag) BETWEEN 1 AND 256),
  UNIQUE (user_id, operation_key),
  CHECK (expires_at > created_at),
  CHECK (retain_until >= expires_at),
  CHECK ((state = 'uploaded') = (uploaded_at IS NOT NULL)),
  CHECK ((state = 'uploaded') = (object_etag IS NOT NULL)),
  CHECK (uploaded_at IS NULL OR uploaded_at BETWEEN created_at AND retain_until)
);

CREATE INDEX diagnostic_upload_intents_expiry_idx
  ON diagnostic_upload_intents(expires_at, id) WHERE state = 'pending';
CREATE INDEX diagnostic_upload_intents_retention_idx
  ON diagnostic_upload_intents(retain_until, id) WHERE state IN ('uploaded', 'expired');

-- +goose Down
DROP TABLE diagnostic_upload_intents;
