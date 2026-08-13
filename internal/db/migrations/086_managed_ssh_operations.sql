-- +goose Up
CREATE TABLE managed_ssh_operations (
  operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$'),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation_kind text NOT NULL CHECK (operation_kind IN
    ('client_key_register', 'client_key_revoke', 'target_register', 'target_update',
     'host_keys_observe', 'host_keys_promote')),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  resource_id text NOT NULL CHECK (octet_length(resource_id) BETWEEN 1 AND 256),
  result_revision bigint NOT NULL CHECK (result_revision > 0),
  created_at timestamptz NOT NULL
);

-- +goose Down
SELECT 1;
