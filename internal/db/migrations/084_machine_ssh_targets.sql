-- +goose Up
CREATE TABLE machine_ssh_targets (
  user_machine_id text PRIMARY KEY REFERENCES user_machines(id) ON DELETE CASCADE,
  machine_generation bigint NOT NULL CHECK (machine_generation > 0),
  os_user text NOT NULL CHECK (
    octet_length(os_user) BETWEEN 1 AND 255
    AND os_user = btrim(os_user)
    AND os_user !~ '[[:cntrl:][:space:]@]'
    AND left(os_user, 1) <> '-'
  ),
  target_port integer NOT NULL DEFAULT 22 CHECK (target_port BETWEEN 1 AND 65535),
  reconciliation_version bigint NOT NULL DEFAULT 1 CHECK (reconciliation_version > 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (updated_at >= created_at)
);

-- +goose Down
SELECT 1;
