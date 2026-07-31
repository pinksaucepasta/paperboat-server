-- +goose Up
CREATE TABLE user_transfer_destination_defaults (
  user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  machine_id text NOT NULL REFERENCES user_machines(id) ON DELETE CASCADE,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE project_terminal_sessions
  ADD COLUMN transfer_destination_machine_id text REFERENCES user_machines(id) ON DELETE SET NULL;

ALTER TABLE user_machine_terminal_sessions
  ADD COLUMN transfer_destination_machine_id text REFERENCES user_machines(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE user_machine_terminal_sessions DROP COLUMN transfer_destination_machine_id;
ALTER TABLE project_terminal_sessions DROP COLUMN transfer_destination_machine_id;
DROP TABLE user_transfer_destination_defaults;
