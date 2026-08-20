-- +goose Up
ALTER TABLE user_machine_pairings
  ADD COLUMN ssh_user text,
  ADD COLUMN ssh_port integer;

ALTER TABLE user_machine_pairings
  ADD CONSTRAINT user_machine_pairings_ssh_target_check CHECK (
    (ssh_user IS NULL AND ssh_port IS NULL) OR
    (ssh_user IS NOT NULL AND ssh_user = btrim(ssh_user) AND length(ssh_user) BETWEEN 1 AND 128
      AND ssh_user !~ '[\x00\r\n]' AND ssh_port BETWEEN 1 AND 65535)
  );

-- +goose Down
ALTER TABLE user_machine_pairings DROP CONSTRAINT user_machine_pairings_ssh_target_check;
ALTER TABLE user_machine_pairings DROP COLUMN ssh_port, DROP COLUMN ssh_user;
