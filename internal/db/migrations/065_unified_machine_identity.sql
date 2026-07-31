-- +goose Up
ALTER TABLE user_machines
  ADD COLUMN setup_roles text[] NOT NULL DEFAULT ARRAY['host']::text[],
  ADD COLUMN public_identity_key text,
  ADD COLUMN installation_generation bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT user_machines_setup_roles_check
    CHECK (setup_roles <@ ARRAY['interactive','host']::text[]),
  ADD CONSTRAINT user_machines_public_identity_key_check
    CHECK (public_identity_key IS NULL OR length(public_identity_key) BETWEEN 40 AND 256),
  ADD CONSTRAINT user_machines_installation_generation_check
    CHECK (installation_generation > 0);

CREATE UNIQUE INDEX user_machines_public_identity_key
  ON user_machines(public_identity_key)
  WHERE public_identity_key IS NOT NULL;

ALTER TABLE user_machine_pairings
  ADD COLUMN public_identity_key text NOT NULL,
  ADD CONSTRAINT user_machine_pairings_public_identity_key_check
    CHECK (length(public_identity_key) BETWEEN 40 AND 256);

-- +goose Down
ALTER TABLE user_machine_pairings
  DROP CONSTRAINT user_machine_pairings_public_identity_key_check,
  DROP COLUMN public_identity_key;

DROP INDEX user_machines_public_identity_key;

ALTER TABLE user_machines
  DROP CONSTRAINT user_machines_installation_generation_check,
  DROP CONSTRAINT user_machines_public_identity_key_check,
  DROP CONSTRAINT user_machines_setup_roles_check,
  DROP COLUMN installation_generation,
  DROP COLUMN public_identity_key,
  DROP COLUMN setup_roles;
