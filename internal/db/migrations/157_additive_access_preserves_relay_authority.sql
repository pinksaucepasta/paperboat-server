-- +goose Up
-- Adding a resource expands the next signed configuration but does not withdraw
-- any existing scope. Keep established carriers on their narrower signed grants
-- until normal reauthentication; they cannot authorize the new resource yet.
-- Updates retain the existing withdrawal fence, including lease shortening.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET relay_revocation_generation = CASE WHEN TG_OP = 'INSERT'
        THEN relay_revocation_generation ELSE config_generation + 1 END,
      config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id
    AND endpoint_id IN (NEW.cli_client_session_id, NEW.user_machine_id);
  RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION advance_peer_network_for_access_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE peer_network_identities
  SET relay_revocation_generation = config_generation + 1,
      config_generation = config_generation + 1, updated_at = now()
  WHERE user_id = NEW.user_id
    AND endpoint_id IN (NEW.cli_client_session_id, NEW.user_machine_id);
  RETURN NEW;
END $$;
-- +goose StatementEnd
