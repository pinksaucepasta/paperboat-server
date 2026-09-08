-- +goose Up

-- One authenticated CLI session owns exactly one device signing identity.
-- Exact enrollment retries reuse that row; a session cannot mint additional
-- signing authorities under different public keys.
CREATE UNIQUE INDEX account_e2ee_keys_cli_session_unique
  ON account_e2ee_keys (cli_client_session_id)
  WHERE cli_client_session_id IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS account_e2ee_keys_cli_session_unique;
