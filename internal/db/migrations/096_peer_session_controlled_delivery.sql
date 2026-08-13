-- +goose Up
ALTER TABLE peer_session_intents
  ADD COLUMN controlled_delivered_at timestamptz;

CREATE INDEX peer_session_intents_controlled_delivery_idx
  ON peer_session_intents(controlled_certificate_fingerprint, controlled_delivered_at, created_at, id)
  WHERE state = 'active';

-- +goose Down
DROP INDEX peer_session_intents_controlled_delivery_idx;
ALTER TABLE peer_session_intents DROP COLUMN controlled_delivered_at;
