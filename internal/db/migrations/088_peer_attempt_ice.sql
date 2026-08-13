-- +goose Up
ALTER TABLE peer_session_intents
  ADD COLUMN ice_credentials_ciphertext bytea,
  ADD COLUMN edge_pool text,
  ADD COLUMN signaling_host text,
  ADD COLUMN stun_host text,
  ADD COLUMN stun_port integer;

ALTER TABLE peer_session_intents
  ADD CONSTRAINT peer_session_intents_descriptor_snapshot_check CHECK (
    (ice_credentials_ciphertext IS NULL AND edge_pool IS NULL AND signaling_host IS NULL AND stun_host IS NULL AND stun_port IS NULL) OR
    (octet_length(ice_credentials_ciphertext) >= 32 AND length(edge_pool) BETWEEN 1 AND 128 AND
     length(signaling_host) BETWEEN 1 AND 253 AND length(stun_host) BETWEEN 1 AND 253 AND
     stun_port BETWEEN 1 AND 65535)
  );

-- +goose Down
ALTER TABLE peer_session_intents DROP CONSTRAINT peer_session_intents_descriptor_snapshot_check;
ALTER TABLE peer_session_intents
  DROP COLUMN stun_port,
  DROP COLUMN stun_host,
  DROP COLUMN signaling_host,
  DROP COLUMN edge_pool,
  DROP COLUMN ice_credentials_ciphertext;
