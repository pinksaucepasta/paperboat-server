-- +goose Up
ALTER TABLE peer_session_intents
  DROP CONSTRAINT peer_session_intents_purpose_check;
ALTER TABLE peer_session_intents
  ADD CONSTRAINT peer_session_intents_purpose_check
  CHECK (purpose IN ('interactive', 'private_preview', 'health_probe', 'direct_probe', 'file_transfer_key'));

-- +goose Down
ALTER TABLE peer_session_intents
  DROP CONSTRAINT peer_session_intents_purpose_check;
ALTER TABLE peer_session_intents
  ADD CONSTRAINT peer_session_intents_purpose_check
  CHECK (purpose IN ('interactive', 'direct_probe', 'file_transfer_key'));
