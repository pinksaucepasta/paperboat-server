-- +goose Up

-- Certificate tombstones must preserve the reason that caused a device
-- removal or account shutdown. The original operations table predated the
-- multi-device key lifecycle and only allowed endpoint removal/compromise.
UPDATE peer_endpoint_certificate_revocations
SET reason = 'endpoint_removed'
WHERE reason NOT IN ('endpoint_removed', 'device_removed', 'account_revoked', 'key_compromise');

ALTER TABLE peer_endpoint_certificate_revocations
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificate_revocations_reason_check,
  ADD CONSTRAINT peer_endpoint_certificate_revocations_reason_check
    CHECK (reason IN ('endpoint_removed', 'device_removed', 'account_revoked', 'key_compromise'));

-- +goose Down

ALTER TABLE peer_endpoint_certificate_revocations
  DROP CONSTRAINT IF EXISTS peer_endpoint_certificate_revocations_reason_check,
  ADD CONSTRAINT peer_endpoint_certificate_revocations_reason_check
    CHECK (reason IN ('endpoint_removed', 'key_compromise'));
