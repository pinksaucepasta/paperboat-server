# Control-Plane Credential Rotation

This runbook covers Paperboat mint signing keys and the revocation snapshots consumed by
`paperboat-tunnel` and helpers. Never paste private key material into tickets, logs, API
requests, or the workspace.

## Planned rotation

1. Generate the new Ed25519 key through the approved secret-management path.
2. Add the new key to the configured mint secret set while retaining the previous key, set
   the configured active key ID to the new ID, and deploy `paperboat-server`.
3. Confirm `/.well-known/jwks.json` contains both key IDs and new credentials use the new
   ID. Do not remove the prior public key during the overlap window.
4. Confirm tunnel diagnostics remain ready and revocation refresh errors stay at zero for
   at least the maximum issued credential lifetime plus clock skew.
5. Remove the retired private key from server signing configuration. Retain its public key
   until every credential it signed has expired.

## Emergency revocation

1. Stop issuing with the affected key by activating an uncompromised configured key and
   deploying the server.
2. As an authenticated administrator with a current CSRF token, send
   `POST /api/admin/mint/signing-keys/{key_id}/revoke` with an `Idempotency-Key` header and
   JSON body `{"reason":"<bounded operator reason>"}`.
3. Verify `GET /v1/trust/revocations` through the private edge-control identity contains
   the key ID in `key_ids`. Do not expose the edge-control credential in command history.
4. Confirm tunnel instances refresh within one control interval. New use fails closed after
   three missed intervals when revocation state cannot be refreshed.
5. Search redacted audit events for `mint.signing_key_revoked`, correlating the request and
   operation IDs. Verify no private key, token, or credential body appears in the event.

## Recovery

- If the server is unavailable, restore it before changing consumer trust files. Consumers
  retain the last valid snapshot only until the freshness deadline and then reject new
  credentials.
- If a malformed snapshot is served, stop the faulty artifact, restore the last compatible
  server artifact, and verify a valid snapshot refresh. Never hand-edit a snapshot to remove
  a revocation.
- If the wrong key was revoked, do not delete or roll back the revocation record. Introduce
  a new key ID and rotate forward; key IDs are never reused.
- Rollback may restore an older server binary only if it can read the additive revocation
  table and continues serving all recorded revocations.

Record deployment IDs, affected key IDs, first/last observed refresh times, audit event IDs,
and recovery actions in the incident record. Do not record secret values.
