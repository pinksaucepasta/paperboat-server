# Preview And Tunnel Control-Plane Recovery

Use this runbook for preview leases, durable tunnels, routes, custom domains,
connectors, edge assignments, and certificate distribution. Preserve the last
known-good generation while investigating. Never delete state, manufacture an
acknowledgement, or retry a mutation with a new idempotency key.

## Record safe evidence first

Record the account-safe resource ID, operation ID, request or correlation ID,
desired and observed generations, typed health dimension, first observation,
and next retry time. Do not record credentials, authorization headers, signed
grants, certificate private keys, provider tokens, origin payloads, or private
hostnames.

## Reconciliation or edge-assignment lag

1. Confirm the server worker is running and PostgreSQL is healthy before
   changing any resource.
2. Compare the desired configuration generation with the connector session,
   edge process epoch, assignment generation, and last complete snapshot.
3. Treat an incomplete snapshot, stale acknowledgement, or old process epoch as
   rejected input. Keep the active generation and allow the normal retry path
   to reconcile.
4. If a replacement is staged, require its route and origin readiness before
   draining the old assignment. Never mark the new assignment ready manually.
5. Close the incident only after the durable operation and edge observation
   agree and the retired generation can no longer remove the replacement.

## DNS ownership or certificate failure

1. Separate `dns` health from `certificate` health. A DNS mismatch must not
   withdraw the managed Paperboat hostname or a still-valid certificate.
2. Use the current domain instruction projection. Verify the normalized
   hostname, authoritative CNAME or TXT target, provider proxy mode, DNSSEC,
   and CAA result. Never infer instructions from an edge node.
3. For a customer-owned domain, verify its `_acme-challenge` CNAME points to
   the immutable Paperboat challenge target before retrying issuance. The two
   Paperboat-owned preview/tunnel wildcard parents are different: the server
   writes their TXT records directly through the configured provider and must
   not depend on an external CNAME.
4. Confirm one issuance lease owns the domain and certificate generation.
   Preserve the previous active certificate until every captured edge target
   has staged and acknowledged the replacement.
5. For renewal or revocation failure, inspect the durable retry state and
   expiry horizon. Do not copy provider credentials or certificate key bytes
   to an edge or a ticket.

## Managed certificate deployment readiness

Run this gate before deploying or restarting the server or rolling a
paperboat-tunnel image. Production requires
`PAPERBOAT_CERTIFICATES_ENABLED=true`; `false` is not a production workaround
for missing references or failed issuance. A healthy process is not
sufficient: the server-side issuer, durable certificate ledger, authenticated
distribution handler, and edge broker must all be composed together.

### Reference-only secret injection

1. Keep only public certificate settings and opaque references in the server
   environment. The required overlay names are the `PAPERBOAT_CERTIFICATES_*`
   names in `deploy/.env.example`; the reference values identify the ACME
   account key, envelope master key, DNS token, distribution credential, and
   owner, but are not secret bytes.
2. For a reference `R`, the environment adapter derives
   `PAPERBOAT_CERT_SECRET_*` by uppercasing each alphanumeric rune, replacing
   every other rune with `_`, and appending `_` plus the first 12 lowercase
   hexadecimal characters of `SHA-256(R)`. This digest suffix prevents
   punctuation-normalization collisions. For example, the reference
   `secret://edge/distribution` maps to the name
   `PAPERBOAT_CERT_SECRET_SECRET___EDGE_DISTRIBUTION_db21dd9c8bbf`.
   The example is a name only and must never be populated with a value in
   source control, SQL, logs, or evidence.
3. Inject the referenced values into the server process only at startup or
   restart, with the secret manager's normal bounded environment mechanism.
   Do not persist or print PEM data, private keys, DNS tokens, master keys, or
   credentials. Confirm that
   `PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE` resolves to
   exactly the same bytes loaded through
   `PAPERBOAT_EDGE_CONTROL_CREDENTIAL_FILE`; a mismatch must fail closed.
4. The production overlay must set `PAPERBOAT_CERTIFICATES_ENABLED=true`.
   Never set it to `false` while waiting for a reference, issuance, or
   distribution to recover. A missing reference or a startup error is a
   rollout blocker, not a reason to add a plaintext fallback.
5. The configured DNS zone must authoritatively contain both platform base
   domains and the delegated challenge zone. Its token needs only the bounded
   TXT create/delete permission used by the certificate worker. Do not add
   platform `_acme-challenge` CNAMEs or grant DNS credentials to an edge.

### Read-only rollout gates

1. Verify the live server configuration uses the current generated overlay,
   then inspect the certificate worker and distribution-handler health without
   sending a mutation. A `404` or `5xx` on a distribution path, an absent
   worker, or a credential-mismatch startup error fails this gate.
2. Apply migration 150 before starting the serving path, and wait for the
   migration service to finish successfully:

   ```sh
   docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
     up -d migrate
   docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
     wait migrate
   ```

   Start the server and edge only with the signaling certificate and private
   broker/distribution path available. From the paperboat-server repository,
   run the deterministic, read-only gate after both services are running:

   ```sh
   ./deploy/certificate-preflight.sh \
     --env-file deploy/.env \
     --compose-file deploy/docker-compose.yml \
     --wait-seconds 300
   ```

   The gate waits for migration 150, both durable platform targets
   (`platform_cert_preview_v1` and `platform_cert_tunnel_v1`), and active edge
   distributions for every current ready edge process. A distribution counts
   only when `edge.state = 'active'` and its observed certificate generation
   matches the active server certificate. Do not admit public preview/tunnel
   traffic until both platform targets and active edge distributions pass.
3. From a read-only database connection, substitute only the two configured
   public base domains for the psql variables below. This query deliberately
   omits ciphertext and private-key columns:

   ```sh
   psql "$PAPERBOAT_DATABASE_DSN" \
     --set=ON_ERROR_STOP=1 \
     --set=preview_base_domain="$PAPERBOAT_PREVIEW_BASE_DOMAIN" \
     --set=tunnel_base_domain="$PAPERBOAT_TUNNEL_BASE_DOMAIN" <<'SQL'
   BEGIN READ ONLY;
   SELECT 'platform_target' AS source, id, kind, hostname, desired_state,
          certificate_state, certificate_reference, certificate_expires_at,
          certificate_failure_code, retry_count, next_retry_at
     FROM paperboat.tunnel_platform_certificate_targets
    WHERE hostname IN ('*.' || :'preview_base_domain', '*.' || :'tunnel_base_domain')
   ORDER BY id;

   SELECT 'certificate' AS source, target_kind, hostname, leaf_hostname, state,
          strategy, certificate_generation, expires_at, renewal_at,
          failure_code
     FROM paperboat.tunnel_certificate_records
    WHERE hostname IN ('*.' || :'preview_base_domain', '*.' || :'tunnel_base_domain')
   ORDER BY 2, 3, 7 DESC;

   SELECT 'distribution' AS source, cert.target_kind, cert.hostname,
          edge.edge_node_id, edge.edge_process_epoch, edge.state,
          edge.observed_certificate_generation, cert.certificate_generation,
          edge.observed_at, edge.failure_code
     FROM paperboat.tunnel_certificate_edge_distributions AS edge
     JOIN paperboat.tunnel_certificate_records AS cert
       ON cert.id = edge.certificate_id
    WHERE cert.hostname IN ('*.' || :'preview_base_domain', '*.' || :'tunnel_base_domain')
   ORDER BY 2, 3, 4, 5;

   SELECT domain_id, owner_id, domain_generation, lease_until
     FROM paperboat.tunnel_certificate_issuance_locks
    WHERE lease_until > now()
      AND EXISTS (
            SELECT 1
              FROM paperboat.tunnel_platform_certificate_targets AS target
             WHERE target.id = tunnel_certificate_issuance_locks.domain_id
               AND target.hostname IN ('*.' || :'preview_base_domain', '*.' || :'tunnel_base_domain')
          )
   ORDER BY domain_id;
   ROLLBACK;
   SQL
   ```

   Missing parents, non-ready states, expired records, generation mismatches,
   failed rows, or unexpected active locks require stopping the rollout. The
   transaction is read-only; never repair these rows by hand.
4. Inspect the live generated Caddy configuration, not a stale static
   Caddyfile. The generated config belongs to the paperboat-tunnel Compose
   deployment, so run these commands against that deployment (not the server
   Compose file), and read its loopback admin endpoint:

   ```sh
   docker compose --env-file paperboat-tunnel/deploy/.env \
     -f paperboat-tunnel/deploy/docker-compose.yml \
     exec -T tunnel caddy validate \
     --config /var/lib/paperboat-tunnel/runtime/caddy.json
   docker compose --env-file paperboat-tunnel/deploy/.env \
     -f paperboat-tunnel/deploy/docker-compose.yml \
     exec -T tunnel curl -fsS \
     http://127.0.0.1:2019/config/apps/tls/automation/policies
   ```

   For both managed wildcard subjects, confirm `get_certificate[0].via` is
   `paperboat` and its socket is the current runtime certificate socket. The
   managed policies must not contain an issuer, `on_demand`, file storage, or
   any other certificate fallback. Keep the admin listener private.
5. Check the broker boundary and exercise it through TLS without writing any
   state. The socket must be a private Unix socket owned by the tunnel runtime:

   ```sh
   docker compose --env-file paperboat-tunnel/deploy/.env \
     -f paperboat-tunnel/deploy/docker-compose.yml \
     exec -T tunnel sh -ceu \
     'test -S /var/lib/paperboat-tunnel/runtime/config/certificate.sock && \
      stat -c "%F %a %U:%G" /var/lib/paperboat-tunnel/runtime/config/certificate.sock'
   ```

   Resolve one synthetic, one-label host under each wildcard and run
   `openssl s_client -verify_return_error` with the matching SNI. Require a
   peer certificate, a valid chain, and a SAN covering that exact one-label
   host; `no peer certificate`, a TLS alert, or a broker error is a failure.
   Do not send a raw broker request with credentials or capture certificate
   key material. A successful public TLS handshake is the end-to-end broker
   check.

### Rollback

Stop before changing the next service when any reference is missing, the
distribution credential differs from the edge control credential (the
distribution credential must equal the edge control credential byte-for-byte),
either platform wildcard is not active, SQL rows are absent or stale, the
handler is unregistered, the broker socket is missing, Caddy is not
broker-only, or a public TLS probe has no certificate. Keep the previous signed server and
tunnel images, generated configuration, and last-known-good certificate state
active. Use the deployment's signed rollback and journal; do not edit SQL,
DNS, firewall, keys, Caddy JSON, or certificate volumes by hand.

If composition was incomplete, restore the matching server image/config and
runtime references first. Wait for migration 150, both platform target rows,
and active edge distributions by rerunning `certificate-preflight.sh`; then
verify worker health, edge distribution generations, and both public TLS
probes before reopening the edge rollout. Record only bounded status/error
categories, resource IDs, and timings. Never put secret values, certificate
private keys, or provider tokens in rollback evidence.

## Connector loss, rotation, drain, or revoke

1. Identify the exact connector, credential generation, session, process
   generation, and aggregate operation.
2. During rotation, keep the old credential only for the configured overlap.
   Complete the aggregate operation only after every captured target proves and
   becomes ready with the new credential generation.
3. During drain, stop new streams and let existing streams finish within the
   bounded deadline. Reject acknowledgements from a replaced session or wrong
   operation ID.
4. During revoke, preserve `revoked` and `forced_closed` terminal state even if
   a late drain acknowledgement arrives.
5. A final connector going offline does not delete the tunnel, route, domain,
   DNS target, or certificate.

## Private-access failure

Private traffic must follow:

```text
browser -> hostd-owned PAC/CONNECT proxy -> authenticated carrier -> edge -> origin
```

No browser cookie, redirect, login flow, extension, or public request header is
an access credential. Interpret `401` as missing or invalid current machine
authentication, `403` as an authenticated but denied or revoked route binding,
and `503` as temporary hostd, carrier, edge-binding, or authorization-authority
unavailability. Confirm the exact account, route, machine session, connector,
configuration, assignment, edge node, and process epoch before retrying. Keep
denial responses non-enumerating.

## Control-plane or database outage

1. Stop new mutations and preserve established last-known-good traffic.
2. Restore PostgreSQL and the control worker from the current compatible
   release. Do not edit operation, snapshot, or assignment rows by hand.
3. Resume with the original operation and idempotency key. Duplicate delivery
   must converge to the same durable result.
4. Wait for a complete snapshot and exact acknowledgements. Reject stale reads,
   deltas, or observations that cannot prove the current generation.
5. Verify preview expiry, durable route continuity, certificate distribution,
   connector recovery, and private-access fail-closed behavior before reopening
   mutations.

## Update rollback

Stop rollout when a candidate fails signature, compatibility, process health,
route generation, origin readiness, edge canary, or certificate checks. Keep
the previous signed release and last-known-good runtime active, let the update
journal drive rollback, and quarantine the failed version. Do not replace the
release selector manually. Reopen rollout only after the signed manifest,
deployment plan, runtime verifier, server readiness check, and rollback test
agree.

## Closure

Close the incident only when typed health has recovered, the durable operation
is terminal, desired and observed generations agree, old sessions are fenced,
bounded retry queues are draining, and no secret entered logs or evidence. For
user-visible diagnostics, follow the `pb tunnel doctor` support-bundle flow and
review its redaction manifest before upload.
