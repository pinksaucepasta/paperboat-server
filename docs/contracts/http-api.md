# HTTP API Contract

Status: implemented contract baseline.

This document freezes the `paperboat-server` HTTP/JSON contract shape for production
implementation. Endpoint behavior remains server-side authoritative; clients are
untrusted.

## General Rules

- JSON field names use `snake_case`.
- IDs are opaque strings.
- State enums are lowercase strings.
- Mutations that create provider resources require idempotency keys.
- Billing-impacting and irreversible mutations write audit events.
- Provider credentials, tokens, SSH keys, API keys, and secrets are never returned.
- `paperboat-server` does not proxy live terminal, preview, or WebSocket traffic.

## Response Shape

Success responses:

```json
{
  "data": {}
}
```

Error responses:

```json
{
  "error": {
    "code": "machine_not_ready",
    "message": "Machine is not ready for connection.",
    "request_id": "req_...",
    "details": {}
  }
}
```

Note: provider_route uses its own `ok` envelope. `paperboat-server` must treat provider_route as
an external provider contract and translate provider errors at its own boundary. Do not
change provider_route's public contract from this repo.

## Cross-Cutting Headers

Requests:

- `Authorization: Bearer <token>` for non-browser clients where approved.
- Cookie session plus CSRF header for dashboard browser writes.
- `Idempotency-Key` for project create, checkout/customer portal, admin billing
  adjustments, and config repo provisioning. Lifecycle and access mutations are
  replay-safe through server-side state and aggregate-scoped orchestration/session
  records.
- `If-Match` with the numeric project `version`, or a JSON `version` field, for
  `PATCH /v1/projects/{project_id}` optimistic concurrency.

Responses:

- `Request-Id` on every response.
- Rate limit headers where limits apply.

## Endpoint List

### Health

- `GET /.well-known/jwks.json`
- `GET /v1/client-configuration`
- `GET /healthz`
- `GET /readyz`

### Auth and Session

- `GET /v1/me`
- `POST /v1/auth/workos/callback`
- `POST /v1/auth/logout`
- `GET /v1/auth/csrf`
- `POST /v1/auth/device/authorize`
- `POST /v1/auth/device/token`
- `GET /v1/auth/device/requests/{user_code}`
- `POST /v1/auth/device/requests/{user_code}/approve`
- `POST /v1/auth/device/requests/{user_code}/deny`
- `POST /v1/auth/token/refresh`
- `POST /v1/auth/token/revoke`
- `GET /v1/auth/cli-client-sessions`
- `DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}`

The device/session contract, polling outcomes, rotation, and revocation behavior are frozen
in [cli-authorization.md](cli-authorization.md). Browser approval uses cookie plus CSRF;
CLI project reads and connects use scoped Paperboat bearer access tokens.

### Billing and Entitlements

- `GET /v1/billing/entitlement`
- `GET /v1/billing/usage`
- `GET /v1/billing/plan-products`
- `GET /v1/billing/storage`
- `GET /v1/billing/storage-change-preview?storage_gb={integer}`
- `PUT /v1/billing/storage`
- `GET /v1/billing/auto-topup`
- `PUT /v1/billing/auto-topup`
- `GET /v1/usage-summary`
- `POST /v1/billing/checkout`
- `POST /v1/billing/customer-portal`
- `POST /v1/webhooks/polar`

### Configuration Sync

- `GET /v1/config-sync/status` requires an authenticated account with an active entitlement and
  returns the authoritative policy plus bounded environment, assignment, consent, helper,
  repository, revision, conflict, and recovery state. Stale helper observations are `offline`;
  unassigned environments are `disabled`. Policy reports the server rollout mode
  (`disabled`, `read_only`, or `leased_writes`) and whether BYOD is enabled.
- `GET|PUT|DELETE /v1/config-sync/overrides` lists and changes exact account-path overrides.
  Mandatory exclusions return `mandatory_exclusion` and cannot be weakened.
- `POST /v1/config-sync/recovery-key/export` and `/rotate` require CSRF plus a short-lived,
  purpose-bound WorkOS reauthentication proof. Export responses are non-cacheable and audited.
- `POST /v1/config/classify` requires helper proof plus a current assignment-bound config
  credential and accepts only the versioned, bounded relative-path metadata schema. Provider API
  keys, contents, absolute paths, identities, repository coordinates, and workspace names are
  never accepted from or returned to a helper.
- `POST /v1/config-sync/environments/{environment_id}/conflict-resolutions` records an
  explicit `keep_local`, `keep_remote`, or `externally_resolved` action against the current
  assignment version, remote revision, relative path, and deterministic conflict revision.
  Stale or ambiguous actions return a conflict.
- `POST /v1/config/conflict-resolutions/pending` and
  `/v1/config/conflict-resolutions/acknowledge` require helper proof and the current
  assignment-bound config credential. A helper sees only its active binding and acknowledges
  only after the selected result lands.
- `POST /v1/runtime-observations` accepts authenticated runtime availability and diagnostics
  plus an optional validated `config_sync` object. Its required `updated_at` timestamp tracks the
  freshness of the sync daemon independently. A status timestamp newer
  than its enclosing sample is persisted as a sanitized `status_clock_invalid` error at sample time,
  allowing later clock-corrected status to replace it. Paths and errors are sanitized and bounded;
  file contents, credentials, and raw command output are never accepted or persisted.

### Catalogs

- `GET /v1/catalog/plans`
- `GET /v1/catalog/machine-types`
- `GET /v1/catalog/presets`
- `GET /v1/catalog/regions`

### GitHub

- `GET /v1/github/status`
- `POST /v1/github/oauth/start`
- `POST /v1/github/oauth/callback`
- `POST /v1/github/config-repositories/provision`

### Projects

- `GET /v1/projects`
- `POST /v1/projects`
- `GET /v1/projects/{project_id}`
- `PATCH /v1/projects/{project_id}`
- `DELETE /v1/projects/{project_id}`
- `POST /v1/projects/{project_id}/start`
- `POST /v1/projects/{project_id}/stop`
- `POST /v1/projects/{project_id}/restart`
- `GET /v1/projects/{project_id}/events`
- `GET /v1/projects/{project_id}/usage`

### Access

- `POST /v1/projects/{project_id}/connection-descriptor`
- `GET /v1/projects/{project_id}/connection-readiness?terminal_session_id=pts_...`

`GET /v1/projects` supports `limit`, `offset`, `state`, and `sort`. Sort fields are
`created_at`, `updated_at`, `name`, and `state`; prefix with `-` for descending order.

### Admin

- `GET /v1/admin/users`
- `GET /v1/admin/projects`
- `GET /v1/admin/orchestration-jobs`
- `POST /v1/admin/reconcile`
- `POST /v1/admin/users/{user_id}/adjust-credits`
- `POST /v1/admin/users/{user_id}/adjust-storage`

## Canonical Error Codes

Initial contract:

- `unauthenticated`
- `forbidden`
- `payment_required`
- `github_required`
- `validation_failed`
- `idempotency_conflict`
- `quota_exceeded`
- `credits_exhausted`
- `project_not_found`
- `project_not_ready`
- `machine_not_ready`
- `provider_unavailable`
- `provider_outcome_unknown`
- `provider_conflict`
- `tunnel_unavailable`
- `credential_issuer_unavailable`
- `github_config_not_ready`
- `invalid_pagination`
- `invalid_sort`
- `invalid_version`
- `version_required`
- `version_conflict`
- `rate_limited`
- `authorization_pending`
- `slow_down`
- `access_denied`
- `expired_token`
- `invalid_grant`
- `invalid_client`
- `invalid_scope`
- `device_request_not_pending`
- `device_request_expired`
- `device_request_consumed`
- `internal_error`

Adding or renaming public codes after approval requires explicit contract approval.

## Private Control-Plane Endpoints

The following endpoints are private service-to-service contracts and are not browser or
CLI APIs:

- `POST /v1/connectors/admission` requires the renewable machine-control bearer credential and an
  unpadded base64url `X-Paperboat-Machine-Proof` envelope signed by that machine's enrolled
  Ed25519 key. The proof binds `POST`, the exact path and body hash, machine/environment,
  operation ID, and a lifetime of at most one minute. The strict body contains
  `operation_id`, `environment_id`, `machine_id`, `connector_id`, `edge_pool`, and protocol version `1.0`.
  The response is the canonical connector-admission document: the same operation and
  identity bindings, generation, assigned node/pool, one `{host,port}` endpoint, at least
  one revisioned route handoff, protocol version, optional capabilities, and the scoped
  connector credential. It contains no provider credential or internal alternate port.
  Exact retries replay the encrypted recorded document; changed body or proof bindings
  fail before a new admission is minted.
- `POST /v1/hosted-helper-enrollments` accepts only a short-lived Fly OIDC workload identity
  obtained through the Machine-local `/.fly/api` socket and the helper's Ed25519 public
  key. The server verifies signature, issuer, audience, expiry, configured Fly app, and
  exact Fly machine-to-environment ownership before consuming canonical enrollment state.
  Hosted bootstrap credentials are never stored in Fly secrets or Machine environment.
- `POST /v1/helper-enrollments` remains the one-time credential exchange for BYOD enrollment;
  hosted production composition does not use it.
- `POST /v1/config/credentials` accepts a machine-control credential, a bounded `{}` JSON
  body, and `X-Paperboat-Machine-Proof`; it returns a short-lived `config_sync` credential
  bound to the active machine assignment, installation generation, and warning revision. Exact operation
  replays return the original credential; conflicting replays return `operation_conflict`.
- `POST /v1/previews/credentials` accepts the machine-control bearer, a bounded `{}` JSON
  body, and `X-Paperboat-Machine-Proof`; it returns a five-minute
  `preview_registration` credential with exact `preview:register` scope and machine/
  installation-generation binding. Preview operations and observations use that credential as the
  bearer, carry the durable identity separately in `X-Paperboat-Machine-Identity`, and
  remain signed by the enrolled machine key. The preview credential is held only in
  preview-runner memory.
- `POST /v1/machine-installation-failures` accepts an active helper identity,
  its exact Ed25519 request proof, and only `enrollment_id` plus the bounded stage
  `service_install|service_readiness`. It transitions the matching `installing|connecting`
  enrollment to `failed_retryable`; its stage is `artifact_verification`, `service_install`,
  or `service_readiness`; it carries no local paths, error output, credentials,
  artifact URLs, or process data. Retry preserves the existing machine, environment,
  helper identity, and seat while rotating bootstrap generation and material.
- `GET /v1/trust/revocations` requires the edge-control bearer credential and returns the
  bounded revocation document consumed by tunnel trust snapshots (`jtis`, `environments`,
  `connector_generations`, and `key_ids`).
- `POST /v1/edge/routes/observations` accepts the bounded applied route snapshot from the assigned
  tunnel node. Each item is accepted only when route revision, node ID, and connector
  generation still match current desired ownership; stale observations return
  `version_conflict` and cannot mutate newer intent.
- `POST /v1/machines/{machine_id}/preview-launch-descriptor` is a CLI endpoint for an
  owned online paired machine. It returns the machine's routed `/v1/preview-launches`
  endpoint and a two-minute `preview_launch` credential with exact `preview:launch`
  scope, bound to user, machine, environment, and CLI client session. The target runtime
  validates the binding and launches one isolated preview service; it does not grant
  terminal, transfer, config, preview-registration, or connector authority.

These endpoints never return repository/provider secrets. Assignment replacement, consent
revocation, helper replacement, and environment revocation invalidate subsequent credential
use through the snapshot document.

## Project State Enums

Initial contract:

- `creating`
- `provisioning_storage`
- `provisioning_machine`
- `ready`
- `starting`
- `running`
- `stopping`
- `stopped`
- `restarting`
- `deleting`
- `deleted`
- `failed`
- `suspended`

## Approval Checklist

- Dashboard approves endpoint list, response shapes, error codes, and project states.
- CLI approves `cli-connect`, connection status, and structured error behavior.
- provider_route boundary remains adapter-only; no provider_route contract changes from this repo.
