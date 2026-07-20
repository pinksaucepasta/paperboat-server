# HTTP API Contract

Status: implemented Phase 10 contract baseline.

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

Note: agentunnel uses its own `ok` envelope. `paperboat-server` must treat agentunnel as
an external provider contract and translate provider errors at its own boundary. Do not
change agentunnel's public contract from this repo.

## Cross-Cutting Headers

Requests:

- `Authorization: Bearer <token>` for non-browser clients where approved.
- Cookie session plus CSRF header for dashboard browser writes.
- `Idempotency-Key` for project create, checkout/customer portal, admin billing
  adjustments, and config repo provisioning. Lifecycle and access mutations are
  replay-safe through server-side state and aggregate-scoped orchestration/session
  records.
- `If-Match` with the numeric project `version`, or a JSON `version` field, for
  `PATCH /api/projects/{project_id}` optimistic concurrency.

Responses:

- `Request-Id` on every response.
- Rate limit headers where limits apply.

## Endpoint List

### Health

- `GET /.well-known/jwks.json`
- `GET /healthz`
- `GET /readyz`

### Auth and Session

- `GET /api/me`
- `POST /api/auth/workos/callback`
- `POST /api/auth/logout`
- `GET /api/auth/csrf`
- `POST /api/auth/device/authorize`
- `POST /api/auth/device/token`
- `GET /api/auth/device/requests/{user_code}`
- `POST /api/auth/device/requests/{user_code}/approve`
- `POST /api/auth/device/requests/{user_code}/deny`
- `POST /api/auth/token/refresh`
- `POST /api/auth/token/revoke`
- `GET /api/auth/clients`
- `DELETE /api/auth/clients/{client_session_id}`

The device/session contract, polling outcomes, rotation, and revocation behavior are frozen
in [cli-authorization.md](cli-authorization.md). Browser approval uses cookie plus CSRF;
CLI project reads and connects use scoped Paperboat bearer access tokens.

### Billing and Entitlements

- `GET /api/billing/entitlement`
- `GET /api/billing/usage`
- `GET /api/billing/plan-products`
- `GET /api/billing/storage`
- `GET /api/billing/storage-preview?storage_gb={integer}`
- `PUT /api/billing/storage`
- `GET /api/billing/auto-topup`
- `PUT /api/billing/auto-topup`
- `GET /api/dashboard/usage-summary`
- `POST /api/billing/checkout`
- `POST /api/billing/customer-portal`
- `POST /api/webhooks/polar`

### Configuration Sync

- `GET /api/config-sync/status` requires an authenticated account with an active entitlement and
  returns safe repository metadata,
  effective policy revision and byte limits, aggregate state, and bounded per-project machine
  status. Stale active-machine heartbeats are reported as `offline`; stopped machines are
  reported as `idle` with their last result retained.
- `GET|PUT|DELETE /api/config-sync/overrides` lists and changes exact account-path overrides.
  Mandatory exclusions return `mandatory_exclusion` and cannot be weakened.
- `POST /api/config-sync/recovery-key/export` and `/rotate` require CSRF plus a short-lived,
  purpose-bound WorkOS reauthentication proof. Export responses are non-cacheable and audited.
- `POST /api/machine/config-sync/classify` uses the existing owning project-machine credential and
  accepts only bounded relative-path metadata. Provider API keys, contents, absolute paths, and
  workspace names are never accepted from or returned to a VM.
- `POST /api/machine/activity-heartbeat` accepts the existing authenticated activity payload
  plus an optional validated `config_sync` object. Its required `updated_at` timestamp tracks the
  freshness of the sync daemon independently from the activity reporter. A status timestamp newer
  than its enclosing sample is persisted as a sanitized `status_clock_invalid` error at sample time,
  allowing later clock-corrected status to replace it. Paths and errors are sanitized and bounded;
  file contents, credentials, and raw command output are never accepted or persisted.

### Catalogs

- `GET /api/catalog/plans`
- `GET /api/catalog/machine-types`
- `GET /api/catalog/presets`
- `GET /api/catalog/idle-timeouts`
- `GET /api/catalog/regions`

### GitHub

- `GET /api/github/status`
- `POST /api/github/oauth/start`
- `POST /api/github/oauth/callback`
- `POST /api/github/config-repo/provision`

### Projects

- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/{project_id}`
- `PATCH /api/projects/{project_id}`
- `DELETE /api/projects/{project_id}`
- `POST /api/projects/{project_id}/start`
- `POST /api/projects/{project_id}/stop`
- `POST /api/projects/{project_id}/restart`
- `POST /api/projects/{project_id}/activity`
- `GET /api/projects/{project_id}/events`
- `GET /api/projects/{project_id}/usage`

### Access

- `POST /api/projects/{project_id}/connect`
- `POST /api/projects/{project_id}/cli-connect`
- `POST /api/projects/{project_id}/papercode-connect`
- `GET /api/projects/{project_id}/connection-status?terminal_session_id=pts_...`

`GET /api/projects` supports `limit`, `offset`, `state`, and `sort`. Sort fields are
`created_at`, `updated_at`, `name`, and `state`; prefix with `-` for descending order.

### Admin

- `GET /api/admin/users`
- `GET /api/admin/projects`
- `GET /api/admin/orchestration-jobs`
- `POST /api/admin/reconcile`
- `POST /api/admin/users/{user_id}/adjust-credits`
- `POST /api/admin/users/{user_id}/adjust-storage`

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
- `invalid_activity_source`
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

- `POST /v1/connectors/admission` requires the helper identity bearer credential and an
  unpadded base64url `X-Paperboat-Helper-Proof` envelope signed by that helper's enrolled
  Ed25519 key. The proof binds `POST`, the exact path and body hash, helper/environment,
  operation ID, and a lifetime of at most one minute. The strict body contains
  `operation_id`, `environment_id`, `helper_id`, `edge_pool`, and protocol version `1.0`.
  The response is the canonical connector-admission document: the same operation and
  identity bindings, generation, assigned node/pool, one `{host,port}` endpoint, at least
  one revisioned route handoff, protocol version, optional capabilities, and the scoped
  connector credential. It contains no provider credential or internal alternate port.
  Exact retries replay the encrypted recorded document; changed body or proof bindings
  fail before a new admission is minted.
- `POST /v1/config/credentials` accepts a helper identity credential, a bounded `{}` JSON
  body, and `X-Paperboat-Helper-Proof`; it returns a short-lived `config_sync` credential
  bound to the active environment/helper assignment and warning revision. Exact operation
  replays return the original credential; conflicting replays return `operation_conflict`.
- `GET /v1/trust/revocations` requires the edge-control bearer credential and returns the
  bounded revocation document consumed by tunnel trust snapshots (`jtis`, `environments`,
  `helper_generations`, and `key_ids`).
- `POST /v1/routes/observed` accepts the bounded applied route snapshot from the assigned
  tunnel node. Each item is accepted only when route revision, node ID, and connector
  generation still match current desired ownership; stale observations return
  `version_conflict` and cannot mutate newer intent.

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
- papercode approves `papercode-connect` descriptor shape in [access-handoff.md](access-handoff.md).
- agentunnel boundary remains adapter-only; no agentunnel contract changes from this repo.
