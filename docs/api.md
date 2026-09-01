# Paperboat Server API

The API is contract-first. Its schemas are maintained in
[`docs/openapi.json`](openapi.json); CI extracts registered methods and paths from the
router and requires matching OpenAPI operations. Focused contract tests additionally
verify authentication and important request and response schemas.

This API is the control-plane contract for dashboard and CLI clients. It authorizes,
meters, and orchestrates resources; it does not proxy terminal, preview, or WebSocket
data.

## Response Envelope

Success:

```json
{
  "data": {}
}
```

Error:

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

Every response includes a `Request-Id` header. Browser writes use the session cookie plus
CSRF protection. Project create, billing checkout/customer portal, admin billing
adjustments, and GitHub config-repo provisioning require an `Idempotency-Key` header.
Project lifecycle and access routes are replay-safe through persisted project, session,
and orchestration state; they do not currently require a client idempotency key.

Preview and tunnel v1 responses also include `Correlation-Id`. Their typed errors add
component, outcome certainty, retryability, and a safe repair action. Every create uses
`Idempotency-Key`; mutable-resource writes use a strong ETag and require `If-Match` when
a stale write could overwrite another actor. Lists use bounded keyset pagination and
events resume from an opaque account-and-resource-bound cursor.

`GET /v1/operations/{operation_id}` returns typed long-running progress. Safe pending
work can be canceled with idempotent `DELETE /v1/operations/{operation_id}`. Work that
has crossed its cancellation boundary returns `operation_not_cancellable` without
claiming that its outcome is known.

Mutable resources include a numeric `version`. Dashboard updates to
`PATCH /v1/projects/{project_id}` must send either an `If-Match` header containing that
version or a `version` field in the JSON body. Stale writes fail with `version_conflict`.

## Dashboard Reads

- `GET /v1/me`
- `GET /v1/billing/entitlement`
- `GET /v1/billing/usage`
- `GET /v1/billing/plan-products`
- `GET /v1/usage-summary`
- `GET /v1/config-sync/status`
- `GET|PUT|DELETE /v1/config-sync/overrides`
- `POST /v1/config-sync/recovery-key/export`
- `POST /v1/config-sync/recovery-key/rotate`
- `GET /v1/catalog/plans`
- `GET /v1/catalog/machine-types`
- `GET /v1/catalog/presets`
- `GET /v1/catalog/regions`
- `GET /v1/github/status`
- `GET /v1/projects`
- `GET /v1/projects/{project_id}`
- `GET /v1/projects/{project_id}/events`
- `GET /v1/projects/{project_id}/connection-readiness`
- `GET /v1/projects/{project_id}/terminal-sessions`

`GET /v1/projects` returns a shaped list response:

```json
{
  "data": {
    "items": [],
    "pagination": {
      "limit": 50,
      "offset": 0,
      "total": 0,
      "next_offset": null
    },
    "filters": {
      "state": ""
    },
    "sort": "-created_at"
  }
}
```

Supported list query parameters:

- `limit` from `1` to `200` defaults to `50`.
- `offset` defaults to `0`.
- `state` filters by project state.
- `sort` accepts `created_at`, `updated_at`, `name`, or `state`; prefix with `-` for
  descending order.

Catalog values are database/config driven. Dashboard clients must not hardcode plans,
machine types, presets, regions, credit weights, or storage limits.

## Dashboard Writes

- `POST /v1/auth/workos/callback`
- `POST /v1/auth/logout`
- `GET /v1/auth/device/requests/{user_code}`
- `POST /v1/auth/device/requests/{user_code}/approve`
- `POST /v1/auth/device/requests/{user_code}/deny`
- `POST /v1/billing/checkout`
- `POST /v1/billing/customer-portal`
- `POST /v1/github/oauth/start`
- `GET /v1/github/oauth/callback`
- `POST /v1/github/oauth/callback`
- `POST /v1/github/config-repositories/provision`
- `POST /v1/projects`
- `PATCH /v1/projects/{project_id}`
- `DELETE /v1/projects/{project_id}`
- `POST /v1/projects/{project_id}/start`
- `POST /v1/projects/{project_id}/stop`
- `POST /v1/projects/{project_id}/restart`

Project create returns `201` for a new idempotency key and `200` for a matching retry.
Project lifecycle writes return accepted state and enqueue provider work; clients should
use project reads, project events, and connection status for progress.

## CLI Access

CLI sign-in uses the device authorization and rotating client-session contract documented
in `docs/contracts/cli-authorization.md`. Browser cookies and helper environment tokens
are not accepted as CLI identity. CLI project APIs require scoped Paperboat bearer tokens.
Dashboard `POST /v1/auth/logout` revokes only the current browser session; CLI family
logout uses `POST /v1/auth/token/revoke`. Account suspension and administrative account
revocation revoke all authorized CLI clients.
Client revocation also marks linked Paperboat access-session records revoked and those
records now retain helper terminal/file session IDs. Signed bearer invalidation is
implemented for client, user, project, and metering/entitlement enforcement. Enforcement
uses a durable delivery marker and retries failed downstream propagation. Downstream
credentials otherwise expire at their configured short lifetime.
`GET /v1/projects` requires `projects:read`. `POST /v1/projects/{project_id}/connection-descriptor`
and `GET /v1/projects/{project_id}/connection-readiness` require `projects:connect`.

## Terminal Sessions

Each non-deleted project has one durable `default` terminal session. `cli-connect` accepts
an optional `{ "terminal_session_id": "pts_..." }` body; omission preserves the default
session used by existing CLI versions. Session names are lower-case, unique per project, and
must match `[a-z0-9][a-z0-9._-]{0,63}`. The server creates opaque terminal IDs; client
supplied names never become runtime terminal IDs.

`GET /v1/projects/{project_id}/connection-readiness` accepts the same optional
`terminal_session_id` query parameter. CLI readiness polls and the final descriptor
re-broker therefore retain the selected session rather than reverting to `default`.
When any terminal close or history purge is awaiting Helper reconciliation, the endpoint
returns the retryable `helper_starting` / `terminal_session_operation_pending` state until
the cleanup is complete.

- `GET /v1/projects/{project_id}/terminal-sessions` requires `projects:read` and accepts
  `limit` (1-200) and `offset`.
- `POST /v1/projects/{project_id}/terminal-sessions` requires `projects:connect`, an
  `Idempotency-Key`, and an optional `{ "name": "api" }` body.
- `PATCH /v1/projects/{project_id}/terminal-sessions/{session_id}` renames a non-default
  session.
- `POST /v1/projects/{project_id}/terminal-sessions/{session_id}/close` and `DELETE ...`
  first apply physical helper work when the runtime is reachable. `200` means it was
  applied immediately; `202` means it remains pending and that session cannot be attached
  until reconciliation completes.

Session list records contain `id`, `name`, `is_default`, `state`, nullable
`attached_count`, `last_active_at`, `created_at`, and `updated_at`.

- `GET /.well-known/jwks.json`
- `GET /v1/client-configuration` returns server-owned URLs used by unauthenticated clients.
- `POST /v1/auth/device/authorize`
- `POST /v1/auth/device/token`
- `POST /v1/auth/token/refresh`
- `POST /v1/auth/token/revoke`
- `GET /v1/auth/cli-client-sessions`
- `DELETE /v1/auth/cli-client-sessions/{cli_client_session_id}`
- `POST /v1/projects/{project_id}/connection-descriptor`
- `GET /v1/projects/{project_id}/connection-readiness`

`cli-connect` returns a short-lived descriptor that lets the CLI connect through
provider_route. The server may start or resume the project machine before returning the
descriptor. A not-ready response is HTTP `202` and contains no credentials; the CLI polls
connection status and calls `cli-connect` again once ready. Live terminal and file-transfer
traffic still goes through provider_route to helper, not this API.

## Error Codes

Documented public codes currently emitted by the handlers include:

- `unauthenticated`
- `forbidden`
- `payment_required`
- `github_required`
- `validation_failed`
- `invalid_request`
- `idempotency_key_required`
- `idempotency_key_conflict`
- `quota_exceeded`
- `insufficient_storage`
- `credits_exhausted`
- `project_not_found`
- `project_not_ready`
- `project_deleted`
- `invalid_project_state`
- `machine_not_ready`
- `terminal_session_not_found`
- `terminal_session_name_conflict`
- `terminal_session_limit_reached`
- `terminal_session_reserved`
- `terminal_session_operation_pending`
- `terminal_runtime_unavailable`
- `provider_unavailable`
- `provider_outcome_unknown`
- `tunnel_unavailable`
- `tunnel_not_ready`
- `credential_issuer_unavailable`
- `github_config_not_ready`
- `invalid_pagination`
- `invalid_sort`
- `invalid_version`
- `version_required`
- `version_conflict`
- `internal_error`

Adding, removing, or renaming public error codes requires contract approval.

## Private Connector Admission

`POST /v1/connectors/admission` is a machine-runtime-to-control-plane endpoint, not a browser or CLI
API. It requires a machine-control bearer credential plus an unpadded base64url
`X-Paperboat-Machine-Proof` signed by the enrolled machine key. The proof covers the exact
method, path, body hash, operation ID, machine/environment binding, and a maximum one-minute
lifetime.

The strict JSON request contains `operation_id`, `environment_id`, `machine_id`, `connector_id`, `edge_pool`,
and `protocol_version: "1.0"`. A successful response follows the canonical
`contracts/schemas/edge/admission.schema.json` shape and includes one assigned endpoint,
at least one revisioned route handoff, and a short-lived connector credential. Alternate
node ports, credential expiry internals, provider values, and reusable edge-control secrets
are never returned.
