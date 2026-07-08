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
- `paperboat-server` does not proxy live terminal, SSH, preview, or WebSocket traffic.

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

- `GET /healthz`
- `GET /readyz`

### Auth and Session

- `GET /api/me`
- `POST /api/auth/workos/callback`
- `POST /api/auth/logout`
- `GET /api/auth/csrf`

### Billing and Entitlements

- `GET /api/billing/entitlement`
- `GET /api/billing/usage`
- `GET /api/dashboard/usage-summary`
- `POST /api/billing/checkout`
- `POST /api/billing/customer-portal`
- `POST /api/webhooks/polar`

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
- `GET /api/projects/{project_id}/connection-status`

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
- `internal_error`

Adding or renaming public codes after approval requires explicit contract approval.

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
