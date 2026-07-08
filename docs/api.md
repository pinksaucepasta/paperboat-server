# Paperboat Server API

Status: Phase 10 hardening complete. The machine-readable schema is
[`docs/openapi.json`](openapi.json).

This API is the control-plane contract for dashboard and CLI clients. It authorizes,
meters, and orchestrates resources; it does not proxy SSH, terminal, preview, or
WebSocket data.

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

Mutable resources include a numeric `version`. Dashboard updates to
`PATCH /api/projects/{project_id}` must send either an `If-Match` header containing that
version or a `version` field in the JSON body. Stale writes fail with `version_conflict`.

## Dashboard Reads

- `GET /api/me`
- `GET /api/billing/entitlement`
- `GET /api/billing/usage`
- `GET /api/billing/plan-products`
- `GET /api/dashboard/usage-summary`
- `GET /api/catalog/plans`
- `GET /api/catalog/machine-types`
- `GET /api/catalog/presets`
- `GET /api/catalog/idle-timeouts`
- `GET /api/catalog/regions`
- `GET /api/github/status`
- `GET /api/projects`
- `GET /api/projects/{project_id}`
- `GET /api/projects/{project_id}/events`
- `GET /api/projects/{project_id}/connection-status`

`GET /api/projects` returns a shaped list response:

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
machine types, presets, idle timeouts, regions, credit weights, or storage limits.

## Dashboard Writes

- `POST /api/auth/workos/callback`
- `POST /api/auth/logout`
- `POST /api/billing/checkout`
- `POST /api/billing/customer-portal`
- `POST /api/github/oauth/start`
- `GET /api/github/oauth/callback`
- `POST /api/github/oauth/callback`
- `POST /api/github/config-repo/provision`
- `POST /api/projects`
- `PATCH /api/projects/{project_id}`
- `DELETE /api/projects/{project_id}`
- `POST /api/projects/{project_id}/start`
- `POST /api/projects/{project_id}/stop`
- `POST /api/projects/{project_id}/restart`
- `POST /api/projects/{project_id}/keep-alive`
- `POST /api/projects/{project_id}/activity`

Project create returns `201` for a new idempotency key and `200` for a matching retry.
Project lifecycle writes return accepted state and enqueue provider work; clients should
use project reads, project events, and connection status for progress.

## CLI Access

- `POST /api/projects/{project_id}/cli-connect`
- `GET /api/projects/{project_id}/connection-status`

`cli-connect` returns a short-lived descriptor that lets the CLI connect through
agentunnel. The server may start or resume the project machine before returning the
descriptor. Live terminal traffic still goes through agentunnel, not this API.

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
- `provider_unavailable`
- `tunnel_unavailable`
- `tunnel_not_ready`
- `credential_issuer_unavailable`
- `github_config_not_ready`
- `invalid_activity_source`
- `invalid_keep_alive`
- `invalid_pagination`
- `invalid_sort`
- `invalid_version`
- `version_required`
- `version_conflict`
- `internal_error`

Adding, removing, or renaming public error codes requires contract approval.
