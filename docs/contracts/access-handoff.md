# Access Handoff Contracts

Status: Contract frozen implementation target.

## Boundary

`paperboat-server` authorizes and brokers access. It never carries live terminal,
preview, HTTP, or WebSocket traffic.

Live data path:

```text
helper / paperboat-cli / dashboard
  -> provider_route route
  -> project VM
  -> helper server / preview service
```

Project access uses the ProviderRoute HTTP/WebSocket route exclusively. No project SSH/TCP
route is provisioned or returned from `cli-connect`.

Control path:

```text
client
  -> paperboat-server pre-connect endpoint
  -> server-side checks and provider lookups
  -> short-lived descriptor
```

## Server-Side Checks

Every connect endpoint must verify:

- User is authenticated.
- User owns project.
- User has active entitlement.
- User has enough credit state to connect or start according to approved policy.
- Project is not deleted, deleting, failed without recovery, or suspended.
- GitHub/config provisioning state is compatible with requested action.
- Machine and provider_route resources exist or can be reconciled.
- Access event and failure reason are recorded.

## Shared Descriptor Rules

Descriptors:

- Are short-lived.
- Include `expires_at`.
- Include `project_id`.
- Include current `project_state`.
- Include connection status and reason if not connectable.
- Include only client-safe routing metadata.
- Exclude raw provider_route client tokens, API keys, SSH keys, provider tokens, and
  VM-injected credentials.

The former generic `connect` and Helper-specific `helper-connect` endpoints are
retired. They are not registered production routes. Hosted terminal clients use the
canonical bearer-authenticated endpoint below.

## `POST /v1/projects/{project_id}/connection-descriptor`

Ready CLI descriptors include `issuer`, the normalized Paperboat public issuer. Clients
must compare it to the normalized issuer of their active credential profile before using
any terminal or upload endpoint.

The descriptor's `environment` object includes both `environment_id` (the stable runtime
identity) and `project_id` (the owning Paperboat project). These identifiers are distinct;
clients bind the environment to `project_id` and do not infer one from the other.

`POST /v1/projects/{project_id}/activity` accepts either the dashboard cookie plus CSRF
header or a Paperboat bearer session with `projects:connect`; CLI activity uses the latter
and sends `source: "cli_activity"` with the event name in metadata.

Purpose:

- Return CLI-safe connection metadata for terminal attach and image paste upload.
- The CLI is a headless helper terminal client: it attaches over the
  tunneled helper HTTP/WebSocket route, not over SSH.

Frozen ready response data shape:

```json
{
  "project_id": "prj_...",
  "project_state": "running",
  "connectable": true,
  "status": "ready",
  "reason": "ready",
  "retry_after_seconds": 0,
  "expires_at": "2026-07-05T12:00:00Z",
  "environment": {
    "environment_id": "env_...",
    "display_name": "Project name",
    "project_root": "/workspace/project"
  },
  "terminal": {
    "kind": "paperboat_terminal_v1",
    "websocket_base_url": "wss://...",
    "auth": {
      "method": "websocket_ticket",
      "ticket": "pct_...",
      "expires_at": "2026-07-05T12:00:00Z",
      "scopes": ["terminal:operate"]
    },
    "thread_id": "paperboat-cli",
    "terminal_id": "term_...",
    "cwd": "/workspace/project"
  },
  "upload": {
    "kind": "paperboat_staged_image_v1",
    "http_base_url": "https://...",
    "path": "/v1/files/staged-images",
    "auth": {
      "method": "bearer",
      "token": "pat_...",
      "expires_at": "2026-07-05T12:00:00Z",
      "scopes": ["file:stage"]
    },
    "max_bytes": 10485760,
    "allowed_mime_types": ["image/*"],
    "retention_seconds": 604800
  }
}
```

`thread_id` and `terminal_id` are server-authored protocol identifiers, not project or
machine identities. `expires_at` is no later than any nested credential expiry. Endpoint
URLs must be HTTPS/WSS provider_route routes and never contain VM addresses or provider tokens.

Not-ready `cli-connect` responses use HTTP `202`, `connectable: false`, and one of these
stable statuses:

- `machine_starting` with reason `machine_start_queued` or `machine_not_running`
- `tunnel_connecting` with reason `tunnel_offline`
- `helper_starting` with reason `helper_unhealthy`

They include `project_id`, `project_state`, `status`, `reason`, and
`retry_after_seconds`. Every pending combination has `connectable: false` and a positive
retry interval. The only ready combination is `connectable: true`, `status: ready`,
`reason: ready`, and `retry_after_seconds: 0`.
`GET /v1/projects/{project_id}/connection-readiness` reports those readiness fields but never
returns terminal or upload credentials. Its optional `terminal_session_id` query parameter
retains the selected terminal identity during polling; once it reports ready, the client calls
`cli-connect` again with that same ID to mint fresh auth material.
Pending terminal close and history-purge operations are reconciled before it reports ready;
until then it returns `helper_starting` with
`terminal_session_operation_pending` and a retry interval.

Runtime status:

- In fake-provider mode, `cli-connect` issues short-lived scoped terminal/upload auth
  metadata for local orchestration coverage.
- In real-provider mode, `cli-connect` must fail closed with
  `credential_issuer_unavailable` unless a helper-valid credential issuer is configured.
- Do not return random, placeholder, unpersisted, or server-local-only token strings in
  `terminal.auth` or `upload.auth`.

Approved baseline:

- Real-provider `cli-connect` requires a configured helper credential issuer. Without
  it, the endpoint fails closed with `credential_issuer_unavailable`.
- Terminal auth is a single-use WebSocket ticket scoped to `terminal:operate`. Upload auth
  is a short-lived bearer token scoped only to `file:stage`.
- Terminal ids are per connect descriptor unless the credential issuer explicitly returns
  stable ids.
- Upload endpoint path, image size limit, and MIME policy are dynamic credential issuer or
  server configuration values, never CLI constants.

## User-machine descriptors

`POST /v1/user-machines/{user_machine_id}/connection-descriptor` and
`GET /v1/user-machines/{user_machine_id}/connection-readiness` uses the canonical
`paperboat.environment-connection/v1` descriptor. The connect request accepts the optional
`terminal_session_id` body field; status accepts it as a query field.

Ready responses bind the environment to the user machine:

```json
{
  "schema": "paperboat.environment-connection/v1",
  "connectable": true,
  "environment": {
    "id": "env_...",
    "kind": "byod",
    "resource_id": "um_...",
    "display_name": "Studio",
    "state": "ready",
    "root": "/home/user"
  },
  "terminal": {"endpoint": "wss://machine.example/v1/runtime"},
  "upload": {"endpoint": "https://machine.example/v1/uploads"}
}
```

The descriptor must not contain `project_id`, legacy user-machine fields, raw
connector addresses, connector tokens, or ProviderRoute/Helper implementation names.
Terminal and upload endpoints use the applied `helper_https_wss` route assigned to the
environment. Readiness requires the active environment and helper, the current admitted
connector generation, its matching applied route observation, and a ready assigned edge
node. Terminal and upload auth are separate server-signed `paperboat-credential+jwt`
bearer credentials, respectively classed `terminal_operation` with exact scope
`terminal:operate` and `image_stage` with exact scope `file:stage`. Both are bound to the
environment, user, client session, and selected terminal session and expire within five
minutes. A descriptor request fails closed when the machine is revoked, disconnected,
offline, lacks a seat, or has no remaining allowance/top-up capacity.
- The environment id is allocated with the project and is stable across machine stop/start,
  machine replacement, and route reconciliation. It changes only when the project identity
  is permanently deleted and recreated.

## Helper Mint Proof

The production mint request is a compact Ed25519 JWS with `alg=EdDSA`,
`typ=t3-cloud-mint+jwt`, and a required `kid` published by the Paperboat issuer's JWKS.
The payload and verification rules are owned by helper's
`packages/contracts/src/paperboat.ts` contract:

- Required claims: `iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `environmentId`,
  `clientSessionId`, `nonce`, and exactly `scope=["environment:connect"]`.
- `iss` is the normalized Paperboat server issuer, `aud` is
  `t3-env:<environmentId>`, and `sub` is the linked Paperboat owner id.
- The Paperboat profile intentionally omits `clientProofKeyThumbprint` and `cnf`. Neither
  the CLI nor `paperboat-server` generates, registers, or owns a downstream proof key.
- Maximum proof lifetime is 300 seconds and maximum accepted clock skew is 60 seconds.
- `jti` and `nonce` are atomically single-use and retained through expiry plus clock skew.
- JWKS caching follows HTTP cache policy. An unknown `kid` triggers one refresh. Old keys
  work only during the configured overlap while still published; unknown or unavailable
  keys fail closed.
- Every issued helper session id is recorded against the Paperboat client session so
  logout, entitlement loss, project suspension/deletion, account suspension, and refresh
  replay can revoke downstream access.
- `cli-connect` performs two independent mint/exchange flows: one session requests exactly
  `terminal:operate` and produces the WebSocket ticket; the other requests exactly
  `file:stage` and supplies the upload bearer. A bootstrap credential is never reused, and
  both downstream session ids are recorded for revocation.
- Helper creates both pairing grants without a proof-key thumbprint. `paperboat-server`
  exchanges each bootstrap credential without a DPoP header, so helper issues scoped
  bearer sessions. The terminal bearer remains server-side and is used only to mint the
  single-use WebSocket ticket; the short-lived file bearer is the only access token returned
  to the CLI. Helper's separate proof-bound pairing profile remains DPoP-only.

The normalized Paperboat issuer publishes `GET /.well-known/jwks.json`. It is
unauthenticated and returns public signing keys with `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`,
`use=sig`, `kid`, and `x`. Cache lifetime and rotation overlap are dynamic configuration.
Private key material is never exposed or stored in VM configuration.

## `POST /v1/projects/{project_id}/activity`

Purpose:

- Let authenticated helper and paperboat-cli clients report user/agent activity that
  should reset the server-owned idle detector.

Request data shape:

```json
{
  "source": "helper_activity",
  "observed_at": "2026-07-05T12:00:00Z",
  "metadata": {
    "event": "editor_input"
  }
}
```

Approved client sources:

- `helper_activity`
- `cli_activity`

Rules:

- The endpoint requires an authenticated, entitled project owner.
- `observed_at` is optional; the server records receipt time when it is omitted.
- The endpoint rejects `connect_session`, `provider_route_connection`, and `vm_heartbeat`
  because those are server/provider-owned sources.
- Metadata is diagnostic only and must not contain secrets or billing totals.

## provider_route Adapter Boundary

Observed provider_route docs:

- API envelope uses `ok` plus `data` or `error`.
- Persistent TCP supports connect-info and forwarding status.
- Serving existing persistent TCP tunnel uses client-token auth.
- Desktop-safe connect info must not return raw client tokens, API keys, access-policy
  config, SSH keys, or passwords.

Paperboat adapter behavior:

- Calls provider_route admin/control APIs server-side.
- Stores provider_route resource IDs in `provider_routes`.
- Translates provider_route status into Paperboat connection status.
- Keeps provider_route response envelope internal to the adapter.

Approved baseline:

- Paperboat uses server-side provider_route admin/control APIs only.
- Paperboat stores resource identifiers and client-safe route metadata, not raw provider
  secrets.
- ProviderRoute provisioning is idempotent and keyed by project.
- User connect descriptors are short-lived and default to five minutes unless configured
  otherwise.
- Revocation is implemented by refusing future descriptors and invoking provider-side
  resource/session revocation when the provider_route API exposes it.
