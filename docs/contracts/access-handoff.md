# Access Handoff Contracts

Status: Phase 0 frozen implementation target.

## Boundary

`paperboat-server` authorizes and brokers access. It never carries live terminal, SSH,
preview, HTTP, or WebSocket traffic.

Live data path:

```text
papercode / paperboat-cli / dashboard
  -> agentunnel route
  -> project VM
  -> papercode server / preview service
```

SSH, if enabled, is optional debug/operator access only. It is not the
production CLI handoff and must not be returned from `cli-connect`.

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
- Machine and agentunnel resources exist or can be reconciled.
- Access event and failure reason are recorded.

## Shared Descriptor Rules

Descriptors:

- Are short-lived.
- Include `expires_at`.
- Include `project_id`.
- Include current `project_state`.
- Include connection status and reason if not connectable.
- Include only client-safe routing metadata.
- Exclude raw agentunnel client tokens, API keys, SSH keys, provider tokens, and
  VM-injected credentials.

## `POST /api/projects/{project_id}/connect`

Purpose:

- Generic access descriptor for dashboard or future clients.

Ready response data shape (`200`):

```json
{
  "project_id": "prj_...",
  "project_state": "running",
  "connectable": true,
  "status": "ready",
  "reason": "ready",
  "retry_after_seconds": 0,
  "expires_at": "2026-07-05T12:00:00Z",
  "descriptors": []
}
```

## `POST /api/projects/{project_id}/papercode-connect`

Purpose:

- Return a papercode environment registration and tunneled WebSocket endpoint.

Frozen response data shape:

```json
{
  "project_id": "prj_...",
  "environment": {
    "environment_id": "env_...",
    "display_name": "Project display name from project metadata",
    "repository_identity": {
      "provider": "github",
      "owner": "example",
      "name": "repo"
    }
  },
  "access_endpoint": {
    "kind": "tunneled_websocket",
    "provider": "agentunnel",
    "http_base_url": "https://...",
    "websocket_base_url": "wss://...",
    "compatibility": {
      "hosted_https_web": true,
      "desktop": true,
      "mobile": true
    },
    "expires_at": "2026-07-05T12:00:00Z"
  }
}
```

Alignment with papercode docs:

- Environment identity stays one per project and is served by the project's current VM-local
  T3 server.
- Access is modeled as an `AccessEndpoint`.
- Client connection remains HTTP/WebSocket.
- Endpoint reachability is a hint until client connects successfully.

Approved baseline:

- Papercode receives one stable Paperboat environment per project, served by the current VM.
- The endpoint is an agentunnel-backed HTTP/WebSocket route to the VM-local T3 server.
- Field names in this document are versioned contract names until papercode finalizes
  native `AccessEndpoint` naming.
- Descriptor expiry requires the client to request a fresh `papercode-connect`
  descriptor; reconnect never extends a descriptor client-side.
- Revocation is server-side: entitlement loss, project deletion/suspension, or credential
  invalidation causes future descriptor requests to fail and active agentunnel/papercode
  sessions to be closed by provider-side revocation where supported.

## `POST /api/projects/{project_id}/cli-connect`

Ready CLI descriptors include `issuer`, the normalized Paperboat public issuer. Clients
must compare it to the normalized issuer of their active credential profile before using
any terminal or upload endpoint.

The descriptor's `environment` object includes both `environment_id` (the stable runtime
identity) and `project_id` (the owning Paperboat project). These identifiers are distinct;
clients bind the environment to `project_id` and do not infer one from the other.

`POST /api/projects/{project_id}/activity` accepts either the dashboard cookie plus CSRF
header or a Paperboat bearer session with `projects:connect`; CLI activity uses the latter
and sends `source: "cli_activity"` with the event name in metadata.

Purpose:

- Return CLI-safe connection metadata for terminal attach and image paste upload.
- The CLI is a headless papercode terminal client: it attaches over the
  tunneled papercode HTTP/WebSocket route, not over SSH.

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
    "kind": "papercode_websocket",
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
    "kind": "papercode_staged_image",
    "http_base_url": "https://...",
    "path": "/api/files/staged-images",
    "auth": {
      "method": "bearer",
      "token": "pat_...",
      "expires_at": "2026-07-05T12:00:00Z",
      "scopes": ["file:stage"]
    },
    "max_bytes": 10485760,
    "allowed_mime_types": ["image/png", "image/jpeg", "image/webp"],
    "retention_seconds": 604800
  }
}
```

`thread_id` and `terminal_id` are server-authored protocol identifiers, not project or
machine identities. `expires_at` is no later than any nested credential expiry. Endpoint
URLs must be HTTPS/WSS agentunnel routes and never contain VM addresses or provider tokens.

Not-ready `cli-connect` responses use HTTP `202`, `connectable: false`, and one of these
stable statuses:

- `machine_starting` with reason `machine_start_queued` or `machine_not_running`
- `tunnel_connecting` with reason `tunnel_offline`
- `papercode_starting` with reason `papercode_unhealthy`

They include `project_id`, `project_state`, `status`, `reason`, and
`retry_after_seconds`. Every pending combination has `connectable: false` and a positive
retry interval. The only ready combination is `connectable: true`, `status: ready`,
`reason: ready`, and `retry_after_seconds: 0`.
`GET /api/projects/{project_id}/connection-status` reports those
readiness fields but never returns terminal or upload credentials. Once it reports ready,
the client calls `cli-connect` again to mint fresh auth material.

Runtime status:

- In fake-provider mode, `cli-connect` issues short-lived scoped terminal/upload auth
  metadata for local orchestration coverage.
- In real-provider mode, `cli-connect` must fail closed with
  `credential_issuer_unavailable` unless a papercode-valid credential issuer is configured.
- Do not return random, placeholder, unpersisted, or server-local-only token strings in
  `terminal.auth` or `upload.auth`.

Approved baseline:

- Real-provider `cli-connect` requires a configured papercode credential issuer. Without
  it, the endpoint fails closed with `credential_issuer_unavailable`.
- Terminal auth is a single-use WebSocket ticket scoped to `terminal:operate`. Upload auth
  is a short-lived bearer token scoped only to `file:stage`.
- Terminal ids are per connect descriptor unless the credential issuer explicitly returns
  stable ids.
- Upload endpoint path, image size limit, and MIME policy are dynamic credential issuer or
  server configuration values, never CLI constants.
- The environment id is allocated with the project and is stable across machine stop/start,
  machine replacement, and route reconciliation. It changes only when the project identity
  is permanently deleted and recreated.

## Papercode Mint Proof

The production mint request is a compact Ed25519 JWS with `alg=EdDSA`,
`typ=t3-cloud-mint+jwt`, and a required `kid` published by the Paperboat issuer's JWKS.
The payload and verification rules are owned by papercode's
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
- Every issued papercode session id is recorded against the Paperboat client session so
  logout, entitlement loss, project suspension/deletion, account suspension, and refresh
  replay can revoke downstream access.
- `cli-connect` performs two independent mint/exchange flows: one session requests exactly
  `terminal:operate` and produces the WebSocket ticket; the other requests exactly
  `file:stage` and supplies the upload bearer. A bootstrap credential is never reused, and
  both downstream session ids are recorded for revocation.
- Papercode creates both pairing grants without a proof-key thumbprint. `paperboat-server`
  exchanges each bootstrap credential without a DPoP header, so papercode issues scoped
  bearer sessions. The terminal bearer remains server-side and is used only to mint the
  single-use WebSocket ticket; the short-lived file bearer is the only access token returned
  to the CLI. Papercode's separate proof-bound pairing profile remains DPoP-only.

The normalized Paperboat issuer publishes `GET /.well-known/jwks.json`. It is
unauthenticated and returns public signing keys with `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`,
`use=sig`, `kid`, and `x`. Cache lifetime and rotation overlap are dynamic configuration.
Private key material is never exposed or stored in VM configuration.

## `POST /api/projects/{project_id}/activity`

Purpose:

- Let authenticated papercode and paperboat-cli clients report user/agent activity that
  should reset the server-owned idle detector.

Request data shape:

```json
{
  "source": "papercode_activity",
  "observed_at": "2026-07-05T12:00:00Z",
  "metadata": {
    "event": "editor_input"
  }
}
```

Approved client sources:

- `papercode_activity`
- `cli_activity`

Rules:

- The endpoint requires an authenticated, entitled project owner.
- `observed_at` is optional; the server records receipt time when it is omitted.
- The endpoint rejects `connect_session`, `agentunnel_connection`, and `vm_heartbeat`
  because those are server/provider-owned sources.
- Metadata is diagnostic only and must not contain secrets or billing totals.

## agentunnel Adapter Boundary

Observed agentunnel docs:

- API envelope uses `ok` plus `data` or `error`.
- Persistent TCP supports connect-info and forwarding status.
- Serving existing persistent TCP tunnel uses client-token auth.
- Desktop-safe connect info must not return raw client tokens, API keys, access-policy
  config, SSH keys, or passwords.

Paperboat adapter behavior:

- Calls agentunnel admin/control APIs server-side.
- Stores agentunnel resource IDs in `agentunnel_resources`.
- Translates agentunnel status into Paperboat connection status.
- Keeps agentunnel response envelope internal to the adapter.

Approved baseline:

- Paperboat uses server-side agentunnel admin/control APIs only.
- Paperboat stores resource identifiers and client-safe route metadata, not raw provider
  secrets.
- Agentunnel provisioning is idempotent and keyed by project.
- User connect descriptors are short-lived and default to five minutes unless configured
  otherwise.
- Revocation is implemented by refusing future descriptors and invoking provider-side
  resource/session revocation when the agentunnel API exposes it.
