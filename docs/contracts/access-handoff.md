# Access Handoff Contracts

Status: implemented contract baseline, pending final client field-name sign-off.

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

Response data shape:

```json
{
  "project_id": "prj_...",
  "project_state": "running",
  "connectable": true,
  "expires_at": "2026-07-05T12:00:00Z",
  "descriptors": []
}
```

## `POST /api/projects/{project_id}/papercode-connect`

Purpose:

- Return a papercode environment registration and tunneled WebSocket endpoint.

Proposed response data shape:

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

- Environment stays one per-VM T3 server.
- Access is modeled as an `AccessEndpoint`.
- Client connection remains HTTP/WebSocket.
- Endpoint reachability is a hint until client connects successfully.

Approved baseline:

- Papercode receives one Paperboat environment per project VM.
- The endpoint is an agentunnel-backed HTTP/WebSocket route to the VM-local T3 server.
- Field names in this document are versioned contract names until papercode finalizes
  native `AccessEndpoint` naming.
- Descriptor expiry requires the client to request a fresh `papercode-connect`
  descriptor; reconnect never extends a descriptor client-side.
- Revocation is server-side: entitlement loss, project deletion/suspension, or credential
  invalidation causes future descriptor requests to fail and active agentunnel/papercode
  sessions to be closed by provider-side revocation where supported.

## `POST /api/projects/{project_id}/cli-connect`

Purpose:

- Return CLI-safe connection metadata for terminal attach and image paste upload.
- The CLI is a headless papercode terminal client: it attaches over the
  tunneled papercode HTTP/WebSocket route, not over SSH.

Proposed response data shape:

```json
{
  "project_id": "prj_...",
  "connectable": true,
  "expires_at": "2026-07-05T12:00:00Z",
  "environment": {
    "environment_id": "env_...",
    "display_name": "Project name",
    "project_root": "/workspace"
  },
  "terminal": {
    "kind": "papercode_websocket",
    "http_base_url": "https://...",
    "websocket_base_url": "wss://...",
    "auth": {
      "method": "websocket_ticket",
      "ticket": "pct_...",
      "expires_at": "2026-07-05T12:00:00Z",
      "scopes": ["terminal:operate"]
    },
    "thread_id": "paperboat-cli",
    "terminal_id": "term-1",
    "cwd": "/workspace"
  },
  "upload": {
    "kind": "papercode_file_upload",
    "http_base_url": "https://...",
    "auth": {
      "method": "bearer",
      "token": "pat_...",
      "expires_at": "2026-07-05T12:00:00Z",
      "scopes": ["terminal:operate"]
    },
    "max_bytes": 10485760,
    "allowed_mime_types": ["image/png", "image/jpeg", "image/webp"]
  }
}
```

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
- Credential method is issuer-defined and short-lived. The server may return only
  issuer-validated terminal/upload auth metadata.
- Terminal ids are per connect descriptor unless the credential issuer explicitly returns
  stable ids.
- Upload endpoint path, image size limit, and MIME policy are dynamic credential issuer or
  server configuration values, never CLI constants.

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
