# Access Handoff Contracts

Status: implementation contract pending the current contract freeze.

## Boundary

`paperboat-server` authorizes and brokers access. It never carries terminal,
file-transfer, preview, HTTP, WebSocket, or QUIC payload bytes. Ready project and
user-machine endpoints return the common `paperboat.environment-connection/v1`
descriptor defined by `contracts/schemas/environment/connection-v1.schema.json`.

Before returning a ready descriptor, the server verifies ownership, entitlement,
environment state, active helper generation, applied route, ready edge assignment,
and the selected terminal session. A not-ready response contains no operation
credentials.

## Connection Descriptor

Ready descriptors contain client-safe environment identity, negotiated capabilities,
terminal endpoints and auth, and the file-transfer endpoint, auth, and authoritative
policy. They never expose connector credentials, provider tokens, edge internals,
helper loopback tokens, VM addresses, or reusable infrastructure credentials.

```json
{
  "schema": "paperboat.environment-connection/v1",
  "issuer": "https://api.paperboat.example",
  "connectable": true,
  "expires_at": "2026-07-29T12:05:00Z",
  "environment": {
    "id": "env_...",
    "kind": "hosted",
    "resource_id": "prj_...",
    "display_name": "Project name",
    "state": "ready",
    "root": "/workspace/project"
  },
  "helper": {"id": "hlp_...", "generation": 7},
  "capabilities": ["terminal", "file_transfer", "preview"],
  "terminal": {
    "protocol": "paperboat.terminal.v2",
    "endpoints": {
      "quic": "quic://environment.example:443",
      "wss": "wss://environment.example/v1/runtime"
    },
    "auth": {
      "method": "bearer",
      "token": "...",
      "expires_at": "2026-07-29T12:05:00Z",
      "scopes": ["terminal:operate"]
    },
    "session_id": "ses_...",
    "thread_id": "paperboat-cli",
    "terminal_id": "default",
    "cwd": "/workspace/project"
  },
  "file_transfer": {
    "endpoint": "https://environment.example/v1/file-transfers",
    "auth": {
      "method": "bearer",
      "token": "...",
      "expires_at": "2026-07-29T12:05:00Z",
      "scopes": ["file:transfer"]
    },
    "policy": {
      "revision": "file-transfer-v1",
      "max_file_bytes": 52428800,
      "max_batch_files": 10,
      "max_batch_bytes": 524288000,
      "max_concurrent_transfers": 2,
      "retention_seconds": 604800,
      "delivery_timeout_seconds": 600,
      "max_pending_spool_bytes": 1073741824
    }
  },
  "status": "ready",
  "reason": "ready",
  "retry_after_seconds": 0
}
```

Hosted environments use `kind=hosted` and a project resource ID. User machines use
`kind=byod` and a user-machine resource ID. The stable environment ID is distinct
from either resource ID.

`POST /v1/projects/{project_id}/connection-descriptor` and
`POST /v1/user-machines/{user_machine_id}/connection-descriptor` accept the selected
terminal session. Their readiness endpoints retain that selection while polling but
never return operation credentials.

## Credentials

The server signs two independent five-minute operation credentials:

- `terminal_operation` has exact scope `terminal:operate`.
- `file_transfer` has exact scope `file:transfer`.

Both bind the environment, user, CLI client session, and selected terminal session.
The CLI proactively re-brokers them through its revocable CLI session and retries one
request after `401`. Credential expiry or rotation only authorizes requests; it does
not expire terminal state, transfer IDs, committed offsets, staged content, pending
deliveries, partial inbox files, or completed records. Session/client revocation does
stop access immediately.

The helper agent uses its durable private loopback token for `pbh send`; that token is
never returned in a connection descriptor and does not depend on the short-lived CLI
credential.

## File Transfer

The descriptor policy must exactly match the helper `/healthz` capability response.
The CLI disables file transfer, without disabling the terminal, if they differ.

All file bytes are opaque. The helper exposes one resumable resource API at
`/v1/file-transfers` for both `pb -> pbh` staging and `pbh send -> pb` delivery. It
accepts regular files, including empty files, without MIME policy. Authorization
determines which direction may be created and binds every resource to its session and
CLI client. See `contracts/helper/operations.md` for methods, states, receipts, and
typed errors.

The helper receives the same signed `FileTransferPolicy` in connector admission and
enforces it dynamically. The server remains the only authority for limits, retention,
concurrency, delivery timeout, spool capacity, and policy revision.

## Readiness And Failure

Pending descriptors use `connectable=false`, omit terminal/file credentials, provide
a stable status and reason, and set a positive `retry_after_seconds`. Ready descriptors
use `connectable=true`, `status=ready`, `reason=ready`, and zero retry delay.

Descriptor creation fails closed when identity, ownership, entitlement, helper,
connector, route, minting, or selected-session checks fail. No placeholder or
server-local token may be returned.
