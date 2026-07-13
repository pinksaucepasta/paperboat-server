# Project VM Runtime

Phase 6 owns the Fly machine image contract consumed by `paperboat-server` machine specs.
The default boot command is `/usr/local/bin/paperboat-entrypoint`.

Build the image from the workspace root through:

```sh
paperboat-server/deploy/project-vm/build-image.sh registry.example/paperboat/project-vm:tag
```

The build requires `PAPERBOAT_NODE_BASE_IMAGE` and `PAPERBOAT_GO_BASE_IMAGE`, each an
immutable `name@sha256:<digest>` reference. Tag-only base images are rejected. It also
requires clean `paperboat-server`, `papercode`, and `agentunnel` source trees and records
each source and base-image reference in OCI labels. For local development only,
`PAPERBOAT_ALLOW_DIRTY_SOURCES=true` permits an uncommitted source tree. Papercode is a
mandatory image component; there is no production-disabled build or boot mode.

## Required Runtime Inputs

- `PAPERBOAT_PROJECT_ID`
- `PAPERBOAT_REPOSITORY_URL`
- `PAPERBOAT_AGENTUNNEL_SERVER_URL`
- `PAPERBOAT_AGENTUNNEL_CLIENT_ID`
- `PAPERBOAT_AGENTUNNEL_TUNNEL_ID`
- `AGENTUNNEL_MACHINE_TOKEN` from the Fly process secret configured as
  `fly.agentunnel_secret`

Optional inputs are env-driven: workspace path, papercode local URL, config repo URL,
config branch, preset directory, setup script, activity interval, and the complete config-sync
policy (home override, include/exclude patterns, byte ceilings, timing, retry, and retention).

## Boot Order

1. Validate required env and create runtime/log/workspace directories.
2. Clone the project repository into the mounted workspace if it is not already a git repo.
3. Restore managed home configuration from the GitHub-backed Paperboat config repo.
4. Start the supervised config-sync daemon.
5. Apply selected preset scripts from `/etc/paperboat/presets.d`.
6. Start papercode `apps/server` in headless mode against the project workspace.
7. Wait for the local papercode HTTP endpoint.
8. Start the agentunnel machine client for the project route.
9. Wait for the agentunnel route readiness probe.
10. Start the activity reporter and write readiness JSON.

The sync checkout lives under `/var/lib/paperboat/config-sync`, outside both `$HOME` and the
project workspace. The daemon recursively watches managed home paths, reconciles remote changes,
coalesces local writes, enforces file and batch ceilings, and writes atomic health state to
`/var/lib/paperboat/config-sync-status.json`. Initial restore failures block readiness. Later
network or Git failures leave the VM usable and retry; shutdown always recomputes the full managed
snapshot and waits for a bounded final flush, even when the watcher observed no event.
Shutdown keeps the activity reporter alive until the daemon flush or fallback save has written its
terminal status. The reporter then sends one final heartbeat, bounded by
`PAPERBOAT_ACTIVITY_SHUTDOWN_REPORT_SECONDS`, before it exits so the control plane observes the
shutdown sync result.
Fly's machine stop timeout is derived from the configured flush deadline, daemon grace period,
and final-report timeout, so the platform grace period covers the complete shutdown sequence.
The control plane persists the status file's own `updated_at` separately from activity-heartbeat
time, so an active reporter cannot keep a failed or stopped sync daemon falsely online.
On the first restore, the remote snapshot is canonical: managed files present only in the image's
home directory are removed before the baseline is recorded, while unmanaged and mandatory-excluded
paths remain untouched. When no config repository is configured, restore, sync, and flush are
successful no-ops and shutdown does not wait for the flush deadline.
Batch accounting counts unique config blobs newly introduced to Git. A conflict artifact may
reference the losing blob already present in the remote history without charging those bytes a
second time; its bounded Paperboat metadata is excluded from the user-data ceiling. The final
staged-object guard still applies the per-file ceiling to preserved conflict content and rejects
new config blob data above the batch ceiling.

The runtime creates or upgrades `.paperboat/config-sync.json` in the private config repository.
This manifest records the complete effective server policy and retains user include/exclude
patterns and stricter repository byte limits. Upgrades never remove unrelated tracked content.
Symlink targets are normalized to portable relative paths and restored only when they remain
inside the destination home. Copy and deletion operations also resolve destination parent
directories before modifying them, so an existing symlink cannot redirect a restore outside
`$HOME`. Any snapshot read or traversal failure aborts that reconciliation instead of being
interpreted as a remote deletion.

Mandatory exclusions are additive and cannot be replaced by server, repository, or user policy.
They cover credential stores, SSH/GPG and cloud credentials, Git/package-manager credentials,
agent authentication and session state, browser/runtime state, caches, logs, histories,
environment files, and temporary editor files. The runtime unions its built-in security policy
with server additions as a final defense before snapshotting.

Concurrent same-path changes create an atomic, collision-resistant artifact under
`.paperboat/conflicts` containing metadata and the losing file content or symlink target. The
canonical path is changed only after artifact creation succeeds. Conflict summaries remain in
health status across routine polls and restarts while their metadata remains in the private
repository; deleting the reviewed artifact resolves the dashboard warning.

Before cloning, the runtime stores the stable Paperboat project and papercode environment
identities below `.paperboat/identity` on the mounted volume. A later boot with mismatched
identity fails before modifying repository data. Project directory names are restricted to
a single non-reserved path segment.

Readiness is written to `/var/lib/paperboat/readiness.json`. A ready VM means the mounted
workspace exists, config sync completed, papercode is listening locally, and the agentunnel
machine client has completed its authenticated relay connection for the assigned project
route. Agentunnel publishes its state atomically in
`/var/lib/paperboat/agentunnel-status.json`; stale state is replaced with `connecting`
before each connection and becomes `disconnected` when the route drops. The entrypoint
changes VM readiness to failed during reconnect, and the Docker healthcheck independently
requires the agentunnel state to be `connected`. Both return to ready after reconnection.

Readiness updates are atomic and identify the active boot stage. A partial boot records
`state=failed` with the failing stage before teardown; the next boot immediately replaces
that stale state as it reconciles the workspace, config, services, and route. This keeps Fly
health and control-plane diagnostics aligned without exposing command output or secrets.

The image Docker healthcheck runs `/usr/local/bin/paperboat-healthcheck`, which reports
healthy only when the readiness JSON state is `ready`.

Production server configuration requires `agentunnel.machine_mode=required`. An agentunnel
startup or runtime failure therefore fails the VM instead of leaving a papercode process
running behind an unavailable route. Optional restart mode is limited to non-production
diagnostics.

`PAPERBOAT_AGENTUNNEL_FORWARD_COMMAND` can override the default client launch command.
Use it when the hosted dev agentunnel exposes a more specific HTTP/WSS machine-client
forwarder than `agentunnel client run --config`.

Project Fly machine configs intentionally contain no `services` entries. Papercode binds
inside the machine and is reachable only through its assigned Agentunnel HTTP/WSS route;
no public Fly application port is created. The launcher rejects non-loopback papercode host
configuration and invalid ports instead of accidentally exposing the application server.
