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
config branch, preset directory, setup script, and activity interval.

## Boot Order

1. Validate required env and create runtime/log/workspace directories.
2. Clone the project repository into the mounted workspace if it is not already a git repo.
3. Restore the GitHub-backed Paperboat config repo when configured.
4. Apply selected preset scripts from `/etc/paperboat/presets.d`.
5. Start papercode `apps/server` in headless mode against the project workspace.
6. Wait for the local papercode HTTP endpoint.
7. Start the agentunnel machine client for the project route.
8. Wait for the agentunnel route readiness probe.
9. Start the activity reporter and write readiness JSON.

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
