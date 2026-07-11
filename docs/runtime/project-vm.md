# Project VM Runtime

Phase 6 owns the Fly machine image contract consumed by `paperboat-server` machine specs.
The default boot command is `/usr/local/bin/paperboat-entrypoint`.

Build the image from the workspace root through:

```sh
paperboat-server/deploy/project-vm/build-image.sh registry.example/paperboat/project-vm:tag
```

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

Readiness is written to `/var/lib/paperboat/readiness.json`. A ready VM means the mounted
workspace exists, config sync completed, papercode is listening locally, and the agentunnel
route readiness probe has passed.

The image Docker healthcheck runs `/usr/local/bin/paperboat-healthcheck`, which reports
healthy only when the readiness JSON state is `ready`.

`PAPERBOAT_AGENTUNNEL_FORWARD_COMMAND` can override the default client launch command.
Use it when the hosted dev agentunnel exposes a more specific HTTP/WSS machine-client
forwarder than `agentunnel client run --config`.

Project Fly machine configs intentionally contain no `services` entries. Papercode binds
inside the machine and is reachable only through its assigned Agentunnel HTTP/WSS route;
no public Fly application port is created.
