# Hosted Project Image

The managed image runs `paperboat-helper run`. Papercode and standalone Agentunnel are not
image components: the helper owns workspace boot, durable sessions, the embedded frp
connector, readiness, and bounded shutdown.

Build from the workspace root through:

```sh
paperboat-server/deploy/project-vm/build-image.sh registry.example/paperboat/project-vm:tag
```

`PAPERBOAT_NODE_BASE_IMAGE` and `PAPERBOAT_GO_BASE_IMAGE` must be immutable
`name@sha256:<digest>` references. Clean `paperboat-helper` and `paperboat-server` revisions
are recorded as OCI labels. The image records hosted contract/protocol metadata and installs
Herdr 0.7.4 from architecture-specific release assets whose SHA-256 values are checked.

## Boot Contract

The control plane supplies project/repository/branch/preset/setup intent, the control URL,
the helper profile and state root, config-sync policy, and a one-time helper enrollment as
a named Fly secret. The helper persists its key and renewable runtime identity below the
mounted volume, removes one-time enrollment and setup values from its environment, writes
the age identity to its configured `0600` file, and then performs:

1. Validate the volume, project identity, repository host/URL, branch, preset catalog, and
   all execution bounds.
2. Create or verify the durable workspace identity and clone/fetch the exact HTTPS origin.
3. Restore assigned configuration through `paperboat-config-sync`.
4. Apply catalog presets and the bounded setup revision.
5. Fetch control-plane JWKS, verify operation credentials, request connector admission,
   and start the embedded frp route.
6. Report ready only after the hosted lifecycle and edge connector are both ready.

Shutdown stops admission, drains the connector and sessions, performs the bounded
config-sync save hook, closes durable state, and exits within the Fly stop timeout. The
Docker healthcheck reads the helper `/healthz` response and requires liveness plus ready
`hosted_lifecycle` and `edge` capabilities.

The image contains Git, CA roots, Node/npm, Python/venv, the helper, Herdr, config-sync,
version-pinned catalog preset definitions, and shell tooling required by supported presets. It exposes no Fly service;
all terminal/upload/preview traffic traverses the assigned Paperboat edge route.

## Rollout And Rollback

Server catalogs must reference the image by immutable digest. Rollout metadata includes
the helper/server revisions, helper protocol, hosted image contract, Herdr version,
architecture, and both base-image digests. Rollback selects the previous compatible image
digest and preserves the mounted volume; it does not rewrite workspace identity or apply
pending project configuration silently.

Verify the retained rollback image before promotion:

```sh
deploy/project-vm/tests/image-rollback-check.sh CURRENT_IMAGE ROLLBACK_IMAGE
```
