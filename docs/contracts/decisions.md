# Phase 0 Decisions

Status: draft, pending user approval.

## Sources Reviewed

- Workspace `AGENTS.md`
- Workspace `USERSTORY.md`
- `paperboat-server/AGENTS.md`
- `paperboat-server/docs/PLAN.md`
- `agentunnel/docs/api.md`
- `agentunnel/docs/cloud-agents-platform-plan.md`
- `papercode/AGENTS.md`
- `papercode/docs/architecture/remote.md`
- `papercode/docs/architecture/connection-runtime.md`
- `papercode/docs/cloud/environment-auth.md`
- `papercode/docs/user/remote-access.md`
- `paperboat-dashboard/AGENTS.md`
- `paperboat-cli/AGENTS.md`

## Approved Or Draft Decisions

### Control Plane Boundary

Status: proposed approval.

`paperboat-server` is a control plane only. Live terminal, SSH, preview, HTTP, and
WebSocket traffic stays out of `paperboat-server` and flows through `agentunnel` and
the per-VM papercode server.

### Persistence Backend

Status: approved.

Decision:

Postgres ships from the first production release. Phase 2 migrations create Paperboat
objects inside a dedicated `paperboat` schema so the service does not collide with
provider-managed or pre-existing `public` schema tables.

Implementation rules:

- `paperboat-server migrate` applies forward-only migrations.
- Runtime repositories use explicit transaction boundaries and set their transaction
  search path to the `paperboat` schema.
- Dynamic catalogs are seeded with `paperboat-server seed-catalogs`; catalog values remain
  data, not Go constants.

### Plan Values, Credits, Storage, and Machine Weights

Status: TBD.

Decision required before Phase 4 seed data:

- Sailor, Navigator, Captain included credits.
- Sailor, Navigator, Captain included storage GB.
- Credit top-up product catalog.
- Extra storage per-GB monthly billing catalog.
- Machine type catalog and credit-per-hour weights.
- Minimum credit threshold needed to start/resume a machine, if any.

All values must be seed data or database records, not Go constants that require redeploy.

### WorkOS Session Model

Status: pending approval.

Proposed:

- Dashboard uses WorkOS authentication and sends the callback to
  `POST /api/auth/workos/callback`.
- Server maps WorkOS subject plus email to a Paperboat user idempotently.
- Browser session uses an HttpOnly secure session cookie and CSRF token.
- Core feature APIs require both authenticated session and active entitlement.

TBD before Phase 3:

- Production dashboard origin allowlist.
- WorkOS redirect/callback URL list for local, preview, staging, and production.
- Session idle and absolute expiry durations.

### Polar Catalog and Webhooks

Status: TBD.

Decision required before Phase 4:

- Polar product IDs and price IDs for plans.
- Polar product IDs and price IDs for top-ups.
- Polar product IDs and price IDs for extra storage.
- Customer portal behavior for subscription change, extra storage cancellation, and
  payment-method update.
- Webhook event allowlist and entitlement transition policy.

### Fly.io Organization and Resource Naming

Status: TBD.

Decision required before Phase 7:

- Fly organization slug.
- App naming policy.
- Machine naming/tagging policy.
- Volume naming/tagging policy.
- Region allowlist and default placement policy.
- Machine image reference policy.
- Restart behavior for applying pending config changes.
- Volume resize or replacement policy.

### GitHub OAuth and Config Repo

Status: pending approval.

Proposed:

- GitHub OAuth is required before first project creation.
- Server stores encrypted GitHub token material.
- Server provisions one private per-user config repository.
- VM daemon handles ongoing config sync; server provisions repo and credentials only.

TBD before Phase 5:

- Required OAuth scopes.
- Config repo name policy.
- Token refresh/revalidation cadence.
- Token revocation behavior.
- Clone credential model for project repositories and config sync.

### agentunnel Pre-Connect

Status: pending approval.

Proposed:

- `paperboat-server` authorizes user/project/entitlement state.
- `paperboat-server` provisions or looks up agentunnel resources.
- Returned descriptors reference agentunnel-managed SSH/TCP/WebSocket/preview routes.
- No agentunnel client tokens, API keys, SSH private keys, or raw credentials are
  returned to dashboard, papercode, or CLI clients.

See [access-handoff.md](access-handoff.md).

### papercode AccessEndpoint

Status: pending approval.

Proposed:

- Paperboat represents hosted project VMs as papercode environments.
- Remoteness is expressed as a tunneled `AccessEndpoint`.
- The final papercode client connection is still HTTP/WebSocket to the per-VM T3 server
  through agentunnel.
- Paperboat does not split papercode runtime behavior.

See [access-handoff.md](access-handoff.md).

### paperboat-cli Descriptor

Status: pending approval.

Proposed:

- CLI asks `paperboat-server` for a project CLI connect descriptor.
- Descriptor tells CLI how to open the agentunnel-mediated terminal/SSH path and how to
  reach the VM papercode server upload endpoint for image paste bridging.
- CLI reuses papercode auth config; no separate login.

### Custom Fly Shapes

Status: TBD.

Decision required before exposing custom-shape API fields:

- Ship first release with fixed machine catalog only and custom shape creation disabled.
- Or ship user-defined Fly shape creation in first release.

Schema must remain compatible with future custom shapes either way.

## Open Blockers

These block marking Phase 0 complete:

- Plan, credit, storage, top-up, extra storage, and machine weight values.
- WorkOS origins and callback URLs.
- Polar product IDs, price IDs, and webhook allowlist.
- Fly organization, naming, region, image, restart, and volume policies.
- GitHub OAuth scopes, repo naming, token lifecycle, and clone credential policy.
- agentunnel handoff approval.
- papercode AccessEndpoint descriptor approval.
- paperboat-cli descriptor approval.
- Custom Fly shape release decision.
