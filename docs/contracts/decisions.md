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

Status: approved.

Decision:

The plan catalog, credit quantities, included storage quantities, credit top-up catalog,
extra-storage billing catalog, machine type catalog, and machine credit weights are
approved as dynamic catalog/database records.

Implementation rules:

- All values remain seed data or database records, not Go constants that require redeploy.
- `plans.current_version_id` and `plan_versions` are the source of truth for included
  subscription credits and included storage.
- `machine_types` and `machine_type_versions` are the source of truth for credit/hour
  weights used by metering.
- `billing_products` maps Polar product/price IDs to catalog entries. Plan products use
  `catalog_type = "plan"` and `catalog_ref = <plan_code>`. Credit top-ups use
  `catalog_type = "credit_topup"` and `catalog_ref = <credit_amount>`. Extra storage uses
  `catalog_type = "extra_storage"` and `catalog_ref = <purchased_storage_gb>`.

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

Status: approved.

Decision:

Polar product IDs, price IDs, product mapping, customer portal behavior, webhook event
allowlist, and entitlement transition policy are approved. The `billing_products` table is
the runtime source of truth for mapping Polar events to Paperboat resources.

Implementation rules:

- Webhook processing is idempotent by Polar event id.
- Subscription status maps to Paperboat states: `active`, `trialing`, `past_due`,
  `canceled`, `incomplete`, and `expired`.
- Only `active` and `trialing` entitlements unlock core features.
- Active or trialing plan webhooks grant the current plan-version included credits once per
  webhook event and set included storage through an append-only storage ledger entry.
- Credit top-up webhooks grant credits once per webhook event.
- Extra-storage webhooks set purchased storage through an append-only storage ledger entry.
- Refund, chargeback, or dispute webhooks reverse catalog-backed top-up credits without
  allowing negative balances, cancel extra storage only when doing so does not over-allocate
  existing project storage, and move matching plan subscriptions into a non-active state
  according to the event state mapping.

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

- WorkOS origins and callback URLs.
- Fly organization, naming, region, image, restart, and volume policies.
- GitHub OAuth scopes, repo naming, token lifecycle, and clone credential policy.
- agentunnel handoff approval.
- papercode AccessEndpoint descriptor approval.
- paperboat-cli descriptor approval.
- Custom Fly shape release decision.
