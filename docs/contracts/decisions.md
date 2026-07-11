# Phase 0 Decisions

Status: implemented contract baseline, pending final cross-project sign-off.

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

Status: approved baseline.

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
- Goose executes immutable SQL migrations from `internal/db/migrations`.
- sqlc generates typed application queries from `internal/db/queries`; generated code is
  checked in under `internal/db/dbsqlc`.
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

Status: approved baseline.

Decision:

- Dashboard uses WorkOS authentication and sends the callback to
  `POST /api/auth/workos/callback`.
- Server maps WorkOS subject plus email to a Paperboat user idempotently.
- Browser session uses an HttpOnly secure session cookie and CSRF token.
- Core feature APIs require both authenticated session and active entitlement.
- Allowed dashboard origins are environment-specific dynamic config values.
- WorkOS redirect and callback URLs are environment-specific provider configuration.
- Session idle and absolute expiry durations are dynamic config values and may differ by
  environment.

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

Status: approved baseline.

Decision:

- Fly organization slug, app name, image reference, default region, and region allowlist
  are dynamic config/catalog values.
- App names are environment-scoped and must be unique per Paperboat deployment.
- Machine names use the configured machine prefix plus project id.
- Volume names use the configured volume prefix plus project id.
- Machines and volumes are tagged with `managed_by=paperboat-server` and
  `paperboat_project_id=<project_id>`.
- Region placement is selected from the enabled `regions` catalog.
- Pending machine type, preset, setup script, and idle-timeout changes apply on restart.
- Project storage resize remains blocked until an explicit Fly volume resize/replacement
  policy is approved; storage changes keep `pending_restart_apply` intact.

### GitHub OAuth and Config Repo

Status: approved baseline.

Decision:

- GitHub OAuth is required before first project creation.
- Server stores encrypted GitHub token material.
- Server provisions one private per-user config repository.
- VM daemon handles ongoing config sync; server provisions repo and credentials only.
- OAuth scopes are dynamic config; production default is the minimum GitHub scopes that
  allow cloning authorized project repositories and provisioning/pushing the private
  config repository.
- Config repo name is dynamic config and defaults to `paperboat-config` in local examples.
- Token material is encrypted at rest, revalidated before sensitive provider operations,
  and treated as revoked when GitHub rejects validation or refresh.
- Clone/config sync credentials are VM-scoped secret material injected through provider
  secret handoff; they are never returned by user-facing APIs.

### agentunnel Pre-Connect

Status: approved baseline, descriptor details versioned in `access-handoff.md`.

Decision:

- `paperboat-server` authorizes user/project/entitlement state.
- `paperboat-server` provisions or looks up agentunnel resources.
- Returned descriptors reference agentunnel-managed HTTP/WebSocket/preview routes. SSH/TCP
  remains operator/debug access and is not returned to the production CLI.
- No agentunnel client tokens, API keys, SSH private keys, or raw credentials are
  returned to dashboard, papercode, or CLI clients.

See [access-handoff.md](access-handoff.md).

### papercode AccessEndpoint

Status: Phase 0 frozen; client field names are versioned in `access-handoff.md`.

Decision:

- Paperboat represents each project as one stable papercode environment whose current
  server runs on that project's VM.
- Remoteness is expressed as a tunneled `AccessEndpoint`.
- The final papercode client connection is still HTTP/WebSocket to the per-VM T3 server
  through agentunnel.
- Paperboat does not split papercode runtime behavior.

See [access-handoff.md](access-handoff.md).

### paperboat-cli Descriptor

Status: Phase 0 frozen; authorization is versioned in `cli-authorization.md` and the
descriptor/mint contract in `access-handoff.md`.

Decision:

- CLI asks `paperboat-server` for a project CLI connect descriptor.
- Descriptor tells CLI how to open the agentunnel-mediated papercode WebSocket path and how to
  reach the VM papercode server upload endpoint for image paste bridging.
- CLI uses dashboard-approved device authorization and its own revocable Paperboat client
  session. It never synthesizes a browser cookie or treats a papercode token as a Paperboat
  session.
- CLI terminal auth is a single-use `terminal:operate` WebSocket ticket. Upload auth is a
  separate short-lived bearer token scoped to `file:stage`.
- Paperboat's downstream papercode mint profile is intentionally keyless: its signed proof
  omits proof-key claims and its bootstrap exchanges omit DPoP. The terminal bearer stays
  server-side to mint the ticket; only the separately scoped file bearer reaches the CLI.

### Paperboat CLI Device Sessions

Status: Phase 0 frozen in [cli-authorization.md](cli-authorization.md).

Decision:

- WorkOS plus `paperboat-server` is the only Paperboat identity authority.
- Device grants are explicitly approved or denied through the dashboard and are single-use.
- Each installation has an independently revocable client-session family with rotating
  refresh tokens and family revocation on replay.
- CLI and papercode may share only the documented Paperboat credential profile and OS
  secure-store references, never private application state.

### Custom Fly Shapes

Status: approved.

Decision:

First release ships with fixed, catalog-driven machine types only. User-defined custom
Fly shape creation is disabled behind the `custom-machine-shapes` feature flag. The schema
and catalog model remain compatible with future custom shapes.

## Open Blockers

These block release validation, not the Phase 0 wire-contract freeze:

- Immutable commit links for the approved dashboard, agentunnel, papercode, server, and CLI
  contract changes.
- Production environment values for WorkOS, Fly, GitHub, Polar, and public origins must be
  supplied as deployment configuration or catalog seed data before release validation.
