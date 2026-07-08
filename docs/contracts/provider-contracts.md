# Provider and Catalog Contracts

Status: implemented contract baseline, pending production provider values.

## Dynamic Catalog Rule

Plans, credits, storage amounts, machine types, machine weights, presets,
idle-timeout options, regions, billing products, endpoint URLs, domain names, webhook
mappings, and feature switches must be dynamic configuration or database seed records.
They must not be hardcoded into production logic.

## WorkOS

Purpose:

- Dashboard authentication.
- Mapping WorkOS identities to Paperboat users.
- Session creation for dashboard-origin browser access.

Approved baseline:

- WorkOS organization/environment identifiers are deployment configuration.
- Redirect/callback URLs for local, preview, staging, and production are provider
  configuration and must point to the configured Paperboat public base URL.
- Dashboard origin allowlist is `http.allowed_origins`; production must set only the
  deployed dashboard origins.
- Session idle expiry and absolute expiry are dynamic session configuration values.

Implementation constraints:

- Store WorkOS subject and identity metadata needed for idempotent user lookup.
- Never log identity provider tokens.
- Callback handling writes audit events.

## Polar

Purpose:

- Subscription state.
- Plan entitlement.
- Credit grants and top-ups.
- Extra storage billing.
- Customer portal.

Approved:

- Product and price IDs for Sailor, Navigator, Captain.
- Product and price IDs for credit top-ups.
- Product and price IDs for monthly extra storage.
- Webhook event allowlist.
- Customer portal behavior.

Implementation constraints:

- Webhooks are verified and idempotent.
- Webhook processing records provider event id and processing state.
- Credits and storage changes are ledger entries.
- Dashboard usage display reads server-side ledger state only.
- `billing_products` maps Polar products and prices to Paperboat catalog actions.
- Refund, chargeback, cancellation, and downgrade behavior must be enforced through
  ledger-backed transitions and may not mutate historical ledger entries.

## Fly.io

Purpose:

- Project VM lifecycle.
- One machine and one volume per project.
- Runtime state used for orchestration and metering.

Approved baseline:

- Organization slug is `fly.org_slug`.
- App name is `fly.app_name` and must be unique per environment.
- Machine naming reads `fly.machine_name_prefix`; resources are tagged with
  `paperboat_project_id` and `managed_by=paperboat-server`.
- Volume naming reads `fly.volume_name_prefix`; resources use the same managed tags.
- Default region and region allowlist come from the dynamic `regions` catalog.
- Machine image reference is `fly.image_ref`.
- Production image tags must be immutable release image references.
- Storage resize/replacement is disabled until a separate volume policy is approved.

Implementation constraints:

- Provider operations are idempotent and reconciled.
- Persist desired intent before provider calls.
- The server uses the official Fly Go SDK for app, machine, volume, and secret
  operations; the configured Fly app is created on demand using `fly.org_slug` before
  provisioning machines or volumes.
- Do not mark storage released until approved cleanup terminal state is reached.
- Do not trust client-reported runtime for billing.
- Machine image ref, app name, mount path, boot command, and provider secret names are
  configuration values, not code constants.
- Restart apply updates the provider machine and clears `pending_restart_apply` only after
  the provider update succeeds.
- Agentunnel machine token and GitHub config sync token are injected into the provider
  machine spec through configurable Fly secret names. Machine process config explicitly
  opts out of app-wide secret inheritance and references only the required secret names.
  Secret values are never returned by HTTP APIs or written to project/audit event
  metadata.
- Until a Fly volume resize or replacement policy is approved, restart apply blocks storage
  changes with a project event and leaves `pending_restart_apply` intact.
- Reconciliation queues orphan Paperboat-tagged Fly machines into `orchestration_jobs` with
  `state='needs_review'`; destructive remediation requires an explicit operator action.

## GitHub

Purpose:

- User OAuth connection before first project creation.
- Project repository clone authorization.
- Private per-user config repo provisioning.

Approved baseline:

- OAuth app identity is deployment/provider configuration.
- OAuth scopes are `github.oauth_scopes`; production must use the minimum scope set that
  supports authorized repository cloning plus private config repo provisioning and sync.
- Config repo name is `github.config_repo_name`.
- Token material is encrypted, validated before sensitive GitHub operations, and marked
  unusable when provider validation/refresh fails.
- Clone/config sync credential handoff is VM-scoped secret injection. User-facing APIs do
  not return GitHub OAuth tokens or clone credentials.

Implementation constraints:

- Token material is encrypted.
- Private config repo provisioning is idempotent.
- VM config sync daemon owns ongoing pull/commit/push behavior.
- Server provisions repo and credential handoff only.

## Catalog Seed Sets

Phase 2 must seed these catalogs from approved dynamic sources:

- `plans`
- `plan_versions`
- `machine_types`
- `vm_presets`
- `idle_timeout_options`
- `regions`
- `billing_products`
- `feature_flags`

Seed files or provider-backed catalog sources must be environment-specific where values
differ across local, staging, and production.
