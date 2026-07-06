# Provider and Catalog Contracts

Status: draft, pending provider values and user approval.

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

Pending approval:

- WorkOS organization and environment.
- Redirect/callback URLs for local, preview, staging, and production.
- Dashboard origin allowlist.
- Session idle expiry and absolute expiry.

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

Pending approval:

- Organization slug.
- App naming policy.
- Machine naming and tagging policy. Current implementation reads the machine name prefix
  from `fly.machine_name_prefix` and tags resources with `paperboat_project_id` and
  `managed_by=paperboat-server`.
- Volume naming and tagging policy. Current implementation reads the volume name prefix
  from `fly.volume_name_prefix` and uses the same managed tags.
- Default region and region allowlist.
- Machine image naming policy.
- Production machine image naming policy.
- Fly volume resize versus replacement policy for increasing/decreasing project storage.

Implementation constraints:

- Provider operations are idempotent and reconciled.
- Persist desired intent before provider calls.
- Do not mark storage released until approved cleanup terminal state is reached.
- Do not trust client-reported runtime for billing.
- Machine image ref, app name, mount path, boot command, and provider secret names are
  configuration values, not code constants.
- Restart apply updates the provider machine and clears `pending_restart_apply` only after
  the provider update succeeds.
- Agentunnel machine token and GitHub config sync token are injected into the provider
  machine spec through configurable Fly secret names and are never returned by HTTP APIs or
  written to project/audit event metadata.
- Until a Fly volume resize or replacement policy is approved, restart apply blocks storage
  changes with a project event and leaves `pending_restart_apply` intact.
- Reconciliation queues orphan Paperboat-tagged Fly machines into `orchestration_jobs` with
  `state='needs_review'`; destructive remediation requires an explicit operator action.

## GitHub

Purpose:

- User OAuth connection before first project creation.
- Project repository clone authorization.
- Private per-user config repo provisioning.

Pending approval:

- OAuth app identity.
- OAuth scopes.
- Config repo name policy.
- Token refresh, validation, and revocation policy.
- Clone credential model.

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
