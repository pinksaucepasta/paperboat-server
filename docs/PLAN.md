# paperboat-server Production Implementation Plan

Status: not started.

This plan defines the complete production implementation scope for `paperboat-server`, the
Paperboat control plane. It follows the workspace `USERSTORY.md`, `AGENTS.md`, and
`paperboat-server/AGENTS.md`.

There is no prototype scope and no phased product downgrade. Every phase below is part of
the production release. Phases exist only to order implementation, review, verification,
and progress tracking. A phase is complete only when its code, migrations, tests,
documentation, observability, and release evidence are complete.

## Progress Tracking

Update this table after each implementation pass. Never mark a phase complete without
filling its evidence section.

| Phase | Area | Status | Owner | Evidence |
| --- | --- | --- | --- | --- |
| 0 | Product decisions and contract freeze | Blocked | Codex | Draft contract pack in `docs/contracts/`; pending user approval for required decisions. |
| 1 | Repository foundation and service skeleton | In progress | Codex | Initial Go module, CLI surface, config loader, HTTP middleware, health/readiness endpoints, local config example, README commands, and foundation tests. |
| 2 | Persistence, migrations, config, and data catalogs | Complete | Codex | Postgres schema, migration runner, transaction wrapper, catalog repositories, storage ledger repository, dynamic catalog seed validation/upserts, and Postgres integration evidence complete. |
| 3 | Identity, sessions, authorization, and audit base | Implemented | Codex | WorkOS verifier abstraction, idempotent user/session creation, secure cookies with CSRF binding and rotation, `/api/me`, auth/entitlement/admin middleware foundations, audit writer/query base, and auth integration tests. |
| 4 | Billing, entitlements, credits, and storage ledger | In progress | Codex | Phase 4 decision gate approved; billing service, Polar client abstraction, signed/idempotent webhook processing, subscription entitlement transitions, checkout/customer portal handlers, entitlement/usage APIs, credit grants/debits/refunds, storage included/purchased/release/cancellation ledger primitives, admin adjustments, docs, and focused Go/vet evidence are in place. Project create/update quota enforcement remains for Phase 6 API wiring. |
| 5 | GitHub OAuth and private config repo provisioning | Implemented | Codex | Configurable GitHub OAuth/repo policy, encrypted token persistence schema, fake/HTTP GitHub client abstraction, auth/CSRF-protected GitHub API handlers, browser callback for ngrok-backed server testing, GitHub-required project-create gate, idempotent private config repo provisioning with preview URL skill fixture, provided-Postgres fake-provider tests, and local Go/vet evidence are in place. |
| 6 | Project lifecycle and VM customization model | Implemented | Codex | Project service, Phase 6 migration, project create/list/get/update/delete/events APIs, idempotent create, catalog validation, setup-script revision storage, storage quota enforcement for create/update, pending restart apply model, delete workflow intent with deferred storage release, event records, and DB-backed project lifecycle tests are in place. |
| 7 | Fly.io machines, volumes, reconciliation, and restart apply | Not started | TBD | None |
| 8 | Metering workers, idle detection, credit exhaustion, and enforcement | Not started | TBD | None |
| 9 | agentunnel pre-connect brokering and access descriptors | Not started | TBD | None |
| 10 | Dashboard and CLI API surface hardening | Not started | TBD | None |
| 11 | Security, privacy, abuse controls, and secret handling | Not started | TBD | None |
| 12 | Observability, operations, admin tooling, and runbooks | Not started | TBD | None |
| 13 | Full integration, load, failure, and release validation | Not started | TBD | None |

Status values:

- `Not started`: no production code merged for this phase.
- `In progress`: production implementation underway.
- `Blocked`: waiting on an explicit external decision or credential.
- `Implemented`: code merged, release evidence not complete.
- `Complete`: all acceptance criteria and evidence complete.

## Global Release Invariants

- `paperboat-server` is the authoritative control plane for identity mapping,
  entitlement state, credit metering, storage accounting, project lifecycle,
  Fly machine and volume orchestration, GitHub config-repo provisioning, and
  pre-connect authorization.
- Live agent, terminal, preview, SSH, and WebSocket traffic never flows through
  `paperboat-server`; it flows through `agentunnel` and the per-VM papercode server.
- Clients are untrusted. Dashboard, CLI, papercode, and VM daemons may request actions,
  but server-side authorization, quota checks, metering, and lifecycle state decide.
- Plans, credit quantities, storage quantities, machine catalogs, preset catalogs,
  idle-timeout bounds, domain names, external endpoint URLs, pricing IDs, webhook
  mappings, and feature switches are dynamic configuration or database records.
- No frozen API, CLI, JSON, status enum, or cross-project contract may change without
  explicit user approval.
- All external provider calls are idempotent, retried with bounded backoff, traced, and
  reconciled from persisted intent.
- No secrets are logged, returned after creation, stored in plaintext unless a provider
  requires reversible use, or copied into user-visible errors.
- Every irreversible or billing-impacting action writes an audit event.
- Every background worker is context-cancellable, horizontally safe, idempotent, and
  resumable after process restart.
- Every storage and credit decision is ledger-backed, not computed from mutable client
  summaries.

## Required Decisions Before Coding Affected Areas

These decisions are explicit gates. Do not silently choose defaults in code.

1. Persistence backend:
   - Gate: before Phase 2 implementation.
   - Decision needed: SQLite-first single-node with clear migration path, or Postgres from
     first release.
   - Plan default for documentation: repository pattern supports either; migrations and
     tests must prove selected backend.

2. Plan values and machine credit weights:
   - Gate: before Phase 4 seed data and billing tests.
   - Decision needed: Sailor, Navigator, Captain credit amounts, included storage, top-up
     packages, extra storage price IDs, and machine weight catalog.
   - Implementation rule: values live in config/database catalogs and can change without
     redeploy.

3. agentunnel pre-connect contract:
   - Gate: before Phase 9 implementation.
   - Decision needed: exact token/session handoff, response fields, expiry semantics,
     reconnect semantics, and revocation flow.
   - Implementation rule: traffic still stays out of `paperboat-server`.

4. papercode AccessEndpoint wiring:
   - Gate: before Phase 9 end-to-end tests.
   - Decision needed: how papercode desktop/mobile/web receives Paperboat access metadata
     and authenticates through agentunnel.

5. Custom Fly machine shapes:
   - Gate: before exposing custom-shape API fields.
   - Decision needed: whether custom user-defined shapes ship in first production release.
   - Implementation rule: fixed catalog must be schema-compatible with future custom
     shapes, even if custom creation is disabled.

## Architecture Target

### Process Layout

Single Go binary with explicit subcommands:

- `paperboat-server serve`: HTTP API, webhooks, worker supervisor.
- `paperboat-server migrate`: apply database migrations.
- `paperboat-server seed-catalogs`: upsert dynamic plan, machine, preset, and timeout
  catalogs from configured sources.
- `paperboat-server reconcile`: one-shot reconciliation for Fly, billing, metering, and
  agentunnel state.
- `paperboat-server admin`: safe operational commands that require admin credentials.

### Internal Packages

Target package boundaries:

- `cmd/paperboat-server`: CLI entrypoint.
- `internal/app`: application wiring, lifecycle, dependency injection.
- `internal/config`: config loading, validation, redaction.
- `internal/httpapi`: router, middleware, request/response models.
- `internal/auth`: WorkOS integration, sessions, roles, CSRF.
- `internal/billing`: Polar integration, entitlements, webhooks.
- `internal/catalog`: plan, machine, preset, timeout catalogs.
- `internal/db`: migrations, transactions, repository interfaces.
- `internal/audit`: audit writer and query API.
- `internal/projects`: project lifecycle domain services.
- `internal/fly`: Fly API client, orchestration primitives.
- `internal/orchestrator`: workflows, state machines, reconciliation.
- `internal/metering`: usage events, credit ledger, storage ledger.
- `internal/github`: OAuth, token storage, config repo provisioning.
- `internal/agentunnel`: broker client and pre-connect contracts.
- `internal/workers`: worker supervisor, leases, retry queues.
- `internal/observability`: logs, metrics, traces, health checks.
- `internal/security`: secret encryption, redaction, rate limits.
- `internal/testutil`: fake providers, clock, fixtures, contract helpers.

### External Systems

- WorkOS: dashboard authentication and identity.
- Polar.sh: subscriptions, top-ups, extra storage, webhooks, customer portal.
- GitHub: OAuth, repository clone authorization, private config repo provisioning.
- Fly.io: one machine and one volume per project.
- agentunnel: SSH, preview URLs, and tunneled WebSocket data path.
- papercode server on VM: environment-local T3 WebSocket server.

## Canonical Domain Model

IDs are stable opaque strings. JSON uses `snake_case`. State enums are stored as strings.

### Users and Auth

- `users`: Paperboat user identity, WorkOS subject, primary email, display name, status.
- `sessions`: hashed session IDs, CSRF secret binding, expiry, rotation metadata.
- `user_identities`: provider identity links for WorkOS and GitHub.
- `github_oauth_tokens`: encrypted OAuth token material, granted scopes, expiry/refresh
  metadata, revocation metadata, and last validation time for user-authorized repository
  clone plus config-repo provisioning access.
- `audit_events`: append-only user/admin/system events.

### Billing and Entitlements

- `plans`: Sailor, Navigator, Captain catalog records.
- `plan_versions`: immutable catalog snapshots for historical billing correctness.
- `subscriptions`: Polar subscription state and active entitlement pointer.
- `credit_accounts`: user credit balance state.
- `credit_ledger_entries`: append-only grants, debits, refunds, adjustments, expirations.
- `storage_accounts`: included, purchased, allocated, and available GB.
- `storage_ledger_entries`: append-only allocation, release, purchase, cancellation,
  adjustment.
- `polar_events`: webhook idempotency records.
- `billing_products`: Polar product and price IDs mapped to catalog entries.

### Catalogs

- `machine_types`: fixed named shapes and credit weights.
- `vm_presets`: curated tool/agent presets, versioned and data-driven.
- `idle_timeout_options`: allowed per-project timeout options.
- `regions`: enabled Fly regions and placement policy.
- `feature_flags`: server-side flags for rollout and kill switches.

### Projects and Orchestration

- `projects`: user-owned project record and desired configuration.
- `project_repositories`: source git URL, provider, clone metadata, default branch.
- `project_storage_allocations`: assigned GB and volume linkage.
- `project_runtime_configs`: desired machine type, presets, setup script reference,
  idle timeout, pending restart apply status.
- `project_credentials`: encrypted deployment credentials, clone token references.
- `fly_machines`: Fly machine IDs, state, image ref, region, observed config hash.
- `fly_volumes`: Fly volume IDs, size, region, state.
- `orchestration_jobs`: durable workflow queue with idempotency key, state, attempts.
- `reconciliation_runs`: reconciliation audit and provider drift findings.

### Access and agentunnel

- `access_sessions`: short-lived pre-connect approvals and descriptors.
- `agentunnel_resources`: tunnel/client/resource IDs owned by a project.
- `connection_events`: connect attempts, authorization result, failure reason.
- `preview_url_records`: project preview mappings where server owns metadata.

## HTTP API Shape

All responses use structured JSON. All errors use:

```json
{
  "error": {
    "code": "machine_not_ready",
    "message": "Machine is not ready for connection.",
    "request_id": "req_...",
    "details": {}
  }
}
```

Endpoint names below are the target contract. Before implementation, review with
dashboard, CLI, papercode, and agentunnel owners because contracts freeze once shipped.

### Auth and Session

- `GET /healthz`
- `GET /readyz`
- `GET /api/me`
- `GET /api/auth/workos/state`
- `POST /api/auth/workos/callback`
- `POST /api/auth/logout`
- `GET /api/auth/csrf`

### Billing and Entitlements

- `GET /api/billing/entitlement`
- `GET /api/billing/usage`
- `POST /api/billing/checkout`
- `POST /api/billing/customer-portal`
- `POST /api/webhooks/polar`

### Catalogs

- `GET /api/catalog/plans`
- `GET /api/catalog/machine-types`
- `GET /api/catalog/presets`
- `GET /api/catalog/idle-timeouts`
- `GET /api/catalog/regions`

### GitHub

- `GET /api/github/status`
- `POST /api/github/oauth/start`
- `POST /api/github/oauth/callback`
- `POST /api/github/config-repo/provision`

### Projects

- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/{project_id}`
- `PATCH /api/projects/{project_id}`
- `DELETE /api/projects/{project_id}`
- `POST /api/projects/{project_id}/start`
- `POST /api/projects/{project_id}/stop`
- `POST /api/projects/{project_id}/restart`
- `GET /api/projects/{project_id}/events`
- `GET /api/projects/{project_id}/usage`

### Access

- `POST /api/projects/{project_id}/connect`
- `POST /api/projects/{project_id}/cli-connect`
- `POST /api/projects/{project_id}/papercode-connect`
- `GET /api/projects/{project_id}/connection-status`

### Admin

- `GET /api/admin/users`
- `GET /api/admin/projects`
- `GET /api/admin/orchestration-jobs`
- `POST /api/admin/reconcile`
- `POST /api/admin/users/{user_id}/adjust-credits`
- `POST /api/admin/users/{user_id}/adjust-storage`

## Phase 0: Product Decisions and Contract Freeze

Goal: resolve implementation blockers and freeze contracts before code makes them costly.

Tasks:

- [x] Read workspace `USERSTORY.md`, root `AGENTS.md`, `paperboat-server/AGENTS.md`,
  `agentunnel/docs/api.md`, `agentunnel/docs/cloud-agents-platform-plan.md`, relevant
  papercode remote docs, dashboard AGENTS, CLI AGENTS.
- [ ] Confirm persistence backend selection.
- [x] Confirm plan values, credit grants, included storage, top-up catalog, extra storage
  billing behavior, and machine credit weights.
- [ ] Confirm WorkOS session model and dashboard callback URLs.
- [x] Confirm Polar product/price mapping and webhook event list.
- [ ] Confirm Fly organization, app naming, region policy, image naming, volume naming,
  and machine restart behavior.
- [ ] Confirm GitHub OAuth scopes, config repo name policy, private repo visibility, token
  lifecycle, and clone credential model.
- [ ] Confirm agentunnel pre-connect handoff, token lifetime, descriptor schema, and
  revocation semantics.
- [ ] Confirm papercode AccessEndpoint descriptor format.
- [ ] Confirm paperboat-cli descriptor requirements.
- [ ] Confirm whether custom Fly shapes ship in first release or remain catalog-compatible
  but disabled.
- [ ] Write `docs/contracts/*.md` for approved API and provider contracts.
- [x] Write initial draft contract pack in `docs/contracts/` for review.

Acceptance criteria:

- [ ] No unresolved `USERSTORY.md` open question blocks Phase 1-13 implementation.
- [ ] API endpoint list and JSON schemas are approved for dashboard and CLI consumers.
- [ ] agentunnel/papercode handoff is approved in writing.
- [ ] Billing catalog and product IDs are defined as dynamic seed data.

Evidence:

- Decision log: `docs/contracts/decisions.md`
- Approved contract docs: pending approval; draft docs in `docs/contracts/`
- Review links: pending

## Phase 1: Repository Foundation and Service Skeleton

Goal: create production Go service foundation with no business stubs.

Tasks:

- [x] Initialize Go module with correct module path.
- [x] Add `cmd/paperboat-server` with `serve`, `migrate`, `seed-catalogs`, `reconcile`,
  and `admin` subcommands.
- [x] Add config loader with environment, file, and secret source support.
- [x] Add config validation that fails fast on missing required production settings.
- [x] Add redacted config dump for diagnostics.
- [x] Add HTTP router, request IDs, structured logging, panic recovery, timeout handling,
  body size limits, CORS allowlist, and secure headers.
- [x] Add health and readiness endpoints.
- [x] Add graceful shutdown for HTTP server and workers.
- [x] Add local development config examples with fake provider mode.
- [ ] Add test harness with fake clock, fake providers, temp database, and HTTP client.
- [x] Add CI commands documented in README.

Acceptance criteria:

- [x] `go test ./...` passes.
- [x] `go vet ./...` passes.
- [x] `gofmt -w .` produces no diff.
- [x] `paperboat-server serve` starts with local config.
- [x] `GET /healthz` returns healthy before provider readiness.
- [x] `GET /readyz` reflects database and required provider readiness.
- [x] No production path returns placeholder data.

Evidence:

- Test output: `go test ./...` passed.
- Local smoke command: `go run ./cmd/paperboat-server serve -config config/local.example.json`; `curl -i http://127.0.0.1:8080/healthz` returned `{"data":{"status":"healthy"}}`; `curl -i http://127.0.0.1:8080/readyz` returned `{"data":{"status":"ready"}}`.
- Config validation examples: `internal/config/config_test.go` covers env overlays, `_FILE` secret loading, production fake-provider rejection, required production provider secrets, weak production secret rejection, and redacted diagnostics.

## Phase 2: Persistence, Migrations, Config, and Data Catalogs

Goal: durable data model, migrations, and dynamic catalogs.

Tasks:

- [x] Implement selected database driver and transaction wrapper.
- [x] Add migration runner with up/down or forward-only policy documented.
- [x] Create tables for users, sessions, identities, audit, catalogs, billing, projects,
  Fly resources, metering, access sessions, jobs, provider events, and reconciliation.
- [x] Add optimistic locking or version columns to mutable aggregate records.
- [x] Add unique idempotency keys for project creation, webhook events, provider jobs, and
  ledger operations.
- [x] Add repository interfaces and concrete implementations.
- [x] Add dynamic seed loader for plans, machine types, presets, timeout options, regions,
  billing products, and feature flags.
- [x] Add catalog versioning so historical usage references immutable values.
- [x] Add config schema validation tests.
- [x] Add migration tests from empty database to current schema.
- [x] Add repository transaction tests for rollback and concurrency invariants.

Acceptance criteria:

- [x] Database can be created from scratch with one command.
- [x] Catalog changes are upserts, not code changes.
- [x] Plan/machine/preset values can be changed without recompiling.
- [x] Ledger tables are append-only in normal application flows.
- [x] Concurrent allocation tests prevent over-allocation of storage.

Evidence:

- Migration command output: `PAPERBOAT_DATABASE_DSN=<provided-postgres-dsn> go run ./cmd/paperboat-server migrate -config config/local.example.json` returned `database migrations applied`.
- Repository test output: `PAPERBOAT_TEST_DATABASE_DSN=<provided-postgres-dsn> go test ./internal/db ./internal/catalog ./internal/metering` passed.
- Catalog seed sample: `config/catalogs.example.json`; `PAPERBOAT_DATABASE_DSN=<provided-postgres-dsn> go run ./cmd/paperboat-server seed-catalogs -config config/local.example.json` returned `catalog seed applied`.
- Local hygiene: `go test ./...` and `go vet ./...` passed.

## Phase 3: Identity, Sessions, Authorization, and Audit Base

Goal: WorkOS-backed auth, secure sessions, RBAC, and audit events.

Tasks:

- [x] Implement WorkOS callback verification.
- [x] Map WorkOS identities to Paperboat users idempotently.
- [x] Implement secure HttpOnly session cookies with rotation and expiry.
- [x] Implement CSRF protection for cookie-authenticated writes.
- [x] Implement role model: user, support/admin, system worker.
- [x] Add authorization middleware for account-owned resources.
- [x] Add account gating helper that checks active entitlement before core feature access.
- [x] Add audit writer for auth, billing, project, provider, admin, and access events.
- [x] Add audit query repository and admin API foundation.
- [x] Add login/logout/session tests.
- [x] Add authorization tests for cross-user access denial.
- [x] Add audit tests proving required events are written once.

Acceptance criteria:

- [x] Authenticated user can retrieve `GET /api/me`.
- [x] Unauthenticated requests cannot access project/billing APIs.
- [x] User cannot access another user's project or ledger.
- [x] Core dashboard APIs return payment-required style structured errors without active
  entitlement.
- [x] Auth events are audited without storing secrets.

Evidence:

- Auth test output: `GOCACHE=/tmp/paperboat-go-build go test ./internal/httpapi ./internal/auth` passed; DB-backed auth integration tests are included and run when `PAPERBOAT_TEST_DATABASE_DSN` is set, matching the existing repository-test pattern. Full `GOCACHE=/tmp/paperboat-go-build go test ./...` passed with local port-bind permission for the pre-existing app shutdown test.
- Cross-user denial tests: `TestProjectOwnershipDeniesCrossUserAccess` proves another user's project is rejected by the ownership helper while the requesting user's session remains valid.
- Audit sample: `TestAuthLoginMeCSRFLogoutAndAudit` verifies `auth.login` and `auth.logout` audit events are written from the login/logout flow without token material in event metadata.

## Phase 4: Billing, Entitlements, Credits, and Storage Ledger

Goal: Polar integration and authoritative resource accounting.

Tasks:

- [x] Implement Polar API client with idempotent checkout and customer portal creation.
- [x] Implement Polar webhook verification and replay protection.
- [x] Store raw webhook metadata safely and processed event state.
- [x] Map subscriptions to active, trialing, past_due, canceled, incomplete, and expired
  entitlement states.
- [x] Implement active-plan gating for core features.
- [x] Implement credit account and append-only ledger.
- [x] Implement credit grants from subscription and top-ups.
- [x] Implement credit debits from metered machine runtime.
- [x] Implement storage account and append-only ledger.
- [x] Implement included storage, purchased storage, allocation, release, cancellation, and
  adjustment flows.
- [ ] Implement quota checks for project creation and storage changes.
- [x] Implement refund/chargeback/cancellation behavior according to approved Polar rules.
- [x] Add billing API responses for dashboard usage display.
- [x] Add tests for webhook idempotency, out-of-order events, entitlement transitions,
  credit debit idempotency, and storage over-allocation prevention.

Acceptance criteria:

- [x] Duplicate Polar webhook does not duplicate credits or storage.
- [x] User without active plan cannot create/start/connect projects.
- [x] Credits cannot go below zero except through explicit documented pending-stop window,
  if approved.
- [x] Project deletion returns allocated storage through ledger entry.
- [x] Extra storage cancellation updates purchased amount and available storage correctly.

Evidence:

- Polar webhook test output: `GOCACHE=/tmp/paperboat-go-build go test ./internal/billing ./internal/httpapi` passed; includes webhook signature coverage, approved subscription state mapping, flexible nested Polar payload parsing, and router coverage for billing/admin handlers. DB-backed webhook idempotency/refund/storage-overallocation integration tests are present and run when `PAPERBOAT_TEST_DATABASE_DSN` is set.
- Ledger invariant tests: existing `internal/metering` storage allocation invariants remain covered; new `internal/billing` credit/storage ledger primitives are implemented for plan grants, top-up grants, metered debits, refunds, included storage, purchased storage, release entries, cancellation, and admin adjustments. Project create/update quota checks remain for Phase 6 API wiring.
- API response examples: `GET /api/billing/entitlement` returns `{"data":{"state":"none","active":false}}` for an authenticated user without a subscription; `GET /api/billing/usage` returns server-side credit and storage account totals; checkout/customer portal return only provider URLs, never provider secrets.
- Full hygiene: `GOCACHE=/tmp/paperboat-go-build go vet ./...` and `GOCACHE=/tmp/paperboat-go-build go test ./...` passed. DB-backed billing integration tests run when `PAPERBOAT_TEST_DATABASE_DSN` is set.

## Phase 5: GitHub OAuth and Private Config Repo Provisioning

Goal: GitHub connection and per-user config repo setup.

Tasks:

- [x] Implement GitHub OAuth start/callback with state and CSRF protection.
- [x] Store GitHub token material encrypted with rotation metadata.
- [x] Validate required scopes before project creation.
- [x] Implement private config repo existence check.
- [x] Create private config repo if missing.
- [x] Initialize config repo with required default files, including preview URL skill
  placement required by the product story.
- [x] Store repo owner/name/default branch/clone URL metadata.
- [x] Add credential handoff model for VM config sync daemon without logging secrets.
- [x] Add repo provisioning idempotency key and retry behavior.
- [x] Add tests with fake GitHub for OAuth, scope denial, repo already exists, repo
  creation failure, and retry recovery.

Acceptance criteria:

- [x] First project creation blocks with structured GitHub-required state when GitHub is
  not connected.
- [x] Repo provisioning is idempotent across retries.
- [x] Config repo is private.
- [x] Token values never appear in logs, API responses, or audit event details.

Evidence:

- GitHub fake-provider tests: `internal/httpapi/github_integration_test.go` covers OAuth success, missing-scope denial, GitHub-required state, project-create GitHub gating after entitlement, idempotent repo provisioning, repo creation retry recovery, and repo initialization with a fake GitHub client. These DB-backed tests run when `PAPERBOAT_TEST_DATABASE_DSN` is set.
- Repo initialization fixture: service initializes `README.md`, `.paperboat/preview-url-skill.md`, and `.paperboat/config-sync.json` in the private config repo.
- Secret redaction test: `TestGitHubOAuthProvisionAndSecretRedaction` asserts the fake token is absent from API responses and audit metadata.
- Ngrok smoke test: with `PAPERBOAT_PUBLIC_BASE_URL=https://unified-camel-humorous.ngrok-free.app`, `GET https://unified-camel-humorous.ngrok-free.app/healthz` returned healthy through the tunnel; `GET /api/github/oauth/callback?code=test&state=test` reached the server and returned structured `unauthenticated`, proving the callback route is exposed and session-gated.
- Provided-Postgres evidence: `set -a; source .env.local; set +a; PAPERBOAT_TEST_DATABASE_DSN="$PAPERBOAT_DATABASE_DSN" PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET=true go test -p 1 ./internal/httpapi ./internal/db ./internal/catalog ./internal/metering ./internal/billing` passed after migrations against the provided database URL.
- Local hygiene: `go test ./...` and `go vet ./...` passed.

## Phase 6: Project Lifecycle and VM Customization Model

Goal: project domain model from repository clone request to desired runtime state.

Tasks:

- [x] Implement `POST /api/projects` with idempotency key support.
- [x] Validate active entitlement, GitHub connection, repository URL, storage availability,
  machine type, region, preset IDs, idle timeout, and setup script constraints.
- [x] Persist desired project state before provider calls.
- [x] Implement project states: `creating`, `provisioning_storage`, `provisioning_machine`,
  `ready`, `starting`, `running`, `stopping`, `stopped`, `restarting`, `deleting`,
  `deleted`, `failed`, `suspended`.
- [x] Implement resource config pending-apply model for disk allocation, machine type,
  presets, setup script, and idle timeout.
- [x] Implement setup script storage with size limits, secret redaction guidance, and
  immutable revision history.
- [x] Implement preset selection as versioned catalog references.
- [x] Implement project update API that records desired changes and marks whether restart
  is required.
- [x] Implement delete workflow intent and storage-release deferral until provider cleanup
  succeeds.
- [x] Add project event stream/query API for dashboard progress display.
- [x] Add tests for validation, idempotency, entitlement gating, restart-required changes,
  and deletion lifecycle.

Acceptance criteria:

- [x] Project create cannot allocate more storage than available.
- [x] Project create cannot use catalog entries disabled in database.
- [x] Resource changes do not mutate running machine immediately.
- [x] API clearly reports current config, desired config, and pending restart apply state.
- [x] Failed create leaves recoverable persisted intent and no silent orphan resources.

Evidence:

- Project API tests: `go test ./internal/httpapi` passed locally; the existing GitHub
  gate test now reaches the real Phase 6 project-create handler after entitlement and
  GitHub validation.
- State transition tests:
  `PAPERBOAT_TEST_DATABASE_DSN="$PAPERBOAT_DATABASE_DSN" PAPERBOAT_ALLOW_DESTRUCTIVE_TEST_DB_RESET=true go test -p 1 ./internal/projects ./internal/httpapi`
  passed, covering idempotent create, storage quota enforcement, disabled catalog
  rejection, desired config updates, pending restart apply, no Fly machine mutation during
  resource changes, delete intent, and project events.
- Example project events: create records `project.created` and
  `project.provisioning_queued`; update records `project.config_updated`; delete records
  `project.delete_queued`.
- Full hygiene: `go test ./...` and `go vet ./...` passed.

## Phase 7: Fly.io Machines, Volumes, Reconciliation, and Restart Apply

Goal: reliable Fly resource orchestration for one project equals one machine plus one volume.

Tasks:

- [ ] Implement Fly API client for machines, volumes, images, secrets, status, start, stop,
  restart, destroy, and list operations.
- [ ] Implement provider idempotency strategy and name/tag conventions.
- [ ] Implement volume creation exactly once per project.
- [ ] Implement machine creation with correct image, volume mount, environment, secrets,
  region, size, and boot command.
- [ ] Inject agentunnel machine credentials through approved secret mechanism.
- [ ] Inject GitHub config repo sync credentials through approved secret mechanism.
- [ ] Inject papercode server configuration and project repository clone metadata.
- [ ] Implement start/stop/restart workflows.
- [ ] Implement restart apply: pending config changes are applied only during restart.
- [ ] Implement volume resize flow if Fly supports safe resize for selected storage model;
  otherwise require documented replacement/migration decision before enabling resize.
- [ ] Implement deletion workflow: stop machine, run final config sync hook if needed,
  destroy machine, release or destroy volume according to approved retention policy,
  release storage ledger allocation.
- [ ] Implement reconciliation worker comparing persisted desired state with Fly actual
  state.
- [ ] Add orphan detection and safe remediation queue.
- [ ] Add tests with fake Fly for partial failures at every step.

Acceptance criteria:

- [ ] A project reaches `ready` only after volume and machine are provisioned and recorded.
- [ ] Retried create does not create duplicate volumes or machines.
- [ ] Restart applies pending machine type and preset changes exactly once.
- [ ] Provider drift is detected and either repaired or escalated with event record.
- [ ] Delete reclaims storage only after provider cleanup reaches approved terminal state.

Evidence:

- Fake Fly workflow tests:
- Reconciliation tests:
- Orphan remediation dry run:

## Phase 8: Metering Workers, Idle Detection, Credit Exhaustion, and Enforcement

Goal: trusted runtime metering and automatic lifecycle control.

Tasks:

- [ ] Implement runtime observation source approved in Phase 0: Fly events, polling, or
  hybrid.
- [ ] Persist machine runtime intervals with start, stop, observed state, source, and
  confidence.
- [ ] Debit credits by runtime interval multiplied by catalog machine weight snapshot.
- [ ] Support multiple concurrent running machines debiting in parallel.
- [ ] Implement idempotent metering checkpoints so restarts do not double-charge.
- [ ] Implement credit exhaustion detector.
- [ ] Stop running machines when credits are exhausted.
- [ ] Prevent starting machines when credits are insufficient by approved threshold.
- [ ] Implement activity tracking for human and agent events.
- [ ] Define accepted activity inputs: connect sessions, agentunnel connection events,
  papercode activity callbacks, CLI activity callbacks, VM heartbeat, or approved
  provider source.
- [ ] Implement per-project idle timeout using catalog option selected by user.
- [ ] Auto-stop idle machines.
- [ ] Add tests for concurrent debit, worker restart, out-of-order provider state,
  credit exhaustion stop, and idle auto-stop.

Acceptance criteria:

- [ ] Runtime is never computed from client-reported billing totals.
- [ ] Two running 2x machines debit credits independently and concurrently.
- [ ] Worker restart resumes from last checkpoint without duplicate debit.
- [ ] Machine stops when credits run out.
- [ ] Idle timeout changes affect next evaluation using project setting.

Evidence:

- Metering invariant tests:
- Exhaustion stop tests:
- Idle worker tests:

## Phase 9: agentunnel Pre-Connect Brokering and Access Descriptors

Goal: authorized connection descriptors for papercode and paperboat-cli while data remains
in agentunnel.

Tasks:

- [ ] Implement approved agentunnel admin/API client.
- [ ] Provision or look up agentunnel client identity for each project machine.
- [ ] Provision or look up persistent TCP/SSH tunnel records needed for the project.
- [ ] Provision preview URL support and metadata records.
- [ ] Implement pre-connect checks: authenticated user, active entitlement, project
  ownership, project not deleted/suspended, credits sufficient, machine start/resume
  allowed, tunnel resource exists, access policy permits request.
- [ ] Start or resume machine on connect when allowed.
- [ ] Wait for machine and agentunnel readiness with bounded timeout and useful statuses.
- [ ] Issue short-lived access session record.
- [ ] Return approved descriptor for papercode AccessEndpoint.
- [ ] Return approved descriptor for paperboat-cli.
- [ ] Record connection events and denial reasons.
- [ ] Revoke access sessions on user logout, entitlement loss, project deletion, machine
  stop, or admin action where contract supports revocation.
- [ ] Add fake agentunnel tests for happy path, not ready, wrong owner, suspended tunnel,
  expired token, and reconnect behavior.

Acceptance criteria:

- [ ] `paperboat-server` never proxies SSH/WebSocket payload bytes.
- [ ] Connect without active entitlement fails before provider side effects.
- [ ] Connect to another user's project fails and writes denial event.
- [ ] Descriptor contains no long-lived secrets.
- [ ] Failure responses distinguish unauthorized, payment required, machine starting,
  tunnel unavailable, and provider error.

Evidence:

- agentunnel contract tests:
- Descriptor examples:
- Denial event examples:

## Phase 10: Dashboard and CLI API Surface Hardening

Goal: stable user-facing API for dashboard and CLI consumers.

Tasks:

- [ ] Review every endpoint response with dashboard and CLI needs.
- [ ] Add OpenAPI or equivalent schema generation.
- [ ] Add request/response contract tests.
- [ ] Add pagination, filtering, and sorting for list endpoints.
- [ ] Add idempotency-key support to all create and billing-impacting writes.
- [ ] Add consistent structured error codes.
- [ ] Add optimistic concurrency headers or body version fields for project updates.
- [ ] Add dashboard-specific usage summary endpoint.
- [ ] Add CLI-specific connect status endpoint if required by approved contract.
- [ ] Add API docs under `docs/api.md`.

Acceptance criteria:

- [ ] All public endpoints have schemas and examples.
- [ ] Error codes are documented and tested.
- [ ] Idempotent retry tests pass for create, checkout, project update, start, stop,
  restart, delete, and connect.
- [ ] API docs match tests.

Evidence:

- Contract test output:
- Generated schema path:
- API docs review:

## Phase 11: Security, Privacy, Abuse Controls, and Secret Handling

Goal: production-grade security posture.

Tasks:

- [ ] Implement secret encryption at rest with key versioning.
- [ ] Implement token hashing for non-reversible tokens.
- [ ] Implement redaction for logs, traces, errors, audit details, and panic output.
- [ ] Add rate limits for login callback abuse, webhook abuse, project creation, connect,
  start/stop/restart, GitHub OAuth, and admin actions.
- [ ] Add request body limits per endpoint.
- [ ] Add SSRF protection for git repository URLs and provider callback URLs.
- [ ] Validate setup scripts as user content: size limits, storage, display, and VM-only
  execution boundary.
- [ ] Add webhook signature verification tests for Polar and WorkOS/GitHub if used.
- [ ] Add admin authentication and authorization controls.
- [ ] Add data retention policy hooks for sessions, audit, provider events, and logs.
- [ ] Add dependency vulnerability scanning workflow.
- [ ] Add security review checklist under `docs/security.md`.

Acceptance criteria:

- [ ] Secret fixtures never appear in logs during tests.
- [ ] Expired/revoked sessions fail.
- [ ] Rate-limited endpoints return documented structured error.
- [ ] SSRF tests reject local, link-local, metadata, and private network URLs where user
  supplied external URLs are fetched server-side.
- [ ] Admin endpoints are inaccessible to normal users.

Evidence:

- Security test output:
- Redaction test output:
- Vulnerability scan output:

## Phase 12: Observability, Operations, Admin Tooling, and Runbooks

Goal: service can be operated and debugged in production.

Tasks:

- [ ] Add structured logs with request IDs, user IDs where safe, project IDs, job IDs, and
  provider correlation IDs.
- [ ] Add metrics for HTTP latency, error codes, database pool, worker lag, job attempts,
  provider calls, billing webhooks, credit debit rate, storage allocation, Fly resources,
  agentunnel connect attempts, and reconciliation drift.
- [ ] Add tracing around external provider calls and orchestration workflows.
- [ ] Add `/metrics` endpoint protected according to deployment model.
- [ ] Add readiness checks for database, WorkOS, Polar, Fly, GitHub, and agentunnel.
- [ ] Add admin reconciliation command with dry-run and apply modes.
- [ ] Add admin credit/storage adjustment commands with required reason and audit event.
- [ ] Add runbooks for provider outage, webhook backlog, credit over-debit correction,
  orphan Fly resource cleanup, GitHub token revocation, agentunnel outage, and database
  restore.
- [ ] Add backup and restore procedure for selected persistence backend.

Acceptance criteria:

- [ ] Operator can identify why a project is not connectable from API status and logs.
- [ ] Reconciliation dry-run lists drift without side effects.
- [ ] Admin adjustments require reason and produce audit entries.
- [ ] Metrics cover every SLO listed in release validation.

Evidence:

- Metrics sample:
- Reconciliation dry-run:
- Runbook review:

## Phase 13: Full Integration, Load, Failure, and Release Validation

Goal: prove production readiness end to end.

Tasks:

- [ ] Run unit tests: `go test ./...`.
- [ ] Run vet: `go vet ./...`.
- [ ] Run race tests for workers, orchestration, metering, and access packages.
- [ ] Run database migration tests from empty and previous schema.
- [ ] Run fake provider integration suite.
- [ ] Run real-provider staging suite with WorkOS sandbox, Polar sandbox, GitHub test org,
  Fly staging app, agentunnel staging relay, and papercode staging client.
- [ ] Validate happy path: login, pay, connect GitHub, create project, allocate storage,
  provision config repo, create Fly volume/machine, start, connect through agentunnel,
  use papercode WebSocket, use CLI, generate preview URL, idle auto-stop, resume.
- [ ] Validate credit exhaustion: concurrent running machines drain credits, server stops
  machines, top-up resumes start/connect.
- [ ] Validate storage reclaim: delete project returns assigned storage and removes or
  retains provider resources according to approved policy.
- [ ] Validate restart apply: machine type, presets, setup script, and idle timeout apply
  only on restart.
- [ ] Validate provider failures: Polar replay, GitHub outage, Fly partial create,
  agentunnel unavailable, database restart, worker crash.
- [ ] Run load tests for API read/write, webhook ingestion, project job queue, metering
  workers, and connect endpoint.
- [ ] Run security tests and secret-leak tests.
- [ ] Publish release evidence with measured limits.

Acceptance criteria:

- [ ] All tests pass.
- [ ] Staging end-to-end flow passes without manual database edits or provider cleanup.
- [ ] Load tests meet approved launch targets or release notes state measured lower limits
  and user approves.
- [ ] No known placeholder, stub, dummy function, fake provider path, or TODO-backed
  production branch remains.
- [ ] Runbooks and API docs are current.

Evidence:

- Go test output:
- Race test output:
- Staging E2E transcript:
- Load test summary:
- Security scan:
- Release notes:

## Release Evidence Template

Copy this block into `docs/release-evidence/YYYY-MM-DD.md` for each release candidate.

```md
# paperboat-server Release Evidence - YYYY-MM-DD

## Build

- Commit:
- Go version:
- OS/arch:
- Build command:

## Config

- Persistence backend:
- WorkOS environment:
- Polar environment:
- GitHub org/user:
- Fly org/app/regions:
- agentunnel environment:
- papercode client build:

## Verification

- gofmt:
- go vet:
- go test:
- go test -race:
- migration tests:
- contract tests:
- security tests:

## End-to-End

- Login:
- Entitlement:
- GitHub OAuth:
- Config repo:
- Project create:
- Fly volume:
- Fly machine:
- agentunnel connect:
- papercode WebSocket:
- CLI connect:
- Preview URL:
- Idle auto-stop:
- Resume:
- Delete/reclaim:

## Load

- API:
- Webhooks:
- Job queue:
- Metering:
- Connect:

## Failure Drills

- Polar replay:
- GitHub outage:
- Fly partial failure:
- agentunnel outage:
- DB restart:
- Worker crash:

## Known Limits

- Validated users:
- Validated projects:
- Validated concurrent machines:
- Validated connects/min:
- Validated metering intervals/min:

## Sign-off

- Engineering:
- Product:
- Security:
- Operations:
```

## Definition of Done

Production release is done only when:

- [ ] Every phase is `Complete`.
- [ ] Every required decision is resolved and documented.
- [ ] Every external contract is approved and documented.
- [ ] No production code path contains stubs, dummy behavior, hardcoded catalog values, or
  placeholder provider logic.
- [ ] Dashboard, CLI, papercode, agentunnel, Fly, GitHub, WorkOS, and Polar integration
  paths are verified in staging.
- [ ] Server-side billing, metering, quota, and authorization invariants are tested.
- [ ] Release evidence exists and states measured operating limits.
- [ ] Runbooks exist for all critical provider and lifecycle failures.
