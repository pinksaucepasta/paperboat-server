# AGENTS.md — paperboat-server

Repo-specific guide for **paperboat-server**, the core backend of the Paperboat platform.
This folder is opened inside the Paperboat workspace; the workspace-root `AGENTS.md` and
`USERSTORY.md` are the source of truth for the overall product and the non-negotiable rules
(no hardcoding, frozen contracts, UX first, ask before touching other sub-projects). This
file covers only what is specific to the backend.

> **Status:** scaffolded — docs only, no implementation yet.

---

## What this is

paperboat-server is the **control plane** that couples the whole platform together. It is the
authoritative brain behind the dashboard: it owns identity, billing/metering, project and
machine lifecycle, and the coordination between the other sub-projects.

It is a **control-plane service, not a data-plane proxy.** Live agent/terminal traffic flows
through **agentunnel**, not through this server. paperboat-server decides, authorizes, meters,
and orchestrates; agentunnel and the papercode server on each VM do the live work.

### Responsibilities

- **Identity** — integrate **WorkOS** for authentication; own sessions, and the mapping from
  WorkOS identities to Paperboat users. It is the trust root for the dashboard and for
  pre-connect authorization.
- **Billing & entitlements** — integrate **Polar.sh** (plans: Sailor / Navigator / Captain;
  extra per-GB storage; credit top-ups). Handle Polar webhooks and keep entitlement state
  current. Gate platform access on an active plan.
- **Metering (authoritative)** — meter **credit consumption** (machine runtime × machine-type
  weight, in parallel across running machines) and **storage accounting**. This must be
  server-side and trusted; never rely on client-reported usage. Enforce credit exhaustion
  (stop machines) and storage quotas.
- **Project lifecycle** — create projects (git clone), storage allocation out of the user's
  pool (with reclaim on delete), machine-type selection, and VM customization (presets +
  optional setup script). The presets and machine-type catalogs are **data-driven**, not
  hardcoded.
- **Machine & volume orchestration** — drive **Fly.io** machines and block volumes (one
  machine + one volume per project): create, start, auto-stop on idle (user-selected
  timeout), resume, terminate. Apply resource changes on next restart.
- **GitHub integration** — handle **GitHub OAuth** (at first project creation) and provision
  the user's **private config repo**. (The config *sync* itself runs as a daemon on the VM;
  the server sets up the repo and credentials.)
- **Agent-access pre-connect** — perform auth/authorization/brokering checks before a
  papercode/paperboat-cli client connects to a VM through agentunnel. Confirm the exact
  hand-off with agentunnel; do not duplicate its tunneling logic.

---

## Stack

**Go.** Chosen to match agentunnel and paperboat-cli, forming a shared Go **infra /
control-plane** side of the platform (product/UI stays TypeScript). Prefer the standard
library and small, well-maintained dependencies; avoid heavy frameworks that obscure routing,
auth, or orchestration. Single binary, explicit dependencies, strong concurrency for the
orchestration workers.

Follow standard Go hygiene before considering a change done:

```sh
gofmt -w .
go vet ./...
go test ./...   # add -race when touching concurrent/orchestration code
```

---

## Conventions

- **Server-side trust.** Authorization, metering, and quota enforcement live here, never in
  the dashboard or CLI. Clients are untrusted.
- **Stable, JSON APIs.** The dashboard, CLI, and other services consume this backend. Its
  HTTP/JSON contracts (endpoints, fields, error codes, status enums) are **frozen** per the
  workspace rules — changing them needs explicit permission. Use snake_case JSON and
  structured errors.
- **No hardcoding.** Plans, credit weights, machine-type catalog, preset catalog, quotas,
  idle-timeout bounds, domains — all dynamic/config-driven so values change without a
  redeploy.
- **Idempotent, reconcilable orchestration.** Fly machine/volume operations must tolerate
  retries and partial failures; reconcile persisted intent against actual Fly state (a
  machine that failed to stop, a volume left dangling). Background workers must be explicit,
  context-cancellable, and stoppable.
- **Never log secrets** — WorkOS/Polar/GitHub tokens, Fly API tokens, config-repo
  credentials. Redact.
- **Contracts with other repos are frozen.** agentunnel's interface, the papercode server's
  API, and Fly's API are external contracts — treat them as fixed and coordinate changes with
  their owners. Do not edit other sub-projects from here.

---

## Open decisions (resolve before building the relevant part)

- **Persistence.** DB choice for users/plans/projects/machines/usage. Default lean:
  SQLite-first to match agentunnel, moving to Postgres only if multi-node scale demands it —
  confirm before committing.
- **agentunnel hand-off.** The precise pre-connect protocol between this server and
  agentunnel (token issuance, session brokering, reconnect).
- **Metering source of truth.** How runtime is measured (Fly machine events vs. server-side
  polling) so credits are accurate without trusting the client.

See the workspace `USERSTORY.md` "Open questions" for the product-level versions of these.

---

## Relationship to other sub-projects

- **paperboat-dashboard** — the UI; calls this backend's API for everything.
- **agentunnel** — the data-plane tunnel; this server brokers/authorizes, it does not proxy.
- **papercode** / **paperboat-cli** — clients that reach VMs through agentunnel after this
  server's pre-connect checks.
- **Fly.io** — the compute/storage provider this server orchestrates.

Before building against any of these, read their repos; do not guess internals or change
contracts without permission.
