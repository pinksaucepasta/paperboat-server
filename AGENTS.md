# AGENTS.md - paperboat-server

Inherit [`../AGENTS.md`](../AGENTS.md). Server, backend, and control plane mean this repo.

## Ownership

Authoritative WorkOS identity, sessions, authorization, Polar billing, credits, storage,
BYOD seats, bandwidth entitlement, projects, machines, config repos/assignments, route
intent, scoped credentials, reconciliation, and audit state. Never proxy terminal,
upload, or preview bytes.

## Stack

Go `1.25.7`; PostgreSQL/pgx; embedded Goose `v3.27.1`; sqlc `v1.30.0`; standard HTTP with
narrow provider adapters. Application SQL belongs in sqlc queries; schema changes are
forward migrations.

## Local Rules

- Handlers map transport; services own policy; repositories own transactions; adapters
  own provider protocols and failure translation.
- Persist desired state and reconcile provider observations. Never hold a transaction
  during network I/O.
- Cross-boundary mutations use idempotency, operation IDs, optimistic versions, durable
  outboxes, and explicit uncertain-outcome handling where applicable.
- APIs use snake_case JSON, stable error codes, safe messages, request IDs, structured
  details, pagination, and retry metadata.
- External clients require explicit timeouts, bounded reads, validation, redaction,
  metrics, and operation-specific retry policy. No production `http.DefaultClient`.
- Required PostgreSQL tests must not silently skip in CI; use deterministic clocks and
  repository-local fixture infrastructure.

## Verify

Run `make check`, required PostgreSQL integration tests, and race tests for affected
workers, auth, metering, reconciliation, or concurrent mutations.
