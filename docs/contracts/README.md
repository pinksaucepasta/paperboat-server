# Phase 0 Contract Pack

Status: implemented contract baseline, pending final cross-project sign-off.

These docs capture the Phase 0 contract freeze work for `paperboat-server`.
They define the implementation baseline for later phases while keeping environment-
specific provider values in dynamic configuration and catalog seed data.

## Documents

- [decisions.md](decisions.md) - Phase 0 decision log, blockers, and review gates.
- [http-api.md](http-api.md) - Paperboat server HTTP API and JSON response contract.
- [provider-contracts.md](provider-contracts.md) - WorkOS, Polar, Fly.io, GitHub, and
  catalog seed boundaries.
- [access-handoff.md](access-handoff.md) - agentunnel, papercode, and paperboat-cli
  pre-connect descriptor contracts.
- [cli-authorization.md](cli-authorization.md) - device grants, scoped CLI sessions,
  refresh rotation, and client revocation.

## Approval Rule

Contract changes after this baseline require explicit approval. Production provider
values and final dashboard, agentunnel, papercode, and CLI sign-off links remain release
evidence, not code defaults. Values that can change after launch must remain dynamic
configuration or database records.
