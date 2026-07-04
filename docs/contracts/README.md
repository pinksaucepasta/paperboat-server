# Phase 0 Contract Pack

Status: draft, pending user approval.

These docs capture the Phase 0 contract freeze work for `paperboat-server`.
They are intentionally written before production code exists, so later phases can
implement against reviewed contracts instead of inventing behavior.

## Documents

- [decisions.md](decisions.md) - Phase 0 decision log, blockers, and review gates.
- [http-api.md](http-api.md) - Paperboat server HTTP API and JSON response contract.
- [provider-contracts.md](provider-contracts.md) - WorkOS, Polar, Fly.io, GitHub, and
  catalog seed boundaries.
- [access-handoff.md](access-handoff.md) - agentunnel, papercode, and paperboat-cli
  pre-connect descriptor contracts.

## Approval Rule

Anything marked `TBD` or `Pending approval` blocks the affected implementation phase.
Do not silently choose defaults in code. Values that can change after launch must remain
dynamic configuration or database records.

