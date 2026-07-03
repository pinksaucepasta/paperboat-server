# paperboat-server

The core backend / **control plane** of the Paperboat platform. It couples everything
together: identity (WorkOS), billing and metering (Polar.sh, credits, storage), project and
Fly.io machine/volume lifecycle, GitHub config-repo provisioning, and pre-connect
authorization for agent access.

It is a control-plane service — live agent/terminal traffic flows through **agentunnel**, not
through this server. paperboat-server decides, authorizes, meters, and orchestrates.

> **Status:** scaffolded, not yet implemented. See [AGENTS.md](AGENTS.md) for responsibilities
> and conventions, and the workspace `USERSTORY.md` for how this fits the platform.

## Stack

Go — single binary, part of the platform's Go infra/control-plane side alongside agentunnel
and paperboat-cli.
