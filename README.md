# paperboat-server

The core backend / **control plane** of the Paperboat platform. It couples everything
together: identity (WorkOS), billing and metering (Polar.sh, credits, storage), project and
Fly.io machine/volume lifecycle, GitHub config-repo provisioning, and pre-connect
authorization for agent access.

It is a control-plane service — live agent/terminal traffic flows through **agentunnel**, not
through this server. paperboat-server decides, authorizes, meters, and orchestrates.

> **Status:** Phase 3 identity/session foundation implemented. See [AGENTS.md](AGENTS.md) for responsibilities
> and conventions, and the workspace `USERSTORY.md` for how this fits the platform.

## Stack

Go — single binary, part of the platform's Go infra/control-plane side alongside agentunnel
and paperboat-cli.

## Local Development

Run the service skeleton with fake providers:

```sh
go run ./cmd/paperboat-server serve -config config/local.example.json
```

Apply Postgres migrations and seed dynamic catalogs:

```sh
PAPERBOAT_DATABASE_DSN='postgres://...' go run ./cmd/paperboat-server migrate -config config/local.example.json
PAPERBOAT_DATABASE_DSN='postgres://...' go run ./cmd/paperboat-server seed-catalogs -config config/local.example.json
```

Useful checks:

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
go test ./...
go vet ./...
gofmt -w .
```

The server currently implements foundation endpoints (`/healthz` and
`/readyz`) plus the Phase 3 auth/session foundation (`/api/auth/workos/state`,
`/api/auth/workos/callback`, `/api/auth/csrf`, `/api/auth/logout`, and `/api/me`).
Later product APIs are protected by
the auth, CSRF, and entitlement middleware foundations and return structured errors until
their gated phases implement real behavior.

## Configuration

Configuration can come from defaults, a JSON file, environment variables, and secret-file
environment variables. Secret-file variables use the same name with `_FILE`, for example
`PAPERBOAT_ENCRYPTION_KEY_FILE`.

Common environment overrides:

- `PAPERBOAT_ENV`
- `PAPERBOAT_HTTP_ADDRESS`
- `PAPERBOAT_PUBLIC_BASE_URL`
- `PAPERBOAT_ALLOWED_ORIGINS`
- `PAPERBOAT_DATABASE_DRIVER`
- `PAPERBOAT_DATABASE_DSN`
- `PAPERBOAT_CATALOG_SEED_FILE`
- `PAPERBOAT_FAKE_PROVIDERS`
- `PAPERBOAT_SESSION_KEYS` or `PAPERBOAT_SESSION_KEYS_FILE`
- `PAPERBOAT_ENCRYPTION_KEY` or `PAPERBOAT_ENCRYPTION_KEY_FILE`
- `PAPERBOAT_WORKOS_API_KEY` or `PAPERBOAT_WORKOS_API_KEY_FILE`
- `PAPERBOAT_WORKOS_CLIENT_ID` or `PAPERBOAT_WORKOS_CLIENT_ID_FILE`
- `PAPERBOAT_WORKOS_CLIENT_SECRET` or `PAPERBOAT_WORKOS_CLIENT_SECRET_FILE`
- `PAPERBOAT_POLAR_API_KEY` or `PAPERBOAT_POLAR_API_KEY_FILE`
- `PAPERBOAT_POLAR_WEBHOOK_SECRET` or `PAPERBOAT_POLAR_WEBHOOK_SECRET_FILE`
- `PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS`
- `PAPERBOAT_FLY_API_TOKEN` or `PAPERBOAT_FLY_API_TOKEN_FILE`

Postgres tables live in the dedicated `paperboat` schema. The migration policy is
forward-only for production releases.
