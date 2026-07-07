# paperboat-server

The core backend / **control plane** of the Paperboat platform. It couples everything
together: identity (WorkOS), billing and metering (Polar.sh, credits, storage), project and
Fly.io machine/volume lifecycle, GitHub config-repo provisioning, and pre-connect
authorization for agent access.

It is a control-plane service — live agent/terminal traffic flows through **agentunnel**, not
through this server. paperboat-server decides, authorizes, meters, and orchestrates.

> **Status:** Phase 5 GitHub OAuth/config-repo foundation is in progress. See [AGENTS.md](AGENTS.md) for responsibilities
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
`/readyz`), auth/session APIs, billing/usage APIs, and the Phase 5 GitHub endpoints
(`/api/github/status`, `/api/github/oauth/start`, `/api/github/oauth/callback`, and
`/api/github/config-repo/provision`). Later product APIs are protected by the auth, CSRF,
and entitlement middleware foundations and return structured errors until their gated
phases implement real behavior.

For direct server OAuth testing through ngrok, set the GitHub OAuth app callback URL to:

```text
https://unified-camel-humorous.ngrok-free.app/api/github/oauth/callback
```

Run the server with:

```sh
PAPERBOAT_PUBLIC_BASE_URL='https://unified-camel-humorous.ngrok-free.app' \
PAPERBOAT_FAKE_PROVIDERS=false \
PAPERBOAT_GITHUB_BASE_URL='https://api.github.com' \
PAPERBOAT_GITHUB_CLIENT_ID='...' \
PAPERBOAT_GITHUB_CLIENT_SECRET='...' \
go run ./cmd/paperboat-server serve -config config/local.example.json
```

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
- `PAPERBOAT_GITHUB_OAUTH_AUTHORIZE_URL`
- `PAPERBOAT_GITHUB_OAUTH_TOKEN_URL`
- `PAPERBOAT_GITHUB_OAUTH_SCOPES`
- `PAPERBOAT_GITHUB_CONFIG_REPO_NAME`
- `PAPERBOAT_GITHUB_CONFIG_REPO_BRANCH`
- `PAPERBOAT_FAKE_PROVIDERS`
- `PAPERBOAT_SESSION_KEYS` or `PAPERBOAT_SESSION_KEYS_FILE`
- `PAPERBOAT_ENCRYPTION_KEY` or `PAPERBOAT_ENCRYPTION_KEY_FILE`
- `PAPERBOAT_WORKOS_API_KEY` or `PAPERBOAT_WORKOS_API_KEY_FILE`
- `PAPERBOAT_WORKOS_CLIENT_ID` or `PAPERBOAT_WORKOS_CLIENT_ID_FILE`
- `PAPERBOAT_WORKOS_CLIENT_SECRET` or `PAPERBOAT_WORKOS_CLIENT_SECRET_FILE`
- `PAPERBOAT_POLAR_API_KEY` or `PAPERBOAT_POLAR_API_KEY_FILE`
- `PAPERBOAT_POLAR_WEBHOOK_SECRET` or `PAPERBOAT_POLAR_WEBHOOK_SECRET_FILE`
- `PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS`
- `PAPERBOAT_GITHUB_CLIENT_ID` or `PAPERBOAT_GITHUB_CLIENT_ID_FILE`
- `PAPERBOAT_GITHUB_CLIENT_SECRET` or `PAPERBOAT_GITHUB_CLIENT_SECRET_FILE`
- `PAPERBOAT_FLY_API_TOKEN` or `PAPERBOAT_FLY_API_TOKEN_FILE`
- `PAPERBOAT_FLY_APP_NAME`
- `PAPERBOAT_FLY_ORG_SLUG`
- `PAPERBOAT_FLY_IMAGE_REF`
- `PAPERBOAT_FLY_BASE_URL`
- `PAPERBOAT_FLY_VOLUME_NAME_PREFIX`
- `PAPERBOAT_FLY_MACHINE_NAME_PREFIX`
- `PAPERBOAT_FLY_MOUNT_PATH`
- `PAPERBOAT_FLY_BOOT_COMMAND`
- `PAPERBOAT_FLY_AGENTUNNEL_SECRET`
- `PAPERBOAT_FLY_GITHUB_SECRET`
- `PAPERBOAT_AGENTUNNEL_API_KEY` or `PAPERBOAT_AGENTUNNEL_API_KEY_FILE`
- `PAPERBOAT_AGENTUNNEL_MACHINE_TOKEN` or `PAPERBOAT_AGENTUNNEL_MACHINE_TOKEN_FILE`

Fly.io TODO for real-provider smoke testing:

- Rotate any token that was shared outside a secret store.
- Create a fresh org-scoped Fly token and set `PAPERBOAT_FLY_API_TOKEN`.
- Set `PAPERBOAT_FLY_ORG_SLUG` and `PAPERBOAT_FLY_APP_NAME`; the Fly SDK client creates
  the configured app if it does not already exist.
- Build/push the project VM image and set `PAPERBOAT_FLY_IMAGE_REF`.
- Set `PAPERBOAT_AGENTUNNEL_API_KEY` to a server-side agentunnel API key with the approved
  control-plane scope.
- Set `PAPERBOAT_AGENTUNNEL_BASE_URL`, `PAPERBOAT_AGENTUNNEL_PAPERCODE_LOCAL_URL`,
  `PAPERBOAT_AGENTUNNEL_ROUTE_EXPIRES_IN`, and
  `PAPERBOAT_AGENTUNNEL_ROUTE_SUBDOMAIN_PREFIX` for papercode HTTP/WSS route
  reconciliation.
- Do not configure a shared production `PAPERBOAT_AGENTUNNEL_MACHINE_TOKEN`; project VM
  tokens are issued through agentunnel client provisioning and injected per machine. The
  env var remains only as a local development fallback.

Postgres tables live in the dedicated `paperboat` schema. The migration policy is
forward-only for production releases.
