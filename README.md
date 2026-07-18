# paperboat-server

The control plane for Paperboat. It owns identity, billing and metering, hosted and BYOD
environment lifecycle, config-repository assignment, authorization, and tunnel policy.

Live terminal, upload, and preview traffic does not pass through this service.
`paperboat-server` decides, authorizes, meters, and orchestrates.

See [AGENTS.md](AGENTS.md) for repository ownership and engineering requirements.

## Development

The server is a Go service backed by PostgreSQL. Application SQL is generated with `sqlc` from `internal/db/queries`,
while Goose owns forward-only Postgres migration execution from `internal/db/migrations`.

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
make check
```

## Deployment

The repo includes a Compose-based production stack under `deploy/`. It runs PostgreSQL,
one-shot migration and seed jobs, the backend server, and Caddy for TLS termination. Start
from `deploy/.env.example`, provide the required domain and secret files, then run
`docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --build`.

The server exposes health/readiness, authentication, billing, usage, project, environment,
and config-repository APIs. See [docs/api.md](docs/api.md) and
[docs/contracts/http-api.md](docs/contracts/http-api.md) for the maintained interface.

For direct server OAuth testing, set the GitHub OAuth app callback URL to:

```text
https://<public-base-url>/api/github/oauth/callback
```

Run the server with:

```sh
PAPERBOAT_PUBLIC_BASE_URL='https://<public-base-url>' \
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
- `PAPERBOAT_AUTO_TOPUP_RETRY_COOLDOWN_SECONDS`
- `PAPERBOAT_CHECKOUT_RESERVATION_TTL_SECONDS`
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
- `PAPERBOAT_MINT_ACTIVE_KEY_ID`
- `PAPERBOAT_MINT_SIGNING_KEYS` or `PAPERBOAT_MINT_SIGNING_KEYS_FILE` as comma-separated
  `kid:base64url` Ed25519 seeds/private keys. Publish the previous key alongside the active
  key for the configured `PAPERBOAT_MINT_JWKS_MAX_AGE` rotation overlap.


Postgres tables live in the dedicated `paperboat` schema. The migration policy is
forward-only for production releases.

## License

MIT. See [LICENSE](LICENSE).
