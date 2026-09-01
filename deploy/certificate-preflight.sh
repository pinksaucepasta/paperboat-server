#!/bin/sh

# Production certificate deployment preflight.
#
# This check is deliberately read-only. It validates the Compose projection,
# verifies that the four reference-derived environment names are populated in
# the running server, compares the distribution credential with the exact edge
# credential file bytes, and waits for migration 150 plus both platform
# certificate targets and their active edge distributions. It never prints a
# secret value or repairs a database row.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE=$SCRIPT_DIR/docker-compose.yml
ENV_FILE=$SCRIPT_DIR/.env
EXAMPLE_ENV_FILE=$SCRIPT_DIR/.env.example
SERVER_SERVICE=server
WAIT_SECONDS=300
POLL_SECONDS=5
SOURCE_ONLY=0
ENV_FILE_EXPLICIT=0

CERTIFICATE_KEYS='PAPERBOAT_CERTIFICATES_ENABLED
PAPERBOAT_CERTIFICATES_DIRECTORY_URL
PAPERBOAT_CERTIFICATES_ACCOUNT_KID
PAPERBOAT_CERTIFICATES_ACCOUNT_EMAIL
PAPERBOAT_CERTIFICATES_ISSUER
PAPERBOAT_CERTIFICATES_ACCOUNT_KEY_REFERENCE
PAPERBOAT_CERTIFICATES_MASTER_KEY_REFERENCE
PAPERBOAT_CERTIFICATES_DNS_PROVIDER
PAPERBOAT_CERTIFICATES_DNS_ZONE_ID
PAPERBOAT_CERTIFICATES_DNS_TOKEN_REFERENCE
PAPERBOAT_CERTIFICATES_CHALLENGE_ZONE
PAPERBOAT_CERTIFICATES_CAA_RESOLVER
PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE
PAPERBOAT_CERTIFICATES_OWNER_ID
PAPERBOAT_CERTIFICATES_RENEW_BEFORE
PAPERBOAT_CERTIFICATES_LOCK_TTL
PAPERBOAT_CERTIFICATES_DISTRIBUTION_TIMEOUT
PAPERBOAT_CERTIFICATES_EXPIRY_ALERT_WINDOW
PAPERBOAT_CERTIFICATES_MAX_LIFETIME
PAPERBOAT_CERTIFICATES_ACME_TIMEOUT
PAPERBOAT_CERTIFICATES_PROPAGATION_TIMEOUT
PAPERBOAT_CERTIFICATES_CLEANUP_TIMEOUT
PAPERBOAT_CERTIFICATES_POLL_INTERVAL
PAPERBOAT_CERTIFICATES_RETRY_BASE
PAPERBOAT_CERTIFICATES_RETRY_MAX
PAPERBOAT_CERTIFICATES_MAX_ATTEMPTS'

REFERENCE_VALUES='secret://acme/account
secret://paperboat/master
secret://cloudflare/dns
secret://edge/distribution'

REFERENCE_KEYS='PAPERBOAT_CERTIFICATES_ACCOUNT_KEY_REFERENCE
PAPERBOAT_CERTIFICATES_MASTER_KEY_REFERENCE
PAPERBOAT_CERTIFICATES_DNS_TOKEN_REFERENCE
PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE'

usage() {

  cat <<'EOF'
Usage: certificate-preflight.sh [options]

Options:
  --env-file PATH       production server env file (default: deploy/.env)
  --compose-file PATH   server Compose file (default: deploy/docker-compose.yml)
  --server-service NAME running server service (default: server)
  --wait-seconds N      maximum database wait (default: 300)
  --poll-seconds N      database polling interval (default: 5)
  --source-only         check source policy without Docker, a server, or a database
  -h, --help            show this help
EOF
}

fail() {
  printf '%s\n' "certificate preflight failed: $*" >&2
  exit 1
}

info() {
  printf '%s\n' "certificate preflight: $*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

read_env_value() {
  # Read a simple KEY=value dotenv entry without sourcing arbitrary shell.
  # Deployment values are intentionally kept free of shell interpolation.
  key=$1
  file=$2
  value=$(awk -v wanted="$key" '
    /^[[:space:]]*#/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (index(line, wanted "=") == 1) {
        value = substr(line, length(wanted) + 2)
        if (value ~ /^".*"$/) {
          value = substr(value, 2, length(value) - 2)
        }
        print value
        exit
      }
    }
  ' "$file")
  printf '%s' "$value"
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
    return
  fi
  require_command shasum
  shasum -a 256 | awk '{print $1}'
}

reference_env_name() {
  reference=$1
  normalized=
  old_lc_all=${LC_ALL-}
  LC_ALL=C
  export LC_ALL
  rest=$reference
  while [ -n "$rest" ]; do
    character=${rest%"${rest#?}"}
    rest=${rest#?}
    case "$character" in
      [A-Za-z0-9]) normalized=$normalized$(printf '%s' "$character" | tr '[:lower:]' '[:upper:]') ;;
      *) normalized=${normalized}_ ;;
    esac
  done
  digest=$(printf '%s' "$reference" | sha256_stdin | cut -c 1-12)
  if [ -n "$old_lc_all" ]; then
    LC_ALL=$old_lc_all
    export LC_ALL
  else
    unset LC_ALL
  fi
  printf 'PAPERBOAT_CERT_SECRET_%s_%s' "$normalized" "$digest"
}

make_absolute_path() {
  path=$1
  case "$path" in
    /*) printf '%s' "$path" ;;
    *)
      directory=$(dirname -- "$path")
      filename=$(basename -- "$path")
      directory=$(CDPATH='' cd -- "$directory" 2>/dev/null && pwd) || fail "directory does not exist: $directory"
      printf '%s/%s' "$directory" "$filename"
      ;;
  esac
}

compose() {
  # Supplying PAPERBOAT_ENV_FILE explicitly makes the env_file path absolute,
  # regardless of the caller's current working directory.
  PAPERBOAT_ENV_FILE=$ENV_FILE docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

check_source_policy() {
  [ -f "$COMPOSE_FILE" ] || fail "Compose file does not exist: $COMPOSE_FILE"
  [ -f "$EXAMPLE_ENV_FILE" ] || fail "example environment file does not exist: $EXAMPLE_ENV_FILE"
  if [ "$SOURCE_ONLY" -eq 0 ]; then
    [ -f "$ENV_FILE" ] || fail "environment file does not exist: $ENV_FILE"
  fi
  runbook=$SCRIPT_DIR/../docs/runbooks/preview-tunnel-control-plane.md
  [ -f "$runbook" ] || fail "certificate runbook does not exist: $runbook"

  # Keep this check safe to run in CI and on an operator laptop without
  # loading any deployment environment into the shell.
  sh -n "$0" || fail "shell syntax is invalid: $0"

  for key in $CERTIFICATE_KEYS; do
    grep -Eq "^${key}=" "$EXAMPLE_ENV_FILE" || fail "missing certificate setting in $(basename "$EXAMPLE_ENV_FILE"): $key"
  done

  for reference in $REFERENCE_VALUES; do
    name=$(reference_env_name "$reference")
    grep -Fq "$name" "$EXAMPLE_ENV_FILE" || fail "missing derived reference name in $(basename "$EXAMPLE_ENV_FILE"): $name"
  done

  # The service-level aliases are intentional. They make the migration and
  # serving paths visibly inherit the same production overlay.
  service_env_file_count=$(grep -Fc 'env_file: *server-env-file' "$COMPOSE_FILE" || true)
  [ "$service_env_file_count" -ge 4 ] || fail "Compose does not explicitly attach the shared env_file to server phases"

  grep -Fq 'PAPERBOAT_CERTIFICATES_ENABLED=true' "$EXAMPLE_ENV_FILE" || fail "the example overlay must require certificates enabled"
  grep -Fq 'PAPERBOAT_CERTIFICATES_RETRY_MAX=2m' "$EXAMPLE_ENV_FILE" || fail "the example retry maximum must stay within the runtime validation bound"
  grep -Fq 'PAPERBOAT_CERTIFICATES_ENABLED=false' "$runbook" && fail "the production runbook must not document enabled=false as a workaround"
  grep -Fq 'migration 150' "$runbook" || fail "runbook does not gate rollout on migration 150"
  grep -Fq 'platform_cert_preview_v1' "$runbook" || fail "runbook does not name the preview platform target"
  grep -Fq 'platform_cert_tunnel_v1' "$runbook" || fail "runbook does not name the tunnel platform target"
  grep -Fq "edge.state = 'active'" "$runbook" || fail "runbook does not require active edge distributions"
  grep -Fq 'distribution credential must equal the edge control credential' "$runbook" || fail "runbook does not state credential equality"
  grep -Fq 'exactly the same bytes' "$runbook" || fail "runbook does not state byte equality"

  # Only reference names may be committed. These patterns intentionally do not
  # inspect the opaque values injected by a secret manager at runtime.
  if grep -Eq '^PAPERBOAT_CERT_SECRET_[A-Za-z0-9_]+=([^[:space:]#].*)$' "$EXAMPLE_ENV_FILE"; then
    fail "derived certificate secret values must not be committed"
  fi
  if grep -Eiq -- '-----BEGIN (CERTIFICATE|[^-]*PRIVATE KEY)-----' "$EXAMPLE_ENV_FILE"; then
    fail "certificate or private-key material must not be committed"
  fi

  info "source policy and certificate references are valid"
}

compose_env_keys_json() {
  printf '%s\n' "$CERTIFICATE_KEYS" | jq -Rsc 'split("\n") | map(select(length > 0))'
}

check_compose_projection() {
  require_command docker
  require_command jq

  compose config --quiet >/dev/null 2>&1 || fail "Compose configuration is invalid"
  required_json=$(compose_env_keys_json)
  if ! compose config --format json 2>/dev/null | jq -e --argjson required "$required_json" '
    .services.migrate.environment as $migrate
    | .services.server.environment as $server
    | {
        migrate_missing: [$required[] as $key | select(($migrate | has($key)) | not)],
        server_missing: [$required[] as $key | select(($server | has($key)) | not)],
        mismatched: [$required[] as $key | select(($migrate[$key] // null) != ($server[$key] // null))]
      }
    | select((.migrate_missing | length) == 0
        and (.server_missing | length) == 0
        and (.mismatched | length) == 0)
  ' >/dev/null; then
    fail "Compose migrate/server projection does not carry the same certificate settings"
  fi
  info "Compose migrate/server env_file projection carries every certificate setting"
}

check_runtime_settings() {
  enabled=$(read_env_value PAPERBOAT_CERTIFICATES_ENABLED "$ENV_FILE")
  [ "$enabled" = true ] || fail "production requires PAPERBOAT_CERTIFICATES_ENABLED=true"

	for key in \
	    PAPERBOAT_DATABASE_DSN \
	    PAPERBOAT_RUNTIME_BASE_DOMAIN \
	    PAPERBOAT_PREVIEW_BASE_DOMAIN \
    PAPERBOAT_TUNNEL_BASE_DOMAIN \
    PAPERBOAT_CERTIFICATES_DIRECTORY_URL \
    PAPERBOAT_CERTIFICATES_ACCOUNT_KEY_REFERENCE \
    PAPERBOAT_CERTIFICATES_MASTER_KEY_REFERENCE \
    PAPERBOAT_CERTIFICATES_DNS_TOKEN_REFERENCE \
    PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE \
    PAPERBOAT_CERTIFICATES_DNS_ZONE_ID \
    PAPERBOAT_CERTIFICATES_CHALLENGE_ZONE; do
    value=$(read_env_value "$key" "$ENV_FILE")
    [ -n "$value" ] || fail "required production value is missing: $key"
  done

  case "$(read_env_value PAPERBOAT_CERTIFICATES_DIRECTORY_URL "$ENV_FILE")" in
    https://*) ;;
    *) fail "production ACME directory must use HTTPS" ;;
  esac
  [ "$(read_env_value PAPERBOAT_CERTIFICATES_DNS_PROVIDER "$ENV_FILE")" = cloudflare ] || fail "production DNS provider must be cloudflare"
  case "$(read_env_value PAPERBOAT_CERTIFICATES_DNS_ZONE_ID "$ENV_FILE")" in
    replace-with-*|example*|*example.*) fail "production DNS zone must be provisioned" ;;
  esac

  preview_domain=$(read_env_value PAPERBOAT_PREVIEW_BASE_DOMAIN "$ENV_FILE")
  tunnel_domain=$(read_env_value PAPERBOAT_TUNNEL_BASE_DOMAIN "$ENV_FILE")
  [ "$preview_domain" != "$tunnel_domain" ] || fail "preview and tunnel base domains must differ"
  case "$preview_domain$tunnel_domain" in
    *[!A-Za-z0-9.-]*) fail "preview/tunnel base domains contain unsupported characters" ;;
  esac

  for key in $REFERENCE_KEYS; do
    reference=$(read_env_value "$key" "$ENV_FILE")
    case "$reference" in
      secret://*) ;;
      *) fail "certificate references must remain opaque secret:// references" ;;
    esac
  done

  DATABASE_DSN=$(read_env_value PAPERBOAT_DATABASE_DSN "$ENV_FILE")
  [ -n "$DATABASE_DSN" ] || fail "PAPERBOAT_DATABASE_DSN is required"
}

check_container_secret_env() {
  require_command docker
  container_id=$(compose ps --status running -q "$SERVER_SERVICE" 2>/dev/null || true)
  [ -n "$container_id" ] || fail "server service is not running: $SERVER_SERVICE"

  for key in $REFERENCE_KEYS; do
    reference=$(read_env_value "$key" "$ENV_FILE")
    name=$(reference_env_name "$reference")
    # The generated name contains only shell-safe identifier characters. The
    # value remains inside the container and is never included in diagnostics.
    compose exec -T "$SERVER_SERVICE" sh -ceu "test -n \"\${${name}:-}\"" >/dev/null 2>&1 || fail "derived certificate secret is missing in the running server: $name"
  done
  info "four derived certificate references are populated in the running server"
}

check_distribution_credential_equality() {
  distribution_reference=$(read_env_value PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE "$ENV_FILE")
  distribution_name=$(reference_env_name "$distribution_reference")
  compose exec -T "$SERVER_SERVICE" sh -ceu "
    set -eu
    distribution=\$(printenv '$distribution_name')
    credential_file=\$(printenv PAPERBOAT_EDGE_CONTROL_CREDENTIAL_FILE)
    test -n \"\$distribution\"
    test -n \"\$credential_file\" -a -r \"\$credential_file\"
    expected=\$(printf '%s' \"\$distribution\" | sha256sum | awk '{print \$1}')
    actual=\$(sha256sum \"\$credential_file\" | awk '{print \$1}')
    test \"\$expected\" = \"\$actual\"
  " >/dev/null 2>&1 || fail "distribution credential does not equal the edge control credential file bytes"
  info "distribution credential equality matches the edge control credential"
}

wait_for_certificate_state() {
  require_command psql
  preview_base_domain=$(read_env_value PAPERBOAT_PREVIEW_BASE_DOMAIN "$ENV_FILE")
  tunnel_base_domain=$(read_env_value PAPERBOAT_TUNNEL_BASE_DOMAIN "$ENV_FILE")
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  while :; do
    now=$(date +%s)
    [ "$now" -le "$deadline" ] || fail "migration 150, both platform targets, and active edge distributions did not become ready within ${WAIT_SECONDS}s"

    migration_ok=$(psql "$DATABASE_DSN" -X -A -t -q \
      --set=ON_ERROR_STOP=1 \
      -c "SELECT EXISTS (SELECT 1 FROM paperboat.goose_db_version WHERE version_id = 150 AND is_applied)" \
      2>/dev/null || true)
    if [ "$migration_ok" = t ]; then
      certificate_state_sql="
WITH expected(id, kind, hostname) AS (
  VALUES
    ('platform_cert_preview_v1', 'preview_wildcard', '*.$preview_base_domain'),
    ('platform_cert_tunnel_v1', 'tunnel_wildcard', '*.$tunnel_base_domain')
),
targets AS (
  SELECT target.*
    FROM paperboat.tunnel_platform_certificate_targets AS target
    JOIN expected ON expected.id = target.id
                 AND expected.kind = target.kind
                 AND expected.hostname = target.hostname
   WHERE target.desired_state = 'active'
     AND target.certificate_state = 'ready'
     AND target.certificate_reference IS NOT NULL
     AND target.certificate_expires_at > now()
),
certificates AS (
  SELECT target.id AS target_id, cert.id AS certificate_id,
         cert.certificate_generation
    FROM targets AS target
    JOIN paperboat.tunnel_certificate_records AS cert
      ON cert.domain_id = target.id
     AND cert.target_kind = 'platform_wildcard'
     AND cert.leaf_hostname IS NULL
     AND cert.hostname = target.hostname
     AND cert.state = 'active'
     AND cert.expires_at > now()
),
ready_edges AS (
  SELECT id, process_epoch
    FROM paperboat.control_tunnel_nodes
   WHERE state = 'ready'
     AND ready = true
     AND last_heartbeat_at > now() - interval '2 minutes'
     AND version > 0
),
fully_distributed AS (
  SELECT certificate.target_id
    FROM certificates AS certificate
   WHERE NOT EXISTS (
           SELECT 1
             FROM ready_edges AS edge_target
            WHERE NOT EXISTS (
                    SELECT 1
                      FROM paperboat.tunnel_certificate_edge_distributions AS distribution
                     WHERE distribution.certificate_id = certificate.certificate_id
                       AND distribution.edge_node_id = edge_target.id
                       AND distribution.edge_process_epoch = edge_target.process_epoch
                       AND distribution.edge_assignment_generation = 1
                       AND distribution.state = 'active'
                       AND distribution.observed_certificate_generation = certificate.certificate_generation
                       AND distribution.observed_at IS NOT NULL
                       AND distribution.failure_code IS NULL
                  )
         )
)
SELECT (
  (SELECT count(*) FROM targets) = 2
  AND (SELECT count(*) FROM certificates) = 2
  AND (SELECT count(*) FROM ready_edges) > 0
  AND (SELECT count(*) FROM fully_distributed) = 2
)"
      if state_ok=$(psql "$DATABASE_DSN" -X -A -t -q \
        --set=ON_ERROR_STOP=1 \
        --command="$certificate_state_sql" 2>/dev/null); then
        :
      else
        state_ok=
      fi
      if [ "$state_ok" = t ]; then
        info "migration 150, both platform targets, and all current edge distributions are ready"
        return 0
      fi
    fi
    sleep "$POLL_SECONDS"
  done
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file)
      [ "$#" -ge 2 ] || fail "--env-file requires a path"
      ENV_FILE=$2
      ENV_FILE_EXPLICIT=1
      shift 2
      ;;
    --compose-file)
      [ "$#" -ge 2 ] || fail "--compose-file requires a path"
      COMPOSE_FILE=$2
      shift 2
      ;;
    --server-service)
      [ "$#" -ge 2 ] || fail "--server-service requires a name"
      SERVER_SERVICE=$2
      shift 2
      ;;
    --wait-seconds)
      [ "$#" -ge 2 ] || fail "--wait-seconds requires a number"
      WAIT_SECONDS=$2
      shift 2
      ;;
    --poll-seconds)
      [ "$#" -ge 2 ] || fail "--poll-seconds requires a number"
      POLL_SECONDS=$2
      shift 2
      ;;
    --source-only)
      SOURCE_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown option: $1"
      ;;
  esac
done

if [ "$SOURCE_ONLY" -eq 1 ] && [ "$ENV_FILE_EXPLICIT" -eq 0 ]; then
  ENV_FILE=$SCRIPT_DIR/.env.example
fi

COMPOSE_FILE=$(make_absolute_path "$COMPOSE_FILE")
ENV_FILE=$(make_absolute_path "$ENV_FILE")

check_source_policy

if [ "$SOURCE_ONLY" -eq 1 ]; then
  info "source-only preflight passed"
  exit 0
fi

check_runtime_settings
check_compose_projection
check_container_secret_env
check_distribution_credential_equality
wait_for_certificate_state
info "production certificate deployment preflight passed"
