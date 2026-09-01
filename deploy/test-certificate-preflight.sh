#!/bin/sh

# Focused source/config test for certificate deployment composition. It uses
# only .env.example, so it never needs or creates a secret value.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EXAMPLE_ENV_FILE=$SCRIPT_DIR/.env.example
COMPOSE_FILE=$SCRIPT_DIR/docker-compose.yml

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' 'certificate deployment test: docker is required' >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  printf '%s\n' 'certificate deployment test: jq is required' >&2
  exit 1
}

sh -n "$SCRIPT_DIR/certificate-preflight.sh"
grep -Fq "'*.\$preview_base_domain'" "$SCRIPT_DIR/certificate-preflight.sh"
grep -Fq "'*.\$tunnel_base_domain'" "$SCRIPT_DIR/certificate-preflight.sh"
! grep -Fq ":'preview_base_domain'" "$SCRIPT_DIR/certificate-preflight.sh"
! grep -Fq ":'tunnel_base_domain'" "$SCRIPT_DIR/certificate-preflight.sh"
"$SCRIPT_DIR/certificate-preflight.sh" --source-only

PAPERBOAT_ENV_FILE=$EXAMPLE_ENV_FILE \
  docker compose --env-file "$EXAMPLE_ENV_FILE" -f "$COMPOSE_FILE" config --quiet

required_keys=$(awk -F= '/^PAPERBOAT_CERTIFICATES_[A-Z0-9_]+=/ { print $1 }' "$EXAMPLE_ENV_FILE" | jq -Rsc 'split("\n") | map(select(length > 0))')
PAPERBOAT_ENV_FILE=$EXAMPLE_ENV_FILE \
  docker compose --env-file "$EXAMPLE_ENV_FILE" -f "$COMPOSE_FILE" config --format json |
  jq -e --argjson required "$required_keys" '
    .services.migrate.environment as $migrate
    | .services.server.environment as $server
    | [$required[] as $key | select(($migrate | has($key)) | not)] as $migrate_missing
    | [$required[] as $key | select(($server | has($key)) | not)] as $server_missing
    | [$required[] as $key | select(($migrate[$key] // null) != ($server[$key] // null))] as $mismatched
    | ($migrate_missing | length) == 0
      and ($server_missing | length) == 0
      and ($mismatched | length) == 0
  ' >/dev/null

printf '%s\n' 'certificate deployment test: source and Compose checks passed'
