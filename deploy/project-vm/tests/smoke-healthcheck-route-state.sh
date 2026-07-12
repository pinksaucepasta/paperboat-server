#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export PAPERBOAT_READINESS_FILE="$tmp/readiness.json"
export PAPERBOAT_AGENTUNNEL_STATUS_FILE="$tmp/agentunnel.json"
printf '{"state":"ready","reason":"ready"}\n' > "$PAPERBOAT_READINESS_FILE"

printf '{"status":"disconnected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
if "$root/bin/paperboat-healthcheck"; then
  printf 'healthcheck accepted a disconnected agentunnel route\n' >&2
  exit 1
fi

printf '{"status":"connecting"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
if "$root/bin/paperboat-healthcheck"; then
  printf 'healthcheck accepted a connecting agentunnel route\n' >&2
  exit 1
fi

printf '{"status":"connected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
"$root/bin/paperboat-healthcheck"
