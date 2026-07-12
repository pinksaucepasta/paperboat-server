#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export PAPERBOAT_PAPERCODE_BASE_DIR="$tmp/home"
export PAPERBOAT_PAPERCODE_ENVIRONMENT_ID="prj_loopback"
export PAPERBOAT_PAPERCODE_OWNER_ID="usr_loopback"
export PAPERBOAT_PAPERCODE_ISSUER="https://api.paperboat.example"

assert_rejected() {
  local url="$1"
  local host_override="${2:-}"
  set +e
  PAPERBOAT_PAPERCODE_LOCAL_URL="$url" PAPERBOAT_PAPERCODE_HOST="$host_override" \
    "$root/bin/paperboat-start-papercode" >"$tmp/stdout" 2>"$tmp/stderr"
  local status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf 'unsafe papercode bind unexpectedly succeeded: url=%s host=%s\n' "$url" "$host_override" >&2
    exit 1
  fi
}

assert_rejected "http://0.0.0.0:4099"
assert_rejected "http://127.0.0.1:4099" "0.0.0.0"
assert_rejected "http://127.0.0.1:not-a-port"
assert_rejected "http://127.0.0.1:70000"
