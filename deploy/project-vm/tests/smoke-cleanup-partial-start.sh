#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/workspace/.git" "$tmp/runtime" "$tmp/logs"

cat > "$bin/prepare" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF

cat > "$bin/config-sync" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'config-sync:%s\n' "${1:-}" >> "$PAPERBOAT_TEST_EVENT_LOG"
exit 0
EOF

cat > "$bin/presets" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF

cat > "$bin/papercode" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$$" > "$PAPERBOAT_TEST_CHILD_PID_FILE"
trap 'printf terminated > "$PAPERBOAT_TEST_CHILD_TERMINATED_FILE"; printf "child:terminated\n" >> "$PAPERBOAT_TEST_EVENT_LOG"; exit 0' TERM
while :; do sleep 1; done
EOF

cat > "$bin/wait-http" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 41
EOF

chmod +x "$bin"/*

export PAPERBOAT_TEST_EVENT_LOG="$tmp/events.log"
export PAPERBOAT_TEST_CHILD_PID_FILE="$tmp/papercode.pid"
export PAPERBOAT_TEST_CHILD_TERMINATED_FILE="$tmp/papercode.terminated"
export PAPERBOAT_RUNTIME_DIR="$tmp/runtime"
export PAPERBOAT_LOG_DIR="$tmp/logs"
export PAPERBOAT_WORKSPACE="$tmp/workspace"
export PAPERBOAT_READINESS_FILE="$tmp/runtime/readiness.json"
export PAPERBOAT_PREPARE_WORKSPACE_COMMAND="$bin/prepare"
export PAPERBOAT_CONFIG_SYNC_COMMAND="$bin/config-sync"
export PAPERBOAT_PRESET_APPLY_COMMAND="$bin/presets"
export PAPERBOAT_PAPERCODE_COMMAND="$bin/papercode"
export PAPERBOAT_WAIT_HTTP_COMMAND="$bin/wait-http"
export PAPERBOAT_PROJECT_ID="prj_smoke"
export PAPERBOAT_REPOSITORY_URL="https://github.com/example/repo.git"
export PAPERBOAT_AGENTUNNEL_SERVER_URL="https://agentunnel.example"
export PAPERBOAT_AGENTUNNEL_CLIENT_ID="cli_smoke"
export PAPERBOAT_AGENTUNNEL_TUNNEL_ID="tun_smoke"
export AGENTUNNEL_MACHINE_TOKEN="token_smoke"

set +e
"$root/bin/paperboat-entrypoint" >/tmp/paperboat-cleanup-smoke.out 2>/tmp/paperboat-cleanup-smoke.err
status=$?
set -e

if [ "$status" -eq 0 ]; then
  printf 'entrypoint unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'config-sync:save' "$PAPERBOAT_TEST_EVENT_LOG"
grep -q 'terminated' "$PAPERBOAT_TEST_CHILD_TERMINATED_FILE"
if [ "$(tail -n 2 "$PAPERBOAT_TEST_EVENT_LOG")" != "$(printf 'child:terminated\nconfig-sync:save')" ]; then
  printf 'cleanup did not stop children before saving config\n' >&2
  cat "$PAPERBOAT_TEST_EVENT_LOG" >&2
  exit 1
fi
