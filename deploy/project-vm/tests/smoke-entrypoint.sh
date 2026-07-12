#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'kill "$entrypoint_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

log="$tmp/events.log"
bin="$tmp/bin"
mkdir -p "$bin" "$tmp/workspace/.git" "$tmp/runtime" "$tmp/logs"

cat > "$bin/prepare" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'prepare\n' >> "$PAPERBOAT_TEST_EVENT_LOG"
EOF

cat > "$bin/config-sync" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'config-sync:%s\n' "${1:-}" >> "$PAPERBOAT_TEST_EVENT_LOG"
EOF

cat > "$bin/presets" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'presets\n' >> "$PAPERBOAT_TEST_EVENT_LOG"
EOF

cat > "$bin/papercode" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'papercode:start\n' >> "$PAPERBOAT_TEST_EVENT_LOG"
printf ready > "$PAPERBOAT_TEST_PAPERCODE_STARTED_FILE"
while :; do sleep 1; done
EOF

cat > "$bin/wait-http" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
for _ in $(seq 1 50); do
  [ -f "$PAPERBOAT_TEST_PAPERCODE_STARTED_FILE" ] && break
  sleep 0.1
done
printf 'wait-http:%s\n' "$1" >> "$PAPERBOAT_TEST_EVENT_LOG"
EOF

cat > "$bin/agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'agentunnel:start\n' >> "$PAPERBOAT_TEST_EVENT_LOG"
printf ready > "$PAPERBOAT_TEST_AGENTUNNEL_STARTED_FILE"
printf '{"status":"connected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
while :; do sleep 1; done
EOF

cat > "$bin/wait-agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
for _ in $(seq 1 50); do
  [ -f "$PAPERBOAT_TEST_AGENTUNNEL_STARTED_FILE" ] && break
  sleep 0.1
done
printf '{"status":"connected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
printf 'wait-agentunnel:%s\n' "${1:-}" >> "$PAPERBOAT_TEST_EVENT_LOG"
EOF

cat > "$bin/activity" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'activity:start\n' >> "$PAPERBOAT_TEST_EVENT_LOG"
while :; do sleep 1; done
EOF

chmod +x "$bin"/*

export PAPERBOAT_TEST_EVENT_LOG="$log"
export PAPERBOAT_TEST_PAPERCODE_STARTED_FILE="$tmp/papercode.started"
export PAPERBOAT_TEST_AGENTUNNEL_STARTED_FILE="$tmp/agentunnel.started"
export PAPERBOAT_RUNTIME_DIR="$tmp/runtime"
export PAPERBOAT_LOG_DIR="$tmp/logs"
export PAPERBOAT_WORKSPACE="$tmp/workspace"
export PAPERBOAT_READINESS_FILE="$tmp/runtime/readiness.json"
export PAPERBOAT_AGENTUNNEL_STATUS_FILE="$tmp/runtime/agentunnel-status.json"
export PAPERBOAT_PREPARE_WORKSPACE_COMMAND="$bin/prepare"
export PAPERBOAT_CONFIG_SYNC_COMMAND="$bin/config-sync"
export PAPERBOAT_PRESET_APPLY_COMMAND="$bin/presets"
export PAPERBOAT_PAPERCODE_COMMAND="$bin/papercode"
export PAPERBOAT_WAIT_HTTP_COMMAND="$bin/wait-http"
export PAPERBOAT_AGENTUNNEL_COMMAND="$bin/agentunnel"
export PAPERBOAT_WAIT_AGENTUNNEL_COMMAND="$bin/wait-agentunnel"
export PAPERBOAT_ACTIVITY_COMMAND="$bin/activity"
export PAPERBOAT_PROJECT_ID="prj_smoke"
export PAPERBOAT_REPOSITORY_URL="https://github.com/example/repo.git"
export PAPERBOAT_AGENTUNNEL_SERVER_URL="https://agentunnel.example"
export PAPERBOAT_AGENTUNNEL_CLIENT_ID="cli_smoke"
export PAPERBOAT_AGENTUNNEL_TUNNEL_ID="tun_smoke"
export AGENTUNNEL_MACHINE_TOKEN="token_smoke"

"$root/bin/paperboat-entrypoint" >/tmp/paperboat-entrypoint-smoke.out 2>/tmp/paperboat-entrypoint-smoke.err &
entrypoint_pid=$!

for _ in $(seq 1 50); do
  if [ -f "$PAPERBOAT_READINESS_FILE" ] && grep -q '"state":"ready"' "$PAPERBOAT_READINESS_FILE"; then
    break
  fi
  sleep 0.1
done

grep -q '"state":"ready"' "$PAPERBOAT_READINESS_FILE"

for _ in $(seq 1 50); do
  if [ -f "$log" ] && [ "$(wc -l < "$log")" -ge 8 ]; then
    break
  fi
  sleep 0.1
done

expected='prepare
config-sync:restore
presets
papercode:start
wait-http:http://127.0.0.1:4099
agentunnel:start
wait-agentunnel:60
activity:start'

actual="$(sed -n '1,8p' "$log")"
if [ "$actual" != "$expected" ]; then
  printf 'unexpected boot order\nexpected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
  exit 1
fi
