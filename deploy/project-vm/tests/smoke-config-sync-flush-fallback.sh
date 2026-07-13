#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
entrypoint_pid=""
trap 'kill "$entrypoint_pid" 2>/dev/null || true; wait "$entrypoint_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

bin="$tmp/bin"
events="$tmp/events.log"
mkdir -p "$bin" "$tmp/workspace/.git" "$tmp/runtime" "$tmp/logs"

cat > "$bin/prepare" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$bin/presets" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$bin/config-sync" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  restore) printf 'config:restore\n' >> "$PAPERBOAT_TEST_EVENT_LOG" ;;
  daemon)
    trap 'printf "config:flush-failed\n" >> "$PAPERBOAT_TEST_EVENT_LOG"; exit 1' TERM
    while :; do sleep 1; done
    ;;
  save) printf 'config:fallback-save\n' >> "$PAPERBOAT_TEST_EVENT_LOG" ;;
esac
EOF
cat > "$bin/papercode" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "papercode:stopped\n" >> "$PAPERBOAT_TEST_EVENT_LOG"; exit 0' TERM
while :; do sleep 1; done
EOF
cat > "$bin/wait-http" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$bin/agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "agentunnel:stopped\n" >> "$PAPERBOAT_TEST_EVENT_LOG"; exit 0' TERM
printf '{"status":"connected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
while :; do sleep 1; done
EOF
cat > "$bin/wait-agentunnel" <<'EOF'
#!/usr/bin/env bash
printf '{"status":"connected"}\n' > "$PAPERBOAT_AGENTUNNEL_STATUS_FILE"
EOF
cat > "$bin/activity" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "activity:final-heartbeat\nactivity:stopped\n" >> "$PAPERBOAT_TEST_EVENT_LOG"; exit 0' TERM
while :; do sleep 1; done
EOF
chmod +x "$bin"/*

export PAPERBOAT_TEST_EVENT_LOG="$events"
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
export PAPERBOAT_PROJECT_ID=prj_flush_fallback
export PAPERBOAT_REPOSITORY_URL=https://github.com/example/repo.git
export PAPERBOAT_AGENTUNNEL_SERVER_URL=https://agentunnel.example
export PAPERBOAT_AGENTUNNEL_CLIENT_ID=cli_flush_fallback
export PAPERBOAT_AGENTUNNEL_TUNNEL_ID=tun_flush_fallback
export AGENTUNNEL_MACHINE_TOKEN=token_flush_fallback

"$root/bin/paperboat-entrypoint" >"$tmp/stdout" 2>"$tmp/stderr" &
entrypoint_pid=$!
for _ in $(seq 1 80); do
  if grep -q '"state":"ready"' "$PAPERBOAT_READINESS_FILE" 2>/dev/null; then break; fi
  sleep 0.1
done
grep -q '"state":"ready"' "$PAPERBOAT_READINESS_FILE"
kill -TERM "$entrypoint_pid"
wait "$entrypoint_pid"
entrypoint_pid=""

grep -q 'config:flush-failed' "$events"
grep -q 'config:fallback-save' "$events"
child_stop_line="$(grep -n -m1 -E 'papercode:stopped|agentunnel:stopped' "$events" | cut -d: -f1)"
flush_line="$(grep -n -m1 'config:flush-failed' "$events" | cut -d: -f1)"
fallback_line="$(grep -n -m1 'config:fallback-save' "$events" | cut -d: -f1)"
final_heartbeat_line="$(grep -n -m1 'activity:final-heartbeat' "$events" | cut -d: -f1)"
activity_stop_line="$(grep -n -m1 'activity:stopped' "$events" | cut -d: -f1)"
if [ "$child_stop_line" -ge "$flush_line" ] || [ "$flush_line" -ge "$fallback_line" ] || [ "$fallback_line" -ge "$final_heartbeat_line" ] || [ "$final_heartbeat_line" -ge "$activity_stop_line" ]; then
  printf 'unexpected shutdown ordering:\n' >&2
  cat "$events" >&2
  exit 1
fi
