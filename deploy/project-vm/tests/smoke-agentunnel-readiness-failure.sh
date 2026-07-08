#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/workspace/.git" "$tmp/runtime" "$tmp/logs"

for name in prepare presets; do
  cat > "$bin/$name" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF
done

cat > "$bin/config-sync" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF

cat > "$bin/papercode" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
while :; do sleep 1; done
EOF

cat > "$bin/wait-http" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF

cat > "$bin/agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
while :; do sleep 1; done
EOF

cat > "$bin/wait-agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 42
EOF

cat > "$bin/activity" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
EOF

chmod +x "$bin"/*

export PAPERBOAT_RUNTIME_DIR="$tmp/runtime"
export PAPERBOAT_LOG_DIR="$tmp/logs"
export PAPERBOAT_WORKSPACE="$tmp/workspace"
export PAPERBOAT_READINESS_FILE="$tmp/runtime/readiness.json"
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

set +e
"$root/bin/paperboat-entrypoint" >/tmp/paperboat-entrypoint-failure-smoke.out 2>/tmp/paperboat-entrypoint-failure-smoke.err
status=$?
set -e

if [ "$status" -eq 0 ]; then
  printf 'entrypoint unexpectedly succeeded\n' >&2
  exit 1
fi
if [ -f "$PAPERBOAT_READINESS_FILE" ] && grep -q '"state":"ready"' "$PAPERBOAT_READINESS_FILE"; then
  printf 'entrypoint wrote ready despite agentunnel readiness failure\n' >&2
  exit 1
fi
