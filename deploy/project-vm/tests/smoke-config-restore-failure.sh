#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/bin"
mkdir -p "$bin" "$tmp/workspace/.git" "$tmp/runtime" "$tmp/logs"

cat > "$bin/prepare" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$bin/config-sync" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = restore ]; then exit 42; fi
exit 0
EOF
cat > "$bin/presets" <<'EOF'
#!/usr/bin/env bash
printf 'presets-ran\n' > "$PAPERBOAT_TEST_PRESETS_MARKER"
EOF
chmod +x "$bin"/*

export PAPERBOAT_TEST_PRESETS_MARKER="$tmp/presets-ran"
export PAPERBOAT_RUNTIME_DIR="$tmp/runtime"
export PAPERBOAT_LOG_DIR="$tmp/logs"
export PAPERBOAT_WORKSPACE="$tmp/workspace"
export PAPERBOAT_READINESS_FILE="$tmp/runtime/readiness.json"
export PAPERBOAT_PREPARE_WORKSPACE_COMMAND="$bin/prepare"
export PAPERBOAT_CONFIG_SYNC_COMMAND="$bin/config-sync"
export PAPERBOAT_PRESET_APPLY_COMMAND="$bin/presets"
export PAPERBOAT_PROJECT_ID=prj_restore_failure
export PAPERBOAT_REPOSITORY_URL=https://github.com/example/repo.git
export PAPERBOAT_AGENTUNNEL_SERVER_URL=https://agentunnel.example
export PAPERBOAT_AGENTUNNEL_CLIENT_ID=cli_restore_failure
export PAPERBOAT_AGENTUNNEL_TUNNEL_ID=tun_restore_failure
export AGENTUNNEL_MACHINE_TOKEN=token_restore_failure

set +e
"$root/bin/paperboat-entrypoint" >"$tmp/stdout" 2>"$tmp/stderr"
status=$?
set -e
if [ "$status" -ne 42 ]; then
  printf 'entrypoint status = %s, want 42\n' "$status" >&2
  exit 1
fi
grep -q '"state":"failed"' "$PAPERBOAT_READINESS_FILE"
grep -q '"reason":"config_restore"' "$PAPERBOAT_READINESS_FILE"
test ! -e "$PAPERBOAT_TEST_PRESETS_MARKER"
