#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for file in "$root"/bin/paperboat-*; do
  test -x "$file"
  bash -n "$file"
done
for file in "$root"/presets.d/*.sh; do
  test -x "$file"
  bash -n "$file"
done
test -x "$root/build-image.sh"
bash -n "$root/build-image.sh"

grep -q 'paperboat-entrypoint' "$root/Dockerfile"
grep -q 'paperboat-healthcheck' "$root/Dockerfile"
grep -q 'paperboat-server/deploy/project-vm/bin/' "$root/Dockerfile"
grep -q 'AGENTUNNEL_MACHINE_TOKEN' "$root/bin/paperboat-entrypoint"
grep -q 'PAPERBOAT_AGENTUNNEL_TOKEN_ENV' "$root/bin/paperboat-start-agentunnel"
grep -q 'GIT_ASKPASS' "$root/bin/paperboat-entrypoint"
grep -q 'PAPERBOAT_GITHUB_CONFIG_TOKEN' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_GITHUB_TOKEN_ENV' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_GITHUB_TOKEN_ALLOWED_HOSTS' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_AGENTUNNEL_TUNNEL_ID' "$root/bin/paperboat-entrypoint"
grep -q 'T3CODE_HOME' "$root/bin/paperboat-start-papercode"
grep -q -- '--no-browser' "$root/bin/paperboat-start-papercode"
grep -q 'PAPERBOAT_AGENTUNNEL_FORWARD_COMMAND' "$root/bin/paperboat-start-agentunnel"
grep -q 'PAPERBOAT_WAIT_AGENTUNNEL_COMMAND' "$root/bin/paperboat-entrypoint"
grep -q 'child_pids' "$root/bin/paperboat-entrypoint"
grep -q 'PAPERBOAT_CONFIG_GIT_AUTHOR_EMAIL' "$root/bin/paperboat-config-sync"
grep -q 'PAPERBOAT_SETUP_SCRIPT' "$root/bin/paperboat-apply-presets"
grep -q 'PAPERBOAT_SETUP_SCRIPT_ENV' "$root/bin/paperboat-apply-presets"

"$root/tests/smoke-entrypoint.sh"
"$root/tests/smoke-agentunnel-readiness-failure.sh"
"$root/tests/smoke-cleanup-partial-start.sh"
"$root/tests/smoke-config-sync-save.sh"
"$root/tests/smoke-setup-script-env.sh"
"$root/tests/smoke-git-askpass-host-scope.sh"
"$root/tests/smoke-agentunnel-token-env.sh"

server_root="$(cd "$root/../.." && pwd)"
grep -q 'BootCommand:.*paperboat-entrypoint' "$server_root/internal/config/config.go"
grep -q 'paperboat-server/deploy/project-vm/presets.d/' "$root/Dockerfile"
