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
grep -q 'agentunnel-status.json' "$root/bin/paperboat-healthcheck"
grep -q 'paperboat-server/deploy/project-vm/bin/' "$root/Dockerfile"
test "$(grep -c 'COPY legacy/papercode/patches ./patches' "$root/Dockerfile")" -eq 1
grep -q 'io.paperboat.source.papercode.revision' "$root/Dockerfile"
grep -q 'PAPERCODE_REVISION' "$root/build-image.sh"
grep -q 'PAPERBOAT_NODE_BASE_IMAGE' "$root/build-image.sh"
grep -q 'PAPERBOAT_GO_BASE_IMAGE' "$root/build-image.sh"
grep -q 'NODE_BASE_IMAGE' "$root/Dockerfile"
grep -q 'GO_BASE_IMAGE' "$root/Dockerfile"
grep -q 'npm --version' "$root/Dockerfile"
if grep -q 'PAPERBOAT_PAPERCODE_MODE\|papercode-disabled\|PAPERCODE=disabled' "$root/Dockerfile" "$root/build-image.sh" "$root/bin/paperboat-entrypoint"; then
  printf 'papercode must not be optional in the production project image\n' >&2
  exit 1
fi
grep -q 'AGENTUNNEL_MACHINE_TOKEN' "$root/bin/paperboat-entrypoint"
grep -q 'PAPERBOAT_AGENTUNNEL_TOKEN_ENV' "$root/bin/paperboat-start-agentunnel"
grep -q 'PAPERBOAT_PAPERCODE_ENVIRONMENT_ID' "$root/bin/paperboat-start-papercode"
grep -q 'cloud-linked-user-id.bin' "$root/bin/paperboat-start-papercode"
grep -q 'cloud-relay-issuer.bin' "$root/bin/paperboat-start-papercode"
grep -q 'GIT_ASKPASS' "$root/bin/paperboat-entrypoint"
grep -q 'PAPERBOAT_GITHUB_CONFIG_TOKEN' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_GITHUB_TOKEN_ENV' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_GITHUB_TOKEN_ALLOWED_HOSTS' "$root/bin/paperboat-git-askpass"
grep -q 'PAPERBOAT_AGENTUNNEL_TUNNEL_ID' "$root/bin/paperboat-entrypoint"
grep -q 'T3CODE_HOME' "$root/bin/paperboat-start-papercode"
grep -q -- '--no-browser' "$root/bin/paperboat-start-papercode"
grep -q 'PAPERBOAT_AGENTUNNEL_FORWARD_COMMAND' "$root/bin/paperboat-start-agentunnel"
grep -q 'PAPERBOAT_WAIT_AGENTUNNEL_COMMAND' "$root/bin/paperboat-entrypoint"
grep -q 'agentunnel-status.json' "$root/bin/paperboat-wait-agentunnel"
grep -q 'child_pids' "$root/bin/paperboat-entrypoint"
grep -q '/out/paperboat-config-sync' "$root/Dockerfile"
grep -q './cmd/paperboat-config-sync' "$root/Dockerfile"
grep -q 'CHEZMOI_VERSION=2.71.0' "$root/Dockerfile"
grep -q '2a051bb2\|6ea2040e' "$root/Dockerfile"
grep -q 'd8fb35f9' "$root/Dockerfile"
grep -q 'config-age-identity.txt' "$root/bin/paperboat-entrypoint"
if grep -q 'PAPERBOAT_CLASSIFIER_API_KEY' "$root/Dockerfile" "$root/bin/"paperboat-*; then
  printf 'classifier provider credentials must not be present in the VM image\n' >&2
  exit 1
fi
grep -q 'PAPERBOAT_SETUP_SCRIPT' "$root/bin/paperboat-apply-presets"
grep -q 'PAPERBOAT_SETUP_SCRIPT_ENV' "$root/bin/paperboat-apply-presets"

"$root/tests/smoke-entrypoint.sh"
"$root/tests/smoke-agentunnel-readiness-failure.sh"
"$root/tests/smoke-cleanup-partial-start.sh"
"$root/tests/smoke-config-sync-save.sh"
"$root/tests/smoke-config-sync-flush-fallback.sh"
"$root/tests/smoke-config-restore-failure.sh"
"$root/tests/smoke-preset-failure-config-flush.sh"
"$root/tests/smoke-setup-script-env.sh"
"$root/tests/smoke-git-askpass-host-scope.sh"
"$root/tests/smoke-agentunnel-token-env.sh"
"$root/tests/smoke-papercode-loopback.sh"
"$root/tests/smoke-workspace-identity.sh"
"$root/tests/smoke-healthcheck-route-state.sh"

server_root="$(cd "$root/../.." && pwd)"
grep -q 'BootCommand:.*paperboat-entrypoint' "$server_root/internal/config/config.go"
grep -q 'paperboat-server/deploy/project-vm/presets.d/' "$root/Dockerfile"
