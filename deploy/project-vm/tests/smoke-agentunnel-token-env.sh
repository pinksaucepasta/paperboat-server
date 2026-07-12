#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

agentunnel="$tmp/agentunnel"
cat > "$agentunnel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
config=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      config="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
grep -q '"client_token": "custom-agentunnel-token"' "$config"
grep -q '"serve_http_tunnels"' "$config"
grep -q '"status_file"' "$config"
EOF
chmod +x "$agentunnel"

export PATH="$tmp:$PATH"
export PAPERBOAT_AGENTUNNEL_CONFIG_DIR="$tmp/config"
export PAPERBOAT_AGENTUNNEL_SERVER_URL="https://agentunnel.example"
export PAPERBOAT_AGENTUNNEL_CLIENT_ID="cli_custom"
export PAPERBOAT_AGENTUNNEL_TOKEN_ENV="PAPERBOAT_CUSTOM_AGENTUNNEL_TOKEN"
export PAPERBOAT_CUSTOM_AGENTUNNEL_TOKEN="custom-agentunnel-token"

"$root/bin/paperboat-start-agentunnel"
