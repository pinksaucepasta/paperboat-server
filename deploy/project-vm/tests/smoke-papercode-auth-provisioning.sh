#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/home"
cat > "$tmp/bin/node" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$tmp/bin/node"

export PATH="$tmp/bin:$PATH"
export PAPERBOAT_PAPERCODE_BASE_DIR="$tmp/home"
export PAPERBOAT_PAPERCODE_ENVIRONMENT_ID="prj_stable"
export PAPERBOAT_PAPERCODE_OWNER_ID="usr_owner"
export PAPERBOAT_PAPERCODE_ISSUER="https://api.paperboat.example"
export PAPERBOAT_WORKSPACE="$tmp/workspace"

"$root/bin/paperboat-start-papercode"

test "$(tr -d '\n' < "$tmp/home/userdata/environment-id")" = "prj_stable"
test "$(tr -d '\n' < "$tmp/home/userdata/secrets/cloud-linked-user-id.bin")" = "usr_owner"
test "$(tr -d '\n' < "$tmp/home/userdata/secrets/cloud-relay-issuer.bin")" = "https://api.paperboat.example"
test "$(stat -f '%Lp' "$tmp/home/userdata/secrets/cloud-linked-user-id.bin" 2>/dev/null || stat -c '%a' "$tmp/home/userdata/secrets/cloud-linked-user-id.bin")" = "600"
