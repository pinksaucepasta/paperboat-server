#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat >"$tmp_dir/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >"$CURL_ARGS_FILE"
exit 1
EOF
chmod +x "$tmp_dir/curl"

export CURL_ARGS_FILE="$tmp_dir/curl-args"
if PATH="$tmp_dir:$PATH" "$repo_root/deploy/project-vm/bin/paperboat-wait-http" http://127.0.0.1:1 1 2>/dev/null; then
  echo "wait-http unexpectedly succeeded" >&2
  exit 1
fi

grep -Eq -- '--connect-timeout [1-2]' "$CURL_ARGS_FILE"
grep -Eq -- '--max-time [1-2]' "$CURL_ARGS_FILE"
