#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server_root="$(cd "$root/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

remote="$tmp/remote.git"
seed="$tmp/seed"
home="$tmp/home"
runtime="$tmp/runtime"
workspace="$tmp/workspace"
binary="$tmp/paperboat-config-sync"

GOCACHE="${GOCACHE:-$tmp/go-cache}" go build -o "$binary" "$server_root/cmd/paperboat-config-sync"
git init --bare --initial-branch=main "$remote" >/dev/null
git init --initial-branch=main "$seed" >/dev/null
git -C "$seed" config user.name "Seed"
git -C "$seed" config user.email "seed@example.test"
mkdir -p "$seed/.config"
printf 'initial\n' > "$seed/.config/tool"
git -C "$seed" add -A
git -C "$seed" commit -m initial >/dev/null
git -C "$seed" remote add origin "$remote"
git -C "$seed" push origin main >/dev/null 2>&1

mkdir -p "$home" "$workspace" "$runtime"
export PAPERBOAT_CONFIG_HOME="$home"
export PAPERBOAT_RUNTIME_DIR="$runtime"
export PAPERBOAT_WORKSPACE="$workspace"
export PAPERBOAT_CONFIG_REPO_URL="$remote"
export PAPERBOAT_CONFIG_REPO_BRANCH=main
export PAPERBOAT_PROJECT_ID=prj_config_sync
export PAPERBOAT_CONFIG_GIT_AUTHOR_NAME="Paperboat Test Sync"
export PAPERBOAT_CONFIG_GIT_AUTHOR_EMAIL="paperboat-test@example.test"

"$binary" restore >/dev/null 2>&1
grep -q initial "$home/.config/tool"

other="$tmp/other"
git clone --branch main "$remote" "$other" >/dev/null 2>&1
git -C "$other" config user.name "Other VM"
git -C "$other" config user.email "other@example.test"
mkdir -p "$other/.codex"
printf 'other\n' > "$other/.codex/config.toml"
git -C "$other" add -A
git -C "$other" commit -m "other vm sync" >/dev/null
git -C "$other" push origin main >/dev/null 2>&1

printf 'changed\n' > "$home/.config/tool"
"$binary" save >/dev/null 2>&1

author="$(git --git-dir="$remote" log -1 --format='%an <%ae>' main)"
if [ "$author" != "Paperboat Test Sync <paperboat-test@example.test>" ]; then
  printf 'unexpected author: %s\n' "$author" >&2
  exit 1
fi
git clone --branch main "$remote" "$tmp/final" >/dev/null 2>&1
grep -q changed "$tmp/final/.config/tool"
grep -q other "$tmp/final/.codex/config.toml"
