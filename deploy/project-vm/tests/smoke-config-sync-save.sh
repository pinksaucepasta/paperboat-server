#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

remote="$tmp/remote.git"
seed="$tmp/seed"
workspace="$tmp/workspace"

git init --bare "$remote" >/dev/null
git clone "$remote" "$seed" >/dev/null 2>&1
git -C "$seed" config user.name "Seed"
git -C "$seed" config user.email "seed@example.test"
printf 'initial\n' > "$seed/config.txt"
git -C "$seed" add config.txt
git -C "$seed" commit -m initial >/dev/null
git -C "$seed" push origin HEAD:main >/dev/null 2>&1

export PAPERBOAT_WORKSPACE="$workspace"
export PAPERBOAT_CONFIG_REPO_URL="$remote"
export PAPERBOAT_CONFIG_REPO_BRANCH=main
export PAPERBOAT_PROJECT_ID=prj_config_sync
export PAPERBOAT_CONFIG_GIT_AUTHOR_NAME="Paperboat Test Sync"
export PAPERBOAT_CONFIG_GIT_AUTHOR_EMAIL="paperboat-test@example.test"

"$root/bin/paperboat-config-sync" restore >/dev/null 2>&1

other="$tmp/other"
git clone "$remote" "$other" >/dev/null 2>&1
git -C "$other" config user.name "Other VM"
git -C "$other" config user.email "other@example.test"
printf 'other\n' > "$other/other-vm.txt"
git -C "$other" add other-vm.txt
git -C "$other" commit -m "other vm sync" >/dev/null
git -C "$other" push origin HEAD:main >/dev/null 2>&1

printf 'changed\n' > "$workspace/.paperboat/config/config.txt"
"$root/bin/paperboat-config-sync" save >/dev/null 2>&1

author="$(git --git-dir="$remote" log -1 --format='%an <%ae>' main)"
if [ "$author" != "Paperboat Test Sync <paperboat-test@example.test>" ]; then
  printf 'unexpected author: %s\n' "$author" >&2
  exit 1
fi
git clone "$remote" "$tmp/final" >/dev/null 2>&1
grep -q 'changed' "$tmp/final/config.txt"
grep -q 'other' "$tmp/final/other-vm.txt"
