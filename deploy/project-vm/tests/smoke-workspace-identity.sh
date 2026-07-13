#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_repo="$tmp/source"
workspace="$tmp/workspace"
git init -q "$source_repo"
git -C "$source_repo" config user.name Test
git -C "$source_repo" config user.email test@example.com
printf 'project\n' > "$source_repo/README.md"
git -C "$source_repo" add README.md
git -C "$source_repo" commit -qm initial

export PAPERBOAT_WORKSPACE="$workspace"
export PAPERBOAT_REPOSITORY_URL="$source_repo"
export PAPERBOAT_PROJECT_ID="prj_stable"
export PAPERBOAT_PAPERCODE_ENVIRONMENT_ID="env_stable"

"$root/bin/paperboat-prepare-workspace"
"$root/bin/paperboat-prepare-workspace"

test "$(tr -d '\r\n' < "$workspace/.paperboat/identity/project-id")" = "prj_stable"
test "$(tr -d '\r\n' < "$workspace/.paperboat/identity/environment-id")" = "env_stable"
if stat --version >/dev/null 2>&1; then
  project_id_mode="$(stat -c '%a' "$workspace/.paperboat/identity/project-id")"
else
  project_id_mode="$(stat -f '%Lp' "$workspace/.paperboat/identity/project-id")"
fi
test "$project_id_mode" = "600"

set +e
PAPERBOAT_PROJECT_ID="prj_wrong" "$root/bin/paperboat-prepare-workspace" >"$tmp/mismatch.out" 2>"$tmp/mismatch.err"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  printf 'workspace identity mismatch unexpectedly succeeded\n' >&2
  exit 1
fi
grep -q 'workspace project identity mismatch' "$tmp/mismatch.err"

for unsafe in . .. .paperboat nested/path; do
  set +e
  PAPERBOAT_PROJECT_DIR="$unsafe" PAPERBOAT_WORKSPACE="$tmp/unsafe-$status" \
    "$root/bin/paperboat-prepare-workspace" >"$tmp/unsafe.out" 2>"$tmp/unsafe.err"
  unsafe_status=$?
  set -e
  if [ "$unsafe_status" -eq 0 ]; then
    printf 'unsafe project directory unexpectedly succeeded: %s\n' "$unsafe" >&2
    exit 1
  fi
done
