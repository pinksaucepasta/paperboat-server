#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd "$script_dir/../../.." && pwd)"
image_ref="${1:-${PAPERBOAT_PROJECT_VM_IMAGE_REF:-paperboat/project-vm:dev}}"
# PAPERCODE=disabled builds the runtime without the papercode server (used
# while the papercode repo is unavailable in the build context).
papercode="${PAPERCODE:-enabled}"
platform="${PAPERBOAT_PROJECT_VM_PLATFORM:-linux/amd64}"

docker build \
  -f "$script_dir/Dockerfile" \
  --platform "$platform" \
  --build-arg "PAPERCODE=$papercode" \
  -t "$image_ref" \
  "$workspace_root"
