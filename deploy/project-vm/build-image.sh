#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd "$script_dir/../../.." && pwd)"
image_ref="${1:-${PAPERBOAT_PROJECT_VM_IMAGE_REF:-paperboat/project-vm:dev}}"

docker build \
  -f "$script_dir/Dockerfile" \
  -t "$image_ref" \
  "$workspace_root"
