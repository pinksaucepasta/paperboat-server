#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd "$script_dir/../../.." && pwd)"
image_ref="${1:-${PAPERBOAT_PROJECT_VM_IMAGE_REF:-paperboat/project-vm:dev}}"
platform="${PAPERBOAT_PROJECT_VM_PLATFORM:-linux/amd64}"
node_base_image="${PAPERBOAT_NODE_BASE_IMAGE:-}"
go_base_image="${PAPERBOAT_GO_BASE_IMAGE:-}"

is_digest_image() {
  [[ "$1" =~ @sha256:[0-9a-fA-F]{64}$ ]]
}

if ! is_digest_image "$node_base_image" || ! is_digest_image "$go_base_image"; then
  printf 'PAPERBOAT_NODE_BASE_IMAGE and PAPERBOAT_GO_BASE_IMAGE must be immutable name@sha256:<digest> references\n' >&2
  printf 'tag-only base images are not reproducible and are rejected\n' >&2
  exit 64
fi

source_revision() {
  local repo="$1"
  local revision
  revision="$(git -C "$repo" rev-parse --verify HEAD)"
  if [ "${PAPERBOAT_ALLOW_DIRTY_SOURCES:-false}" != "true" ] && [ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]; then
    printf 'project VM source tree is dirty: %s\n' "$repo" >&2
    printf 'commit the pinned source or set PAPERBOAT_ALLOW_DIRTY_SOURCES=true for a local-only build\n' >&2
    exit 65
  fi
  printf '%s' "$revision"
}

papercode_revision="$(source_revision "$workspace_root/papercode")"
agentunnel_revision="$(source_revision "$workspace_root/agentunnel")"
server_revision="$(source_revision "$workspace_root/paperboat-server")"

docker build \
  -f "$script_dir/Dockerfile" \
  --platform "$platform" \
  --build-arg "PAPERCODE_REVISION=$papercode_revision" \
  --build-arg "NODE_BASE_IMAGE=$node_base_image" \
  --build-arg "GO_BASE_IMAGE=$go_base_image" \
  --build-arg "AGENTUNNEL_REVISION=$agentunnel_revision" \
  --build-arg "PAPERBOAT_SERVER_REVISION=$server_revision" \
  -t "$image_ref" \
  "$workspace_root"
