#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export PAPERBOAT_PRESET_CODES=""
export PAPERBOAT_SETUP_SCRIPT_ENV="PAPERBOAT_CUSTOM_SETUP_SCRIPT"
export PAPERBOAT_CUSTOM_SETUP_SCRIPT="printf custom > '$tmp/setup-ran'"

"$root/bin/paperboat-apply-presets"

grep -q custom "$tmp/setup-ran"
