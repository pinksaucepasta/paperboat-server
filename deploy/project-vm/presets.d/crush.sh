#!/usr/bin/env bash
set -Eeuo pipefail
command -v crush >/dev/null 2>&1 && exit 0
npm install -g @charmland/crush
