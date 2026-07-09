#!/usr/bin/env bash
set -Eeuo pipefail
command -v opencode >/dev/null 2>&1 && exit 0
npm install -g opencode-ai
