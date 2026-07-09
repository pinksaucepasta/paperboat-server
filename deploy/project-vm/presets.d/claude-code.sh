#!/usr/bin/env bash
set -Eeuo pipefail
command -v claude >/dev/null 2>&1 && exit 0
npm install -g @anthropic-ai/claude-code
