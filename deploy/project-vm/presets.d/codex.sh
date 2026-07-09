#!/usr/bin/env bash
set -Eeuo pipefail
command -v codex >/dev/null 2>&1 && exit 0
npm install -g @openai/codex
