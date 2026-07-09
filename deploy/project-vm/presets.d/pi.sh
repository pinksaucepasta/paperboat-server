#!/usr/bin/env bash
set -Eeuo pipefail
command -v pi >/dev/null 2>&1 && exit 0
npm install -g @mariozechner/pi-coding-agent
