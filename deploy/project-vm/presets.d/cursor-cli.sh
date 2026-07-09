#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="$HOME/.local/bin:$PATH"
command -v cursor-agent >/dev/null 2>&1 && exit 0
curl -fsS https://cursor.com/install | bash
