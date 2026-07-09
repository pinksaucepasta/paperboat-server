#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="$HOME/.local/bin:$PATH"
command -v aider >/dev/null 2>&1 && exit 0
curl -LsSf https://aider.chat/install.sh | sh
