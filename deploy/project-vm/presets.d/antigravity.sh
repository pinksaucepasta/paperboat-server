#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="$HOME/.local/bin:$PATH"
command -v agy >/dev/null 2>&1 && exit 0
curl -fsSL https://antigravity.google/cli/install.sh | bash
