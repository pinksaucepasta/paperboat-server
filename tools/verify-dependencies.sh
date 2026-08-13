#!/bin/sh
set -eu

require_module() {
  path=$1
  version=$2
  actual=$(GOTOOLCHAIN=local go list -m -f '{{.Version}}' "$path")
  [ "$actual" = "$version" ] || {
    echo "dependency mismatch: $path is $actual, want $version" >&2
    exit 1
  }
}

require_module golang.org/x/crypto v0.54.0
require_module github.com/realclientip/realclientip-go v1.0.0

forbidden='github.com/lib/pq'

if GOTOOLCHAIN=local go mod graph | awk -v forbidden="$forbidden" '$1 == forbidden || $2 == forbidden { found = 1 } END { exit !found }'; then
  echo "forbidden module dependency: $forbidden" >&2
  exit 1
fi

if GOTOOLCHAIN=local go list -deps -test ./... | awk -v forbidden="$forbidden" '$0 == forbidden { found = 1 } END { exit !found }'; then
  echo "forbidden compiled dependency: $forbidden" >&2
  exit 1
fi

for forbidden in github.com/bradleyfalzon/ghinstallation/v2 github.com/golang-jwt/jwt/v4; do
  if GOTOOLCHAIN=local go list -deps -test ./... | awk -v forbidden="$forbidden" '$0 == forbidden { found = 1 } END { exit !found }'; then
    echo "forbidden compiled dependency: $forbidden" >&2
    exit 1
  fi
done

echo "server dependencies: valid"
