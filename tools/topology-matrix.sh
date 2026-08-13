#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
(
  cd "$root"
  GOTOOLCHAIN=local go run ./tools/scenario-matrix -check testdata/topology/scenarios.json internal/testtopology/topology_test.go .github/generated/topology-matrix.json
)
cache_root=${PAPERBOAT_TOPOLOGY_CACHE:-${TMPDIR:-/tmp}/paperboat-topology-cache}
mkdir -p "$cache_root"
arch=${GOARCH:-$(GOTOOLCHAIN=local go env GOARCH)}

fingerprint=$(
  {
    git -C "$root" rev-parse HEAD 2>/dev/null || true
    for f in "$root/go.mod" "$root/go.sum" "$root/../paperboat/go.mod" "$root/../paperboat/go.sum" "$root/../paperboat-tunnel/go.mod" "$root/../paperboat-tunnel/go.sum"; do
      test -f "$f" && sha256sum "$f"
    done
    find "$root" "$root/../paperboat" "$root/../paperboat-tunnel" \
      -path '*/.git' -prune -o -path '*/frp' -prune -o -type f -name '*.go' -print0 |
      sort -z | xargs -0 sha256sum
  } | sha256sum | cut -d' ' -f1
)
dir="$cache_root/$fingerprint-$arch"
manifest="$dir/manifest.sha256"
if test ! -f "$manifest"; then
  tmp="$cache_root/.build-$$"
  trap 'rm -rf "$tmp"' EXIT INT TERM
  mkdir -p "$tmp"
  build() {
    name=$1; module=$2; package=$3
    (cd "$module" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local go test -c -o "$tmp/$name" "$package")
  }
  build stun "$root/../paperboat-tunnel" ./internal/stunserver
  build relay "$root/../paperboat-tunnel/caddymodules/paperboatquic" .
  build endpoint "$root/../paperboat" ./internal/testtopology/peerendpoint
  build host "$root/../paperboat" ./internal/hostruntime/peerrelay
  build terminal "$root/../paperboat" ./internal/tunnel
  build authority "$root" ./internal/httpapi
  build regional "$root" ./internal/peersessions
  (cd "$tmp" && sha256sum stun relay endpoint host terminal authority regional > manifest.sha256)
  rm -rf "$dir"
  mv "$tmp" "$dir"
  trap - EXIT INT TERM
fi
cat "$manifest"
export PAPERBOAT_TOPOLOGY_TEST=1
export PAPERBOAT_TOPOLOGY_STUN_BINARY="$dir/stun"
export PAPERBOAT_TOPOLOGY_RELAY_BINARY="$dir/relay"
export PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$dir/endpoint"
export PAPERBOAT_TOPOLOGY_HOST_BINARY="$dir/host"
export PAPERBOAT_TOPOLOGY_TERMINAL_BINARY="$dir/terminal"
export PAPERBOAT_TOPOLOGY_AUTHORITY_BINARY="$dir/authority"
export PAPERBOAT_TOPOLOGY_REGIONAL_AUTHORITY_BINARY="$dir/regional"
log="$dir/last-run.log"
if go test -tags topology ./internal/testtopology -run '^Test' -count=1 -v >"$log" 2>&1; then
  printf 'pass\n' >"$dir/last-run.status"
  cat "$log"
  exit 0
fi
printf 'fail\n' >"$dir/last-run.status"
cat "$log"
exit 1
