#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
baseline=$root/tools/binary-size-baseline.tsv
output=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-server-binary-size.XXXXXX")
trap 'rm -rf "$output"' EXIT HUP INT TERM

tab=$(printf '\t')
while IFS="$tab" read -r platform architecture baseline_bytes; do
  case "$platform" in ''|'#'*) continue ;; esac
  case "$baseline_bytes" in ''|*[!0-9]*)
    echo "invalid binary size baseline for $platform/$architecture: $baseline_bytes" >&2
    exit 1
    ;;
  esac

  artifact=$output/paperboat-server-$platform-$architecture
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=$platform GOARCH=$architecture GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
      go build -buildvcs=false -trimpath -ldflags '-s -w' \
      -o "$artifact" ./cmd/paperboat-server
  )
  actual_bytes=$(wc -c < "$artifact" | tr -d ' ')
  growth_bytes=$((actual_bytes - baseline_bytes))
  if test "$growth_bytes" -gt 1048576 && \
    awk -v actual="$actual_bytes" -v baseline="$baseline_bytes" \
      'BEGIN { exit !((actual - baseline) * 100 > baseline * 5) }'; then
    echo "paperboat-server $platform/$architecture grew from $baseline_bytes to $actual_bytes bytes" >&2
    echo "growth exceeds both 1 MiB and 5%; update the reviewed baseline with attribution" >&2
    exit 1
  fi
  printf 'paperboat-server %s/%s: %s bytes\n' "$platform" "$architecture" "$actual_bytes"
done < "$baseline"
