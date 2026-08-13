#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-server-reproducible.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

build_set() {
  output_dir=$1
  mkdir -p "$output_dir"
  for target in linux/amd64 linux/arm64; do
    os=${target%/*}
    arch=${target#*/}
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
      go build -buildvcs=false -trimpath -ldflags '-s -w' \
      -o "$output_dir/paperboat-server-$os-$arch" ./cmd/paperboat-server
  done
}

cd "$root"
build_set "$work/first"
build_set "$work/second"

for first in "$work/first"/*; do
  name=${first##*/}
  cmp -s "$first" "$work/second/$name" || {
    echo "reproducible builds: $name differs between builds" >&2
    exit 1
  }
done

echo "reproducible builds: all supported server artifacts are identical"
