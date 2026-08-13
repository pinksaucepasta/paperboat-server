#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-server-license.XXXXXX")

cleanup() {
	status=$?
	if ! cmp -s "$root/go.mod" "$snapshot/go.mod" || ! cmp -s "$root/go.sum" "$snapshot/go.sum"; then
		echo "license analysis changed go.mod or go.sum" >&2
		status=1
	fi
	rm -rf "$snapshot"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$root/go.mod" "$snapshot/go.mod"
cp "$root/go.sum" "$snapshot/go.sum"

cd "$root"
GOTOOLCHAIN=local go run github.com/google/go-licenses@v1.6.0 check \
	--disallowed_types=forbidden,restricted,unknown \
	./cmd/paperboat-server
