#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tunnel_root=$(CDPATH= cd -- "$root/../paperboat-tunnel" && pwd)
run_id="paperboat-control-storm-$(date -u +%Y%m%d%H%M%S)-$$"
network="$run_id-network"
postgres="$run_id-postgres"
go_cache="$run_id-go-cache"
mod_cache="$run_id-mod-cache"
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-control-storm.XXXXXX")
report=$report_dir/report.json
postgres_samples=$report_dir/postgres-resources.tsv
postgres_sampler_pid=
postgres_image="postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4"
go_image="golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b"

cleanup() {
	status=$?
	stop_postgres_sampler
	docker rm -f "$postgres" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
	docker volume rm "$go_cache" "$mod_cache" >/dev/null 2>&1 || true
	rm -rf "$report_dir"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

stop_postgres_sampler() {
	if test -n "$postgres_sampler_pid"; then
		kill "$postgres_sampler_pid" >/dev/null 2>&1 || true
		wait "$postgres_sampler_pid" >/dev/null 2>&1 || true
		postgres_sampler_pid=
	fi
}

summarize_postgres_resources() {
	awk -F '\t' '
		function bytes(value, number, unit) {
			gsub(/^ +| +$/, "", value)
			number = value + 0
			unit = value
			sub(/^[0-9.]+/, "", unit)
			if (unit == "kB") return number * 1000
			if (unit == "MB") return number * 1000 * 1000
			if (unit == "GB") return number * 1000 * 1000 * 1000
			if (unit == "KiB") return number * 1024
			if (unit == "MiB") return number * 1024 * 1024
			if (unit == "GiB") return number * 1024 * 1024 * 1024
			return number
		}
		{
			cpu = $1; sub(/%$/, "", cpu)
			split($2, memory, " "); memory_bytes = bytes(memory[1])
			pids = $3 + 0
			split($4, network, " "); network_rx = bytes(network[1]); network_tx = bytes(network[3])
			split($5, block, " "); block_read = bytes(block[1]); block_write = bytes(block[3])
			samples++
			if (cpu > max_cpu) max_cpu = cpu
			if (memory_bytes > max_memory) max_memory = memory_bytes
			if (pids > max_pids) max_pids = pids
			if (network_rx > max_network_rx) max_network_rx = network_rx
			if (network_tx > max_network_tx) max_network_tx = network_tx
			if (block_read > max_block_read) max_block_read = block_read
			if (block_write > max_block_write) max_block_write = block_write
		}
		END {
			printf "{\"samples\":%d,\"max_cpu_percent\":%.2f,\"max_memory_bytes\":%.0f,\"max_pids\":%d,\"max_network_rx_bytes\":%.0f,\"max_network_tx_bytes\":%.0f,\"max_block_read_bytes\":%.0f,\"max_block_write_bytes\":%.0f}\n", samples, max_cpu, max_memory, max_pids, max_network_rx, max_network_tx, max_block_read, max_block_write
			if (samples < 1 || max_cpu > 1600 || max_memory > 1073741824 || max_pids > 256) exit 1
		}
	' "$postgres_samples"
}

command -v docker >/dev/null 2>&1 || { echo "Docker is required for control-storm verification" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is unavailable" >&2; exit 1; }

docker network create --label "paperboat.test.run=$run_id" "$network" >/dev/null
docker volume create --label "paperboat.test.run=$run_id" "$go_cache" >/dev/null
docker volume create --label "paperboat.test.run=$run_id" "$mod_cache" >/dev/null
docker run -d --name "$postgres" --network "$network" \
	--label "paperboat.test.run=$run_id" \
	--tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=2g \
	-e POSTGRES_USER=paperboat -e POSTGRES_PASSWORD=paperboat-test-only \
	-e POSTGRES_DB=paperboat_test "$postgres_image" >/dev/null

attempt=0
until docker exec "$postgres" pg_isready -U paperboat -d paperboat_test >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if test "$attempt" -ge 60; then
		echo "PostgreSQL did not become ready" >&2
		docker logs --tail 100 "$postgres" >&2 || true
		exit 1
	fi
	sleep 1
done

docker stats --format '{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}\t{{.NetIO}}\t{{.BlockIO}}' "$postgres" >"$postgres_samples" &
postgres_sampler_pid=$!

docker run --rm --network "$network" --label "paperboat.test.run=$run_id" \
	-v "$root:/workspace:ro" -v "$tunnel_root:/paperboat-tunnel:ro" \
	-v "$go_cache:/root/.cache/go-build" -v "$mod_cache:/go/pkg/mod" \
	-v "$(dirname "$report"):/report" -w /workspace \
	-e GOTOOLCHAIN=local -e PAPERBOAT_CONTROL_STORM=1 \
	-e PAPERBOAT_CONTROL_STORM_TUNNEL_BINARY=/tmp/paperboat-tunnel-control.test \
	-e "PAPERBOAT_CONTROL_STORM_SCALES=${PAPERBOAT_CONTROL_STORM_SCALES:-1,10,100,300,1000}" \
	-e PAPERBOAT_CONTROL_STORM_REPORT=/report/$(basename "$report") \
	-e PAPERBOAT_TEST_DATABASE_DSN="postgres://paperboat:paperboat-test-only@$postgres:5432/paperboat_test?sslmode=disable" \
	"$go_image" sh -eu -c 'cd /paperboat-tunnel
go test -c ./internal/control -o /tmp/paperboat-tunnel-control.test
cd /workspace
go test ./internal/controlplane -run "^TestControlPlaneStorm$" -count=1 -v'

stop_postgres_sampler

test -s "$report" || { echo "control-storm report was not produced" >&2; exit 1; }
test -s "$postgres_samples" || { echo "PostgreSQL resource samples were not produced" >&2; exit 1; }
echo "control-storm report:"
sed -n '1p' "$report"
echo "PostgreSQL resource report:"
summarize_postgres_resources
