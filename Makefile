# paperboat-server developer tasks.
#
# The server reads configuration from real environment variables (it has no
# dotenv loader), so these targets source .env.local before running Go. Each
# make recipe runs in its own shell, so the source + command must stay on one
# logical line.

CONFIG ?=
ENV_FILE ?= .env.local
GO_VERSION := 1.26.6
SQLC_VERSION := v1.30.0
GO_ROOT := $(shell GOTOOLCHAIN=go$(GO_VERSION) go env GOROOT)
export PATH := $(GO_ROOT)/bin:$(PATH)
GO := GOTOOLCHAIN=local go
GOFMT := $(GO_ROOT)/bin/gofmt
GO_FILES := $(shell find . -path ./.git -prune -o -name '*.go' -print)
TOPOLOGY_TERMINAL_CASE ?= TestPeerTerminalPingUsesProductionWSSConnector

# Load ENV_FILE (if present) into the environment, exporting every key.
load-env = set -a; [ -f $(ENV_FILE) ] && . ./$(ENV_FILE); set +a
config-arg = $(if $(strip $(CONFIG)),-config $(CONFIG),)

.PHONY: binary-size-check build check clean control-storm dependencies fmt fmt-check generate generate-check license-check metrics-check metrics-generate migrate race reproducible-builds run scenario-matrix-check scenario-matrix-generate seed-catalogs source-policy static-analysis test tidy topology-matrix topology-direct-smoke topology-fault-smoke topology-host-service-smoke topology-preview-direct-smoke topology-preview-relay-smoke topology-preview-wss-smoke topology-regional-selection-smoke topology-relay-smoke topology-reverse-file-direct-smoke topology-reverse-file-h2-smoke topology-selection-smoke topology-smoke topology-ssh-direct-smoke topology-ssh-relay-smoke topology-ssh-wss-smoke topology-stun-smoke topology-terminal-cancel-direct-smoke topology-terminal-cancel-relay-smoke topology-terminal-cancel-smoke topology-terminal-direct-smoke topology-terminal-ping-smoke topology-terminal-relay-smoke topology-terminal-workflow-smoke topology-wss-smoke verification verify-toolchain vet vulnerability-check

dependencies:
	@./tools/verify-dependencies.sh

source-policy:
	@./tools/verify-source-policy.sh

metrics-generate:
	$(GO) run ./tools/metric-schema -write docs/metrics.json

metrics-check:
	$(GO) run ./tools/metric-schema docs/metrics.json

verify-toolchain:
	@test "$$(GOTOOLCHAIN=local go env GOVERSION)" = "go$(GO_VERSION)" || { echo "required Go $(GO_VERSION), found $$(GOTOOLCHAIN=local go env GOVERSION)" >&2; exit 1; }

build:
	$(GO) build ./...

## run: start the server with .env.local loaded (real providers)
run:
	$(load-env); $(GO) run ./cmd/paperboat-server serve $(config-arg)

## migrate: apply database migrations with .env.local loaded
migrate:
	$(load-env); $(GO) run ./cmd/paperboat-server migrate $(config-arg)

## seed-catalogs: seed dynamic catalogs with .env.local loaded
seed-catalogs:
	$(load-env); $(GO) run ./cmd/paperboat-server seed-catalogs $(config-arg)

## generate: regenerate type-safe database access
generate:
	$(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

generate-check:
	@before="$$(git diff -- internal/db/dbsqlc)"; $(MAKE) generate >/dev/null; test "$$(git diff -- internal/db/dbsqlc)" = "$$before" || { echo "generated sqlc output is stale; run make generate" >&2; git diff -- internal/db/dbsqlc; exit 1; }

check: verify-toolchain dependencies source-policy metrics-check scenario-matrix-check fmt-check generate-check vet test build

scenario-matrix-generate:
	$(GO) run ./tools/scenario-matrix testdata/topology/scenarios.json internal/testtopology/topology_test.go .github/generated/topology-matrix.json

scenario-matrix-check:
	$(GO) run ./tools/scenario-matrix -check testdata/topology/scenarios.json internal/testtopology/topology_test.go .github/generated/topology-matrix.json

## test: run the test suite
test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

reproducible-builds: verify-toolchain
	@./tools/verify-reproducible-builds.sh

binary-size-check: verify-toolchain
	@./tools/verify-binary-sizes.sh

static-analysis: verify-toolchain source-policy
	@./tools/verify-static-analysis.sh

vulnerability-check: verify-toolchain
	@./tools/verify-vulnerabilities.sh

license-check: verify-toolchain
	@./tools/verify-licenses.sh

control-storm:
	@./tools/run-control-storm.sh

topology-matrix:
	@tools/topology-matrix.sh

topology-smoke:
	PAPERBOAT_TOPOLOGY_TEST=1 $(GO) test ./internal/testtopology -run '^TestConcurrentScopesOwnAndCleanOnlyTheirResources$$' -count=1 -v

topology-fault-smoke:
	PAPERBOAT_TOPOLOGY_TEST=1 $(GO) test ./internal/testtopology -run '^TestNetworkFaultInjectionAffectsOwnedUDPAndRecovers$$' -count=1 -v

topology-stun-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; \
		cd ../paperboat-tunnel && CGO_ENABLED=0 GOOS=linux GOARCH="$$(GOTOOLCHAIN=local go env GOARCH)" $(GO) test -c -o "$$tmp/paperboat-stun.test" ./internal/stunserver; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_STUN_BINARY="$$tmp/paperboat-stun.test" $(GO) test ./internal/testtopology -run '^TestOwnedTunnelSTUNAcrossIsolatedContainers$$' -count=1 -v

topology-direct-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd ../paperboat-tunnel && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-edge.test" ./internal/stunserver; \
		cd ../paperboat && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_STUN_BINARY="$$tmp/paperboat-edge.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" $(GO) test -tags=topology ./internal/testtopology -run '^TestAuthenticatedICEAndDirectQUICBypassTunnel$$' -count=1 -v

topology-relay-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd ../paperboat-tunnel/caddymodules/paperboatquic && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-relay.test" .; \
		cd ../../../paperboat && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_RELAY_BINARY="$$tmp/paperboat-relay.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" $(GO) test ./internal/testtopology -run '^TestAuthenticatedNoiseRelayQUICAcrossEdge$$' -count=1 -v

topology-wss-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd ../paperboat-tunnel/caddymodules/paperboatquic && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-relay.test" .; \
		cd ../../../paperboat && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_RELAY_BINARY="$$tmp/paperboat-relay.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" $(GO) test ./internal/testtopology -run '^TestAuthenticatedNoiseWSSAcrossEdge$$' -count=1 -v

topology-selection-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd ../paperboat-tunnel/caddymodules/paperboatquic && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-relay.test" .; \
		cd ../../../paperboat && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_RELAY_BINARY="$$tmp/paperboat-relay.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" $(GO) test ./internal/testtopology -run '^TestAutoSelectsAuthenticatedNoise(RelayQUIC|WSSWhenUDPBlocked)$$' -count=1 -v

topology-regional-selection-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-regional-authority.test" ./internal/peersessions; \
		PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_REGIONAL_AUTHORITY_BINARY="$$tmp/paperboat-regional-authority.test" $(GO) test ./internal/testtopology -run '^TestRegionalRelaySelectionAuthorityAcrossPostgres$$' -count=1 -v

topology-host-service-smoke:
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd ../paperboat-tunnel/caddymodules/paperboatquic && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-relay.test" .; \
		cd ../../../paperboat && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-host.test" ./internal/hostruntime/peerrelay; \
		cd ../paperboat-server && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_RELAY_BINARY="$$tmp/paperboat-relay.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" PAPERBOAT_TOPOLOGY_HOST_BINARY="$$tmp/paperboat-host.test" $(GO) test ./internal/testtopology -run '^TestHostPeerRelayServiceLifecycleAcrossWSS$$' -count=1 -v

topology-terminal-ping-smoke:
	@set -eu; tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT INT TERM; arch="$$(GOTOOLCHAIN=local go env GOARCH)"; \
		cd "$(CURDIR)/../paperboat-tunnel/caddymodules/paperboatquic" && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-relay.test" .; \
		cd "$(CURDIR)/../paperboat" && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-endpoint.test" ./internal/testtopology/peerendpoint; \
		cd "$(CURDIR)/../paperboat" && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-host.test" ./internal/hostruntime/peerrelay; \
		cd "$(CURDIR)/../paperboat" && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-terminal.test" ./internal/tunnel; \
		cd "$(CURDIR)" && CGO_ENABLED=0 GOOS=linux GOARCH="$$arch" $(GO) test -c -o "$$tmp/paperboat-authority.test" ./internal/httpapi; \
		cd "$(CURDIR)" && PAPERBOAT_TOPOLOGY_TEST=1 PAPERBOAT_TOPOLOGY_RELAY_BINARY="$$tmp/paperboat-relay.test" PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY="$$tmp/paperboat-endpoint.test" PAPERBOAT_TOPOLOGY_HOST_BINARY="$$tmp/paperboat-host.test" PAPERBOAT_TOPOLOGY_TERMINAL_BINARY="$$tmp/paperboat-terminal.test" PAPERBOAT_TOPOLOGY_AUTHORITY_BINARY="$$tmp/paperboat-authority.test" $(GO) test ./internal/testtopology -run '^$(TOPOLOGY_TERMINAL_CASE)$$' -count=1 -v

topology-terminal-workflow-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalWorkflowUsesProductionWSSConnector

topology-terminal-cancel-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalCancellationUsesProductionWSSConnector

topology-terminal-cancel-relay-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalCancellationUsesProductionRelayQUICConnector

topology-terminal-cancel-direct-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalCancellationUsesProductionDirectQUICConnector

topology-terminal-relay-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalWorkflowUsesProductionRelayQUICConnector

topology-terminal-direct-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerTerminalWorkflowUsesProductionDirectQUICConnector

topology-ssh-wss-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerSSHUsesProductionWSSConnector

topology-ssh-relay-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerSSHUsesProductionRelayQUICConnector

topology-ssh-direct-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerSSHUsesProductionDirectQUICConnector

topology-reverse-file-direct-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerReverseFileTransferPromotesToProductionDirectQUIC

topology-reverse-file-h2-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerReverseFileTransferFallsBackToProductionRelayHTTP2

topology-preview-wss-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerPrivatePreviewUsesProductionWSSConnector

topology-preview-relay-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerPrivatePreviewUsesProductionRelayQUICConnector

topology-preview-direct-smoke:
	@$(MAKE) topology-terminal-ping-smoke TOPOLOGY_TERMINAL_CASE=TestPeerPrivatePreviewUsesProductionDirectQUICConnector

verification: check race static-analysis vulnerability-check license-check control-storm

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: format the codebase
fmt:
	$(GOFMT) -w $(GO_FILES)

fmt-check:
	@test -z "$$($(GOFMT) -l $(GO_FILES))" || { $(GOFMT) -l $(GO_FILES); echo "Go files are not formatted" >&2; exit 1; }

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin dist coverage.out
