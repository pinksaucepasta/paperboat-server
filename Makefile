# paperboat-server developer tasks.
#
# The server reads configuration from real environment variables (it has no
# dotenv loader), so these targets source .env.local before running Go. Each
# make recipe runs in its own shell, so the source + command must stay on one
# logical line.

CONFIG ?=
ENV_FILE ?= .env.local
GO_VERSION := 1.25.7
SQLC_VERSION := v1.30.0
GO := GOTOOLCHAIN=local go
GOFMT := $(shell GOTOOLCHAIN=local go env GOROOT 2>/dev/null)/bin/gofmt
GO_FILES := $(shell find . -path ./.git -prune -o -name '*.go' -print)

# Load ENV_FILE (if present) into the environment, exporting every key.
load-env = set -a; [ -f $(ENV_FILE) ] && . ./$(ENV_FILE); set +a
config-arg = $(if $(strip $(CONFIG)),-config $(CONFIG),)

.PHONY: build check clean contracts fmt fmt-check generate generate-check migrate race run seed-catalogs test tidy verify-toolchain vet

contracts:
	@./testdata/contracts/validate.sh

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

check: verify-toolchain contracts fmt-check generate-check vet test build

## test: run the test suite
test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

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
