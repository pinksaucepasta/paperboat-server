# paperboat-server developer tasks.
#
# The server reads configuration from real environment variables (it has no
# dotenv loader), so these targets source .env.local before running Go. Each
# make recipe runs in its own shell, so the source + command must stay on one
# logical line.

CONFIG ?= config/local.example.json
ENV_FILE ?= .env.local

# Load ENV_FILE (if present) into the environment, exporting every key.
load-env = set -a; [ -f $(ENV_FILE) ] && . ./$(ENV_FILE); set +a

.PHONY: run migrate seed-catalogs test vet fmt

## run: start the server with .env.local loaded (real providers)
run:
	$(load-env); go run ./cmd/paperboat-server serve -config $(CONFIG)

## migrate: apply database migrations with .env.local loaded
migrate:
	$(load-env); go run ./cmd/paperboat-server migrate -config $(CONFIG)

## seed-catalogs: seed dynamic catalogs with .env.local loaded
seed-catalogs:
	$(load-env); go run ./cmd/paperboat-server seed-catalogs -config $(CONFIG)

## test: run the test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format the codebase
fmt:
	gofmt -w .
