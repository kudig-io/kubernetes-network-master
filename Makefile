# knm-cli Makefile
BINARY    := knm
BIN_DIR   := bin
MODULE    := github.com/kudig-io/knm-cli
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -X $(MODULE)/internal/version.Version=$(VERSION) \
             -X $(MODULE)/internal/version.Commit=$(COMMIT)  \
             -X $(MODULE)/internal/version.BuildDate=$(DATE)

GO        := go
GOFLAGS   := -trimpath
LDFLAGS_F := -ldflags "$(LDFLAGS) -s -w"

.PHONY: all build run test vet lint fmt clean install krew kind-integration

all: build

## build: compile the knm binary into ./bin
build:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS_F) -o $(BIN_DIR)/$(BINARY) ./cmd/knm

## run: go run with version injected (pass extra args via ARGS="...")
run:
	$(GO) run $(LDFLAGS) ./cmd/knm $(ARGS)

## test: run unit tests
test:
	$(GO) test ./...

## vet: go vet
vet:
	$(GO) vet ./...

## lint: go vet + gofmt check (placeholder for golangci-lint)
lint: vet
	@test -z "$$(gofmt -l . | grep -v '^vendor/' | tee /dev/stderr)" || (echo "gofmt issues above" && exit 1)

## fmt: gofmt the whole tree
fmt:
	gofmt -s -w .

## install: install knm to $$GOPATH/bin and create kubectl-net plugin alias
install: build
	@mkdir -p $$GOPATH/bin
	@cp $(BIN_DIR)/$(BINARY) $$GOPATH/bin/$(BINARY)
	@ln -sf $$GOPATH/bin/$(BINARY) $$GOPATH/bin/kubectl-net 2>/dev/null || cp $(BIN_DIR)/$(BINARY) $$GOPATH/bin/kubectl-net
	@echo "Installed $$GOPATH/bin/$(BINARY) and kubectl-net alias"
	@echo "  knm trace pod/web svc/api"
	@echo "  kubectl net trace pod/web svc/api   (same binary)"

## krew: print path to a future krew plugin manifest (placeholder)
krew:
	@echo "krew manifest: hack/knm.yaml (TODO — generate from version)"

## kind-integration: spin up kind cluster + run smoke tests (placeholder)
kind-integration:
	@echo "kind integration: hack/integration.sh (TODO)"

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR)
