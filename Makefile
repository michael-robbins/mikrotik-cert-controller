VERSION ?= dev
IMAGE   ?= mikrotik-cert-controller
GOFLAGS ?= -trimpath
GO_LDFLAGS := -s -w -X main.version=$(VERSION)

# Colors
CYAN  := \033[36m
GREEN := \033[32m
RESET := \033[0m

.DEFAULT_GOAL := help

.PHONY: help build test lint vet fmt docker-build clean

help: ## Show this help
	@printf '\n$(GREEN)Usage:$(RESET) make $(CYAN)<target>$(RESET)\n\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ''

build: ## Build the cert-controller binary
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(GO_LDFLAGS)' -o bin/cert-controller ./cmd/cert-controller

clean: ## Remove build artifacts
	rm -rf bin/

docker-build: ## Build container image
	docker build -f Containerfile --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

fmt: ## Format Go source files
	gofmt -w .

lint: vet ## Run linters (requires golangci-lint)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

test: ## Run tests with race detector and coverage
	go test -race -cover ./...

vet: ## Run go vet
	go vet ./...
