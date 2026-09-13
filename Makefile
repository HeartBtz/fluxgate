VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: build server cli run clean test test-coverage lint docker up down logs dev deps

# Build all
build: server cli

server:
	go build $(LDFLAGS) -o bin/fluxgate ./cmd/server

cli:
	go build $(LDFLAGS) -o bin/fluxgate-cli ./cmd/fluxgate-cli

# Run locally
run: server
	./bin/fluxgate

# Test
test:
	go test -race -coverprofile=coverage.out ./...

test-coverage: test
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

# Docker
docker:
	docker build -t ghcr.io/heartbtz/fluxgate:$(VERSION) -t ghcr.io/heartbtz/fluxgate:latest .

# Docker Compose
up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f fluxgate

# Development
dev:
	FLUXGATE_LOG_LEVEL=debug FLUXGATE_LOG_FORMAT=text go run ./cmd/server

# Dependencies
deps:
	go mod download
	go mod tidy

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html
