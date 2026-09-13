# syntax=docker/dockerfile:1.7
FROM golang:1.26.7-alpine3.24 AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Copy source
COPY . .

# Build server
ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
	-ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o /bin/fluxgate \
    ./cmd/server

# Build CLI
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
	-ldflags="-s -w -X main.Version=${VERSION}" \
    -o /bin/fluxgate-cli \
    ./cmd/fluxgate-cli

# --- Runtime Stage ---
FROM alpine:3.24.1

ARG VERSION=dev
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.title="FluxGate" \
      org.opencontainers.image.description="Self-hosted file distribution for browsers, curl, and wget" \
      org.opencontainers.image.url="https://github.com/HeartBtz/fluxgate" \
      org.opencontainers.image.documentation="https://github.com/HeartBtz/fluxgate#readme" \
      org.opencontainers.image.source="https://github.com/HeartBtz/fluxgate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_TIME}"

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 fluxgate && \
    adduser -u 1000 -G fluxgate -s /bin/sh -D fluxgate

COPY --from=builder /bin/fluxgate /usr/local/bin/fluxgate
COPY --from=builder /bin/fluxgate-cli /usr/local/bin/fluxgate-cli
COPY --from=builder /build/migrations /app/migrations
COPY --from=builder /build/internal/handler/templates /app/internal/handler/templates
COPY --from=builder /build/web/static /app/web/static

WORKDIR /app

# Storage directory
RUN mkdir -p /data/files && chown -R fluxgate:fluxgate /data /app

USER fluxgate

EXPOSE 8080

ENV FLUXGATE_HOST=0.0.0.0 \
    FLUXGATE_PORT=8080 \
    FLUXGATE_STORAGE_BACKEND=local \
    FLUXGATE_STORAGE_LOCAL_PATH=/data/files \
    FLUXGATE_MIGRATIONS_PATH=/app/migrations \
    FLUXGATE_METRICS_PORT=9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["fluxgate"]
