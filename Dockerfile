# syntax=docker/dockerfile:1
# Build stage - uses Go's native cross-compilation (no QEMU needed)
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Cross-compile for target platform using Go's native support
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o hanzo-mpc ./cmd/hanzo-mpc
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o hanzo-mpc-cli ./cmd/hanzo-mpc-cli

# Runtime stage
FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/hanzoai/mpc"

RUN apk add --no-cache ca-certificates curl bash

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/hanzo-mpc /usr/local/bin/
COPY --from=builder /build/hanzo-mpc-cli /usr/local/bin/

# Copy config templates
COPY config.yaml.template /app/
COPY config.prod.yaml.template /app/

# Create Hanzo data + log directories. The binary defaults MPC_DATA_DIR to
# /data/hanzo-mpc when unset (see cmd/hanzo-mpc/main.go).
RUN mkdir -p /data/hanzo-mpc/db /data/hanzo-mpc/backups /app/logs /app/identity

# Hanzo defaults — surfaced as env vars so operators can grep `docker inspect`
# to confirm what defaults the binary will use. The binary applies these
# same defaults internally if env is unset.
ENV MPC_DATA_DIR=/data/hanzo-mpc \
    MPC_DB_PATH=/data/hanzo-mpc/db \
    MPC_BACKUP_DIR=/data/hanzo-mpc/backups \
    BRAND_NAME=Hanzo

# Expose ports: 9651=MPC P2P (consensus), 9800=internal API, 8081=dashboard
EXPOSE 9651 9800 8081

# Health check uses the unauthenticated /health endpoint on the dashboard API.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

# Default command — `start` subcommand reads /app/config.yaml.
CMD ["hanzo-mpc", "start", "--config", "/app/config.yaml"]
