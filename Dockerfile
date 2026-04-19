# syntax=docker/dockerfile:1
#
# Hanzo MPC — thin wrapper over luxfi/mpc.
#
# Build context is the PARENT of hanzo/mpc and lux/mpc (CI checkout layout):
#   ./hanzo/mpc  (this repo)
#   ./lux/mpc    (canonical luxfi/mpc, sibling)
# This matches the relative `replace github.com/luxfi/mpc => ../../lux/mpc`
# directive in hanzo/mpc/go.mod so dev and CI builds resolve identically.

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

RUN apk add --no-cache git make

WORKDIR /build

# Copy both checkouts so the relative replace directive resolves.
COPY hanzo/mpc /build/hanzo/mpc
COPY lux/mpc   /build/lux/mpc

WORKDIR /build/hanzo/mpc

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o hanzo-mpc ./cmd/hanzo-mpc

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o hanzo-mpc-cli ./cmd/hanzo-mpc-cli

# Runtime stage
FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/hanzoai/mpc"

RUN apk add --no-cache ca-certificates curl bash

WORKDIR /app

COPY --from=builder /build/hanzo/mpc/hanzo-mpc     /usr/local/bin/
COPY --from=builder /build/hanzo/mpc/hanzo-mpc-cli /usr/local/bin/

# Config templates from the hanzo/mpc checkout.
COPY hanzo/mpc/config.yaml.template      /app/
COPY hanzo/mpc/config.prod.yaml.template /app/

# Hanzo data + log directories. The binary defaults MPC_DATA_DIR to
# /data/hanzo-mpc when unset (see cmd/hanzo-mpc/main.go).
RUN mkdir -p /data/hanzo-mpc/db /data/hanzo-mpc/backups /app/logs /app/identity

ENV MPC_DATA_DIR=/data/hanzo-mpc \
    MPC_DB_PATH=/data/hanzo-mpc/db \
    MPC_BACKUP_DIR=/data/hanzo-mpc/backups \
    BRAND_NAME=Hanzo

# 9651=MPC P2P (consensus), 9800=internal API, 8081=dashboard
EXPOSE 9651 9800 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

CMD ["hanzo-mpc", "start", "--config", "/app/config.yaml"]
