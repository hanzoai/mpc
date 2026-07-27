# syntax=docker/dockerfile:1
#
# Hanzo MPC — thin white-label wrapper over the canonical luxfi/mpc engine.
#
# The wrapper imports github.com/luxfi/mpc as a normal versioned module
# (pinned in go.mod), so there is exactly one source of the upstream
# version: bump it with `go get github.com/luxfi/mpc@vX.Y.Z`. No sibling
# checkout, no build-arg ref — the module graph is the single source of truth.
#
# Built and pushed as ghcr.io/hanzoai/mpc by the canonical reusable workflow
# hanzoai/.github/.github/workflows/docker-build.yml (context: ., single
# actions/checkout). The default (no-tag) build ships the daemon + CLI; the
# admin dashboard lives upstream and is opt-in via `-tags embedui`.

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

RUN apk add --no-cache git

WORKDIR /src

# luxfi modules resolve direct from the GitHub origin: tags have been
# force-pushed upstream in the past (notably edwards25519@v0.1.0), so the
# public sumdb may serve a stale entry. Matches luxfi/mpc's own CI knobs.
ENV GOPRIVATE=github.com/luxfi/*,github.com/hanzoai/*
ENV GOFLAGS=-mod=mod

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o mpcd ./cmd/mpcd

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o mpc ./cmd/mpc

# Runtime stage
FROM alpine:3.21

LABEL org.opencontainers.image.source="https://github.com/hanzoai/mpc"

RUN apk add --no-cache ca-certificates curl bash tzdata

WORKDIR /app

COPY --from=builder /src/mpcd /usr/local/bin/
COPY --from=builder /src/mpc  /usr/local/bin/

# Config templates from the hanzo/mpc checkout.
COPY config.yaml.template      /app/
COPY config.prod.yaml.template /app/

# Hanzo data + log directories. The binary defaults MPC_DATA_DIR to
# /data/mpcd when unset (see cmd/mpcd/main.go).
RUN mkdir -p /data/mpcd/db /data/mpcd/backups /app/logs /app/identity

ENV MPC_DATA_DIR=/data/mpcd \
    MPC_DB_PATH=/data/mpcd/db \
    MPC_BACKUP_DIR=/data/mpcd/backups

# 9999=MPC P2P (canonical ZAP), 9800=internal API, 8081=dashboard
EXPOSE 9999 9800 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

CMD ["mpcd", "start", "--config", "/app/config.yaml"]
