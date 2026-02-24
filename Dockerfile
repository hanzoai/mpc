# Build stage - uses Go's native cross-compilation (no QEMU needed)
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETARCH
ARG TARGETOS=linux

RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Cross-compile for target platform using Go's native support
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o hanzo-mpc ./cmd/hanzo-mpc
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o hanzo-mpc-cli ./cmd/hanzo-mpc-cli

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

# Create data and log directories
RUN mkdir -p /data/mpc /app/logs /app/identity

# Expose ports (6000=MPC protocol, 8080=HTTP API with IAM auth, 9090=gRPC)
EXPOSE 6000 8080 9090

# Health check uses the unauthenticated /health endpoint
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["hanzo-mpc", "start", "--config", "/app/config.yaml"]
