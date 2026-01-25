#!/bin/sh
# Docker build helper script to handle Go 1.24.5 requirement

# Create a temporary go.mod for Docker builds
cat > go.mod.docker <<EOF
module github.com/luxfi/mpc

go 1.23

replace github.com/luxfi/log => github.com/luxfi/log v1.0.5

$(grep -v "^go " go.mod | grep -v "^module ")
EOF

# Use the Docker-specific go.mod
mv go.mod go.mod.original
mv go.mod.docker go.mod

# Download dependencies
go mod download

# Restore original go.mod
mv go.mod.original go.mod