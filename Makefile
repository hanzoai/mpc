.PHONY: all build clean mpcd mpc test test-verbose test-coverage e2e-test e2e-clean cleanup-test-env

BIN_DIR := bin

# Default target
all: build

# Build all binaries
build: mpcd mpc mpc-bridge

# Install mpcd (builds and places it in $GOBIN or $GOPATH/bin)
mpcd:
	GOWORK=off go build -o mpcd ./cmd/mpcd

# Install mpc
mpc:
	GOWORK=off go build -o mpc ./cmd/mpc

# Install mpc-bridge (bridge compatibility)
mpc-bridge:
	GOWORK=off go build -o mpc-bridge ./cmd/mpc-bridge 2>/dev/null || true

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage report
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run E2E integration tests
e2e-test: build
	@echo "Running E2E integration tests..."
	cd e2e && make test

# Run E2E tests with coverage
e2e-test-coverage: build
	@echo "Running E2E integration tests with coverage..."
	cd e2e && make test-coverage

# Clean up E2E test artifacts
e2e-clean:
	@echo "Cleaning up E2E test artifacts..."
	cd e2e && make clean

# Comprehensive cleanup of test environment (kills processes, removes artifacts)
cleanup-test-env:
	@echo "Performing comprehensive test environment cleanup..."
	cd e2e && ./cleanup_test_env.sh

# Run all tests (unit + E2E)
test-all: test e2e-test

# Wipe out manually built binaries if needed (not required by go install)
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -f mpcd mpc mpc-bridge

# Full clean (including E2E artifacts)
clean-all: clean e2e-clean

# Run local development environment with Docker
run-local: build
	@echo "Starting local MPC environment..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo ""
	@echo "Services running:"
	@echo "  - NATS: http://localhost:8222"
	@echo "  - Consul: http://localhost:8500"
	@echo ""
	@echo "To start MPC nodes, run:"
	@echo "  ./mpcd --node-id node0 --config config.yaml"

# Stop local environment
stop-local:
	@echo "Stopping local MPC environment..."
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Run a single MPC node (example)
run-node0: build
	@echo "Starting MPC node0..."
	./mpcd --node-id node0 --config config.yaml.template

# Quick start - build and run everything
start: build run-local
	@echo "Environment ready! Run 'make run-node0' in another terminal to start a node."
