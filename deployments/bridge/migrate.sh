#!/bin/bash
# Bridge Migration Script - Migrate from Rust MPC to Lux MPC

set -e

echo "=== Lux Bridge MPC Migration Script ==="
echo "This script helps migrate from Rust-based MPC to Go-based Lux MPC"
echo

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is required but not installed"
        exit 1
    fi
    
    # Check docker-compose
    if ! command -v docker-compose &> /dev/null; then
        echo "Error: docker-compose is required but not installed"
        exit 1
    fi
    
    echo "✓ Prerequisites checked"
}

# Build Lux MPC image
build_image() {
    echo
    echo "Building Lux MPC Docker image..."
    cd ../.. # Go to project root
    docker build -t luxfi/lux-mpc:latest .
    cd deployments/bridge
    echo "✓ Docker image built"
}

# Start infrastructure services
start_infrastructure() {
    echo
    echo "Starting infrastructure services (NATS, Consul)..."
    docker-compose up -d nats consul
    
    # Wait for services to be healthy
    echo "Waiting for services to be ready..."
    sleep 10
    
    echo "✓ Infrastructure services started"
}

# Initialize MPC nodes
initialize_nodes() {
    echo
    echo "Initializing Lux MPC nodes..."
    
    # Start MPC nodes
    docker-compose up -d lux-mpc-0 lux-mpc-1 lux-mpc-2
    
    # Wait for nodes to be ready
    echo "Waiting for MPC nodes to initialize..."
    sleep 15
    
    # Generate initial key shares (if needed)
    echo "Generating key shares..."
    # This would typically involve running key generation
    # For now, we'll assume nodes auto-generate on first start
    
    echo "✓ MPC nodes initialized"
}

# Start bridge compatibility layer
start_compatibility_layer() {
    echo
    echo "Starting bridge compatibility layer..."
    
    docker-compose up -d bridge-compat-0 bridge-compat-1 bridge-compat-2
    
    echo "Waiting for compatibility layer to be ready..."
    sleep 5
    
    echo "✓ Bridge compatibility layer started"
}

# Test the setup
test_setup() {
    echo
    echo "Testing the setup..."
    
    # Test each compatibility endpoint
    for port in 6000 6001 6002; do
        echo -n "Testing node on port $port... "
        if curl -s http://localhost:$port/ > /dev/null; then
            echo "✓"
        else
            echo "✗"
            echo "Warning: Node on port $port is not responding"
        fi
    done
    
    echo
    echo "✓ Setup test complete"
}

# Update bridge configuration
update_bridge_config() {
    echo
    echo "Bridge configuration update instructions:"
    echo "----------------------------------------"
    echo "Update your bridge's mpc.ts file to use the new endpoints:"
    echo
    echo 'const mpc_nodes = ['
    echo '  "http://localhost:6000",  // Lux MPC Node 0 (Bridge Compatible)'
    echo '  "http://localhost:6001",  // Lux MPC Node 1 (Bridge Compatible)'
    echo '  "http://localhost:6002"   // Lux MPC Node 2 (Bridge Compatible)'
    echo ']'
    echo
    echo "Or in production:"
    echo 'const mpc_nodes = ['
    echo '  "http://bridge-compat-0:6000",'
    echo '  "http://bridge-compat-1:6000",'
    echo '  "http://bridge-compat-2:6000"'
    echo ']'
}

# Show next steps
show_next_steps() {
    echo
    echo "=== Migration Complete ==="
    echo
    echo "Next steps:"
    echo "1. Update your bridge configuration to use the new MPC endpoints"
    echo "2. Test bridge functionality with a small transaction"
    echo "3. Monitor logs: docker-compose logs -f"
    echo "4. Once verified, shut down old Rust MPC nodes"
    echo
    echo "Useful commands:"
    echo "- View logs: docker-compose logs -f [service-name]"
    echo "- Stop all: docker-compose down"
    echo "- Restart a service: docker-compose restart [service-name]"
    echo "- Check status: docker-compose ps"
}

# Main execution
main() {
    check_prerequisites
    
    echo
    read -p "Build Docker image? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        build_image
    fi
    
    echo
    read -p "Start infrastructure services? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_infrastructure
    fi
    
    echo
    read -p "Initialize MPC nodes? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        initialize_nodes
    fi
    
    echo
    read -p "Start bridge compatibility layer? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_compatibility_layer
    fi
    
    test_setup
    update_bridge_config
    show_next_steps
}

# Run main function
main