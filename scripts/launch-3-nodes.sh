#!/bin/bash

echo "🚀 Launching 3-node MPC cluster..."
echo ""

# Generate identities for all nodes if not exist
for node in node0 node1 node2; do
    if [ ! -f "identity/${node}_identity.json" ]; then
        echo "Generating identity for $node..."
        ./lux-mpc-cli generate-identity --node $node --peers peers.json --output-dir identity
    fi
done

echo ""
echo "Starting nodes with environment prefix..."
echo "Environment: local (from config.yaml)"
echo ""

# Start nodes in background
echo "Starting lux-local-node0..."
./lux-mpc start --name node0 > logs/node0.log 2>&1 &
echo "PID: $!"

sleep 2

echo "Starting lux-local-node1..."
./lux-mpc start --name node1 > logs/node1.log 2>&1 &
echo "PID: $!"

sleep 2

echo "Starting lux-local-node2..."
./lux-mpc start --name node2 > logs/node2.log 2>&1 &
echo "PID: $!"

echo ""
echo "✅ All nodes launched!"
echo ""
echo "Check status:"
echo "  - Logs: tail -f logs/*.log"
echo "  - Consul UI: http://localhost:8500"
echo "  - NATS: http://localhost:8222"
echo ""
echo "To stop all nodes: pkill lux-mpc"