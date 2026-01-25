#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              🚀 Lux MPC Cluster Status                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check services
echo "📡 Infrastructure Services:"
echo -n "   NATS:   "
if curl -s http://localhost:8222/varz > /dev/null 2>&1; then
    echo "✅ Running (http://localhost:8222)"
else
    echo "❌ Not running"
fi

echo -n "   Consul: "
if curl -s http://localhost:8500/v1/agent/self > /dev/null 2>&1; then
    echo "✅ Running (http://localhost:8500)"
else
    echo "❌ Not running"
fi

echo ""
echo "🖥️  MPC Nodes (Environment: local):"

# Check each node
for i in 0 1 2; do
    if ps aux | grep -v grep | grep -q "lux-mpc start --name node$i"; then
        echo "   lux-local-node$i: ✅ Running"
    else
        echo "   lux-local-node$i: ❌ Not running"
    fi
done

echo ""
echo "📊 Cluster Readiness:"
# Get latest status from logs
READY_COUNT=$(grep -h "readyPeers=" logs/node*.log 2>/dev/null | tail -1 | grep -o "readyPeers=\[[0-9]\]" | grep -o "[0-9]")
TOTAL_COUNT=$(grep -h "totalPeers=" logs/node*.log 2>/dev/null | tail -1 | grep -o "totalPeers=\[[0-9]\]" | grep -o "[0-9]")

if [ -n "$READY_COUNT" ] && [ -n "$TOTAL_COUNT" ]; then
    echo "   Ready Peers: $READY_COUNT/$TOTAL_COUNT"
    echo "   Threshold: 2 (requires 3 nodes for signing)"
    if [ "$READY_COUNT" -ge 3 ]; then
        echo "   Status: ✅ Ready for operations"
    else
        echo "   Status: ⏳ Waiting for nodes..."
    fi
else
    echo "   Status: ⏳ Initializing..."
fi

echo ""
echo "📝 Commands:"
echo "   View logs:     tail -f logs/*.log"
echo "   Stop cluster:  make stop-local"
echo "   Kill nodes:    pkill lux-mpc"
echo ""