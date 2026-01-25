#!/bin/bash

echo "=== Testing Lux MPC Integration ==="

# Check binaries exist
echo "1. Checking binaries..."
if [ -f "./lux-mpc" ] && [ -f "./lux-mpc-cli" ]; then
    echo "✓ Binaries found"
else
    echo "✗ Binaries missing"
    exit 1
fi

# Check versions
echo -e "\n2. Binary versions:"
./lux-mpc --version
./lux-mpc-cli version

# Test key generation (need peers.json first)
echo -e "\n3. Creating test peers.json..."
cat > /tmp/test-peers.json << EOF
{
  "test-node": "c53e799e-d3e7-4b4a-b9f3-41221d5ec905",
  "node1": "edac4cc8-5f73-49aa-b257-3fbfa56a7534",
  "node2": "604410dd-b004-47b7-a1c5-ad75d7645496"
}
EOF

echo -e "\n4. Testing identity generation..."
./lux-mpc-cli generate-identity --node test-node --peers /tmp/test-peers.json --output-dir /tmp/test-identity

if [ -d "/tmp/test-identity" ]; then
    echo "✓ Identity generated successfully"
    rm -rf /tmp/test-identity /tmp/test-peers.json
else
    echo "✗ Failed to generate identity"
    exit 1
fi

# Test running with help
echo -e "\n5. Testing MPC node help..."
./lux-mpc --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ MPC node help works"
else
    echo "✗ MPC node help failed"
    exit 1
fi

echo -e "\n=== All tests passed! ==="
echo "Lux MPC is ready for deployment with the bridge."