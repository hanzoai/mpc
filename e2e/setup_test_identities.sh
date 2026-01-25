#!/bin/bash

# E2E Test Identity Setup Script
# This script sets up identities for testing with separate test database paths

set -e

# Number of test nodes
NUM_NODES=3
BASE_DIR="$(pwd)"
TEST_DB_PATH="$BASE_DIR/test_db"

echo "🚀 Setting up E2E Test Node Identities..."

# Generate random password for badger encryption
echo "🔐 Generating random password for badger encryption..."
BADGER_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
echo "✅ Generated password: $BADGER_PASSWORD"

# Generate config.test.yaml from template
echo "📝 Generating config.test.yaml from template..."
if [ ! -f "config.test.yaml.template" ]; then
    echo "❌ Template file config.test.yaml.template not found"
    exit 1
fi

# Create a temporary config with placeholder values (will be updated later with real pubkey)
TEMP_PUBKEY="0000000000000000000000000000000000000000000000000000000000000000"

# Escape special characters in password for sed
ESCAPED_PASSWORD=$(printf '%s\n' "$BADGER_PASSWORD" | sed 's/[[\.*^$()+?{|]/\\&/g')

sed -e "s/{{\.BadgerPassword}}/$ESCAPED_PASSWORD/g" \
    -e "s/{{\.EventInitiatorPubkey}}/$TEMP_PUBKEY/g" \
    config.test.yaml.template > config.test.yaml

echo "✅ Generated config.test.yaml from template"

# Clean up any existing test data
echo "🧹 Cleaning up existing test data..."
rm -rf "$TEST_DB_PATH"
rm -rf "$BASE_DIR"/test_node*

# Create test node directories
echo "📁 Creating test node directories..."
# Generate UUIDs for the nodes
NODE0_UUID=$(uuidgen)
NODE1_UUID=$(uuidgen)
NODE2_UUID=$(uuidgen)

for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$BASE_DIR/test_node$i/identity"
    cp "$BASE_DIR/config.test.yaml" "$BASE_DIR/test_node$i/config.yaml"
    
    # Create peers.json with proper UUIDs
    cat > "$BASE_DIR/test_node$i/peers.json" << EOF
{
  "test_node0": "$NODE0_UUID",
  "test_node1": "$NODE1_UUID",
  "test_node2": "$NODE2_UUID"
}
EOF
done

# Generate identity for each test node
echo "🔑 Generating identities for each test node..."
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "📝 Generating identity for test_node$i..."
    cd "$BASE_DIR/test_node$i"
    
    # Generate identity using hanzo-mpc-cli
    hanzo-mpc-cli generate-identity --node "test_node$i"
    
    cd - > /dev/null
done

# Distribute identity files to all test nodes
echo "🔄 Distributing identity files across test nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ $i != $j ]; then
            echo "📋 Copying test_node${i}_identity.json to test_node$j..."
            cp "$BASE_DIR/test_node$i/identity/test_node${i}_identity.json" "$BASE_DIR/test_node$j/identity/"
        fi
    done
done

# Generate test event initiator
echo "🔐 Generating test event initiator..."
cd "$BASE_DIR"
hanzo-mpc-cli generate-initiator --node-name test_event_initiator --output-dir . --overwrite

# Extract the public key from the generated identity
if [ -f "test_event_initiator.identity.json" ]; then
    PUBKEY=$(cat test_event_initiator.identity.json | jq -r '.public_key')
    echo "📝 Updating config files with event initiator public key and password..."
    
    # Update all test node config files with the actual public key and password
    for i in $(seq 0 $((NUM_NODES-1))); do
        # Update public key using sed with | as delimiter (safer than /)
        sed -i '' "s|event_initiator_pubkey:.*|event_initiator_pubkey: $PUBKEY|g" "$BASE_DIR/test_node$i/config.yaml"
        # Update password using sed with | as delimiter and escaped password
        sed -i '' "s|badger_password:.*|badger_password: $ESCAPED_PASSWORD|g" "$BASE_DIR/test_node$i/config.yaml"
    done
    
    # Also update the main config.test.yaml
    sed -i '' "s|event_initiator_pubkey:.*|event_initiator_pubkey: $PUBKEY|g" "$BASE_DIR/config.test.yaml"
    sed -i '' "s|badger_password:.*|badger_password: $ESCAPED_PASSWORD|g" "$BASE_DIR/config.test.yaml"
    
    echo "✅ Event initiator public key updated: $PUBKEY"
    echo "✅ Badger password updated: $BADGER_PASSWORD"
else
    echo "❌ Failed to generate event initiator identity"
    exit 1
fi

cd - > /dev/null

echo "✨ E2E Test identities setup complete!"
echo
echo "📂 Created test folder structure:"
echo "├── test_node0"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "├── test_node1"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "└── test_node2"
echo "    ├── config.yaml"
echo "    ├── identity/"
echo "    └── peers.json"
echo
echo "✅ Test nodes are ready for E2E testing!" 
