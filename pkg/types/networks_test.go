package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkConstants(t *testing.T) {
	// Test XRPL network constants
	assert.Equal(t, "XRPL", string(NetworkXRPL))
	assert.Equal(t, "XRPL-testnet", string(NetworkXRPLTestnet))
	assert.Equal(t, "XRPL-devnet", string(NetworkXRPLDevnet))
}

func TestIsNetworkSupported(t *testing.T) {
	testCases := []struct {
		name     string
		network  string
		expected bool
	}{
		// XRPL networks
		{"XRPL mainnet", "XRPL", true},
		{"XRPL testnet", "XRPL-testnet", true},
		{"XRPL devnet", "XRPL-devnet", true},

		// Other networks
		{"Bitcoin", "BTC", true},
		{"Ethereum", "ETH", true},
		{"Solana", "SOL", true},
		{"Lux", "LUX", true},

		// Unsupported
		{"Unknown", "UNKNOWN", false},
		{"Empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsNetworkSupported(tc.network)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetNetworkKeyType(t *testing.T) {
	testCases := []struct {
		name     string
		network  NetworkCode
		expected KeyType
	}{
		// XRPL uses secp256k1
		{"XRPL mainnet", NetworkXRPL, KeyTypeSecp256k1},
		{"XRPL testnet", NetworkXRPLTestnet, KeyTypeSecp256k1},
		{"XRPL devnet", NetworkXRPLDevnet, KeyTypeSecp256k1},

		// Solana uses Ed25519
		{"Solana mainnet", NetworkSOL, KeyTypeEd25519},
		{"Solana devnet", NetworkSOLDevnet, KeyTypeEd25519},

		// Bitcoin uses secp256k1
		{"Bitcoin", NetworkBTC, KeyTypeSecp256k1},

		// Ethereum uses secp256k1
		{"Ethereum", NetworkETH, KeyTypeSecp256k1},

		// TON uses Ed25519
		{"TON", NetworkTON, KeyTypeEd25519},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetNetworkKeyType(tc.network)
			assert.Equal(t, tc.expected, result)
		})
	}
}
