// Copyright (c) 2024-2025 Hanzo AI Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Ethereum/EVM Threshold Signing Example
// Demonstrates threshold ECDSA signing for Ethereum and EVM-compatible chains
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/luxfi/mpc/pkg/threshold"
	"golang.org/x/crypto/sha3"
)

func main() {
	fmt.Println("=== Ethereum/EVM Threshold Signing Example ===")
	fmt.Println()

	// Create unified threshold API
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	// Define MPC nodes with 2-of-3 threshold
	partyIDs := []string{"signer1", "signer2", "signer3"}
	thresholdValue := 1 // 2-of-3 threshold

	fmt.Println("1. Ethereum Transaction Signing")
	fmt.Println("   Protocol: CGGMP21 (ECDSA on secp256k1)")
	fmt.Println("   Compatible: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche C-Chain")
	fmt.Println()

	// Initialize key generation
	party, err := api.KeyGen(threshold.SchemeECDSA, "signer1", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start keygen: %v", err)
	}

	// Example EIP-155 transaction (Ethereum mainnet)
	tx := &EthTransaction{
		Nonce:    uint64(42),
		GasPrice: big.NewInt(50_000_000_000), // 50 Gwei
		GasLimit: uint64(21000),
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f1D123",
		Value:    big.NewInt(1_000_000_000_000_000_000), // 1 ETH
		Data:     []byte{},
		ChainID:  big.NewInt(1), // Mainnet
	}

	// Compute transaction hash (Keccak256)
	txHash := tx.Hash()

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ Transaction details:\n")
	fmt.Printf("     - Nonce: %d\n", tx.Nonce)
	fmt.Printf("     - Gas Price: %s Gwei\n", new(big.Int).Div(tx.GasPrice, big.NewInt(1_000_000_000)))
	fmt.Printf("     - Gas Limit: %d\n", tx.GasLimit)
	fmt.Printf("     - To: %s\n", tx.To)
	fmt.Printf("     - Value: %s ETH\n", formatEther(tx.Value))
	fmt.Printf("     - Chain ID: %d (Mainnet)\n", tx.ChainID)
	fmt.Printf("   ✓ TX Hash: 0x%s\n", hex.EncodeToString(txHash[:16])+"...")
	fmt.Printf("   ✓ Threshold: %d-of-%d signers required\n", thresholdValue+1, len(partyIDs))
	fmt.Printf("   ✓ Party status: Done=%v\n", party.Done())
	fmt.Println()

	// Example 2: ERC-20 Token Transfer
	fmt.Println("2. ERC-20 Token Transfer")
	fmt.Println()

	// ERC-20 transfer function signature: transfer(address,uint256)
	transferData := encodeERC20Transfer(
		"0x1234567890123456789012345678901234567890",
		big.NewInt(1000_000_000_000_000_000), // 1 token (18 decimals)
	)

	erc20Tx := &EthTransaction{
		Nonce:    uint64(43),
		GasPrice: big.NewInt(50_000_000_000),
		GasLimit: uint64(60000),
		To:       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // Example: USDC
		Value:    big.NewInt(0),
		Data:     transferData,
		ChainID:  big.NewInt(1),
	}

	erc20Hash := erc20Tx.Hash()

	fmt.Printf("   ✓ ERC-20 Transfer encoded\n")
	fmt.Printf("   ✓ Contract: %s\n", erc20Tx.To)
	fmt.Printf("   ✓ TX Hash: 0x%s\n", hex.EncodeToString(erc20Hash[:16])+"...")
	fmt.Println()

	// Supported EVM chains
	fmt.Println("=== Supported EVM Chains ===")
	chains := []struct {
		name    string
		chainID int64
	}{
		{"Ethereum Mainnet", 1},
		{"Polygon", 137},
		{"BNB Smart Chain", 56},
		{"Arbitrum One", 42161},
		{"Optimism", 10},
		{"Avalanche C-Chain", 43114},
		{"Base", 8453},
		{"Lux Network", 9000},
	}
	for _, chain := range chains {
		fmt.Printf("   ✓ %s (Chain ID: %d)\n", chain.name, chain.chainID)
	}
	fmt.Println()

	fmt.Println("=== EVM MPC Benefits ===")
	fmt.Println("   • Institutional-grade custody for ETH and tokens")
	fmt.Println("   • Compatible with all ERC-20, ERC-721, ERC-1155 tokens")
	fmt.Println("   • DeFi protocol interaction support")
	fmt.Println("   • Multi-chain deployment with single key setup")
	fmt.Println("   • EIP-712 typed data signing support")
	fmt.Println()
	fmt.Println("✅ Ethereum/EVM threshold signing ready!")
}

// EthTransaction represents a simplified Ethereum transaction
type EthTransaction struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       string
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// Hash computes the Keccak256 hash of the transaction for signing
func (tx *EthTransaction) Hash() [32]byte {
	// Simplified: in production use RLP encoding
	h := sha3.NewLegacyKeccak256()
	h.Write(big.NewInt(int64(tx.Nonce)).Bytes())
	h.Write(tx.GasPrice.Bytes())
	h.Write(big.NewInt(int64(tx.GasLimit)).Bytes())
	h.Write([]byte(tx.To))
	h.Write(tx.Value.Bytes())
	h.Write(tx.Data)
	h.Write(tx.ChainID.Bytes())
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// encodeERC20Transfer encodes an ERC-20 transfer call
func encodeERC20Transfer(to string, amount *big.Int) []byte {
	// Function selector: keccak256("transfer(address,uint256)")[:4]
	selector := []byte{0xa9, 0x05, 0x9c, 0xbb}
	// Pad address to 32 bytes
	addrBytes := make([]byte, 32)
	copy(addrBytes[12:], []byte(to)[2:22]) // Remove 0x prefix
	// Pad amount to 32 bytes
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)

	result := make([]byte, 0, 68)
	result = append(result, selector...)
	result = append(result, addrBytes...)
	result = append(result, amountBytes...)
	return result
}

// formatEther converts wei to ETH string
func formatEther(wei *big.Int) string {
	eth := new(big.Float).SetInt(wei)
	divisor := new(big.Float).SetInt(big.NewInt(1_000_000_000_000_000_000))
	eth.Quo(eth, divisor)
	return eth.Text('f', 4)
}
