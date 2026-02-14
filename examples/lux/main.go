// Copyright (c) 2024-2025 Hanzo AI Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Lux Network Threshold Signing Example
// Demonstrates threshold signing for Lux Network (X-Chain, P-Chain, C-Chain)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/hanzoai/mpc/pkg/threshold"
	"golang.org/x/crypto/sha3"
)

func main() {
	fmt.Println("=== Lux Network Threshold Signing Example ===")
	fmt.Println()

	// Create unified threshold API
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	// Define MPC nodes with 2-of-3 threshold
	partyIDs := []string{"validator1", "validator2", "validator3"}
	thresholdValue := 1 // 2-of-3 threshold

	// Example 1: X-Chain (Exchange Chain) - ECDSA/secp256k1
	fmt.Println("1. X-Chain (Exchange Chain) Transaction Signing")
	fmt.Println("   Protocol: CGGMP21 (ECDSA on secp256k1)")
	fmt.Println("   Use case: Asset transfers, LUX native token")
	fmt.Println()

	xchainParty, err := api.KeyGen(threshold.SchemeECDSA, "validator1", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start X-Chain keygen: %v", err)
	}

	// Example X-Chain transfer transaction
	xchainTx := &LuxTransaction{
		NetworkID:   9000, // Lux Mainnet
		ChainID:     "X",
		TypeID:      0, // Base transaction
		Inputs:      []UTXO{{TxID: "abc123", OutputIndex: 0, Amount: 1_000_000_000}},
		Outputs:     []Output{{Address: "X-lux1...", Amount: 999_000_000}},
		Memo:        []byte("MPC threshold transfer"),
	}

	xchainHash := xchainTx.Hash()

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ Transaction details:\n")
	fmt.Printf("     - Network ID: %d (Lux Mainnet)\n", xchainTx.NetworkID)
	fmt.Printf("     - Chain: %s-Chain\n", xchainTx.ChainID)
	fmt.Printf("     - Inputs: %d UTXO(s)\n", len(xchainTx.Inputs))
	fmt.Printf("     - Outputs: %d\n", len(xchainTx.Outputs))
	fmt.Printf("   ✓ TX Hash: %s\n", hex.EncodeToString(xchainHash[:16])+"...")
	fmt.Printf("   ✓ Threshold: %d-of-%d signers required\n", thresholdValue+1, len(partyIDs))
	fmt.Printf("   ✓ Party status: Done=%v\n", xchainParty.Done())
	fmt.Println()

	// Example 2: P-Chain (Platform Chain) - ECDSA/secp256k1
	fmt.Println("2. P-Chain (Platform Chain) Transaction Signing")
	fmt.Println("   Protocol: CGGMP21 (ECDSA on secp256k1)")
	fmt.Println("   Use case: Staking, subnet creation, validator management")
	fmt.Println()

	pchainParty, err := api.KeyGen(threshold.SchemeECDSA, "validator2", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start P-Chain keygen: %v", err)
	}

	// Example P-Chain staking transaction
	stakingTx := &StakingTransaction{
		NetworkID:     9000,
		NodeID:        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
		StakeAmount:   2000_000_000_000, // 2000 LUX
		StartTime:     1704067200,       // Unix timestamp
		EndTime:       1735689600,       // Unix timestamp
		RewardAddress: "P-lux1...",
	}

	stakingHash := stakingTx.Hash()

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ Staking details:\n")
	fmt.Printf("     - Node ID: %s...\n", stakingTx.NodeID[:20])
	fmt.Printf("     - Stake Amount: %d LUX\n", stakingTx.StakeAmount/1_000_000_000)
	fmt.Printf("     - Duration: ~1 year\n")
	fmt.Printf("   ✓ TX Hash: %s\n", hex.EncodeToString(stakingHash[:16])+"...")
	fmt.Printf("   ✓ Party status: Done=%v\n", pchainParty.Done())
	fmt.Println()

	// Example 3: C-Chain (Contract Chain) - EVM Compatible
	fmt.Println("3. C-Chain (Contract Chain) Transaction Signing")
	fmt.Println("   Protocol: CGGMP21 (ECDSA on secp256k1)")
	fmt.Println("   Use case: Smart contracts, DeFi, ERC-20 tokens")
	fmt.Println()

	cchainParty, err := api.KeyGen(threshold.SchemeECDSA, "validator3", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start C-Chain keygen: %v", err)
	}

	// Example C-Chain EVM transaction
	cchainTx := &EVMTransaction{
		Nonce:    uint64(42),
		GasPrice: big.NewInt(25_000_000_000), // 25 nLUX
		GasLimit: uint64(21000),
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f1D123",
		Value:    big.NewInt(1_000_000_000_000_000_000), // 1 LUX
		Data:     []byte{},
		ChainID:  big.NewInt(9000), // Lux C-Chain
	}

	cchainHash := cchainTx.Hash()

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ EVM Transaction details:\n")
	fmt.Printf("     - Nonce: %d\n", cchainTx.Nonce)
	fmt.Printf("     - Gas Price: %s nLUX\n", new(big.Int).Div(cchainTx.GasPrice, big.NewInt(1_000_000_000)))
	fmt.Printf("     - Gas Limit: %d\n", cchainTx.GasLimit)
	fmt.Printf("     - Chain ID: %d (Lux C-Chain)\n", cchainTx.ChainID)
	fmt.Printf("   ✓ TX Hash: 0x%s\n", hex.EncodeToString(cchainHash[:16])+"...")
	fmt.Printf("   ✓ Party status: Done=%v\n", cchainParty.Done())
	fmt.Println()

	// Example 4: Cross-Chain Transfer
	fmt.Println("4. Cross-Chain Transfer (X-Chain → C-Chain)")
	fmt.Println()

	crossChainTx := &CrossChainTransaction{
		SourceChain: "X",
		DestChain:   "C",
		Amount:      100_000_000_000, // 100 LUX
		ExportTxID:  "export123",
	}

	crossChainHash := crossChainTx.Hash()
	fmt.Printf("   ✓ Cross-chain transfer encoded\n")
	fmt.Printf("   ✓ Source: %s-Chain → Dest: %s-Chain\n", crossChainTx.SourceChain, crossChainTx.DestChain)
	fmt.Printf("   ✓ Amount: %d LUX\n", crossChainTx.Amount/1_000_000_000)
	fmt.Printf("   ✓ TX Hash: %s\n", hex.EncodeToString(crossChainHash[:16])+"...")
	fmt.Println()

	// Lux Network features
	fmt.Println("=== Lux Network Chain Support ===")
	chains := []struct {
		name    string
		chainID string
		purpose string
	}{
		{"X-Chain", "X", "Asset transfers, native tokens"},
		{"P-Chain", "P", "Staking, validators, subnets"},
		{"C-Chain", "C", "Smart contracts, EVM/DeFi"},
	}
	for _, chain := range chains {
		fmt.Printf("   ✓ %s (%s): %s\n", chain.name, chain.chainID, chain.purpose)
	}
	fmt.Println()

	fmt.Println("=== Lux MPC Benefits ===")
	fmt.Println("   • Multi-chain threshold custody (X, P, C chains)")
	fmt.Println("   • Institutional-grade staking security")
	fmt.Println("   • Cross-chain atomic swaps with MPC")
	fmt.Println("   • Subnet deployment with distributed keys")
	fmt.Println("   • EVM compatibility for DeFi protocols")
	fmt.Println("   • Post-quantum ready (future upgrades)")
	fmt.Println()
	fmt.Println("✅ Lux Network threshold signing ready!")
}

// LuxTransaction represents a simplified Lux X-Chain transaction
type LuxTransaction struct {
	NetworkID uint32
	ChainID   string
	TypeID    uint32
	Inputs    []UTXO
	Outputs   []Output
	Memo      []byte
}

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID        string
	OutputIndex uint32
	Amount      uint64
}

// Output represents a transaction output
type Output struct {
	Address string
	Amount  uint64
}

// Hash computes the transaction hash for signing
func (tx *LuxTransaction) Hash() [32]byte {
	h := sha256.New()
	// Simplified: in production use proper Lux serialization
	h.Write([]byte(fmt.Sprintf("%d", tx.NetworkID)))
	h.Write([]byte(tx.ChainID))
	for _, input := range tx.Inputs {
		h.Write([]byte(input.TxID))
	}
	for _, output := range tx.Outputs {
		h.Write([]byte(output.Address))
	}
	h.Write(tx.Memo)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// StakingTransaction represents a P-Chain staking transaction
type StakingTransaction struct {
	NetworkID     uint32
	NodeID        string
	StakeAmount   uint64
	StartTime     int64
	EndTime       int64
	RewardAddress string
}

// Hash computes the staking transaction hash
func (tx *StakingTransaction) Hash() [32]byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", tx.NetworkID)))
	h.Write([]byte(tx.NodeID))
	h.Write([]byte(fmt.Sprintf("%d", tx.StakeAmount)))
	h.Write([]byte(fmt.Sprintf("%d", tx.StartTime)))
	h.Write([]byte(fmt.Sprintf("%d", tx.EndTime)))
	h.Write([]byte(tx.RewardAddress))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// EVMTransaction represents a C-Chain EVM transaction
type EVMTransaction struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       string
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// Hash computes the Keccak256 hash for EVM signing
func (tx *EVMTransaction) Hash() [32]byte {
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

// CrossChainTransaction represents a cross-chain transfer
type CrossChainTransaction struct {
	SourceChain string
	DestChain   string
	Amount      uint64
	ExportTxID  string
}

// Hash computes the cross-chain transaction hash
func (tx *CrossChainTransaction) Hash() [32]byte {
	h := sha256.New()
	h.Write([]byte(tx.SourceChain))
	h.Write([]byte(tx.DestChain))
	h.Write([]byte(fmt.Sprintf("%d", tx.Amount)))
	h.Write([]byte(tx.ExportTxID))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
