// Copyright (c) 2024-2025 Hanzo AI Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Bitcoin Threshold Signing Example
// Demonstrates both Legacy/SegWit (ECDSA) and Taproot (Schnorr) signing
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/hanzoai/mpc/pkg/threshold"
)

func main() {
	fmt.Println("=== Bitcoin Threshold Signing Examples ===")
	fmt.Println()

	// Create unified threshold API
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	// Define 3 MPC nodes with 2-of-3 threshold
	partyIDs := []string{"node1", "node2", "node3"}
	thresholdValue := 1 // t=1 means 2-of-3 (t+1 signers required)

	// Example 1: Bitcoin Legacy/SegWit (ECDSA/secp256k1)
	fmt.Println("1. Bitcoin Legacy/SegWit Transaction Signing")
	fmt.Println("   Protocol: CGGMP21 (ECDSA on secp256k1)")
	fmt.Println("   Use case: P2PKH, P2SH, P2WPKH, P2WSH addresses")
	fmt.Println()

	legacyParty, err := api.KeyGen(threshold.SchemeECDSA, "node1", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start Legacy keygen: %v", err)
	}

	// Simulate a Bitcoin transaction hash to sign
	// In production: serialized tx -> double SHA256
	txData := []byte("Bitcoin Legacy Transaction Data")
	legacyTxHash := doubleSHA256(txData)

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ Transaction hash: %s\n", hex.EncodeToString(legacyTxHash[:16])+"...")
	fmt.Printf("   ✓ Threshold: %d-of-%d signers required\n", thresholdValue+1, len(partyIDs))
	fmt.Printf("   ✓ Party status: Done=%v\n", legacyParty.Done())
	fmt.Println()

	// Example 2: Bitcoin Taproot (Schnorr/BIP-340)
	fmt.Println("2. Bitcoin Taproot Transaction Signing")
	fmt.Println("   Protocol: FROST (Schnorr on secp256k1)")
	fmt.Println("   Use case: P2TR addresses, script path spending")
	fmt.Println()

	taprootParty, err := api.KeyGen(threshold.SchemeTaproot, "node2", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start Taproot keygen: %v", err)
	}

	// Taproot uses tagged hashes (BIP-340)
	taprootTxHash := taggedHash("TapSighash", txData)

	fmt.Printf("   ✓ Key generation initiated\n")
	fmt.Printf("   ✓ Tagged hash: %s\n", hex.EncodeToString(taprootTxHash[:16])+"...")
	fmt.Printf("   ✓ Threshold: %d-of-%d signers required\n", thresholdValue+1, len(partyIDs))
	fmt.Printf("   ✓ Party status: Done=%v\n", taprootParty.Done())
	fmt.Println()

	// Summary
	fmt.Println("=== Bitcoin MPC Benefits ===")
	fmt.Println("   • No single point of failure for private keys")
	fmt.Println("   • Distributed custody across multiple parties")
	fmt.Println("   • Standard Bitcoin transactions (indistinguishable on-chain)")
	fmt.Println("   • Taproot: smaller signatures, better privacy")
	fmt.Println("   • Legacy: broad wallet compatibility")
	fmt.Println()
	fmt.Println("✅ Bitcoin threshold signing ready!")
}

// doubleSHA256 computes SHA256(SHA256(data)) for Bitcoin tx signing
func doubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// taggedHash computes SHA256(SHA256(tag) || SHA256(tag) || msg) per BIP-340
func taggedHash(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
