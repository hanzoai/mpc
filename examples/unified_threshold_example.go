package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/luxfi/mpc/pkg/threshold"
)

func main() {
	// Create a unified threshold API
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	// Define participants
	partyIDs := []string{"alice", "bob", "charlie"}
	thresholdValue := 1 // 2-of-3 threshold (threshold + 1 required to sign)

	fmt.Println("=== Unified Threshold Signing Example ===")
	fmt.Println()

	// Example 1: ECDSA (using CMP/CGGMP21)
	fmt.Println("1. ECDSA Threshold Signing (CMP/CGGMP21 Protocol)")
	fmt.Println("   - Used for: Bitcoin, Ethereum, and other ECDSA-based chains")
	fmt.Println("   - Features: Presigning support for faster online signing")

	ecdsaParty, err := api.KeyGen(threshold.SchemeECDSA, "alice", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start ECDSA keygen: %v", err)
	}
	fmt.Printf("   ✓ ECDSA KeyGen initiated for party 'alice'\n")
	fmt.Printf("   - Protocol: %s\n", "CGGMP21")
	fmt.Printf("   - Threshold: %d-of-%d\n", thresholdValue+1, len(partyIDs))
	fmt.Println()

	// Example 2: EdDSA (using FROST)
	fmt.Println("2. EdDSA Threshold Signing (FROST Protocol)")
	fmt.Println("   - Used for: Solana, Cardano, and Ed25519-based systems")
	fmt.Println("   - Features: Efficient Schnorr signatures, no presigning needed")

	eddsaParty, err := api.KeyGen(threshold.SchemeEdDSA, "bob", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start EdDSA keygen: %v", err)
	}
	fmt.Printf("   ✓ EdDSA KeyGen initiated for party 'bob'\n")
	fmt.Printf("   - Protocol: %s\n", "FROST")
	fmt.Printf("   - Threshold: %d-of-%d\n", thresholdValue+1, len(partyIDs))
	fmt.Println()

	// Example 3: Taproot (using FROST)
	fmt.Println("3. Taproot/Schnorr Threshold Signing (FROST Protocol)")
	fmt.Println("   - Used for: Bitcoin Taproot, privacy-preserving signatures")
	fmt.Println("   - Features: BIP-340 compatible, aggregatable signatures")

	taprootParty, err := api.KeyGen(threshold.SchemeTaproot, "charlie", partyIDs, thresholdValue)
	if err != nil {
		log.Fatalf("Failed to start Taproot keygen: %v", err)
	}
	fmt.Printf("   ✓ Taproot KeyGen initiated for party 'charlie'\n")
	fmt.Printf("   - Protocol: %s\n", "FROST")
	fmt.Printf("   - Threshold: %d-of-%d\n", thresholdValue+1, len(partyIDs))
	fmt.Println()

	// Check supported schemes
	fmt.Println("=== Supported Signature Schemes ===")
	schemes := api.GetSupportedSchemes()
	for _, scheme := range schemes {
		supported := api.IsSchemeSupported(scheme)
		status := "✓"
		if !supported {
			status = "✗"
		}
		fmt.Printf("   %s %s\n", status, scheme)
	}
	fmt.Println()

	// Generate a message to sign
	messageHash := make([]byte, 32)
	_, err = rand.Read(messageHash)
	if err != nil {
		log.Fatalf("Failed to generate message hash: %v", err)
	}

	fmt.Println("=== Integration Benefits ===")
	fmt.Println("   • Unified API for all threshold signature schemes")
	fmt.Println("   • Support for multiple blockchain ecosystems")
	fmt.Println("   • Concurrent protocol execution capability")
	fmt.Println("   • Automatic protocol selection based on scheme")
	fmt.Println("   • Extensible architecture for adding new protocols")
	fmt.Println()

	fmt.Println("=== Protocol Status ===")
	fmt.Printf("   ECDSA Party Status: Done=%v\n", ecdsaParty.Done())
	fmt.Printf("   EdDSA Party Status: Done=%v\n", eddsaParty.Done())
	fmt.Printf("   Taproot Party Status: Done=%v\n", taprootParty.Done())
	fmt.Println()

	fmt.Println("✅ Successfully integrated CMP and FROST protocols!")
	fmt.Println("   The MPC system now supports both ECDSA and EdDSA threshold signing.")
}
