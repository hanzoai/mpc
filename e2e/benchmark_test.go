package e2e

import (
	"crypto/rand"
	"testing"

	"github.com/hanzoai/mpc/pkg/threshold"
)

// BenchmarkProtocolKeyGen benchmarks key generation for MPC protocols
// This runs protocol-level benchmarks without requiring full E2E infrastructure
func BenchmarkProtocolKeyGen(b *testing.B) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	partyIDs := []string{"party1", "party2", "party3"}
	thresholdValue := 1 // t+1 = 2 parties needed for signing

	b.Run("ECDSA_3_of_2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeECDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})

	b.Run("EdDSA_3_of_2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeEdDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})

	b.Run("Taproot_3_of_2", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeTaproot, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})
}

// BenchmarkProtocolKeyGen5Parties benchmarks key generation with 5 parties
func BenchmarkProtocolKeyGen5Parties(b *testing.B) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	partyIDs := []string{"party1", "party2", "party3", "party4", "party5"}
	thresholdValue := 2 // t+1 = 3 parties needed for signing

	b.Run("ECDSA_5_of_3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeECDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})

	b.Run("EdDSA_5_of_3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeEdDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})
}

// BenchmarkProtocolSchemeSelection benchmarks protocol selection by scheme
func BenchmarkProtocolSchemeSelection(b *testing.B) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	b.Run("GetSupportedSchemes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			schemes := api.GetSupportedSchemes()
			_ = schemes
		}
	})

	b.Run("IsSchemeSupported_ECDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			supported := api.IsSchemeSupported(threshold.SchemeECDSA)
			_ = supported
		}
	})

	b.Run("IsSchemeSupported_EdDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			supported := api.IsSchemeSupported(threshold.SchemeEdDSA)
			_ = supported
		}
	})
}

// BenchmarkConcurrentKeyGen benchmarks concurrent protocol instantiation
func BenchmarkConcurrentKeyGen(b *testing.B) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	partyIDs := []string{"alice", "bob", "charlie"}
	thresholdValue := 1

	b.Run("Concurrent_ECDSA_EdDSA", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Create both ECDSA and EdDSA parties concurrently
			ecdsaParty, err := api.KeyGen(threshold.SchemeECDSA, "alice", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}

			eddsaParty, err := api.KeyGen(threshold.SchemeEdDSA, "alice", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}

			_, _ = ecdsaParty, eddsaParty
		}
	})
}

// BenchmarkMessageHashGeneration benchmarks message hash generation for signing
func BenchmarkMessageHashGeneration(b *testing.B) {
	messageHash := make([]byte, 32)

	b.Run("GenerateRandomHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := rand.Read(messageHash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
