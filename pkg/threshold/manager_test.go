package threshold_test

import (
	"crypto/rand"
	"testing"

	"github.com/hanzoai/mpc/pkg/threshold"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {
	manager := threshold.NewManager()
	defer manager.Close()

	// Test protocol registration
	protocols := manager.ListProtocols()
	assert.Contains(t, protocols, "CGGMP21")
	assert.Contains(t, protocols, "FROST")

	// Test getting protocols
	cggmp21, err := manager.GetProtocol("CGGMP21")
	require.NoError(t, err)
	assert.NotNil(t, cggmp21)
	assert.Equal(t, "CGGMP21", cggmp21.Name())

	frost, err := manager.GetProtocol("FROST")
	require.NoError(t, err)
	assert.NotNil(t, frost)
	assert.Equal(t, "FROST", frost.Name())

	// Test getting protocol for scheme
	ecdsaProtocol, err := manager.GetProtocolForScheme(threshold.SchemeECDSA)
	require.NoError(t, err)
	assert.Equal(t, "CGGMP21", ecdsaProtocol.Name())

	eddsaProtocol, err := manager.GetProtocolForScheme(threshold.SchemeEdDSA)
	require.NoError(t, err)
	assert.Equal(t, "FROST", eddsaProtocol.Name())

	taprootProtocol, err := manager.GetProtocolForScheme(threshold.SchemeTaproot)
	require.NoError(t, err)
	assert.Equal(t, "FROST", taprootProtocol.Name())
}

func TestUnifiedThresholdAPI(t *testing.T) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	// Test supported schemes
	schemes := api.GetSupportedSchemes()
	assert.Contains(t, schemes, threshold.SchemeECDSA)
	assert.Contains(t, schemes, threshold.SchemeEdDSA)
	assert.Contains(t, schemes, threshold.SchemeTaproot)

	// Test scheme support check
	assert.True(t, api.IsSchemeSupported(threshold.SchemeECDSA))
	assert.True(t, api.IsSchemeSupported(threshold.SchemeEdDSA))
	assert.True(t, api.IsSchemeSupported(threshold.SchemeTaproot))

	// Test KeyGen initialization for different schemes
	partyIDs := []string{"party1", "party2", "party3"}
	thresholdValue := 1

	t.Run("ECDSA KeyGen", func(t *testing.T) {
		party, err := api.KeyGen(threshold.SchemeECDSA, "party1", partyIDs, thresholdValue)
		require.NoError(t, err)
		assert.NotNil(t, party)
	})

	t.Run("EdDSA KeyGen", func(t *testing.T) {
		party, err := api.KeyGen(threshold.SchemeEdDSA, "party1", partyIDs, thresholdValue)
		require.NoError(t, err)
		assert.NotNil(t, party)
	})

	t.Run("Taproot KeyGen", func(t *testing.T) {
		party, err := api.KeyGen(threshold.SchemeTaproot, "party1", partyIDs, thresholdValue)
		require.NoError(t, err)
		assert.NotNil(t, party)
	})
}

func TestProtocolIntegration(t *testing.T) {
	// Test that both CMP and FROST protocols can be used together
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	partyIDs := []string{"alice", "bob", "charlie"}
	thresholdValue := 1

	// Generate message to sign
	messageHash := make([]byte, 32)
	_, err := rand.Read(messageHash)
	require.NoError(t, err)

	t.Run("Concurrent ECDSA and EdDSA", func(t *testing.T) {
		// Start ECDSA keygen
		ecdsaParty, err := api.KeyGen(threshold.SchemeECDSA, "alice", partyIDs, thresholdValue)
		require.NoError(t, err)
		assert.NotNil(t, ecdsaParty)

		// Start EdDSA keygen simultaneously
		eddsaParty, err := api.KeyGen(threshold.SchemeEdDSA, "alice", partyIDs, thresholdValue)
		require.NoError(t, err)
		assert.NotNil(t, eddsaParty)

		// Both should work independently
		assert.False(t, ecdsaParty.Done())
		assert.False(t, eddsaParty.Done())
	})
}

func BenchmarkProtocolCreation(b *testing.B) {
	api := threshold.NewUnifiedThresholdAPI()
	defer api.Close()

	partyIDs := []string{"party1", "party2", "party3"}
	thresholdValue := 1

	b.Run("ECDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeECDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})

	b.Run("EdDSA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			party, err := api.KeyGen(threshold.SchemeEdDSA, "party1", partyIDs, thresholdValue)
			if err != nil {
				b.Fatal(err)
			}
			_ = party
		}
	})
}
