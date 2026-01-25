package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXRPLSigning tests MPC signing specifically for XRP Ledger transactions.
// XRPL uses secp256k1 (ECDSA) signatures like Bitcoin and Ethereum.
func TestXRPLSigning(t *testing.T) {
	suite := NewE2ETestSuite(".")
	logger.Init("dev", true)

	// Comprehensive cleanup before starting tests
	t.Log("Performing pre-test cleanup...")
	suite.CleanupTestEnvironment(t)

	// Ensure cleanup happens even if test fails
	defer func() {
		t.Log("Performing post-test cleanup...")
		suite.Cleanup(t)
	}()

	// Setup infrastructure
	t.Run("Setup", func(t *testing.T) {
		t.Log("Running make clean to ensure clean build...")
		err := suite.RunMakeClean()
		require.NoError(t, err, "Failed to run make clean")
		t.Log("make clean completed")

		t.Log("Starting setupInfrastructure...")
		suite.SetupInfrastructure(t)
		t.Log("setupInfrastructure completed")

		t.Log("Starting setupTestNodes...")
		suite.SetupTestNodes(t)
		t.Log("setupTestNodes completed")

		// Load config after setup script runs
		err = suite.LoadConfig()
		require.NoError(t, err, "Failed to load config after setup")

		t.Log("Starting registerPeers...")
		suite.RegisterPeers(t)
		t.Log("registerPeers completed")

		t.Log("Starting setupMPCClient...")
		suite.SetupMPCClient(t)
		t.Log("setupMPCClient completed")

		t.Log("Starting startNodes...")
		suite.StartNodes(t)
		t.Log("startNodes completed")
	})

	// Test key generation for XRPL wallet
	t.Run("XRPLKeyGeneration", func(t *testing.T) {
		testXRPLKeyGeneration(t, suite)
	})

	// Test XRPL signing with different transaction types
	t.Run("XRPLSigningPayment", func(t *testing.T) {
		testXRPLPaymentSigning(t, suite)
	})

	t.Run("XRPLSigningTrustSet", func(t *testing.T) {
		testXRPLTrustSetSigning(t, suite)
	})

	t.Run("XRPLSigningOfferCreate", func(t *testing.T) {
		testXRPLOfferCreateSigning(t, suite)
	})
}

func testXRPLKeyGeneration(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing key generation for XRPL wallet...")

	if suite.mpcClient == nil {
		t.Fatal("MPC client is not initialized. Make sure Setup subtest runs first.")
	}

	suite.WaitForNodesReady(t)

	// Generate wallet ID for XRPL testing
	walletID := uuid.New().String()
	suite.walletIDs = append(suite.walletIDs, walletID)

	t.Logf("Generated XRPL wallet ID: %s", walletID)

	// Setup result listener
	err := suite.mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		t.Logf("Received keygen result for wallet %s: %s", result.WalletID, result.ResultType)
		suite.keygenResults[result.WalletID] = &result

		if result.ResultType == event.ResultTypeError {
			t.Logf("Keygen failed for wallet %s: %s (%s)", result.WalletID, result.ErrorReason, result.ErrorCode)
		} else {
			t.Logf("Keygen succeeded for wallet %s", result.WalletID)
		}
	})
	require.NoError(t, err, "Failed to setup keygen result listener")

	time.Sleep(2 * time.Second)

	// Trigger key generation
	t.Logf("Triggering key generation for XRPL wallet %s", walletID)
	err = suite.mpcClient.CreateWallet(walletID)
	require.NoError(t, err, "Failed to trigger key generation for wallet %s", walletID)

	// Wait for key generation to complete
	t.Log("Waiting for key generation to complete...")
	timeout := time.NewTimer(keygenTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Logf("Timeout waiting for keygen results. Received %d results", len(suite.keygenResults))
			goto checkResults
		case <-ticker.C:
			t.Logf("Still waiting... Received %d keygen results", len(suite.keygenResults))
			if result, exists := suite.keygenResults[walletID]; exists {
				if result.ResultType != event.ResultTypeError {
					goto checkResults
				}
			}
		}
	}

checkResults:
	result, exists := suite.keygenResults[walletID]
	if !exists {
		t.Fatalf("No keygen result received for XRPL wallet %s", walletID)
	}

	if result.ResultType == event.ResultTypeError {
		t.Fatalf("Keygen failed for XRPL wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
	}

	t.Logf("XRPL keygen succeeded for wallet %s", result.WalletID)
	assert.NotEmpty(t, result.ECDSAPubKey, "ECDSA public key should not be empty (required for XRPL secp256k1)")
	t.Log("XRPL key generation completed successfully")
}

func testXRPLPaymentSigning(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing XRPL Payment transaction signing...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing. Make sure key generation ran first.")
	}

	walletID := suite.walletIDs[0]

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received signing result for tx %s: %s", result.TxID, result.ResultType)
		signingResults[result.TxID] = &result
	})
	require.NoError(t, err, "Failed to setup signing result listener")

	time.Sleep(1 * time.Second)

	// Sample XRPL Payment transaction (serialized for signing)
	// In real usage, this would be a properly serialized XRPL transaction blob
	xrplPaymentTx := []byte(`{"TransactionType":"Payment","Account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","Destination":"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe","Amount":"1000000"}`)

	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  xrplPaymentTx,
		KeyType:             types.KeyTypeSecp256k1, // XRPL uses secp256k1
		NetworkInternalCode: string(types.NetworkXRPL),
	}

	t.Logf("Signing XRPL Payment transaction with wallet %s", walletID)
	err = suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger XRPL signing")

	// Wait for signing result
	result := waitForXRPLSigningResult(t, txID, signingResults)
	validateXRPLSigningResult(t, walletID, result)

	t.Log("XRPL Payment signing completed successfully")
}

func testXRPLTrustSetSigning(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing XRPL TrustSet transaction signing...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing. Make sure key generation ran first.")
	}

	walletID := suite.walletIDs[0]

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received signing result for tx %s: %s", result.TxID, result.ResultType)
		signingResults[result.TxID] = &result
	})
	require.NoError(t, err, "Failed to setup signing result listener")

	time.Sleep(1 * time.Second)

	// Sample XRPL TrustSet transaction
	xrplTrustSetTx := []byte(`{"TransactionType":"TrustSet","Account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","LimitAmount":{"currency":"USD","issuer":"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe","value":"1000"}}`)

	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  xrplTrustSetTx,
		KeyType:             types.KeyTypeSecp256k1,
		NetworkInternalCode: string(types.NetworkXRPL),
	}

	t.Logf("Signing XRPL TrustSet transaction with wallet %s", walletID)
	err = suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger XRPL signing")

	// Wait for signing result
	result := waitForXRPLSigningResult(t, txID, signingResults)
	validateXRPLSigningResult(t, walletID, result)

	t.Log("XRPL TrustSet signing completed successfully")
}

func testXRPLOfferCreateSigning(t *testing.T, suite *E2ETestSuite) {
	t.Log("Testing XRPL OfferCreate transaction signing...")

	if len(suite.walletIDs) == 0 {
		t.Fatal("No wallets available for signing. Make sure key generation ran first.")
	}

	walletID := suite.walletIDs[0]

	// Setup signing result listener
	signingResults := make(map[string]*event.SigningResultEvent)
	err := suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		t.Logf("Received signing result for tx %s: %s", result.TxID, result.ResultType)
		signingResults[result.TxID] = &result
	})
	require.NoError(t, err, "Failed to setup signing result listener")

	time.Sleep(1 * time.Second)

	// Sample XRPL OfferCreate transaction (DEX order)
	xrplOfferCreateTx := []byte(`{"TransactionType":"OfferCreate","Account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","TakerGets":"1000000","TakerPays":{"currency":"USD","issuer":"rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe","value":"1"}}`)

	txID := uuid.New().String()
	signTxMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  xrplOfferCreateTx,
		KeyType:             types.KeyTypeSecp256k1,
		NetworkInternalCode: string(types.NetworkXRPL),
	}

	t.Logf("Signing XRPL OfferCreate transaction with wallet %s", walletID)
	err = suite.mpcClient.SignTransaction(signTxMsg)
	require.NoError(t, err, "Failed to trigger XRPL signing")

	// Wait for signing result
	result := waitForXRPLSigningResult(t, txID, signingResults)
	validateXRPLSigningResult(t, walletID, result)

	t.Log("XRPL OfferCreate signing completed successfully")
}

// waitForXRPLSigningResult waits for a signing result with the given txID
func waitForXRPLSigningResult(t *testing.T, txID string, signingResults map[string]*event.SigningResultEvent) *event.SigningResultEvent {
	timeout := time.NewTimer(signingTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			t.Fatalf("Timeout waiting for XRPL signing result for tx %s", txID)
		case <-ticker.C:
			if result, exists := signingResults[txID]; exists {
				return result
			}
			t.Logf("Still waiting for signing result for tx %s...", txID)
		}
	}
}

// validateXRPLSigningResult validates an XRPL signing result
func validateXRPLSigningResult(t *testing.T, walletID string, result *event.SigningResultEvent) {
	logger.Info("Received XRPL signing result", "walletID", walletID, "result", result)

	if result.ResultType == event.ResultTypeError {
		t.Fatalf("XRPL signing failed for wallet %s: %s (%s)", walletID, result.ErrorReason, result.ErrorCode)
	}

	t.Logf("XRPL signing succeeded for wallet %s (tx: %s)", walletID, result.TxID)

	// XRPL uses ECDSA/secp256k1, so we expect R, S, and SignatureRecovery
	assert.NotEmpty(t, result.R, "XRPL ECDSA R value should not be empty")
	assert.NotEmpty(t, result.S, "XRPL ECDSA S value should not be empty")
	assert.NotEmpty(t, result.SignatureRecovery, "XRPL signature recovery should not be empty")

	// Verify signature can be composed
	composedSig, err := ComposeSignature(result.SignatureRecovery, result.R, result.S)
	if err != nil {
		t.Errorf("Failed to compose XRPL ECDSA signature: %v", err)
	} else {
		t.Logf("Successfully composed XRPL signature: %d bytes", len(composedSig))
		assert.Equal(t, 65, len(composedSig), "Composed XRPL signature should be 65 bytes")

		// Log signature components for debugging
		t.Logf("XRPL signature components - R: %d bytes, S: %d bytes, V: %d bytes",
			len(result.R), len(result.S), len(result.SignatureRecovery))
	}
}

// TestXRPLNetworkCodeValidation tests that XRPL network codes are correctly recognized
func TestXRPLNetworkCodeValidation(t *testing.T) {
	t.Run("XRPLMainnet", func(t *testing.T) {
		assert.True(t, types.IsNetworkSupported(string(types.NetworkXRPL)), "XRPL mainnet should be supported")
		assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPL), "XRPL should use secp256k1")
	})

	t.Run("XRPLTestnet", func(t *testing.T) {
		assert.True(t, types.IsNetworkSupported(string(types.NetworkXRPLTestnet)), "XRPL testnet should be supported")
		assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPLTestnet), "XRPL testnet should use secp256k1")
	})

	t.Run("XRPLDevnet", func(t *testing.T) {
		assert.True(t, types.IsNetworkSupported(string(types.NetworkXRPLDevnet)), "XRPL devnet should be supported")
		assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkXRPLDevnet), "XRPL devnet should use secp256k1")
	})
}

// TestLUXNetworkCodeValidation tests that LUX network codes are correctly recognized
func TestLUXNetworkCodeValidation(t *testing.T) {
	t.Run("LUXMainnet", func(t *testing.T) {
		assert.True(t, types.IsNetworkSupported(string(types.NetworkLUX)), "LUX mainnet should be supported")
		assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkLUX), "LUX should use secp256k1")
	})

	t.Run("LUXTestnet", func(t *testing.T) {
		assert.True(t, types.IsNetworkSupported(string(types.NetworkLUXTestnet)), "LUX testnet should be supported")
		assert.Equal(t, types.KeyTypeSecp256k1, types.GetNetworkKeyType(types.NetworkLUXTestnet), "LUX testnet should use secp256k1")
	})
}

// TestAllSupportedNetworks validates all network codes are properly configured
func TestAllSupportedNetworks(t *testing.T) {
	networks := []struct {
		code    types.NetworkCode
		name    string
		keyType types.KeyType
	}{
		{types.NetworkBTC, "BTC", types.KeyTypeSecp256k1},
		{types.NetworkBTCTestnet, "BTC-testnet", types.KeyTypeSecp256k1},
		{types.NetworkETH, "ETH", types.KeyTypeSecp256k1},
		{types.NetworkETHSepolia, "ETH-sepolia", types.KeyTypeSecp256k1},
		{types.NetworkETHGoerli, "ETH-goerli", types.KeyTypeSecp256k1},
		{types.NetworkSOL, "SOL", types.KeyTypeEd25519},
		{types.NetworkSOLDevnet, "SOL-devnet", types.KeyTypeEd25519},
		{types.NetworkSOLTestnet, "SOL-testnet", types.KeyTypeEd25519},
		{types.NetworkXRPL, "XRPL", types.KeyTypeSecp256k1},
		{types.NetworkXRPLTestnet, "XRPL-testnet", types.KeyTypeSecp256k1},
		{types.NetworkXRPLDevnet, "XRPL-devnet", types.KeyTypeSecp256k1},
		{types.NetworkLUX, "LUX", types.KeyTypeSecp256k1},
		{types.NetworkLUXTestnet, "LUX-testnet", types.KeyTypeSecp256k1},
		{types.NetworkTON, "TON", types.KeyTypeEd25519},
		{types.NetworkTONTestnet, "TON-testnet", types.KeyTypeEd25519},
	}

	for _, tc := range networks {
		t.Run(fmt.Sprintf("Network_%s", tc.name), func(t *testing.T) {
			assert.True(t, types.IsNetworkSupported(string(tc.code)),
				"%s should be supported", tc.name)
			assert.Equal(t, tc.keyType, types.GetNetworkKeyType(tc.code),
				"%s should use %s", tc.name, tc.keyType)
		})
	}
}
