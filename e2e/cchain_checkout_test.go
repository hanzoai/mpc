package e2e

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanzoai/mpc/pkg/event"
	mpctypes "github.com/hanzoai/mpc/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	// C-Chain RPC endpoint (local luxd)
	cchainRPC = "http://localhost:9650/ext/bc/C/rpc"

	// Test amounts
	testAmountWei = 1000000000000000 // 0.001 LUX

	// Timeouts
	txTimeout   = 60 * time.Second
	signTimeout = 5 * time.Minute
)

// TestCChainCryptoCheckout tests the full crypto checkout flow:
// 1. Generate MPC wallet
// 2. Fund the wallet with test LUX
// 3. Sign and broadcast a C-chain transaction using MPC
// 4. Verify transaction confirmation
func TestCChainCryptoCheckout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping C-chain integration test in short mode")
	}

	suite := NewE2ETestSuite(".")

	// Cleanup
	t.Log("Performing pre-test cleanup...")
	suite.CleanupTestEnvironment(t)
	defer func() {
		t.Log("Performing post-test cleanup...")
		suite.Cleanup(t)
	}()

	// Setup infrastructure including luxd
	t.Run("Setup", func(t *testing.T) {
		suite.SetupInfrastructure(t)
		suite.SetupTestNodes(t)

		err := suite.LoadConfig()
		require.NoError(t, err, "Failed to load config")

		suite.RegisterPeers(t)
		suite.StartNodes(t)
		suite.WaitForNodesReady(t)
		suite.SetupMPCClient(t)

		// Wait for luxd to be ready
		waitForLuxd(t)
	})

	var walletID string
	var walletAddress common.Address

	// Generate MPC wallet
	t.Run("GenerateWallet", func(t *testing.T) {
		walletID = uuid.New().String()
		suite.walletIDs = append(suite.walletIDs, walletID)

		// Setup result listener
		resultCh := make(chan *event.KeygenResultEvent, 1)
		err := suite.mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
			if result.WalletID == walletID {
				resultCh <- &result
			}
		})
		require.NoError(t, err)

		// Trigger keygen
		err = suite.mpcClient.CreateWallet(walletID)
		require.NoError(t, err, "Failed to create wallet")

		// Wait for result
		select {
		case result := <-resultCh:
			require.Equal(t, event.ResultTypeSuccess, result.ResultType, "Keygen failed: %s", result.ErrorReason)

			// Derive C-chain address from ECDSA public key
			// ECDSAPubKey is already []byte
			walletAddress = pubKeyToAddress(result.ECDSAPubKey)
			t.Logf("Generated wallet address: %s (pubkey: %s)", walletAddress.Hex(), hex.EncodeToString(result.ECDSAPubKey))

		case <-time.After(keygenTimeout):
			t.Fatal("Timeout waiting for keygen result")
		}
	})

	// Fund the wallet (using pre-funded test account)
	t.Run("FundWallet", func(t *testing.T) {
		client, err := ethclient.Dial(cchainRPC)
		require.NoError(t, err)
		defer client.Close()

		// Use the pre-funded genesis account for local network
		// This is a well-known test private key - NEVER use in production
		fundingKey := getFundingKey(t)

		// Send funds to MPC wallet
		err = sendFunds(t, client, fundingKey, walletAddress, big.NewInt(testAmountWei*10))
		require.NoError(t, err)

		// Verify balance
		balance, err := client.BalanceAt(context.Background(), walletAddress, nil)
		require.NoError(t, err)
		t.Logf("Wallet balance: %s wei", balance.String())
		assert.True(t, balance.Cmp(big.NewInt(testAmountWei)) >= 0, "Insufficient balance")
	})

	// Execute crypto checkout (MPC-signed transaction)
	t.Run("CryptoCheckout", func(t *testing.T) {
		client, err := ethclient.Dial(cchainRPC)
		require.NoError(t, err)
		defer client.Close()

		// Create transaction
		merchantAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")

		nonce, err := client.PendingNonceAt(context.Background(), walletAddress)
		require.NoError(t, err)

		gasPrice, err := client.SuggestGasPrice(context.Background())
		require.NoError(t, err)

		chainID, err := client.ChainID(context.Background())
		require.NoError(t, err)

		tx := types.NewTransaction(
			nonce,
			merchantAddress,
			big.NewInt(testAmountWei),
			21000,  // gas limit for simple transfer
			gasPrice,
			nil,    // no data
		)

		// Get transaction hash for signing
		signer := types.NewEIP155Signer(chainID)
		txHash := signer.Hash(tx)

		t.Logf("Transaction hash to sign: %s", txHash.Hex())

		// Request MPC signature
		signResultCh := make(chan *event.SigningResultEvent, 1)
		err = suite.mpcClient.OnSignResult(func(result event.SigningResultEvent) {
			if result.WalletID == walletID {
				signResultCh <- &result
			}
		})
		require.NoError(t, err)

		sessionID := uuid.New().String()
		signMsg := &mpctypes.SignTxMessage{
			KeyType:             mpctypes.KeyTypeSecp256k1,
			WalletID:            walletID,
			NetworkInternalCode: "LUX_CCHAIN",
			TxID:                sessionID,
			Tx:                  txHash.Bytes(),
		}
		err = suite.mpcClient.SignTransaction(signMsg)
		require.NoError(t, err)

		// Wait for signature
		var signResult *event.SigningResultEvent
		select {
		case signResult = <-signResultCh:
			require.Equal(t, event.ResultTypeSuccess, signResult.ResultType, "Signing failed: %s", signResult.ErrorReason)
			t.Logf("Received signature: R=%s, S=%s", hex.EncodeToString(signResult.R), hex.EncodeToString(signResult.S))

		case <-time.After(signTimeout):
			t.Fatal("Timeout waiting for signature")
		}

		// Reconstruct signed transaction
		r := new(big.Int).SetBytes(signResult.R)
		s := new(big.Int).SetBytes(signResult.S)
		// SignatureRecovery is []byte, get first byte as recovery ID
		recoveryID := 0
		if len(signResult.SignatureRecovery) > 0 {
			recoveryID = int(signResult.SignatureRecovery[0])
		}
		v := calculateV(chainID, recoveryID)

		signedTx, err := tx.WithSignature(signer, encodeSignature(r, s, v))
		require.NoError(t, err)

		// Broadcast transaction
		err = client.SendTransaction(context.Background(), signedTx)
		require.NoError(t, err)

		t.Logf("Transaction broadcast: %s", signedTx.Hash().Hex())

		// Wait for confirmation
		receipt, err := waitForReceipt(t, client, signedTx.Hash())
		require.NoError(t, err)
		require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "Transaction failed")

		t.Logf("Transaction confirmed in block %d", receipt.BlockNumber.Uint64())
	})

	t.Log("C-chain crypto checkout test completed successfully!")
}

// Helper functions

func waitForLuxd(t *testing.T) {
	t.Log("Waiting for luxd to be ready...")

	client, err := ethclient.Dial(cchainRPC)
	if err != nil {
		t.Logf("Initial connection failed, retrying...")
	}

	for i := 0; i < 30; i++ {
		if client == nil {
			client, err = ethclient.Dial(cchainRPC)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
		}

		_, err := client.ChainID(context.Background())
		if err == nil {
			t.Log("luxd is ready")
			client.Close()
			return
		}

		time.Sleep(2 * time.Second)
	}

	t.Fatal("Timeout waiting for luxd")
}

func pubKeyToAddress(pubKeyBytes []byte) common.Address {
	// For compressed public key, we need to decompress first
	// For uncompressed (65 bytes), skip the 0x04 prefix
	var pubKey *ecdsa.PublicKey
	var err error

	if len(pubKeyBytes) == 33 {
		// Compressed public key
		pubKey, err = crypto.DecompressPubkey(pubKeyBytes)
		if err != nil {
			fmt.Printf("Failed to decompress public key: %v\n", err)
			return common.Address{}
		}
	} else if len(pubKeyBytes) == 65 {
		// Uncompressed public key (with 0x04 prefix)
		pubKey, err = crypto.UnmarshalPubkey(pubKeyBytes)
		if err != nil {
			fmt.Printf("Failed to unmarshal public key: %v\n", err)
			return common.Address{}
		}
	} else {
		fmt.Printf("Invalid public key length: %d\n", len(pubKeyBytes))
		return common.Address{}
	}

	return crypto.PubkeyToAddress(*pubKey)
}

func getFundingKey(t *testing.T) *ecdsa.PrivateKey {
	// Pre-funded key for local network testing
	// This is the default genesis allocation key for local lux networks
	keyHex := "56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027"

	key, err := crypto.HexToECDSA(keyHex)
	require.NoError(t, err, "Failed to parse funding key")

	return key
}

func sendFunds(t *testing.T, client *ethclient.Client, from *ecdsa.PrivateKey, to common.Address, amount *big.Int) error {
	ctx := context.Background()

	fromAddress := crypto.PubkeyToAddress(from.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("failed to get gas price: %w", err)
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	tx := types.NewTransaction(nonce, to, amount, 21000, gasPrice, nil)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), from)
	if err != nil {
		return fmt.Errorf("failed to sign tx: %w", err)
	}

	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("failed to send tx: %w", err)
	}

	t.Logf("Funding tx sent: %s", signedTx.Hash().Hex())

	_, err = waitForReceipt(t, client, signedTx.Hash())
	return err
}

func waitForReceipt(t *testing.T, client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), txTimeout)
	defer cancel()

	for {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err == nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for receipt")
		case <-time.After(time.Second):
			// retry
		}
	}
}

func calculateV(chainID *big.Int, recoveryID int) *big.Int {
	// EIP-155: v = chainID * 2 + 35 + recovery_id
	v := new(big.Int).Mul(chainID, big.NewInt(2))
	v.Add(v, big.NewInt(35))
	v.Add(v, big.NewInt(int64(recoveryID)))
	return v
}

func encodeSignature(r, s, v *big.Int) []byte {
	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = byte(v.Uint64())

	return sig
}
