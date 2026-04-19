package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/luxfi/mpc/pkg/client"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/nats-io/nats.go"
)

func main() {
	// Connect to NATS
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatal("Failed to connect to NATS:", err)
	}
	defer nc.Close()

	// Create MPC client
	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: nc,
		KeyPath:  "./event_initiator.key",
	})

	// Example 1: Sign an XRPL transaction
	signXRPLTransaction(mpcClient)
}

func signXRPLTransaction(mpcClient client.MPCClient) {
	fmt.Println("=== XRPL Transaction Signing Example ===")

	// In a real scenario, you would have a wallet ID from a previously created wallet
	walletID := "your-xrpl-wallet-id"

	// Example XRPL transaction data
	// In production, this would be a properly formatted XRPL transaction JSON
	// that has been serialized according to XRPL standards
	xrplTxJSON := `{
		"TransactionType": "Payment",
		"Account": "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH",
		"Destination": "rLNaPoKeeBjZe2qs6x52yVPZpZ8td4dc6w",
		"Amount": "1000000",
		"Fee": "12",
		"Sequence": 1,
		"SigningPubKey": "YOUR_PUBLIC_KEY_HERE"
	}`

	// Convert to bytes (in production, use proper XRPL serialization)
	txData := []byte(xrplTxJSON)
	txID := fmt.Sprintf("xrpl-tx-%s", uuid.New().String())

	// Create signing message
	signingMsg := &types.SignTxMessage{
		WalletID:            walletID,
		TxID:                txID,
		Tx:                  txData,
		KeyType:             types.KeyTypeSecp256k1, // XRPL uses secp256k1
		NetworkInternalCode: string(types.NetworkXRPL),
	}

	// Sign the message with initiator key
	_, err := signingMsg.Raw()
	if err != nil {
		log.Fatal("Failed to get raw message:", err)
	}

	// In production, use your actual initiator private key
	// signature, err := initiatorPrivKey.Sign(msg)
	// signingMsg.Signature = signature

	// Set up result listener
	resultChan := make(chan event.SigningResultEvent, 1)
	err = mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		if result.TxID == txID {
			resultChan <- result
		}
	})
	if err != nil {
		log.Fatal("Failed to set up result listener:", err)
	}

	// Send signing request
	fmt.Printf("Sending XRPL signing request for transaction: %s\n", txID)
	err = mpcClient.SignTransaction(signingMsg)
	if err != nil {
		log.Fatal("Failed to send signing request:", err)
	}

	// Wait for result
	select {
	case result := <-resultChan:
		if result.ResultType == event.ResultTypeSuccess {
			fmt.Println("✅ XRPL Transaction signed successfully!")
			fmt.Printf("Wallet ID: %s\n", result.WalletID)
			fmt.Printf("Transaction ID: %s\n", result.TxID)
			fmt.Printf("Network: %s\n", result.NetworkInternalCode)
			fmt.Printf("Signature (hex): %s\n", hex.EncodeToString(result.Signature))

			// The signature can now be added to the XRPL transaction
			// and submitted to the XRPL network
		} else {
			fmt.Printf("❌ Signing failed: %s\n", result.ErrorReason)
		}
	case <-time.After(30 * time.Second):
		fmt.Println("⏱️ Timeout waiting for signing result")
	}
}

// Example function showing how to verify network support
func verifyXRPLSupport() {
	networks := []string{
		string(types.NetworkXRPL),
		string(types.NetworkXRPLTestnet),
		string(types.NetworkXRPLDevnet),
	}

	fmt.Println("=== XRPL Network Support ===")
	for _, network := range networks {
		if types.IsNetworkSupported(network) {
			keyType := types.GetNetworkKeyType(types.NetworkCode(network))
			fmt.Printf("✅ %s is supported (uses %s)\n", network, keyType)
		} else {
			fmt.Printf("❌ %s is not supported\n", network)
		}
	}
}
