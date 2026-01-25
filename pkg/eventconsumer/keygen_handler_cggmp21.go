package eventconsumer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/mpc"
)

// handleKeyGenEventCGGMP21 handles key generation events for both CGGMP21 (ECDSA) and FROST (EdDSA)
func (ec *eventConsumer) handleKeyGenEventCGGMP21(msg *event.Message, natMsg *nats.Msg) {
	logger.Info(">>> KEYGEN-HANDLER START", "walletID", msg.WalletID)

	// Mark session as active
	ec.trackSession(msg.WalletID, "")

	// Remove session from active list when done
	defer ec.untrackSession(msg.WalletID, "")

	// Create a context with timeout for the entire key generation process
	baseCtx, cancel := context.WithTimeout(context.Background(), KeyGenTimeOut)
	defer cancel()

	// Decode the message
	if msg.EventType != MPCGenerateEvent {
		logger.Error("unexpected event type", nil, "expected", MPCGenerateEvent, "got", msg.EventType)
		return
	}

	walletID := msg.WalletID

	// Prepare success event
	successEvent := &event.KeygenResultEvent{
		WalletID:   walletID,
		ResultType: event.ResultTypeSuccess,
	}

	// Use WaitGroup to run both protocols in parallel
	var wg sync.WaitGroup
	var ecdsaErr, eddsaErr error
	var ecdsaPubKey, eddsaPubKey []byte
	var mu sync.Mutex

	// Run ECDSA (CGGMP21) keygen
	wg.Add(1)
	go func() {
		defer func() {
			logger.Info(">>> ECDSA GOROUTINE DONE (calling wg.Done)", "walletID", walletID)
			wg.Done()
		}()
		logger.Info(">>> ECDSA GOROUTINE STARTED", "walletID", walletID)
		pubKey, err := ec.runECDSAKeygen(baseCtx, walletID)
		logger.Info(">>> ECDSA KEYGEN RETURNED", "walletID", walletID, "pubKeyLen", len(pubKey), "err", err)
		mu.Lock()
		ecdsaErr = err
		ecdsaPubKey = pubKey
		mu.Unlock()
		logger.Info(">>> ECDSA GOROUTINE ABOUT TO EXIT", "walletID", walletID)
	}()

	// Run EdDSA (FROST) keygen
	wg.Add(1)
	go func() {
		defer func() {
			logger.Info(">>> EdDSA GOROUTINE DONE (calling wg.Done)", "walletID", walletID)
			wg.Done()
		}()
		logger.Info(">>> EdDSA GOROUTINE STARTED", "walletID", walletID)
		pubKey, err := ec.runEdDSAKeygen(baseCtx, walletID)
		logger.Info(">>> EdDSA KEYGEN RETURNED", "walletID", walletID, "pubKeyLen", len(pubKey), "err", err)
		mu.Lock()
		eddsaErr = err
		eddsaPubKey = pubKey
		mu.Unlock()
		logger.Info(">>> EdDSA GOROUTINE ABOUT TO EXIT", "walletID", walletID)
	}()

	// Wait for both to complete
	logger.Info(">>> WAITING FOR BOTH KEYGENS", "walletID", walletID)
	wg.Wait()

	// CRITICAL: Log immediately after wg.Wait() to see the values
	logger.Info("!!! CRITICAL: BOTH KEYGENS DONE !!!",
		"walletID", walletID,
		"ecdsaPubKeyLen", len(ecdsaPubKey),
		"eddsaPubKeyLen", len(eddsaPubKey),
		"eddsaPubKeyHex", fmt.Sprintf("%x", eddsaPubKey),
		"ecdsaErr", ecdsaErr,
		"eddsaErr", eddsaErr,
	)

	// Check for errors - ECDSA is required, EdDSA is optional for now
	if ecdsaErr != nil {
		ec.handleKeygenSessionError(walletID, ecdsaErr, "LSS (ECDSA) keygen error", natMsg)
		return
	}

	// Set the public keys
	successEvent.ECDSAPubKey = ecdsaPubKey
	if eddsaErr != nil {
		logger.Warn("EdDSA keygen failed, continuing with ECDSA only", "walletID", walletID, "error", eddsaErr)
	} else if len(eddsaPubKey) == 0 {
		// FROST returned nil, nil - no error but also no key
		logger.Warn("EdDSA keygen returned no public key (nil, nil)", "walletID", walletID)
	} else {
		successEvent.EDDSAPubKey = eddsaPubKey
		logger.Info("Setting EdDSA pubkey in event", "walletID", walletID, "len", len(eddsaPubKey), "hex", fmt.Sprintf("%x", eddsaPubKey))
	}

	// Marshal and publish success event
	payload, err := json.Marshal(successEvent)
	if err != nil {
		logger.Error("Failed to marshal keygen success event", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to marshal keygen success event", natMsg)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	if err := ec.genKeyResultQueue.Enqueue(
		key,
		payload,
		&messaging.EnqueueOptions{IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg)},
	); err != nil {
		logger.Error("Failed to publish key generation success message", err)
		ec.handleKeygenSessionError(walletID, err, "Failed to publish key generation success message", natMsg)
		return
	}

	ec.sendReplyToRemoveMsg(natMsg)
	logger.Info("[COMPLETED KEY GEN] Both ECDSA and EdDSA key generation completed", "walletID", walletID)
}

// runECDSAKeygen runs the CGGMP21 keygen for ECDSA
// CGGMP21 is used for proper ECDSA signatures compatible with Ethereum/Bitcoin
// Note: For dynamic resharing, LSS can be used but its signing produces Schnorr (not ECDSA)
func (ec *eventConsumer) runECDSAKeygen(ctx context.Context, walletID string) ([]byte, error) {
	// Create CGGMP21 keygen session for proper ECDSA signing
	keygenSession, err := ec.node.CreateKeyGenSession(walletID, ec.mpcThreshold, ec.genKeyResultQueue)
	if err != nil {
		return nil, fmt.Errorf("failed to create CGGMP21 key generation session: %w", err)
	}
	keygenSession.Init()

	// Channel to communicate errors
	errorChan := make(chan error, 1)

	// Monitor for errors in background
	go func() {
		select {
		case <-ctx.Done():
			return
		case err := <-keygenSession.ErrChan():
			if err != nil {
				logger.Error("CGGMP21 keygen session error", err)
				errorChan <- err
			}
		}
	}()

	// Start listening to messages
	keygenSession.ListenToIncomingMessageAsync()

	// Small delay for peer setup
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	// Start processing outbound messages
	go keygenSession.ProcessOutboundMessage()

	// Wait for the keygen to complete
	completionChan := make(chan string, 1)
	go func() {
		result := keygenSession.WaitForFinish()
		completionChan <- result
	}()

	// Wait for completion, error, or timeout
	select {
	case pubKeyHex := <-completionChan:
		if pubKeyHex != "" {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err == nil {
				logger.Info("CGGMP21 (ECDSA) keygen completed", "walletID", walletID, "pubKey", pubKeyHex)
				return pubKeyBytes, nil
			}
		}
		return nil, nil

	case err := <-errorChan:
		return nil, err

	case <-ctx.Done():
		return nil, fmt.Errorf("CGGMP21 (ECDSA) keygen session timed out")
	}
}

// runEdDSAKeygen runs the FROST keygen for EdDSA
func (ec *eventConsumer) runEdDSAKeygen(ctx context.Context, walletID string) ([]byte, error) {
	logger.Info("[FROST-DEBUG] Starting EdDSA keygen", "walletID", walletID)

	// Create FROST keygen session
	keygenSession, err := ec.node.CreateEdDSAKeyGenSession(walletID, ec.mpcThreshold, ec.genKeyResultQueue)
	if err != nil {
		logger.Error("[FROST-DEBUG] Failed to create session", err, "walletID", walletID)
		return nil, fmt.Errorf("failed to create FROST key generation session: %w", err)
	}
	logger.Info("[FROST-DEBUG] Session created, calling Init()", "walletID", walletID)
	keygenSession.Init()
	logger.Info("[FROST-DEBUG] Init() completed", "walletID", walletID)

	// Channel to communicate errors
	errorChan := make(chan error, 1)

	// Monitor for errors in background
	go func() {
		select {
		case <-ctx.Done():
			return
		case err := <-keygenSession.ErrChan():
			if err != nil {
				logger.Error("FROST keygen session error", err)
				errorChan <- err
			}
		}
	}()

	// Start listening to messages
	keygenSession.ListenToIncomingMessageAsync()

	// Small delay for peer setup
	time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

	// Start processing outbound messages
	go keygenSession.ProcessOutboundMessage()

	// Wait for the keygen to complete
	completionChan := make(chan string, 1)
	go func() {
		logger.Info("[FROST-DEBUG] Calling WaitForFinish()", "walletID", walletID)
		result := keygenSession.WaitForFinish()
		logger.Info("[FROST-DEBUG] WaitForFinish() returned", "walletID", walletID, "resultLen", len(result))
		completionChan <- result
	}()

	// Wait for completion, error, or timeout
	logger.Info("[FROST-DEBUG] Waiting on select", "walletID", walletID)
	select {
	case pubKeyHex := <-completionChan:
		logger.Info("[FROST-DEBUG] Received from completionChan", "walletID", walletID, "pubKeyHex", pubKeyHex)
		if pubKeyHex != "" {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err == nil {
				logger.Info("FROST (EdDSA) keygen completed", "walletID", walletID, "pubKey", pubKeyHex)
				return pubKeyBytes, nil
			}
			logger.Error("[FROST-DEBUG] Hex decode failed", err, "walletID", walletID, "pubKeyHex", pubKeyHex)
		}
		logger.Info("[FROST-DEBUG] pubKeyHex was empty", "walletID", walletID)
		return nil, nil

	case err := <-errorChan:
		return nil, err

	case <-ctx.Done():
		return nil, fmt.Errorf("EdDSA keygen session timed out")
	}
}
