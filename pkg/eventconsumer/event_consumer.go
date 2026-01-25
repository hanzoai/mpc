package eventconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/mpc"
	"github.com/hanzoai/mpc/pkg/types"
)

const (
	MPCGenerateEvent = "mpc:generate"
	MPCSignEvent     = "mpc:sign"
	MPCReshareEvent  = "mpc:reshare"

	DefaultConcurrentKeygen    = 2
	DefaultSessionStartupDelay = 500

	KeyGenTimeOut = 90 * time.Second // CGGMP21 keygen is expensive (prime generation)
)

type EventConsumer interface {
	Run()
	Close() error
}

type eventConsumer struct {
	node         *mpc.Node
	pubsub       messaging.PubSub
	mpcThreshold int

	genKeyResultQueue  messaging.MessageQueue
	signingResultQueue messaging.MessageQueue
	reshareResultQueue messaging.MessageQueue

	keyGenerationSub messaging.Subscription
	signingSub       messaging.Subscription
	reshareSub       messaging.Subscription
	identityStore    identity.Store
	keyinfoStore     keyinfo.Store

	msgBuffer           chan *nats.Msg
	maxConcurrentKeygen int

	// Track active sessions with timestamps for cleanup
	activeSessions  map[string]time.Time // Maps "walletID-txID" to creation time
	sessionsLock    sync.RWMutex
	cleanupInterval time.Duration // How often to run cleanup
	sessionTimeout  time.Duration // How long before a session is considered stale
	cleanupStopChan chan struct{} // Signal to stop cleanup goroutine
}

func NewEventConsumer(
	node *mpc.Node,
	pubsub messaging.PubSub,
	genKeyResultQueue messaging.MessageQueue,
	signingResultQueue messaging.MessageQueue,
	reshareResultQueue messaging.MessageQueue,
	identityStore identity.Store,
) EventConsumer {
	maxConcurrentKeygen := viper.GetInt("max_concurrent_keygen")
	if maxConcurrentKeygen == 0 {
		maxConcurrentKeygen = DefaultConcurrentKeygen
	}

	ec := &eventConsumer{
		node:                node,
		pubsub:              pubsub,
		genKeyResultQueue:   genKeyResultQueue,
		signingResultQueue:  signingResultQueue,
		reshareResultQueue:  reshareResultQueue,
		activeSessions:      make(map[string]time.Time),
		cleanupInterval:     5 * time.Minute,  // Run cleanup every 5 minutes
		sessionTimeout:      30 * time.Minute, // Consider sessions older than 30 minutes stale
		cleanupStopChan:     make(chan struct{}),
		mpcThreshold:        viper.GetInt("mpc_threshold"),
		maxConcurrentKeygen: maxConcurrentKeygen,
		identityStore:       identityStore,
		keyinfoStore:        node.KeyInfoStore(),
		msgBuffer:           make(chan *nats.Msg, 100),
	}

	go ec.startKeyGenEventWorker()
	// Start background cleanup goroutine
	go ec.sessionCleanupRoutine()

	return ec
}

func (ec *eventConsumer) Run() {
	err := ec.consumeKeyGenerationEvent()
	if err != nil {
		log.Fatal("Failed to consume key reconstruction event", err)
	}

	err = ec.consumeTxSigningEvent()
	if err != nil {
		log.Fatal("Failed to consume tx signing event", err)
	}

	err = ec.consumeReshareEvent()
	if err != nil {
		log.Fatal("Failed to consume reshare event", err)
	}

	logger.Info("MPC Event consumer started...!")
}

func (ec *eventConsumer) handleKeyGenEvent(natMsg *nats.Msg) {
	raw := natMsg.Data
	var msg types.GenerateKeyMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		logger.Error("Failed to unmarshal keygen message", err)
		ec.handleKeygenSessionError("", err, "Failed to unmarshal keygen message", natMsg)
		return
	}

	if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
		logger.Error("Failed to verify initiator message", err)
		ec.handleKeygenSessionError(msg.WalletID, err, "Failed to verify initiator message", natMsg)
		return
	}

	// Convert to event message format and use CGGMP21 handler
	eventMsg := &event.Message{
		EventType: MPCGenerateEvent,
		WalletID:  msg.WalletID,
	}
	ec.handleKeyGenEventCGGMP21(eventMsg, natMsg)
}

// handleKeygenSessionError handles errors that occur during key generation
func (ec *eventConsumer) handleKeygenSessionError(walletID string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)
	keygenResult := event.KeygenResultEvent{
		ResultType:  event.ResultTypeError,
		ErrorCode:   string(errorCode),
		WalletID:    walletID,
		ErrorReason: fullErrMsg,
	}

	keygenResultBytes, err := json.Marshal(keygenResult)
	if err != nil {
		logger.Error("Failed to marshal keygen result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, walletID)
	err = ec.genKeyResultQueue.Enqueue(key, keygenResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: composeKeygenIdempotentKey(walletID, natMsg),
	})
	if err != nil {
		logger.Error("Failed to enqueue keygen result event", err,
			"walletID", walletID,
			"payload", string(keygenResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) startKeyGenEventWorker() {
	// semaphore to limit concurrency
	semaphore := make(chan struct{}, ec.maxConcurrentKeygen)

	for natMsg := range ec.msgBuffer {
		semaphore <- struct{}{} // acquire a slot
		go func(msg *nats.Msg) {
			defer func() { <-semaphore }() // release the slot when done
			ec.handleKeyGenEvent(msg)
		}(natMsg)
	}
}

func (ec *eventConsumer) consumeKeyGenerationEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCGenerateEvent, func(natMsg *nats.Msg) {
		ec.msgBuffer <- natMsg
	})

	ec.keyGenerationSub = sub
	if err != nil {
		return err
	}
	return nil
}

func (ec *eventConsumer) consumeTxSigningEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCSignEvent, func(natMsg *nats.Msg) {
		raw := natMsg.Data
		var msg types.SignTxMessage
		err := json.Unmarshal(raw, &msg)
		if err != nil {
			logger.Error("Failed to unmarshal signing message", err)
			return
		}

		err = ec.identityStore.VerifyInitiatorMessage(&msg)
		if err != nil {
			logger.Error("Failed to verify initiator message", err)
			return
		}

		logger.Info(
			"Received signing event",
			"waleltID",
			msg.WalletID,
			"type",
			msg.KeyType,
			"tx",
			msg.TxID,
			"Id",
			ec.node.ID(),
		)

		// Route to appropriate signing handler based on key type
		switch msg.KeyType {
		case types.KeyTypeSecp256k1:
			// CGGMP21 for ECDSA (Secp256k1)
			ec.handleSigningEventCGGMP21(&msg, natMsg)
		case types.KeyTypeEd25519:
			// FROST for EdDSA (Ed25519)
			ec.handleSigningEventFROST(&msg, natMsg)
		default:
			logger.Error("Unsupported key type for signing", nil,
				"walletID", msg.WalletID,
				"txID", msg.TxID,
				"keyType", msg.KeyType,
			)
			ec.handleSigningSessionError(
				msg.WalletID,
				msg.TxID,
				msg.NetworkInternalCode,
				fmt.Errorf("unsupported key type: %v", msg.KeyType),
				"Unsupported key type",
				natMsg,
			)
			return
		}
	})

	ec.signingSub = sub
	if err != nil {
		return err
	}

	return nil
}
func (ec *eventConsumer) handleSigningSessionError(walletID, txID, networkInternalCode string, err error, contextMsg string, natMsg *nats.Msg) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Signing session error",
		"walletID", walletID,
		"txID", txID,
		"networkInternalCode", networkInternalCode,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	signingResult := event.SigningResultEvent{
		ResultType:          event.ResultTypeError,
		ErrorCode:           errorCode,
		NetworkInternalCode: networkInternalCode,
		WalletID:            walletID,
		TxID:                txID,
		ErrorReason:         fullErrMsg,
	}

	signingResultBytes, err := json.Marshal(signingResult)
	if err != nil {
		logger.Error("Failed to marshal signing result event", err,
			"walletID", walletID,
			"txID", txID,
		)
		return
	}
	err = ec.signingResultQueue.Enqueue(event.SigningResultCompleteTopic, signingResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: txID,
	})
	if err != nil {
		logger.Error("Failed to enqueue signing result event", err,
			"walletID", walletID,
			"txID", txID,
			"payload", string(signingResultBytes),
		)
	}
	ec.sendReplyToRemoveMsg(natMsg)
}

func (ec *eventConsumer) sendReplyToRemoveMsg(natMsg *nats.Msg) {
	msg := natMsg.Data

	logger.Info("sendReplyToRemoveMsg called", "hasReply", natMsg.Reply != "", "reply", natMsg.Reply)

	if natMsg.Reply == "" {
		logger.Warn("No reply inbox specified for sign success message", "msg", string(msg))
		return
	}

	err := ec.pubsub.Publish(natMsg.Reply, msg)
	if err != nil {
		logger.Error("Failed to reply message", err, "reply", natMsg.Reply)
		return
	}
	logger.Info("Successfully sent reply to inbox", "reply", natMsg.Reply)
}

func (ec *eventConsumer) consumeReshareEvent() error {
	sub, err := ec.pubsub.Subscribe(MPCReshareEvent, func(natMsg *nats.Msg) {
		var msg types.ResharingMessage
		if err := json.Unmarshal(natMsg.Data, &msg); err != nil {
			logger.Error("Failed to unmarshal resharing message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to unmarshal resharing message")
			return
		}

		if msg.SessionID == "" {
			ec.handleReshareSessionError(
				msg.WalletID,
				msg.KeyType,
				msg.NewThreshold,
				errors.New("validation: session ID is empty"),
				"Session ID is empty",
			)
			return
		}

		if err := ec.identityStore.VerifyInitiatorMessage(&msg); err != nil {
			logger.Error("Failed to verify initiator message", err)
			ec.handleReshareSessionError(msg.WalletID, msg.KeyType, msg.NewThreshold, err, "Failed to verify initiator message")
			return
		}

		walletID := msg.WalletID
		keyType := msg.KeyType

		sessionType, err := sessionTypeFromKeyType(keyType)
		if err != nil {
			logger.Error("Failed to get session type", err)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to get session type")
			return
		}

		createSession := func(isNewPeer bool) (mpc.ReshareSession, error) {
			return ec.node.CreateReshareSession(
				sessionType,
				walletID,
				ec.mpcThreshold,
				msg.NewThreshold,
				msg.NodeIDs,
				isNewPeer,
				ec.reshareResultQueue,
			)
		}

		oldSession, err := createSession(false)
		if err != nil {
			logger.Error("Failed to create old reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create old reshare session")
			return
		}
		newSession, err := createSession(true)
		if err != nil {
			logger.Error("Failed to create new reshare session", err, "walletID", walletID)
			ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to create new reshare session")
			return
		}

		if oldSession == nil && newSession == nil {
			logger.Info("Node is not participating in this reshare (neither old nor new)", "walletID", walletID)
			return
		}

		successEvent := &event.ResharingResultEvent{
			WalletID:     walletID,
			NewThreshold: msg.NewThreshold,
			KeyType:      msg.KeyType,
			ResultType:   event.ResultTypeSuccess,
		}

		var wg sync.WaitGroup
		ctx := context.Background()

		time.Sleep(DefaultSessionStartupDelay * time.Millisecond)

		if oldSession != nil {
			ctxOld, doneOld := context.WithCancel(ctx)
			oldSession.Init()
			// Note: ListenToIncomingMessageAsync is called inside Reshare() after party creation
			go oldSession.Reshare(doneOld)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxOld.Done():
						return
					case err := <-oldSession.ErrChan():
						logger.Error("Old reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Old reshare session error")
						doneOld() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		if newSession != nil {
			ctxNew, doneNew := context.WithCancel(ctx)
			newSession.Init()
			// Note: ListenToIncomingMessageAsync is called inside Reshare() after party creation
			go newSession.Reshare(doneNew)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctxNew.Done():
						successEvent.PubKey = newSession.GetPubKeyResult()
						return
					case err := <-newSession.ErrChan():
						logger.Error("New reshare session error", err)
						ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "New reshare session error")
						doneNew() // Cancel the context to stop this session
						return
					}
				}
			}()
		}

		wg.Wait()

		logger.Info("Reshare session finished", "walletID", walletID, "pubKey", fmt.Sprintf("%x", successEvent.PubKey))

		if newSession != nil {
			successBytes, err := json.Marshal(successEvent)
			if err != nil {
				logger.Error("Failed to marshal reshare success event", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to marshal reshare success event")
				return
			}

			key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, msg.SessionID)
			err = ec.reshareResultQueue.Enqueue(
				key,
				successBytes,
				&messaging.EnqueueOptions{
					IdempotententKey: key,
				})
			if err != nil {
				logger.Error("Failed to publish reshare success message", err)
				ec.handleReshareSessionError(walletID, keyType, msg.NewThreshold, err, "Failed to publish reshare success message")
				return
			}
			logger.Info("[COMPLETED RESHARE] Successfully published", "walletID", walletID)
		} else {
			logger.Info("[COMPLETED RESHARE] Done (not a new party)", "walletID", walletID)
		}
	})

	ec.reshareSub = sub
	return err
}

// handleReshareSessionError handles errors that occur during reshare operations
func (ec *eventConsumer) handleReshareSessionError(
	walletID string,
	keyType types.KeyType,
	newThreshold int,
	err error,
	contextMsg string,
) {
	fullErrMsg := fmt.Sprintf("%s: %v", contextMsg, err)
	errorCode := event.GetErrorCodeFromError(err)

	logger.Warn("Reshare session error",
		"walletID", walletID,
		"keyType", keyType,
		"newThreshold", newThreshold,
		"error", err.Error(),
		"errorCode", errorCode,
		"context", contextMsg,
	)

	reshareResult := event.ResharingResultEvent{
		ResultType:   event.ResultTypeError,
		ErrorCode:    string(errorCode),
		WalletID:     walletID,
		KeyType:      keyType,
		NewThreshold: newThreshold,
		ErrorReason:  fullErrMsg,
	}

	reshareResultBytes, err := json.Marshal(reshareResult)
	if err != nil {
		logger.Error("Failed to marshal reshare result event", err,
			"walletID", walletID,
		)
		return
	}

	key := fmt.Sprintf(mpc.TypeReshareWalletResultFmt, walletID)
	err = ec.reshareResultQueue.Enqueue(key, reshareResultBytes, &messaging.EnqueueOptions{
		IdempotententKey: key,
	})
	if err != nil {
		logger.Error("Failed to enqueue reshare result event", err,
			"walletID", walletID,
			"payload", string(reshareResultBytes),
		)
	}
}

// Add a cleanup routine that runs periodically
func (ec *eventConsumer) sessionCleanupRoutine() {
	ticker := time.NewTicker(ec.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ec.cleanupStaleSessions()
		case <-ec.cleanupStopChan:
			return
		}
	}
}

// Cleanup stale sessions
func (ec *eventConsumer) cleanupStaleSessions() {
	now := time.Now()
	ec.sessionsLock.Lock()
	defer ec.sessionsLock.Unlock()

	for sessionID, creationTime := range ec.activeSessions {
		if now.Sub(creationTime) > ec.sessionTimeout {
			delete(ec.activeSessions, sessionID)
		}
	}
}

// markSessionAsActive marks a session as active with the current timestamp
func (ec *eventConsumer) addSession(walletID, txID string) {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)
	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// trackSession tracks a new session
func (ec *eventConsumer) trackSession(walletID, txID string) {
	sessionID := walletID
	if txID != "" {
		sessionID = fmt.Sprintf("%s-%s", walletID, txID)
	}

	ec.sessionsLock.Lock()
	ec.activeSessions[sessionID] = time.Now()
	ec.sessionsLock.Unlock()
}

// untrackSession removes a session from tracking
func (ec *eventConsumer) untrackSession(walletID, txID string) {
	sessionID := walletID
	if txID != "" {
		sessionID = fmt.Sprintf("%s-%s", walletID, txID)
	}

	ec.sessionsLock.Lock()
	delete(ec.activeSessions, sessionID)
	ec.sessionsLock.Unlock()
}

// checkAndTrackSession checks if a session already exists and tracks it if new.
// Returns true if the session is a duplicate.
func (ec *eventConsumer) checkDuplicateSession(walletID, txID string) bool {
	sessionID := fmt.Sprintf("%s-%s", walletID, txID)

	// Check for duplicate
	ec.sessionsLock.RLock()
	_, isDuplicate := ec.activeSessions[sessionID]
	ec.sessionsLock.RUnlock()

	if isDuplicate {
		logger.Info("Duplicate signing request detected", "walletID", walletID, "txID", txID)
		return true
	}

	return false
}

// Close and clean up
func (ec *eventConsumer) Close() error {
	// Signal cleanup routine to stop
	close(ec.cleanupStopChan)

	err := ec.keyGenerationSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.signingSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = ec.reshareSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}

func sessionTypeFromKeyType(keyType types.KeyType) (mpc.SessionType, error) {
	switch keyType {
	case types.KeyTypeSecp256k1:
		return mpc.SessionTypeECDSA, nil
	case types.KeyTypeEd25519:
		return mpc.SessionTypeEDDSA, nil
	default:
		logger.Warn("Unsupported key type", "keyType", keyType)
		return "", fmt.Errorf("unsupported key type: %v", keyType)
	}
}

func composeKeygenIdempotentKey(walletID string, natMsg *nats.Msg) string {
	var uniqueKey string
	sid := natMsg.Header.Get("SessionID")
	if sid != "" {
		uniqueKey = fmt.Sprintf("%s:%s", walletID, sid)
	} else {
		uniqueKey = walletID
	}
	return fmt.Sprintf(mpc.TypeGenerateWalletResultFmt, uniqueKey)
}
