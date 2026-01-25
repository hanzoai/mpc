package mpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/taproot"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/rs/zerolog"

	"github.com/hanzoai/mpc/pkg/encoding"
	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
)

// curve import used for extracting signature components

// FROSTSignSession is the interface for EdDSA signing sessions
type FROSTSignSession interface {
	Session
}

type frostSigningSession struct {
	session
	handler        *protocol.Handler
	pool           *pool.Pool
	config         *frost.TaprootConfig
	signature      taproot.Signature // 64-byte BIP-340 signature (R_x || s)
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	messageHash    []byte
	signerIDs      []party.ID
	useBroadcast   bool
	protocolLogger log.Logger
}

func newFROSTSigningSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	signerIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	useBroadcast bool,
) (*frostSigningSession, error) {
	// Load config from kvstore - FROST keys are stored with frost: prefix
	frostKey := fmt.Sprintf("frost:%s", walletID)
	shareBytes, err := kvstore.Get(frostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get FROST key share: %w", err)
	}

	// TaprootConfig is stored as CBOR (to properly preserve crypto types)
	config, err := UnmarshalFROSTConfig(shareBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal FROST key share: %w", err)
	}

	// BIP-340/Taproot requires 32-byte message hash
	// If message is not already 32 bytes, hash it with SHA-256
	var hashedMessage []byte
	if len(messageHash) == 32 {
		hashedMessage = messageHash
	} else {
		hash := sha256.Sum256(messageHash)
		hashedMessage = hash[:]
	}

	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &frostSigningSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           signerIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             3, // FROST signing has 3 rounds
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          config.Threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         make(map[string]bool),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:broadcast:frost:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:frost:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		pool:         threadPool,
		config:       config,
		messagesCh:   make(chan *protocol.Message, 100),
		messageHash:  hashedMessage, // Use the SHA-256 hashed message
		signerIDs:    signerIDs,
		useBroadcast: useBroadcast,
		done:         false,
	}, nil
}

// ListenToIncomingMessageAsync subscribes to FROST signing messages
func (s *frostSigningSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("FROST: Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("FROST: Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("FROST: Listening to incoming signing messages")
}

func (s *frostSigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("messageHash", s.messageHash).
		Interface("signerIDs", s.signerIDs).
		Bool("useBroadcast", s.useBroadcast).
		Msg("Initializing FROST signing session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create FROST Taproot signing protocol
	startFunc := frost.SignTaproot(s.config, s.signerIDs, s.messageHash)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.sessionID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create FROST signing handler")
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("partyID", string(s.selfPartyID)).
		Interface("signerIDs", s.signerIDs).
		Msg("[INITIALIZED] FROST signing session initialized successfully")
}

func (s *frostSigningSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.resultErr = err
					s.errCh <- err
				} else {
					// FROST Taproot signing returns taproot.Signature which is []byte (64 bytes)
					s.signature = result.(taproot.Signature)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("FROST: Failed to marshal protocol message")
				continue
			}

			// Determine recipients for routing
			var toPartyIDs []party.ID
			if !protoMsg.Broadcast && protoMsg.To != "" {
				toPartyIDs = []party.ID{protoMsg.To}
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("recipients", len(toPartyIDs)).
				Int("dataLen", len(protoBytes)).
				Msg("FROST: Protocol emitted message")

			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoBytes,
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("dataLen", len(protoMsg.Data)).
				Msg("FROST: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Bool("broadcast", protoMsg.Broadcast).
					Msg("FROST: Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("FROST: Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

func (s *frostSigningSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format
	inboundMessage := &types.Message{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("FROST: ProcessInboundMessage unmarshal error")
		return
	}

	// Deduplication check
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Deserialize the full protocol message from the body
	protoMsg := &protocol.Message{}
	if err := protoMsg.UnmarshalBinary(inboundMessage.Body); err != nil {
		s.logger.Error().Err(err).Msg("FROST: Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("FROST: Received protocol message")

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *frostSigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("FROST ProcessOutboundMessage started: %s", s.sessionID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}

			msgWireBytes := &types.Message{
				SessionID:    s.sessionID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipientIDs,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			}

			s.sendMsg(msgWireBytes)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("FROST: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("FROST: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *frostSigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "FROST",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("FROST: failed to publish sign failure event")
		}
		s.externalFinishChan <- ""
		return
	}

	if s.signature == nil || len(s.signature) != 64 {
		s.logger.Error().Int("sigLen", len(s.signature)).Msg("FROST: Invalid signature after signing completion (expected 64 bytes)")
		s.externalFinishChan <- ""
		return
	}

	// taproot.Signature is already in BIP-340 format: R_x (32 bytes) || s (32 bytes) = 64 bytes
	fullSignature := []byte(s.signature)

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("sigRX", fullSignature[:32]).
		Hex("sigZ", fullSignature[32:]).
		Int("sigLen", len(fullSignature)).
		Msg("FROST/Taproot signing completed successfully")

	// Create success event with EdDSA signature format
	successEvent := event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   s.walletID,
		TxID:       s.sessionID,
		// For EdDSA, use the Signature field with full 64-byte signature
		Signature: fullSignature,
	}

	evtData, _ := encoding.StructToJsonBytes(successEvent)
	if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
		s.logger.Error().Err(err).Msg("FROST: failed to publish sign success event")
	}

	// IMPORTANT: Send to externalFinishChan so WaitForFinish() unblocks
	s.externalFinishChan <- hex.EncodeToString(fullSignature)
}

func (s *frostSigningSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *frostSigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
