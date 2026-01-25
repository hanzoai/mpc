package mpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	lssConfig "github.com/luxfi/threshold/protocols/lss/config"
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

// lssSigningSession implements SignSession using LSS protocol
// LSS supports dynamic resharing (changing participants), unlike CGGMP21
type lssSigningSession struct {
	session
	handler        *protocol.Handler
	pool           *pool.Pool
	config         *lssConfig.Config
	signature      *ecdsa.Signature
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	messageHash    []byte
	signerIDs      []party.ID
	useBroadcast   bool
	protocolLogger log.Logger
}

func newLSSSigningSession(
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
) (*lssSigningSession, error) {
	// Load config from kvstore
	shareBytes, err := kvstore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key share: %w", err)
	}

	// Create empty config with the correct group - REQUIRED for unmarshalling
	config := lss.EmptyConfig(curve.Secp256k1{})
	if err := json.Unmarshal(shareBytes, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key share: %w", err)
	}

	// Normalize message hash to 32 bytes (LSS requires exactly 32 bytes)
	// If the input is not 32 bytes, hash it with SHA-256
	normalizedHash := messageHash
	if len(messageHash) != 32 {
		hash := sha256.Sum256(messageHash)
		normalizedHash = hash[:]
	}

	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &lssSigningSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           signerIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             4, // LSS signing has 4 rounds
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
					return fmt.Sprintf("sign:broadcast:lss:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:lss:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		pool:         threadPool,
		config:       config,
		messagesCh:   make(chan *protocol.Message, 100),
		messageHash:  normalizedHash,
		signerIDs:    signerIDs,
		useBroadcast: useBroadcast,
		done:         false,
	}, nil
}

// ListenToIncomingMessageAsync subscribes to LSS signing messages
func (s *lssSigningSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("LSS: Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("LSS: Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	// Use extractNodeID to match how sendMsg publishes (strips any suffix)
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("LSS: Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("LSS: Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("LSS: Listening to incoming signing messages")
}

func (s *lssSigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("messageHash", s.messageHash).
		Interface("signerIDs", s.signerIDs).
		Bool("useBroadcast", s.useBroadcast).
		Msg("Initializing LSS signing session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create LSS signing protocol with blinding for ECDSA signatures
	// Note: lss.Sign() returns SchnorrSignature, but we need ecdsa.Signature
	// SignWithBlinding() returns *ecdsa.Signature which is what we need
	startFunc := lss.SignWithBlinding(s.config, s.signerIDs, s.messageHash, lss.BlindingProtocolI, s.pool)

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
		s.logger.Fatal().Err(err).Msg("Failed to create LSS signing handler")
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("partyID", string(s.selfPartyID)).
		Interface("signerIDs", s.signerIDs).
		Msg("[INITIALIZED] LSS signing session initialized successfully")
}

func (s *lssSigningSession) handleProtocolMessages() {
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
					s.signature = result.(*ecdsa.Signature)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message to preserve all fields (SSID, RoundNumber, etc.)
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("LSS: Failed to marshal protocol message")
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
				Msg("LSS: Protocol emitted message")

			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoBytes, // Use serialized protocol message
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("dataLen", len(protoMsg.Data)).
				Msg("LSS: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Bool("broadcast", protoMsg.Broadcast).
					Msg("LSS: Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("LSS: Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

func (s *lssSigningSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("LSS: ProcessInboundMessage unmarshal error")
		return
	}

	// Deduplication check using message body hash
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Deserialize the full protocol message from the body
	protoMsg := &protocol.Message{}
	if err := protoMsg.UnmarshalBinary(inboundMessage.Body); err != nil {
		s.logger.Error().Err(err).Msg("LSS: Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("LSS: Received protocol message")

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *lssSigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("LSS ProcessOutboundMessage started: %s", s.sessionID)
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
			s.logger.Error().Err(err).Msg("LSS: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("LSS: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *lssSigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "LSS",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("LSS: failed to publish sign failure event")
		}
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.signature == nil {
		s.logger.Error().Msg("LSS: No signature available after signing completion")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Verify signature
	pubPoint, err := s.config.PublicPoint()
	if err != nil {
		s.logger.Error().Err(err).Msg("LSS: Failed to get public point for verification")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if !s.signature.Verify(pubPoint, s.messageHash) {
		s.logger.Error().Msg("LSS: Failed to verify signature")
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    "signature verification failed",
				"protocol": "LSS",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("LSS: failed to publish sign failure event")
		}
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Convert signature to bytes
	// R is a curve.Point - MarshalBinary returns compressed format (0x02/0x03 || X)
	// We need just the X coordinate (32 bytes)
	sigRCompressed, _ := s.signature.R.MarshalBinary()
	sigRBytes := sigRCompressed
	if len(sigRCompressed) == 33 {
		// Strip the prefix byte to get raw X coordinate
		sigRBytes = sigRCompressed[1:]
	}
	sigSBytes, _ := s.signature.S.MarshalBinary()

	// Get public key bytes for recovery calculation
	pubPointBytes, err := pubPoint.MarshalBinary()
	if err != nil {
		s.logger.Error().Err(err).Msg("LSS: Failed to marshal public point for recovery calculation")
		s.externalFinishChan <- ""
		return
	}

	// Calculate recovery byte
	recoveryByte, err := CalculateRecoveryByte(sigRBytes, sigSBytes, s.messageHash, pubPointBytes)
	if err != nil {
		s.logger.Warn().Err(err).Msg("LSS: Failed to calculate recovery byte, using 0")
		recoveryByte = 0
	}

	s.logger.Debug().
		Uint8("recoveryByte", recoveryByte).
		Int("pubKeyLen", len(pubPointBytes)).
		Hex("sigR", sigRBytes).
		Hex("sigS", sigSBytes).
		Msg("LSS: Calculated signature recovery byte")

	// Publish success event with raw bytes
	successEvent := event.CreateSignSuccess(
		s.sessionID,
		s.walletID,
		sigRBytes,
		sigSBytes,
		recoveryByte,
		map[string]any{
			"messageHash": hex.EncodeToString(s.messageHash),
			"signers":     len(s.signerIDs),
			"protocol":    "LSS",
		},
	)

	evtData, _ := encoding.StructToJsonBytes(successEvent)
	if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
		s.logger.Error().Err(err).Msg("LSS: failed to publish sign success event")
	}

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("sigR", sigRBytes).
		Hex("sigS", sigSBytes).
		Uint8("recoveryByte", recoveryByte).
		Msg("LSS signing completed successfully")

	// IMPORTANT: Send to externalFinishChan so WaitForFinish() unblocks
	s.externalFinishChan <- hex.EncodeToString(sigRBytes)
}

func (s *lssSigningSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *lssSigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
