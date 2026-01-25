package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/rs/zerolog"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
)

type KeyGenSession interface {
	Session
}

type cggmp21KeygenSession struct {
	session
	handler        *protocol.Handler
	pool           *pool.Pool
	config         *config.Config
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	protocolLogger log.Logger
}

func newCGGMP21KeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *cggmp21KeygenSession {
	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &cggmp21KeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             5, // CGGMP21 keygen has 5 rounds
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         make(map[string]bool),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:cggmp21:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:cggmp21:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		pool:       threadPool,
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

// ListenToIncomingMessageAsync overrides the base session's method to call the correct ProcessInboundMessage
func (s *cggmp21KeygenSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("Received broadcast message")
		s.ProcessInboundMessage(m.Data) // Calls cggmp21KeygenSession's implementation
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	// Use extractNodeID to match the routing done in sendMsg
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("Received direct message")
		s.ProcessInboundMessage(m.Data) // Calls cggmp21KeygenSession's implementation
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("Listening to incoming messages")
}

func (s *cggmp21KeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Interface("partyIDs", s.partyIDs).
		Msg("Initializing CGGMP21 keygen session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create CGGMP21 keygen protocol
	startFunc := cmp.Keygen(curve.Secp256k1{}, s.selfPartyID, s.partyIDs, s.threshold, s.pool)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.walletID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create keygen handler")
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] CGGMP21 keygen session initialized successfully")
}

func (s *cggmp21KeygenSession) handleProtocolMessages() {
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
					s.config = result.(*config.Config)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message to preserve all fields (SSID, RoundNumber, etc.)
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("Failed to marshal protocol message")
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
				Msg("Protocol emitted message")

			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoBytes, // Use serialized protocol message
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			s.logger.Info().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Hex("ssid", protoMsg.SSID).
				Int("dataLen", len(protoMsg.Data)).
				Msg("Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Hex("ssid", protoMsg.SSID).
					Str("selfPartyID", string(s.selfPartyID)).
					Msg("Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

func (s *cggmp21KeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("ProcessInboundMessage unmarshal error")
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
		s.logger.Error().Err(err).Msg("Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("Received protocol message")

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *cggmp21KeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("ProcessOutboundMessage started: %s", s.walletID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}

			msgWireBytes := &types.Message{
				SessionID:    s.walletID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipientIDs,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			}

			s.sendMsg(msgWireBytes)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *cggmp21KeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("CGGMP21: keygen failed with error")
		failureEvent := event.CreateKeygenFailure(
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "CGGMP21",
			},
		)
		evtData, _ := json.Marshal(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.mpc_keygen_result.%s", s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("failed to publish keygen failure event")
		}
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("CGGMP21: No config available after keygen completion")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Save key share using binary marshaling (CBOR) - required for curve.Curve interface
	shareBytes, err := s.config.MarshalBinary()
	if err != nil {
		s.logger.Error().Err(err).Msg("CGGMP21: Failed to marshal key share")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if err := s.kvstore.Put(s.walletID, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("CGGMP21: Failed to save key share for wallet %s", s.walletID)
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Convert public key to hex
	// Use the X coordinate as a simple representation
	var pubKeyHex string
	if s.config != nil && s.config.PublicPoint() != nil {
		if xScalar := s.config.PublicPoint().XScalar(); xScalar != nil {
			xBytes, _ := xScalar.MarshalBinary()
			pubKeyHex = fmt.Sprintf("%x", xBytes)
		}
	}

	// Save key info
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: convertFromPartyIDs(s.partyIDs),
		Threshold:          s.threshold,
		Version:            1,
	}

	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		s.logger.Error().Err(err).Msgf("CGGMP21: Failed to save key info for wallet %s", s.walletID)
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// NOTE: Do NOT publish success event to queue here!
	// The handler (keygen_handler_cggmp21.go) is responsible for publishing
	// the combined result with both ECDSA and EdDSA keys.
	// We only send the pubkey to externalFinishChan so WaitForFinish() returns.

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("CGGMP21 keygen completed successfully, sending to externalFinishChan")

	// Send pubkey to externalFinishChan so handler can collect it
	s.externalFinishChan <- pubKeyHex
}

func (s *cggmp21KeygenSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *cggmp21KeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// Helper functions
func convertToPartyIDs(ids []string) []party.ID {
	result := make([]party.ID, len(ids))
	for i, id := range ids {
		result[i] = party.ID(id)
	}
	return result
}

func convertFromPartyIDs(ids []party.ID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		// Extract just the node ID (UUID) from party ID format "UUID:purpose:version"
		result[i] = extractNodeID(string(id))
	}
	return result
}
