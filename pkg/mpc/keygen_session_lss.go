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
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/rs/zerolog"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
)

// lssKeygenSession implements KeyGenSession using LSS protocol
// LSS supports dynamic resharing (changing participants), unlike CGGMP21
type lssKeygenSession struct {
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

func newLSSKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *lssKeygenSession {
	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &lssKeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             4, // LSS keygen has 4 rounds
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
					return fmt.Sprintf("keygen:broadcast:lss:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:lss:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		pool:       threadPool,
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

// ListenToIncomingMessageAsync subscribes to protocol messages
func (s *lssKeygenSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("dataLen", len(m.Data)).
			Msg("Received LSS broadcast message")
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.logger.Error().Err(err).Str("topic", broadcastTopic).Msg("Failed to subscribe to broadcast topic")
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, broadcastSub)
	s.logger.Info().Str("topic", broadcastTopic).Msg("Subscribed to LSS broadcast topic")

	// Subscribe to direct messages for this node
	// Use extractNodeID to match how sendMsg publishes (strips :keygen:1 suffix)
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("dataLen", len(m.Data)).
			Msg("Received LSS direct message")
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.logger.Error().Err(err).Str("topic", directTopic).Msg("Failed to subscribe to direct topic")
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, directSub)
	s.logger.Info().Str("topic", directTopic).Msg("Subscribed to LSS direct topic")
}

// Init creates the LSS protocol handler
func (s *lssKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Str("selfPartyID", string(s.selfPartyID)).
		Int("threshold", s.threshold).
		Int("numParties", len(s.partyIDs)).
		Msg("Initializing LSS keygen session (supports dynamic resharing)")

	// Create LSS protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create LSS keygen protocol
	startFunc := lss.Keygen(curve.Secp256k1{}, s.selfPartyID, s.partyIDs, s.threshold, s.pool)

	// Create protocol handler
	ctx := context.Background()
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.walletID), // Use walletID as session ID
		protocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create LSS keygen handler")
		return
	}
	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] LSS keygen session initialized successfully")
}

// handleProtocolMessages handles both outgoing and incoming protocol messages
func (s *lssKeygenSession) handleProtocolMessages() {
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
				s.logger.Error().Err(err).Msg("Failed to marshal LSS protocol message")
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
				Msg("LSS protocol emitted message")

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
				Msg("Received LSS protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Hex("ssid", protoMsg.SSID).
					Str("selfPartyID", string(s.selfPartyID)).
					Msg("LSS Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("LSS Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

// ProcessInboundMessage handles incoming protocol messages from the network
func (s *lssKeygenSession) ProcessInboundMessage(msgBytes []byte) {
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
		s.logger.Error().Err(err).Msg("Failed to unmarshal LSS protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("Received LSS protocol message")

	// Send to handler via channel
	s.messagesCh <- protoMsg
}

// ProcessOutboundMessage sends outgoing protocol messages to the network
func (s *lssKeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("LSS ProcessOutboundMessage started: %s", s.walletID)
	for {
		select {
		case m, ok := <-s.outCh:
			if !ok {
				s.logger.Info().Msg("LSS outCh closed")
				return
			}

			// Create wire message
			wireMsg := &types.Message{
				SessionID:   s.walletID,
				SenderID:    string(m.FromPartyID),
				Body:        m.Data,
				IsBroadcast: m.IsBroadcast,
			}

			if len(m.ToPartyIDs) > 0 {
				wireMsg.RecipientIDs = make([]string, len(m.ToPartyIDs))
				for i, id := range m.ToPartyIDs {
					wireMsg.RecipientIDs[i] = string(id)
				}
			}

			s.sendMsg(wireMsg)

		case <-s.finishCh:
			// Handle completion
			s.resultMutex.Lock()
			if s.resultErr != nil {
				s.publishFailure(fmt.Sprintf("LSS keygen failed: %s", s.resultErr.Error()))
				s.externalFinishChan <- ""
			} else if s.config != nil {
				// Save the config to storage
				if err := s.saveConfig(); err != nil {
					s.logger.Error().Err(err).Msg("Failed to save LSS keygen config")
					s.publishFailure(fmt.Sprintf("Failed to save config: %s", err.Error()))
					s.externalFinishChan <- ""
				} else {
					// Extract public key and send success
					pubKeyHex := s.extractPublicKey()
					s.logger.Info().
						Str("walletID", s.walletID).
						Str("pubKey", pubKeyHex).
						Msg("LSS keygen completed successfully (supports dynamic resharing)")
					s.externalFinishChan <- pubKeyHex
				}
			}
			s.resultMutex.Unlock()
			return
		}
	}
}

// saveConfig saves the LSS config to storage
func (s *lssKeygenSession) saveConfig() error {
	// Serialize the config using CBOR (not JSON) to preserve curve types
	configData, err := MarshalLSSConfig(s.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Save to kvstore
	if err := s.kvstore.Put(s.walletID, configData); err != nil {
		return fmt.Errorf("failed to save config to kvstore: %w", err)
	}

	// Save key info - extract just the node ID (UUID) from party ID format "UUID:purpose:version"
	partyIDStrings := make([]string, len(s.partyIDs))
	for i, id := range s.partyIDs {
		partyIDStrings[i] = extractNodeID(string(id))
	}

	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: partyIDStrings,
		Threshold:          s.threshold,
		Version:            1,
	}

	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		return fmt.Errorf("failed to save key info: %w", err)
	}

	s.logger.Info().
		Str("walletID", s.walletID).
		Int("numParties", len(partyIDStrings)).
		Int("threshold", s.threshold).
		Msg("LSS config saved to storage")

	return nil
}

// extractPublicKey extracts the public key from the config
func (s *lssKeygenSession) extractPublicKey() string {
	if s.config == nil {
		return ""
	}

	point, err := s.config.PublicPoint()
	if err != nil || point == nil {
		s.logger.Warn().Err(err).Msg("Failed to get public point from LSS config")
		return ""
	}

	// Marshal the point to bytes
	pointBytes, err := point.MarshalBinary()
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to marshal public point")
		return ""
	}

	return fmt.Sprintf("%x", pointBytes)
}

// publishFailure publishes a failure event to the result queue
func (s *lssKeygenSession) publishFailure(reason string) {
	failureEvent := &event.KeygenResultEvent{
		WalletID:    s.walletID,
		ResultType:  event.ResultTypeError,
		ErrorReason: reason,
	}

	payload, err := json.Marshal(failureEvent)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal failure event")
		return
	}

	key := fmt.Sprintf(TypeGenerateWalletResultFmt, s.walletID)
	if err := s.resultQueue.Enqueue(key, payload, nil); err != nil {
		s.logger.Error().Err(err).Msg("Failed to publish failure event")
	}
}

// ErrChan returns the error channel
func (s *lssKeygenSession) ErrChan() <-chan error {
	return s.errCh
}

// Stop stops the session
func (s *lssKeygenSession) Stop() {
	// Unsubscribe from all topics
	for _, sub := range s.subscriberList {
		if err := sub.Unsubscribe(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to unsubscribe")
		}
	}

	// Close the pool
	if s.pool != nil {
		s.pool.TearDown()
	}

	close(s.outCh)
	close(s.errCh)
}

// WaitForFinish waits for the session to complete and returns the public key
func (s *lssKeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
