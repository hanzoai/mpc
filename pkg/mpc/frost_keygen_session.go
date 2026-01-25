package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
)

// FROSTKeygenSession interface for FROST keygen
type FROSTKeygenSession interface {
	Session
}

type frostKeygenSession struct {
	session
	handler        *protocol.Handler
	config         *frost.TaprootConfig
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	protocolLogger log.Logger
}

func newFROSTKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *frostKeygenSession {
	return &frostKeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             3, // FROST keygen has 3 rounds
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
					return fmt.Sprintf("keygen:broadcast:frost:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:frost:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

// ListenToIncomingMessageAsync subscribes to FROST keygen messages
func (s *frostKeygenSession) ListenToIncomingMessageAsync() {
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
	// Use extractNodeID to match how sendMsg publishes (strips :keygen:1 suffix)
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
		Msg("FROST: Listening to incoming messages")
}

func (s *frostKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("partyCount", len(s.partyIDs)).
		Str("selfPartyID", string(s.selfPartyID)).
		Msg("[FROST] Initializing FROST keygen session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)
	s.logger.Info().Msg("[FROST] Protocol logger created")

	// Create FROST keygen protocol for Taproot (Ed25519-based Schnorr)
	s.logger.Info().Msg("[FROST] Creating KeygenTaproot start function")
	startFunc := frost.KeygenTaproot(s.selfPartyID, s.partyIDs, s.threshold)
	s.logger.Info().Msg("[FROST] KeygenTaproot start function created")

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	s.logger.Info().Msg("[FROST] Creating protocol handler")
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.walletID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Error().Err(err).Msg("[FROST] ERROR: Failed to create handler")
		s.errCh <- err
		return
	}
	s.logger.Info().Msg("[FROST] Protocol handler created successfully")

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] FROST keygen session initialized successfully")
}

func (s *frostKeygenSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.logger.Info().Msg("[FROST-PROTOCOL] handler.Listen() returned !ok - protocol finished")
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.logger.Error().Err(err).Msg("[FROST-PROTOCOL] handler.Result() returned error")
					s.resultErr = err
					s.errCh <- err
				} else {
					s.config = result.(*frost.TaprootConfig)
					if s.config != nil {
						s.logger.Info().
							Int("publicKeyLen", len(s.config.PublicKey)).
							Str("publicKeyHex", fmt.Sprintf("%x", s.config.PublicKey)).
							Msg("[FROST-PROTOCOL] handler.Result() returned valid config")
					} else {
						s.logger.Warn().Msg("[FROST-PROTOCOL] handler.Result() returned nil config!")
					}
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
			s.logger.Info().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Hex("ssid", protoMsg.SSID).
				Int("dataLen", len(protoMsg.Data)).
				Msg("FROST: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Hex("ssid", protoMsg.SSID).
					Str("selfPartyID", string(s.selfPartyID)).
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

func (s *frostKeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("FROST: ProcessInboundMessage unmarshal error")
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

func (s *frostKeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("FROST: ProcessOutboundMessage started: %s", s.walletID)
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
			s.logger.Error().Err(err).Msg("FROST: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("FROST: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *frostKeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("FROST: keygen failed with error")
		failureEvent := event.CreateKeygenFailure(
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "FROST",
			},
		)
		evtData, _ := json.Marshal(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.mpc_keygen_result.%s", s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("FROST: failed to publish keygen failure event")
		}
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("FROST: No config available after keygen completion")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Save key share with frost prefix using CBOR (JSON doesn't preserve crypto types)
	shareBytes, err := MarshalFROSTConfig(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("FROST: Failed to marshal key share")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Save with frost: prefix to distinguish from ECDSA keys
	frostKey := fmt.Sprintf("frost:%s", s.walletID)
	if err := s.kvstore.Put(frostKey, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to save key share for wallet %s", s.walletID)
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Get public key hex
	var pubKeyHex string
	if s.config != nil && len(s.config.PublicKey) > 0 {
		pubKeyHex = fmt.Sprintf("%x", s.config.PublicKey)
		s.logger.Info().
			Int("configPubKeyLen", len(s.config.PublicKey)).
			Str("pubKeyHex", pubKeyHex).
			Msg("[FROST-PUBLISH] PublicKey available")
	} else {
		s.logger.Warn().
			Bool("configNil", s.config == nil).
			Int("configPubKeyLen", func() int { if s.config != nil { return len(s.config.PublicKey) }; return -1 }()).
			Msg("[FROST-PUBLISH] PublicKey is empty or config is nil!")
	}

	// Notify via external finish channel
	s.logger.Info().Str("sendingPubKeyHex", pubKeyHex).Msg("[FROST-PUBLISH] Sending to externalFinishChan")
	s.externalFinishChan <- pubKeyHex

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("FROST keygen completed successfully")
}

func (s *frostKeygenSession) Stop() {
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *frostKeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// GetPublicKey returns the EdDSA public key after keygen completes
func (s *frostKeygenSession) GetPublicKey() []byte {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	if s.config != nil {
		return s.config.PublicKey
	}
	return nil
}
