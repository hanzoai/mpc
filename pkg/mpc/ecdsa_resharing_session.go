package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	mpsProtocol "github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	lssConfig "github.com/luxfi/threshold/protocols/lss/config"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
)

// cggmp21ReshareSession implements ReshareSession for ECDSA using LSS for dynamic resharing
// Uses direct mpsProtocol.Handler with binary serialization like frost_keygen_session.go
type cggmp21ReshareSession struct {
	session
	isNewPeer      bool
	pubKeyResult   []byte
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	resultQueue    messaging.MessageQueue
	handler        *mpsProtocol.Handler
	lssConfig      *lssConfig.Config
	newThreshold   int
	newNodeIDs     []string
	messagesCh     chan *mpsProtocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	protocolLogger log.Logger
	pool           *pool.Pool
}

// newCGGMP21ReshareSession creates a new CGGMP21 reshare session
func newCGGMP21ReshareSession(
	walletID string,
	threshold int,
	newThreshold int,
	newNodeIDs []string,
	isNewPeer bool,
	pubSub messaging.PubSub,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	selfNodeID string,
) (*cggmp21ReshareSession, error) {
	// Generate session ID for resharing
	sessionID := fmt.Sprintf("reshare-%s", walletID)

	// Check if this node is in the NEW committee (required for participation)
	isInNewCommittee := false
	for _, id := range newNodeIDs {
		if id == selfNodeID {
			isInNewCommittee = true
			break
		}
	}

	// Check if this node has an existing key share (makes it an old peer)
	hasExistingShare := false
	if _, err := keyinfoStore.Get(walletID); err == nil {
		hasExistingShare = true
	}

	// Determine participation:
	// - Old peer (isNewPeer=false): Must have existing share AND be in new committee
	// - New peer (isNewPeer=true): Must NOT have existing share AND be in new committee
	if !isNewPeer {
		// For old peer session: must have share AND be in new committee
		if !hasExistingShare || !isInNewCommittee {
			return nil, nil
		}
	} else {
		// For new peer session: must NOT have share AND be in new committee
		if hasExistingShare || !isInNewCommittee {
			return nil, nil
		}
	}

	// Party IDs are the NEW committee (who will hold shares after reshare)
	var partyIDs []party.ID
	for _, id := range newNodeIDs {
		partyIDs = append(partyIDs, party.ID(id))
	}

	s := &cggmp21ReshareSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        party.ID(selfNodeID),
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             5, // LSS reshare has multiple rounds
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
					return fmt.Sprintf("reshare:broadcast:lss:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("reshare:direct:lss:%s:%s", nodeID, walletID)
				},
			},
			identityStore: nil, // Not needed for resharing
		},
		isNewPeer:    isNewPeer,
		kvstore:      kvstore,
		keyinfoStore: keyinfoStore,
		resultQueue:  resultQueue,
		newThreshold: newThreshold,
		newNodeIDs:   newNodeIDs,
		messagesCh:   make(chan *mpsProtocol.Message, 100),
		done:         false,
		pool:         pool.NewPool(0), // Use max threads
	}

	// Load existing LSS config for old peers
	if !isNewPeer {
		config, err := s.loadLSSConfig(walletID)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing LSS config: %w", err)
		}
		s.lssConfig = config
	}

	return s, nil
}

// Init initializes the reshare session
func (s *cggmp21ReshareSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Int("threshold", s.threshold).
		Int("newThreshold", s.newThreshold).
		Strs("newNodeIDs", s.newNodeIDs).
		Str("selfPartyID", string(s.selfPartyID)).
		Msg("[LSS-RESHARE] Initializing LSS reshare session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Convert party IDs
	newIDs := make([]party.ID, len(s.newNodeIDs))
	for i, id := range s.newNodeIDs {
		newIDs[i] = party.ID(id)
	}

	// Create the appropriate protocol start function
	var startFunc mpsProtocol.StartFunc
	ctx := context.Background()

	if s.isNewPeer {
		// New peers participate in fresh key generation with the new committee
		s.logger.Info().Msg("[LSS-RESHARE] Creating keygen for new peer")
		startFunc = lss.Keygen(curve.Secp256k1{}, s.selfPartyID, newIDs, s.newThreshold, s.pool)
	} else {
		// Old peers run the reshare protocol with NEW participants
		s.logger.Info().Msg("[LSS-RESHARE] Creating reshare for old peer")
		startFunc = lss.Reshare(s.lssConfig, newIDs, s.newThreshold, s.pool)
	}

	// Create handler with proper context, logging, and session ID
	sessionIDBytes := []byte(fmt.Sprintf("lss-reshare-%s", s.walletID))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		sessionIDBytes,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Error().Err(err).Msg("[LSS-RESHARE] Failed to create handler")
		s.errCh <- err
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Strs("newNodeIDs", s.newNodeIDs).
		Int("newThreshold", s.newThreshold).
		Msg("[LSS-RESHARE] Session initialized successfully")
}

// Reshare starts the resharing protocol - runs after Init
func (s *cggmp21ReshareSession) Reshare(done func()) {
	defer done()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Msg("[LSS-RESHARE] Starting reshare protocol")

	// Start listening for messages
	s.ListenToIncomingMessageAsync()
	go s.ProcessOutboundMessage()

	// Wait for protocol to complete - finishCh is triggered by handleProtocolMessages
	<-s.finishCh

	s.logger.Info().Msg("[LSS-RESHARE] Protocol finished, publishing result")
	s.publishResult()
}

// handleProtocolMessages handles messages from the protocol handler
func (s *cggmp21ReshareSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.logger.Info().Msg("[LSS-RESHARE] handler.Listen() returned !ok - protocol finished")
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.logger.Error().Err(err).Msg("[LSS-RESHARE] handler.Result() returned error")
					s.resultErr = err
					s.errCh <- err
				} else if cfg, ok := result.(*lssConfig.Config); ok {
					s.lssConfig = cfg
					s.logger.Info().Msg("[LSS-RESHARE] Got LSS config result")
				} else {
					s.logger.Error().Msgf("[LSS-RESHARE] Unexpected result type: %T", result)
					s.resultErr = fmt.Errorf("unexpected result type: %T", result)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message using MarshalBinary
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("[LSS-RESHARE] Failed to marshal protocol message")
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
				Msg("[LSS-RESHARE] Protocol emitted message")

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
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Msg("[LSS-RESHARE] Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Str("selfPartyID", string(s.selfPartyID)).
					Msg("[LSS-RESHARE] Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("[LSS-RESHARE] Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

// ListenToIncomingMessageAsync subscribes to protocol messages
// This override is required because the base session's method calls the base ProcessInboundMessage which panics
func (s *cggmp21ReshareSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("Received reshare broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	directTopic := s.topicComposer.ComposeDirectTopic(string(s.selfPartyID))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("Received reshare direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcastTopic", broadcastTopic).
		Str("directTopic", directTopic).
		Msg("Listening to incoming reshare messages")
}

// ProcessInboundMessage handles incoming protocol messages with proper binary deserialization
func (s *cggmp21ReshareSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("[LSS-RESHARE] ProcessInboundMessage unmarshal error")
		return
	}

	// Deduplication check using message body hash
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Deserialize the full protocol message from the body using UnmarshalBinary
	protoMsg := &mpsProtocol.Message{}
	if err := protoMsg.UnmarshalBinary(inboundMessage.Body); err != nil {
		s.logger.Error().Err(err).Msg("[LSS-RESHARE] Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("[LSS-RESHARE] Received protocol message")

	// Send to handler via messagesCh
	s.messagesCh <- protoMsg
}

// ProcessOutboundMessage handles outgoing protocol messages
func (s *cggmp21ReshareSession) ProcessOutboundMessage() {
	s.logger.Info().Str("sessionID", s.sessionID).Msg("[LSS-RESHARE] ProcessOutboundMessage started")

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
				Body:         m.Data, // Already binary serialized by handleProtocolMessages
				IsBroadcast:  m.IsBroadcast,
			}

			s.sendMsg(msgWireBytes)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("[LSS-RESHARE] Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("[LSS-RESHARE] Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

// GetPubKeyResult returns the public key after successful resharing
func (s *cggmp21ReshareSession) GetPubKeyResult() []byte {
	return s.pubKeyResult
}

// IsNewPeer returns true if this node is joining as a new peer
func (s *cggmp21ReshareSession) IsNewPeer() bool {
	return s.isNewPeer
}

// ErrChan returns the error channel
func (s *cggmp21ReshareSession) ErrChan() <-chan error {
	return s.errCh
}

// Stop stops the session
func (s *cggmp21ReshareSession) Stop() {
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
	if s.pool != nil {
		s.pool.TearDown()
	}
}

// WaitForFinish waits for the session to complete
func (s *cggmp21ReshareSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// publishResult publishes the reshare result
func (s *cggmp21ReshareSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("[LSS-RESHARE] Reshare failed with error")
		// Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.lssConfig == nil {
		s.logger.Error().Msg("[LSS-RESHARE] No config available after reshare completion")
		s.externalFinishChan <- ""
		return
	}

	// Save the new key share using CBOR (not JSON) to preserve curve types
	shareBytes, err := MarshalLSSConfig(s.lssConfig)
	if err != nil {
		s.logger.Error().Err(err).Msg("[LSS-RESHARE] Failed to marshal key share")
		s.externalFinishChan <- ""
		return
	}

	if err := s.kvstore.Put(s.walletID, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("[LSS-RESHARE] Failed to save key share for wallet %s", s.walletID)
		s.externalFinishChan <- ""
		return
	}

	// Update key info with new participants and threshold
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: s.newNodeIDs,
		Threshold:          s.newThreshold,
		Version:            1, // Increment version on reshare
		Curve:              "secp256k1",
	}

	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		s.logger.Error().Err(err).Msg("[LSS-RESHARE] Failed to save key info")
		s.externalFinishChan <- ""
		return
	}

	// Get public key hex from config
	var pubKeyHex string
	pubPoint, err := s.lssConfig.PublicPoint()
	if err == nil && pubPoint != nil {
		if xScalar := pubPoint.XScalar(); xScalar != nil {
			xBytes, _ := xScalar.MarshalBinary()
			pubKeyHex = fmt.Sprintf("%x", xBytes)
			s.pubKeyResult = xBytes
		}
	}

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Int("newThreshold", s.newThreshold).
		Strs("newNodeIDs", s.newNodeIDs).
		Msg("[LSS-RESHARE] Reshare completed successfully")

	// Notify via external finish channel
	s.externalFinishChan <- pubKeyHex
}

// loadLSSConfig loads the existing LSS configuration directly
func (s *cggmp21ReshareSession) loadLSSConfig(walletID string) (*lssConfig.Config, error) {
	// Load the key share data
	keyShareData, err := s.kvstore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key share: %w", err)
	}

	// Deserialize to LSS config using CBOR (not JSON) to preserve curve types
	config, err := UnmarshalLSSConfig(keyShareData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal as LSS config: %w", err)
	}

	return config, nil
}
