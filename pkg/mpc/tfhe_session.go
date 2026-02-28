// Copyright (c) 2024-2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/luxfi/fhe"
	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/messaging"
	"github.com/hanzoai/mpc/pkg/types"
	"github.com/hanzoai/mpc/pkg/utils"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/tfhe"
)

// TFHESession interface for threshold FHE operations
type TFHESession interface {
	Session
	// Encrypt encrypts a value using the threshold FHE scheme
	Encrypt(value uint64, fheType fhe.FheUintType) (*fhe.BitCiphertext, error)
	// CreateDecryptionShare creates this party's partial decryption share
	CreateDecryptionShare(ctx context.Context, ct *fhe.BitCiphertext) (*tfhe.DecryptionShare, error)
	// AddDecryptionShare adds a share from another party
	AddDecryptionShare(share *tfhe.DecryptionShare) error
	// Decrypt combines shares and decrypts (requires threshold shares)
	Decrypt(ctx context.Context, ct *fhe.BitCiphertext) (uint64, error)
	// CanDecrypt returns true if enough shares are collected
	CanDecrypt() bool
	// GetProtocol returns the underlying TFHE protocol
	GetProtocol() *tfhe.Protocol
}

// tfheKeygenSession handles threshold FHE key generation
type tfheKeygenSession struct {
	session
	params       fhe.Parameters
	threshold    int
	totalParties int
	pubKey       *fhe.PublicKey
	shares       map[party.ID]*tfhe.SecretKeyShare
	resultMutex  sync.Mutex
	done         bool
	resultErr    error
}

// newTFHEKeygenSession creates a new TFHE keygen session
func newTFHEKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	params fhe.Parameters,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *tfheKeygenSession {
	return &tfheKeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             2, // TFHE keygen is simpler - trusted dealer
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
					return fmt.Sprintf("tfhe:keygen:broadcast:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("tfhe:keygen:direct:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		params:       params,
		threshold:    threshold,
		totalParties: len(partyIDs),
		done:         false,
	}
}

func (s *tfheKeygenSession) ListenToIncomingMessageAsync() {
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("Received TFHE broadcast message")
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to TFHE broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, broadcastSub)

	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("Received TFHE direct message")
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to TFHE direct topic %s", directTopic)
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("Listening to TFHE incoming messages")
}

func (s *tfheKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("totalParties", s.totalParties).
		Msg("Initializing TFHE keygen session")

	// Create key generator
	kg, err := tfhe.NewKeyGenerator(s.threshold, s.totalParties, s.params, nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create TFHE key generator")
		s.errCh <- err
		return
	}

	// Generate keys (trusted dealer approach)
	parties := make([]party.ID, len(s.partyIDs))
	copy(parties, s.partyIDs)

	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate TFHE keys")
		s.errCh <- err
		return
	}

	s.pubKey = pubKey
	s.shares = shares

	s.logger.Info().
		Str("walletID", s.walletID).
		Int("numShares", len(shares)).
		Msg("[INITIALIZED] TFHE keygen session initialized")

	// Signal completion
	s.finishCh <- true
}

func (s *tfheKeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("TFHE ProcessInboundMessage unmarshal error")
		return
	}

	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	s.logger.Debug().
		Str("sender", inboundMessage.SenderID).
		Int("bodyLen", len(inboundMessage.Body)).
		Msg("Processing TFHE inbound message")
}

func (s *tfheKeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("TFHE ProcessOutboundMessage started: %s", s.walletID)
	for {
		select {
		case m := <-s.outCh:
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
			s.logger.Error().Err(err).Msg("TFHE received error")

		case <-s.finishCh:
			s.logger.Info().Msg("TFHE keygen finished")
			s.publishResult()
			return
		}
	}
}

func (s *tfheKeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("TFHE keygen failed")
		s.externalFinishChan <- ""
		return
	}

	// Get this party's share
	share, ok := s.shares[s.selfPartyID]
	if !ok {
		s.logger.Error().Msg("No share found for this party")
		s.externalFinishChan <- ""
		return
	}

	// Serialize and save the TFHE config
	config := &tfhe.Config{
		Threshold:      s.threshold,
		TotalParties:   s.totalParties,
		PartyID:        s.selfPartyID,
		Generation:     1,
		FHEParams:      s.params,
		PublicKey:      s.pubKey,
		SecretKeyShare: share,
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal TFHE config")
		s.externalFinishChan <- ""
		return
	}

	// Save with tfhe: prefix to distinguish from other key types
	tfheKey := fmt.Sprintf("tfhe:%s", s.walletID)
	if err := s.kvstore.Put(tfheKey, configBytes); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save TFHE config for %s", s.walletID)
		s.externalFinishChan <- ""
		return
	}

	// Save key info
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: convertFromPartyIDs(s.partyIDs),
		Threshold:          s.threshold,
		Version:            1,
		Curve:              "tfhe",
	}
	if err := s.keyinfoStore.Save(tfheKey, keyInfo); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save TFHE key info for %s", s.walletID)
		s.externalFinishChan <- ""
		return
	}

	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Msg("TFHE keygen completed successfully")

	s.externalFinishChan <- tfheKey
}

func (s *tfheKeygenSession) Stop() {
	close(s.outCh)
	close(s.errCh)
}

func (s *tfheKeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// tfheComputeSession handles threshold FHE encryption/decryption
type tfheComputeSession struct {
	session
	protocol    *tfhe.Protocol
	resultMutex sync.Mutex
}

// newTFHEComputeSession creates a session for TFHE computation
func newTFHEComputeSession(
	sessionID string,
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	participantIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) (*tfheComputeSession, error) {
	// Load TFHE config from kvstore
	tfheKey := fmt.Sprintf("tfhe:%s", walletID)
	configBytes, err := kvstore.Get(tfheKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get TFHE config: %w", err)
	}

	var config tfhe.Config
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TFHE config: %w", err)
	}

	// Create protocol
	protocol, err := tfhe.NewProtocol(&config, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TFHE protocol: %w", err)
	}

	return &tfheComputeSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           participantIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             1,
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
					return fmt.Sprintf("tfhe:compute:broadcast:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("tfhe:compute:direct:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		protocol: protocol,
	}, nil
}

func (s *tfheComputeSession) ListenToIncomingMessageAsync() {
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, broadcastSub)

	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.ProcessInboundMessage(m.Data)
	})
	if err != nil {
		s.errCh <- err
		return
	}
	s.subscriberList = append(s.subscriberList, directSub)
}

func (s *tfheComputeSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Msg("TFHE compute session initialized")
}

func (s *tfheComputeSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("TFHE compute unmarshal error")
		return
	}

	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Handle decryption share messages
	var share tfhe.DecryptionShare
	if err := json.Unmarshal(inboundMessage.Body, &share); err == nil {
		if err := s.protocol.AddDecryptionShare(&share); err != nil {
			s.logger.Error().Err(err).Msg("Failed to add decryption share")
		}
	}
}

func (s *tfheComputeSession) ProcessOutboundMessage() {
	for {
		select {
		case m := <-s.outCh:
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

		case <-s.errCh:
			// Handle errors

		case <-s.finishCh:
			return
		}
	}
}

func (s *tfheComputeSession) Stop() {
	close(s.outCh)
	close(s.errCh)
}

func (s *tfheComputeSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// Encrypt encrypts a value using TFHE
func (s *tfheComputeSession) Encrypt(value uint64, fheType fhe.FheUintType) (*fhe.BitCiphertext, error) {
	enc := s.protocol.GetEncryptor()
	if enc == nil {
		return nil, fmt.Errorf("encryptor not initialized")
	}
	return enc.EncryptUint64(value, fheType), nil
}

// CreateDecryptionShare creates this party's partial decryption
func (s *tfheComputeSession) CreateDecryptionShare(ctx context.Context, ct *fhe.BitCiphertext) (*tfhe.DecryptionShare, error) {
	return s.protocol.CreateDecryptionShare(ctx, ct)
}

// AddDecryptionShare adds a share from another party
func (s *tfheComputeSession) AddDecryptionShare(share *tfhe.DecryptionShare) error {
	return s.protocol.AddDecryptionShare(share)
}

// Decrypt combines shares and produces final decryption
func (s *tfheComputeSession) Decrypt(ctx context.Context, ct *fhe.BitCiphertext) (uint64, error) {
	plaintext, err := s.protocol.CombineShares(ctx, ct)
	if err != nil {
		return 0, err
	}
	// Convert bytes to uint64
	var result uint64
	for i := 0; i < len(plaintext) && i < 8; i++ {
		result |= uint64(plaintext[i]) << (8 * i)
	}
	return result, nil
}

// CanDecrypt returns true if enough shares are collected
func (s *tfheComputeSession) CanDecrypt() bool {
	return s.protocol.CanDecrypt()
}

// GetProtocol returns the underlying TFHE protocol
func (s *tfheComputeSession) GetProtocol() *tfhe.Protocol {
	return s.protocol
}
