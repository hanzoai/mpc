package lss

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	log "github.com/luxfi/log"
	mpsEcdsa "github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	mpsProtocol "github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"

	"github.com/hanzoai/mpc/pkg/protocol"
)

// LSSProtocol implements the Protocol interface using LSS for dynamic resharing
type LSSProtocol struct {
	pool   *pool.Pool
	logger log.Logger
}

// NewLSSProtocol creates a new LSS protocol adapter
func NewLSSProtocol() *LSSProtocol {
	return &LSSProtocol{
		pool:   pool.NewPool(0), // Use max threads
		logger: log.NewTestLogger(log.InfoLevel),
	}
}

// Close cleans up resources
func (p *LSSProtocol) Close() {
	if p.pool != nil {
		p.pool.TearDown()
	}
}

// Name returns the protocol name
func (p *LSSProtocol) Name() string {
	return "LSS"
}

// KeyGen starts a distributed key generation using LSS
func (p *LSSProtocol) KeyGen(selfID string, partyIDs []string, threshold int) (protocol.Party, error) {
	// Convert string IDs to party.ID
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create the LSS keygen protocol
	startFunc := lss.Keygen(curve.Secp256k1{}, party.ID(selfID), ids, threshold, p.pool)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("lss-keygen-%s", selfID))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LSS keygen handler: %w", err)
	}

	return &lssPartyAdapter{
		handler: handler,
		selfID:  selfID,
	}, nil
}

// Refresh refreshes shares from an existing config (same committee)
func (p *LSSProtocol) Refresh(cfg protocol.KeyGenConfig) (protocol.Party, error) {
	// Convert to LSS config
	lssConfig, err := toLSSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Create refresh protocol (same parties)
	startFunc := lss.Refresh(lssConfig, p.pool)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("lss-refresh-%s", cfg.GetPartyID()))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LSS refresh handler: %w", err)
	}

	return &lssPartyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// Reshare performs dynamic resharing to change the participant set (LSS key feature!)
func (p *LSSProtocol) Reshare(cfg protocol.KeyGenConfig, newParticipants []string, newThreshold int) (protocol.Party, error) {
	// Convert to LSS config
	lssConfig, err := toLSSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert participant IDs
	newIDs := make([]party.ID, len(newParticipants))
	for i, id := range newParticipants {
		newIDs[i] = party.ID(id)
	}

	// Create reshare protocol with NEW participants and threshold
	startFunc := lss.Reshare(lssConfig, newIDs, newThreshold, p.pool)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("lss-reshare-%s", cfg.GetPartyID()))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LSS reshare handler: %w", err)
	}

	return &lssPartyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// Sign starts a signing protocol
func (p *LSSProtocol) Sign(cfg protocol.KeyGenConfig, signers []string, messageHash []byte) (protocol.Party, error) {
	// Convert to LSS config
	lssConfig, err := toLSSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create sign protocol
	startFunc := lss.Sign(lssConfig, signerIDs, messageHash, p.pool)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("lss-sign-%s-%x", cfg.GetPartyID(), messageHash[:8]))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LSS sign handler: %w", err)
	}

	return &lssPartyAdapter{
		handler: handler,
		selfID:  cfg.GetPartyID(),
	}, nil
}

// PreSign - LSS doesn't support presigning in the same way
func (p *LSSProtocol) PreSign(cfg protocol.KeyGenConfig, signers []string) (protocol.Party, error) {
	return nil, errors.New("LSS protocol does not support presigning")
}

// PreSignOnline - LSS doesn't support presigning
func (p *LSSProtocol) PreSignOnline(cfg protocol.KeyGenConfig, preSig protocol.PreSignature, messageHash []byte) (protocol.Party, error) {
	return nil, errors.New("LSS protocol does not support presigning")
}

// lssPartyAdapter adapts mpsProtocol.Handler to protocol.Party
type lssPartyAdapter struct {
	handler *mpsProtocol.Handler
	selfID  string
	mu      sync.Mutex
	done    bool
	result  interface{}
	err     error
}

func (p *lssPartyAdapter) Update(msg protocol.Message) error {
	// Convert to MPS message format
	var to party.ID
	if !msg.IsBroadcast() && len(msg.GetTo()) > 0 {
		to = party.ID(msg.GetTo()[0])
	}

	mpsMsg := &mpsProtocol.Message{
		From:      party.ID(msg.GetFrom()),
		To:        to,
		Broadcast: msg.IsBroadcast(),
		Data:      msg.GetData(),
	}

	// Check if handler can accept the message
	if !p.handler.CanAccept(mpsMsg) {
		return errors.New("message rejected by handler")
	}

	p.handler.Accept(mpsMsg)
	return nil
}

func (p *lssPartyAdapter) Messages() <-chan protocol.Message {
	ch := make(chan protocol.Message)

	go func() {
		defer close(ch)

		for {
			select {
			case msg, ok := <-p.handler.Listen():
				if !ok {
					// Protocol finished
					p.mu.Lock()
					p.done = true
					p.result, p.err = p.handler.Result()
					p.mu.Unlock()
					return
				}

				// Convert and send message
				var toList []string
				if !msg.Broadcast && msg.To != "" {
					toList = []string{string(msg.To)}
				}
				ch <- &messageAdapter{
					from:      string(msg.From),
					to:        toList,
					data:      msg.Data,
					broadcast: msg.Broadcast,
				}
			}
		}
	}()

	return ch
}

func (p *lssPartyAdapter) Errors() <-chan error {
	ch := make(chan error)
	close(ch)
	return ch
}

func (p *lssPartyAdapter) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

func (p *lssPartyAdapter) Result() (interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.done {
		return nil, errors.New("protocol not finished")
	}

	if p.err != nil {
		return nil, p.err
	}

	// Convert result to appropriate type
	switch r := p.result.(type) {
	case *config.Config:
		return &lssConfigAdapter{config: r}, nil
	case *mpsEcdsa.Signature:
		return &lssSignatureAdapter{sig: r}, nil
	default:
		return p.result, nil
	}
}

// messageAdapter implements protocol.Message
type messageAdapter struct {
	from      string
	to        []string
	data      []byte
	broadcast bool
}

func (m *messageAdapter) GetFrom() string   { return m.from }
func (m *messageAdapter) GetTo() []string   { return m.to }
func (m *messageAdapter) GetData() []byte   { return m.data }
func (m *messageAdapter) IsBroadcast() bool { return m.broadcast }

// lssConfigAdapter implements protocol.KeyGenConfig
type lssConfigAdapter struct {
	config *config.Config
}

func (c *lssConfigAdapter) GetPartyID() string {
	return string(c.config.ID)
}

func (c *lssConfigAdapter) GetThreshold() int {
	return c.config.Threshold
}

func (c *lssConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	point, err := c.config.PublicPoint()
	if err != nil || point == nil {
		return nil
	}
	// Convert curve.Point to ecdsa.PublicKey
	if point.XScalar() != nil {
		xBytes, _ := point.XScalar().MarshalBinary()
		x := new(big.Int).SetBytes(xBytes)
		return &ecdsa.PublicKey{
			Curve: nil,
			X:     x,
			Y:     new(big.Int), // Placeholder
		}
	}
	return nil
}

func (c *lssConfigAdapter) GetShare() *big.Int {
	if c.config.ECDSA != nil {
		bytes, _ := c.config.ECDSA.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (c *lssConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	if public, ok := c.config.Public[c.config.ID]; ok && public.ECDSA != nil {
		if public.ECDSA.XScalar() != nil {
			xBytes, _ := public.ECDSA.XScalar().MarshalBinary()
			x := new(big.Int).SetBytes(xBytes)
			return &ecdsa.PublicKey{
				Curve: nil,
				X:     x,
				Y:     new(big.Int),
			}
		}
	}
	return nil
}

func (c *lssConfigAdapter) GetPartyIDs() []string {
	ids := c.config.PartyIDs()
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}

func (c *lssConfigAdapter) Serialize() ([]byte, error) {
	return json.Marshal(c.config)
}

// lssSignatureAdapter implements protocol.Signature
type lssSignatureAdapter struct {
	sig *mpsEcdsa.Signature
}

func (s *lssSignatureAdapter) GetR() *big.Int {
	if s.sig.R != nil && s.sig.R.XScalar() != nil {
		bytes, _ := s.sig.R.XScalar().MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (s *lssSignatureAdapter) GetS() *big.Int {
	if s.sig.S != nil {
		bytes, _ := s.sig.S.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (s *lssSignatureAdapter) Verify(pubKey *ecdsa.PublicKey, message []byte) bool {
	return false
}

func (s *lssSignatureAdapter) Serialize() ([]byte, error) {
	return json.Marshal(s.sig)
}

// toLSSConfig converts a protocol.KeyGenConfig to *config.Config
func toLSSConfig(cfg protocol.KeyGenConfig) (*config.Config, error) {
	// Try to cast directly first
	if adapter, ok := cfg.(*lssConfigAdapter); ok {
		return adapter.config, nil
	}

	// Otherwise, try to deserialize from the stored data
	serialized, err := cfg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config for conversion: %w", err)
	}

	// Deserialize to LSS config
	lssConfig := lss.EmptyConfig(curve.Secp256k1{})
	if err := json.Unmarshal(serialized, lssConfig); err != nil {
		return nil, fmt.Errorf("failed to deserialize as LSS config: %w", err)
	}

	return lssConfig, nil
}

// ReshareProtocol is a specialized protocol interface that supports dynamic resharing
type ReshareProtocol interface {
	protocol.Protocol
	// Reshare performs dynamic resharing to change participants
	Reshare(cfg protocol.KeyGenConfig, newParticipants []string, newThreshold int) (protocol.Party, error)
}

// Ensure LSSProtocol implements ReshareProtocol
var _ ReshareProtocol = (*LSSProtocol)(nil)
