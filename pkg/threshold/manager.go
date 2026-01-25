package threshold

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hanzoai/mpc/pkg/protocol"
	"github.com/hanzoai/mpc/pkg/protocol/cggmp21"
	"github.com/hanzoai/mpc/pkg/protocol/frost"
)

// SignatureScheme represents the type of signature scheme
type SignatureScheme string

const (
	// SchemeECDSA represents ECDSA signature scheme (using CMP/CGGMP21)
	SchemeECDSA SignatureScheme = "ECDSA"
	// SchemeEdDSA represents EdDSA signature scheme (using FROST)
	SchemeEdDSA SignatureScheme = "EdDSA"
	// SchemeTaproot represents Taproot/Schnorr signature scheme (using FROST)
	SchemeTaproot SignatureScheme = "Taproot"
)

// Manager manages multiple threshold signature protocols
type Manager struct {
	protocols map[string]protocol.Protocol
	mu        sync.RWMutex
}

// NewManager creates a new protocol manager with all supported protocols
func NewManager() *Manager {
	m := &Manager{
		protocols: make(map[string]protocol.Protocol),
	}

	// Register default protocols
	m.RegisterProtocol("CGGMP21", cggmp21.NewCGGMP21Protocol())
	m.RegisterProtocol("FROST", frost.NewFROSTProtocol())

	return m
}

// RegisterProtocol registers a new protocol implementation
func (m *Manager) RegisterProtocol(name string, proto protocol.Protocol) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protocols[name] = proto
}

// GetProtocol returns a protocol by name
func (m *Manager) GetProtocol(name string) (protocol.Protocol, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	proto, ok := m.protocols[name]
	if !ok {
		return nil, fmt.Errorf("protocol %s not found", name)
	}
	return proto, nil
}

// GetProtocolForScheme returns the appropriate protocol for a signature scheme
func (m *Manager) GetProtocolForScheme(scheme SignatureScheme) (protocol.Protocol, error) {
	switch scheme {
	case SchemeECDSA:
		return m.GetProtocol("CGGMP21")
	case SchemeEdDSA, SchemeTaproot:
		return m.GetProtocol("FROST")
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %s", scheme)
	}
}

// ListProtocols returns a list of registered protocol names
func (m *Manager) ListProtocols() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.protocols))
	for name := range m.protocols {
		names = append(names, name)
	}
	return names
}

// Close cleans up all protocols
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, protocol := range m.protocols {
		// Check if protocol has a Close method
		if closer, ok := protocol.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

// UnifiedThresholdAPI provides a unified interface for threshold signing operations
type UnifiedThresholdAPI struct {
	manager *Manager
}

// NewUnifiedThresholdAPI creates a new unified threshold API
func NewUnifiedThresholdAPI() *UnifiedThresholdAPI {
	return &UnifiedThresholdAPI{
		manager: NewManager(),
	}
}

// KeyGen initiates distributed key generation for the specified scheme
func (api *UnifiedThresholdAPI) KeyGen(
	scheme SignatureScheme,
	selfID string,
	partyIDs []string,
	threshold int,
) (protocol.Party, error) {
	proto, err := api.manager.GetProtocolForScheme(scheme)
	if err != nil {
		return nil, err
	}

	return proto.KeyGen(selfID, partyIDs, threshold)
}

// Sign creates a threshold signature
func (api *UnifiedThresholdAPI) Sign(
	scheme SignatureScheme,
	config protocol.KeyGenConfig,
	signers []string,
	messageHash []byte,
) (protocol.Party, error) {
	// Validate that we have the right config type for the scheme
	if scheme == SchemeECDSA && config.GetPublicKey() == nil {
		return nil, errors.New("ECDSA scheme requires ECDSA public key in config")
	}

	proto, err := api.manager.GetProtocolForScheme(scheme)
	if err != nil {
		return nil, err
	}

	return proto.Sign(config, signers, messageHash)
}

// Refresh refreshes key shares
func (api *UnifiedThresholdAPI) Refresh(
	scheme SignatureScheme,
	config protocol.KeyGenConfig,
) (protocol.Party, error) {
	proto, err := api.manager.GetProtocolForScheme(scheme)
	if err != nil {
		return nil, err
	}

	return proto.Refresh(config)
}

// PreSign initiates presigning (only for ECDSA)
func (api *UnifiedThresholdAPI) PreSign(
	config protocol.KeyGenConfig,
	signers []string,
) (protocol.Party, error) {
	// PreSign is only supported by ECDSA protocols
	proto, err := api.manager.GetProtocol("CGGMP21")
	if err != nil {
		return nil, err
	}

	return proto.PreSign(config, signers)
}

// PreSignOnline completes a signature with a presignature (only for ECDSA)
func (api *UnifiedThresholdAPI) PreSignOnline(
	config protocol.KeyGenConfig,
	preSignature protocol.PreSignature,
	messageHash []byte,
) (protocol.Party, error) {
	// PreSignOnline is only supported by ECDSA protocols
	proto, err := api.manager.GetProtocol("CGGMP21")
	if err != nil {
		return nil, err
	}

	return proto.PreSignOnline(config, preSignature, messageHash)
}

// Close cleans up resources
func (api *UnifiedThresholdAPI) Close() {
	api.manager.Close()
}

// GetSupportedSchemes returns all supported signature schemes
func (api *UnifiedThresholdAPI) GetSupportedSchemes() []SignatureScheme {
	return []SignatureScheme{
		SchemeECDSA,
		SchemeEdDSA,
		SchemeTaproot,
	}
}

// IsSchemeSupported checks if a signature scheme is supported
func (api *UnifiedThresholdAPI) IsSchemeSupported(scheme SignatureScheme) bool {
	_, err := api.manager.GetProtocolForScheme(scheme)
	return err == nil
}
