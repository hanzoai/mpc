package mpc

import (
	"fmt"
	"time"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"

	"github.com/hanzoai/mpc/pkg/identity"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/messaging"
)

const (
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	DefaultVersion int = 1
)

type ID string

type Node struct {
	nodeID        string
	peerIDs       []string
	pubSub        messaging.PubSub
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	identityStore identity.Store
	peerRegistry  PeerRegistry
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
) *Node {
	start := time.Now()
	elapsed := time.Since(start)
	logger.Info("Starting new CGGMP21 node", "nodeID", nodeID, "elapsed", elapsed.Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
	}

	go peerRegistry.WatchPeersReady()
	return node
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) KeyInfoStore() keyinfo.Store {
	return p.keyinfoStore
}

func (p *Node) CreateKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			p.peerRegistry.GetReadyPeersCount(),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, DefaultVersion)

	session := newCGGMP21KeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)

	// Note: Init() is called by the caller (keygen handler)
	return session, nil
}

// CreateEdDSAKeyGenSession creates a FROST keygen session for EdDSA
func (p *Node) CreateEdDSAKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (FROSTKeygenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			p.peerRegistry.GetReadyPeersCount(),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	// Use version 0 for FROST to create raw party IDs without suffixes
	// This is required for resharing compatibility - reshare sessions use raw node IDs
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, 0)

	session := newFROSTKeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)

	// Note: Init() is called by the caller (keygen handler)
	return session, nil
}

// CreateLSSKeyGenSession creates an LSS keygen session for ECDSA
// LSS supports dynamic resharing (changing participants), unlike CGGMP21
func (p *Node) CreateLSSKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			p.peerRegistry.GetReadyPeersCount(),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	// Use version 0 for LSS to create raw party IDs without suffixes
	// This is required for resharing compatibility - reshare sessions use raw node IDs
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, 0)

	session := newLSSKeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)

	// Note: Init() is called by the caller (keygen handler)
	return session, nil
}

func (p *Node) CreateSignSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	signerPeerIDs []string,
	resultQueue messaging.MessageQueue,
	useBroadcast bool,
) (SignSession, error) {
	// Check if we have enough signers
	keyInfo, err := p.keyinfoStore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	if len(signerPeerIDs) < keyInfo.Threshold+1 {
		return nil, ErrNotEnoughParticipants
	}

	// Check if this node is in the signer list
	if !contains(signerPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

	// Generate party IDs for signers using DefaultVersion and PurposeKeygen
	// IMPORTANT: Must use PurposeKeygen because the party IDs stored in the config
	// were created during keygen with "UUID:keygen:1" format
	selfPartyID, signerPartyIDs := p.generatePartyIDs(PurposeKeygen, signerPeerIDs, DefaultVersion)

	session, err := newCGGMP21SigningSession(
		sessionID,
		walletID,
		messageHash,
		p.pubSub,
		selfPartyID,
		signerPartyIDs,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		useBroadcast,
	)
	if err != nil {
		return nil, err
	}

	// Note: Init() is called by the caller (sign handler)
	return session, nil
}

// CreateEdDSASignSession creates a FROST signing session for EdDSA (Ed25519)
func (p *Node) CreateEdDSASignSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	signerPeerIDs []string,
	resultQueue messaging.MessageQueue,
	useBroadcast bool,
) (FROSTSignSession, error) {
	// Check if we have enough signers
	keyInfo, err := p.keyinfoStore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	if len(signerPeerIDs) < keyInfo.Threshold+1 {
		return nil, ErrNotEnoughParticipants
	}

	// Check if this node is in the signer list
	if !contains(signerPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

	// Generate party IDs for signers
	// FROST uses version 0 for raw party IDs without suffixes
	selfPartyID, signerPartyIDs := p.generatePartyIDs(PurposeKeygen, signerPeerIDs, 0)

	session, err := newFROSTSigningSession(
		sessionID,
		walletID,
		messageHash,
		p.pubSub,
		selfPartyID,
		signerPartyIDs,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		useBroadcast,
	)
	if err != nil {
		return nil, err
	}

	// Note: Init() is called by the caller (sign handler)
	return session, nil
}

func (p *Node) generatePartyIDs(purpose string, peerIDs []string, version int) (party.ID, []party.ID) {
	partyIDs := make([]party.ID, len(peerIDs))
	var selfPartyID party.ID

	for i, peerID := range peerIDs {
		partyID := createPartyID(peerID, purpose, version)
		partyIDs[i] = partyID
		if peerID == p.nodeID {
			selfPartyID = partyID
		}
	}

	return selfPartyID, partyIDs
}

func createPartyID(sessionID string, keyType string, version int) party.ID {
	if version == 0 {
		// Backward compatible version - just use sessionID
		return party.ID(sessionID)
	}
	// Include version in party ID
	return party.ID(fmt.Sprintf("%s:%s:%d", sessionID, keyType, version))
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	// In production, you might want to store and retrieve version info
	// For now, always use the default version
	return DefaultVersion
}

func (p *Node) CreateReshareSession(
	sessionType SessionType,
	walletID string,
	threshold int,
	newThreshold int,
	newNodeIDs []string,
	isNewPeer bool,
	resultQueue messaging.MessageQueue,
) (ReshareSession, error) {
	logger.Info("Creating reshare session",
		"sessionType", sessionType,
		"walletID", walletID,
		"threshold", threshold,
		"newThreshold", newThreshold,
		"newNodeIDs", newNodeIDs,
		"isNewPeer", isNewPeer,
		"nodeID", p.nodeID,
	)

	switch sessionType {
	case SessionTypeECDSA:
		session, err := newCGGMP21ReshareSession(
			walletID,
			threshold,
			newThreshold,
			newNodeIDs,
			isNewPeer,
			p.pubSub,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.nodeID,
		)
		// Explicitly return nil interface if session is nil
		// (prevents nil pointer inside non-nil interface)
		if session == nil {
			return nil, err
		}
		return session, err
	case SessionTypeEDDSA:
		session, err := newEdDSAReshareSession(
			walletID,
			threshold,
			newThreshold,
			newNodeIDs,
			isNewPeer,
			p.pubSub,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.nodeID,
		)
		// Explicitly return nil interface if session is nil
		if session == nil {
			return nil, err
		}
		return session, err
	default:
		return nil, fmt.Errorf("unsupported session type for reshare: %v", sessionType)
	}
}

// CreateTFHEKeyGenSession creates a threshold FHE key generation session
// TFHE enables computation on encrypted data using lattice-based cryptography
func (p *Node) CreateTFHEKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (*tfheKeygenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			p.peerRegistry.GetReadyPeersCount(),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	// TFHE uses version 0 for raw party IDs
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, 0)

	// Use default FHE parameters (128-bit security)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return nil, fmt.Errorf("failed to create FHE parameters: %w", err)
	}

	session := newTFHEKeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		params,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)

	return session, nil
}

// CreateTFHEComputeSession creates a session for threshold FHE computation
// Requires a wallet that was created with CreateTFHEKeyGenSession
func (p *Node) CreateTFHEComputeSession(
	sessionID string,
	walletID string,
	participantPeerIDs []string,
	resultQueue messaging.MessageQueue,
) (TFHESession, error) {
	// Check if this node is in the participant list
	if !contains(participantPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

	// Generate party IDs for participants
	selfPartyID, participantPartyIDs := p.generatePartyIDs(PurposeKeygen, participantPeerIDs, 0)

	session, err := newTFHEComputeSession(
		sessionID,
		walletID,
		p.pubSub,
		selfPartyID,
		participantPartyIDs,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
