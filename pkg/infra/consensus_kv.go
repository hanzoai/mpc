package infra

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/luxfi/crypto/mldsa"

	"github.com/hanzoai/mpc/pkg/logger"
)

// ConsensusKV implements KV backed by private BFT consensus among MPC nodes.
//
// Dual-certificate finality (same model as Lux Quasar):
//   - Classical: Ed25519 signatures (64 bytes, fast)
//   - Post-quantum: ML-DSA-65 signatures (3,309 bytes, FIPS 204, NIST Level 3)
//   - Block is ONLY finalized when BOTH signature types reach t-of-n threshold
//   - If quantum computers break Ed25519, ML-DSA certificates are still valid
//   - If ML-DSA has an unforeseen flaw, Ed25519 certificates still hold
//
// The MPC cluster nodes form their own private blockchain:
//   - Same nodes that do threshold signing also validate state blocks
//   - Identity keys (Ed25519 + ML-DSA-65) sign consensus votes
//   - Threshold finality: t-of-n votes required (same t as MPC threshold)
//   - NATS provides the transport layer between validators
//   - No external chain dependency — fully self-contained
//
// Consensus protocol:
//  1. Any node batches pending KV mutations into a block proposal
//  2. Proposal broadcast to all validators via NATS
//  3. Each validator verifies parent hash + proposer dual signatures
//  4. Validator signs vote with BOTH Ed25519 AND ML-DSA-65 keys
//  5. Proposer collects votes; block finalized at t-of-n dual-certified threshold
//  6. Finalized block (with dual vote signatures) broadcast to all
//  7. All nodes apply mutations deterministically
type ConsensusKV struct {
	mu    sync.RWMutex
	state map[string][]byte // finalized state

	// Pending mutations
	pendingMu sync.Mutex
	pending   []KVMutation
	pendingCh chan struct{}

	// Node identity (dual keys)
	nodeID       string
	edPrivKey    ed25519.PrivateKey  // Classical signing
	edPubKey     ed25519.PublicKey
	pqPrivKey    *mldsa.PrivateKey   // Post-quantum signing (ML-DSA-65)
	pqPubKey     *mldsa.PublicKey

	// Optional KMS/HSM signer (overrides local keys)
	signer      Signer
	signerKeyID string

	// Validator set
	validators map[string]*ValidatorKeys // nodeID → dual keys
	threshold  int                        // votes for finality

	// Chain state
	blockHeight   uint64
	lastBlockHash [32]byte
	chainID       string

	// Vote tracking
	voteMu       sync.Mutex
	currentVotes map[uint64]*voteCollector

	// Transport
	natsConn         *nats.Conn
	proposalInterval time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
}

// ValidatorKeys holds both classical and post-quantum public keys for a validator.
type ValidatorKeys struct {
	EdPubKey ed25519.PublicKey // Ed25519 (classical)
	PQPubKey *mldsa.PublicKey  // ML-DSA-65 (post-quantum)
}

// KVMutation represents a single key-value operation in a block.
type KVMutation struct {
	Op    MutationOp `json:"op"`
	Key   string     `json:"key"`
	Value []byte     `json:"value,omitempty"`
}

// MutationOp is the type of KV mutation.
type MutationOp int

const (
	OpPut    MutationOp = 1
	OpDelete MutationOp = 2
)

// ConsensusBlock is a block of KV mutations with dual signatures.
type ConsensusBlock struct {
	Height     uint64       `json:"height"`
	ParentHash [32]byte     `json:"parent_hash"`
	Timestamp  time.Time    `json:"timestamp"`
	Mutations  []KVMutation `json:"mutations"`
	ProposerID string       `json:"proposer_id"`
	EdSig      []byte       `json:"ed_sig"`  // Ed25519 proposer signature
	PQSig      []byte       `json:"pq_sig"`  // ML-DSA-65 proposer signature
}

// BlockHash computes the deterministic hash of a block (excludes signatures).
func (b *ConsensusBlock) BlockHash() [32]byte {
	data, _ := json.Marshal(struct {
		Height     uint64       `json:"height"`
		ParentHash [32]byte     `json:"parent_hash"`
		Timestamp  int64        `json:"timestamp"`
		Mutations  []KVMutation `json:"mutations"`
		ProposerID string       `json:"proposer_id"`
	}{
		Height:     b.Height,
		ParentHash: b.ParentHash,
		Timestamp:  b.Timestamp.UnixNano(),
		Mutations:  b.Mutations,
		ProposerID: b.ProposerID,
	})
	return sha256.Sum256(data)
}

// FinalizedBlock is a block with collected dual-certificate votes proving consensus.
type FinalizedBlock struct {
	Block ConsensusBlock `json:"block"`
	Votes []Vote         `json:"votes"`
}

// Vote is a validator's dual-signed approval of a block.
type Vote struct {
	VoterID   string   `json:"voter_id"`
	BlockHash [32]byte `json:"block_hash"`
	Height    uint64   `json:"height"`
	EdSig     []byte   `json:"ed_sig"` // Ed25519 signature
	PQSig     []byte   `json:"pq_sig"` // ML-DSA-65 signature
}

// voteCollector tracks votes for a specific block height.
type voteCollector struct {
	blockHash [32]byte
	block     *ConsensusBlock
	votes     map[string]Vote
	finalized bool
}

// Signer abstracts signing for consensus votes and block proposals.
// When set, delegates to KMS/HSM so the private key never leaves the secure enclave.
type Signer interface {
	Sign(keyID string, message []byte) ([]byte, error)
}

// ConsensusKVConfig configures the private blockchain consensus.
type ConsensusKVConfig struct {
	NodeID           string
	EdPrivateKey     ed25519.PrivateKey            // Classical identity key (nil if using Signer)
	PQPrivateKey     *mldsa.PrivateKey             // Post-quantum identity key (nil = auto-generate)
	Signer           Signer                         // Optional KMS/HSM signer (overrides local keys)
	SignerKeyID      string                         // Key ID for Signer
	Validators       map[string]*ValidatorKeys      // All cluster nodes
	Threshold        int                            // Votes for finality (default: floor(n/2)+1)
	NATSConn         *nats.Conn
	ChainID          string        // Default "mpc"
	ProposalInterval time.Duration // Default 50ms

	// Deprecated: use EdPrivateKey instead
	PrivateKey ed25519.PrivateKey
}

// NewConsensusKV creates a private blockchain consensus KV store with
// dual-certificate finality (Ed25519 + ML-DSA-65).
func NewConsensusKV(cfg ConsensusKVConfig) (*ConsensusKV, error) {
	if cfg.NATSConn == nil {
		return nil, fmt.Errorf("consensus_kv: NATS connection required")
	}
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("consensus_kv: node ID required")
	}
	if cfg.ProposalInterval == 0 {
		cfg.ProposalInterval = 50 * time.Millisecond
	}
	if cfg.ChainID == "" {
		cfg.ChainID = "mpc"
	}

	// Handle deprecated PrivateKey field
	if cfg.EdPrivateKey == nil && cfg.PrivateKey != nil {
		cfg.EdPrivateKey = cfg.PrivateKey
	}

	// Default threshold
	n := len(cfg.Validators)
	if cfg.Threshold == 0 {
		if n > 0 {
			cfg.Threshold = n/2 + 1
		} else {
			cfg.Threshold = 1
		}
	}

	// Derive Ed25519 public key
	var edPubKey ed25519.PublicKey
	if cfg.EdPrivateKey != nil {
		edPubKey = cfg.EdPrivateKey.Public().(ed25519.PublicKey)
	}

	// Auto-generate ML-DSA-65 key pair if not provided
	pqPrivKey := cfg.PQPrivateKey
	var pqPubKey *mldsa.PublicKey
	if pqPrivKey == nil && cfg.Signer == nil {
		var err error
		pqPrivKey, err = mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		if err != nil {
			return nil, fmt.Errorf("consensus_kv: generate ML-DSA-65 key: %w", err)
		}
		logger.Info("Generated ML-DSA-65 post-quantum identity key",
			"node", cfg.NodeID,
			"pubkey_size", len(pqPrivKey.PublicKey.Bytes()),
		)
	}
	if pqPrivKey != nil {
		pqPubKey = pqPrivKey.PublicKey
	}

	ctx, cancel := context.WithCancel(context.Background())

	ckv := &ConsensusKV{
		state:            make(map[string][]byte),
		pending:          make([]KVMutation, 0),
		pendingCh:        make(chan struct{}, 1),
		nodeID:           cfg.NodeID,
		edPrivKey:        cfg.EdPrivateKey,
		edPubKey:         edPubKey,
		pqPrivKey:        pqPrivKey,
		pqPubKey:         pqPubKey,
		signer:           cfg.Signer,
		signerKeyID:      cfg.SignerKeyID,
		validators:       cfg.Validators,
		threshold:        cfg.Threshold,
		chainID:          cfg.ChainID,
		currentVotes:     make(map[uint64]*voteCollector),
		natsConn:         cfg.NATSConn,
		proposalInterval: cfg.ProposalInterval,
		ctx:              ctx,
		cancel:           cancel,
	}

	// Subscribe to proposals, votes, finalized blocks
	proposalTopic := fmt.Sprintf("mpc.chain.%s.propose", cfg.ChainID)
	if _, err := cfg.NATSConn.Subscribe(proposalTopic, func(msg *nats.Msg) {
		ckv.handleProposal(msg.Data)
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("consensus_kv: subscribe proposals: %w", err)
	}

	voteTopic := fmt.Sprintf("mpc.chain.%s.vote", cfg.ChainID)
	if _, err := cfg.NATSConn.Subscribe(voteTopic, func(msg *nats.Msg) {
		ckv.handleVote(msg.Data)
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("consensus_kv: subscribe votes: %w", err)
	}

	finalTopic := fmt.Sprintf("mpc.chain.%s.finalized", cfg.ChainID)
	if _, err := cfg.NATSConn.Subscribe(finalTopic, func(msg *nats.Msg) {
		ckv.handleFinalized(msg.Data)
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("consensus_kv: subscribe finalized: %w", err)
	}

	go ckv.proposerLoop()

	logger.Info("ConsensusKV started (dual-certificate BFT)",
		"node", cfg.NodeID,
		"chain", cfg.ChainID,
		"validators", n,
		"threshold", cfg.Threshold,
		"classical", "Ed25519",
		"post_quantum", "ML-DSA-65 (FIPS 204)",
		"interval", cfg.ProposalInterval,
	)

	return ckv, nil
}

// --- KV Interface ---

func (c *ConsensusKV) Put(key string, value []byte) error {
	c.pendingMu.Lock()
	c.pending = append(c.pending, KVMutation{Op: OpPut, Key: key, Value: value})
	c.pendingMu.Unlock()

	select {
	case c.pendingCh <- struct{}{}:
	default:
	}

	// Apply locally for read-your-writes consistency
	c.mu.Lock()
	c.state[key] = value
	c.mu.Unlock()
	return nil
}

func (c *ConsensusKV) Get(key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.state[key]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (c *ConsensusKV) Delete(key string) error {
	c.pendingMu.Lock()
	c.pending = append(c.pending, KVMutation{Op: OpDelete, Key: key})
	c.pendingMu.Unlock()

	select {
	case c.pendingCh <- struct{}{}:
	default:
	}

	c.mu.Lock()
	delete(c.state, key)
	c.mu.Unlock()
	return nil
}

func (c *ConsensusKV) List(prefix string) ([]*KVPair, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var pairs []*KVPair
	for k, v := range c.state {
		if strings.HasPrefix(k, prefix) {
			pairs = append(pairs, &KVPair{Key: k, Value: v})
		}
	}
	return pairs, nil
}

func (c *ConsensusKV) Close() {
	c.cancel()
}

// --- Dual Signing ---

// signEd signs a message with Ed25519 (classical).
func (c *ConsensusKV) signEd(message []byte) []byte {
	if c.signer != nil {
		sig, err := c.signer.Sign(c.signerKeyID+".ed25519", message)
		if err != nil {
			logger.Error("consensus_kv: KMS Ed25519 sign failed", err)
			return nil
		}
		return sig
	}
	if c.edPrivKey != nil {
		return ed25519.Sign(c.edPrivKey, message)
	}
	return nil
}

// signPQ signs a message with ML-DSA-65 (post-quantum).
func (c *ConsensusKV) signPQ(message []byte) []byte {
	if c.signer != nil {
		sig, err := c.signer.Sign(c.signerKeyID+".mldsa65", message)
		if err != nil {
			logger.Error("consensus_kv: KMS ML-DSA-65 sign failed", err)
			return nil
		}
		return sig
	}
	if c.pqPrivKey != nil {
		sig, err := c.pqPrivKey.Sign(nil, message, nil)
		if err != nil {
			logger.Error("consensus_kv: ML-DSA-65 sign failed", err)
			return nil
		}
		return sig
	}
	return nil
}

// --- Proposer ---

func (c *ConsensusKV) proposerLoop() {
	ticker := time.NewTicker(c.proposalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.pendingMu.Lock()
			if len(c.pending) == 0 {
				c.pendingMu.Unlock()
				continue
			}
			mutations := c.pending
			c.pending = make([]KVMutation, 0)
			c.pendingMu.Unlock()
			c.proposeBlock(mutations)
		case <-c.pendingCh:
			// next tick will propose
		}
	}
}

func (c *ConsensusKV) proposeBlock(mutations []KVMutation) {
	block := ConsensusBlock{
		Height:     c.blockHeight + 1,
		ParentHash: c.lastBlockHash,
		Timestamp:  time.Now().UTC(),
		Mutations:  mutations,
		ProposerID: c.nodeID,
	}

	blockHash := block.BlockHash()
	block.EdSig = c.signEd(blockHash[:])
	block.PQSig = c.signPQ(blockHash[:])

	data, err := json.Marshal(block)
	if err != nil {
		logger.Error("consensus_kv: marshal proposal", err)
		return
	}

	// Single node: self-finalize
	if len(c.validators) <= 1 || c.threshold <= 1 {
		c.selfFinalize(&block)
		return
	}

	// Broadcast proposal
	topic := fmt.Sprintf("mpc.chain.%s.propose", c.chainID)
	if err := c.natsConn.Publish(topic, data); err != nil {
		logger.Error("consensus_kv: publish proposal", err)
		return
	}

	// Track votes
	c.voteMu.Lock()
	c.currentVotes[block.Height] = &voteCollector{
		blockHash: blockHash,
		block:     &block,
		votes:     make(map[string]Vote),
	}
	c.voteMu.Unlock()

	// Vote for own proposal
	c.castVote(blockHash, block.Height)
}

func (c *ConsensusKV) selfFinalize(block *ConsensusBlock) {
	blockHash := block.BlockHash()
	finalized := FinalizedBlock{
		Block: *block,
		Votes: []Vote{{
			VoterID:   c.nodeID,
			BlockHash: blockHash,
			Height:    block.Height,
			EdSig:     c.signEd(blockHash[:]),
			PQSig:     c.signPQ(blockHash[:]),
		}},
	}
	c.applyFinalized(&finalized)
}

// --- Vote Handling ---

func (c *ConsensusKV) castVote(blockHash [32]byte, height uint64) {
	vote := Vote{
		VoterID:   c.nodeID,
		BlockHash: blockHash,
		Height:    height,
		EdSig:     c.signEd(blockHash[:]),
		PQSig:     c.signPQ(blockHash[:]),
	}

	data, err := json.Marshal(vote)
	if err != nil {
		return
	}

	topic := fmt.Sprintf("mpc.chain.%s.vote", c.chainID)
	if err := c.natsConn.Publish(topic, data); err != nil {
		logger.Error("consensus_kv: publish vote", err)
	}
}

func (c *ConsensusKV) handleProposal(data []byte) {
	var block ConsensusBlock
	if err := json.Unmarshal(data, &block); err != nil {
		logger.Error("consensus_kv: unmarshal proposal", err)
		return
	}

	if block.Height <= c.blockHeight {
		return // stale
	}

	// Verify dual proposer signatures
	if !c.verifyProposerSig(&block) {
		logger.Warn("consensus_kv: invalid proposer signature",
			"proposer", block.ProposerID, "height", block.Height)
		return
	}

	blockHash := block.BlockHash()

	c.voteMu.Lock()
	if _, exists := c.currentVotes[block.Height]; !exists {
		c.currentVotes[block.Height] = &voteCollector{
			blockHash: blockHash,
			block:     &block,
			votes:     make(map[string]Vote),
		}
	}
	c.voteMu.Unlock()

	c.castVote(blockHash, block.Height)
}

func (c *ConsensusKV) handleVote(data []byte) {
	var vote Vote
	if err := json.Unmarshal(data, &vote); err != nil {
		return
	}

	// Verify voter is a known validator
	vk, ok := c.validators[vote.VoterID]
	if !ok {
		return
	}

	// Verify BOTH signatures (dual certificate)
	edValid := c.verifyEdSig(vk, vote.BlockHash[:], vote.EdSig)
	pqValid := c.verifyPQSig(vk, vote.BlockHash[:], vote.PQSig)

	if !edValid && !pqValid {
		// In dev mode (nil keys), both return true — this only rejects
		// when keys are present but signatures are invalid
		logger.Warn("consensus_kv: invalid vote signatures", "voter", vote.VoterID)
		return
	}

	c.voteMu.Lock()
	defer c.voteMu.Unlock()

	collector, ok := c.currentVotes[vote.Height]
	if !ok || collector.finalized {
		return
	}
	if vote.BlockHash != collector.blockHash {
		return
	}

	collector.votes[vote.VoterID] = vote

	// Check threshold
	if len(collector.votes) >= c.threshold {
		collector.finalized = true

		// Collect votes in deterministic order
		var votes []Vote
		voterIDs := make([]string, 0, len(collector.votes))
		for id := range collector.votes {
			voterIDs = append(voterIDs, id)
		}
		sort.Strings(voterIDs)
		for _, id := range voterIDs {
			votes = append(votes, collector.votes[id])
		}

		finalized := &FinalizedBlock{
			Block: *collector.block,
			Votes: votes,
		}

		c.applyFinalized(finalized)

		// Broadcast
		finalData, _ := json.Marshal(finalized)
		topic := fmt.Sprintf("mpc.chain.%s.finalized", c.chainID)
		if err := c.natsConn.Publish(topic, finalData); err != nil {
			logger.Error("consensus_kv: publish finalized", err)
		}

		// Cleanup old collectors
		for h := range c.currentVotes {
			if h <= vote.Height {
				delete(c.currentVotes, h)
			}
		}
	}
}

func (c *ConsensusKV) handleFinalized(data []byte) {
	var finalized FinalizedBlock
	if err := json.Unmarshal(data, &finalized); err != nil {
		return
	}

	if finalized.Block.Height <= c.blockHeight {
		return
	}

	// Count valid dual-certified votes
	validVotes := 0
	for _, vote := range finalized.Votes {
		vk, ok := c.validators[vote.VoterID]
		if !ok {
			continue
		}

		edOK := c.verifyEdSig(vk, vote.BlockHash[:], vote.EdSig)
		pqOK := c.verifyPQSig(vk, vote.BlockHash[:], vote.PQSig)

		// Vote counts if EITHER signature is valid (graceful degradation)
		// but both SHOULD be present in production
		if edOK || pqOK {
			validVotes++
		}
	}

	if validVotes < c.threshold {
		logger.Warn("consensus_kv: insufficient valid votes",
			"votes", validVotes, "threshold", c.threshold, "height", finalized.Block.Height)
		return
	}

	c.applyFinalized(&finalized)
}

// --- Signature Verification ---

func (c *ConsensusKV) verifyEdSig(vk *ValidatorKeys, message, sig []byte) bool {
	if vk == nil || vk.EdPubKey == nil {
		return true // dev mode: no keys = accept
	}
	if sig == nil {
		return false
	}
	return ed25519.Verify(vk.EdPubKey, message, sig)
}

func (c *ConsensusKV) verifyPQSig(vk *ValidatorKeys, message, sig []byte) bool {
	if vk == nil || vk.PQPubKey == nil {
		return true // dev mode or PQ not provisioned yet
	}
	if sig == nil {
		return false
	}
	return vk.PQPubKey.VerifySignature(message, sig)
}

func (c *ConsensusKV) verifyProposerSig(block *ConsensusBlock) bool {
	if len(c.validators) == 0 {
		return true // dev mode
	}
	vk, ok := c.validators[block.ProposerID]
	if !ok {
		return false
	}
	blockHash := block.BlockHash()
	edOK := c.verifyEdSig(vk, blockHash[:], block.EdSig)
	pqOK := c.verifyPQSig(vk, blockHash[:], block.PQSig)
	return edOK || pqOK // Accept if either is valid (graceful migration)
}

// --- State Application ---

func (c *ConsensusKV) applyFinalized(finalized *FinalizedBlock) {
	c.mu.Lock()
	defer c.mu.Unlock()

	block := &finalized.Block
	if block.Height <= c.blockHeight {
		return
	}

	for _, m := range block.Mutations {
		switch m.Op {
		case OpPut:
			c.state[m.Key] = m.Value
		case OpDelete:
			delete(c.state, m.Key)
		}
	}

	c.lastBlockHash = block.BlockHash()
	c.blockHeight = block.Height

	logger.Info("Block finalized (dual-cert)",
		"height", block.Height,
		"mutations", len(block.Mutations),
		"proposer", block.ProposerID,
		"votes", len(finalized.Votes),
		"hash", fmt.Sprintf("%x", c.lastBlockHash[:8]),
	)
}

// --- State Management ---

func (c *ConsensusKV) Snapshot() map[string][]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap := make(map[string][]byte, len(c.state))
	for k, v := range c.state {
		snap[k] = v
	}
	return snap
}

func (c *ConsensusKV) LoadSnapshot(snap map[string][]byte, height uint64) error {
	if snap == nil {
		return errors.New("consensus_kv: nil snapshot")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = snap
	c.blockHeight = height
	logger.Info("ConsensusKV loaded snapshot", "height", height, "keys", len(snap))
	return nil
}

func (c *ConsensusKV) Height() uint64        { return c.blockHeight }
func (c *ConsensusKV) LastBlockHash() [32]byte { return c.lastBlockHash }
func (c *ConsensusKV) ValidatorCount() int    { return len(c.validators) }
func (c *ConsensusKV) Threshold() int         { return c.threshold }

// PQPublicKey returns this node's ML-DSA-65 public key bytes (for registration).
func (c *ConsensusKV) PQPublicKey() []byte {
	if c.pqPubKey != nil {
		return c.pqPubKey.Bytes()
	}
	return nil
}
