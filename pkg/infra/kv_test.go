package infra

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/crypto/mldsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKV runs a standard suite of KV operations against any KV implementation.
// Used to verify 100% parity between consensus, NATS, and Consul backends.
func testKV(t *testing.T, kv KV) {
	t.Helper()

	// Put + Get
	err := kv.Put("ready/node0", []byte("true"))
	require.NoError(t, err)
	val, err := kv.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, []byte("true"), val)

	// Get non-existent
	val, err = kv.Get("ready/nonexistent")
	require.NoError(t, err)
	assert.Nil(t, val)

	// Put more keys
	require.NoError(t, kv.Put("ready/node1", []byte("true")))
	require.NoError(t, kv.Put("ready/node2", []byte("true")))
	require.NoError(t, kv.Put("threshold_keyinfo/wallet1", []byte(`{"threshold":2}`)))

	// List with prefix
	pairs, err := kv.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 3)
	keys := make(map[string]string)
	for _, p := range pairs {
		keys[p.Key] = string(p.Value)
	}
	assert.Equal(t, "true", keys["ready/node0"])
	assert.Equal(t, "true", keys["ready/node1"])
	assert.Equal(t, "true", keys["ready/node2"])

	// List different prefix
	pairs, err = kv.List("threshold_keyinfo/")
	require.NoError(t, err)
	assert.Len(t, pairs, 1)

	// Delete
	require.NoError(t, kv.Delete("ready/node1"))
	val, err = kv.Get("ready/node1")
	require.NoError(t, err)
	assert.Nil(t, val)

	// List after delete
	pairs, err = kv.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	// Delete non-existent (no error)
	require.NoError(t, kv.Delete("ready/nonexistent"))

	// Empty prefix
	pairs, err = kv.List("nothing/")
	require.NoError(t, err)
	assert.Len(t, pairs, 0)

	// Overwrite
	require.NoError(t, kv.Put("ready/node0", []byte("false")))
	val, err = kv.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, []byte("false"), val)
}

func newTestConsensusKV() *ConsensusKV {
	return &ConsensusKV{
		state:        make(map[string][]byte),
		pending:      make([]KVMutation, 0),
		pendingCh:    make(chan struct{}, 1),
		nodeID:       "test-node",
		validators:   make(map[string]*ValidatorKeys),
		threshold:    1,
		chainID:      "test",
		currentVotes: make(map[uint64]*voteCollector),
	}
}

func TestConsensusKV_KVInterface(t *testing.T) {
	testKV(t, newTestConsensusKV())
}

func TestConsensusKV_Snapshot(t *testing.T) {
	ckv := newTestConsensusKV()
	testKV(t, ckv)

	snap := ckv.Snapshot()
	assert.Contains(t, snap, "ready/node0")
	assert.Contains(t, snap, "ready/node2")
	assert.NotContains(t, snap, "ready/node1")

	ckv2 := newTestConsensusKV()
	require.NoError(t, ckv2.LoadSnapshot(snap, 42))
	assert.Equal(t, uint64(42), ckv2.Height())

	val, _ := ckv2.Get("ready/node0")
	assert.Equal(t, []byte("false"), val)
}

func TestConsensusKV_BlockHash(t *testing.T) {
	block := ConsensusBlock{
		Height:     1,
		Timestamp:  time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC),
		Mutations:  []KVMutation{{Op: OpPut, Key: "foo", Value: []byte("bar")}},
		ProposerID: "node0",
	}
	hash1 := block.BlockHash()
	hash2 := block.BlockHash()
	assert.Equal(t, hash1, hash2, "deterministic")

	block.Mutations[0].Value = []byte("baz")
	assert.NotEqual(t, hash1, block.BlockHash(), "different content = different hash")
}

func TestConsensusKV_BlockApply(t *testing.T) {
	ckv := newTestConsensusKV()

	block := ConsensusBlock{
		Height:    1,
		Timestamp: time.Now().UTC(),
		Mutations: []KVMutation{
			{Op: OpPut, Key: "ready/node0", Value: []byte("true")},
			{Op: OpPut, Key: "ready/node1", Value: []byte("true")},
		},
		ProposerID: "node0",
	}
	ckv.applyFinalized(&FinalizedBlock{
		Block: block,
		Votes: []Vote{{VoterID: "node0", BlockHash: block.BlockHash(), Height: 1}},
	})

	val, _ := ckv.Get("ready/node0")
	assert.Equal(t, []byte("true"), val)
	assert.Equal(t, uint64(1), ckv.Height())

	// Delete block
	block2 := ConsensusBlock{
		Height:     2,
		ParentHash: ckv.LastBlockHash(),
		Timestamp:  time.Now().UTC(),
		Mutations:  []KVMutation{{Op: OpDelete, Key: "ready/node1"}},
		ProposerID: "node0",
	}
	ckv.applyFinalized(&FinalizedBlock{
		Block: block2,
		Votes: []Vote{{VoterID: "node0", BlockHash: block2.BlockHash(), Height: 2}},
	})

	val, _ = ckv.Get("ready/node1")
	assert.Nil(t, val)
	assert.Equal(t, uint64(2), ckv.Height())
}

// TestConsensusKV_DualCertificate verifies Ed25519 + ML-DSA-65 dual signing.
func TestConsensusKV_DualCertificate(t *testing.T) {
	// Generate dual keys for 3 validators
	edPub0, edPriv0, _ := ed25519.GenerateKey(rand.Reader)
	edPub1, edPriv1, _ := ed25519.GenerateKey(rand.Reader)
	edPub2, _, _ := ed25519.GenerateKey(rand.Reader)

	pqPriv0, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pqPriv1, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pqPriv2, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	validators := map[string]*ValidatorKeys{
		"node0": {EdPubKey: edPub0, PQPubKey: pqPriv0.PublicKey},
		"node1": {EdPubKey: edPub1, PQPubKey: pqPriv1.PublicKey},
		"node2": {EdPubKey: edPub2, PQPubKey: pqPriv2.PublicKey},
	}

	// Node0 proposes a block with dual signatures
	block := ConsensusBlock{
		Height:     1,
		Timestamp:  time.Now().UTC(),
		Mutations:  []KVMutation{{Op: OpPut, Key: "ready/node0", Value: []byte("true")}},
		ProposerID: "node0",
	}
	blockHash := block.BlockHash()

	// Sign with Ed25519
	block.EdSig = ed25519.Sign(edPriv0, blockHash[:])
	assert.True(t, ed25519.Verify(edPub0, blockHash[:], block.EdSig))

	// Sign with ML-DSA-65
	pqSig0, err := pqPriv0.Sign(nil, blockHash[:], nil)
	require.NoError(t, err)
	block.PQSig = pqSig0
	assert.True(t, pqPriv0.PublicKey.VerifySignature(blockHash[:], pqSig0))

	// Node0 and Node1 cast dual-signed votes
	pqSig0Vote, _ := pqPriv0.Sign(nil, blockHash[:], nil)
	pqSig1Vote, _ := pqPriv1.Sign(nil, blockHash[:], nil)

	vote0 := Vote{
		VoterID:   "node0",
		BlockHash: blockHash,
		Height:    1,
		EdSig:     ed25519.Sign(edPriv0, blockHash[:]),
		PQSig:     pqSig0Vote,
	}
	vote1 := Vote{
		VoterID:   "node1",
		BlockHash: blockHash,
		Height:    1,
		EdSig:     ed25519.Sign(edPriv1, blockHash[:]),
		PQSig:     pqSig1Vote,
	}

	// Verify both signatures on both votes
	assert.True(t, ed25519.Verify(edPub0, blockHash[:], vote0.EdSig))
	assert.True(t, pqPriv0.PublicKey.VerifySignature(blockHash[:], vote0.PQSig))
	assert.True(t, ed25519.Verify(edPub1, blockHash[:], vote1.EdSig))
	assert.True(t, pqPriv1.PublicKey.VerifySignature(blockHash[:], vote1.PQSig))

	// Apply finalized block to node2
	ckv := &ConsensusKV{
		state:        make(map[string][]byte),
		pending:      make([]KVMutation, 0),
		pendingCh:    make(chan struct{}, 1),
		nodeID:       "node2",
		validators:   validators,
		threshold:    2,
		chainID:      "test",
		currentVotes: make(map[uint64]*voteCollector),
	}

	finalized := FinalizedBlock{Block: block, Votes: []Vote{vote0, vote1}}
	ckv.applyFinalized(&finalized)

	val, _ := ckv.Get("ready/node0")
	assert.Equal(t, []byte("true"), val)
	assert.Equal(t, uint64(1), ckv.Height())
}

// TestConsensusKV_DualCertVerification tests that handleFinalized verifies signatures.
func TestConsensusKV_DualCertVerification(t *testing.T) {
	edPub0, edPriv0, _ := ed25519.GenerateKey(rand.Reader)
	edPub1, _, _ := ed25519.GenerateKey(rand.Reader)
	edPub2, _, _ := ed25519.GenerateKey(rand.Reader)

	pqPriv0, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	pqPriv1, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	pqPriv2, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	validators := map[string]*ValidatorKeys{
		"node0": {EdPubKey: edPub0, PQPubKey: pqPriv0.PublicKey},
		"node1": {EdPubKey: edPub1, PQPubKey: pqPriv1.PublicKey},
		"node2": {EdPubKey: edPub2, PQPubKey: pqPriv2.PublicKey},
	}

	ckv := &ConsensusKV{
		state:        make(map[string][]byte),
		pending:      make([]KVMutation, 0),
		pendingCh:    make(chan struct{}, 1),
		nodeID:       "node2",
		validators:   validators,
		threshold:    2, // need 2 votes
		chainID:      "test",
		currentVotes: make(map[uint64]*voteCollector),
	}

	block := ConsensusBlock{
		Height:     1,
		Timestamp:  time.Now().UTC(),
		Mutations:  []KVMutation{{Op: OpPut, Key: "test/key", Value: []byte("val")}},
		ProposerID: "node0",
	}
	blockHash := block.BlockHash()

	// Only 1 valid dual-signed vote — should NOT apply (threshold=2)
	pqSig, _ := pqPriv0.Sign(nil, blockHash[:], nil)
	finalized := FinalizedBlock{
		Block: block,
		Votes: []Vote{{
			VoterID:   "node0",
			BlockHash: blockHash,
			Height:    1,
			EdSig:     ed25519.Sign(edPriv0, blockHash[:]),
			PQSig:     pqSig,
		}},
	}

	data, _ := json.Marshal(finalized)
	ckv.handleFinalized(data)

	val, _ := ckv.Get("test/key")
	assert.Nil(t, val, "insufficient votes should not apply")
	assert.Equal(t, uint64(0), ckv.Height())
}

func TestConsensusKV_PQKeyGeneration(t *testing.T) {
	// Verify ML-DSA-65 key sizes
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	assert.Equal(t, mldsa.MLDSA65PublicKeySize, len(priv.PublicKey.Bytes()))  // 1,952 bytes
	assert.Equal(t, mldsa.MLDSA65PrivateKeySize, len(priv.Bytes()))          // 4,032 bytes

	// Sign and verify
	msg := []byte("test message for post-quantum signing")
	sig, err := priv.Sign(nil, msg, nil)
	require.NoError(t, err)
	assert.Equal(t, mldsa.MLDSA65SignatureSize, len(sig)) // 3,309 bytes

	assert.True(t, priv.PublicKey.VerifySignature(msg, sig))

	// Tampered message should fail
	assert.False(t, priv.PublicKey.VerifySignature([]byte("wrong"), sig))

	t.Logf("ML-DSA-65 sizes: pubkey=%d, privkey=%d, sig=%d",
		len(priv.PublicKey.Bytes()), len(priv.Bytes()), len(sig))
}

func TestConsensusKV_Metadata(t *testing.T) {
	ckv := newTestConsensusKV()
	ckv.validators = map[string]*ValidatorKeys{
		"node0": nil, "node1": nil, "node2": nil,
	}
	ckv.threshold = 2

	assert.Equal(t, 3, ckv.ValidatorCount())
	assert.Equal(t, 2, ckv.Threshold())
}
