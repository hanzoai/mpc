package infra

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHybridKV(t *testing.T) (*HybridKV, *ConsensusKV, *SQLiteMeta) {
	t.Helper()

	encrypted := newTestConsensusKV()
	meta := newTestSQLiteMeta(t)
	hybrid := NewHybridKV(encrypted, meta)

	return hybrid, encrypted, meta
}

// TestHybridKV_KVInterface runs the full KV test suite against the hybrid.
func TestHybridKV_KVInterface(t *testing.T) {
	hybrid, _, _ := newTestHybridKV(t)
	testKV(t, hybrid)
}

// TestHybridKV_KeyShareRouting verifies threshold_keyinfo goes to encrypted backend.
func TestHybridKV_KeyShareRouting(t *testing.T) {
	hybrid, encrypted, meta := newTestHybridKV(t)

	// Write key share metadata through hybrid
	require.NoError(t, hybrid.Put("threshold_keyinfo/wallet-1", []byte(`{"threshold":2}`)))

	// Should be in encrypted backend
	val, err := encrypted.Get("threshold_keyinfo/wallet-1")
	require.NoError(t, err)
	assert.Equal(t, `{"threshold":2}`, string(val))

	// Should NOT be in SQLite
	val, err = meta.Get("threshold_keyinfo/wallet-1")
	require.NoError(t, err)
	assert.Nil(t, val, "key share metadata must not leak to SQLite")
}

// TestHybridKV_MetadataRouting verifies ready/ and api_keys/ go to SQLite.
func TestHybridKV_MetadataRouting(t *testing.T) {
	hybrid, encrypted, meta := newTestHybridKV(t)

	// Write peer readiness through hybrid
	require.NoError(t, hybrid.Put("ready/node0", []byte("true")))

	// Should be in SQLite
	val, err := meta.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, "true", string(val))

	// Should NOT be in encrypted backend
	val, err = encrypted.Get("ready/node0")
	require.NoError(t, err)
	assert.Nil(t, val, "metadata must not be in encrypted store")

	// Write API key through hybrid
	apiJSON := `{"id":"abc1","name":"test","owner_id":"u1","key_hash":"hash1","created_at":"2026-01-01T00:00:00Z","last_used":""}`
	require.NoError(t, hybrid.Put("api_keys/hash1", []byte(apiJSON)))

	// Should be in SQLite
	val, err = meta.Get("api_keys/hash1")
	require.NoError(t, err)
	assert.NotNil(t, val)

	// Should NOT be in encrypted backend
	val, err = encrypted.Get("api_keys/hash1")
	require.NoError(t, err)
	assert.Nil(t, val)
}

// TestHybridKV_ListRouting verifies List returns from the correct backend.
func TestHybridKV_ListRouting(t *testing.T) {
	hybrid, _, _ := newTestHybridKV(t)

	// Populate both sides
	require.NoError(t, hybrid.Put("threshold_keyinfo/w1", []byte(`{"threshold":2}`)))
	require.NoError(t, hybrid.Put("threshold_keyinfo/w2", []byte(`{"threshold":3}`)))
	require.NoError(t, hybrid.Put("ready/node0", []byte("true")))
	require.NoError(t, hybrid.Put("ready/node1", []byte("true")))

	// List key share metadata — from encrypted
	pairs, err := hybrid.List("threshold_keyinfo/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	// List peers — from SQLite
	pairs, err = hybrid.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

// TestHybridKV_DeleteRouting verifies Delete hits the correct backend.
func TestHybridKV_DeleteRouting(t *testing.T) {
	hybrid, encrypted, meta := newTestHybridKV(t)

	require.NoError(t, hybrid.Put("threshold_keyinfo/w1", []byte(`{"threshold":2}`)))
	require.NoError(t, hybrid.Put("ready/node0", []byte("true")))

	// Delete key share metadata
	require.NoError(t, hybrid.Delete("threshold_keyinfo/w1"))
	val, err := encrypted.Get("threshold_keyinfo/w1")
	require.NoError(t, err)
	assert.Nil(t, val)

	// Delete peer
	require.NoError(t, hybrid.Delete("ready/node0"))
	val, err = meta.Get("ready/node0")
	require.NoError(t, err)
	assert.Nil(t, val)
}

// TestHybridKV_IsKeyShareKey verifies the routing predicate.
func TestHybridKV_IsKeyShareKey(t *testing.T) {
	assert.True(t, isKeyShareKey("threshold_keyinfo/wallet-1"))
	assert.True(t, isKeyShareKey("threshold_keyinfo/abc"))
	assert.False(t, isKeyShareKey("threshold_keyinf")) // too short
	assert.False(t, isKeyShareKey("ready/node0"))
	assert.False(t, isKeyShareKey("api_keys/hash"))
	assert.False(t, isKeyShareKey("config/something"))
	assert.False(t, isKeyShareKey(""))
}
