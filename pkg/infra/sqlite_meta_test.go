package infra

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSQLiteMeta(t *testing.T) *SQLiteMeta {
	t.Helper()
	s, err := NewSQLiteMeta(SQLiteMetaConfig{Path: ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

// TestSQLiteMeta_KVInterface exercises metadata-only KV operations.
// The full testKV suite includes threshold_keyinfo keys which SQLiteMeta
// correctly rejects (F5). HybridKV runs the full suite via routing.
func TestSQLiteMeta_KVInterface(t *testing.T) {
	s := newTestSQLiteMeta(t)

	// Put + Get
	require.NoError(t, s.Put("ready/node0", []byte("true")))
	val, err := s.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, []byte("true"), val)

	// Get non-existent
	val, err = s.Get("ready/nonexistent")
	require.NoError(t, err)
	assert.Nil(t, val)

	// Put more keys
	require.NoError(t, s.Put("ready/node1", []byte("true")))
	require.NoError(t, s.Put("ready/node2", []byte("true")))
	require.NoError(t, s.Put("config/timeout", []byte("30")))

	// List with prefix
	pairs, err := s.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 3)

	// Delete
	require.NoError(t, s.Delete("ready/node1"))
	val, err = s.Get("ready/node1")
	require.NoError(t, err)
	assert.Nil(t, val)

	// List after delete
	pairs, err = s.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	// Overwrite
	require.NoError(t, s.Put("ready/node0", []byte("false")))
	val, err = s.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, []byte("false"), val)
}

// TestSQLiteMeta_RejectsKeyShareKeys verifies that key share keys are refused.
func TestSQLiteMeta_RejectsKeyShareKeys(t *testing.T) {
	s := newTestSQLiteMeta(t)
	err := s.Put("threshold_keyinfo/wallet-1", []byte(`{"threshold":2}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key share keys must use encrypted backend")
}

func TestSQLiteMeta_APIKeyRoundTrip(t *testing.T) {
	s := newTestSQLiteMeta(t)

	key := "api_keys/abc123def456"
	val := `{"id":"abc1","name":"test-key","owner_id":"user-1","key_hash":"abc123def456","created_at":"2026-01-01T00:00:00Z","last_used":""}`

	require.NoError(t, s.Put(key, []byte(val)))

	got, err := s.Get(key)
	require.NoError(t, err)
	require.NotNil(t, got)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(got, &parsed))
	assert.Equal(t, "abc1", parsed["id"])
	assert.Equal(t, "test-key", parsed["name"])
	assert.Equal(t, "user-1", parsed["owner_id"])
	assert.Equal(t, "abc123def456", parsed["key_hash"])
}

func TestSQLiteMeta_APIKeyList(t *testing.T) {
	s := newTestSQLiteMeta(t)

	keys := []struct {
		key string
		val string
	}{
		{"api_keys/hash1", `{"id":"h1","name":"k1","owner_id":"u1","key_hash":"hash1","created_at":"2026-01-01T00:00:00Z","last_used":""}`},
		{"api_keys/hash2", `{"id":"h2","name":"k2","owner_id":"u1","key_hash":"hash2","created_at":"2026-01-02T00:00:00Z","last_used":""}`},
	}
	for _, k := range keys {
		require.NoError(t, s.Put(k.key, []byte(k.val)))
	}

	pairs, err := s.List("api_keys/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

func TestSQLiteMeta_PeerReadiness(t *testing.T) {
	s := newTestSQLiteMeta(t)

	// Register 3 peers
	require.NoError(t, s.Put("ready/node0", []byte("true")))
	require.NoError(t, s.Put("ready/node1", []byte("true")))
	require.NoError(t, s.Put("ready/node2", []byte("false")))

	// Check individual
	val, err := s.Get("ready/node0")
	require.NoError(t, err)
	assert.Equal(t, "true", string(val))

	val, err = s.Get("ready/node2")
	require.NoError(t, err)
	assert.Equal(t, "false", string(val))

	// List only returns ready peers
	pairs, err := s.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2) // node0 and node1

	// Delete peer
	require.NoError(t, s.Delete("ready/node1"))
	pairs, err = s.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 1)
}

func TestSQLiteMeta_GetNonExistent(t *testing.T) {
	s := newTestSQLiteMeta(t)

	val, err := s.Get("ready/nonexistent")
	require.NoError(t, err)
	assert.Nil(t, val)

	val, err = s.Get("api_keys/nonexistent")
	require.NoError(t, err)
	assert.Nil(t, val)

	val, err = s.Get("something/else")
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestSQLiteMeta_GenericKV(t *testing.T) {
	s := newTestSQLiteMeta(t)

	// Generic keys that don't match typed prefixes
	require.NoError(t, s.Put("config/timeout", []byte("30")))
	require.NoError(t, s.Put("config/retries", []byte("3")))
	require.NoError(t, s.Put("other/key", []byte("val")))

	val, err := s.Get("config/timeout")
	require.NoError(t, err)
	assert.Equal(t, []byte("30"), val)

	pairs, err := s.List("config/")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)

	// Overwrite
	require.NoError(t, s.Put("config/timeout", []byte("60")))
	val, err = s.Get("config/timeout")
	require.NoError(t, err)
	assert.Equal(t, []byte("60"), val)
}

func TestSQLiteMeta_Audit(t *testing.T) {
	s := newTestSQLiteMeta(t)

	require.NoError(t, s.Audit(AuditEntry{
		OrgID:    "org-1",
		Action:   "keygen.completed",
		Actor:    "node0",
		Resource: "wallet/w-123",
		Detail:   `{"curve":"secp256k1","threshold":2}`,
	}))

	require.NoError(t, s.Audit(AuditEntry{
		OrgID:    "org-1",
		Action:   "signing.completed",
		Actor:    "node0",
		Resource: "wallet/w-123",
		Detail:   `{"tx_id":"tx-456"}`,
	}))

	// Verify via raw query (audit log is append-only, not exposed via KV).
	var count int
	err := s.db.NewQuery("SELECT COUNT(*) FROM audit_log WHERE org_id={:org}").
		Bind(map[string]any{"org": "org-1"}).
		Row(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestSQLiteMeta_DeleteNonExistent(t *testing.T) {
	s := newTestSQLiteMeta(t)

	// Deleting non-existent keys should not error (matches KV contract).
	require.NoError(t, s.Delete("ready/ghost"))
	require.NoError(t, s.Delete("api_keys/ghost"))
	require.NoError(t, s.Delete("generic/ghost"))
}

func TestSQLiteMeta_EmptyList(t *testing.T) {
	s := newTestSQLiteMeta(t)

	pairs, err := s.List("nothing/")
	require.NoError(t, err)
	assert.Len(t, pairs, 0)

	pairs, err = s.List("ready/")
	require.NoError(t, err)
	assert.Len(t, pairs, 0)

	pairs, err = s.List("api_keys/")
	require.NoError(t, err)
	assert.Len(t, pairs, 0)
}
