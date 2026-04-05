package infra

import (
	"github.com/hanzoai/mpc/pkg/logger"
)

// HybridKV implements KV by routing key share material to an encrypted store
// (ZapDB/BadgerDB with AES-256) and metadata to SQLite.
//
// Routing rules:
//   - "threshold_keyinfo/*" → encrypted KV (key share metadata bound to shares)
//   - Everything else       → SQLiteMeta (queryable, per-org indexed)
//
// The encrypted KV is any infra.KV implementation backed by ZapDB (typically
// ConsensusKV or a BadgerDB-backed KV adapter). Key shares themselves are
// stored directly in kvstore.BadgerKVStore and are NOT routed through this
// interface — this only handles the infra.KV traffic.
//
// Security invariant: threshold_keyinfo is co-located with the encrypted key
// share data in ZapDB so that a compromise of the SQLite file alone does NOT
// yield enough information to reconstruct signing capability.
type HybridKV struct {
	encrypted KV // ZapDB-backed (ConsensusKV, NatsKV, or BadgerKV adapter)
	meta      KV // SQLiteMeta
}

// NewHybridKV creates a routing KV that sends key-share-adjacent data to the
// encrypted store and everything else to SQLite metadata.
func NewHybridKV(encrypted KV, meta KV) *HybridKV {
	logger.Info("HybridKV initialized",
		"encrypted_backend", backendName(encrypted),
		"metadata_backend", "SQLiteMeta",
	)
	return &HybridKV{encrypted: encrypted, meta: meta}
}

func (h *HybridKV) Put(key string, value []byte) error {
	return h.route(key).Put(key, value)
}

func (h *HybridKV) Get(key string) ([]byte, error) {
	return h.route(key).Get(key)
}

func (h *HybridKV) Delete(key string) error {
	return h.route(key).Delete(key)
}

func (h *HybridKV) List(prefix string) ([]*KVPair, error) {
	return h.route(prefix).List(prefix)
}

// route returns the appropriate backend for a given key or prefix.
func (h *HybridKV) route(key string) KV {
	if isKeyShareKey(key) {
		return h.encrypted
	}
	return h.meta
}

// isKeyShareKey returns true if the key belongs with encrypted key share storage.
// threshold_keyinfo contains participant IDs and threshold — if leaked alongside
// the SQLite metadata, an attacker would know exactly which nodes to compromise.
// Keeping it in the encrypted store forces the attacker to break AES-256 first.
func isKeyShareKey(key string) bool {
	// "threshold_keyinfo/" is 18 characters
	const prefix = "threshold_keyinfo/"
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}

// Close closes both backends, returning the first error encountered.
func (h *HybridKV) Close() error {
	var firstErr error
	if c, ok := h.encrypted.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c, ok := h.meta.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// backendName returns a short name for logging.
func backendName(kv KV) string {
	switch kv.(type) {
	case *ConsensusKV:
		return "ConsensusKV"
	case *NatsKV:
		return "NatsKV"
	case *ConsulKVAdapter:
		return "ConsulKV"
	case *SQLiteMeta:
		return "SQLiteMeta"
	default:
		return "unknown"
	}
}
