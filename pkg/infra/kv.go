package infra

// KV is the abstract key-value store interface for MPC cluster state.
// Replaces Consul KV. Implementations: NatsKV (NATS JetStream KV),
// BadgerKV (local BadgerDB), LuxKV (Lux consensus-backed).
//
// All MPC subsystems (PeerRegistry, KeyInfoStore, APIKeyStore, WalletOwner)
// use this interface through the ConsulKV compatibility adapter.

// KVPair mirrors the consul api.KVPair for drop-in compatibility.
type KVPair struct {
	Key   string
	Value []byte
}

// KV is the native key-value interface for MPC state management.
type KV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
	List(prefix string) ([]*KVPair, error)
}
