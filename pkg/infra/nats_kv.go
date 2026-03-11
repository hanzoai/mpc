package infra

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hanzoai/mpc/pkg/logger"
)

// NatsKV implements KV using NATS JetStream Key-Value store.
// This replaces Consul KV — MPC already depends on NATS for messaging,
// so this eliminates the Consul server entirely.
//
// JetStream KV provides:
//   - Persistent key-value storage (replicated across NATS cluster)
//   - Watch/subscribe for key changes (peer readiness)
//   - TTL support for ephemeral keys
//   - History for key versioning
type NatsKV struct {
	kv     jetstream.KeyValue
	bucket string
}

// NewNatsKV creates a NATS JetStream KV store, creating the bucket if needed.
func NewNatsKV(nc *nats.Conn, bucket string) (*NatsKV, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("nats_kv: failed to create JetStream context: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to bind to existing bucket, create if not found
	kv, err := js.KeyValue(ctx, bucket)
	if err != nil {
		// Create the bucket
		kv, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket:      bucket,
			Description: "MPC cluster state (replaces Consul KV)",
			History:     5,
			TTL:         0, // no global TTL
			Storage:     jetstream.FileStorage,
			Replicas:    1, // increase for HA
		})
		if err != nil {
			return nil, fmt.Errorf("nats_kv: failed to create bucket %q: %w", bucket, err)
		}
		logger.Info("Created NATS KV bucket", "bucket", bucket)
	}

	return &NatsKV{kv: kv, bucket: bucket}, nil
}

func (n *NatsKV) Put(key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// NATS KV uses "." as separator, Consul uses "/". Convert.
	natsKey := consulKeyToNats(key)
	_, err := n.kv.Put(ctx, natsKey, value)
	if err != nil {
		return fmt.Errorf("nats_kv: put %q failed: %w", key, err)
	}
	return nil
}

func (n *NatsKV) Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natsKey := consulKeyToNats(key)
	entry, err := n.kv.Get(ctx, natsKey)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, nil // not found = nil, matching Consul behavior
		}
		return nil, fmt.Errorf("nats_kv: get %q failed: %w", key, err)
	}
	return entry.Value(), nil
}

func (n *NatsKV) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natsKey := consulKeyToNats(key)
	err := n.kv.Delete(ctx, natsKey)
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("nats_kv: delete %q failed: %w", key, err)
	}
	return nil
}

func (n *NatsKV) List(prefix string) ([]*KVPair, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	natsPrefix := consulKeyToNats(prefix)

	// List all keys matching prefix
	keys, err := n.kv.ListKeys(ctx, jetstream.MetaOnly())
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("nats_kv: list %q failed: %w", prefix, err)
	}

	var pairs []*KVPair
	for key := range keys.Keys() {
		if !strings.HasPrefix(key, natsPrefix) {
			continue
		}

		entry, getErr := n.kv.Get(ctx, key)
		if getErr != nil {
			continue // skip deleted/expired
		}

		pairs = append(pairs, &KVPair{
			Key:   natsKeyToConsul(key),
			Value: entry.Value(),
		})
	}

	return pairs, nil
}

// consulKeyToNats converts Consul-style "ready/node0" to NATS-style "ready.node0"
func consulKeyToNats(key string) string {
	return strings.ReplaceAll(key, "/", ".")
}

// natsKeyToConsul converts NATS-style "ready.node0" back to "ready/node0"
func natsKeyToConsul(key string) string {
	return strings.ReplaceAll(key, ".", "/")
}
