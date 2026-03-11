package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/mpc/pkg/infra"
	"github.com/hanzoai/mpc/pkg/logger"
)

const (
	apiKeyPrefix       = "sk_mpc_"
	apiKeyConsulPrefix = "api_keys/"
)

// APIKey is a long-lived credential for programmatic MPC access.
// The plaintext is shown once at creation; only the SHA-256 hash is stored.
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OwnerID   string    `json:"owner_id"`
	KeyHash   string    `json:"key_hash"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// APIKeyStore persists API keys in the cluster KV store.
type APIKeyStore struct {
	kv infra.KV
}

func NewAPIKeyStore(kv infra.KV) *APIKeyStore {
	return &APIKeyStore{kv: kv}
}

// Create generates sk_mpc_<hex>, stores its SHA-256, returns plaintext once.
func (s *APIKeyStore) Create(ownerID, name string) (plaintext string, key *APIKey, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate: %w", err)
	}
	plaintext = apiKeyPrefix + hex.EncodeToString(raw)

	h := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(h[:])

	key = &APIKey{
		ID:        keyHash[:16],
		Name:      name,
		OwnerID:   ownerID,
		KeyHash:   keyHash,
		CreatedAt: time.Now().UTC(),
	}

	data, _ := json.Marshal(key)
	if err = s.kv.Put(apiKeyConsulPrefix+keyHash, data); err != nil {
		return "", nil, fmt.Errorf("store: %w", err)
	}
	return plaintext, key, nil
}

// Validate resolves a plaintext API key to its stored record, updating LastUsed async.
func (s *APIKeyStore) Validate(plaintext string) (*APIKey, error) {
	if s.kv == nil {
		return nil, fmt.Errorf("kv store unavailable")
	}
	h := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(h[:])

	data, err := s.kv.Get(apiKeyConsulPrefix + keyHash)
	if err != nil || data == nil {
		return nil, fmt.Errorf("invalid API key")
	}

	var key APIKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	// Update last_used without blocking the request
	go func() {
		key.LastUsed = time.Now().UTC()
		if updated, err := json.Marshal(key); err == nil {
			if err := s.kv.Put(apiKeyConsulPrefix+key.KeyHash, updated); err != nil {
				logger.Warn("Failed to update API key last_used", "error", err)
			}
		}
	}()

	return &key, nil
}

// List returns all keys belonging to ownerID.
func (s *APIKeyStore) List(ownerID string) ([]*APIKey, error) {
	pairs, err := s.kv.List(apiKeyConsulPrefix)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	var out []*APIKey
	for _, p := range pairs {
		var k APIKey
		if json.Unmarshal(p.Value, &k) == nil && k.OwnerID == ownerID {
			out = append(out, &k)
		}
	}
	return out, nil
}

// Revoke deletes the key with the given short ID if it belongs to ownerID.
func (s *APIKeyStore) Revoke(shortID, ownerID string) error {
	pairs, err := s.kv.List(apiKeyConsulPrefix)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	for _, p := range pairs {
		var k APIKey
		if json.Unmarshal(p.Value, &k) != nil {
			continue
		}
		if k.ID == shortID {
			if k.OwnerID != ownerID {
				return fmt.Errorf("access denied")
			}
			if err := s.kv.Delete(p.Key); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("key not found")
}

// isAPIKey returns true if the bearer token is an MPC API key.
func isAPIKey(token string) bool {
	return strings.HasPrefix(token, apiKeyPrefix)
}
