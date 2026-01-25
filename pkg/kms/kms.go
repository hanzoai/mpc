package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// KMS represents a simple Key Management System
type KMS struct {
	mu          sync.RWMutex
	masterKey   []byte
	storagePath string
	keys        map[string]*EncryptedKey
}

// EncryptedKey represents an encrypted key in storage
type EncryptedKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Encrypted   string `json:"encrypted"`
	Salt        string `json:"salt"`
	Nonce       string `json:"nonce"`
	CreatedAt   string `json:"created_at"`
	Description string `json:"description"`
}

// NewKMS creates a new KMS instance
func NewKMS(storagePath string, masterKey []byte) (*KMS, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master key must be at least 32 bytes")
	}

	kms := &KMS{
		storagePath: storagePath,
		masterKey:   masterKey,
		keys:        make(map[string]*EncryptedKey),
	}

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create KMS storage directory: %w", err)
	}

	// Load existing keys
	if err := kms.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys: %w", err)
	}

	return kms, nil
}

// StoreKey encrypts and stores a key
func (k *KMS) StoreKey(id, name, keyType string, keyData []byte, description string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Generate salt for key derivation
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key using Argon2
	encKey := argon2.IDKey(k.masterKey, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the key data
	ciphertext := gcm.Seal(nil, nonce, keyData, nil)

	// Create encrypted key entry
	encryptedKey := &EncryptedKey{
		ID:          id,
		Name:        name,
		Type:        keyType,
		Encrypted:   base64.StdEncoding.EncodeToString(ciphertext),
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Description: description,
	}

	// Store in memory
	k.keys[id] = encryptedKey

	// Persist to disk
	return k.saveKey(encryptedKey)
}

// RetrieveKey decrypts and retrieves a key
func (k *KMS) RetrieveKey(id string) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	encKey, exists := k.keys[id]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", id)
	}

	// Decode from base64
	salt, err := base64.StdEncoding.DecodeString(encKey.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encKey.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encKey.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Derive decryption key
	decKey := argon2.IDKey(k.masterKey, salt, 1, 64*1024, 4, 32)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return plaintext, nil
}

// ListKeys returns a list of all stored keys (without the actual key data)
func (k *KMS) ListKeys() []EncryptedKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	keys := make([]EncryptedKey, 0, len(k.keys))
	for _, key := range k.keys {
		// Create a copy without sensitive data
		keyCopy := EncryptedKey{
			ID:          key.ID,
			Name:        key.Name,
			Type:        key.Type,
			CreatedAt:   key.CreatedAt,
			Description: key.Description,
		}
		keys = append(keys, keyCopy)
	}
	return keys
}

// DeleteKey removes a key from storage
func (k *KMS) DeleteKey(id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, exists := k.keys[id]; !exists {
		return fmt.Errorf("key not found: %s", id)
	}

	// Remove from memory
	delete(k.keys, id)

	// Remove from disk
	keyPath := filepath.Join(k.storagePath, fmt.Sprintf("%s.json", id))
	return os.Remove(keyPath)
}

// loadKeys loads all encrypted keys from storage
func (k *KMS) loadKeys() error {
	files, err := os.ReadDir(k.storagePath)
	if err != nil {
		return fmt.Errorf("failed to read KMS storage directory: %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		keyPath := filepath.Join(k.storagePath, file.Name())
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", file.Name(), err)
		}

		var encKey EncryptedKey
		if err := json.Unmarshal(data, &encKey); err != nil {
			return fmt.Errorf("failed to unmarshal key file %s: %w", file.Name(), err)
		}

		k.keys[encKey.ID] = &encKey
	}

	return nil
}

// saveKey persists an encrypted key to disk
func (k *KMS) saveKey(encKey *EncryptedKey) error {
	data, err := json.MarshalIndent(encKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPath := filepath.Join(k.storagePath, fmt.Sprintf("%s.json", encKey.ID))
	return os.WriteFile(keyPath, data, 0600)
}

// DeriveKeyFromPassword derives a key from a password using scrypt
func DeriveKeyFromPassword(password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// HashKey creates a SHA256 hash of a key for identification
func HashKey(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:])
}
