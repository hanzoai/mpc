package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"

	"github.com/hanzoai/mpc/pkg/logger"
)

// FileProvider implements Provider using the local filesystem.
// Keys are stored as hex-encoded Ed25519 seeds, optionally age-encrypted.
type FileProvider struct {
	basePath   string
	encrypted  bool
	hexEncoded bool
	mu         sync.RWMutex
}

// NewFileProvider creates a file-based HSM provider.
func NewFileProvider(cfg *FileConfig) (*FileProvider, error) {
	if cfg == nil {
		cfg = &FileConfig{}
	}

	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "."
	}

	// Ensure the directory exists.
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("hsm/file: create base path %q: %w", basePath, err)
	}

	return &FileProvider{
		basePath:   basePath,
		encrypted:  cfg.Encrypted,
		hexEncoded: cfg.HexEncoded,
	}, nil
}

func (f *FileProvider) Name() string { return "file" }

// GetKey reads an Ed25519 seed from disk. If hex_encoded is true (default),
// the file content is decoded from hex. If encrypted is true, the file
// must have a .age extension and will be decrypted with the HANZO_MPC_AGE_PASSPHRASE
// environment variable.
func (f *FileProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	raw, err := f.readKeyFile(keyID)
	if err != nil {
		return nil, fmt.Errorf("hsm/file: get key %q: %w", keyID, err)
	}
	return raw, nil
}

// StoreKey writes an Ed25519 seed to disk.
func (f *FileProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.encrypted {
		return fmt.Errorf("hsm/file: store key %q: writing age-encrypted keys is not supported", keyID)
	}

	path := filepath.Join(f.basePath, keyID)

	var data []byte
	if f.hexEncoded {
		data = []byte(hex.EncodeToString(key))
	} else {
		data = key
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("hsm/file: store key %q: %w", keyID, err)
	}

	logger.Info("hsm/file: stored key", "keyID", keyID, "path", path)
	return nil
}

// DeleteKey removes a key file from disk.
func (f *FileProvider) DeleteKey(ctx context.Context, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyPath(keyID)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("hsm/file: delete key %q: %w", keyID, err)
	}

	logger.Info("hsm/file: deleted key", "keyID", keyID)
	return nil
}

// ListKeys returns all key file names in the base directory.
func (f *FileProvider) ListKeys(ctx context.Context) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entries, err := os.ReadDir(f.basePath)
	if err != nil {
		return nil, fmt.Errorf("hsm/file: list keys: %w", err)
	}

	var keys []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Strip .age suffix for display.
		name = strings.TrimSuffix(name, ".age")
		keys = append(keys, name)
	}
	return keys, nil
}

// Sign loads the Ed25519 seed identified by keyID and signs the message locally.
func (f *FileProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	seed, err := f.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hsm/file: sign: key %q has invalid seed length %d, want %d", keyID, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, message)
	return sig, nil
}

// Healthy checks that the base path directory exists and is readable.
func (f *FileProvider) Healthy(ctx context.Context) error {
	info, err := os.Stat(f.basePath)
	if err != nil {
		return fmt.Errorf("hsm/file: health check: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("hsm/file: health check: %q is not a directory", f.basePath)
	}
	return nil
}

// Close is a no-op for the file provider.
func (f *FileProvider) Close() error { return nil }

// keyPath returns the filesystem path for a given keyID.
func (f *FileProvider) keyPath(keyID string) string {
	if f.encrypted {
		return filepath.Join(f.basePath, keyID+".age")
	}
	return filepath.Join(f.basePath, keyID)
}

// readKeyFile reads and decodes a key file, handling hex and age decryption.
func (f *FileProvider) readKeyFile(keyID string) ([]byte, error) {
	path := f.keyPath(keyID)

	if f.encrypted {
		return f.readAgeEncrypted(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))

	if f.hexEncoded {
		decoded, err := hex.DecodeString(content)
		if err != nil {
			return nil, fmt.Errorf("hex decode: %w", err)
		}
		return decoded, nil
	}

	return []byte(content), nil
}

// readAgeEncrypted decrypts an age-encrypted key file.
// The passphrase is read from HANZO_MPC_AGE_PASSPHRASE environment variable.
func (f *FileProvider) readAgeEncrypted(path string) ([]byte, error) {
	passphrase := os.Getenv("HANZO_MPC_AGE_PASSPHRASE")
	if passphrase == "" {
		return nil, fmt.Errorf("HANZO_MPC_AGE_PASSPHRASE not set (required for age-encrypted keys)")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create age identity: %w", err)
	}

	reader, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read decrypted: %w", err)
	}

	content := strings.TrimSpace(string(decrypted))

	if f.hexEncoded {
		decoded, err := hex.DecodeString(content)
		if err != nil {
			return nil, fmt.Errorf("hex decode after decrypt: %w", err)
		}
		return decoded, nil
	}

	return []byte(content), nil
}
