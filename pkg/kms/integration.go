package kms

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/hanzoai/mpc/pkg/logger"
)

// MPCKMSIntegration provides KMS integration for MPC nodes
type MPCKMSIntegration struct {
	kms    *KMS
	nodeID string
}

// NewMPCKMSIntegration creates a new MPC KMS integration
func NewMPCKMSIntegration(nodeID string, dataDir string) (*MPCKMSIntegration, error) {
	// Create KMS directory
	kmsDir := filepath.Join(dataDir, "kms")

	// Derive master key from environment or generate one
	masterKeyStr := os.Getenv("MPC_KMS_MASTER_KEY")
	var masterKey []byte

	if masterKeyStr == "" {
		// For production, this should be properly managed
		// For now, we'll use a deterministic key based on node ID
		logger.Warn("No MPC_KMS_MASTER_KEY provided, using deterministic key (NOT FOR PRODUCTION)")
		masterKey, _ = DeriveKeyFromPassword(fmt.Sprintf("mpc-node-%s-default-key", nodeID), []byte(nodeID))
	} else {
		var err error
		masterKey, err = base64.StdEncoding.DecodeString(masterKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MPC_KMS_MASTER_KEY: %w", err)
		}
	}

	kms, err := NewKMS(kmsDir, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KMS: %w", err)
	}

	return &MPCKMSIntegration{
		kms:    kms,
		nodeID: nodeID,
	}, nil
}

// StoreMPCKeyShare stores an MPC key share
func (m *MPCKMSIntegration) StoreMPCKeyShare(walletID string, keyType string, share []byte) error {
	keyID := fmt.Sprintf("mpc-%s-%s-%s", m.nodeID, walletID, keyType)
	name := fmt.Sprintf("MPC Share for %s (%s)", walletID, keyType)
	description := fmt.Sprintf("MPC key share for wallet %s, key type %s, node %s", walletID, keyType, m.nodeID)

	return m.kms.StoreKey(keyID, name, keyType, share, description)
}

// RetrieveMPCKeyShare retrieves an MPC key share
func (m *MPCKMSIntegration) RetrieveMPCKeyShare(walletID string, keyType string) ([]byte, error) {
	keyID := fmt.Sprintf("mpc-%s-%s-%s", m.nodeID, walletID, keyType)
	return m.kms.RetrieveKey(keyID)
}

// StoreInitiatorKey stores the initiator private key
func (m *MPCKMSIntegration) StoreInitiatorKey(privateKey []byte) error {
	keyID := fmt.Sprintf("initiator-%s", m.nodeID)
	name := fmt.Sprintf("Initiator Key for %s", m.nodeID)
	description := fmt.Sprintf("Ed25519 initiator private key for node %s", m.nodeID)

	return m.kms.StoreKey(keyID, name, "ed25519", privateKey, description)
}

// RetrieveInitiatorKey retrieves the initiator private key
func (m *MPCKMSIntegration) RetrieveInitiatorKey() ([]byte, error) {
	keyID := fmt.Sprintf("initiator-%s", m.nodeID)
	return m.kms.RetrieveKey(keyID)
}

// StoreNodePrivateKey stores the node's P2P private key
func (m *MPCKMSIntegration) StoreNodePrivateKey(privateKey []byte) error {
	keyID := fmt.Sprintf("node-p2p-%s", m.nodeID)
	name := fmt.Sprintf("P2P Key for %s", m.nodeID)
	description := fmt.Sprintf("P2P communication private key for node %s", m.nodeID)

	return m.kms.StoreKey(keyID, name, "ecdsa", privateKey, description)
}

// RetrieveNodePrivateKey retrieves the node's P2P private key
func (m *MPCKMSIntegration) RetrieveNodePrivateKey() ([]byte, error) {
	keyID := fmt.Sprintf("node-p2p-%s", m.nodeID)
	return m.kms.RetrieveKey(keyID)
}

// ListStoredKeys lists all keys stored for this node
func (m *MPCKMSIntegration) ListStoredKeys() []EncryptedKey {
	return m.kms.ListKeys()
}

// BackupKeys creates an encrypted backup of all keys using Age encryption
func (m *MPCKMSIntegration) BackupKeys(backupPath string, backupPassword string) error {
	if backupPassword == "" {
		return fmt.Errorf("backup password is required")
	}

	// Create tar.gz of the KMS directory
	var tarBuffer bytes.Buffer
	gzWriter := gzip.NewWriter(&tarBuffer)
	tarWriter := tar.NewWriter(gzWriter)

	kmsPath := m.kms.storagePath
	err := filepath.Walk(kmsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only backup JSON key files
		if filepath.Ext(path) != ".json" {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Create tar header
		relPath, _ := filepath.Rel(kmsPath, path)
		header := &tar.Header{
			Name:    relPath,
			Mode:    0600,
			Size:    int64(len(content)),
			ModTime: info.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		if _, err := tarWriter.Write(content); err != nil {
			return fmt.Errorf("failed to write tar content: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create backup archive: %w", err)
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Encrypt with Age using password
	recipient, err := age.NewScryptRecipient(backupPassword)
	if err != nil {
		return fmt.Errorf("failed to create age recipient: %w", err)
	}

	// Create output file
	outFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer outFile.Close()

	// Write magic header
	magic := []byte("HANZO_KMS_BACKUP_V1\n")
	if _, err := outFile.Write(magic); err != nil {
		return fmt.Errorf("failed to write magic header: %w", err)
	}

	// Encrypt and write
	encWriter, err := age.Encrypt(outFile, recipient)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}

	if _, err := io.Copy(encWriter, &tarBuffer); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	if err := encWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	logger.Info("KMS backup created successfully",
		"path", backupPath,
		"node", m.nodeID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)

	return nil
}

// RestoreKeys restores keys from an encrypted backup
func (m *MPCKMSIntegration) RestoreKeys(backupPath string, backupPassword string) error {
	if backupPassword == "" {
		return fmt.Errorf("backup password is required")
	}

	// Open backup file
	inFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer inFile.Close()

	// Verify magic header
	magic := make([]byte, 20)
	if _, err := io.ReadFull(inFile, magic); err != nil {
		return fmt.Errorf("failed to read magic header: %w", err)
	}
	if string(magic) != "HANZO_KMS_BACKUP_V1\n" {
		return fmt.Errorf("invalid backup file format")
	}

	// Decrypt with Age
	identity, err := age.NewScryptIdentity(backupPassword)
	if err != nil {
		return fmt.Errorf("failed to create age identity: %w", err)
	}

	decReader, err := age.Decrypt(inFile, identity)
	if err != nil {
		return fmt.Errorf("failed to decrypt backup (wrong password?): %w", err)
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(decReader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Extract tar
	tarReader := tar.NewReader(gzReader)
	kmsPath := m.kms.storagePath

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Validate filename (only allow .json files)
		if filepath.Ext(header.Name) != ".json" {
			continue
		}

		// Create target path
		targetPath := filepath.Join(kmsPath, filepath.Clean(header.Name))

		// Ensure target is within KMS directory (prevent path traversal)
		if !filepath.HasPrefix(targetPath, kmsPath) {
			return fmt.Errorf("invalid path in backup: %s", header.Name)
		}

		// Read content
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, content); err != nil {
			return fmt.Errorf("failed to read file content: %w", err)
		}

		// Write file
		if err := os.WriteFile(targetPath, content, 0600); err != nil {
			return fmt.Errorf("failed to write restored file: %w", err)
		}
	}

	// Reload keys
	if err := m.kms.loadKeys(); err != nil {
		return fmt.Errorf("failed to reload keys after restore: %w", err)
	}

	logger.Info("KMS backup restored successfully",
		"path", backupPath,
		"node", m.nodeID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)

	return nil
}
