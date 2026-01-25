package kms

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

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

// BackupKeys creates an encrypted backup of all keys
func (m *MPCKMSIntegration) BackupKeys(backupPath string, backupPassword string) error {
	// This would implement a secure backup mechanism
	// For now, we'll leave it as a placeholder
	return fmt.Errorf("backup not yet implemented")
}

// RestoreKeys restores keys from an encrypted backup
func (m *MPCKMSIntegration) RestoreKeys(backupPath string, backupPassword string) error {
	// This would implement a secure restore mechanism
	// For now, we'll leave it as a placeholder
	return fmt.Errorf("restore not yet implemented")
}
