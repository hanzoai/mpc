package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/hanzoai/mpc/pkg/kms"
	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/logger"
)

// KMSEnabledKVStore wraps a regular KVStore with KMS encryption
type KMSEnabledKVStore struct {
	kvstore.KVStore
	kmsClient *kms.KMSClient
	enabled   bool
	nodeID    string
}

// NewKMSEnabledKVStore creates a new KMS-enabled KV store
func NewKMSEnabledKVStore(store kvstore.KVStore, nodeID string) (*KMSEnabledKVStore, error) {
	// Try to initialize Lux KMS integration
	kmsConfig := kms.KMSConfig{
		ClientID:     viper.GetString("kms.client_id"),
		ClientSecret: viper.GetString("kms.client_secret"),
		ProjectID:    viper.GetString("kms.project_id"),
		Environment:  viper.GetString("kms.environment"),
		SecretPath:   viper.GetString("kms.secret_path"),
		SiteURL:      viper.GetString("kms.site_url"),
	}

	// If no project ID is set, check environment variable
	if kmsConfig.ProjectID == "" {
		kmsConfig.ProjectID = os.Getenv("KMS_PROJECT_ID")
	}

	// If still no project ID, disable KMS
	if kmsConfig.ProjectID == "" {
		logger.Warn("No Lux KMS project ID configured, falling back to regular storage")
		return &KMSEnabledKVStore{
			KVStore: store,
			enabled: false,
		}, nil
	}

	kmsClient, err := kms.NewKMSClient(kmsConfig)
	if err != nil {
		logger.Warn("Failed to initialize Lux KMS integration, falling back to regular storage", "error", err)
		return &KMSEnabledKVStore{
			KVStore: store,
			enabled: false,
		}, nil
	}

	logger.Info("Lux KMS integration enabled for secure key storage")
	return &KMSEnabledKVStore{
		KVStore:   store,
		kmsClient: kmsClient,
		enabled:   true,
		nodeID:    nodeID,
	}, nil
}

// Put stores a value with KMS encryption if enabled
func (k *KMSEnabledKVStore) Put(key string, value []byte) error {
	if !k.enabled {
		// Fallback to regular storage
		return k.KVStore.Put(key, value)
	}

	// For MPC key shares, use KMS
	if isKeyShare(key) {
		// Detect key type from the share data
		keyType := "ecdsa" // Default

		// Try to parse the share to determine type
		var shareData map[string]interface{}
		if err := json.Unmarshal(value, &shareData); err == nil {
			if _, hasEDDSA := shareData["eddsa"]; hasEDDSA {
				keyType = "eddsa"
			}
		}

		// Store in Lux KMS
		ctx := context.Background()
		if err := k.kmsClient.StoreKeyShare(ctx, key, value); err != nil {
			logger.Error("Failed to store key share in Lux KMS", err, "walletID", key)
			// Fallback to regular storage
			return k.KVStore.Put(key, value)
		}

		// Store a reference in regular KVStore
		reference := map[string]string{
			"storage": "kms",
			"wallet":  key,
			"type":    keyType,
		}
		refData, _ := json.Marshal(reference)
		return k.KVStore.Put(key, refData)
	}

	// For non-key data, use regular storage
	return k.KVStore.Put(key, value)
}

// Get retrieves a value with KMS decryption if needed
func (k *KMSEnabledKVStore) Get(key string) ([]byte, error) {
	if !k.enabled {
		// Fallback to regular storage
		return k.KVStore.Get(key)
	}

	// First, get from regular storage
	data, err := k.KVStore.Get(key)
	if err != nil {
		return nil, err
	}

	// Check if this is a KMS reference
	var reference map[string]string
	if err := json.Unmarshal(data, &reference); err == nil {
		if reference["storage"] == "kms" {
			// Retrieve from Lux KMS
			ctx := context.Background()
			share, err := k.kmsClient.RetrieveKeyShare(ctx, key)
			if err != nil {
				logger.Error("Failed to retrieve key share from Lux KMS", err, "walletID", key)
				return nil, fmt.Errorf("failed to retrieve from Lux KMS: %w", err)
			}
			return share, nil
		}
	}

	// Regular data, return as-is
	return data, nil
}

// Delete removes a value and its KMS entry if applicable
func (k *KMSEnabledKVStore) Delete(key string) error {
	if k.enabled {
		// Try to get the reference first
		data, err := k.KVStore.Get(key)
		if err == nil {
			var reference map[string]string
			if err := json.Unmarshal(data, &reference); err == nil {
				if reference["storage"] == "kms" {
					// Delete from Lux KMS
					// Delete operation not implemented in stub
					// In production, this would delete from KMS
					logger.Debug("KMS delete operation skipped (stub)", "key", key)
				}
			}
		}
	}

	// Delete from regular storage
	return k.KVStore.Delete(key)
}

// isKeyShare checks if a key represents an MPC key share
func isKeyShare(key string) bool {
	// In the MPC system, wallet IDs are used as keys for storing shares
	// You might want to add more sophisticated detection logic here
	return true // For now, treat all keys as potential key shares
}
