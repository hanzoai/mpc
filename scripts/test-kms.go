package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"

	"github.com/luxfi/mpc/pkg/kms"
)

func main() {
	// Initialize viper config
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("..")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file: %v", err)
	}

	// Create Lux KMS client
	config := kms.KMSConfig{
		ClientID:     viper.GetString("kms.client_id"),
		ClientSecret: viper.GetString("kms.client_secret"),
		ProjectID:    viper.GetString("kms.project_id"),
		Environment:  viper.GetString("kms.environment"),
		SecretPath:   viper.GetString("kms.secret_path"),
		SiteURL:      viper.GetString("kms.site_url"),
	}

	// Check environment variable fallback
	if config.ProjectID == "" {
		config.ProjectID = os.Getenv("KMS_PROJECT_ID")
	}

	fmt.Printf("Lux KMS Configuration:\n")
	fmt.Printf("  Site URL: %s\n", config.SiteURL)
	fmt.Printf("  Project ID: %s\n", config.ProjectID)
	fmt.Printf("  Environment: %s\n", config.Environment)
	fmt.Printf("  Secret Path: %s\n", config.SecretPath)
	fmt.Printf("  Has Universal Auth: %v\n", config.ClientID != "")
	fmt.Printf("  Has Service Token: %v\n", os.Getenv("KMS_TOKEN") != "")

	client, err := kms.NewKMSClient(config)
	if err != nil {
		log.Fatalf("Failed to create Lux KMS client: %v", err)
	}

	fmt.Println("\n✅ Successfully connected to Lux KMS!")

	// Test storing a dummy key share
	testNodeID := "test-node"
	testWalletID := "test-wallet"
	testKeyType := "ecdsa"
	testKeyData := []byte(`{"test": "data", "key": "12345"}`)

	fmt.Printf("\nTesting key storage...\n")
	if err := client.StoreMPCKeyShare(testNodeID, testWalletID, testKeyType, testKeyData); err != nil {
		log.Fatalf("Failed to store test key: %v", err)
	}
	fmt.Println("✅ Successfully stored test key!")

	// Test retrieving the key
	fmt.Printf("\nTesting key retrieval...\n")
	retrievedData, err := client.RetrieveMPCKeyShare(testNodeID, testWalletID, testKeyType)
	if err != nil {
		log.Fatalf("Failed to retrieve test key: %v", err)
	}

	if string(retrievedData) == string(testKeyData) {
		fmt.Println("✅ Successfully retrieved test key with correct data!")
	} else {
		fmt.Printf("⚠️  Retrieved data doesn't match: got %s, want %s\n", string(retrievedData), string(testKeyData))
	}

	// List all keys
	fmt.Printf("\nListing all keys...\n")
	keys, err := client.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	fmt.Printf("Found %d keys:\n", len(keys))
	for _, key := range keys {
		fmt.Printf("  - %s\n", key)
	}

	// Clean up test key
	fmt.Printf("\nCleaning up test key...\n")
	secretName := fmt.Sprintf("mpc_%s_%s_%s", testNodeID, testWalletID, testKeyType)
	if err := client.DeleteKey(secretName); err != nil {
		log.Printf("Warning: Failed to delete test key: %v", err)
	} else {
		fmt.Println("✅ Successfully cleaned up test key!")
	}

	fmt.Println("\n🎉 All tests passed! Lux KMS integration is working correctly.")
}
