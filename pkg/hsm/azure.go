//go:build azure

package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/hanzoai/mpc/pkg/logger"
)

// AzureProvider implements Provider using Azure Key Vault / Managed HSM.
// Signing keys use Key Vault cryptographic operations (FIPS 140-2 Level 3 for Managed HSM).
// Ed25519 seeds are stored as Key Vault secrets.
type AzureProvider struct {
	vaultURL string
	keyName  string

	keysClient    *azkeys.Client
	secretsClient *azsecrets.Client
}

// NewAzureProvider creates an Azure Key Vault / Managed HSM provider.
func NewAzureProvider(cfg *AzureConfig) (*AzureProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hsm/azure: config is nil")
	}
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("hsm/azure: vault_url is required")
	}

	var cred azidentity.TokenCredential
	var err error

	if cfg.UseManagedIdentity {
		cred, err = azidentity.NewManagedIdentityCredential(nil)
	} else if cfg.ClientID != "" && cfg.ClientSecret != "" && cfg.TenantID != "" {
		cred, err = azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	}
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: create credential: %w", err)
	}

	keysClient, err := azkeys.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: create keys client: %w", err)
	}

	secretsClient, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: create secrets client: %w", err)
	}

	p := &AzureProvider{
		vaultURL:      cfg.VaultURL,
		keyName:       cfg.KeyName,
		keysClient:    keysClient,
		secretsClient: secretsClient,
	}

	logger.Info("hsm/azure: initialized",
		"vaultURL", cfg.VaultURL,
		"keyName", cfg.KeyName,
	)
	return p, nil
}

func (a *AzureProvider) Name() string { return "azure" }

// GetKey retrieves an Ed25519 seed from Key Vault secrets.
// If a key name is configured for KMS operations, returns the key name (private key never leaves HSM).
func (a *AzureProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if a.keyName != "" {
		return []byte(a.keyName), nil
	}

	resp, err := a.secretsClient.GetSecret(ctx, keyID, "", nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: get secret %q: %w", keyID, err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("hsm/azure: secret %q has no value", keyID)
	}

	seed, err := hex.DecodeString(*resp.Value)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: hex decode secret %q: %w", keyID, err)
	}

	return seed, nil
}

// StoreKey stores an Ed25519 seed as a hex-encoded Key Vault secret.
func (a *AzureProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	hexKey := hex.EncodeToString(key)

	params := azsecrets.SetSecretParameters{
		Value: &hexKey,
	}
	_, err := a.secretsClient.SetSecret(ctx, keyID, params, nil)
	if err != nil {
		return fmt.Errorf("hsm/azure: store key %q: %w", keyID, err)
	}

	logger.Info("hsm/azure: stored key", "keyID", keyID)
	return nil
}

// DeleteKey deletes a secret from Key Vault.
func (a *AzureProvider) DeleteKey(ctx context.Context, keyID string) error {
	_, err := a.secretsClient.DeleteSecret(ctx, keyID, nil)
	if err != nil {
		return fmt.Errorf("hsm/azure: delete key %q: %w", keyID, err)
	}

	logger.Info("hsm/azure: deleted key", "keyID", keyID)
	return nil
}

// ListKeys lists all secrets in the Key Vault.
func (a *AzureProvider) ListKeys(ctx context.Context) ([]string, error) {
	var keys []string

	pager := a.secretsClient.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("hsm/azure: list keys: %w", err)
		}
		for _, item := range page.Value {
			if item.ID != nil {
				keys = append(keys, string(*item.ID))
			}
		}
	}

	return keys, nil
}

// Sign signs a message.
// Key Vault key mode: uses Key Vault Sign operation.
// Secret mode: loads Ed25519 seed and signs locally.
func (a *AzureProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if a.keyName != "" {
		return a.kvSign(ctx, message)
	}
	return a.localSign(ctx, keyID, message)
}

func (a *AzureProvider) kvSign(ctx context.Context, message []byte) ([]byte, error) {
	params := azkeys.SignParameters{
		Algorithm: toPtr(azkeys.SignatureAlgorithmES256),
		Value:     message,
	}
	resp, err := a.keysClient.Sign(ctx, a.keyName, "", params, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/azure: kv sign: %w", err)
	}

	return resp.Result, nil
}

func (a *AzureProvider) localSign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	seed, err := a.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hsm/azure: key %q has invalid seed length %d, want %d", keyID, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, message), nil
}

// Healthy checks Key Vault connectivity.
func (a *AzureProvider) Healthy(ctx context.Context) error {
	if a.keyName != "" {
		_, err := a.keysClient.GetKey(ctx, a.keyName, "", nil)
		if err != nil {
			return fmt.Errorf("hsm/azure: health check (key): %w", err)
		}
		return nil
	}

	// Check secrets access.
	pager := a.secretsClient.NewListSecretPropertiesPager(nil)
	if pager.More() {
		_, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("hsm/azure: health check (secrets): %w", err)
		}
	}
	return nil
}

// Close is a no-op; Azure SDK clients manage connections internally.
func (a *AzureProvider) Close() error { return nil }

func toPtr[T any](v T) *T { return &v }
