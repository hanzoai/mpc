//go:build gcp

package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"

	"github.com/hanzoai/mpc/pkg/logger"
)

// GCPProvider implements Provider using Google Cloud KMS for signing
// and Secret Manager for Ed25519 seed storage.
type GCPProvider struct {
	project  string
	location string
	keyRing  string
	keyName  string
	hsmLevel string

	kmsClient *kms.KeyManagementClient
	smClient  *secretmanager.Client
}

// NewGCPProvider creates a Google Cloud KMS provider.
func NewGCPProvider(cfg *GCPConfig) (*GCPProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hsm/gcp: config is nil")
	}
	if cfg.Project == "" {
		return nil, fmt.Errorf("hsm/gcp: project is required")
	}

	location := cfg.Location
	if location == "" {
		location = "global"
	}
	hsmLevel := cfg.HSMLevel
	if hsmLevel == "" {
		hsmLevel = "HSM"
	}

	ctx := context.Background()

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp: create kms client: %w", err)
	}

	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		kmsClient.Close()
		return nil, fmt.Errorf("hsm/gcp: create secret manager client: %w", err)
	}

	p := &GCPProvider{
		project:   cfg.Project,
		location:  location,
		keyRing:   cfg.KeyRing,
		keyName:   cfg.KeyName,
		hsmLevel:  hsmLevel,
		kmsClient: kmsClient,
		smClient:  smClient,
	}

	logger.Info("hsm/gcp: initialized",
		"project", cfg.Project,
		"location", location,
		"keyRing", cfg.KeyRing,
	)
	return p, nil
}

func (g *GCPProvider) Name() string { return "gcp" }

// keyVersionName returns the full resource name for the first key version.
func (g *GCPProvider) keyVersionName() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1",
		g.project, g.location, g.keyRing, g.keyName,
	)
}

// secretName returns the Secret Manager resource name for a key ID.
func (g *GCPProvider) secretName(keyID string) string {
	return fmt.Sprintf("projects/%s/secrets/%s", g.project, keyID)
}

// GetKey retrieves an Ed25519 seed from Secret Manager.
// If a KMS key is configured, returns the key version name (private key never leaves Cloud HSM).
func (g *GCPProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if g.keyName != "" {
		return []byte(g.keyVersionName()), nil
	}

	result, err := g.smClient.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: g.secretName(keyID) + "/versions/latest",
	})
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp: get secret %q: %w", keyID, err)
	}

	seed, err := hex.DecodeString(string(result.Payload.Data))
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp: hex decode secret %q: %w", keyID, err)
	}

	return seed, nil
}

// StoreKey stores an Ed25519 seed in Secret Manager as a hex string.
func (g *GCPProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	hexKey := hex.EncodeToString(key)

	// Create the secret resource (ignore error if already exists).
	_, _ = g.smClient.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", g.project),
		SecretId: keyID,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	})

	// Add the secret version with the actual data.
	crc := crc32.Checksum([]byte(hexKey), crc32.MakeTable(crc32.Castagnoli))
	_, err := g.smClient.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: g.secretName(keyID),
		Payload: &secretmanagerpb.SecretPayload{
			Data:       []byte(hexKey),
			DataCrc32C: int64Ptr(int64(crc)),
		},
	})
	if err != nil {
		return fmt.Errorf("hsm/gcp: store key %q: %w", keyID, err)
	}

	logger.Info("hsm/gcp: stored key", "keyID", keyID)
	return nil
}

// DeleteKey destroys a secret in Secret Manager.
func (g *GCPProvider) DeleteKey(ctx context.Context, keyID string) error {
	err := g.smClient.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: g.secretName(keyID),
	})
	if err != nil {
		return fmt.Errorf("hsm/gcp: delete key %q: %w", keyID, err)
	}

	logger.Info("hsm/gcp: deleted key", "keyID", keyID)
	return nil
}

// ListKeys lists all secrets in the project.
func (g *GCPProvider) ListKeys(ctx context.Context) ([]string, error) {
	var keys []string

	it := g.smClient.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", g.project),
	})
	for {
		secret, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("hsm/gcp: list keys: %w", err)
		}
		keys = append(keys, secret.Name)
	}

	return keys, nil
}

// Sign signs a message.
// KMS mode: uses Cloud KMS AsymmetricSign.
// Secret Manager mode: loads the seed and signs locally.
func (g *GCPProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if g.keyName != "" {
		return g.kmsSign(ctx, message)
	}
	return g.localSign(ctx, keyID, message)
}

func (g *GCPProvider) kmsSign(ctx context.Context, message []byte) ([]byte, error) {
	crc := crc32.Checksum(message, crc32.MakeTable(crc32.Castagnoli))

	result, err := g.kmsClient.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: g.keyVersionName(),
		Data: message,
		DataCrc32C: &kmspb.Int64Value{Value: int64(crc)},
	})
	if err != nil {
		return nil, fmt.Errorf("hsm/gcp: kms sign: %w", err)
	}

	return result.Signature, nil
}

func (g *GCPProvider) localSign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	seed, err := g.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hsm/gcp: key %q has invalid seed length %d, want %d", keyID, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, message), nil
}

// Healthy checks Cloud KMS connectivity by listing key rings.
func (g *GCPProvider) Healthy(ctx context.Context) error {
	if g.keyRing != "" {
		name := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.project, g.location, g.keyRing)
		_, err := g.kmsClient.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: name})
		if err != nil {
			return fmt.Errorf("hsm/gcp: health check: %w", err)
		}
		return nil
	}

	// Fallback: check Secret Manager access.
	it := g.smClient.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent:   fmt.Sprintf("projects/%s", g.project),
		PageSize: 1,
	})
	_, err := it.Next()
	if err != nil && err != iterator.Done {
		return fmt.Errorf("hsm/gcp: health check: %w", err)
	}
	return nil
}

// Close releases GCP client resources.
func (g *GCPProvider) Close() error {
	var firstErr error
	if err := g.kmsClient.Close(); err != nil {
		firstErr = fmt.Errorf("hsm/gcp: close kms client: %w", err)
	}
	if err := g.smClient.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("hsm/gcp: close secret manager client: %w", err)
	}
	return firstErr
}

func int64Ptr(v int64) *int64 { return &v }
