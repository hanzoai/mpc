package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/hanzoai/mpc/pkg/logger"
)

// AWSProvider implements Provider using AWS KMS for signing and
// Secrets Manager for Ed25519 seed storage.
//
// Two usage modes:
//  1. KMS-native keys (key_arn set): Sign delegates to KMS. GetKey returns the ARN.
//     Keys never leave the HSM boundary.
//  2. Secrets Manager keys (no key_arn): Ed25519 seeds stored as hex in Secrets Manager.
//     GetKey returns the raw seed. Sign loads the seed and signs locally.
type AWSProvider struct {
	region string
	keyARN string

	kmsClient *kms.Client
	smClient  *secretsmanager.Client

	mu sync.RWMutex
}

// NewAWSProvider creates an AWS KMS / Secrets Manager provider.
func NewAWSProvider(cfg *AWSConfig) (*AWSProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hsm/aws: config is nil")
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	// Build AWS config with optional profile.
	opts := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(region),
	}
	if cfg.Profile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(cfg.Profile))
	}

	awsCfg, err := awscfg.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws: load config: %w", err)
	}

	// Assume role if configured.
	if cfg.RoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		awsCfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN)
	}

	kmsOpts := []func(*kms.Options){}
	if cfg.CustomKeyStore != "" {
		// CloudHSM-backed custom key store uses the same KMS API.
		logger.Info("hsm/aws: using CloudHSM custom key store", "id", cfg.CustomKeyStore)
	}

	p := &AWSProvider{
		region:    region,
		keyARN:    cfg.KeyARN,
		kmsClient: kms.NewFromConfig(awsCfg, kmsOpts...),
		smClient:  secretsmanager.NewFromConfig(awsCfg),
	}

	logger.Info("hsm/aws: initialized", "region", region, "keyARN", cfg.KeyARN)
	return p, nil
}

func (a *AWSProvider) Name() string { return "aws" }

// GetKey retrieves a key by ID.
// If a KMS key ARN is configured, returns the ARN bytes (the private key never leaves KMS).
// Otherwise, fetches the Ed25519 seed from Secrets Manager.
func (a *AWSProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if a.keyARN != "" {
		// KMS-native mode: return the ARN as the "key material".
		return []byte(a.keyARN), nil
	}

	// Secrets Manager mode: fetch hex-encoded Ed25519 seed.
	out, err := a.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("hsm/aws: get secret %q: %w", keyID, err)
	}

	if out.SecretString == nil {
		return nil, fmt.Errorf("hsm/aws: secret %q has no string value", keyID)
	}

	seed, err := hex.DecodeString(*out.SecretString)
	if err != nil {
		return nil, fmt.Errorf("hsm/aws: hex decode secret %q: %w", keyID, err)
	}

	return seed, nil
}

// StoreKey stores an Ed25519 seed in Secrets Manager as a hex string.
func (a *AWSProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	hexKey := hex.EncodeToString(key)

	// Try to create; if it exists, update.
	_, err := a.smClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         &keyID,
		SecretString: &hexKey,
	})
	if err != nil {
		// Attempt update if creation fails (secret may already exist).
		_, updateErr := a.smClient.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     &keyID,
			SecretString: &hexKey,
		})
		if updateErr != nil {
			return fmt.Errorf("hsm/aws: store key %q: create=%v, update=%w", keyID, err, updateErr)
		}
	}

	logger.Info("hsm/aws: stored key", "keyID", keyID)
	return nil
}

// DeleteKey deletes a secret from Secrets Manager.
func (a *AWSProvider) DeleteKey(ctx context.Context, keyID string) error {
	forceDelete := true
	_, err := a.smClient.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   &keyID,
		ForceDeleteWithoutRecovery: &forceDelete,
	})
	if err != nil {
		return fmt.Errorf("hsm/aws: delete key %q: %w", keyID, err)
	}

	logger.Info("hsm/aws: deleted key", "keyID", keyID)
	return nil
}

// ListKeys lists secrets in Secrets Manager. This returns all secrets visible
// to the configured credentials; use a naming convention (prefix) to scope.
func (a *AWSProvider) ListKeys(ctx context.Context) ([]string, error) {
	var keys []string
	paginator := secretsmanager.NewListSecretsPaginator(a.smClient, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("hsm/aws: list keys: %w", err)
		}
		for _, s := range page.SecretList {
			if s.Name != nil {
				keys = append(keys, *s.Name)
			}
		}
	}

	return keys, nil
}

// Sign signs a message.
// KMS mode: uses KMS Sign API with the configured key ARN.
// Secrets Manager mode: loads the Ed25519 seed and signs locally.
func (a *AWSProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if a.keyARN != "" {
		return a.kmsSign(ctx, message)
	}
	return a.localSign(ctx, keyID, message)
}

// kmsSign delegates signing to AWS KMS.
func (a *AWSProvider) kmsSign(ctx context.Context, message []byte) ([]byte, error) {
	out, err := a.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            &a.keyARN,
		Message:          message,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("hsm/aws: kms sign: %w", err)
	}

	return out.Signature, nil
}

// localSign fetches the seed from Secrets Manager and signs with Ed25519.
func (a *AWSProvider) localSign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	seed, err := a.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hsm/aws: key %q has invalid seed length %d, want %d", keyID, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, message), nil
}

// Healthy verifies KMS connectivity by describing the configured key.
func (a *AWSProvider) Healthy(ctx context.Context) error {
	if a.keyARN != "" {
		_, err := a.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: &a.keyARN,
		})
		if err != nil {
			return fmt.Errorf("hsm/aws: health check (kms): %w", err)
		}
		return nil
	}

	// No KMS key configured; check Secrets Manager access.
	_, err := a.smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: int32Ptr(1),
	})
	if err != nil {
		return fmt.Errorf("hsm/aws: health check (secrets manager): %w", err)
	}
	return nil
}

// Close is a no-op; AWS SDK clients do not hold persistent connections.
func (a *AWSProvider) Close() error { return nil }

func int32Ptr(v int32) *int32 { return &v }
