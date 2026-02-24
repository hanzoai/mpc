// Package hsm provides a unified interface for hardware and cloud key management.
//
// Supported providers:
//   - file: Local filesystem (default, always available)
//   - aws: AWS KMS / CloudHSM (always compiled, requires aws-sdk-go-v2/service/kms)
//   - gcp: Google Cloud KMS (build tag: gcp)
//   - azure: Azure Key Vault / Managed HSM (build tag: azure)
//   - zymbit: Zymbit ZYMKEY/HSM6 REST API (build tag: zymbit)
//   - kms: Hanzo KMS secret manager (always available, net/http only)
package hsm

import "context"

// Provider abstracts HSM key operations across cloud and hardware backends.
type Provider interface {
	// Name returns the provider identifier (e.g., "aws", "gcp", "azure", "zymbit", "kms", "file").
	Name() string

	// GetKey retrieves a key by ID.
	// For software providers: returns raw Ed25519 seed bytes.
	// For hardware HSMs: returns an opaque handle or public key (private never leaves device).
	GetKey(ctx context.Context, keyID string) ([]byte, error)

	// StoreKey stores key material under the given ID.
	StoreKey(ctx context.Context, keyID string, key []byte) error

	// DeleteKey removes a key by ID.
	DeleteKey(ctx context.Context, keyID string) error

	// ListKeys returns all key IDs managed by this provider.
	ListKeys(ctx context.Context) ([]string, error)

	// Sign signs a message using the key identified by keyID.
	// For cloud KMS: delegates signing to the remote service (key never leaves HSM).
	// For software/file: loads key and signs locally with Ed25519.
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)

	// Healthy returns nil if the provider is reachable and operational.
	Healthy(ctx context.Context) error

	// Close releases any resources held by the provider.
	Close() error
}

// Config holds HSM provider configuration loaded from config.yaml.
type Config struct {
	Provider string `yaml:"provider" mapstructure:"provider"` // aws, gcp, azure, zymbit, kms, file

	AWS    *AWSConfig    `yaml:"aws" mapstructure:"aws"`
	GCP    *GCPConfig    `yaml:"gcp" mapstructure:"gcp"`
	Azure  *AzureConfig  `yaml:"azure" mapstructure:"azure"`
	Zymbit *ZymbitConfig `yaml:"zymbit" mapstructure:"zymbit"`
	KMS    *KMSConfig    `yaml:"kms" mapstructure:"kms"`
	File   *FileConfig   `yaml:"file" mapstructure:"file"`
}

// FileConfig configures the local filesystem provider.
type FileConfig struct {
	BasePath  string `yaml:"base_path" mapstructure:"base_path"`   // directory containing key files
	Encrypted bool   `yaml:"encrypted" mapstructure:"encrypted"`   // whether keys are age-encrypted
	HexEncoded bool  `yaml:"hex_encoded" mapstructure:"hex_encoded"` // whether key files contain hex (default true)
}

// AWSConfig configures the AWS KMS / CloudHSM provider.
type AWSConfig struct {
	Region         string `yaml:"region" mapstructure:"region"`
	KeyARN         string `yaml:"key_arn" mapstructure:"key_arn"`                   // KMS key ARN or alias
	CustomKeyStore string `yaml:"custom_key_store" mapstructure:"custom_key_store"` // CloudHSM cluster ID (optional)
	Profile        string `yaml:"profile" mapstructure:"profile"`                   // AWS profile (optional)
	RoleARN        string `yaml:"role_arn" mapstructure:"role_arn"`                 // STS assume role (optional)
}

// GCPConfig configures the Google Cloud KMS provider.
type GCPConfig struct {
	Project  string `yaml:"project" mapstructure:"project"`
	Location string `yaml:"location" mapstructure:"location"`     // e.g. "global", "us-east1"
	KeyRing  string `yaml:"key_ring" mapstructure:"key_ring"`
	KeyName  string `yaml:"key_name" mapstructure:"key_name"`
	HSMLevel string `yaml:"hsm_level" mapstructure:"hsm_level"` // "SOFTWARE" or "HSM" (default HSM)
}

// AzureConfig configures the Azure Key Vault / Managed HSM provider.
type AzureConfig struct {
	VaultURL           string `yaml:"vault_url" mapstructure:"vault_url"`                       // e.g. "https://mpc-hsm.managedhsm.azure.net"
	KeyName            string `yaml:"key_name" mapstructure:"key_name"`
	TenantID           string `yaml:"tenant_id" mapstructure:"tenant_id"`
	ClientID           string `yaml:"client_id" mapstructure:"client_id"`
	ClientSecret       string `yaml:"client_secret" mapstructure:"client_secret"`
	UseManagedIdentity bool   `yaml:"use_managed_identity" mapstructure:"use_managed_identity"`
}

// ZymbitConfig configures the Zymbit ZYMKEY/HSM6 provider.
type ZymbitConfig struct {
	DevicePath  string `yaml:"device_path" mapstructure:"device_path"`   // default "/dev/zymbit0"
	SlotID      int    `yaml:"slot_id" mapstructure:"slot_id"`           // key slot (default 0)
	KeyType     string `yaml:"key_type" mapstructure:"key_type"`         // "ed25519" or "secp256k1"
	APIEndpoint string `yaml:"api_endpoint" mapstructure:"api_endpoint"` // REST API if using Zymbit SCM
}

// KMSConfig configures the Hanzo KMS (kms.hanzo.ai) provider.
type KMSConfig struct {
	SiteURL      string `yaml:"site_url" mapstructure:"site_url"`           // default "https://kms.hanzo.ai"
	ClientID     string `yaml:"client_id" mapstructure:"client_id"`         // Machine Identity client ID
	ClientSecret string `yaml:"client_secret" mapstructure:"client_secret"` // Machine Identity client secret
	ProjectID    string `yaml:"project_id" mapstructure:"project_id"`       // KMS project/workspace ID
	Environment  string `yaml:"environment" mapstructure:"environment"`     // "prod", "staging", "dev"
	SecretPath   string `yaml:"secret_path" mapstructure:"secret_path"`     // default "/mpc"
}
