package hsm

import "fmt"

// NewProvider creates an HSM provider from configuration.
// Returns a FileProvider by default when no provider is specified.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case "aws":
		return NewAWSProvider(cfg.AWS)
	case "gcp":
		return NewGCPProvider(cfg.GCP)
	case "azure":
		return NewAzureProvider(cfg.Azure)
	case "zymbit":
		return NewZymbitProvider(cfg.Zymbit)
	case "kms":
		return NewKMSProvider(cfg.KMS)
	case "file", "":
		return NewFileProvider(cfg.File)
	default:
		return nil, fmt.Errorf("hsm: unknown provider %q", cfg.Provider)
	}
}
