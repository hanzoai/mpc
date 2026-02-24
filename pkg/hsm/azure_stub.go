//go:build !azure

package hsm

import "fmt"

// NewAzureProvider returns an error when compiled without the azure build tag.
// Build with: go build -tags azure
func NewAzureProvider(cfg *AzureConfig) (Provider, error) {
	return nil, fmt.Errorf("hsm/azure: not compiled (build with -tags azure)")
}
