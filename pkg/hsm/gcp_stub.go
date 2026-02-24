//go:build !gcp

package hsm

import "fmt"

// NewGCPProvider returns an error when compiled without the gcp build tag.
// Build with: go build -tags gcp
func NewGCPProvider(cfg *GCPConfig) (Provider, error) {
	return nil, fmt.Errorf("hsm/gcp: not compiled (build with -tags gcp)")
}
