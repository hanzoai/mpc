//go:build !zymbit

package hsm

import "fmt"

// NewZymbitProvider returns an error when compiled without the zymbit build tag.
// Build with: go build -tags zymbit
func NewZymbitProvider(cfg *ZymbitConfig) (Provider, error) {
	return nil, fmt.Errorf("hsm/zymbit: not compiled (build with -tags zymbit)")
}
