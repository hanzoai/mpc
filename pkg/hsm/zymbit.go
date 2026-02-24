//go:build zymbit

package hsm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hanzoai/mpc/pkg/logger"
)

// ZymbitProvider implements Provider using the Zymbit Secure Compute Module REST API.
// Private keys never leave the hardware device; signing is performed on-device.
type ZymbitProvider struct {
	endpoint string
	slotID   int
	keyType  string
	client   *http.Client
}

// NewZymbitProvider creates a Zymbit HSM provider using the REST API.
func NewZymbitProvider(cfg *ZymbitConfig) (*ZymbitProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hsm/zymbit: config is nil")
	}

	endpoint := cfg.APIEndpoint
	if endpoint == "" {
		return nil, fmt.Errorf("hsm/zymbit: api_endpoint is required")
	}

	keyType := cfg.KeyType
	if keyType == "" {
		keyType = "ed25519"
	}

	p := &ZymbitProvider{
		endpoint: endpoint,
		slotID:   cfg.SlotID,
		keyType:  keyType,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	logger.Info("hsm/zymbit: initialized",
		"endpoint", endpoint,
		"slotID", cfg.SlotID,
		"keyType", keyType,
	)
	return p, nil
}

func (z *ZymbitProvider) Name() string { return "zymbit" }

// GetKey returns the public key for a key slot. The private key never leaves the device.
func (z *ZymbitProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/keys/%s/public", z.endpoint, keyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: create request: %w", err)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: get key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hsm/zymbit: get key %q: status %d: %s", keyID, resp.StatusCode, body)
	}

	var result struct {
		PublicKey []byte `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hsm/zymbit: decode response: %w", err)
	}

	return result.PublicKey, nil
}

// StoreKey generates a new key in the specified slot.
// The key material parameter is ignored; the device generates the key internally.
func (z *ZymbitProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	url := fmt.Sprintf("%s/api/v1/keys", z.endpoint)

	body := map[string]interface{}{
		"key_id":   keyID,
		"key_type": z.keyType,
		"slot_id":  z.slotID,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("hsm/zymbit: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: store key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/zymbit: store key %q: status %d: %s", keyID, resp.StatusCode, respBody)
	}

	logger.Info("hsm/zymbit: generated key on device", "keyID", keyID, "slot", z.slotID)
	return nil
}

// DeleteKey removes a key from the device.
func (z *ZymbitProvider) DeleteKey(ctx context.Context, keyID string) error {
	url := fmt.Sprintf("%s/api/v1/keys/%s", z.endpoint, keyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: create request: %w", err)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: delete key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/zymbit: delete key %q: status %d: %s", keyID, resp.StatusCode, body)
	}

	logger.Info("hsm/zymbit: deleted key", "keyID", keyID)
	return nil
}

// ListKeys returns all key IDs from the device.
func (z *ZymbitProvider) ListKeys(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/api/v1/keys", z.endpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: create request: %w", err)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hsm/zymbit: list keys: status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Keys []struct {
			ID string `json:"key_id"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hsm/zymbit: decode response: %w", err)
	}

	ids := make([]string, len(result.Keys))
	for i, k := range result.Keys {
		ids[i] = k.ID
	}
	return ids, nil
}

// Sign delegates signing to the Zymbit device. The private key never leaves hardware.
func (z *ZymbitProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/keys/%s/sign", z.endpoint, keyID)

	body := map[string]interface{}{
		"message": message,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := z.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm/zymbit: sign with key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hsm/zymbit: sign with key %q: status %d: %s", keyID, resp.StatusCode, respBody)
	}

	var result struct {
		Signature []byte `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hsm/zymbit: decode sign response: %w", err)
	}

	return result.Signature, nil
}

// Healthy checks device connectivity via the API status endpoint.
func (z *ZymbitProvider) Healthy(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/status", z.endpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: create request: %w", err)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("hsm/zymbit: health check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/zymbit: health check: status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// Close releases the HTTP client resources.
func (z *ZymbitProvider) Close() error {
	z.client.CloseIdleConnections()
	return nil
}
