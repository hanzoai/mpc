package hsm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hanzoai/mpc/pkg/logger"
)

// KMSProvider implements Provider using the Hanzo KMS API (kms.hanzo.ai).
// KMS is a secret manager; signing is always done locally after fetching the Ed25519 seed.
type KMSProvider struct {
	siteURL      string
	clientID     string
	clientSecret string
	projectID    string
	environment  string
	secretPath   string

	client *http.Client

	// Token management.
	mu          sync.RWMutex
	accessToken string
	tokenExpiry time.Time
}

// NewKMSProvider creates a Hanzo KMS secret manager provider.
func NewKMSProvider(cfg *KMSConfig) (*KMSProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hsm/kms: config is nil")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("hsm/kms: client_id and client_secret are required")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("hsm/kms: project_id is required")
	}

	siteURL := cfg.SiteURL
	if siteURL == "" {
		siteURL = "https://kms.hanzo.ai"
	}
	env := cfg.Environment
	if env == "" {
		env = "prod"
	}
	secretPath := cfg.SecretPath
	if secretPath == "" {
		secretPath = "/mpc"
	}

	p := &KMSProvider{
		siteURL:      siteURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		projectID:    cfg.ProjectID,
		environment:  env,
		secretPath:   secretPath,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	logger.Info("hsm/kms: initialized",
		"siteURL", siteURL,
		"projectID", cfg.ProjectID,
		"environment", env,
		"secretPath", secretPath,
	)
	return p, nil
}

func (k *KMSProvider) Name() string { return "kms" }

// authenticate obtains or refreshes the Universal Auth access token.
func (k *KMSProvider) authenticate(ctx context.Context) (string, error) {
	k.mu.RLock()
	if k.accessToken != "" && time.Now().Before(k.tokenExpiry) {
		token := k.accessToken
		k.mu.RUnlock()
		return token, nil
	}
	k.mu.RUnlock()

	k.mu.Lock()
	defer k.mu.Unlock()

	// Double-check after acquiring write lock.
	if k.accessToken != "" && time.Now().Before(k.tokenExpiry) {
		return k.accessToken, nil
	}

	body := map[string]string{
		"clientId":     k.clientID,
		"clientSecret": k.clientSecret,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal auth request: %w", err)
	}

	url := k.siteURL + "/api/v1/auth/universal-auth/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		AccessToken       string `json:"accessToken"`
		ExpiresIn         int    `json:"expiresIn"`         // seconds
		AccessTokenMaxTTL int    `json:"accessTokenMaxTTL"` // seconds
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode auth response: %w", err)
	}

	k.accessToken = result.AccessToken
	// Expire 60 seconds early to avoid clock-skew issues.
	ttl := time.Duration(result.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	k.tokenExpiry = time.Now().Add(ttl - 60*time.Second)

	return k.accessToken, nil
}

// doAuthRequest executes an authenticated HTTP request.
func (k *KMSProvider) doAuthRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	token, err := k.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("hsm/kms: authenticate: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return k.client.Do(req)
}

// GetKey retrieves an Ed25519 seed from KMS.
func (k *KMSProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	url := fmt.Sprintf(
		"%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s",
		k.siteURL, keyID, k.projectID, k.environment, k.secretPath,
	)

	resp, err := k.doAuthRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/kms: get key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hsm/kms: get key %q: status %d: %s", keyID, resp.StatusCode, body)
	}

	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hsm/kms: decode response: %w", err)
	}

	seed, err := hex.DecodeString(result.Secret.SecretValue)
	if err != nil {
		return nil, fmt.Errorf("hsm/kms: hex decode key %q: %w", keyID, err)
	}

	return seed, nil
}

// StoreKey stores an Ed25519 seed in KMS as a hex-encoded secret.
func (k *KMSProvider) StoreKey(ctx context.Context, keyID string, key []byte) error {
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s", k.siteURL, keyID)

	body := map[string]string{
		"workspaceId": k.projectID,
		"environment": k.environment,
		"secretPath":  k.secretPath,
		"secretValue": hex.EncodeToString(key),
		"type":        "shared",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("hsm/kms: marshal request: %w", err)
	}

	resp, err := k.doAuthRequest(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("hsm/kms: store key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		// Try PATCH (update) if POST (create) returned conflict.
		if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusBadRequest {
			return k.updateKey(ctx, keyID, key)
		}
		return fmt.Errorf("hsm/kms: store key %q: status %d: %s", keyID, resp.StatusCode, respBody)
	}

	logger.Info("hsm/kms: stored key", "keyID", keyID)
	return nil
}

// updateKey updates an existing secret value.
func (k *KMSProvider) updateKey(ctx context.Context, keyID string, key []byte) error {
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s", k.siteURL, keyID)

	body := map[string]string{
		"workspaceId": k.projectID,
		"environment": k.environment,
		"secretPath":  k.secretPath,
		"secretValue": hex.EncodeToString(key),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("hsm/kms: marshal update request: %w", err)
	}

	resp, err := k.doAuthRequest(ctx, http.MethodPatch, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("hsm/kms: update key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/kms: update key %q: status %d: %s", keyID, resp.StatusCode, respBody)
	}

	logger.Info("hsm/kms: updated key", "keyID", keyID)
	return nil
}

// DeleteKey removes a secret from KMS.
func (k *KMSProvider) DeleteKey(ctx context.Context, keyID string) error {
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s", k.siteURL, keyID)

	body := map[string]string{
		"workspaceId": k.projectID,
		"environment": k.environment,
		"secretPath":  k.secretPath,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("hsm/kms: marshal delete request: %w", err)
	}

	resp, err := k.doAuthRequest(ctx, http.MethodDelete, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("hsm/kms: delete key %q: %w", keyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/kms: delete key %q: status %d: %s", keyID, resp.StatusCode, respBody)
	}

	logger.Info("hsm/kms: deleted key", "keyID", keyID)
	return nil
}

// ListKeys lists all secrets at the configured path.
func (k *KMSProvider) ListKeys(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf(
		"%s/api/v3/secrets/raw?workspaceId=%s&environment=%s&secretPath=%s",
		k.siteURL, k.projectID, k.environment, k.secretPath,
	)

	resp, err := k.doAuthRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("hsm/kms: list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hsm/kms: list keys: status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Secrets []struct {
			SecretKey string `json:"secretKey"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hsm/kms: decode list response: %w", err)
	}

	keys := make([]string, len(result.Secrets))
	for i, s := range result.Secrets {
		keys[i] = s.SecretKey
	}
	return keys, nil
}

// Sign fetches the Ed25519 seed from KMS and signs locally.
// KMS is a secret manager; it cannot perform cryptographic operations.
func (k *KMSProvider) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	seed, err := k.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hsm/kms: key %q has invalid seed length %d, want %d", keyID, len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, message), nil
}

// Healthy checks KMS API connectivity.
func (k *KMSProvider) Healthy(ctx context.Context) error {
	url := k.siteURL + "/api/status"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("hsm/kms: create health request: %w", err)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("hsm/kms: health check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hsm/kms: health check: status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// Close releases HTTP client resources.
func (k *KMSProvider) Close() error {
	k.client.CloseIdleConnections()

	k.mu.Lock()
	k.accessToken = ""
	k.tokenExpiry = time.Time{}
	k.mu.Unlock()

	return nil
}
