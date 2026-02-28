package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hanzoai/mpc/pkg/logger"
)

// validateWebhookURL rejects internal/loopback URLs to prevent SSRF attacks.
func validateWebhookURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only HTTPS webhook URLs are allowed")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host in URL")
	}
	// Reject known internal hostnames
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "metadata.google.internal" {
		return fmt.Errorf("internal hostnames are not allowed")
	}
	// Reject IP literals in private/loopback/link-local ranges
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("private/loopback IP addresses are not allowed")
		}
	}
	return nil
}

// WebhookEvent types that can trigger webhooks.
type WebhookEvent string

const (
	WebhookKeygenCompleted WebhookEvent = "keygen.completed"
	WebhookKeygenFailed    WebhookEvent = "keygen.failed"
	WebhookSignCompleted   WebhookEvent = "sign.completed"
	WebhookSignFailed      WebhookEvent = "sign.failed"
	WebhookSignTimeout     WebhookEvent = "sign.timeout"
	WebhookPolicyDenied    WebhookEvent = "policy.denied"
)

// Webhook represents a registered HTTP callback.
type Webhook struct {
	ID        string         `json:"id"`
	URL       string         `json:"url"`
	Events    []WebhookEvent `json:"events"`
	Secret    string         `json:"secret,omitempty"` // HMAC signing secret
	Owner     string         `json:"owner"`
	Active    bool           `json:"active"`
	CreatedAt time.Time      `json:"created_at"`
}

// WebhookPayload is the body sent to webhook endpoints.
type WebhookPayload struct {
	ID        string         `json:"id"`
	Event     WebhookEvent   `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// WebhookStore manages webhook registrations and dispatching.
type WebhookStore struct {
	mu       sync.RWMutex
	webhooks map[string]*Webhook
	client   *http.Client
}

// NewWebhookStore creates a new webhook store.
func NewWebhookStore() *WebhookStore {
	return &WebhookStore{
		webhooks: make(map[string]*Webhook),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Register adds a new webhook with a randomly generated HMAC secret.
func (ws *WebhookStore) Register(rawURL, owner string, events []WebhookEvent) *Webhook {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		logger.Error("Failed to generate webhook secret", err)
	}

	wh := &Webhook{
		ID:        uuid.New().String(),
		URL:       rawURL,
		Events:    events,
		Secret:    hex.EncodeToString(secretBytes),
		Owner:     owner,
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	ws.webhooks[wh.ID] = wh
	return wh
}

// Get returns a webhook by ID.
func (ws *WebhookStore) Get(id string) (*Webhook, bool) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	wh, ok := ws.webhooks[id]
	return wh, ok
}

// List returns all webhooks for a given owner.
func (ws *WebhookStore) List(owner string) []*Webhook {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	result := make([]*Webhook, 0)
	for _, wh := range ws.webhooks {
		if owner == "" || wh.Owner == owner {
			result = append(result, wh)
		}
	}
	return result
}

// Remove deletes a webhook.
func (ws *WebhookStore) Remove(id string) bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if _, ok := ws.webhooks[id]; !ok {
		return false
	}
	delete(ws.webhooks, id)
	return true
}

// Dispatch sends an event to all matching webhooks (async, fire-and-forget).
func (ws *WebhookStore) Dispatch(evt WebhookEvent, data map[string]any) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	payload := WebhookPayload{
		ID:        uuid.New().String(),
		Event:     evt,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal webhook payload", err)
		return
	}

	for _, wh := range ws.webhooks {
		if !wh.Active {
			continue
		}
		for _, e := range wh.Events {
			if e == evt {
				go ws.send(wh, body)
				break
			}
		}
	}
}

func (ws *WebhookStore) send(wh *Webhook, body []byte) {
	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(body))
	if err != nil {
		logger.Error("Failed to create webhook request", err, "url", wh.URL)
		return
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MPC-Webhook-ID", wh.ID)
	req.Header.Set("X-MPC-Timestamp", ts)

	// HMAC-SHA256 signature over "timestamp.body" using the per-webhook secret
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write([]byte(ts))
		mac.Write([]byte("."))
		mac.Write(body)
		req.Header.Set("X-MPC-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := ws.client.Do(req)
	if err != nil {
		logger.Warn("Webhook delivery failed", "url", wh.URL, "error", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		logger.Warn("Webhook returned non-2xx", "url", wh.URL, "status", resp.StatusCode)
	}
}
