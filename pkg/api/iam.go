package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IAMUser represents the authenticated user from hanzo.id
type IAMUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Owner       string `json:"owner"`
	Type        string `json:"type"`
}

// IAMMiddleware validates bearer tokens against Hanzo IAM (hanzo.id)
type IAMMiddleware struct {
	userinfoURL    string
	introspectURL  string
	clientID       string
	clientSecret   string
	client         *http.Client
}

// NewIAMMiddleware creates a new IAM auth middleware.
// iamEndpoint should be the base URL of the IAM service (e.g. "https://hanzo.id").
func NewIAMMiddleware(iamEndpoint string) *IAMMiddleware {
	endpoint := strings.TrimRight(iamEndpoint, "/")
	return &IAMMiddleware{
		userinfoURL:   endpoint + "/api/userinfo",
		introspectURL: endpoint + "/oauth/introspect",
		clientID:      "hanzo-app-client-id",
		clientSecret:  "3c7c4d9817bf0993681f6da2605e07ba5949da87a32862ed",
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Wrap returns an http.Handler that requires a valid IAM bearer token.
// The authenticated IAMUser is stored in the request context.
func (m *IAMMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "missing or invalid Authorization header",
			})
			return
		}

		user, err := m.validateToken(token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": fmt.Sprintf("authentication failed: %v", err),
			})
			return
		}

		// Store user in context for downstream handlers
		ctx := setUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken tries userinfo first (for user tokens), then falls back to
// token introspection (for client_credentials / service tokens).
func (m *IAMMiddleware) validateToken(token string) (*IAMUser, error) {
	// Try userinfo first (works for user-scoped tokens)
	user, err := m.tryUserinfo(token)
	if err == nil {
		return user, nil
	}

	// Fall back to introspection (works for all token types)
	user, introErr := m.tryIntrospection(token)
	if introErr == nil {
		return user, nil
	}

	return nil, fmt.Errorf("userinfo: %v; introspection: %v", err, introErr)
}

func (m *IAMMiddleware) tryUserinfo(token string) (*IAMUser, error) {
	req, err := http.NewRequest("GET", m.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IAM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("IAM returned %d: %s", resp.StatusCode, string(body))
	}

	var user IAMUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	if user.ID == "" && user.Name == "" {
		return nil, fmt.Errorf("IAM returned empty user")
	}

	return &user, nil
}

// introspectionResponse is the RFC 7662 token introspection response.
type introspectionResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Username string `json:"username"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

func (m *IAMMiddleware) tryIntrospection(token string) (*IAMUser, error) {
	data := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
		"client_id":       {m.clientID},
		"client_secret":   {m.clientSecret},
	}

	req, err := http.NewRequest("POST", m.introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("introspection returned %d: %s", resp.StatusCode, string(body))
	}

	var intro introspectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&intro); err != nil {
		return nil, fmt.Errorf("decode introspection: %w", err)
	}

	if !intro.Active {
		return nil, fmt.Errorf("token is not active")
	}

	return &IAMUser{
		ID:   intro.Sub,
		Name: intro.Username,
		Type: "service",
	}, nil
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
