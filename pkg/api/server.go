package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/logger"
)

// Server provides HTTP REST API for MPC operations with IAM auth.
type Server struct {
	httpServer *http.Server
	natsConn   *nats.Conn
	iam        *IAMMiddleware
}

// Config holds configuration for the API server.
type Config struct {
	Port        int
	IAMEndpoint string // e.g. "https://hanzo.id"
	NATSConn    *nats.Conn
}

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	s := &Server{
		natsConn: cfg.NATSConn,
		iam:      NewIAMMiddleware(cfg.IAMEndpoint),
	}

	mux := http.NewServeMux()

	// Public endpoints (no auth)
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)

	// Protected endpoints (IAM auth required)
	authed := s.iam.Wrap(http.HandlerFunc(s.routeAPI))
	mux.Handle("/api/", authed)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening. Blocks until the server is shut down.
func (s *Server) Start() error {
	logger.Info("API server starting", "addr", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the API server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// routeAPI dispatches authenticated API requests.
func (s *Server) routeAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/v1/wallets":
		s.handleCreateWallet(w, r)
	case r.Method == "GET" && r.URL.Path == "/api/v1/wallets":
		s.handleListWallets(w, r)
	case r.Method == "POST" && r.URL.Path == "/api/v1/sign":
		s.handleSign(w, r)
	case r.Method == "POST" && r.URL.Path == "/api/v1/reshare":
		s.handleReshare(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// --- Landing ---

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(landingHTML))
}

const landingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hanzo MPC — Threshold Wallet Infrastructure</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#d4d4d4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column}
a{color:#fff;text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:960px;margin:0 auto;padding:0 24px;width:100%}
header{border-bottom:1px solid #1a1a1a;padding:20px 0}
header .container{display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:12px;font-size:18px;font-weight:600;color:#fff;letter-spacing:-0.02em}
.logo svg{width:28px;height:28px}
.nav-links{display:flex;gap:24px;align-items:center}
.nav-links a{color:#a3a3a3;font-size:14px}
.nav-links a:hover{color:#fff}
.btn{display:inline-flex;align-items:center;padding:8px 20px;border-radius:6px;font-size:14px;font-weight:500;transition:all 0.15s}
.btn-primary{background:#fff;color:#000}
.btn-primary:hover{background:#d4d4d4;text-decoration:none}
.btn-outline{border:1px solid #333;color:#fff}
.btn-outline:hover{border-color:#666;text-decoration:none}
main{flex:1;display:flex;align-items:center;padding:80px 0}
.hero{text-align:center}
.hero h1{font-size:clamp(32px,5vw,56px);font-weight:700;color:#fff;letter-spacing:-0.03em;line-height:1.1;margin-bottom:20px}
.hero .subtitle{font-size:18px;color:#a3a3a3;max-width:600px;margin:0 auto 40px;line-height:1.6}
.hero .ctas{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:60px}
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:32px;text-align:left;margin-top:60px;border-top:1px solid #1a1a1a;padding-top:48px}
.feature h3{color:#fff;font-size:15px;font-weight:600;margin-bottom:8px}
.feature p{color:#666;font-size:14px;line-height:1.5}
.stats{display:flex;justify-content:center;gap:48px;flex-wrap:wrap}
.stat{text-align:center}
.stat .value{font-size:28px;font-weight:700;color:#fff}
.stat .label{font-size:13px;color:#525252;margin-top:4px}
footer{border-top:1px solid #1a1a1a;padding:24px 0}
footer .container{display:flex;justify-content:space-between;align-items:center;font-size:13px;color:#525252}
footer a{color:#525252}
footer a:hover{color:#a3a3a3}
</style>
</head>
<body>
<header>
<div class="container">
  <a href="/" class="logo">
    <svg viewBox="0 0 67 67" xmlns="http://www.w3.org/2000/svg"><rect width="67" height="67" fill="#000"/><path d="M22.21 67V44.6369H0V67H22.21Z" fill="#fff"/><path d="M0 44.6369L22.21 46.8285V44.6369H0Z" fill="#ddd"/><path d="M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z" fill="#fff"/><path d="M22.21 0H0V22.3184H22.21V0Z" fill="#fff"/><path d="M66.7198 0H44.5098V22.3184H66.7198V0Z" fill="#fff"/><path d="M66.6753 22.3185L44.5098 20.0822V22.3185H66.6753Z" fill="#ddd"/><path d="M66.7198 67V44.6369H44.5098V67H66.7198Z" fill="#fff"/></svg>
    Hanzo MPC
  </a>
  <div class="nav-links">
    <a href="https://hanzo.industries/security">Security</a>
    <a href="https://hanzo.ai/docs/mpc">Docs</a>
    <a href="https://hanzo.id" class="btn btn-primary">Sign In</a>
  </div>
</div>
</header>
<main>
<div class="container">
  <div class="hero">
    <h1>Threshold Wallet<br>Infrastructure</h1>
    <p class="subtitle">Enterprise-grade multi-party computation for key generation, threshold signing, and secure custody. No single point of failure.</p>
    <div class="ctas">
      <a href="https://hanzo.id" class="btn btn-primary">Sign In with Hanzo ID</a>
      <a href="/health" class="btn btn-outline">API Status</a>
    </div>
    <div class="stats">
      <div class="stat"><div class="value">2-of-3</div><div class="label">Threshold</div></div>
      <div class="stat"><div class="value">CGGMP21</div><div class="label">Protocol</div></div>
      <div class="stat"><div class="value">FROST</div><div class="label">Taproot/EdDSA</div></div>
      <div class="stat"><div class="value">IAM</div><div class="label">Auth via hanzo.id</div></div>
    </div>
    <div class="features">
      <div class="feature">
        <h3>Key Generation</h3>
        <p>Distributed key generation across threshold parties. Private keys never exist in a single location.</p>
      </div>
      <div class="feature">
        <h3>Threshold Signing</h3>
        <p>Sign transactions with t-of-n parties. Supports secp256k1 (EVM, Bitcoin) and Ed25519 (Solana, Cosmos).</p>
      </div>
      <div class="feature">
        <h3>Dynamic Resharing</h3>
        <p>Add or remove parties without changing the public key. Zero-downtime key rotation.</p>
      </div>
      <div class="feature">
        <h3>Unified Auth</h3>
        <p>All operations secured via Hanzo IAM. Bearer token authentication validated against hanzo.id.</p>
      </div>
    </div>
  </div>
</div>
</main>
<footer>
<div class="container">
  <span>&copy; 2026 Hanzo AI Inc.</span>
  <div style="display:flex;gap:24px">
    <a href="https://hanzo.ai">hanzo.ai</a>
    <a href="https://hanzo.industries">hanzo.industries</a>
    <a href="https://github.com/hanzoai/mpc">GitHub</a>
  </div>
</div>
</footer>
</body>
</html>`

// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	natsOK := s.natsConn != nil && s.natsConn.IsConnected()
	if !natsOK {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"nats":   natsOK,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Wallet (Keygen) ---

type createWalletRequest struct {
	Curve    string         `json:"curve"`    // "secp256k1" (default) or "ed25519"
	Metadata map[string]any `json:"metadata"` // optional user metadata
}

func (s *Server) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	var req createWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Curve == "" {
		req.Curve = "secp256k1"
	}

	walletID := uuid.New().String()
	event := map[string]any{
		"wallet_id":    walletID,
		"curve":        req.Curve,
		"metadata":     req.Metadata,
		"requested_by": user.ID,
	}

	data, _ := json.Marshal(event)
	topic := fmt.Sprintf("mpc.keygen_request.%s", walletID)
	if err := s.natsConn.Publish(topic, data); err != nil {
		logger.Error("Failed to publish keygen request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate keygen"})
		return
	}

	logger.Info("Keygen requested", "walletID", walletID, "curve", req.Curve, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"wallet_id": walletID,
		"status":    "keygen_initiated",
		"curve":     req.Curve,
	})
}

func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	// Wallet listing requires reading from Consul keyinfo store.
	// For now return a placeholder that indicates the endpoint is live.
	writeJSON(w, http.StatusOK, map[string]any{
		"wallets": []any{},
		"message": "wallet listing via keyinfo store — connect to consul for full data",
	})
}

// --- Signing ---

type signRequest struct {
	WalletID string         `json:"wallet_id"`
	Message  string         `json:"message"`  // hex-encoded message to sign
	Metadata map[string]any `json:"metadata"` // chain, tx_type, etc.
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.WalletID == "" || req.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "wallet_id and message are required"})
		return
	}

	sessionID := uuid.New().String()
	event := map[string]any{
		"session_id":   sessionID,
		"wallet_id":    req.WalletID,
		"message":      req.Message,
		"metadata":     req.Metadata,
		"requested_by": user.ID,
	}

	data, _ := json.Marshal(event)
	topic := fmt.Sprintf("mpc.signing_request.%s", req.WalletID)
	if err := s.natsConn.Publish(topic, data); err != nil {
		logger.Error("Failed to publish signing request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate signing"})
		return
	}

	logger.Info("Signing requested", "sessionID", sessionID, "walletID", req.WalletID, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id": sessionID,
		"wallet_id":  req.WalletID,
		"status":     "signing_initiated",
	})
}

// --- Reshare ---

type reshareRequest struct {
	WalletID string `json:"wallet_id"`
	NewN     int    `json:"new_n"` // new total parties
	NewT     int    `json:"new_t"` // new threshold
}

func (s *Server) handleReshare(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	var req reshareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.WalletID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "wallet_id is required"})
		return
	}

	sessionID := uuid.New().String()
	event := map[string]any{
		"session_id":   sessionID,
		"wallet_id":    req.WalletID,
		"new_n":        req.NewN,
		"new_t":        req.NewT,
		"requested_by": user.ID,
	}

	data, _ := json.Marshal(event)
	topic := fmt.Sprintf("mpc.reshare_request.%s", req.WalletID)
	if err := s.natsConn.Publish(topic, data); err != nil {
		logger.Error("Failed to publish reshare request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate reshare"})
		return
	}

	logger.Info("Reshare requested", "sessionID", sessionID, "walletID", req.WalletID, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id": sessionID,
		"wallet_id":  req.WalletID,
		"status":     "reshare_initiated",
	})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
