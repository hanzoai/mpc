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
<title>Hanzo MPC — Enterprise Digital Asset Infrastructure</title>
<meta name="description" content="Self-sovereign wallet infrastructure with multi-party computation. Configurable t-of-n threshold signing, 8 cryptographic protocols, multi-chain support. No single point of failure.">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#d4d4d4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column;-webkit-font-smoothing:antialiased}
a{color:#fff;text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1080px;margin:0 auto;padding:0 24px;width:100%}
header{border-bottom:1px solid #1a1a1a;padding:16px 0;position:sticky;top:0;background:#000;z-index:10}
header .container{display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;color:#fff;letter-spacing:-0.02em}
.logo svg{width:26px;height:26px}
.nav-links{display:flex;gap:20px;align-items:center}
.nav-links a{color:#666;font-size:14px;transition:color 0.15s}
.nav-links a:hover{color:#fff;text-decoration:none}
.btn{display:inline-flex;align-items:center;padding:8px 20px;border-radius:6px;font-size:14px;font-weight:500;transition:all 0.15s}
.btn-primary{background:#fff;color:#000}
.btn-primary:hover{background:#d4d4d4;text-decoration:none}
.btn-outline{border:1px solid #333;color:#fff}
.btn-outline:hover{border-color:#666;text-decoration:none}
.btn-sm{padding:6px 14px;font-size:13px}

/* Hero */
.hero{text-align:center;padding:80px 0 60px}
.hero .badge{display:inline-block;padding:4px 12px;border:1px solid #1a1a1a;border-radius:20px;font-size:12px;color:#666;margin-bottom:24px;letter-spacing:0.04em;text-transform:uppercase}
.hero h1{font-size:clamp(36px,5.5vw,64px);font-weight:700;color:#fff;letter-spacing:-0.035em;line-height:1.05;margin-bottom:20px}
.hero h1 span{color:#525252}
.hero .subtitle{font-size:18px;color:#a3a3a3;max-width:640px;margin:0 auto 36px;line-height:1.65}
.hero .ctas{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}

/* Stats bar */
.stats-bar{border-top:1px solid #1a1a1a;border-bottom:1px solid #1a1a1a;padding:32px 0}
.stats-bar .container{display:flex;justify-content:space-around;flex-wrap:wrap;gap:24px}
.stat{text-align:center;min-width:100px}
.stat .value{font-size:24px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.stat .label{font-size:12px;color:#525252;margin-top:4px;text-transform:uppercase;letter-spacing:0.04em}

/* Section */
section{padding:64px 0}
section h2{font-size:28px;font-weight:700;color:#fff;letter-spacing:-0.02em;margin-bottom:8px}
section .section-sub{color:#666;font-size:15px;margin-bottom:40px;max-width:560px}

/* Protocol grid */
.protocols{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:1px;background:#1a1a1a;border:1px solid #1a1a1a;border-radius:8px;overflow:hidden}
.protocol{background:#050505;padding:24px}
.protocol h3{color:#fff;font-size:14px;font-weight:600;margin-bottom:4px}
.protocol .proto-type{color:#525252;font-size:12px;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:12px}
.protocol p{color:#666;font-size:13px;line-height:1.5}

/* Feature grid */
.features{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:24px}
.feature{border:1px solid #1a1a1a;border-radius:8px;padding:28px}
.feature h3{color:#fff;font-size:15px;font-weight:600;margin-bottom:8px}
.feature p{color:#666;font-size:14px;line-height:1.55}

/* Chain grid */
.chains{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1px;background:#1a1a1a;border:1px solid #1a1a1a;border-radius:8px;overflow:hidden}
.chain{background:#050505;padding:16px 20px;display:flex;align-items:center;justify-content:space-between}
.chain .name{color:#d4d4d4;font-size:14px;font-weight:500}
.chain .curve{color:#525252;font-size:12px;font-family:monospace}

/* Perf table */
.perf{width:100%;border-collapse:collapse;border:1px solid #1a1a1a;border-radius:8px;overflow:hidden}
.perf th{background:#050505;color:#525252;font-size:12px;font-weight:500;text-transform:uppercase;letter-spacing:0.04em;padding:12px 16px;text-align:left;border-bottom:1px solid #1a1a1a}
.perf td{padding:12px 16px;font-size:14px;border-bottom:1px solid #0a0a0a;color:#a3a3a3;font-variant-numeric:tabular-nums}
.perf tr:last-child td{border-bottom:none}
.perf .op{color:#fff;font-weight:500}

/* CTA */
.cta-section{border-top:1px solid #1a1a1a;text-align:center;padding:80px 0}
.cta-section h2{margin-bottom:16px}
.cta-section p{color:#666;font-size:16px;margin-bottom:32px}

footer{border-top:1px solid #1a1a1a;padding:24px 0;margin-top:auto}
footer .container{display:flex;justify-content:space-between;align-items:center;font-size:13px;color:#333}
footer a{color:#333;transition:color 0.15s}
footer a:hover{color:#666;text-decoration:none}

@media(max-width:640px){
  .hero{padding:48px 0 40px}
  .stats-bar .container{justify-content:center}
  .protocols,.chains{grid-template-columns:1fr}
  .features{grid-template-columns:1fr}
  .perf{font-size:13px}
  .perf th,.perf td{padding:8px 12px}
}
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
    <a href="#protocols">Protocols</a>
    <a href="#chains">Chains</a>
    <a href="#performance">Performance</a>
    <a href="https://hanzo.ai/docs/mpc">Docs</a>
    <a href="https://hanzo.id" class="btn btn-primary btn-sm">Sign In</a>
  </div>
</div>
</header>

<div class="hero">
<div class="container">
  <div class="badge">Self-Sovereign Wallet Infrastructure</div>
  <h1>Digital Asset Custody<br><span>Without Compromise</span></h1>
  <p class="subtitle">Enterprise-grade multi-party computation with 8 cryptographic protocols, configurable t-of-n thresholds, multi-chain support, and post-quantum security. Your keys never exist in a single location.</p>
  <div class="ctas">
    <a href="https://hanzo.id" class="btn btn-primary">Get Started with Hanzo ID</a>
    <a href="/health" class="btn btn-outline">API Status</a>
    <a href="https://github.com/hanzoai/mpc" class="btn btn-outline">GitHub</a>
  </div>
</div>
</div>

<div class="stats-bar">
<div class="container">
  <div class="stat"><div class="value">8</div><div class="label">Protocols</div></div>
  <div class="stat"><div class="value">t-of-n</div><div class="label">Configurable</div></div>
  <div class="stat"><div class="value">21ms</div><div class="label">Signing (5-of-n)</div></div>
  <div class="stat"><div class="value">4</div><div class="label">Curves</div></div>
  <div class="stat"><div class="value">17</div><div class="label">ZK Proofs</div></div>
  <div class="stat"><div class="value">PQ</div><div class="label">Quantum-Safe</div></div>
</div>
</div>

<section id="protocols">
<div class="container">
  <h2>Cryptographic Protocols</h2>
  <p class="section-sub">Production-grade implementations spanning classical threshold cryptography, post-quantum lattice schemes, and fully homomorphic encryption.</p>
  <div class="protocols">
    <div class="protocol">
      <h3>CGGMP21</h3>
      <div class="proto-type">Threshold ECDSA</div>
      <p>4-round signing with identifiable aborts over secp256k1. Presignatures for offline signing. Bitcoin, Ethereum, all EVM chains.</p>
    </div>
    <div class="protocol">
      <h3>FROST</h3>
      <div class="proto-type">Threshold Schnorr / EdDSA</div>
      <p>2-round signing with hedged deterministic nonces. Ed25519 for Solana and TON. BIP-340 Taproot for Bitcoin. BIP-32 chaining keys.</p>
    </div>
    <div class="protocol">
      <h3>LSSS</h3>
      <div class="proto-type">Linear Secret Sharing</div>
      <p>Dynamic resharing without key reconstruction. Transition t-of-n to t'-of-(n&plusmn;k) with zero downtime. Generation history with rollback. Byzantine fault tolerant.</p>
    </div>
    <div class="protocol">
      <h3>TFHE</h3>
      <div class="proto-type">Threshold Homomorphic Encryption</div>
      <p>Multi-party threshold decryption with homomorphic operations. Partial share aggregation via Lagrange coefficients. Confidential compute on encrypted data.</p>
    </div>
    <div class="protocol">
      <h3>Ringtail</h3>
      <div class="proto-type">Post-Quantum Lattice</div>
      <p>Module-LWE threshold signatures at 128/192/256-bit security levels. Proactive share refresh. Protection against quantum adversaries.</p>
    </div>
    <div class="protocol">
      <h3>Quasar</h3>
      <div class="proto-type">Hybrid BLS + Post-Quantum</div>
      <p>Quantum-Safe And Reliable. Combines BLS12-381 pairing-based signatures with Ringtail lattice for immediate and future-proof security.</p>
    </div>
    <div class="protocol">
      <h3>BLS</h3>
      <div class="proto-type">Aggregate Signatures</div>
      <p>BLS12-381 pairing-based threshold signatures with efficient aggregation. Compatible with Ethereum 2.0 and other consensus systems.</p>
    </div>
    <div class="protocol">
      <h3>Doerner</h3>
      <div class="proto-type">Optimized 2-of-2 ECDSA</div>
      <p>Constant-time 2-party ECDSA at ~5ms signing. Specialized for peer-to-peer custody and co-signing workflows.</p>
    </div>
  </div>
</div>
</section>

<section>
<div class="container">
  <h2>Platform Capabilities</h2>
  <p class="section-sub">Everything you need for institutional-grade digital asset custody and wallet operations.</p>
  <div class="features">
    <div class="feature">
      <h3>Configurable Threshold</h3>
      <p>Any t-of-n scheme: 2-of-3, 3-of-5, 5-of-9, 10-of-15, or any custom configuration. Byzantine-resilient majority with t &ge; &lfloor;n/2&rfloor; + 1.</p>
    </div>
    <div class="feature">
      <h3>Dynamic Resharing</h3>
      <p>Add or remove signing parties without changing public keys or addresses. LSSS-based protocol transitions t-of-n to t'-of-(n&plusmn;k) with generation rollback on failure.</p>
    </div>
    <div class="feature">
      <h3>Post-Quantum Security</h3>
      <p>Ringtail lattice-based signatures and Quasar hybrid scheme provide protection against future quantum computer attacks at configurable security levels.</p>
    </div>
    <div class="feature">
      <h3>Confidential Compute</h3>
      <p>TFHE threshold homomorphic encryption enables computation on encrypted data. Multi-party decryption with partial share aggregation. Private policy evaluation.</p>
    </div>
    <div class="feature">
      <h3>Zero-Knowledge Proofs</h3>
      <p>17 ZK proof systems including Paillier multiplication, Pedersen-Rabin, Schnorr proofs, range proofs, and polynomial commitments for verifiable computation.</p>
    </div>
    <div class="feature">
      <h3>Unified IAM</h3>
      <p>All operations authenticated via Hanzo ID. Bearer token validation, role-based access control, and audit logging for compliance.</p>
    </div>
  </div>
</div>
</section>

<section id="chains">
<div class="container">
  <h2>Multi-Chain Support</h2>
  <p class="section-sub">Native support for every major blockchain ecosystem through protocol-specific curve implementations.</p>
  <div class="chains">
    <div class="chain"><span class="name">Bitcoin</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Bitcoin Taproot</span><span class="curve">BIP-340</span></div>
    <div class="chain"><span class="name">Ethereum</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">All EVM Chains</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Solana</span><span class="curve">Ed25519</span></div>
    <div class="chain"><span class="name">TON</span><span class="curve">Ed25519</span></div>
    <div class="chain"><span class="name">Cardano</span><span class="curve">Ed25519</span></div>
    <div class="chain"><span class="name">NEAR</span><span class="curve">Ed25519</span></div>
    <div class="chain"><span class="name">Polkadot</span><span class="curve">Ed25519</span></div>
    <div class="chain"><span class="name">Cosmos</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Lux Network</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">XRPL</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">BNB Chain</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Polygon</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Arbitrum</span><span class="curve">secp256k1</span></div>
    <div class="chain"><span class="name">Ethereum 2.0</span><span class="curve">BLS12-381</span></div>
  </div>
</div>
</section>

<section id="performance">
<div class="container">
  <h2>Performance</h2>
  <p class="section-sub">Real benchmarks on Apple M-series silicon. Signing is O(t) — independent of total party count. Keygen is O(n&sup2;) communication.</p>

  <h3 style="color:#fff;font-size:16px;margin:32px 0 16px;font-weight:600">FROST Protocol — Full Execution (secp256k1)</h3>
  <table class="perf">
    <thead><tr><th>Operation</th><th>3 parties</th><th>10 parties</th><th>20 parties</th><th>30 parties</th><th>50 parties</th></tr></thead>
    <tbody>
      <tr><td class="op">Key Generation</td><td>22ms</td><td>38ms</td><td>332ms</td><td>535ms</td><td>1.9s</td></tr>
      <tr><td class="op">Signing (t signers)</td><td>25ms</td><td>21ms</td><td>30ms</td><td>45ms</td><td>65ms</td></tr>
      <tr><td class="op">Verification</td><td>2ms</td><td>2ms</td><td>2ms</td><td>2ms</td><td>2ms</td></tr>
    </tbody>
  </table>

  <h3 style="color:#fff;font-size:16px;margin:32px 0 16px;font-weight:600">Cryptographic Primitives at Scale</h3>
  <table class="perf">
    <thead><tr><th>Operation</th><th>10</th><th>100</th><th>1,000</th><th>10,000</th></tr></thead>
    <tbody>
      <tr><td class="op">Scalar Multiplication</td><td>6.6ms</td><td>2.3ms</td><td>23ms</td><td>232ms</td></tr>
      <tr><td class="op">Point Addition</td><td>&lt;0.01ms</td><td>0.1ms</td><td>1.1ms</td><td>11ms</td></tr>
      <tr><td class="op">Lagrange Coefficients</td><td>0.1ms</td><td>10ms</td><td>1.3s</td><td>115s</td></tr>
      <tr><td class="op">Polynomial Evaluation</td><td>&lt;0.01ms</td><td>1.6ms</td><td>166ms</td><td>16.7s</td></tr>
      <tr><td class="op">Blake3 Hashing</td><td>&lt;0.01ms</td><td>0.03ms</td><td>0.4ms</td><td>3.4ms</td></tr>
    </tbody>
  </table>
  <p style="color:#525252;font-size:13px;margin-top:16px">Signing uses only t threshold signers regardless of total n. A 10-of-10,000 scheme signs as fast as 10-of-10. Keygen/reshare touch all n parties — use tiered architecture at &gt;100 nodes.</p>
</div>
</section>

<section>
<div class="container">
  <h2>Security Properties</h2>
  <div class="features">
    <div class="feature">
      <h3>No Single Point of Failure</h3>
      <p>Private keys are never reconstructed. Threshold parties hold shares that are individually useless. Compromise of t-1 parties reveals nothing.</p>
    </div>
    <div class="feature">
      <h3>Identifiable Aborts</h3>
      <p>CGGMP21 identifies the exact cheating party in a failed signing session. Automated fault recovery with node eviction via LSSS.</p>
    </div>
    <div class="feature">
      <h3>Proactive Security</h3>
      <p>LSSS share refresh and Ringtail proactive rotation ensure long-term security even if shares are periodically exposed. Generation-based key lifecycle.</p>
    </div>
    <div class="feature">
      <h3>Encrypted Storage</h3>
      <p>All key shares encrypted at rest with AES-256 via BadgerDB. Optional KMS integration for hardware-backed encryption keys.</p>
    </div>
  </div>
</div>
</section>

<div class="cta-section">
<div class="container">
  <h2>Ready to secure your digital assets?</h2>
  <p>Get started with Hanzo MPC in minutes. Self-hosted or managed.</p>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
    <a href="https://hanzo.id" class="btn btn-primary">Sign In with Hanzo ID</a>
    <a href="https://hanzo.industries/contact" class="btn btn-outline">Contact Sales</a>
    <a href="https://hanzo.ai/docs/mpc" class="btn btn-outline">Read the Docs</a>
  </div>
</div>
</div>

<footer>
<div class="container">
  <span>&copy; 2026 Hanzo AI Inc. &middot; Techstars '17</span>
  <div style="display:flex;gap:20px">
    <a href="https://hanzo.ai">hanzo.ai</a>
    <a href="https://hanzo.industries">hanzo.industries</a>
    <a href="https://hanzo.network">hanzo.network</a>
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
