package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/client"
	"github.com/hanzoai/mpc/pkg/hsm"
	"github.com/hanzoai/mpc/pkg/infra"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/logger"
	"github.com/hanzoai/mpc/pkg/policy"
	"github.com/hanzoai/mpc/pkg/types"
)

// Server provides HTTP REST API for MPC operations with IAM auth.
type Server struct {
	httpServer   *http.Server
	natsConn     *nats.Conn
	iam          *IAMMiddleware
	apiKeys      *APIKeyStore
	wallets      *WalletStore
	policy       *policy.PolicyEngine
	webhooks     *WebhookStore
	consulKV     infra.ConsulKV
	keyInfoStore keyinfo.Store
	mpcClient    client.MPCClient // signs and publishes keygen/signing/reshare via JetStream
	hsmProvider  hsm.Provider     // HSM provider for key management (optional)
}

// Config holds configuration for the API server.
type Config struct {
	Port             int
	IAMEndpoint      string // e.g. "https://hanzo.id"
	NATSConn         *nats.Conn
	ConsulKV         infra.ConsulKV // Consul KV for wallet metadata
	InitiatorKeyPath string         // path to event_initiator.key (Ed25519 private key)
	HSMProvider      hsm.Provider   // HSM provider for key management (optional)
}

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	var kis keyinfo.Store
	if cfg.ConsulKV != nil {
		kis = keyinfo.NewStore(cfg.ConsulKV)
	}

	// Create MPC client for signed message publishing (graceful — don't crash if key is missing)
	keyPath := cfg.InitiatorKeyPath
	if keyPath == "" {
		keyPath = "./event_initiator.key"
	}
	var mpcCli client.MPCClient
	if cfg.NATSConn != nil {
		mpcCli = newMPCClientSafe(cfg.NATSConn, keyPath)
	}

	var apiKeys *APIKeyStore
	if cfg.ConsulKV != nil {
		apiKeys = NewAPIKeyStore(cfg.ConsulKV)
	}

	s := &Server{
		natsConn:     cfg.NATSConn,
		iam:          NewIAMMiddleware(cfg.IAMEndpoint),
		apiKeys:      apiKeys,
		wallets:      NewWalletStore(cfg.NATSConn),
		policy:       policy.NewPolicyEngine(),
		webhooks:     NewWebhookStore(),
		consulKV:     cfg.ConsulKV,
		keyInfoStore: kis,
		mpcClient:    mpcCli,
		hsmProvider:  cfg.HSMProvider,
	}

	mux := http.NewServeMux()

	// Public endpoints (no auth)
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)

	// Protected endpoints (IAM token or sk_mpc_ API key)
	authed := s.iam.Wrap(s.apiKeys, http.HandlerFunc(s.routeAPI))
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
	s.wallets.Close()
	return s.httpServer.Shutdown(ctx)
}

// routeAPI dispatches authenticated API requests.
func (s *Server) routeAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	// Wallets
	case r.Method == "POST" && path == "/api/v1/wallets":
		s.handleCreateWallet(w, r)
	case r.Method == "GET" && path == "/api/v1/wallets":
		s.handleListWallets(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/wallets/") && !strings.Contains(path[len("/api/v1/wallets/"):], "/"):
		s.handleGetWallet(w, r)

	// Signing
	case r.Method == "POST" && path == "/api/v1/sign":
		s.handleSign(w, r)

	// Transactions (signing history)
	case r.Method == "GET" && path == "/api/v1/transactions":
		s.handleListTransactions(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/transactions/"):
		s.handleGetTransaction(w, r)

	// Reshare
	case r.Method == "POST" && path == "/api/v1/reshare":
		s.handleReshare(w, r)

	// Policies
	case r.Method == "POST" && path == "/api/v1/policies":
		s.handleCreatePolicy(w, r)
	case r.Method == "GET" && path == "/api/v1/policies":
		s.handleListPolicies(w, r)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/policies/"):
		s.handleDeletePolicy(w, r)

	// Wallet-specific policies
	case r.Method == "PUT" && strings.HasSuffix(path, "/policy") && strings.HasPrefix(path, "/api/v1/wallets/"):
		s.handleSetWalletPolicy(w, r)
	case r.Method == "GET" && strings.HasSuffix(path, "/policy") && strings.HasPrefix(path, "/api/v1/wallets/"):
		s.handleGetWalletPolicy(w, r)

	// Signers
	case r.Method == "POST" && path == "/api/v1/signers":
		s.handleCreateSigner(w, r)
	case r.Method == "GET" && path == "/api/v1/signers":
		s.handleListSigners(w, r)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/signers/"):
		s.handleDeleteSigner(w, r)

	// Webhooks
	case r.Method == "POST" && path == "/api/v1/webhooks":
		s.handleCreateWebhook(w, r)
	case r.Method == "GET" && path == "/api/v1/webhooks":
		s.handleListWebhooks(w, r)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/webhooks/"):
		s.handleDeleteWebhook(w, r)

	// API Keys
	case r.Method == "POST" && path == "/api/v1/keys":
		s.handleCreateAPIKey(w, r)
	case r.Method == "GET" && path == "/api/v1/keys":
		s.handleListAPIKeys(w, r)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/api/v1/keys/"):
		s.handleDeleteAPIKey(w, r)

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
    <a href="#" onclick="startLogin()" class="btn btn-primary btn-sm">Sign In</a>
  </div>
</div>
</header>

<div class="hero">
<div class="container">
  <div class="badge">Self-Sovereign Wallet Infrastructure</div>
  <h1>Digital Asset Custody<br><span>Without Compromise</span></h1>
  <p class="subtitle">Enterprise-grade multi-party computation with 8 cryptographic protocols, configurable t-of-n thresholds, multi-chain support, and post-quantum security. Your keys never exist in a single location.</p>
  <div class="ctas">
    <a href="#" onclick="startLogin()" class="btn btn-primary">Get Started with Hanzo ID</a>
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
    <a href="#" onclick="startLogin()" class="btn btn-primary">Sign In with Hanzo ID</a>
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
<script>
// PKCE OAuth — client-side, no backend secret needed
const IAM_URL = 'https://hanzo.id';
const CLIENT_ID = 'hanzo-app-client-id';
const REDIRECT_URI = location.origin + '/auth/callback';
const SCOPE = 'openid profile email';

function generateCodeVerifier() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function sha256(plain) {
  const enc = new TextEncoder().encode(plain);
  const hash = await crypto.subtle.digest('SHA-256', enc);
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function startLogin() {
  const verifier = generateCodeVerifier();
  const challenge = await sha256(verifier);
  sessionStorage.setItem('pkce_verifier', verifier);
  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: state,
  });
  location.href = IAM_URL + '/login/oauth/authorize?' + params;
}
// Check if already logged in
if (localStorage.getItem('mpc_token')) {
  const btn = document.querySelector('.nav-links a[onclick]');
  if (btn) { btn.textContent = 'Dashboard'; btn.setAttribute('onclick', "location.href='/dashboard'"); }
}
</script>
</body>
</html>`

// --- Auth ---

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(authCallbackHTML))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML))
}

const authCallbackHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hanzo MPC — Authenticating...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#d4d4d4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{border:1px solid #1a1a1a;border-radius:12px;padding:48px;max-width:420px;text-align:center}
h1{color:#fff;font-size:20px;margin-bottom:12px}
p{color:#666;font-size:14px;line-height:1.6}
.spinner{width:32px;height:32px;border:3px solid #1a1a1a;border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 24px}
@keyframes spin{to{transform:rotate(360deg)}}
.error{color:#dc2626;margin-top:16px;display:none}
a{color:#fff;text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <div class="spinner" id="spinner"></div>
  <h1>Authenticating...</h1>
  <p id="status">Exchanging authorization code with Hanzo ID</p>
  <p class="error" id="error"></p>
</div>
<script>
const IAM_URL = 'https://hanzo.id';
const CLIENT_ID = 'hanzo-app-client-id';
const REDIRECT_URI = location.origin + '/auth/callback';

async function handleCallback() {
  const params = new URLSearchParams(location.search);
  const code = params.get('code');
  const state = params.get('state');
  const error = params.get('error');

  // Check for direct token (from worker flow)
  const accessToken = params.get('access_token');
  if (accessToken) {
    localStorage.setItem('mpc_token', accessToken);
    localStorage.setItem('mpc_refresh_token', params.get('refresh_token') || '');
    location.href = '/dashboard';
    return;
  }

  if (error) {
    showError(params.get('error_description') || error);
    return;
  }

  if (!code) {
    showError('No authorization code received');
    return;
  }

  // Verify state
  const savedState = sessionStorage.getItem('oauth_state');
  if (savedState && state !== savedState) {
    showError('State mismatch — possible CSRF attack');
    return;
  }

  // Exchange code with PKCE (no secret needed)
  const verifier = sessionStorage.getItem('pkce_verifier');
  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    });
    if (verifier) body.set('code_verifier', verifier);

    const resp = await fetch(IAM_URL + '/api/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: body,
    });
    const data = await resp.json();

    if (data.access_token) {
      localStorage.setItem('mpc_token', data.access_token);
      localStorage.setItem('mpc_refresh_token', data.refresh_token || '');
      sessionStorage.removeItem('pkce_verifier');
      sessionStorage.removeItem('oauth_state');
      location.href = '/dashboard';
    } else {
      showError(data.error_description || data.error || 'Token exchange failed');
    }
  } catch (e) {
    showError('Network error: ' + e.message);
  }
}

function showError(msg) {
  document.getElementById('spinner').style.display = 'none';
  document.getElementById('status').textContent = 'Authentication failed';
  const el = document.getElementById('error');
  el.style.display = 'block';
  el.innerHTML = msg + '<br><br><a href="/">Back to home</a>';
}

handleCallback();
</script>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hanzo MPC — Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#d4d4d4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column;-webkit-font-smoothing:antialiased}
a{color:#fff;text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1080px;margin:0 auto;padding:0 24px;width:100%}
header{border-bottom:1px solid #1a1a1a;padding:16px 0;background:#000}
header .container{display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;color:#fff;letter-spacing:-0.02em}
.logo svg{width:26px;height:26px}
.nav-links{display:flex;gap:16px;align-items:center}
.nav-links a{color:#666;font-size:14px}
.nav-links a:hover{color:#fff}
.btn{display:inline-flex;align-items:center;padding:8px 20px;border-radius:6px;font-size:14px;font-weight:500;transition:all 0.15s;cursor:pointer;border:none}
.btn-primary{background:#fff;color:#000}
.btn-primary:hover{background:#d4d4d4}
.btn-outline{border:1px solid #333;color:#fff;background:transparent}
.btn-outline:hover{border-color:#666}
.btn-sm{padding:6px 14px;font-size:13px}
.btn-danger{background:#dc2626;color:#fff}
.btn-danger:hover{background:#b91c1c}
main{flex:1;padding:40px 0}
h1{font-size:28px;font-weight:700;color:#fff;letter-spacing:-0.02em;margin-bottom:8px}
.subtitle{color:#666;font-size:15px;margin-bottom:32px}
.user-info{border:1px solid #1a1a1a;border-radius:8px;padding:24px;margin-bottom:32px}
.user-info h3{color:#fff;font-size:15px;font-weight:600;margin-bottom:12px}
.user-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #0a0a0a;font-size:14px}
.user-row:last-child{border-bottom:none}
.user-row .label{color:#525252}
.user-row .value{color:#d4d4d4;font-family:monospace}
.token-box{border:1px solid #1a1a1a;border-radius:8px;padding:24px;margin-bottom:32px}
.token-box h3{color:#fff;font-size:15px;font-weight:600;margin-bottom:12px}
.token-box p{color:#666;font-size:13px;margin-bottom:12px}
.token-display{background:#050505;border:1px solid #1a1a1a;border-radius:6px;padding:12px 16px;font-family:monospace;font-size:13px;color:#a3a3a3;word-break:break-all;position:relative;cursor:pointer}
.token-display:hover{border-color:#333}
.copied{position:absolute;top:8px;right:12px;color:#22c55e;font-size:12px;opacity:0;transition:opacity 0.2s}
.copied.show{opacity:1}
.api-test{border:1px solid #1a1a1a;border-radius:8px;padding:24px;margin-bottom:32px}
.api-test h3{color:#fff;font-size:15px;font-weight:600;margin-bottom:12px}
.api-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.result{background:#050505;border:1px solid #1a1a1a;border-radius:6px;padding:16px;font-family:monospace;font-size:13px;color:#a3a3a3;white-space:pre-wrap;max-height:300px;overflow:auto;display:none}
.wallets-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-top:16px}
.wallet-card{border:1px solid #1a1a1a;border-radius:8px;padding:20px}
.wallet-card h4{color:#fff;font-size:14px;margin-bottom:8px}
.wallet-card .curve-badge{display:inline-block;padding:2px 8px;border:1px solid #333;border-radius:4px;font-size:11px;color:#a3a3a3;font-family:monospace;margin-bottom:8px}
.wallet-card .id{color:#525252;font-size:12px;font-family:monospace;word-break:break-all}
footer{border-top:1px solid #1a1a1a;padding:24px 0;margin-top:auto}
footer .container{display:flex;justify-content:space-between;font-size:13px;color:#333}
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
    <a href="/">Home</a>
    <a href="https://hanzo.ai/docs/mpc">Docs</a>
    <a href="https://github.com/hanzoai/mpc">GitHub</a>
    <a href="#" onclick="logout()" class="btn btn-outline btn-sm">Sign Out</a>
  </div>
</div>
</header>

<main>
<div class="container">
  <h1>MPC Dashboard</h1>
  <p class="subtitle">Manage wallets, sign transactions, and monitor your MPC infrastructure.</p>

  <div class="user-info" id="user-info" style="display:none">
    <h3>Authenticated User</h3>
    <div class="user-row"><span class="label">Name</span><span class="value" id="u-name">—</span></div>
    <div class="user-row"><span class="label">Email</span><span class="value" id="u-email">—</span></div>
    <div class="user-row"><span class="label">ID</span><span class="value" id="u-id">—</span></div>
    <div class="user-row"><span class="label">Type</span><span class="value" id="u-type">—</span></div>
  </div>

  <div class="token-box">
    <h3>API Bearer Token</h3>
    <p>Use this token in the <code>Authorization: Bearer &lt;token&gt;</code> header for all API requests.</p>
    <div class="token-display" id="token-display" onclick="copyToken()">
      <span id="token-text">Loading...</span>
      <span class="copied" id="copied-msg">Copied!</span>
    </div>
  </div>

  <div class="api-test">
    <h3>Quick Actions</h3>
    <div class="api-actions">
      <button class="btn btn-outline btn-sm" onclick="apiCall('GET','/api/v1/wallets')">List Wallets</button>
      <button class="btn btn-primary btn-sm" onclick="createWallet('secp256k1')">+ secp256k1 Wallet</button>
      <button class="btn btn-primary btn-sm" onclick="createWallet('ed25519')">+ Ed25519 Wallet</button>
      <button class="btn btn-primary btn-sm" onclick="createWallet('bls12381')">+ BLS12-381 Wallet</button>
      <button class="btn btn-outline btn-sm" onclick="apiCall('GET','/health')">Health Check</button>
    </div>
    <pre class="result" id="result"></pre>
  </div>

  <div id="wallets-section" style="display:none">
    <h3 style="color:#fff;font-size:15px;font-weight:600;margin-bottom:4px">Wallets</h3>
    <p style="color:#666;font-size:13px;margin-bottom:16px">Your MPC wallets across all supported curves.</p>
    <div class="wallets-grid" id="wallets-grid"></div>
  </div>
</div>
</main>

<footer>
<div class="container">
  <span>&copy; 2026 Hanzo AI Inc.</span>
  <a href="https://hanzo.ai" style="color:#333">hanzo.ai</a>
</div>
</footer>

<script>
const API_BASE = location.origin;
const IAM_URL = 'https://hanzo.id';
const token = localStorage.getItem('mpc_token');

if (!token) {
  location.href = '/';
}

// Show token
document.getElementById('token-text').textContent = token ? (token.substring(0, 20) + '...' + token.substring(token.length - 10)) : 'No token';

// Fetch user info
async function loadUser() {
  try {
    const resp = await fetch(IAM_URL + '/api/userinfo', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (resp.ok) {
      const user = await resp.json();
      document.getElementById('u-name').textContent = user.displayName || user.name || '—';
      document.getElementById('u-email').textContent = user.email || '—';
      document.getElementById('u-id').textContent = user.id || user.sub || '—';
      document.getElementById('u-type').textContent = user.type || 'user';
      document.getElementById('user-info').style.display = 'block';
    }
  } catch (e) { console.error('Failed to load user:', e); }
}

function copyToken() {
  navigator.clipboard.writeText(token || '');
  const msg = document.getElementById('copied-msg');
  msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 1500);
}

async function apiCall(method, path, body) {
  const el = document.getElementById('result');
  el.style.display = 'block';
  el.textContent = method + ' ' + path + '\n\nLoading...';
  try {
    const opts = {
      method,
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(API_BASE + path, opts);
    const data = await resp.json();
    el.textContent = method + ' ' + path + ' → ' + resp.status + '\n\n' + JSON.stringify(data, null, 2);
    return data;
  } catch (e) {
    el.textContent = method + ' ' + path + '\n\nError: ' + e.message;
  }
}

async function createWallet(curve) {
  const data = await apiCall('POST', '/api/v1/wallets', { curve });
  if (data && data.wallet_id) {
    loadWallets();
  }
}

async function loadWallets() {
  try {
    const resp = await fetch(API_BASE + '/api/v1/wallets', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const data = await resp.json();
    if (data.wallets && data.wallets.length > 0) {
      const section = document.getElementById('wallets-section');
      const grid = document.getElementById('wallets-grid');
      section.style.display = 'block';
      grid.innerHTML = data.wallets.map(w => ` + "`" + `
        <div class="wallet-card">
          <h4>Wallet</h4>
          <span class="curve-badge">${w.curve || 'unknown'}</span>
          <div class="id">${w.wallet_id || w.id}</div>
        </div>
      ` + "`" + `).join('');
    }
  } catch (e) {}
}

function logout() {
  localStorage.removeItem('mpc_token');
  localStorage.removeItem('mpc_refresh_token');
  location.href = '/';
}

loadUser();
loadWallets();
</script>
</body>
</html>`

// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	natsOK := s.natsConn != nil && s.natsConn.IsConnected()

	consulOK := false
	if s.consulKV != nil {
		// Quick check: list ready/ prefix (lightweight)
		_, _, err := s.consulKV.List("ready/", nil)
		consulOK = err == nil
	}

	if !natsOK || (s.consulKV != nil && !consulOK) {
		status = "degraded"
	}

	hsmStatus := map[string]any{"enabled": false}
	if s.hsmProvider != nil {
		hsmStatus["enabled"] = true
		hsmStatus["provider"] = s.hsmProvider.Name()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.hsmProvider.Healthy(ctx); err != nil {
			hsmStatus["healthy"] = false
			hsmStatus["error"] = err.Error()
		} else {
			hsmStatus["healthy"] = true
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"nats":   natsOK,
		"consul": consulOK,
		"hsm":    hsmStatus,
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

	if s.mpcClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MPC client not initialized"})
		return
	}

	walletID := uuid.New().String()

	// Track in wallet store before publishing
	s.wallets.TrackWallet(walletID, req.Curve, user.ID, req.Metadata)

	// Persist wallet owner to Consul so ownership survives pod restarts
	if s.consulKV != nil {
		if _, err := s.consulKV.Put(&consulapi.KVPair{
			Key:   "wallet_owner/" + walletID,
			Value: []byte(user.ID),
		}, nil); err != nil {
			logger.Warn("Failed to persist wallet owner to Consul", "walletID", walletID, "error", err)
		}
	}

	// Use the MPC client which signs the message with the initiator key
	// and publishes via JetStream (same flow as the CLI client)
	if err := s.mpcClient.CreateWallet(walletID); err != nil {
		logger.Error("Failed to publish signed keygen request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate keygen"})
		return
	}

	// Dispatch webhook
	s.webhooks.Dispatch(WebhookKeygenCompleted, map[string]any{
		"wallet_id": walletID, "curve": req.Curve, "status": "pending",
	})

	logger.Info("Keygen requested (signed)", "walletID", walletID, "curve", req.Curve, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"wallet_id": walletID,
		"status":    "keygen_initiated",
		"curve":     req.Curve,
	})
}

func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())

	// Merge in-memory pending wallets with Consul-backed completed wallets.
	result := make([]map[string]any, 0)

	// 1. Get in-memory wallets owned by this user
	memWallets := s.wallets.ListWallets(user.ID)
	seen := make(map[string]bool)
	for _, mw := range memWallets {
		seen[mw.ID] = true
		result = append(result, map[string]any{
			"id":         mw.ID,
			"curve":      mw.Curve,
			"status":     mw.Status,
			"public_key": mw.PublicKey,
			"owner":      mw.Owner,
			"created_at": mw.CreatedAt,
			"updated_at": mw.UpdatedAt,
		})
	}

	// 2. Enumerate Consul keyinfo for wallets completed across all pods (filter by owner)
	if s.consulKV != nil {
		pairs, _, err := s.consulKV.List("threshold_keyinfo/", nil)
		if err != nil {
			logger.Warn("Failed to list wallets from Consul", "error", err)
		} else {
			for _, pair := range pairs {
				walletID := strings.TrimPrefix(pair.Key, "threshold_keyinfo/")
				if walletID == "" || seen[walletID] {
					continue
				}

				// Check ownership via wallet_owner/ prefix
				ownerPair, _, oErr := s.consulKV.Get("wallet_owner/"+walletID, nil)
				if oErr != nil || ownerPair == nil || string(ownerPair.Value) != user.ID {
					continue
				}
				seen[walletID] = true

				var ki keyinfo.KeyInfo
				if err := json.Unmarshal(pair.Value, &ki); err != nil {
					continue
				}
				result = append(result, map[string]any{
					"id":        walletID,
					"status":    "active",
					"threshold": ki.Threshold,
					"parties":   len(ki.ParticipantPeerIDs),
					"version":   ki.Version,
					"curve":     ki.Curve,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"wallets": result,
		"count":   len(result),
	})
}

func (s *Server) handleGetWallet(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	walletID := strings.TrimPrefix(r.URL.Path, "/api/v1/wallets/")

	// Check in-memory first (for pending wallets on this pod)
	if wallet, ok := s.wallets.GetWallet(walletID); ok {
		if wallet.Owner != user.ID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}
		// Enrich with Consul keyinfo if available
		if s.keyInfoStore != nil {
			if ki, err := s.keyInfoStore.Get(walletID); err == nil {
				writeJSON(w, http.StatusOK, map[string]any{
					"id":         wallet.ID,
					"curve":      wallet.Curve,
					"status":     wallet.Status,
					"public_key": wallet.PublicKey,
					"owner":      wallet.Owner,
					"threshold":  ki.Threshold,
					"parties":    len(ki.ParticipantPeerIDs),
					"version":    ki.Version,
					"created_at": wallet.CreatedAt,
					"updated_at": wallet.UpdatedAt,
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, wallet)
		return
	}

	// Fall back to Consul keyinfo (wallet created on another pod or before restart)
	// Verify ownership via wallet_owner/ prefix
	if s.consulKV != nil {
		ownerPair, _, err := s.consulKV.Get("wallet_owner/"+walletID, nil)
		if err != nil || ownerPair == nil || string(ownerPair.Value) != user.ID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet not found"})
			return
		}
	}
	if s.keyInfoStore != nil {
		ki, err := s.keyInfoStore.Get(walletID)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"id":        walletID,
				"status":    "active",
				"threshold": ki.Threshold,
				"parties":   len(ki.ParticipantPeerIDs),
				"version":   ki.Version,
				"curve":     ki.Curve,
			})
			return
		}
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet not found"})
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

	// Verify wallet ownership before signing
	if wallet, ok := s.wallets.GetWallet(req.WalletID); ok {
		if wallet.Owner != user.ID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}
	} else if s.consulKV != nil {
		ownerPair, _, err := s.consulKV.Get("wallet_owner/"+req.WalletID, nil)
		if err != nil || ownerPair == nil || string(ownerPair.Value) != user.ID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet not found"})
			return
		}
	}

	// Evaluate policy before signing
	chain := ""
	asset := ""
	destination := ""
	var amount *big.Int
	if req.Metadata != nil {
		if c, ok := req.Metadata["chain"].(string); ok {
			chain = c
		}
		if a, ok := req.Metadata["asset"].(string); ok {
			asset = a
		}
		if d, ok := req.Metadata["destination"].(string); ok {
			destination = d
		}
		if amt, ok := req.Metadata["amount"].(string); ok {
			amount = new(big.Int)
			amount.SetString(amt, 10)
		}
	}
	if amount == nil {
		amount = big.NewInt(0)
	}

	policyResult, err := s.policy.Evaluate(r.Context(), &policy.TransactionRequest{
		ID:          uuid.New().String(),
		WalletID:    req.WalletID,
		InitiatorID: user.ID,
		Chain:       chain,
		Asset:       asset,
		Amount:      amount,
		Destination: destination,
		Metadata:    mapAnyToString(req.Metadata),
		CreatedAt:   time.Now(),
	})
	if err != nil {
		logger.Error("Policy evaluation failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy evaluation failed"})
		return
	}

	if !policyResult.Allowed {
		s.webhooks.Dispatch(WebhookPolicyDenied, map[string]any{
			"wallet_id": req.WalletID, "reason": policyResult.DenyReason,
			"matched_rules": policyResult.MatchedRules,
		})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":         "transaction denied by policy",
			"reason":        policyResult.DenyReason,
			"matched_rules": policyResult.MatchedRules,
		})
		return
	}

	if policyResult.Action == policy.ActionRequireApproval {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":           "approval_required",
			"wallet_id":        req.WalletID,
			"required_signers": policyResult.RequiredSigners,
			"required_count":   policyResult.RequiredCount,
			"matched_rules":    policyResult.MatchedRules,
		})
		return
	}

	if s.mpcClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MPC client not initialized"})
		return
	}

	sessionID := uuid.New().String()

	// Track in session store
	s.wallets.TrackSession(sessionID, req.WalletID, req.Message, user.ID, req.Metadata)

	// Determine key type from wallet curve or metadata
	keyType := types.KeyTypeSecp256k1
	if wallet, ok := s.wallets.GetWallet(req.WalletID); ok {
		if wallet.Curve == "ed25519" {
			keyType = types.KeyTypeEd25519
		}
	}

	// Decode the hex message to bytes for signing
	txBytes, err := hex.DecodeString(req.Message)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message must be hex-encoded"})
		return
	}

	// Build a properly typed and signed message via the MPC client
	signMsg := &types.SignTxMessage{
		KeyType:  keyType,
		WalletID: req.WalletID,
		TxID:     sessionID,
		Tx:       txBytes,
	}
	if req.Metadata != nil {
		if nic, ok := req.Metadata["network"].(string); ok {
			signMsg.NetworkInternalCode = nic
		}
	}

	if err := s.mpcClient.SignTransaction(signMsg); err != nil {
		logger.Error("Failed to publish signed signing request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate signing"})
		return
	}

	logger.Info("Signing requested (signed)", "sessionID", sessionID, "walletID", req.WalletID, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id":    sessionID,
		"wallet_id":     req.WalletID,
		"status":        "signing_initiated",
		"policy_result": policyResult.Action,
		"warnings":      policyResult.Warnings,
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

	if s.mpcClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MPC client not initialized"})
		return
	}

	sessionID := uuid.New().String()

	// Determine key type from wallet
	keyType := types.KeyTypeSecp256k1
	if wallet, ok := s.wallets.GetWallet(req.WalletID); ok {
		if wallet.Curve == "ed25519" {
			keyType = types.KeyTypeEd25519
		}
	}

	reshareMsg := &types.ResharingMessage{
		SessionID:    sessionID,
		WalletID:     req.WalletID,
		KeyType:      keyType,
		NewThreshold: req.NewT,
	}

	if err := s.mpcClient.Resharing(reshareMsg); err != nil {
		logger.Error("Failed to publish signed reshare request", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initiate reshare"})
		return
	}

	logger.Info("Reshare requested (signed)", "sessionID", sessionID, "walletID", req.WalletID, "user", user.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id": sessionID,
		"wallet_id":  req.WalletID,
		"status":     "reshare_initiated",
	})
}

// --- Transactions (Signing History) ---

func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	walletID := r.URL.Query().Get("wallet_id")
	sessions := s.wallets.ListSessions(walletID)
	writeJSON(w, http.StatusOK, map[string]any{
		"transactions": sessions,
		"count":        len(sessions),
	})
}

func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	txID := strings.TrimPrefix(r.URL.Path, "/api/v1/transactions/")
	session, ok := s.wallets.GetSession(txID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "transaction not found"})
		return
	}
	writeJSON(w, http.StatusOK, session)
}

// --- Policies ---

type createPolicyRequest struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Priority    int                `json:"priority"`
	Conditions  []policy.Condition `json:"conditions"`
	Action      policy.RuleAction  `json:"action"`
	Signers     policy.SignerConfig `json:"signers"`
	Enabled     bool               `json:"enabled"`
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	rule := policy.Rule{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		Action:      req.Action,
		Signers:     req.Signers,
		Enabled:     req.Enabled,
	}

	s.policy.AddRule(rule)
	logger.Info("Policy rule created", "id", rule.ID, "name", rule.Name, "action", rule.Action)

	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	data, _ := s.policy.MarshalJSON()
	var state map[string]any
	json.Unmarshal(data, &state)
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	_ = strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	// PolicyEngine doesn't have RemoveRule yet — acknowledge receipt
	writeJSON(w, http.StatusOK, map[string]string{"status": "policy deletion acknowledged"})
}

// --- Wallet Policies ---

func (s *Server) handleSetWalletPolicy(w http.ResponseWriter, r *http.Request) {
	// Extract wallet ID: /api/v1/wallets/{id}/policy
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	walletID := parts[4]

	var wp policy.WalletPolicy
	if err := json.NewDecoder(r.Body).Decode(&wp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	wp.WalletID = walletID

	if err := s.policy.SetWalletPolicy(&wp); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	logger.Info("Wallet policy set", "walletID", walletID, "name", wp.Name)
	writeJSON(w, http.StatusOK, wp)
}

func (s *Server) handleGetWalletPolicy(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	walletID := parts[4]

	wp, ok := s.policy.GetWalletPolicy(walletID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no policy for wallet"})
		return
	}
	writeJSON(w, http.StatusOK, wp)
}

// --- Signers ---

func (s *Server) handleCreateSigner(w http.ResponseWriter, r *http.Request) {
	var signer policy.Signer
	if err := json.NewDecoder(r.Body).Decode(&signer); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if signer.ID == "" {
		signer.ID = uuid.New().String()
	}

	if err := s.policy.AddSigner(&signer); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	logger.Info("Signer created", "id", signer.ID, "name", signer.Name, "role", signer.Role)
	writeJSON(w, http.StatusCreated, signer)
}

func (s *Server) handleListSigners(w http.ResponseWriter, r *http.Request) {
	signers := s.policy.ListSigners()
	writeJSON(w, http.StatusOK, map[string]any{
		"signers": signers,
		"count":   len(signers),
	})
}

func (s *Server) handleDeleteSigner(w http.ResponseWriter, r *http.Request) {
	signerID := strings.TrimPrefix(r.URL.Path, "/api/v1/signers/")
	if err := s.policy.RemoveSigner(signerID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signer removed"})
}

// --- Webhooks ---

type createWebhookRequest struct {
	URL    string         `json:"url"`
	Events []WebhookEvent `json:"events"`
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}

	if err := validateWebhookURL(req.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if len(req.Events) == 0 {
		// Default to all events
		req.Events = []WebhookEvent{
			WebhookKeygenCompleted, WebhookKeygenFailed,
			WebhookSignCompleted, WebhookSignFailed, WebhookSignTimeout,
			WebhookPolicyDenied,
		}
	}

	wh := s.webhooks.Register(req.URL, user.ID, req.Events)
	logger.Info("Webhook registered", "id", wh.ID, "url", wh.URL, "events", len(wh.Events))
	writeJSON(w, http.StatusCreated, wh)
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	webhooks := s.webhooks.List(user.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"webhooks": webhooks,
		"count":    len(webhooks),
	})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	whID := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
	wh, ok := s.webhooks.Get(whID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}
	if wh.Owner != user.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
		return
	}
	s.webhooks.Remove(whID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "webhook removed"})
}

// --- API Keys ---

type createAPIKeyRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "API key store not available"})
		return
	}
	user := GetUser(r.Context())
	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		req.Name = "default"
	}

	plaintext, key, err := s.apiKeys.Create(user.ID, req.Name)
	if err != nil {
		logger.Error("Failed to create API key", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create API key"})
		return
	}

	logger.Info("API key created", "id", key.ID, "name", key.Name, "owner", user.ID)
	// Return the plaintext key exactly once — it cannot be recovered after this response.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         key.ID,
		"name":       key.Name,
		"key":        plaintext,
		"created_at": key.CreatedAt,
		"note":       "Save this key — it will not be shown again.",
	})
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "API key store not available"})
		return
	}
	user := GetUser(r.Context())
	keys, err := s.apiKeys.List(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list API keys"})
		return
	}
	if keys == nil {
		keys = []*APIKey{}
	}
	// Never return the hash in list responses
	type safeKey struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		LastUsed  time.Time `json:"last_used,omitempty"`
	}
	safe := make([]safeKey, len(keys))
	for i, k := range keys {
		safe[i] = safeKey{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt, LastUsed: k.LastUsed}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": safe, "count": len(safe)})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "API key store not available"})
		return
	}
	user := GetUser(r.Context())
	keyID := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	if err := s.apiKeys.Revoke(keyID, user.ID); err != nil {
		if err.Error() == "access denied" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	logger.Info("API key revoked", "id", keyID, "owner", user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- Helpers ---

// newMPCClientSafe attempts to create an MPC client but returns nil instead of crashing
// if the event_initiator.key file is missing (common when the API server runs inside
// MPC node pods that don't carry the initiator private key).
func newMPCClientSafe(nc *nats.Conn, keyPath string) client.MPCClient {
	// Check if the key file exists before attempting to create the client
	// (client.NewMPCClient calls logger.Fatal on missing key, which calls os.Exit)
	if _, err := os.Stat(keyPath); err != nil {
		logger.Warn("Event initiator key not found, API wallet/signing operations will be unavailable",
			"keyPath", keyPath, "error", err)
		return nil
	}
	mpcCli := client.NewMPCClient(client.Options{
		NatsConn: nc,
		KeyPath:  keyPath,
	})
	logger.Info("API server initialized MPC client with initiator key", "keyPath", keyPath)
	return mpcCli
}

func mapAnyToString(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = fmt.Sprint(v)
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
