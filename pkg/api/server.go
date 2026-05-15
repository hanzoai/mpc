package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/client"
	"github.com/hanzoai/mpc/pkg/hsm"
	"github.com/hanzoai/mpc/pkg/infra"
	"github.com/hanzoai/mpc/pkg/keyinfo"
	"github.com/hanzoai/mpc/pkg/landing"
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
	kv           infra.KV
	keyInfoStore keyinfo.Store
	mpcClient    client.MPCClient // signs and publishes keygen/signing/reshare via JetStream
	hsmProvider  hsm.Provider     // HSM provider for key management (optional)
}

// Config holds configuration for the API server.
type Config struct {
	Port             int
	IAMEndpoint      string // e.g. "https://id.lux.network"
	NATSConn         *nats.Conn
	KV               infra.KV       // KV store for wallet metadata (consensus, NATS, or Consul)
	InitiatorKeyPath string         // path to event_initiator.key (Ed25519 private key)
	HSMProvider      hsm.Provider   // HSM provider for key management (optional)
}

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	var kis keyinfo.Store
	if cfg.KV != nil {
		kis = keyinfo.NewStore(cfg.KV)
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
	if cfg.KV != nil {
		apiKeys = NewAPIKeyStore(cfg.KV)
	}

	s := &Server{
		natsConn:     cfg.NATSConn,
		iam:          NewIAMMiddleware(cfg.IAMEndpoint),
		apiKeys:      apiKeys,
		wallets:      NewWalletStore(cfg.NATSConn),
		policy:       policy.NewPolicyEngine(),
		webhooks:     NewWebhookStore(),
		kv:           cfg.KV,
		keyInfoStore: kis,
		mpcClient:    mpcCli,
		hsmProvider:  cfg.HSMProvider,
	}

	mux := http.NewServeMux()

	// Public endpoints (no auth)
	mux.HandleFunc("GET /{$}", s.handleLanding)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	mux.HandleFunc("GET /v1/mpc/health", s.handleHealth)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("GET /dashboard/wallets/{id}", s.handleWalletDetail)

	// Protected endpoints (IAM token or sk_mpc_ API key).
	//
	// Canonical surface: /v1/mpc/* (org-policy: api.<org>.* hosts MUST NOT
	// re-prefix routes with /api/). The legacy /api/v1/* prefix remains
	// mounted for backward-compat with older clients; new integrations
	// should use /v1/mpc/*. Both prefixes resolve to the same handlers via
	// path canonicalization in routeAPI().
	authed := s.iam.Wrap(s.apiKeys, http.HandlerFunc(s.routeAPI))
	mux.Handle("/v1/mpc/", authed)
	mux.Handle("/api/", authed) // legacy, undocumented

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
//
// Path canonicalization: handlers are written against "/api/v1/<resource>"
// for historical reasons. Callers may hit either:
//
//   /v1/mpc/<resource>    canonical (advertised, matches org policy that
//                         api.<org>.<tld> hosts MUST NOT use /api/* prefix)
//   /api/v1/<resource>    legacy, undocumented, kept for backward compat
//
// We rewrite /v1/mpc/* → /api/v1/* once on entry so the case table below
// stays single-source for both prefixes.
func (s *Server) routeAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1/mpc/") {
		path = "/api/v1/" + strings.TrimPrefix(path, "/v1/mpc/")
		// Mutate the request so downstream handlers (which TrimPrefix on
		// r.URL.Path) see the legacy form they were written against.
		r.URL.Path = path
	}

	switch {
	// Wallets
	case r.Method == "POST" && path == "/api/v1/wallets":
		s.handleCreateWallet(w, r)
	case r.Method == "GET" && path == "/api/v1/wallets":
		s.handleListWallets(w, r)
	case r.Method == "GET" && strings.HasSuffix(path, "/balance") && strings.HasPrefix(path, "/api/v1/wallets/"):
		s.handleGetWalletBalance(w, r)
	case r.Method == "POST" && strings.HasSuffix(path, "/sign") && strings.HasPrefix(path, "/api/v1/wallets/"):
		s.handleWalletSign(w, r)
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
//
// All three HTML surfaces (landing, dashboard, auth callback) delegate
// to pkg/landing, which renders brand-aware pages from the request
// Host header (mpc.hanzo.ai -> Hanzo, mpc.lux.network -> Lux, etc.).
// The wire-protocol API surface below this comment is unchanged.

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	landing.RenderLanding(w, r)
}


// --- Auth ---

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	landing.RenderAuthCallback(w, r)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	landing.RenderDashboard(w, r)
}

// handleWalletDetail serves the brand-aware wallet-detail SPA fragment.
// The wallet id comes from the URL path; the page itself fetches wallet
// + balance from /v1/mpc/wallets/<id> and /v1/mpc/wallets/<id>/balance
// using the bearer token in localStorage (same auth as the dashboard).
func (s *Server) handleWalletDetail(w http.ResponseWriter, r *http.Request) {
	landing.RenderWalletDetail(w, r)
}


// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	natsOK := s.natsConn != nil && s.natsConn.IsConnected()

	kvOK := false
	if s.kv != nil {
		// Quick check: list ready/ prefix (lightweight)
		_, err := s.kv.List("ready/")
		kvOK = err == nil
	}

	if !natsOK || (s.kv != nil && !kvOK) {
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
		"kv":     kvOK,
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

	// Persist wallet owner so ownership survives pod restarts
	if s.kv != nil {
		if err := s.kv.Put("wallet_owner/"+walletID, []byte(user.ID)); err != nil {
			logger.Warn("Failed to persist wallet owner", "walletID", walletID, "error", err)
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

	// 2. Enumerate keyinfo for wallets completed across all pods (filter by owner)
	if s.kv != nil {
		pairs, err := s.kv.List("threshold_keyinfo/")
		if err != nil {
			logger.Warn("Failed to list wallets from KV", "error", err)
		} else {
			for _, pair := range pairs {
				walletID := strings.TrimPrefix(pair.Key, "threshold_keyinfo/")
				if walletID == "" || seen[walletID] {
					continue
				}

				// Check ownership via wallet_owner/ prefix
				ownerData, oErr := s.kv.Get("wallet_owner/" + walletID)
				if oErr != nil || ownerData == nil || string(ownerData) != user.ID {
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

	// Fall back to KV keyinfo (wallet created on another pod or before restart)
	// Verify ownership via wallet_owner/ prefix
	if s.kv != nil {
		ownerData, err := s.kv.Get("wallet_owner/" + walletID)
		if err != nil || ownerData == nil || string(ownerData) != user.ID {
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

// --- Wallet Balance ---
//
// Balance lookup is chain-specific; this MPC service does not run light
// clients so it cannot natively report balances. The handler returns a
// stub `0` until a chain-adapter layer is added, but with `pending: true`
// so the SPA can flag the value as approximate. New integration target:
// chain adapters live in pkg/chain/<id>.go and implement BalanceProvider.

func (s *Server) handleGetWalletBalance(w http.ResponseWriter, r *http.Request) {
	user := GetUser(r.Context())
	// Path is /api/v1/wallets/{id}/balance after canonicalization.
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/wallets/")
	walletID := strings.TrimSuffix(path, "/balance")
	if walletID == "" || strings.Contains(walletID, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid wallet id"})
		return
	}

	// Ownership check (in-memory first, then KV).
	if wallet, ok := s.wallets.GetWallet(walletID); ok {
		if wallet.Owner != user.ID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}
	} else if s.kv != nil {
		ownerData, err := s.kv.Get("wallet_owner/" + walletID)
		if err != nil || ownerData == nil || string(ownerData) != user.ID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet not found"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_id": walletID,
		"balance":   "0",
		"unit":      "wei",
		"pending":   true,
		"note":      "chain-adapter not yet wired; balance is a placeholder",
	})
}

// --- Wallet-Scoped Sign ---
//
// Mirrors POST /api/v1/sign but extracts the wallet id from the URL so the
// dashboard can POST /v1/mpc/wallets/<id>/sign with just {to, amount, data}
// instead of repeating wallet_id in the body. Body schema:
//
//   { "message": "<hex>", "metadata": { "chain": "...", "to": "...", "amount": "..." } }
//
// We DO NOT broadcast. The response carries session_id and the eventual
// signature once threshold protocols finalise — broadcasting is a chain
// adapter's responsibility, not MPC's.

func (s *Server) handleWalletSign(w http.ResponseWriter, r *http.Request) {
	// /api/v1/wallets/{id}/sign
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/wallets/")
	walletID := strings.TrimSuffix(path, "/sign")
	if walletID == "" || strings.Contains(walletID, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid wallet id"})
		return
	}

	// Decode the wallet-scoped payload and forward into handleSign by
	// rewriting the body to the canonical {wallet_id, message, metadata}
	// shape. Keeps the policy/keytype/curve logic single-source.
	var body struct {
		Message  string         `json:"message"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	rewrapped, _ := json.Marshal(signRequest{
		WalletID: walletID,
		Message:  body.Message,
		Metadata: body.Metadata,
	})
	r.Body = io.NopCloser(strings.NewReader(string(rewrapped)))
	s.handleSign(w, r)
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
	} else if s.kv != nil {
		ownerData, err := s.kv.Get("wallet_owner/" + req.WalletID)
		if err != nil || ownerData == nil || string(ownerData) != user.ID {
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
