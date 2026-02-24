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
