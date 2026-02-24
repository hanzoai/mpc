package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/hanzoai/mpc/pkg/event"
	"github.com/hanzoai/mpc/pkg/logger"
)

// Wallet represents a stored MPC wallet with its metadata.
type Wallet struct {
	ID        string         `json:"id"`
	Curve     string         `json:"curve"`
	Status    WalletStatus   `json:"status"`
	PublicKey string         `json:"public_key,omitempty"` // hex-encoded
	Owner     string         `json:"owner"`
	Name      string         `json:"name,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Error     string         `json:"error,omitempty"`
}

// WalletStatus tracks the lifecycle of a wallet.
type WalletStatus string

const (
	WalletStatusPending WalletStatus = "pending"  // Keygen in progress
	WalletStatusActive  WalletStatus = "active"   // Ready to sign
	WalletStatusFailed  WalletStatus = "failed"   // Keygen failed
	WalletStatusFrozen  WalletStatus = "frozen"   // Temporarily disabled
	WalletStatusArchived WalletStatus = "archived" // No longer in use
)

// SigningSession tracks an in-flight or completed signing operation.
type SigningSession struct {
	ID        string         `json:"id"`
	WalletID  string         `json:"wallet_id"`
	Message   string         `json:"message"`
	Status    SessionStatus  `json:"status"`
	Signature string         `json:"signature,omitempty"` // hex-encoded result
	R         string         `json:"r,omitempty"`
	S         string         `json:"s,omitempty"`
	Recovery  string         `json:"recovery,omitempty"`
	Owner     string         `json:"owner"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Error     string         `json:"error,omitempty"`
}

// SessionStatus tracks the lifecycle of a signing session.
type SessionStatus string

const (
	SessionPending   SessionStatus = "pending"
	SessionCompleted SessionStatus = "completed"
	SessionFailed    SessionStatus = "failed"
	SessionTimeout   SessionStatus = "timeout"
)

// WalletStore holds wallet and session state, subscribing to NATS for updates.
type WalletStore struct {
	mu       sync.RWMutex
	wallets  map[string]*Wallet
	sessions map[string]*SigningSession

	natsConn *nats.Conn
	subs     []*nats.Subscription
}

// NewWalletStore creates a wallet store and subscribes to NATS result topics.
func NewWalletStore(nc *nats.Conn) *WalletStore {
	ws := &WalletStore{
		wallets:  make(map[string]*Wallet),
		sessions: make(map[string]*SigningSession),
		natsConn: nc,
	}

	if nc != nil && nc.IsConnected() {
		ws.subscribeToResults()
	}

	return ws
}

// TrackWallet records a newly created wallet (pending keygen).
func (ws *WalletStore) TrackWallet(id, curve, owner string, metadata map[string]any) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	now := time.Now().UTC()
	ws.wallets[id] = &Wallet{
		ID:        id,
		Curve:     curve,
		Status:    WalletStatusPending,
		Owner:     owner,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// TrackSession records a newly created signing session.
func (ws *WalletStore) TrackSession(id, walletID, message, owner string, metadata map[string]any) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	now := time.Now().UTC()
	ws.sessions[id] = &SigningSession{
		ID:        id,
		WalletID:  walletID,
		Message:   message,
		Status:    SessionPending,
		Owner:     owner,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// GetWallet returns a wallet by ID.
func (ws *WalletStore) GetWallet(id string) (*Wallet, bool) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	w, ok := ws.wallets[id]
	return w, ok
}

// ListWallets returns all wallets, optionally filtered by owner.
func (ws *WalletStore) ListWallets(owner string) []*Wallet {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	result := make([]*Wallet, 0, len(ws.wallets))
	for _, w := range ws.wallets {
		if owner == "" || w.Owner == owner {
			result = append(result, w)
		}
	}
	return result
}

// GetSession returns a signing session by ID.
func (ws *WalletStore) GetSession(id string) (*SigningSession, bool) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	s, ok := ws.sessions[id]
	return s, ok
}

// ListSessions returns all sessions, optionally filtered by wallet ID.
func (ws *WalletStore) ListSessions(walletID string) []*SigningSession {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	result := make([]*SigningSession, 0)
	for _, s := range ws.sessions {
		if walletID == "" || s.WalletID == walletID {
			result = append(result, s)
		}
	}
	return result
}

// Close unsubscribes from NATS topics.
func (ws *WalletStore) Close() {
	for _, sub := range ws.subs {
		sub.Unsubscribe()
	}
}

// subscribeToResults sets up NATS subscriptions for keygen and signing results.
func (ws *WalletStore) subscribeToResults() {
	// Subscribe to keygen results
	keygenSub, err := ws.natsConn.Subscribe("mpc.mpc_keygen_result.*", func(msg *nats.Msg) {
		ws.handleKeygenResult(msg.Data)
	})
	if err != nil {
		logger.Error("Failed to subscribe to keygen results", err)
	} else {
		ws.subs = append(ws.subs, keygenSub)
		logger.Info("WalletStore subscribed to keygen results")
	}

	// Subscribe to signing results
	signingSub, err := ws.natsConn.Subscribe("mpc.mpc_signing_result.*", func(msg *nats.Msg) {
		ws.handleSigningResult(msg.Data)
	})
	if err != nil {
		logger.Error("Failed to subscribe to signing results", err)
	} else {
		ws.subs = append(ws.subs, signingSub)
		logger.Info("WalletStore subscribed to signing results")
	}
}

func (ws *WalletStore) handleKeygenResult(data []byte) {
	var evt event.KeygenResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		logger.Error("Failed to unmarshal keygen result", err)
		return
	}

	ws.mu.Lock()
	defer ws.mu.Unlock()

	w, ok := ws.wallets[evt.WalletID]
	if !ok {
		// Wallet created by another node or before this API started
		w = &Wallet{
			ID:        evt.WalletID,
			CreatedAt: time.Now().UTC(),
		}
		ws.wallets[evt.WalletID] = w
	}

	w.UpdatedAt = time.Now().UTC()

	if evt.ResultType == event.ResultTypeSuccess {
		w.Status = WalletStatusActive
		if len(evt.ECDSAPubKey) > 0 {
			w.PublicKey = string(evt.ECDSAPubKey) // Already hex from CreateKeygenSuccess
			if w.Curve == "" {
				w.Curve = "secp256k1"
			}
		}
		if len(evt.EDDSAPubKey) > 0 {
			w.PublicKey = fmt.Sprintf("%x", evt.EDDSAPubKey)
			if w.Curve == "" {
				w.Curve = "ed25519"
			}
		}
		logger.Info("Wallet keygen succeeded", "walletID", evt.WalletID, "pubKey", truncate(w.PublicKey, 16))
	} else {
		w.Status = WalletStatusFailed
		w.Error = evt.ErrorReason
		logger.Warn("Wallet keygen failed", "walletID", evt.WalletID, "error", evt.ErrorReason)
	}
}

func (ws *WalletStore) handleSigningResult(data []byte) {
	var evt event.SigningResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		logger.Error("Failed to unmarshal signing result", err)
		return
	}

	ws.mu.Lock()
	defer ws.mu.Unlock()

	s, ok := ws.sessions[evt.TxID]
	if !ok {
		// Session created before this API started or by another path
		s = &SigningSession{
			ID:        evt.TxID,
			WalletID:  evt.WalletID,
			CreatedAt: time.Now().UTC(),
		}
		ws.sessions[evt.TxID] = s
	}

	s.UpdatedAt = time.Now().UTC()

	if evt.ResultType == event.ResultTypeSuccess {
		s.Status = SessionCompleted
		if len(evt.R) > 0 {
			s.R = hex.EncodeToString(evt.R)
		}
		if len(evt.S) > 0 {
			s.S = hex.EncodeToString(evt.S)
		}
		if len(evt.SignatureRecovery) > 0 {
			s.Recovery = hex.EncodeToString(evt.SignatureRecovery)
		}
		if len(evt.Signature) > 0 {
			s.Signature = hex.EncodeToString(evt.Signature)
		}
		logger.Info("Signing session completed", "sessionID", evt.TxID, "walletID", evt.WalletID)
	} else if evt.IsTimeout {
		s.Status = SessionTimeout
		s.Error = "signing timed out"
		logger.Warn("Signing session timed out", "sessionID", evt.TxID)
	} else {
		s.Status = SessionFailed
		s.Error = evt.ErrorReason
		logger.Warn("Signing session failed", "sessionID", evt.TxID, "error", evt.ErrorReason)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
