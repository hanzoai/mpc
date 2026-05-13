// Package client — canonical client interface for Hanzo MPC.
//
//	import mpc "github.com/hanzoai/mpc/client"
//	var t mpc.Threshold = hanzomp.NewThreshold(cfg)

package client

import "context"

// Threshold is the compliance-gated threshold-signature surface.
// Every custody mutation (mint, burn, transfer, settle) signs through
// Threshold.Sign — there is no direct path to the MPC backend.
type Threshold interface {
	// Kind reports the backend identifier
	// (ta-cggmp21 | lit-protocol | fireblocks-mpc | coinbase-custody).
	Kind() string

	// Sign requests a threshold signature. The implementation applies its
	// compliance ruleset before signing; rejections return an error whose
	// kind names the gate (sanctions, velocity, blocklist, ...).
	//
	// IdempotencyKey is required. The implementation must coalesce repeat
	// calls with the same key to one MPC session, and must verify the
	// PayloadHash matches the cached session's payload before reusing it.
	Sign(ctx context.Context, req SignRequest) (*SignResult, error)

	// GetSession returns the current state of a signature session.
	GetSession(ctx context.Context, sessionID string) (*SignSession, error)

	// Cancel cancels a pending session. Idempotent on completed sessions.
	Cancel(ctx context.Context, sessionID string) error
}

// SignRequest is the caller-side payload. Backends map to their protocols.
type SignRequest struct {
	UserID, OrgID string
	// Intent: settle_trade | swap_dex | mint | burn | withdraw |
	// redeem | corporate_action.
	Intent string
	// WalletID is the provider_wallet_id from custody_wallets.
	WalletID string
	// Asset is the token symbol (BTC, USDL, ETH, ...).
	Asset string
	// Amount is the human-readable string. Backends parse to the asset's
	// native decimals.
	Amount string
	// PayloadHash is the 32-byte hex of the tx payload. Signed verbatim.
	PayloadHash string
	// KeyType: secp256k1 | ed25519 | sr25519 | mldsa65.
	KeyType string
	// IdempotencyKey is required.
	IdempotencyKey string
	// TradeID is optional context for settle_trade.
	TradeID string
}

// SignResult is the immediate response. Synchronous backends populate
// Signature; asynchronous backends return Status=pending + SessionID for
// later polling via GetSession.
type SignResult struct {
	SessionID  string
	Signature  []byte
	Status     string // pending | signed | rejected
	ApprovalID string
}

// SignSession is the poll response.
type SignSession struct {
	SessionID  string
	Status     string // pending | signed | rejected | cancelled
	Signature  []byte
	ApprovalID string
	// Reason populated when Status=rejected. Values:
	// sanctions | velocity | blocklist | manual_review |
	// key_disabled | tenant_disabled.
	Reason string
}
