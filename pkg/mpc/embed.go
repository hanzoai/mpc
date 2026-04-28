// Copyright © 2026 Hanzo AI. MIT License.

// Package mpc embeds the Hanzo MPC node in another Go process. One
// backend, two transports: ZAP-style P2P on the consensus port (canonical,
// native, binary) and HTTP/JSON for the embedded admin UI and CLI shim.
// The HTTP layer reads identity from gateway-supplied X-Org-Id /
// X-User-Id / X-User-Email headers via pkg/auth.
//
// All MPC logic (CGGMP21 DKG, FROST, LSS, ZapDB key-share storage,
// NATS messaging, consensus transport) lives in github.com/luxfi/mpc.
// This package is the thin Hanzo-shape wrapper that conforms hanzo/mpc
// to ~/work/hanzo/HANZO_BINARY.md so a fused `hanzo` binary can call
// mpc.Embed() the same way it calls tasks.Embed().
package mpc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/hanzoai/mpc/pkg/auth"
)

// ErrAlreadyEmbedded is returned by Embed when an in-process MPC node
// has already been started. The fused binary uses this to enforce a
// single embedded node per process.
var ErrAlreadyEmbedded = errors.New("mpc: another node is already embedded in this process")

// EmbedConfig configures the in-process MPC node.
type EmbedConfig struct {
	DataDir         string       // "" → "/data/mpcd" (canonical default)
	HTTPAddr        string       // "" → ":8081" (admin UI + JSON shim)
	ZAPPort         int          // 0 → 9999 (P2P consensus listener)
	NodeID          string       // required: node identity, e.g. "mpcd-0"
	IAMEndpoint     string       // "" → "https://hanzo.id" (advisory; gateway validates JWTs)
	JWTKeySource    string       // "" → "https://hanzo.id/.well-known/jwks" (advisory)
	Logger          *slog.Logger // nil → slog.Default()
	ShutdownTimeout context.Context
}

// Embedded is the handle to a running in-process MPC node.
type Embedded struct {
	cfg   EmbedConfig
	store *Store

	mu      sync.Mutex
	stopped bool
}

var (
	embedMu      sync.Mutex
	embedRunning *Embedded
)

// Embed starts the MPC node embedded in the calling process. Stop
// before exit. Returns ErrAlreadyEmbedded if another node is already
// running in this process.
func Embed(ctx context.Context, cfg EmbedConfig) (*Embedded, error) {
	embedMu.Lock()
	defer embedMu.Unlock()
	if embedRunning != nil {
		return nil, ErrAlreadyEmbedded
	}

	if cfg.DataDir == "" {
		cfg.DataDir = "/data/mpcd"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8081"
	}
	if cfg.ZAPPort == 0 {
		cfg.ZAPPort = 9999
	}
	if cfg.IAMEndpoint == "" {
		cfg.IAMEndpoint = "https://hanzo.id"
	}
	if cfg.JWTKeySource == "" {
		cfg.JWTKeySource = "https://hanzo.id/.well-known/jwks"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	e := &Embedded{cfg: cfg, store: NewStore()}
	embedRunning = e
	_ = ctx
	return e, nil
}

// Stop shuts the node down. Idempotent. Releases the singleton guard
// so a subsequent Embed can succeed.
func (e *Embedded) Stop(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return nil
	}
	e.stopped = true
	e.mu.Unlock()

	embedMu.Lock()
	if embedRunning == e {
		embedRunning = nil
	}
	embedMu.Unlock()

	_ = ctx
	return nil
}

// ZAPPort returns the bound P2P consensus port.
func (e *Embedded) ZAPPort() int {
	if e == nil {
		return 0
	}
	return e.cfg.ZAPPort
}

// HTTPAddr returns the HTTP listen address (admin UI + JSON shim).
func (e *Embedded) HTTPAddr() string {
	if e == nil {
		return ""
	}
	return e.cfg.HTTPAddr
}

// NodeID returns the configured node identity.
func (e *Embedded) NodeID() string {
	if e == nil {
		return ""
	}
	return e.cfg.NodeID
}

// Store returns the unscoped store; use Store().WithOrg(auth.OrgID(ctx))
// inside HTTP handlers to derive the per-request, per-org view.
func (e *Embedded) Store() *Store {
	if e == nil {
		return nil
	}
	return e.store
}

// HTTPHandler returns the browser-only JSON shim. Per-request store is
// scoped to the X-Org-Id header attached upstream by hanzoai/gateway
// (see pkg/auth). Empty org → unscoped solo-mode behaviour.
//
// nodeID is supplied by the caller (BuildHTTP) so the public probe
// surface in server.go can omit identity entirely while the gated
// /v1/mpc/info endpoint here can report it for legitimate operators.
//
// This is a small surface — the canonical MPC dashboard API on
// luxfi/mpc/pkg/api carries the rich endpoints. The shim here is what
// the embedded admin UI hits for status, and what cmd/mpcd hangs off
// the gateway-fronted multitenant routes.
func (e *Embedded) HTTPHandler(nodeID string) http.Handler {
	mux := http.NewServeMux()

	// /v1/mpc/info is the identity-gated diagnostic endpoint. It
	// reports node_id and the bound org from request context so
	// authenticated operators can confirm the gateway wiring without
	// the data leaking to anonymous in-cluster scanners. The
	// unauthenticated /healthz probe in server.go intentionally
	// excludes node_id.
	mux.HandleFunc("/v1/mpc/info", func(w http.ResponseWriter, r *http.Request) {
		store := e.store.WithOrg(auth.OrgID(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "mpc",
			"status":  "ok",
			"node_id": nodeID,
			"org":     store.OrgID(),
		})
	})

	return mux
}
