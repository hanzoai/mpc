// Copyright © 2026 Hanzo AI. MIT License.

package mpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzoai/mpc/pkg/auth"
)

// TestEmbedLifecycle exercises the public Embed contract end-to-end:
// start, hit /healthz via httptest, hit /v1/mpc/health under the
// identity middleware, Stop, and confirm a second Embed succeeds after
// the singleton releases.
func TestEmbedLifecycle(t *testing.T) {
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv, err := Embed(deadline, EmbedConfig{
		DataDir:  t.TempDir(),
		HTTPAddr: ":0",
		ZAPPort:  0,
		NodeID:   "mpcd-embed-test",
	})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	if srv.NodeID() != "mpcd-embed-test" {
		t.Fatalf("NodeID: want %q got %q", "mpcd-embed-test", srv.NodeID())
	}
	if srv.ZAPPort() != 9999 {
		t.Fatalf("ZAPPort default: want 9999 got %d", srv.ZAPPort())
	}
	if srv.HTTPAddr() != ":0" {
		t.Fatalf("HTTPAddr: want :0 got %q", srv.HTTPAddr())
	}

	// Singleton guard: second Embed must fail.
	if _, err := Embed(deadline, EmbedConfig{NodeID: "mpcd-second"}); !errors.Is(err, ErrAlreadyEmbedded) {
		t.Fatalf("second Embed: want ErrAlreadyEmbedded got %v", err)
	}

	// Probe /healthz via the canonical BuildHTTP wiring.
	mux := BuildHTTP(srv, srv.NodeID(), false)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz: want 200 got %d body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/healthz body: %v", err)
	}
	if body["service"] != "mpc" {
		t.Fatalf("/healthz service: want %q got %q", "mpc", body["service"])
	}

	// /v1/mpc/health under identity middleware (require=false → empty ctx allowed).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/mpc/health (solo): want 200 got %d body=%q", rec.Code, rec.Body.String())
	}

	// Stop releases the singleton.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := Embed(deadline, EmbedConfig{NodeID: "mpcd-after-stop"}); err != nil {
		t.Fatalf("Embed after Stop: %v", err)
	}
	embedMu.Lock()
	embedRunning = nil
	embedMu.Unlock()
}

// TestRequireIdentityCloud confirms BuildHTTP under MPCD_REQUIRE_IDENTITY
// rejects requests missing X-Org-Id / X-User-Id, but lets the public
// /healthz probe through unauthenticated.
func TestRequireIdentityCloud(t *testing.T) {
	srv, err := Embed(context.Background(), EmbedConfig{
		DataDir:  t.TempDir(),
		HTTPAddr: ":0",
		NodeID:   "mpcd-cloud-test",
	})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	defer func() {
		_ = srv.Stop(context.Background())
		embedMu.Lock()
		embedRunning = nil
		embedMu.Unlock()
	}()

	mux := BuildHTTP(srv, srv.NodeID(), true)

	// /healthz public — must pass with no headers.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz public: want 200 got %d", rec.Code)
	}

	// /v1/mpc/health is the public gateway probe — must pass without
	// identity headers even when require=true. The auth-gated surface
	// hides under HTTPHandler() (the inner JSON shim mux), which
	// BuildHTTP wraps with identity for everything except the explicit
	// public probes.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/mpc/health public probe: want 200 got %d", rec.Code)
	}

	// /v1/mpc/wallets is gated — no headers → 401. The route doesn't
	// exist (HTTPHandler returns 404 for unknown paths) but the
	// identity middleware runs first and rejects with 401.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/wallets", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/mpc/wallets unauth: want 401 got %d body=%q", rec.Code, rec.Body.String())
	}

	// Identity headers present → middleware allows through to the
	// inner mux, which 404s for the unknown route. The point: the
	// 401 became 404, proving the auth gate is the trust boundary.
	req := httptest.NewRequest(http.MethodGet, "/v1/mpc/wallets", nil)
	req.Header.Set(auth.HeaderOrgID, "hanzo")
	req.Header.Set(auth.HeaderUserID, "user-1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1/mpc/wallets auth (passthrough to 404): want 404 got %d body=%q", rec.Code, rec.Body.String())
	}
}
