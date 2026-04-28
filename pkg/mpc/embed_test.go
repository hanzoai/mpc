// Copyright © 2026 Hanzo AI. MIT License.

package mpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/mpc/pkg/auth"
)

// TestEmbedLifecycle exercises the public Embed contract end-to-end:
// start, hit /healthz via httptest, hit /v1/mpc/info under the
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

	// Probe /healthz via the canonical BuildHTTP wiring. Body must be
	// {"status":"ok"} — no node_id, no org, no service field.
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
	if body["status"] != "ok" {
		t.Fatalf("/healthz status: want %q got %q", "ok", body["status"])
	}
	if _, leaks := body["node_id"]; leaks {
		t.Fatalf("/healthz must NOT leak node_id; body=%q", rec.Body.String())
	}
	if _, leaks := body["service"]; leaks {
		t.Fatalf("/healthz must NOT leak service; body=%q", rec.Body.String())
	}

	// /v1/mpc/info under identity middleware (require=false → empty ctx allowed).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/info", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/mpc/info (solo): want 200 got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mpcd-embed-test") {
		t.Fatalf("/v1/mpc/info should report node_id behind auth; body=%q", rec.Body.String())
	}

	// Legacy /v1/mpc/health is gone — must 401 (require=false here, but
	// the inner mux returns 404 because the route isn't registered).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/health", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1/mpc/health (retired): want 404 got %d body=%q", rec.Code, rec.Body.String())
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

// TestRequireIdentityCloud confirms BuildHTTP under MPCD_REQUIRE_IDENTITY:
//   - /healthz is public, identity-free, body never includes node_id
//   - /v1/mpc/* (including /v1/mpc/info) requires identity headers
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

	// /healthz public — must pass with no headers and never leak identity.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz public: want 200 got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "mpcd-cloud-test") {
		t.Fatalf("/healthz must NOT leak node_id even in cloud mode; body=%q", rec.Body.String())
	}

	// /v1/mpc/info is now identity-gated — no headers → 401.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/info", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/mpc/info unauth: want 401 got %d body=%q", rec.Code, rec.Body.String())
	}

	// Legacy /v1/mpc/health route is also gated now — must 401 without identity.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/health", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/mpc/health unauth: want 401 got %d body=%q", rec.Code, rec.Body.String())
	}

	// /v1/mpc/wallets is gated — no headers → 401.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/mpc/wallets", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1/mpc/wallets unauth: want 401 got %d body=%q", rec.Code, rec.Body.String())
	}

	// Identity headers present → middleware allows through to the inner
	// mux. /v1/mpc/info now responds 200 with node_id; /v1/mpc/wallets
	// 404s (route not registered). The point: the 401 became something
	// else, proving the auth gate is the trust boundary.
	req := httptest.NewRequest(http.MethodGet, "/v1/mpc/info", nil)
	req.Header.Set(auth.HeaderOrgID, "hanzo")
	req.Header.Set(auth.HeaderUserID, "user-1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/mpc/info auth: want 200 got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mpcd-cloud-test") {
		t.Fatalf("/v1/mpc/info should include node_id behind auth; body=%q", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/mpc/wallets", nil)
	req.Header.Set(auth.HeaderOrgID, "hanzo")
	req.Header.Set(auth.HeaderUserID, "user-1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1/mpc/wallets auth (passthrough to 404): want 404 got %d body=%q", rec.Code, rec.Body.String())
	}
}
