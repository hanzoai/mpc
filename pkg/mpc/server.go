// Copyright © 2026 Hanzo AI. MIT License.

package mpc

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/mpc/pkg/auth"
	mpcui "github.com/hanzoai/mpc/ui"
)

// BuildHTTP returns the canonical mpcd HTTP mux. Public probes
// (/healthz, /v1/mpc/health) live outside the identity middleware so
// K8s liveness/readiness checks never touch the JWT path. Authenticated
// routes (/v1/mpc/*) sit behind RequireIdentity, which reads the
// gateway-supplied X-Org-Id / X-User-Id / X-User-Email headers into
// request context.
//
// requireID = MPCD_REQUIRE_IDENTITY (true in cloud, false in solo dev).
// nodeID is included in probe payloads for cluster diagnostics.
//
// /_/mpc/* serves the embedded admin UI from ui/embed.go. The bundle
// is empty until the @hanzo/gui admin-mpc workspace lands; the handler
// returns 503 with an actionable message rather than a blank page.
func BuildHTTP(srv *Embedded, nodeID string, requireID bool) http.Handler {
	mux := http.NewServeMux()

	probe := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "mpc",
			"status":  "ok",
			"node_id": nodeID,
		})
	}
	mux.HandleFunc("/healthz", probe)
	mux.HandleFunc("/v1/mpc/health", probe)

	identity := auth.RequireIdentity(requireID)
	mux.Handle("/v1/mpc/", identity(srv.HTTPHandler()))

	// Embedded admin UI shell. The bundle ships empty (no admin-mpc
	// workspace yet); the handler returns a typed 503 so operators see
	// the missing-bundle state explicitly. When the SPA lands, swap
	// the empty embed.FS in ui/embed.go and this route picks it up.
	mux.Handle("/_/mpc/", http.StripPrefix("/_/mpc", mpcui.Handler()))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/_/mpc/", http.StatusFound)
	})

	return mux
}
