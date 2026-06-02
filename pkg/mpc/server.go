// Copyright © 2026 Hanzo AI. MIT License.

package mpc

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/mpc/pkg/auth"
	mpcui "github.com/hanzoai/mpc/ui"
)

// BuildHTTP returns the canonical mpcd HTTP mux. The only public probe
// is /healthz; it returns {"status":"ok"} with no node identity, so an
// in-cluster scanner cannot fingerprint mpcd via the unauthenticated
// surface. Detailed node info (node_id, org binding) lives behind
// the identity middleware at /v1/mpc/info.
//
// Authenticated routes (/v1/mpc/*) sit behind RequireIdentity, which
// reads the gateway-supplied X-Org-Id / X-User-Id / X-User-Email
// headers into request context.
//
// requireID = MPCD_REQUIRE_IDENTITY (true in cloud, false in solo dev).
// nodeID is reported only on the identity-gated /v1/mpc/info endpoint.
//
// /_/mpc/* serves the embedded admin UI from ui/embed.go. The bundle
// is empty until the @hanzo/gui admin-mpc workspace lands; the handler
// returns 503 with an actionable message rather than a blank page.
func BuildHTTP(srv *Embedded, nodeID string, requireID bool) http.Handler {
	mux := http.NewServeMux()

	// Public probe — ok-only, no identity leak. K8s liveness/readiness
	// hits this; an attacker scanning the cluster gets nothing here.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	identity := auth.RequireIdentity(requireID)
	mux.Handle("/v1/mpc/", identity(srv.HTTPHandler(nodeID)))

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
