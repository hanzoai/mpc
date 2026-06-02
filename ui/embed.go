// Copyright © 2026 Hanzo AI. MIT License.

// Package ui exposes the built admin-mpc bundle as an embedded
// filesystem. The bundle is produced externally in the @hanzo/gui
// workspace and synced into ui/dist by scripts/sync-admin-ui.sh.
//
// Until the admin-mpc SPA lands, the embed is intentionally empty —
// the handler returns 503 with an actionable message rather than 404,
// so operators notice the missing bundle in staging before shipping a
// blank page. Mount the returned handler at /_/mpc/ in the mpcd HTTP
// router so it serves the SPA shell for every non-API request:
//
//	import mpcui "github.com/hanzoai/mpc/ui"
//	mux.Handle("/_/mpc/", http.StripPrefix("/_/mpc", mpcui.Handler()))
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded built-UI filesystem rooted at dist/. When
// the admin-mpc workspace has not produced a bundle, the returned FS
// is empty — Stat lookups fall through to the 503 path in Handler.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return distFS
	}
	return sub
}

// Handler returns an http.Handler that serves the embedded SPA. While
// the bundle is empty (admin-mpc workspace pending), every request
// returns 503 with a typed message so operators see the missing-bundle
// state in logs and in the browser.
func Handler() http.Handler {
	root := FS()
	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		reqPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if reqPath == "" {
			reqPath = "index.html"
		}

		if _, err := fs.Stat(root, reqPath); err != nil {
			serveIndex(w, r, root)
			return
		}

		if strings.HasPrefix(reqPath, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	data, err := fs.ReadFile(root, "index.html")
	if err != nil {
		http.Error(w, "mpc UI not built (run scripts/sync-admin-ui.sh once admin-mpc workspace lands)", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
	_ = r
}
