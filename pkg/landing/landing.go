package landing

import (
	"bytes"
	"html/template"
	"net/http"
	"sync"
)

// Handler returns an http.Handler that serves three brand-neutral pages
// driven by the Host header:
//
//	GET /              landing page (marketing surface)
//	GET /dashboard     post-OAuth dashboard
//	GET /auth/callback OAuth code-exchange page
//
// All other paths are delegated to next. The brand for each request is
// resolved from r.Host via FromHost so the same binary serves every
// white-label tenant without rebuilds.
func Handler(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveLanding)
	mux.HandleFunc("GET /dashboard", serveDashboard)
	mux.HandleFunc("GET /auth/callback", serveAuthCallback)
	if next != nil {
		mux.Handle("/", next)
	}
	return mux
}

// pageData is the template payload. We keep one template per page (parsed
// once) and execute it per request with the resolved Brand. tpls is a
// sync.Once-guarded pre-parsed cache so we never re-parse on the hot path.
type pageData struct {
	Brand Brand
}

var (
	tpls     map[string]*template.Template
	tplsOnce sync.Once
)

func loadTemplates() {
	tpls = map[string]*template.Template{
		"landing":      template.Must(template.New("landing").Parse(landingTemplate)),
		"dashboard":    template.Must(template.New("dashboard").Parse(dashboardTemplate)),
		"authCallback": template.Must(template.New("authCallback").Parse(authCallbackTemplate)),
	}
}

func render(w http.ResponseWriter, r *http.Request, name string) {
	tplsOnce.Do(loadTemplates)
	t, ok := tpls[name]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, pageData{Brand: FromHost(r.Host)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func serveLanding(w http.ResponseWriter, r *http.Request)      { render(w, r, "landing") }
func serveDashboard(w http.ResponseWriter, r *http.Request)    { render(w, r, "dashboard") }
func serveAuthCallback(w http.ResponseWriter, r *http.Request) { render(w, r, "authCallback") }
