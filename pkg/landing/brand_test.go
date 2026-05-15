package landing

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFromHost(t *testing.T) {
	cases := []struct {
		host     string
		wantName string
		wantIAM  string
	}{
		{"mpc.hanzo.ai", "Hanzo", "https://hanzo.id"},
		{"mpc.hanzo.ai:443", "Hanzo", "https://hanzo.id"},
		{"MPC.HANZO.AI", "Hanzo", "https://hanzo.id"},
		{"mpc.lux.network", "Lux", "https://id.lux.network"},
		{"mpc.zoo.network", "Zoo", "https://zoo.id"},
		{"mpc.example.com", "", ""},
		{"localhost", "", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		got := FromHost(tc.host)
		if got.Name != tc.wantName {
			t.Errorf("FromHost(%q).Name = %q, want %q", tc.host, got.Name, tc.wantName)
		}
		if got.IAMURL != tc.wantIAM {
			t.Errorf("FromHost(%q).IAMURL = %q, want %q", tc.host, got.IAMURL, tc.wantIAM)
		}
	}
}

func TestBrandHelpers(t *testing.T) {
	hanzo := Brand{Name: "Hanzo"}
	if hanzo.TitlePrefix() != "Hanzo " {
		t.Errorf("TitlePrefix branded = %q, want %q", hanzo.TitlePrefix(), "Hanzo ")
	}
	if hanzo.SignInLabel() != "Sign In with Hanzo ID" {
		t.Errorf("SignInLabel branded = %q, want %q", hanzo.SignInLabel(), "Sign In with Hanzo ID")
	}
	if !hanzo.HasBrand() {
		t.Errorf("HasBrand for non-empty Name should be true")
	}

	none := Brand{}
	if none.TitlePrefix() != "" {
		t.Errorf("TitlePrefix unbranded = %q, want empty", none.TitlePrefix())
	}
	if none.SignInLabel() != "Sign In" {
		t.Errorf("SignInLabel unbranded = %q, want %q", none.SignInLabel(), "Sign In")
	}
	if none.HasBrand() {
		t.Errorf("HasBrand for empty Name should be false")
	}
}

func TestHandlerPerHostBranding(t *testing.T) {
	h := Handler(nil)

	type want struct {
		titleContains    string
		titleMustNotHave []string
		bodyContains     []string
		bodyMustNotHave  []string
	}
	cases := []struct {
		path string
		host string
		want want
	}{
		{
			path: "/",
			host: "mpc.hanzo.ai",
			want: want{
				titleContains:    "Hanzo MPC — Enterprise Digital Asset Infrastructure",
				titleMustNotHave: []string{"Lux MPC", "Zoo MPC"},
				bodyContains:     []string{"Sign In with Hanzo ID", "https://hanzo.id", "docs.hanzo.ai"},
				bodyMustNotHave:  []string{"Lux MPC", "Sign In with Lux ID", "id.lux.network", "docs.lux.network"},
			},
		},
		{
			path: "/",
			host: "mpc.lux.network",
			want: want{
				titleContains:    "Lux MPC — Enterprise Digital Asset Infrastructure",
				titleMustNotHave: []string{"Hanzo MPC", "Zoo MPC"},
				bodyContains:     []string{"Sign In with Lux ID", "https://id.lux.network", "docs.lux.network"},
				bodyMustNotHave:  []string{"Sign In with Hanzo ID", "hanzo.id"},
			},
		},
		{
			path: "/",
			host: "mpc.zoo.network",
			want: want{
				titleContains:    "Zoo MPC — Enterprise Digital Asset Infrastructure",
				titleMustNotHave: []string{"Lux MPC", "Hanzo MPC"},
				bodyContains:     []string{"Sign In with Zoo ID", "https://zoo.id", "docs.zoo.ngo"},
				bodyMustNotHave:  []string{"Sign In with Lux ID", "lux.network"},
			},
		},
		{
			path: "/",
			host: "mpc.example.com",
			want: want{
				titleContains:    "MPC — Enterprise Digital Asset Infrastructure",
				titleMustNotHave: []string{"Hanzo MPC", "Lux MPC", "Zoo MPC"},
				bodyContains:     []string{},
				bodyMustNotHave:  []string{"Sign In with Hanzo ID", "Sign In with Lux ID", "Sign In with Zoo ID"},
			},
		},
		{
			path: "/dashboard",
			host: "mpc.hanzo.ai",
			want: want{
				titleContains:   "Hanzo MPC — Dashboard",
				bodyContains:    []string{"Hanzo MPC Dashboard"},
				bodyMustNotHave: []string{"Lux MPC"},
			},
		},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s host=%s: status=%d, want 200", tc.path, tc.host, w.Code)
			continue
		}
		body := w.Body.String()
		if !strings.Contains(body, tc.want.titleContains) {
			t.Errorf("%s host=%s: title %q not found in body", tc.path, tc.host, tc.want.titleContains)
		}
		for _, s := range tc.want.titleMustNotHave {
			if strings.Contains(body, "<title>"+s) {
				t.Errorf("%s host=%s: unexpected title %q in body", tc.path, tc.host, s)
			}
		}
		for _, s := range tc.want.bodyContains {
			if !strings.Contains(body, s) {
				t.Errorf("%s host=%s: missing %q in body", tc.path, tc.host, s)
			}
		}
		for _, s := range tc.want.bodyMustNotHave {
			if strings.Contains(body, s) {
				t.Errorf("%s host=%s: forbidden %q present in body", tc.path, tc.host, s)
			}
		}
	}
}

// TestLandingRendersLiteralIAMURL guards the v1.2.4 fix: the rendered
// HTML must contain `const IAM_URL = "https://hanzo.id"` *verbatim* —
// no `\"` Go-quoted form (was the bug pre-fix), no `\/` JS-escaped slash
// (still parses fine but breaks verify-curl substring match and clutters
// source). Same for CLIENT_ID.
func TestLandingRendersLiteralIAMURL(t *testing.T) {
	h := Handler(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "mpc.hanzo.ai"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	wantIAM := `const IAM_URL = "https://hanzo.id"`
	wantClient := `const CLIENT_ID = "hanzo-mpc-client"`
	for _, want := range []string{wantIAM, wantClient} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in rendered HTML", want)
		}
	}
	// Negative: ensure the double-quote bug never reappears.
	for _, bad := range []string{
		`IAM_URL = "\"`,            // Go-quoted, the original bug
		`IAM_URL = "https:\/\/`,    // JS-escaped slash, the secondary bug
		`CLIENT_ID = "\"`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("forbidden substring %q present in rendered HTML", bad)
		}
	}
}

// TestWalletDetailRoute exercises GET /dashboard/wallets/<id>.
// The page is brand-aware and includes the wallet send/receive UI.
func TestWalletDetailRoute(t *testing.T) {
	h := Handler(nil)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/wallets/wallet-abc-123", nil)
	req.Host = "mpc.hanzo.ai"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	body := w.Body.String()
	must := []string{
		"Hanzo MPC — Wallet",
		"Send",
		"Receive",
		"Sign &amp; Send",
		"/v1/mpc/wallets/",
	}
	for _, s := range must {
		if !strings.Contains(body, s) {
			t.Errorf("missing %q in wallet-detail body", s)
		}
	}
}

func TestHandlerDelegatesUnknownPaths(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	h := Handler(next)

	req := httptest.NewRequest(http.MethodGet, "/v1/wallets", nil)
	req.Host = "mpc.hanzo.ai"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !called {
		t.Fatalf("next handler not called for /v1/wallets")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("status=%d, want 418 (delegated)", w.Code)
	}
}
