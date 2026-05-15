// Package landing serves the brand-neutral MPC marketing landing page and
// post-OAuth dashboard. Brand is resolved from the request Host header so
// the same binary serves mpc.hanzo.ai, mpc.lux.network, mpc.zoo.network,
// etc. with the right wordmark, IAM endpoint, and footer links.
//
// Resolution rules:
//
//   - Strip the leading subdomain ("mpc.hanzo.ai" -> "hanzo.ai").
//   - Look up the registered domain in the table below.
//   - Anything not in the table resolves to the empty Brand which renders
//     a generic, brand-free "MPC" surface (title, sign-in button, etc.
//     all drop the brand prefix).
package landing

import (
	"encoding/json"
	"html/template"
	"strings"
)

// Brand captures every visible string a deployment needs to brand the
// landing/dashboard. The empty Brand renders an entirely brand-neutral
// page (no wordmark prefix, no brand-suffixed sign-in button).
type Brand struct {
	// Name is the wordmark, e.g. "Hanzo". Empty means no brand prefix —
	// the page title becomes "MPC — ..." and the sign-in button becomes
	// "Sign In" (no "with X ID" suffix).
	Name string
	// IAMURL is the OAuth issuer that backs the sign-in button, e.g.
	// "https://hanzo.id". Empty disables in-page login (the button is
	// hidden / linked to /health).
	IAMURL string
	// ClientID is the OAuth client_id registered at IAMURL for this
	// deployment. Empty for unbranded.
	ClientID string
	// SiteURL is the marketing homepage, e.g. "https://hanzo.ai".
	SiteURL string
	// DocsURL is where "Docs" / "Read the Docs" link to.
	DocsURL string
	// GitHubURL is the public source link in the footer / nav.
	GitHubURL string
}

// HasBrand reports whether the deployment is associated with a known
// org. Used to gate the "Sign In with X ID" button vs a plain "Sign In".
func (b Brand) HasBrand() bool { return b.Name != "" }

// TitlePrefix returns "Hanzo " for branded deployments and "" for the
// unbranded default, so callers can write "{{.TitlePrefix}}MPC — ..."
// and get either "Hanzo MPC — ..." or "MPC — ...".
func (b Brand) TitlePrefix() string {
	if b.Name == "" {
		return ""
	}
	return b.Name + " "
}

// SignInLabel returns either "Sign In with Hanzo ID" (branded) or plain
// "Sign In" (unbranded).
func (b Brand) SignInLabel() string {
	if b.Name == "" {
		return "Sign In"
	}
	return "Sign In with " + b.Name + " ID"
}

// IAMURLJS returns the IAM endpoint as a JS string literal safe to drop
// into a <script> context. html/template's default JS escaping turns
// every `/` in a URL into `\/`, which breaks the verify-curl literal
// match in CI (and clutters page source) even though browsers parse it
// fine. We pre-quote with encoding/json (which preserves `/`) and wrap
// in template.JS to bypass the auto-escaper. Returns `""` for unbranded.
func (b Brand) IAMURLJS() template.JS { return jsString(b.IAMURL) }

// ClientIDJS is the JS-safe pre-quoted ClientID for <script> contexts.
func (b Brand) ClientIDJS() template.JS { return jsString(b.ClientID) }

// jsString returns `"<value>"` with proper JS escaping for the contents
// but without escaping `/` (so URLs render as `https://...` not
// `https:\/\/...`). Empty input returns `""`.
func jsString(s string) template.JS {
	if s == "" {
		return template.JS(`""`)
	}
	buf, err := json.Marshal(s)
	if err != nil {
		return template.JS(`""`)
	}
	// encoding/json emits valid JSON strings which are also valid JS string
	// literals; it preserves "/" by default. Cast to template.JS to skip
	// html/template's JS escaper.
	return template.JS(buf)
}

// brandTable is the per-Host brand registry. Keys are the registered
// domain (no `mpc.` subdomain, no port). One entry per supported brand —
// add a row here to onboard a new white-label deployment.
var brandTable = map[string]Brand{
	"hanzo.ai": {
		Name:      "Hanzo",
		IAMURL:    "https://hanzo.id",
		ClientID:  "hanzo-mpc-client",
		SiteURL:   "https://hanzo.ai",
		DocsURL:   "https://docs.hanzo.ai",
		GitHubURL: "https://github.com/hanzoai/mpc",
	},
	"lux.network": {
		Name:      "Lux",
		IAMURL:    "https://id.lux.network",
		ClientID:  "lux-mpc-client",
		SiteURL:   "https://lux.network",
		DocsURL:   "https://docs.lux.network/mpc",
		GitHubURL: "https://github.com/luxfi/mpc",
	},
	"zoo.network": {
		Name:      "Zoo",
		IAMURL:    "https://zoo.id",
		ClientID:  "zoo-mpc-client",
		SiteURL:   "https://zoo.ngo",
		DocsURL:   "https://docs.zoo.ngo",
		GitHubURL: "https://github.com/zooai/mpc",
	},
}

// FromHost resolves a Brand from an HTTP Host header. Strips port and
// the leading "mpc." subdomain, then looks up the remaining registered
// domain in brandTable. Unknown hosts resolve to the zero Brand which
// renders a generic, brand-free page.
func FromHost(host string) Brand {
	// Strip port if present (":443", ":8080", etc.).
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// Strip leading "mpc." or any other single-label subdomain that
	// fronts the deployment.
	if strings.HasPrefix(host, "mpc.") {
		host = host[len("mpc."):]
	}

	return brandTable[host]
}
