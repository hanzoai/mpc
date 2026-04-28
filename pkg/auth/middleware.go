// Copyright © 2026 Hanzo AI. MIT License.

// Package auth wires gateway-supplied identity headers (X-Org-Id,
// X-User-Id, X-User-Email) into request context. mpcd does not validate
// JWTs itself — hanzoai/gateway already did that. The middleware is
// the trust boundary: in production, only the gateway can reach mpcd,
// and MPCD_REQUIRE_IDENTITY=true rejects any request without identity
// headers.
package auth

import (
	"context"
	"net/http"
	"strings"
)

const (
	HeaderOrgID     = "X-Org-Id"
	HeaderUserID    = "X-User-Id"
	HeaderUserEmail = "X-User-Email"
)

type ctxKey int

const (
	ctxKeyOrgID ctxKey = iota
	ctxKeyUserID
	ctxKeyUserEmail
)

// RequireIdentity reads identity headers and attaches them to ctx.
// When require=true:
//   - Both X-Org-Id and X-User-Id absent (or whitespace-only) → 401.
//   - X-Org-Id present-but-empty (whitespace-only) with X-User-Id set
//     → 401. An empty OrgID would unscope every store query and
//     collapse tenant isolation; defense-in-depth, since hanzoai/gateway
//     should never forward an empty owner claim, but mpcd does not
//     trust that assumption.
//
// When require=false, missing headers yield empty ctx values — the
// embedded/dev path.
func RequireIdentity(require bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawOrg := r.Header.Get(HeaderOrgID)
			rawUser := r.Header.Get(HeaderUserID)
			org := strings.TrimSpace(rawOrg)
			user := strings.TrimSpace(rawUser)
			email := strings.TrimSpace(r.Header.Get(HeaderUserEmail))

			if require {
				if org == "" && user == "" {
					http.Error(w, `{"error":"identity required","code":401}`, http.StatusUnauthorized)
					return
				}
				// X-Org-Id present-but-empty (whitespace) with a user
				// set would unscope queries — reject.
				if rawOrg != "" && org == "" {
					http.Error(w, `{"error":"empty org id","code":401}`, http.StatusUnauthorized)
					return
				}
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxKeyOrgID, org)
			ctx = context.WithValue(ctx, ctxKeyUserID, user)
			ctx = context.WithValue(ctx, ctxKeyUserEmail, email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OrgID returns the org id attached by RequireIdentity, or "".
func OrgID(ctx context.Context) string { return strFromCtx(ctx, ctxKeyOrgID) }

// UserID returns the user id attached by RequireIdentity, or "".
func UserID(ctx context.Context) string { return strFromCtx(ctx, ctxKeyUserID) }

// UserEmail returns the user email attached by RequireIdentity, or "".
func UserEmail(ctx context.Context) string { return strFromCtx(ctx, ctxKeyUserEmail) }

func strFromCtx(ctx context.Context, k ctxKey) string {
	if v, ok := ctx.Value(k).(string); ok {
		return v
	}
	return ""
}
