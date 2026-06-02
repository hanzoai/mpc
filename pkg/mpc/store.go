// Copyright © 2026 Hanzo AI. MIT License.

package mpc

// Store is the per-org view of MPC node-local state. The underlying
// MPC machinery (key shards, wallet ownership, audit log) lives in the
// canonical luxfi/mpc runtime; this layer is the thin routing wrapper
// that maps an X-Org-Id from the request middleware to the
// node-storage shard the upstream OrgScopedKey() helper already uses.
//
// The wrapper is deliberately small. luxfi/mpc/pkg/mpc.OrgScopedKey
// already namespaces keys by orgID; the canonical KV stores in
// node0/, node1/, node2/ remain the only on-disk shards. WithOrg here
// is the request-scope binding so handler code reads the org from
// context (set by pkg/auth/middleware.go) rather than from a JSON body
// field.
type Store struct {
	orgID string
}

// NewStore returns a Store with no org binding. Use WithOrg to derive a
// per-org view.
func NewStore() *Store { return &Store{} }

// WithOrg returns a per-org view of s. The view shares no mutable
// state with s; concurrent use across orgs is safe. Empty orgID
// returns s unchanged (solo-mode default).
func (s *Store) WithOrg(orgID string) *Store {
	if orgID == "" {
		return s
	}
	return &Store{orgID: orgID}
}

// OrgID returns the org id this view is bound to, or "" for unscoped.
func (s *Store) OrgID() string {
	if s == nil {
		return ""
	}
	return s.orgID
}
