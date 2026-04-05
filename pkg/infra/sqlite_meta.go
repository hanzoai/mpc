package infra

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/mpc/pkg/logger"

	"github.com/hanzoai/dbx"
	_ "modernc.org/sqlite"
)

// SQLiteMeta implements KV using SQLite (via hanzoai/dbx) for queryable metadata.
// Key shares NEVER touch this store — only wallets, peers, API keys, audit logs.
//
// org_id column reserved for future per-org isolation. Not enforced yet.
//
// Schema is auto-migrated on open (idempotent CREATE TABLE IF NOT EXISTS).
type SQLiteMeta struct {
	db   *dbx.DB
	mu   sync.RWMutex
	path string
}

// SQLiteMetaConfig configures the SQLite metadata store.
type SQLiteMetaConfig struct {
	// Path to the SQLite database file. Use ":memory:" for testing.
	Path string
	// WAL enables write-ahead logging (recommended for concurrent reads).
	WAL bool
}

// NewSQLiteMeta opens (or creates) a SQLite metadata store and runs migrations.
func NewSQLiteMeta(cfg SQLiteMetaConfig) (*SQLiteMeta, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("sqlite_meta: path required")
	}

	dsn := cfg.Path
	if cfg.WAL && dsn != ":memory:" {
		dsn += "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON"
	} else if dsn != ":memory:" {
		dsn += "?_busy_timeout=5000&_foreign_keys=ON"
	}

	db, err := dbx.MustOpen("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite_meta: open %q: %w", cfg.Path, err)
	}

	s := &SQLiteMeta{db: db, path: cfg.Path}

	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite_meta: migrate: %w", err)
	}

	logger.Info("SQLiteMeta opened", "path", cfg.Path, "wal", cfg.WAL)
	return s, nil
}

// migrate creates tables idempotently.
func (s *SQLiteMeta) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS wallets (
			id         TEXT PRIMARY KEY,
			org_id     TEXT NOT NULL DEFAULT '',
			curve      TEXT NOT NULL DEFAULT '',
			status     TEXT NOT NULL DEFAULT 'pending',
			public_key TEXT NOT NULL DEFAULT '',
			owner      TEXT NOT NULL DEFAULT '',
			name       TEXT NOT NULL DEFAULT '',
			metadata   TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_wallets_org ON wallets(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_wallets_owner ON wallets(owner)`,

		`CREATE TABLE IF NOT EXISTS peers (
			node_id    TEXT PRIMARY KEY,
			org_id     TEXT NOT NULL DEFAULT '',
			ready      INTEGER NOT NULL DEFAULT 0,
			last_seen  TEXT NOT NULL DEFAULT (datetime('now')),
			metadata   TEXT NOT NULL DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_peers_org ON peers(org_id)`,

		`CREATE TABLE IF NOT EXISTS api_keys (
			key_hash   TEXT PRIMARY KEY,
			org_id     TEXT NOT NULL DEFAULT '',
			id         TEXT NOT NULL DEFAULT '',
			name       TEXT NOT NULL DEFAULT '',
			owner_id   TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			last_used  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_id)`,

		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id     TEXT NOT NULL DEFAULT '',
			action     TEXT NOT NULL,
			actor      TEXT NOT NULL DEFAULT '',
			resource   TEXT NOT NULL DEFAULT '',
			detail     TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)`,

		// Generic KV fallback for keys that don't map to a typed table.
		// This ensures 100% KV interface compatibility.
		`CREATE TABLE IF NOT EXISTS kv (
			key   TEXT PRIMARY KEY,
			value BLOB NOT NULL
		)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.NewQuery(stmt).Execute(); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:min(len(stmt), 60)], err)
		}
	}
	return nil
}

// --- KV Interface (infra.KV) ---

func (s *SQLiteMeta) Put(key string, value []byte) error {
	if isKeyShareKey(key) {
		return fmt.Errorf("key share keys must use encrypted backend, not SQLite")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Route to typed tables when possible, fall back to generic KV.
	switch {
	case strings.HasPrefix(key, "api_keys/"):
		return s.putAPIKey(key, value)
	case strings.HasPrefix(key, "ready/"):
		return s.putPeer(key, value)
	default:
		return s.putGenericKV(key, value)
	}
}

func (s *SQLiteMeta) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch {
	case strings.HasPrefix(key, "api_keys/"):
		return s.getAPIKey(key)
	case strings.HasPrefix(key, "ready/"):
		return s.getPeer(key)
	default:
		return s.getGenericKV(key)
	}
}

func (s *SQLiteMeta) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case strings.HasPrefix(key, "api_keys/"):
		hash := strings.TrimPrefix(key, "api_keys/")
		_, err := s.db.NewQuery("DELETE FROM api_keys WHERE key_hash={:hash}").Bind(dbx.Params{"hash": hash}).Execute()
		return err
	case strings.HasPrefix(key, "ready/"):
		nodeID := strings.TrimPrefix(key, "ready/")
		_, err := s.db.NewQuery("DELETE FROM peers WHERE node_id={:id}").Bind(dbx.Params{"id": nodeID}).Execute()
		return err
	default:
		_, err := s.db.NewQuery("DELETE FROM kv WHERE key={:key}").Bind(dbx.Params{"key": key}).Execute()
		return err
	}
}

func (s *SQLiteMeta) List(prefix string) ([]*KVPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch {
	case strings.HasPrefix(prefix, "api_keys/"):
		return s.listAPIKeys()
	case strings.HasPrefix(prefix, "ready/"):
		return s.listPeers()
	default:
		return s.listGenericKV(prefix)
	}
}

// --- Typed Table Operations ---

func (s *SQLiteMeta) putAPIKey(key string, value []byte) error {
	hash := strings.TrimPrefix(key, "api_keys/")

	// Parse JSON to extract structured fields.
	var rec struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		OwnerID   string `json:"owner_id"`
		KeyHash   string `json:"key_hash"`
		CreatedAt string `json:"created_at"`
		LastUsed  string `json:"last_used"`
	}
	if err := json.Unmarshal(value, &rec); err != nil {
		// Fall back to generic KV if not valid API key JSON.
		return s.putGenericKV(key, value)
	}

	q := s.db.NewQuery(`INSERT INTO api_keys (key_hash, id, name, owner_id, created_at, last_used)
		VALUES ({:hash}, {:id}, {:name}, {:owner}, {:created}, {:used})
		ON CONFLICT(key_hash) DO UPDATE SET
			name=excluded.name, last_used=excluded.last_used`)
	q.Bind(dbx.Params{
		"hash":    hash,
		"id":      rec.ID,
		"name":    rec.Name,
		"owner":   rec.OwnerID,
		"created": rec.CreatedAt,
		"used":    rec.LastUsed,
	})
	_, err := q.Execute()
	return err
}

func (s *SQLiteMeta) getAPIKey(key string) ([]byte, error) {
	hash := strings.TrimPrefix(key, "api_keys/")

	var row struct {
		KeyHash   string `db:"key_hash"`
		ID        string `db:"id"`
		Name      string `db:"name"`
		OwnerID   string `db:"owner_id"`
		CreatedAt string `db:"created_at"`
		LastUsed  string `db:"last_used"`
	}
	err := s.db.NewQuery("SELECT key_hash, id, name, owner_id, created_at, last_used FROM api_keys WHERE key_hash={:hash}").
		Bind(dbx.Params{"hash": hash}).
		One(&row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Reconstruct the JSON that the APIKeyStore expects.
	out := map[string]any{
		"id":         row.ID,
		"name":       row.Name,
		"owner_id":   row.OwnerID,
		"key_hash":   row.KeyHash,
		"created_at": row.CreatedAt,
		"last_used":  row.LastUsed,
	}
	return json.Marshal(out)
}

func (s *SQLiteMeta) listAPIKeys() ([]*KVPair, error) {
	var rows []struct {
		KeyHash   string `db:"key_hash"`
		ID        string `db:"id"`
		Name      string `db:"name"`
		OwnerID   string `db:"owner_id"`
		CreatedAt string `db:"created_at"`
		LastUsed  string `db:"last_used"`
	}
	err := s.db.NewQuery("SELECT key_hash, id, name, owner_id, created_at, last_used FROM api_keys").All(&rows)
	if err != nil {
		return nil, err
	}

	pairs := make([]*KVPair, 0, len(rows))
	for _, r := range rows {
		val, _ := json.Marshal(map[string]any{
			"id":         r.ID,
			"name":       r.Name,
			"owner_id":   r.OwnerID,
			"key_hash":   r.KeyHash,
			"created_at": r.CreatedAt,
			"last_used":  r.LastUsed,
		})
		pairs = append(pairs, &KVPair{
			Key:   "api_keys/" + r.KeyHash,
			Value: val,
		})
	}
	return pairs, nil
}

func (s *SQLiteMeta) putPeer(key string, value []byte) error {
	nodeID := strings.TrimPrefix(key, "ready/")
	ready := 0
	if string(value) == "true" {
		ready = 1
	}

	q := s.db.NewQuery(`INSERT INTO peers (node_id, ready, last_seen)
		VALUES ({:id}, {:ready}, {:seen})
		ON CONFLICT(node_id) DO UPDATE SET
			ready=excluded.ready, last_seen=excluded.last_seen`)
	q.Bind(dbx.Params{
		"id":    nodeID,
		"ready": ready,
		"seen":  time.Now().UTC().Format(time.RFC3339),
	})
	_, err := q.Execute()
	return err
}

func (s *SQLiteMeta) getPeer(key string) ([]byte, error) {
	nodeID := strings.TrimPrefix(key, "ready/")

	var row struct {
		NodeID string `db:"node_id"`
		Ready  int    `db:"ready"`
	}
	err := s.db.NewQuery("SELECT node_id, ready FROM peers WHERE node_id={:id}").
		Bind(dbx.Params{"id": nodeID}).
		One(&row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if row.Ready == 1 {
		return []byte("true"), nil
	}
	return []byte("false"), nil
}

func (s *SQLiteMeta) listPeers() ([]*KVPair, error) {
	var rows []struct {
		NodeID string `db:"node_id"`
		Ready  int    `db:"ready"`
	}
	err := s.db.NewQuery("SELECT node_id, ready FROM peers WHERE ready=1").All(&rows)
	if err != nil {
		return nil, err
	}

	pairs := make([]*KVPair, 0, len(rows))
	for _, r := range rows {
		pairs = append(pairs, &KVPair{
			Key:   "ready/" + r.NodeID,
			Value: []byte("true"),
		})
	}
	return pairs, nil
}

// --- Generic KV (fallback for untyped keys) ---

func (s *SQLiteMeta) putGenericKV(key string, value []byte) error {
	q := s.db.NewQuery(`INSERT INTO kv (key, value) VALUES ({:key}, {:val})
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	q.Bind(dbx.Params{"key": key, "val": value})
	_, err := q.Execute()
	return err
}

func (s *SQLiteMeta) getGenericKV(key string) ([]byte, error) {
	var row struct {
		Value []byte `db:"value"`
	}
	err := s.db.NewQuery("SELECT value FROM kv WHERE key={:key}").
		Bind(dbx.Params{"key": key}).
		One(&row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return row.Value, nil
}

func (s *SQLiteMeta) listGenericKV(prefix string) ([]*KVPair, error) {
	// SQLite LIKE with prefix: "foo/" → "foo/%".
	// Escape % and _ to prevent wildcard injection regardless of input source.
	escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(prefix)
	pattern := escaped + "%"

	var rows []struct {
		Key   string `db:"key"`
		Value []byte `db:"value"`
	}
	err := s.db.NewQuery("SELECT key, value FROM kv WHERE key LIKE {:pattern} ESCAPE '\\'").
		Bind(dbx.Params{"pattern": pattern}).
		All(&rows)
	if err != nil {
		return nil, err
	}

	pairs := make([]*KVPair, 0, len(rows))
	for _, r := range rows {
		pairs = append(pairs, &KVPair{Key: r.Key, Value: r.Value})
	}
	return pairs, nil
}

// --- Audit Log ---

// AuditEntry is a structured audit record.
type AuditEntry struct {
	OrgID    string `json:"org_id"`
	Action   string `json:"action"`
	Actor    string `json:"actor"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
}

// Audit writes a structured audit log entry.
func (s *SQLiteMeta) Audit(entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := s.db.NewQuery(`INSERT INTO audit_log (org_id, action, actor, resource, detail)
		VALUES ({:org}, {:action}, {:actor}, {:resource}, {:detail})`)
	q.Bind(dbx.Params{
		"org":      entry.OrgID,
		"action":   entry.Action,
		"actor":    entry.Actor,
		"resource": entry.Resource,
		"detail":   entry.Detail,
	})
	_, err := q.Execute()
	return err
}

// Close closes the underlying SQLite database.
func (s *SQLiteMeta) Close() error {
	return s.db.Close()
}

