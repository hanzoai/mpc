// Package storage provides BadgerDB-based storage with native backups
// and S3-compatible cloud backup support for MPC nodes.
package storage

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/luxfi/zapdb/v4"
)

// BadgerStore provides a BadgerDB-based key-value store with backup capabilities.
type BadgerStore struct {
	db     *badger.DB
	path   string
	mu     sync.RWMutex
	closed bool
}

// Options configures the BadgerStore.
type Options struct {
	// Path is the directory where BadgerDB files are stored.
	Path string
	// EncryptionKey is the AES-256 key for encryption at rest.
	// Must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
	EncryptionKey []byte
	// InMemory runs the store entirely in memory (for testing).
	InMemory bool
	// SyncWrites forces synchronous writes for durability.
	SyncWrites bool
	// Logger is an optional logger interface.
	Logger badger.Logger
}

// NewBadgerStore creates a new BadgerDB-backed storage.
func NewBadgerStore(opts Options) (*BadgerStore, error) {
	badgerOpts := badger.DefaultOptions(opts.Path)

	if opts.InMemory {
		badgerOpts = badger.DefaultOptions("").WithInMemory(true)
	}

	if len(opts.EncryptionKey) > 0 {
		badgerOpts = badgerOpts.WithEncryptionKey(opts.EncryptionKey)
	}

	if opts.SyncWrites {
		badgerOpts = badgerOpts.WithSyncWrites(true)
	}

	if opts.Logger != nil {
		badgerOpts = badgerOpts.WithLogger(opts.Logger)
	} else {
		// Disable badger's verbose logging by default
		badgerOpts = badgerOpts.WithLogger(nil)
	}

	db, err := badger.Open(badgerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	return &BadgerStore{
		db:   db,
		path: opts.Path,
	}, nil
}

// Get retrieves a value by key.
func (s *BadgerStore) Get(key []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	var value []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})

	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	return value, err
}

// Set stores a key-value pair.
func (s *BadgerStore) Set(key, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// Delete removes a key.
func (s *BadgerStore) Delete(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// SetWithTTL stores a key-value pair with a time-to-live.
func (s *BadgerStore) SetWithTTL(key, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, value).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

// Scan iterates over keys with a given prefix.
func (s *BadgerStore) Scan(prefix []byte, fn func(key, value []byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			err := item.Value(func(val []byte) error {
				return fn(key, val)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Batch performs multiple operations atomically.
func (s *BadgerStore) Batch(ops []BatchOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	wb := s.db.NewWriteBatch()
	defer wb.Cancel()

	for _, op := range ops {
		switch op.Type {
		case OpSet:
			if err := wb.Set(op.Key, op.Value); err != nil {
				return err
			}
		case OpDelete:
			if err := wb.Delete(op.Key); err != nil {
				return err
			}
		}
	}

	return wb.Flush()
}

// BatchOp represents a batch operation.
type BatchOp struct {
	Type  OpType
	Key   []byte
	Value []byte
}

// OpType is the type of batch operation.
type OpType int

const (
	OpSet OpType = iota
	OpDelete
)

// Close closes the database.
func (s *BadgerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return s.db.Close()
}

// Sync forces a sync to disk.
func (s *BadgerStore) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.Sync()
}

// RunGC runs the garbage collector.
func (s *BadgerStore) RunGC(discardRatio float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	for {
		err := s.db.RunValueLogGC(discardRatio)
		if err == badger.ErrNoRewrite {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ============================================================
// NATIVE BADGER BACKUP SUPPORT
// ============================================================

// BackupInfo contains metadata about a backup.
type BackupInfo struct {
	Version      uint64    `json:"version"`
	Timestamp    time.Time `json:"timestamp"`
	SinceVersion uint64    `json:"since_version"`
	Size         int64     `json:"size"`
	Path         string    `json:"path"`
	Incremental  bool      `json:"incremental"`
}

// Backup creates a full backup of the database to a writer.
// Returns the version number at the time of backup.
func (s *BadgerStore) Backup(w io.Writer) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, fmt.Errorf("store is closed")
	}

	// Get latest version
	version, err := s.db.Backup(w, 0)
	if err != nil {
		return 0, fmt.Errorf("backup failed: %w", err)
	}

	return version, nil
}

// BackupSince creates an incremental backup since the given version.
func (s *BadgerStore) BackupSince(w io.Writer, sinceVersion uint64) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, fmt.Errorf("store is closed")
	}

	version, err := s.db.Backup(w, sinceVersion)
	if err != nil {
		return 0, fmt.Errorf("incremental backup failed: %w", err)
	}

	return version, nil
}

// BackupToFile creates a backup to a file.
func (s *BadgerStore) BackupToFile(path string) (*BackupInfo, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	version, err := s.Backup(f)
	if err != nil {
		os.Remove(path)
		return nil, err
	}

	stat, _ := f.Stat()
	return &BackupInfo{
		Version:     version,
		Timestamp:   time.Now(),
		Size:        stat.Size(),
		Path:        path,
		Incremental: false,
	}, nil
}

// BackupIncrementalToFile creates an incremental backup to a file.
func (s *BadgerStore) BackupIncrementalToFile(path string, sinceVersion uint64) (*BackupInfo, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	version, err := s.BackupSince(f, sinceVersion)
	if err != nil {
		os.Remove(path)
		return nil, err
	}

	stat, _ := f.Stat()
	return &BackupInfo{
		Version:      version,
		Timestamp:    time.Now(),
		SinceVersion: sinceVersion,
		Size:         stat.Size(),
		Path:         path,
		Incremental:  true,
	}, nil
}

// Load restores the database from a backup.
func (s *BadgerStore) Load(r io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	return s.db.Load(r, 16) // 16 concurrent writes
}

// LoadFromFile restores from a backup file.
func (s *BadgerStore) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer f.Close()

	return s.Load(f)
}

// ============================================================
// SNAPSHOT SUPPORT
// ============================================================

// SnapshotManager manages periodic snapshots and retention.
type SnapshotManager struct {
	store           *BadgerStore
	snapshotDir     string
	lastVersion     uint64
	maxSnapshots    int
	mu              sync.Mutex
}

// NewSnapshotManager creates a new snapshot manager.
func NewSnapshotManager(store *BadgerStore, snapshotDir string, maxSnapshots int) (*SnapshotManager, error) {
	if err := os.MkdirAll(snapshotDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	sm := &SnapshotManager{
		store:        store,
		snapshotDir:  snapshotDir,
		maxSnapshots: maxSnapshots,
	}

	// Load last version from metadata if exists
	sm.loadLastVersion()

	return sm, nil
}

// CreateSnapshot creates a new snapshot (full or incremental).
func (sm *SnapshotManager) CreateSnapshot(incremental bool) (*BackupInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	timestamp := time.Now().Format("20060102-150405")
	var info *BackupInfo
	var err error

	if incremental && sm.lastVersion > 0 {
		path := filepath.Join(sm.snapshotDir, fmt.Sprintf("snapshot-%s-incr-%d.bak", timestamp, sm.lastVersion))
		info, err = sm.store.BackupIncrementalToFile(path, sm.lastVersion)
	} else {
		path := filepath.Join(sm.snapshotDir, fmt.Sprintf("snapshot-%s-full.bak", timestamp))
		info, err = sm.store.BackupToFile(path)
	}

	if err != nil {
		return nil, err
	}

	sm.lastVersion = info.Version
	sm.saveLastVersion()

	// Cleanup old snapshots
	sm.cleanupOldSnapshots()

	return info, nil
}

// ListSnapshots returns all available snapshots.
func (sm *SnapshotManager) ListSnapshots() ([]BackupInfo, error) {
	entries, err := os.ReadDir(sm.snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot directory: %w", err)
	}

	var snapshots []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		snapshots = append(snapshots, BackupInfo{
			Path:      filepath.Join(sm.snapshotDir, entry.Name()),
			Timestamp: info.ModTime(),
			Size:      info.Size(),
		})
	}

	return snapshots, nil
}

func (sm *SnapshotManager) loadLastVersion() {
	metaPath := filepath.Join(sm.snapshotDir, ".version")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return
	}
	if len(data) >= 8 {
		sm.lastVersion = binary.LittleEndian.Uint64(data)
	}
}

func (sm *SnapshotManager) saveLastVersion() {
	metaPath := filepath.Join(sm.snapshotDir, ".version")
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, sm.lastVersion)
	os.WriteFile(metaPath, data, 0600)
}

func (sm *SnapshotManager) cleanupOldSnapshots() {
	if sm.maxSnapshots <= 0 {
		return
	}

	snapshots, err := sm.ListSnapshots()
	if err != nil {
		return
	}

	if len(snapshots) <= sm.maxSnapshots {
		return
	}

	// Remove oldest snapshots
	for i := 0; i < len(snapshots)-sm.maxSnapshots; i++ {
		os.Remove(snapshots[i].Path)
	}
}
