package kvstore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate random encryption key
func generateRandomKey(size int) []byte {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		panic(err) // Should never happen in tests
	}
	return key
}

// Helper function to generate test encryption keys
func generateTestKeys() ([]byte, []byte) {
	return generateRandomKey(32), generateRandomKey(32)
}

func TestBadgerBackupExecutor_Execute(t *testing.T) {
	// Setup test directories
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	// Generate random encryption keys
	encryptionKey, backupEncryptionKey := generateTestKeys()

	// Create BadgerDB
	opts := badger.DefaultOptions(dbPath).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithSyncWrites(false) // Faster for tests
	db, err := badger.Open(opts)
	require.NoError(t, err)
	defer db.Close()

	// Create backup executor
	executor := NewBadgerBackupExecutor("test-node", db, backupEncryptionKey, backupDir)

	t.Run("first backup should create initial backup", func(t *testing.T) {
		// Add some data
		err := db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte("key1"), []byte("value1"))
		})
		require.NoError(t, err)

		// Execute backup
		err = executor.Execute()
		require.NoError(t, err)

		// Check that backup file was created
		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 1)

		// Check version info was saved
		info, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		assert.Greater(t, info.Version, uint64(0))
	})

	t.Run("incremental backup should only backup changes", func(t *testing.T) {
		// Get initial version
		initialInfo, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		initialVersion := initialInfo.Version

		// Add more data
		err = db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte("key2"), []byte("value2"))
		})
		require.NoError(t, err)

		// Execute backup again
		err = executor.Execute()
		require.NoError(t, err)

		// Check that new backup file was created
		paths := filepath.Join(backupDir, "backup-*.enc")
		files, err := filepath.Glob(paths)
		require.NoError(t, err)
		assert.Len(t, files, 2)

		// Check version was incremented
		finalInfo, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		assert.Greater(t, finalInfo.Version, initialVersion)
	})

	t.Run("backup with no changes should be skipped", func(t *testing.T) {
		// Get current version
		info, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		currentVersion := info.Version

		// Execute backup without changes
		err = executor.Execute()
		require.NoError(t, err)

		// Check that version didn't change
		newInfo, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, currentVersion, newInfo.Version)

		// Check that no new backup file was created
		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 2) // Should still be 2 from previous test
	})
}

func TestBadgerBackupExecutor_BackupMetadata(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	opts := badger.DefaultOptions(dbPath).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithSyncWrites(false)
	db, err := badger.Open(opts)
	require.NoError(t, err)
	defer db.Close()

	executor := NewBadgerBackupExecutor("test-node", db, backupEncryptionKey, backupDir)

	// Add data and create backup
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("test-key"), []byte("test-value"))
	})
	require.NoError(t, err)

	// Debug: check version info before backup
	info, err := executor.LoadVersionInfo()
	require.NoError(t, err)
	t.Logf("Version before backup: %d", info.Version)

	err = executor.Execute()
	require.NoError(t, err)

	// Debug: check version info after backup
	info, err = executor.LoadVersionInfo()
	require.NoError(t, err)
	t.Logf("Version after backup: %d", info.Version)

	// Verify that a backup was actually created (not skipped)
	assert.Greater(t, info.Version, uint64(0), "Backup should have been created and version should be > 0")

	// Find backup file
	files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Debug: list all files in backup directory
	allFiles, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	t.Logf("Files in backup directory:")
	for _, file := range allFiles {
		t.Logf("  - %s (dir: %v)", file.Name(), file.IsDir())
	}

	// Test metadata parsing
	t.Run("backup file should have correct metadata", func(t *testing.T) {
		// Debug: check if backup file exists and has content
		backupFile := files[0]
		fileInfo, err := os.Stat(backupFile)
		require.NoError(t, err)
		assert.Greater(t, fileInfo.Size(), int64(0), "Backup file should not be empty")

		// Debug: read the first few bytes to see the magic header
		data, err := os.ReadFile(backupFile)
		require.NoError(t, err)
		t.Logf("Backup file size: %d bytes", len(data))
		if len(data) >= len(magic) {
			t.Logf("Magic header: %s", string(data[:len(magic)]))
		}

		meta, err := executor.parseBackupMetadata(backupFile)
		if err != nil {
			t.Logf("parseBackupMetadata error: %v", err)
		}
		require.NoError(t, err)

		assert.Equal(t, "AES-256-GCM", meta.Algo)
		assert.NotEmpty(t, meta.NonceB64)
		assert.NotEmpty(t, meta.CreatedAt)
		assert.GreaterOrEqual(t, meta.Since, uint64(0)) // Since can be 0 for first backup
		assert.Greater(t, meta.NextSince, meta.Since)
		assert.NotEmpty(t, meta.EncryptionKeyID)
	})

	t.Run("backup file should be encrypted", func(t *testing.T) {
		// Read the backup file
		data, err := os.ReadFile(files[0])
		require.NoError(t, err)

		// Should contain magic header
		assert.Contains(t, string(data), "LUX_MPC_BACKUP")

		// Should not contain plaintext data
		assert.NotContains(t, string(data), "test-value")
	})
}

func TestBadgerBackupExecutor_VersionTracking(t *testing.T) {
	testDir := t.TempDir()
	backupDir := filepath.Join(testDir, "backups")

	// Create backup directory for the mock executor
	err := os.MkdirAll(backupDir, 0755)
	require.NoError(t, err)

	// Create a mock executor just for version tracking tests
	executor := &badgerBackupExecutor{
		NodeID:              "test-node",
		BackupEncryptionKey: generateRandomKey(32),
		BackupDir:           backupDir,
	}

	t.Run("should create version file on first save", func(t *testing.T) {
		version := uint64(12345)
		since := uint64(100)
		err := executor.SaveVersionInfo(version, since)
		require.NoError(t, err)

		// Check file was created
		versionFile := filepath.Join(backupDir, "latest.version")
		_, err = os.Stat(versionFile)
		require.NoError(t, err)

		// Load and verify
		info, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, version, info.Version)
		assert.NotEmpty(t, info.UpdatedAt)
	})

	t.Run("should update version file on subsequent saves", func(t *testing.T) {
		// Get the file modification time before the update
		versionFile := filepath.Join(backupDir, "latest.version")
		oldFileInfo, err := os.Stat(versionFile)
		require.NoError(t, err)
		oldModTime := oldFileInfo.ModTime()

		// Wait a bit to ensure different timestamp
		time.Sleep(100 * time.Millisecond) // Increased from 10ms to 100ms

		newVersion := uint64(67890)
		newSince := uint64(200)
		err = executor.SaveVersionInfo(newVersion, newSince)
		require.NoError(t, err)

		// Check that the file modification time changed
		newFileInfo, err := os.Stat(versionFile)
		require.NoError(t, err)
		newModTime := newFileInfo.ModTime()
		assert.True(t, newModTime.After(oldModTime), "File modification time should be updated")

		// Also check the version was updated
		newInfo, err := executor.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, newVersion, newInfo.Version)
	})

	t.Run("should handle missing version file gracefully", func(t *testing.T) {
		// Remove version file
		versionFile := filepath.Join(backupDir, "latest.version")
		os.Remove(versionFile)

		// Load should return default values (not error)
		info, err := executor.LoadVersionInfo()
		require.NoError(t, err) // Should NOT error because LoadVersionInfo returns default
		assert.Equal(t, uint64(0), info.Version)
		assert.NotEmpty(t, info.UpdatedAt) // Should have current timestamp
	})
}

func TestBadgerBackupExecutor_Restore(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")
	restorePath := filepath.Join(testDir, "restored")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	// Create source database
	opts := badger.DefaultOptions(dbPath).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithSyncWrites(false)
	db, err := badger.Open(opts)
	require.NoError(t, err)

	executor := NewBadgerBackupExecutor("test-node", db, backupEncryptionKey, backupDir)

	// Add data in multiple batches
	testData := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	// First batch
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("key1"), []byte("value1"))
	})
	require.NoError(t, err)

	err = executor.Execute()
	require.NoError(t, err)

	// Second batch
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("key2"), []byte("value2"))
	})
	require.NoError(t, err)

	err = executor.Execute()
	require.NoError(t, err)

	// Third batch
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("key3"), []byte("value3"))
	})
	require.NoError(t, err)

	err = executor.Execute()
	require.NoError(t, err)

	db.Close()

	t.Run("should restore all backups in order", func(t *testing.T) {
		err := executor.RestoreAllBackupsEncrypted(restorePath, encryptionKey)
		require.NoError(t, err)

		// Open restored database
		restoreOpts := badger.DefaultOptions(restorePath).
			WithEncryptionKey(encryptionKey).
			WithIndexCacheSize(10 << 20)
		restoreDB, err := badger.Open(restoreOpts)
		require.NoError(t, err)
		defer restoreDB.Close()

		// Verify all data was restored
		for key, expectedValue := range testData {
			var value []byte
			err := restoreDB.View(func(txn *badger.Txn) error {
				item, err := txn.Get([]byte(key))
				if err != nil {
					return err
				}
				return item.Value(func(val []byte) error {
					value = append([]byte{}, val...)
					return nil
				})
			})
			require.NoError(t, err)
			assert.Equal(t, expectedValue, string(value))
		}
	})

	t.Run("should handle empty backup directory", func(t *testing.T) {
		emptyBackupDir := filepath.Join(testDir, "empty_backups")
		err := os.MkdirAll(emptyBackupDir, 0755)
		require.NoError(t, err)

		emptyExecutor := NewBadgerBackupExecutor("test-node", nil, backupEncryptionKey, emptyBackupDir)

		restorePath := filepath.Join(testDir, "empty_restored")
		err = emptyExecutor.RestoreAllBackupsEncrypted(restorePath, encryptionKey)
		require.NoError(t, err)

		// Should create an empty database
		restoreOpts := badger.DefaultOptions(restorePath).
			WithEncryptionKey(encryptionKey).
			WithIndexCacheSize(10 << 20)
		restoreDB, err := badger.Open(restoreOpts)
		require.NoError(t, err)
		defer restoreDB.Close()
	})
}

func TestBadgerBackupExecutor_BackupFileFormat(t *testing.T) {
	testDir := t.TempDir()
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	opts := badger.DefaultOptions(filepath.Join(testDir, "testdb")).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithSyncWrites(false)
	db, err := badger.Open(opts)
	require.NoError(t, err)
	defer db.Close()

	executor := NewBadgerBackupExecutor("test-node", db, backupEncryptionKey, backupDir)

	// Add data and create backup
	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("test-key"), []byte("test-value"))
	})
	require.NoError(t, err)

	err = executor.Execute()
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	t.Run("backup file should have correct format", func(t *testing.T) {
		// Read file
		data, err := os.ReadFile(files[0])
		require.NoError(t, err)

		// Check magic header
		assert.True(t, len(data) >= len(magic))
		assert.Equal(t, magic, string(data[:len(magic)]))

		// Check metadata length (4 bytes after magic)
		if len(data) >= len(magic)+4 {
			metaLen := uint32(data[len(magic)])<<24 | uint32(data[len(magic)+1])<<16 |
				uint32(data[len(magic)+2])<<8 | uint32(data[len(magic)+3])
			assert.Greater(t, metaLen, uint32(0))
			assert.Less(t, metaLen, uint32(len(data)-len(magic)-4))
		}
	})

	t.Run("backup filename should follow pattern", func(t *testing.T) {
		filename := filepath.Base(files[0])
		assert.Contains(t, filename, "backup-test-node-")
		assert.Contains(t, filename, ".enc")
	})
}

// Helper method to parse backup metadata for testing
func (b *badgerBackupExecutor) parseBackupMetadata(path string) (BadgerBackupMeta, error) {
	var meta BadgerBackupMeta

	f, err := os.Open(path)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	// Skip magic
	magicBuf := make([]byte, len(magic))
	if _, err := f.Read(magicBuf); err != nil {
		return meta, err
	}

	// Read metadata length
	var metaLen uint32
	if err := binary.Read(f, binary.BigEndian, &metaLen); err != nil {
		return meta, err
	}

	// Read metadata
	metaBuf := make([]byte, metaLen)
	if _, err := f.Read(metaBuf); err != nil {
		return meta, err
	}

	err = json.Unmarshal(metaBuf, &meta)
	return meta, err
}

func TestBadgerKVStore_BackupIntegration(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	// Create BadgerKVStore with BadgerConfig
	config := BadgerConfig{
		NodeID:              "test-node",
		EncryptionKey:       encryptionKey,
		BackupEncryptionKey: backupEncryptionKey,
		BackupDir:           backupDir,
		DBPath:              dbPath,
	}

	store, err := NewBadgerKVStore(config)
	require.NoError(t, err)
	defer store.Close()

	t.Run("store should work with incremental backup", func(t *testing.T) {
		// Add data
		err := store.Put("key1", []byte("value1"))
		require.NoError(t, err)

		// First backup
		err = store.Backup()
		require.NoError(t, err)

		// Add more data
		err = store.Put("key2", []byte("value2"))
		require.NoError(t, err)
		err = store.Put("key3", []byte("value3"))
		require.NoError(t, err)

		// Second backup
		err = store.Backup()
		require.NoError(t, err)

		// Verify data is still accessible
		value1, err := store.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", string(value1))

		value2, err := store.Get("key2")
		require.NoError(t, err)
		assert.Equal(t, "value2", string(value2))

		value3, err := store.Get("key3")
		require.NoError(t, err)
		assert.Equal(t, "value3", string(value3))

		// Check backup files were created
		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 2)
	})

	t.Run("store should handle backup without executor", func(t *testing.T) {
		store.BackupExecutor = nil
		err := store.Backup()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backup executor is not initialized")
	})
}
