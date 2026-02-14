// Package storage provides S3-compatible backup support for MPC nodes.
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config configures the S3 backup client.
type S3Config struct {
	// Endpoint is the S3-compatible endpoint (e.g., MinIO, Hanzo Storage)
	Endpoint string
	// Region is the AWS region or custom region for MinIO
	Region string
	// Bucket is the S3 bucket name
	Bucket string
	// AccessKeyID for authentication
	AccessKeyID string
	// SecretAccessKey for authentication
	SecretAccessKey string
	// Prefix is the key prefix for all backups
	Prefix string
	// UsePathStyle forces path-style URLs (required for MinIO)
	UsePathStyle bool
}

// S3BackupClient provides S3-compatible backup operations.
type S3BackupClient struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3BackupClient creates a new S3 backup client.
func NewS3BackupClient(ctx context.Context, cfg S3Config) (*S3BackupClient, error) {
	var awsCfg aws.Config
	var err error

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		// Use static credentials
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"",
			)),
		)
	} else {
		// Use default credentials chain (env vars, IAM role, etc.)
		awsCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom endpoint if provided
	var clientOpts []func(*s3.Options)

	if cfg.Endpoint != "" {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	if cfg.UsePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)

	return &S3BackupClient{
		client: client,
		bucket: cfg.Bucket,
		prefix: cfg.Prefix,
	}, nil
}

// Upload uploads a backup to S3.
func (c *S3BackupClient) Upload(ctx context.Context, key string, data io.Reader, metadata map[string]string) error {
	fullKey := c.fullKey(key)

	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(c.bucket),
		Key:      aws.String(fullKey),
		Body:     data,
		Metadata: metadata,
	})

	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	return nil
}

// UploadFromStore creates and uploads a backup directly from BadgerStore.
func (c *S3BackupClient) UploadFromStore(ctx context.Context, store *BadgerStore, key string, incremental bool, sinceVersion uint64) (*BackupInfo, error) {
	// Create a buffer to hold the backup
	var buf bytes.Buffer

	var version uint64
	var err error

	if incremental && sinceVersion > 0 {
		version, err = store.BackupSince(&buf, sinceVersion)
	} else {
		version, err = store.Backup(&buf)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create backup: %w", err)
	}

	// Upload to S3
	metadata := map[string]string{
		"version":       fmt.Sprintf("%d", version),
		"timestamp":     time.Now().Format(time.RFC3339),
		"incremental":   fmt.Sprintf("%t", incremental),
		"since_version": fmt.Sprintf("%d", sinceVersion),
	}

	if err := c.Upload(ctx, key, &buf, metadata); err != nil {
		return nil, err
	}

	return &BackupInfo{
		Version:      version,
		Timestamp:    time.Now(),
		SinceVersion: sinceVersion,
		Size:         int64(buf.Len()),
		Path:         c.fullKey(key),
		Incremental:  incremental,
	}, nil
}

// Download downloads a backup from S3.
func (c *S3BackupClient) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	fullKey := c.fullKey(key)

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}

	return result.Body, nil
}

// DownloadAndRestore downloads a backup and restores it to a BadgerStore.
func (c *S3BackupClient) DownloadAndRestore(ctx context.Context, store *BadgerStore, key string) error {
	reader, err := c.Download(ctx, key)
	if err != nil {
		return err
	}
	defer reader.Close()

	return store.Load(reader)
}

// List lists all backups in the bucket with the configured prefix.
func (c *S3BackupClient) List(ctx context.Context) ([]S3BackupInfo, error) {
	var backups []S3BackupInfo

	paginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
		Prefix: aws.String(c.prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			backups = append(backups, S3BackupInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
				ETag:         aws.ToString(obj.ETag),
			})
		}
	}

	return backups, nil
}

// Delete deletes a backup from S3.
func (c *S3BackupClient) Delete(ctx context.Context, key string) error {
	fullKey := c.fullKey(key)

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
}

// DeleteOldBackups deletes backups older than the retention period.
func (c *S3BackupClient) DeleteOldBackups(ctx context.Context, retention time.Duration) (int, error) {
	backups, err := c.List(ctx)
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-retention)
	deleted := 0

	for _, backup := range backups {
		if backup.LastModified.Before(cutoff) {
			if err := c.Delete(ctx, strings.TrimPrefix(backup.Key, c.prefix+"/")); err != nil {
				continue
			}
			deleted++
		}
	}

	return deleted, nil
}

func (c *S3BackupClient) fullKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return c.prefix + "/" + key
}

// S3BackupInfo contains metadata about an S3 backup.
type S3BackupInfo struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	ETag         string    `json:"etag"`
}

// ============================================================
// AUTOMATIC BACKUP SCHEDULER
// ============================================================

// BackupScheduler provides automatic periodic backups to S3.
type BackupScheduler struct {
	store       *BadgerStore
	s3Client    *S3BackupClient
	nodeID      string
	interval    time.Duration
	retention   time.Duration
	lastVersion uint64
	stopCh      chan struct{}
	doneCh      chan struct{}
}

// BackupSchedulerConfig configures the backup scheduler.
type BackupSchedulerConfig struct {
	// Store is the BadgerStore to backup
	Store *BadgerStore
	// S3Client is the S3 backup client
	S3Client *S3BackupClient
	// NodeID identifies this MPC node
	NodeID string
	// Interval between backups (default: 1 hour)
	Interval time.Duration
	// Retention period for old backups (default: 7 days)
	Retention time.Duration
}

// NewBackupScheduler creates a new backup scheduler.
func NewBackupScheduler(cfg BackupSchedulerConfig) *BackupScheduler {
	if cfg.Interval == 0 {
		cfg.Interval = time.Hour
	}
	if cfg.Retention == 0 {
		cfg.Retention = 7 * 24 * time.Hour
	}

	return &BackupScheduler{
		store:     cfg.Store,
		s3Client:  cfg.S3Client,
		nodeID:    cfg.NodeID,
		interval:  cfg.Interval,
		retention: cfg.Retention,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start starts the backup scheduler.
func (s *BackupScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop stops the backup scheduler.
func (s *BackupScheduler) Stop() {
	close(s.stopCh)
	<-s.doneCh
}

func (s *BackupScheduler) run(ctx context.Context) {
	defer close(s.doneCh)

	// Do an initial full backup
	s.doBackup(ctx, false)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Do incremental backups after the first full backup
			s.doBackup(ctx, s.lastVersion > 0)
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *BackupScheduler) doBackup(ctx context.Context, incremental bool) {
	timestamp := time.Now().Format("20060102-150405")
	var key string
	if incremental {
		key = fmt.Sprintf("%s/incr-%s-v%d.bak", s.nodeID, timestamp, s.lastVersion)
	} else {
		key = fmt.Sprintf("%s/full-%s.bak", s.nodeID, timestamp)
	}

	info, err := s.s3Client.UploadFromStore(ctx, s.store, key, incremental, s.lastVersion)
	if err != nil {
		// Log error but don't stop scheduler
		return
	}

	s.lastVersion = info.Version

	// Cleanup old backups
	s.s3Client.DeleteOldBackups(ctx, s.retention)
}

// ============================================================
// LOCAL FILE BACKUP (for manual backups)
// ============================================================

// LocalBackupManager manages local file backups with optional S3 sync.
type LocalBackupManager struct {
	store       *BadgerStore
	backupDir   string
	s3Client    *S3BackupClient
	lastVersion uint64
}

// NewLocalBackupManager creates a new local backup manager.
func NewLocalBackupManager(store *BadgerStore, backupDir string, s3Client *S3BackupClient) (*LocalBackupManager, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	return &LocalBackupManager{
		store:     store,
		backupDir: backupDir,
		s3Client:  s3Client,
	}, nil
}

// CreateAndSync creates a local backup and optionally syncs to S3.
func (m *LocalBackupManager) CreateAndSync(ctx context.Context, syncToS3 bool) (*BackupInfo, error) {
	// Create local backup
	timestamp := time.Now().Format("20060102-150405")
	localPath := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.bak", timestamp))

	info, err := m.store.BackupToFile(localPath)
	if err != nil {
		return nil, err
	}

	m.lastVersion = info.Version

	// Sync to S3 if configured
	if syncToS3 && m.s3Client != nil {
		f, err := os.Open(localPath)
		if err != nil {
			return info, nil // Return local backup info even if S3 sync fails
		}
		defer f.Close()

		key := filepath.Base(localPath)
		metadata := map[string]string{
			"version":   fmt.Sprintf("%d", info.Version),
			"timestamp": info.Timestamp.Format(time.RFC3339),
		}

		m.s3Client.Upload(ctx, key, f, metadata)
	}

	return info, nil
}

// RestoreFromS3 downloads and restores a backup from S3.
func (m *LocalBackupManager) RestoreFromS3(ctx context.Context, key string) error {
	return m.s3Client.DownloadAndRestore(ctx, m.store, key)
}

// ============================================================
// HELPER: Parse S3 URL
// ============================================================

// ParseS3URL parses an S3 URL into its components.
// Supports: s3://bucket/prefix, https://endpoint/bucket/prefix
func ParseS3URL(s3URL string) (*S3Config, error) {
	u, err := url.Parse(s3URL)
	if err != nil {
		return nil, err
	}

	cfg := &S3Config{
		Region:       "us-east-1", // Default region
		UsePathStyle: true,        // Default for MinIO compatibility
	}

	switch u.Scheme {
	case "s3":
		cfg.Bucket = u.Host
		cfg.Prefix = strings.TrimPrefix(u.Path, "/")
	case "http", "https":
		cfg.Endpoint = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
		if len(parts) > 0 {
			cfg.Bucket = parts[0]
		}
		if len(parts) > 1 {
			cfg.Prefix = parts[1]
		}
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	return cfg, nil
}
