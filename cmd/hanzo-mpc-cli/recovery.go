package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/hanzoai/mpc/pkg/kvstore"
)

// recoverDatabase handles the database recovery from encrypted backup files
func recoverDatabase(ctx context.Context, c *cli.Command) error {
	backupDir := c.String("backup-dir")
	recoveryPath := c.String("recovery-path")
	force := c.Bool("force")

	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("backup directory does not exist: %s", backupDir)
	}

	if _, err := os.Stat(recoveryPath); err == nil && !force {
		return fmt.Errorf("recovery path already exists: %s (use --force to overwrite)", recoveryPath)
	}

	// Prompt for encryption key
	var key []byte
	fmt.Print("Enter backup encryption key: ")
	keyBytes, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read encryption key: %w", err)
	}
	fmt.Println() // Add newline after password input
	key = keyBytes
	if len(key) == 0 {
		return fmt.Errorf("encryption key cannot be empty")
	}

	// Remove existing recovery path if force flag is set
	if force {
		if err := os.RemoveAll(recoveryPath); err != nil {
			return fmt.Errorf("failed to remove existing recovery path: %w", err)
		}
	}

	fmt.Printf("Starting database recovery...\n")
	fmt.Printf("Backup directory: %s\n", backupDir)
	fmt.Printf("Recovery path: %s\n", recoveryPath)

	// Create a temporary backup executor to access the backup files
	tempExecutor := kvstore.NewBadgerBackupExecutor("temp", nil, key, backupDir)

	// Perform the recovery using the existing method with specified recovery path
	if err := tempExecutor.RestoreAllBackupsEncrypted(recoveryPath, key); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	fmt.Printf("✅ Database recovery completed successfully!\n")
	fmt.Printf("Restored database is available at: %s\n", recoveryPath)
	return nil
}
