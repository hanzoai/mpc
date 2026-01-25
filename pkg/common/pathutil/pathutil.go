package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SafePath validates and constructs a safe file path within a base directory
func SafePath(baseDir, filename string) (string, error) {
	// Clean the filename to prevent path traversal
	cleanFilename := filepath.Clean(filename)

	// Check for path traversal attempts
	if strings.Contains(cleanFilename, "..") {
		return "", fmt.Errorf("invalid filename: path traversal not allowed")
	}

	// Construct the full path
	fullPath := filepath.Join(baseDir, cleanFilename)

	// Ensure the path is within the base directory
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for base directory: %w", err)
	}

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	if !strings.HasPrefix(absPath, absBase) {
		return "", fmt.Errorf("path outside base directory not allowed")
	}

	return fullPath, nil
}

// ValidateFilePath validates a file path for security concerns
func ValidateFilePath(filePath string) error {
	// Clean the path
	cleanPath := filepath.Clean(filePath)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid file path: path traversal not allowed")
	}

	return nil
}
