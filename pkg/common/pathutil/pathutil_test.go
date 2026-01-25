package pathutil

import (
	"testing"
)

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "test.json",
			wantErr: false,
		},
		{
			name:    "valid relative path",
			path:    "config/test.json",
			wantErr: false,
		},
		{
			name:    "path traversal attempt",
			path:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal with clean",
			path:    "config/../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "valid absolute path",
			path:    "/tmp/test.json",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSafePath(t *testing.T) {
	tests := []struct {
		name     string
		baseDir  string
		filename string
		wantErr  bool
	}{
		{
			name:     "valid file in base dir",
			baseDir:  "/tmp",
			filename: "test.json",
			wantErr:  false,
		},
		{
			name:     "path traversal attempt",
			baseDir:  "/tmp",
			filename: "../../../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "path traversal with clean",
			baseDir:  "/tmp",
			filename: "config/../../../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "valid subdirectory",
			baseDir:  "/tmp",
			filename: "config/test.json",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SafePath(tt.baseDir, tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
