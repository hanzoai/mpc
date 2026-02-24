package hsm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFileProvider_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	p, err := NewFileProvider(&FileConfig{
		BasePath:   dir,
		HexEncoded: true,
	})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if p.Name() != "file" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "file")
	}

	// Generate a deterministic Ed25519 seed.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	keyID := "test-key-01"

	// Store.
	if err := p.StoreKey(ctx, keyID, seed); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Verify file exists and contains hex.
	data, err := os.ReadFile(filepath.Join(dir, keyID))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != hex.EncodeToString(seed) {
		t.Fatalf("file content = %q, want %q", data, hex.EncodeToString(seed))
	}

	// Get.
	got, err := p.GetKey(ctx, keyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(seed) {
		t.Fatalf("GetKey returned %x, want %x", got, seed)
	}

	// List.
	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0] != keyID {
		t.Fatalf("ListKeys = %v, want [%q]", keys, keyID)
	}

	// Delete.
	if err := p.DeleteKey(ctx, keyID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	keys, err = p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys after delete: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListKeys after delete = %v, want empty", keys)
	}
}

func TestFileProvider_Sign(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	p, err := NewFileProvider(&FileConfig{
		BasePath:   dir,
		HexEncoded: true,
	})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	// Use a real Ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	seed := priv.Seed()
	keyID := "sign-test"

	if err := p.StoreKey(ctx, keyID, seed); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	message := []byte("threshold signing test message")
	sig, err := p.Sign(ctx, keyID, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !ed25519.Verify(pub, message, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestFileProvider_Healthy(t *testing.T) {
	dir := t.TempDir()

	p, err := NewFileProvider(&FileConfig{BasePath: dir})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if err := p.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy: %v", err)
	}

	// Non-existent path should fail.
	p2, err := NewFileProvider(&FileConfig{BasePath: filepath.Join(dir, "nonexistent")})
	if err != nil {
		// NewFileProvider creates the directory, so it should succeed.
		t.Fatalf("NewFileProvider: %v", err)
	}
	// But it exists now because we created it.
	if err := p2.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy after create: %v", err)
	}
}

func TestFileProvider_RawBytes(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Test non-hex mode.
	p, err := NewFileProvider(&FileConfig{
		BasePath:   dir,
		HexEncoded: false,
	})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 100)
	}

	keyID := "raw-key"
	if err := p.StoreKey(ctx, keyID, seed); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	got, err := p.GetKey(ctx, keyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	if hex.EncodeToString(got) != hex.EncodeToString(seed) {
		t.Fatalf("raw GetKey returned %x, want %x", got, seed)
	}
}

func TestNewProvider_File(t *testing.T) {
	dir := t.TempDir()

	p, err := NewProvider(Config{
		Provider: "file",
		File:     &FileConfig{BasePath: dir},
	})
	if err != nil {
		t.Fatalf("NewProvider(file): %v", err)
	}
	if p.Name() != "file" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "file")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewProvider_Default(t *testing.T) {
	dir := t.TempDir()

	// Empty provider string should default to file.
	p, err := NewProvider(Config{
		File: &FileConfig{BasePath: dir},
	})
	if err != nil {
		t.Fatalf("NewProvider(default): %v", err)
	}
	if p.Name() != "file" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "file")
	}
}

func TestNewProvider_Unknown(t *testing.T) {
	_, err := NewProvider(Config{Provider: "quantum"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestNewProvider_GCP_Stub(t *testing.T) {
	// Without gcp build tag, should return "not compiled" error.
	_, err := NewGCPProvider(&GCPConfig{Project: "test"})
	if err == nil {
		t.Skip("gcp build tag is active; skipping stub test")
	}
}

func TestNewProvider_Azure_Stub(t *testing.T) {
	_, err := NewAzureProvider(&AzureConfig{VaultURL: "https://test"})
	if err == nil {
		t.Skip("azure build tag is active; skipping stub test")
	}
}

func TestNewProvider_Zymbit_Stub(t *testing.T) {
	_, err := NewZymbitProvider(&ZymbitConfig{APIEndpoint: "http://localhost"})
	if err == nil {
		t.Skip("zymbit build tag is active; skipping stub test")
	}
}
