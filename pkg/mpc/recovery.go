package mpc

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// CalculateRecoveryByte computes the ECDSA signature recovery byte (0 or 1)
// by trying both possible recovery IDs and checking which one recovers
// the expected public key.
//
// Parameters:
//   - rBytes: The R component of the signature (32 bytes)
//   - sBytes: The S component of the signature (32 bytes)
//   - messageHash: The 32-byte hash that was signed
//   - expectedPubKey: The expected compressed public key (33 bytes) or uncompressed (65 bytes)
//
// Returns the recovery byte (0 or 1) and an error if recovery fails.
func CalculateRecoveryByte(rBytes, sBytes, messageHash, expectedPubKey []byte) (byte, error) {
	// Ensure R and S are 32 bytes each
	if len(rBytes) > 32 {
		rBytes = rBytes[len(rBytes)-32:]
	}
	if len(sBytes) > 32 {
		sBytes = sBytes[len(sBytes)-32:]
	}

	// Pad R and S to 32 bytes if needed
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Parse the expected public key
	var expectedPubKeySecp *secp256k1.PublicKey
	var err error

	switch len(expectedPubKey) {
	case 33:
		// Compressed public key
		expectedPubKeySecp, err = secp256k1.ParsePubKey(expectedPubKey)
	case 65:
		// Uncompressed public key
		expectedPubKeySecp, err = secp256k1.ParsePubKey(expectedPubKey)
	default:
		return 0, fmt.Errorf("invalid public key length: %d", len(expectedPubKey))
	}
	if err != nil {
		return 0, fmt.Errorf("failed to parse expected public key: %w", err)
	}

	expectedCompressed := expectedPubKeySecp.SerializeCompressed()

	// Try both recovery IDs (0 and 1)
	for recoveryID := byte(0); recoveryID < 2; recoveryID++ {
		// Create compact signature format: [recoveryID + 27] || R || S
		// The +27 is the compact signature header for non-compressed recovery
		compactSig := make([]byte, 65)
		compactSig[0] = 27 + recoveryID
		copy(compactSig[1:33], rPadded)
		copy(compactSig[33:65], sPadded)

		// Try to recover the public key
		recoveredPubKey, _, err := ecdsa.RecoverCompact(compactSig, messageHash)
		if err != nil {
			continue // This recovery ID doesn't work
		}

		// Check if the recovered public key matches the expected one
		recoveredCompressed := recoveredPubKey.SerializeCompressed()
		if bytes.Equal(recoveredCompressed, expectedCompressed) {
			return recoveryID, nil
		}
	}

	// Try with compressed flag (recovery IDs 2 and 3 for older secp256k1 formats)
	for recoveryID := byte(0); recoveryID < 2; recoveryID++ {
		// Try with compressed recovery header
		compactSig := make([]byte, 65)
		compactSig[0] = 31 + recoveryID // 31 for compressed
		copy(compactSig[1:33], rPadded)
		copy(compactSig[33:65], sPadded)

		recoveredPubKey, _, err := ecdsa.RecoverCompact(compactSig, messageHash)
		if err != nil {
			continue
		}

		recoveredCompressed := recoveredPubKey.SerializeCompressed()
		if bytes.Equal(recoveredCompressed, expectedCompressed) {
			return recoveryID, nil
		}
	}

	return 0, fmt.Errorf("failed to recover matching public key")
}

// HashIfNeeded ensures the message is exactly 32 bytes by hashing if necessary
func HashIfNeeded(message []byte) []byte {
	if len(message) == 32 {
		return message
	}
	hash := sha256.Sum256(message)
	return hash[:]
}
