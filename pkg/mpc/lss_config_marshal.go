package mpc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	lssConfig "github.com/luxfi/threshold/protocols/lss/config"
)

// lssConfigMarshal is the CBOR-friendly representation of LSS Config
type lssConfigMarshal struct {
	ID           party.ID
	GroupName    string // "secp256k1" or "ed25519"
	Threshold    int
	Generation   uint64
	RollbackFrom uint64
	ECDSA        []byte // Private key share (scalar binary)
	Public       []lssPublicMarshal
	ChainKey     []byte
	RID          []byte
}

type lssPublicMarshal struct {
	ID    party.ID
	ECDSA []byte // Public key share (point binary)
}

// MarshalLSSConfig serializes an LSS Config to CBOR bytes
func MarshalLSSConfig(config *lssConfig.Config) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Marshal private share (ECDSA scalar)
	ecdsaBytes, err := config.ECDSA.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA scalar: %w", err)
	}

	// Marshal public shares
	publicShares := make([]lssPublicMarshal, 0, len(config.Public))
	for id, pub := range config.Public {
		if pub == nil || pub.ECDSA == nil {
			continue
		}
		pointBytes, err := pub.ECDSA.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public share for %s: %w", id, err)
		}
		publicShares = append(publicShares, lssPublicMarshal{
			ID:    id,
			ECDSA: pointBytes,
		})
	}

	// Determine group name
	groupName := "secp256k1" // default
	if config.Group != nil {
		switch config.Group.(type) {
		case curve.Secp256k1:
			groupName = "secp256k1"
		case *curve.Secp256k1:
			groupName = "secp256k1"
		default:
			// Try to detect from scalar/point types
			groupName = "secp256k1"
		}
	}

	cm := &lssConfigMarshal{
		ID:           config.ID,
		GroupName:    groupName,
		Threshold:    config.Threshold,
		Generation:   config.Generation,
		RollbackFrom: config.RollbackFrom,
		ECDSA:        ecdsaBytes,
		Public:       publicShares,
		ChainKey:     config.ChainKey,
		RID:          config.RID,
	}

	return cbor.Marshal(cm)
}

// UnmarshalLSSConfig deserializes CBOR bytes to an LSS Config
func UnmarshalLSSConfig(data []byte) (*lssConfig.Config, error) {
	cm := &lssConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LSS config: %w", err)
	}

	// Determine group from name
	var group curve.Curve
	switch cm.GroupName {
	case "secp256k1", "":
		group = curve.Secp256k1{}
	default:
		return nil, fmt.Errorf("unsupported group: %s", cm.GroupName)
	}

	// Unmarshal private share
	ecdsaScalar := group.NewScalar()
	if err := ecdsaScalar.UnmarshalBinary(cm.ECDSA); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ECDSA scalar: %w", err)
	}

	// Unmarshal public shares
	publicShares := make(map[party.ID]*lssConfig.Public, len(cm.Public))
	for _, ps := range cm.Public {
		point := group.NewPoint()
		if err := point.UnmarshalBinary(ps.ECDSA); err != nil {
			return nil, fmt.Errorf("failed to unmarshal public share for %s: %w", ps.ID, err)
		}
		publicShares[ps.ID] = &lssConfig.Public{
			ECDSA: point,
		}
	}

	return &lssConfig.Config{
		ID:           cm.ID,
		Group:        group,
		Threshold:    cm.Threshold,
		Generation:   cm.Generation,
		RollbackFrom: cm.RollbackFrom,
		ECDSA:        ecdsaScalar,
		Public:       publicShares,
		ChainKey:     cm.ChainKey,
		RID:          cm.RID,
	}, nil
}
