package mpc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
)

// taprootConfigMarshal is the CBOR-friendly representation of TaprootConfig
type taprootConfigMarshal struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte // 32 bytes (Secp256k1Scalar)
	PublicKey          []byte // 32 bytes (x-only Taproot public key)
	ChainKey           []byte // 32 bytes
	VerificationShares []verificationShareMarshal
}

type verificationShareMarshal struct {
	ID    party.ID
	Point []byte // 33 bytes (compressed Secp256k1Point)
}

// MarshalFROSTConfig serializes a TaprootConfig to CBOR bytes
func MarshalFROSTConfig(config *frost.TaprootConfig) ([]byte, error) {
	// Marshal private share
	privateShareBytes, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private share: %w", err)
	}

	// Marshal verification shares
	shares := make([]verificationShareMarshal, 0, len(config.VerificationShares))
	for id, point := range config.VerificationShares {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verification share for %s: %w", id, err)
		}
		shares = append(shares, verificationShareMarshal{
			ID:    id,
			Point: pointBytes,
		})
	}

	cm := &taprootConfigMarshal{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateShareBytes,
		PublicKey:          config.PublicKey,
		ChainKey:           config.ChainKey,
		VerificationShares: shares,
	}

	return cbor.Marshal(cm)
}

// UnmarshalFROSTConfig deserializes CBOR bytes to a TaprootConfig
func UnmarshalFROSTConfig(data []byte) (*frost.TaprootConfig, error) {
	cm := &taprootConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Unmarshal private share
	group := curve.Secp256k1{}
	privateShare := group.NewScalar().(*curve.Secp256k1Scalar)
	if err := privateShare.UnmarshalBinary(cm.PrivateShare); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private share: %w", err)
	}

	// Unmarshal verification shares
	verificationShares := make(map[party.ID]*curve.Secp256k1Point, len(cm.VerificationShares))
	for _, vs := range cm.VerificationShares {
		point := group.NewPoint().(*curve.Secp256k1Point)
		if err := point.UnmarshalBinary(vs.Point); err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification share for %s: %w", vs.ID, err)
		}
		verificationShares[vs.ID] = point
	}

	return &frost.TaprootConfig{
		ID:                 cm.ID,
		Threshold:          cm.Threshold,
		PrivateShare:       privateShare,
		PublicKey:          cm.PublicKey,
		ChainKey:           cm.ChainKey,
		VerificationShares: verificationShares,
	}, nil
}
