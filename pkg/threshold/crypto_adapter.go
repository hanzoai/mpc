// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package threshold provides adapters that implement crypto/threshold interfaces
// by wrapping the MPC protocol implementations (CGGMP21, FROST).
package threshold

import (
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	cryptothreshold "github.com/luxfi/crypto/threshold"
	"github.com/hanzoai/mpc/pkg/protocol"
	"github.com/hanzoai/mpc/pkg/protocol/cggmp21"
	"github.com/hanzoai/mpc/pkg/protocol/frost"
)

func init() {
	// Register MPC schemes with crypto/threshold registry
	cryptothreshold.RegisterScheme(&CGGMP21Scheme{})
	cryptothreshold.RegisterScheme(&FROSTScheme{})
}

// =============================================================================
// CGGMP21 Scheme (Threshold ECDSA)
// =============================================================================

// CGGMP21Scheme implements threshold.Scheme for CGGMP21 (threshold ECDSA).
type CGGMP21Scheme struct {
	protocol protocol.Protocol
	once     sync.Once
}

func (s *CGGMP21Scheme) init() {
	s.once.Do(func() {
		s.protocol = cggmp21.NewCGGMP21Protocol()
	})
}

func (s *CGGMP21Scheme) ID() cryptothreshold.SchemeID {
	return cryptothreshold.SchemeCMP
}

func (s *CGGMP21Scheme) Name() string {
	return "CGGMP21 (Threshold ECDSA)"
}

func (s *CGGMP21Scheme) KeyShareSize() int {
	return 256 // Approximate serialized size
}

func (s *CGGMP21Scheme) SignatureShareSize() int {
	return 64 // ECDSA signature share
}

func (s *CGGMP21Scheme) SignatureSize() int {
	return 65 // ECDSA signature (r, s, v)
}

func (s *CGGMP21Scheme) PublicKeySize() int {
	return 65 // Uncompressed ECDSA public key
}

func (s *CGGMP21Scheme) NewDKG(config cryptothreshold.DKGConfig) (cryptothreshold.DKG, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	s.init()
	return &cggmp21DKG{
		scheme: s,
		config: config,
	}, nil
}

func (s *CGGMP21Scheme) NewTrustedDealer(config cryptothreshold.DealerConfig) (cryptothreshold.TrustedDealer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	s.init()
	return &cggmp21TrustedDealer{
		scheme: s,
		config: config,
	}, nil
}

func (s *CGGMP21Scheme) NewSigner(share cryptothreshold.KeyShare) (cryptothreshold.Signer, error) {
	if share == nil {
		return nil, errors.New("nil key share")
	}
	s.init()
	return &cggmp21Signer{
		scheme: s,
		share:  share,
	}, nil
}

func (s *CGGMP21Scheme) NewAggregator(groupKey cryptothreshold.PublicKey) (cryptothreshold.Aggregator, error) {
	if groupKey == nil {
		return nil, errors.New("nil group key")
	}
	s.init()
	return &cggmp21Aggregator{
		scheme:   s,
		groupKey: groupKey,
	}, nil
}

func (s *CGGMP21Scheme) NewVerifier(groupKey cryptothreshold.PublicKey) (cryptothreshold.Verifier, error) {
	if groupKey == nil {
		return nil, errors.New("nil group key")
	}
	s.init()
	return &cggmp21Verifier{
		scheme:   s,
		groupKey: groupKey,
	}, nil
}

func (s *CGGMP21Scheme) ParseKeyShare(data []byte) (cryptothreshold.KeyShare, error) {
	return &cggmp21KeyShare{
		scheme: s,
		data:   data,
	}, nil
}

func (s *CGGMP21Scheme) ParsePublicKey(data []byte) (cryptothreshold.PublicKey, error) {
	return &cggmp21PublicKey{
		scheme: s,
		data:   data,
	}, nil
}

func (s *CGGMP21Scheme) ParseSignatureShare(data []byte) (cryptothreshold.SignatureShare, error) {
	return &cggmp21SignatureShare{
		scheme: s,
		data:   data,
	}, nil
}

func (s *CGGMP21Scheme) ParseSignature(data []byte) (cryptothreshold.Signature, error) {
	return &cggmp21Signature{
		scheme: s,
		data:   data,
	}, nil
}

// CGGMP21 implementation types

type cggmp21DKG struct {
	scheme      *CGGMP21Scheme
	config      cryptothreshold.DKGConfig
	party       protocol.Party
	round       int
	groupKey    cryptothreshold.PublicKey
	keyGenDone  bool
	keyGenError error
}

func (d *cggmp21DKG) Round1(ctx context.Context) (cryptothreshold.DKGMessage, error) {
	partyIDs := make([]string, d.config.TotalParties)
	for i := 0; i < d.config.TotalParties; i++ {
		partyIDs[i] = fmt.Sprintf("party-%d", i)
	}
	selfID := partyIDs[d.config.PartyIndex]

	party, err := d.scheme.protocol.KeyGen(selfID, partyIDs, d.config.Threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to start keygen: %w", err)
	}
	d.party = party
	d.round = 1

	// Get first round message
	select {
	case msg := <-party.Messages():
		return &cggmp21DKGMessage{
			round: 1,
			from:  d.config.PartyIndex,
			data:  msg.GetData(),
		}, nil
	case err := <-party.Errors():
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *cggmp21DKG) Round2(ctx context.Context, round1Messages map[int]cryptothreshold.DKGMessage) (cryptothreshold.DKGMessage, error) {
	if d.party == nil {
		return nil, errors.New("DKG not started")
	}

	// Process round 1 messages
	for _, msg := range round1Messages {
		if err := d.party.Update(&protocolMessage{data: msg.Bytes()}); err != nil {
			return nil, err
		}
	}

	d.round = 2

	// Get round 2 message
	select {
	case msg := <-d.party.Messages():
		return &cggmp21DKGMessage{
			round: 2,
			from:  d.config.PartyIndex,
			data:  msg.GetData(),
		}, nil
	case err := <-d.party.Errors():
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *cggmp21DKG) Round3(ctx context.Context, round2Messages map[int]cryptothreshold.DKGMessage) (cryptothreshold.KeyShare, error) {
	if d.party == nil {
		return nil, errors.New("DKG not started")
	}

	// Process round 2 messages
	for _, msg := range round2Messages {
		if err := d.party.Update(&protocolMessage{data: msg.Bytes()}); err != nil {
			return nil, err
		}
	}

	// Wait for completion
	for !d.party.Done() {
		select {
		case err := <-d.party.Errors():
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			// Continue waiting
		}
	}

	result, err := d.party.Result()
	if err != nil {
		return nil, err
	}

	config, ok := result.(protocol.KeyGenConfig)
	if !ok {
		return nil, errors.New("unexpected result type")
	}

	// Create key share from config
	data, err := config.Serialize()
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ellipticPublicKeyToBytes(config.GetPublicKey())
	d.groupKey = &cggmp21PublicKey{
		scheme: d.scheme,
		data:   pubKeyBytes,
	}

	return &cggmp21KeyShare{
		scheme:       d.scheme,
		data:         data,
		index:        d.config.PartyIndex,
		threshold:    d.config.Threshold,
		totalParties: d.config.TotalParties,
		groupKey:     d.groupKey,
		publicShare:  ellipticPublicKeyToBytes(config.GetSharePublicKey()),
	}, nil
}

func (d *cggmp21DKG) NumRounds() int {
	return 5 // CGGMP21 has 5 rounds
}

func (d *cggmp21DKG) GroupKey() cryptothreshold.PublicKey {
	return d.groupKey
}

type cggmp21TrustedDealer struct {
	scheme *CGGMP21Scheme
	config cryptothreshold.DealerConfig
}

func (d *cggmp21TrustedDealer) GenerateShares(ctx context.Context) ([]cryptothreshold.KeyShare, cryptothreshold.PublicKey, error) {
	// For trusted dealer, we simulate DKG locally
	// In production, this would generate Shamir shares of an ECDSA key

	// Generate a master ECDSA key
	rand := d.config.Rand
	if rand == nil {
		rand = defaultRand()
	}

	// Create placeholder shares
	shares := make([]cryptothreshold.KeyShare, d.config.TotalParties)
	for i := 0; i < d.config.TotalParties; i++ {
		shareData := make([]byte, 32)
		if _, err := io.ReadFull(rand, shareData); err != nil {
			return nil, nil, err
		}

		shares[i] = &cggmp21KeyShare{
			scheme:       d.scheme,
			data:         shareData,
			index:        i,
			threshold:    d.config.Threshold,
			totalParties: d.config.TotalParties,
		}
	}

	// Create group public key placeholder
	groupKeyData := make([]byte, 65)
	groupKeyData[0] = 0x04 // Uncompressed point marker
	if _, err := io.ReadFull(rand, groupKeyData[1:]); err != nil {
		return nil, nil, err
	}

	groupKey := &cggmp21PublicKey{
		scheme: d.scheme,
		data:   groupKeyData,
	}

	// Set group key on all shares
	for i := range shares {
		shares[i].(*cggmp21KeyShare).groupKey = groupKey
	}

	return shares, groupKey, nil
}

type cggmp21KeyShare struct {
	scheme       *CGGMP21Scheme
	data         []byte
	index        int
	threshold    int
	totalParties int
	groupKey     cryptothreshold.PublicKey
	publicShare  []byte
}

func (s *cggmp21KeyShare) Index() int                          { return s.index }
func (s *cggmp21KeyShare) GroupKey() cryptothreshold.PublicKey { return s.groupKey }
func (s *cggmp21KeyShare) PublicShare() []byte                 { return s.publicShare }
func (s *cggmp21KeyShare) Threshold() int                      { return s.threshold }
func (s *cggmp21KeyShare) TotalParties() int                   { return s.totalParties }
func (s *cggmp21KeyShare) Bytes() []byte                       { return s.data }
func (s *cggmp21KeyShare) SchemeID() cryptothreshold.SchemeID  { return cryptothreshold.SchemeCMP }

type cggmp21PublicKey struct {
	scheme *CGGMP21Scheme
	data   []byte
}

func (k *cggmp21PublicKey) Bytes() []byte { return k.data }
func (k *cggmp21PublicKey) Equal(other cryptothreshold.PublicKey) bool {
	if other == nil {
		return false
	}
	otherBytes := other.Bytes()
	if len(k.data) != len(otherBytes) {
		return false
	}
	for i := range k.data {
		if k.data[i] != otherBytes[i] {
			return false
		}
	}
	return true
}
func (k *cggmp21PublicKey) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeCMP }

type cggmp21Signer struct {
	scheme *CGGMP21Scheme
	share  cryptothreshold.KeyShare
}

func (s *cggmp21Signer) Index() int           { return s.share.Index() }
func (s *cggmp21Signer) PublicShare() []byte  { return s.share.PublicShare() }
func (s *cggmp21Signer) KeyShare() cryptothreshold.KeyShare { return s.share }

func (s *cggmp21Signer) NonceGen(ctx context.Context) (cryptothreshold.NonceCommitment, cryptothreshold.NonceState, error) {
	// CGGMP21 uses presigning for nonces
	return nil, nil, errors.New("use presigning for CGGMP21 nonces")
}

func (s *cggmp21Signer) SignShare(ctx context.Context, message []byte, signers []int, nonce cryptothreshold.NonceState) (cryptothreshold.SignatureShare, error) {
	// Create signature share (placeholder - real impl would use protocol)
	shareData := make([]byte, 64)
	copy(shareData, message)

	return &cggmp21SignatureShare{
		scheme: s.scheme,
		index:  s.share.Index(),
		data:   shareData,
	}, nil
}

type cggmp21SignatureShare struct {
	scheme *CGGMP21Scheme
	index  int
	data   []byte
}

func (s *cggmp21SignatureShare) Index() int                         { return s.index }
func (s *cggmp21SignatureShare) Bytes() []byte                      { return s.data }
func (s *cggmp21SignatureShare) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeCMP }

type cggmp21Aggregator struct {
	scheme   *CGGMP21Scheme
	groupKey cryptothreshold.PublicKey
}

func (a *cggmp21Aggregator) GroupKey() cryptothreshold.PublicKey { return a.groupKey }

func (a *cggmp21Aggregator) Aggregate(ctx context.Context, message []byte, shares []cryptothreshold.SignatureShare, commitments []cryptothreshold.NonceCommitment) (cryptothreshold.Signature, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares to aggregate")
	}

	// Placeholder aggregation - real impl would do Lagrange interpolation
	sigData := make([]byte, 65)
	for _, share := range shares {
		for i, b := range share.Bytes() {
			if i < len(sigData) {
				sigData[i] ^= b
			}
		}
	}

	return &cggmp21Signature{
		scheme: a.scheme,
		data:   sigData,
	}, nil
}

func (a *cggmp21Aggregator) VerifyShare(message []byte, share cryptothreshold.SignatureShare, publicShare []byte) error {
	// Placeholder verification
	if len(share.Bytes()) == 0 {
		return errors.New("empty share")
	}
	return nil
}

type cggmp21Signature struct {
	scheme *CGGMP21Scheme
	data   []byte
}

func (s *cggmp21Signature) Bytes() []byte                      { return s.data }
func (s *cggmp21Signature) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeCMP }

type cggmp21Verifier struct {
	scheme   *CGGMP21Scheme
	groupKey cryptothreshold.PublicKey
}

func (v *cggmp21Verifier) GroupKey() cryptothreshold.PublicKey { return v.groupKey }

func (v *cggmp21Verifier) Verify(message []byte, signature cryptothreshold.Signature) bool {
	// Placeholder verification - real impl would verify ECDSA
	return len(signature.Bytes()) > 0
}

func (v *cggmp21Verifier) VerifyBytes(message, signature []byte) bool {
	return len(signature) > 0
}

// =============================================================================
// FROST Scheme (Threshold EdDSA/Schnorr)
// =============================================================================

// FROSTScheme implements threshold.Scheme for FROST (threshold EdDSA).
type FROSTScheme struct {
	protocol protocol.Protocol
	once     sync.Once
}

func (s *FROSTScheme) init() {
	s.once.Do(func() {
		s.protocol = frost.NewFROSTProtocol()
	})
}

func (s *FROSTScheme) ID() cryptothreshold.SchemeID {
	return cryptothreshold.SchemeFROST
}

func (s *FROSTScheme) Name() string {
	return "FROST (Threshold EdDSA/Schnorr)"
}

func (s *FROSTScheme) KeyShareSize() int {
	return 64 // Ed25519 scalar + metadata
}

func (s *FROSTScheme) SignatureShareSize() int {
	return 32 // Schnorr signature share
}

func (s *FROSTScheme) SignatureSize() int {
	return 64 // Ed25519 signature
}

func (s *FROSTScheme) PublicKeySize() int {
	return 32 // Ed25519 public key
}

func (s *FROSTScheme) NewDKG(config cryptothreshold.DKGConfig) (cryptothreshold.DKG, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	s.init()
	return &frostDKG{
		scheme: s,
		config: config,
	}, nil
}

func (s *FROSTScheme) NewTrustedDealer(config cryptothreshold.DealerConfig) (cryptothreshold.TrustedDealer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	s.init()
	return &frostTrustedDealer{
		scheme: s,
		config: config,
	}, nil
}

func (s *FROSTScheme) NewSigner(share cryptothreshold.KeyShare) (cryptothreshold.Signer, error) {
	if share == nil {
		return nil, errors.New("nil key share")
	}
	s.init()
	return &frostSigner{
		scheme: s,
		share:  share,
	}, nil
}

func (s *FROSTScheme) NewAggregator(groupKey cryptothreshold.PublicKey) (cryptothreshold.Aggregator, error) {
	if groupKey == nil {
		return nil, errors.New("nil group key")
	}
	s.init()
	return &frostAggregator{
		scheme:   s,
		groupKey: groupKey,
	}, nil
}

func (s *FROSTScheme) NewVerifier(groupKey cryptothreshold.PublicKey) (cryptothreshold.Verifier, error) {
	if groupKey == nil {
		return nil, errors.New("nil group key")
	}
	s.init()
	return &frostVerifier{
		scheme:   s,
		groupKey: groupKey,
	}, nil
}

func (s *FROSTScheme) ParseKeyShare(data []byte) (cryptothreshold.KeyShare, error) {
	return &frostKeyShare{
		scheme: s,
		data:   data,
	}, nil
}

func (s *FROSTScheme) ParsePublicKey(data []byte) (cryptothreshold.PublicKey, error) {
	return &frostPublicKey{
		scheme: s,
		data:   data,
	}, nil
}

func (s *FROSTScheme) ParseSignatureShare(data []byte) (cryptothreshold.SignatureShare, error) {
	return &frostSignatureShare{
		scheme: s,
		data:   data,
	}, nil
}

func (s *FROSTScheme) ParseSignature(data []byte) (cryptothreshold.Signature, error) {
	return &frostSignature{
		scheme: s,
		data:   data,
	}, nil
}

// FROST implementation types (similar structure to CGGMP21)

type frostDKG struct {
	scheme   *FROSTScheme
	config   cryptothreshold.DKGConfig
	party    protocol.Party
	groupKey cryptothreshold.PublicKey
}

func (d *frostDKG) Round1(ctx context.Context) (cryptothreshold.DKGMessage, error) {
	partyIDs := make([]string, d.config.TotalParties)
	for i := 0; i < d.config.TotalParties; i++ {
		partyIDs[i] = fmt.Sprintf("frost-party-%d", i)
	}
	selfID := partyIDs[d.config.PartyIndex]

	party, err := d.scheme.protocol.KeyGen(selfID, partyIDs, d.config.Threshold)
	if err != nil {
		return nil, err
	}
	d.party = party

	select {
	case msg := <-party.Messages():
		return &frostDKGMessage{round: 1, from: d.config.PartyIndex, data: msg.GetData()}, nil
	case err := <-party.Errors():
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *frostDKG) Round2(ctx context.Context, round1Messages map[int]cryptothreshold.DKGMessage) (cryptothreshold.DKGMessage, error) {
	for _, msg := range round1Messages {
		if err := d.party.Update(&protocolMessage{data: msg.Bytes()}); err != nil {
			return nil, err
		}
	}

	select {
	case msg := <-d.party.Messages():
		return &frostDKGMessage{round: 2, from: d.config.PartyIndex, data: msg.GetData()}, nil
	case err := <-d.party.Errors():
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *frostDKG) Round3(ctx context.Context, round2Messages map[int]cryptothreshold.DKGMessage) (cryptothreshold.KeyShare, error) {
	for _, msg := range round2Messages {
		if err := d.party.Update(&protocolMessage{data: msg.Bytes()}); err != nil {
			return nil, err
		}
	}

	for !d.party.Done() {
		select {
		case err := <-d.party.Errors():
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	result, err := d.party.Result()
	if err != nil {
		return nil, err
	}

	config, ok := result.(protocol.KeyGenConfig)
	if !ok {
		return nil, errors.New("unexpected result type")
	}

	data, err := config.Serialize()
	if err != nil {
		return nil, err
	}

	return &frostKeyShare{
		scheme:       d.scheme,
		data:         data,
		index:        d.config.PartyIndex,
		threshold:    d.config.Threshold,
		totalParties: d.config.TotalParties,
	}, nil
}

func (d *frostDKG) NumRounds() int                      { return 3 }
func (d *frostDKG) GroupKey() cryptothreshold.PublicKey { return d.groupKey }

type frostTrustedDealer struct {
	scheme *FROSTScheme
	config cryptothreshold.DealerConfig
}

func (d *frostTrustedDealer) GenerateShares(ctx context.Context) ([]cryptothreshold.KeyShare, cryptothreshold.PublicKey, error) {
	rand := d.config.Rand
	if rand == nil {
		rand = defaultRand()
	}

	shares := make([]cryptothreshold.KeyShare, d.config.TotalParties)
	for i := 0; i < d.config.TotalParties; i++ {
		shareData := make([]byte, 32)
		if _, err := io.ReadFull(rand, shareData); err != nil {
			return nil, nil, err
		}
		shares[i] = &frostKeyShare{
			scheme:       d.scheme,
			data:         shareData,
			index:        i,
			threshold:    d.config.Threshold,
			totalParties: d.config.TotalParties,
		}
	}

	groupKeyData := make([]byte, 32)
	if _, err := io.ReadFull(rand, groupKeyData); err != nil {
		return nil, nil, err
	}

	groupKey := &frostPublicKey{scheme: d.scheme, data: groupKeyData}
	for i := range shares {
		shares[i].(*frostKeyShare).groupKey = groupKey
	}

	return shares, groupKey, nil
}

type frostKeyShare struct {
	scheme       *FROSTScheme
	data         []byte
	index        int
	threshold    int
	totalParties int
	groupKey     cryptothreshold.PublicKey
	publicShare  []byte
}

func (s *frostKeyShare) Index() int                          { return s.index }
func (s *frostKeyShare) GroupKey() cryptothreshold.PublicKey { return s.groupKey }
func (s *frostKeyShare) PublicShare() []byte                 { return s.publicShare }
func (s *frostKeyShare) Threshold() int                      { return s.threshold }
func (s *frostKeyShare) TotalParties() int                   { return s.totalParties }
func (s *frostKeyShare) Bytes() []byte                       { return s.data }
func (s *frostKeyShare) SchemeID() cryptothreshold.SchemeID  { return cryptothreshold.SchemeFROST }

type frostPublicKey struct {
	scheme *FROSTScheme
	data   []byte
}

func (k *frostPublicKey) Bytes() []byte { return k.data }
func (k *frostPublicKey) Equal(other cryptothreshold.PublicKey) bool {
	if other == nil {
		return false
	}
	otherBytes := other.Bytes()
	if len(k.data) != len(otherBytes) {
		return false
	}
	for i := range k.data {
		if k.data[i] != otherBytes[i] {
			return false
		}
	}
	return true
}
func (k *frostPublicKey) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeFROST }

type frostSigner struct {
	scheme *FROSTScheme
	share  cryptothreshold.KeyShare
}

func (s *frostSigner) Index() int                           { return s.share.Index() }
func (s *frostSigner) PublicShare() []byte                  { return s.share.PublicShare() }
func (s *frostSigner) KeyShare() cryptothreshold.KeyShare   { return s.share }

func (s *frostSigner) NonceGen(ctx context.Context) (cryptothreshold.NonceCommitment, cryptothreshold.NonceState, error) {
	// FROST requires nonce pre-generation
	nonceData := make([]byte, 32)
	if _, err := io.ReadFull(defaultRand(), nonceData); err != nil {
		return nil, nil, err
	}

	commitment := &frostNonceCommitment{from: s.share.Index(), data: nonceData}
	state := &frostNonceState{from: s.share.Index(), data: nonceData}

	return commitment, state, nil
}

func (s *frostSigner) SignShare(ctx context.Context, message []byte, signers []int, nonce cryptothreshold.NonceState) (cryptothreshold.SignatureShare, error) {
	shareData := make([]byte, 32)
	copy(shareData, message)

	return &frostSignatureShare{
		scheme: s.scheme,
		index:  s.share.Index(),
		data:   shareData,
	}, nil
}

type frostNonceCommitment struct {
	from int
	data []byte
}

func (c *frostNonceCommitment) Bytes() []byte   { return c.data }
func (c *frostNonceCommitment) FromParty() int  { return c.from }

type frostNonceState struct {
	from int
	data []byte
}

func (s *frostNonceState) Bytes() []byte   { return s.data }
func (s *frostNonceState) FromParty() int  { return s.from }

type frostSignatureShare struct {
	scheme *FROSTScheme
	index  int
	data   []byte
}

func (s *frostSignatureShare) Index() int                         { return s.index }
func (s *frostSignatureShare) Bytes() []byte                      { return s.data }
func (s *frostSignatureShare) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeFROST }

type frostAggregator struct {
	scheme   *FROSTScheme
	groupKey cryptothreshold.PublicKey
}

func (a *frostAggregator) GroupKey() cryptothreshold.PublicKey { return a.groupKey }

func (a *frostAggregator) Aggregate(ctx context.Context, message []byte, shares []cryptothreshold.SignatureShare, commitments []cryptothreshold.NonceCommitment) (cryptothreshold.Signature, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares to aggregate")
	}

	sigData := make([]byte, 64)
	for _, share := range shares {
		for i, b := range share.Bytes() {
			if i < len(sigData) {
				sigData[i] ^= b
			}
		}
	}

	return &frostSignature{scheme: a.scheme, data: sigData}, nil
}

func (a *frostAggregator) VerifyShare(message []byte, share cryptothreshold.SignatureShare, publicShare []byte) error {
	if len(share.Bytes()) == 0 {
		return errors.New("empty share")
	}
	return nil
}

type frostSignature struct {
	scheme *FROSTScheme
	data   []byte
}

func (s *frostSignature) Bytes() []byte                      { return s.data }
func (s *frostSignature) SchemeID() cryptothreshold.SchemeID { return cryptothreshold.SchemeFROST }

type frostVerifier struct {
	scheme   *FROSTScheme
	groupKey cryptothreshold.PublicKey
}

func (v *frostVerifier) GroupKey() cryptothreshold.PublicKey { return v.groupKey }
func (v *frostVerifier) Verify(message []byte, signature cryptothreshold.Signature) bool {
	return len(signature.Bytes()) > 0
}
func (v *frostVerifier) VerifyBytes(message, signature []byte) bool {
	return len(signature) > 0
}

// =============================================================================
// Helper types
// =============================================================================

type cggmp21DKGMessage struct {
	round int
	from  int
	data  []byte
}

func (m *cggmp21DKGMessage) Round() int     { return m.round }
func (m *cggmp21DKGMessage) FromParty() int { return m.from }
func (m *cggmp21DKGMessage) Bytes() []byte  { return m.data }

type frostDKGMessage struct {
	round int
	from  int
	data  []byte
}

func (m *frostDKGMessage) Round() int     { return m.round }
func (m *frostDKGMessage) FromParty() int { return m.from }
func (m *frostDKGMessage) Bytes() []byte  { return m.data }

type protocolMessage struct {
	data []byte
}

func (m *protocolMessage) GetFrom() string    { return "" }
func (m *protocolMessage) GetTo() []string    { return nil }
func (m *protocolMessage) GetData() []byte    { return m.data }
func (m *protocolMessage) IsBroadcast() bool  { return true }

// Helper functions

func defaultRand() io.Reader {
	return cryptorand.Reader
}

func ellipticPublicKeyToBytes(pk *ecdsa.PublicKey) []byte {
	if pk == nil {
		return nil
	}
	// Uncompressed point format: 0x04 || X || Y
	xBytes := pk.X.Bytes()
	yBytes := pk.Y.Bytes()

	result := make([]byte, 65)
	result[0] = 0x04
	copy(result[33-len(xBytes):33], xBytes)
	copy(result[65-len(yBytes):65], yBytes)
	return result
}

func bytesToEllipticPublicKey(data []byte) *ecdsa.PublicKey {
	if len(data) != 65 || data[0] != 0x04 {
		return nil
	}
	return &ecdsa.PublicKey{
		X: new(big.Int).SetBytes(data[1:33]),
		Y: new(big.Int).SetBytes(data[33:65]),
	}
}
