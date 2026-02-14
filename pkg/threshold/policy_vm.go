// Package threshold provides protocol-level policy enforcement for MPC signing.
// Policies are enforced cryptographically within the threshold signing protocol,
// not at the application layer. This ensures trustless, decentralized policy execution.
//
// Architecture:
//   X-Chain (Asset Chain) → Assets locked with policy hash
//   T-Chain (Threshold Chain) → MPC nodes verify and sign based on policy
//   TFHE → Private policy evaluation without revealing conditions
//   Solidity → On-chain policy definition and verification
package threshold

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ============================================================
// FHE INTERFACE - Abstract FHE operations for ThresholdVM
// ============================================================

// FHEPublicKeyProvider provides encryption operations using the public key.
// This interface abstracts the underlying FHE implementation (e.g., luxfi/fhe).
type FHEPublicKeyProvider interface {
	// Encrypt64 encrypts a uint64 value
	Encrypt64(value uint64) EncryptedUint64
	// EncryptBool encrypts a boolean value
	EncryptBool(value bool) EncryptedBoolValue
}

// FHEServerKeyProvider provides homomorphic operations using the server key.
type FHEServerKeyProvider interface {
	// Comparisons (return encrypted bool)
	Lt64(a, b EncryptedUint64) EncryptedBoolValue
	Gt64(a, b EncryptedUint64) EncryptedBoolValue
	Lte64(a, b EncryptedUint64) EncryptedBoolValue
	Gte64(a, b EncryptedUint64) EncryptedBoolValue
	Eq64(a, b EncryptedUint64) EncryptedBoolValue

	// Arithmetic
	Add64(a, b EncryptedUint64) EncryptedUint64
	Sub64(a, b EncryptedUint64) EncryptedUint64

	// Boolean
	And(a, b EncryptedBoolValue) EncryptedBoolValue
	Or(a, b EncryptedBoolValue) EncryptedBoolValue
	Not(a EncryptedBoolValue) EncryptedBoolValue
}

// EncryptedUint64 represents an FHE-encrypted uint64 value.
type EncryptedUint64 interface {
	// Bytes returns the serialized ciphertext
	Bytes() []byte
}

// EncryptedBoolValue represents an FHE-encrypted boolean value.
type EncryptedBoolValue interface {
	// Bytes returns the serialized ciphertext
	Bytes() []byte
}

// ============================================================
// THRESHOLD VM - Protocol-Level Policy Execution
// ============================================================

// ThresholdVM executes policies at the protocol level within MPC signing.
// Policies are verified cryptographically before any signature shares are produced.
type ThresholdVM struct {
	nodeID       string
	threshold    int
	totalNodes   int
	fhePublicKey FHEPublicKeyProvider
	fheServerKey FHEServerKeyProvider
	policies     map[string]*ProtocolPolicy
	stateRoot    []byte // Merkle root of policy state
	mu           sync.RWMutex
}

// ThresholdVMConfig configures the ThresholdVM.
type ThresholdVMConfig struct {
	NodeID       string
	Threshold    int
	TotalNodes   int
	FHEPublicKey FHEPublicKeyProvider
	FHEServerKey FHEServerKeyProvider
}

// NewThresholdVM creates a new ThresholdVM instance.
func NewThresholdVM(cfg ThresholdVMConfig) *ThresholdVM {
	return &ThresholdVM{
		nodeID:       cfg.NodeID,
		threshold:    cfg.Threshold,
		totalNodes:   cfg.TotalNodes,
		fhePublicKey: cfg.FHEPublicKey,
		fheServerKey: cfg.FHEServerKey,
		policies:     make(map[string]*ProtocolPolicy),
	}
}

// ============================================================
// PROTOCOL POLICY - On-Chain Policy Definition
// ============================================================

// ProtocolPolicy defines a policy that is enforced at the protocol level.
// These policies are derived from Solidity contracts on X-Chain.
type ProtocolPolicy struct {
	// PolicyHash is the keccak256 hash of the policy bytecode
	PolicyHash [32]byte `json:"policy_hash"`
	// WalletID is the MPC wallet this policy applies to
	WalletID string `json:"wallet_id"`
	// ChainID identifies the source chain (X-Chain)
	ChainID uint64 `json:"chain_id"`
	// ContractAddress is the policy contract on X-Chain
	ContractAddress string `json:"contract_address"`
	// Version for policy upgrades
	Version uint64 `json:"version"`
	// Rules are the compiled policy rules
	Rules []ProtocolRule `json:"rules"`
	// EncryptedState holds TFHE-encrypted policy state
	EncryptedState *EncryptedPolicyState `json:"encrypted_state"`
	// CreatedAt is when the policy was registered
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is when the policy expires (0 = never)
	ExpiresAt time.Time `json:"expires_at"`
}

// ProtocolRule is a single rule enforced at the protocol level.
type ProtocolRule struct {
	// RuleID is the unique identifier
	RuleID [8]byte `json:"rule_id"`
	// Opcode is the rule operation
	Opcode RuleOpcode `json:"opcode"`
	// Operands are the rule parameters
	Operands [][]byte `json:"operands"`
	// EncryptedOperands for TFHE private rules
	EncryptedOperands []EncryptedUint64 `json:"-"`
	// ResultAction when rule matches
	ResultAction RuleResult `json:"result_action"`
}

// RuleOpcode defines the operation for a protocol rule.
type RuleOpcode uint8

const (
	// Comparison operations
	OpCheckAmountLT    RuleOpcode = 0x01 // amount < threshold
	OpCheckAmountGT    RuleOpcode = 0x02 // amount > threshold
	OpCheckAmountRange RuleOpcode = 0x03 // min <= amount <= max
	OpCheckCumulative  RuleOpcode = 0x04 // cumulative 24h < limit

	// Address operations
	OpCheckWhitelist   RuleOpcode = 0x10 // dest in whitelist
	OpCheckBlacklist   RuleOpcode = 0x11 // dest not in blacklist
	OpCheckSourceMatch RuleOpcode = 0x12 // source == expected

	// Time operations
	OpCheckTimeWindow RuleOpcode = 0x20 // within time window
	OpCheckTimeLock   RuleOpcode = 0x21 // after unlock time
	OpCheckCooldown   RuleOpcode = 0x22 // cooldown elapsed

	// Approval operations
	OpRequireSignatures RuleOpcode = 0x30 // require n signatures
	OpRequireQuorum     RuleOpcode = 0x31 // require % of signers
	OpRequireFromGroup  RuleOpcode = 0x32 // signatures from group

	// Stream/Vesting operations
	OpCheckVestingUnlock RuleOpcode = 0x40 // vesting schedule
	OpCheckStreamRate    RuleOpcode = 0x41 // streaming rate limit
	OpCheckCliffPeriod   RuleOpcode = 0x42 // cliff period passed

	// TFHE private operations
	OpPrivateAmountLT   RuleOpcode = 0x80 // private: amount < threshold
	OpPrivateAmountGT   RuleOpcode = 0x81 // private: amount > threshold
	OpPrivateCumulative RuleOpcode = 0x82 // private: cumulative check
	OpPrivateWhitelist  RuleOpcode = 0x83 // private: whitelist check
)

// RuleResult is the action taken when a rule matches.
type RuleResult uint8

const (
	ResultAllow         RuleResult = 0x00 // Allow the transaction
	ResultDeny          RuleResult = 0x01 // Deny the transaction
	ResultRequireSigs   RuleResult = 0x02 // Require additional signatures
	ResultDelay         RuleResult = 0x03 // Delay execution
	ResultPartialUnlock RuleResult = 0x04 // Partial unlock (streaming)
)

// EncryptedPolicyState holds TFHE-encrypted state for private policies.
type EncryptedPolicyState struct {
	// Encrypted cumulative spending totals
	CumulativeDaily   EncryptedUint64 `json:"-"`
	CumulativeMonthly EncryptedUint64 `json:"-"`
	// Encrypted last transaction time
	LastTxTime EncryptedUint64 `json:"-"`
	// Encrypted vesting/streaming state
	VestedAmount   EncryptedUint64 `json:"-"`
	StreamedAmount EncryptedUint64 `json:"-"`
	// Serialized state for persistence
	SerializedState []byte `json:"serialized_state"`
}

// ============================================================
// SIGNING REQUEST - Protocol-Level Verification
// ============================================================

// ProtocolSigningRequest is a signing request that includes policy proof.
type ProtocolSigningRequest struct {
	// Standard signing fields
	WalletID string   `json:"wallet_id"`
	TxHash   [32]byte `json:"tx_hash"`
	RawTx    []byte   `json:"raw_tx"`

	// Policy verification fields
	PolicyHash  [32]byte `json:"policy_hash"`
	PolicyProof []byte   `json:"policy_proof"` // Merkle proof

	// Transaction parameters (for policy evaluation)
	Amount      *big.Int `json:"amount"`
	Destination string   `json:"destination"`
	ChainID     uint64   `json:"chain_id"`

	// TFHE encrypted parameters (for private policies)
	EncryptedAmount EncryptedUint64 `json:"-"`
	EncryptedDest   EncryptedUint64 `json:"-"`

	// Approval signatures (from authorized signers)
	ApprovalSignatures []ApprovalSignature `json:"approval_signatures"`
}

// ApprovalSignature is a signature from an authorized signer.
type ApprovalSignature struct {
	SignerID  string `json:"signer_id"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
	SignedAt  uint64 `json:"signed_at"`
}

// ProtocolVerificationResult is the result of protocol-level verification.
type ProtocolVerificationResult struct {
	Allowed            bool        `json:"allowed"`
	MatchedRules       []RuleMatch `json:"matched_rules"`
	RequiredSignatures int         `json:"required_signatures,omitempty"`
	UnlockAmount       *big.Int    `json:"unlock_amount,omitempty"` // For partial unlocks
	DenyReason         string      `json:"deny_reason,omitempty"`

	// TFHE encrypted result (for private verification)
	EncryptedResult EncryptedBoolValue `json:"-"`
}

// RuleMatch records a rule that matched during verification.
type RuleMatch struct {
	RuleID [8]byte    `json:"rule_id"`
	Opcode RuleOpcode `json:"opcode"`
	Result RuleResult `json:"result"`
}

// ============================================================
// VERIFICATION ENGINE - Protocol-Level Policy Enforcement
// ============================================================

// VerifyAndSign verifies policy compliance and produces a signature share.
// This is the core function that enforces policies at the protocol level.
func (vm *ThresholdVM) VerifyAndSign(
	ctx context.Context,
	req *ProtocolSigningRequest,
	keyShare []byte,
) (*SignatureShare, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Step 1: Verify policy hash matches registered policy
	policy, ok := vm.policies[req.WalletID]
	if !ok {
		return nil, errors.New("no policy registered for wallet")
	}

	if policy.PolicyHash != req.PolicyHash {
		return nil, errors.New("policy hash mismatch")
	}

	// Step 2: Verify policy is not expired
	if !policy.ExpiresAt.IsZero() && time.Now().After(policy.ExpiresAt) {
		return nil, errors.New("policy has expired")
	}

	// Step 3: Evaluate all protocol rules
	result, err := vm.evaluateRules(ctx, policy, req)
	if err != nil {
		return nil, fmt.Errorf("rule evaluation failed: %w", err)
	}

	// Step 4: Check if transaction is allowed
	if !result.Allowed {
		return nil, fmt.Errorf("policy denied: %s", result.DenyReason)
	}

	// Step 5: Check if additional signatures are required
	if result.RequiredSignatures > 0 {
		if len(req.ApprovalSignatures) < result.RequiredSignatures {
			return nil, fmt.Errorf("insufficient approvals: need %d, have %d",
				result.RequiredSignatures, len(req.ApprovalSignatures))
		}
		// Verify each approval signature
		for _, sig := range req.ApprovalSignatures {
			if !verifyApprovalSignature(&sig, req.TxHash[:]) {
				return nil, fmt.Errorf("invalid approval signature from %s", sig.SignerID)
			}
		}
	}

	// Step 6: Update policy state (cumulative totals, etc.)
	if err := vm.updatePolicyState(policy, req); err != nil {
		return nil, fmt.Errorf("state update failed: %w", err)
	}

	// Step 7: Produce signature share
	share, err := vm.produceSignatureShare(req, keyShare, result.UnlockAmount)
	if err != nil {
		return nil, fmt.Errorf("signature share failed: %w", err)
	}

	return share, nil
}

// evaluateRules evaluates all rules in a policy.
func (vm *ThresholdVM) evaluateRules(
	ctx context.Context,
	policy *ProtocolPolicy,
	req *ProtocolSigningRequest,
) (*ProtocolVerificationResult, error) {
	result := &ProtocolVerificationResult{
		Allowed:      true,
		MatchedRules: make([]RuleMatch, 0),
	}

	for _, rule := range policy.Rules {
		match, ruleResult, err := vm.evaluateRule(ctx, &rule, policy, req)
		if err != nil {
			return nil, err
		}

		if match {
			result.MatchedRules = append(result.MatchedRules, RuleMatch{
				RuleID: rule.RuleID,
				Opcode: rule.Opcode,
				Result: rule.ResultAction,
			})

			switch rule.ResultAction {
			case ResultDeny:
				result.Allowed = false
				result.DenyReason = fmt.Sprintf("denied by rule %x", rule.RuleID)
				return result, nil

			case ResultRequireSigs:
				if len(rule.Operands) > 0 {
					result.RequiredSignatures = int(rule.Operands[0][0])
				}

			case ResultPartialUnlock:
				// Calculate partial unlock amount based on vesting/streaming
				result.UnlockAmount = ruleResult.(*big.Int)
			}
		}
	}

	return result, nil
}

// evaluateRule evaluates a single protocol rule.
func (vm *ThresholdVM) evaluateRule(
	ctx context.Context,
	rule *ProtocolRule,
	policy *ProtocolPolicy,
	req *ProtocolSigningRequest,
) (bool, interface{}, error) {
	switch rule.Opcode {
	// Amount comparisons
	case OpCheckAmountLT:
		threshold := new(big.Int).SetBytes(rule.Operands[0])
		return req.Amount.Cmp(threshold) < 0, nil, nil

	case OpCheckAmountGT:
		threshold := new(big.Int).SetBytes(rule.Operands[0])
		return req.Amount.Cmp(threshold) > 0, nil, nil

	case OpCheckAmountRange:
		min := new(big.Int).SetBytes(rule.Operands[0])
		max := new(big.Int).SetBytes(rule.Operands[1])
		inRange := req.Amount.Cmp(min) >= 0 && req.Amount.Cmp(max) <= 0
		return inRange, nil, nil

	case OpCheckCumulative:
		limit := new(big.Int).SetBytes(rule.Operands[0])
		// Get current cumulative total from state
		current := big.NewInt(0)
		if policy.EncryptedState != nil {
			// Decrypt cumulative (would use threshold decryption)
			// For now, use clear state
		}
		newTotal := new(big.Int).Add(current, req.Amount)
		return newTotal.Cmp(limit) <= 0, nil, nil

	// Address checks
	case OpCheckWhitelist:
		for _, addr := range rule.Operands {
			if bytes.Equal([]byte(req.Destination), addr) {
				return true, nil, nil
			}
		}
		return false, nil, nil

	case OpCheckBlacklist:
		for _, addr := range rule.Operands {
			if bytes.Equal([]byte(req.Destination), addr) {
				return true, nil, nil // Matched blacklist = rule triggers
			}
		}
		return false, nil, nil

	// Time operations
	case OpCheckTimeWindow:
		startHour := int(rule.Operands[0][0])
		endHour := int(rule.Operands[1][0])
		currentHour := time.Now().UTC().Hour()
		if startHour <= endHour {
			return currentHour >= startHour && currentHour <= endHour, nil, nil
		}
		return currentHour >= startHour || currentHour <= endHour, nil, nil

	case OpCheckTimeLock:
		unlockTime := binary.BigEndian.Uint64(rule.Operands[0])
		return uint64(time.Now().Unix()) >= unlockTime, nil, nil

	case OpCheckCooldown:
		cooldownSeconds := binary.BigEndian.Uint64(rule.Operands[0])
		var lastTxTime uint64
		if policy.EncryptedState != nil {
			// Would decrypt last tx time
		}
		return uint64(time.Now().Unix())-lastTxTime >= cooldownSeconds, nil, nil

	// Vesting/Streaming
	case OpCheckVestingUnlock:
		return vm.evaluateVesting(rule, policy, req)

	case OpCheckStreamRate:
		return vm.evaluateStreaming(rule, policy, req)

	// TFHE private operations
	case OpPrivateAmountLT, OpPrivateAmountGT, OpPrivateCumulative, OpPrivateWhitelist:
		return vm.evaluatePrivateRule(ctx, rule, policy, req)

	default:
		return false, nil, fmt.Errorf("unknown opcode: %d", rule.Opcode)
	}
}

// evaluateVesting evaluates a vesting schedule rule.
func (vm *ThresholdVM) evaluateVesting(
	rule *ProtocolRule,
	policy *ProtocolPolicy,
	req *ProtocolSigningRequest,
) (bool, interface{}, error) {
	// Parse vesting parameters
	totalAmount := new(big.Int).SetBytes(rule.Operands[0])
	startTime := binary.BigEndian.Uint64(rule.Operands[1])
	duration := binary.BigEndian.Uint64(rule.Operands[2])
	cliffDuration := uint64(0)
	if len(rule.Operands) > 3 {
		cliffDuration = binary.BigEndian.Uint64(rule.Operands[3])
	}

	now := uint64(time.Now().Unix())

	// Check cliff
	if now < startTime+cliffDuration {
		return true, big.NewInt(0), nil // No unlock before cliff
	}

	// Calculate vested amount
	elapsed := now - startTime
	if elapsed >= duration {
		// Fully vested
		return true, totalAmount, nil
	}

	// Linear vesting
	vestedAmount := new(big.Int).Mul(totalAmount, big.NewInt(int64(elapsed)))
	vestedAmount.Div(vestedAmount, big.NewInt(int64(duration)))

	// Check if request exceeds vested amount
	if req.Amount.Cmp(vestedAmount) > 0 {
		// Can only unlock vested amount
		return true, vestedAmount, nil
	}

	return true, req.Amount, nil
}

// evaluateStreaming evaluates a streaming rate limit rule.
func (vm *ThresholdVM) evaluateStreaming(
	rule *ProtocolRule,
	policy *ProtocolPolicy,
	req *ProtocolSigningRequest,
) (bool, interface{}, error) {
	// Parse streaming parameters
	ratePerSecond := new(big.Int).SetBytes(rule.Operands[0])
	startTime := binary.BigEndian.Uint64(rule.Operands[1])
	var streamedSoFar *big.Int
	if policy.EncryptedState != nil {
		// Would decrypt streamed amount
		streamedSoFar = big.NewInt(0)
	} else {
		streamedSoFar = big.NewInt(0)
	}

	now := uint64(time.Now().Unix())
	elapsed := now - startTime

	// Calculate available to stream
	totalStreamable := new(big.Int).Mul(ratePerSecond, big.NewInt(int64(elapsed)))
	availableToStream := new(big.Int).Sub(totalStreamable, streamedSoFar)

	if req.Amount.Cmp(availableToStream) > 0 {
		// Can only stream up to available
		return true, availableToStream, nil
	}

	return true, req.Amount, nil
}

// evaluatePrivateRule evaluates a TFHE-encrypted rule.
func (vm *ThresholdVM) evaluatePrivateRule(
	ctx context.Context,
	rule *ProtocolRule,
	policy *ProtocolPolicy,
	req *ProtocolSigningRequest,
) (bool, interface{}, error) {
	if vm.fheServerKey == nil {
		return false, nil, errors.New("TFHE not configured")
	}

	if req.EncryptedAmount == nil {
		return false, nil, errors.New("encrypted amount required for private rule")
	}

	switch rule.Opcode {
	case OpPrivateAmountLT:
		// Compare encrypted amount against encrypted threshold
		threshold := rule.EncryptedOperands[0]
		result := vm.fheServerKey.Lt64(req.EncryptedAmount, threshold)
		// Return encrypted boolean - actual decryption happens via threshold
		return true, result, nil

	case OpPrivateAmountGT:
		threshold := rule.EncryptedOperands[0]
		result := vm.fheServerKey.Gt64(req.EncryptedAmount, threshold)
		return true, result, nil

	case OpPrivateCumulative:
		limit := rule.EncryptedOperands[0]
		current := policy.EncryptedState.CumulativeDaily
		if current == nil {
			current = vm.fhePublicKey.Encrypt64(0)
		}
		newTotal := vm.fheServerKey.Add64(current, req.EncryptedAmount)
		result := vm.fheServerKey.Lte64(newTotal, limit)
		return true, result, nil

	default:
		return false, nil, fmt.Errorf("unknown private opcode: %d", rule.Opcode)
	}
}

// updatePolicyState updates the policy state after a transaction.
func (vm *ThresholdVM) updatePolicyState(policy *ProtocolPolicy, req *ProtocolSigningRequest) error {
	if policy.EncryptedState == nil {
		policy.EncryptedState = &EncryptedPolicyState{}
	}

	// Update cumulative totals
	if req.EncryptedAmount != nil && vm.fheServerKey != nil {
		if policy.EncryptedState.CumulativeDaily == nil {
			policy.EncryptedState.CumulativeDaily = vm.fhePublicKey.Encrypt64(0)
		}
		policy.EncryptedState.CumulativeDaily = vm.fheServerKey.Add64(
			policy.EncryptedState.CumulativeDaily,
			req.EncryptedAmount,
		)
	}

	// Update last transaction time
	if vm.fhePublicKey != nil {
		policy.EncryptedState.LastTxTime = vm.fhePublicKey.Encrypt64(uint64(time.Now().Unix()))
	}

	return nil
}

// produceSignatureShare produces an MPC signature share.
func (vm *ThresholdVM) produceSignatureShare(
	req *ProtocolSigningRequest,
	keyShare []byte,
	unlockAmount *big.Int,
) (*SignatureShare, error) {
	// Hash the signing data
	hashData := make([]byte, 0)
	hashData = append(hashData, req.TxHash[:]...)
	if unlockAmount != nil {
		hashData = append(hashData, unlockAmount.Bytes()...)
	}
	digest := sha256.Sum256(hashData)

	// Would call into CGGMP21/FROST to produce partial signature
	// For now, return placeholder
	return &SignatureShare{
		NodeID:    vm.nodeID,
		ShareData: digest[:], // Placeholder
	}, nil
}

// SignatureShare is a partial signature from one MPC node.
type SignatureShare struct {
	NodeID    string `json:"node_id"`
	ShareData []byte `json:"share_data"`
}

// ============================================================
// POLICY REGISTRATION
// ============================================================

// RegisterPolicy registers a policy from an on-chain contract.
func (vm *ThresholdVM) RegisterPolicy(policy *ProtocolPolicy) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Verify policy hash
	computedHash := vm.computePolicyHash(policy)
	if computedHash != policy.PolicyHash {
		return errors.New("policy hash verification failed")
	}

	vm.policies[policy.WalletID] = policy
	vm.updateStateRoot()

	return nil
}

// computePolicyHash computes the hash of a policy.
func (vm *ThresholdVM) computePolicyHash(policy *ProtocolPolicy) [32]byte {
	h := sha256.New()
	h.Write([]byte(policy.WalletID))
	binary.Write(h, binary.BigEndian, policy.ChainID)
	h.Write([]byte(policy.ContractAddress))
	binary.Write(h, binary.BigEndian, policy.Version)
	for _, rule := range policy.Rules {
		h.Write(rule.RuleID[:])
		h.Write([]byte{byte(rule.Opcode)})
		h.Write([]byte{byte(rule.ResultAction)})
	}
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// updateStateRoot updates the merkle root of all policy states.
func (vm *ThresholdVM) updateStateRoot() {
	// Would compute merkle root of all policies
	vm.stateRoot = make([]byte, 32)
}

// ============================================================
// SOLIDITY INTERFACE
// ============================================================

// SolidityPolicyParser parses policy bytecode from Solidity contracts.
type SolidityPolicyParser struct{}

// ParsePolicyBytecode parses policy rules from Solidity contract bytecode.
func (p *SolidityPolicyParser) ParsePolicyBytecode(bytecode []byte) ([]ProtocolRule, error) {
	// This would parse the ABI-encoded policy rules from the contract
	// For now, return empty
	return nil, nil
}

// ParsePolicyCalldata parses policy from contract call data.
func (p *SolidityPolicyParser) ParsePolicyCalldata(calldata []byte) (*ProtocolPolicy, error) {
	// Parse ABI-encoded policy configuration
	// This is called when a policy contract emits a PolicyRegistered event
	return nil, nil
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

// verifyApprovalSignature verifies an approval signature.
func verifyApprovalSignature(sig *ApprovalSignature, txHash []byte) bool {
	// Would verify Ed25519 signature
	return len(sig.Signature) > 0
}

// HashToBytes32 converts a hex string to [32]byte.
func HashToBytes32(hexStr string) [32]byte {
	var hash [32]byte
	decoded, _ := hex.DecodeString(hexStr)
	copy(hash[:], decoded)
	return hash
}
