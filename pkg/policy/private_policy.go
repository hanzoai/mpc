// Package policy provides TFHE-powered private policy evaluation.
// Rules can be evaluated on encrypted transaction data without revealing
// amounts, addresses, or other sensitive information.
package policy

import (
	"context"
	"fmt"
	"math/big"
)

// ============================================================
// FHE INTERFACE - Abstract FHE operations
// ============================================================

// FHEEngine provides homomorphic encryption operations.
// This interface abstracts the underlying FHE implementation (luxfi/fhe).
type FHEEngine interface {
	// Encryption
	Encrypt64(value uint64) EncryptedValue
	EncryptBool(value bool) EncryptedValue

	// Homomorphic comparisons (return encrypted bool)
	Lt64(a, b EncryptedValue) EncryptedValue
	Gt64(a, b EncryptedValue) EncryptedValue
	Lte64(a, b EncryptedValue) EncryptedValue
	Gte64(a, b EncryptedValue) EncryptedValue
	Eq64(a, b EncryptedValue) EncryptedValue

	// Homomorphic arithmetic
	Add64(a, b EncryptedValue) EncryptedValue
	Sub64(a, b EncryptedValue) EncryptedValue

	// Homomorphic boolean
	And(a, b EncryptedValue) EncryptedValue
	Or(a, b EncryptedValue) EncryptedValue
	Not(a EncryptedValue) EncryptedValue

	// Serialization
	Serialize(v EncryptedValue) []byte
	Deserialize(data []byte) (EncryptedValue, error)
}

// EncryptedValue represents an FHE-encrypted value.
type EncryptedValue interface {
	// Bytes returns the serialized ciphertext
	Bytes() []byte
}

// ============================================================
// PRIVATE POLICY ENGINE (TFHE-POWERED)
// ============================================================

// PrivatePolicyEngine evaluates policies on encrypted data using FHE.
type PrivatePolicyEngine struct {
	fhe   FHEEngine
	rules []PrivateRule
}

// PrivateRule is a policy rule that operates on encrypted data.
type PrivateRule struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Priority    int                   `json:"priority"`
	Conditions  []PrivateCondition    `json:"conditions"`
	Action      RuleAction            `json:"action"`
	Enabled     bool                  `json:"enabled"`
}

// PrivateCondition is a condition that can be evaluated on encrypted data.
type PrivateCondition struct {
	Type     PrivateConditionType `json:"type"`
	Operator Operator             `json:"operator"`
	// EncryptedValue is the threshold/comparison value (encrypted)
	EncryptedValue EncryptedValue `json:"-"`
	// SerializedValue for persistence
	SerializedValue []byte `json:"serialized_value"`
	// ClearValue is used for non-sensitive comparisons (optional)
	ClearValue interface{} `json:"clear_value,omitempty"`
}

// PrivateConditionType defines types of private conditions.
type PrivateConditionType string

const (
	// Amount comparisons on encrypted values
	PrivateConditionAmount PrivateConditionType = "private_amount"
	// Range checks (is amount within [min, max])
	PrivateConditionAmountRange PrivateConditionType = "private_amount_range"
	// Cumulative spending limits (encrypted running total)
	PrivateConditionCumulative PrivateConditionType = "private_cumulative"
	// Address matching on encrypted addresses
	PrivateConditionAddress PrivateConditionType = "private_address"
	// Encrypted whitelist membership
	PrivateConditionWhitelist PrivateConditionType = "private_whitelist"
)

// EncryptedTransaction contains encrypted transaction fields.
type EncryptedTransaction struct {
	ID              string         `json:"id"`
	WalletID        string         `json:"wallet_id"`
	InitiatorID     string         `json:"initiator_id"`
	Chain           string         `json:"chain"`              // Clear (non-sensitive)
	Asset           string         `json:"asset"`              // Clear (non-sensitive)
	EncryptedAmount EncryptedValue `json:"-"`                  // FHE encrypted
	EncryptedDest   EncryptedValue `json:"-"`                  // FHE encrypted
	EncryptedSource EncryptedValue `json:"-"`                  // FHE encrypted
	// Serialized forms for persistence
	SerializedAmount []byte `json:"encrypted_amount"`
	SerializedDest   []byte `json:"encrypted_dest"`
	SerializedSource []byte `json:"encrypted_source"`
}

// EncryptedPolicyResult is the result of private policy evaluation.
type EncryptedPolicyResult struct {
	// EncryptedAllowed is an encrypted boolean (1 = allowed, 0 = denied)
	EncryptedAllowed EncryptedValue `json:"-"`
	SerializedAllowed []byte        `json:"encrypted_allowed"`
	// MatchedRules are the rules that were evaluated (clear, for audit)
	MatchedRules []string `json:"matched_rules"`
	// DecryptedResult is populated after threshold decryption
	DecryptedResult *PolicyResult `json:"decrypted_result,omitempty"`
}

// NewPrivatePolicyEngine creates a new FHE-powered policy engine.
func NewPrivatePolicyEngine(fhe FHEEngine) *PrivatePolicyEngine {
	return &PrivatePolicyEngine{
		fhe:   fhe,
		rules: make([]PrivateRule, 0),
	}
}

// AddRule adds a private rule.
func (e *PrivatePolicyEngine) AddRule(rule PrivateRule) {
	e.rules = append(e.rules, rule)
}

// EncryptAmount encrypts an amount for private evaluation.
func (e *PrivatePolicyEngine) EncryptAmount(amount *big.Int) (EncryptedValue, error) {
	if e.fhe == nil {
		return nil, fmt.Errorf("FHE engine not set")
	}
	// Convert amount to uint64 (may lose precision for very large amounts)
	return e.fhe.Encrypt64(amount.Uint64()), nil
}

// EncryptAddress encrypts an address for private evaluation.
func (e *PrivatePolicyEngine) EncryptAddress(address string) (EncryptedValue, error) {
	if e.fhe == nil {
		return nil, fmt.Errorf("FHE engine not set")
	}
	// Hash address to 64-bit value for encryption
	hash := hashAddress(address)
	return e.fhe.Encrypt64(hash), nil
}

// EvaluatePrivate evaluates policies on encrypted transaction data.
// Returns an encrypted result that must be threshold-decrypted.
func (e *PrivatePolicyEngine) EvaluatePrivate(ctx context.Context, tx *EncryptedTransaction) (*EncryptedPolicyResult, error) {
	if e.fhe == nil {
		return nil, fmt.Errorf("FHE engine not set")
	}

	result := &EncryptedPolicyResult{
		MatchedRules: make([]string, 0),
	}

	// Start with "allowed" = true (encrypted 1)
	encryptedAllowed := e.fhe.EncryptBool(true)

	// Evaluate each rule homomorphically
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		// Evaluate conditions homomorphically
		ruleMatches, err := e.evaluatePrivateConditions(rule.Conditions, tx)
		if err != nil {
			continue // Skip rule on error
		}

		// If rule matches and action is DENY, set allowed to 0
		if rule.Action == ActionDeny {
			// Homomorphic: allowed = allowed AND NOT(ruleMatches)
			notMatches := e.fhe.Not(ruleMatches)
			encryptedAllowed = e.fhe.And(encryptedAllowed, notMatches)
		}

		// Track matched rules (clear, for audit)
		result.MatchedRules = append(result.MatchedRules, rule.ID)
	}

	result.EncryptedAllowed = encryptedAllowed
	result.SerializedAllowed = e.fhe.Serialize(encryptedAllowed)
	return result, nil
}

// evaluatePrivateConditions evaluates conditions homomorphically.
func (e *PrivatePolicyEngine) evaluatePrivateConditions(
	conditions []PrivateCondition,
	tx *EncryptedTransaction,
) (EncryptedValue, error) {
	// Start with true
	result := e.fhe.EncryptBool(true)

	for _, cond := range conditions {
		var condResult EncryptedValue
		var err error

		switch cond.Type {
		case PrivateConditionAmount:
			condResult, err = e.evaluatePrivateAmountCondition(cond, tx.EncryptedAmount)
		case PrivateConditionAmountRange:
			condResult, err = e.evaluatePrivateRangeCondition(cond, tx.EncryptedAmount)
		default:
			continue // Skip unsupported condition types
		}

		if err != nil {
			return nil, err
		}

		// AND all conditions together
		result = e.fhe.And(result, condResult)
	}

	return result, nil
}

// evaluatePrivateAmountCondition evaluates amount comparison homomorphically.
func (e *PrivatePolicyEngine) evaluatePrivateAmountCondition(
	cond PrivateCondition,
	encryptedAmount EncryptedValue,
) (EncryptedValue, error) {
	threshold := cond.EncryptedValue

	switch cond.Operator {
	case OpGreaterThan:
		return e.fhe.Gt64(encryptedAmount, threshold), nil
	case OpLessThan:
		return e.fhe.Lt64(encryptedAmount, threshold), nil
	case OpGreaterOrEqual:
		return e.fhe.Gte64(encryptedAmount, threshold), nil
	case OpLessOrEqual:
		return e.fhe.Lte64(encryptedAmount, threshold), nil
	case OpEquals:
		return e.fhe.Eq64(encryptedAmount, threshold), nil
	default:
		return nil, fmt.Errorf("unsupported operator for private amount: %s", cond.Operator)
	}
}

// evaluatePrivateRangeCondition checks if amount is in [min, max] range.
func (e *PrivatePolicyEngine) evaluatePrivateRangeCondition(
	cond PrivateCondition,
	encryptedAmount EncryptedValue,
) (EncryptedValue, error) {
	// Range is encoded in ClearValue for simplicity
	rangeVal, ok := cond.ClearValue.([]interface{})
	if !ok || len(rangeVal) != 2 {
		return nil, fmt.Errorf("invalid range value")
	}

	minVal := uint64(rangeVal[0].(float64))
	maxVal := uint64(rangeVal[1].(float64))

	// Encrypt bounds
	minCt := e.fhe.Encrypt64(minVal)
	maxCt := e.fhe.Encrypt64(maxVal)

	// Check: amount >= min AND amount <= max
	gteMin := e.fhe.Gte64(encryptedAmount, minCt)
	lteMax := e.fhe.Lte64(encryptedAmount, maxCt)

	return e.fhe.And(gteMin, lteMax), nil
}

// ============================================================
// PRIVATE WHITELIST
// ============================================================

// PrivateWhitelist manages an encrypted whitelist of addresses.
type PrivateWhitelist struct {
	fhe     FHEEngine
	entries []EncryptedValue
}

// NewPrivateWhitelist creates a new private whitelist.
func NewPrivateWhitelist(fhe FHEEngine) *PrivateWhitelist {
	return &PrivateWhitelist{
		fhe:     fhe,
		entries: make([]EncryptedValue, 0),
	}
}

// AddAddress adds an address to the whitelist (encrypted).
func (w *PrivateWhitelist) AddAddress(address string) error {
	hash := hashAddress(address)
	encrypted := w.fhe.Encrypt64(hash)
	w.entries = append(w.entries, encrypted)
	return nil
}

// Contains checks if an encrypted address is in the whitelist.
// Returns an encrypted boolean.
func (w *PrivateWhitelist) Contains(encryptedAddress EncryptedValue) EncryptedValue {
	// Start with false
	result := w.fhe.EncryptBool(false)

	// Check against each entry: result = result OR (addr == entry)
	for _, entry := range w.entries {
		matches := w.fhe.Eq64(encryptedAddress, entry)
		result = w.fhe.Or(result, matches)
	}

	return result
}

// ============================================================
// PRIVATE SPENDING TRACKER
// ============================================================

// PrivateSpendingTracker tracks cumulative spending using encrypted state.
type PrivateSpendingTracker struct {
	fhe           FHEEngine
	dailyTotals   map[string]EncryptedValue
	monthlyTotals map[string]EncryptedValue
}

// NewPrivateSpendingTracker creates a new private spending tracker.
func NewPrivateSpendingTracker(fhe FHEEngine) *PrivateSpendingTracker {
	return &PrivateSpendingTracker{
		fhe:           fhe,
		dailyTotals:   make(map[string]EncryptedValue),
		monthlyTotals: make(map[string]EncryptedValue),
	}
}

// AddSpend adds an encrypted spend amount to the running totals.
func (t *PrivateSpendingTracker) AddSpend(walletID, asset string, encryptedAmount EncryptedValue) {
	key := walletID + ":" + asset

	// Update daily total
	if _, ok := t.dailyTotals[key]; !ok {
		t.dailyTotals[key] = t.fhe.Encrypt64(0)
	}
	t.dailyTotals[key] = t.fhe.Add64(t.dailyTotals[key], encryptedAmount)

	// Update monthly total
	if _, ok := t.monthlyTotals[key]; !ok {
		t.monthlyTotals[key] = t.fhe.Encrypt64(0)
	}
	t.monthlyTotals[key] = t.fhe.Add64(t.monthlyTotals[key], encryptedAmount)
}

// CheckDailyLimit checks if adding amount would exceed the daily limit.
// Returns encrypted bool (true = within limit).
func (t *PrivateSpendingTracker) CheckDailyLimit(
	walletID, asset string,
	encryptedAmount EncryptedValue,
	encryptedLimit EncryptedValue,
) EncryptedValue {
	key := walletID + ":" + asset

	// Get current total or zero
	currentTotal := t.dailyTotals[key]
	if currentTotal == nil {
		currentTotal = t.fhe.Encrypt64(0)
	}

	// newTotal = currentTotal + amount
	newTotal := t.fhe.Add64(currentTotal, encryptedAmount)

	// Check: newTotal <= limit
	return t.fhe.Lte64(newTotal, encryptedLimit)
}

// CheckMonthlyLimit checks if adding amount would exceed the monthly limit.
func (t *PrivateSpendingTracker) CheckMonthlyLimit(
	walletID, asset string,
	encryptedAmount EncryptedValue,
	encryptedLimit EncryptedValue,
) EncryptedValue {
	key := walletID + ":" + asset

	currentTotal := t.monthlyTotals[key]
	if currentTotal == nil {
		currentTotal = t.fhe.Encrypt64(0)
	}

	newTotal := t.fhe.Add64(currentTotal, encryptedAmount)
	return t.fhe.Lte64(newTotal, encryptedLimit)
}

// ResetDaily resets daily totals (call at midnight).
func (t *PrivateSpendingTracker) ResetDaily() {
	t.dailyTotals = make(map[string]EncryptedValue)
}

// ResetMonthly resets monthly totals (call at month start).
func (t *PrivateSpendingTracker) ResetMonthly() {
	t.monthlyTotals = make(map[string]EncryptedValue)
}

// ============================================================
// THRESHOLD DECRYPTION
// ============================================================

// ThresholdDecryptResult performs threshold decryption of an encrypted policy result.
// This requires participation from t-of-n MPC nodes.
func ThresholdDecryptResult(
	ctx context.Context,
	result *EncryptedPolicyResult,
	decryptionShares [][]byte,
	threshold int,
) (*PolicyResult, error) {
	if len(decryptionShares) < threshold {
		return nil, fmt.Errorf("insufficient decryption shares: got %d, need %d",
			len(decryptionShares), threshold)
	}

	// Combine shares to decrypt
	// This would use the FHE threshold decryption protocol
	// For now, return a placeholder

	return &PolicyResult{
		Allowed:      true, // Would be decrypted value
		Action:       ActionAllow,
		MatchedRules: result.MatchedRules,
	}, nil
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

// hashAddress hashes an address to a 64-bit value for FHE operations.
func hashAddress(address string) uint64 {
	// Simple hash for demo - use proper cryptographic hash in production
	var hash uint64
	for i, c := range address {
		hash ^= uint64(c) << (uint(i*7) % 64)
	}
	return hash
}
