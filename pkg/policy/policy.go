// Package policy provides transaction governance and access control
// for MPC wallets, similar to Fireblocks and Utila policy engines.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// ============================================================
// CORE TYPES
// ============================================================

// PolicyEngine evaluates transaction policies.
type PolicyEngine struct {
	rules          []Rule
	signers        map[string]*Signer
	walletPolicies map[string]*WalletPolicy
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		rules:          make([]Rule, 0),
		signers:        make(map[string]*Signer),
		walletPolicies: make(map[string]*WalletPolicy),
	}
}

// ============================================================
// SIGNERS - Users who can manage wallets and approve transactions
// ============================================================

// Signer represents a user who can sign/approve transactions.
type Signer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Email       string            `json:"email"`
	PublicKey   string            `json:"public_key"`   // Ed25519 public key for verification
	Role        SignerRole        `json:"role"`
	Groups      []string          `json:"groups"`       // Group memberships
	Permissions []Permission      `json:"permissions"`
	SpendLimits map[string]*Limit `json:"spend_limits"` // Per-asset limits
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Status      SignerStatus      `json:"status"`
}

// SignerRole defines the role of a signer.
type SignerRole string

const (
	RoleOwner     SignerRole = "owner"      // Full control, can add/remove signers
	RoleAdmin     SignerRole = "admin"      // Can manage wallets and approve
	RoleApprover  SignerRole = "approver"   // Can approve transactions
	RoleInitiator SignerRole = "initiator"  // Can create but not approve
	RoleViewer    SignerRole = "viewer"     // Read-only access
)

// SignerStatus is the status of a signer.
type SignerStatus string

const (
	StatusActive    SignerStatus = "active"
	StatusPending   SignerStatus = "pending"   // Awaiting approval
	StatusSuspended SignerStatus = "suspended"
	StatusRevoked   SignerStatus = "revoked"
)

// Permission defines what a signer can do.
type Permission string

const (
	PermCreateTransaction Permission = "create_transaction"
	PermApproveTransaction Permission = "approve_transaction"
	PermRejectTransaction  Permission = "reject_transaction"
	PermViewTransaction    Permission = "view_transaction"
	PermManageWallet       Permission = "manage_wallet"
	PermManageSigners      Permission = "manage_signers"
	PermManagePolicies     Permission = "manage_policies"
	PermViewAuditLog       Permission = "view_audit_log"
	PermExportKeys         Permission = "export_keys"
)

// Limit defines spending limits.
type Limit struct {
	MaxAmount       *big.Int      `json:"max_amount"`       // Max per transaction
	DailyLimit      *big.Int      `json:"daily_limit"`      // Max per day
	MonthlyLimit    *big.Int      `json:"monthly_limit"`    // Max per month
	CooldownPeriod  time.Duration `json:"cooldown_period"`  // Time between transactions
	RequiredSigners int           `json:"required_signers"` // Required approvals above this limit
}

// ============================================================
// WALLET POLICIES
// ============================================================

// WalletPolicy defines the policy for a specific wallet.
type WalletPolicy struct {
	WalletID    string         `json:"wallet_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Rules       []Rule         `json:"rules"`
	Signers     []WalletSigner `json:"signers"`
	Defaults    PolicyDefaults `json:"defaults"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// WalletSigner links a signer to a wallet with specific permissions.
type WalletSigner struct {
	SignerID    string       `json:"signer_id"`
	Permissions []Permission `json:"permissions"`
	Weight      int          `json:"weight"` // For weighted threshold
}

// PolicyDefaults are the default settings for a wallet.
type PolicyDefaults struct {
	RequiredApprovals int           `json:"required_approvals"` // Default approvals needed
	TimeoutDuration   time.Duration `json:"timeout_duration"`   // Auto-reject after timeout
	AutoApproveBelow  *big.Int      `json:"auto_approve_below"` // Auto-approve small amounts
}

// ============================================================
// RULES - Fireblocks/Utila style policy rules
// ============================================================

// Rule defines a policy rule.
type Rule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Priority    int           `json:"priority"` // Lower = higher priority
	Conditions  []Condition   `json:"conditions"`
	Action      RuleAction    `json:"action"`
	Signers     SignerConfig  `json:"signers"`      // Who must approve if action is REQUIRE_APPROVAL
	TimeWindow  *TimeWindow   `json:"time_window"`  // Optional time restrictions
	RateLimits  []RateLimit   `json:"rate_limits"`  // Optional rate limiting
	Enabled     bool          `json:"enabled"`
}

// RuleAction is the action to take when a rule matches.
type RuleAction string

const (
	ActionAllow           RuleAction = "allow"            // Auto-approve
	ActionDeny            RuleAction = "deny"             // Auto-reject
	ActionRequireApproval RuleAction = "require_approval" // Require specified approvals
	ActionNotify          RuleAction = "notify"           // Notify but allow
	ActionDelay           RuleAction = "delay"            // Delay execution
)

// SignerConfig specifies who must approve.
type SignerConfig struct {
	RequiredCount int      `json:"required_count"` // Number of approvals needed
	FromGroups    []string `json:"from_groups"`    // Must be from these groups
	FromSigners   []string `json:"from_signers"`   // Must be from these signers
	ExcludeSigners []string `json:"exclude_signers"` // Cannot be from these signers
	Weighted      bool     `json:"weighted"`       // Use weight-based threshold
	WeightThreshold int    `json:"weight_threshold"` // Required weight if weighted
}

// Condition is a single condition in a rule.
type Condition struct {
	Type     ConditionType `json:"type"`
	Operator Operator      `json:"operator"`
	Value    interface{}   `json:"value"`
}

// ConditionType is the type of condition.
type ConditionType string

const (
	ConditionAmount          ConditionType = "amount"           // Transaction amount
	ConditionAsset           ConditionType = "asset"            // Token/asset type
	ConditionChain           ConditionType = "chain"            // Blockchain network
	ConditionDestination     ConditionType = "destination"      // Recipient address
	ConditionSource          ConditionType = "source"           // Source wallet
	ConditionInitiator       ConditionType = "initiator"        // Who created the tx
	ConditionTimeOfDay       ConditionType = "time_of_day"      // Time-based restrictions
	ConditionDayOfWeek       ConditionType = "day_of_week"      // Day restrictions
	ConditionCountry         ConditionType = "country"          // Geo restrictions
	ConditionContractAddress ConditionType = "contract_address" // Smart contract calls
	ConditionMethodID        ConditionType = "method_id"        // Contract method being called
	ConditionGasLimit        ConditionType = "gas_limit"        // Gas/fee limits
	ConditionCumulative24h   ConditionType = "cumulative_24h"   // 24h cumulative amount
	ConditionCumulative7d    ConditionType = "cumulative_7d"    // 7d cumulative amount
	ConditionWhitelist       ConditionType = "whitelist"        // Address whitelist
	ConditionBlacklist       ConditionType = "blacklist"        // Address blacklist
)

// Operator for condition comparison.
type Operator string

const (
	OpEquals           Operator = "eq"
	OpNotEquals        Operator = "ne"
	OpGreaterThan      Operator = "gt"
	OpLessThan         Operator = "lt"
	OpGreaterOrEqual   Operator = "gte"
	OpLessOrEqual      Operator = "lte"
	OpIn               Operator = "in"
	OpNotIn            Operator = "not_in"
	OpContains         Operator = "contains"
	OpStartsWith       Operator = "starts_with"
	OpEndsWith         Operator = "ends_with"
	OpMatches          Operator = "matches" // Regex
	OpBetween          Operator = "between"
)

// TimeWindow restricts when transactions can be executed.
type TimeWindow struct {
	Timezone   string   `json:"timezone"`    // IANA timezone
	StartHour  int      `json:"start_hour"`  // 0-23
	EndHour    int      `json:"end_hour"`    // 0-23
	AllowedDays []string `json:"allowed_days"` // ["monday", "tuesday", ...]
}

// RateLimit defines rate limiting for transactions.
type RateLimit struct {
	MaxCount   int           `json:"max_count"`   // Max transactions
	MaxAmount  *big.Int      `json:"max_amount"`  // Max total amount
	Window     time.Duration `json:"window"`      // Time window
	PerAsset   bool          `json:"per_asset"`   // Rate limit per asset
	PerAddress bool          `json:"per_address"` // Rate limit per destination
}

// ============================================================
// TRANSACTION REQUEST
// ============================================================

// TransactionRequest represents a transaction to be evaluated.
type TransactionRequest struct {
	ID              string            `json:"id"`
	WalletID        string            `json:"wallet_id"`
	InitiatorID     string            `json:"initiator_id"`
	Chain           string            `json:"chain"`
	Asset           string            `json:"asset"`
	Amount          *big.Int          `json:"amount"`
	Destination     string            `json:"destination"`
	ContractAddress string            `json:"contract_address,omitempty"`
	MethodID        string            `json:"method_id,omitempty"`
	GasLimit        uint64            `json:"gas_limit,omitempty"`
	Metadata        map[string]string `json:"metadata"`
	CreatedAt       time.Time         `json:"created_at"`
}

// PolicyResult is the result of policy evaluation.
type PolicyResult struct {
	Allowed        bool           `json:"allowed"`
	Action         RuleAction     `json:"action"`
	MatchedRules   []string       `json:"matched_rules"`
	RequiredSigners []string      `json:"required_signers,omitempty"`
	RequiredCount  int            `json:"required_count,omitempty"`
	DenyReason     string         `json:"deny_reason,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
	DelayUntil     *time.Time     `json:"delay_until,omitempty"`
}

// ============================================================
// POLICY ENGINE METHODS
// ============================================================

// AddSigner adds a signer to the engine.
func (e *PolicyEngine) AddSigner(signer *Signer) error {
	if signer.ID == "" {
		return fmt.Errorf("signer ID is required")
	}
	signer.CreatedAt = time.Now()
	signer.UpdatedAt = time.Now()
	signer.Status = StatusActive
	e.signers[signer.ID] = signer
	return nil
}

// GetSigner returns a signer by ID.
func (e *PolicyEngine) GetSigner(id string) (*Signer, bool) {
	s, ok := e.signers[id]
	return s, ok
}

// ListSigners returns all signers.
func (e *PolicyEngine) ListSigners() []*Signer {
	signers := make([]*Signer, 0, len(e.signers))
	for _, s := range e.signers {
		signers = append(signers, s)
	}
	return signers
}

// UpdateSigner updates a signer.
func (e *PolicyEngine) UpdateSigner(signer *Signer) error {
	if _, ok := e.signers[signer.ID]; !ok {
		return fmt.Errorf("signer not found: %s", signer.ID)
	}
	signer.UpdatedAt = time.Now()
	e.signers[signer.ID] = signer
	return nil
}

// RemoveSigner removes a signer.
func (e *PolicyEngine) RemoveSigner(id string) error {
	if _, ok := e.signers[id]; !ok {
		return fmt.Errorf("signer not found: %s", id)
	}
	delete(e.signers, id)
	return nil
}

// SetWalletPolicy sets the policy for a wallet.
func (e *PolicyEngine) SetWalletPolicy(policy *WalletPolicy) error {
	if policy.WalletID == "" {
		return fmt.Errorf("wallet ID is required")
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	e.walletPolicies[policy.WalletID] = policy
	return nil
}

// GetWalletPolicy returns the policy for a wallet.
func (e *PolicyEngine) GetWalletPolicy(walletID string) (*WalletPolicy, bool) {
	p, ok := e.walletPolicies[walletID]
	return p, ok
}

// AddRule adds a global rule.
func (e *PolicyEngine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// ============================================================
// POLICY EVALUATION
// ============================================================

// Evaluate evaluates a transaction against all policies.
func (e *PolicyEngine) Evaluate(ctx context.Context, tx *TransactionRequest) (*PolicyResult, error) {
	result := &PolicyResult{
		Allowed:      true,
		Action:       ActionAllow,
		MatchedRules: make([]string, 0),
		Warnings:     make([]string, 0),
	}

	// Get wallet-specific policy
	walletPolicy, hasWalletPolicy := e.walletPolicies[tx.WalletID]

	// Combine global rules with wallet-specific rules
	allRules := make([]Rule, len(e.rules))
	copy(allRules, e.rules)
	if hasWalletPolicy {
		allRules = append(allRules, walletPolicy.Rules...)
	}

	// Sort rules by priority
	sortRulesByPriority(allRules)

	// Evaluate each rule
	for _, rule := range allRules {
		if !rule.Enabled {
			continue
		}

		match, err := e.evaluateRule(ctx, &rule, tx)
		if err != nil {
			return nil, fmt.Errorf("error evaluating rule %s: %w", rule.ID, err)
		}

		if match {
			result.MatchedRules = append(result.MatchedRules, rule.ID)

			switch rule.Action {
			case ActionDeny:
				result.Allowed = false
				result.Action = ActionDeny
				result.DenyReason = fmt.Sprintf("Denied by rule: %s", rule.Name)
				return result, nil

			case ActionRequireApproval:
				result.Action = ActionRequireApproval
				result.RequiredSigners = e.getRequiredSigners(&rule, tx, walletPolicy)
				result.RequiredCount = rule.Signers.RequiredCount

			case ActionDelay:
				if rule.TimeWindow != nil {
					delay := calculateDelay(rule.TimeWindow)
					result.DelayUntil = &delay
				}

			case ActionNotify:
				result.Warnings = append(result.Warnings, fmt.Sprintf("Notification: %s", rule.Name))
			}
		}
	}

	// Apply wallet defaults if no rules required approval
	if hasWalletPolicy && result.Action == ActionAllow && walletPolicy.Defaults.RequiredApprovals > 0 {
		if walletPolicy.Defaults.AutoApproveBelow == nil || tx.Amount.Cmp(walletPolicy.Defaults.AutoApproveBelow) > 0 {
			result.Action = ActionRequireApproval
			result.RequiredCount = walletPolicy.Defaults.RequiredApprovals
			result.RequiredSigners = e.getWalletSigners(walletPolicy)
		}
	}

	return result, nil
}

func (e *PolicyEngine) evaluateRule(ctx context.Context, rule *Rule, tx *TransactionRequest) (bool, error) {
	// Check time window first
	if rule.TimeWindow != nil && !isInTimeWindow(rule.TimeWindow) {
		return false, nil
	}

	// All conditions must match (AND logic)
	for _, cond := range rule.Conditions {
		match, err := e.evaluateCondition(&cond, tx)
		if err != nil {
			return false, err
		}
		if !match {
			return false, nil
		}
	}

	return true, nil
}

func (e *PolicyEngine) evaluateCondition(cond *Condition, tx *TransactionRequest) (bool, error) {
	switch cond.Type {
	case ConditionAmount:
		return compareAmount(tx.Amount, cond.Operator, cond.Value)
	case ConditionAsset:
		return compareString(tx.Asset, cond.Operator, cond.Value)
	case ConditionChain:
		return compareString(tx.Chain, cond.Operator, cond.Value)
	case ConditionDestination:
		return compareString(tx.Destination, cond.Operator, cond.Value)
	case ConditionInitiator:
		return compareString(tx.InitiatorID, cond.Operator, cond.Value)
	case ConditionContractAddress:
		return compareString(tx.ContractAddress, cond.Operator, cond.Value)
	case ConditionWhitelist:
		return isInWhitelist(tx.Destination, cond.Value)
	case ConditionBlacklist:
		return isInBlacklist(tx.Destination, cond.Value)
	default:
		return false, fmt.Errorf("unsupported condition type: %s", cond.Type)
	}
}

func (e *PolicyEngine) getRequiredSigners(rule *Rule, tx *TransactionRequest, walletPolicy *WalletPolicy) []string {
	var signers []string

	if len(rule.Signers.FromSigners) > 0 {
		signers = rule.Signers.FromSigners
	} else if len(rule.Signers.FromGroups) > 0 {
		// Get signers from specified groups
		for _, s := range e.signers {
			for _, group := range rule.Signers.FromGroups {
				if contains(s.Groups, group) {
					signers = append(signers, s.ID)
					break
				}
			}
		}
	} else if walletPolicy != nil {
		// Get signers from wallet policy
		for _, ws := range walletPolicy.Signers {
			if contains(ws.Permissions, PermApproveTransaction) {
				signers = append(signers, ws.SignerID)
			}
		}
	}

	// Exclude specified signers
	if len(rule.Signers.ExcludeSigners) > 0 {
		filtered := make([]string, 0)
		for _, s := range signers {
			if !contains(rule.Signers.ExcludeSigners, s) {
				filtered = append(filtered, s)
			}
		}
		signers = filtered
	}

	// Exclude initiator (can't approve own transactions)
	filtered := make([]string, 0)
	for _, s := range signers {
		if s != tx.InitiatorID {
			filtered = append(filtered, s)
		}
	}

	return filtered
}

func (e *PolicyEngine) getWalletSigners(policy *WalletPolicy) []string {
	signers := make([]string, 0)
	for _, ws := range policy.Signers {
		if contains(ws.Permissions, PermApproveTransaction) {
			signers = append(signers, ws.SignerID)
		}
	}
	return signers
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

func sortRulesByPriority(rules []Rule) {
	// Simple bubble sort (rules are typically few)
	for i := 0; i < len(rules)-1; i++ {
		for j := 0; j < len(rules)-i-1; j++ {
			if rules[j].Priority > rules[j+1].Priority {
				rules[j], rules[j+1] = rules[j+1], rules[j]
			}
		}
	}
}

func compareAmount(amount *big.Int, op Operator, value interface{}) (bool, error) {
	var compareVal *big.Int

	switch v := value.(type) {
	case string:
		compareVal = new(big.Int)
		compareVal.SetString(v, 10)
	case float64:
		compareVal = big.NewInt(int64(v))
	case int64:
		compareVal = big.NewInt(v)
	case *big.Int:
		compareVal = v
	default:
		return false, fmt.Errorf("invalid amount value type: %T", value)
	}

	cmp := amount.Cmp(compareVal)

	switch op {
	case OpEquals:
		return cmp == 0, nil
	case OpNotEquals:
		return cmp != 0, nil
	case OpGreaterThan:
		return cmp > 0, nil
	case OpLessThan:
		return cmp < 0, nil
	case OpGreaterOrEqual:
		return cmp >= 0, nil
	case OpLessOrEqual:
		return cmp <= 0, nil
	default:
		return false, fmt.Errorf("unsupported operator for amount: %s", op)
	}
}

func compareString(actual string, op Operator, value interface{}) (bool, error) {
	switch op {
	case OpEquals:
		return actual == fmt.Sprint(value), nil
	case OpNotEquals:
		return actual != fmt.Sprint(value), nil
	case OpContains:
		return strings.Contains(actual, fmt.Sprint(value)), nil
	case OpStartsWith:
		return strings.HasPrefix(actual, fmt.Sprint(value)), nil
	case OpEndsWith:
		return strings.HasSuffix(actual, fmt.Sprint(value)), nil
	case OpMatches:
		re, err := regexp.Compile(fmt.Sprint(value))
		if err != nil {
			return false, err
		}
		return re.MatchString(actual), nil
	case OpIn:
		list, ok := value.([]interface{})
		if !ok {
			return false, fmt.Errorf("in operator requires array value")
		}
		for _, v := range list {
			if actual == fmt.Sprint(v) {
				return true, nil
			}
		}
		return false, nil
	case OpNotIn:
		list, ok := value.([]interface{})
		if !ok {
			return false, fmt.Errorf("not_in operator requires array value")
		}
		for _, v := range list {
			if actual == fmt.Sprint(v) {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported operator for string: %s", op)
	}
}

func isInWhitelist(address string, value interface{}) (bool, error) {
	list, ok := value.([]interface{})
	if !ok {
		return false, fmt.Errorf("whitelist requires array value")
	}
	for _, v := range list {
		if strings.EqualFold(address, fmt.Sprint(v)) {
			return true, nil
		}
	}
	return false, nil
}

func isInBlacklist(address string, value interface{}) (bool, error) {
	list, ok := value.([]interface{})
	if !ok {
		return false, fmt.Errorf("blacklist requires array value")
	}
	for _, v := range list {
		if strings.EqualFold(address, fmt.Sprint(v)) {
			return true, nil // In blacklist = condition matches
		}
	}
	return false, nil
}

func isInTimeWindow(tw *TimeWindow) bool {
	loc, err := time.LoadLocation(tw.Timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	hour := now.Hour()

	// Check hour range
	if tw.StartHour <= tw.EndHour {
		if hour < tw.StartHour || hour > tw.EndHour {
			return false
		}
	} else {
		// Wraps around midnight
		if hour < tw.StartHour && hour > tw.EndHour {
			return false
		}
	}

	// Check day of week
	if len(tw.AllowedDays) > 0 {
		dayName := strings.ToLower(now.Weekday().String())
		found := false
		for _, d := range tw.AllowedDays {
			if strings.ToLower(d) == dayName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func calculateDelay(tw *TimeWindow) time.Time {
	loc, err := time.LoadLocation(tw.Timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)

	// Find next allowed time
	for i := 0; i < 8; i++ { // Check up to 8 days ahead
		checkTime := now.Add(time.Duration(i) * 24 * time.Hour)
		dayName := strings.ToLower(checkTime.Weekday().String())

		// Check if day is allowed
		dayAllowed := len(tw.AllowedDays) == 0
		for _, d := range tw.AllowedDays {
			if strings.ToLower(d) == dayName {
				dayAllowed = true
				break
			}
		}

		if dayAllowed {
			// Set to start hour
			target := time.Date(checkTime.Year(), checkTime.Month(), checkTime.Day(),
				tw.StartHour, 0, 0, 0, loc)
			if target.After(now) {
				return target
			}
		}
	}

	return now // Fallback
}

func contains[T comparable](slice []T, item T) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ============================================================
// SERIALIZATION
// ============================================================

// MarshalJSON marshals the policy engine state.
func (e *PolicyEngine) MarshalJSON() ([]byte, error) {
	state := struct {
		Rules          []Rule                    `json:"rules"`
		Signers        map[string]*Signer        `json:"signers"`
		WalletPolicies map[string]*WalletPolicy  `json:"wallet_policies"`
	}{
		Rules:          e.rules,
		Signers:        e.signers,
		WalletPolicies: e.walletPolicies,
	}
	return json.Marshal(state)
}

// UnmarshalJSON unmarshals the policy engine state.
func (e *PolicyEngine) UnmarshalJSON(data []byte) error {
	var state struct {
		Rules          []Rule                    `json:"rules"`
		Signers        map[string]*Signer        `json:"signers"`
		WalletPolicies map[string]*WalletPolicy  `json:"wallet_policies"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	e.rules = state.Rules
	e.signers = state.Signers
	e.walletPolicies = state.WalletPolicies
	return nil
}
