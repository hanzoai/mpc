// Package policy provides approval workflow for MPC transactions.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ============================================================
// APPROVAL WORKFLOW
// ============================================================

// ApprovalWorkflow manages transaction approval process.
type ApprovalWorkflow struct {
	engine   *PolicyEngine
	pending  map[string]*ApprovalRequest
	mu       sync.RWMutex
	notifier ApprovalNotifier
}

// ApprovalNotifier sends notifications for approval events.
type ApprovalNotifier interface {
	// NotifyPendingApproval notifies signers about a pending approval.
	NotifyPendingApproval(ctx context.Context, req *ApprovalRequest, signers []string) error
	// NotifyApproved notifies when a transaction is approved.
	NotifyApproved(ctx context.Context, req *ApprovalRequest) error
	// NotifyRejected notifies when a transaction is rejected.
	NotifyRejected(ctx context.Context, req *ApprovalRequest, reason string) error
	// NotifyExpired notifies when a transaction approval expires.
	NotifyExpired(ctx context.Context, req *ApprovalRequest) error
}

// ApprovalRequest represents a pending approval.
type ApprovalRequest struct {
	ID               string               `json:"id"`
	TransactionID    string               `json:"transaction_id"`
	WalletID         string               `json:"wallet_id"`
	Transaction      *TransactionRequest  `json:"transaction"`
	PolicyResult     *PolicyResult        `json:"policy_result"`
	Status           ApprovalStatus       `json:"status"`
	RequiredCount    int                  `json:"required_count"`
	CurrentCount     int                  `json:"current_count"`
	EligibleSigners  []string             `json:"eligible_signers"`
	Approvals        []Approval           `json:"approvals"`
	Rejections       []Rejection          `json:"rejections"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	ExpiresAt        time.Time            `json:"expires_at"`
	CompletedAt      *time.Time           `json:"completed_at,omitempty"`
}

// ApprovalStatus is the status of an approval request.
type ApprovalStatus string

const (
	ApprovalStatusPending   ApprovalStatus = "pending"
	ApprovalStatusApproved  ApprovalStatus = "approved"
	ApprovalStatusRejected  ApprovalStatus = "rejected"
	ApprovalStatusExpired   ApprovalStatus = "expired"
	ApprovalStatusCancelled ApprovalStatus = "cancelled"
)

// Approval represents a single approval from a signer.
type Approval struct {
	SignerID   string    `json:"signer_id"`
	SignerName string    `json:"signer_name"`
	Signature  string    `json:"signature"` // Ed25519 signature of approval
	Comment    string    `json:"comment,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

// Rejection represents a rejection from a signer.
type Rejection struct {
	SignerID   string    `json:"signer_id"`
	SignerName string    `json:"signer_name"`
	Reason     string    `json:"reason"`
	RejectedAt time.Time `json:"rejected_at"`
}

// NewApprovalWorkflow creates a new approval workflow.
func NewApprovalWorkflow(engine *PolicyEngine, notifier ApprovalNotifier) *ApprovalWorkflow {
	return &ApprovalWorkflow{
		engine:   engine,
		pending:  make(map[string]*ApprovalRequest),
		notifier: notifier,
	}
}

// SubmitTransaction submits a transaction for approval.
func (w *ApprovalWorkflow) SubmitTransaction(ctx context.Context, tx *TransactionRequest) (*ApprovalRequest, error) {
	// Evaluate policy
	result, err := w.engine.Evaluate(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// If denied, return immediately
	if result.Action == ActionDeny {
		return nil, fmt.Errorf("transaction denied: %s", result.DenyReason)
	}

	// If allowed without approval, return success
	if result.Action == ActionAllow {
		return &ApprovalRequest{
			ID:            generateID(),
			TransactionID: tx.ID,
			WalletID:      tx.WalletID,
			Transaction:   tx,
			PolicyResult:  result,
			Status:        ApprovalStatusApproved,
			CreatedAt:     time.Now(),
			CompletedAt:   timePtr(time.Now()),
		}, nil
	}

	// Create approval request
	req := &ApprovalRequest{
		ID:              generateID(),
		TransactionID:   tx.ID,
		WalletID:        tx.WalletID,
		Transaction:     tx,
		PolicyResult:    result,
		Status:          ApprovalStatusPending,
		RequiredCount:   result.RequiredCount,
		CurrentCount:    0,
		EligibleSigners: result.RequiredSigners,
		Approvals:       make([]Approval, 0),
		Rejections:      make([]Rejection, 0),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(24 * time.Hour), // Default 24h expiry
	}

	// Apply delay if required
	if result.DelayUntil != nil && result.DelayUntil.After(time.Now()) {
		req.ExpiresAt = result.DelayUntil.Add(24 * time.Hour)
	}

	w.mu.Lock()
	w.pending[req.ID] = req
	w.mu.Unlock()

	// Notify eligible signers
	if w.notifier != nil {
		w.notifier.NotifyPendingApproval(ctx, req, req.EligibleSigners)
	}

	return req, nil
}

// Approve adds an approval to a pending request.
func (w *ApprovalWorkflow) Approve(ctx context.Context, requestID string, approval Approval) (*ApprovalRequest, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	req, ok := w.pending[requestID]
	if !ok {
		return nil, fmt.Errorf("approval request not found: %s", requestID)
	}

	// Check if request is still pending
	if req.Status != ApprovalStatusPending {
		return nil, fmt.Errorf("request is no longer pending: %s", req.Status)
	}

	// Check if expired
	if time.Now().After(req.ExpiresAt) {
		req.Status = ApprovalStatusExpired
		if w.notifier != nil {
			w.notifier.NotifyExpired(ctx, req)
		}
		return nil, fmt.Errorf("approval request has expired")
	}

	// Check if signer is eligible
	if !contains(req.EligibleSigners, approval.SignerID) {
		return nil, fmt.Errorf("signer is not eligible to approve this request")
	}

	// Check if already approved/rejected
	for _, a := range req.Approvals {
		if a.SignerID == approval.SignerID {
			return nil, fmt.Errorf("signer has already approved this request")
		}
	}
	for _, r := range req.Rejections {
		if r.SignerID == approval.SignerID {
			return nil, fmt.Errorf("signer has already rejected this request")
		}
	}

	// Verify signature
	signer, ok := w.engine.GetSigner(approval.SignerID)
	if !ok {
		return nil, fmt.Errorf("signer not found: %s", approval.SignerID)
	}

	if signer.Status != StatusActive {
		return nil, fmt.Errorf("signer is not active: %s", signer.Status)
	}

	// TODO: Verify Ed25519 signature of approval
	// This would verify that the approval.Signature is a valid Ed25519 signature
	// of the transaction data signed by the signer's public key

	// Add approval
	approval.SignerName = signer.Name
	approval.ApprovedAt = time.Now()
	req.Approvals = append(req.Approvals, approval)
	req.CurrentCount++
	req.UpdatedAt = time.Now()

	// Check if we have enough approvals
	if req.CurrentCount >= req.RequiredCount {
		req.Status = ApprovalStatusApproved
		req.CompletedAt = timePtr(time.Now())
		if w.notifier != nil {
			w.notifier.NotifyApproved(ctx, req)
		}
	}

	return req, nil
}

// Reject adds a rejection to a pending request.
func (w *ApprovalWorkflow) Reject(ctx context.Context, requestID string, rejection Rejection) (*ApprovalRequest, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	req, ok := w.pending[requestID]
	if !ok {
		return nil, fmt.Errorf("approval request not found: %s", requestID)
	}

	// Check if request is still pending
	if req.Status != ApprovalStatusPending {
		return nil, fmt.Errorf("request is no longer pending: %s", req.Status)
	}

	// Check if signer is eligible
	if !contains(req.EligibleSigners, rejection.SignerID) {
		return nil, fmt.Errorf("signer is not eligible to reject this request")
	}

	// Get signer info
	signer, ok := w.engine.GetSigner(rejection.SignerID)
	if !ok {
		return nil, fmt.Errorf("signer not found: %s", rejection.SignerID)
	}

	// Add rejection
	rejection.SignerName = signer.Name
	rejection.RejectedAt = time.Now()
	req.Rejections = append(req.Rejections, rejection)
	req.UpdatedAt = time.Now()

	// Single rejection rejects the entire request
	req.Status = ApprovalStatusRejected
	req.CompletedAt = timePtr(time.Now())

	if w.notifier != nil {
		w.notifier.NotifyRejected(ctx, req, rejection.Reason)
	}

	return req, nil
}

// Cancel cancels a pending approval request.
func (w *ApprovalWorkflow) Cancel(ctx context.Context, requestID string, initiatorID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	req, ok := w.pending[requestID]
	if !ok {
		return fmt.Errorf("approval request not found: %s", requestID)
	}

	// Only the initiator or an owner can cancel
	if req.Transaction.InitiatorID != initiatorID {
		signer, ok := w.engine.GetSigner(initiatorID)
		if !ok || signer.Role != RoleOwner {
			return fmt.Errorf("only the initiator or an owner can cancel this request")
		}
	}

	if req.Status != ApprovalStatusPending {
		return fmt.Errorf("request is no longer pending: %s", req.Status)
	}

	req.Status = ApprovalStatusCancelled
	req.CompletedAt = timePtr(time.Now())
	req.UpdatedAt = time.Now()

	return nil
}

// GetRequest returns an approval request by ID.
func (w *ApprovalWorkflow) GetRequest(requestID string) (*ApprovalRequest, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	req, ok := w.pending[requestID]
	return req, ok
}

// ListPending returns all pending approval requests.
func (w *ApprovalWorkflow) ListPending() []*ApprovalRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()

	requests := make([]*ApprovalRequest, 0)
	for _, req := range w.pending {
		if req.Status == ApprovalStatusPending {
			requests = append(requests, req)
		}
	}
	return requests
}

// ListForSigner returns pending requests that a signer can approve.
func (w *ApprovalWorkflow) ListForSigner(signerID string) []*ApprovalRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()

	requests := make([]*ApprovalRequest, 0)
	for _, req := range w.pending {
		if req.Status == ApprovalStatusPending && contains(req.EligibleSigners, signerID) {
			// Check if signer hasn't already approved/rejected
			alreadyActed := false
			for _, a := range req.Approvals {
				if a.SignerID == signerID {
					alreadyActed = true
					break
				}
			}
			for _, r := range req.Rejections {
				if r.SignerID == signerID {
					alreadyActed = true
					break
				}
			}
			if !alreadyActed {
				requests = append(requests, req)
			}
		}
	}
	return requests
}

// CleanupExpired removes expired requests.
func (w *ApprovalWorkflow) CleanupExpired(ctx context.Context) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	expired := 0

	for id, req := range w.pending {
		if req.Status == ApprovalStatusPending && now.After(req.ExpiresAt) {
			req.Status = ApprovalStatusExpired
			req.CompletedAt = timePtr(now)
			if w.notifier != nil {
				w.notifier.NotifyExpired(ctx, req)
			}
			expired++
			delete(w.pending, id)
		}
	}

	return expired
}

// ============================================================
// AUDIT LOG
// ============================================================

// AuditLog records all policy-related events.
type AuditLog struct {
	entries []AuditEntry
	mu      sync.RWMutex
}

// AuditEntry is a single audit log entry.
type AuditEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        AuditEventType         `json:"type"`
	ActorID     string                 `json:"actor_id"`
	ActorName   string                 `json:"actor_name"`
	ActorIP     string                 `json:"actor_ip,omitempty"`
	Resource    string                 `json:"resource"`      // wallet_id, signer_id, etc.
	ResourceType string                `json:"resource_type"` // wallet, signer, transaction, etc.
	Action      string                 `json:"action"`
	Details     map[string]interface{} `json:"details"`
	Result      string                 `json:"result"` // success, failure
	Error       string                 `json:"error,omitempty"`
}

// AuditEventType is the type of audit event.
type AuditEventType string

const (
	AuditSignerAdded          AuditEventType = "signer_added"
	AuditSignerRemoved        AuditEventType = "signer_removed"
	AuditSignerUpdated        AuditEventType = "signer_updated"
	AuditPolicyUpdated        AuditEventType = "policy_updated"
	AuditRuleAdded            AuditEventType = "rule_added"
	AuditRuleRemoved          AuditEventType = "rule_removed"
	AuditTransactionSubmitted AuditEventType = "transaction_submitted"
	AuditTransactionApproved  AuditEventType = "transaction_approved"
	AuditTransactionRejected  AuditEventType = "transaction_rejected"
	AuditTransactionCancelled AuditEventType = "transaction_cancelled"
	AuditTransactionExpired   AuditEventType = "transaction_expired"
	AuditTransactionSigned    AuditEventType = "transaction_signed"
	AuditKeyGenerated         AuditEventType = "key_generated"
	AuditKeyExported          AuditEventType = "key_exported"
	AuditLoginSuccess         AuditEventType = "login_success"
	AuditLoginFailure         AuditEventType = "login_failure"
)

// NewAuditLog creates a new audit log.
func NewAuditLog() *AuditLog {
	return &AuditLog{
		entries: make([]AuditEntry, 0),
	}
}

// Log records an audit entry.
func (l *AuditLog) Log(entry AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.ID = generateID()
	entry.Timestamp = time.Now()
	l.entries = append(l.entries, entry)
}

// Query returns audit entries matching the filter.
func (l *AuditLog) Query(filter AuditFilter) []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	results := make([]AuditEntry, 0)
	for _, entry := range l.entries {
		if matchesFilter(&entry, &filter) {
			results = append(results, entry)
		}
	}
	return results
}

// AuditFilter filters audit entries.
type AuditFilter struct {
	ActorID      string
	ResourceType string
	Resource     string
	EventType    AuditEventType
	StartTime    time.Time
	EndTime      time.Time
	Limit        int
}

func matchesFilter(entry *AuditEntry, filter *AuditFilter) bool {
	if filter.ActorID != "" && entry.ActorID != filter.ActorID {
		return false
	}
	if filter.ResourceType != "" && entry.ResourceType != filter.ResourceType {
		return false
	}
	if filter.Resource != "" && entry.Resource != filter.Resource {
		return false
	}
	if filter.EventType != "" && entry.Type != filter.EventType {
		return false
	}
	if !filter.StartTime.IsZero() && entry.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && entry.Timestamp.After(filter.EndTime) {
		return false
	}
	return true
}

// Export exports the audit log as JSON.
func (l *AuditLog) Export() ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return json.Marshal(l.entries)
}

// ============================================================
// HELPERS
// ============================================================

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func timePtr(t time.Time) *time.Time {
	return &t
}
