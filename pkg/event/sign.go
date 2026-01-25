package event

const (
	SigningPublisherStream     = "mpc-signing"
	SigningConsumerStream      = "mpc-signing-consumer"
	SigningRequestTopic        = "mpc.signing_request.*"
	SigningResultTopic         = "mpc.mpc_signing_result.*"     // Pattern for subscribing (with wildcard)
	SigningResultTopicBase     = "mpc.mpc_signing_result"       // Base topic for publishing (no wildcard)
	SigningResultCompleteTopic = "mpc.mpc_signing_result.complete"
)

type SigningResultEvent struct {
	ResultType          ResultType `json:"result_type"`
	ErrorCode           ErrorCode  `json:"error_code"`
	ErrorReason         string     `json:"error_reason"`
	IsTimeout           bool       `json:"is_timeout"`
	NetworkInternalCode string     `json:"network_internal_code"`
	WalletID            string     `json:"wallet_id"`
	TxID                string     `json:"tx_id"`
	// ECDSA signature components (secp256k1)
	R                 []byte `json:"r"`
	S                 []byte `json:"s"`
	SignatureRecovery []byte `json:"signature_recovery"`

	// EdDSA signature (ed25519/Schnorr) - 64-byte combined signature
	// For ECDSA, use R/S/SignatureRecovery fields above
	// For EdDSA, use this Signature field
	Signature []byte `json:"signature"`
}

func CreateSignSuccess(sessionID, walletID string, r, s []byte, recoveryByte byte, metadata map[string]any) SigningResultEvent {
	return SigningResultEvent{
		ResultType:          ResultTypeSuccess,
		ErrorCode:           "",
		WalletID:            walletID,
		TxID:                sessionID,
		R:                   r,
		S:                   s,
		SignatureRecovery:   []byte{recoveryByte},
		NetworkInternalCode: "",
	}
}

func CreateSignFailure(sessionID, walletID string, metadata map[string]any) SigningResultEvent {
	errorReason := ""
	if err, ok := metadata["error"]; ok {
		errorReason = err.(string)
	}

	return SigningResultEvent{
		ResultType:          ResultTypeError,
		ErrorCode:           ErrorCodeSigningFailure,
		ErrorReason:         errorReason,
		WalletID:            walletID,
		TxID:                sessionID,
		NetworkInternalCode: "",
	}
}

type SigningResultSuccessEvent struct {
	NetworkInternalCode string `json:"network_internal_code"`
	WalletID            string `json:"wallet_id"`
	TxID                string `json:"tx_id"`
	// ECDSA signature components (secp256k1)
	R                 []byte `json:"r"`
	S                 []byte `json:"s"`
	SignatureRecovery []byte `json:"signature_recovery"`

	// EdDSA signature (ed25519/Schnorr) - 64-byte combined signature
	Signature []byte `json:"signature"`
}

type SigningResultErrorEvent struct {
	NetworkInternalCode string    `json:"network_internal_code"`
	WalletID            string    `json:"wallet_id"`
	TxID                string    `json:"tx_id"`
	ErrorCode           ErrorCode `json:"error_code"`
	ErrorReason         string    `json:"error_reason"`
	IsTimeout           bool      `json:"is_timeout"`
}
