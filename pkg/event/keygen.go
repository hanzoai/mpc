package event

const (
	KeygenBrokerStream   = "mpc-keygen"
	KeygenConsumerStream = "mpc-keygen-consumer"
	KeygenRequestTopic   = "mpc.keygen_request.*"
)

type KeygenResultEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`
}

// CreateKeygenSuccess creates a successful keygen event
func CreateKeygenSuccess(walletID string, pubKeyHex string, metadata map[string]any) *KeygenResultEvent {
	return &KeygenResultEvent{
		WalletID:    walletID,
		ECDSAPubKey: []byte(pubKeyHex),
		ResultType:  ResultTypeSuccess,
	}
}

// CreateKeygenFailure creates a failed keygen event
func CreateKeygenFailure(walletID string, metadata map[string]any) *KeygenResultEvent {
	errorMsg := ""
	if err, ok := metadata["error"].(string); ok {
		errorMsg = err
	}
	return &KeygenResultEvent{
		WalletID:    walletID,
		ResultType:  ResultTypeError,
		ErrorReason: errorMsg,
		ErrorCode:   string(ErrorCodeKeygenFailure),
	}
}
