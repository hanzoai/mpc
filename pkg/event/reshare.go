package event

import "github.com/hanzoai/mpc/pkg/types"

type ResharingResultEvent struct {
	WalletID     string        `json:"wallet_id"`
	NewThreshold int           `json:"new_threshold"`
	KeyType      types.KeyType `json:"key_type"`
	PubKey       []byte        `json:"pub_key"`

	ResultType  ResultType `json:"result_type"`
	ErrorReason string     `json:"error_reason"`
	ErrorCode   string     `json:"error_code"`
}
