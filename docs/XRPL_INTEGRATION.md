# XRPL Integration Guide

This guide explains how to use the Lux MPC library for XRP Ledger (XRPL) transaction signing.

## Overview

The Lux MPC library now includes explicit support for XRPL networks. XRPL uses secp256k1 signatures for transaction authorization, which is fully supported by our threshold signature implementation.

## Supported Networks

- `XRPL` - XRP Ledger Mainnet
- `XRPL-testnet` - XRP Ledger Testnet
- `XRPL-devnet` - XRP Ledger Devnet

## Key Type

XRPL uses **secp256k1** (ECDSA) signatures. The library automatically selects the correct key type when you specify an XRPL network code.

## Usage Example

```go
import (
    "github.com/luxfi/mpc/pkg/types"
    "github.com/luxfi/mpc/pkg/client"
)

// Create signing request for XRPL
signingMsg := &types.SignTxMessage{
    WalletID:            "your-wallet-id",
    TxID:                "unique-tx-id",
    Tx:                  xrplTransactionBytes,
    KeyType:             types.KeyTypeSecp256k1,
    NetworkInternalCode: string(types.NetworkXRPL),
}

// Sign the transaction
err := mpcClient.SignTransaction(signingMsg)
```

## Transaction Format

XRPL transactions should be provided as serialized bytes according to the XRPL binary codec specification. The typical flow is:

1. Create XRPL transaction JSON
2. Serialize using XRPL binary codec
3. Pass serialized bytes to MPC for signing
4. Apply signature to transaction
5. Submit to XRPL network

## Integration with ripple-lib

When integrating with JavaScript XRPL libraries:

```javascript
const RippleAPI = require('ripple-lib').RippleAPI;
const api = new RippleAPI();

// Create transaction
const txJSON = {
  TransactionType: 'Payment',
  Account: 'rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH',
  Destination: 'rLNaPoKeeBjZe2qs6x52yVPZpZ8td4dc6w',
  Amount: '1000000', // 1 XRP in drops
  Fee: '12',
  Sequence: 1
};

// Serialize transaction (prepare for signing)
const serialized = api.encodeTransaction(txJSON);

// Send serialized bytes to MPC for signing
// ... MPC signing process ...

// Apply MPC signature to transaction
const signedTx = {
  ...txJSON,
  TxnSignature: mpcSignature
};

// Submit to XRPL
api.submit(signedTx);
```

## Security Considerations

1. **Key Derivation**: XRPL uses specific key derivation paths. Ensure your wallet implementation follows XRPL standards.

2. **Transaction Validation**: Always validate transaction data before signing:
   - Check destination addresses
   - Verify amounts
   - Confirm fees are reasonable
   - Validate sequence numbers

3. **Network Selection**: Always specify the correct network code to prevent signing mainnet transactions with testnet keys or vice versa.

## Testing

Run XRPL-specific tests:

```bash
go test ./e2e -run TestXRPL
```

## Network Configuration

The supported networks are defined in `pkg/types/networks.go`:

```go
const (
    NetworkXRPL        NetworkCode = "XRPL"
    NetworkXRPLTestnet NetworkCode = "XRPL-testnet"
    NetworkXRPLDevnet  NetworkCode = "XRPL-devnet"
)
```

## Error Handling

Common XRPL-related errors:

- Invalid network code: Ensure you're using one of the supported XRPL network codes
- Wrong key type: XRPL only supports secp256k1 signatures
- Invalid transaction format: Ensure proper XRPL transaction serialization

## References

- [XRPL Documentation](https://xrpl.org/)
- [XRPL Binary Codec](https://xrpl.org/serialization.html)
- [XRPL Transaction Types](https://xrpl.org/transaction-types.html)