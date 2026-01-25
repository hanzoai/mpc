# LLM.md - Hanzo MPC Signer Architecture & Development Guide

This document provides comprehensive guidance for AI assistants working with the Hanzo MPC (Multi-Party Computation) codebase.

## 📚 Overview

Hanzo MPC is a threshold signing service that provides:
- **ECDSA (secp256k1)** for Bitcoin/Ethereum/EVM chains
- **EdDSA (Ed25519)** for Solana/Polkadot/Sui
- **Threshold signatures** (t-of-n) with CGGMP21 protocol
- **Key resharing** for rotation without changing addresses

### Architecture Position

Hanzo MPC is designed as a **pluggable signer backend** for Hanzo KMS:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Hanzo KMS (Control Plane)                  │
│  ┌──────────┬─────────────┬──────────────┬─────────────────┐    │
│  │ Policy   │ Approvals   │  Audit Log   │  Key Registry   │    │
│  └────┬─────┴──────┬──────┴───────┬──────┴───────┬─────────┘    │
│       │            │              │              │              │
│  ┌────▼────────────▼──────────────▼──────────────▼─────────┐    │
│  │              Unified Signing API                         │    │
│  └────┬────────────┬──────────────┬──────────────┬─────────┘    │
│       │            │              │              │              │
│  ┌────▼────┐  ┌────▼────┐   ┌─────▼─────┐  ┌─────▼─────┐        │
│  │  HSM    │  │  MPC    │   │  Software │  │  Remote   │        │
│  │ Signer  │  │ Signer  │   │  Signer   │  │  Signer   │        │
│  └─────────┘  └─────────┘   └───────────┘  └───────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Product Architecture

1. **Hanzo KMS Platform** (Control Plane)
   - Key registry + metadata
   - Policy + workflow (quorum, time locks, spend limits, allowlists)
   - Audit log
   - Unified API
   - Secrets manager

2. **Hanzo MPC Signer** (This Project - Data Plane)
   - DKG / key share management
   - Threshold signing sessions
   - Reshare/rotate shares
   - Optional hardware-rooted modes

3. **Hanzo HSM** (Alternative Signer)
   - HSM-backed keys for classic KMS workloads
   - HSM-sealed share storage for MPC nodes

4. **Hanzo Treasury** (Optional UI)
   - Transaction building + chain adapters
   - Simulation / policy previews
   - Approvals UI (backed by KMS workflow engine)

## 🚀 Quick Start

### Build and Install
```bash
# Build binaries
make build

# Or install directly
go install ./cmd/hanzo-mpc
go install ./cmd/hanzo-mpc-cli
```

### Basic Usage
```bash
# Generate peers configuration
hanzo-mpc-cli generate-peers -n 3

# Register peers to Consul
hanzo-mpc-cli register-peers

# Generate event initiator
hanzo-mpc-cli generate-initiator

# Generate node identity
hanzo-mpc-cli generate-identity --node node0

# Start MPC node
hanzo-mpc start -n node0
```

## 📁 Project Structure

```
/Users/z/work/hanzo/mpc/
├── cmd/                    # Command-line applications
│   ├── hanzo-mpc/         # Main MPC node binary
│   └── hanzo-mpc-cli/     # CLI tools for configuration
├── pkg/                    # Core packages
│   ├── client/            # Go client library
│   ├── mpc/               # MPC implementation (TSS)
│   ├── kvstore/           # BadgerDB storage
│   ├── messaging/         # NATS messaging
│   ├── identity/          # Ed25519 identity management
│   └── eventconsumer/     # Event processing
├── e2e/                    # End-to-end tests
├── examples/               # Usage examples
└── scripts/                # Utility scripts
```

## 🏗️ Core Components

### 1. MPC Engine
Based on threshold cryptography:
- **CGGMP21** protocol for ECDSA (secp256k1) - **IMPLEMENTED & TESTED**
- **FROST** protocol for EdDSA (Ed25519) - **IMPLEMENTED & TESTED** (keygen generates both ECDSA and EdDSA keys)
- Configurable threshold (t-of-n)
- Default: t = ⌊n/2⌋ + 1 (majority)

### 2. Storage Layer: BadgerDB
- AES-256 encrypted key shares
- Session data persistence
- Automatic backups

### 3. Messaging: NATS JetStream
- Pub/sub for broadcasts
- Direct messaging for P2P
- Message persistence

### 4. Service Discovery: Consul
- Node registration
- Health checking
- Configuration management

### 5. Identity: Ed25519 keypairs
- Node authentication
- Message signing/verification
- Encrypted with Age

## 🔧 Configuration

```yaml
# config.yaml
environment: development
consul:
  address: localhost:8500
nats:
  url: nats://localhost:4222
badger_password: "secure-password"
event_initiator_pubkey: "hex-encoded-pubkey"
```

### Environment Variables
- `HANZO_MPC_CONFIG` - Path to config.yaml
- `HANZO_MPC_BACKUP` - Backup file identifier

## 🔐 Security Model

- **Threshold Security**: No single node has the complete key
- **Message Authentication**: All messages signed with Ed25519
- **Storage Encryption**: BadgerDB encrypted with user password
- **Network Security**: TLS + mutual authentication
- **Key Rotation**: Supports resharing without changing addresses

## 📊 Performance

- **Key Generation**: ~30s for 3 nodes
- **Signing**: <1s for threshold signatures
- **Storage**: ~100MB per node (with backups)
- **Network**: Low bandwidth, resilient to failures

## 🔗 Integration with Hanzo Commerce

The MPC Signer integrates with Commerce for crypto payments:

```go
// Commerce uses MPC via the processor interface
type MPCProcessor struct {
    kmsClient  *kms.Client   // Hanzo KMS for policy/approval
    mpcClient  *mpc.Client   // Hanzo MPC for signing
}

func (p *MPCProcessor) Charge(ctx context.Context, req PaymentRequest) (*PaymentResult, error) {
    // 1. KMS validates policy and approvals
    // 2. MPC signs the transaction
    // 3. Transaction broadcast to blockchain
}
```

## 🔧 Development Workflow

### Testing
```bash
# Run unit tests
make test

# Run with coverage
make test-coverage

# Run E2E tests
make e2e-test
```

### Common Tasks

1. **Generate 3-node test cluster**:
   ```bash
   ./setup_identities.sh
   ```

2. **Recover from backup**:
   ```bash
   hanzo-mpc-cli recover --backup-dir ./backups --recovery-path ./recovered-db
   ```

3. **Production deployment**:
   - Use `--encrypt` flag for identity generation
   - Enable TLS on all services
   - Use `--prompt-credentials` to avoid hardcoded passwords

## 🐛 Common Issues

1. **Port conflicts**: Default ports are 4222 (NATS), 8500 (Consul)
2. **Database locks**: Ensure single process per node
3. **Network delays**: Check NATS/Consul connectivity
4. **Backup failures**: Verify disk space and permissions

### CGGMP21 Protocol Issues (Debugged Jan 2026)

5. **Protocol message serialization**: Protocol messages MUST use `MarshalBinary/UnmarshalBinary` to preserve all fields (SSID, RoundNumber, etc.). Raw JSON marshaling loses critical protocol state.

6. **Party ID ordering**: Party IDs must be sorted consistently across all nodes. The `GetReadyPeersIncludeSelf()` function in `registry.go` sorts peer IDs to ensure deterministic ordering.

7. **NATS topic naming**: Result topics must match JetStream stream configuration:
   - Keygen results: `mpc.mpc_keygen_result.<walletID>` (note the `mpc.mpc_` prefix)
   - Signing results: `mpc.mpc_signing_result.<walletID>`
   - Stream expects pattern: `mpc.mpc_*_result.*`

8. **Self-message rejection**: It's NORMAL for nodes to log "Handler cannot accept message" warnings when they receive their own broadcast messages back. This is expected behavior in pub/sub systems.

9. **Binary rebuild for e2e tests**: E2E tests use `hanzo-mpc` from PATH. After code changes, run `go install ./cmd/hanzo-mpc && go install ./cmd/hanzo-mpc-cli` to update the installed binaries.

10. **Session result publishing pattern**: Individual protocol sessions (CGGMP21, FROST) should NOT publish success events directly to the result queue. The handler (`keygen_handler_cggmp21.go`) is responsible for publishing the combined result with both ECDSA and EdDSA keys. Sessions should only:
    - Publish FAILURE events to the queue (for immediate error notification)
    - Send success pubkey via `externalFinishChan` so `WaitForFinish()` returns
    - Always send to `externalFinishChan` (even empty string for errors) to prevent blocking

11. **Dual keygen architecture**: The `handleKeyGenEventCGGMP21` function runs both ECDSA (CGGMP21) and EdDSA (FROST) keygen protocols in parallel via goroutines with WaitGroup. Both sessions must complete before the handler publishes the combined result containing both public keys.

### FROST Signing Issues (Debugged Jan 2026)

12. **FROST config serialization (CRITICAL)**: `frost.TaprootConfig` contains crypto types (`*curve.Secp256k1Scalar`, `*curve.Secp256k1Point`) that **do NOT have JSON marshalers**. Using `json.Marshal()` corrupts the key shares. **MUST use CBOR serialization** via `MarshalFROSTConfig()` and `UnmarshalFROSTConfig()` in `frost_config_marshal.go`.

13. **FROST signing result type**: The FROST Taproot signing protocol returns `taproot.Signature` (which is `[]byte` of 64 bytes), NOT `*frost.Signature`. The `signing_session_frost.go` handles this correctly with: `s.signature = result.(taproot.Signature)`.

14. **BIP-340/Taproot signature format**: FROST signing produces BIP-340 compatible signatures (64 bytes: R_x || s). The `taproot.Signature` type is already in this format, so no additional conversion is needed in `publishResult()`.

### LSS Protocol Issues (Fixed Jan 2026)

15. **LSS config serialization (CRITICAL - FIXED)**: Similar to FROST, `lssConfig.Config` contains crypto types (`curve.Scalar`, `curve.Point`) that **do NOT have JSON marshalers**. Fixed by implementing `MarshalLSSConfig()` and `UnmarshalLSSConfig()` in `lss_config_marshal.go` using CBOR serialization.

16. **LSS capabilities vs CGGMP21**: LSS supports dynamic resharing (change T-of-N without reconstructing keys), threshold changes, and adding/removing participants. CGGMP21 only supports refresh (same committee). Both produce valid ECDSA signatures.

### Security Audit Findings (Jan 2026)

17. **Message authentication**: Protocol messages between nodes are not signed. Ed25519 signing code exists but is disabled. Consider re-enabling for production deployments.

18. **Deduplication map cleanup**: The `processing` map used for deduplication grows unbounded. Recommend adding TTL-based cleanup for long-running sessions.

19. **Protocol timeouts**: No timeout enforcement on protocol handlers. Recommend adding context with timeout to prevent indefinite hangs from stalling parties.

## 🌐 Blockchain Support

| Blockchain | Support | Curve | Protocol |
|------------|---------|-------|----------|
| Bitcoin (Legacy/SegWit) | ✅ Full | secp256k1 | CGGMP21/LSS |
| Bitcoin (Taproot) | ✅ Full | secp256k1 | FROST |
| Ethereum/EVM | ✅ Full | secp256k1 | CGGMP21/LSS |
| XRPL (XRP Ledger) | ✅ Full | secp256k1 | CGGMP21/LSS |
| Lux Network | ✅ Full | secp256k1 | CGGMP21/LSS |
| Solana | ⚠️ Partial | Ed25519 | FROST (Taproot mode) |
| TON | ⚠️ Partial | Ed25519 | FROST (Taproot mode) |

**Note**: Solana/TON use Ed25519 natively but our FROST implementation produces Taproot/BIP-340 signatures. Native Ed25519 support requires implementing the Ed25519 FROST variant.

## 🎯 Best Practices

1. **Always backup** BadgerDB before major operations
2. **Test locally** with 3-node setup before production
3. **Monitor health** via Consul UI (http://localhost:8500)
4. **Rotate keys** periodically using reshare functionality
5. **Use Age encryption** for production identities
6. **Keep logs** for debugging MPC rounds

## Context for All AI Assistants

This file (`LLM.md`) is symlinked as:
- `.AGENTS.md`
- `CLAUDE.md`
- `QWEN.md`
- `GEMINI.md`

All files reference the same knowledge base. Updates here propagate to all AI systems.

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
