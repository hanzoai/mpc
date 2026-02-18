# MPC Signer - LLM Context

## Overview

Threshold signing service. Pluggable signer backend for Hanzo KMS.

- **ECDSA (secp256k1)**: CGGMP21 protocol -- Bitcoin, Ethereum, EVM, XRPL, Lux
- **ECDSA (secp256k1) Taproot**: FROST protocol -- Bitcoin Taproot
- **EdDSA (Ed25519)**: FROST (Taproot mode) -- Solana/TON partial support
- **LSS**: Dynamic resharing (change T-of-N without key reconstruction)
- Threshold: default t = floor(n/2) + 1

## Architecture

```
KMS (Control Plane): Policy, Approvals, Audit, Key Registry, Unified Signing API
  |
  +-- HSM Signer
  +-- MPC Signer (this project) -- DKG, threshold signing, reshare
  +-- Software Signer
  +-- Remote Signer
```

## Project Structure

```
mpc/
  cmd/hanzo-mpc/       Main node binary
  cmd/hanzo-mpc-cli/   CLI tools
  pkg/
    mpc/               TSS implementation (CGGMP21, FROST, LSS)
    kvstore/           BadgerDB storage (AES-256 encrypted)
    messaging/         NATS JetStream (pub/sub + P2P)
    identity/          Ed25519 node identity (Age encrypted)
    client/            Go client library
    policy/            Policy engine (signers, limits, whitelist, FHE)
    threshold/         ThresholdVM (policy enforcement in signing)
    storage/           BadgerDB store + S3 backup client
    eventconsumer/     Event processing
  contracts/           ThresholdPolicy.sol (on-chain policy)
  deploy/              compose.yml with full stack
  e2e/                 End-to-end tests
```

## Quick Start

```bash
make build
hanzo-mpc-cli generate-peers -n 3
hanzo-mpc-cli register-peers
hanzo-mpc-cli generate-initiator
hanzo-mpc-cli generate-identity --node node0
hanzo-mpc start -n node0
```

## Config

```yaml
environment: development
consul:
  address: localhost:8500
nats:
  url: nats://localhost:4222
badger_password: "secure-password"
event_initiator_pubkey: "hex-encoded-pubkey"
```

Env vars: `HANZO_MPC_CONFIG` (config path), `HANZO_MPC_BACKUP` (backup ID).

## Deploy Stack (`deploy/compose.yml`)

| Service | Port | Purpose |
|---------|------|---------|
| lux-mpc-{0,1,2} | 6000-6002 | MPC nodes |
| lux-kms | 8080 | Key management |
| nats | 4222 | Message broker |
| consul | 8500 | Service discovery |
| minio | 9000 | S3 backup storage |

## Testing

```bash
make test            # Unit tests
make test-coverage   # With coverage
make e2e-test        # End-to-end
```

## Critical Gotchas (Debugged Jan 2026)

### Serialization
- Protocol messages MUST use `MarshalBinary/UnmarshalBinary`, NOT JSON (loses SSID, RoundNumber)
- FROST `TaprootConfig` crypto types have NO JSON marshalers -- MUST use CBOR via `MarshalFROSTConfig()`/`UnmarshalFROSTConfig()`
- LSS `lssConfig.Config` same issue -- use CBOR via `MarshalLSSConfig()`/`UnmarshalLSSConfig()`

### Protocol Behavior
- Party IDs must be sorted consistently (`GetReadyPeersIncludeSelf()` handles this)
- "Handler cannot accept message" warnings are NORMAL (nodes receiving own broadcasts)
- FROST signing returns `taproot.Signature` (64-byte `[]byte`), NOT `*frost.Signature`
- BIP-340 format (R_x || s) needs no conversion

### Result Publishing
- Sessions must NOT publish success to result queue -- handler publishes combined ECDSA+EdDSA result
- Sessions publish FAILURE directly for immediate notification
- Sessions send success via `externalFinishChan`; always send (even empty on error) to prevent blocking
- Dual keygen runs ECDSA (CGGMP21) and EdDSA (FROST) in parallel via goroutines+WaitGroup

### NATS Topics
- Keygen: `mpc.mpc_keygen_result.<walletID>` (note `mpc.mpc_` prefix)
- Signing: `mpc.mpc_signing_result.<walletID>`
- Stream pattern: `mpc.mpc_*_result.*`

### E2E Tests
- Tests use `hanzo-mpc` from PATH -- run `go install ./cmd/hanzo-mpc && go install ./cmd/hanzo-mpc-cli` after code changes

## Security Audit Findings (Jan 2026)

1. Protocol messages between nodes are NOT signed (Ed25519 code exists but disabled)
2. Deduplication `processing` map grows unbounded -- needs TTL cleanup
3. No timeout on protocol handlers -- needs context with deadline

## Policy Engine (`pkg/policy/`)

Fireblocks/Utila-style transaction governance:
- Signers and roles (ADMIN, SIGNER, VIEWER)
- Spending limits (per-tx, daily, monthly by asset)
- Whitelist/blacklist, time windows, rate limiting
- ThresholdVM (`pkg/threshold/policy_vm.go`): evaluates policies before signature shares
- FHE private policies via pluggable `FHEEngine` interface (compatible with luxfi/fhe)

## Blockchain Support

| Chain | Curve | Protocol | Status |
|-------|-------|----------|--------|
| Bitcoin (Legacy/SegWit) | secp256k1 | CGGMP21/LSS | Full |
| Bitcoin (Taproot) | secp256k1 | FROST | Full |
| Ethereum/EVM | secp256k1 | CGGMP21/LSS | Full |
| XRPL | secp256k1 | CGGMP21/LSS | Full |
| Lux Network | secp256k1 | CGGMP21/LSS | Full |
| Solana | Ed25519 | FROST (Taproot) | Partial -- needs native Ed25519 FROST |
| TON | Ed25519 | FROST (Taproot) | Partial -- needs native Ed25519 FROST |
