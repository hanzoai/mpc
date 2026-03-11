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
kv_backend: consensus            # "consensus" (default), "nats", or "consul"
consensus:
  chain_id: m-chain              # "m-chain", "t-chain", or custom
nats:
  url: nats://localhost:4222
  kv_bucket: mpc-state           # only used when kv_backend: nats
consul:                           # only used when kv_backend: consul (legacy)
  address: localhost:8500
badger_password: "secure-password"
event_initiator_pubkey: "hex-encoded-pubkey"
```

Env vars: `HANZO_MPC_CONFIG` (config path), `HANZO_MPC_BACKUP` (backup ID).

## KV Backend Architecture (Mar 2026)

All MPC cluster state (peers, key info, API keys, wallet owners) goes through an
abstract `infra.KV` interface. Three backends are available:

| Backend | Config | Transport | Finality | Use Case |
|---------|--------|-----------|----------|----------|
| `consensus` | `kv_backend: consensus` | NATS + Lux Quasar | Post-quantum (<100ms) | Production (blockchain-native) |
| `nats` | `kv_backend: nats` | NATS JetStream KV | JetStream replication | Dev/staging |
| `consul` | `kv_backend: consul` | Consul HTTP | Raft | Legacy / parity testing |

### ConsensusKV (Private MPC Blockchain, Dual-Certificate)
- MPC nodes run their own private BFT blockchain — no external chain needed
- **Dual-certificate finality** (same model as Lux Quasar):
  - Classical: **Ed25519** (64-byte sig, fast)
  - Post-quantum: **ML-DSA-65** (FIPS 204, NIST Level 3, 3,309-byte sig)
  - Block finalized ONLY when BOTH signature types reach t-of-n threshold
  - If quantum computers break Ed25519, ML-DSA certs still valid
  - If ML-DSA has a flaw, Ed25519 certs still hold
- t-of-n threshold finality (same t as MPC threshold, e.g. 2-of-3)
- Protocol: propose → broadcast → dual-sign vote → threshold met → finalize
- KV mutations batched into blocks, applied deterministically on all nodes
- NATS provides transport between validators
- Keys stored in KMS/HSM when `hsm.provider` is configured
- Can optionally register as Lux subnet (M-Chain/T-Chain) for network integration
- State sync via snapshot for new node joins
- Bootstrap: peers discovered from `mpc-bootstrap` NATS KV bucket

### ML-DSA-65 Key Sizes (FIPS 204)
| Component | Size |
|-----------|------|
| Public key | 1,952 bytes |
| Private key | 4,032 bytes |
| Signature | 3,309 bytes |
| Security level | NIST Level 3 (192-bit) |
| Package | `github.com/luxfi/crypto/mldsa` |

### Files
- `pkg/infra/kv.go` — abstract `KV` interface + `KVPair` type
- `pkg/infra/consensus_kv.go` — Lux consensus-backed KV
- `pkg/infra/nats_kv.go` — NATS JetStream KV
- `pkg/infra/consul_adapter.go` — wraps Consul → KV interface
- `pkg/infra/consul.go` — raw Consul client (kept for backward compat)

## Deploy Stack (`deploy/compose.yml`)

| Service | Port | Purpose |
|---------|------|---------|
| hanzo-mpc-{0,1,2} | 6000-6002 | MPC nodes (consensus validators) |
| hanzo-kms | 8080 | Key management |
| nats | 4222 | Message broker + consensus transport |
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
- Consensus blocks: `mpc.consensus.<chainID>.blocks`
- Consensus proposals: `mpc.consensus.<chainID>.proposals`

### E2E Tests
- Tests use `hanzo-mpc` from PATH -- run `go install ./cmd/hanzo-mpc && go install ./cmd/hanzo-mpc-cli` after code changes

## Production Deployment (Feb 2026)

### Cluster: hanzo-k8s (do-sfo3)
- **Namespace**: `hanzo`
- **StatefulSet**: `hanzo-mpc` (3 replicas)
- **Image**: `ghcr.io/hanzoai/mpc:v0.4.3`
- **API**: `mpc.hanzo.ai` (port 8080, IAM auth via hanzo.id)
- **Node peers**: hanzo-mpc-{0,1,2}
- **Threshold**: 2-of-3

### Infrastructure
- **NATS**: `nats://nats.hanzo.svc.cluster.local:4222` (JetStream + consensus transport)
- **KV Backend**: `consensus` (M-Chain) — Consul deprecated, kept for parity testing
- **Config**: ConfigMap `hanzo-mpc-config` at `/app/config.yaml`
- **Identity**: Secret `hanzo-mpc-identity` at `/app/identity/` + `/app/event_initiator.key`

### Key Architecture
- **Event initiator key** (Ed25519): Signs all keygen/signing/reshare messages
  - Private key: K8s secret `hanzo-mpc-identity` key `event_initiator.key` (hex seed)
  - Public key: ConfigMap `event_initiator_pubkey`
  - Mounted at `/app/event_initiator.key` via subPath volumeMount
- **Node identity keys**: Per-node Ed25519 keys in identity secret
  - `hanzo-mpc-{N}_private.key` + `hanzo-mpc-{N}_identity.json`
- **MPC key shards**: BadgerDB at `/data/mpc/db/hanzo-mpc-{N}/` (PVC)

### Message Flow (verified working Feb 24 2026)
```
API → MPCClient.CreateWallet(walletID)
  → Ed25519 sign(GenerateKeyMessage)
  → JetStream publish to mpc.keygen_request.<walletID>
  → KeygenConsumer → PubSub mpc:generate
  → EventConsumer.VerifyInitiatorMessage() ✓
  → CGGMP21 DKG protocol (3 rounds) → ~16s
  → Result → mpc.mpc_keygen_result.<walletID>
  → WalletStore.handleKeygenResult() → status: active
```

### TODO: KMS-First Key Management
- Store event_initiator private key in KMS (kms.hanzo.ai)
- Store Ed25519 + ML-DSA-65 consensus signing keys in KMS
- Each node authenticates to KMS with Machine Identity
- Fetch key shards + dual consensus keys at runtime (never plaintext on disk)
- HSM abstraction (PKCS#11) for AWS CloudHSM / Azure HSM
- Node identity keys (Ed25519 + ML-DSA-65) also in KMS with encrypted backups
- Generate `{node}_pq_identity.json` and `{node}_pq_private.key` via `hanzo-mpc-cli generate-identity`

## Security Audit Findings (Jan 2026)

1. Protocol messages between nodes are NOT signed (Ed25519 code exists but disabled)
   **UPDATE (Mar 2026)**: ConsensusKV now signs all blocks and votes with Ed25519 identity keys
2. Deduplication `processing` map grows unbounded -- needs TTL cleanup
3. No timeout on protocol handlers -- needs context with deadline

## Policy Engine (`pkg/policy/`)

Fireblocks/Utila-style transaction governance:
- Signers and roles (ADMIN, SIGNER, VIEWER)
- Spending limits (per-tx, daily, monthly by asset)
- Whitelist/blacklist, time windows, rate limiting
- ThresholdVM (`pkg/threshold/policy_vm.go`): evaluates policies before signature shares
- FHE private policies via pluggable `FHEEngine` interface (compatible with luxfi/fhe)

## TFHE Integration (`pkg/mpc/tfhe_session.go`)

Threshold FHE via `luxfi/fhe v1.7.6`:

### Key Types
- `tfhe-uint{8,16,32,64,128,256}`, `tfhe-bool`, `tfhe-address`

### Sessions
- **tfheKeygenSession**: Trusted-dealer DKG → distributes key shares to MPC nodes
- **tfheComputeSession**: Load config → encrypt/decrypt/compute on encrypted data

### TFHE Policy Opcodes (ThresholdVM)
| Opcode | Name | Description |
|--------|------|-------------|
| 0x80 | PrivateAmountLT | Encrypted amount < encrypted threshold |
| 0x81 | PrivateAmountGT | Encrypted amount > encrypted threshold |
| 0x82 | PrivateCumulative | Encrypted cumulative spending check |
| 0x83 | PrivateWhitelist | Encrypted address whitelist check |

### Encrypted Policy State
```go
EncryptedPolicyState {
  CumulativeDaily   EncryptedUint64  // 24h spending (encrypted)
  CumulativeMonthly EncryptedUint64  // monthly spending (encrypted)
  LastTxTime        EncryptedUint64  // last tx timestamp (encrypted)
  VestedAmount      EncryptedUint64  // vesting state (encrypted)
  StreamedAmount    EncryptedUint64  // streaming state (encrypted)
}
```

### KMS-MPC-TFHE Integration (2026-03-11)

A new TFHE-KMS bridge was added to Hanzo KMS (`backend/src/services/tfhe/`):
- KMS stores TFHE key metadata + public key references
- Bridge triggers MPC keygen via NATS JetStream (`mpc.keygen_request.*`)
- MPC nodes run TFHE DKG, store shares in BadgerDB
- KMS receives public key via result queue
- Encryption uses public key (KMS-side, no MPC needed)
- Decryption requires t-of-n shares (MPC threshold decryption)
- Private policy evaluation runs on encrypted data (no plaintext exposure)
- Integrates with T-Chain precompile (`0x0700...0080`) for on-chain FHE

### T-Chain FHE Architecture
```
C-Chain (Contracts)  → Smart contracts with encrypted operations
         ↓ (emit DecryptionRequested)
T-Chain (Threshold)  → MPC nodes with TFHE/threshold protocols
         ↓ (callback with plaintext)
C-Chain (Results)    → Finality via contract callback
```

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
