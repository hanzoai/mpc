# Bridge Integration Guide: Migrating from Rust to Go MPC

## Overview

This document outlines the strategy for replacing the Rust-based MPC implementation in the Lux Bridge with the new Go-based Lux MPC implementation.

## Current Architecture Analysis

### Bridge MPC Implementation (Rust)
The bridge currently uses **KZen's multi-party-ecdsa** (v0.8.1) Rust library:

#### Key Components:
1. **MPC Nodes**: Node.js wrapper around Rust binaries
   - Location: `/mpc-nodes/docker/common/node/`
   - Spawns Rust processes for key generation and signing
   - Uses HTTP API on port 6000

2. **Rust Binaries**:
   - Key Generation: `gg18_keygen_client`
   - Signing: `gg18_sign_client`
   - State Manager: `gg18_sm_manager`

3. **Process Management**:
   ```typescript
   // Spawning signing process
   const cmd = `./target/release/examples/${signClientName} ${signSmManager} ${keyStore} ${msgHash}`
   await exec(cmd, { cwd: __dirname + "/multiparty", shell: "/bin/bash" })
   ```

4. **Storage**: Files on disk (`keys.store`)

### Lux MPC Implementation (Go)
The new implementation uses **Lux's threshold** (v2.0.2) Go library:

#### Key Components:
1. **MPC Nodes**: Full Go implementation with gRPC/REST APIs
   - Binary: `lux-mpc`
   - Uses NATS JetStream for messaging
   - BadgerDB for encrypted storage

2. **Protocol**: CGG21 (improved from GG18)
   - Better security properties
   - More efficient communication

3. **Features**:
   - Built-in service discovery (Consul)
   - Automatic session management
   - Encrypted key storage
   - Comprehensive monitoring

## Architecture Differences

| Component | Bridge (Rust) | Lux MPC (Go) |
|-----------|---------------|--------------|
| Protocol | GG18 | CGG21 |
| Language | Rust + Node.js wrapper | Pure Go |
| Communication | HTTP + file-based | NATS JetStream |
| Storage | File system | BadgerDB (encrypted) |
| Service Discovery | Hard-coded | Consul |
| Session Management | Process-based | Built-in registry |
| Key Format | KZen proprietary | threshold standard |

## Migration Strategy

### Phase 1: API Compatibility Layer
Create a compatibility layer that mimics the bridge's HTTP API:

```go
// compatibility/bridge_api.go
package compatibility

import (
    "net/http"
    "github.com/luxfi/lux-mpc/pkg/client"
)

// BridgeCompatServer provides backward compatibility with bridge API
type BridgeCompatServer struct {
    mpcClient *client.Client
}

// POST /api/v1/generate_mpc_sig
func (s *BridgeCompatServer) GenerateMPCSig(w http.ResponseWriter, r *http.Request) {
    // Parse bridge request format
    // Convert to Lux MPC signing request
    // Return response in bridge format
}

// POST /api/v1/complete
func (s *BridgeCompatServer) CompleteSwap(w http.ResponseWriter, r *http.Request) {
    // Handle swap completion
}
```

### Phase 2: Key Migration
Convert existing KZen key shares to threshold format:

```go
// migration/key_converter.go
package migration

// ConvertKZenKeyToTSSLib converts KZen multi-party-ecdsa keys to threshold format
func ConvertKZenKeyToTSSLib(kzenKeyPath string) (*ecdsa.LocalPartySaveData, error) {
    // 1. Parse KZen key format
    // 2. Extract private share, public key, and other parameters
    // 3. Reconstruct in threshold format
    // 4. Validate the conversion
}
```

### Phase 3: Docker Integration
Update bridge deployment to use Lux MPC:

```yaml
# docker-compose.yaml
services:
  mpc-node-0:
    image: luxfi/lux-mpc:latest
    environment:
      - LUX_MPC_CONFIG=/config/config.yaml
      - NODE_ID=0
    volumes:
      - ./config:/config
      - mpc-data-0:/data
    ports:
      - "6000:6000"  # Bridge compatibility API
      - "8080:8080"  # Lux MPC API
```

### Phase 4: Gradual Rollout
1. **Test Environment**: Deploy Lux MPC alongside existing Rust nodes
2. **Shadow Mode**: Run both implementations, compare signatures
3. **Canary Deployment**: Route small percentage of traffic
4. **Full Migration**: Complete switchover

## Implementation Steps

### 1. Create Bridge Compatibility Package
```bash
cd /Users/z/work/lux/mpc
mkdir -p pkg/bridge
```

Create compatibility server that translates bridge API calls to Lux MPC operations.

### 2. Implement Key Migration Tool
```bash
cd cmd
mkdir lux-mpc-migrate
```

Tool to convert existing KZen keys to threshold format.

### 3. Update Bridge Configuration
Modify bridge's `mpc.ts` to support both implementations:

```typescript
const mpc_nodes = process.env.USE_NEW_MPC === 'true' 
  ? [
      "http://lux-mpc-0:6000",  // New Go implementation
      "http://lux-mpc-1:6000"
    ]
  : [
      "http://mpc-node-0:6000", // Legacy Rust implementation
      "http://mpc-node-1:6000"
    ]
```

### 4. Testing Strategy
1. **Unit Tests**: Test key conversion accuracy
2. **Integration Tests**: Verify API compatibility
3. **End-to-End Tests**: Full bridge transaction flow
4. **Performance Tests**: Compare latency and throughput
5. **Security Audit**: Verify signature validity

## Risk Mitigation

### 1. Signature Compatibility
- Both implementations use ECDSA on secp256k1
- Signatures are standard and interchangeable
- Risk: Different deterministic nonce generation
- Mitigation: Extensive signature validation testing

### 2. Key Share Format
- Risk: Incompatible key representations
- Mitigation: Thorough key migration testing with test vectors

### 3. Network Coordination
- Risk: Protocol mismatch during transition
- Mitigation: Run parallel networks during migration

### 4. Performance Impact
- Risk: Go implementation might have different performance characteristics
- Mitigation: Comprehensive benchmarking before production

## Benefits of Migration

1. **Unified Stack**: Single Go codebase for all MPC operations
2. **Better Monitoring**: Built-in metrics and tracing
3. **Improved Security**: CGG21 protocol enhancements
4. **Easier Maintenance**: No need for Rust toolchain
5. **Better Integration**: Native Go integration with Lux ecosystem
6. **Enhanced Features**: Resharing, key refresh, batch signing

## Timeline Estimate

- **Week 1-2**: Implement compatibility layer
- **Week 3-4**: Key migration tool and testing
- **Week 5-6**: Integration testing
- **Week 7-8**: Canary deployment and monitoring
- **Week 9-10**: Full production rollout

## Conclusion

The migration from Rust (KZen) to Go (threshold) MPC implementation is achievable with careful planning. The compatibility layer approach allows for gradual migration with minimal risk to the bridge operations.

Key success factors:
1. Maintain API compatibility during transition
2. Thoroughly test key migration
3. Run parallel implementations for validation
4. Monitor performance and security metrics
5. Have rollback plan ready

The end result will be a more maintainable, feature-rich, and integrated MPC solution for the Lux Bridge.