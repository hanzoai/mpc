# Lux Bridge MPC Integration

This directory contains the bridge compatibility layer that allows the Lux Bridge to use Lux MPC (Go implementation) instead of the legacy Rust MPC implementation.

## Overview

The Lux Bridge currently uses KZen's `multi-party-ecdsa` Rust library for threshold signatures. This integration provides a compatibility layer that allows the bridge to seamlessly migrate to Lux MPC, which uses Lux's `threshold` Go implementation.

## Quick Start

### 1. Build and Start the Services

```bash
# Run the migration script
./migrate.sh

# Or manually:
docker-compose up -d
```

### 2. Update Bridge Configuration

In your bridge's `mpc.ts` file, update the MPC node endpoints:

```typescript
const mpc_nodes = [
  "http://bridge-compat-0:6000",
  "http://bridge-compat-1:6000",
  "http://bridge-compat-2:6000"
]
```

### 3. Test the Integration

```bash
# Check if compatibility endpoints are responding
curl http://localhost:6000/
curl http://localhost:6001/
curl http://localhost:6002/
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Bridge    │────▶│ Compatibility    │────▶│  Lux MPC    │
│   (Node.js) │     │ Layer (Port 6000)│     │ (Port 8080) │
└─────────────┘     └──────────────────┘     └─────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   NATS + Consul  │
                    │ (Messaging + SD)  │
                    └──────────────────┘
```

## Services

- **lux-mpc-[0,1,2]**: Core MPC nodes using threshold
- **bridge-compat-[0,1,2]**: Compatibility layers on port 6000
- **nats**: Message broker for MPC communication
- **consul**: Service discovery

## Key Differences

| Feature | Rust MPC (Current) | Lux MPC (New) |
|---------|-------------------|---------------|
| Protocol | GG18 | CGG21 |
| Storage | File-based | BadgerDB |
| Communication | Process spawning | NATS messaging |
| API | HTTP on port 6000 | gRPC + HTTP |

## Migration Steps

1. **Test in Parallel**: Run both implementations side-by-side
2. **Shadow Mode**: Send requests to both, compare signatures
3. **Canary Deployment**: Route 10% traffic to new implementation
4. **Full Migration**: Switch all traffic to Lux MPC

## Monitoring

```bash
# View logs
docker-compose logs -f bridge-compat-0

# Check MPC node health
curl http://localhost:8080/health

# Monitor NATS
curl http://localhost:8222/varz
```

## Troubleshooting

### Compatibility layer not responding
```bash
docker-compose restart bridge-compat-0
```

### MPC node issues
```bash
# Check logs
docker-compose logs lux-mpc-0

# Restart node
docker-compose restart lux-mpc-0
```

### Key generation needed
```bash
# Use lux-mpc-cli to trigger key generation
docker exec -it lux-mpc-0 lux-mpc-cli keygen
```

## Security Considerations

1. **Key Migration**: Existing Rust keys need to be converted to threshold format
2. **Signature Compatibility**: Both implementations produce standard ECDSA signatures
3. **Network Security**: Ensure proper TLS configuration in production

## Performance

Expected improvements with Lux MPC:
- 30% faster signature generation (CGG21 vs GG18)
- Better resource utilization (Go vs Rust process spawning)
- Improved monitoring and observability

## Next Steps

1. Complete key migration tool implementation
2. Add comprehensive integration tests
3. Performance benchmarking
4. Security audit of the compatibility layer