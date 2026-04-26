# DEPRECATED — Use luxfi/mpc

`hanzoai/mpc` is **deprecated**. The canonical Lux MPC implementation lives at:

- **Code:** https://github.com/luxfi/mpc
- **Image:** `ghcr.io/luxfi/mpc:v1.10.0` (latest semver)
- **Go module:** `github.com/luxfi/mpc`

This repo is archived as `mpc-v1` for historical reference. All new
development happens upstream in `luxfi/mpc`.

## Migration

| Old | New |
|---|---|
| `ghcr.io/hanzoai/mpc:*` | `ghcr.io/luxfi/mpc:v1.10.0` |
| `github.com/hanzoai/mpc` (Go import) | `github.com/luxfi/mpc` |
| `hanzo-mpc` binary | `mpcd` (daemon) |
| `hanzo-mpc-cli` binary | `mpc` (CLI) |

For service discovery, use canonical DNS:

- `zap.mpc.svc.cluster.local:9999` — ZAP transport (in-cluster)
- `mpc-node-headless.lux-mpc.svc:9999` — direct peer access

## Why

Single canonical implementation. One way to do everything. No parallel
forks. The previous `hanzoai/mpc` was a thin wrapper that drifted from
upstream over time — every wrapper API drift was a foot-gun. Using
`luxfi/mpc` directly removes the drift class entirely.
