# DEPRECATED — Use luxfi/mpc

`hanzoai/mpc` is **deprecated**. The canonical Lux MPC implementation lives at:

- **Code:** https://github.com/luxfi/mpc
- **Image:** `ghcr.io/luxfi/mpc` (the Hanzo ring runs `v1.17.32`)
- **Go module:** `github.com/luxfi/mpc`

All development happens upstream in `luxfi/mpc` — 860 commits there against
111 here, and the 3-node Hanzo ring pulls that image directly.

This repo is read-only. Earlier text here said it had been "archived as
`mpc-v1`"; it had not been archived, and no `mpc-v1` repo was ever created.

## Migration

| Old | New |
|---|---|
| `ghcr.io/hanzoai/mpc:*` | `ghcr.io/luxfi/mpc` |
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

## Where MPC is going

Lux is moving its decentralized MPC on-chain, onto the primary network.
Three VMs are already registered in `luxfi/node` (`node/vms.go`): `mpcvm`
— M-Chain, threshold signing and bridge custody — alongside `keyvm`
(K-Chain, key management) and `identityvm` (I-Chain). That is where the
protocol work lands.

A daemon is the other shape: a node ring an operator runs, centralized by
construction. The stated intent is that this centralized edition becomes
Hanzo's and lives here.

That has not happened, and this section is the direction rather than a
description of this repository. What is true today is what the rest of
this file already says: `pkg/mpc` holds a thin HTTP shim with no signing
in it, the ring pulls `ghcr.io/luxfi/mpc`, and nothing built here is
deployed anywhere. Delete this section when the code arrives, not before.
