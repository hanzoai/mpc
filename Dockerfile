# syntax=docker/dockerfile:1
#
# Hanzo MPC — sovereign wrapper over the canonical luxfi/mpc binary.
#
# Sovereign version tag MIRRORS the wrapped upstream: hanzoai/mpc:1.17.15 ==
# luxfi/mpc:1.17.15, which carries the CGGMP21 keygen-degree fix (luxfi/mpc
# 1e1d318): runNodeConsensus now wires --threshold into viper "mpc_threshold"
# so the keygen polynomial degree = threshold-1. hanzo-mpc runs --threshold=2 →
# degree 1 → genuine 2-of-3 (was degree 0 = 1-of-3: any single node could sign).
#
# Why wrap instead of source-build: luxfi/mpc is a PRIVATE repo, so the previous
# `git clone github.com/luxfi/mpc` build step cannot authenticate in the ARC
# buildkit sandbox. The pre-built image lives in GHCR (CI has pull access), and
# is the exact binary proven live on zoo-mpc (5/5). The Hanzo deployment drives
# explicit flags (--node-id/--listen/--api/--data/--threshold/--peer), so the
# upstream binary's compile-time defaults are overridden at runtime; org identity
# is runtime (keygen org_id=hanzo). Patch-pin only, never :latest.
#
# The in-repo cmd/mpcd source (Hanzo-branded mirror of luxfi cmd/mpcd, incl. the
# same threshold fix) is retained for local dev / parity; it is NOT what ships.
FROM ghcr.io/luxfi/mpc:v1.17.15
LABEL org.opencontainers.image.source="https://github.com/hanzoai/mpc"
ENV MPC_ORG=hanzo
