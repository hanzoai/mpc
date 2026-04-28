# Migration Guide — hanzo/mpc → HANZO_BINARY shape

Per `~/work/hanzo/HANZO_BINARY.md`, hanzo/mpc now follows the canonical
Hanzo Go binary architecture. One breaking change ships in this revision.

## Breaking change: `OrgID` body field removed

The internal API (`:9800`) `/keygen` endpoint **no longer accepts**
`org_id` as a JSON body field. Identity is read from the `X-Org-Id`
HTTP header populated by `hanzoai/gateway` after IAM JWT validation.

### Before

```bash
curl -X POST http://mpcd-0.mpc:9800/keygen \
  -H 'Authorization: Bearer ${MPC_INTERNAL_API_KEY}' \
  -H 'Content-Type: application/json' \
  -d '{"org_id": "hanzo", "wallet_id": "w-123"}'
```

### After

```bash
curl -X POST http://mpcd-0.mpc:9800/keygen \
  -H 'Authorization: Bearer ${MPC_INTERNAL_API_KEY}' \
  -H 'X-Org-Id: hanzo' \
  -H 'X-User-Id: user-7' \
  -H 'X-User-Email: z@hanzo.ai' \
  -H 'Content-Type: application/json' \
  -d '{"wallet_id": "w-123"}'
```

### Why

Reading the org from a body field is a forgery vector: any caller with
the bearer token could impersonate any tenant. The gateway-validated
`X-Org-Id` header is the single canonical identity source — same model
hanzoai/tasks already uses.

The audit log preserves the `orgID` field semantics; the value now comes
from request context (set by `pkg/auth/middleware.go`) instead of the
request body.

## New: pkg/mpc.Embed() contract

The fusion-binary contract from HANZO_BINARY.md is wired:

```go
import mpcpkg "github.com/hanzoai/mpc/pkg/mpc"

srv, err := mpcpkg.Embed(ctx, mpcpkg.EmbedConfig{
    DataDir:  "/data/mpcd",
    HTTPAddr: ":8081",
    ZAPPort:  9999,
    NodeID:   "mpcd-0",
})
defer srv.Stop(ctx)

httpSrv := &http.Server{
    Addr:    ":8081",
    Handler: mpcpkg.BuildHTTP(srv, "mpcd-0", os.Getenv("MPCD_REQUIRE_IDENTITY") == "true"),
}
```

Singleton-guarded via `mpc.ErrAlreadyEmbedded`.

## New: identity middleware

`pkg/auth.RequireIdentity(require bool)` reads `X-Org-Id`, `X-User-Id`,
`X-User-Email` from request headers and binds them to ctx. Accessors:
`auth.OrgID(ctx)`, `auth.UserID(ctx)`, `auth.UserEmail(ctx)`.

Set `MPCD_REQUIRE_IDENTITY=true` in production (the K8s deployment
manifest does this). Default is `false` for solo-mode dev.

## Run modes

| Mode | Command | Behaviour |
|---|---|---|
| Embedded (thin) | `mpcd --http :8081 --data ./mpcd-data` | Serves `/healthz`, `/v1/mpc/health`, `/_/mpc/*` (UI shell). No NATS, no consensus. |
| Consensus (production) | `mpcd consensus start --node-id mpcd-0 --data /data --peer …` | Full luxfi/mpc consensus runtime: NATS, KV, threshold signing. |

Same binary. Subcommand selects the path.
