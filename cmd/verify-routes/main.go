// verify-routes spins up an in-process MPC API server with nil deps to
// exercise the actual route table (handleLanding via landing.Handler,
// /v1/mpc/health no-auth, /v1/mpc/wallets through IAM middleware) end to
// end on a real HTTP socket. No NATS, no consensus — just the handler
// tree as compiled.
//
// Used by the local verification flow in lieu of bootstrapping a real
// 3-node BFT cluster on a laptop. Not a production binary.
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/hanzoai/mpc/pkg/api"
)

func main() {
	srv := api.NewServer(api.Config{
		Port:        8082,
		IAMEndpoint: "http://localhost:8000",
	})
	fmt.Println("verify-routes listening :8082 (no NATS, no KV)")
	if err := srv.Start(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
