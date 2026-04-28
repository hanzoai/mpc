// Copyright © 2026 Hanzo AI. MIT License.
//
// mpcd is the Hanzo MPC daemon. One Go binary, native consensus
// transport, IAM-fronted admin UI. The default boot path is the thin
// pkg/mpc.Embed contract: a developer or fused-binary host gets a
// running node with /healthz and the embedded UI shell at /_/mpc/ —
// no consensus cluster, no NATS, no flags. The full luxfi/mpc
// consensus runtime is opt-in via the `consensus` subcommand (see
// runConsensus in consensus.go) and is what production runs.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	mpcpkg "github.com/hanzoai/mpc/pkg/mpc"
)

func main() {
	// Subcommand routing: `mpcd consensus …` runs the heavy luxfi/mpc
	// consensus path (urfave/cli v3 inside consensus.go); everything
	// else runs the thin Embed shape.
	if len(os.Args) > 1 && os.Args[1] == "consensus" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		runConsensus()
		return
	}

	var (
		httpAddr = flag.String("http", envStr("MPCD_HTTP_ADDR", ":8081"), "HTTP listen address (admin UI + JSON shim)")
		zapPort  = flag.Int("zap-port", envInt("MPCD_ZAP_PORT", 9999), "P2P consensus listener port")
		dataDir  = flag.String("data", envStr("MPCD_DATA_DIR", "/data/mpcd"), "Persistence directory")
		nodeID   = flag.String("node-id", envStr("MPCD_NODE_ID", "mpcd-embed"), "Node identity")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := mpcpkg.Embed(ctx, mpcpkg.EmbedConfig{
		DataDir:  *dataDir,
		HTTPAddr: *httpAddr,
		ZAPPort:  *zapPort,
		NodeID:   *nodeID,
		Logger:   logger,
	})
	if err != nil {
		logger.Error("mpc.Embed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = srv.Stop(context.Background()) }()
	logger.Info("zap listener", "port", srv.ZAPPort(), "service", "_mpc._tcp")

	requireID := envBool("MPCD_REQUIRE_IDENTITY", false)
	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           mpcpkg.BuildHTTP(srv, *nodeID, requireID),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("http listener", "addr", *httpAddr, "require_identity", requireID)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}
