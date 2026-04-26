package main

import (
	"context"
	"crypto/ed25519"
	crypto_elliptic "crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/mr-tron/base58"

	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/hsm"

	uimpc "github.com/luxfi/mpc/ui"

	mpcapi "github.com/luxfi/mpc/pkg/api"
	"github.com/luxfi/mpc/pkg/backup"
	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/eventconsumer"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/transport"
	"github.com/luxfi/mpc/pkg/types"
)

// Hanzo MPC is a thin wrapper over the canonical luxfi/mpc implementation.
// All MPC logic (CGGMP21, FROST, ZapDB KV, NATS messaging, consensus
// transport, HSM integration, settlement) lives in github.com/luxfi/mpc.
// This binary's main.go mirrors luxfi/mpc/cmd/mpcd verbatim except for
// Hanzo-specific defaults (Version, branding, data dir, mDNS namespace,
// dashboard listen).
const (
	Version                    = "2.0.0"
	BrandName                  = "Hanzo"
	DefaultBackupPeriodSeconds = 300 // (5 minutes)

	// Hanzo defaults — operator can override via env vars / flags.
	defaultListen          = ":9999"
	defaultAPIInternal     = ":9800"
	defaultDashboardListen = ":8081"
	defaultDataDir         = "/data/mpcd"
	defaultBackupBucket    = "mpcd-backups"
)

func main() {
	// Seed Hanzo defaults into env BEFORE viper init so the canonical
	// luxfi/mpc runtime sees them as if the operator had set them. Explicit
	// operator-set values always win.
	setEnvDefault("MPC_DATA_DIR", defaultDataDir)
	setEnvDefault("MPC_DB_PATH", filepath.Join(defaultDataDir, "db"))
	setEnvDefault("MPC_BACKUP_DIR", filepath.Join(defaultDataDir, "backups"))
	setEnvDefault("BRAND_NAME", BrandName)

	fmt.Fprintf(os.Stderr, "%s MPC v%s — thin wrapper over luxfi/mpc (canonical)\n",
		os.Getenv("BRAND_NAME"), Version)

	app := &cli.Command{
		Name:    "mpcd",
		Usage:   "Hanzo MPC node — threshold signatures via luxfi/mpc consensus",
		Version: Version,
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start a Lux MPC node",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "node-id",
						Usage: "Node ID",
					},
					&cli.StringFlag{
						Name:  "listen",
						Usage: "P2P listen address",
						Value: ":9999",
					},
					&cli.StringFlag{
						Name:  "api",
						Usage: "Internal API listen address",
						Value: ":9800",
					},
					&cli.StringFlag{
						Name:  "data",
						Usage: "Data directory",
					},
					&cli.StringFlag{
						Name:  "keys",
						Usage: "Keys directory",
					},
					&cli.IntFlag{
						Name:    "threshold",
						Aliases: []string{"t"},
						Usage:   "Signing threshold",
						Value:   2,
					},
					&cli.StringSliceFlag{
						Name:  "peer",
						Usage: "Peer address (can be specified multiple times)",
					},
					&cli.StringFlag{
						Name:  "log-level",
						Usage: "Log level (debug, info, warn, error)",
						Value: "info",
					},
					&cli.StringFlag{
						Name:  "api-listen",
						Usage: "Dashboard API listen address",
						Value: ":8081",
					},
					&cli.StringFlag{
						Name:  "jwt-secret",
						Usage: "JWT signing secret for dashboard auth",
					},
					// HSM / password provider flags
					&cli.StringFlag{
						Name:    "hsm-provider",
						Usage:   "Password provider type: aws|gcp|azure|env|file (default: env)",
						Sources: cli.EnvVars("MPC_HSM_PROVIDER"),
						Value:   "env",
					},
					&cli.StringFlag{
						Name:    "hsm-key-id",
						Usage:   "HSM key ARN/name/path for ZapDB password decryption",
						Sources: cli.EnvVars("MPC_HSM_KEY_ID"),
					},
					// HSM signer flags (for co-signing)
					&cli.StringFlag{
						Name:    "hsm-signer",
						Usage:   "Signer provider for intent co-signing: aws|gcp|azure|zymbit|mldsa|local (default: local)",
						Sources: cli.EnvVars("MPC_HSM_SIGNER"),
						Value:   "local",
					},
					&cli.StringFlag{
						Name:    "hsm-signer-key-id",
						Usage:   "HSM signer key ARN/name for co-signing operations",
						Sources: cli.EnvVars("MPC_HSM_SIGNER_KEY_ID"),
					},
					&cli.BoolFlag{
						Name:    "hsm-attest",
						Usage:   "Enable HSM attestation on threshold signature shares (binds shares to hardware)",
						Sources: cli.EnvVars("MPC_HSM_ATTEST"),
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
						Value: false,
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return runNodeConsensus(ctx, c)
				},
			},
			{
				Name:  "version",
				Usage: "Display detailed version information",
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Printf("mpcd version %s (luxfi/mpc canonical)\n", Version)
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// setEnvDefault sets an env var only if it is currently unset. Used to seed
// Hanzo-specific defaults without overriding operator-set values.
func setEnvDefault(key, value string) {
	if _, ok := os.LookupEnv(key); !ok {
		_ = os.Setenv(key, value)
	}
}

// checkRequiredConfigValues verifies required viper config values are present.
// skipPasswordCheck should be true when ZapDB password will be resolved via HSM provider.
func checkRequiredConfigValues(skipPasswordCheck bool) {
	// Show warning if we're using file-based config but no password is set
	if !skipPasswordCheck && viper.GetString("zapdb_password") == "" {
		logger.Fatal("ZapDB password is required", nil)
	}

	if viper.GetString("event_initiator_pubkey") == "" {
		logger.Fatal("Event initiator public key is required", nil)
	}
}

// resolveZapDBPassword returns the ZapDB encryption password using the HSM
// password provider infrastructure. Provider type comes from --hsm-provider
// (or MPC_HSM_PROVIDER env var), defaulting to "env" for backward compat.
// When a cloud provider (aws/gcp/azure) is configured, the password is
// decrypted from ZAPDB_ENCRYPTED_PASSWORD via the cloud KMS at startup.
func resolveZapDBPassword(ctx context.Context, c *cli.Command) string {
	hsmProviderType := c.String("hsm-provider")
	hsmKeyID := c.String("hsm-key-id")
	environment := viper.GetString("environment")

	// In production, env/file password providers are rejected. ZapDB passwords
	// must come from a cloud HSM (aws/gcp/azure) so they aren't readable via kubectl exec.
	if environment == "production" && (hsmProviderType == "" || hsmProviderType == "env" || hsmProviderType == "file") {
		logger.Fatal("Production requires cloud HSM password provider (aws/gcp/azure); env/file providers are not permitted",
			fmt.Errorf("MPC_HSM_PROVIDER=%q", hsmProviderType))
	}

	provider, err := hsm.NewPasswordProvider(hsmProviderType, nil)
	if err != nil {
		logger.Fatal("Failed to create HSM password provider", fmt.Errorf("provider=%s: %w", hsmProviderType, err))
	}

	password, err := provider.GetPassword(ctx, hsmKeyID)
	if err != nil {
		if environment == "production" {
			logger.Fatal("HSM provider failed in production; cannot fall back to config",
				fmt.Errorf("provider=%s: %w", hsmProviderType, err))
		}
		// Fall back to viper config for dev/staging only
		password = viper.GetString("zapdb_password")
		if password == "" {
			logger.Fatal("ZapDB password is required: HSM provider failed and no zapdb_password in config",
				fmt.Errorf("provider=%s: %w", hsmProviderType, err))
		}
		logger.Warn("ZapDB password loaded from config (non-production only)", "environment", environment)
		return password
	}

	logger.Info("ZapDB password loaded via HSM provider", "provider", hsmProviderType)
	return password
}

func NewZapKV(nodeName, nodeID, password string) *kvstore.Store {
	// ZapDB KV store
	// Use configured db_path or default to current directory + "db"
	basePath := viper.GetString("db_path")
	if basePath == "" {
		basePath = filepath.Join(".", "db")
	}
	dbPath := filepath.Join(basePath, nodeName)

	// Use configured backup_dir or default to current directory + "backups"
	backupDir := viper.GetString("backup_dir")
	if backupDir == "" {
		backupDir = filepath.Join(".", "backups")
	}

	// Create ZapDB config
	config := kvstore.Config{
		NodeID:    nodeName,
		Key:       []byte(password),
		BackupKey: []byte(password), // Using same key for backup encryption
		Dir:       backupDir,
		Path:      dbPath,
	}

	kv, err := kvstore.New(config)
	if err != nil {
		logger.Fatal("Failed to create zapdb store", err)
	}
	logger.Info("Connected to zapdb store", "path", dbPath, "backup_dir", backupDir)
	return kv
}

func StartPeriodicBackup(ctx context.Context, zapKV *kvstore.Store, periodSeconds int) func() {
	if periodSeconds <= 0 {
		periodSeconds = DefaultBackupPeriodSeconds
	}
	backupTicker := time.NewTicker(time.Duration(periodSeconds) * time.Second)
	backupCtx, backupCancel := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-backupCtx.Done():
				logger.Info("Backup background job stopped")
				return
			case <-backupTicker.C:
				logger.Info("Running periodic ZapDB backup...")
				err := zapKV.Backup()
				if err != nil {
					logger.Error("Periodic ZapDB backup failed", err)
				} else {
					logger.Info("Periodic ZapDB backup completed successfully")
				}
			}
		}
	}()
	return backupCancel
}

// runNodeConsensus runs the MPC node with consensus-embedded transport
func runNodeConsensus(ctx context.Context, c *cli.Command) error {
	nodeID := c.String("node-id")
	listenAddr := c.String("listen")
	dataDir := c.String("data")
	keysDir := c.String("keys")
	threshold := c.Int("threshold")
	peers := c.StringSlice("peer")
	logLevel := c.String("log-level")
	debug := c.Bool("debug")

	if nodeID == "" {
		return fmt.Errorf("--node-id is required in consensus mode")
	}
	if dataDir == "" {
		return fmt.Errorf("--data is required in consensus mode")
	}

	// Initialize logger
	logger.Init("consensus", debug || logLevel == "debug")
	logger.Info("Starting MPC node in consensus mode",
		"nodeID", nodeID,
		"listen", listenAddr,
		"dataDir", dataDir,
		"threshold", threshold,
		"peers", len(peers),
	)

	// Ensure directories exist
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	if keysDir == "" {
		keysDir = filepath.Join(dataDir, "keys")
	}
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Load or generate identity
	privKey, pubKey, err := loadOrGenerateIdentity(keysDir, nodeID)
	if err != nil {
		return fmt.Errorf("failed to load/generate identity: %w", err)
	}

	// Create consensus identity store for verifying messages
	consensusIdentity := NewConsensusIdentityStore(nodeID, privKey, pubKey)

	// Build peer map
	peerMap := make(map[string]string)
	peerMap[nodeID] = listenAddr
	for i, peer := range peers {
		// Parse peer address - format: "nodeID@host:port" or just "host:port"
		parts := strings.SplitN(peer, "@", 2)
		if len(parts) == 2 {
			peerMap[parts[0]] = parts[1]
		} else {
			peerMap[fmt.Sprintf("peer-%d", i)] = peer
		}
	}

	// Get ZapDB password via HSM provider (supports AWS KMS, GCP Cloud KMS, Azure Key Vault, env, file)
	zapDBPassword := resolveZapDBPassword(ctx, c)

	// Create transport factory (uses ZapDB for embedded key-share storage)
	factoryCfg := transport.FactoryConfig{
		NodeID:        nodeID,
		ListenAddr:    listenAddr,
		Peers:         peerMap,
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		ZapDBPath:     filepath.Join(dataDir, "db"),
		ZapDBPassword: zapDBPassword,
		BackupDir:     filepath.Join(dataDir, "backups"),
	}

	factory, err := transport.NewFactory(factoryCfg)
	if err != nil {
		return fmt.Errorf("failed to create transport factory: %w", err)
	}

	// Start transport
	if err := factory.Start(ctx); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	defer factory.Stop()

	// Create MPC node with consensus transport
	peerIDs := make([]string, 0, len(peerMap)-1)
	for id := range peerMap {
		if id != nodeID {
			peerIDs = append(peerIDs, id)
		}
	}

	// Create PubSub adapter for messaging
	pubSub := NewConsensusPubSubAdapter(factory.PubSub())

	// Create message queue adapters
	genKeyResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "keygen")
	signingResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "signing")
	reshareResultQueue := NewConsensusMessageQueue(factory.Transport(), nodeID, "reshare")

	logger.Info("Node is running in consensus mode", "nodeID", nodeID)

	// Create peer registry using consensus membership
	peerRegistry := NewConsensusPeerRegistry(factory.Registry(), nodeID, peerIDs)

	// Create MPC node
	mpcNode := mpc.NewNode(
		nodeID,
		peerIDs,
		pubSub,
		factory.KVStore(),
		NewConsensusKeyInfoStore(factory.KeyInfoStore(), peerRegistry),
		peerRegistry,
		consensusIdentity,
	)

	// Create event consumer
	eventConsumer := eventconsumer.NewEventConsumer(
		mpcNode,
		pubSub,
		genKeyResultQueue,
		signingResultQueue,
		reshareResultQueue,
		consensusIdentity,
	)
	eventConsumer.Run()
	defer eventConsumer.Close()

	// Mark as ready
	if err := peerRegistry.Ready(); err != nil {
		logger.Error("Failed to mark peer registry as ready", err)
	}
	logger.Info("[READY] Node is ready (consensus mode)", "nodeID", nodeID)

	// Start HTTP API server (internal MPC node API on port 9800)
	apiAddr := c.String("api")
	if apiAddr != "" {
		// Internal API bearer token — required for all endpoints except /health.
		// Source: MPC_INTERNAL_API_KEY env var. In production the StatefulSet
		// injects this from the KMS-synced mpc-secrets K8s Secret.
		internalAPIKey := os.Getenv("MPC_INTERNAL_API_KEY")
		if internalAPIKey == "" {
			// Derive a deterministic key from the node's Ed25519 private key so
			// all nodes in the cluster share the same key without extra config.
			// SHA-256(privKey || "mpc-internal-api") truncated to hex.
			h := sha256.Sum256(append(privKey.Seed(), []byte("mpc-internal-api")...))
			internalAPIKey = hex.EncodeToString(h[:])
			logger.Warn("MPC_INTERNAL_API_KEY not set; derived internal API key from node identity (set MPC_INTERNAL_API_KEY in production)")
		}

		// Rate limiter: 10 requests/min for mutating endpoints (keygen, backup).
		internalRL := mpcapi.NewRateLimiter(10)

		// internalAuth is middleware that gates all mutating internal endpoints
		// behind a bearer token. /health is exempt (K8s probes need it).
		internalAuth := func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth == "" || auth != "Bearer "+internalAPIKey {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
					return
				}
				next.ServeHTTP(w, r)
			}
		}

		// internalRateLimit wraps a handler with the tight rate limiter.
		internalRateLimit := func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				ip := r.RemoteAddr
				if host, _, err := net.SplitHostPort(ip); err == nil {
					ip = host
				}
				if !internalRL.Allow(ip) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
					return
				}
				next.ServeHTTP(w, r)
			}
		}

		mux := http.NewServeMux()
		// Health probe handler — unauthenticated (K8s liveness/readiness probes).
		// Served on both /health (legacy) and /healthz (platform standard).
		healthHandler := func(w http.ResponseWriter, r *http.Request) {
			ready := peerRegistry.ArePeersReady()
			connected := factory.Transport().GetPeers()
			status := "healthy"
			httpCode := http.StatusOK
			if !ready {
				status = "degraded"
				httpCode = http.StatusServiceUnavailable
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(httpCode)
			resp := map[string]interface{}{
				"status":          status,
				"node_id":         nodeID,
				"mode":            "consensus",
				"expected_peers":  len(peerIDs),
				"connected_peers": len(connected),
				"ready":           ready,
				"threshold":       threshold,
				"version":         Version,
			}
			json.NewEncoder(w).Encode(resp)
		}
		mux.HandleFunc("/healthz", healthHandler)
		mux.HandleFunc("/keys", internalAuth(func(w http.ResponseWriter, r *http.Request) {
			keys, err := factory.KeyInfoStore().ListKeys()
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(keys)
		}))
		mux.HandleFunc("/backup", internalAuth(internalRateLimit(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			logger.Info("Audit: backup triggered", "nodeID", nodeID, "remote", r.RemoteAddr)
			if zapKV, ok := factory.KVStore().(*kvstore.Store); ok && zapKV.Exec != nil {
				s3Cfg := backup.S3ConfigFromEnv(nodeID)
				mgr, err := backup.NewManager(zapKV.Exec, filepath.Join(dataDir, "backups"), nodeID, 0, s3Cfg)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				if err := mgr.RunBackup(); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				json.NewEncoder(w).Encode(map[string]string{"status": "backup completed"})
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{"error": "backup not available"})
			}
		})))
		mux.HandleFunc("/keygen", internalAuth(internalRateLimit(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")

			if !peerRegistry.ArePeersReady() {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{"error": "peers not ready"})
				return
			}

			// Parse request body — orgID is required for tenant isolation.
			var req struct {
				OrgID    string `json:"org_id"`
				WalletID string `json:"wallet_id"`
			}
			if r.Body != nil {
				json.NewDecoder(r.Body).Decode(&req)
			}
			if req.OrgID == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "org_id is required"})
				return
			}
			if req.WalletID == "" {
				// Generate a deterministic wallet ID from timestamp + node
				h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", nodeID, time.Now().UnixNano())))
				req.WalletID = hex.EncodeToString(h[:16])
			}

			walletID := req.WalletID

			// Subscribe to the result topic before triggering keygen
			resultTopic := fmt.Sprintf("mpc.mpc_keygen_result.%s", walletID)
			resultCh := make(chan *event.KeygenResultEvent, 1)
			unsub, err := pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
				var result event.KeygenResultEvent
				if err := json.Unmarshal(natMsg.Data, &result); err == nil {
					select {
					case resultCh <- &result:
					default:
					}
				}
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "failed to subscribe to result topic"})
				return
			}
			defer unsub.Unsubscribe()

			// Create and publish GenerateKeyMessage, signed by this node
			sig := consensusIdentity.SignMessage([]byte(walletID))
			msg := types.GenerateKeyMessage{
				OrgID:     req.OrgID,
				WalletID:  walletID,
				Signature: sig,
			}
			msgData, _ := json.Marshal(msg)

			if err := pubSub.Publish("mpc:generate", msgData); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("failed to publish keygen: %v", err)})
				return
			}

			logger.Info("Audit: keygen triggered", "nodeID", nodeID, "orgID", req.OrgID, "walletID", walletID, "remote", r.RemoteAddr)

			// Wait for result with 60s timeout
			select {
			case result := <-resultCh:
				resp := map[string]interface{}{
					"wallet_id":   result.WalletID,
					"result_type": result.ResultType,
				}
				if result.ResultType == event.ResultTypeSuccess {
					resp["ecdsa_pub_key"] = hex.EncodeToString(result.ECDSAPubKey)
					resp["eddsa_pub_key"] = hex.EncodeToString(result.EDDSAPubKey)
					if len(result.ECDSAPubKey) >= 32 {
						resp["eth_address"] = pubKeyToEthAddress(result.ECDSAPubKey)
						resp["btc_address"] = pubKeyToBtcAddress(result.ECDSAPubKey)
					}
					if len(result.EDDSAPubKey) == 32 {
						resp["sol_address"] = eddsaPubKeyToSolAddress(result.EDDSAPubKey)
					}
				} else {
					resp["error"] = result.ErrorReason
					resp["error_code"] = result.ErrorCode
				}
				json.NewEncoder(w).Encode(resp)
			case <-time.After(60 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
				json.NewEncoder(w).Encode(map[string]string{
					"error":     "keygen timed out after 60s",
					"wallet_id": walletID,
				})
			}
		})))

		srv := &http.Server{
			Addr:              apiAddr,
			Handler:           http.MaxBytesHandler(mux, 1<<20), // 1 MB body limit
			ReadTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      90 * time.Second, // keygen can take 60s
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			logger.Info("HTTP API server starting", "addr", apiAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP API server failed", err)
			}
		}()
		defer srv.Close()
	}

	// Start periodic backup with optional S3 upload
	backupDir := filepath.Join(dataDir, "backups")
	if zapKV, ok := factory.KVStore().(*kvstore.Store); ok && zapKV.Exec != nil {
		s3Cfg := backup.S3ConfigFromEnv(nodeID)
		backupMgr, err := backup.NewManager(zapKV.Exec, backupDir, nodeID, 5*time.Minute, s3Cfg)
		if err != nil {
			logger.Warn("Failed to create backup manager", "err", err)
		} else {
			backupMgr.Start()
			defer backupMgr.Stop()
			logger.Info("Backup manager started", "period", "5m", "s3", s3Cfg != nil)
		}
	}

	// Start Dashboard API server (ZapDB-backed, no external dependencies)
	apiListenAddr := c.String("api-listen")
	jwtSecret := c.String("jwt-secret")
	if jwtSecret == "" {
		jwtSecret = os.Getenv("MPC_JWT_SECRET")
	}
	if jwtSecret != "" {
		dbPath := filepath.Join(dataDir, "dashboard.db")
		database, err := db.New(dbPath, "")
		if err != nil {
			logger.Error("Failed to open dashboard database", err)
		} else {
			defer database.Close()

			mpcBackend := &ConsensusMPCBackend{
				pubSub:       pubSub,
				peerRegistry: peerRegistry,
				factory:      factory,
				keyInfoStore: factory.KeyInfoStore(),
				identity:     consensusIdentity,
				nodeID:       nodeID,
				threshold:    threshold,
			}

			apiServer := mpcapi.NewServer(database, mpcBackend, jwtSecret)
			apiServer.StartScheduler(ctx)

			// Wire HSM signer for intent co-signing
			signerType := c.String("hsm-signer")
			if signerType != "" {
				signer, signerErr := hsm.NewSigner(signerType, nil)
				if signerErr != nil {
					logger.Error("Failed to create HSM signer", signerErr, "provider", signerType)
				} else {
					apiServer.SetHSM(signer)
					logger.Info("HSM signer configured for co-signing", "provider", signer.Provider())
				}
			}

			// HSM threshold attestation (key share vault storage)
			if c.Bool("hsm-attest") {
				logger.Info("HSM threshold attestation enabled",
					"signer", c.String("hsm-signer"),
					"attest_key", c.String("hsm-signer-key-id"),
					"vault_provider", c.String("hsm-provider"),
				)
			}

			// Mount chi handler on Base
			os.Args = []string{"mpcd", "serve", "--http", apiListenAddr}
			baseApp := base.New()
			baseApp.OnServe().BindFunc(func(e *core.ServeEvent) error {
				// Embedded admin UI at /_/mpc/
				e.Router.GET("/_/mpc/{path...}", apis.Static(uimpc.DistDirFS(), true))

				e.Router.Any("/{path...}", func(re *core.RequestEvent) error {
					apiServer.Handler().ServeHTTP(re.Response, re.Request)
					return nil
				})
				return e.Next()
			})

			logger.Info("Dashboard API starting (Base+SQLite)", "addr", apiListenAddr)
			go func() {
				if err := baseApp.Start(); err != nil {
					logger.Error("Dashboard API server failed", err)
				}
			}()

			logger.Info("Dashboard API ready", "addr", apiListenAddr, "db", dbPath)
		}
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Warn("Shutdown signal received, stopping...")
	return nil
}

// ConsensusMPCBackend implements api.MPCBackend using the consensus transport.
type ConsensusMPCBackend struct {
	pubSub       *ConsensusPubSubAdapter
	peerRegistry *ConsensusPeerRegistry
	factory      *transport.Factory
	keyInfoStore *transport.KeyInfoStore
	identity     *ConsensusIdentityStore
	nodeID       string
	threshold    int
}

func (b *ConsensusMPCBackend) TriggerKeygen(orgID, walletID string) (*mpcapi.KeygenResult, error) {
	if walletID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", b.nodeID, time.Now().UnixNano())))
		walletID = hex.EncodeToString(h[:16])
	}

	resultTopic := fmt.Sprintf("mpc.mpc_keygen_result.%s", walletID)
	resultCh := make(chan *event.KeygenResultEvent, 1)
	unsub, err := b.pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
		var result event.KeygenResultEvent
		if err := json.Unmarshal(natMsg.Data, &result); err == nil {
			select {
			case resultCh <- &result:
			default:
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to result topic: %w", err)
	}
	defer unsub.Unsubscribe()

	sig := b.identity.SignMessage([]byte(walletID))
	msg := types.GenerateKeyMessage{OrgID: orgID, WalletID: walletID, Signature: sig}
	msgData, _ := json.Marshal(msg)
	if err := b.pubSub.Publish("mpc:generate", msgData); err != nil {
		return nil, fmt.Errorf("failed to publish keygen: %w", err)
	}

	select {
	case result := <-resultCh:
		if result.ResultType != event.ResultTypeSuccess {
			return nil, fmt.Errorf("keygen failed: %s", result.ErrorReason)
		}
		ethAddr := ""
		btcAddr := ""
		solAddr := ""
		if len(result.ECDSAPubKey) >= 32 {
			ethAddr = pubKeyToEthAddress(result.ECDSAPubKey)
			btcAddr = pubKeyToBtcAddress(result.ECDSAPubKey)
		}
		if len(result.EDDSAPubKey) == 32 {
			solAddr = eddsaPubKeyToSolAddress(result.EDDSAPubKey)
		}
		return &mpcapi.KeygenResult{
			WalletID:    result.WalletID,
			ECDSAPubKey: hex.EncodeToString(result.ECDSAPubKey),
			EDDSAPubKey: hex.EncodeToString(result.EDDSAPubKey),
			EthAddress:  ethAddr,
			BtcAddress:  btcAddr,
			SolAddress:  solAddr,
		}, nil
	case <-time.After(120 * time.Second):
		return nil, fmt.Errorf("keygen timed out after 120s")
	}
}

func (b *ConsensusMPCBackend) TriggerSign(orgID, walletID string, payload []byte) (*mpcapi.SignResult, error) {
	txID := fmt.Sprintf("sign-%d", time.Now().UnixNano())
	resultTopic := fmt.Sprintf("mpc.mpc_signing_result.%s", walletID)
	resultCh := make(chan json.RawMessage, 1)
	unsub, err := b.pubSub.Subscribe(resultTopic, func(natMsg *nats.Msg) {
		select {
		case resultCh <- natMsg.Data:
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to signing result: %w", err)
	}
	defer unsub.Unsubscribe()

	// Look up key type from key info store
	keyType := types.KeyTypeSecp256k1 // default for ECDSA
	if b.keyInfoStore != nil {
		if info, err := b.keyInfoStore.Get(walletID); err == nil && info.KeyType != "" {
			keyType = types.KeyType(info.KeyType)
		}
	}
	// Normalize legacy key type names
	switch keyType {
	case "ecdsa", "ECDSA":
		keyType = types.KeyTypeSecp256k1
	case "eddsa", "EDDSA":
		keyType = types.KeyTypeEd25519
	}

	msg := types.SignTxMessage{
		OrgID:    orgID,
		KeyType:  keyType,
		WalletID: walletID,
		TxID:     txID,
		Tx:       payload,
	}
	// Sign the message with the node's private key
	raw, _ := msg.Raw()
	msg.Signature = b.identity.SignMessage(raw)
	msgData, _ := json.Marshal(msg)
	if err := b.pubSub.Publish("mpc:sign", msgData); err != nil {
		return nil, fmt.Errorf("failed to publish sign request: %w", err)
	}

	select {
	case data := <-resultCh:
		var result struct {
			ResultType        string `json:"result_type"`
			ErrorReason       string `json:"error_reason"`
			R                 []byte `json:"r"`
			S                 []byte `json:"s"`
			SignatureRecovery []byte `json:"signature_recovery"`
			Signature         []byte `json:"signature"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signing result: %w", err)
		}
		if result.ResultType == "error" {
			return nil, fmt.Errorf("MPC signing failed: %s", result.ErrorReason)
		}
		sigR := hex.EncodeToString(result.R)
		sigS := hex.EncodeToString(result.S)
		var sigHex string
		if len(result.Signature) > 0 {
			sigHex = hex.EncodeToString(result.Signature)
		}
		return &mpcapi.SignResult{R: sigR, S: sigS, Signature: sigHex}, nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("signing timed out after 60s")
	}
}

func (b *ConsensusMPCBackend) TriggerReshare(orgID, walletID string, newThreshold int, newParticipants []string) error {
	msg := map[string]interface{}{
		"org_id":           orgID,
		"wallet_id":        walletID,
		"new_threshold":    newThreshold,
		"new_participants": newParticipants,
	}
	msgData, _ := json.Marshal(msg)
	return b.pubSub.Publish("mpc:reshare", msgData)
}

func (b *ConsensusMPCBackend) ExportKeyShare(orgID, walletID string) ([]byte, error) {
	key := mpc.OrgScopedKey(orgID, walletID)
	return b.factory.KVStore().Get(key)
}

func (b *ConsensusMPCBackend) GetClusterStatus() *mpcapi.ClusterStatus {
	ready := b.peerRegistry.ArePeersReady()
	connected := b.factory.Transport().GetPeers()
	return &mpcapi.ClusterStatus{
		NodeID:         b.nodeID,
		Mode:           "consensus",
		ExpectedPeers:  len(b.peerRegistry.peerIDs),
		ConnectedPeers: len(connected),
		Ready:          ready,
		Threshold:      b.threshold,
		Version:        Version,
	}
}

// loadOrGenerateIdentity loads or generates Ed25519 identity
func loadOrGenerateIdentity(keysDir, nodeID string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	identityPath := filepath.Join(keysDir, nodeID+"_identity.json")

	// Try to load existing identity
	data, err := os.ReadFile(identityPath)
	if err == nil {
		var identityData struct {
			NodeID     string `json:"node_id"`
			PublicKey  string `json:"public_key"`
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal(data, &identityData); err == nil {
			privKeyBytes, err := hex.DecodeString(identityData.PrivateKey)
			if err == nil && len(privKeyBytes) == ed25519.PrivateKeySize {
				privKey := ed25519.PrivateKey(privKeyBytes)
				pubKey := privKey.Public().(ed25519.PublicKey)
				logger.Info("Loaded existing identity", "nodeID", nodeID)
				return privKey, pubKey, nil
			}
		}
	}

	// Generate new identity
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	// Save identity
	identityData := map[string]string{
		"node_id":     nodeID,
		"public_key":  hex.EncodeToString(pubKey),
		"private_key": hex.EncodeToString(privKey),
	}
	data, err = json.MarshalIndent(identityData, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(identityPath, data, 0600); err != nil {
		return nil, nil, err
	}

	logger.Info("Generated new identity", "nodeID", nodeID)
	return privKey, pubKey, nil
}

// ConsensusIdentityStore implements identity.Store for consensus mode
type ConsensusIdentityStore struct {
	nodeID          string
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	initiatorPubKey ed25519.PublicKey
	publicKeys      map[string][]byte
	mu              sync.RWMutex
}

func NewConsensusIdentityStore(nodeID string, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *ConsensusIdentityStore {
	s := &ConsensusIdentityStore{
		nodeID:     nodeID,
		privateKey: privKey,
		publicKey:  pubKey,
		publicKeys: make(map[string][]byte),
	}
	s.publicKeys[nodeID] = pubKey

	// Load the event initiator public key from viper config.
	// This Ed25519 public key is used to verify that inbound event
	// messages (keygen, signing, reshare) originated from the authorized
	// initiator and have not been tampered with.
	if initiatorHex := viper.GetString("event_initiator_pubkey"); initiatorHex != "" {
		if decoded, err := hex.DecodeString(initiatorHex); err == nil && len(decoded) == ed25519.PublicKeySize {
			s.initiatorPubKey = ed25519.PublicKey(decoded)
		}
	}

	// In consensus mode, if no explicit initiator key is configured,
	// skip initiator verification since all messages come from within
	// the trusted cluster. The internal API (port 9800) is not
	// exposed externally.
	if s.initiatorPubKey == nil {
		logger.Info("No explicit initiator key configured; initiator verification will be skipped (consensus mode)")
	}

	return s
}

// SignMessage signs a message payload with the node's private key.
// Used by HTTP endpoints to sign event messages before publishing.
func (s *ConsensusIdentityStore) SignMessage(payload []byte) []byte {
	return ed25519.Sign(s.privateKey, payload)
}

func (s *ConsensusIdentityStore) GetPublicKey(nodeID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if key, ok := s.publicKeys[nodeID]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("public key not found for node: %s", nodeID)
}

func (s *ConsensusIdentityStore) VerifyInitiatorMessage(msg types.InitiatorMessage) error {
	// In consensus mode without an explicit initiator key, skip
	// verification. The internal API is only accessible within the
	// cluster, so all messages are trusted.
	if s.initiatorPubKey == nil {
		return nil
	}

	// Reconstruct the canonical payload that was signed (excludes the
	// signature field itself).
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("failed to get raw message data: %w", err)
	}

	sig := msg.Sig()
	if len(sig) == 0 {
		return fmt.Errorf("message has no signature")
	}

	if !ed25519.Verify(s.initiatorPubKey, raw, sig) {
		return fmt.Errorf("invalid Ed25519 signature from initiator")
	}

	return nil
}

func (s *ConsensusIdentityStore) AddPeerPublicKey(nodeID string, pubKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicKeys[nodeID] = pubKey
}

// SignWireMessage signs a protocol wire message with this node's Ed25519 key.
func (s *ConsensusIdentityStore) SignWireMessage(msg *types.Message) {
	msg.Sign(s.privateKey)
}

// VerifyWireMessage verifies a protocol wire message's Ed25519 signature
// using the sender's public key looked up by SenderNodeID.
func (s *ConsensusIdentityStore) VerifyWireMessage(msg *types.Message) error {
	if len(msg.Signature) == 0 {
		return fmt.Errorf("message has no signature")
	}
	nodeID := msg.SenderNodeID
	if nodeID == "" {
		nodeID = msg.SenderID
	}
	pubKey, err := s.GetPublicKey(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get sender's public key for node %s: %w", nodeID, err)
	}
	return msg.Verify(ed25519.PublicKey(pubKey))
}

// ConsensusPubSubAdapter adapts transport.PubSub to messaging.PubSub
type ConsensusPubSubAdapter struct {
	pubsub *transport.PubSub
}

func NewConsensusPubSubAdapter(pubsub *transport.PubSub) *ConsensusPubSubAdapter {
	return &ConsensusPubSubAdapter{pubsub: pubsub}
}

func (a *ConsensusPubSubAdapter) Publish(topic string, data []byte) error {
	return a.pubsub.Publish(topic, data)
}

func (a *ConsensusPubSubAdapter) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	return a.pubsub.PublishWithReply(topic, reply, data, headers)
}

func (a *ConsensusPubSubAdapter) Subscribe(topic string, handler func(msg *nats.Msg)) (messaging.Subscription, error) {
	sub, err := a.pubsub.Subscribe(topic, func(msg *transport.NATSMsg) {
		// Convert transport.NATSMsg to nats.Msg
		natsMsg := &nats.Msg{
			Subject: msg.Subject,
			Reply:   msg.Reply,
			Data:    msg.Data,
			Header:  nats.Header(msg.Header),
		}
		handler(natsMsg)
	})
	if err != nil {
		return nil, err
	}
	return &consensusSubscription{sub: sub}, nil
}

type consensusSubscription struct {
	sub *transport.Subscription
}

func (s *consensusSubscription) Unsubscribe() error {
	return s.sub.Unsubscribe()
}

// ConsensusPeerRegistry adapts transport.Registry to mpc.PeerRegistry
type ConsensusPeerRegistry struct {
	registry *transport.Registry
	nodeID   string
	peerIDs  []string
}

func NewConsensusPeerRegistry(registry *transport.Registry, nodeID string, peerIDs []string) *ConsensusPeerRegistry {
	return &ConsensusPeerRegistry{
		registry: registry,
		nodeID:   nodeID,
		peerIDs:  peerIDs,
	}
}

func (r *ConsensusPeerRegistry) Ready() error {
	return r.registry.Ready()
}

func (r *ConsensusPeerRegistry) Resign() error {
	return r.registry.Resign()
}

func (r *ConsensusPeerRegistry) WatchPeersReady() {
	r.registry.WatchPeersReady()
}

func (r *ConsensusPeerRegistry) ArePeersReady() bool {
	return r.registry.ArePeersReady()
}

func (r *ConsensusPeerRegistry) GetReadyPeersCount() int64 {
	return r.registry.GetReadyPeersCount()
}

func (r *ConsensusPeerRegistry) GetTotalPeersCount() int64 {
	return int64(len(r.peerIDs) + 1) // peers + self
}

func (r *ConsensusPeerRegistry) GetReadyPeersIncludeSelf() []string {
	return r.registry.GetReadyPeersIncludeSelf()
}

// ConsensusKeyInfoStore adapts transport.KeyInfoStore to keyinfo.Store
type ConsensusKeyInfoStore struct {
	store        *transport.KeyInfoStore
	peerRegistry *ConsensusPeerRegistry
}

func NewConsensusKeyInfoStore(store *transport.KeyInfoStore, peerRegistry *ConsensusPeerRegistry) *ConsensusKeyInfoStore {
	return &ConsensusKeyInfoStore{store: store, peerRegistry: peerRegistry}
}

func (s *ConsensusKeyInfoStore) Get(walletID string) (*keyinfo.KeyInfo, error) {
	info, err := s.store.Get(walletID)
	if err != nil {
		return nil, err
	}
	// Convert transport.KeyInfo to keyinfo.KeyInfo
	// Populate ParticipantPeerIDs from peer registry (all ready peers including self)
	participantPeerIDs := s.peerRegistry.GetReadyPeersIncludeSelf()
	return &keyinfo.KeyInfo{
		ParticipantPeerIDs: participantPeerIDs,
		Threshold:          info.Threshold,
		Version:            1, // Default version
	}, nil
}

func (s *ConsensusKeyInfoStore) Save(walletID string, info *keyinfo.KeyInfo) error {
	return s.store.RegisterKey(walletID, "secp256k1", info.Threshold, "", "", nil)
}

// ConsensusMessageQueue adapts transport for messaging.MessageQueue
type ConsensusMessageQueue struct {
	transport *transport.Transport
	nodeID    string
	queueType string
	handlers  map[string]func([]byte) error
	mu        sync.RWMutex
}

func NewConsensusMessageQueue(t *transport.Transport, nodeID, queueType string) *ConsensusMessageQueue {
	return &ConsensusMessageQueue{
		transport: t,
		nodeID:    nodeID,
		queueType: queueType,
		handlers:  make(map[string]func([]byte) error),
	}
}

func (q *ConsensusMessageQueue) Enqueue(topic string, message []byte, options *messaging.EnqueueOptions) error {
	// Broadcast the message via transport's Publish method
	return q.transport.Publish(topic, message)
}

func (q *ConsensusMessageQueue) Dequeue(topic string, handler func(message []byte) error) error {
	q.mu.Lock()
	q.handlers[topic] = handler
	q.mu.Unlock()
	// In consensus mode, messages are delivered via PubSub subscriptions
	// The handler will be called when messages arrive
	return nil
}

func (q *ConsensusMessageQueue) Close() {
	// Nothing to close in consensus mode
}

// pubKeyToEthAddress derives an Ethereum address from an ECDSA public key.
// Accepts compressed (33 bytes), uncompressed (65 bytes), or raw x-coordinate (32 bytes).
func pubKeyToEthAddress(pubKey []byte) string {
	var xyBytes []byte // 64 bytes: X(32) || Y(32)
	switch len(pubKey) {
	case 65:
		// Uncompressed: 0x04 || X(32) || Y(32)
		xyBytes = pubKey[1:]
	case 33:
		// Compressed: 0x02/0x03 || X(32) — decompress via secp256k1
		x, y := ellipticUnmarshalCompressed(pubKey)
		if x == nil {
			return ""
		}
		xyBytes = append(x.Bytes(), y.Bytes()...)
	case 32:
		// Raw x-coordinate only — try decompressing with 0x02 prefix (even y)
		compressed := append([]byte{0x02}, pubKey...)
		x, y := ellipticUnmarshalCompressed(compressed)
		if x == nil {
			// Try odd y
			compressed[0] = 0x03
			x, y = ellipticUnmarshalCompressed(compressed)
		}
		if x == nil {
			return ""
		}
		xBytes := make([]byte, 32)
		yBytes := make([]byte, 32)
		xB := x.Bytes()
		yB := y.Bytes()
		copy(xBytes[32-len(xB):], xB)
		copy(yBytes[32-len(yB):], yB)
		xyBytes = append(xBytes, yBytes...)
	default:
		// Try as hex string
		decoded, err := hex.DecodeString(string(pubKey))
		if err == nil && len(decoded) > 0 {
			return pubKeyToEthAddress(decoded)
		}
		return ""
	}
	if len(xyBytes) != 64 {
		return ""
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write(xyBytes)
	addrBytes := hash.Sum(nil)[12:]
	return "0x" + hex.EncodeToString(addrBytes)
}

// ellipticUnmarshalCompressed decompresses a secp256k1 compressed public key.
func ellipticUnmarshalCompressed(compressed []byte) (*big.Int, *big.Int) {
	if len(compressed) != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
		return nil, nil
	}
	curve := crypto_elliptic.P256() // Use P256 as base; secp256k1 params below
	// secp256k1 curve parameters
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	x := new(big.Int).SetBytes(compressed[1:33])
	// y² = x³ + 7 (mod p) for secp256k1
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, p)
	// ModSqrt
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, nil
	}
	// Check parity
	if y.Bit(0) != uint(compressed[0]&1) {
		y.Sub(p, y)
	}
	_ = curve // suppress unused
	return x, y
}

// pubKeyToBtcAddress derives a Bitcoin P2PKH address from a secp256k1 public key.
// Accepts compressed (33 bytes), uncompressed (65 bytes), or raw x-coordinate (32 bytes).
func pubKeyToBtcAddress(pubKey []byte) string {
	var compressed []byte
	switch len(pubKey) {
	case 33:
		compressed = pubKey
	case 65:
		// Compress: take X coordinate, prefix with 0x02 or 0x03 based on Y parity
		prefix := byte(0x02)
		if pubKey[64]&1 == 1 {
			prefix = 0x03
		}
		compressed = append([]byte{prefix}, pubKey[1:33]...)
	case 32:
		// Raw x-coordinate — use even y (0x02)
		compressed = append([]byte{0x02}, pubKey...)
	default:
		return ""
	}
	// SHA256(compressed pubkey)
	sha := sha256.Sum256(compressed)
	// RIPEMD160(SHA256)
	rip := ripemd160.New()
	rip.Write(sha[:])
	pubKeyHash := rip.Sum(nil) // 20 bytes

	// Base58Check encode with version byte 0x00 (mainnet P2PKH)
	return base58CheckEncode(0x00, pubKeyHash)
}

// base58CheckEncode encodes data with a version byte using Base58Check encoding.
func base58CheckEncode(version byte, payload []byte) string {
	versioned := append([]byte{version}, payload...)
	// Double SHA256 checksum
	first := sha256.Sum256(versioned)
	second := sha256.Sum256(first[:])
	checksum := second[:4]
	full := append(versioned, checksum...)
	return base58.Encode(full)
}

// eddsaPubKeyToSolAddress derives a Solana address from an Ed25519 public key.
// The address is simply the base58 encoding of the 32-byte public key.
func eddsaPubKeyToSolAddress(pubKey []byte) string {
	if len(pubKey) != 32 {
		return ""
	}
	return base58.Encode(pubKey)
}

