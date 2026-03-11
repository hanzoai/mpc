package mpc

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samber/lo"

	"github.com/hanzoai/mpc/pkg/infra"
	"github.com/hanzoai/mpc/pkg/logger"
)

const (
	ReadinessCheckPeriod = 1 * time.Second
)

type PeerRegistry interface {
	Ready() error
	ArePeersReady() bool
	WatchPeersReady()
	// Resign is called by the node when it is going to shutdown
	Resign() error
	GetReadyPeersCount() int64
	GetReadyPeersIncludeSelf() []string // get ready peers include self
	GetTotalPeersCount() int64
}

type registry struct {
	nodeID      string
	peerNodeIDs []string
	readyMap    map[string]bool
	readyCount  int64
	mu          sync.RWMutex
	ready       bool // ready is true when all peers are ready

	kv infra.KV
}

func NewRegistry(
	nodeID string,
	peerNodeIDs []string,
	kv infra.KV,
) *registry {
	return &registry{
		kv:          kv,
		nodeID:      nodeID,
		peerNodeIDs: getPeerIDsExceptSelf(nodeID, peerNodeIDs),
		readyMap:    make(map[string]bool),
		readyCount:  1, // self
	}
}

func getPeerIDsExceptSelf(nodeID string, peerNodeIDs []string) []string {
	peerIDs := make([]string, 0, len(peerNodeIDs))
	for _, peerID := range peerNodeIDs {
		if peerID != nodeID {
			peerIDs = append(peerIDs, peerID)
		}
	}
	return peerIDs
}

func (r *registry) readyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (r *registry) registerReadyPairs(peerIDs []string) {
	for _, peerID := range peerIDs {
		ready, exist := r.readyMap[peerID]
		if !exist {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Register", "peerID", peerID)
		} else if !ready {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Reconnecting...", "peerID", peerID)
		}

		r.readyMap[peerID] = true
	}

	if len(peerIDs) == len(r.peerNodeIDs) && !r.ready {
		r.mu.Lock()
		r.ready = true
		r.mu.Unlock()
		logger.Info("ALL PEERS ARE READY! Starting to accept MPC requests")
	}

}

// Ready is called by the node when it complete generate preparams and starting to accept
// incoming requests
func (r *registry) Ready() error {
	k := r.readyKey(r.nodeID)

	err := r.kv.Put(k, []byte("true"))
	if err != nil {
		return fmt.Errorf("Put ready key failed: %w", err)
	}

	return nil
}

func (r *registry) WatchPeersReady() {
	ticker := time.NewTicker(ReadinessCheckPeriod)
	go r.logReadyStatus()
	// Re-announce readiness periodically until all peers are discovered.
	// This handles the case where early consensus proposals fail during
	// rolling restarts (not enough validators for quorum yet).
	reannounceInterval := 5 * time.Second
	lastReannounce := time.Time{}
	// first tick is executed immediately
	for ; true; <-ticker.C {
		if !r.ArePeersReady() && time.Since(lastReannounce) >= reannounceInterval {
			if err := r.kv.Put(r.readyKey(r.nodeID), []byte("true")); err != nil {
				logger.Error("Re-announce readiness failed", err)
			}
			lastReannounce = time.Now()
		}
		pairs, err := r.kv.List("ready/")
		if err != nil {
			logger.Error("List ready keys failed", err)
		}

		newReadyPeerIDs := r.getReadyPeersFromKVStore(pairs)
		if len(newReadyPeerIDs) != len(r.peerNodeIDs) {
			r.mu.Lock()
			r.ready = false
			r.mu.Unlock()

			var readyPeerIDs []string
			for peerID, isReady := range r.readyMap {
				if isReady {
					readyPeerIDs = append(readyPeerIDs, peerID)
				}
			}

			disconnecteds, _ := lo.Difference(readyPeerIDs, newReadyPeerIDs)
			if len(disconnecteds) > 0 {
				for _, peerID := range disconnecteds {
					logger.Warn("Peer disconnected!", "peerID", peerID)
					r.readyMap[peerID] = false
					atomic.AddInt64(&r.readyCount, -1)
				}

			}

		}
		r.registerReadyPairs(newReadyPeerIDs)
	}

}

func (r *registry) logReadyStatus() {
	for {
		time.Sleep(5 * time.Second)
		if !r.ArePeersReady() {
			logger.Info("Peers are not ready yet", "ready", r.GetReadyPeersCount(), "expected", len(r.peerNodeIDs)+1)
		}
	}
}

func (r *registry) GetReadyPeersCount() int64 {
	return atomic.LoadInt64(&r.readyCount)
}

func (r *registry) GetReadyPeersIncludeSelf() []string {
	var peerIDs []string
	for peerID, isReady := range r.readyMap {
		if isReady {
			peerIDs = append(peerIDs, peerID)
		}
	}

	peerIDs = append(peerIDs, r.nodeID) // append self

	// Sort to ensure consistent ordering across all nodes
	// This is critical for MPC protocols where party IDs must match
	sort.Strings(peerIDs)

	return peerIDs
}

func (r *registry) getReadyPeersFromKVStore(kvPairs []*infra.KVPair) []string {
	var peers []string
	for _, k := range kvPairs {
		var peerNodeID string
		_, err := fmt.Sscanf(k.Key, "ready/%s", &peerNodeID)
		if err != nil {
			logger.Error("Parse ready key failed", err)
		}
		if peerNodeID == r.nodeID {
			continue
		}

		peers = append(peers, peerNodeID)
	}

	return peers
}

func (r *registry) ArePeersReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.ready
}

func (r *registry) GetTotalPeersCount() int64 {
	var self int64 = 1
	return int64(len(r.peerNodeIDs)) + self
}

func (r *registry) Resign() error {
	k := r.readyKey(r.nodeID)

	err := r.kv.Delete(k)
	if err != nil {
		return fmt.Errorf("Delete ready key failed: %w", err)
	}

	return nil
}
