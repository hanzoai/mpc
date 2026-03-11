package config

import (
	"fmt"

	"github.com/hashicorp/consul/api"

	"github.com/hanzoai/mpc/pkg/infra"
)

type Peer struct {
	ID   string
	Name string
}

// LoadPeersFromConsul loads peers from a Consul KV client (backward compatibility).
func LoadPeersFromConsul(kv *api.KV, prefix string) ([]Peer, error) {
	// Retrieve node IDs with the "peers" prefix
	pairs, _, err := kv.List(prefix, nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("List of node IDs with the prefix: " + prefix)
	peers := make([]Peer, 0, len(pairs))
	for _, pair := range pairs {
		peers = append(peers, Peer{
			ID: string(pair.Value),
			// remove prefix from key
			Name: pair.Key[len(prefix):],
		})

		fmt.Printf("Key: %s, Value: %s\n", pair.Key, pair.Value)
	}

	return peers, nil
}

// LoadPeersFromKV loads peers from the abstract KV interface.
// Works with any backend: consensus, NATS, or Consul adapter.
func LoadPeersFromKV(kv infra.KV, prefix string) ([]Peer, error) {
	pairs, err := kv.List(prefix)
	if err != nil {
		return nil, err
	}

	fmt.Println("List of node IDs with the prefix: " + prefix)
	peers := make([]Peer, 0, len(pairs))
	for _, pair := range pairs {
		peers = append(peers, Peer{
			ID:   string(pair.Value),
			Name: pair.Key[len(prefix):],
		})

		fmt.Printf("Key: %s, Value: %s\n", pair.Key, pair.Value)
	}

	return peers, nil
}

func GetNodeID(nodeName string, peers []Peer) string {
	for _, peer := range peers {
		if peer.Name == nodeName {
			return peer.ID
		}
	}

	return ""
}
