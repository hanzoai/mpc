package infra

import (
	"github.com/hashicorp/consul/api"
)

// ConsulKVAdapter wraps the existing ConsulKV interface to implement the
// abstract KV interface. This allows existing Consul-based deployments to
// continue working while new deployments use consensus-backed storage.
type ConsulKVAdapter struct {
	consul ConsulKV
}

// NewConsulKVAdapter creates a KV implementation backed by Consul.
func NewConsulKVAdapter(consulKV ConsulKV) *ConsulKVAdapter {
	return &ConsulKVAdapter{consul: consulKV}
}

func (c *ConsulKVAdapter) Put(key string, value []byte) error {
	_, err := c.consul.Put(&api.KVPair{Key: key, Value: value}, nil)
	return err
}

func (c *ConsulKVAdapter) Get(key string) ([]byte, error) {
	pair, _, err := c.consul.Get(key, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, nil
	}
	return pair.Value, nil
}

func (c *ConsulKVAdapter) Delete(key string) error {
	_, err := c.consul.Delete(key, nil)
	return err
}

func (c *ConsulKVAdapter) List(prefix string) ([]*KVPair, error) {
	pairs, _, err := c.consul.List(prefix, nil)
	if err != nil {
		return nil, err
	}

	result := make([]*KVPair, 0, len(pairs))
	for _, p := range pairs {
		result = append(result, &KVPair{
			Key:   p.Key,
			Value: p.Value,
		})
	}
	return result, nil
}
