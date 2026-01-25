# Using Lux MPC as a Go Module in Bridge

## Overview

Instead of copying binaries or using a compatibility layer, the bridge can import Lux MPC directly as a Go module dependency. This is cleaner and more maintainable.

## How to Use in Bridge

### 1. Add as Go Module Dependency

In the bridge's Go backend:

```bash
cd /Users/z/work/lux/bridge/app/server
go get github.com/luxfi/mpc@v0.3.1  # or latest tag
```

### 2. Import and Use the Package

```go
package main

import (
    "github.com/luxfi/mpc/pkg/client"
    "github.com/luxfi/mpc/pkg/mpc"
    "github.com/luxfi/mpc/pkg/types"
)

// Initialize MPC client
mpcClient := client.NewClient(config)

// Or use the MPC node directly
node := mpc.NewNode(nodeConfig)
```

### 3. Example Integration

```go
// bridge/app/server/mpc/service.go
package mpc

import (
    "context"
    "github.com/luxfi/mpc/pkg/client"
    "github.com/luxfi/mpc/pkg/types"
)

type BridgeMPCService struct {
    client *client.Client
}

func NewBridgeMPCService(config *Config) (*BridgeMPCService, error) {
    mpcClient, err := client.NewClient(&client.Config{
        NodeID:     config.NodeID,
        NATSUrl:    config.NATSUrl,
        ConsulAddr: config.ConsulAddr,
    })
    if err != nil {
        return nil, err
    }
    
    return &BridgeMPCService{
        client: mpcClient,
    }, nil
}

func (s *BridgeMPCService) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
    // Use the MPC client to sign
    result, err := s.client.Sign(ctx, &types.SignRequest{
        KeyID:   keyID,
        Message: message,
    })
    if err != nil {
        return nil, err
    }
    
    return result.Signature, nil
}
```

## Available Packages

The Lux MPC module exports these packages:

- `github.com/luxfi/mpc/pkg/client` - High-level client API
- `github.com/luxfi/mpc/pkg/mpc` - Core MPC node implementation
- `github.com/luxfi/mpc/pkg/types` - Common types and messages
- `github.com/luxfi/mpc/pkg/messaging` - NATS messaging utilities
- `github.com/luxfi/mpc/pkg/infra` - Consul integration
- `github.com/luxfi/mpc/pkg/kvstore` - BadgerDB storage

## Version Tags

Current version: `v0.3.1`

To use a specific version:
```bash
go get github.com/luxfi/mpc@v0.3.1
```

To use the latest:
```bash
go get github.com/luxfi/mpc@latest
```

## Creating a New Release

When you're ready to tag a new version:

```bash
# Commit all changes
git add -A
git commit -m "Rebrand to Lux MPC and add bridge integration"

# Create and push tag
git tag v0.3.1
git push origin v0.3.1

# Or for a new minor version
git tag v0.4.0
git push origin v0.4.0
```

## Benefits

1. **No Binary Management** - Go modules handle versioning
2. **Type Safety** - Direct Go integration with compile-time checks
3. **Easy Updates** - Just update the version in go.mod
4. **Better Testing** - Can mock interfaces for unit tests
5. **IDE Support** - Full autocomplete and documentation

## Migration from Binary Approach

Instead of:
```bash
# Old way - copying binaries
cp lux-mpc ../bridge/
./lux-mpc --config config.yaml
```

Use:
```go
// New way - Go module
import "github.com/luxfi/mpc/pkg/client"
mpcClient := client.NewClient(config)
```

This is the modern, clean way to integrate the MPC functionality into the bridge!