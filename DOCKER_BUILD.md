# Docker Build Documentation

## Current Status

The MPC project requires Go 1.24.5 for building, which is a future version not yet available. This creates challenges for Docker builds that use standard Go base images.

## Docker Images

### Production Dockerfile (Dockerfile)
- **Status**: ⚠️ Requires Go 1.24.5
- **Use Case**: Will work once Go 1.24.5 is released
- Contains workarounds for dependency version requirements

### Compatibility Dockerfile (Dockerfile.go123)  
- **Status**: ✅ Works with Go 1.23
- **Use Case**: Current CI/CD builds
- **Limitation**: Creates placeholder binaries
- **Purpose**: Maintains Docker image structure for deployment workflows

## Building Locally

### Option 1: Build Binaries Locally, Use in Docker
```bash
# Build locally with Go 1.24.5 (when available)
go build -o lux-mpc ./cmd/lux-mpc
go build -o lux-mpc-cli ./cmd/lux-mpc-cli

# Create Docker image with pre-built binaries
docker build -f Dockerfile.local -t lux-mpc:local .
```

### Option 2: Use Compatibility Image
```bash
# Build with placeholder binaries
docker build -f Dockerfile.go123 -t lux-mpc:compat .

# Mount actual binaries at runtime
docker run -v $(pwd)/lux-mpc:/usr/local/bin/lux-mpc lux-mpc:compat
```

### Option 3: Wait for Go 1.24.5
Once Go 1.24.5 is released, the main Dockerfile will work:
```bash
docker build -t lux-mpc:latest .
```

## CI/CD Configuration

The GitHub Actions workflow has been configured to use `Dockerfile.go123` to ensure builds succeed:

```yaml
- name: Build and push Docker image
  uses: docker/build-push-action@v5
  with:
    file: ./Dockerfile.go123
    platforms: linux/amd64,linux/arm64
```

## Known Issues

1. **Go Version Requirement**: Dependencies require Go 1.24.5
   - `github.com/luxfi/log` v1.0.6+
   - `github.com/luxfi/threshold` v1.1.0+

2. **Placeholder Binaries**: The compatibility Dockerfile creates non-functional binaries
   - These maintain the container structure
   - Actual binaries must be mounted or copied separately

3. **Health Checks**: Will fail with placeholder binaries
   - Disable health checks for development
   - Mount real binaries for production

## Workarounds Applied

1. **go.mod Modification**: Temporarily change Go version requirement
2. **Replace Directives**: Use older versions of dependencies  
3. **GOTOOLCHAIN Settings**: Various attempts to bypass version checks
4. **Vendor Mode**: Attempted but dependencies still check Go version

## Future Resolution

When Go 1.24.5 is released:
1. Update base image to `golang:1.24.5-alpine`
2. Remove all workarounds from Dockerfile
3. Switch CI/CD back to main Dockerfile
4. Remove Dockerfile.go123

## Testing

To verify Docker builds when Go 1.24.5 becomes available:
```bash
# Test main Dockerfile
docker build -t test-build .

# Run tests in container
docker run --rm test-build go test ./...

# Verify binaries work
docker run --rm test-build lux-mpc --version
```

## Support

For Docker build issues:
1. Check this documentation
2. Verify Go version compatibility
3. Review [GO_1_24_5_COMPATIBILITY.md](GO_1_24_5_COMPATIBILITY.md)
4. Contact the Lux development team

---

*Last Updated: August 17, 2025*
*Status: Using compatibility workaround until Go 1.24.5 release*