#!/usr/bin/env python3
"""Bootstrap MPC node identities and peers configuration.

Generates:
- Ed25519 keypair for each node
- Identity JSON files
- peers.json mapping
- Event initiator keypair for API server
"""
import json
import os
import sys
from datetime import datetime, timezone

# Ed25519 via standard lib
from hashlib import sha512
import secrets


def ed25519_keygen():
    """Generate Ed25519 keypair using PyNaCl-compatible approach."""
    try:
        # Try using cryptography library if available
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Ed25519 private key in Go is seed + public (64 bytes)
        return (private_bytes + public_bytes).hex(), public_bytes.hex()
    except ImportError:
        pass

    # Fallback: use subprocess to call openssl
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as f:
        privfile = f.name

    try:
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', privfile],
                      check=True, capture_output=True)

        # Extract raw private key
        result = subprocess.run(['openssl', 'pkey', '-in', privfile, '-outform', 'DER'],
                              check=True, capture_output=True)
        der = result.stdout
        # DER format: skip header to get 32-byte seed
        seed = der[-32:]

        # Extract public key
        result = subprocess.run(['openssl', 'pkey', '-in', privfile, '-pubout', '-outform', 'DER'],
                              check=True, capture_output=True)
        pub_der = result.stdout
        pub = pub_der[-32:]

        return (seed + pub).hex(), pub.hex()
    finally:
        os.unlink(privfile)


def main():
    nodes = [
        ("hanzo-mpc-0", "b23bee37-526c-46b9-b870-c235cc9e8a7c"),
        ("hanzo-mpc-1", "562b0c28-9203-4a38-9f79-dee5987706f0"),
        ("hanzo-mpc-2", "73a40bf2-130a-4102-9da7-09c0cf12d084"),
    ]

    output_dir = sys.argv[1] if len(sys.argv) > 1 else "bootstrap-output"
    identity_dir = os.path.join(output_dir, "identity")
    os.makedirs(identity_dir, exist_ok=True)

    peers = {}

    for name, node_id in nodes:
        print(f"Generating identity for {name} ({node_id})...")

        # Generate Ed25519 keypair
        private_hex, public_hex = ed25519_keygen()

        # Write private key (hex-encoded seed+pub, 64 bytes = 128 hex chars)
        key_path = os.path.join(identity_dir, f"{name}_private.key")
        with open(key_path, 'w') as f:
            f.write(private_hex)
        os.chmod(key_path, 0o600)

        # Write identity JSON
        identity = {
            "node_name": name,
            "node_id": node_id,
            "public_key": public_hex,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        identity_path = os.path.join(identity_dir, f"{name}_identity.json")
        with open(identity_path, 'w') as f:
            json.dump(identity, f, indent=2)

        peers[name] = node_id
        print(f"  Private key: {key_path}")
        print(f"  Identity:    {identity_path}")
        print(f"  Public key:  {public_hex}")

    # Write peers.json
    peers_path = os.path.join(output_dir, "peers.json")
    with open(peers_path, 'w') as f:
        json.dump(peers, f, indent=2)
    print(f"\npeers.json: {peers_path}")

    # Generate event initiator keypair
    print("\nGenerating event initiator keypair...")
    initiator_priv_hex, initiator_pub_hex = ed25519_keygen()

    initiator_path = os.path.join(output_dir, "initiator_private.key")
    with open(initiator_path, 'w') as f:
        f.write(initiator_priv_hex)
    os.chmod(initiator_path, 0o600)

    print(f"  Private key: {initiator_path}")
    print(f"  Public key:  {initiator_pub_hex}")
    print(f"\nSet event_initiator_pubkey in config: {initiator_pub_hex}")

    # Write summary
    summary = {
        "peers": peers,
        "event_initiator_pubkey": initiator_pub_hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    summary_path = os.path.join(output_dir, "bootstrap-summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary: {summary_path}")


if __name__ == "__main__":
    main()
