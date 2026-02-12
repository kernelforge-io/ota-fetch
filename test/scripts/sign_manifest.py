#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import argparse
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.backends import default_backend

def main():
    parser = argparse.ArgumentParser(description="Sign manifest.json with a PEM private key.")
    parser.add_argument('--key', default="../private/signer.key", help='Path to signer private key (PEM)')
    parser.add_argument('--infile', default="../server/manifest.json", help='Path to manifest.json')
    parser.add_argument('--sigfile', default="../server/manifest.json.sig", help='Output signature file (binary)')
    parser.add_argument('--password', help='Key password if encrypted')
    args = parser.parse_args()

    # Load private key
    key_path = Path(args.key).resolve()
    with open(key_path, "rb") as f:
        privkey = serialization.load_pem_private_key(
            f.read(),
            password=args.password.encode() if args.password else None,
            backend=default_backend()
        )

    # Read manifest
    infile = Path(args.infile).resolve()
    with open(infile, "rb") as f:
        data = f.read()

    # Sign the data
    if isinstance(privkey, rsa.RSAPrivateKey):
        sig = privkey.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif isinstance(privkey, ec.EllipticCurvePrivateKey):
        sig = privkey.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
    elif isinstance(privkey, ed25519.Ed25519PrivateKey):
        sig = privkey.sign(data)
    else:
        print("Unsupported private key type.", file=sys.stderr)
        sys.exit(1)

    # Write signature
    sigfile = Path(args.sigfile).resolve()
    with open(sigfile, "wb") as f:
        f.write(sig)
    print(f"Signature written to {sigfile}")

if __name__ == '__main__':
    main()
