#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import argparse
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

# ---- Configuration ----
DEFAULT_TESTDIR = Path(__file__).resolve().parent.parent
TESTDIR = DEFAULT_TESTDIR
PRIVATE = TESTDIR / "private"
SERVER = TESTDIR / "server"
CLIENT = TESTDIR / "client"

CA_KEY = PRIVATE / "rootCA.key"
CA_CERT = PRIVATE / "rootCA.crt"
SIGNER_KEY = PRIVATE / "signer.key"
SIGNER_CERT = SERVER / "signer.crt"

CA_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"OTA Test Root CA")])
SIGNER_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"OTA Manifest Signer")])
SERVER_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"ota-fetch-test-server")])
CLIENT_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"ota-fetch-client")])

def now_utc():
    return datetime.now(timezone.utc)

def configure_paths(output_root: Path):
    global TESTDIR, PRIVATE, SERVER, CLIENT
    global CA_KEY, CA_CERT, SIGNER_KEY, SIGNER_CERT

    TESTDIR = output_root.resolve()
    PRIVATE = TESTDIR / "private"
    SERVER = TESTDIR / "server"
    CLIENT = TESTDIR / "client"
    CA_KEY = PRIVATE / "rootCA.key"
    CA_CERT = PRIVATE / "rootCA.crt"
    SIGNER_KEY = PRIVATE / "signer.key"
    SIGNER_CERT = SERVER / "signer.crt"

def ensure_dirs():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    SERVER.mkdir(parents=True, exist_ok=True)
    CLIENT.mkdir(parents=True, exist_ok=True)

def save_key_and_cert(key_path, cert_path, key, cert):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        key_format = serialization.PrivateFormat.PKCS8
    else:
        key_format = serialization.PrivateFormat.TraditionalOpenSSL
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            key_format,
            serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def gen_root_ca():
    print(f"[*] Generating Root CA key ({CA_KEY}) and cert ({CA_CERT})...")
    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ca_pub = ca_key.public_key()
    tls_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(CA_SUBJECT)
        .issuer_name(CA_SUBJECT)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc() - timedelta(days=1))
        .not_valid_after(now_utc() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_pub),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pub),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    save_key_and_cert(CA_KEY, CA_CERT, ca_key, tls_ca_cert)
    print("    Done.")

def sign_cert(ca_key, tls_ca_cert, subject, public_key, usage_oid, san_list=None):
    if usage_oid == ExtendedKeyUsageOID.SERVER_AUTH:
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    elif usage_oid == ExtendedKeyUsageOID.CODE_SIGNING:
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    else:
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(tls_ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc() - timedelta(days=1))
        .not_valid_after(now_utc() + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage_oid]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_list]),
            critical=False
        )
    return builder.sign(ca_key, hashes.SHA256(), default_backend())

def gen_signer_cert(signer_type):
    print(f"[*] Generating signer key ({SIGNER_KEY}) and cert ({SIGNER_CERT}) signed by Root CA...")
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT, "rb") as f:
        tls_ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    if signer_type == "ed25519":
        signer_key = ed25519.Ed25519PrivateKey.generate()
    else:
        signer_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    signer_cert = sign_cert(ca_key, tls_ca_cert, SIGNER_SUBJECT, signer_key.public_key(), ExtendedKeyUsageOID.CODE_SIGNING)
    save_key_and_cert(SIGNER_KEY, SIGNER_CERT, signer_key, signer_cert)
    print("    Done.")

def gen_tls_cert(name, subject, usage_oid, output_dir, san_list=None):
    key_path = output_dir / f"{name}.key"
    cert_path = output_dir / f"{name}.crt"
    print(f"[*] Generating TLS cert for {name} ({key_path}, {cert_path})...")
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT, "rb") as f:
        tls_ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cert = sign_cert(ca_key, tls_ca_cert, subject, key.public_key(), usage_oid, san_list)
    save_key_and_cert(key_path, cert_path, key, cert)
    print("    Done.")

def main():
    parser = argparse.ArgumentParser(description="Generate test keys and certs.")
    parser.add_argument(
        "--signer-type",
        choices=["ec", "ed25519"],
        default="ec",
        help="Signer key type for manifest signing (default: ec)",
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_TESTDIR),
        help="Directory containing private/, server/, and client/ (default: test/)",
    )
    args = parser.parse_args()

    configure_paths(Path(args.output_root))
    ensure_dirs()
    gen_root_ca()
    gen_signer_cert(args.signer_type)
    gen_tls_cert("server", SERVER_SUBJECT, ExtendedKeyUsageOID.SERVER_AUTH, SERVER, san_list=["localhost"])
    gen_tls_cert("client", CLIENT_SUBJECT, ExtendedKeyUsageOID.CLIENT_AUTH, CLIENT, san_list=["ota-fetch-client"])



    print("\nTest keys and certs generated:\n")
    print(f"  Root CA key:     {CA_KEY}")
    print(f"  Root CA cert:    {CA_CERT}")
    print(f"  Signer key:      {SIGNER_KEY}")
    print(f"  Signer cert:     {SIGNER_CERT}")
    print(f"  Server key:      {SERVER / 'server.key'}")
    print(f"  Server cert:     {SERVER / 'server.crt'}")
    print(f"  Client key:      {CLIENT / 'client.key'}")
    print(f"  Client cert:     {CLIENT / 'client.crt'}")

if __name__ == "__main__":
    main()
