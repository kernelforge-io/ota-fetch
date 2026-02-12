#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import http.server
import argparse
import ssl
import sys
import os
from pathlib import Path

def env_truthy(name):
    value = os.getenv(name, "")
    return value.lower() in ("1", "true", "yes", "on")

ENABLE_HTTP_LOG = env_truthy("OTA_FETCH_HTTP_LOG")


class TestHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        if not ENABLE_HTTP_LOG:
            return
        super().log_message(format, *args)

def parse_args():
    parser = argparse.ArgumentParser(description="HTTPS test server with required mTLS.")
    parser.add_argument("port", nargs="?", default=8443, type=int, help="TCP port (default: 8443)")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Root directory containing private/ and server/ (default: test/)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1)",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    test_root = Path(args.root).resolve()
    server_root = test_root / "server"
    ca_cert = test_root / "private/rootCA.crt"
    server_cert = server_root / "server.crt"
    server_key = server_root / "server.key"

    httpd = http.server.ThreadingHTTPServer((args.host, args.port), TestHTTPRequestHandler)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_cert))
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    os.chdir(str(server_root))

    print("Serving from directory:", server_root, flush=True)
    print("CA_CERT:", ca_cert, flush=True)
    print("SERVER_CERT:", server_cert, flush=True)
    print("SERVER_KEY:", server_key, flush=True)
    print(
        f"HTTPS server with mTLS running on https://{args.host}:{args.port}/ serving directory: {server_root}",
        flush=True,
    )
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
