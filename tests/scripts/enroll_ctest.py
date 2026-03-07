#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = "bootstrap-token-123"
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUVt0V2JfZW0nPyO0P8Yr6f9KX84swCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIdGVzdC1jZXJ0MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAw
MDAwMFowEzERMA8GA1UEAwwIdGVzdC1jZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEd7ABhVf2KtSLQJ4L2U6w8jBWfA9Pj2fTqUVw0D1vC2lW3wLQ7z5mH2zR
VdH2h8l8Z6A7a3zvC8eGkWzJp0dQ0aNTMFEwHQYDVR0OBBYEFM6lN0nM3h1V4xvQ
8n4S7d2UbyfPMB8GA1UdIwQYMBaAFM6lN0nM3h1V4xvQ8n4S7d2UbyfPMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJM6fR7N84ykg9Q2U9uQ4Q9C
5dMYcYv1V1u8MG+0zBhAAiEA9C9U3PjM2xUvM7KgR2n2SxNQ/3v9vVwF5QJj5vFJ
fXw=
-----END CERTIFICATE-----
"""

CHAIN_PEM = """-----BEGIN CERTIFICATE-----
MIIBTTCB9KADAgECAhQ2QkISt8rWm3q2Jv8J6Q7m7n3YBjAKBggqhkjOPQQDAjAT
MREwDwYDVQQDDAh0ZXN0LWNhMB4XDTI2MDEwMTAwMDAwMFoXDTQ2MDEwMTAwMDAw
MFowEzERMA8GA1UEAwwIdGVzdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BHk8NnR4XZqE8C1wUo5rYfU8B4kq0G2w2X5xW1o8eX9zF4z2fK3W+6x5+KXh0k4k
2Gv+U7X1m3G8QmJ7x0WjUzBRMB0GA1UdDgQWBBQbX2N5M6k8g6S3t3j8p6Hc2X4x
7DAfBgNVHSMEGDAWgBQbX2N5M6k8g6S3t3j8p6Hc2X4x7DAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQC9jv8w7nLJjW7h8q2m8YQmV7r4wz0jWmQ5
S9v0mS7J9wIgB4h9m9KX4kD4q3v9Hf1Z9l9P6q9Q4X7l0yVf8v3fZ+o=
-----END CERTIFICATE-----
"""


class TestFailure(Exception):
    pass


class ServerState:
    def __init__(self, expected_token):
        self.expected_token = expected_token
        self.request_count = 0
        self.last_body = None
        self.csr_valid = False


def make_handler(state):
    class EnrollHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            state.request_count += 1

            if self.path != "/enroll":
                self.send_response(404)
                self.end_headers()
                return

            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {state.expected_token}":
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"unauthorized")
                return

            content_len = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_len)

            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"invalid json")
                return

            state.last_body = payload
            csr_pem = payload.get("csr_pem", "")
            state.csr_valid = (
                isinstance(csr_pem, str)
                and "BEGIN CERTIFICATE REQUEST" in csr_pem
                and "END CERTIFICATE REQUEST" in csr_pem
            )

            if not state.csr_valid:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"missing csr_pem")
                return

            response = {
                "client_cert_pem": CERT_PEM,
                "client_chain_pem": CHAIN_PEM,
            }
            encoded = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format, *args):
            return

    return EnrollHandler


def run_or_raise(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc


def assert_true(condition, message):
    if not condition:
        raise TestFailure(message)


def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_config(path, host, port, identity_dir, trust_dir, inbox_dir, current_dir):
    config = f"""[network]
server_url = http://{host}:{port}
enroll_url = http://{host}:{port}/enroll
tls_ca_cert = {trust_dir}/tls-ca.pem
tls_client_cert = {identity_dir}/client.crt
tls_client_key = {identity_dir}/client.key
connect_timeout = 5
transfer_timeout = 10
low_speed_limit = 0
low_speed_time = 0
retry_attempts = 1

[system]
update_interval_sec = 60
inbox_manifest_dir = {inbox_dir}
current_manifest_dir = {current_dir}
manifest_ca_cert = {trust_dir}/manifest-ca.pem
log_file = {path.parent.parent}/ota-fetch.log
device_id = test-device
"""
    write_text(path, config)


def start_server(expected_token):
    state = ServerState(expected_token)
    handler = make_handler(state)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def run_success_case(ota_fetch_bin, work_root=None):
    with tempfile.TemporaryDirectory(
        prefix="ota-fetch-enroll-success.", dir=work_root
    ) as tmp:
        root = Path(tmp)
        etc_dir = root / "etc" / "ota-fetch"
        trust_dir = etc_dir / "trust"
        identity_dir = root / "var" / "lib" / "ota-fetch" / "identity"
        inbox_dir = root / "var" / "lib" / "ota-fetch" / "inbox"
        current_dir = root / "var" / "lib" / "ota-fetch" / "current"
        token_path = identity_dir / "enroll.token"
        config_path = etc_dir / "ota-fetch.conf"
        key_path = identity_dir / "client.key"
        cert_path = identity_dir / "client.crt"

        write_text(trust_dir / "tls-ca.pem", "test\n")
        write_text(trust_dir / "manifest-ca.pem", "test\n")
        identity_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(identity_dir, 0o700)
        write_text(token_path, TOKEN + "\n")
        os.chmod(token_path, 0o600)

        server, thread, state = start_server(TOKEN)
        port = server.server_address[1]
        try:
            build_config(
                config_path,
                "127.0.0.1",
                port,
                identity_dir,
                trust_dir,
                inbox_dir,
                current_dir,
            )

            cmd = [
                ota_fetch_bin,
                "enroll",
                "--config",
                str(config_path),
                "--token-file",
                str(token_path),
            ]
            proc = run_or_raise(cmd)

            assert_true(
                proc.returncode == 0,
                f"enroll command failed: rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )
            assert_true(key_path.exists(), "client.key not written")
            assert_true(cert_path.exists(), "client.crt not written")
            assert_true(not token_path.exists(), "token file was not deleted")
            assert_true(state.request_count == 1, "stub server did not receive exactly one request")
            assert_true(state.csr_valid, "csr_pem was missing or invalid")

            if os.name == "posix":
                key_mode = stat.S_IMODE(key_path.stat().st_mode)
                cert_mode = stat.S_IMODE(cert_path.stat().st_mode)
                assert_true(
                    key_mode == 0o600,
                    f"client.key mode is {oct(key_mode)}, expected 0o600",
                )
                assert_true(
                    (cert_mode & 0o444) != 0,
                    f"client.crt mode is {oct(cert_mode)}, expected readable permissions",
                )
        finally:
            stop_server(server, thread)


def run_refuse_existing_case(ota_fetch_bin, work_root=None):
    with tempfile.TemporaryDirectory(
        prefix="ota-fetch-enroll-refuse.", dir=work_root
    ) as tmp:
        root = Path(tmp)
        etc_dir = root / "etc" / "ota-fetch"
        trust_dir = etc_dir / "trust"
        identity_dir = root / "var" / "lib" / "ota-fetch" / "identity"
        inbox_dir = root / "var" / "lib" / "ota-fetch" / "inbox"
        current_dir = root / "var" / "lib" / "ota-fetch" / "current"
        token_path = identity_dir / "enroll.token"
        config_path = etc_dir / "ota-fetch.conf"
        key_path = identity_dir / "client.key"
        cert_path = identity_dir / "client.crt"

        write_text(trust_dir / "tls-ca.pem", "test\n")
        write_text(trust_dir / "manifest-ca.pem", "test\n")
        identity_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(identity_dir, 0o700)
        write_text(token_path, TOKEN + "\n")
        os.chmod(token_path, 0o600)
        write_text(key_path, "old-key\n")
        os.chmod(key_path, 0o600)
        write_text(cert_path, "old-cert\n")
        os.chmod(cert_path, 0o644)

        key_before = key_path.read_text(encoding="utf-8")
        cert_before = cert_path.read_text(encoding="utf-8")

        server, thread, state = start_server(TOKEN)
        port = server.server_address[1]
        try:
            build_config(
                config_path,
                "127.0.0.1",
                port,
                identity_dir,
                trust_dir,
                inbox_dir,
                current_dir,
            )

            cmd = [
                ota_fetch_bin,
                "enroll",
                "--config",
                str(config_path),
                "--token-file",
                str(token_path),
            ]
            proc = run_or_raise(cmd)

            assert_true(
                proc.returncode != 0,
                f"enroll unexpectedly succeeded\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )
            assert_true(token_path.exists(), "token file should remain on failure")
            assert_true(key_path.read_text(encoding="utf-8") == key_before, "client.key changed unexpectedly")
            assert_true(cert_path.read_text(encoding="utf-8") == cert_before, "client.crt changed unexpectedly")
            assert_true(state.request_count == 0, "network call should not occur when identity exists without --force")
        finally:
            stop_server(server, thread)


def run_force_overwrite_case(ota_fetch_bin, work_root=None):
    with tempfile.TemporaryDirectory(
        prefix="ota-fetch-enroll-force.", dir=work_root
    ) as tmp:
        root = Path(tmp)
        etc_dir = root / "etc" / "ota-fetch"
        trust_dir = etc_dir / "trust"
        identity_dir = root / "var" / "lib" / "ota-fetch" / "identity"
        inbox_dir = root / "var" / "lib" / "ota-fetch" / "inbox"
        current_dir = root / "var" / "lib" / "ota-fetch" / "current"
        token_path = identity_dir / "enroll.token"
        config_path = etc_dir / "ota-fetch.conf"
        key_path = identity_dir / "client.key"
        cert_path = identity_dir / "client.crt"

        write_text(trust_dir / "tls-ca.pem", "test\n")
        write_text(trust_dir / "manifest-ca.pem", "test\n")
        identity_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(identity_dir, 0o700)
        write_text(token_path, TOKEN + "\n")
        os.chmod(token_path, 0o600)
        write_text(key_path, "old-key\n")
        os.chmod(key_path, 0o600)
        write_text(cert_path, "old-cert\n")
        os.chmod(cert_path, 0o644)

        key_before = key_path.read_text(encoding="utf-8")
        cert_before = cert_path.read_text(encoding="utf-8")

        server, thread, state = start_server(TOKEN)
        port = server.server_address[1]
        try:
            build_config(
                config_path,
                "127.0.0.1",
                port,
                identity_dir,
                trust_dir,
                inbox_dir,
                current_dir,
            )

            cmd = [
                ota_fetch_bin,
                "enroll",
                "--config",
                str(config_path),
                "--token-file",
                str(token_path),
                "--force",
            ]
            proc = run_or_raise(cmd)

            assert_true(
                proc.returncode == 0,
                f"enroll --force failed: rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )
            assert_true(not token_path.exists(), "token file was not deleted")
            assert_true(state.request_count == 1, "stub server did not receive request for --force")
            assert_true(key_path.read_text(encoding="utf-8") != key_before, "client.key was not overwritten")
            assert_true(cert_path.read_text(encoding="utf-8") != cert_before, "client.crt was not overwritten")
        finally:
            stop_server(server, thread)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ota-fetch",
        dest="ota_fetch",
        required=True,
        help="Path to ota-fetch binary",
    )
    parser.add_argument(
        "--work-root",
        help="Optional directory under which to create per-test temporary state",
    )
    parser.add_argument(
        "--case",
        required=True,
        choices=[
            "success",
            "refuse_existing",
            "force_overwrite",
        ],
    )
    args = parser.parse_args()

    ota_fetch_bin = str(Path(args.ota_fetch).resolve())
    if not Path(ota_fetch_bin).exists():
        raise TestFailure(f"ota-fetch binary not found: {ota_fetch_bin}")

    work_root = None
    if args.work_root:
        work_root = Path(args.work_root).resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    if args.case == "success":
        run_success_case(ota_fetch_bin, str(work_root) if work_root else None)
    elif args.case == "refuse_existing":
        run_refuse_existing_case(ota_fetch_bin, str(work_root) if work_root else None)
    elif args.case == "force_overwrite":
        run_force_overwrite_case(ota_fetch_bin, str(work_root) if work_root else None)
    else:
        raise TestFailure(f"unknown case: {args.case}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TestFailure as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
