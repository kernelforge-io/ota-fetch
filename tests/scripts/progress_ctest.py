#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC

import argparse
import errno
import hashlib
import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOAD_FILENAME = "progress-bundle.raucb"
PAYLOAD_RELATIVE_PATH = f"default/{PAYLOAD_FILENAME}"
PAYLOAD_SIZE = 1024 * 1024
PAYLOAD_CHUNK_SIZE = 32768
PAYLOAD_CHUNK_DELAY_SEC = 0.05


class TestFailure(Exception):
    pass


class ServerState:
    def __init__(self, root: Path):
        self.root = root
        self.payload_requests = 0


def assert_true(condition, message):
    if not condition:
        raise TestFailure(message)


def write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_checked(cmd, cwd=None):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TestFailure(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
                " ".join(cmd), proc.stdout, proc.stderr
            )
        )
    return proc


def generate_signing_material(work_root: Path):
    openssl = shutil.which("openssl")
    if not openssl:
        raise TestFailure("openssl command not found")

    trust_dir = work_root / "trust"
    private_dir = work_root / "private"
    server_dir = work_root / "server"

    trust_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)
    server_dir.mkdir(parents=True, exist_ok=True)

    root_ca_key = private_dir / "rootCA.key"
    root_ca_cert = trust_dir / "rootCA.crt"
    signer_key = private_dir / "signer.key"
    signer_csr = private_dir / "signer.csr"
    signer_cert = server_dir / "signer.crt"
    signer_ext = private_dir / "signer.ext"

    write_text(
        signer_ext,
        "\n".join(
            [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,nonRepudiation",
                "extendedKeyUsage=codeSigning",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
                "",
            ]
        ),
    )

    run_checked(
        [
            openssl,
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(root_ca_key),
        ]
    )
    run_checked(
        [
            openssl,
            "req",
            "-x509",
            "-new",
            "-key",
            str(root_ca_key),
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=Progress Test Root CA",
            "-out",
            str(root_ca_cert),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )

    run_checked(
        [
            openssl,
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(signer_key),
        ]
    )
    run_checked(
        [
            openssl,
            "req",
            "-new",
            "-key",
            str(signer_key),
            "-out",
            str(signer_csr),
            "-subj",
            "/CN=Progress Manifest Signer",
        ]
    )
    run_checked(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(signer_csr),
            "-CA",
            str(root_ca_cert),
            "-CAkey",
            str(root_ca_key),
            "-CAcreateserial",
            "-out",
            str(signer_cert),
            "-days",
            "730",
            "-sha256",
            "-extfile",
            str(signer_ext),
        ]
    )

    return root_ca_cert, signer_key, signer_cert


def prepare_server_files(work_root: Path, root_ca_cert: Path, signer_key: Path):
    server_dir = work_root / "server"
    payload_path = server_dir / PAYLOAD_RELATIVE_PATH
    manifest_path = server_dir / "manifest.json"
    signature_path = server_dir / "manifest.json.sig"

    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (b"ota-fetch progress validation\n" * 4096)[:PAYLOAD_SIZE]
    if len(payload) < PAYLOAD_SIZE:
        payload += b"x" * (PAYLOAD_SIZE - len(payload))
    payload_path.write_bytes(payload)

    payload_hash = hashlib.sha256(payload).hexdigest()
    manifest = {
        "manifest_version": "progress-test-1",
        "created": "2026-03-22T00:00:00Z",
        "releases": [
            {
                "device_id": "progress-device",
                "release_name": "progress-demo",
                "release_version": "1.0.0",
                "created": "2026-03-22T00:00:00Z",
                "files": [
                    {
                        "file_type": "rauc_bundle_test",
                        "filename": PAYLOAD_FILENAME,
                        "size": PAYLOAD_SIZE,
                        "sha256": payload_hash,
                        "path": PAYLOAD_RELATIVE_PATH,
                    }
                ],
            }
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    run_checked(
        [
            shutil.which("openssl"),
            "dgst",
            "-sha256",
            "-sign",
            str(signer_key),
            "-out",
            str(signature_path),
            str(manifest_path),
        ]
    )

    return payload_path, manifest_path, signature_path, root_ca_cert


def build_config(
    path: Path,
    host: str,
    port: int,
    inbox_dir: Path,
    current_dir: Path,
    log_file: Path,
    root_ca_cert: Path,
    signer_cert: Path,
    signer_key: Path,
):
    config = f"""[network]
server_url = http://{host}:{port}
tls_ca_cert = {root_ca_cert}
tls_client_cert = {signer_cert}
tls_client_key = {signer_key}
connect_timeout = 5
transfer_timeout = 30
low_speed_limit = 0
low_speed_time = 0
retry_attempts = 1

[system]
update_interval_sec = 60
inbox_manifest_dir = {inbox_dir}
current_manifest_dir = {current_dir}
manifest_ca_cert = {root_ca_cert}
log_file = {log_file}
device_id = progress-device
"""
    write_text(path, config)


def make_handler(state: ServerState):
    class ProgressHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            relative_path = self.path.lstrip("/")
            file_path = state.root / relative_path

            if not file_path.exists():
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Length", str(file_path.stat().st_size))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()

            if relative_path == PAYLOAD_RELATIVE_PATH:
                state.payload_requests += 1
                with file_path.open("rb") as fp:
                    while True:
                        chunk = fp.read(PAYLOAD_CHUNK_SIZE)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        time.sleep(PAYLOAD_CHUNK_DELAY_SEC)
                return

            self.wfile.write(file_path.read_bytes())

        def log_message(self, format, *args):
            return

    return ProgressHandler


def start_server(server_root: Path):
    state = ServerState(server_root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def run_with_tty_stderr(cmd, env):
    if os.name != "posix":
        raise TestFailure("progress TTY test requires POSIX support")

    master_fd, slave_fd = pty.openpty()
    stderr_chunks = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=slave_fd,
            env=env,
            close_fds=True,
        )
    finally:
        os.close(slave_fd)

    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        os.close(master_fd)
        raise TestFailure("ota-fetch timed out in TTY progress test")

    while True:
        try:
            chunk = os.read(master_fd, 4096)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            os.close(master_fd)
            raise
        if not chunk:
            break
        stderr_chunks.append(chunk)

    os.close(master_fd)
    return proc.returncode, b"".join(stderr_chunks).decode("utf-8", errors="replace")


def run_with_pipe_stderr(cmd, env):
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stderr


def build_env():
    env = os.environ.copy()
    env["NO_PROXY"] = env.get("NO_PROXY", "127.0.0.1,localhost")
    env["no_proxy"] = env.get("no_proxy", env["NO_PROXY"])
    return env


def prepare_case(work_root):
    root = Path(work_root)
    etc_dir = root / "etc" / "ota-fetch"
    inbox_dir = root / "var" / "lib" / "ota-fetch" / "inbox"
    current_dir = root / "var" / "lib" / "ota-fetch" / "current"
    log_file = root / "var" / "log" / "ota-fetch.log"
    config_path = etc_dir / "ota-fetch.conf"

    log_file.parent.mkdir(parents=True, exist_ok=True)

    root_ca_cert, signer_key, signer_cert = generate_signing_material(root)
    payload_path, manifest_path, signature_path, manifest_ca_cert = prepare_server_files(
        root, root_ca_cert, signer_key
    )

    build_config(
        config_path,
        "127.0.0.1",
        0,
        inbox_dir,
        current_dir,
        log_file,
        root_ca_cert,
        signer_cert,
        signer_key,
    )

    server, thread, state = start_server(root / "server")
    actual_port = server.server_address[1]
    build_config(
        config_path,
        "127.0.0.1",
        actual_port,
        inbox_dir,
        current_dir,
        log_file,
        root_ca_cert,
        signer_cert,
        signer_key,
    )

    return {
        "root": root,
        "config_path": config_path,
        "inbox_dir": inbox_dir,
        "current_dir": current_dir,
        "log_file": log_file,
        "payload_path": payload_path,
        "manifest_path": manifest_path,
        "signature_path": signature_path,
        "server": server,
        "thread": thread,
        "state": state,
    }


def validate_success_artifacts(case_data):
    current_manifest = case_data["current_dir"] / "manifest.json"
    inbox_payload = case_data["inbox_dir"] / PAYLOAD_FILENAME

    assert_true(current_manifest.exists(), "current manifest was not written")
    assert_true(inbox_payload.exists(), "payload file was not downloaded")
    assert_true(case_data["state"].payload_requests == 1, "payload was not requested exactly once")
    assert_true(case_data["log_file"].exists(), "log file was not created")


def run_tty_progress_case(ota_fetch_bin, work_root=None):
    with tempfile.TemporaryDirectory(prefix="ota-fetch-progress-tty.", dir=work_root) as tmp:
        case_data = prepare_case(tmp)
        cmd = [ota_fetch_bin, "--config", str(case_data["config_path"]), "--oneshot"]

        try:
            rc, stderr_text = run_with_tty_stderr(cmd, build_env())
        finally:
            stop_server(case_data["server"], case_data["thread"])

        assert_true(
            rc == 0,
            f"tty progress run failed: rc={rc}\nstderr:\n{stderr_text}",
        )
        assert_true(
            "[PROGRESS]" in stderr_text,
            f"expected progress output on TTY stderr, got:\n{stderr_text}",
        )
        assert_true(
            "Downloading payload: progress-bundle.raucb" in stderr_text,
            f"payload start log missing:\n{stderr_text}",
        )
        assert_true(
            "Payload download completed:" in stderr_text,
            f"payload completion log missing:\n{stderr_text}",
        )
        validate_success_artifacts(case_data)

        log_text = case_data["log_file"].read_text(encoding="utf-8")
        assert_true(
            "[PROGRESS]" not in log_text,
            f"progress lines should not be written to log_file:\n{log_text}",
        )


def run_non_tty_case(ota_fetch_bin, work_root=None):
    with tempfile.TemporaryDirectory(prefix="ota-fetch-progress-pipe.", dir=work_root) as tmp:
        case_data = prepare_case(tmp)
        cmd = [ota_fetch_bin, "--config", str(case_data["config_path"]), "--oneshot"]

        try:
            rc, stderr_text = run_with_pipe_stderr(cmd, build_env())
        finally:
            stop_server(case_data["server"], case_data["thread"])

        assert_true(
            rc == 0,
            f"non-tty progress run failed: rc={rc}\nstderr:\n{stderr_text}",
        )
        assert_true(
            "[PROGRESS]" in stderr_text,
            f"expected milestone progress output on non-tty stderr, got:\n{stderr_text}",
        )
        assert_true(
            "Downloading payload: progress-bundle.raucb" in stderr_text,
            f"payload start log missing:\n{stderr_text}",
        )
        progress_lines = [
            line for line in stderr_text.splitlines() if line.startswith("[PROGRESS]")
        ]
        assert_true(
            len(progress_lines) >= 2,
            f"expected multiple progress milestones in stderr:\n{stderr_text}",
        )
        assert_true(
            "100%" in stderr_text,
            f"expected final progress milestone in stderr:\n{stderr_text}",
        )
        assert_true(
            "Payload download completed:" in stderr_text,
            f"payload completion log missing:\n{stderr_text}",
        )
        validate_success_artifacts(case_data)


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
        choices=["tty_progress", "non_tty_milestones"],
    )
    args = parser.parse_args()

    ota_fetch_bin = str(Path(args.ota_fetch).resolve())
    if not Path(ota_fetch_bin).exists():
        raise TestFailure(f"ota-fetch binary not found: {ota_fetch_bin}")

    work_root = None
    if args.work_root:
        work_root = Path(args.work_root).resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    if args.case == "tty_progress":
        run_tty_progress_case(ota_fetch_bin, str(work_root) if work_root else None)
    elif args.case == "non_tty_milestones":
        run_non_tty_case(ota_fetch_bin, str(work_root) if work_root else None)
    else:
        raise TestFailure(f"unknown case: {args.case}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TestFailure as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
