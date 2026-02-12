#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 KERNEL FORGE LLC
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TEST_DIR/.." && pwd)"
SCRIPTS_DIR="$TEST_DIR/scripts"
BASE_MANIFEST_SRC="$TEST_DIR/server/manifest_base.json"

BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
OTA_FETCH_BIN="${OTA_FETCH_BIN:-$BUILD_DIR/ota-fetch}"
PORT="${OTA_FETCH_TEST_PORT:-8443}"
WAIT_TIMEOUT_SEC="${OTA_FETCH_WAIT_TIMEOUT_SEC:-10}"
SIGNER_KEY_TYPE="${SIGNER_KEY_TYPE:-ec}"

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ota-fetch-e2e.XXXXXX")"
SERVER_ROOT="$RUN_DIR/server"
PRIVATE_DIR="$RUN_DIR/private"
CLIENT_DIR="$RUN_DIR/client"
TRUST_DIR="$RUN_DIR/trust"
INBOX_DIR="$RUN_DIR/var/lib/ota_fetch/inbox"
CURRENT_DIR="$RUN_DIR/var/lib/ota_fetch/current"
LOG_DIR="$RUN_DIR/var/log"
CONFIG_PATH="$RUN_DIR/etc/ota_fetch/ota_fetch.conf"
CURRENT_MANIFEST="$CURRENT_DIR/manifest.json"
BASE_MANIFEST="$SERVER_ROOT/manifest_base.json"
DAEMON_LOG="$LOG_DIR/ota_fetch_daemon.log"
SERVER_LOG="$LOG_DIR/https_server.log"

export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1}"
export no_proxy="${no_proxy:-$NO_PROXY}"

PAYLOAD_DEFAULT="$SERVER_ROOT/default/h4-bundle.raucb"
PAYLOAD_GW="$SERVER_ROOT/h4-gw/h4-gw-bundle.raucb"
PAYLOAD_VISION="$SERVER_ROOT/h4-vision/h4-vision-bundle.raucb"

SERVER_PID=""
DAEMON_PID=""

cleanup() {
    local rc=$?
    trap - EXIT

    if [[ -n "$DAEMON_PID" ]]; then
        echo "Stopping ota-fetch daemon (PID $DAEMON_PID)"
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi

    if [[ -n "$SERVER_PID" ]]; then
        echo "Stopping HTTPS server (PID $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    if (( rc != 0 )); then
        echo "===== FAILURE DIAGNOSTICS ====="
        [[ -f "$SERVER_LOG" ]] && sed -n '1,200p' "$SERVER_LOG" || true
        [[ -f "$DAEMON_LOG" ]] && sed -n '1,200p' "$DAEMON_LOG" || true
    fi

    rm -rf "$RUN_DIR"
    exit "$rc"
}
trap cleanup EXIT

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[FAIL] Missing required command: $1"
        exit 1
    }
}

need_cmd python3
need_cmd jq
need_cmd curl
need_cmd sha256sum
need_cmd stat
need_cmd cmake

if [[ ! -x "$OTA_FETCH_BIN" ]]; then
    echo "ota-fetch binary not found at $OTA_FETCH_BIN; building in $BUILD_DIR"
    cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
    cmake --build "$BUILD_DIR"
fi

if [[ ! -x "$OTA_FETCH_BIN" ]]; then
    echo "[FAIL] ota-fetch binary not found: $OTA_FETCH_BIN"
    exit 1
fi

mkdir -p "$SERVER_ROOT" "$PRIVATE_DIR" "$CLIENT_DIR" "$TRUST_DIR" \
         "$INBOX_DIR" "$CURRENT_DIR" "$LOG_DIR" "$(dirname "$CONFIG_PATH")"
cp "$BASE_MANIFEST_SRC" "$BASE_MANIFEST"

prepare_payloads() {
    mkdir -p "$(dirname "$PAYLOAD_DEFAULT")" "$(dirname "$PAYLOAD_GW")" "$(dirname "$PAYLOAD_VISION")"

    if [[ ! -f "$PAYLOAD_DEFAULT" ]]; then
        printf "ota-fetch test bundle\n" > "$PAYLOAD_DEFAULT"
    fi
    if [[ ! -f "$PAYLOAD_GW" ]]; then
        cp "$PAYLOAD_DEFAULT" "$PAYLOAD_GW"
    fi
    if [[ ! -f "$PAYLOAD_VISION" ]]; then
        cp "$PAYLOAD_DEFAULT" "$PAYLOAD_VISION"
    fi
}

payload_hash() {
    sha256sum "$1" | awk '{print $1}'
}

payload_size() {
    stat -c %s "$1"
}

hash_file() {
    if [[ -f "$1" ]]; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

wait_for_manifest_hash() {
    local expected_hash="$1"
    local timeout_sec="$2"
    local elapsed=0

    while (( elapsed < timeout_sec )); do
        if [[ "$(hash_file "$CURRENT_MANIFEST")" == "$expected_hash" ]]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

wait_for_server_ready() {
    local elapsed=0

    while (( elapsed < WAIT_TIMEOUT_SEC )); do
        if curl --silent --show-error --fail \
                --cacert "$TRUST_DIR/tls-ca-chain.pem" \
                --cert "$CLIENT_DIR/client.crt" \
                --key "$CLIENT_DIR/client.key" \
                "https://localhost:${PORT}/manifest_base.json" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

set_manifest_version() {
    local version="$1"
    local manifest="$2"
    local hash
    local size
    hash=$(payload_hash "$PAYLOAD_DEFAULT")
    size=$(payload_size "$PAYLOAD_DEFAULT")

    jq --arg ver "$version" --arg hash "$hash" --argjson size "$size" \
        '.manifest_version = $ver
         | .releases[].files[].sha256 = $hash
         | .releases[].files[].size = $size' \
        "$BASE_MANIFEST" > "$manifest"

    python3 "$SCRIPTS_DIR/sign_manifest.py" \
        --key "$PRIVATE_DIR/signer.key" \
        --infile "$manifest" \
        --sigfile "$SERVER_ROOT/manifest.json.sig"
}

echo "Generating E2E certificates and trust bundles in $RUN_DIR"
python3 "$SCRIPTS_DIR/gen_test_keys.py" \
    --signer-type "$SIGNER_KEY_TYPE" \
    --output-root "$RUN_DIR"
cp "$PRIVATE_DIR/rootCA.crt" "$TRUST_DIR/tls-ca-chain.pem"
cp "$PRIVATE_DIR/rootCA.crt" "$TRUST_DIR/manifest-ca-chain.pem"

cat > "$CONFIG_PATH" <<EOF
[network]
server_url = https://localhost:${PORT}
tls_ca_cert = $TRUST_DIR/tls-ca-chain.pem
tls_client_cert = $CLIENT_DIR/client.crt
tls_client_key = $CLIENT_DIR/client.key
connect_timeout = 5
transfer_timeout = 30
retry_attempts = 1

[system]
update_interval_sec = 1
inbox_manifest_dir = $INBOX_DIR
current_manifest_dir = $CURRENT_DIR
manifest_ca_cert = $TRUST_DIR/manifest-ca-chain.pem
log_file = $LOG_DIR/ota_fetch.log
EOF

echo "Starting local HTTPS (mTLS) test server on port $PORT"
prepare_payloads
python3 "$SCRIPTS_DIR/https_server.py" "$PORT" --root "$RUN_DIR" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

if ! wait_for_server_ready; then
    echo "[FAIL] HTTPS test server did not become ready in time."
    exit 1
fi

set_manifest_version "8.8.8-test" "$SERVER_ROOT/manifest.json"

echo "Cleaning current and inbox directories..."
rm -f "$INBOX_DIR"/* "$CURRENT_DIR"/*

echo "===== FIRST ota-fetch RUN (should apply update) ====="
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Manifest unchanged after first run."
else
    echo "[FAIL] Manifest hash changed unexpectedly after first run."
    exit 1
fi

echo "===== SECOND ota-fetch RUN (should do nothing) ====="
"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Manifest unchanged after second run."
else
    echo "[FAIL] Manifest hash changed unexpectedly after second run."
    exit 1
fi

echo "===== MODIFY MANIFEST TO SIMULATE NEW UPDATE ====="
set_manifest_version "9.9.9-test" "$SERVER_ROOT/manifest.json"

"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --oneshot

SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] New manifest applied and matches server version."
else
    echo "[FAIL] Manifest hash changed unexpectedly after third run."
    exit 1
fi

echo "===== DAEMON MODE TEST (UPDATE INTERVAL) ====="
PAYLOAD_NAME=$(jq -r '.releases[] | select(.device_id=="default") | .files[0].filename' "$BASE_MANIFEST")
if [[ -z "$PAYLOAD_NAME" || "$PAYLOAD_NAME" == "null" ]]; then
    echo "[FAIL] Could not determine default payload filename."
    exit 1
fi
INBOX_PAYLOAD="$INBOX_DIR/$PAYLOAD_NAME"
rm -f "$INBOX_PAYLOAD"

"$OTA_FETCH_BIN" --config="$CONFIG_PATH" --daemon >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

sleep 2

SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")
CUR_HASH=$(hash_file "$CURRENT_MANIFEST")
if [[ "$SERVER_HASH" == "$CUR_HASH" ]]; then
    echo "[OK] Daemon idle while up to date."
else
    echo "[FAIL] Daemon changed manifest while up to date."
    exit 1
fi
if [[ -e "$INBOX_PAYLOAD" ]]; then
    echo "[FAIL] Daemon downloaded payload while up to date."
    exit 1
fi
echo "[OK] Daemon did not download payload while up to date."

set_manifest_version "10.10.10-test" "$SERVER_ROOT/manifest.json"
SERVER_HASH=$(hash_file "$SERVER_ROOT/manifest.json")

if wait_for_manifest_hash "$SERVER_HASH" "$WAIT_TIMEOUT_SEC"; then
    echo "[OK] Daemon applied new manifest within interval."
else
    echo "[FAIL] Daemon did not apply new manifest in time."
    exit 1
fi
if [[ -f "$INBOX_PAYLOAD" ]]; then
    echo "[OK] Daemon downloaded payload for update."
else
    echo "[FAIL] Daemon did not download payload for update."
    exit 1
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo "===== ALL TESTS PASSED ====="
exit 0
