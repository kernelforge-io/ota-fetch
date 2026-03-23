<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2025-2026 KERNEL FORGE LLC -->

# Testing

`ota-fetch` uses CMake + CTest as the default and authoritative test runner.
All default tests are offline and deterministic.

## Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
  cmake \
  gcc \
  jq \
  python3 \
  python3-cryptography \
  clang-format-18 \
  curl \
  libcjson-dev \
  libcurl4-openssl-dev \
  libssl-dev
```

## Build + Run Tests

Use these exact commands:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

The default CTest suite covers config parsing, manifest parsing, SHA-256
helpers, logging/progress formatting helpers, and the enrollment flow.

## Test Discovery and Targeted Runs

List tests:

```bash
ctest --test-dir build -N
```

Run a single test by regex:

```bash
ctest --test-dir build -R <name> --output-on-failure
```

## Formatting Check

CI runs `clang-format-18`. A practical local check for touched C sources is:

```bash
clang-format-18 --dry-run --Werror src/*.c src/*.h tests/*.c tests/*.h
```

## Legacy HTTPS/mTLS Integration

For an end-to-end local regression of the real download path, run:

```bash
bash test/scripts/run-fetch-test.sh
```

This script starts a local HTTPS server with mTLS, exercises oneshot and daemon
flows, and verifies manifest/payload handling. It additionally requires
`python3-cryptography`, `jq`, and `curl`.

`test/scripts/` remains available for manual HTTPS/mTLS integration checks, but
it is not the default local test workflow and is not used as the primary CI
gate.
