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

## Test Discovery and Targeted Runs

List tests:

```bash
ctest --test-dir build -N
```

Run a single test by regex:

```bash
ctest --test-dir build -R <name> --output-on-failure
```

## Legacy Integration Scripts

`test/scripts/` remains available for manual HTTPS/mTLS integration checks, but
it is not the default local test workflow and is not used as the primary CI
gate.
