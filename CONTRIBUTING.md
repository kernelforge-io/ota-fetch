# Contributing

Thanks for your interest in improving ota-fetch.

## Build

Dependencies (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake \
  libcurl4-openssl-dev libssl-dev libcjson-dev
```

Build:

```bash
cmake -B build -S .
cmake --build build
```

## Tests

Use CMake + CTest for default local and CI test execution:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

See `TESTING.md` for test discovery and targeted test runs.

Legacy HTTPS/mTLS integration scripts in `test/scripts/` remain available for
manual validation but are not the primary CI gate.

## Style and expectations

- C11, keep changes minimal and focused.
- Prefer clear error handling and unambiguous logs.
- Maintain Doxygen comments for public headers and core modules.
- Use underscores in directory names; hyphens are reserved for executables.
