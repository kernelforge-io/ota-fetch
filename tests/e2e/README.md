# E2E Script Test

Legacy end-to-end validation is provided by:

```bash
./test/scripts/run-fetch-test.sh
```

The script is self-contained:
- Starts a local HTTPS server with required mTLS.
- Generates test certificates and manifest signatures in a temporary directory.
- Uses config keys `tls_ca_cert`, `tls_client_cert`, `tls_client_key`, and `manifest_ca_cert`.
- Uses split trust bundles named `tls-ca-chain.pem` and `manifest-ca-chain.pem`.

Optional environment variables:
- `BUILD_DIR` (default: `build`)
- `OTA_FETCH_BIN` (overrides binary path)
- `SIGNER_KEY_TYPE` (`ec` or `ed25519`, default: `ec`)
- `OTA_FETCH_TEST_PORT` (default: `8443`)
- `OTA_FETCH_WAIT_TIMEOUT_SEC` (default: `10`)
