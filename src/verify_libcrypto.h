// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file verify_libcrypto.h
 * @brief Signature verification API using OpenSSL libcrypto.
 *
 * Provides a detached signature verification helper for OTA update manifests
 * using OpenSSL and X.509 certificates. Used to validate manifest integrity
 * and authenticity via a trusted root CA.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef VERIFY_LIBCRYPTO_H
#define VERIFY_LIBCRYPTO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def VERIFY_ERRBUF_LEN
 * @brief Maximum length of the error message buffer (including null
 * terminator).
 */
#define VERIFY_ERRBUF_LEN 256

/**
 * @defgroup verify Signature Verification
 * @brief Manifest signature verification using OpenSSL.
 * @{
 */

/**
 * @brief Verification result codes for signature and certificate validation.
 */
typedef enum {
	VERIFY_OK = 0,		/**< Verification successful */
	VERIFY_ERR_OPEN_FILE,	/**< Failed to open file */
	VERIFY_ERR_LOAD_CERT,	/**< Failed to load signer certificate */
	VERIFY_ERR_LOAD_CA,	/**< Failed to load root CA(s) */
	VERIFY_ERR_CERT_VERIFY, /**< Certificate failed to verify */
	VERIFY_ERR_LOAD_PUBKEY, /**< Err loading public key from certificate */
	VERIFY_ERR_READ_SIG,	/**< Could not read signature file */
	VERIFY_ERR_MEM,		/**< Out of memory */
	VERIFY_ERR_SIG_VERIFY,	/**< Signature verification failed */
	VERIFY_ERR_HASH,	/**< Failed to compute hash */
	VERIFY_ERR_READ_DATA,	/**< Failed to read data file */
	VERIFY_ERR_UNKNOWN	/**< Unknown/internal error */
} verify_result_t;

/**
 * @brief Verify a detached signature using a signer certificate and CA chain.
 *
 * Verifies that the detached signature in @p sig_path matches @p data_path
 * using the public key from @p cert_path, and that the signer certificate
 * chains to a trusted root CA in @p ca_path. The CA path may reference a
 * PEM bundle file or a directory of hashed CA certificates.
 *
 * Supported key types: Ed25519 (64-byte signature), ECDSA (SHA-256), RSA
 * (SHA-256). The signature file is expected to contain raw signature bytes.
 *
 * @param data_path   Path to the original data file (e.g. manifest.json).
 * @param sig_path    Path to the detached signature file (e.g.
 * manifest.json.sig).
 * @param cert_path   Path to PEM-encoded signer certificate (e.g.
 * signer.crt).
 * @param ca_path     Path to trusted root CA bundle file or directory (PEM).
 * @param errbuf      Buffer for human-readable error message (may be NULL). If
 *                    provided with non-zero length, it is cleared on entry and
 *                    populated on failure (best effort). If no specific
 *                    message is set, an OpenSSL error summary may be used.
 * @param errbuf_len  Size of @p errbuf, including null terminator.
 * @return VERIFY_OK (0) if signature is valid and cert chains to CA; otherwise,
 * error code.
 *
 * @note Uses OpenSSL libcrypto APIs internally.
 */
verify_result_t verify_signature_with_cert(const char *data_path,
					   const char *sig_path,
					   const char *cert_path,
					   const char *ca_path, char *errbuf,
					   size_t errbuf_len);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // VERIFY_LIBCRYPTO_H
