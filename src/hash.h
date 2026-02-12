// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file hash.h
 * @brief SHA-256 hashing and hex formatting helpers.
 *
 * Provides:
 *  - File SHA-256 hashing for integrity verification
 *  - Hex formatting helpers suitable for logging/diagnostics
 *
 * No I/O is performed by formatting helpers.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup hash Hashing Helpers
 * @brief SHA-256 helpers for file integrity checks.
 * @{
 */

/** Length of a SHA-256 digest in bytes. */
#define SHA256_DIGEST_LEN 32

/** Return codes for sha256sum_file(). */
typedef enum {
	SHA256SUM_OK = 0,     /**< Success */
	SHA256SUM_EOPEN = -1, /**< Failed to open file (errno set by fopen()) */
	SHA256SUM_EREAD = -2, /**< I/O error reading file (ferror() true) */
	SHA256SUM_EINVAL = -3,	/**< Invalid argument */
	SHA256SUM_EINIT = -4,	/**< EVP_DigestInit_ex() failed */
	SHA256SUM_EUPDATE = -5, /**< EVP_DigestUpdate() failed */
	SHA256SUM_EFINAL = -6,	/**< EVP_DigestFinal_ex() failed */
} sha256sum_rc_t;

/**
 * @brief Compute the SHA-256 digest of a file.
 *
 * Reads the file at @p path and computes a SHA-256 digest over its contents.
 * On success, writes exactly ::SHA256_DIGEST_LEN bytes to @p digest_out.
 *
 * @param path       Path to the file to hash (must not be NULL).
 * @param digest_out Output buffer (must not be NULL; size >=
 * ::SHA256_DIGEST_LEN).
 *
 * @return One of ::sha256sum_rc_t values.
 */
int sha256sum_file(const char *path, uint8_t *digest_out);

/**
 * @brief Encode a digest to lowercase hex into a caller-provided buffer.
 *
 * Writes 2*len hex characters plus a terminating NUL to @p out.
 *
 * @param out     Output buffer for hex string (must not be NULL).
 * @param out_sz  Size of @p out in bytes. Must be >= (len*2 + 1).
 * @param in      Input bytes to encode (must not be NULL).
 * @param len     Number of bytes in @p in.
 *
 * @retval 0   Success.
 * @retval -1  Invalid argument.
 * @retval -2  Output buffer too small.
 */
int hex_encode(char *out, size_t out_sz, const uint8_t *in, size_t len);

/**
 * @brief Format a SHA-256 digest as lowercase hex for logging.
 *
 * Convenience wrapper that returns a pointer to an internal buffer containing
 * 64 lowercase hex characters plus a terminating NUL.
 *
 * @note The returned pointer refers to an internal buffer. Do not free it.
 * @note Thread-safety depends on platform support for thread-local storage.
 *       Prefer hex_encode() if you need strict portability and reentrancy.
 *
 * @param digest Pointer to a ::SHA256_DIGEST_LEN-byte digest. If NULL, a
 *               placeholder string is returned.
 *
 * @return Pointer to an internal NUL-terminated string.
 */
const char *sha256_hex(const uint8_t digest[SHA256_DIGEST_LEN]);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* HASH_H */
