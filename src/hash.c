// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file hash.c
 * @brief SHA-256 hashing and hex formatting helpers.
 */

#include "hash.h"
#include "logging.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static void log_openssl_error(const char *context) {
	unsigned long err;
	char msg[160];

	err = ERR_get_error();
	if (err == 0) {
		LOG_ERROR("%s", context);
		return;
	}

	ERR_error_string_n(err, msg, sizeof(msg));
	LOG_ERROR("%s: %s", context, msg);
	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, msg, sizeof(msg));
		LOG_ERROR("%s: %s", context, msg);
	}
}

/* ------------------------------------------------------------------------ */
int sha256sum_file(const char *path, uint8_t *digest_out) {
	EVP_MD_CTX *ctx = NULL;
	FILE *fp = NULL;
	unsigned char buf[4096];
	unsigned int digest_len = 0;
	size_t n;
	int rc = SHA256SUM_OK;

	if (!path || !digest_out)
		return SHA256SUM_EINVAL;

	fp = fopen(path, "rb");
	if (!fp) {
		LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
		return SHA256SUM_EOPEN;
	}

	ERR_clear_error();
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		log_openssl_error("EVP_MD_CTX_new failed");
		rc = SHA256SUM_EINIT;
		goto cleanup;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		log_openssl_error("EVP_DigestInit_ex failed");
		rc = SHA256SUM_EINIT;
		goto cleanup;
	}

	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (EVP_DigestUpdate(ctx, buf, n) != 1) {
			log_openssl_error("EVP_DigestUpdate failed");
			rc = SHA256SUM_EUPDATE;
			goto cleanup;
		}
	}

	if (ferror(fp)) {
		LOG_ERROR("Failed to read %s: %s", path, strerror(errno));
		rc = SHA256SUM_EREAD;
		goto cleanup;
	}

	if (EVP_DigestFinal_ex(ctx, digest_out, &digest_len) != 1) {
		log_openssl_error("EVP_DigestFinal_ex failed");
		rc = SHA256SUM_EFINAL;
		goto cleanup;
	}
	if (digest_len != SHA256_DIGEST_LEN) {
		LOG_ERROR("Unexpected SHA-256 length %u", digest_len);
		rc = SHA256SUM_EFINAL;
		goto cleanup;
	}

cleanup:
	EVP_MD_CTX_free(ctx);
	if (fp)
		fclose(fp);
	return rc;
}

/* ------------------------------------------------------------------------ */
int hex_encode(char *out, size_t out_sz, const uint8_t *in, size_t len) {
	if (!out || !in)
		return -1;
	if (out_sz < (len * 2 + 1))
		return -2;

	static const char hexd[] = "0123456789abcdef";
	for (size_t i = 0; i < len; ++i) {
		out[i * 2 + 0] = hexd[(in[i] >> 4) & 0xF];
		out[i * 2 + 1] = hexd[in[i] & 0xF];
	}
	out[len * 2] = '\0';
	return 0;
}

/* ------------------------------------------------------------------------ */
const char *sha256_hex(const uint8_t digest[SHA256_DIGEST_LEN]) {
	if (!digest)
		return "(null)";

	/* Use Thread local storage when available;
	 * Fall back to a single static buffer. */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
	enum { RING_SLOTS = 4 };
	static _Thread_local char ring[RING_SLOTS][SHA256_DIGEST_LEN * 2 + 1];
	static _Thread_local unsigned idx;
	char *out = ring[idx++ % RING_SLOTS];
#else
	static char out[SHA256_DIGEST_LEN * 2 + 1];
#endif

	(void)hex_encode(out, SHA256_DIGEST_LEN * 2 + 1, digest,
			 SHA256_DIGEST_LEN);
	return out;
}
