// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file verify_libcrypto.c
 * @brief OpenSSL-backed manifest signature verification.
 *
 * Verifies detached signatures over manifest.json using a signer certificate
 * and validates the signer certificate against a trusted root CA bundle or
 * hashed CA directory.
 */

#include "verify_libcrypto.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "logging.h"

#define SIG_MAX_LEN (16u * 1024u)
#define SIG_ED25519_LEN 64u
#define MANIFEST_MAX_LEN (1024u * 1024u)

/* ------------------------------------------------------------------------ */
/* Format OpenSSL error stack into a single string (best effort). */
static void format_openssl_errors(char *errbuf, size_t len) {
	unsigned long err;
	size_t used = 0;

	if (!errbuf || len == 0)
		return;

	errbuf[0] = '\0';
	while ((err = ERR_get_error()) != 0) {
		char msg[256];
		int written;

		ERR_error_string_n(err, msg, sizeof(msg));
		written = snprintf(errbuf + used, len - used, "%s%s",
				   used ? "; " : "", msg);
		if (written < 0 || (size_t)written >= len - used) {
			errbuf[len - 1] = '\0';
			break;
		}
		used += (size_t)written;
	}
}

/* ------------------------------------------------------------------------ */
/* Clear OpenSSL error state and reset caller error buffer. */
static void init_error_state(char *errbuf, size_t errbuf_len) {
	ERR_clear_error();
	if (errbuf && errbuf_len > 0)
		errbuf[0] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Write a formatted error message if the caller provided a buffer. */
static void set_errbuf(char *errbuf, size_t errbuf_len, const char *fmt, ...) {
	va_list args;

	if (!errbuf || errbuf_len == 0)
		return;

	va_start(args, fmt);
	vsnprintf(errbuf, errbuf_len, fmt, args);
	va_end(args);

	errbuf[errbuf_len - 1] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Write a formatted error message and append OpenSSL errors if present. */
static void set_errbuf_openssl(char *errbuf, size_t errbuf_len, const char *fmt,
			       ...) {
	char prefix[128];
	char openssl_err[VERIFY_ERRBUF_LEN];
	va_list args;
	int written;

	if (!errbuf || errbuf_len == 0)
		return;

	va_start(args, fmt);
	vsnprintf(prefix, sizeof(prefix), fmt, args);
	va_end(args);
	prefix[sizeof(prefix) - 1] = '\0';

	openssl_err[0] = '\0';
	format_openssl_errors(openssl_err, sizeof(openssl_err));

	if (openssl_err[0])
		written = snprintf(errbuf, errbuf_len, "%s: %s", prefix,
				   openssl_err);
	else
		written = snprintf(errbuf, errbuf_len, "%s", prefix);
	if (written < 0 || (size_t)written >= errbuf_len)
		errbuf[errbuf_len - 1] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Provide a user-friendly key type label for logs and errors. */
static const char *friendly_key_type_name(EVP_PKEY *pkey, char *tmp,
					  size_t tmp_len) {
	int key_type;
	int written;

	if (!pkey)
		return "unknown";

	key_type = EVP_PKEY_base_id(pkey);
	switch (key_type) {
	case EVP_PKEY_ED25519:
		return "Ed25519";
	case EVP_PKEY_EC:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		{
			char group_name[80];
			size_t group_len = 0;
			const char *curve_name = NULL;

			if (EVP_PKEY_get_utf8_string_param(
				pkey, OSSL_PKEY_PARAM_GROUP_NAME,
				group_name, sizeof(group_name),
				&group_len) != 1)
				return "ECDSA";

			if (group_len >= sizeof(group_name))
				group_name[sizeof(group_name) - 1] = '\0';
			else
				group_name[group_len] = '\0';

			curve_name = group_name;
			if (strcmp(group_name, "prime256v1") == 0 ||
			    strcmp(group_name, "secp256r1") == 0)
				curve_name = "P-256";

			if (!curve_name || !tmp || tmp_len == 0)
				return "ECDSA";
			written = snprintf(tmp, tmp_len, "ECDSA %s",
					   curve_name);
			if (written < 0 || (size_t)written >= tmp_len)
				return "ECDSA";
			return tmp;
		}
#else
		{
			const EC_KEY *ec_key = NULL;
			const EC_GROUP *ec_group = NULL;
			const char *curve_name = NULL;
			int curve_nid;

			ec_key = EVP_PKEY_get0_EC_KEY(pkey);
			if (!ec_key)
				return "ECDSA";
			ec_group = EC_KEY_get0_group(ec_key);
			if (!ec_group)
				return "ECDSA";
			curve_nid = EC_GROUP_get_curve_name(ec_group);
			if (curve_nid == NID_undef)
				return "ECDSA";
			if (curve_nid == NID_X9_62_prime256v1)
				curve_name = "P-256";
			else
				curve_name = OBJ_nid2sn(curve_nid);
			if (!curve_name || !tmp || tmp_len == 0)
				return "ECDSA";
			written = snprintf(tmp, tmp_len, "ECDSA %s",
					   curve_name);
			if (written < 0 || (size_t)written >= tmp_len)
				return "ECDSA";
			return tmp;
		}
#endif
	case EVP_PKEY_RSA:
		return "RSA";
	default:
		return "unknown";
	}
}

enum read_file_status {
	READ_FILE_OK = 1,
	READ_FILE_OPEN = 0,
	READ_FILE_READ = -1,
	READ_FILE_MEM = -2,
	READ_FILE_TOO_LARGE = -3
};

/* ------------------------------------------------------------------------ */
/* Read an entire file into memory (used for Ed25519 one-shot verify). */
static int read_file_all(const char *path, unsigned char **out,
			 size_t *out_len) {
	FILE *fp = NULL;
	unsigned char *buf = NULL;
	long file_len = 0;
	size_t len = 0;
	size_t read_len;

	if (!path || !out || !out_len)
		return READ_FILE_READ;

	*out = NULL;
	*out_len = 0;

	fp = fopen(path, "rb");
	if (!fp)
		return READ_FILE_OPEN;

	if (fseek(fp, 0, SEEK_END) != 0)
		goto read_fail;
	file_len = ftell(fp);
	if (file_len < 0)
		goto read_fail;
	if (file_len > (long)MANIFEST_MAX_LEN) {
		*out_len = (size_t)file_len;
		fclose(fp);
		return READ_FILE_TOO_LARGE;
	}
	if (fseek(fp, 0, SEEK_SET) != 0)
		goto read_fail;

	if (file_len == 0) {
		fclose(fp);
		return READ_FILE_OK;
	}

	len = (size_t)file_len;
	if ((long)len != file_len)
		goto read_fail;

	buf = (unsigned char *)malloc(len);
	if (!buf) {
		fclose(fp);
		return READ_FILE_MEM;
	}

	read_len = fread(buf, 1, len, fp);
	if (read_len != len)
		goto read_fail;

	fclose(fp);
	*out = buf;
	*out_len = len;
	return READ_FILE_OK;

read_fail:
	if (fp)
		fclose(fp);
	if (buf) {
		OPENSSL_cleanse(buf, len);
		free(buf);
	}
	return READ_FILE_READ;
}

/* ------------------------------------------------------------------------ */
/* Load a PEM-encoded signer certificate from disk. */
static verify_result_t load_signer_cert(const char *cert_path, X509 **out_cert,
					char *errbuf, size_t errbuf_len) {
	FILE *fp = NULL;
	X509 *cert = NULL;

	if (!cert_path || !out_cert)
		return VERIFY_ERR_UNKNOWN;

	*out_cert = NULL;
	fp = fopen(cert_path, "rb");
	if (!fp) {
		set_errbuf(errbuf, errbuf_len,
			   "Failed to open signer certificate: %s", cert_path);
		return VERIFY_ERR_OPEN_FILE;
	}

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!cert) {
		set_errbuf_openssl(errbuf, errbuf_len,
				   "Failed to load signer certificate: %s",
				   cert_path);
		return VERIFY_ERR_LOAD_CERT;
	}

	*out_cert = cert;
	return VERIFY_OK;
}

/* ------------------------------------------------------------------------ */
/* Load a CA bundle (file or directory) into an X509 store. */
static verify_result_t load_ca_store(const char *ca_path,
				     X509_STORE **out_store, char *errbuf,
				     size_t errbuf_len) {
	X509_STORE *store = NULL;
	struct stat st;

	if (!ca_path || !out_store)
		return VERIFY_ERR_UNKNOWN;

	*out_store = NULL;
	store = X509_STORE_new();
	if (!store) {
		set_errbuf(errbuf, errbuf_len,
			   "Out of memory creating CA store");
		return VERIFY_ERR_MEM;
	}

	if (stat(ca_path, &st) != 0) {
		set_errbuf(errbuf, errbuf_len, "Failed to stat CA path: %s",
			   ca_path);
		X509_STORE_free(store);
		return VERIFY_ERR_LOAD_CA;
	}

	if (S_ISDIR(st.st_mode)) {
		if (X509_STORE_load_locations(store, NULL, ca_path) != 1) {
			set_errbuf_openssl(errbuf, errbuf_len,
					   "Failed to load CA directory: %s",
					   ca_path);
			X509_STORE_free(store);
			return VERIFY_ERR_LOAD_CA;
		}
	} else {
		if (X509_STORE_load_locations(store, ca_path, NULL) != 1) {
			set_errbuf_openssl(errbuf, errbuf_len,
					   "Failed to load CA bundle: %s",
					   ca_path);
			X509_STORE_free(store);
			return VERIFY_ERR_LOAD_CA;
		}
	}

	*out_store = store;
	return VERIFY_OK;
}

/* ------------------------------------------------------------------------ */
/* Verify the signer certificate against the provided CA store. */
static verify_result_t verify_signer_cert(X509_STORE *store, X509 *cert,
					  char *errbuf, size_t errbuf_len) {
	X509_STORE_CTX *ctx = NULL;
	verify_result_t result = VERIFY_OK;

	if (!store || !cert) {
		set_errbuf(errbuf, errbuf_len,
			   "Certificate verification failed: invalid inputs");
		return VERIFY_ERR_CERT_VERIFY;
	}

	ctx = X509_STORE_CTX_new();
	if (!ctx) {
		set_errbuf(errbuf, errbuf_len,
			   "Out of memory creating cert verify context");
		return VERIFY_ERR_MEM;
	}

	if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
		set_errbuf_openssl(errbuf, errbuf_len,
				   "Certificate verification init failed");
		result = VERIFY_ERR_CERT_VERIFY;
		goto cleanup;
	}

	if (X509_verify_cert(ctx) != 1) {
		set_errbuf(errbuf, errbuf_len,
			   "Certificate verification failed: %s",
			   X509_verify_cert_error_string(
			       X509_STORE_CTX_get_error(ctx)));
		result = VERIFY_ERR_CERT_VERIFY;
		goto cleanup;
	}

cleanup:
	if (ctx)
		X509_STORE_CTX_free(ctx);
	return result;
}

/* ------------------------------------------------------------------------ */
/* Extract the public key and friendly name from the signer certificate. */
static verify_result_t
load_public_key(X509 *cert, EVP_PKEY **out_key, int *out_key_type,
		const char **out_key_name, char *key_name_buf,
		size_t key_name_buf_len, char *errbuf, size_t errbuf_len) {
	EVP_PKEY *pubkey = NULL;

	if (!cert || !out_key || !out_key_type || !out_key_name)
		return VERIFY_ERR_UNKNOWN;

	pubkey = X509_get_pubkey(cert);
	if (!pubkey) {
		set_errbuf_openssl(
		    errbuf, errbuf_len,
		    "Failed to load public key from signer cert");
		return VERIFY_ERR_LOAD_PUBKEY;
	}

	*out_key = pubkey;
	*out_key_type = EVP_PKEY_base_id(pubkey);
	*out_key_name = friendly_key_type_name(pubkey, key_name_buf,
					       key_name_buf_len);
	return VERIFY_OK;
}

/* ------------------------------------------------------------------------ */
/* Read a detached signature file with basic size sanity checks.
 * Signature file is expected to contain raw signature bytes. */
static verify_result_t read_signature_file(const char *sig_path,
					   unsigned char **sigbuf,
					   size_t *siglen, char *errbuf,
					   size_t errbuf_len) {
	FILE *fp = NULL;
	unsigned char *buf = NULL;
	long file_len = 0;
	size_t len = 0;
	size_t read_len;
	verify_result_t result = VERIFY_ERR_READ_SIG;

	if (!sig_path || !sigbuf || !siglen)
		return VERIFY_ERR_UNKNOWN;

	*sigbuf = NULL;
	*siglen = 0;

	fp = fopen(sig_path, "rb");
	if (!fp) {
		set_errbuf(errbuf, errbuf_len, "Signature read failed: open %s",
			   sig_path);
		return VERIFY_ERR_OPEN_FILE;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		set_errbuf(errbuf, errbuf_len,
			   "Signature read failed: seek error for %s",
			   sig_path);
		goto cleanup;
	}
	file_len = ftell(fp);
	if (file_len <= 0) {
		set_errbuf(errbuf, errbuf_len,
			   "Signature read failed: invalid length %ld for %s",
			   file_len, sig_path);
		goto cleanup;
	}
	if ((size_t)file_len > SIG_MAX_LEN) {
		set_errbuf(
		    errbuf, errbuf_len,
		    "Signature read failed: length %ld exceeds max %u for %s",
		    file_len, SIG_MAX_LEN, sig_path);
		goto cleanup;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		set_errbuf(errbuf, errbuf_len,
			   "Signature read failed: rewind error for %s",
			   sig_path);
		goto cleanup;
	}

	len = (size_t)file_len;
	buf = (unsigned char *)malloc(len);
	if (!buf) {
		result = VERIFY_ERR_MEM;
		set_errbuf(errbuf, errbuf_len,
			   "Out of memory reading signature (%zu bytes)", len);
		goto cleanup;
	}

	read_len = fread(buf, 1, len, fp);
	if (read_len != len) {
		set_errbuf(errbuf, errbuf_len,
			   "Signature read failed: short read %zu/%zu for %s",
			   read_len, len, sig_path);
		goto cleanup;
	}

	fclose(fp);
	*sigbuf = buf;
	*siglen = len;
	return VERIFY_OK;

cleanup:
	if (fp)
		fclose(fp);
	if (buf) {
		OPENSSL_cleanse(buf, len);
		free(buf);
	}
	return result;
}

/* ------------------------------------------------------------------------ */
/* Verify an Ed25519 detached signature using one-shot EVP API. */
static verify_result_t verify_ed25519_signature(
    const char *data_path, EVP_PKEY *pubkey, const unsigned char *sigbuf,
    size_t siglen, const char *key_name, char *errbuf, size_t errbuf_len) {
	EVP_MD_CTX *mdctx = NULL;
	unsigned char *data_buf = NULL;
	size_t data_len = 0;
	verify_result_t result = VERIFY_ERR_SIG_VERIFY;
	int read_rc;

	if (siglen != SIG_ED25519_LEN) {
		set_errbuf(errbuf, errbuf_len,
			   "Invalid Ed25519 signature length (key type %s, sig "
			   "len %zu)",
			   key_name, siglen);
		return VERIFY_ERR_SIG_VERIFY;
	}

	read_rc = read_file_all(data_path, &data_buf, &data_len);
	if (read_rc != READ_FILE_OK) {
		if (read_rc == READ_FILE_OPEN) {
			set_errbuf(errbuf, errbuf_len,
				   "Failed to open data file: %s", data_path);
			result = VERIFY_ERR_OPEN_FILE;
		} else if (read_rc == READ_FILE_MEM) {
			set_errbuf(errbuf, errbuf_len,
				   "Out of memory reading data file");
			result = VERIFY_ERR_MEM;
		} else if (read_rc == READ_FILE_TOO_LARGE) {
			set_errbuf(errbuf, errbuf_len,
				   "Data file too large: %s (%zu bytes)",
				   data_path, data_len);
			result = VERIFY_ERR_READ_DATA;
		} else {
			set_errbuf(
			    errbuf, errbuf_len,
			    "Failed to read data for signature verification");
			result = VERIFY_ERR_READ_DATA;
		}
		goto cleanup;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		set_errbuf(errbuf, errbuf_len,
			   "Out of memory creating signature verify context");
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey) != 1) {
		set_errbuf_openssl(errbuf, errbuf_len,
				   "Signature verify init failed (key type %s)",
				   key_name);
		result = VERIFY_ERR_SIG_VERIFY;
		goto cleanup;
	}

	int verify_rc =
	    EVP_DigestVerify(mdctx, sigbuf, siglen, data_buf, data_len);
	if (verify_rc == 1) {
		result = VERIFY_OK;
	} else if (verify_rc == 0) {
		set_errbuf(
		    errbuf, errbuf_len,
		    "Signature invalid (key type %s, sig len %zu)", key_name,
		    siglen);
		result = VERIFY_ERR_SIG_VERIFY;
	} else {
		set_errbuf_openssl(
		    errbuf, errbuf_len,
		    "Signature verification error (key type %s)", key_name);
		result = VERIFY_ERR_SIG_VERIFY;
	}

cleanup:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	if (data_buf) {
		OPENSSL_cleanse(data_buf, data_len);
		free(data_buf);
	}
	return result;
}

/* ------------------------------------------------------------------------ */
/* Verify RSA/ECDSA detached signature using streaming SHA-256. */
static verify_result_t verify_rsa_ecdsa_signature(
    const char *data_path, EVP_PKEY *pubkey, const unsigned char *sigbuf,
    size_t siglen, const char *key_name, char *errbuf, size_t errbuf_len) {
	EVP_MD_CTX *mdctx = NULL;
	BIO *data_bio = NULL;
	unsigned char buf[4096];
	int readlen;
	verify_result_t result = VERIFY_ERR_SIG_VERIFY;

	data_bio = BIO_new_file(data_path, "rb");
	if (!data_bio) {
		set_errbuf(errbuf, errbuf_len, "Failed to open data file: %s",
			   data_path);
		return VERIFY_ERR_OPEN_FILE;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		set_errbuf(errbuf, errbuf_len,
			   "Out of memory creating signature verify context");
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) !=
	    1) {
		set_errbuf_openssl(errbuf, errbuf_len,
				   "Signature verify init failed (key type %s)",
				   key_name);
		result = VERIFY_ERR_SIG_VERIFY;
		goto cleanup;
	}

	while ((readlen = BIO_read(data_bio, buf, sizeof(buf))) > 0) {
		if (EVP_DigestVerifyUpdate(mdctx, buf, readlen) != 1) {
			set_errbuf_openssl(
			    errbuf, errbuf_len,
			    "Signature hash update failed (key type %s)",
			    key_name);
			result = VERIFY_ERR_HASH;
			goto cleanup;
		}
	}
	if (readlen < 0) {
		set_errbuf(errbuf, errbuf_len,
			   "Failed to read data for signature verification "
			   "(key type %s)",
			   key_name);
		result = VERIFY_ERR_HASH;
		goto cleanup;
	}

	int verify_rc = EVP_DigestVerifyFinal(mdctx, sigbuf, siglen);
	if (verify_rc == 1) {
		result = VERIFY_OK;
	} else if (verify_rc == 0) {
		set_errbuf(
		    errbuf, errbuf_len,
		    "Signature invalid (key type %s, sig len %zu)", key_name,
		    siglen);
		result = VERIFY_ERR_SIG_VERIFY;
	} else {
		set_errbuf_openssl(
		    errbuf, errbuf_len,
		    "Signature verification error (key type %s)", key_name);
		result = VERIFY_ERR_SIG_VERIFY;
	}

cleanup:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	if (data_bio)
		BIO_free(data_bio);
	return result;
}

/* ------------------------------------------------------------------------ */
verify_result_t verify_signature_with_cert(const char *data_path,
					   const char *sig_path,
					   const char *cert_path,
					   const char *ca_path, char *errbuf,
					   size_t errbuf_len) {
	X509 *signer_cert = NULL;
	X509_STORE *store = NULL;
	EVP_PKEY *pubkey = NULL;
	unsigned char *sigbuf = NULL;
	size_t siglen = 0;
	int key_type = NID_undef;
	const char *key_name = "unknown";
	const char *openssl_key_name = "unknown";
	char key_name_buf[64];
	verify_result_t result = VERIFY_ERR_UNKNOWN;

	init_error_state(errbuf, errbuf_len);

	if (!data_path || !sig_path || !cert_path || !ca_path) {
		set_errbuf(
		    errbuf, errbuf_len,
		    "Invalid parameter: data, signature, cert, and CA paths "
		    "must be non-NULL");
		return VERIFY_ERR_UNKNOWN;
	}

	result = load_signer_cert(cert_path, &signer_cert, errbuf, errbuf_len);
	if (result != VERIFY_OK)
		goto cleanup;

	result = load_ca_store(ca_path, &store, errbuf, errbuf_len);
	if (result != VERIFY_OK)
		goto cleanup;

	result = verify_signer_cert(store, signer_cert, errbuf, errbuf_len);
	if (result != VERIFY_OK)
		goto cleanup;

	result = load_public_key(signer_cert, &pubkey, &key_type, &key_name,
				 key_name_buf, sizeof(key_name_buf), errbuf,
				 errbuf_len);
	if (result != VERIFY_OK)
		goto cleanup;

	openssl_key_name = OBJ_nid2sn(key_type);
	if (!openssl_key_name)
		openssl_key_name = "unknown";
	LOG_INFO("Signer key type: %s", key_name);
	LOG_DEBUG("Signer key type (OpenSSL): %s", openssl_key_name);

	result = read_signature_file(sig_path, &sigbuf, &siglen, errbuf,
				     errbuf_len);
	if (result != VERIFY_OK)
		goto cleanup;

	if (key_type == EVP_PKEY_ED25519) {
		result = verify_ed25519_signature(data_path, pubkey, sigbuf,
						  siglen, key_name, errbuf,
						  errbuf_len);
		goto cleanup;
	}

	if (key_type != EVP_PKEY_EC && key_type != EVP_PKEY_RSA) {
		set_errbuf(errbuf, errbuf_len,
			   "Unsupported key type %s (sig len %zu)", key_name,
			   siglen);
		result = VERIFY_ERR_SIG_VERIFY;
		goto cleanup;
	}

	result = verify_rsa_ecdsa_signature(data_path, pubkey, sigbuf, siglen,
					    key_name, errbuf, errbuf_len);

cleanup:
	if (sigbuf) {
		OPENSSL_cleanse(sigbuf, siglen);
		free(sigbuf);
	}
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (store)
		X509_STORE_free(store);
	if (signer_cert)
		X509_free(signer_cert);

	if (result != VERIFY_OK && errbuf && errbuf_len > 0 && !errbuf[0])
		format_openssl_errors(errbuf, errbuf_len);

	return result;
}
