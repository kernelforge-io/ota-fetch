// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file enroll.c
 * @brief Runtime identity enrollment using bootstrap token.
 */

#include "enroll.h"
#include "logging.h"

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct memory_buffer {
	char *data;
	size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb,
			     void *userp) {
	size_t total_size = size * nmemb;
	struct memory_buffer *mem = (struct memory_buffer *)userp;
	char *ptr = realloc(mem->data, mem->size + total_size + 1);

	if (!ptr) {
		return 0;
	}

	mem->data = ptr;
	memcpy(mem->data + mem->size, contents, total_size);
	mem->size += total_size;
	mem->data[mem->size] = '\0';
	return total_size;
}

static int file_exists(const char *path) {
	struct stat st;
	return path && stat(path, &st) == 0;
}

static int mkdir_p(const char *path, mode_t mode) {
	char temp[PATH_MAX];
	size_t len;
	char *p = NULL;

	if (!path || !*path) {
		errno = EINVAL;
		return -1;
	}

	len = strnlen(path, PATH_MAX);
	if (len == 0 || len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strncpy(temp, path, sizeof(temp));
	temp[len] = '\0';

	if (len > 1 && temp[len - 1] == '/') {
		temp[len - 1] = '\0';
	}

	for (p = temp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(temp, mode) != 0 && errno != EEXIST) {
				return -1;
			}
			*p = '/';
		}
	}

	if (mkdir(temp, mode) != 0 && errno != EEXIST) {
		return -1;
	}

	return 0;
}

static int ensure_parent_dir(const char *path, mode_t mode) {
	char dir[PATH_MAX];
	size_t len;
	char *slash = NULL;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	len = strnlen(path, PATH_MAX);
	if (len == 0 || len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strncpy(dir, path, sizeof(dir));
	dir[len] = '\0';

	slash = strrchr(dir, '/');
	if (!slash) {
		return 0;
	}
	if (slash == dir) {
		return 0;
	}

	*slash = '\0';
	return mkdir_p(dir, mode);
}

static int fsync_parent_dir(const char *path) {
	char dir[PATH_MAX];
	size_t len;
	char *slash = NULL;
	int dir_fd = -1;
	int rc = -1;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	len = strnlen(path, PATH_MAX);
	if (len == 0 || len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strncpy(dir, path, sizeof(dir));
	dir[len] = '\0';

	slash = strrchr(dir, '/');
	if (!slash) {
		return 0;
	}
	if (slash == dir) {
		return 0;
	}

	*slash = '\0';

	dir_fd = open(dir, O_RDONLY | O_DIRECTORY);
	if (dir_fd < 0) {
		return -1;
	}

	if (fsync(dir_fd) == 0) {
		rc = 0;
	}

	close(dir_fd);
	return rc;
}

static int write_all(int fd, const char *data, size_t len) {
	size_t offset = 0;

	while (offset < len) {
		ssize_t written = write(fd, data + offset, len - offset);
		if (written < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		offset += (size_t)written;
	}

	return 0;
}

static int write_file_atomic(const char *path, const char *data, size_t len,
			     mode_t mode) {
	char *tmp_path = NULL;
	size_t tmp_len;
	int fd = -1;
	int rc = -1;

	if (!path || !data) {
		errno = EINVAL;
		return -1;
	}

	if (ensure_parent_dir(path, 0700) != 0) {
		LOG_ERROR("Failed to create parent dir for %s: %s", path,
			  strerror(errno));
		return -1;
	}

	tmp_len = strlen(path) + sizeof(".tmp");
	tmp_path = malloc(tmp_len);
	if (!tmp_path) {
		return -1;
	}
	snprintf(tmp_path, tmp_len, "%s.tmp", path);

	fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd < 0) {
		LOG_ERROR("Failed to open %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (write_all(fd, data, len) != 0) {
		LOG_ERROR("Failed to write %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (fchmod(fd, mode) != 0) {
		LOG_ERROR("Failed to chmod %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (fsync(fd) != 0) {
		LOG_ERROR("Failed to fsync %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (close(fd) != 0) {
		fd = -1;
		LOG_ERROR("Failed to close %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}
	fd = -1;

	if (rename(tmp_path, path) != 0) {
		LOG_ERROR("Failed to rename %s -> %s: %s", tmp_path, path,
			  strerror(errno));
		goto cleanup;
	}

	if (fsync_parent_dir(path) != 0) {
		LOG_ERROR("Failed to fsync parent dir for %s: %s", path,
			  strerror(errno));
		goto cleanup;
	}

	rc = 0;

cleanup:
	if (fd >= 0) {
		close(fd);
	}
	if (rc != 0 && tmp_path) {
		unlink(tmp_path);
	}
	free(tmp_path);
	return rc;
}

static int read_token_file(const char *path, char **token_out) {
	FILE *fp = NULL;
	char *buf = NULL;
	size_t len = 0;
	size_t cap = 256;
	int c;
	int rc = -1;
	size_t start = 0;

	if (!path || !token_out) {
		return -1;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		LOG_ERROR("Failed to open token file %s: %s", path,
			  strerror(errno));
		return -1;
	}

	buf = malloc(cap);
	if (!buf) {
		goto cleanup;
	}

	while ((c = fgetc(fp)) != EOF) {
		if (len + 1 >= cap) {
			size_t new_cap = cap * 2;
			char *new_buf = realloc(buf, new_cap);
			if (!new_buf) {
				goto cleanup;
			}
			buf = new_buf;
			cap = new_cap;
		}
		buf[len++] = (char)c;
	}

	if (ferror(fp)) {
		goto cleanup;
	}

	while (len > 0 && isspace((unsigned char)buf[len - 1])) {
		len--;
	}

	while (start < len && isspace((unsigned char)buf[start])) {
		start++;
	}

	if (start > 0 && start < len) {
		memmove(buf, buf + start, len - start);
		len -= start;
	} else if (start >= len) {
		len = 0;
	}

	buf[len] = '\0';

	if (len == 0) {
		LOG_ERROR("Token file %s is empty", path);
		goto cleanup;
	}

	*token_out = buf;
	buf = NULL;
	rc = 0;

cleanup:
	if (fp) {
		fclose(fp);
	}
	free(buf);
	return rc;
}

static char *derive_enroll_url(const char *server_url) {
	const char *suffix = NULL;
	size_t len;
	size_t total_len;
	char *url = NULL;

	if (!server_url || server_url[0] == '\0') {
		return NULL;
	}

	len = strlen(server_url);
	suffix = (server_url[len - 1] == '/') ? "enroll" : "/enroll";
	total_len = len + strlen(suffix) + 1;

	url = malloc(total_len);
	if (!url) {
		return NULL;
	}

	snprintf(url, total_len, "%s%s", server_url, suffix);
	return url;
}

static int generate_key_and_csr(char **key_pem_out, char **csr_pem_out,
				const char *device_id) {
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *pkey = NULL;
	X509_REQ *req = NULL;
	X509_NAME *name = NULL;
	BIO *key_bio = NULL;
	BIO *csr_bio = NULL;
	BUF_MEM *key_mem = NULL;
	BUF_MEM *csr_mem = NULL;
	const char *cn = NULL;
	int rc = -1;

	if (!key_pem_out || !csr_pem_out) {
		return -1;
	}

	key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!key_ctx) {
		goto cleanup;
	}

	if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
		goto cleanup;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0) {
		goto cleanup;
	}
	if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
		goto cleanup;
	}

	req = X509_REQ_new();
	if (!req) {
		goto cleanup;
	}

	if (X509_REQ_set_version(req, 0L) != 1) {
		goto cleanup;
	}

	name = X509_NAME_new();
	if (!name) {
		goto cleanup;
	}

	cn = (device_id && device_id[0] != '\0') ? device_id : "ota-fetch";
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				       (const unsigned char *)cn, -1, -1,
				       0) != 1) {
		goto cleanup;
	}

	if (X509_REQ_set_subject_name(req, name) != 1) {
		goto cleanup;
	}

	if (X509_REQ_set_pubkey(req, pkey) != 1) {
		goto cleanup;
	}

	if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
		goto cleanup;
	}

	key_bio = BIO_new(BIO_s_mem());
	csr_bio = BIO_new(BIO_s_mem());
	if (!key_bio || !csr_bio) {
		goto cleanup;
	}

	if (PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL) !=
	    1) {
		goto cleanup;
	}
	if (PEM_write_bio_X509_REQ(csr_bio, req) != 1) {
		goto cleanup;
	}

	BIO_get_mem_ptr(key_bio, &key_mem);
	BIO_get_mem_ptr(csr_bio, &csr_mem);
	if (!key_mem || !csr_mem || key_mem->length == 0 ||
	    csr_mem->length == 0) {
		goto cleanup;
	}

	*key_pem_out = malloc(key_mem->length + 1);
	*csr_pem_out = malloc(csr_mem->length + 1);
	if (!*key_pem_out || !*csr_pem_out) {
		goto cleanup;
	}

	memcpy(*key_pem_out, key_mem->data, key_mem->length);
	(*key_pem_out)[key_mem->length] = '\0';
	memcpy(*csr_pem_out, csr_mem->data, csr_mem->length);
	(*csr_pem_out)[csr_mem->length] = '\0';

	rc = 0;

cleanup:
	if (rc != 0) {
		free(*key_pem_out);
		free(*csr_pem_out);
		*key_pem_out = NULL;
		*csr_pem_out = NULL;
		LOG_ERROR("Failed to generate private key/CSR");
	}

	BIO_free(key_bio);
	BIO_free(csr_bio);
	X509_NAME_free(name);
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(key_ctx);
	return rc;
}

static char *build_enroll_request_json(const char *csr_pem,
				       const char *device_id) {
	cJSON *root = NULL;
	char *json = NULL;

	root = cJSON_CreateObject();
	if (!root) {
		return NULL;
	}

	if (!cJSON_AddStringToObject(root, "csr_pem", csr_pem)) {
		cJSON_Delete(root);
		return NULL;
	}

	if (device_id && device_id[0] != '\0' &&
	    !cJSON_AddStringToObject(root, "device_id", device_id)) {
		cJSON_Delete(root);
		return NULL;
	}

	json = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	return json;
}

static int parse_enroll_response(const char *json, char **cert_pem_out) {
	cJSON *root = NULL;
	cJSON *cert = NULL;
	cJSON *chain = NULL;
	const char *cert_text = NULL;
	const char *chain_text = NULL;
	int need_newline = 0;
	size_t cert_len;
	size_t chain_len = 0;
	size_t total_len;
	char *combined = NULL;

	if (!json || !cert_pem_out) {
		return -1;
	}

	root = cJSON_Parse(json);
	if (!root || !cJSON_IsObject(root)) {
		LOG_ERROR("Invalid enrollment response JSON");
		cJSON_Delete(root);
		return -1;
	}

	cert = cJSON_GetObjectItemCaseSensitive(root, "client_cert_pem");
	if (!cert || !cJSON_IsString(cert) || !cert->valuestring ||
	    cert->valuestring[0] == '\0') {
		LOG_ERROR("Enrollment response missing client_cert_pem");
		cJSON_Delete(root);
		return -1;
	}
	cert_text = cert->valuestring;
	cert_len = strlen(cert_text);

	chain = cJSON_GetObjectItemCaseSensitive(root, "client_chain_pem");
	if (chain && cJSON_IsString(chain) && chain->valuestring &&
	    chain->valuestring[0] != '\0') {
		chain_text = chain->valuestring;
		chain_len = strlen(chain_text);
		need_newline =
		    cert_len > 0 && cert_text[cert_len - 1] != '\n';
	}

	total_len = cert_len + chain_len + (need_newline ? 1u : 0u) + 1u;
	combined = malloc(total_len);
	if (!combined) {
		cJSON_Delete(root);
		return -1;
	}

	memcpy(combined, cert_text, cert_len);
	if (chain_text) {
		size_t pos = cert_len;
		if (need_newline) {
			combined[pos++] = '\n';
		}
		memcpy(combined + pos, chain_text, chain_len);
		pos += chain_len;
		combined[pos] = '\0';
	} else {
		combined[cert_len] = '\0';
	}

	*cert_pem_out = combined;
	cJSON_Delete(root);
	return 0;
}

static int post_enroll_request(const char *url, const struct ota_config *cfg,
			       const char *token, const char *request_json,
			       char **response_json_out) {
	int rc = -1;
	CURL *curl = NULL;
	CURLcode res;
	long http_code = 0;
	struct memory_buffer resp = {0};
	struct curl_slist *headers = NULL;
	char *auth_header = NULL;
	size_t auth_len;

	if (!url || !cfg || !token || !request_json || !response_json_out) {
		return -1;
	}

	auth_len = strlen("Authorization: Bearer ") + strlen(token) + 1;
	auth_header = malloc(auth_len);
	if (!auth_header) {
		return -1;
	}
	snprintf(auth_header, auth_len, "Authorization: Bearer %s", token);

	curl = curl_easy_init();
	if (!curl) {
		free(auth_header);
		return -1;
	}

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, auth_header);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(request_json));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

	if (cfg->connect_timeout > 0) {
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
				 cfg->connect_timeout);
	}
	if (cfg->transfer_timeout > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg->transfer_timeout);
	}
	if (cfg->low_speed_limit > 0 && cfg->low_speed_time > 0) {
		curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
				 (long)cfg->low_speed_limit);
		curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
				 (long)cfg->low_speed_time);
	}
	if (cfg->tls_ca_cert && cfg->tls_ca_cert[0] != '\0') {
		curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->tls_ca_cert);
	}

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (res != CURLE_OK) {
		LOG_ERROR("Enrollment HTTP request failed: %s",
			  curl_easy_strerror(res));
		goto cleanup;
	}

	if (http_code < 200 || http_code >= 300) {
		LOG_ERROR("Enrollment endpoint returned HTTP %ld", http_code);
		goto cleanup;
	}

	if (!resp.data || resp.size == 0) {
		LOG_ERROR("Enrollment endpoint returned empty body");
		goto cleanup;
	}

	*response_json_out = resp.data;
	resp.data = NULL;
	rc = 0;

cleanup:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	free(auth_header);
	free(resp.data);
	return rc;
}

int ota_fetch_enroll(const struct ota_config *cfg, const char *token_file,
		     bool force) {
	int rc = -1;
	char *token = NULL;
	char *derived_enroll_url = NULL;
	const char *enroll_url = NULL;
	char *key_pem = NULL;
	char *csr_pem = NULL;
	char *request_json = NULL;
	char *response_json = NULL;
	char *cert_pem = NULL;

	if (!cfg || !token_file) {
		return -1;
	}

	if (!cfg->tls_client_key || !cfg->tls_client_cert) {
		LOG_ERROR("TLS identity paths are required in config");
		return -1;
	}

	if (!force && (file_exists(cfg->tls_client_key) ||
		       file_exists(cfg->tls_client_cert))) {
		LOG_ERROR(
		    "Refusing to enroll: identity already exists "
		    "(use --force to overwrite)");
		return -1;
	}

	if (read_token_file(token_file, &token) != 0) {
		goto cleanup;
	}

	if (cfg->enroll_url && cfg->enroll_url[0] != '\0') {
		enroll_url = cfg->enroll_url;
	} else {
		derived_enroll_url = derive_enroll_url(cfg->server_url);
		enroll_url = derived_enroll_url;
	}

	if (!enroll_url) {
		LOG_ERROR("Failed to resolve enrollment endpoint URL");
		goto cleanup;
	}

	if (generate_key_and_csr(&key_pem, &csr_pem, cfg->device_id) != 0) {
		goto cleanup;
	}

	request_json = build_enroll_request_json(csr_pem, cfg->device_id);
	if (!request_json) {
		LOG_ERROR("Failed to build enrollment request JSON");
		goto cleanup;
	}

	if (post_enroll_request(enroll_url, cfg, token, request_json,
				&response_json) != 0) {
		goto cleanup;
	}

	if (parse_enroll_response(response_json, &cert_pem) != 0) {
		goto cleanup;
	}

	if (write_file_atomic(cfg->tls_client_key, key_pem, strlen(key_pem),
			      0600) != 0) {
		goto cleanup;
	}

	if (write_file_atomic(cfg->tls_client_cert, cert_pem, strlen(cert_pem),
			      0644) != 0) {
		goto cleanup;
	}

	if (unlink(token_file) != 0 && errno != ENOENT) {
		LOG_ERROR("Failed to remove token file %s: %s", token_file,
			  strerror(errno));
		goto cleanup;
	}

	LOG_INFO("Enrollment completed successfully");
	rc = 0;

cleanup:
	free(token);
	free(derived_enroll_url);
	free(key_pem);
	free(csr_pem);
	free(request_json);
	free(response_json);
	free(cert_pem);
	return rc;
}
