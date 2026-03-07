// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file ota-fetch.c
 * @brief OTA Fetcher core logic for secure embedded update downloads.
 *
 * This file implements the main OTA fetch and update loop for embedded Linux.
 * Features:
 *   - Secure HTTPS/mTLS downloads via libcurl
 *   - Manifest signature verification (OpenSSL)
 *   - Payload integrity validation (SHA-256)
 *   - RAUC bundle install integration
 *   - One-shot and periodic (daemon_mode) operation
 *
 * The "daemon" mode is a polling loop and does not daemonize the process.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#include "ota_fetch.h"
#include "hash.h"
#include "logging.h"
#include "manifest.h"
#include "verify_libcrypto.h"
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @def FETCH_INTERVAL_SEC
 * @brief Default number of seconds between update checks in daemon mode.
 */
#define FETCH_INTERVAL_SEC 3600

/**
 * @def RETRY_DELAY
 * @brief Number of seconds to wait before retrying a failed fetch.
 */
#define RETRY_DELAY 5

/**
 * @brief OTA context state.
 *
 * Holds paths, manifests, and configuration for a single OTA operation.
 */
typedef struct ota_ctx {
	struct ota_config config;
	manifest_t *current_manifest;
	manifest_t *inbox_manifest;
	char *current_manifest_path;
	char *inbox_manifest_path;
	char *inbox_sig_path;
	char *inbox_cert_path;
	char *payload_path;
	const manifest_release_t *release;
} ota_ctx_t;

static volatile sig_atomic_t g_terminate = 0;

static void handle_termination_signal(int sig) {
	(void)sig;
	g_terminate = 1;
}

/**
 * @brief In-memory data buffer for HTTP(S) downloads.
 */
struct memory_buffer {
	char *data;
	size_t size;
};

/**
 * @brief Result codes for file equality checks.
 */
typedef enum {
	FILES_EQ = 0,  /**< Files are equal */
	FILES_NEQ = 1, /**< Files are not equal */
	FILES_ERR = -1 /**< Error occurred */
} files_equal_result_t;

/**
 * @brief libcurl write callback for in-memory downloads.
 *
 * @param contents Data pointer from libcurl.
 * @param size     Size of each item.
 * @param nmemb    Number of items.
 * @param userp    User data pointer (memory_buffer).
 * @return Number of bytes written.
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb,
			     void *userp) {
	size_t total_size = size * nmemb;
	struct memory_buffer *mem = (struct memory_buffer *)userp;

	char *ptr = realloc(mem->data, mem->size + total_size + 1);
	if (!ptr)
		return 0;

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), contents, total_size);
	mem->size += total_size;
	mem->data[mem->size] = 0;
	return total_size;
}

/**
 * @brief Build a path by joining a directory and a filename.
 *
 * @param dir  Directory path.
 * @param file Filename.
 * @return Newly allocated path string (must be freed), or NULL on error.
 */
static char *build_path(const char *dir, const char *file) {
	if (!dir || !file) {
		return NULL; // Prevent undefined behavior
	}

	size_t len = strlen(dir) + strlen(file) + 2; // '/' + '\0'
	char *result = malloc(len);
	if (!result) {
		return NULL; // Allocation failed
	}

	snprintf(result, len, "%s/%s", dir, file);
	return result;
}

/**
 * mkdir_p - Recursively create directories like "mkdir -p".
 * @path: Directory path to create.
 * @mode: Permissions to use for any newly created directories.
 *
 * Returns 0 on success, or -1 on error (sets errno).
 *
 * Notes:
 *   - This function handles absolute and relative paths.
 *   - Intermediate directories are created as needed.
 *   - Returns 0 if the path already exists as a directory.
 */
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

	// Remove trailing slash (except root)
	if (len > 1 && temp[len - 1] == '/')
		temp[len - 1] = '\0';

	for (p = temp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(temp, mode) != 0) {
				if (errno != EEXIST) {
					return -1;
				}
			}
			*p = '/';
		}
	}
	if (mkdir(temp, mode) != 0) {
		if (errno != EEXIST) {
			return -1;
		}
	}
	return 0;
}

/**
 * @brief Compare two files by SHA256 hash.
 *
 * @param path1 First file path.
 * @param path2 Second file path.
 * @return FILES_EQ if equal, FILES_NEQ if not, FILES_ERR on error.
 */
static files_equal_result_t files_equal(const char *path1, const char *path2) {
	uint8_t hash1[SHA256_DIGEST_LEN];
	uint8_t hash2[SHA256_DIGEST_LEN];
	int irethash1;
	int irethash2;

	if ((path1 == NULL) || (path2 == NULL)) {
		return FILES_ERR;
	}

	irethash1 = sha256sum_file(path1, hash1);
	irethash2 = sha256sum_file(path2, hash2);

	if ((irethash1 != 0) || (irethash2 != 0)) {
		if (irethash1 != 0) {
			LOG_ERROR("Failed to hash %s: %d", path1, irethash1);
		}
		if (irethash2 != 0) {
			LOG_ERROR("Failed to hash %s: %d", path2, irethash2);
		}
		return FILES_ERR;
	}

	LOG_INFO("file1 =%s, hash1 =%s, ret =%d", path1, sha256_hex(hash1),
		 irethash1);
	LOG_INFO("file2 =%s, hash2 =%s, ret =%d", path2, sha256_hex(hash2),
		 irethash2);

	return (memcmp(hash1, hash2, SHA256_DIGEST_LEN) == 0) ? FILES_EQ
							      : FILES_NEQ;
}

/**
 * @brief Check if a file exists.
 *
 * @param path File path.
 * @return 1 if file exists, 0 otherwise.
 */
static int file_exists(const char *path) {
	struct stat st;
	return (path && stat(path, &st) == 0);
}

/**
 * @brief Download a file from a URL to a local path using HTTPS/mTLS.
 *
 * @param url       Remote file URL.
 * @param dest_path Local destination path.
 * @param cfg       OTA config (includes certs/keys).
 * @return 0 on success, -1 on error.
 */
static int fetch_file(const char *url, const char *dest_path,
		      const struct ota_config *cfg) {
	int rc = -1;
	long http_code = 0;
	CURL *curl = curl_easy_init();
	char *tmp_path = NULL;
	struct memory_buffer buf = {0};

	if (!curl) {
		LOG_ERROR("Failed to initialize libcurl");
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cfg->connect_timeout);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg->transfer_timeout);

	if (cfg->low_speed_limit > 0 && cfg->low_speed_time > 0) {
		curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
				 (long)cfg->low_speed_limit);
		curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
				 (long)cfg->low_speed_time);
	}

	// mTLS setup
	curl_easy_setopt(curl, CURLOPT_SSLCERT, cfg->tls_client_cert);
	curl_easy_setopt(curl, CURLOPT_SSLKEY, cfg->tls_client_key);
	curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->tls_ca_cert);

	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (res != CURLE_OK) {
		if (http_code >= 400) {
			LOG_ERROR("HTTP error fetching %s: %ld", url,
				  http_code);
		} else {
			LOG_ERROR("curl error fetching %s: %s", url,
				  curl_easy_strerror(res));
		}

		long verify_result = 0;
		curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT,
				  &verify_result);
		LOG_ERROR("SSL verify result: %ld", verify_result);
		goto cleanup;
	}

	if (http_code < 200 || http_code >= 300) {
		LOG_ERROR("HTTP error fetching %s: %ld", url, http_code);
		goto cleanup;
	}

	// Ensure directory exists
	char dir[PATH_MAX];
	strncpy(dir, dest_path, sizeof(dir));
	dir[sizeof(dir) - 1] = '\0';
	char *slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		if (mkdir_p(dir, 0755) != 0) {
			LOG_ERROR("Failed to create directory: %s",
				  strerror(errno));
		}
	}

	size_t tmp_len = strlen(dest_path) + 5;
	tmp_path = malloc(tmp_len);
	if (!tmp_path) {
		LOG_ERROR("Failed to allocate temp path");
		goto cleanup;
	}
	snprintf(tmp_path, tmp_len, "%s.tmp", dest_path);

	FILE *fp = fopen(tmp_path, "wb");
	if (!fp) {
		LOG_ERROR("Failed to write %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (fwrite(buf.data, 1, buf.size, fp) != buf.size) {
		LOG_ERROR("Short write to %s: %s", tmp_path, strerror(errno));
		fclose(fp);
		goto cleanup;
	}
	fclose(fp);

	if (rename(tmp_path, dest_path) != 0) {
		LOG_ERROR("Failed to move %s to %s: %s", tmp_path, dest_path,
			  strerror(errno));
		goto cleanup;
	}

	LOG_INFO("%s saved to: %s", url, dest_path);
	rc = 0;

cleanup:
	if (rc != 0 && tmp_path) {
		unlink(tmp_path);
	}
	free(tmp_path);
	curl_easy_cleanup(curl);
	free(buf.data);
	return rc;
}

/**
 * @brief Initialize OTA context (paths, config, manifests).
 *
 * @param ctx OTA context struct to initialize.
 * @param cfg OTA configuration.
 * @note ctx->payload_path is allocated in this function and freed by
 * ota_ctx_free().
 * @return 0 on success, -1 on error.
 */
static int ota_ctx_init(ota_ctx_t *ctx, const struct ota_config *cfg) {
	int iRet = 0;
	memset(ctx, 0, sizeof(*ctx));
	memcpy(&ctx->config, cfg, sizeof(*cfg));

	// Current Manifest Path
	ctx->current_manifest_path = build_path(cfg->current_manifest_dir,
						"manifest.json");
	if (ctx->current_manifest_path == NULL) {
		LOG_ERROR("Failed to create current manifest path");
		iRet = -1;
	}

	// Inbox Manifest Path
	ctx->inbox_manifest_path = build_path(cfg->inbox_manifest_dir,
					      "manifest.json");
	if (ctx->inbox_manifest_path == NULL) {
		LOG_ERROR("Failed to create inbox manifest path");
		iRet = -1;
	}

	// Inbox Manifest Sig Path
	ctx->inbox_sig_path = build_path(cfg->inbox_manifest_dir,
					 "manifest.json.sig");
	if (ctx->inbox_sig_path == NULL) {
		LOG_ERROR("Failed to create inbox manifest sig path");
		iRet = -1;
	}

	// Inbox Signer Cert Path
	ctx->inbox_cert_path = build_path(cfg->inbox_manifest_dir,
					  "signer.crt");
	if (ctx->inbox_cert_path == NULL) {
		LOG_ERROR("Failed to create inbox cert path");
		iRet = -1;
	}

	return iRet;
}

/**
 * @brief Free all memory/resources in OTA context.
 *
 * @param ctx OTA context to clean up.
 */
static void ota_ctx_free(ota_ctx_t *ctx) {

	if (ctx->inbox_manifest != NULL) {
		manifest_free(ctx->inbox_manifest);
		ctx->inbox_manifest = NULL;
	}

	if (ctx->current_manifest != NULL) {
		manifest_free(ctx->current_manifest);
		ctx->current_manifest = NULL;
	}

	if (ctx->current_manifest_path != NULL) {
		free(ctx->current_manifest_path);
		ctx->current_manifest_path = NULL;
	}

	if (ctx->inbox_manifest_path != NULL) {
		free(ctx->inbox_manifest_path);
		ctx->inbox_manifest_path = NULL;
	}

	if (ctx->inbox_sig_path != NULL) {
		free(ctx->inbox_sig_path);
		ctx->inbox_sig_path = NULL;
	}

	if (ctx->inbox_cert_path != NULL) {
		free(ctx->inbox_cert_path);
		ctx->inbox_cert_path = NULL;
	}

	if (ctx->payload_path != NULL) {
		free(ctx->payload_path);
		ctx->payload_path = NULL;
	}
}

static void ota_inbox_cleanup(ota_ctx_t *ctx) {
	const char *paths[] = {
	    ctx->inbox_manifest_path,
	    ctx->inbox_sig_path,
	    ctx->inbox_cert_path,
	};

	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		const char *path = paths[i];
		if (!path) {
			continue;
		}
		if (unlink(path) != 0 && errno != ENOENT) {
			LOG_WARN("Failed to remove inbox file %s: %s", path,
				 strerror(errno));
		}
	}

	DIR *dir = opendir(ctx->config.inbox_manifest_dir);
	if (!dir) {
		if (errno != ENOENT) {
			LOG_WARN("Failed to open inbox dir %s: %s",
				 ctx->config.inbox_manifest_dir,
				 strerror(errno));
		}
		return;
	}

	struct dirent *entry = NULL;
	while ((entry = readdir(dir)) != NULL) {
		size_t name_len = strlen(entry->d_name);
		if (name_len < 4) {
			continue;
		}
		if (strcmp(entry->d_name + name_len - 4, ".tmp") != 0) {
			continue;
		}

		char *tmp_path = build_path(ctx->config.inbox_manifest_dir,
					    entry->d_name);
		if (!tmp_path) {
			LOG_WARN("Failed to build inbox tmp path for %s",
				 entry->d_name);
			continue;
		}
		if (unlink(tmp_path) != 0 && errno != ENOENT) {
			LOG_WARN("Failed to remove inbox tmp %s: %s", tmp_path,
				 strerror(errno));
		}
		free(tmp_path);
	}
	closedir(dir);
}

/**
 * @brief Download new manifest, signature, and signer cert from server.
 *
 * @param ctx OTA context.
 * @return 0 on success, non-zero on error.
 */
static int fetch_new_manifest(ota_ctx_t *ctx) {

	char *manifest_url = NULL;
	char *sig_url = NULL;
	char *cert_url = NULL;

	manifest_url = build_path(ctx->config.server_url, "manifest.json");
	sig_url = build_path(ctx->config.server_url, "manifest.json.sig");
	cert_url = build_path(ctx->config.server_url, "signer.crt");

	int rc1 = fetch_file(manifest_url, ctx->inbox_manifest_path,
			     &ctx->config);
	int rc2 = fetch_file(sig_url, ctx->inbox_sig_path, &ctx->config);
	int rc3 = fetch_file(cert_url, ctx->inbox_cert_path, &ctx->config);

	if (rc1)
		LOG_ERROR("Failed to fetch manifest.json");
	if (rc2)
		LOG_ERROR("Failed to fetch manifest.json.sig");
	if (rc3)
		LOG_ERROR("Failed to fetch signer.crt");

	if (manifest_url != NULL) {
		free(manifest_url);
	}
	if (sig_url != NULL) {
		free(sig_url);
	}
	if (cert_url != NULL) {
		free(cert_url);
	}

	return rc1 || rc2 || rc3;
}

/**
 * @brief Verify new manifest signature with OpenSSL and provided certs.
 *
 * @param ctx OTA context.
 * @return 0 if valid, -1 on error.
 */
static int validate_new_manifest(ota_ctx_t *ctx) {
	char errbuf[VERIFY_ERRBUF_LEN] = {0};
	verify_result_t vres = verify_signature_with_cert(
	    ctx->inbox_manifest_path, ctx->inbox_sig_path, ctx->inbox_cert_path,
	    ctx->config.manifest_ca_cert, errbuf, sizeof(errbuf));

	if (vres != VERIFY_OK) {
		LOG_ERROR("Manifest signature validation "
			  "failed: %s",
			  errbuf);
		return -1;
	}
	LOG_INFO("Manifest signature validation OK.");
	return 0;
}

/**
 * @brief Compare new and current manifests for changes.
 *
 * @param ctx OTA context.
 * @return FILES_EQ if same, FILES_NEQ if update required, FILES_ERR on error.
 */
static files_equal_result_t compare_manifests(ota_ctx_t *ctx) {

	if (!file_exists(ctx->current_manifest_path)) {
		LOG_WARN("No current manifest found: Update required");
		return FILES_NEQ;
	}
	if (!file_exists(ctx->inbox_manifest_path)) {
		LOG_ERROR("No inbox manifest to compare: Aborting");
		return FILES_ERR;
	}

	files_equal_result_t ret = files_equal(ctx->current_manifest_path,
					       ctx->inbox_manifest_path);
	if (ret == FILES_EQ) {
		LOG_INFO("Manifest matches: System up to date");
	} else if (ret == FILES_NEQ) {
		LOG_INFO("Manifest mismatch: Update required");
	} else {
		LOG_ERROR("Error comparing manifests");
	}

	return ret;
}

/**
 * @brief Move new inbox manifest into place as current manifest.
 *
 * @param ctx OTA context.
 * @return 0 on success, -1 on error.
 */
static int make_new_manifest_current(ota_ctx_t *ctx) {

	// Ensure destination directory exists
	if (mkdir_p(ctx->config.current_manifest_dir, 0755) != 0) {
		LOG_ERROR("Failed to create directory: %s", strerror(errno));
	}

	// Remove existing destination file, if any
	unlink(ctx->current_manifest_path);

	// Move (rename) the file
	if (rename(ctx->inbox_manifest_path, ctx->current_manifest_path) != 0) {
		LOG_ERROR("Failed to move manifest from %s to %s: %s",
			  ctx->inbox_manifest_path, ctx->current_manifest_path,
			  strerror(errno));
		return -1;
	}

	LOG_INFO("Moved manifest: %s → %s", ctx->inbox_manifest_path,
		 ctx->current_manifest_path);
	return 0;
}

/**
 * @brief Download OTA release payload file specified in the manifest.
 *
 * @param ctx OTA context.
 * @return 0 on success, -1 on error.
 */
static int fetch_release(ota_ctx_t *ctx) {
	int ret;
	const manifest_file_t *file = NULL;

	ctx->release = manifest_select_release(ctx->inbox_manifest,
					       ctx->config.device_id);

	if (ctx->release == NULL) {
		LOG_ERROR("Release not found");
		return -1;
	}

	if (ctx->release->files_count == 0 || !ctx->release->files) {
		LOG_ERROR("Release contains no files");
		return -1;
	}

	file = &ctx->release->files[0];
	if (!file->filename || !file->path || !file->sha256 ||
	    !file->file_type) {
		LOG_ERROR(
		    "Release file entry missing required fields "
		    "(file_type, filename, path, sha256)");
		return -1;
	}

	// Assemble path where payload will be downloaded
	// Note: ctx->payload_path is freed in ota_ctx_free.
	if (ctx->payload_path != NULL) {
		free(ctx->payload_path);
		ctx->payload_path = NULL;
	}
	ctx->payload_path =
	    build_path(ctx->config.inbox_manifest_dir, file->filename);

	char *payload_url = NULL;
	payload_url = build_path(ctx->config.server_url, file->path);

	if (payload_url == NULL) {
		LOG_ERROR("Failed to assemble release payload URL");
		return -1;
	}

	// Fetch payload from URL provided in manifest
	ret = fetch_file(payload_url, ctx->payload_path, &ctx->config);

	if (ret != 0) {
		LOG_ERROR("Release payload download failed");
	}

	free(payload_url);

	return ret;
}

/**
 * @brief Validate downloaded release payload by SHA256 hash.
 *
 * @param ctx OTA context.
 * @return 0 if valid, -1 on mismatch or error.
 */
static int validate_release(ota_ctx_t *ctx) {
	if (!ctx->release || !ctx->release->files ||
	    ctx->release->files_count == 0 ||
	    !ctx->release->files[0].sha256) {
		LOG_ERROR("Release file hash missing from manifest");
		return -1;
	}

	uint8_t hash[SHA256_DIGEST_LEN];
	char hash_string[SHA256_DIGEST_LEN * 2 + 1];
	int rc;

	rc = sha256sum_file(ctx->payload_path, hash);
	if (rc != SHA256SUM_OK) {
		LOG_ERROR("Failed to hash payload %s: %d", ctx->payload_path,
			  rc);
		return -1;
	}

	if (hex_encode(hash_string, sizeof(hash_string), hash,
		       SHA256_DIGEST_LEN) != 0) {
		LOG_ERROR("Failed to format payload SHA256");
		return -1;
	}

	if (strcmp(hash_string, ctx->release->files[0].sha256) != 0) {
		LOG_ERROR("SHA256 mismatch");
		LOG_ERROR("Expected: %s", ctx->release->files[0].sha256);
		LOG_ERROR("Actual:   %s", hash_string);
		return -1;
	}

	LOG_INFO("Payload SHA256 validated successfully.");
	return 0;
}

/**
 * @brief Apply the OTA release payload.
 *
 * Integrates with RAUC or simulates update for testing.
 *
 * @param ctx OTA context.
 * @return 0 on success, non-zero on error.
 */
static int apply_release(ota_ctx_t *ctx) {
	LOG_INFO("Applying release payload");

	if (!ctx->release || !ctx->release->files ||
	    ctx->release->files_count == 0 ||
	    !ctx->release->files[0].file_type) {
		LOG_ERROR("Release file_type missing from manifest");
		return -1;
	}

	const char *file_type = ctx->release->files[0].file_type;

	if (strcmp(file_type, "rauc_bundle_test") == 0) {
		LOG_INFO("Simulating RAUC bundle update for testing");
		make_new_manifest_current(ctx);

	} else if (strcmp(file_type, "rauc_bundle") == 0) {
		LOG_INFO("Installing RAUC bundle");

		const char *bundle_path = ctx->payload_path;
		char *const argv[] = {"rauc", "install", (char *)bundle_path,
				      NULL};

		pid_t pid = fork();
		if (pid == 0) {
			// Child process
			execvp("rauc", argv);
			perror("execvp failed");
			_exit(1);
		} else if (pid > 0) {
			// Parent process
			int status;
			if (waitpid(pid, &status, 0) < 0) {
				LOG_ERROR("waitpid failed: %s",
					  strerror(errno));
				return -1;
			}
			if (WIFEXITED(status)) {
				int exit_status = WEXITSTATUS(status);
				if (exit_status != 0) {
					LOG_ERROR("RAUC install failed with "
						  "exit status %d",
						  exit_status);
					return -1;
				}
			} else if (WIFSIGNALED(status)) {
				LOG_ERROR(
				    "RAUC install terminated by signal %d",
				    WTERMSIG(status));
				return -1;
			} else {
				LOG_ERROR("RAUC install ended unexpectedly");
				return -1;
			}
		} else {
			// Fork failed
			perror("fork failed");
			return -1;
		}

		LOG_INFO("RAUC install succeeded");

		if (make_new_manifest_current(ctx) != 0) {
			LOG_ERROR("Failed to update current manifest");
			return 1;
		}

		LOG_INFO("Rebooting system...");
		sync();
		reboot(RB_AUTOBOOT); // or system("reboot")

	} else {
		LOG_ERROR("Unsupported update type: %s", file_type);
		return 1;
	}

	return 0;
}

/* ------------------------------------------------------------------------ */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg) {
	int attempt = 0;
	int rc = 0;
	ota_ctx_t ctx;
	int fetch_interval_sec = FETCH_INTERVAL_SEC;
	struct sigaction sa;

	if (cfg->update_interval_sec > 0)
		fetch_interval_sec = cfg->update_interval_sec;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_termination_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	while (1) {
		rc = ota_ctx_init(&ctx, cfg);
		if (rc != 0)
			goto attempt_end;

		ota_inbox_cleanup(&ctx);

		rc = fetch_new_manifest(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = validate_new_manifest(&ctx);
		if (rc != 0)
			goto attempt_end;

		files_equal_result_t cmp_rc = compare_manifests(&ctx);
		if (cmp_rc == FILES_EQ) {
			if (!daemon_mode) {
				// System up to date + one-shot, return
				ota_ctx_free(&ctx);
				return 0;
			}
			rc = 0;
			goto attempt_end;
		}
		if (cmp_rc == FILES_ERR) {
			rc = -1;
			goto attempt_end;
		}

		ctx.inbox_manifest = manifest_load(ctx.inbox_manifest_path);
		if (ctx.inbox_manifest == NULL) {
			LOG_ERROR("Failed to load new manifest");
			rc = -1;
			goto attempt_end;
		}

		rc = fetch_release(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = validate_release(&ctx);
		if (rc != 0)
			goto attempt_end;

		rc = apply_release(&ctx);
		if ((rc == 0) && (!daemon_mode)) {
			// Update applied + one-shot, return
			ota_ctx_free(&ctx);
			return rc;
		}

	attempt_end:
		if (!daemon_mode)
			attempt++;
		ota_ctx_free(&ctx);

		if (daemon_mode) {
			// daemon mode
			sleep(fetch_interval_sec);
		} else {
			// one-shot mode
			if (attempt < cfg->retry_attempts) {
				sleep(RETRY_DELAY);
			} else {
				return rc;
			}
		}

		if (g_terminate)
			return 0;
	};

	return 0;
}
