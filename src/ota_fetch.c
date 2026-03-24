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
#include "log.h"
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
#include <time.h>
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
#define LOG_PROGRESS_NONTTY_BYTE_INTERVAL (5ULL * 1024ULL * 1024ULL)

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
 * @brief Result codes for file equality checks.
 */
typedef enum {
	FILES_EQ = 0,  /**< Files are equal */
	FILES_NEQ = 1, /**< Files are not equal */
	FILES_ERR = -1 /**< Error occurred */
} files_equal_result_t;

/**
 * @brief Streaming download progress state for libcurl callbacks.
 */
struct download_progress {
	int64_t started_ms;
	int64_t last_emit_ms;
	int last_percent;
	int last_non_tty_percent_milestone;
	uint64_t last_non_tty_byte_milestone;
	uint64_t transferred;
	uint64_t total;
};

static int64_t monotonic_ms(void) {
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return ((int64_t)ts.tv_sec * 1000LL) + (ts.tv_nsec / 1000000LL);
}

static size_t file_write_callback(void *contents, size_t size, size_t nmemb,
				  void *userp) {
	FILE *fp = (FILE *)userp;
	size_t total_size = size * nmemb;

	if (!fp || total_size == 0) {
		return 0;
	}

	return fwrite(contents, 1, total_size, fp);
}

static void download_progress_init(struct download_progress *progress) {
	if (!progress) {
		return;
	}

	memset(progress, 0, sizeof(*progress));
	progress->started_ms = monotonic_ms();
	progress->last_emit_ms = -1;
	progress->last_percent = -1;
	progress->last_non_tty_percent_milestone = -1;
}

static int download_progress_percent(uint64_t transferred, uint64_t total) {
	uint64_t percent;

	if (total == 0) {
		return -1;
	}

	percent = (transferred * 100u) / total;
	if (percent > 100u) {
		percent = 100u;
	}

	return (int)percent;
}

static double
download_progress_speed(const struct download_progress *progress) {
	int64_t elapsed_ms;

	if (!progress || progress->transferred == 0 ||
	    progress->started_ms <= 0) {
		return 0.0;
	}

	elapsed_ms = monotonic_ms() - progress->started_ms;
	if (elapsed_ms <= 0) {
		return 0.0;
	}

	return ((double)progress->transferred * 1000.0) / (double)elapsed_ms;
}

static void download_progress_render(const struct download_progress *progress,
				     bool final_line) {
	char line[128];
	uint64_t total;

	if (!progress || !log_progress_enabled() ||
	    progress->transferred == 0) {
		return;
	}

	total = progress->total;
	if (final_line && total == 0) {
		total = progress->transferred;
	}

	if (log_format_progress_line(line, sizeof(line), progress->transferred,
				     total,
				     download_progress_speed(progress)) != 0) {
		return;
	}

	if (final_line) {
		log_progress_finish(line);
	} else {
		log_progress_update(line);
	}
}

static int download_progress_callback(void *clientp, curl_off_t dltotal,
				      curl_off_t dlnow, curl_off_t ultotal,
				      curl_off_t ulnow) {
	struct download_progress *progress = (struct download_progress *)
	    clientp;
	int64_t now_ms;
	int current_percent;
	int current_percent_milestone;
	uint64_t current_byte_milestone;

	(void)ultotal;
	(void)ulnow;

	if (!progress) {
		return 0;
	}

	progress->total = dltotal > 0 ? (uint64_t)dltotal : 0;
	progress->transferred = dlnow > 0 ? (uint64_t)dlnow : 0;

	if (!log_progress_enabled() || progress->transferred == 0) {
		return 0;
	}

	if (progress->total > 0 && progress->transferred >= progress->total) {
		return 0;
	}

	if (!isatty(fileno(stderr))) {
		if (progress->total > 0) {
			current_percent = download_progress_percent(
			    progress->transferred, progress->total);
			current_percent_milestone =
			    log_progress_percent_milestone(current_percent);
			if (current_percent_milestone < 0 ||
			    current_percent_milestone ==
				progress->last_non_tty_percent_milestone) {
				return 0;
			}

			progress->last_non_tty_percent_milestone =
			    current_percent_milestone;
		} else {
			current_byte_milestone = log_progress_byte_milestone(
			    progress->transferred,
			    LOG_PROGRESS_NONTTY_BYTE_INTERVAL);
			if (current_byte_milestone == 0 ||
			    current_byte_milestone ==
				progress->last_non_tty_byte_milestone) {
				return 0;
			}

			progress->last_non_tty_byte_milestone =
			    current_byte_milestone;
		}

		download_progress_render(progress, false);
		return 0;
	}

	now_ms = monotonic_ms();
	current_percent = download_progress_percent(progress->transferred,
						    progress->total);
	if (!log_progress_should_emit(now_ms, progress->last_emit_ms,
				      progress->last_percent, current_percent,
				      false)) {
		return 0;
	}

	progress->last_emit_ms = now_ms;
	progress->last_percent = current_percent;
	download_progress_render(progress, false);
	return 0;
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

	log_debug("file1=%s hash1=%s ret=%d", path1, sha256_hex(hash1),
		  irethash1);
	log_debug("file2=%s hash2=%s ret=%d", path2, sha256_hex(hash2),
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
static int ensure_parent_dir_exists(const char *dest_path) {
	char dir[PATH_MAX];
	char *slash = NULL;

	if (!dest_path) {
		errno = EINVAL;
		return -1;
	}

	strncpy(dir, dest_path, sizeof(dir));
	dir[sizeof(dir) - 1] = '\0';

	slash = strrchr(dir, '/');
	if (!slash) {
		return 0;
	}

	*slash = '\0';
	if (dir[0] == '\0') {
		return 0;
	}

	return mkdir_p(dir, 0755);
}

static int fetch_file(const char *url, const char *dest_path,
		      const struct ota_config *cfg, bool show_progress) {
	int rc = -1;
	long http_code = 0;
	CURLcode res;
	CURL *curl = NULL;
	char *tmp_path = NULL;
	FILE *fp = NULL;
	bool progress_enabled = false;
	struct download_progress progress;

	if (ensure_parent_dir_exists(dest_path) != 0) {
		log_error("Failed to create directory for %s: %s", dest_path,
			  strerror(errno));
		return -1;
	}

	size_t tmp_len = strlen(dest_path) + 5;
	tmp_path = malloc(tmp_len);
	if (!tmp_path) {
		log_error("Failed to allocate temp path");
		return -1;
	}
	snprintf(tmp_path, tmp_len, "%s.tmp", dest_path);

	fp = fopen(tmp_path, "wb");
	if (!fp) {
		log_error("Failed to open %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	curl = curl_easy_init();

	if (!curl) {
		log_error("Failed to initialize libcurl");
		goto cleanup;
	}

	progress_enabled = show_progress && log_progress_enabled();
	download_progress_init(&progress);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
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

	if (progress_enabled) {
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,
				 download_progress_callback);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	}

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (res != CURLE_OK) {
		if (http_code >= 400) {
			log_error("HTTP error fetching %s: %ld", url,
				  http_code);
		} else {
			log_error("curl error fetching %s: %s", url,
				  curl_easy_strerror(res));
		}

		long verify_result = 0;
		curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT,
				  &verify_result);
		log_error("SSL verify result: %ld", verify_result);
		goto cleanup;
	}

	if (http_code < 200 || http_code >= 300) {
		log_error("HTTP error fetching %s: %ld", url, http_code);
		goto cleanup;
	}

	if (fflush(fp) != 0) {
		log_error("Failed to flush %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}

	if (fclose(fp) != 0) {
		fp = NULL;
		log_error("Failed to close %s: %s", tmp_path, strerror(errno));
		goto cleanup;
	}
	fp = NULL;

	if (rename(tmp_path, dest_path) != 0) {
		log_error("Failed to move %s to %s: %s", tmp_path, dest_path,
			  strerror(errno));
		goto cleanup;
	}

	if (progress_enabled) {
		download_progress_render(&progress, true);
	}

	rc = 0;

cleanup:
	if (fp) {
		fclose(fp);
	}
	if (rc != 0 && tmp_path) {
		unlink(tmp_path);
	}
	free(tmp_path);
	curl_easy_cleanup(curl);
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
	int rc1;
	int rc2;
	int rc3;

	manifest_url = build_path(ctx->config.server_url, "manifest.json");
	sig_url = build_path(ctx->config.server_url, "manifest.json.sig");
	cert_url = build_path(ctx->config.server_url, "signer.crt");
	if (!manifest_url || !sig_url || !cert_url) {
		log_error("Failed to build manifest download URLs");
		free(manifest_url);
		free(sig_url);
		free(cert_url);
		return -1;
	}

	log_info("Downloading manifest: manifest.json");
	rc1 = fetch_file(manifest_url, ctx->inbox_manifest_path, &ctx->config,
			 false);
	if (rc1 == 0) {
		log_info("Manifest download completed: %s",
			 ctx->inbox_manifest_path);
	}

	log_info("Downloading manifest signature: manifest.json.sig");
	rc2 = fetch_file(sig_url, ctx->inbox_sig_path, &ctx->config, false);
	if (rc2 == 0) {
		log_info("Manifest signature download completed: %s",
			 ctx->inbox_sig_path);
	}

	log_info("Downloading signer certificate: signer.crt");
	rc3 = fetch_file(cert_url, ctx->inbox_cert_path, &ctx->config, false);
	if (rc3 == 0) {
		log_info("Signer certificate download completed: %s",
			 ctx->inbox_cert_path);
	}

	if (rc1)
		log_error("Failed to fetch manifest.json");
	if (rc2)
		log_error("Failed to fetch manifest.json.sig");
	if (rc3)
		log_error("Failed to fetch signer.crt");

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
		log_error("Manifest verification failed: %s", errbuf);
		return -1;
	}
	log_info("Manifest verification succeeded");
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
		log_info("Update available: no current manifest found");
		return FILES_NEQ;
	}
	if (!file_exists(ctx->inbox_manifest_path)) {
		log_error("No inbox manifest to compare");
		return FILES_ERR;
	}

	files_equal_result_t ret = files_equal(ctx->current_manifest_path,
					       ctx->inbox_manifest_path);
	if (ret == FILES_EQ) {
		log_info("System already up to date");
	} else if (ret == FILES_NEQ) {
		log_info("Update available: manifest changed");
	} else {
		log_error("Failed to compare current and new manifests");
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
		log_error("Failed to create directory: %s", strerror(errno));
	}

	// Remove existing destination file, if any
	unlink(ctx->current_manifest_path);

	// Move (rename) the file
	if (rename(ctx->inbox_manifest_path, ctx->current_manifest_path) != 0) {
		log_error("Failed to move manifest from %s to %s: %s",
			  ctx->inbox_manifest_path, ctx->current_manifest_path,
			  strerror(errno));
		return -1;
	}

	log_info("Updated current manifest: %s -> %s", ctx->inbox_manifest_path,
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
		log_error("No release found for device %s",
			  ctx->config.device_id ? ctx->config.device_id
						: "(default)");
		return -1;
	}

	if (ctx->release->files_count == 0 || !ctx->release->files) {
		log_error("Selected release contains no files");
		return -1;
	}

	file = &ctx->release->files[0];
	if (!file->filename || !file->path || !file->sha256 ||
	    !file->file_type) {
		log_error("Release file entry missing required fields "
			  "(file_type, filename, path, sha256)");
		return -1;
	}

	// Assemble path where payload will be downloaded
	// Note: ctx->payload_path is freed in ota_ctx_free.
	if (ctx->payload_path != NULL) {
		free(ctx->payload_path);
		ctx->payload_path = NULL;
	}
	ctx->payload_path = build_path(ctx->config.inbox_manifest_dir,
				       file->filename);
	if (ctx->payload_path == NULL) {
		log_error("Failed to allocate payload path");
		return -1;
	}

	char *payload_url = NULL;
	payload_url = build_path(ctx->config.server_url, file->path);

	if (payload_url == NULL) {
		log_error("Failed to assemble release payload URL");
		return -1;
	}

	log_info("Update selected: %s %s",
		 ctx->release->release_name ? ctx->release->release_name
					    : "(unnamed release)",
		 ctx->release->release_version ? ctx->release->release_version
					       : "(unknown version)");
	log_info("Downloading payload: %s", file->filename);
	ret = fetch_file(payload_url, ctx->payload_path, &ctx->config, true);

	if (ret != 0) {
		log_error("Payload download failed");
	} else {
		log_info("Payload download completed: %s", ctx->payload_path);
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
	    ctx->release->files_count == 0 || !ctx->release->files[0].sha256) {
		log_error("Release file hash missing from manifest");
		return -1;
	}

	uint8_t hash[SHA256_DIGEST_LEN];
	char hash_string[SHA256_DIGEST_LEN * 2 + 1];
	int rc;

	rc = sha256sum_file(ctx->payload_path, hash);
	if (rc != SHA256SUM_OK) {
		log_error("Failed to hash payload %s: %d", ctx->payload_path,
			  rc);
		return -1;
	}

	if (hex_encode(hash_string, sizeof(hash_string), hash,
		       SHA256_DIGEST_LEN) != 0) {
		log_error("Failed to format payload SHA256");
		return -1;
	}

	if (strcmp(hash_string, ctx->release->files[0].sha256) != 0) {
		log_error("Payload hash verification failed");
		log_error("Expected: %s", ctx->release->files[0].sha256);
		log_error("Actual:   %s", hash_string);
		return -1;
	}

	log_info("Payload hash verification succeeded");
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
	log_info("Starting apply stage");

	if (!ctx->release || !ctx->release->files ||
	    ctx->release->files_count == 0 ||
	    !ctx->release->files[0].file_type) {
		log_error("Release file_type missing from manifest");
		return -1;
	}

	const char *file_type = ctx->release->files[0].file_type;

	if (strcmp(file_type, "rauc_bundle_test") == 0) {
		log_info("Simulating RAUC bundle apply for testing");
		if (make_new_manifest_current(ctx) != 0) {
			log_error("Failed to update current manifest");
			return -1;
		}

	} else if (strcmp(file_type, "rauc_bundle") == 0) {
		log_info("Handing payload to RAUC");

		const char *bundle_path = ctx->payload_path;
		char *const argv[] = {"rauc", "install", (char *)bundle_path,
				      NULL};

		pid_t pid = fork();
		if (pid == 0) {
			// Child process
			execvp("rauc", argv);
			log_error("execvp failed: %s", strerror(errno));
			_exit(1);
		} else if (pid > 0) {
			// Parent process
			int status;
			if (waitpid(pid, &status, 0) < 0) {
				log_error("waitpid failed: %s",
					  strerror(errno));
				return -1;
			}
			if (WIFEXITED(status)) {
				int exit_status = WEXITSTATUS(status);
				if (exit_status != 0) {
					log_error("RAUC install failed with "
						  "exit status %d",
						  exit_status);
					return -1;
				}
			} else if (WIFSIGNALED(status)) {
				log_error(
				    "RAUC install terminated by signal %d",
				    WTERMSIG(status));
				return -1;
			} else {
				log_error("RAUC install ended unexpectedly");
				return -1;
			}
		} else {
			// Fork failed
			log_error("fork failed: %s", strerror(errno));
			return -1;
		}

		log_info("RAUC install succeeded");

		if (make_new_manifest_current(ctx) != 0) {
			log_error("Failed to update current manifest");
			return 1;
		}

		log_info("Rebooting system");
		sync();
		reboot(RB_AUTOBOOT); // or system("reboot")

	} else {
		log_error("Unsupported update type: %s", file_type);
		return 1;
	}

	log_info("Apply stage completed successfully");
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
		log_info("Starting update check");
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
				log_info("Update check completed successfully");
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
			log_error("Failed to load downloaded manifest");
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
			log_info("OTA update completed successfully");
			ota_ctx_free(&ctx);
			return rc;
		}

	attempt_end:
		if (!daemon_mode)
			attempt++;
		ota_ctx_free(&ctx);

		if (rc != 0) {
			log_error("Update check failed");
		}

		if (daemon_mode) {
			// daemon mode
			sleep(fetch_interval_sec);
		} else {
			// one-shot mode
			if (attempt < cfg->retry_attempts) {
				log_warn("Retrying update check in %d seconds "
					 "(%d/%d)",
					 RETRY_DELAY, attempt,
					 cfg->retry_attempts);
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
