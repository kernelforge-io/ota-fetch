// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file config.h
 * @brief OTA Fetcher configuration structure and helpers.
 *
 * Defines the OTA config structure and functions for loading, freeing,
 * and printing OTA update client configuration. Configuration is read
 * from an INI file with [network] and [system] sections.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef OTA_FETCH_CONFIG_H
#define OTA_FETCH_CONFIG_H

#include <stdbool.h>

/**
 * @defgroup config Configuration
 * @brief INI configuration for OTA Fetcher.
 *
 * The default config path is `/etc/ota-fetch/ota-fetch.conf`. Keys are read
 * from [network] and [system] sections.
 * @{
 */

/**
 * @brief OTA Fetcher configuration settings.
 *
 * Holds server URLs, certificates, credentials, timeouts, and paths
 * used for OTA update fetching and validation.
 */
struct ota_config {
	/**< OTA server base URL (e.g., "https://updates.example.com") */
	char *server_url;
	/**< Optional enrollment endpoint (defaults to server_url + "/enroll")
	 */
	char *enroll_url;
	/**< Path to CA certificate for TLS validation */
	char *tls_ca_cert;
	/**< Path to client certificate for mTLS */
	char *tls_client_cert;
	/**< Path to client private key for mTLS */
	char *tls_client_key;
	/**< HTTP(S) connect timeout, in seconds */
	int connect_timeout;
	/**< HTTP(S) transfer timeout, in seconds */
	int transfer_timeout;
	/**< Low speed limit (bytes/sec) before aborting (0 disables) */
	int low_speed_limit;
	/**< Low speed time (seconds) before aborting (0 disables) */
	int low_speed_time;
	/**< Number of download retry attempts on failure */
	int retry_attempts;
	/**< Daemon update interval, in seconds (0 uses default) */
	int update_interval_sec;
	/**< Directory to store inbox (pending) manifests and payloads */
	char *inbox_manifest_dir;
	/**< Directory for current/active manifest and state */
	char *current_manifest_dir;
	/**< Path to root CA cert for manifest signature validation */
	char *manifest_ca_cert;
	/**< Optional log file path (logs always go to stderr) */
	char *log_file;
	/**< Device ID for release */
	char *device_id;
};

/**
 * @brief Load OTA config from file.
 *
 * Loads OTA configuration from a file (default: /etc/ota-fetch/ota-fetch.conf).
 *
 * @param filename Path to config file.
 * @param config   Pointer to ota_config struct to populate.
 * @return 0 on success, nonzero on error (parse errors return a line number).
 *
 * @note Dynamically allocates strings in @p config; must call config_free().
 */
int config_load(const char *filename, struct ota_config *config);

/**
 * @brief Free all dynamically allocated strings in OTA config.
 *
 * @param config Pointer to ota_config struct to free.
 */
void config_free(struct ota_config *config);

/**
 * @brief Log OTA config fields at DEBUG level.
 *
 * @param config Pointer to ota_config struct to print.
 */
void config_print(const struct ota_config *config);

/** @} */

#endif // OTA_FETCH_CONFIG_H
