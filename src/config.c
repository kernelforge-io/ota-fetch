// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file config.c
 * @brief INI-based configuration parsing and validation.
 *
 * Loads OTA Fetcher configuration from an INI file with [network] and
 * [system] sections, performs basic validation, and provides helpers for
 * printing and cleanup.
 */

#include "config.h"
#include "ini.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUP(s) ((s) ? strdup(s) : NULL)

static int validate_required_string(const char *value, const char *name) {
	if (!value || value[0] == '\0') {
		fprintf(stderr, "Config missing required value: %s\n", name);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
int config_handler(void *user, const char *section, const char *name,
		   const char *value) {
	struct ota_config *cfg = (struct ota_config *)user;

#define MATCH(sec, key) strcmp(section, sec) == 0 && strcmp(name, key) == 0

	if (MATCH("network", "server_url")) {
		cfg->server_url = DUP(value);
	} else if (MATCH("network", "tls_ca_cert")) {
		cfg->tls_ca_cert = DUP(value);
	} else if (MATCH("network", "tls_client_cert")) {
		cfg->tls_client_cert = DUP(value);
	} else if (MATCH("network", "tls_client_key")) {
		cfg->tls_client_key = DUP(value);
	} else if (MATCH("network", "connect_timeout")) {
		cfg->connect_timeout = atoi(value);
	} else if (MATCH("network", "transfer_timeout")) {
		cfg->transfer_timeout = atoi(value);
	} else if (MATCH("network", "low_speed_limit")) {
		cfg->low_speed_limit = atoi(value);
	} else if (MATCH("network", "low_speed_time")) {
		cfg->low_speed_time = atoi(value);
	} else if (MATCH("network", "retry_attempts")) {
		cfg->retry_attempts = atoi(value);
	} else if (MATCH("system", "update_interval_sec")) {
		cfg->update_interval_sec = atoi(value);
	} else if (MATCH("system", "inbox_manifest_dir")) {
		cfg->inbox_manifest_dir = DUP(value);
	} else if (MATCH("system", "current_manifest_dir")) {
		cfg->current_manifest_dir = DUP(value);
	} else if (MATCH("system", "manifest_ca_cert")) {
		cfg->manifest_ca_cert = DUP(value);
	} else if (MATCH("system", "log_file")) {
		cfg->log_file = DUP(value);
	} else if (MATCH("system", "device_id")) {
		cfg->device_id = DUP(value);
	}

	return 1; // success
}

/* ------------------------------------------------------------------------ */
int config_load(const char *filename, struct ota_config *config) {
	memset(config, 0, sizeof(*config));
	int rc = ini_parse(filename, config_handler, config);
	if (rc != 0) {
		config_free(config);
		return rc;
	}

	if (validate_required_string(config->server_url,
				     "network.server_url") != 0 ||
	    validate_required_string(config->tls_ca_cert, "network.tls_ca_cert") != 0 ||
	    validate_required_string(config->tls_client_cert,
				     "network.tls_client_cert") != 0 ||
	    validate_required_string(config->tls_client_key,
				     "network.tls_client_key") != 0 ||
	    validate_required_string(config->inbox_manifest_dir,
				     "system.inbox_manifest_dir") != 0 ||
	    validate_required_string(config->current_manifest_dir,
				     "system.current_manifest_dir") != 0 ||
	    validate_required_string(config->manifest_ca_cert,
				     "system.manifest_ca_cert") != 0) {
		config_free(config);
		return -1;
	}

	return 0;
}

/* ------------------------------------------------------------------------ */
void config_free(struct ota_config *config) {
	free(config->server_url);
	free(config->tls_ca_cert);
	free(config->tls_client_cert);
	free(config->tls_client_key);
	free(config->inbox_manifest_dir);
	free(config->current_manifest_dir);
	free(config->manifest_ca_cert);
	free(config->log_file);
	free(config->device_id);
}

/* ------------------------------------------------------------------------ */
void config_print(const struct ota_config *config) {
	printf("Config:\n");
	printf("server_url          = %s\n",
	       config->server_url ? config->server_url : "(null)");
	printf("tls_ca_cert             = %s\n",
	       config->tls_ca_cert ? config->tls_ca_cert : "(null)");
	printf("tls_client_cert         = %s\n",
	       config->tls_client_cert ? config->tls_client_cert : "(null)");
	printf("tls_client_key          = %s\n",
	       config->tls_client_key ? config->tls_client_key : "(null)");
	printf("connect_timeout     = %d\n", config->connect_timeout);
	printf("transfer_timeout    = %d\n", config->transfer_timeout);
	printf("low_speed_limit     = %d\n", config->low_speed_limit);
	printf("low_speed_time      = %d\n", config->low_speed_time);
	printf("retry_attempts      = %d\n", config->retry_attempts);
	printf("update_interval_sec = %d\n", config->update_interval_sec);
	printf("inbox_manifest_dir  = %s\n",
	       config->inbox_manifest_dir ? config->inbox_manifest_dir : "(null)");
	printf("current_manifest_dir= %s\n",
	       config->current_manifest_dir ? config->current_manifest_dir
					     : "(null)");
	printf("manifest_ca_cert        = %s\n",
	       config->manifest_ca_cert ? config->manifest_ca_cert : "(null)");
	printf("log_file            = %s\n",
	       config->log_file ? config->log_file : "(null)");
	printf("device_id           = %s\n",
	       config->device_id ? config->device_id : "(null)");
}
