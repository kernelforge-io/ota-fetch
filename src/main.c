// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file main.c
 * @brief OTA Fetcher CLI entry point.
 *
 * Parses command-line arguments, loads configuration, and invokes
 * the main OTA fetch/update logic. Supports one-shot and periodic
 * (daemon_mode) operation without backgrounding the process.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#include "config.h"
#include "enroll.h"
#include "log.h"
#include "ota_fetch.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Supported run modes for OTA fetcher.
 */
enum run_mode {
	MODE_ONESHOT, /**< Run once and exit */
	MODE_DAEMON   /**< Run periodically as a daemon */
};

enum command_mode {
	CMD_FETCH,
	CMD_ENROLL,
};

/**
 * @brief Print usage/help text to stdout.
 *
 * @param progname Name of the executable (argv[0]).
 */
void print_usage(const char *progname) {
	printf("Usage:\n");
	printf("  %s [--daemon] [--oneshot] [--debug] [--config=PATH]\n",
	       progname);
	printf("  %s enroll [--config PATH] [--token-file PATH] [--force] "
	       "[--debug]\n",
	       progname);
}

static int parse_fetch_args(int argc, char *argv[], const char **config_path,
			    enum run_mode *mode, bool *debug_enabled) {
	static struct option long_opts[] = {
	    {"daemon", no_argument, 0, 'd'},
	    {"oneshot", no_argument, 0, 'o'},
	    {"config", required_argument, 0, 'c'},
	    {"debug", no_argument, 0, 'v'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	int opt;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "doc:vh", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'd':
			*mode = MODE_DAEMON;
			break;
		case 'o':
			*mode = MODE_ONESHOT;
			break;
		case 'c':
			*config_path = optarg;
			break;
		case 'v':
			*debug_enabled = true;
			break;
		case 'h':
			print_usage(argv[0]);
			return 1;
		default:
			print_usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

static int parse_enroll_args(int argc, char *argv[], const char **config_path,
			     const char **token_file, bool *force,
			     bool *debug_enabled, const char *progname) {
	static struct option long_opts[] = {{"config", required_argument, 0,
					     'c'},
					    {"token-file", required_argument, 0,
					     't'},
					    {"force", no_argument, 0, 'f'},
					    {"debug", no_argument, 0, 'v'},
					    {"help", no_argument, 0, 'h'},
					    {0, 0, 0, 0}};

	int opt;
	optind = 1;
	while ((opt = getopt_long(argc, argv, "c:t:fvh", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'c':
			*config_path = optarg;
			break;
		case 't':
			*token_file = optarg;
			break;
		case 'f':
			*force = true;
			break;
		case 'v':
			*debug_enabled = true;
			break;
		case 'h':
			print_usage(progname);
			return 1;
		default:
			print_usage(progname);
			return -1;
		}
	}

	return 0;
}

/**
 * @brief Main entry point for OTA fetcher CLI.
 *
 * Parses CLI arguments, loads OTA configuration, and dispatches either the
 * fetch loop or bootstrap enrollment flow.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit code (0 on success, nonzero on error).
 */
int main(int argc, char *argv[]) {
	const char *config_path = "/etc/ota-fetch/ota-fetch.conf";
	const char *token_file = "/var/lib/ota-fetch/identity/enroll.token";
	enum run_mode mode = MODE_ONESHOT;
	enum command_mode command = CMD_FETCH;
	bool force = false;
	bool debug_enabled = false;
	int parse_rc = 0;

	if (argc > 1 && strcmp(argv[1], "enroll") == 0) {
		command = CMD_ENROLL;
		parse_rc = parse_enroll_args(argc - 1, argv + 1, &config_path,
					     &token_file, &force,
					     &debug_enabled, argv[0]);
	} else {
		parse_rc = parse_fetch_args(argc, argv, &config_path, &mode,
					    &debug_enabled);
	}

	if (parse_rc > 0) {
		return 0;
	}
	if (parse_rc < 0) {
		return 1;
	}

	log_set_level(debug_enabled ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO);

	struct ota_config config;
	int config_rc = config_load(config_path, &config);
	if (config_rc != 0) {
		if (config_rc > 0) {
			log_error("Failed to load config %s (parse error near "
				  "line %d)",
				  config_path, config_rc);
		} else {
			log_error("Failed to load config: %s", config_path);
		}
		return 1;
	}

	log_set_file(config.log_file);
	config_print(&config);
	if (command == CMD_ENROLL) {
		log_info("Starting ota-fetch enrollment");
	} else {
		log_info("Starting ota-fetch (%s mode)",
			 mode == MODE_DAEMON ? "daemon" : "oneshot");
	}

	int rc;
	if (command == CMD_ENROLL) {
		rc = ota_fetch_enroll(&config, token_file, force);
	} else {
		rc = ota_fetch_run(mode == MODE_DAEMON, &config);
	}

	config_free(&config);
	log_close();
	return rc;
}
