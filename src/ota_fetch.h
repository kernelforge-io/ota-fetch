// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file ota_fetch.h
 * @brief OTA Fetcher API for secure embedded update downloads.
 *
 * Declares the OTA fetch and update entry point for embedded Linux systems.
 * Features:
 *   - Secure HTTPS/mTLS downloads via libcurl
 *   - Manifest signature verification (OpenSSL)
 *   - Payload integrity validation (SHA-256)
 *   - RAUC bundle install integration
 *   - One-shot and periodic (daemon_mode) operation
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef OTA_FETCH_H
#define OTA_FETCH_H

#include "config.h"
#include <stdbool.h>

/**
 * @defgroup ota_fetch OTA Fetch Loop
 * @brief High-level OTA fetch and apply operation.
 * @{
 */

/**
 * @brief Run OTA fetch and update loop (main entry point).
 *
 * Checks for new updates, verifies, downloads, validates, and applies them.
 * If @p daemon_mode is true, runs as a periodic loop (no backgrounding).
 *
 * @param daemon_mode If true, run periodically; else, exit after one update
 * check.
 * @param cfg         OTA configuration (server URL, certs, etc.).
 * @return 0 on success, non-zero on failure.
 */
int ota_fetch_run(bool daemon_mode, const struct ota_config *cfg);

/** @} */

#endif // OTA_FETCH_H
