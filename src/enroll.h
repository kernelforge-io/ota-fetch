// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file enroll.h
 * @brief Enrollment flow for runtime mTLS identity provisioning.
 */

#ifndef OTA_FETCH_ENROLL_H
#define OTA_FETCH_ENROLL_H

#include "config.h"
#include <stdbool.h>

/**
 * @brief Enroll device identity using a bootstrap token.
 *
 * Generates a private key and CSR, submits enrollment request, writes
 * configured TLS client key/cert paths atomically, and removes token on
 * success.
 *
 * @param cfg        Loaded OTA configuration.
 * @param token_file Path to bootstrap token file.
 * @param force      Overwrite existing identity files when true.
 * @return 0 on success, non-zero on failure.
 */
int ota_fetch_enroll(const struct ota_config *cfg, const char *token_file,
		     bool force);

#endif // OTA_FETCH_ENROLL_H
