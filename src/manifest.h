// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file manifest.h
 * @brief OTA update manifest API.
 *
 * Parses and represents an OTA update manifest that may contain multiple
 * per-device (device_id) releases. Each release contains one or more files.
 *
 * Manifest design notes:
 * - File entries contain a RELATIVE "path" (relative to device Base URL).
 * - Selection logic is handled here:
 *     - prefer exact device_id match
 *     - else fall back to "default"
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef OTA_FETCH_MANIFEST_H
#define OTA_FETCH_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup manifest Manifest Parsing
 * @brief Parse and select OTA manifest releases and files.
 * @{
 */

typedef struct {
	char *file_type; /**< e.g. "rauc_bundle" */
	char *filename;	 /**< filename, e.g. "bundle.raucb" */
	uint64_t size;	 /**< size in bytes */
	char *sha256;	 /**< hex string */
	char *path;	 /**< relative path, e.g. "default/bundle.raucb" */
} manifest_file_t;

typedef struct {
	char *device_id;	/**< "default" or a device-specific id */
	char *release_name;	/**< e.g. "lab_r5bp_test" */
	char *release_version;	/**< e.g. "1.1.1" */
	char *created;		/**< ISO8601 timestamp */
	manifest_file_t *files; /**< array of files */
	size_t files_count;
} manifest_release_t;

typedef struct {
	char *manifest_version;	      /**< e.g. "9.9.9-test" */
	char *created;		      /**< ISO8601 timestamp */
	manifest_release_t *releases; /**< array of releases */
	size_t releases_count;
} manifest_t;

/**
 * @brief Parse a manifest JSON file from disk.
 *
 * Loads and parses a manifest from the specified file.
 *
 * @param path Path to manifest JSON file.
 * @return Pointer to allocated manifest_t on success, NULL on error.
 *
 * @note The returned manifest_t must be freed with manifest_free().
 */
manifest_t *manifest_load(const char *path);

/**
 * @brief Free a manifest structure and all its fields.
 *
 * @param m Pointer to manifest_t to free (may be NULL).
 */
void manifest_free(manifest_t *m);

/**
 * @brief Print manifest fields and values for debugging/logging.
 *
 * Prints top-level fields and each release/file entry.
 *
 * @param m Pointer to manifest_t to print.
 */
void manifest_print(const manifest_t *m);

/**
 * @brief Select a release for a given device_id, with fallback to "default".
 *
 * Selection rules:
 * - If device_id is non-NULL and a matching release exists, return it.
 * - Else, if a release with device_id == "default" exists, return it.
 * - Else, return NULL.
 *
 * @param m Manifest document (may be NULL).
 * @param device_id Device ID to match (may be NULL).
 * @return Pointer to selected release within manifest (do not free).
 */
const manifest_release_t *manifest_select_release(const manifest_t *m,
						  const char *device_id);

/**
 * @brief Select a file entry from a release by file_type.
 *
 * Selection rules:
 * - If file_type is non-NULL and a matching entry exists, return it.
 * - Else, if release has files, return the first file.
 * - Else, return NULL.
 *
 * @param r Release (may be NULL).
 * @param file_type Desired file type, e.g. "rauc_bundle" (may be NULL).
 * @return Pointer to selected file within release (do not free).
 */
const manifest_file_t *manifest_release_select_file(const manifest_release_t *r,
						    const char *file_type);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // OTA_FETCH_MANIFEST_H
