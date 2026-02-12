// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file manifest.c
 * @brief Manifest JSON parsing and selection logic.
 *
 * Parses OTA manifest JSON documents into in-memory structures and provides
 * selection helpers for device-specific releases.
 */

#include "manifest.h"

#include <cjson/cJSON.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUP(s) ((s) ? strdup(s) : NULL)

/* ------------------------------------------------------------------------ */
static char *dup_json_string(cJSON *obj, const char *key) {
	cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
	if (!it || !cJSON_IsString(it) || !it->valuestring)
		return NULL;
	return strdup(it->valuestring);
}

/* ------------------------------------------------------------------------ */
static uint64_t json_u64(cJSON *obj, const char *key, int *ok) {
	cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
	if (!it || !cJSON_IsNumber(it)) {
		if (ok)
			*ok = 0;
		return 0;
	}
	if (ok)
		*ok = 1;

	/* cJSON stores numbers as double; cast carefully. */
	double v = it->valuedouble;
	if (v < 0)
		return 0;
	return (uint64_t)v;
}

/* ------------------------------------------------------------------------ */
static void free_file(manifest_file_t *f) {
	if (!f)
		return;
	free(f->file_type);
	free(f->filename);
	free(f->sha256);
	free(f->path);
	memset(f, 0, sizeof(*f));
}

/* ------------------------------------------------------------------------ */
static void free_release(manifest_release_t *r) {
	if (!r)
		return;

	free(r->device_id);
	free(r->release_name);
	free(r->release_version);
	free(r->created);

	if (r->files) {
		for (size_t i = 0; i < r->files_count; i++)
			free_file(&r->files[i]);
		free(r->files);
	}

	memset(r, 0, sizeof(*r));
}

/* ------------------------------------------------------------------------ */
manifest_t *manifest_load(const char *path) {
	FILE *fp = fopen(path, "rb");
	if (!fp)
		return NULL;

	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}

	long len = ftell(fp);
	if (len < 0) {
		fclose(fp);
		return NULL;
	}
	rewind(fp);

	char *data = (char *)malloc((size_t)len + 1);
	if (!data) {
		fclose(fp);
		return NULL;
	}

	size_t nread = fread(data, 1, (size_t)len, fp);
	fclose(fp);
	data[nread] = '\0';

	cJSON *root = cJSON_Parse(data);
	free(data);
	if (!root || !cJSON_IsObject(root)) {
		if (root)
			cJSON_Delete(root);
		return NULL;
	}

	manifest_t *m = (manifest_t *)calloc(1, sizeof(manifest_t));
	if (!m) {
		cJSON_Delete(root);
		return NULL;
	}

	/* Top-level required-ish fields */
	m->manifest_version = dup_json_string(root, "manifest_version");
	m->created = dup_json_string(root, "created");

	/* releases[] */
	cJSON *releases = cJSON_GetObjectItemCaseSensitive(root, "releases");
	if (releases && cJSON_IsArray(releases)) {
		size_t count = (size_t)cJSON_GetArraySize(releases);
		if (count > 0) {
			m->releases = (manifest_release_t *)
			    calloc(count, sizeof(manifest_release_t));
			if (!m->releases) {
				manifest_free(m);
				cJSON_Delete(root);
				return NULL;
			}
			m->releases_count = count;

			for (size_t i = 0; i < count; i++) {
				cJSON *rj = cJSON_GetArrayItem(releases,
							       (int)i);
				if (!rj || !cJSON_IsObject(rj)) {
					/* Skip invalid entries but keep
					 * structure consistent */
					continue;
				}

				manifest_release_t *r = &m->releases[i];
				r->device_id = dup_json_string(rj, "device_id");
				r->release_name =
				    dup_json_string(rj, "release_name");
				r->release_version =
				    dup_json_string(rj, "release_version");
				r->created = dup_json_string(rj, "created");

				cJSON *files = cJSON_GetObjectItemCaseSensitive(
				    rj, "files");
				if (files && cJSON_IsArray(files)) {
					size_t fcount = (size_t)
					    cJSON_GetArraySize(files);
					if (fcount > 0) {
						r->files = (manifest_file_t *)
						    calloc(
							fcount,
							sizeof(
							    manifest_file_t));
						if (!r->files) {
							manifest_free(m);
							cJSON_Delete(root);
							return NULL;
						}
						r->files_count = fcount;

						for (size_t k = 0; k < fcount;
						     k++) {
							cJSON *fj =
							    cJSON_GetArrayItem(
								files, (int)k);
							if (!fj ||
							    !cJSON_IsObject(fj))
								continue;

							manifest_file_t *f =
							    &r->files[k];
							f->file_type =
							    dup_json_string(
								fj,
								"file_type");
							f->filename =
							    dup_json_string(
								fj, "filename");
							f->sha256 =
							    dup_json_string(
								fj, "sha256");
							f->path =
							    dup_json_string(
								fj, "path");

							int ok = 0;
							f->size = json_u64(
							    fj, "size", &ok);
							/* size missing is
							 * allowed; keep as 0 */
						}
					}
				}
			}
		}
	}

	cJSON_Delete(root);
	return m;
}

/* ------------------------------------------------------------------------ */
void manifest_free(manifest_t *m) {
	if (!m)
		return;

	free(m->manifest_version);
	free(m->created);

	if (m->releases) {
		for (size_t i = 0; i < m->releases_count; i++)
			free_release(&m->releases[i]);
		free(m->releases);
	}

	free(m);
}

/* ------------------------------------------------------------------------ */
void manifest_print(const manifest_t *m) {
	if (!m)
		return;

	printf("Manifest:\n");
	printf("  manifest_version: %s\n",
	       m->manifest_version ? m->manifest_version : "(null)");
	printf("  created:          %s\n", m->created ? m->created : "(null)");
	printf("  releases_count:   %zu\n", m->releases_count);

	for (size_t i = 0; i < m->releases_count; i++) {
		const manifest_release_t *r = &m->releases[i];
		if (!r)
			continue;

		printf("  Release[%zu]:\n", i);
		printf("    device_id:       %s\n",
		       r->device_id ? r->device_id : "(null)");
		printf("    release_name:    %s\n",
		       r->release_name ? r->release_name : "(null)");
		printf("    release_version: %s\n",
		       r->release_version ? r->release_version : "(null)");
		printf("    created:         %s\n",
		       r->created ? r->created : "(null)");
		printf("    files_count:     %zu\n", r->files_count);

		for (size_t k = 0; k < r->files_count; k++) {
			const manifest_file_t *f = &r->files[k];
			printf("    File[%zu]:\n", k);
			printf("      file_type: %s\n",
			       f->file_type ? f->file_type : "(null)");
			printf("      filename:  %s\n",
			       f->filename ? f->filename : "(null)");
			printf("      path:      %s\n",
			       f->path ? f->path : "(null)");
			printf("      sha256:    %s\n",
			       f->sha256 ? f->sha256 : "(null)");
			printf("      size:      %" PRIu64 "\n", f->size);
		}
	}
}

/* ------------------------------------------------------------------------ */
const manifest_release_t *manifest_select_release(const manifest_t *m,
						  const char *device_id) {
	if (!m || !m->releases || m->releases_count == 0)
		return NULL;

	/* 1) Exact match */
	if (device_id && device_id[0] != '\0') {
		for (size_t i = 0; i < m->releases_count; i++) {
			const manifest_release_t *r = &m->releases[i];
			if (r->device_id &&
			    strcmp(r->device_id, device_id) == 0)
				return r;
		}
	}

	/* 2) Fallback to "default" */
	for (size_t i = 0; i < m->releases_count; i++) {
		const manifest_release_t *r = &m->releases[i];
		if (r->device_id && strcmp(r->device_id, "default") == 0)
			return r;
	}

	return NULL;
}

/* ------------------------------------------------------------------------ */
const manifest_file_t *manifest_release_select_file(const manifest_release_t *r,
						    const char *file_type) {
	if (!r || !r->files || r->files_count == 0)
		return NULL;

	/* 1) Exact file_type match */
	if (file_type && file_type[0] != '\0') {
		for (size_t i = 0; i < r->files_count; i++) {
			const manifest_file_t *f = &r->files[i];
			if (f->file_type &&
			    strcmp(f->file_type, file_type) == 0)
				return f;
		}
	}

	/* 2) Fallback to first file */
	return &r->files[0];
}
