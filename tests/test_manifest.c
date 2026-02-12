// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC

#include "manifest.h"
#include "test_common.h"

int main(void) {
	char manifest_path[512];
	manifest_t *manifest;
	const manifest_release_t *release;
	const manifest_file_t *file;

	TEST_ASSERT_INT_EQ(0,
			   test_data_path(manifest_path, sizeof(manifest_path),
					  "manifest_valid.json"));

	manifest = manifest_load(manifest_path);
	TEST_ASSERT(manifest != NULL);
	TEST_ASSERT_STR_EQ("1.2.3-test", manifest->manifest_version);
	TEST_ASSERT_INT_EQ(2, (int)manifest->releases_count);

	release = manifest_select_release(manifest, "h4-gw");
	TEST_ASSERT(release != NULL);
	TEST_ASSERT_STR_EQ("h4-gw", release->device_id);
	TEST_ASSERT_STR_EQ("h4-gw-bundle.raucb", release->files[0].filename);

	release = manifest_select_release(manifest, "unknown-device");
	TEST_ASSERT(release != NULL);
	TEST_ASSERT_STR_EQ("default", release->device_id);

	file = manifest_release_select_file(release, "delta");
	TEST_ASSERT(file != NULL);
	TEST_ASSERT_STR_EQ("default.delta", file->filename);

	file = manifest_release_select_file(release, "does-not-exist");
	TEST_ASSERT(file != NULL);
	TEST_ASSERT_STR_EQ("default-bundle.raucb", file->filename);

	manifest_free(manifest);
	return 0;
}
