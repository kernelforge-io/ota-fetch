// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC

#include "hash.h"
#include "test_common.h"

int main(void) {
	char data_path[512];
	uint8_t digest[SHA256_DIGEST_LEN];
	char digest_hex[SHA256_DIGEST_LEN * 2 + 1];
	char too_small[8];
	int rc;

	TEST_ASSERT_INT_EQ(0, test_data_path(data_path, sizeof(data_path),
					     "hash_input.txt"));

	rc = sha256sum_file(data_path, digest);
	TEST_ASSERT_INT_EQ(SHA256SUM_OK, rc);

	rc = hex_encode(digest_hex, sizeof(digest_hex), digest,
			SHA256_DIGEST_LEN);
	TEST_ASSERT_INT_EQ(0, rc);
	TEST_ASSERT_STR_EQ(
	    "ba115a108972dadacbb8d43488fec4daf9f91b63890877cf0d8b75af21da4999",
	    digest_hex);
	TEST_ASSERT_STR_EQ(digest_hex, sha256_hex(digest));

	rc = hex_encode(too_small, sizeof(too_small), digest,
			SHA256_DIGEST_LEN);
	TEST_ASSERT_INT_EQ(-2, rc);

	return 0;
}
