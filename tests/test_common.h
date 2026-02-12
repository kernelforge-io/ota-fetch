// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC

#ifndef OTA_FETCH_TEST_COMMON_H
#define OTA_FETCH_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TEST_DATA_DIR
#define TEST_DATA_DIR "."
#endif

static inline int test_data_path(char *out, size_t out_sz, const char *name) {
	int written;

	if (!out || out_sz == 0 || !name) {
		return -1;
	}

	written = snprintf(out, out_sz, "%s/%s", TEST_DATA_DIR, name);
	if (written < 0 || (size_t)written >= out_sz) {
		return -1;
	}

	return 0;
}

#define TEST_ASSERT(expr)                                                      \
	do {                                                                   \
		if (!(expr)) {                                                 \
			fprintf(stderr, "Assertion failed at %s:%d: %s\n",     \
				__FILE__, __LINE__, #expr);                    \
			return 1;                                              \
		}                                                              \
	} while (0)

#define TEST_ASSERT_INT_EQ(expected, actual)                                   \
	do {                                                                   \
		int exp_ = (expected);                                         \
		int act_ = (actual);                                           \
		if (exp_ != act_) {                                            \
			fprintf(stderr,                                        \
				"Assertion failed at %s:%d: expected %d, got " \
				"%d\n",                                        \
				__FILE__, __LINE__, exp_, act_);               \
			return 1;                                              \
		}                                                              \
	} while (0)

#define TEST_ASSERT_STR_EQ(expected, actual)                                   \
	do {                                                                   \
		const char *exp_ = (expected);                                 \
		const char *act_ = (actual);                                   \
		if (!exp_ || !act_ || strcmp(exp_, act_) != 0) {               \
			fprintf(stderr,                                        \
				"Assertion failed at %s:%d: expected \"%s\", " \
				"got \"%s\"\n",                                \
				__FILE__, __LINE__, exp_ ? exp_ : "(null)",    \
				act_ ? act_ : "(null)");                       \
			return 1;                                              \
		}                                                              \
	} while (0)

#endif // OTA_FETCH_TEST_COMMON_H
