// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC

#include "log.h"
#include "test_common.h"

int main(void) {
	char buf[128];
	const uint64_t mib = 1024u * 1024u;
	int original_level = log_get_level();

	TEST_ASSERT(log_format_bytes(buf, sizeof(buf), 512u) > 0);
	TEST_ASSERT_STR_EQ("512 B", buf);

	TEST_ASSERT(log_format_bytes(buf, sizeof(buf), 1536u) > 0);
	TEST_ASSERT_STR_EQ("1.5 KiB", buf);

	TEST_ASSERT(log_format_bytes(buf, sizeof(buf), 5u * mib) > 0);
	TEST_ASSERT_STR_EQ("5.0 MiB", buf);

	TEST_ASSERT(log_format_eta(buf, sizeof(buf), 17u) > 0);
	TEST_ASSERT_STR_EQ("00:17", buf);

	TEST_ASSERT(log_format_eta(buf, sizeof(buf), 3723u) > 0);
	TEST_ASSERT_STR_EQ("01:02:03", buf);

	TEST_ASSERT_INT_EQ(-1, log_progress_percent_milestone(9));
	TEST_ASSERT_INT_EQ(10, log_progress_percent_milestone(10));
	TEST_ASSERT_INT_EQ(40, log_progress_percent_milestone(49));
	TEST_ASSERT_INT_EQ(100, log_progress_percent_milestone(100));

	TEST_ASSERT_INT_EQ(0, (int)log_progress_byte_milestone(0u, 1024u));
	TEST_ASSERT_INT_EQ(0, (int)log_progress_byte_milestone(1023u, 1024u));
	TEST_ASSERT_INT_EQ(1, (int)log_progress_byte_milestone(1024u, 1024u));
	TEST_ASSERT_INT_EQ(3, (int)log_progress_byte_milestone(3072u, 1024u));

	TEST_ASSERT(log_progress_should_emit(1000, -1, -1, 0, false));
	TEST_ASSERT(!log_progress_should_emit(1100, 1000, 10, 11, false));
	TEST_ASSERT(log_progress_should_emit(1250, 1000, 10, 11, false));
	TEST_ASSERT(log_progress_should_emit(1500, 1000, 11, 11, false));
	TEST_ASSERT(log_progress_should_emit(1100, 1000, 11, 11, true));

	TEST_ASSERT(log_format_progress_line(buf, sizeof(buf), 42u * mib,
					     100u * mib,
					     2.0 * (double)mib) == 0);
	TEST_ASSERT_STR_EQ("42%  42.0 MiB / 100.0 MiB  2.0 MiB/s  ETA 00:29",
			   buf);

	TEST_ASSERT(log_format_progress_line(buf, sizeof(buf), 12u * mib, 0u,
					     1.5 * (double)mib) == 0);
	TEST_ASSERT_STR_EQ("12.0 MiB downloaded  1.5 MiB/s", buf);

	log_set_level(LOG_LEVEL_WARN);
	TEST_ASSERT(log_is_enabled(LOG_LEVEL_ERROR));
	TEST_ASSERT(log_is_enabled(LOG_LEVEL_WARN));
	TEST_ASSERT(!log_is_enabled(LOG_LEVEL_INFO));
	TEST_ASSERT(!log_is_enabled(LOG_LEVEL_DEBUG));

	log_set_level(LOG_LEVEL_DEBUG);
	TEST_ASSERT(log_is_enabled(LOG_LEVEL_DEBUG));

	log_set_level(original_level);
	return 0;
}
