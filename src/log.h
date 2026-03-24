// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file log.h
 * @brief Centralized logging and console progress helpers.
 */

#ifndef OTA_FETCH_LOG_H
#define OTA_FETCH_LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LOG_PRINTF_FORMAT(fmt_index, first_arg)                                \
	__attribute__((format(printf, fmt_index, first_arg)))
#else
#define LOG_PRINTF_FORMAT(fmt_index, first_arg)
#endif

const char *log_level_str(int level);
const char *log_basename(const char *path);

void log_set_level(int level);
int log_get_level(void);
bool log_is_enabled(int level);

void log_vwrite(int level, const char *fmt, va_list args);
void log_write(int level, const char *fmt, ...) LOG_PRINTF_FORMAT(2, 3);

int log_set_file(const char *path);
void log_close(void);

bool log_progress_enabled(void);
void log_progress_update(const char *message);
void log_progress_finish(const char *message);
void log_progress_clear(void);

int log_format_bytes(char *buf, size_t buf_sz, uint64_t bytes);
int log_format_eta(char *buf, size_t buf_sz, uint64_t seconds);
int log_progress_percent_milestone(int percent);
uint64_t log_progress_byte_milestone(uint64_t transferred,
				     uint64_t interval_bytes);
bool log_progress_should_emit(int64_t now_ms, int64_t last_emit_ms,
			      int previous_percent, int current_percent,
			      bool completed);
int log_format_progress_line(char *buf, size_t buf_sz, uint64_t transferred,
			     uint64_t total, double bytes_per_sec);

#define LOG(level, fmt, ...)                                                   \
	do {                                                                   \
		if (log_is_enabled(level)) {                                   \
			log_write((level), fmt, ##__VA_ARGS__);                \
		}                                                              \
	} while (0)

#define log_error(fmt, ...) LOG(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) LOG(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) LOG(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) log_error(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) log_warn(fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_info(fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_debug(fmt, ##__VA_ARGS__)

#endif // OTA_FETCH_LOG_H
