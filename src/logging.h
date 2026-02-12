// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file logging.h
 * @brief Simple embedded logging macros and helpers.
 *
 * Provides compile-time configurable logging levels and convenience macros for
 * standardized error, warning, info, and debug output. Designed to be minimal,
 * portable, and friendly to embedded and Linux systems.
 *
 * @author Dustin Hoskins
 * @date 2025
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/**
 * @defgroup logging Logging
 * @brief Minimal logging macros with compile-time log levels.
 * @{
 */

/**
 * @def LOG_LEVEL_NONE
 * @brief Logging level: disables all logging.
 */
#define LOG_LEVEL_NONE 0

/**
 * @def LOG_LEVEL_ERROR
 * @brief Logging level: errors only.
 */
#define LOG_LEVEL_ERROR 1

/**
 * @def LOG_LEVEL_WARN
 * @brief Logging level: warnings and above.
 */
#define LOG_LEVEL_WARN 2

/**
 * @def LOG_LEVEL_INFO
 * @brief Logging level: info, warnings, and errors.
 */
#define LOG_LEVEL_INFO 3

/**
 * @def LOG_LEVEL_DEBUG
 * @brief Logging level: all log output, including debug.
 */
#define LOG_LEVEL_DEBUG 4

/**
 * @def LOG_LEVEL
 * @brief Default compile-time log level (change with -DLOG_LEVEL=...).
 */
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

/**
 * @brief Convert a numeric log level to its string label.
 *
 * @param level Integer log level (LOG_LEVEL_ERROR, etc).
 * @return Pointer to static string ("ERROR", "WARN", "INFO", "DEBUG", "LOG").
 */
static inline const char *log_level_str(int level) {
	switch (level) {
	case LOG_LEVEL_ERROR:
		return "ERROR";
	case LOG_LEVEL_WARN:
		return "WARN";
	case LOG_LEVEL_INFO:
		return "INFO";
	case LOG_LEVEL_DEBUG:
		return "DEBUG";
	default:
		return "LOG";
	}
}

/**
 * @brief Returns pointer to the base filename within a path (no allocations).
 *
 * Cross-platform: supports '/' (POSIX) and '\\' (Windows).
 *
 * @param path Full file path string.
 * @return Pointer to filename component.
 */
static inline const char *basename_c(const char *path) {
	const char *slash = strrchr(path, '/');
#ifdef _WIN32
	const char *backslash = strrchr(path, '\\');
	if (!slash || (backslash && backslash > slash))
		slash = backslash;
#endif
	return slash ? slash + 1 : path;
}

/**
 * @def LOG(level, fmt, ...)
 * @brief Core logging macro for custom log levels.
 *
 * Prints standardized log output to stderr and an optional log file with
 * source file, line, and function.
 *
 * Example:
 *   LOG(LOG_LEVEL_INFO, "Initialization complete: status=%d", status);
 *
 * @param level Log level constant (LOG_LEVEL_INFO, etc).
 * @param fmt   printf-style format string.
 * @param ...   Additional arguments for format string.
 */
void log_write(int level, const char *file, int line, const char *func,
	       const char *fmt, ...);
int log_set_file(const char *path);
void log_close(void);

#define LOG(level, fmt, ...)                                                   \
	do {                                                                   \
		if ((level) <= LOG_LEVEL) {                                    \
			log_write((level), __FILE__, __LINE__, __func__,       \
				  fmt, ##__VA_ARGS__);                       \
		}                                                              \
	} while (0)

/**
 * @def LOG_ERROR(fmt, ...)
 * @brief Convenience macro for logging errors.
 *
 * @param fmt printf-style format string.
 * @param ... Additional arguments.
 */
#define LOG_ERROR(fmt, ...) LOG(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

/**
 * @def LOG_WARN(fmt, ...)
 * @brief Convenience macro for logging warnings.
 *
 * @param fmt printf-style format string.
 * @param ... Additional arguments.
 */
#define LOG_WARN(fmt, ...) LOG(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)

/**
 * @def LOG_INFO(fmt, ...)
 * @brief Convenience macro for logging informational messages.
 *
 * @param fmt printf-style format string.
 * @param ... Additional arguments.
 */
#define LOG_INFO(fmt, ...) LOG(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)

/**
 * @def LOG_DEBUG(fmt, ...)
 * @brief Convenience macro for logging debug messages.
 *
 * @param fmt printf-style format string.
 * @param ... Additional arguments.
 */
#define LOG_DEBUG(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

/** @} */

#endif // LOGGING_H
