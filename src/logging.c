// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file logging.c
 * @brief Logging implementation with optional file tee.
 */

#include "logging.h"
#include <errno.h>

static FILE *log_fp = NULL;

/* ------------------------------------------------------------------------ */
static void log_write_line(FILE *out, int level, const char *file, int line,
			   const char *func, const char *fmt, va_list args) {
	fprintf(out, "[%s] %s:%d:%s(): ", log_level_str(level),
		basename_c(file), line, func);
	vfprintf(out, fmt, args);
	fputc('\n', out);
}

/* ------------------------------------------------------------------------ */
int log_set_file(const char *path) {
	if (!path || path[0] == '\0')
		return 0;

	FILE *fp = fopen(path, "a");
	if (!fp) {
		fprintf(stderr, "Warning: Failed to open log_file %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	if (log_fp && log_fp != fp)
		fclose(log_fp);

	log_fp = fp;
	setvbuf(log_fp, NULL, _IOLBF, 0);
	return 0;
}

/* ------------------------------------------------------------------------ */
void log_close(void) {
	if (!log_fp)
		return;
	fclose(log_fp);
	log_fp = NULL;
}
/* ------------------------------------------------------------------------ */

void log_write(int level, const char *file, int line, const char *func,
	       const char *fmt, ...) {
	va_list args;
	va_list args_copy;

	va_start(args, fmt);
	va_copy(args_copy, args);
	log_write_line(stderr, level, file, line, func, fmt, args);
	if (log_fp)
		log_write_line(log_fp, level, file, line, func, fmt, args_copy);
	va_end(args_copy);
	va_end(args);
}
