// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 KERNEL FORGE LLC
/**
 * @file log.c
 * @brief Logging implementation with stderr progress coordination.
 */

#include "log.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_PROGRESS_PERCENT_INTERVAL_MS 200
#define LOG_PROGRESS_FORCE_INTERVAL_MS 500

static FILE *g_log_fp = NULL;
static int g_log_level = LOG_LEVEL;
static int g_stderr_is_tty = -1;
static int g_progress_active = 0;
static size_t g_progress_width = 0;

static bool log_stderr_is_tty(void) {
	if (g_stderr_is_tty < 0) {
		g_stderr_is_tty = isatty(fileno(stderr)) ? 1 : 0;
	}
	return g_stderr_is_tty == 1;
}

static void log_render_line(FILE *out, const char *label, const char *message) {
	fprintf(out, "[%s] %s\n", label, message);
	fflush(out);
}

static void log_reset_progress_state(void) {
	g_progress_active = 0;
	g_progress_width = 0;
}

static void log_render_progress(const char *message, bool final_line) {
	size_t printed_width;

	if (!message || !log_stderr_is_tty() ||
	    !log_is_enabled(LOG_LEVEL_INFO)) {
		return;
	}

	printed_width = (size_t)fprintf(stderr, "\r[PROGRESS] %s", message);
	if (g_progress_active && printed_width < g_progress_width) {
		size_t padding = g_progress_width - printed_width;
		while (padding-- > 0) {
			fputc(' ', stderr);
		}
	}

	fflush(stderr);

	if (final_line) {
		fputc('\n', stderr);
		fflush(stderr);
		log_reset_progress_state();
		return;
	}

	g_progress_active = 1;
	g_progress_width = printed_width;
}

const char *log_level_str(int level) {
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

const char *log_basename(const char *path) {
	const char *slash = NULL;

	if (!path) {
		return "";
	}

	slash = strrchr(path, '/');
#ifdef _WIN32
	{
		const char *backslash = strrchr(path, '\\');
		if (!slash || (backslash && backslash > slash)) {
			slash = backslash;
		}
	}
#endif
	return slash ? slash + 1 : path;
}

void log_set_level(int level) {
	if (level < LOG_LEVEL_NONE) {
		level = LOG_LEVEL_NONE;
	} else if (level > LOG_LEVEL_DEBUG) {
		level = LOG_LEVEL_DEBUG;
	}

	g_log_level = level;
}

int log_get_level(void) { return g_log_level; }

bool log_is_enabled(int level) {
	if (level <= LOG_LEVEL_NONE) {
		return false;
	}

	return level <= g_log_level;
}

void log_vwrite(int level, const char *fmt, va_list args) {
	char message[1024];

	if (!log_is_enabled(level) || !fmt) {
		return;
	}

	if (g_progress_active) {
		log_progress_clear();
	}

	vsnprintf(message, sizeof(message), fmt, args);
	log_render_line(stderr, log_level_str(level), message);

	if (g_log_fp) {
		log_render_line(g_log_fp, log_level_str(level), message);
	}
}

void log_write(int level, const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	log_vwrite(level, fmt, args);
	va_end(args);
}

int log_set_file(const char *path) {
	FILE *fp = NULL;

	if (!path || path[0] == '\0') {
		return 0;
	}

	fp = fopen(path, "a");
	if (!fp) {
		log_warn("Failed to open log file %s: %s", path,
			 strerror(errno));
		return -1;
	}

	if (g_log_fp && g_log_fp != fp) {
		fclose(g_log_fp);
	}

	g_log_fp = fp;
	setvbuf(g_log_fp, NULL, _IOLBF, 0);
	return 0;
}

void log_close(void) {
	log_progress_clear();

	if (!g_log_fp) {
		return;
	}

	fclose(g_log_fp);
	g_log_fp = NULL;
}

bool log_progress_enabled(void) {
	return log_is_enabled(LOG_LEVEL_INFO) && log_stderr_is_tty();
}

void log_progress_update(const char *message) {
	log_render_progress(message, false);
}

void log_progress_finish(const char *message) {
	log_render_progress(message, true);
}

void log_progress_clear(void) {
	size_t padding;

	if (!g_progress_active || !log_stderr_is_tty()) {
		log_reset_progress_state();
		return;
	}

	fputc('\r', stderr);
	padding = g_progress_width;
	while (padding-- > 0) {
		fputc(' ', stderr);
	}
	fputc('\r', stderr);
	fflush(stderr);
	log_reset_progress_state();
}

int log_format_bytes(char *buf, size_t buf_sz, uint64_t bytes) {
	static const char *const units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
	double value = (double)bytes;
	size_t unit_index = 0;

	if (!buf || buf_sz == 0) {
		return -1;
	}

	while (value >= 1024.0 &&
	       unit_index + 1 < sizeof(units) / sizeof(units[0])) {
		value /= 1024.0;
		unit_index++;
	}

	if (unit_index == 0) {
		return snprintf(buf, buf_sz, "%" PRIu64 " %s", bytes,
				units[unit_index]);
	}

	return snprintf(buf, buf_sz, "%.1f %s", value, units[unit_index]);
}

int log_format_eta(char *buf, size_t buf_sz, uint64_t seconds) {
	uint64_t hours;
	uint64_t minutes;
	uint64_t secs;

	if (!buf || buf_sz == 0) {
		return -1;
	}

	hours = seconds / 3600u;
	minutes = (seconds % 3600u) / 60u;
	secs = seconds % 60u;

	if (hours > 0) {
		return snprintf(buf, buf_sz,
				"%02" PRIu64 ":%02" PRIu64 ":%02" PRIu64, hours,
				minutes, secs);
	}

	return snprintf(buf, buf_sz, "%02" PRIu64 ":%02" PRIu64, minutes, secs);
}

bool log_progress_should_emit(int64_t now_ms, int64_t last_emit_ms,
			      int previous_percent, int current_percent,
			      bool completed) {
	int64_t elapsed_ms;

	if (completed) {
		return true;
	}

	if (last_emit_ms < 0) {
		return true;
	}

	elapsed_ms = now_ms - last_emit_ms;
	if (elapsed_ms >= LOG_PROGRESS_FORCE_INTERVAL_MS) {
		return true;
	}

	if (current_percent >= 0 && current_percent != previous_percent &&
	    elapsed_ms >= LOG_PROGRESS_PERCENT_INTERVAL_MS) {
		return true;
	}

	return false;
}

int log_format_progress_line(char *buf, size_t buf_sz, uint64_t transferred,
			     uint64_t total, double bytes_per_sec) {
	char transferred_buf[32];
	char total_buf[32];
	char speed_buf[32];
	char eta_buf[16];
	int percent = -1;
	int written;

	if (!buf || buf_sz == 0) {
		return -1;
	}

	if (total > 0 && transferred > total) {
		transferred = total;
	}

	if (log_format_bytes(transferred_buf, sizeof(transferred_buf),
			     transferred) < 0) {
		return -1;
	}

	if (bytes_per_sec > 0.0) {
		uint64_t rounded_speed = (uint64_t)(bytes_per_sec + 0.5);
		if (log_format_bytes(speed_buf, sizeof(speed_buf),
				     rounded_speed) < 0) {
			return -1;
		}
	} else {
		speed_buf[0] = '\0';
	}

	if (total > 0) {
		uint64_t eta_seconds = 0;

		percent = (int)((transferred * 100u) / total);
		if (percent > 100) {
			percent = 100;
		}

		if (log_format_bytes(total_buf, sizeof(total_buf), total) < 0) {
			return -1;
		}

		if (bytes_per_sec > 0.0 && transferred < total) {
			double remaining = (double)(total - transferred);
			eta_seconds = (uint64_t)(remaining / bytes_per_sec);
			if (log_format_eta(eta_buf, sizeof(eta_buf),
					   eta_seconds) < 0) {
				return -1;
			}
			written = snprintf(buf, buf_sz,
					   "%d%%  %s / %s  %s/s  ETA %s",
					   percent, transferred_buf, total_buf,
					   speed_buf, eta_buf);
		} else if (bytes_per_sec > 0.0) {
			written = snprintf(buf, buf_sz, "%d%%  %s / %s  %s/s",
					   percent, transferred_buf, total_buf,
					   speed_buf);
		} else {
			written = snprintf(buf, buf_sz, "%d%%  %s / %s",
					   percent, transferred_buf, total_buf);
		}
	} else if (bytes_per_sec > 0.0) {
		written = snprintf(buf, buf_sz, "%s downloaded  %s/s",
				   transferred_buf, speed_buf);
	} else {
		written = snprintf(buf, buf_sz, "%s downloaded",
				   transferred_buf);
	}

	if (written < 0 || (size_t)written >= buf_sz) {
		return -1;
	}

	return 0;
}
