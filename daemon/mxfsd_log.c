/*
 * MXFS — Multinode XFS
 * Logging infrastructure
 *
 * Supports simultaneous output to a log file and syslog.
 * Thread-safe via internal mutex.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "mxfsd_log.h"

static FILE            *log_fp;
static int              log_level = LOG_INFO;
static bool             log_syslog;
static pthread_mutex_t  log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool             log_initialized;

static const char *level_str(int level)
{
	switch (level) {
	case LOG_ERR:     return "ERROR";
	case LOG_WARNING: return "WARN";
	case LOG_NOTICE:  return "NOTICE";
	case LOG_INFO:    return "INFO";
	case LOG_DEBUG:   return "DEBUG";
	default:          return "???";
	}
}

int mxfsd_log_init(const char *log_file, int level, bool use_syslog)
{
	pthread_mutex_lock(&log_mutex);

	if (log_initialized) {
		pthread_mutex_unlock(&log_mutex);
		return 0;
	}

	log_level = level;
	log_syslog = use_syslog;
	log_fp = NULL;

	if (log_file && log_file[0]) {
		log_fp = fopen(log_file, "a");
		if (!log_fp) {
			int saved = errno;
			pthread_mutex_unlock(&log_mutex);
			fprintf(stderr, "mxfsd: cannot open log file '%s': %s\n",
				log_file, strerror(saved));
			return -saved;
		}
		/* line-buffer so log lines appear promptly */
		setvbuf(log_fp, NULL, _IOLBF, 0);
	}

	if (log_syslog)
		openlog("mxfsd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	log_initialized = true;
	pthread_mutex_unlock(&log_mutex);
	return 0;
}

void mxfsd_log_shutdown(void)
{
	pthread_mutex_lock(&log_mutex);

	if (!log_initialized) {
		pthread_mutex_unlock(&log_mutex);
		return;
	}

	if (log_fp) {
		fclose(log_fp);
		log_fp = NULL;
	}

	if (log_syslog)
		closelog();

	log_initialized = false;
	pthread_mutex_unlock(&log_mutex);
}

void mxfsd_log_set_level(int level)
{
	pthread_mutex_lock(&log_mutex);
	log_level = level;
	pthread_mutex_unlock(&log_mutex);
}

void mxfsd_log(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > log_level)
		return;

	pthread_mutex_lock(&log_mutex);

	/* File output */
	if (log_fp) {
		struct timespec ts;
		struct tm tm;

		clock_gettime(CLOCK_REALTIME, &ts);
		localtime_r(&ts.tv_sec, &tm);

		fprintf(log_fp, "%04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			ts.tv_nsec / 1000000,
			level_str(level));

		va_start(ap, fmt);
		vfprintf(log_fp, fmt, ap);
		va_end(ap);

		fputc('\n', log_fp);
	}

	/* Syslog output */
	if (log_syslog) {
		va_start(ap, fmt);
		vsyslog(level, fmt, ap);
		va_end(ap);
	}

	/* Before init (or no outputs), write to stderr */
	if (!log_fp && !log_syslog) {
		fprintf(stderr, "[%s] ", level_str(level));
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputc('\n', stderr);
	}

	pthread_mutex_unlock(&log_mutex);
}
