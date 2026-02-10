/*
 * MXFS — Multinode XFS
 * Logging infrastructure
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFSD_LOG_H
#define MXFSD_LOG_H

#include <syslog.h>
#include <stdbool.h>

/* Log levels map directly to syslog levels:
 *   LOG_ERR     = 3
 *   LOG_WARNING = 4
 *   LOG_NOTICE  = 5
 *   LOG_INFO    = 6
 *   LOG_DEBUG   = 7
 */

int  mxfsd_log_init(const char *log_file, int level, bool use_syslog);
void mxfsd_log_shutdown(void);
void mxfsd_log_set_level(int level);

void mxfsd_log(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* Convenience macros */
#define mxfsd_err(fmt, ...)     mxfsd_log(LOG_ERR,     fmt, ##__VA_ARGS__)
#define mxfsd_warn(fmt, ...)    mxfsd_log(LOG_WARNING,  fmt, ##__VA_ARGS__)
#define mxfsd_notice(fmt, ...)  mxfsd_log(LOG_NOTICE,   fmt, ##__VA_ARGS__)
#define mxfsd_info(fmt, ...)    mxfsd_log(LOG_INFO,     fmt, ##__VA_ARGS__)
#define mxfsd_dbg(fmt, ...)     mxfsd_log(LOG_DEBUG,    fmt, ##__VA_ARGS__)

#endif /* MXFSD_LOG_H */
