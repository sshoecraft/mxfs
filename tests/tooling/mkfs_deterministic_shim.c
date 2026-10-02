/*
 * mkfs_deterministic_shim.c — LD_PRELOAD shim that makes a format repeatable,
 * so two builds of tools/mkfs_mxfs can be proven to write byte-identical
 * devices.
 *
 * WHY.  mkfs_mxfs draws its UUIDs and hash seed from /dev/urandom and stamps
 * records with time(NULL), so no two formats match byte for byte.  A change
 * that is meant to alter only HOW mkfs writes (batching, chunk size) and never
 * WHAT it writes can only be proven by formatting the same device twice with
 * the same inputs and comparing every byte.
 *
 * MXFS_SHIM_RAND=<file>  open("/dev/urandom") opens this file instead (give it
 *                        more bytes than one format reads).
 * MXFS_SHIM_TIME=<secs>  time() returns this.
 *
 * Build: cc -shared -fPIC -O2 -o <out>.so tests/tooling/mkfs_deterministic_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *redirect(const char *path)
{
	const char *r = getenv("MXFS_SHIM_RAND");

	if (r && path && strcmp(path, "/dev/urandom") == 0)
		return r;
	return path;
}

int open(const char *path, int flags, ...)
{
	static int (*real_open)(const char *, int, ...);
	mode_t mode = 0;

	if (!real_open)
		real_open = dlsym(RTLD_NEXT, "open");
	if (flags & O_CREAT) {
		va_list ap;

		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_open(redirect(path), flags, mode);
}

int open64(const char *path, int flags, ...)
{
	static int (*real_open64)(const char *, int, ...);
	mode_t mode = 0;

	if (!real_open64)
		real_open64 = dlsym(RTLD_NEXT, "open64");
	if (flags & O_CREAT) {
		va_list ap;

		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_open64(redirect(path), flags, mode);
}

time_t time(time_t *t)
{
	const char *s = getenv("MXFS_SHIM_TIME");
	time_t v;

	if (!s) {
		static time_t (*real_time)(time_t *);

		if (!real_time)
			real_time = dlsym(RTLD_NEXT, "time");
		return real_time(t);
	}
	v = (time_t)strtoll(s, NULL, 10);
	if (t)
		*t = v;
	return v;
}
