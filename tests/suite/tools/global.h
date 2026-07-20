/* shim global.h for standalone fsx build (xfstests fsx.c).
 * Built ONCE on clyde; binary lives on NFS (/src/mxfs/...) for all VMs.
 * Host and VMs are identical (Ubuntu 24.04, kernel 6.8, same glibc). */
#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <assert.h>
#include <stdint.h>
#include <linux/falloc.h>
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef roundup
#define roundup(x,y) ((((x) + ((y) - 1)) / (y)) * (y))
#endif
#ifndef FALLOC_FL_WRITE_ZEROES
#define FALLOC_FL_WRITE_ZEROES 0x80
#endif
static inline uint64_t roundup_64(uint64_t x, uint64_t y)   { return y ? ((x + y - 1) / y) * y : x; }
static inline uint64_t rounddown_64(uint64_t x, uint64_t y) { return y ? (x / y) * y : x; }
