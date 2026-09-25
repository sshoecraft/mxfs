/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared helpers for the tauth usermode tests: a temp-file "device", raw
 * platter access behind the PAL's back, and mkfs's region format reproduced
 * byte-for-byte from the shared layout helpers (mxfs_tauth.h).
 */
#ifndef MXFS_TAUTH_TESTLIB_H
#define MXFS_TAUTH_TESTLIB_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dlm/tauth_store.h"

static const char *tl_path;
static int tl_fails;

#define CHECK(cond, ...) do { if (cond) { printf("  PASS " __VA_ARGS__); printf("\n"); } \
    else { printf("  FAIL " __VA_ARGS__); printf("\n"); tl_fails++; } } while (0)

static uint32_t tl_crc(uint32_t s, const void *d, size_t n) { return mxfs_pal_crc32c(s, d, n); }

static void raw_write(uint64_t off, const void *buf, size_t len)
{
    int fd = open(tl_path, O_WRONLY);
    if (fd < 0 || pwrite(fd, buf, len, off) != (ssize_t)len) { perror("raw_write"); exit(2); }
    fsync(fd); close(fd);
}

static inline void raw_read(uint64_t off, void *buf, size_t len)
{
    int fd = open(tl_path, O_RDONLY);
    if (fd < 0 || pread(fd, buf, len, off) != (ssize_t)len) { perror("raw_read"); exit(2); }
    close(fd);
}

/* sess427 (D-0348 step 2): every usermode region is formatted with the
 * MINIMUM geometry and this fixed seed, so a test can route a resource
 * without an open ledger (tl_page / tl_home == the ledger's own routing). */
#define TL_SEED 0x5eed0000c0ffee11ULL
static inline uint32_t tl_hash(const struct mxfs_resource_id *r)
{
    return mxfs_tauth_res_hash(r, sizeof(*r), TL_SEED);
}
static inline uint32_t tl_page(const struct mxfs_resource_id *r)
{
    return mxfs_tauth_home_page(tl_hash(r), MXFS_TAUTH_NPAGES);
}
static inline uint32_t tl_home(const struct mxfs_resource_id *r)
{
    return mxfs_tauth_home_index(tl_hash(r), MXFS_TAUTH_NPAGES);
}

/* mkfs's format, reproduced here byte-for-byte from the shared helpers */
static void format_region(uint64_t base, const uint8_t uuid[16])
{
    struct mxfs_tauth_region_hdr *rh = calloc(1, sizeof(*rh));
    struct mxfs_tauth_page *pg = calloc(1, sizeof(*pg));
    uint32_t fs_gen = mxfs_tauth_fs_gen(uuid);
    uint32_t p;
    int fd = open(tl_path, O_WRONLY);

    if (fd < 0 || ftruncate(fd, base + MXFS_TAUTH_REGION_BYTES) < 0) { perror("truncate"); exit(2); }
    close(fd);
    mxfs_tauth_region_init(rh, fs_gen, uuid, MXFS_TAUTH_NPAGES, TL_SEED, 1000, tl_crc);
    raw_write(base + mxfs_tauth_hdr_off(0), rh, sizeof(*rh));
    for (p = 0; p < MXFS_TAUTH_NPAGES; p++) {
        mxfs_tauth_page_init_empty(pg, p, fs_gen, uuid, 1, 1000, tl_crc);
        raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, p, 0), pg, sizeof(*pg));
    }
    free(rh); free(pg);
}

/* Create the temp file and return its path (static storage). */
static const char *tl_mktemp(const char *tag)
{
    static char tmpl[64];

    snprintf(tmpl, sizeof(tmpl), "/tmp/%s_XXXXXX", tag);
    int tfd = mkstemp(tmpl);
    if (tfd < 0) { perror("mkstemp"); exit(2); }
    close(tfd);
    tl_path = tmpl;
    return tmpl;
}

#endif /* MXFS_TAUTH_TESTLIB_H */
