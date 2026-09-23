// SPDX-License-Identifier: GPL-2.0
/*
 * tauth_test — torn-write recovery for the TCP authority ledger shadow-page
 * store (docs/tcp-authority-ledger.md step 2: "write copy A, kill, verify B
 * wins").  Runs against a temp file through the usermode PAL, i.e. the SAME
 * dlm/tauth_store.c the kernel module links.
 *
 * Cases (every one is an assertion; the process exits non-zero on the first
 * failure and prints a RESULT line per case):
 *   1 format      a freshly formatted region opens, verify = all pages
 *                 exactly one valid copy (A), zero unknown.
 *   2 rmw         write page P twice: seq 1 -> 2 -> 3, copies alternate
 *                 (B, then A), read returns the newest, the other copy still
 *                 validates (never overwrite the only valid copy).
 *   3 torn        write page P with torn_after_bytes=1024 (partial image,
 *                 no flush): the call fails, read STILL returns the previous
 *                 committed image, and the torn copy is not valid.  Then a
 *                 normal write repairs it on that very copy.
 *   4 corrupt-1   flip one byte in the winning copy: read falls back to the
 *                 other copy's older seq (not an error).
 *   5 corrupt-2   destroy both copies: read = -EUCLEAN (UNKNOWN), verify
 *                 reports none=1 and returns -EUCLEAN; a write with the
 *                 caller's content repairs it (repairs counter = 1).
 *   6 identity    a page rewritten with a different fs_gen does not validate
 *                 for this fs (foreign page = not valid, fail closed).
 *   7 ids         seq never regresses across 200 writes on one page; the
 *                 winning copy carries the highest seq.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dlm/tauth_store.h"

static const char *path;
static int fails;

#define CHECK(cond, ...) do { if (cond) { printf("  PASS " __VA_ARGS__); printf("\n"); } \
    else { printf("  FAIL " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t crc(uint32_t s, const void *d, size_t n) { return mxfs_pal_crc32c(s, d, n); }

static void raw_write(uint64_t off, const void *buf, size_t len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0 || pwrite(fd, buf, len, off) != (ssize_t)len) { perror("raw_write"); exit(2); }
    fsync(fd); close(fd);
}

static void raw_read(uint64_t off, void *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0 || pread(fd, buf, len, off) != (ssize_t)len) { perror("raw_read"); exit(2); }
    close(fd);
}

/* mkfs's format, reproduced here byte-for-byte from the shared helpers */
static void format_region(uint64_t base, const uint8_t uuid[16])
{
    struct mxfs_tauth_region_hdr *rh = calloc(1, sizeof(*rh));
    struct mxfs_tauth_page *pg = calloc(1, sizeof(*pg));
    uint32_t fs_gen = mxfs_tauth_fs_gen(uuid);
    uint32_t p;
    int fd = open(path, O_WRONLY);

    if (fd < 0 || ftruncate(fd, base + MXFS_TAUTH_REGION_BYTES) < 0) { perror("truncate"); exit(2); }
    close(fd);
    mxfs_tauth_region_init(rh, fs_gen, uuid, MXFS_TAUTH_NPAGES, 0x5eed0000c0ffee11ULL, 1000, crc);
    raw_write(base + mxfs_tauth_hdr_off(0), rh, sizeof(*rh));
    for (p = 0; p < MXFS_TAUTH_NPAGES; p++) {
        mxfs_tauth_page_init_empty(pg, p, fs_gen, uuid, 1, 1000, crc);
        raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, p, 0), pg, sizeof(*pg));
    }
    free(rh); free(pg);
}

int main(int argc, char **argv)
{
    static const uint8_t uuid[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static const uint8_t uuid2[16] = {9,9,9,9,5,6,7,8,9,10,11,12,13,14,15,16};
    const uint64_t base = 65536;   /* pretend envelope offset */
    struct mxfs_tauth_store s;
    struct mxfs_tauth_page *pg = calloc(1, sizeof(*pg)), *raw = calloc(1, sizeof(*raw));
    mxfs_bdev_t *dev;
    uint32_t two, one, none, P = 1234, fs_gen = mxfs_tauth_fs_gen(uuid);
    int rc, copy, i;
    char tmpl[] = "/tmp/tauth_test_XXXXXX";

    (void)argc; (void)argv;
    int tfd = mkstemp(tmpl);
    if (tfd < 0) { perror("mkstemp"); return 2; }
    close(tfd);
    path = tmpl;
    printf("=== tauth_test file=%s npages=%u region=%llu bytes ===\n", path,
           MXFS_TAUTH_NPAGES, (unsigned long long)MXFS_TAUTH_REGION_BYTES);

    /* 1 format */
    format_region(base, uuid);
    dev = mxfs_pal_bdev_open(path);
    if (!dev) { perror("bdev_open"); return 2; }
    rc = mxfs_tauth_store_open(&s, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 7, 0x1234);
    CHECK(rc == 0, "1 open after format rc=%d", rc);
    rc = mxfs_tauth_store_verify(&s, &two, &one, &none);
    CHECK(rc == 0 && one == MXFS_TAUTH_NPAGES && two == 0 && none == 0,
          "1 verify fresh: rc=%d two=%u one=%u none=%u", rc, two, one, none);
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 0 && pg->hdr.seq == 1 && pg->ent[0].state == MXFS_TAUTH_ST_EMPTY,
          "1 read fresh page: rc=%d copy=%d seq=%llu", rc, copy, (unsigned long long)pg->hdr.seq);

    /* 2 rmw */
    pg->ent[3].state = MXFS_TAUTH_ST_ACTIVE; pg->ent[3].ex_node = 42; pg->ent[3].grant_seq64 = 1;
    rc = mxfs_tauth_page_write(&s, pg, 5, 9, 0);
    CHECK(rc == 0 && pg->hdr.seq == 2, "2 write#1 rc=%d seq=%llu", rc, (unsigned long long)pg->hdr.seq);
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 1 && pg->hdr.seq == 2 && pg->ent[3].ex_node == 42,
          "2 read after write#1: copy=%d seq=%llu owner=%u", copy, (unsigned long long)pg->hdr.seq, pg->ent[3].ex_node);
    raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 0), raw, sizeof(*raw));
    CHECK(mxfs_tauth_page_valid(raw, P, fs_gen, crc) && raw->hdr.seq == 1,
          "2 copy A untouched (seq 1 still valid)");
    pg->ent[3].grant_seq64 = 2;
    rc = mxfs_tauth_page_write(&s, pg, 5, 9, 0);
    rc |= mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 0 && pg->hdr.seq == 3 && pg->ent[3].grant_seq64 == 2,
          "2 write#2 alternated to copy A: copy=%d seq=%llu", copy, (unsigned long long)pg->hdr.seq);
    raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 1), raw, sizeof(*raw));
    CHECK(mxfs_tauth_page_valid(raw, P, fs_gen, crc) && raw->hdr.seq == 2, "2 copy B still valid (seq 2)");

    /* 3 torn — the changed bytes (entry 20, offset 2688) lie BEYOND the
     * 1024-byte tear, so the partial image is header(seq 4)+stale tail:
     * crc must reject it.  (A tear that happens to contain every changed
     * byte is indistinguishable from a complete write, and correctly so.) */
    pg->ent[20].state = MXFS_TAUTH_ST_ACTIVE; pg->ent[20].grant_seq64 = 77;
    rc = mxfs_tauth_page_write(&s, pg, 5, 9, 1024);
    CHECK(rc == -EIO, "3 torn write reports failure rc=%d", rc);
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 0 && pg->hdr.seq == 3 && pg->ent[20].state == MXFS_TAUTH_ST_EMPTY,
          "3 read after torn: previous commit wins (copy=%d seq=%llu ent20.state=%u)", copy,
          (unsigned long long)pg->hdr.seq, pg->ent[20].state);
    raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 1), raw, sizeof(*raw));
    CHECK(!mxfs_tauth_page_valid(raw, P, fs_gen, crc), "3 torn copy B does not validate");
    CHECK(s.torn_seen >= 1, "3 store counted the torn copy (torn_seen=%llu)", (unsigned long long)s.torn_seen);
    pg->ent[3].grant_seq64 = 3;
    rc = mxfs_tauth_page_write(&s, pg, 5, 9, 0);
    rc |= mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 1 && pg->hdr.seq == 4 && pg->ent[3].grant_seq64 == 3,
          "3 repair: next write lands on the torn copy B (copy=%d seq=%llu)", copy, (unsigned long long)pg->hdr.seq);

    /* 4 corrupt one byte of the winner (B, seq 4) */
    raw_read(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 1), raw, sizeof(*raw));
    ((uint8_t *)raw)[2000] ^= 0xff;
    raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 1), raw, sizeof(*raw));
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && copy == 0 && pg->hdr.seq == 3, "4 bit-flip in winner: fallback to copy A seq=%llu", (unsigned long long)pg->hdr.seq);

    /* 5 destroy both */
    memset(raw, 0, sizeof(*raw));
    raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 0), raw, sizeof(*raw));
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == -EUCLEAN, "5 both copies invalid: read = -EUCLEAN (UNKNOWN) rc=%d", rc);
    rc = mxfs_tauth_store_verify(&s, &two, &one, &none);
    CHECK(rc == -EUCLEAN && none == 1, "5 verify: rc=%d none=%u", rc, none);
    memset(pg, 0, sizeof(*pg)); pg->hdr.page_id = P;
    for (i = 0; i < (int)MXFS_TAUTH_ENTRIES_PER_PAGE; i++) pg->ent[i].state = MXFS_TAUTH_ST_UNKNOWN;
    rc = mxfs_tauth_page_write(&s, pg, 5, 9, 0);
    rc |= mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && pg->hdr.seq == 1 && pg->ent[0].state == MXFS_TAUTH_ST_UNKNOWN && s.repairs == 1,
          "5 repair write with caller content: seq=%llu repairs=%llu", (unsigned long long)pg->hdr.seq, (unsigned long long)s.repairs);
    rc = mxfs_tauth_store_verify(&s, &two, &one, &none);
    CHECK(rc == 0 && none == 0, "5 verify after repair: rc=%d none=%u", rc, none);

    /* 6 foreign identity */
    mxfs_tauth_page_init_empty(raw, P, mxfs_tauth_fs_gen(uuid2), uuid2, 99, 1000, crc);
    raw_write(base + mxfs_tauth_page_off(MXFS_TAUTH_NPAGES, P, 1), raw, sizeof(*raw));
    rc = mxfs_tauth_page_read(&s, P, pg, &copy);
    CHECK(rc == 0 && pg->hdr.seq == 1 && copy == 0, "6 foreign-fs page (seq 99) ignored: seq=%llu copy=%d", (unsigned long long)pg->hdr.seq, copy);

    /* 7 monotonic */
    {
        uint64_t last = pg->hdr.seq;
        int ok = 1;
        for (i = 0; i < 200 && ok; i++) {
            pg->ent[1].grant_seq64 = i;
            if (mxfs_tauth_page_write(&s, pg, 5, 9, 0) || mxfs_tauth_page_read(&s, P, pg, &copy) ||
                pg->hdr.seq != last + 1 || pg->ent[1].grant_seq64 != (uint64_t)i)
                ok = 0;
            last = pg->hdr.seq;
        }
        CHECK(ok && last == 201, "7 200 writes: seq monotonic, final=%llu", (unsigned long long)last);
    }
    /* region header: spare copy B invalid + copy A valid => open works; both zero => open fails */
    memset(raw, 0, sizeof(*raw));
    raw_write(base + mxfs_tauth_hdr_off(0), raw, MXFS_TAUTH_PAGE_BYTES);
    rc = mxfs_tauth_store_open(&s, dev, base, MXFS_TAUTH_REGION_BYTES, uuid, 7, 0x1234);
    CHECK(rc == -EUCLEAN, "8 no valid region header: open = -EUCLEAN rc=%d", rc);

    mxfs_pal_bdev_close(dev);
    unlink(path);
    printf("=== tauth_test: fails=%d ===\n", fails);
    return fails ? 1 : 0;
}
