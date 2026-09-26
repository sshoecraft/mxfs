/*
 * chk_mxfs — Validate an MXFS-formatted block device
 *
 * Checks:
 *   1. MXFS on-disk superblock (first 4KB)
 *   2. Journal region (super + per-slot headers)
 *   3. Disklock region (heartbeat slots)
 *   4. XFS structures (superblock, per-AG AGF/AGI)
 *   5. Free space btrees (BNO/CNT per AG)
 *   6. Inode btrees (inobt/finobt per AG)
 *   7. Inode spot-check (root dir + sample allocated inodes)
 *   8. Summary report with cross-checks
 *
 * Usage: chk_mxfs [-v] [-a|-p|-y|-n] /dev/sdX
 *
 * Modes:
 *   -n   Check only, no modifications (default for chk_mxfs)
 *   -a   Auto-repair safe fixes (default for fsck.mxfs)
 *   -p   Same as -a (preen mode, used by boot scripts)
 *   -y   Repair all, answer yes to everything
 *
 * Returns (fsck-compatible exit codes):
 *   0  Filesystem clean, no errors
 *   1  Errors found and corrected
 *   2  Usage error
 *   4  Errors found but NOT corrected (check-only or unfixable)
 *
 * Standalone — no libmxfs linkage. Uses POSIX pread() directly.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>
#include <scsi/sg.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>

#include <mxfs/mxfs_super.h>
#include <mxfs/mxfs_dirshard.h>  /* dirshard gates + manifest check */
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_tauth.h>     /* TCP authority ledger region */
#include "mxfs_offline.h"         /* proving no node can write the device */

/* ─── Version ─── */

#define STRINGIFY2(x) #x
#define STRINGIFY(x)  STRINGIFY2(x)
#define CHK_MXFS_VERSION  STRINGIFY(MXFS_VERSION_MAJOR) "." \
                          STRINGIFY(MXFS_VERSION_MINOR) "." \
                          STRINGIFY(MXFS_VERSION_PATCH)

/* ─── Constants from libmxfs headers (duplicated to stay standalone) ─── */

/* Journal layout (from journal.h) */
#define MXFS_JOURNAL_MAGIC              0x4D584A4C  /* "MXJL" */
#define MXFS_JOURNAL_VERSION            1
#define MXFS_JOURNAL_SECTOR_SIZE        512
#define MXFS_JOURNAL_SLOT_SIZE_SECTORS  2048        /* 1 MB per slot */
#define MXFS_JOURNAL_SLOT_FLAG_CLEAN    0x00
#define MXFS_JOURNAL_SLOT_FLAG_DIRTY    0x01

/* Disklock layout (from disklock.h) */
#define MXFS_DISKLOCK_RECORD_SIZE       512
#define MXFS_DISKLOCK_HB_SLOTS          64
#define MXFS_DISKLOCK_HB_SIZE           (MXFS_DISKLOCK_HB_SLOTS * \
                                         MXFS_DISKLOCK_RECORD_SIZE)
#define MXFS_DISKLOCK_MAGIC             0x4D584C4B  /* "MXLK" */
#define MXFS_DISKLOCK_FLAG_ACTIVE       1

/* MEPOCH record inside each HB slot (from disklock.h, net2 step 5) */
#define MXFS_MEPOCH_OFF                 456         /* 40 hdr + 416 evict */
#define MXFS_MEPOCH_SIZE                44
#define MXFS_MEPOCH_MAGIC_C             0x4F50454D  /* "MEPO" */
#define MXFS_MEPOCH_F_PREPARED_C        0x0001
#define MXFS_MEPOCH_F_VOTERS5_C         0x0002

/* MXFS on-disk constants (XFS-derived structures) */
#define MXFS_SB_MAGIC            0x4D585342  /* "MXSB" */
#define MXFS_AGF_MAGIC           0x4D414746  /* "MAGF" */
#define MXFS_AGI_MAGIC           0x4D414749  /* "MAGI" */
#define MXFS_DINODE_MAGIC        0x4D4E      /* "MN" */

/* V5 CRC btree magic numbers (from kernel xfs_format.h) */
#define MXFS_ABTB_CRC_MAGIC     0x4D413342  /* "MA3B" bnobt */
#define MXFS_ABTC_CRC_MAGIC     0x4D413343  /* "MA3C" cntbt */
#define MXFS_IBT_CRC_MAGIC      0x4D494133  /* "MIA3" inobt */
#define MXFS_FIBT_CRC_MAGIC     0x4D464933  /* "MFI3" finobt */

/* V5 btree short-form block header: 56 bytes
 * [0x00] magic    (be32)
 * [0x04] level    (be16)
 * [0x06] numrecs  (be16)
 * [0x08] leftsib  (be32)
 * [0x0C] rightsib (be32)
 * [0x10] blkno    (be64)  disk address in 512-byte sectors
 * [0x18] lsn      (be64)
 * [0x20] uuid     (16 bytes)
 * [0x30] owner    (be32)
 * [0x34] crc      (le32)
 * [0x38] records start
 */
#define BTREE_SBLOCK_CRC_SIZE  56
#define BTREE_CRC_OFF          0x34
#define BTREE_REC_OFF          0x38

/*
 * Interior (level > 0) short-format btree block: the keys start at
 * BTREE_REC_OFF and the child pointers start after the block's MAXIMUM
 * number of keys, not after the numrecs in use — the kernel's
 * xfs_btree_ptr_offset() is block_len + maxrecs * key_len + (n-1) * ptr_len.
 * Every walker here used BTREE_REC_OFF + numrecs * key_len until 0.89.7,
 * which lands inside the unused key slots (zero on a freshly split node):
 * the child agbno decoded as 0, the walk read the AG's block 0 (the
 * superblock, magic XFSB) and reported it as a corrupt btree block.  It was
 * never hit before because no test filesystem had enough inodes in one AG
 * to push its inobt past one leaf (252 chunk records = 16128 inodes at
 * 4 KiB blocks); measured 0.89.6 s69a, AG 0 with 20224 inodes, root 2179
 * level 1 numrecs 2, keys 128/8832 at byte 56, pointers 3/2178 at byte
 * 2076, zeros at byte 64 where the walk looked.
 *
 * keylen is the key size of that btree: 4 (inobt/finobt: startino) or
 * 8 (bnobt/cntbt: startblock+blockcount); the pointer is always a 4-byte
 * agbno.
 */
static inline uint32_t sbtree_node_maxrecs(uint32_t blocksize, uint32_t keylen)
{
    return (blocksize - BTREE_REC_OFF) / (keylen + 4);
}

static inline uint32_t sbtree_ptr_off(uint32_t blocksize, uint32_t keylen)
{
    return BTREE_REC_OFF + sbtree_node_maxrecs(blocksize, keylen) * keylen;
}

/* XFS dinode format types */
#define XFS_DINODE_FMT_DEV      0
#define XFS_DINODE_FMT_LOCAL    1
#define XFS_DINODE_FMT_EXTENTS  2
#define XFS_DINODE_FMT_BTREE    3

/* FINOBT feature flag */
#define XFS_SB_FEAT_RO_COMPAT_FINOBT  (1 << 0)

/* Null AG block */
#define XFS_NULLAGBLOCK  0xFFFFFFFFU
#define XFS_NULLAGINO    0xFFFFFFFFU
#define XFS_AGI_UNLINKED_BUCKETS 64

/* Max reasonable btree depth */
#define MAX_BTREE_DEPTH  16

/* ─── Software CRC32C (Castagnoli polynomial 0x82F63B78) ─── */

static uint32_t crc32c_table[256];
static bool crc32c_initialized;

static void crc32c_init(void)
{
    uint32_t i, j, crc;

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78;
            else
                crc >>= 1;
        }
        crc32c_table[i] = crc;
    }
    crc32c_initialized = true;
}

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t i;

    if (!crc32c_initialized)
        crc32c_init();

    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ p[i]) & 0xFF];

    return crc;
}

/* ─── Big-endian read helpers (XFS on-disk is big-endian) ─── */

static uint16_t get_be16(const void *p)
{
    const uint8_t *b = p;
    return (uint16_t)((b[0] << 8) | b[1]);
}

static uint32_t get_be32(const void *p)
{
    const uint8_t *b = p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
}

static uint64_t get_be64(const void *p)
{
    const uint8_t *b = p;
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | (uint64_t)b[7];
}

/* ─── Big-endian write helpers ─── */

static void put_be32(void *p, uint32_t v)
{
    uint8_t *b = p;
    b[0] = (v >> 24) & 0xFF;
    b[1] = (v >> 16) & 0xFF;
    b[2] = (v >> 8)  & 0xFF;
    b[3] = v & 0xFF;
}

static void put_be64(void *p, uint64_t v)
{
    uint8_t *b = p;
    b[0] = (v >> 56) & 0xFF;
    b[1] = (v >> 48) & 0xFF;
    b[2] = (v >> 40) & 0xFF;
    b[3] = (v >> 32) & 0xFF;
    b[4] = (v >> 24) & 0xFF;
    b[5] = (v >> 16) & 0xFF;
    b[6] = (v >> 8)  & 0xFF;
    b[7] = v & 0xFF;
}

/* ─── Popcount helper ─── */

static int popcount64(uint64_t v)
{
    int count = 0;
    while (v) {
        count += v & 1;
        v >>= 1;
    }
    return count;
}

/* ─── Repair mode ─── */

enum repair_mode {
    REPAIR_NONE,    /* -n: check only, no writes */
    REPAIR_AUTO,    /* -a/-p: auto-fix safe repairs */
    REPAIR_ALL      /* -y: fix everything possible */
};

/* ─── Globals ─── */

static bool verbose;
static int errors;
static int repaired;
static enum repair_mode repair = REPAIR_NONE;

/* Parsed XFS superblock geometry (populated by check_xfs_superblock) */
struct xfs_geo {
    uint32_t    blocksize;
    uint32_t    agcount;
    uint32_t    agblocks;
    uint16_t    inodesize;
    uint16_t    inopblock;
    uint8_t     inopblog;
    uint8_t     agblklog;
    uint64_t    dblocks;
    uint64_t    rootino;
    uint64_t    icount;
    uint64_t    ifree;
    uint64_t    fdblocks;
    uint32_t    features_ro_compat;
    bool        has_finobt;
    bool        has_ftype;      /* sb incompat FTYPE: dirents carry a type byte */
    bool        has_nrext64;    /* sb incompat NREXT64: di_big_nextents at 0x18 */
    uint8_t     dirblklog;      /* a directory block is blocksize << dirblklog */
    uint64_t    xfs_off;        /* byte offset of XFS data on device */
    uint8_t     uuid[16];       /* filesystem UUID for btree block headers */
};

/* Per-AG collected data for cross-checks */
struct ag_summary {
    uint64_t    bno_freeblks;   /* sum of free extents from BNO btree */
    uint32_t    agf_freeblks;   /* AGF reported freeblks */
    uint32_t    agi_count;      /* AGI reported inode count */
    uint32_t    agi_freecount;  /* AGI reported free inode count */
    uint64_t    inobt_total;    /* total inodes from inobt records */
    uint64_t    inobt_free;     /* total free inodes from inobt records */
};

/* both directory-sharding gates present on this device (set by
 * check_xfs_superblock; the inode walk verifies manifests only then, and
 * reports any PARENT/CONTAINER flag as corruption otherwise). */
static bool dirshard_gates_ok;

/* Global summary accumulators */
static uint64_t total_inobt_inodes;
static uint64_t total_inobt_free;
static uint64_t total_bno_freeblks;
static uint64_t total_agf_freeblks;

/* ─── Helpers ─── */

static void err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "  ERROR: ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
    errors++;
}

static void info(const char *fmt, ...)
{
    va_list ap;
    if (!verbose)
        return;
    va_start(ap, fmt);
    fprintf(stdout, "  ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static void format_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes >= (1ULL << 40))
        snprintf(buf, buflen, "%.2f TB", (double)bytes / (1ULL << 40));
    else if (bytes >= (1ULL << 30))
        snprintf(buf, buflen, "%.2f GB", (double)bytes / (1ULL << 30));
    else if (bytes >= (1ULL << 20))
        snprintf(buf, buflen, "%.2f MB", (double)bytes / (1ULL << 20));
    else
        snprintf(buf, buflen, "%llu bytes", (unsigned long long)bytes);
}

static void format_uuid(const uint8_t *uuid, char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5],
             uuid[6], uuid[7],
             uuid[8], uuid[9],
             uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int read_at(int fd, void *buf, size_t len, off_t offset)
{
    ssize_t ret = pread(fd, buf, len, offset);
    if (ret < 0) {
        err("pread at offset %llu: %s", (unsigned long long)offset, strerror(errno));
        return -1;
    }
    if ((size_t)ret != len) {
        err("short read at offset %llu: got %zd, expected %zu",
            (unsigned long long)offset, ret, len);
        return -1;
    }
    return 0;
}

static int write_at(int fd, const void *buf, size_t len, off_t offset)
{
    ssize_t ret = pwrite(fd, buf, len, offset);
    if (ret < 0) {
        fprintf(stderr, "chk_mxfs: pwrite at offset %llu: %s\n",
                (unsigned long long)offset, strerror(errno));
        return -1;
    }
    if ((size_t)ret != len) {
        fprintf(stderr, "chk_mxfs: short write at offset %llu: wrote %zd, expected %zu\n",
                (unsigned long long)offset, ret, len);
        return -1;
    }
    return 0;
}

static bool can_repair(void)
{
    return repair == REPAIR_AUTO || repair == REPAIR_ALL;
}

/*
 * Recompute and store XFS CRC in a buffer, then write it to disk.
 * XFS CRC: zero the crc field, compute crc32c over full block,
 * complement, store as native uint32_t at crc_off.
 */
static int xfs_fix_crc_and_write(int fd, void *buf, size_t len,
                                  size_t crc_off, off_t disk_offset)
{
    uint32_t *field = (uint32_t *)((uint8_t *)buf + crc_off);
    *field = 0;
    *field = ~crc32c(~0U, buf, len);
    return write_at(fd, buf, len, disk_offset);
}

/*
 * Recompute and store MXFS-native CRC in a buffer, then write to disk.
 * MXFS CRC: zero the crc field, compute crc32c over full block,
 * store directly (no complement) as native uint32_t at crc_off.
 */
static int mxfs_fix_crc_and_write(int fd, void *buf, size_t len,
                                   size_t crc_off, off_t disk_offset)
{
    uint32_t *field = (uint32_t *)((uint8_t *)buf + crc_off);
    *field = 0;
    *field = crc32c(~0U, buf, len);
    return write_at(fd, buf, len, disk_offset);
}

/*
 * Verify XFS CRC: read stored CRC at crc_off, zero it, compute,
 * complement, compare. Restores the original buffer contents.
 *
 * XFS stores CRC as native uint32_t (little-endian on x86).
 * Seed ~0U, final complement (~crc).
 */
static bool xfs_verify_crc(void *buf, size_t len, size_t crc_off)
{
    uint32_t *field = (uint32_t *)((uint8_t *)buf + crc_off);
    uint32_t stored = *field;
    uint32_t computed;

    *field = 0;
    computed = ~crc32c(~0U, buf, len);
    *field = stored;

    return computed == stored;
}

/*
 * Read a full filesystem block from the device.
 * Caller must provide a buffer of at least geo->blocksize bytes.
 * agbno is the AG-relative block number.
 */
static int read_ag_block(int fd, const struct xfs_geo *geo,
                         uint32_t agno, uint32_t agbno, void *buf)
{
    uint64_t offset = geo->xfs_off +
                      (uint64_t)agno * geo->agblocks * geo->blocksize +
                      (uint64_t)agbno * geo->blocksize;
    return read_at(fd, buf, geo->blocksize, offset);
}

/* ─── Check: MXFS On-Disk Superblock ─── */

static int check_mxfs_super(int fd, struct mxfs_ondisk_super *super)
{
    uint8_t buf[MXFS_SUPER_SIZE];
    struct mxfs_ondisk_super *s;
    uint32_t stored_crc, computed;
    char sizebuf[64];

    if (read_at(fd, buf, MXFS_SUPER_SIZE, 0) < 0)
        return -1;

    s = (struct mxfs_ondisk_super *)buf;

    /* Magic */
    if (s->magic != MXFS_FORMAT_MAGIC) {
        err("MXFS super magic: expected 0x%08X, got 0x%08X",
            MXFS_FORMAT_MAGIC, s->magic);
        return -1;
    }

    /* Version */
    if (s->version != MXFS_FORMAT_VERSION) {
        err("MXFS super version: expected %u, got %u",
            MXFS_FORMAT_VERSION, s->version);
    }

    /* CRC32C verification: zero the crc field, compute over 4KB */
    stored_crc = s->crc;
    s->crc = 0;
    computed = crc32c(~0U, buf, MXFS_SUPER_SIZE);
    s->crc = stored_crc;

    if (computed != stored_crc) {
        err("MXFS super CRC: stored=0x%08X, computed=0x%08X",
            stored_crc, computed);

        if (can_repair()) {
            /* MXFS-native CRC: zero field, compute, store directly */
            s->crc = 0;
            s->crc = crc32c(~0U, buf, MXFS_SUPER_SIZE);
            if (write_at(fd, buf, MXFS_SUPER_SIZE, 0) == 0) {
                printf("  REPAIRED: MXFS super CRC recomputed\n");
                repaired++;
            }
        }
    }

    /* Offset sanity: all regions must fit within device_size */
    if (s->journal_offset + s->journal_size > s->device_size) {
        err("journal region extends past device: offset=%llu + size=%llu > device=%llu",
            (unsigned long long)s->journal_offset,
            (unsigned long long)s->journal_size,
            (unsigned long long)s->device_size);
    }

    if (s->disklock_offset + s->disklock_size > s->device_size) {
        err("disklock region extends past device: offset=%llu + size=%llu > device=%llu",
            (unsigned long long)s->disklock_offset,
            (unsigned long long)s->disklock_size,
            (unsigned long long)s->device_size);
    }

    if (s->xfs_data_offset + s->xfs_data_size > s->device_size) {
        err("XFS data region extends past device: offset=%llu + size=%llu > device=%llu",
            (unsigned long long)s->xfs_data_offset,
            (unsigned long long)s->xfs_data_size,
            (unsigned long long)s->device_size);
    }

    /* the recovery manifest region (docs/recovery-manifest.md).
     * Protocol gen 7 REQUIRES it: a gen-7 fleet fences victims by writing
     * their manifests there, so a gated super without the flag is a format
     * error, not a legacy layout. */
    if (s->flags & MXFS_FORMAT_F_RMAN) {
        if (s->rman_size != MXFS_RMAN_REGION_BYTES)
            err("recovery manifest region size %llu != expected %llu",
                (unsigned long long)s->rman_size,
                (unsigned long long)MXFS_RMAN_REGION_BYTES);
        if (s->rman_offset + s->rman_size > s->device_size)
            err("recovery manifest region extends past device: offset=%llu + size=%llu > device=%llu",
                (unsigned long long)s->rman_offset,
                (unsigned long long)s->rman_size,
                (unsigned long long)s->device_size);
    } else if ((s->flags & MXFS_FORMAT_F_PROTOGATE) &&
               s->cluster_proto_gen >= 7) {
        err("cluster_proto_gen=%u requires the recovery manifest region (MXFS_FORMAT_F_RMAN) but the super does not carry it",
            s->cluster_proto_gen);
    }

    /* the TCP authority ledger region (docs/tcp-authority-ledger.md).
     * Protocol gen 8 REQUIRES it. */
    if (s->flags & MXFS_FORMAT_F_TAUTH) {
        /* (D-0348 step 2): mkfs-sized; whole pages, at least the
         * minimum geometry.  The header's page count is checked against
         * the size below. */
        if (s->tauth_size < MXFS_TAUTH_REGION_BYTES ||
            s->tauth_size % MXFS_TAUTH_PAGE_BYTES)
            err("authority ledger region size %llu: below the minimum %llu or not page-aligned",
                (unsigned long long)s->tauth_size,
                (unsigned long long)MXFS_TAUTH_REGION_BYTES);
        if (s->tauth_offset + s->tauth_size > s->device_size)
            err("authority ledger region extends past device: offset=%llu + size=%llu > device=%llu",
                (unsigned long long)s->tauth_offset,
                (unsigned long long)s->tauth_size,
                (unsigned long long)s->device_size);
    } else if ((s->flags & MXFS_FORMAT_F_PROTOGATE) &&
               s->cluster_proto_gen >= 8) {
        err("cluster_proto_gen=%u requires the TCP authority ledger region (MXFS_FORMAT_F_TAUTH) but the super does not carry it",
            s->cluster_proto_gen);
    }
    /* the PR registrant ledger region; gen 12 requires it. */
    if (s->flags & MXFS_FORMAT_F_PRKEY64) {
        if (s->prkey_size < MXFS_PRLEDGER_ENTRY_BYTES ||
            s->prkey_size % MXFS_PRLEDGER_ENTRY_BYTES)
            err("PR registrant ledger region size %llu: below one entry or not entry-aligned",
                (unsigned long long)s->prkey_size);
        if (s->prkey_offset + s->prkey_size > s->device_size)
            err("PR registrant ledger region extends past device: offset=%llu + size=%llu > device=%llu",
                (unsigned long long)s->prkey_offset,
                (unsigned long long)s->prkey_size,
                (unsigned long long)s->device_size);
    } else if ((s->flags & MXFS_FORMAT_F_PROTOGATE) &&
               s->cluster_proto_gen >= 12) {
        err("cluster_proto_gen=%u requires the PR registrant ledger region (MXFS_FORMAT_F_PRKEY64) but the super does not carry it",
            s->cluster_proto_gen);
    }
    /* the bootstrap record region; gen 13 requires it. */
    if (s->flags & MXFS_FORMAT_F_BOOTSTRAP) {
        if (s->bootstrap_size < MXFS_BOOTSTRAP_REC_BYTES ||
            s->bootstrap_offset % 512)
            err("bootstrap record region malformed: offset=%llu size=%llu",
                (unsigned long long)s->bootstrap_offset,
                (unsigned long long)s->bootstrap_size);
        /* (§6.8): gen 17 needs the 32 KiB map (banks, tombstones,
         * lineage, takeover journal); the kernel refuses a smaller region */
        if ((s->flags & MXFS_FORMAT_F_PROTOGATE) && s->cluster_proto_gen >= 17 &&
            s->bootstrap_size < MXFS_BOOTSTRAP_BYTES)
            err("bootstrap region size=%llu < %u required by cluster_proto_gen=%u (re-mkfs)",
                (unsigned long long)s->bootstrap_size, MXFS_BOOTSTRAP_BYTES,
                s->cluster_proto_gen);
        if (s->bootstrap_offset + s->bootstrap_size > s->device_size)
            err("bootstrap record region extends past device: offset=%llu + size=%llu > device=%llu",
                (unsigned long long)s->bootstrap_offset,
                (unsigned long long)s->bootstrap_size,
                (unsigned long long)s->device_size);
    } else if ((s->flags & MXFS_FORMAT_F_PROTOGATE) &&
               s->cluster_proto_gen >= 13) {
        err("cluster_proto_gen=%u requires the bootstrap record region (MXFS_FORMAT_F_BOOTSTRAP) but the super does not carry it",
            s->cluster_proto_gen);
    }
    /* 0.88.0: the slice lifecycle region; gen 20 requires it.  One 512 B
     * record per log slice, so the region must hold xfs_log_node_count of
     * them and end before the XFS data. */
    if (s->flags & MXFS_FORMAT_F_SLIFE) {
        if (s->slife_size < (uint64_t)s->xfs_log_node_count * MXFS_SLIFE_RECORD_SIZE ||
            s->slife_size < MXFS_SLIFE_RECORD_SIZE ||
            s->slife_offset % 512)
            err("slice lifecycle region malformed: offset=%llu size=%llu for %u log slices",
                (unsigned long long)s->slife_offset,
                (unsigned long long)s->slife_size, s->xfs_log_node_count);
        if (s->slife_offset + s->slife_size > s->device_size)
            err("slice lifecycle region extends past device: offset=%llu + size=%llu > device=%llu",
                (unsigned long long)s->slife_offset,
                (unsigned long long)s->slife_size,
                (unsigned long long)s->device_size);
    } else if ((s->flags & MXFS_FORMAT_F_PROTOGATE) &&
               s->cluster_proto_gen >= 20) {
        err("cluster_proto_gen=%u requires the slice lifecycle region (MXFS_FORMAT_F_SLIFE) but the super does not carry it",
            s->cluster_proto_gen);
    }

    /* directory sharding (docs/dir-sharding.md).  Optional on a
     * gen 18+ format: mkfs sets MXFS_FORMAT_F_DIRSHARD only when asked
     * (mkfs.mxfs -D), and a format without it simply has sharding off.  The
     * XFS sb incompat bit 29 must agree with it (checked against the sb once
     * the geometry is read), and a sharded inode on a device without both
     * gates is an error (check_dirshard).  No region of its own. */
    if ((s->flags & MXFS_FORMAT_F_DIRSHARD) &&
        (s->flags & MXFS_FORMAT_F_PROTOGATE) && s->cluster_proto_gen < 18)
        err("MXFS_FORMAT_F_DIRSHARD set on cluster_proto_gen=%u (< 18): flag without the protocol that understands it",
            s->cluster_proto_gen);

    /* The cluster name (MXFS_FORMAT_F_CLUSTER_NAME): with the flag the field
     * holds a valid name the mount checks; without it the field is zero, so
     * a name can never be half-set. */
    {
        char name[MXFS_CLUSTER_NAME_LEN + 1];

        memcpy(name, s->cluster_name, MXFS_CLUSTER_NAME_LEN);
        name[MXFS_CLUSTER_NAME_LEN] = '\0';
        if (s->flags & MXFS_FORMAT_F_CLUSTER_NAME) {
            if (!mxfs_cluster_name_valid(name))
                err("cluster name flag set but the name field is not a valid name");
            else
                info("cluster name: %s", name);
        } else {
            int i, nz = 0;

            for (i = 0; i < MXFS_CLUSTER_NAME_LEN; i++)
                nz |= s->cluster_name[i];
            if (nz)
                err("cluster name field is not zero but MXFS_FORMAT_F_CLUSTER_NAME is clear");
            else
                info("cluster name: (none)");
        }
    }

    /* Region non-overlapping checks:
     * Expected layout: [super 4KB] [journal] [disklock] [rman] [XFS data]
     * Check each pair for overlap.
     */
    {
        struct {
            const char *name;
            uint64_t start;
            uint64_t end;
        } regions[8];
        int nreg = 4;

        regions[0].name = "super";
        regions[0].start = 0;
        regions[0].end = MXFS_SUPER_SIZE;

        regions[1].name = "journal";
        regions[1].start = s->journal_offset;
        regions[1].end = s->journal_offset + s->journal_size;

        regions[2].name = "disklock";
        regions[2].start = s->disklock_offset;
        regions[2].end = s->disklock_offset + s->disklock_size;

        regions[3].name = "xfs_data";
        regions[3].start = s->xfs_data_offset;
        regions[3].end = s->xfs_data_offset + s->xfs_data_size;

        if (s->flags & MXFS_FORMAT_F_RMAN) {
            regions[nreg].name = "rman";
            regions[nreg].start = s->rman_offset;
            regions[nreg].end = s->rman_offset + s->rman_size;
            nreg++;
        }
        if (s->flags & MXFS_FORMAT_F_TAUTH) {
            regions[nreg].name = "tauth";
            regions[nreg].start = s->tauth_offset;
            regions[nreg].end = s->tauth_offset + s->tauth_size;
            nreg++;
        }
        if (s->flags & MXFS_FORMAT_F_PRKEY64) {
            regions[nreg].name = "prkey";
            regions[nreg].start = s->prkey_offset;
            regions[nreg].end = s->prkey_offset + s->prkey_size;
            nreg++;
        }
        if (s->flags & MXFS_FORMAT_F_BOOTSTRAP) {
            regions[nreg].name = "bootstrap";
            regions[nreg].start = s->bootstrap_offset;
            regions[nreg].end = s->bootstrap_offset + s->bootstrap_size;
            nreg++;
        }
        if (s->flags & MXFS_FORMAT_F_SLIFE) {
            regions[nreg].name = "slife";
            regions[nreg].start = s->slife_offset;
            regions[nreg].end = s->slife_offset + s->slife_size;
            nreg++;
        }

        for (int i = 0; i < nreg; i++) {
            for (int j = i + 1; j < nreg; j++) {
                if (regions[i].start < regions[j].end &&
                    regions[j].start < regions[i].end) {
                    err("regions overlap: %s [%llu..%llu) and %s [%llu..%llu)",
                        regions[i].name,
                        (unsigned long long)regions[i].start,
                        (unsigned long long)regions[i].end,
                        regions[j].name,
                        (unsigned long long)regions[j].start,
                        (unsigned long long)regions[j].end);
                }
            }
        }
    }

    /* Copy out the super for subsequent checks */
    memcpy(super, buf, sizeof(*super));

    format_size(s->device_size, sizebuf, sizeof(sizebuf));
    printf("MXFS super .............. %s  (version=%u, device=%s)\n",
           errors == 0 ? "OK" : "ERRORS", s->version, sizebuf);
    info("journal_offset=%llu", (unsigned long long)s->journal_offset);
    info("disklock_offset=%llu", (unsigned long long)s->disklock_offset);
    if (s->flags & MXFS_FORMAT_F_RMAN)
        info("rman_offset=%llu size=%llu", (unsigned long long)s->rman_offset,
             (unsigned long long)s->rman_size);
    if (s->flags & MXFS_FORMAT_F_TAUTH)
        info("tauth_offset=%llu size=%llu", (unsigned long long)s->tauth_offset,
             (unsigned long long)s->tauth_size);
    if (s->flags & MXFS_FORMAT_F_PRKEY64)
        info("prkey_offset=%llu size=%llu (%llu registrant entries)",
             (unsigned long long)s->prkey_offset,
             (unsigned long long)s->prkey_size,
             (unsigned long long)(s->prkey_size / MXFS_PRLEDGER_ENTRY_BYTES));
    if (s->flags & MXFS_FORMAT_F_BOOTSTRAP)
        info("bootstrap_offset=%llu size=%llu",
             (unsigned long long)s->bootstrap_offset,
             (unsigned long long)s->bootstrap_size);
    if (s->flags & MXFS_FORMAT_F_SLIFE)
        info("slife_offset=%llu size=%llu (%u slice lifecycle records live)",
             (unsigned long long)s->slife_offset,
             (unsigned long long)s->slife_size, s->xfs_log_node_count);
    info("xfs_data_offset=%llu", (unsigned long long)s->xfs_data_offset);

    return 0;
}

/* ─── Check: TCP authority ledger region ───
 *
 * Every page must have at least one valid committed copy: a page with none
 * makes every resource on it UNKNOWN (never FREE), which the authority
 * code fails closed on — an operator must see it here first.  A page with
 * exactly one valid copy is normal after a crash mid-write (the shadow
 * design's whole point) and is reported, not counted as an error. */
/* (docs/tauth-view-table.md §13, build step 1): the control pages —
 * view slots A/B and the ROOT.  The root must validate (fs identity, crc,
 * zero pads, the 3584 B page tail zero); with gen 0 each slot is empty or a
 * gen-1 proposal; with a committed gen the named slot must carry exactly
 * {gen, digest} and the other slot must be empty, older, or the gen+1
 * proposal chained to it.  Anything else is a control-page error: the
 * membership barrier fails closed on it, so the operator sees it here. */
static const char *tview_errname(int rc)
{
    switch (rc) {
    case MXFS_TVIEW_OK:         return "ok";
    case MXFS_TVIEW_E_MAGIC:    return "magic";
    case MXFS_TVIEW_E_VERSION:  return "version";
    case MXFS_TVIEW_E_COUNT:    return "count";
    case MXFS_TVIEW_E_GEN:      return "gen";
    case MXFS_TVIEW_E_PREV:     return "prev";
    case MXFS_TVIEW_E_IDENTITY: return "identity";
    case MXFS_TVIEW_E_PAD:      return "pad";
    case MXFS_TVIEW_E_MEMBERS:  return "members";
    case MXFS_TVIEW_E_REMOVED:  return "removed";
    case MXFS_TVIEW_E_DIGEST:   return "digest";
    case MXFS_TVIEW_E_CRC:      return "crc";
    case MXFS_TVIEW_E_SLOT:     return "slot";
    case MXFS_TVIEW_E_BALLOT:   return "ballot";
    case MXFS_TVIEW_E_TAIL:     return "tail";
    default:                    return "?";
    }
}

static void check_tauth_ctrl(int fd, const struct mxfs_ondisk_super *s, uint32_t fs_gen)
{
    uint8_t *rpage;
    struct mxfs_tauth_view *va, *vb;
    const struct mxfs_tauth_view *committed = NULL;
    int other = 0, rc, rrc, ra, rb;

    rpage = calloc(1, MXFS_TAUTH_PAGE_BYTES);
    va = calloc(1, sizeof(*va));
    vb = calloc(1, sizeof(*vb));
    if (!rpage || !va || !vb) {
        err("out of memory checking the authority ledger control pages");
        free(rpage); free(va); free(vb);
        return;
    }
    if (read_at(fd, rpage, MXFS_TAUTH_PAGE_BYTES,
                s->tauth_offset + mxfs_tauth_ctrl_off(MXFS_TAUTH_CTRL_ROOT)) < 0 ||
        read_at(fd, va, sizeof(*va),
                s->tauth_offset + mxfs_tauth_ctrl_off(MXFS_TAUTH_CTRL_VIEW_A)) < 0 ||
        read_at(fd, vb, sizeof(*vb),
                s->tauth_offset + mxfs_tauth_ctrl_off(MXFS_TAUTH_CTRL_VIEW_B)) < 0) {
        err("authority ledger control pages: read failed");
        free(rpage); free(va); free(vb);
        return;
    }
    rrc = mxfs_tauth_root_validate(rpage, MXFS_TAUTH_PAGE_BYTES, fs_gen, s->fs_uuid, crc32c);
    ra = mxfs_tauth_view_validate(va, fs_gen, s->fs_uuid, crc32c);
    rb = mxfs_tauth_view_validate(vb, fs_gen, s->fs_uuid, crc32c);
    rc = rrc ? rrc : mxfs_tauth_ctrl_validate((const struct mxfs_tauth_root *)rpage,
                                              va, vb, fs_gen, s->fs_uuid, crc32c,
                                              &committed, &other);
    if (rc) {
        const struct mxfs_tauth_root *root = (const struct mxfs_tauth_root *)rpage;

        err("authority ledger control pages: %s (root=%s gen=%llu slot=%u ballot=%llu; A=%s gen=%llu; B=%s gen=%llu)",
            tview_errname(rc), tview_errname(rrc), (unsigned long long)root->gen,
            (unsigned)root->slot, (unsigned long long)root->coord_ballot,
            tview_errname(ra), (unsigned long long)va->gen,
            tview_errname(rb), (unsigned long long)vb->gen);
    } else {
        const struct mxfs_tauth_root *root = (const struct mxfs_tauth_root *)rpage;

        printf("TCP authority view ...... OK  (gen=%llu slot=%s members=%u removed=%u ballot=%llu coord=%u other=%s)\n",
               (unsigned long long)root->gen,
               root->gen == 0 ? "none" : (root->slot == MXFS_TAUTH_CTRL_VIEW_A ? "A" : "B"),
               committed ? committed->count : 0,
               committed ? committed->nremoved : 0,
               (unsigned long long)root->coord_ballot, root->coord_node,
               other == 0 ? "empty" : (other == 1 ? "older" : "proposal"));
    }
    free(rpage); free(va); free(vb);
}

/*
 * the PR REGISTRANT LEDGER region (dlm/prledger.h).  One 512-byte
 * entry per registrant; crc32c(~0, entry with crc=0) folded with the index.
 * Prints every non-FREE entry and validates its crc.  A PREPARED/REGISTERED
 * entry is a key the target may still hold (PTPL) for a host boot that has
 * not retired it; an operator reading this after a whole-cluster outage sees
 * exactly which boots' keys are outstanding.
 */
static void hex_uuid(const uint8_t *u, char out[37]);

struct chk_prledger_entry {
    uint32_t magic; uint16_t ver; uint16_t state;
    uint32_t key_gen; uint32_t node_id;
    uint64_t pr_key;
    uint8_t host_uuid[16]; uint8_t boot_uuid[16]; uint8_t fs_uuid[16];
    uint64_t stamp_ms; uint64_t seq;
    uint32_t host_src; uint32_t fenced_by; uint32_t crc32c;
    uint32_t succ_pad0;
    uint64_t succ_old_key; uint32_t succ_old_key_gen; uint32_t succ_pad;
    uint8_t succ_old_boot[16];          /* self-succession */
    uint8_t reserved[376];
};
_Static_assert(sizeof(struct chk_prledger_entry) == 512, "prledger entry");
#define MXFS_PRLEDGER_MAGIC_C   0x4B50584Du

static const char *prl_state(uint16_t st)
{
    switch (st) {
    case 0: return "FREE"; case 1: return "PREPARED"; case 2: return "REGISTERED";
    case 3: return "RETIRED"; case 4: return "FENCED"; default: return "?";
    }
}

/*
 * the WHOLE-CLUSTER BOOTSTRAP RECORD (dlm/bootstrap.h).  One
 * 512-byte CAW-written record; mkfs writes it IDLE.  Validates magic/version/
 * crc, prints state, term, owner and the sealed/complete bitmaps — after a
 * total outage this is where an operator sees whether a bootstrap recovery
 * is claimed, sealed, in progress or complete, and by which host boot.
 */
struct chk_bootstrap_rec {
    uint32_t magic; uint16_t ver; uint16_t state;
    uint64_t term; uint64_t seq; uint64_t stamp_ms;
    uint32_t owner_node; uint32_t owner_key_gen;
    uint64_t owner_epoch; uint64_t owner_pr_key; uint64_t owner_nonce;
    uint8_t owner_host_uuid[16]; uint8_t owner_boot_uuid[16];
    uint8_t fs_uuid[16];
    uint32_t fs_gen; uint32_t host_src;
    uint64_t victim_bitmap; uint64_t complete_bitmap;
    uint64_t ledger_gen; uint64_t manifest_hash;
    uint32_t registrants; uint32_t registrants_done;
    uint64_t claim_stamp_ms; uint64_t seal_stamp_ms; uint64_t complete_stamp_ms;
    uint32_t prev_owner_node; uint32_t prev_fence_kind;
    uint64_t prev_owner_epoch; uint64_t prev_owner_pr_key;
    uint32_t crc32c;
    uint32_t refused_slot; uint32_t refused_reason;    /* v2 */
    uint32_t escrow_pad;                               /* v3 */
    struct {
        uint8_t state; uint8_t cls; uint16_t slot;
        uint32_t victim_node;
        uint64_t victim_epoch; uint64_t victim_key;
        uint32_t victim_key_gen; uint32_t old_sector_crc;
        uint8_t victim_host[16]; uint8_t victim_boot[16];
        uint8_t desc[120];
        uint64_t claim_epoch; uint32_t claim_node; int32_t replay_rc;
        uint8_t mptr[64];                              /* */
    } escrow;
    uint64_t episode_term; uint16_t lineage_count; uint16_t takeover_gen; /* v5 */
    uint8_t reserved[12];
};
_Static_assert(sizeof(struct chk_bootstrap_rec) == 512, "bootstrap record");

/* (docs/whole-cluster-restart.md §6.8): the region's other sectors. */
#define CHK_BOOT_SEC_TAKEOVER   31
#define CHK_BOOT_SEC_TOMB       32
#define CHK_BOOT_SEC_LINEAGE    40
#define CHK_BOOT_TOMB_MAGIC     0x4254584Du
#define CHK_BOOT_LIN_MAGIC      0x4C42584Du
#define CHK_BOOT_TK_MAGIC       0x4B42584Du
struct chk_bootstrap_tomb {
    uint32_t magic; uint8_t kind; uint8_t stage; uint16_t slot;
    uint32_t victim_node; uint32_t victim_key_gen;
    uint64_t victim_epoch; uint64_t victim_key; uint64_t term;
    uint32_t obligation; uint32_t proof_crc; uint64_t source_term;
    uint32_t pad; uint32_t crc32c;
};
_Static_assert(sizeof(struct chk_bootstrap_tomb) == 64, "tombstone");
struct chk_bootstrap_lineage {
    uint32_t magic; uint16_t ver; uint16_t idx;
    uint64_t term; uint64_t episode_term;
    uint32_t owner_node; uint32_t owner_key_gen;
    uint64_t owner_epoch; uint64_t owner_pr_key;
    uint8_t owner_host_uuid[16]; uint8_t owner_boot_uuid[16];
    uint64_t manifest_hash; uint64_t victim_bitmap; uint64_t complete_bitmap;
    uint32_t fence_kind; uint32_t fence_pr_gen;
    uint16_t state; uint16_t pad16; uint32_t crc32c;
    uint8_t escrow[264];
    uint8_t reserved[128];
};
_Static_assert(sizeof(struct chk_bootstrap_lineage) == 512, "lineage entry");
struct chk_bootstrap_takeover {
    uint32_t magic; uint16_t ver; uint16_t stage;
    uint64_t seq; uint64_t stamp_ms; uint64_t nonce;
    uint64_t target_term; uint64_t target_nonce; uint64_t target_seq;
    uint16_t target_state; uint16_t pad16;
    uint32_t old_fence_kind; uint32_t old_fence_pr_gen;
    uint32_t pred_fence_kind; uint32_t pred_fence_pr_gen;
    uint32_t k_desc_crc; uint16_t k_slot; uint16_t pad16b; uint32_t crc32c;
    struct { uint32_t node_id, key_gen; uint64_t epoch, pr_key; uint8_t host[16], boot[16]; } owner, us, pred;
    uint8_t reserved[256];
};
_Static_assert(sizeof(struct chk_bootstrap_takeover) == 512, "takeover journal");
static const char *bs_tk_stage(uint16_t st)
{
    switch (st) {
    case 0: return "EMPTY"; case 1: return "CONTENDER";
    case 2: return "OLD_FENCE_INTENT"; case 3: return "OLD_FENCE_DONE";
    case 4: return "K_DESC_DONE"; case 5: return "CAPSULE_WRITTEN";
    case 6: return "RECORD_COMMITTED"; default: return "?";
    }
}
static const char *bs_escrow_name(uint8_t st)
{
    switch (st) {
    case 0: return "NONE";
    case 1: return "PREPARED";
    case 2: return "K_CLAIMED";
    case 3: return "K_REPLAY_OK";
    case 4: return "K_REPLAY_REFUSED";
    default: return "?";
    }
}
#define MXFS_BOOTSTRAP_MAGIC_C  0x5342584Du

static const char *bs_state(uint16_t st)
{
    switch (st) {
    case 0: return "IDLE";
    case 1: return "CLAIMED";
    case 2: return "MANIFEST_SEALED";
    case 3: return "RECOVERING";
    case 4: return "RECOVERY_COMPLETE";
    case 5: return "REFUSED";
    default: return "?";
    }
}

static void check_bootstrap(int fd, const struct mxfs_ondisk_super *s)
{
    struct chk_bootstrap_rec r, t;
    char hu[37], bu[37], fu[37];
    uint32_t c;

    if (!(s->flags & MXFS_FORMAT_F_BOOTSTRAP))
        return;
    if (read_at(fd, &r, sizeof(r), (off_t)s->bootstrap_offset) < 0) {
        err("bootstrap record: read failed");
        return;
    }
    if (r.magic == 0) {
        err("bootstrap record: UNFORMATTED (magic 0) — mkfs never wrote it; the kernel fails closed on this");
        return;
    }
    if (r.magic != MXFS_BOOTSTRAP_MAGIC_C || r.ver != 5) {
        err("bootstrap record: magic 0x%08x ver %u (this build reads v5)", r.magic, r.ver);
        return;
    }
    t = r;
    t.crc32c = 0;
    c = crc32c(~0U, &t, sizeof(t));
    if (c != r.crc32c || r.state > 5 || (r.state != 0 && r.owner_node == 0)) {
        err("bootstrap record: crc expected 0x%08X got 0x%08X state=%u owner=%u",
            c, r.crc32c, r.state, r.owner_node);
        return;
    }
    if (memcmp(r.fs_uuid, s->fs_uuid, 16) != 0) {
        hex_uuid(r.fs_uuid, fu);
        err("bootstrap record: fs_uuid %s is not this volume's", fu);
        return;
    }
    hex_uuid(r.owner_host_uuid, hu);
    hex_uuid(r.owner_boot_uuid, bu);
    info("bootstrap: %s term=%llu seq=%llu owner=%u/%llu key=0x%llx gen=%u host=%s boot=%s victims=0x%016llx complete=0x%016llx registrants=%u/%u prev=%u/%llu kind=%u",
         bs_state(r.state), (unsigned long long)r.term,
         (unsigned long long)r.seq, r.owner_node,
         (unsigned long long)r.owner_epoch,
         (unsigned long long)r.owner_pr_key, r.owner_key_gen,
         r.state ? hu : "-", r.state ? bu : "-",
         (unsigned long long)r.victim_bitmap,
         (unsigned long long)r.complete_bitmap,
         r.registrants_done, r.registrants, r.prev_owner_node,
         (unsigned long long)r.prev_owner_epoch, r.prev_fence_kind);
    if (r.escrow.state != 0) {
        char vh[37], vb[37];

        hex_uuid(r.escrow.victim_host, vh);
        hex_uuid(r.escrow.victim_boot, vb);
        info("bootstrap escrow: %s K=%u cls=%u victim=%u/%llu key=0x%llx gen=%u host=%s boot=%s old_crc=0x%08x claim=%u/%llu replay_rc=%d",
             bs_escrow_name(r.escrow.state), r.escrow.slot, r.escrow.cls,
             r.escrow.victim_node, (unsigned long long)r.escrow.victim_epoch,
             (unsigned long long)r.escrow.victim_key, r.escrow.victim_key_gen,
             vh, vb, r.escrow.old_sector_crc, r.escrow.claim_node,
             (unsigned long long)r.escrow.claim_epoch, r.escrow.replay_rc);
    }
    /* (§6.8): episode, lineage, tombstones, takeover journal */
    info("bootstrap episode: term=%llu lineage=%u takeover_gen=%u",
         (unsigned long long)r.episode_term, r.lineage_count, r.takeover_gen);
    {
        struct chk_bootstrap_lineage l, lt;
        struct chk_bootstrap_tomb tb[8];
        struct chk_bootstrap_takeover tk, tkt;
        unsigned int i, k, ntomb = 0, ndirect = 0, ninh = 0, nbad = 0;

        for (i = 0; i < r.lineage_count && i < 8; i++) {
            if (read_at(fd, &l, sizeof(l), (off_t)(s->bootstrap_offset +
                        (uint64_t)(CHK_BOOT_SEC_LINEAGE + i) * 512)) < 0)
                break;
            lt = l; lt.crc32c = 0;
            if (l.magic != CHK_BOOT_LIN_MAGIC || l.idx != i ||
                crc32c(~0U, &lt, sizeof(lt)) != l.crc32c) {
                err("bootstrap lineage[%u]: invalid (magic 0x%08x idx %u)", i, l.magic, l.idx);
                continue;
            }
            info("bootstrap lineage[%u]: term=%llu owner=%u/%llu key=0x%llx state=%s manifest=0x%016llx victims=0x%016llx complete=0x%016llx fence=%u escrow=%s K=%u",
                 i, (unsigned long long)l.term, l.owner_node,
                 (unsigned long long)l.owner_epoch,
                 (unsigned long long)l.owner_pr_key, bs_state(l.state),
                 (unsigned long long)l.manifest_hash,
                 (unsigned long long)l.victim_bitmap,
                 (unsigned long long)l.complete_bitmap, l.fence_kind,
                 bs_escrow_name(l.escrow[0]), l.escrow[2] | (l.escrow[3] << 8));
        }
        for (i = 0; i < 8; i++) {
            if (read_at(fd, tb, sizeof(tb), (off_t)(s->bootstrap_offset +
                        (uint64_t)(CHK_BOOT_SEC_TOMB + i) * 512)) < 0)
                break;
            for (k = 0; k < 8; k++) {
                struct chk_bootstrap_tomb t = tb[k];
                uint32_t want;

                if (t.magic != CHK_BOOT_TOMB_MAGIC)
                    continue;
                t.crc32c = 0;
                want = crc32c(~0U, &t, sizeof(t));
                if (want != tb[k].crc32c || tb[k].slot != i * 8 + k) {
                    nbad++;
                    continue;
                }
                if (tb[k].term < r.episode_term)
                    continue;               /* an older episode's */
                ntomb++;
                if (tb[k].kind == 1) ndirect++; else ninh++;
                if (verbose)
                    info("bootstrap tombstone: slot=%u kind=%s victim=%u/%llu key=0x%llx term=%llu obligation=0x%08x proof=0x%08x source_term=%llu",
                         tb[k].slot, tb[k].kind == 1 ? "DIRECT" : tb[k].kind == 2 ? "INHERITED" : "?",
                         tb[k].victim_node, (unsigned long long)tb[k].victim_epoch,
                         (unsigned long long)tb[k].victim_key,
                         (unsigned long long)tb[k].term, tb[k].obligation,
                         tb[k].proof_crc, (unsigned long long)tb[k].source_term);
            }
        }
        info("bootstrap tombstones: %u this episode (direct=%u inherited=%u) invalid=%u",
             ntomb, ndirect, ninh, nbad);
        if (r.state != 0 && r.state != 4) {
            unsigned int missing = 0;

            for (k = 0; k < 64; k++)
                if ((r.complete_bitmap >> k) & 1) {
                    /* every set bit needs a tombstone of this episode */
                    unsigned int si = k / 8, sk = k % 8;

                    if (read_at(fd, tb, sizeof(tb), (off_t)(s->bootstrap_offset +
                                (uint64_t)(CHK_BOOT_SEC_TOMB + si) * 512)) < 0 ||
                        tb[sk].magic != CHK_BOOT_TOMB_MAGIC || tb[sk].slot != k ||
                        tb[sk].term < r.episode_term)
                        missing++;
                }
            if (missing)
                err("bootstrap: %u completion bit(s) carry no tombstone of this episode — a takeover would refuse them (INHERITANCE_UNPROVEN)", missing);
        }
        if (read_at(fd, &tk, sizeof(tk), (off_t)(s->bootstrap_offset +
                    (uint64_t)CHK_BOOT_SEC_TAKEOVER * 512)) == 0) {
            tkt = tk; tkt.crc32c = 0;
            if (tk.magic == CHK_BOOT_TK_MAGIC &&
                crc32c(~0U, &tkt, sizeof(tkt)) == tk.crc32c)
                info("bootstrap takeover journal: %s seq=%llu target term=%llu state=%s owner=%u/%llu key=0x%llx contender=%u/%llu key=0x%llx pred=%u/%llu key=0x%llx old_fence=%u/%u pred_fence=%u/%u K=%u",
                     bs_tk_stage(tk.stage), (unsigned long long)tk.seq,
                     (unsigned long long)tk.target_term, bs_state(tk.target_state),
                     tk.owner.node_id, (unsigned long long)tk.owner.epoch,
                     (unsigned long long)tk.owner.pr_key,
                     tk.us.node_id, (unsigned long long)tk.us.epoch,
                     (unsigned long long)tk.us.pr_key,
                     tk.pred.node_id, (unsigned long long)tk.pred.epoch,
                     (unsigned long long)tk.pred.pr_key,
                     tk.old_fence_kind, tk.old_fence_pr_gen,
                     tk.pred_fence_kind, tk.pred_fence_pr_gen, tk.k_slot);
            else if (tk.magic != 0)
                err("bootstrap takeover journal: invalid (magic 0x%08x)", tk.magic);
        }
    }
    if (r.state == 5)
        err("bootstrap: REFUSED slot=%u reason=%u (1=terminal slice, 2=unclassified key, 3=fence unproven, 4=reconcile, 5=inheritance unproven) — a sealed victim could not be recovered; ACTIVE admission stays refused until the named verdict is repaired and the record is cleared",
            r.refused_slot, r.refused_reason);
    else if (r.state != 0 && r.state != 4)
        info("bootstrap: WARNING a recovery is claimed (%s) — ACTIVE admission is refused until it completes",
             bs_state(r.state));
}

/*
 * 0.88.0: the SLICE LIFECYCLE records (mxfs_super.h, struct
 * mxfs_slife_record; D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531).  One per
 * log slice.  INIT_REQUIRED means mkfs wrote it and no node has claimed the
 * slot yet: the payload is whatever the format's userspace zero left, which
 * the kernel treats as untrusted.  ZEROING means a claimant started the FUA
 * zero and did not persist READY — a crash there, or a target that refused
 * to persist the zero; the next claimant restarts the whole zero.  READY
 * means the payload was zeroed through the kernel FUA path and read back,
 * and the slice has been (or may be) journaled into by this incarnation.
 * A record that is missing, malformed or another volume's is an error: the
 * kernel refuses to mount that slot on it.
 */
static const char *slife_state(uint32_t s)
{
    switch (s) {
    case MXFS_SLIFE_INIT_REQUIRED: return "INIT_REQUIRED";
    case MXFS_SLIFE_ZEROING:       return "ZEROING";
    case MXFS_SLIFE_READY:         return "READY";
    default:                       return "?";
    }
}

static void check_slife(int fd, const struct mxfs_ondisk_super *s)
{
    struct mxfs_slife_record r, t;
    uint32_t i, c, n_init = 0, n_zeroing = 0, n_ready = 0, n_bad = 0;
    char fu[37];

    if (!(s->flags & MXFS_FORMAT_F_SLIFE))
        return;
    for (i = 0; i < s->xfs_log_node_count; i++) {
        off_t off = (off_t)(s->slife_offset + (uint64_t)i * MXFS_SLIFE_RECORD_SIZE);

        if (read_at(fd, &r, sizeof(r), off) < 0) {
            err("slice lifecycle[%u]: read failed", i);
            n_bad++;
            continue;
        }
        if (r.magic == 0) {
            err("slice lifecycle[%u]: UNFORMATTED (magic 0) — mkfs never wrote it; the kernel refuses to mount slot %u", i, i);
            n_bad++;
            continue;
        }
        t = r;
        t.crc = 0;
        c = crc32c(~0U, &t, sizeof(t));
        if (r.magic != MXFS_SLIFE_MAGIC || r.version != MXFS_SLIFE_VERSION ||
            r.slice != i || r.state < MXFS_SLIFE_INIT_REQUIRED ||
            r.state > MXFS_SLIFE_READY || c != r.crc) {
            err("slice lifecycle[%u]: invalid (magic 0x%08x ver %u slice %u state %u crc 0x%08x want 0x%08x)",
                i, r.magic, r.version, r.slice, r.state, r.crc, c);
            n_bad++;
            continue;
        }
        if (memcmp(r.fs_uuid, s->fs_uuid, 16) != 0) {
            hex_uuid(r.fs_uuid, fu);
            err("slice lifecycle[%u]: fs_uuid %s is not this volume's", i, fu);
            n_bad++;
            continue;
        }
        switch (r.state) {
        case MXFS_SLIFE_INIT_REQUIRED: n_init++; break;
        case MXFS_SLIFE_ZEROING:       n_zeroing++; break;
        default:                       n_ready++; break;
        }
        if (verbose || r.state == MXFS_SLIFE_ZEROING)
            info("slice lifecycle[%u]: %s gen=%u owner=%llu/%llu when_ms=%llu",
                 i, slife_state(r.state), r.generation,
                 (unsigned long long)r.owner_node,
                 (unsigned long long)r.owner_epoch,
                 (unsigned long long)r.when_ms);
    }
    printf("Slice lifecycle ......... %s  (%u slices: %u INIT_REQUIRED, %u ZEROING, %u READY, %u invalid)\n",
           n_bad == 0 ? "OK" : "ERRORS", s->xfs_log_node_count,
           n_init, n_zeroing, n_ready, n_bad);
    if (n_zeroing)
        info("slice lifecycle: %u slice(s) ZEROING — a claimant's zero did not reach READY; the slot's next claimant restarts it", n_zeroing);
}

/*
 * (docs/whole-cluster-restart.md §6.6/§6.7): `--clear-bootstrap`.
 * A whole-cluster bootstrap term that ended REFUSED is terminal for the
 * kernel: no node can claim, resume or take it over, and ACTIVE admission
 * stays closed.  Only the operator, having repaired what the refusal names,
 * may hand the record back to IDLE.  OFFLINE ONLY, and every pre-check fails
 * closed:
 *   - the device opens O_EXCL (not mounted here);
 *   - no ACTIVE heartbeat advances across 3 s (not mounted anywhere);
 *   - the record validates and is REFUSED (a CLAIMED/SEALED/RECOVERING term
 *     is somebody's live or resumable claim — never cleared from here; the
 *     owner resumes it, or a peer takes it over by fencing the owner);
 *   - a TERMINAL_SLICE refusal names a slot: that sector must no longer
 *     carry a recovery descriptor (`--accept-quarantine-loss` first), else
 *     the same verdict refuses the next term on the spot.
 * What is written: state IDLE, term/seq carried forward (the next claim is
 * term+1, strictly above every certificate ever minted), the refused owner
 * recorded in prev_owner_* with prev_fence_kind = 0 (no fence: the operator
 * cleared it), everything else zeroed, crc sealed.
 */
/*
 * `--bootstrap`: print the whole-cluster bootstrap record and exit.
 *
 * Read-only and WITHOUT O_EXCL, deliberately.  The record is exactly what an
 * operator needs when a mount is refused because a bootstrap term is claimed —
 * and at that moment the ordinary check cannot be run, because some other node
 * may still hold the device and the full check wants it to itself.  This one
 * answers from a mounted node and from an unmounted one.
 *
 * The live sectors are read O_DIRECT.  A buffered read of a shared device
 * returns whatever this node's page cache captured the first time anything
 * touched it, which on a volume another node is actively writing is an image
 * of the past presented as the present.  The envelope superblock is mkfs-time
 * and constant, so it may come through the ordinary fd.
 *
 * One machine-readable BOOTSTRAP line first, so a harness can assert on it
 * without parsing prose, then the escrow detail when there is any.
 */
static int do_bootstrap_show(const char *device)
{
    struct mxfs_ondisk_super sup;
    struct chk_bootstrap_rec r, t;
    uint8_t supbuf[MXFS_SUPER_SIZE];
    uint8_t *aligned = NULL;
    char hu[37], bu[37];
    uint64_t base;
    uint32_t c;
    int fd = -1, dfd = -1, rc = 4;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n",
                device, strerror(errno));
        return 4;
    }
    if (read_at(fd, supbuf, MXFS_SUPER_SIZE, 0) < 0) {
        fprintf(stderr, "chk_mxfs: cannot read the MXFS envelope\n");
        goto out;
    }
    memcpy(&sup, supbuf, sizeof(sup));
    if (sup.magic != MXFS_FORMAT_MAGIC ||
        !(sup.flags & MXFS_FORMAT_F_BOOTSTRAP)) {
        fprintf(stderr, "chk_mxfs: no MXFS envelope with a bootstrap record "
                "region on %s\n", device);
        goto out;
    }
    dfd = open(device, O_RDONLY | O_DIRECT);
    if (dfd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s O_DIRECT: %s\n",
                device, strerror(errno));
        goto out;
    }
    if (posix_memalign((void **)&aligned, 4096, 4096) != 0) {
        fprintf(stderr, "chk_mxfs: out of memory\n");
        goto out;
    }
    base = sup.bootstrap_offset & ~(uint64_t)4095;
    if (read_at(dfd, aligned, 4096, (off_t)base) < 0) {
        fprintf(stderr, "chk_mxfs: cannot read the bootstrap record\n");
        goto out;
    }
    memcpy(&r, aligned + (sup.bootstrap_offset - base), sizeof(r));
    if (r.magic == 0) {
        printf("BOOTSTRAP unformatted — mkfs never wrote the record; the "
               "kernel fails closed on this\n");
        goto out;
    }
    if (r.magic != MXFS_BOOTSTRAP_MAGIC_C || r.ver != 5) {
        printf("BOOTSTRAP unreadable magic=0x%08x ver=%u (this build reads "
               "v5)\n", r.magic, r.ver);
        goto out;
    }
    t = r;
    t.crc32c = 0;
    c = crc32c(~0U, &t, sizeof(t));
    hex_uuid(r.owner_host_uuid, hu);
    hex_uuid(r.owner_boot_uuid, bu);
    printf("BOOTSTRAP state=%s(%u) term=%llu seq=%llu owner=%u/%llu "
           "key=0x%016llx key_gen=%u host=%s boot=%s victims=0x%016llx "
           "complete=0x%016llx registrants=%u/%u escrow=%u K=%u prev=%u/%llu "
           "prev_kind=%u lineage=%u episode=%llu refused_slot=%u "
           "refused_reason=%u crc=%s\n",
           bs_state(r.state), r.state, (unsigned long long)r.term,
           (unsigned long long)r.seq, r.owner_node,
           (unsigned long long)r.owner_epoch,
           (unsigned long long)r.owner_pr_key, r.owner_key_gen,
           r.state ? hu : "-", r.state ? bu : "-",
           (unsigned long long)r.victim_bitmap,
           (unsigned long long)r.complete_bitmap,
           r.registrants_done, r.registrants, r.escrow.state, r.escrow.slot,
           r.prev_owner_node, (unsigned long long)r.prev_owner_epoch,
           r.prev_fence_kind, r.lineage_count,
           (unsigned long long)r.episode_term, r.refused_slot,
           r.refused_reason, c == r.crc32c ? "OK" : "BAD");
    if (r.escrow.state != 0) {
        char vh[37], vb[37];

        hex_uuid(r.escrow.victim_host, vh);
        hex_uuid(r.escrow.victim_boot, vb);
        printf("BOOTSTRAP-ESCROW state=%u K=%u cls=%u victim=%u/%llu "
               "key=0x%016llx key_gen=%u host=%s boot=%s old_crc=0x%08x "
               "claim=%u/%llu replay_rc=%d\n",
               r.escrow.state, r.escrow.slot, r.escrow.cls,
               r.escrow.victim_node, (unsigned long long)r.escrow.victim_epoch,
               (unsigned long long)r.escrow.victim_key, r.escrow.victim_key_gen,
               vh, vb, r.escrow.old_sector_crc, r.escrow.claim_node,
               (unsigned long long)r.escrow.claim_epoch, r.escrow.replay_rc);
    }
    rc = c == r.crc32c ? 0 : 4;
out:
    free(aligned);
    if (dfd >= 0)
        close(dfd);
    if (fd >= 0)
        close(fd);
    return rc;
}

static int do_clear_bootstrap(const char *device)
{
    struct mxfs_ondisk_super sup;
    struct chk_bootstrap_rec r, t;
    uint8_t buf[MXFS_SUPER_SIZE];
    uint8_t sec[512];
    uint64_t hb_ts[64], hb_epoch[64];
    bool hb_active[64];
    uint32_t slot, nlive = 0, c;
    int fd, rc;
    struct hb_hdr {
        uint32_t magic, flags, node_id, fs_gen;
        uint64_t timestamp_ms, epoch;
    } __attribute__((packed)) *h = (void *)sec;

    fd = open(device, O_RDWR | O_EXCL);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s exclusively: %s (is it "
                "mounted?)\n", device, strerror(errno));
        return 4;
    }
    if (read_at(fd, buf, MXFS_SUPER_SIZE, 0) < 0) {
        close(fd);
        return 4;
    }
    memcpy(&sup, buf, sizeof(sup));
    if (sup.magic != MXFS_FORMAT_MAGIC || !(sup.flags & MXFS_FORMAT_F_BOOTSTRAP)) {
        fprintf(stderr, "clear-bootstrap: no MXFS envelope with a bootstrap "
                "record region on this device\n");
        close(fd);
        return 4;
    }
    for (slot = 0; slot < 64; slot++) {
        hb_active[slot] = false;
        if (read_at(fd, sec, 512, sup.disklock_offset + (uint64_t)slot * 512) < 0) {
            close(fd);
            return 4;
        }
        if (h->magic == 0x4D584C4B && h->flags == 1) {
            hb_active[slot] = true;
            hb_ts[slot] = h->timestamp_ms;
            hb_epoch[slot] = h->epoch;
        }
    }
    printf("clear-bootstrap: rechecking heartbeat liveness (3 s)...\n");
    sleep(3);
    for (slot = 0; slot < 64; slot++) {
        if (!hb_active[slot])
            continue;
        if (read_at(fd, sec, 512, sup.disklock_offset + (uint64_t)slot * 512) < 0) {
            close(fd);
            return 4;
        }
        if (h->magic == 0x4D584C4B && h->flags == 1 &&
            (h->timestamp_ms != hb_ts[slot] || h->epoch != hb_epoch[slot])) {
            fprintf(stderr, "clear-bootstrap: heartbeat slot %u is LIVE (node "
                    "%u) — a node still has this filesystem mounted; unmount "
                    "everywhere first\n", slot, h->node_id);
            nlive++;
        }
    }
    if (nlive) {
        close(fd);
        return 4;
    }
    if (read_at(fd, &r, sizeof(r), (off_t)sup.bootstrap_offset) < 0) {
        close(fd);
        return 4;
    }
    if (r.magic != MXFS_BOOTSTRAP_MAGIC_C || r.ver != 5) {
        fprintf(stderr, "clear-bootstrap: record magic 0x%08x ver %u — not a "
                "valid record; nothing written\n", r.magic, r.ver);
        close(fd);
        return 4;
    }
    t = r;
    t.crc32c = 0;
    c = crc32c(~0U, &t, sizeof(t));
    if (c != r.crc32c || memcmp(r.fs_uuid, sup.fs_uuid, 16) != 0) {
        fprintf(stderr, "clear-bootstrap: record crc/volume mismatch; nothing "
                "written\n");
        close(fd);
        return 4;
    }
    if (r.state != 5) {
        fprintf(stderr, "clear-bootstrap: record is %s, not REFUSED — %s; "
                "nothing written\n", bs_state(r.state),
                r.state == 0 ? "there is nothing to clear" :
                r.state == 4 ? "the last bootstrap completed; ordinary "
                               "membership retires it" :
                "a claimed term belongs to its owner (same-boot resume) or to "
                "the peer that fences the owner (takeover); an operator may "
                "not clear it");
        close(fd);
        return 4;
    }
    if (r.refused_reason == 1 && r.refused_slot < 64) {
        if (read_at(fd, sec, 512,
                    sup.disklock_offset + (uint64_t)r.refused_slot * 512) < 0) {
            close(fd);
            return 4;
        }
        if (h->magic == 0x4D584C4B && h->flags == 3 /* RECOVERY_GUARD */) {
            fprintf(stderr, "clear-bootstrap: the refusal names slot %u "
                    "(terminal slice) and that sector still carries a recovery "
                    "descriptor — the next term would refuse on the same "
                    "verdict.  Repair it first (--show-quarantine / "
                    "--accept-quarantine-loss); nothing written\n",
                    r.refused_slot);
            close(fd);
            return 4;
        }
    }
    printf("clear-bootstrap: REFUSED term=%llu owner=%u/%llu key=0x%llx "
           "slot=%u reason=%u escrow=%s K=%u -> IDLE (term carried forward)\n",
           (unsigned long long)r.term, r.owner_node,
           (unsigned long long)r.owner_epoch,
           (unsigned long long)r.owner_pr_key, r.refused_slot,
           r.refused_reason, bs_escrow_name(r.escrow.state), r.escrow.slot);
    t = r;
    t.state = 0;
    t.seq = r.seq + 1;
    t.stamp_ms = 0;
    t.prev_owner_node = r.owner_node;
    t.prev_owner_epoch = r.owner_epoch;
    t.prev_owner_pr_key = r.owner_pr_key;
    t.prev_fence_kind = 0;              /* operator clear, no fence */
    t.owner_node = 0;
    t.owner_key_gen = 0;
    t.owner_epoch = 0;
    t.owner_pr_key = 0;
    t.owner_nonce = 0;
    memset(t.owner_host_uuid, 0, 16);
    memset(t.owner_boot_uuid, 0, 16);
    t.host_src = 0;
    t.victim_bitmap = 0;
    t.complete_bitmap = 0;
    t.ledger_gen = 0;
    t.manifest_hash = 0;
    t.registrants = 0;
    t.registrants_done = 0;
    t.claim_stamp_ms = 0;
    t.seal_stamp_ms = 0;
    t.complete_stamp_ms = 0;
    t.refused_slot = 0;
    t.refused_reason = 0;
    memset(&t.escrow, 0, sizeof(t.escrow));
    t.episode_term = 0;                 /* the next claim opens an episode */
    t.lineage_count = 0;
    t.takeover_gen = 0;
    memset(t.reserved, 0, sizeof(t.reserved));
    t.crc32c = 0;
    t.crc32c = crc32c(~0U, &t, sizeof(t));
    /* a stale takeover journal must not outlive the term it names */
    memset(sec, 0, sizeof(sec));
    rc = write_at(fd, sec, 512, (off_t)(sup.bootstrap_offset +
                                        (uint64_t)CHK_BOOT_SEC_TAKEOVER * 512));
    if (rc == 0)
        rc = write_at(fd, &t, sizeof(t), (off_t)sup.bootstrap_offset);
    if (rc == 0)
        rc = fsync(fd);
    if (rc) {
        fprintf(stderr, "clear-bootstrap: write failed: %s\n", strerror(errno));
        close(fd);
        return 4;
    }
    if (read_at(fd, &r, sizeof(r), (off_t)sup.bootstrap_offset) < 0 ||
        memcmp(&r, &t, sizeof(r)) != 0) {
        fprintf(stderr, "clear-bootstrap: read-back mismatch\n");
        close(fd);
        return 4;
    }
    close(fd);
    printf("clear-bootstrap: record is IDLE; the next mount after a total "
           "outage may claim term %llu\n", (unsigned long long)(t.term + 1));
    return 0;
}

static void check_prledger(int fd, const struct mxfs_ondisk_super *s)
{
    struct chk_prledger_entry e, t;
    uint32_t n, i, owned = 0, retired = 0, fenced = 0, bad = 0;
    int pre_errors = errors;

    if (!(s->flags & MXFS_FORMAT_F_PRKEY64))
        return;
    n = (uint32_t)(s->prkey_size / MXFS_PRLEDGER_ENTRY_BYTES);
    for (i = 0; i < n; i++) {
        uint32_t c;
        char host[37], boot[37];

        if (read_at(fd, &e, sizeof(e),
                    s->prkey_offset + (uint64_t)i * MXFS_PRLEDGER_ENTRY_BYTES) < 0) {
            err("prledger entry %u: read failed", i);
            continue;
        }
        if (e.magic == 0)
            continue;
        if (e.magic != MXFS_PRLEDGER_MAGIC_C) {
            err("prledger entry %u: magic 0x%08x", i, e.magic);
            bad++;
            continue;
        }
        t = e;
        t.crc32c = 0;
        c = crc32c(~0U, &t, sizeof(t));
        c = crc32c(c, &i, sizeof(i));
        if (c != e.crc32c || e.state > 4) {
            err("prledger entry %u: crc expected 0x%08X got 0x%08X state=%u",
                i, c, e.crc32c, e.state);
            bad++;
            continue;
        }
        hex_uuid(e.host_uuid, host);
        hex_uuid(e.boot_uuid, boot);
        if (e.state == 1 || e.state == 2)
            owned++;
        else if (e.state == 3)
            retired++;
        else if (e.state == 4)
            fenced++;
        if (verbose || e.state == 1 || e.state == 2)
            info("prledger entry %u: %s key=0x%llx gen=%u node=%u host=%s "
                 "boot=%s seq=%llu%s succeeds=0x%llx", i, prl_state(e.state),
                 (unsigned long long)e.pr_key, e.key_gen, e.node_id, host,
                 boot, (unsigned long long)e.seq,
                 e.state == 4 ? " (fenced)" : "",
                 (unsigned long long)e.succ_old_key);
    }
    printf("PR registrant ledger .... %s  (%u entries: %u owned, %u retired, "
           "%u fenced, %u bad)\n",
           errors == pre_errors ? "OK" : "ERRORS", n, owned, retired, fenced,
           bad);
}

static void check_tauth(int fd, const struct mxfs_ondisk_super *s)
{
    struct mxfs_tauth_region_hdr *rh;
    struct mxfs_tauth_page *pa, *pb;
    uint32_t fs_gen = mxfs_tauth_fs_gen(s->fs_uuid);
    uint32_t hdr_ok = 0, two = 0, one = 0, none = 0, p;
    uint32_t npages = 0;
    uint64_t hash_seed = 0;
    uint64_t maxseq = 0;
    unsigned c;

    if (!(s->flags & MXFS_FORMAT_F_TAUTH))
        return;
    rh = calloc(1, sizeof(*rh));
    pa = calloc(1, sizeof(*pa));
    pb = calloc(1, sizeof(*pb));
    if (!rh || !pa || !pb) {
        err("out of memory checking the authority ledger");
        free(rh); free(pa); free(pb);
        return;
    }
    for (c = 0; c < MXFS_TAUTH_HDR_COPIES; c++) {
        if (read_at(fd, rh, sizeof(*rh), s->tauth_offset + mxfs_tauth_hdr_off(c)) < 0)
            continue;
        if (mxfs_tauth_region_valid(rh, fs_gen, crc32c) &&
            memcmp(rh->fs_uuid, s->fs_uuid, 16) == 0) {
            if (hdr_ok && (rh->npages != npages || rh->hash_seed != hash_seed))
                err("authority ledger: header copies disagree on geometry (%u/%016llx vs %u/%016llx)",
                    rh->npages, (unsigned long long)rh->hash_seed,
                    npages, (unsigned long long)hash_seed);
            npages = rh->npages;
            hash_seed = rh->hash_seed;
            hdr_ok++;
        }
    }
    if (!hdr_ok) {
        err("authority ledger: no valid region header (unformatted, corrupt, or a pre-v2 format)");
        free(rh); free(pa); free(pb);
        return;
    }
    if (MXFS_TAUTH_REGION_BYTES_FOR(npages) > s->tauth_size) {
        err("authority ledger: header geometry (%u pages = %llu bytes) exceeds the envelope region (%llu)",
            npages, (unsigned long long)MXFS_TAUTH_REGION_BYTES_FOR(npages),
            (unsigned long long)s->tauth_size);
        free(rh); free(pa); free(pb);
        return;
    }
    for (p = 0; p < npages; p++) {
        int va = 0, vb = 0;

        if (read_at(fd, pa, sizeof(*pa),
                    s->tauth_offset + mxfs_tauth_page_off(npages, p, 0)) == 0)
            va = mxfs_tauth_page_valid(pa, p, fs_gen, crc32c);
        if (read_at(fd, pb, sizeof(*pb),
                    s->tauth_offset + mxfs_tauth_page_off(npages, p, 1)) == 0)
            vb = mxfs_tauth_page_valid(pb, p, fs_gen, crc32c);
        if (va && pa->hdr.seq > maxseq)
            maxseq = pa->hdr.seq;
        if (vb && pb->hdr.seq > maxseq)
            maxseq = pb->hdr.seq;
        if (va && vb)
            two++;
        else if (va || vb)
            one++;
        else {
            none++;
            if (none <= 8)
                err("authority ledger page %u: NO valid copy — every resource on it is UNKNOWN", p);
        }
    }
    printf("TCP authority ledger .... %s  (hdr_copies=%u pages=%u records=%llu seed=%016llx two=%u one=%u none=%u maxseq=%llu)\n",
           (hdr_ok && none == 0) ? "OK" : "ERRORS", hdr_ok, npages,
           (unsigned long long)npages * MXFS_TAUTH_ENTRIES_PER_PAGE,
           (unsigned long long)hash_seed, two, one, none,
           (unsigned long long)maxseq);
    check_tauth_ctrl(fd, s, fs_gen);
    free(rh); free(pa); free(pb);
}

/* ─── Check: Journal Region ─── */

static void check_journal(int fd, const struct mxfs_ondisk_super *super)
{
    uint8_t buf[512];
    uint64_t joff = super->journal_offset;
    int pre_errors = errors;

    /* Read journal superblock (first 512 bytes) */
    if (read_at(fd, buf, 512, joff) < 0) {
        printf("Journal ................. READ ERROR\n");
        return;
    }

    /* Journal super: native byte order (same as MXFS super) */
    uint32_t jmagic   = *(uint32_t *)(buf + 0);
    uint32_t jversion = *(uint32_t *)(buf + 4);
    uint32_t slot_count      = *(uint32_t *)(buf + 8);
    uint32_t slot_size_sect  = *(uint32_t *)(buf + 12);
    /* uint32_t sector_size  = *(uint32_t *)(buf + 16); */
    uint32_t jcrc_stored     = *(uint32_t *)(buf + 20);

    if (jmagic != MXFS_JOURNAL_MAGIC) {
        err("journal super magic: expected 0x%08X, got 0x%08X",
            MXFS_JOURNAL_MAGIC, jmagic);
    }

    if (jversion != MXFS_JOURNAL_VERSION) {
        err("journal super version: expected %u, got %u",
            MXFS_JOURNAL_VERSION, jversion);
    }

    /* CRC: zero the crc field at offset 20, compute over 512 bytes */
    {
        uint32_t *crc_field = (uint32_t *)(buf + 20);
        uint32_t saved = *crc_field;
        *crc_field = 0;
        uint32_t computed = crc32c(~0U, buf, 512);
        *crc_field = saved;

        if (computed != jcrc_stored) {
            err("journal super CRC: stored=0x%08X, computed=0x%08X",
                jcrc_stored, computed);

            if (can_repair() && jmagic == MXFS_JOURNAL_MAGIC) {
                if (mxfs_fix_crc_and_write(fd, buf, 512, 20, joff) == 0) {
                    printf("  REPAIRED: journal super CRC recomputed\n");
                    repaired++;
                }
            }
        }
    }

    /* Check slot count is reasonable */
    if (slot_count == 0 || slot_count > 1024) {
        err("journal slot_count=%u (expected 1..1024)", slot_count);
        printf("Journal ................. ERRORS\n");
        return;
    }

    /* Per-slot header check */
    int dirty = 0, clean = 0;
    uint64_t slot_bytes = (uint64_t)slot_size_sect * MXFS_JOURNAL_SECTOR_SIZE;

    for (uint32_t i = 0; i < slot_count; i++) {
        uint64_t slot_off = joff + 512 + i * slot_bytes;

        if (read_at(fd, buf, 512, slot_off) < 0) {
            err("journal slot %u: read failed", i);
            continue;
        }

        uint32_t smagic = *(uint32_t *)(buf + 0);
        uint32_t sflags = *(uint32_t *)(buf + 4);
        uint32_t sowner = *(uint32_t *)(buf + 8);
        uint32_t scrc_stored = *(uint32_t *)(buf + 20);

        if (smagic != MXFS_JOURNAL_MAGIC) {
            err("journal slot %u: magic expected 0x%08X, got 0x%08X",
                i, MXFS_JOURNAL_MAGIC, smagic);
            continue;
        }

        /* CRC: zero field at offset 20, compute over 512 bytes */
        {
            uint32_t *crc_field = (uint32_t *)(buf + 20);
            uint32_t saved = *crc_field;
            *crc_field = 0;
            uint32_t computed = crc32c(~0U, buf, 512);
            *crc_field = saved;

            if (computed != scrc_stored) {
                err("journal slot %u: CRC stored=0x%08X, computed=0x%08X",
                    i, scrc_stored, computed);

                if (can_repair() && !(sflags & MXFS_JOURNAL_SLOT_FLAG_DIRTY)) {
                    if (mxfs_fix_crc_and_write(fd, buf, 512, 20, slot_off) == 0) {
                        printf("  REPAIRED: journal slot %u CRC recomputed\n", i);
                        repaired++;
                    }
                }
            }
        }

        if (sflags & MXFS_JOURNAL_SLOT_FLAG_DIRTY) {
            dirty++;
            info("slot %u: DIRTY (owner=%u)", i, sowner);

            /* Repair: clear dirty slot flag and rewrite */
            if (can_repair()) {
                *(uint32_t *)(buf + 4) = MXFS_JOURNAL_SLOT_FLAG_CLEAN;
                /* Recompute CRC: zero field at offset 20, compute, store */
                uint32_t *crc_f = (uint32_t *)(buf + 20);
                *crc_f = 0;
                *crc_f = crc32c(~0U, buf, 512);
                if (write_at(fd, buf, 512, slot_off) == 0) {
                    printf("  REPAIRED: journal slot %u cleared (was dirty, owner=%u)\n",
                           i, sowner);
                    repaired++;
                    dirty--;
                    clean++;
                }
            }
        } else {
            clean++;
            if (verbose)
                info("slot %u: clean (owner=%u)", i, sowner);
        }
    }

    int jerrors = errors - pre_errors;
    if (jerrors == 0) {
        printf("Journal ................. OK  (%u slots, %d clean, %d dirty)\n",
               slot_count, clean, dirty);
    } else {
        printf("Journal ................. ERRORS (%d errors)\n", jerrors);
    }
}

/* ─── Check: Disklock Region ─── */

/* CRC32C (Castagnoli), kernel crc32c() semantics: raw reflected table,
 * poly 0x82F63B78, seed as-is, no pre/post inversion.  Matches
 * mxfs_pal_crc32c on both sides of the record. */
static uint32_t crc32c_raw(uint32_t crc, const void *data, size_t len)
{
    static uint32_t table[256];
    static int init;
    const uint8_t *p = data;

    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;

            for (int j = 0; j < 8; j++)
                c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
            table[i] = c;
        }
        init = 1;
    }
    while (len--)
        crc = (crc >> 8) ^ table[(crc & 0xFF) ^ *p++];
    return crc;
}

/* ─── Terminal recovery quarantine (D-QUARANTINED-SLOT-…-376) ───────────────
 *
 * A terminal replay refusal turns the victim's heartbeat slot into a
 * RECOVERY_GUARD record whose body carries the durable verdict: a
 * mxfs_recov_desc at byte 40 and a mxfs_recov_outcome at byte 160.  That
 * record is the ONLY copy of the verdict, and until the repair path
 * exists nothing can clear it — so the very first thing an operator needs is
 * to be able to READ it offline.  Before this, they could not: chk_mxfs did
 * not decode the body, caw_slotdump is a CAW-region tool, and the kernel's
 * /sys/kernel/debug/mxfs/<dev>/recovery_blocked only exists on a node that
 * managed to MOUNT — which is exactly what a quarantine can prevent.
 *
 * Layouts duplicated from dlm/disklock.h to keep this tool a standalone
 * single-file build; the _Static_asserts below mirror the ones there, so a
 * layout change in the kernel header breaks this compile instead of silently
 * decoding garbage.
 */
#define MXFS_DISKLOCK_FLAG_WITHDRAWN_C       2
#define MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C  3
#define MXFS_DISKLOCK_FLAG_RETIRE_PENDING_C  4   /* */

#define MXFS_RECOV_DESC_OFF_C       40      /* 40B header, then the body union */
#define MXFS_RECOV_OUTCOME_OFF_C    (MXFS_RECOV_DESC_OFF_C + 120)

#define MXFS_RECOV_DESC_MAGIC_C     0x5643524Du  /* "MRCV" LE */
#define MXFS_RECOV_DESC_VERSION_C   3   /* SNAPSHOTTING + manifest pointer */
#define MXFS_RECOV_OUTCOME_MAGIC_C  0x4F435652u  /* "RVCO" LE */

#define MXFS_RECOV_F_QUARANTINED_C  0x00000001u

#define MXFS_RECOV_OUTCOME_TERMINAL_REFUSED_C           1u
#define MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE_C    1u
#define MXFS_RECOV_REFUSAL_PHYSICALLY_TORN_C            2u
#define MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE_C   3u
#define MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED_C          4u  /* */
#define MXFS_RECOV_REFUSAL_MANIFEST_INVALID_C           5u  /* */
#define MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY_C     6u  /* */
#define MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED_C       8u  /* */
#define MXFS_RECOV_DOMAIN_FSWIDE_C      1u
#define MXFS_RECOV_DOMAIN_AG_MASK_C     2u
#define MXFS_RECOV_OUTCOME_F_DIGEST_VALID_C  (1u << 0)

struct chk_recov_desc {
    uint32_t magic; uint16_t version; uint16_t stage;
    uint64_t victim_epoch; uint64_t owner_epoch; uint64_t recovery_gen;
    uint64_t owner_stamp_ms;
    uint32_t victim_node; uint32_t owner_node; uint32_t victim_fs_gen;
    uint32_t flags;
    uint16_t victim_slot; uint16_t owner_slot;
    uint16_t slice_idx; uint16_t slice_count;
    uint64_t stage_seq; uint32_t owner_term;
    uint16_t fence_kind; uint16_t fence_resv_type;
    uint64_t fence_victim_key; uint64_t fence_prover_epoch;
    uint64_t fence_stamp_ms;
    uint32_t fence_prover_node; uint32_t fence_pr_gen; uint32_t fence_term;
    uint32_t crc32c;
} __attribute__((packed));

struct chk_recov_outcome {
    uint32_t magic; uint16_t version; uint16_t outcome;
    uint16_t reason; uint16_t domain_kind;
    uint16_t victim_slot; uint16_t owner_slot;
    uint64_t victim_epoch; uint64_t owner_epoch; uint64_t recovery_gen;
    uint64_t ag_mask; uint64_t slice_digest; uint64_t publish_seq;
    uint32_t victim_node; uint32_t victim_fs_gen;
    uint32_t owner_node; uint32_t owner_term;
    uint32_t refused_items; uint32_t malformed_items; uint32_t flags;
    uint32_t crc32c;
} __attribute__((packed));

_Static_assert(sizeof(struct chk_recov_desc) == 120,
               "chk_recov_desc must match dlm/disklock.h mxfs_recov_desc (120B)");
_Static_assert(offsetof(struct chk_recov_desc, fence_kind) == 76,
               "the v2 certificate starts at byte 76");
_Static_assert(offsetof(struct chk_recov_desc, crc32c) == 116,
               "the descriptor crc must remain the last field");
_Static_assert(sizeof(struct chk_recov_outcome) == 96,
               "chk_recov_outcome must match dlm/disklock.h mxfs_recov_outcome (96B)");
_Static_assert(offsetof(struct chk_recov_outcome, crc32c) == 92,
               "the outcome crc must remain the last field");

/*
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED item 5, increment 2): the
 * OBLIGATION RECORD at recovery-body byte 280 (sector byte 320) and the
 * OBLIGATION LIST in the victim's rman slot zone [4 KiB, 64 KiB).  Mirrors
 * dlm/recov_obl.h byte for byte; the validation here reproduces
 * mxfs_recov_obl_rec_check / mxfs_rman_obl_hdr_check so the checker and the
 * kernel can never disagree about what a record IS.
 */
#define MXFS_RECOV_OBL_OFF_C        (MXFS_RECOV_DESC_OFF_C + 280)
#define MXFS_RECOV_OBL_MAGIC_C      0x424F5652u  /* "RVOB" LE */
#define MXFS_RECOV_OBL_VERSION_C    1
#define MXFS_RECOV_OBL_F_TERMINAL_C (1u << 0)
#define MXFS_RECOV_OBL_F_FSWIDE_C   (1u << 1)
#define MXFS_RECOV_OBL_F_LIST_C     (1u << 2)
#define MXFS_RECOV_OBL_F_DONE_C     (1u << 3)   /* completion proven + OBLIGATIONS_DONE */
#define MXFS_RECOV_OBL_F_ALL_C      15u
/* the completion proof block (dlm/recov_obl_done.h), slot-relative */
#define MXFS_RMAN_OBL_DONE_OFF_C    57344u  /* 56 KiB */
#define MXFS_RMAN_OBL_DONE_BYTES_C  4096u
#define MXFS_RMAN_OBL_DONE_MAGIC_C  0x444F584Du  /* "MXOD" LE */
#define MXFS_RMAN_OBL_DONE_VERSION_C 1
#define MXFS_RMAN_OBL_DONE_F_COMMITTED_C (1u << 0)
#define MXFS_RMAN_OBL_DONE_BITMAP_BYTES_C 384u
#define MXFS_RMAN_OBL_OFF_C         4096u
#define MXFS_RMAN_OBL_HDR_BYTES_C   4096u
#define MXFS_RMAN_OBL_ENTRIES_OFF_C 8192u
#define MXFS_RECOV_OBL_MAX_EXTENTS_C 3072u
#define MXFS_RMAN_OBL_MAGIC_C       0x424F584Du  /* "MXOB" LE */
#define MXFS_RMAN_OBL_VERSION_C     1

struct chk_recov_obl {
    uint32_t magic; uint16_t version; uint16_t flags;
    uint64_t obl_ag_mask;
    uint32_t count; uint32_t list_crc32c;
    uint64_t census_digest;
    uint32_t pub_seq; uint32_t crc32c;
} __attribute__((packed));

struct chk_recov_obl_ext {
    uint64_t fsbno; uint32_t agno; uint32_t len;
} __attribute__((packed));

struct chk_rman_obl_hdr {
    uint32_t magic; uint16_t version; uint16_t flags;
    uint64_t seq; uint64_t recovery_gen; uint64_t victim_epoch;
    uint32_t victim_node; uint32_t victim_fs_gen;
    uint16_t victim_slot; uint16_t slice_idx; uint16_t slice_count;
    uint16_t entry_bytes;
    uint32_t count; uint32_t byte_len; uint32_t entries_crc32c;
    uint32_t publisher_node;
    uint64_t publisher_epoch;
    uint32_t publisher_term; uint32_t agcount;
    uint64_t census_digest; uint64_t obl_ag_mask; uint64_t stamp_ms;
    uint32_t agblocks; uint32_t hdr_crc32c;
    uint8_t  pad[MXFS_RMAN_OBL_HDR_BYTES_C - 112];
} __attribute__((packed));

_Static_assert(sizeof(struct chk_recov_obl) == 40,
               "chk_recov_obl must match dlm/recov_obl.h mxfs_recov_obl (40B)");
_Static_assert(offsetof(struct chk_recov_obl, crc32c) == 36,
               "the obligation record crc must remain the last field");
_Static_assert(sizeof(struct chk_recov_obl_ext) == 16,
               "chk_recov_obl_ext must match dlm/recov_obl.h (16B)");
_Static_assert(sizeof(struct chk_rman_obl_hdr) == 4096 &&
               offsetof(struct chk_rman_obl_hdr, hdr_crc32c) == 108,
               "chk_rman_obl_hdr must match dlm/recov_obl.h mxfs_rman_obl_hdr");

struct chk_rman_obl_done {
    uint32_t magic; uint16_t version; uint16_t flags;
    uint32_t length; uint32_t rman_slot;
    uint64_t recovery_gen; uint64_t victim_epoch;
    uint32_t victim_node; uint32_t victim_fs_gen;
    uint8_t  fs_uuid[16];
    uint32_t pub_seq; uint32_t count; uint32_t list_crc32c; uint32_t hdr_crc32c;
    uint64_t obl_ag_mask;
    uint32_t n_empty; uint32_t n_full; uint32_t n_sparse; uint32_t owner_term;
    uint64_t stage_seq; uint64_t rcpt_digest;
    uint32_t completer_node; uint32_t completer_slot;
    uint64_t completer_epoch; uint64_t stamp_ms; uint64_t seq;
    uint8_t  outcome[MXFS_RMAN_OBL_DONE_BITMAP_BYTES_C];
    uint8_t  pad[MXFS_RMAN_OBL_DONE_BYTES_C - 144 - MXFS_RMAN_OBL_DONE_BITMAP_BYTES_C - 4];
    uint32_t crc32c;
} __attribute__((packed));
_Static_assert(sizeof(struct chk_rman_obl_done) == 4096 &&
               offsetof(struct chk_rman_obl_done, outcome) == 144 &&
               offsetof(struct chk_rman_obl_done, crc32c) == 4092,
               "chk_rman_obl_done must match dlm/recov_obl_done.h mxfs_rman_obl_done");

/* The heartbeat header fields this decoder needs, by name. */
struct chk_hb_hdr {
    uint32_t magic, flags, node_id, fs_gen;
    uint64_t timestamp_ms, epoch, lock_count;
} __attribute__((packed));
_Static_assert(sizeof(struct chk_hb_hdr) == MXFS_RECOV_DESC_OFF_C,
               "the recovery descriptor starts right after the 40-byte header");

/*
 * recov_desc_crc / recov_outcome_crc from dlm/disklock.c: crc32c (kernel
 * semantics, seed ~0, no final inversion) over the record's own bytes up to
 * the crc field, then folded with the SECTOR's identity triple.  That binding
 * is what makes a descriptor spliced next to a different victim's header fail
 * to validate — so it must be reproduced exactly, not approximated.
 */
static uint32_t chk_recov_body_crc(uint32_t fs_gen, uint32_t node_id,
                                   uint64_t epoch, const void *rec, size_t len)
{
    struct { uint32_t fs_gen; uint32_t node_id; uint64_t epoch; }
        __attribute__((packed)) id;
    uint32_t crc;

    id.fs_gen = fs_gen;
    id.node_id = node_id;
    id.epoch = epoch;
    crc = crc32c_raw(~0U, rec, len);
    return crc32c_raw(crc, &id, sizeof(id));
}

/*
 * The verdict DIGEST an operator must quote back to authorize a repair
 * (ruling: "a generic yes must not be able to clear the wrong victim
 * or filesystem").  Bound to the filesystem UUID, the slot index and the
 * COMPLETE 512-byte guard sector, so it changes if anything about the verdict
 * or its location changes.  Two different seeds give 64 bits; this guards
 * against operator error, and is not claimed to be adversarial.
 */
static uint64_t chk_verdict_digest(const uint8_t *uuid16, uint32_t slot,
                                   const uint8_t *sector512)
{
    uint32_t hi, lo;
    uint32_t s = slot;

    hi = crc32c_raw(~0U, uuid16, 16);
    hi = crc32c_raw(hi, &s, sizeof(s));
    hi = crc32c_raw(hi, sector512, 512);

    lo = crc32c_raw(0x1EDC6F41u, sector512, 512);
    lo = crc32c_raw(lo, &s, sizeof(s));
    lo = crc32c_raw(lo, uuid16, 16);

    return ((uint64_t)hi << 32) | lo;
}

static const char *chk_refusal_reason_name(uint16_t r)
{
    switch (r) {
    case MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE_C:
        return "POLICY_REFUSED_COMPLETE (the replay gate refused every obligation)";
    case MXFS_RECOV_REFUSAL_PHYSICALLY_TORN_C:
        return "PHYSICALLY_TORN (the slice image is unreadable/corrupt)";
    case 7u:
        return "DBG_INJECTED (TEST: quarantine published by mxfs.dbg_purge_refreeze — not a real replay verdict; reformat or repair)";
    case MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE_C:
        return "LEGACY_INTENT_QUARANTINE (backfilled verdict, inherited)";
    case MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED_C:
        return "AUTHORITY_MUTATED (fence-time manifest vs live CAW table mismatch)";
    case MXFS_RECOV_REFUSAL_MANIFEST_INVALID_C:
        return "MANIFEST_INVALID (sealed fence-time manifest fails validation)";
    case MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY_C:
        return "ASSEMBLY_DISCONTINUITY (item assembly crossed an ophdr discontinuity in a stable slice snapshot; not a media tear)";
    case MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED_C:
        return "INTENTS_UNDISCHARGED (the victim's slice holds intent obligations with no done record; refused before purge, needs repair)";
    case 9u:
        return "OBLIGATION_UNRECONCILABLE (an open EFI extent was PARTIALLY free when the custodian examined it, or the mounted geometry/feature bits refuse the completion; refused before purge, needs repair)";
    default:
        return "UNKNOWN";
    }
}

/*
 * decode + print the obligation record of one guard sector.
 * Returns 1 when a valid record naming a published list (count > 0) was
 * printed (the caller may then read the list), 0 when there is no record or
 * it is empty, -1 when the record bytes are present but INVALID (reported
 * loudly: after IMAGES_REPLAYED the kernel treats that as QUARANTINE, never
 * as "no obligations").
 */
static int chk_print_obl_record(uint32_t slot, const uint8_t *sec,
                                struct chk_recov_obl *out)
{
    const struct chk_hb_hdr *h = (const void *)sec;
    struct chk_recov_obl ob;
    uint32_t want;
    bool present = false;
    int i;

    memcpy(&ob, sec + MXFS_RECOV_OBL_OFF_C, sizeof(ob));
    if (out)
        memset(out, 0, sizeof(*out));
    for (i = 0; i < (int)sizeof(ob); i++)
        if (((const uint8_t *)&ob)[i] != 0) { present = true; break; }
    if (!present) {
        printf("     obligations       none recorded (record region all zero)\n");
        return 0;
    }
    if (ob.magic != MXFS_RECOV_OBL_MAGIC_C || ob.version != MXFS_RECOV_OBL_VERSION_C) {
        err("slot %u: obligation record magic/version 0x%08X/%u — INVALID "
            "(the kernel treats this as QUARANTINE)", slot, ob.magic, ob.version);
        return -1;
    }
    want = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch, &ob,
                              offsetof(struct chk_recov_obl, crc32c));
    if (want != ob.crc32c) {
        err("slot %u: obligation record CRC 0x%08X != computed 0x%08X — "
            "INVALID (the kernel treats this as QUARANTINE)", slot,
            ob.crc32c, want);
        return -1;
    }
    if ((ob.flags & ~MXFS_RECOV_OBL_F_ALL_C) ||
        ob.count > MXFS_RECOV_OBL_MAX_EXTENTS_C ||
        (ob.count == 0 && (ob.obl_ag_mask || ob.list_crc32c || ob.pub_seq ||
                           (ob.flags & (MXFS_RECOV_OBL_F_LIST_C | MXFS_RECOV_OBL_F_FSWIDE_C)))) ||
        (ob.count && (!(ob.flags & MXFS_RECOV_OBL_F_LIST_C) || ob.pub_seq == 0)) ||
        (ob.count && (ob.flags & MXFS_RECOV_OBL_F_FSWIDE_C) && ob.obl_ag_mask) ||
        (ob.count && !(ob.flags & MXFS_RECOV_OBL_F_FSWIDE_C) && !ob.obl_ag_mask)) {
        err("slot %u: obligation record is structurally inconsistent "
            "(flags=0x%04X count=%u ag_mask=0x%016llX seq=%u) — INVALID",
            slot, ob.flags, ob.count, (unsigned long long)ob.obl_ag_mask,
            ob.pub_seq);
        return -1;
    }
    printf("     obligations       count=%u %s%s ag_mask=0x%016llX seq=%u "
           "list_crc=0x%08X census=0x%016llX\n",
           ob.count,
           (ob.flags & MXFS_RECOV_OBL_F_TERMINAL_C) ?
               "TERMINAL-EVIDENCE (published next to the verdict; gates nothing)" :
           (ob.flags & MXFS_RECOV_OBL_F_DONE_C) ?
               "DONE (every extent completed and proven; nothing owed)" :
               "OPEN (a completion is owed before the purge)",
           (ob.flags & MXFS_RECOV_OBL_F_FSWIDE_C) ? " FSWIDE" : "",
           (unsigned long long)ob.obl_ag_mask, ob.pub_seq, ob.list_crc32c,
           (unsigned long long)ob.census_digest);
    if (ob.count && !(ob.flags & MXFS_RECOV_OBL_F_FSWIDE_C)) {
        printf("                       AGs:");
        for (i = 0; i < 64; i++)
            if (ob.obl_ag_mask & (1ULL << i))
                printf(" %d", i);
        printf("\n");
    }
    if (out)
        *out = ob;
    return ob.count ? 1 : 0;
}

/*
 * read + validate + print the obligation LIST a record names, from
 * the victim's rman slot zone.  `sec` is the guard sector (for the identity
 * the header must name).  Prints the verdict of every check; never treats a
 * failed check as "no list".
 */
static void chk_print_obl_list(int dfd, uint64_t rman_offset, uint32_t slot,
                               const uint8_t *sec, const struct chk_recov_obl *ob)
{
    const struct chk_hb_hdr *h = (const void *)sec;
    struct chk_recov_desc d;
    struct chk_rman_obl_hdr *hdr = NULL;
    struct chk_recov_obl_ext *ents = NULL;
    uint64_t base, io_len, mask = 0;
    uint32_t i, crc;
    bool fsw = false, ok = true;
    int pad_i;

    if (!ob || ob->count == 0)
        return;
    if (!rman_offset) {
        err("slot %u: obligation record names a list but the volume has no "
            "recovery-manifest region — INVALID", slot);
        return;
    }
    memcpy(&d, sec + MXFS_RECOV_DESC_OFF_C, sizeof(d));
    base = rman_offset + (uint64_t)slot * MXFS_RMAN_SLOT_BYTES + MXFS_RMAN_OBL_OFF_C;
    if (posix_memalign((void **)&hdr, 4096, MXFS_RMAN_OBL_HDR_BYTES_C) != 0) {
        err("slot %u: no memory for the obligation list header", slot);
        return;
    }
    if (pread(dfd, hdr, MXFS_RMAN_OBL_HDR_BYTES_C, (off_t)base) !=
        (ssize_t)MXFS_RMAN_OBL_HDR_BYTES_C) {
        err("slot %u: obligation list header unreadable at %llu: %s", slot,
            (unsigned long long)base, strerror(errno));
        free(hdr);
        return;
    }
    if (hdr->magic != MXFS_RMAN_OBL_MAGIC_C || hdr->version != MXFS_RMAN_OBL_VERSION_C) {
        err("slot %u: obligation list header magic/version 0x%08X/%u — the "
            "record names a list that is not there (INVALID => QUARANTINE)",
            slot, hdr->magic, hdr->version);
        free(hdr);
        return;
    }
    crc = crc32c_raw(~0U, hdr, offsetof(struct chk_rman_obl_hdr, hdr_crc32c));
    crc = crc32c_raw(crc, hdr->pad, sizeof(hdr->pad));
    if (crc != hdr->hdr_crc32c) {
        err("slot %u: obligation list header CRC 0x%08X != computed 0x%08X — "
            "INVALID", slot, hdr->hdr_crc32c, crc);
        ok = false;
    }
    for (pad_i = 0; pad_i < (int)sizeof(hdr->pad); pad_i++)
        if (hdr->pad[pad_i]) { err("slot %u: obligation list header reserved bytes not zero", slot); ok = false; break; }
    if (hdr->victim_node != h->node_id || hdr->victim_epoch != h->epoch ||
        hdr->victim_fs_gen != h->fs_gen || hdr->victim_slot != slot ||
        hdr->recovery_gen != d.recovery_gen) {
        err("slot %u: obligation list header names another recovery case "
            "(node=%u epoch=%llu fs_gen=0x%08X slot=%u gen=%llu vs sector "
            "node=%u epoch=%llu fs_gen=0x%08X gen=%llu) — INVALID", slot,
            hdr->victim_node, (unsigned long long)hdr->victim_epoch,
            hdr->victim_fs_gen, hdr->victim_slot,
            (unsigned long long)hdr->recovery_gen, h->node_id,
            (unsigned long long)h->epoch, h->fs_gen,
            (unsigned long long)d.recovery_gen);
        ok = false;
    }
    if (hdr->seq != ob->pub_seq || hdr->count != ob->count ||
        hdr->entries_crc32c != ob->list_crc32c ||
        hdr->census_digest != ob->census_digest ||
        hdr->obl_ag_mask != ob->obl_ag_mask ||
        (hdr->flags & (MXFS_RECOV_OBL_F_FSWIDE_C | MXFS_RECOV_OBL_F_TERMINAL_C)) !=
            (ob->flags & (MXFS_RECOV_OBL_F_FSWIDE_C | MXFS_RECOV_OBL_F_TERMINAL_C))) {
        err("slot %u: obligation list header does not match the record "
            "(seq %llu/%u count %u/%u crc 0x%08X/0x%08X) — INVALID", slot,
            (unsigned long long)hdr->seq, ob->pub_seq, hdr->count, ob->count,
            hdr->entries_crc32c, ob->list_crc32c);
        ok = false;
    }
    if (hdr->entry_bytes != sizeof(struct chk_recov_obl_ext) ||
        (uint64_t)hdr->byte_len != (uint64_t)hdr->count * hdr->entry_bytes ||
        hdr->count == 0 || hdr->count > MXFS_RECOV_OBL_MAX_EXTENTS_C ||
        hdr->agcount == 0 || hdr->agblocks == 0) {
        err("slot %u: obligation list entry geometry (entry_bytes=%u count=%u "
            "byte_len=%u agcount=%u agblocks=%u) — INVALID", slot,
            hdr->entry_bytes, hdr->count, hdr->byte_len, hdr->agcount,
            hdr->agblocks);
        ok = false;
    }
    if (!ok) {
        free(hdr);
        return;
    }
    io_len = ((uint64_t)hdr->byte_len + 4095) & ~4095ULL;
    if (posix_memalign((void **)&ents, 4096, io_len) != 0) {
        err("slot %u: no memory for the obligation list entries", slot);
        free(hdr);
        return;
    }
    if (pread(dfd, ents, io_len, (off_t)(base + (MXFS_RMAN_OBL_ENTRIES_OFF_C - MXFS_RMAN_OBL_OFF_C))) !=
        (ssize_t)io_len) {
        err("slot %u: obligation list entries unreadable: %s", slot, strerror(errno));
        free(ents); free(hdr);
        return;
    }
    crc = crc32c_raw(~0U, ents, hdr->byte_len);
    if (crc != hdr->entries_crc32c) {
        err("slot %u: obligation list entries CRC 0x%08X != computed 0x%08X — "
            "INVALID", slot, hdr->entries_crc32c, crc);
        free(ents); free(hdr);
        return;
    }
    /* canonical form: sorted by (agno, agbno), in bounds, no overlap */
    {
        unsigned agblklog = 0;
        uint64_t agbno_mask;

        while (agblklog < 63 && ((uint64_t)1 << agblklog) < (uint64_t)hdr->agblocks)
            agblklog++;
        agbno_mask = ((uint64_t)1 << agblklog) - 1;
        for (i = 0; i < hdr->count; i++) {
            const struct chk_recov_obl_ext *e = &ents[i];
            uint64_t agbno = e->fsbno & agbno_mask;

            if (e->len == 0 || e->agno >= hdr->agcount ||
                (e->fsbno >> agblklog) != e->agno ||
                agbno >= hdr->agblocks ||
                (uint64_t)e->len > (uint64_t)hdr->agblocks - agbno) {
                err("slot %u: obligation entry %u (fsbno=%llu agno=%u len=%u) "
                    "is out of bounds — INVALID", slot, i,
                    (unsigned long long)e->fsbno, e->agno, e->len);
                ok = false;
                break;
            }
            if (i > 0) {
                const struct chk_recov_obl_ext *p = &ents[i - 1];

                if (p->agno > e->agno ||
                    (p->agno == e->agno &&
                     (p->fsbno & agbno_mask) + p->len > agbno)) {
                    err("slot %u: obligation entries %u/%u are not canonical "
                        "(order/overlap) — INVALID", slot, i - 1, i);
                    ok = false;
                    break;
                }
            }
            if (e->agno >= 64)
                fsw = true;
            else
                mask |= (uint64_t)1 << e->agno;
        }
        if (ok && (fsw != !!(hdr->flags & MXFS_RECOV_OBL_F_FSWIDE_C) ||
                   (fsw ? 0 : mask) != hdr->obl_ag_mask)) {
            err("slot %u: obligation list recomputed mask 0x%016llX/fswide=%d "
                "differs from the header 0x%016llX/%d — INVALID", slot,
                (unsigned long long)mask, (int)fsw,
                (unsigned long long)hdr->obl_ag_mask,
                (hdr->flags & MXFS_RECOV_OBL_F_FSWIDE_C) ? 1 : 0);
            ok = false;
        }
    }
    if (ok) {
        printf("     obligation list   VALID: %u extent(s), %u byte(s), "
               "published seq=%llu by node=%u term=%u geometry agcount=%u "
               "agblocks=%u\n", hdr->count, hdr->byte_len,
               (unsigned long long)hdr->seq, hdr->publisher_node,
               hdr->publisher_term, hdr->agcount, hdr->agblocks);
        for (i = 0; i < hdr->count && i < 8; i++)
            printf("                       [%u] ag=%u fsbno=%llu len=%u\n", i,
                   ents[i].agno, (unsigned long long)ents[i].fsbno, ents[i].len);
        if (hdr->count > 8)
            printf("                       ... %u more\n", hdr->count - 8);
    }
    free(ents);
    free(hdr);
}

/*
 * The completion PROOF block a DONE (or completing) record's zone carries at
 * 56 KiB of the victim's rman slot.  Mirrors mxfs_rman_obl_done_check: a
 * COMMITTED, crc-valid block whose identity matches the record is the only
 * evidence that OBLIGATIONS_DONE was earned; an uncommitted block is phase 1
 * of a custodian that died mid-proof (no proof); anything else is reported
 * loudly.  A record flagged DONE with no valid proof is INVALID.
 */
static void chk_print_obl_proof(int dfd, uint64_t rman_offset, uint32_t slot,
                                const uint8_t *sec, const struct chk_recov_obl *ob)
{
    const struct chk_hb_hdr *h = (const void *)sec;
    struct chk_recov_desc d;
    struct chk_rman_obl_done *p = NULL;
    uint64_t base;
    uint32_t crc, i, pop = 0;
    bool present = false, ok = true;
    bool done = ob && (ob->flags & MXFS_RECOV_OBL_F_DONE_C);

    if (!ob || ob->count == 0 || !rman_offset)
        return;
    memcpy(&d, sec + MXFS_RECOV_DESC_OFF_C, sizeof(d));
    base = rman_offset + (uint64_t)slot * MXFS_RMAN_SLOT_BYTES + MXFS_RMAN_OBL_DONE_OFF_C;
    if (posix_memalign((void **)&p, 4096, MXFS_RMAN_OBL_DONE_BYTES_C) != 0) {
        err("slot %u: no memory for the completion proof block", slot);
        return;
    }
    if (pread(dfd, p, MXFS_RMAN_OBL_DONE_BYTES_C, (off_t)base) !=
        (ssize_t)MXFS_RMAN_OBL_DONE_BYTES_C) {
        err("slot %u: completion proof block unreadable at %llu: %s", slot,
            (unsigned long long)base, strerror(errno));
        free(p);
        return;
    }
    for (i = 0; i < MXFS_RMAN_OBL_DONE_BYTES_C; i++)
        if (((const uint8_t *)p)[i]) { present = true; break; }
    if (!present) {
        if (done)
            err("slot %u: record flagged DONE but the proof block is all zero "
                "— INVALID (OBLIGATIONS_DONE without evidence)", slot);
        else
            printf("     completion proof  none (no custodian has completed this case yet)\n");
        free(p);
        return;
    }
    if (p->magic != MXFS_RMAN_OBL_DONE_MAGIC_C || p->version != MXFS_RMAN_OBL_DONE_VERSION_C ||
        p->length != MXFS_RMAN_OBL_DONE_BYTES_C) {
        err("slot %u: completion proof magic/version/length 0x%08X/%u/%u — INVALID",
            slot, p->magic, p->version, p->length);
        free(p);
        return;
    }
    crc = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch, p,
                             offsetof(struct chk_rman_obl_done, crc32c));
    if (crc != p->crc32c) {
        err("slot %u: completion proof CRC 0x%08X != computed 0x%08X — INVALID "
            "(a torn proof is no proof)", slot, p->crc32c, crc);
        free(p);
        return;
    }
    if (p->rman_slot != slot || p->victim_node != h->node_id ||
        p->victim_epoch != h->epoch || p->victim_fs_gen != h->fs_gen ||
        p->recovery_gen != d.recovery_gen) {
        err("slot %u: completion proof names another recovery case "
            "(slot=%u node=%u epoch=%llu gen=%llu) — INVALID", slot,
            p->rman_slot, p->victim_node, (unsigned long long)p->victim_epoch,
            (unsigned long long)p->recovery_gen);
        ok = false;
    }
    if (p->pub_seq != ob->pub_seq || p->count != ob->count ||
        p->list_crc32c != ob->list_crc32c || p->obl_ag_mask != ob->obl_ag_mask) {
        err("slot %u: completion proof does not match the record (seq %u/%u "
            "count %u/%u crc 0x%08X/0x%08X) — INVALID", slot, p->pub_seq,
            ob->pub_seq, p->count, ob->count, p->list_crc32c, ob->list_crc32c);
        ok = false;
    }
    for (i = 0; i < MXFS_RMAN_OBL_DONE_BITMAP_BYTES_C * 8u; i++)
        if ((p->outcome[i >> 3] >> (i & 7)) & 1u) {
            if (i >= p->count) {
                err("slot %u: completion proof outcome bit %u beyond count %u — INVALID",
                    slot, i, p->count);
                ok = false;
                break;
            }
            pop++;
        }
    if (p->n_sparse || (uint64_t)p->n_empty + p->n_full != p->count || pop != p->n_empty ||
        p->rcpt_digest != 0) {
        err("slot %u: completion proof counters inconsistent (empty=%u full=%u "
            "sparse=%u count=%u popcount=%u rcpt=%llu) — INVALID", slot,
            p->n_empty, p->n_full, p->n_sparse, p->count, pop,
            (unsigned long long)p->rcpt_digest);
        ok = false;
    }
    for (i = 0; i < sizeof(p->pad); i++)
        if (p->pad[i]) { err("slot %u: completion proof reserved bytes not zero — INVALID", slot); ok = false; break; }
    if (ok && !(p->flags & MXFS_RMAN_OBL_DONE_F_COMMITTED_C)) {
        printf("     completion proof  UNCOMMITTED (phase 1 only: the custodian died before "
               "committing; no proof, the case is still OPEN)\n");
        if (done)
            err("slot %u: record flagged DONE over an UNCOMMITTED proof — INVALID", slot);
        free(p);
        return;
    }
    if (ok) {
        printf("     completion proof  COMMITTED: count=%u freed=%u already-free=%u "
               "ag_mask=0x%016llX by node=%u/%llu (slot %u) term=%u stage_seq=%llu "
               "seq=%llu\n", p->count, p->n_empty, p->n_full,
               (unsigned long long)p->obl_ag_mask, p->completer_node,
               (unsigned long long)p->completer_epoch, p->completer_slot,
               p->owner_term, (unsigned long long)p->stage_seq,
               (unsigned long long)p->seq);
        if (!done)
            printf("                       (record not yet flagged DONE: the "
                   "OBLIGATIONS_DONE advance did not land after this proof)\n");
    } else if (done) {
        err("slot %u: record flagged DONE but the proof is INVALID", slot);
    }
    free(p);
}

/*
 * Decode and PRINT the terminal verdict in one guard sector.  Returns:
 *   1  a valid quarantine verdict was printed
 *   0  the slot is a RECOVERY_GUARD but carries no readable verdict
 *  -1  the slot is not a RECOVERY_GUARD
 * A guard whose descriptor or outcome fails its crc is reported LOUDLY: that
 * is a corrupt verdict, which is a worse state than a readable one, and it
 * must never be silently treated as "no quarantine here".
 */
static int chk_print_guard(uint32_t slot, const uint8_t *sec,
                           const uint8_t *fsuuid, uint16_t slice_count_hint)
{
    const struct chk_hb_hdr *h = (const void *)sec;
    struct chk_recov_desc d;
    struct chk_recov_outcome oc;
    uint32_t want;
    bool desc_ok, oc_present, oc_ok;
    int i;

    if (h->magic != MXFS_DISKLOCK_MAGIC ||
        h->flags != (uint32_t)MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C)
        return -1;

    memcpy(&d, sec + MXFS_RECOV_DESC_OFF_C, sizeof(d));
    memcpy(&oc, sec + MXFS_RECOV_OUTCOME_OFF_C, sizeof(oc));

    /* a RECOVERY_GUARD with NO descriptor body is NOT a damaged
     * verdict — it is the unclaimed-bucket sweep's transient working guard.
     * mxfs_unclaimed_bucket_scan() walks b < XFS_AGI_UNLINKED_BUCKETS (64)
     * and uses the bucket index AS the disklock slot index, taking a bare
     * guard on any unclaimed slot so it can sweep that AGI unlinked bucket.
     * Reporting it as a corrupt terminal verdict would send an operator
     * hunting evidence that was never written. */
    if (d.magic == 0 && oc.magic == 0) {
        printf("\n  ── heartbeat slot %u: bucket-sweep guard (node=%u, "
               "transient) ──\n", slot, h->node_id);
        printf("     Not a quarantine: no recovery descriptor was written "
               "here.  The AGI\n"
               "     unlinked-bucket sweep holds this guard while it sweeps "
               "bucket %u and\n"
               "     releases it when done.\n", slot);
        return 2;
    }

    printf("\n  ── heartbeat slot %u: RECOVERY GUARD ──────────────────────\n",
           slot);
    printf("     sector identity   node=%u fs_gen=0x%08X incarnation=%llu\n",
           h->node_id, h->fs_gen, (unsigned long long)h->epoch);

    desc_ok = false;
    if (d.magic != MXFS_RECOV_DESC_MAGIC_C) {
        err("slot %u: RECOVERY_GUARD with NO recovery descriptor "
            "(magic 0x%08X) but a non-empty outcome region — the verdict is "
            "unreadable", slot, d.magic);
    } else if (d.version != MXFS_RECOV_DESC_VERSION_C) {
        err("slot %u: recovery descriptor version %u — this build speaks "
            "version %u and will not interpret it",
            slot, d.version, MXFS_RECOV_DESC_VERSION_C);
    } else {
        want = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch,
                                  &d, offsetof(struct chk_recov_desc, crc32c));
        if (want != d.crc32c) {
            err("slot %u: recovery descriptor CRC 0x%08X != computed 0x%08X "
                "— the verdict is CORRUPT", slot, d.crc32c, want);
        } else {
            desc_ok = true;
        }
    }

    if (desc_ok) {
        printf("     victim            node=%u incarnation=%llu slot=%u "
               "slice=%u of %u\n",
               d.victim_node, (unsigned long long)d.victim_epoch,
               d.victim_slot, d.slice_idx, d.slice_count);
        printf("     recovery          owner=%u term=%u gen=%llu stage=%u%s "
               "flags=0x%08X%s%s\n",
               d.owner_node, d.owner_term,
               (unsigned long long)d.recovery_gen, d.stage,
               d.stage == 4 ? " (IMAGES_REPLAYED)" :
               d.stage == 5 ? " (OBLIGATIONS_DONE)" :
               d.stage == 6 ? " (GRANTS_RELEASED)" : "",
               d.flags,
               (d.flags & MXFS_RECOV_F_QUARANTINED_C) ? " QUARANTINED" : "",
               (d.flags & 0x00000080u) ? " CENSUS_ZERO" : "");
        printf("     fence certificate kind=%u resv_type=0x%02X "
               "victim_key=0x%016llX prover=%u term=%u\n",
               d.fence_kind, d.fence_resv_type,
               (unsigned long long)d.fence_victim_key,
               d.fence_prover_node, d.fence_term);
        if (!(d.flags & MXFS_RECOV_F_QUARANTINED_C))
            printf("     NOTE: this guard is NOT quarantined — it is a "
                   "recovery in progress, not a terminal verdict.\n");
    }

    oc_present = false;
    for (i = 0; i < (int)sizeof(oc); i++)
        if (((const uint8_t *)&oc)[i] != 0) { oc_present = true; break; }

    oc_ok = false;
    if (!oc_present) {
        printf("     verdict           NONE RECORDED (outcome region all "
               "zero).\n"
               "                       This is the legacy intent-path "
               "quarantine: terminal, but\n"
               "                       carrying no domain evidence.  Treat "
               "the domain as FSWIDE.\n");
    } else if (oc.magic != MXFS_RECOV_OUTCOME_MAGIC_C) {
        err("slot %u: outcome region is non-zero but has magic 0x%08X — "
            "the verdict is CORRUPT", slot, oc.magic);
    } else {
        want = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch,
                                  &oc, offsetof(struct chk_recov_outcome, crc32c));
        if (want != oc.crc32c)
            err("slot %u: outcome CRC 0x%08X != computed 0x%08X — the verdict "
                "is CORRUPT", slot, oc.crc32c, want);
        else
            oc_ok = true;
    }

    if (oc_ok) {
        printf("     verdict           %s\n",
               oc.outcome == MXFS_RECOV_OUTCOME_TERMINAL_REFUSED_C ?
               "TERMINAL REFUSED" : "unknown outcome code");
        printf("     reason            %s\n",
               chk_refusal_reason_name(oc.reason));
        if (oc.domain_kind == MXFS_RECOV_DOMAIN_FSWIDE_C) {
            printf("     domain            FSWIDE — the whole filesystem is "
                   "quarantined\n");
        } else if (oc.domain_kind == MXFS_RECOV_DOMAIN_AG_MASK_C) {
            printf("     domain            AG_MASK 0x%016llX — AGs:",
                   (unsigned long long)oc.ag_mask);
            for (i = 0; i < 64; i++)
                if (oc.ag_mask & (1ULL << i))
                    printf(" %d", i);
            printf("\n");
        } else {
            printf("     domain            UNKNOWN kind=%u — treat as "
                   "FSWIDE\n", oc.domain_kind);
        }
        printf("     refused by        node=%u term=%u publish_seq=%llu\n",
               oc.owner_node, oc.owner_term,
               (unsigned long long)oc.publish_seq);
        printf("     log items         refused=%u malformed=%u\n",
               oc.refused_items, oc.malformed_items);
        if (oc.flags & MXFS_RECOV_OUTCOME_F_DIGEST_VALID_C)
            printf("     refused slice     crc32c=0x%016llX (forensic identity "
                   "of what was refused)\n",
                   (unsigned long long)oc.slice_digest);
        else
            printf("     refused slice     digest NOT captured (the forensic "
                   "reread failed)\n");
    }

    if (desc_ok)
        chk_print_obl_record(slot, sec, NULL);      /* */
    printf("     VERDICT DIGEST    %016llX\n",
           (unsigned long long)chk_verdict_digest(fsuuid, slot, sec));
    if (slice_count_hint && slot >= slice_count_hint)
        printf("     NOTE: this slot is at or above the volume's slice count "
               "(%u) — it bears no journal.\n", slice_count_hint);
    /*
     * (D-379 item 5): a readable guard whose descriptor is NOT
     * flagged QUARANTINED is a recovery IN PROGRESS (or stuck), not a
     * terminal verdict — return 3 so the summary classifies and advises it
     * separately instead of counting it as a quarantine and pointing the
     * operator at the -376 repair.
     */
    if (desc_ok && !(d.flags & MXFS_RECOV_F_QUARANTINED_C))
        return 3;
    return (desc_ok && (oc_ok || !oc_present)) ? 1 : 0;
}

/* Decode the §7.C MEPOCH record at offset 456 of one HB slot.  The
 * record is self-validating (own magic + crc32c over bytes 0..39);
 * returns the committed epoch (0 if absent/PREPARED), errs on a
 * corrupt record. */
/*
 * the host/boot/PR-key IDENTITY block at offset 360 of a heartbeat
 * record (dlm/disklock.h mxfs_hb_identity, 64 B).  crc mirrors
 * dlm/disklock.c hb_ident_crc: packed {magic, ver, key_gen, host_uuid[16],
 * boot_uuid[16], pr_key, host_src, slot, flags, fs_gen, node_id, epoch},
 * crc32c seed ~0, no inversion.
 */
#define MXFS_HB_IDENT_OFF       360
#define MXFS_HB_IDENT_MAGIC_C   0x4449584Du

static void hex_uuid(const uint8_t *u, char out[37])
{
    static const char hx[] = "0123456789abcdef";
    int i, o = 0;

    for (i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = hx[u[i] >> 4];
        out[o++] = hx[u[i] & 0xf];
    }
    out[o] = 0;
}

static void decode_hb_identity(const uint8_t *r, int slot)
{
    const uint8_t *id = r + MXFS_HB_IDENT_OFF;
    uint32_t magic = *(const uint32_t *)(id + 0);
    struct {
        uint32_t magic; uint16_t ver; uint16_t key_gen;
        uint8_t host[16]; uint8_t boot[16];
        uint64_t pr_key; uint32_t host_src;
        uint32_t slot; uint32_t flags; uint32_t fs_gen; uint32_t node_id;
        uint64_t epoch;
    } __attribute__((packed)) b;
    char host[37], boot[37];
    uint32_t want, have;

    if (magic == 0) {
        uint32_t fl; memcpy(&fl, r + 4, 4);
        /* (D-0493): a re-flagged record (GUARD, RETIRE_PENDING)
         * with no identity at all is a different finding from one whose
         * identity no longer binds — say which. */
        if (fl == 3 || fl == 4)
            info("disklock HB slot %d: identity ABSENT (zeroed block) on a "
                 "%s record", slot, fl == 3 ? "RECOVERY GUARD" : "RETIRE_PENDING");
        return;                     /* pre-gen-12 or tool-written record */
    }
    if (magic != MXFS_HB_IDENT_MAGIC_C) {
        err("disklock HB slot %d: identity magic 0x%08x (want 0x%08x)",
            slot, magic, MXFS_HB_IDENT_MAGIC_C);
        return;
    }
    b.magic = magic;
    memcpy(&b.ver, id + 4, 2);
    memcpy(&b.key_gen, id + 6, 2);
    memcpy(b.host, id + 8, 16);
    memcpy(b.boot, id + 24, 16);
    memcpy(&b.pr_key, id + 40, 8);
    memcpy(&b.host_src, id + 48, 4);
    b.slot = (uint32_t)slot;
    memcpy(&b.flags, r + 4, 4);
    memcpy(&b.fs_gen, r + 12, 4);
    memcpy(&b.node_id, r + 8, 4);
    memcpy(&b.epoch, r + 24, 8);
    memcpy(&have, id + 52, 4);
    want = crc32c(~0U, &b, sizeof(b));
    hex_uuid(b.host, host);
    hex_uuid(b.boot, boot);
    if (want != have) {
        /* (D-0493): a recovery GUARD is the victim's record copied
         * byte for byte with only `flags` moved and the identity crc NOT
         * re-bound (dlm/disklock.c recovery_begin / fence intent), so the
         * victim's own identity is still there and binds to the flags the
         * victim wrote.  Report which binding validates instead of only
         * "mismatch": that is what a bootstrap classifier may rely on. */
        uint32_t as_flags = b.flags, alt, altcrc = 0;
        const char *binds = NULL;

        for (alt = 1; alt <= 2 && !binds; alt++) {
            if (alt == as_flags)
                continue;
            b.flags = alt;
            altcrc = crc32c(~0U, &b, sizeof(b));
            if (altcrc == have)
                binds = alt == 1 ? "ACTIVE" : "WITHDRAWN";
        }
        b.flags = as_flags;
        if (binds)
            info("disklock HB slot %d: identity host=%s boot=%s pr_key=0x%llx "
                 "gen=%u src=%u crc binds as %s (record re-flagged to %u; "
                 "the victim's own identity, carried byte for byte)",
                 slot, host, boot, (unsigned long long)b.pr_key, b.key_gen,
                 b.host_src, binds, as_flags);
        else
            err("disklock HB slot %d: identity crc expected 0x%08X, got 0x%08X "
                "(key=0x%llx) — binds to no flag value", slot, want, have,
                (unsigned long long)b.pr_key);
    } else
        info("disklock HB slot %d: identity host=%s boot=%s pr_key=0x%llx "
             "gen=%u src=%u crc ok", slot, host, boot,
             (unsigned long long)b.pr_key, b.key_gen, b.host_src);
}

static uint64_t decode_mepoch(const uint8_t *slot_buf, int slot,
                              uint64_t *members_out)
{
    const uint8_t *m = slot_buf + MXFS_MEPOCH_OFF;
    uint32_t magic = *(const uint32_t *)(m + 24);

    if (magic != MXFS_MEPOCH_MAGIC_C)
        return 0;                     /* pre-step-5 record: no MEPOCH */

    uint64_t epoch = *(const uint64_t *)(m + 0);
    uint64_t member_mask = *(const uint64_t *)(m + 8);
    uint64_t fenced_mask = *(const uint64_t *)(m + 16);
    uint32_t self_inc = *(const uint32_t *)(m + 28);
    uint16_t v0 = *(const uint16_t *)(m + 32);
    uint16_t v1 = *(const uint16_t *)(m + 34);
    uint16_t v2 = *(const uint16_t *)(m + 36);
    uint16_t flags = *(const uint16_t *)(m + 38);
    uint32_t crc = *(const uint32_t *)(m + 40);
    uint32_t want;
    uint8_t tmp[MXFS_MEPOCH_SIZE];

    memcpy(tmp, m, MXFS_MEPOCH_SIZE);
    memset(tmp + 40, 0, 4);
    want = crc32c_raw(0, tmp, 40);
    if (want != crc) {
        err("mepoch slot %d: crc expected 0x%08X, got 0x%08X",
            slot, want, crc);
        return 0;
    }
    if (verbose || (flags & MXFS_MEPOCH_F_PREPARED_C))
        info("mepoch slot %d: epoch=%llu members=0x%llX fenced=0x%llX "
             "voters=%u,%u,%u flags=0x%X%s inc=%u", slot,
             (unsigned long long)epoch,
             (unsigned long long)member_mask,
             (unsigned long long)fenced_mask,
             v0, v1, v2, flags,
             (flags & MXFS_MEPOCH_F_PREPARED_C) ? " (PREPARED)" : "",
             self_inc);
    if (flags & MXFS_MEPOCH_F_PREPARED_C)
        return 0;                     /* staged candidate, not authority */
    if (!epoch)
        return 0;                     /* incarnation-bump carrier */
    if (members_out)
        *members_out = member_mask;
    return epoch;
}

static void check_disklock(int fd, const struct mxfs_ondisk_super *super)
{
    uint8_t buf[512];
    uint64_t dloff = super->disklock_offset;
    int pre_errors = errors;
    uint64_t mep_max = 0, mep_members = 0, mm;
    int mep_recs = 0;

    /* Check that disklock region fits within device */
    if (dloff + super->disklock_size > super->device_size) {
        err("disklock region extends past device");
        printf("Disklock ................ ERRORS\n");
        return;
    }

    /* Read heartbeat slots (first MXFS_DISKLOCK_HB_SLOTS * 512 bytes) */
    int active = 0;
    int empty = 0;
    int guards = 0;
    int withdrawn = 0;

    for (int i = 0; i < MXFS_DISKLOCK_HB_SLOTS; i++) {
        uint64_t hb_off = dloff + (uint64_t)i * MXFS_DISKLOCK_RECORD_SIZE;

        if (read_at(fd, buf, 512, hb_off) < 0) {
            err("disklock HB slot %d: read failed", i);
            continue;
        }

        uint32_t hmagic = *(uint32_t *)(buf + 0);
        uint32_t hflags = *(uint32_t *)(buf + 4);

        /* Empty slots (all zeroes) are fine — skip them */
        bool all_zero = true;
        for (int b = 0; b < 512; b++) {
            if (buf[b] != 0) {
                all_zero = false;
                break;
            }
        }

        if (all_zero) {
            empty++;
            continue;
        }

        if (hmagic != MXFS_DISKLOCK_MAGIC) {
            /* Non-zero but wrong magic */
            err("disklock HB slot %d: magic expected 0x%08X, got 0x%08X",
                i, MXFS_DISKLOCK_MAGIC, hmagic);
            continue;
        }

        mm = 0;
        uint64_t me = decode_mepoch(buf, i, &mm);
        if (me) {
            mep_recs++;
            if (me > mep_max) {
                mep_max = me;
                mep_members = mm;
            }
        }

        /* `flags` is an ENUM (1 ACTIVE, 2 WITHDRAWN, 3
         * RECOVERY_GUARD), never a bitmask.  The old `hflags &
         * MXFS_DISKLOCK_FLAG_ACTIVE` test reported a quarantined slot
         * (flags==3) as a LIVE MEMBER, which is exactly backwards: a guard is
         * a terminal verdict occupying a slice, and an operator counting
         * members off this output would conclude the cluster was full when it
         * was actually one member short and needed repair. */
        uint32_t node_id = *(uint32_t *)(buf + 8);

        switch (hflags) {
        case MXFS_DISKLOCK_FLAG_ACTIVE:
            active++;
            info("disklock HB slot %d: ACTIVE (node_id=%u)", i, node_id);
            decode_hb_identity(buf, i);         /* */
            break;
        case MXFS_DISKLOCK_FLAG_WITHDRAWN_C:
            withdrawn++;
            info("disklock HB slot %d: WITHDRAWN (node_id=%u) — dirty slice "
                 "awaiting fence+replay", i, node_id);
            decode_hb_identity(buf, i);         /* */
            break;
        case MXFS_DISKLOCK_FLAG_RETIRE_PENDING_C:
            withdrawn++;
            info("disklock HB slot %d: RETIRE_PENDING (node_id=%u) — clean "
                 "release awaiting proof its PR key is retired (a live "
                 "peer's READ KEYS settles it; key present past the grace "
                 "-> WITHDRAWN + fence)", i, node_id);
            decode_hb_identity(buf, i);         /* */
            break;
        case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C:
            guards++;
            info("disklock HB slot %d: RECOVERY GUARD (node_id=%u) — terminal "
                 "quarantine verdict; run chk_mxfs --show-quarantine",
                 i, node_id);
            break;
        default:
            empty++;
            if (verbose)
                info("disklock HB slot %d: inactive (flags=%u)", i, hflags);
            break;
        }
    }

    int dlerrors = errors - pre_errors;
    if (dlerrors == 0) {
        printf("Disklock ................ OK  (%d HB slots, %d active)\n",
               MXFS_DISKLOCK_HB_SLOTS, active);
    } else {
        printf("Disklock ................ ERRORS (%d errors)\n", dlerrors);
    }
    if (guards || withdrawn) {
        uint32_t slices = super->xfs_log_node_count;

        printf("Recovery quarantine ..... %d terminal verdict(s), %d withdrawn "
               "slice(s)\n", guards, withdrawn);
        if (guards && slices)
            printf("                          usable RW slices %u of %u — run "
                   "chk_mxfs --show-quarantine\n",
                   slices > (uint32_t)guards ? slices - (uint32_t)guards : 0,
                   slices);
    }
    if (mep_recs)
        printf("Membership epoch ........ OK  (max committed epoch %llu, "
               "members 0x%llX, %d records)\n",
               (unsigned long long)mep_max,
               (unsigned long long)mep_members, mep_recs);
    else if (verbose)
        printf("Membership epoch ........ none (pre-NET2 volume)\n");
}

/* ─── Check: XFS Superblock ─── */

static int check_xfs_superblock(int fd, const struct mxfs_ondisk_super *super,
                                struct xfs_geo *geo)
{
    uint8_t buf[512];
    uint64_t xfs_off = super->xfs_data_offset;
    int pre_errors = errors;

    memset(geo, 0, sizeof(*geo));
    geo->xfs_off = xfs_off;

    /* XFS superblock is at sector 0 of the XFS data area */
    if (read_at(fd, buf, 512, xfs_off) < 0) {
        printf("XFS superblock .......... READ ERROR\n");
        return -1;
    }

    /* XFS fields are big-endian on disk */
    uint32_t sb_magic    = get_be32(buf + 0);
    uint32_t blocksize   = get_be32(buf + 4);
    uint64_t dblocks     = get_be64(buf + 8);
    uint64_t rootino     = get_be64(buf + 0x38);
    uint32_t agblocks    = get_be32(buf + 0x54);
    uint32_t agcount     = get_be32(buf + 0x58);
    uint16_t sectsize    = get_be16(buf + 0x66);
    uint16_t inodesize   = get_be16(buf + 0x68);
    uint16_t inopblock   = get_be16(buf + 0x6A);
    uint8_t  inopblog    = buf[0x7B];
    uint8_t  agblklog    = buf[0x7C];

    /* UUID at offset 0x20, 16 bytes */
    uint8_t uuid[16];
    memcpy(uuid, buf + 0x20, 16);

    if (sb_magic != MXFS_SB_MAGIC) {
        err("XFS superblock magic: expected 0x%08X, got 0x%08X",
            MXFS_SB_MAGIC, sb_magic);
        printf("XFS superblock .......... ERRORS\n");
        return -1;
    }

    /* CRC at offset 0xE0 (224), native uint32_t (little-endian on x86) */
    if (!xfs_verify_crc(buf, 512, 0xE0)) {
        uint32_t stored = *(uint32_t *)(buf + 0xE0);
        err("XFS superblock CRC: stored=0x%08X, verification failed", stored);

        if (can_repair()) {
            if (xfs_fix_crc_and_write(fd, buf, 512, 0xE0, xfs_off) == 0) {
                printf("  REPAIRED: XFS superblock CRC recomputed\n");
                repaired++;
            }
        }
    }

    /* Superblock counters */
    uint64_t icount   = get_be64(buf + 0x80);
    uint64_t ifree    = get_be64(buf + 0x88);
    uint64_t fdblocks = get_be64(buf + 0x90);

    /* V5 feature flags */
    uint32_t features_ro_compat = get_be32(buf + 0xD4);

    /* Basic sanity */
    if (blocksize == 0 || (blocksize & (blocksize - 1)) != 0) {
        err("XFS blocksize %u is not a power of 2", blocksize);
    }
    if (agcount == 0) {
        err("XFS agcount is 0");
    }
    if (sectsize != 512) {
        info("XFS sectsize=%u (expected 512)", sectsize);
    }

    int xerrors = errors - pre_errors;

    char uuidbuf[40];
    format_uuid(uuid, uuidbuf, sizeof(uuidbuf));

    printf("XFS superblock .......... %s  (blocksize=%u, agcount=%u, fdblocks=%llu)\n",
           xerrors == 0 ? "OK" : "ERRORS", blocksize, agcount,
           (unsigned long long)fdblocks);
    info("dblocks=%llu, icount=%llu, ifree=%llu, rootino=%llu",
         (unsigned long long)dblocks,
         (unsigned long long)icount,
         (unsigned long long)ifree,
         (unsigned long long)rootino);
    /* agblocks and the two log2 fields let a harness map an inode number to
     * its AG (agno = ino >> (agblklog + inopblog)) without xfs_db, which
     * cannot read the enveloped superblock. */
    info("sectsize=%u, inodesize=%u, inopblock=%u, agblocks=%u, "
         "agblklog=%u, inopblog=%u",
         sectsize, inodesize, inopblock, agblocks, agblklog, inopblog);
    info("features_ro_compat=0x%08X (finobt=%s)",
         features_ro_compat,
         (features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT) ? "yes" : "no");

    /* the directory-sharding gates must agree — XFS sb incompat
     * bit 29 (sb_features_incompat at 0xD8) and the envelope flag
     * (docs/dir-sharding.md "THREE GATES"). */
    {
        uint32_t features_incompat = get_be32(buf + 0xD8);
        int sbbit = (features_incompat & MXFS_DIRSHARD_SB_INCOMPAT) != 0;
        int envf = (super->flags & MXFS_FORMAT_F_DIRSHARD) != 0;

        info("features_incompat=0x%08X (dirshard: sb bit=%s envelope flag=%s)",
             features_incompat, sbbit ? "yes" : "no", envf ? "yes" : "no");
        if (sbbit != envf)
            err("directory-sharding gates disagree: XFS sb incompat bit 29 is %s but envelope MXFS_FORMAT_F_DIRSHARD is %s",
                sbbit ? "set" : "clear", envf ? "set" : "clear");
        dirshard_gates_ok = sbbit && envf;
        geo->has_ftype = (features_incompat & 0x1) != 0;      /* XFS_SB_FEAT_INCOMPAT_FTYPE */
        geo->has_nrext64 = (features_incompat & 0x20) != 0;   /* XFS_SB_FEAT_INCOMPAT_NREXT64 */
    }
    geo->dirblklog = buf[0xC0];

    /* Populate geometry for subsequent checks */
    geo->blocksize = blocksize;
    geo->agcount = agcount;
    geo->agblocks = agblocks;
    geo->inodesize = inodesize;
    geo->inopblock = inopblock;
    geo->inopblog = inopblog;
    geo->agblklog = agblklog;
    geo->dblocks = dblocks;
    geo->rootino = rootino;
    geo->icount = icount;
    geo->ifree = ifree;
    geo->fdblocks = fdblocks;
    geo->features_ro_compat = features_ro_compat;
    geo->has_finobt = (features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT) != 0;
    memcpy(geo->uuid, uuid, 16);

    printf("  UUID: %s\n", uuidbuf);

    return 0;
}

/* ─── Check: Per-AG structures (AGF + AGI headers) ─── */

/*
 * Read and validate an AG's AGF and AGI headers.
 * Extracts btree roots, levels, and counters for subsequent btree checks.
 */
struct ag_info {
    uint32_t    bno_root;
    uint32_t    cnt_root;
    uint32_t    bno_level;
    uint32_t    cnt_level;
    uint32_t    agf_freeblks;
    uint32_t    agf_longest;
    uint32_t    agf_length;

    uint32_t    ino_root;
    uint32_t    ino_level;
    uint32_t    agi_count;
    uint32_t    agi_freecount;
    uint32_t    agi_length;

    uint32_t    fino_root;
    uint32_t    fino_level;

    bool        agf_ok;
    bool        agi_ok;
};

static void check_xfs_ag_headers(int fd, const struct xfs_geo *geo,
                                 uint32_t agno, struct ag_info *agi_out)
{
    uint8_t buf[512];
    uint64_t ag_base = geo->xfs_off + (uint64_t)agno * geo->agblocks * geo->blocksize;
    uint64_t agf_off = ag_base + 512;  /* sector 1 */
    uint64_t agi_off = ag_base + 1024; /* sector 2 */
    int agf_errors = 0;
    int agi_errors = 0;

    memset(agi_out, 0, sizeof(*agi_out));

    /* Check AGF */
    if (read_at(fd, buf, 512, agf_off) < 0) {
        err("AG %u: AGF read failed", agno);
        return;
    }

    uint32_t agf_magic = get_be32(buf + 0);
    uint32_t agf_seqno = get_be32(buf + 8);

    if (agf_magic != MXFS_AGF_MAGIC) {
        err("AG %u: AGF magic expected 0x%08X, got 0x%08X",
            agno, MXFS_AGF_MAGIC, agf_magic);
        agf_errors++;
    }

    if (agf_seqno != agno) {
        err("AG %u: AGF seqno expected %u, got %u", agno, agno, agf_seqno);
        agf_errors++;
    }

    /* AGF CRC at offset 0xD8 (216) */
    if (!xfs_verify_crc(buf, 512, 0xD8)) {
        uint32_t stored = *(uint32_t *)(buf + 0xD8);
        err("AG %u: AGF CRC stored=0x%08X, verification failed", agno, stored);
        agf_errors++;

        if (can_repair() && agf_magic == MXFS_AGF_MAGIC) {
            if (xfs_fix_crc_and_write(fd, buf, 512, 0xD8, agf_off) == 0) {
                printf("  REPAIRED: AG %u AGF CRC recomputed\n", agno);
                repaired++;
                agf_errors--;
            }
        }
    }

    /* Extract AGF fields */
    agi_out->agf_length   = get_be32(buf + 0x0C);
    agi_out->bno_root     = get_be32(buf + 0x10);
    agi_out->cnt_root     = get_be32(buf + 0x14);
    agi_out->bno_level    = get_be32(buf + 0x1C);
    agi_out->cnt_level    = get_be32(buf + 0x20);
    agi_out->agf_freeblks = get_be32(buf + 0x34);
    agi_out->agf_longest  = get_be32(buf + 0x38);
    agi_out->agf_ok = (agf_errors == 0);

    info("AG %u AGF: bno_root=%u cnt_root=%u bno_level=%u cnt_level=%u freeblks=%u longest=%u",
         agno, agi_out->bno_root, agi_out->cnt_root,
         agi_out->bno_level, agi_out->cnt_level,
         agi_out->agf_freeblks, agi_out->agf_longest);

    /* Check AGI */
    if (read_at(fd, buf, 512, agi_off) < 0) {
        err("AG %u: AGI read failed", agno);
        return;
    }

    uint32_t agi_magic = get_be32(buf + 0);
    uint32_t agi_seqno = get_be32(buf + 8);

    if (agi_magic != MXFS_AGI_MAGIC) {
        err("AG %u: AGI magic expected 0x%08X, got 0x%08X",
            agno, MXFS_AGI_MAGIC, agi_magic);
        agi_errors++;
    }

    if (agi_seqno != agno) {
        err("AG %u: AGI seqno expected %u, got %u", agno, agno, agi_seqno);
        agi_errors++;
    }

    /* AGI CRC at offset 0x138 (312) */
    if (!xfs_verify_crc(buf, 512, 0x138)) {
        uint32_t stored = *(uint32_t *)(buf + 0x138);
        err("AG %u: AGI CRC stored=0x%08X, verification failed", agno, stored);
        agi_errors++;

        if (can_repair() && agi_magic == MXFS_AGI_MAGIC) {
            if (xfs_fix_crc_and_write(fd, buf, 512, 0x138, agi_off) == 0) {
                printf("  REPAIRED: AG %u AGI CRC recomputed\n", agno);
                repaired++;
                agi_errors--;
            }
        }
    }

    /* Extract AGI fields */
    agi_out->agi_length   = get_be32(buf + 0x0C);
    agi_out->agi_count    = get_be32(buf + 0x10);
    agi_out->ino_root     = get_be32(buf + 0x14);
    agi_out->ino_level    = get_be32(buf + 0x18);
    agi_out->agi_freecount = get_be32(buf + 0x1C);
    agi_out->fino_root    = get_be32(buf + 0x148);
    agi_out->fino_level   = get_be32(buf + 0x14C);
    agi_out->agi_ok = (agi_errors == 0);

    info("AG %u AGI: ino_root=%u ino_level=%u count=%u freecount=%u fino_root=%u fino_level=%u",
         agno, agi_out->ino_root, agi_out->ino_level,
         agi_out->agi_count, agi_out->agi_freecount,
         agi_out->fino_root, agi_out->fino_level);

    printf("  AG %u: AGF %s, AGI %s\n",
           agno,
           agf_errors == 0 ? "OK" : "ERRORS",
           agi_errors == 0 ? "OK" : "ERRORS");
}

/* ─── Check: Free Space BTree (BNO/CNT) Validation ─── */

/*
 * Validate a V5 short-form btree block header.
 * Returns 0 on success, -1 on error.
 */
static int validate_btree_sblock(uint8_t *blk, uint32_t blocksize,
                                 uint32_t expected_magic, uint32_t agno,
                                 const char *name, int fd, off_t disk_offset)
{
    uint32_t magic = get_be32(blk + 0x00);
    int ok = 1;

    if (magic != expected_magic) {
        err("AG %u %s btree: magic expected 0x%08X, got 0x%08X",
            agno, name, expected_magic, magic);
        ok = 0;
    }

    if (!xfs_verify_crc((void *)blk, blocksize, BTREE_CRC_OFF)) {
        uint32_t stored = *(uint32_t *)(blk + BTREE_CRC_OFF);
        err("AG %u %s btree: CRC stored=0x%08X, verification failed",
            agno, name, stored);
        ok = 0;

        if (can_repair() && magic == expected_magic) {
            if (xfs_fix_crc_and_write(fd, blk, blocksize,
                                       BTREE_CRC_OFF, disk_offset) == 0) {
                printf("  REPAIRED: AG %u %s btree block CRC recomputed\n",
                       agno, name);
                repaired++;
                ok = 1;
            }
        }
    }

    return ok ? 0 : -1;
}

/*
 * Walk a BNO or CNT btree leaf block and sum up free extents.
 * For BNO: validates records are sorted by startblock (ascending).
 * For CNT: validates records are sorted by blockcount (ascending), then startblock.
 * Each record is 8 bytes: [startblock(be32)] [blockcount(be32)]
 * Returns sum of blockcount values across all records.
 */
/*
 * D-0948: CROSS-TREE BLOCK-OWNERSHIP AUDIT.
 *
 * Checks 5 and 6 above each verify one btree against ITSELF — the free-space
 * trees are checked for ordering, bounds and totals, and the inode trees for
 * alignment, counts and free masks.  Neither has ever been checked against the
 * other, and there is no block-ownership map anywhere in this program.  So the
 * verdict "filesystem clean" has always been compatible with a block being
 * claimed by an inobt inode chunk and by the free-space trees at the same
 * time, which is the precursor to that block being handed to a directory and
 * written over a live inode cluster.
 *
 * That is not hypothetical.  A create was shut down reading `58 44 44 33` —
 * XDD3, a dir3 data block carrying its own address 0x41f1c0 in its header — at
 * the home of an inode the allocator had just handed out, and eight FUA
 * re-reads returned the same bytes and were logged "durable, not transient".
 * This program called that filesystem clean, and was not wrong by its own
 * rules: it simply never asked the question.
 *
 * THE INVARIANT: a block inside an allocated inode chunk is by definition
 * allocated, so it must never also appear in the BNO free-space btree.  One
 * bitmap per tree, then AND them.
 */
static uint8_t  *xtree_chunk;      /* block lies inside an inobt chunk */
static uint8_t  *xtree_free;       /* block is free per the BNO btree */
static uint64_t  xtree_nblocks;
static uint32_t  xtree_agblocks;

static void xtree_init(const struct xfs_geo *geo)
{
    xtree_agblocks = geo->agblocks;
    xtree_nblocks  = (uint64_t)geo->agcount * geo->agblocks;
    if (!xtree_nblocks || xtree_nblocks > (1ULL << 40))
        return;
    xtree_chunk = calloc((size_t)((xtree_nblocks + 7) / 8), 1);
    xtree_free  = calloc((size_t)((xtree_nblocks + 7) / 8), 1);
    if (!xtree_chunk || !xtree_free) {
        free(xtree_chunk);
        free(xtree_free);
        xtree_chunk = NULL;
        xtree_free = NULL;
    }
}

static void xtree_mark(uint8_t *map, uint32_t agno, uint32_t agbno,
                       uint32_t len)
{
    if (!map || agbno >= xtree_agblocks)
        return;
    if ((uint64_t)agbno + len > xtree_agblocks)
        len = xtree_agblocks - agbno;
    for (uint32_t i = 0; i < len; i++) {
        uint64_t b = (uint64_t)agno * xtree_agblocks + agbno + i;

        if (b < xtree_nblocks)
            map[b >> 3] |= (uint8_t)(1u << (b & 7));
    }
}

/*
 * Mark the blocks an inobt chunk record occupies.  A sparse chunk's holemask
 * has one bit per 4 inodes; a hole is a range that was never allocated, so its
 * blocks are legitimately not ours and must not be marked.
 */
static void xtree_mark_chunk(const struct xfs_geo *geo, uint32_t agno,
                             uint32_t startino, uint8_t count,
                             uint16_t holemask)
{
    uint32_t inopblock = geo->inopblock;

    if (!xtree_chunk || !inopblock)
        return;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t agino = startino + i;

        if (holemask & (1u << ((i / 4) & 15)))
            continue;
        xtree_mark(xtree_chunk, agno, agino / inopblock, 1);
    }
}

/*
 * --free-query AGNO:AGBNO:LEN (repeatable): after the BNO btree walk, report
 * whether every block of the range is free (FREE), none is (ALLOCATED) or some
 * are (PARTIAL).  This is the platter-side answer to "did the custodian's
 * completion of a dead peer's open EFI actually land": the extents the
 * obligation list named must read FREE afterwards.  Read-only.
 */
#define CHK_FREE_QUERY_MAX 16
static struct { uint32_t agno, agbno, len; } free_query[CHK_FREE_QUERY_MAX];
static int free_query_n;

static void xtree_free_query_report(const struct xfs_geo *geo)
{
    for (int q = 0; q < free_query_n; q++) {
        uint32_t agno = free_query[q].agno, agbno = free_query[q].agbno;
        uint32_t len = free_query[q].len, nfree = 0;

        if (!xtree_free) {
            printf("  FREE-QUERY ag=%u agbno=%u len=%u: UNKNOWN (no free map)\n",
                   agno, agbno, len);
            continue;
        }
        if (agno >= geo->agcount || len == 0 ||
            (uint64_t)agbno + len > geo->agblocks) {
            printf("  FREE-QUERY ag=%u agbno=%u len=%u: OUT-OF-RANGE (agcount=%u agblocks=%u)\n",
                   agno, agbno, len, geo->agcount, geo->agblocks);
            continue;
        }
        for (uint32_t i = 0; i < len; i++) {
            uint64_t b = (uint64_t)agno * xtree_agblocks + agbno + i;

            if (xtree_free[b >> 3] & (1u << (b & 7)))
                nfree++;
        }
        printf("  FREE-QUERY ag=%u agbno=%u len=%u: %s (free=%u of %u)\n",
               agno, agbno, len,
               nfree == len ? "FREE" : nfree == 0 ? "ALLOCATED" : "PARTIAL",
               nfree, len);
    }
}

static void xtree_report(const struct xfs_geo *geo)
{
    uint64_t overlaps = 0;
    uint64_t shown = 0;

    xtree_free_query_report(geo);
    if (!xtree_chunk || !xtree_free) {
        printf("  Chunk/free-space aliasing . SKIPPED (no map)\n");
        return;
    }
    for (uint64_t b = 0; b < xtree_nblocks; b++) {
        if (!(xtree_chunk[b >> 3] & (1u << (b & 7))))
            continue;
        if (!(xtree_free[b >> 3] & (1u << (b & 7))))
            continue;
        overlaps++;
        if (shown < 16) {
            shown++;
            err("AG %u block %u is inside an allocated inode chunk AND free in the BNO btree — the block can be handed to another consumer while the inobt still calls it an inode home",
                (uint32_t)(b / xtree_agblocks),
                (uint32_t)(b % xtree_agblocks));
        }
    }
    if (overlaps == 0) {
        printf("  Chunk/free-space aliasing . OK  (no inode-chunk block is also free)\n");
    } else {
        printf("  Chunk/free-space aliasing . ERRORS  (%llu block(s) claimed by both trees%s)\n",
               (unsigned long long)overlaps,
               overlaps > 16 ? ", first 16 listed" : "");
    }
    (void)geo;
    free(xtree_chunk);
    free(xtree_free);
    xtree_chunk = NULL;
    xtree_free = NULL;
}

static uint64_t validate_freespace_leaf(const uint8_t *blk, uint16_t numrecs,
                                        uint32_t agno, const char *name,
                                        bool sort_by_bno, uint32_t ag_length)
{
    uint64_t total = 0;
    uint32_t prev_key = 0;
    uint32_t prev_count = 0;

    for (uint16_t i = 0; i < numrecs; i++) {
        const uint8_t *rec = blk + BTREE_REC_OFF + i * 8;
        uint32_t startblock = get_be32(rec + 0);
        uint32_t blockcount = get_be32(rec + 4);

        if (blockcount == 0) {
            err("AG %u %s btree rec %u: blockcount is 0", agno, name, i);
            continue;
        }

        if (startblock + blockcount > ag_length) {
            err("AG %u %s btree rec %u: extent [%u+%u] exceeds AG length %u",
                agno, name, i, startblock, blockcount, ag_length);
        }

        if (sort_by_bno) {
            /* BNO: sorted by startblock ascending */
            if (i > 0 && startblock <= prev_key) {
                err("AG %u %s btree rec %u: startblock %u <= prev %u (not sorted)",
                    agno, name, i, startblock, prev_key);
            }
            prev_key = startblock;
        } else {
            /* CNT: sorted by blockcount ascending, then startblock */
            if (i > 0) {
                if (blockcount < prev_count) {
                    err("AG %u %s btree rec %u: blockcount %u < prev %u (not sorted)",
                        agno, name, i, blockcount, prev_count);
                } else if (blockcount == prev_count && startblock <= prev_key) {
                    err("AG %u %s btree rec %u: same count %u, startblock %u <= prev %u",
                        agno, name, i, blockcount, startblock, prev_key);
                }
            }
            prev_key = startblock;
            prev_count = blockcount;
        }

        if (sort_by_bno)
            xtree_mark(xtree_free, agno, startblock, blockcount);

        total += blockcount;
    }

    return total;
}

/*
 * Recursively walk a free space btree (BNO or CNT).
 * For multi-level trees, descend through internal nodes to leaf blocks.
 * Returns the total free block count from all leaf records.
 */
static uint64_t walk_freespace_btree(int fd, const struct xfs_geo *geo,
                                     uint32_t agno, uint32_t agbno,
                                     uint32_t expected_magic,
                                     const char *name, bool sort_by_bno,
                                     uint32_t expected_level,
                                     uint32_t ag_length)
{
    uint8_t *blk;
    uint64_t total = 0;

    if (expected_level >= MAX_BTREE_DEPTH) {
        err("AG %u %s btree: level %u exceeds max depth %d",
            agno, name, expected_level, MAX_BTREE_DEPTH);
        return 0;
    }

    blk = malloc(geo->blocksize);
    if (!blk) {
        err("AG %u %s btree: malloc failed", agno, name);
        return 0;
    }

    if (read_ag_block(fd, geo, agno, agbno, blk) < 0) {
        err("AG %u %s btree: read block %u failed", agno, name, agbno);
        free(blk);
        return 0;
    }

    {
        off_t blk_off = (off_t)(geo->xfs_off +
                        (uint64_t)agno * geo->agblocks * geo->blocksize +
                        (uint64_t)agbno * geo->blocksize);
        if (validate_btree_sblock(blk, geo->blocksize, expected_magic,
                                  agno, name, fd, blk_off) < 0) {
            free(blk);
            return 0;
        }
    }

    uint16_t level = get_be16(blk + 0x04);
    uint16_t numrecs = get_be16(blk + 0x06);

    if (level != expected_level) {
        err("AG %u %s btree block %u: level=%u, expected=%u",
            agno, name, agbno, level, expected_level);
        free(blk);
        return 0;
    }

    info("AG %u %s btree block %u: level=%u numrecs=%u",
         agno, name, agbno, level, numrecs);

    if (level == 0) {
        /* Leaf block — validate and sum records */
        total = validate_freespace_leaf(blk, numrecs, agno, name,
                                        sort_by_bno, ag_length);
    } else {
        /* Internal node.  Each key is [startblock(be32)][blockcount(be32)]
         * (8 bytes) at BTREE_REC_OFF; each ptr is [agbno(be32)] after the
         * block's maxrecs keys (sbtree_ptr_off). */
        uint32_t maxrecs = sbtree_node_maxrecs(geo->blocksize, 8);
        uint32_t ptr_off = sbtree_ptr_off(geo->blocksize, 8);

        if (numrecs > maxrecs) {
            err("AG %u %s btree block %u: numrecs=%u exceeds maxrecs=%u",
                agno, name, agbno, numrecs, maxrecs);
            free(blk);
            return 0;
        }
        for (uint16_t i = 0; i < numrecs; i++) {
            uint32_t child_agbno = get_be32(blk + ptr_off + i * 4);

            if (child_agbno == XFS_NULLAGBLOCK || child_agbno >= ag_length) {
                err("AG %u %s btree: internal ptr %u has invalid agbno=%u",
                    agno, name, i, child_agbno);
                continue;
            }

            total += walk_freespace_btree(fd, geo, agno, child_agbno,
                                          expected_magic, name, sort_by_bno,
                                          expected_level - 1, ag_length);
        }
    }

    free(blk);
    return total;
}

/*
 * Rebuild BNO and CNT btree roots as single-extent leaves, update AGF.
 * Used when both btrees are structurally damaged and the AG has no
 * allocated inodes, so the entire AG (minus fixed metadata) is free.
 *
 * Standard XFS AG layout (blocksize=4096):
 *   block 0: SB + AGF + AGI + AGFL (4 sectors in 1 block)
 *   block 1: BNO btree root
 *   block 2: CNT btree root
 *   block 3: inobt root
 *   blocks 4-7: AGFL entries (pre-reserved for btree splits)
 *   blocks 8+: free data space
 *
 * Writes BNO/CNT roots at standard positions (blocks 1, 2),
 * each with a single record: [startblock=8, blockcount=agf_length-8].
 * Updates AGF: bno_root=1, cnt_root=2, levels=1, freeblks, longest.
 */
static int rebuild_freespace_btrees(int fd, const struct xfs_geo *geo,
                                    uint32_t agno, uint32_t agf_length)
{
    uint32_t free_start = 8;
    uint32_t free_len = agf_length - free_start;
    uint64_t ag_base = geo->xfs_off +
                       (uint64_t)agno * geo->agblocks * geo->blocksize;
    uint8_t *blk;
    int ret;

    blk = calloc(1, geo->blocksize);
    if (!blk)
        return -1;

    /* Write BNO root leaf at block 1 */
    put_be32(blk + 0x00, MXFS_ABTB_CRC_MAGIC);
    /* level=0, numrecs=1 */
    put_be32(blk + 0x04, 0x00000001);  /* level(be16)=0, numrecs(be16)=1 */
    put_be32(blk + 0x08, 0xFFFFFFFF);  /* leftsib = null */
    put_be32(blk + 0x0C, 0xFFFFFFFF);  /* rightsib = null */
    put_be64(blk + 0x10, (ag_base + 1 * geo->blocksize) / 512);  /* blkno */
    memcpy(blk + 0x20, geo->uuid, 16);
    put_be32(blk + 0x30, agno);

    /* BNO record: [startblock, blockcount] */
    put_be32(blk + BTREE_REC_OFF, free_start);
    put_be32(blk + BTREE_REC_OFF + 4, free_len);

    ret = xfs_fix_crc_and_write(fd, blk, geo->blocksize,
                                 BTREE_CRC_OFF,
                                 ag_base + 1 * geo->blocksize);
    if (ret != 0) {
        free(blk);
        return -1;
    }

    /* Write CNT root leaf at block 2 — same record, different magic */
    memset(blk, 0, geo->blocksize);
    put_be32(blk + 0x00, MXFS_ABTC_CRC_MAGIC);
    put_be32(blk + 0x04, 0x00000001);  /* level=0, numrecs=1 */
    put_be32(blk + 0x08, 0xFFFFFFFF);
    put_be32(blk + 0x0C, 0xFFFFFFFF);
    put_be64(blk + 0x10, (ag_base + 2 * geo->blocksize) / 512);
    memcpy(blk + 0x20, geo->uuid, 16);
    put_be32(blk + 0x30, agno);
    put_be32(blk + BTREE_REC_OFF, free_start);
    put_be32(blk + BTREE_REC_OFF + 4, free_len);

    ret = xfs_fix_crc_and_write(fd, blk, geo->blocksize,
                                 BTREE_CRC_OFF,
                                 ag_base + 2 * geo->blocksize);
    free(blk);
    if (ret != 0)
        return -1;

    /* Update AGF: bno_root=1, cnt_root=2, levels=1, freeblks, longest */
    uint64_t agf_off = ag_base + 512;
    uint8_t agf_buf[512];
    if (read_at(fd, agf_buf, 512, agf_off) != 0)
        return -1;

    put_be32(agf_buf + 0x10, 1);         /* bno_root = 1 */
    put_be32(agf_buf + 0x14, 2);         /* cnt_root = 2 */
    put_be32(agf_buf + 0x1C, 1);         /* bno_level = 1 */
    put_be32(agf_buf + 0x20, 1);         /* cnt_level = 1 */
    put_be32(agf_buf + 0x34, free_len);  /* freeblks */
    put_be32(agf_buf + 0x38, free_len);  /* longest */

    return xfs_fix_crc_and_write(fd, agf_buf, 512, 0xD8, agf_off);
}

static void check_freespace_btrees(int fd, const struct xfs_geo *geo,
                                   uint32_t agno, const struct ag_info *agi,
                                   struct ag_summary *summary)
{
    int pre_errors = errors;
    uint64_t bno_total = 0;
    uint64_t cnt_total = 0;

    if (!agi->agf_ok) {
        printf("  AG %u BNO/CNT btrees .. SKIPPED (AGF errors)\n", agno);
        return;
    }

    /* Validate BNO btree */
    if (agi->bno_root >= agi->agf_length) {
        err("AG %u BNO btree: root block %u >= AG length %u",
            agno, agi->bno_root, agi->agf_length);
    } else if (agi->bno_level == 0) {
        err("AG %u BNO btree: level is 0 (must be >= 1)", agno);
    } else {
        bno_total = walk_freespace_btree(fd, geo, agno, agi->bno_root,
                                         MXFS_ABTB_CRC_MAGIC, "BNO", true,
                                         agi->bno_level - 1, agi->agf_length);
    }

    /* Validate CNT btree */
    if (agi->cnt_root >= agi->agf_length) {
        err("AG %u CNT btree: root block %u >= AG length %u",
            agno, agi->cnt_root, agi->agf_length);
    } else if (agi->cnt_level == 0) {
        err("AG %u CNT btree: level is 0 (must be >= 1)", agno);
    } else {
        cnt_total = walk_freespace_btree(fd, geo, agno, agi->cnt_root,
                                         MXFS_ABTC_CRC_MAGIC, "CNT", false,
                                         agi->cnt_level - 1, agi->agf_length);
    }

    /* Cross-check: BNO and CNT btrees should report the same total */
    if (bno_total != cnt_total) {
        err("AG %u: BNO total free=%llu != CNT total free=%llu",
            agno, (unsigned long long)bno_total, (unsigned long long)cnt_total);
    }

    /* Cross-check: BNO total should match AGF freeblks */
    if (bno_total != agi->agf_freeblks) {
        err("AG %u: BNO btree total free=%llu != AGF freeblks=%u",
            agno, (unsigned long long)bno_total, agi->agf_freeblks);

        if (can_repair() && bno_total == cnt_total && bno_total <= UINT32_MAX) {
            /* Both btrees agree — fix the AGF header */
            uint64_t ag_base = geo->xfs_off +
                               (uint64_t)agno * geo->agblocks * geo->blocksize;
            uint64_t agf_off = ag_base + 512;
            uint8_t agf_buf[512];

            if (read_at(fd, agf_buf, 512, agf_off) == 0) {
                put_be32(agf_buf + 0x34, (uint32_t)bno_total);
                if (xfs_fix_crc_and_write(fd, agf_buf, 512, 0xD8, agf_off) == 0) {
                    printf("  REPAIRED: AG %u AGF freeblks %u -> %llu\n",
                           agno, agi->agf_freeblks, (unsigned long long)bno_total);
                    repaired++;
                }
            }
        }
    }

    summary->bno_freeblks = bno_total;
    summary->agf_freeblks = (bno_total == cnt_total) ? (uint32_t)bno_total : agi->agf_freeblks;

    int btree_errors = errors - pre_errors;

    /* Repair: rebuild BNO/CNT btrees when structurally damaged and
     * no inodes are allocated in this AG.  Rewrites both btree roots
     * as single-extent leaves covering all free space in the AG. */
    bool btree_repaired = false;
    if (btree_errors > 0 && can_repair() && agi->agi_count == 0) {
        if (rebuild_freespace_btrees(fd, geo, agno, agi->agf_length) == 0) {
            uint32_t free_len = agi->agf_length - 8;
            printf("  REPAIRED: AG %u BNO/CNT btrees rebuilt (1 extent, %u free blocks)\n",
                   agno, free_len);
            repaired++;
            btree_repaired = true;
            /* Update summary to reflect rebuilt state */
            summary->bno_freeblks = free_len;
            summary->agf_freeblks = free_len;
            bno_total = free_len;
        }
    }

    printf("  AG %u BNO/CNT btrees .. %s  (free=%llu blocks)\n",
           agno,
           btree_errors == 0 ? "OK" : (btree_repaired ? "REPAIRED" : "ERRORS"),
           (unsigned long long)bno_total);
}

/* ─── Check: Inode BTree (inobt/finobt) Validation ─── */

/*
 * Inobt record: 16 bytes
 *   [0x00] startino   (be32)  — starting AG-relative inode number
 *   [0x04] holemask   (be16)  — sparse inode hole mask
 *   [0x06] count      (u8)    — total inode count in chunk (typically 64)
 *   [0x07] freecount  (u8)    — free inodes in chunk
 *   [0x08] free       (be64)  — free inode bitmask (set bit = free)
 */

struct inobt_totals {
    uint64_t    total_inodes;
    uint64_t    total_free;
    uint32_t    num_records;
};

static void validate_inobt_leaf(const uint8_t *blk, uint16_t numrecs,
                                uint32_t agno, const char *name,
                                const struct xfs_geo *geo,
                                struct inobt_totals *totals)
{
    uint32_t prev_startino = 0;

    for (uint16_t i = 0; i < numrecs; i++) {
        const uint8_t *rec = blk + BTREE_REC_OFF + i * 16;
        uint32_t startino  = get_be32(rec + 0);
        uint16_t holemask  = get_be16(rec + 4);
        uint8_t count      = rec[6];
        uint8_t freecount  = rec[7];
        uint64_t free_mask = get_be64(rec + 8);

        /* Check startino alignment: must be aligned to 64 (inodes per chunk) */
        if (startino % 64 != 0) {
            err("AG %u %s rec %u: startino=%u not aligned to 64",
                agno, name, i, startino);
        }

        /* Check ordering */
        if (i > 0 && startino <= prev_startino) {
            err("AG %u %s rec %u: startino=%u <= prev=%u (not sorted)",
                agno, name, i, startino, prev_startino);
        }
        prev_startino = startino;

        /* Check count is reasonable (64 for non-sparse, less for sparse) */
        if (count == 0 || count > 64) {
            err("AG %u %s rec %u: count=%u out of range [1..64]",
                agno, name, i, count);
            /* Record is garbage — skip remaining validation and don't
             * accumulate into totals (avoids ifree > icount underflow) */
            totals->num_records++;
            continue;
        }

        if (strcmp(name, "inobt") == 0)
            xtree_mark_chunk(geo, agno, startino, count, holemask);

        /* Check freecount <= count */
        if (freecount > count) {
            err("AG %u %s rec %u: freecount=%u > count=%u",
                agno, name, i, freecount, count);
        }

        /* Validate freecount matches popcount of free bitmask.
         * For non-sparse chunks (holemask=0), free_mask has exactly
         * freecount set bits. For sparse chunks, holes are marked in holemask
         * and corresponding bits in free_mask should also be set.
         */
        int pop = popcount64(free_mask);
        if (holemask == 0) {
            /* Non-sparse: popcount of free_mask should equal freecount */
            if (pop != freecount) {
                err("AG %u %s rec %u: freecount=%u but popcount(free)=%d",
                    agno, name, i, freecount, pop);
            }
        } else {
            /* Sparse: holes add to the free bits.
             * Each bit in holemask represents 4 inodes.
             * Hole bits in free_mask are always set.
             * freecount only counts genuinely free (non-hole) inodes.
             * So: pop = freecount + hole_inodes
             */
            int hole_inodes = 0;
            for (int h = 0; h < 16; h++) {
                if (holemask & (1 << h))
                    hole_inodes += 4;
            }
            if (pop != freecount + hole_inodes) {
                err("AG %u %s rec %u: sparse: freecount=%u, holes=%d inodes, popcount(free)=%d (expected %d)",
                    agno, name, i, freecount, hole_inodes, pop, freecount + hole_inodes);
            }
        }

        /* Check startino is within AG bounds */
        uint32_t agbno = startino >> geo->inopblog;
        if (agbno >= geo->agblocks) {
            err("AG %u %s rec %u: startino=%u maps to agbno=%u, beyond AG",
                agno, name, i, startino, agbno);
        }

        totals->total_inodes += count;
        totals->total_free += freecount;
        totals->num_records++;

        if (verbose) {
            /* the free mask is printed so an offline reader can tell, per
             * inode, whether its bit is still allocated (the retained-cohort
             * confirmation of the allocation-coverage witness) */
            info("AG %u %s rec %u: startino=%u count=%u freecount=%u holemask=0x%04X free=0x%016llX",
                 agno, name, i, startino, count, freecount, holemask,
                 (unsigned long long)free_mask);
        }
    }
}

/*
 * Recursively walk an inode btree (inobt or finobt).
 */
static void walk_inobt(int fd, const struct xfs_geo *geo,
                       uint32_t agno, uint32_t agbno,
                       uint32_t expected_magic, const char *name,
                       uint32_t expected_level, uint32_t ag_length,
                       struct inobt_totals *totals)
{
    uint8_t *blk;

    if (expected_level >= MAX_BTREE_DEPTH) {
        err("AG %u %s btree: level %u exceeds max depth %d",
            agno, name, expected_level, MAX_BTREE_DEPTH);
        return;
    }

    blk = malloc(geo->blocksize);
    if (!blk) {
        err("AG %u %s btree: malloc failed", agno, name);
        return;
    }

    if (read_ag_block(fd, geo, agno, agbno, blk) < 0) {
        err("AG %u %s btree: read block %u failed", agno, name, agbno);
        free(blk);
        return;
    }

    {
        off_t blk_off = (off_t)(geo->xfs_off +
                        (uint64_t)agno * geo->agblocks * geo->blocksize +
                        (uint64_t)agbno * geo->blocksize);
        if (validate_btree_sblock(blk, geo->blocksize, expected_magic,
                                  agno, name, fd, blk_off) < 0) {
            free(blk);
            return;
        }
    }

    uint16_t level = get_be16(blk + 0x04);
    uint16_t numrecs = get_be16(blk + 0x06);

    if (level != expected_level) {
        err("AG %u %s btree block %u: level=%u, expected=%u",
            agno, name, agbno, level, expected_level);
        free(blk);
        return;
    }

    info("AG %u %s btree block %u: level=%u numrecs=%u",
         agno, name, agbno, level, numrecs);

    if (level == 0) {
        /* Leaf — validate records */
        validate_inobt_leaf(blk, numrecs, agno, name, geo, totals);
    } else {
        /* Internal node.  Keys [startino(be32)] at BTREE_REC_OFF; ptrs
         * [agbno(be32)] after the block's maxrecs keys (sbtree_ptr_off). */
        uint32_t maxrecs = sbtree_node_maxrecs(geo->blocksize, 4);
        uint32_t ptr_off = sbtree_ptr_off(geo->blocksize, 4);

        if (numrecs > maxrecs) {
            err("AG %u %s btree block %u: numrecs=%u exceeds maxrecs=%u",
                agno, name, agbno, numrecs, maxrecs);
            free(blk);
            return;
        }
        for (uint16_t i = 0; i < numrecs; i++) {
            uint32_t child_agbno = get_be32(blk + ptr_off + i * 4);

            if (child_agbno == XFS_NULLAGBLOCK || child_agbno >= ag_length) {
                err("AG %u %s btree: internal ptr %u has invalid agbno=%u",
                    agno, name, i, child_agbno);
                continue;
            }

            walk_inobt(fd, geo, agno, child_agbno,
                       expected_magic, name,
                       expected_level - 1, ag_length, totals);
        }
    }

    free(blk);
}

/*
 * Reset an inobt/finobt root block to an empty leaf (numrecs=0).
 * Used when the btree contains only garbage records and AGI confirms
 * no real inodes exist in the AG.  Writes a clean V5 btree short-form
 * header with correct magic, UUID, owner, blkno, and CRC.
 */
static int reset_inobt_root(int fd, const struct xfs_geo *geo,
                            uint32_t agno, uint32_t root_agbno,
                            uint32_t magic)
{
    uint8_t *blk = calloc(1, geo->blocksize);
    if (!blk)
        return -1;

    /* V5 btree short-form header (56 bytes):
     * 0x00 magic(be32)  0x04 level(be16)  0x06 numrecs(be16)
     * 0x08 leftsib(be32)  0x0C rightsib(be32)
     * 0x10 blkno(be64)  0x18 lsn(be64)
     * 0x20 uuid(16B)  0x30 owner(be32)  0x34 crc(le32)
     */
    put_be32(blk + 0x00, magic);
    /* level=0, numrecs=0 already zero from calloc */
    put_be32(blk + 0x08, 0xFFFFFFFF);  /* leftsib = null */
    put_be32(blk + 0x0C, 0xFFFFFFFF);  /* rightsib = null */

    uint64_t abs_off = geo->xfs_off +
                       (uint64_t)agno * geo->agblocks * geo->blocksize +
                       (uint64_t)root_agbno * geo->blocksize;
    put_be64(blk + 0x10, abs_off / 512);  /* blkno in 512B sectors */
    /* lsn = 0 already zero */
    memcpy(blk + 0x20, geo->uuid, 16);
    put_be32(blk + 0x30, agno);  /* owner = AG number */

    int ret = xfs_fix_crc_and_write(fd, blk, geo->blocksize,
                                     BTREE_CRC_OFF, abs_off);
    free(blk);
    return ret;
}

/*
 * Reset AGI inobt level to 1 (single empty leaf) on disk.
 * Called after resetting the inobt root block to an empty leaf.
 */
static int reset_agi_level(int fd, const struct xfs_geo *geo,
                           uint32_t agno, uint32_t agi_level_off)
{
    uint64_t ag_base = geo->xfs_off +
                       (uint64_t)agno * geo->agblocks * geo->blocksize;
    uint64_t agi_off = ag_base + 1024;
    uint8_t agi_buf[512];

    if (read_at(fd, agi_buf, 512, agi_off) != 0)
        return -1;

    put_be32(agi_buf + agi_level_off, 1);
    return xfs_fix_crc_and_write(fd, agi_buf, 512, 0x138, agi_off);
}

static void check_inode_btrees(int fd, const struct xfs_geo *geo,
                               uint32_t agno, const struct ag_info *agi,
                               struct ag_summary *summary)
{
    int pre_errors = errors;
    struct inobt_totals inobt_totals;
    struct inobt_totals finobt_totals;

    memset(&inobt_totals, 0, sizeof(inobt_totals));
    memset(&finobt_totals, 0, sizeof(finobt_totals));

    if (!agi->agi_ok) {
        printf("  AG %u inobt ........... SKIPPED (AGI errors)\n", agno);
        return;
    }

    /* Validate inobt */
    if (agi->ino_root >= agi->agi_length) {
        err("AG %u inobt: root block %u >= AG length %u",
            agno, agi->ino_root, agi->agi_length);
    } else if (agi->ino_level == 0) {
        err("AG %u inobt: level is 0 (must be >= 1)", agno);
    } else {
        walk_inobt(fd, geo, agno, agi->ino_root,
                   MXFS_IBT_CRC_MAGIC, "inobt",
                   agi->ino_level - 1, agi->agi_length,
                   &inobt_totals);
    }

    /* Cross-check inobt totals vs AGI */
    bool agi_needs_fix = false;
    if (inobt_totals.total_inodes != agi->agi_count) {
        err("AG %u: inobt total inodes=%llu != AGI count=%u",
            agno, (unsigned long long)inobt_totals.total_inodes, agi->agi_count);
        agi_needs_fix = true;
    }
    if (inobt_totals.total_free != agi->agi_freecount) {
        err("AG %u: inobt total free=%llu != AGI freecount=%u",
            agno, (unsigned long long)inobt_totals.total_free, agi->agi_freecount);
        agi_needs_fix = true;
    }

    if (agi_needs_fix && can_repair() &&
        inobt_totals.total_inodes <= UINT32_MAX &&
        inobt_totals.total_free <= UINT32_MAX) {
        uint64_t ag_base = geo->xfs_off +
                           (uint64_t)agno * geo->agblocks * geo->blocksize;
        uint64_t agi_off = ag_base + 1024;
        uint8_t agi_buf[512];

        if (read_at(fd, agi_buf, 512, agi_off) == 0) {
            put_be32(agi_buf + 0x10, (uint32_t)inobt_totals.total_inodes);
            put_be32(agi_buf + 0x1C, (uint32_t)inobt_totals.total_free);
            if (xfs_fix_crc_and_write(fd, agi_buf, 512, 0x138, agi_off) == 0) {
                printf("  REPAIRED: AG %u AGI count %u->%llu, freecount %u->%llu\n",
                       agno, agi->agi_count,
                       (unsigned long long)inobt_totals.total_inodes,
                       agi->agi_freecount,
                       (unsigned long long)inobt_totals.total_free);
                repaired++;
            }
        }
    }

    summary->agi_count = (uint32_t)inobt_totals.total_inodes;
    summary->agi_freecount = (uint32_t)inobt_totals.total_free;
    summary->inobt_total = inobt_totals.total_inodes;
    summary->inobt_free = inobt_totals.total_free;

    int inobt_errors = errors - pre_errors;

    /* Repair: reset inobt root to empty leaf when the btree contains
     * only garbage records (count=0) and AGI confirms no real inodes.
     * Safe: only resets when total_inodes==0, so no allocated inodes lost. */
    bool inobt_repaired = false;
    if (inobt_errors > 0 && can_repair() &&
        inobt_totals.total_inodes == 0 && agi->agi_count == 0 &&
        inobt_totals.num_records > 0 &&
        agi->ino_root < agi->agi_length) {
        if (reset_inobt_root(fd, geo, agno, agi->ino_root,
                             MXFS_IBT_CRC_MAGIC) == 0) {
            printf("  REPAIRED: AG %u inobt root reset to empty leaf (%u garbage records cleared)\n",
                   agno, inobt_totals.num_records);
            repaired++;
            inobt_repaired = true;
        }
        /* If tree was multi-level, fix AGI level to 1 */
        if (agi->ino_level > 1) {
            /* AGI ino_level at offset 0x18 */
            if (reset_agi_level(fd, geo, agno, 0x18) == 0) {
                printf("  REPAIRED: AG %u AGI inobt level %u -> 1\n",
                       agno, agi->ino_level);
                repaired++;
            }
        }
    }

    printf("  AG %u inobt ........... %s  (%llu inodes, %llu free, %u records)\n",
           agno,
           inobt_errors == 0 ? "OK" : (inobt_repaired ? "REPAIRED" : "ERRORS"),
           (unsigned long long)inobt_totals.total_inodes,
           (unsigned long long)inobt_totals.total_free,
           inobt_totals.num_records);

    /* Validate finobt if present */
    if (geo->has_finobt) {
        int fino_pre_errors = errors;

        if (agi->fino_root >= agi->agi_length) {
            err("AG %u finobt: root block %u >= AG length %u",
                agno, agi->fino_root, agi->agi_length);
        } else if (agi->fino_level == 0) {
            err("AG %u finobt: level is 0 (must be >= 1)", agno);
        } else {
            walk_inobt(fd, geo, agno, agi->fino_root,
                       MXFS_FIBT_CRC_MAGIC, "finobt",
                       agi->fino_level - 1, agi->agi_length,
                       &finobt_totals);
        }

        /* Cross-check: finobt free count should match inobt free count */
        if (finobt_totals.total_free != inobt_totals.total_free) {
            err("AG %u: finobt total free=%llu != inobt total free=%llu",
                agno,
                (unsigned long long)finobt_totals.total_free,
                (unsigned long long)inobt_totals.total_free);
        }

        int fino_errors = errors - fino_pre_errors;

        /* Repair: reset finobt root to empty leaf (same logic as inobt) */
        bool finobt_repaired = false;
        if (fino_errors > 0 && can_repair() &&
            finobt_totals.total_free == 0 && agi->agi_freecount == 0 &&
            finobt_totals.num_records > 0 &&
            agi->fino_root < agi->agi_length) {
            if (reset_inobt_root(fd, geo, agno, agi->fino_root,
                                 MXFS_FIBT_CRC_MAGIC) == 0) {
                printf("  REPAIRED: AG %u finobt root reset to empty leaf (%u garbage records cleared)\n",
                       agno, finobt_totals.num_records);
                repaired++;
                finobt_repaired = true;
            }
            if (agi->fino_level > 1) {
                /* AGI fino_level at offset 0x14C */
                if (reset_agi_level(fd, geo, agno, 0x14C) == 0) {
                    printf("  REPAIRED: AG %u AGI finobt level %u -> 1\n",
                           agno, agi->fino_level);
                    repaired++;
                }
            }
        }

        printf("  AG %u finobt .......... %s  (%llu free, %u records)\n",
               agno,
               fino_errors == 0 ? "OK" : (finobt_repaired ? "REPAIRED" : "ERRORS"),
               (unsigned long long)finobt_totals.total_free,
               finobt_totals.num_records);
    }
}

/* ─── Check: Inode Spot-Check ─── */

/*
 * Read and validate a single on-disk inode.
 * The inode number is an absolute XFS inode number.
 * Returns 0 on success, -1 on error.
 */
static int check_one_inode(int fd, const struct xfs_geo *geo,
                           uint64_t ino, const char *label)
{
    uint8_t ibuf[1024];  /* big enough for 512-byte or 1024-byte inodes */
    int pre_errors = errors;

    if (geo->inodesize > sizeof(ibuf)) {
        err("inode %llu (%s): inodesize %u > buffer %zu",
            (unsigned long long)ino, label, geo->inodesize, sizeof(ibuf));
        return -1;
    }

    /* Calculate disk position:
     * agno = ino / (agblocks * inopblock)  — actually:
     * agno = ino >> (agblklog + inopblog)
     * agino = ino & ((1 << (agblklog + inopblog)) - 1)
     * agbno = agino >> inopblog
     * offset_in_block = (agino & ((1 << inopblog) - 1)) * inodesize
     */
    uint32_t agino_bits = geo->agblklog + geo->inopblog;
    uint32_t agno = (uint32_t)(ino >> agino_bits);
    uint32_t agino = (uint32_t)(ino & ((1ULL << agino_bits) - 1));
    uint32_t agbno = agino >> geo->inopblog;
    uint32_t offset_in_block = (agino & ((1 << geo->inopblog) - 1)) * geo->inodesize;

    uint64_t disk_off = geo->xfs_off +
                        (uint64_t)agno * geo->agblocks * geo->blocksize +
                        (uint64_t)agbno * geo->blocksize +
                        offset_in_block;

    if (read_at(fd, ibuf, geo->inodesize, disk_off) < 0) {
        err("inode %llu (%s): read failed at disk offset %llu",
            (unsigned long long)ino, label, (unsigned long long)disk_off);
        return -1;
    }

    /* Validate magic */
    uint16_t di_magic = get_be16(ibuf + 0x00);
    if (di_magic != MXFS_DINODE_MAGIC) {
        err("inode %llu (%s): magic expected 0x%04X, got 0x%04X",
            (unsigned long long)ino, label, MXFS_DINODE_MAGIC, di_magic);
        return -1;
    }

    /* Validate CRC at offset 0x64 (le32, same as XFS convention) */
    if (!xfs_verify_crc(ibuf, geo->inodesize, 0x64)) {
        uint32_t stored = *(uint32_t *)(ibuf + 0x64);
        err("inode %llu (%s): CRC stored=0x%08X, verification failed",
            (unsigned long long)ino, label, stored);

        if (can_repair()) {
            if (xfs_fix_crc_and_write(fd, ibuf, geo->inodesize,
                                       0x64, disk_off) == 0) {
                printf("  REPAIRED: inode %llu (%s) CRC recomputed\n",
                       (unsigned long long)ino, label);
                repaired++;
            }
        }
    }

    /* Check version */
    uint8_t version = ibuf[0x04];
    if (version != 3) {
        err("inode %llu (%s): version=%u, expected 3 (V5 filesystem)",
            (unsigned long long)ino, label, version);
    }

    /* Check format */
    uint8_t format = ibuf[0x05];
    if (format > XFS_DINODE_FMT_BTREE) {
        err("inode %llu (%s): format=%u out of range [0..3]",
            (unsigned long long)ino, label, format);
    }

    /* Check mode: must have file type bits */
    uint16_t mode = get_be16(ibuf + 0x02);
    uint16_t filetype = mode & 0xF000;
    if (filetype == 0) {
        err("inode %llu (%s): mode=0x%04X has no file type bits",
            (unsigned long long)ino, label, mode);
    }

    /* Metadata inodes must be linked.  For sampled inodes nlink==0 is NOT
     * classified here: an unlinked-open zombie on an AGI bucket is legal —
     * the orphan audit (check_orphan_inodes) does the bucket-aware
     * classification for every allocated inode. */
    uint32_t nlink = get_be32(ibuf + 0x10);
    if (nlink == 0 &&
        (strcmp(label, "rootdir") == 0 || strcmp(label, "rbmino") == 0 ||
         strcmp(label, "rsumino") == 0)) {
        err("inode %llu (%s): nlink=0 for metadata inode",
            (unsigned long long)ino, label, nlink);
    }

    /* Check self-referencing ino field at 0x98 (V3 inode) */
    uint64_t di_ino = get_be64(ibuf + 0x98);
    if (di_ino != ino) {
        err("inode %llu (%s): di_ino=%llu does not match expected %llu",
            (unsigned long long)ino, label,
            (unsigned long long)di_ino, (unsigned long long)ino);
    }

    int ino_errors = errors - pre_errors;

    if (verbose || ino_errors > 0) {
        const char *fmt_names[] = {"DEV", "LOCAL", "EXTENTS", "BTREE"};
        const char *fmt_name = format <= XFS_DINODE_FMT_BTREE ? fmt_names[format] : "UNKNOWN";
        info("inode %llu (%s): mode=0%o format=%s nlink=%u version=%u %s",
             (unsigned long long)ino, label,
             mode, fmt_name, nlink, version,
             ino_errors == 0 ? "OK" : "ERRORS");
    }

    return ino_errors == 0 ? 0 : -1;
}

/*
 * Walk inobt records to find a sample of allocated inodes for spot-checking.
 * Checks the root directory inode plus up to max_sample additional inodes.
 */
static void check_inode_spotcheck(int fd, const struct xfs_geo *geo)
{
    int pre_errors = errors;
    int checked = 0;
    int passed = 0;

    printf("Inode spot-check ........ ");
    fflush(stdout);

    /* Always check root directory inode */
    if (check_one_inode(fd, geo, geo->rootino, "rootdir") == 0)
        passed++;
    checked++;

    /* Check rbmino (rootino + 1) and rsumino (rootino + 2) if they exist */
    uint64_t rbmino = geo->rootino + 1;
    uint64_t rsumino = geo->rootino + 2;

    if (check_one_inode(fd, geo, rbmino, "rbmino") == 0)
        passed++;
    checked++;

    if (check_one_inode(fd, geo, rsumino, "rsumino") == 0)
        passed++;
    checked++;

    /* Walk AG 0 inobt to find a few more allocated inodes to spot-check.
     * Read the inobt root block for AG 0 and check up to 8 additional inodes.
     */
    {
        uint8_t agibuf[512];
        uint64_t agi_off = geo->xfs_off + 1024; /* AG 0 AGI */
        int max_extra = 8;
        int extra_checked = 0;

        if (read_at(fd, agibuf, 512, agi_off) == 0) {
            uint32_t ino_root = get_be32(agibuf + 0x14);
            uint32_t ino_level = get_be32(agibuf + 0x18);

            /* Only spot-check from single-level inobt (leaf root) for simplicity */
            if (ino_level == 1 && ino_root < geo->agblocks) {
                uint8_t *blk = malloc(geo->blocksize);
                if (blk && read_ag_block(fd, geo, 0, ino_root, blk) == 0) {
                    uint16_t numrecs = get_be16(blk + 0x06);

                    for (uint16_t r = 0; r < numrecs && extra_checked < max_extra; r++) {
                        const uint8_t *rec = blk + BTREE_REC_OFF + r * 16;
                        uint32_t startino = get_be32(rec + 0);
                        uint8_t count = rec[6];
                        uint64_t free_mask = get_be64(rec + 8);

                        /* Check allocated inodes in this chunk */
                        for (uint8_t bit = 0; bit < count && extra_checked < max_extra; bit++) {
                            if (!(free_mask & (1ULL << bit))) {
                                uint64_t ino = startino + bit;
                                /* Skip root/rbm/rsum — already checked */
                                if (ino == geo->rootino || ino == rbmino || ino == rsumino)
                                    continue;

                                char label[32];
                                snprintf(label, sizeof(label), "ino-%llu",
                                         (unsigned long long)ino);
                                if (check_one_inode(fd, geo, ino, label) == 0)
                                    passed++;
                                checked++;
                                extra_checked++;
                            }
                        }
                    }
                }
                free(blk);
            }
        }
    }

    int spot_errors = errors - pre_errors;
    printf("%s  (%d/%d inodes passed)\n",
           spot_errors == 0 ? "OK" : "ERRORS",
           passed, checked);
}

/* ─── Check: Orphan inode audit ─── */

/*
 * D-DESTAGE-TEAR-BUCKETLESS-ORPHAN: a dying node's partial destage can land
 * the dirent removal + nlink=0 inode while losing the same-transaction AGI
 * unlinked-bucket insert.  Nothing on disk then references the inode — no
 * dirent, no bucket — so no recovery pass will ever free it: a permanent
 * space leak invisible to every other check here.
 *
 * The audit cross-references disk truth per AG:
 *   members    = every inode reachable from the AGI's 64 unlinked buckets
 *   candidates = every inobt-allocated inode with di_mode!=0, di_nlink==0
 * candidate on a bucket   -> legal crash residue (recovery/reap will free);
 *                            reported informationally, not an error.
 * candidate on NO bucket  -> orphan (the defect).  Repair pushes it onto
 *                            bucket agino%64: inode's di_next_unlinked is
 *                            written FIRST (harmless dangling pointer if we
 *                            crash), the AGI head second (single-sector
 *                            commit point) — a torn repair rerepairs cleanly.
 */

struct orphan_list {
    uint64_t   *v;
    uint32_t    n, cap;
    bool        oom;
};

static void orphan_push(struct orphan_list *l, uint64_t val)
{
    if (l->n == l->cap) {
        uint32_t ncap = l->cap ? l->cap * 2 : 64;
        uint64_t *nv = realloc(l->v, ncap * sizeof(uint64_t));
        if (!nv) {
            l->oom = true;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n++] = val;
}

static int orphan_cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static uint64_t inode_disk_offset(const struct xfs_geo *geo,
                                  uint32_t agno, uint32_t agino)
{
    uint32_t agbno = agino >> geo->inopblog;
    uint32_t off_in_blk = (agino & ((1U << geo->inopblog) - 1)) * geo->inodesize;

    return geo->xfs_off +
           (uint64_t)agno * geo->agblocks * geo->blocksize +
           (uint64_t)agbno * geo->blocksize + off_in_blk;
}

/* Phase A: walk one AGI unlinked chain, recording members. */
static void orphan_walk_chain(int fd, const struct xfs_geo *geo,
                              uint32_t agno, int bucket, uint32_t head,
                              struct orphan_list *members)
{
    uint32_t agino = head;
    uint32_t steps = 0;
    uint8_t *ibuf = malloc(geo->inodesize);

    if (!ibuf) {
        members->oom = true;
        return;
    }
    while (agino != XFS_NULLAGINO) {
        if ((agino >> geo->inopblog) >= geo->agblocks) {
            err("AG %u unlinked bucket %d: agino %u beyond AG bounds",
                agno, bucket, agino);
            break;
        }
        if (steps++ > 1000000) {
            err("AG %u unlinked bucket %d: chain exceeds 1M entries (cycle?)",
                agno, bucket);
            break;
        }
        if (read_at(fd, ibuf, geo->inodesize,
                    inode_disk_offset(geo, agno, agino)) < 0) {
            err("AG %u unlinked bucket %d: read of agino %u failed",
                agno, bucket, agino);
            break;
        }
        if (get_be16(ibuf + 0x00) != MXFS_DINODE_MAGIC) {
            err("AG %u unlinked bucket %d: agino %u has bad inode magic 0x%04X",
                agno, bucket, agino, get_be16(ibuf + 0x00));
            break;
        }
        orphan_push(members, ((uint64_t)agno << (geo->agblklog + geo->inopblog))
                             | agino);
        /* -v names every chain member — the on-disk AGI chain-walk
         * audit (design-consult ruling) needs the ino/mode/nlink/gen of each
         * leftover so its unlink trail can be found in the nodes' logs. */
        if (verbose)
            info("  AG %u unlinked bucket %d: member ino=%llu agino=%u "
                 "mode=0%o nlink=%u gen=%u next=0x%x",
                 agno, bucket,
                 (unsigned long long)(((uint64_t)agno <<
                        (geo->agblklog + geo->inopblog)) | agino),
                 agino, get_be16(ibuf + 0x02), get_be32(ibuf + 0x10),
                 get_be32(ibuf + 0x44), get_be32(ibuf + 0x60));
        /* (D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408):
         * a chain member whose core is FREE (di_mode 0) is corruption, not a
         * pending-reap zombie.  XFS links an inode into a bucket in the same
         * transaction that writes its allocated core, and unlinks it in the
         * same transaction that zeroes di_mode — so a bucket can never reach
         * a mode-0 core on a consistent medium.  On this rig it means the
         * dead node's creation image was never applied while its inobt/AGI
         * images were (8 of 29 clean-unmount checks on 2026-08-23 listed one
         * under -v and were read as PASS).  The slot's next mount re-drives
         * this bucket and trips over it. */
        if (get_be16(ibuf + 0x02) == 0)
            err("AG %u unlinked bucket %d: member agino %u (ino %llu) has a "
                "FREE core (mode 0, nlink %u, gen %u) — bucket chain points "
                "at a freed/never-written inode",
                agno, bucket, agino,
                (unsigned long long)(((uint64_t)agno <<
                       (geo->agblklog + geo->inopblog)) | agino),
                get_be32(ibuf + 0x10), get_be32(ibuf + 0x5c));
        agino = get_be32(ibuf + 0x60);   /* di_next_unlinked */
    }
    free(ibuf);
}

/* Phase B leaf: read each chunk's inodes; allocated + mode!=0 + nlink==0
 * become candidates. */
static void orphan_collect_leaf(int fd, const struct xfs_geo *geo,
                                uint32_t agno, const uint8_t *blk,
                                uint16_t numrecs, struct orphan_list *cand,
                                uint64_t *scanned)
{
    size_t chunk_bytes = 64 * (size_t)geo->inodesize;
    uint8_t *chunk = malloc(chunk_bytes);

    if (!chunk) {
        cand->oom = true;
        return;
    }
    for (uint16_t r = 0; r < numrecs; r++) {
        const uint8_t *rec = blk + BTREE_REC_OFF + r * 16;
        uint32_t startino  = get_be32(rec + 0);
        uint16_t holemask  = get_be16(rec + 4);
        uint64_t free_mask = get_be64(rec + 8);

        if ((startino >> geo->inopblog) >= geo->agblocks)
            continue;       /* already reported by the inobt validation */
        if (read_at(fd, chunk, chunk_bytes,
                    inode_disk_offset(geo, agno, startino)) < 0) {
            err("AG %u orphan audit: chunk read at agino %u failed",
                agno, startino);
            continue;
        }
        for (int i = 0; i < 64; i++) {
            const uint8_t *dip = chunk + (size_t)i * geo->inodesize;

            if (holemask & (1U << (i / 4)))
                continue;                       /* sparse hole */
            if (free_mask & (1ULL << i))
                continue;                       /* free */
            (*scanned)++;
            if (get_be16(dip + 0x00) != MXFS_DINODE_MAGIC) {
                err("AG %u orphan audit: allocated agino %u bad magic 0x%04X",
                    agno, startino + i, get_be16(dip + 0x00));
                continue;
            }
            /* (D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-
             * ZERO-CORE-408, design-consult verification item "inobt allocated
             * implies a valid allocated dinode core"): dialloc clears the
             * inobt free bit and xfs_inode_init sets di_mode in ONE
             * transaction, and xfs_ifree sets the bit and zeroes the mode in
             * one transaction, so after a clean unmount an inobt-allocated
             * inode whose platter core is FREE (mode 0) is a half-applied
             * creation — the inode item skipped while the same transaction's
             * inobt/AGI buffer items applied.  An ERROR, whatever bucket it
             * is (or is not) on. */
            if (get_be16(dip + 0x02) == 0) {
                err("AG %u inobt-allocated agino %u (ino %llu) has a FREE "
                    "core (mode 0, nlink %u, gen %u, changecount %llu) — "
                    "P-ALLOC-FREE-CORE: creation half-applied (inobt yes, "
                    "core no)",
                    agno, startino + i,
                    (unsigned long long)(((uint64_t)agno <<
                        (geo->agblklog + geo->inopblog)) | (startino + i)),
                    get_be32(dip + 0x10), get_be32(dip + 0x5c),
                    (unsigned long long)get_be64(dip + 0x68));
                continue;
            }
            if (get_be32(dip + 0x10) == 0)      /* di_nlink */
                orphan_push(cand,
                    ((uint64_t)agno << (geo->agblklog + geo->inopblog))
                    | (startino + i));
        }
    }
    free(chunk);
}

/* Phase B: quiet recursive inobt walk (structure already validated in the
 * inobt check; failures here only bound the audit, not re-report). */
static void orphan_walk_inobt(int fd, const struct xfs_geo *geo,
                              uint32_t agno, uint32_t agbno, int depth,
                              struct orphan_list *cand, uint64_t *scanned)
{
    uint8_t *blk;

    if (depth > MAX_BTREE_DEPTH)
        return;
    blk = malloc(geo->blocksize);
    if (!blk) {
        cand->oom = true;
        return;
    }
    if (read_ag_block(fd, geo, agno, agbno, blk) < 0 ||
        get_be32(blk + 0x00) != MXFS_IBT_CRC_MAGIC) {
        free(blk);
        return;
    }
    {
        uint16_t level   = get_be16(blk + 0x04);
        uint16_t numrecs = get_be16(blk + 0x06);

        if (level == 0) {
            orphan_collect_leaf(fd, geo, agno, blk, numrecs, cand, scanned);
        } else if (numrecs <= sbtree_node_maxrecs(geo->blocksize, 4)) {
            uint32_t ptr_off = sbtree_ptr_off(geo->blocksize, 4);

            for (uint16_t i = 0; i < numrecs; i++) {
                uint32_t child = get_be32(blk + ptr_off + i * 4);

                if (child == XFS_NULLAGBLOCK || child >= geo->agblocks)
                    continue;
                orphan_walk_inobt(fd, geo, agno, child, depth + 1,
                                  cand, scanned);
            }
        }
    }
    free(blk);
}

/* Repair: push-front onto bucket agino%64.  heads[] tracks in-memory state
 * so multiple orphans in one AG chain correctly. */
static int orphan_repair_insert(int fd, const struct xfs_geo *geo,
                                uint32_t agno, uint32_t agino,
                                uint32_t heads[XFS_AGI_UNLINKED_BUCKETS])
{
    int bucket = agino % XFS_AGI_UNLINKED_BUCKETS;
    uint64_t ino_off = inode_disk_offset(geo, agno, agino);
    uint64_t agi_off = geo->xfs_off +
                       (uint64_t)agno * geo->agblocks * geo->blocksize + 1024;
    uint8_t agi_buf[512];
    uint8_t *ibuf = malloc(geo->inodesize);
    int ret = -1;

    if (!ibuf)
        return -1;
    if (read_at(fd, ibuf, geo->inodesize, ino_off) < 0)
        goto out;
    put_be32(ibuf + 0x60, heads[bucket]);       /* di_next_unlinked */
    if (xfs_fix_crc_and_write(fd, ibuf, geo->inodesize, 0x64, ino_off) < 0)
        goto out;
    if (read_at(fd, agi_buf, 512, agi_off) < 0)
        goto out;
    put_be32(agi_buf + 0x28 + 4 * bucket, agino);
    if (xfs_fix_crc_and_write(fd, agi_buf, 512, 0x138, agi_off) < 0)
        goto out;
    heads[bucket] = agino;
    ret = 0;
out:
    free(ibuf);
    return ret;
}

static void check_orphan_inodes(int fd, const struct xfs_geo *geo)
{
    int pre_errors = errors;
    uint64_t scanned = 0, zombies = 0, orphans = 0, fixed = 0;
    bool incomplete = false;

    printf("Orphan inode audit ...... ");
    fflush(stdout);

    for (uint32_t agno = 0; agno < geo->agcount; agno++) {
        uint8_t agi_buf[512];
        uint64_t agi_off = geo->xfs_off +
                           (uint64_t)agno * geo->agblocks * geo->blocksize +
                           1024;
        uint32_t heads[XFS_AGI_UNLINKED_BUCKETS];
        uint32_t ino_root, ino_level;
        struct orphan_list members = { 0 }, cand = { 0 };

        if (read_at(fd, agi_buf, 512, agi_off) < 0 ||
            get_be32(agi_buf + 0x00) != MXFS_AGI_MAGIC) {
            incomplete = true;
            continue;           /* AGI errors already reported upstream */
        }
        for (int b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++)
            heads[b] = get_be32(agi_buf + 0x28 + 4 * b);
        ino_root  = get_be32(agi_buf + 0x14);
        ino_level = get_be32(agi_buf + 0x18);

        for (int b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++)
            if (heads[b] != XFS_NULLAGINO)
                orphan_walk_chain(fd, geo, agno, b, heads[b], &members);

        if (ino_level >= 1 && ino_root < geo->agblocks)
            orphan_walk_inobt(fd, geo, agno, ino_root, 0, &cand, &scanned);

        if (members.oom || cand.oom) {
            err("AG %u orphan audit: out of memory, audit incomplete", agno);
            incomplete = true;
            goto next_ag;
        }

        if (members.n)
            qsort(members.v, members.n, sizeof(uint64_t), orphan_cmp_u64);
        for (uint32_t i = 0; i < cand.n; i++) {
            uint64_t ino = cand.v[i];

            if (members.n &&
                bsearch(&ino, members.v, members.n, sizeof(uint64_t),
                        orphan_cmp_u64)) {
                zombies++;
                continue;
            }
            orphans++;
            err("inode %llu: allocated, nlink=0, on NO AGI unlinked bucket "
                "— orphaned (space leaked, nothing will reap it)",
                (unsigned long long)ino);
            if (can_repair()) {
                uint32_t agino = (uint32_t)(ino &
                        ((1ULL << (geo->agblklog + geo->inopblog)) - 1));

                if (orphan_repair_insert(fd, geo, agno, agino, heads) == 0) {
                    printf("  REPAIRED: inode %llu linked onto AG %u unlinked "
                           "bucket %u (reaped at next recovery)\n",
                           (unsigned long long)ino, agno,
                           agino % XFS_AGI_UNLINKED_BUCKETS);
                    repaired++;
                    fixed++;
                } else {
                    err("inode %llu: orphan repair FAILED",
                        (unsigned long long)ino);
                }
            }
        }
next_ag:
        free(members.v);
        free(cand.v);
    }

    if (errors == pre_errors)
        printf("OK  (%llu allocated inodes, %llu on unlinked buckets%s)\n",
               (unsigned long long)scanned, (unsigned long long)zombies,
               incomplete ? "; INCOMPLETE" : "");
    else
        printf("ERRORS  (%llu allocated, %llu bucketed zombies, "
               "%llu orphans, %llu repaired)\n",
               (unsigned long long)scanned, (unsigned long long)zombies,
               (unsigned long long)orphans, (unsigned long long)fixed);
    if (zombies)
        info("note: %llu unlinked-but-bucketed inode(s) are legal crash "
             "residue; mount recovery reaps them", (unsigned long long)zombies);
}

/* ─── Summary Report ─── */

static void print_summary(int fd, const struct xfs_geo *geo,
                          const struct ag_summary *ag_summaries)
{
    printf("\n─── Summary ───\n");

    /* Per-AG free block counts */
    printf("  Per-AG free blocks:\n");
    for (uint32_t ag = 0; ag < geo->agcount; ag++) {
        printf("    AG %u: %u blocks (btree verified: %llu)\n",
               ag, ag_summaries[ag].agf_freeblks,
               (unsigned long long)ag_summaries[ag].bno_freeblks);
    }

    /* Total free blocks from btree walk vs superblock */
    printf("  Total free blocks (BNO btree sum): %llu\n",
           (unsigned long long)total_bno_freeblks);
    printf("  Total free blocks (AGF sum):       %llu\n",
           (unsigned long long)total_agf_freeblks);
    printf("  Superblock fdblocks:               %llu\n",
           (unsigned long long)geo->fdblocks);

    /* Note: XFS sb_fdblocks includes AGFL blocks (4 per AG), so
     * sb_fdblocks = sum(AGF.freeblks) + sum(AGFL_count_per_ag).
     * We don't read AGFL counts here, so just report the comparison. */
    bool sb_needs_fix = false;

    if (total_agf_freeblks > geo->fdblocks) {
        err("AGF freeblks sum %llu > superblock fdblocks %llu",
            (unsigned long long)total_agf_freeblks,
            (unsigned long long)geo->fdblocks);
    }
    if (total_bno_freeblks != geo->fdblocks) {
        sb_needs_fix = true;
    }

    /* Inode counts */
    printf("  Total inodes (inobt sum):          %llu\n",
           (unsigned long long)total_inobt_inodes);
    printf("  Superblock icount:                 %llu\n",
           (unsigned long long)geo->icount);

    if (total_inobt_inodes != geo->icount) {
        err("inobt total inodes %llu != superblock icount %llu",
            (unsigned long long)total_inobt_inodes,
            (unsigned long long)geo->icount);
        sb_needs_fix = true;
    }

    printf("  Total free inodes (inobt sum):     %llu\n",
           (unsigned long long)total_inobt_free);
    printf("  Superblock ifree:                  %llu\n",
           (unsigned long long)geo->ifree);

    if (total_inobt_free != geo->ifree) {
        err("inobt total free inodes %llu != superblock ifree %llu",
            (unsigned long long)total_inobt_free,
            (unsigned long long)geo->ifree);
        sb_needs_fix = true;
    }

    /* Check fdblocks: btree sum should be close to superblock value.
     * The difference is AGFL blocks, but a large discrepancy is a bug. */
    if (total_bno_freeblks != total_agf_freeblks) {
        sb_needs_fix = true;  /* AGF was already repaired above, fix SB too */
    }

    /* Repair XFS superblock counters if they don't match btree data */
    if (sb_needs_fix && can_repair()) {
        /* Read the XFS superblock */
        uint8_t sb_buf[512];
        uint64_t sb_off = geo->xfs_off;

        if (read_at(fd, sb_buf, 512, sb_off) == 0) {
            bool changed = false;

            /* Fix icount (offset 0x80, be64) */
            if (total_inobt_inodes != geo->icount) {
                put_be64(sb_buf + 0x80, total_inobt_inodes);
                printf("  REPAIRED: XFS superblock icount %llu -> %llu\n",
                       (unsigned long long)geo->icount,
                       (unsigned long long)total_inobt_inodes);
                changed = true;
            }

            /* Fix ifree (offset 0x88, be64) */
            if (total_inobt_free != geo->ifree) {
                put_be64(sb_buf + 0x88, total_inobt_free);
                printf("  REPAIRED: XFS superblock ifree %llu -> %llu\n",
                       (unsigned long long)geo->ifree,
                       (unsigned long long)total_inobt_free);
                changed = true;
            }

            /* Fix fdblocks (offset 0x90, be64) — use btree-verified sum */
            if (total_bno_freeblks != geo->fdblocks) {
                put_be64(sb_buf + 0x90, total_bno_freeblks);
                printf("  REPAIRED: XFS superblock fdblocks %llu -> %llu\n",
                       (unsigned long long)geo->fdblocks,
                       (unsigned long long)total_bno_freeblks);
                changed = true;
            }

            if (changed) {
                /* XFS sb CRC at offset 0xE0 */
                if (xfs_fix_crc_and_write(fd, sb_buf, 512, 0xE0, sb_off) == 0)
                    repaired++;
            }
        }
    }

    /* Allocated inodes */
    uint64_t allocated = total_inobt_inodes - total_inobt_free;
    printf("  Allocated inodes:                  %llu\n",
           (unsigned long long)allocated);
}

/* ─── Directory sharding (docs/dir-sharding.md) ─── */

/*
 * SipHash-2-4 reference mirror (the kernel uses <linux/siphash.h>; both
 * consume the 16-byte per-directory key as two little-endian u64s).
 * tests/dirshard_hash_vectors.sh pins this, the kernel
 * (MXFS_IOC_DIRSHARD_INFO) and the published vector to each other.
 */
static inline uint64_t ds_rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

static inline uint64_t ds_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

#define DS_SIPROUND do {                                   \
        v0 += v1; v1 = ds_rotl64(v1, 13); v1 ^= v0; v0 = ds_rotl64(v0, 32); \
        v2 += v3; v3 = ds_rotl64(v3, 16); v3 ^= v2;                          \
        v0 += v3; v3 = ds_rotl64(v3, 21); v3 ^= v0;                          \
        v2 += v1; v1 = ds_rotl64(v1, 17); v1 ^= v2; v2 = ds_rotl64(v2, 32); \
    } while (0)

static uint64_t ds_siphash24(const uint8_t key[16], const uint8_t *in,
                             size_t len)
{
    uint64_t k0 = ds_le64(key), k1 = ds_le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    const uint8_t *end = in + (len & ~(size_t)7);
    uint64_t b = (uint64_t)len << 56;

    for (; in != end; in += 8) {
        uint64_t m = ds_le64(in);
        v3 ^= m;
        DS_SIPROUND; DS_SIPROUND;
        v0 ^= m;
    }
    switch (len & 7) {
    case 7: b |= (uint64_t)in[6] << 48; /* fall through */
    case 6: b |= (uint64_t)in[5] << 40; /* fall through */
    case 5: b |= (uint64_t)in[4] << 32; /* fall through */
    case 4: b |= (uint64_t)in[3] << 24; /* fall through */
    case 3: b |= (uint64_t)in[2] << 16; /* fall through */
    case 2: b |= (uint64_t)in[1] << 8;  /* fall through */
    case 1: b |= (uint64_t)in[0];       /* fall through */
    case 0: break;
    }
    v3 ^= b;
    DS_SIPROUND; DS_SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    DS_SIPROUND; DS_SIPROUND; DS_SIPROUND; DS_SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static int ds_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int ds_parse_hex(const char *s, uint8_t *out, size_t max, size_t *lenp)
{
    size_t n = strlen(s), i;

    if (n % 2 || n / 2 > max)
        return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = ds_hexval(s[2 * i]), lo = ds_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *lenp = n / 2;
    return 0;
}

/*
 * --dirshard-hash KEYHEX NAME|hex:NAMEHEX : print the routing hash and the
 * shard index for every legal N.  No device access.
 */
static int dirshard_hash_cmd(const char *keyhex, const char *name)
{
    uint8_t key[16], buf[256];
    const uint8_t *msg;
    size_t klen = 0, mlen;
    uint64_t h;

    if (ds_parse_hex(keyhex, key, sizeof(key), &klen) < 0 || klen != 16) {
        fprintf(stderr, "chk_mxfs: --dirshard-hash needs a 32-hex-digit key\n");
        return 2;
    }
    if (strncmp(name, "hex:", 4) == 0) {
        if (ds_parse_hex(name + 4, buf, sizeof(buf), &mlen) < 0) {
            fprintf(stderr, "chk_mxfs: --dirshard-hash bad hex name\n");
            return 2;
        }
        msg = buf;
    } else {
        msg = (const uint8_t *)name;
        mlen = strlen(name);
    }
    h = ds_siphash24(key, msg, mlen);
    printf("hash=0x%016llx len=%zu shard16=%u shard32=%u shard64=%u\n",
           (unsigned long long)h, mlen,
           mxfs_dirshard_index(h, 16), mxfs_dirshard_index(h, 32),
           mxfs_dirshard_index(h, 64));
    return 0;
}

/* On-platter walk: every PARENT's locator -> holder -> manifest block ->
 * containers; every CONTAINER must be referenced by exactly one manifest
 * (or be an unlinked leftover awaiting reap). */
struct ds_ino {
    uint64_t ino;
    uint32_t gen;
    uint16_t mode;
    uint32_t nlink;
    uint64_t flags2;
    uint32_t refs;      /* manifests / locators naming it */
};

struct ds_list {
    struct ds_ino *v;
    uint32_t n, cap;
    bool oom;
};

static void ds_push(struct ds_list *l, const struct ds_ino *e)
{
    if (l->n == l->cap) {
        uint32_t ncap = l->cap ? l->cap * 2 : 64;
        struct ds_ino *nv = realloc(l->v, (size_t)ncap * sizeof(*nv));
        if (!nv) {
            l->oom = true;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n++] = *e;
}

static struct ds_ino *ds_find(struct ds_list *l, uint64_t ino)
{
    for (uint32_t i = 0; i < l->n; i++)
        if (l->v[i].ino == ino)
            return &l->v[i];
    return NULL;
}

/* v3 dinode field offsets used here (libxfs xfs_format.h struct xfs_dinode) */
#define DS_DI_MODE      0x02
#define DS_DI_FORMAT    0x05
#define DS_DI_NLINK     0x10
#define DS_DI_SIZE      0x38
#define DS_DI_NEXTENTS  0x4c
#define DS_DI_FORKOFF   0x52
#define DS_DI_AFORMAT   0x53
#define DS_DI_GEN       0x5c
#define DS_DI_FLAGS2    0x78
#define DS_DI_LITERAL   0xb0
#define DS_FMT_LOCAL    1
#define DS_FMT_EXTENTS  2
#define DS_S_IFMT       0xf000
#define DS_S_IFDIR      0x4000
#define DS_S_IFREG      0x8000

static int ds_read_dinode(int fd, const struct xfs_geo *geo, uint64_t ino,
                          uint8_t *dip)
{
    uint32_t agino_bits = geo->agblklog + geo->inopblog;
    uint32_t agno = (uint32_t)(ino >> agino_bits);
    uint32_t agino = (uint32_t)(ino & ((1ULL << agino_bits) - 1));

    if (agno >= geo->agcount || (agino >> geo->inopblog) >= geo->agblocks)
        return -1;
    if (read_at(fd, dip, geo->inodesize, inode_disk_offset(geo, agno, agino)) < 0)
        return -1;
    if (get_be16(dip + 0x00) != MXFS_DINODE_MAGIC)
        return -1;
    return 0;
}

/* Shortform ROOT xattr "mxfs.dirshard" -> locator.  0 found, -ENOENT absent,
 * -EINVAL malformed, -EOPNOTSUPP non-shortform attr fork. */
static int ds_locator_get(const struct xfs_geo *geo, const uint8_t *dip,
                          uint64_t *hino, uint32_t *hgen)
{
    uint8_t forkoff = dip[DS_DI_FORKOFF];
    const uint8_t *af, *p, *end;
    uint16_t totsize;
    uint8_t count;

    if (forkoff == 0)
        return -ENOENT;
    if (dip[DS_DI_AFORMAT] != DS_FMT_LOCAL)
        return -EOPNOTSUPP;
    af = dip + DS_DI_LITERAL + (size_t)forkoff * 8;
    if (af + 4 > dip + geo->inodesize)
        return -EINVAL;
    totsize = get_be16(af + 0);
    count = af[2];
    end = af + totsize;
    if (end > dip + geo->inodesize || totsize < 4)
        return -EINVAL;
    p = af + 4;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t namelen, valuelen, flags;

        if (p + 3 > end)
            return -EINVAL;
        namelen = p[0]; valuelen = p[1]; flags = p[2];
        if (p + 3 + namelen + valuelen > end)
            return -EINVAL;
        if ((flags & 0x02) /* XFS_ATTR_ROOT */ &&
            namelen == MXFS_DIRSHARD_XATTR_NAMELEN &&
            memcmp(p + 3, MXFS_DIRSHARD_XATTR_NAME, namelen) == 0) {
            struct mxfs_dirshard_locator loc;

            if (valuelen != MXFS_DIRSHARD_LOCATOR_LEN)
                return -EINVAL;
            memcpy(&loc, p + 3 + namelen, sizeof(loc));
            *hino = mxfs_dirshard_be64(loc.manifest_ino);
            *hgen = mxfs_dirshard_be32(loc.manifest_gen);
            return (*hino && *hgen) ? 0 : -EINVAL;
        }
        p += 3 + namelen + valuelen;
    }
    return -ENOENT;
}

/* First (only) data extent of an extents-format inode: startoff, startblock,
 * blockcount.  Returns 0, or -1 when the fork is not one real extent. */
static int ds_single_extent(const uint8_t *dip, uint64_t *startoff,
                            uint64_t *startblock, uint32_t *blockcount)
{
    uint64_t l0, l1;

    if (dip[DS_DI_FORMAT] != DS_FMT_EXTENTS || get_be32(dip + DS_DI_NEXTENTS) != 1)
        return -1;
    l0 = get_be64(dip + DS_DI_LITERAL);
    l1 = get_be64(dip + DS_DI_LITERAL + 8);
    if (l0 >> 63)               /* unwritten */
        return -1;
    *startoff = (l0 >> 9) & ((1ULL << 54) - 1);
    *startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21);
    *blockcount = (uint32_t)(l1 & ((1U << 21) - 1));
    return 0;
}

static void ds_collect_leaf(int fd, const struct xfs_geo *geo, uint32_t agno,
                            const uint8_t *blk, uint16_t numrecs,
                            struct ds_list *parents, struct ds_list *containers,
                            uint64_t *scanned)
{
    size_t chunk_bytes = 64 * (size_t)geo->inodesize;
    uint8_t *chunk = malloc(chunk_bytes);

    if (!chunk) {
        parents->oom = true;
        return;
    }
    for (uint16_t r = 0; r < numrecs; r++) {
        const uint8_t *rec = blk + BTREE_REC_OFF + r * 16;
        uint32_t startino  = get_be32(rec + 0);
        uint16_t holemask  = get_be16(rec + 4);
        uint64_t free_mask = get_be64(rec + 8);

        if ((startino >> geo->inopblog) >= geo->agblocks)
            continue;
        if (read_at(fd, chunk, chunk_bytes,
                    inode_disk_offset(geo, agno, startino)) < 0)
            continue;
        for (int i = 0; i < 64; i++) {
            const uint8_t *dip = chunk + (size_t)i * geo->inodesize;
            struct ds_ino e;

            if (holemask & (1U << (i / 4)))
                continue;
            if (free_mask & (1ULL << i))
                continue;
            if (get_be16(dip + 0x00) != MXFS_DINODE_MAGIC)
                continue;
            if (get_be16(dip + DS_DI_MODE) == 0)
                continue;
            (*scanned)++;
            e.flags2 = get_be64(dip + DS_DI_FLAGS2);
            if (!(e.flags2 & MXFS_DIFLAG2_DIRSHARD_ANY))
                continue;
            e.ino = ((uint64_t)agno << (geo->agblklog + geo->inopblog)) |
                    (startino + i);
            e.gen = get_be32(dip + DS_DI_GEN);
            e.mode = get_be16(dip + DS_DI_MODE);
            e.nlink = get_be32(dip + DS_DI_NLINK);
            e.refs = 0;
            if (e.flags2 & MXFS_DIFLAG2_DIRSHARD_PARENT)
                ds_push(parents, &e);
            else
                ds_push(containers, &e);
        }
    }
    free(chunk);
}

static void ds_walk_inobt(int fd, const struct xfs_geo *geo, uint32_t agno,
                          uint32_t agbno, int depth, struct ds_list *parents,
                          struct ds_list *containers, uint64_t *scanned)
{
    uint8_t *blk;

    if (depth > MAX_BTREE_DEPTH)
        return;
    blk = malloc(geo->blocksize);
    if (!blk) {
        parents->oom = true;
        return;
    }
    if (read_ag_block(fd, geo, agno, agbno, blk) < 0 ||
        get_be32(blk + 0x00) != MXFS_IBT_CRC_MAGIC) {
        free(blk);
        return;
    }
    {
        uint16_t level   = get_be16(blk + 0x04);
        uint16_t numrecs = get_be16(blk + 0x06);

        if (level == 0) {
            ds_collect_leaf(fd, geo, agno, blk, numrecs, parents, containers,
                            scanned);
        } else if (numrecs <= sbtree_node_maxrecs(geo->blocksize, 4)) {
            uint32_t ptr_off = sbtree_ptr_off(geo->blocksize, 4);

            for (uint16_t i = 0; i < numrecs; i++) {
                uint32_t child = get_be32(blk + ptr_off + i * 4);

                if (child == XFS_NULLAGBLOCK || child >= geo->agblocks)
                    continue;
                ds_walk_inobt(fd, geo, agno, child, depth + 1, parents,
                              containers, scanned);
            }
        }
    }
    free(blk);
}

/* Verify one PARENT end to end.  Returns the number of errors it added. */
static int ds_check_parent(int fd, const struct xfs_geo *geo,
                           struct ds_ino *pe, struct ds_list *containers,
                           uint64_t *published, uint64_t *unlinked_sets,
                           uint64_t *skipped)
{
    int pre = errors;
    uint8_t *pdip = malloc(geo->inodesize);
    uint8_t *hdip = malloc(geo->inodesize);
    uint8_t *cdip = malloc(geo->inodesize);
    uint8_t *blk = malloc(geo->blocksize);
    uint64_t hino = 0, startoff, startblock;
    uint32_t hgen = 0, blockcount;
    struct ds_ino *he;
    struct mxfs_dirshard_view v;
    enum mxfs_dirshard_check c;
    uint64_t blk_off, daddr;
    uint32_t agno, agbno;
    bool crc_ok;
    int rc;

    if (!pdip || !hdip || !cdip || !blk) {
        err("dirshard: out of memory checking parent %llu",
            (unsigned long long)pe->ino);
        goto out;
    }
    if ((pe->mode & DS_S_IFMT) != DS_S_IFDIR)
        err("dirshard parent %llu: PARENT flag on a non-directory (mode 0%o)",
            (unsigned long long)pe->ino, pe->mode);
    if (pe->flags2 & MXFS_DIFLAG2_DIRSHARD_CONTAINER)
        err("dirshard parent %llu: carries BOTH the PARENT and CONTAINER flags",
            (unsigned long long)pe->ino);
    if (ds_read_dinode(fd, geo, pe->ino, pdip) < 0) {
        err("dirshard parent %llu: dinode re-read failed",
            (unsigned long long)pe->ino);
        goto out;
    }
    rc = ds_locator_get(geo, pdip, &hino, &hgen);
    if (rc == -EOPNOTSUPP) {
        info("dirshard parent %llu: attr fork is not shortform; locator not "
             "decoded by chk_mxfs (skipped)", (unsigned long long)pe->ino);
        (*skipped)++;
        goto out;
    }
    if (rc == -ENOENT) {
        if (pe->nlink == 0) {
            info("dirshard parent %llu: no locator, nlink 0 — torn allocation "
                 "anchor awaiting reap (legal)", (unsigned long long)pe->ino);
            (*unlinked_sets)++;
        } else {
            err("dirshard parent %llu: linked (nlink %u) PARENT without a "
                "locator xattr", (unsigned long long)pe->ino, pe->nlink);
        }
        goto out;
    }
    if (rc) {
        err("dirshard parent %llu: malformed locator xattr (%d)",
            (unsigned long long)pe->ino, rc);
        goto out;
    }

    /* the holder */
    he = ds_find(containers, hino);
    if (ds_read_dinode(fd, geo, hino, hdip) < 0) {
        if (pe->nlink == 0) {
            info("dirshard parent %llu: holder %llu gone, nlink 0 — restart "
                 "after the holder free (legal)",
                 (unsigned long long)pe->ino, (unsigned long long)hino);
            (*unlinked_sets)++;
        } else {
            err("dirshard parent %llu: locator names holder %llu which is not "
                "an allocated inode", (unsigned long long)pe->ino,
                (unsigned long long)hino);
        }
        goto out;
    }
    if (get_be32(hdip + DS_DI_GEN) != hgen) {
        if (pe->nlink == 0) {
            info("dirshard parent %llu: holder %llu gen %u != %u, nlink 0 — "
                 "holder freed and reused after the set was torn down (legal)",
                 (unsigned long long)pe->ino, (unsigned long long)hino,
                 get_be32(hdip + DS_DI_GEN), hgen);
            (*unlinked_sets)++;
        } else {
            err("dirshard parent %llu: holder %llu generation %u != locator %u",
                (unsigned long long)pe->ino, (unsigned long long)hino,
                get_be32(hdip + DS_DI_GEN), hgen);
        }
        goto out;
    }
    if (he)
        he->refs++;
    else
        err("dirshard parent %llu: holder %llu lacks the CONTAINER flag",
            (unsigned long long)pe->ino, (unsigned long long)hino);
    if ((get_be16(hdip + DS_DI_MODE) & DS_S_IFMT) != DS_S_IFREG)
        err("dirshard parent %llu: holder %llu is not a regular file (mode 0%o)",
            (unsigned long long)pe->ino, (unsigned long long)hino,
            get_be16(hdip + DS_DI_MODE));
    if (get_be32(hdip + DS_DI_NLINK) != 1 && pe->nlink != 0)
        err("dirshard parent %llu: holder %llu nlink %u != 1",
            (unsigned long long)pe->ino, (unsigned long long)hino,
            get_be32(hdip + DS_DI_NLINK));
    if (ds_single_extent(hdip, &startoff, &startblock, &blockcount) < 0 ||
        startoff != 0 || blockcount != 1) {
        err("dirshard parent %llu: holder %llu data fork is not exactly one "
            "real block at offset 0 (format %u nextents %u)",
            (unsigned long long)pe->ino, (unsigned long long)hino,
            hdip[DS_DI_FORMAT], get_be32(hdip + DS_DI_NEXTENTS));
        goto out;
    }
    agno = (uint32_t)(startblock >> geo->agblklog);
    agbno = (uint32_t)(startblock & ((1ULL << geo->agblklog) - 1));
    if (agno >= geo->agcount || agbno >= geo->agblocks) {
        err("dirshard parent %llu: holder %llu block %llu outside the geometry",
            (unsigned long long)pe->ino, (unsigned long long)hino,
            (unsigned long long)startblock);
        goto out;
    }
    daddr = ((uint64_t)agno * geo->agblocks + agbno) *
            (geo->blocksize / 512);
    blk_off = geo->xfs_off + daddr * 512;
    if (read_at(fd, blk, geo->blocksize, blk_off) < 0) {
        err("dirshard parent %llu: manifest block read at %llu failed",
            (unsigned long long)pe->ino, (unsigned long long)blk_off);
        goto out;
    }
    crc_ok = xfs_verify_crc(blk, geo->blocksize, MXFS_DIRSHARD_BLK_CRC_OFF);
    {
        const struct mxfs_dirshard_blk *b = (const void *)blk;

        if (mxfs_dirshard_be32(b->magic) == MXFS_DIRSHARD_BLK_MAGIC) {
            if (memcmp(b->uuid, geo->uuid, 16) != 0)
                err("dirshard parent %llu: manifest block uuid != sb_meta_uuid",
                    (unsigned long long)pe->ino);
            if (mxfs_dirshard_be64(b->blkno) != daddr)
                err("dirshard parent %llu: manifest block blkno %llu != its "
                    "daddr %llu", (unsigned long long)pe->ino,
                    (unsigned long long)mxfs_dirshard_be64(b->blkno),
                    (unsigned long long)daddr);
        }
    }
    c = mxfs_dirshard_blk_check((const void *)blk, geo->blocksize, hino, hgen,
                                pe->ino, pe->gen, crc_ok, &v);
    if (c != MXFS_DSC_OK) {
        err("dirshard parent %llu: manifest block invalid: reason=%s (holder "
            "%llu gen %u, crc %s)", (unsigned long long)pe->ino,
            mxfs_dirshard_check_name(c), (unsigned long long)hino, hgen,
            crc_ok ? "ok" : "BAD");
        goto out;
    }

    /* lifecycle vs namespace */
    if (v.state == MXFS_DIRSHARD_ST_PUBLISHED) {
        if (pe->nlink == 0)
            err("dirshard parent %llu: manifest PUBLISHED but the parent is "
                "unlinked (nlink 0)", (unsigned long long)pe->ino);
        else
            (*published)++;
    } else {
        if (pe->nlink != 0)
            err("dirshard parent %llu: manifest state %u (not PUBLISHED) on a "
                "linked parent (nlink %u)", (unsigned long long)pe->ino,
                v.state, pe->nlink);
        else
            (*unlinked_sets)++;
    }
    if (verbose)
        info("dirshard parent %llu gen %u: state=%u nshards=%u nentries=%u "
             "mgen=%u valid_mask=0x%016llx holder=%llu blk=%llu",
             (unsigned long long)pe->ino, pe->gen, v.state, v.nshards,
             v.nentries, v.mgen, (unsigned long long)v.valid_mask,
             (unsigned long long)hino, (unsigned long long)daddr);

    /* the containers */
    for (unsigned int i = 0; i < v.nshards; i++) {
        struct ds_ino *ce;

        if (!(v.valid_mask & (1ULL << i)))
            continue;
        ce = ds_find(containers, v.shard[i].ino);
        if (ds_read_dinode(fd, geo, v.shard[i].ino, cdip) < 0 ||
            get_be32(cdip + DS_DI_GEN) != v.shard[i].gen) {
            if (v.state == MXFS_DIRSHARD_ST_DELETING || pe->nlink == 0) {
                info("dirshard parent %llu: live entry %u (ino %llu gen %u) "
                     "already gone during teardown (legal restart shape)",
                     (unsigned long long)pe->ino, i,
                     (unsigned long long)v.shard[i].ino, v.shard[i].gen);
                continue;
            }
            err("dirshard parent %llu: live entry %u names ino %llu gen %u "
                "which is not that allocated inode",
                (unsigned long long)pe->ino, i,
                (unsigned long long)v.shard[i].ino, v.shard[i].gen);
            continue;
        }
        if (!ce) {
            err("dirshard parent %llu: entry %u ino %llu lacks the CONTAINER "
                "flag", (unsigned long long)pe->ino, i,
                (unsigned long long)v.shard[i].ino);
            continue;
        }
        ce->refs++;
        if ((ce->mode & DS_S_IFMT) != DS_S_IFDIR)
            err("dirshard parent %llu: container %llu is not a directory "
                "(mode 0%o)", (unsigned long long)pe->ino,
                (unsigned long long)ce->ino, ce->mode);
        if (ce->flags2 & MXFS_DIFLAG2_DIRSHARD_PARENT)
            err("dirshard parent %llu: container %llu also carries PARENT",
                (unsigned long long)pe->ino, (unsigned long long)ce->ino);
        if (v.state == MXFS_DIRSHARD_ST_PUBLISHED && ce->nlink != 2)
            err("dirshard parent %llu: container %llu nlink %u != 2 (a child "
                "directory inside a shard is not legal in stage 1)",
                (unsigned long long)pe->ino, (unsigned long long)ce->ino,
                ce->nlink);
    }
out:
    free(pdip); free(hdip); free(cdip); free(blk);
    return errors - pre;
}

static void check_dirshard(int fd, const struct xfs_geo *geo)
{
    int pre_errors = errors;
    struct ds_list parents = { 0 }, containers = { 0 };
    uint64_t scanned = 0, published = 0, unlinked_sets = 0, skipped = 0;
    uint64_t unreferenced = 0, pending = 0;

    printf("Directory sharding ...... ");
    fflush(stdout);

    for (uint32_t agno = 0; agno < geo->agcount; agno++) {
        uint8_t agi_buf[512];
        uint64_t agi_off = geo->xfs_off +
                           (uint64_t)agno * geo->agblocks * geo->blocksize +
                           1024;
        uint32_t ino_root, ino_level;

        if (read_at(fd, agi_buf, 512, agi_off) < 0 ||
            get_be32(agi_buf + 0x00) != MXFS_AGI_MAGIC)
            continue;
        ino_root  = get_be32(agi_buf + 0x14);
        ino_level = get_be32(agi_buf + 0x18);
        if (ino_level >= 1 && ino_root < geo->agblocks)
            ds_walk_inobt(fd, geo, agno, ino_root, 0, &parents, &containers,
                          &scanned);
    }
    if (parents.oom || containers.oom) {
        err("dirshard: out of memory, audit incomplete");
        goto out;
    }

    if (!dirshard_gates_ok && (parents.n || containers.n)) {
        err("dirshard: %u PARENT and %u CONTAINER inode flags on a device "
            "without both sharding gates", parents.n, containers.n);
        goto out;
    }

    for (uint32_t i = 0; i < parents.n; i++)
        ds_check_parent(fd, geo, &parents.v[i], &containers, &published,
                        &unlinked_sets, &skipped);

    for (uint32_t i = 0; i < containers.n; i++) {
        struct ds_ino *ce = &containers.v[i];

        if (ce->refs == 1)
            continue;
        if (ce->refs > 1) {
            err("dirshard: container %llu is named by %u manifests/locators",
                (unsigned long long)ce->ino, ce->refs);
            continue;
        }
        if (ce->nlink == 0) {
            pending++;          /* on an unlinked list, awaiting its reap */
            if (verbose)
                info("dirshard: container %llu unreferenced, nlink 0 — "
                     "pending reap", (unsigned long long)ce->ino);
            continue;
        }
        if (skipped) {
            /* a parent whose locator we could not decode may own it */
            info("dirshard: container %llu (nlink %u) not attributed — a "
                 "skipped parent may own it", (unsigned long long)ce->ino,
                 ce->nlink);
            continue;
        }
        unreferenced++;
        err("dirshard: container %llu (mode 0%o nlink %u gen %u) is named by "
            "no manifest and is not unlinked — leaked internal inode",
            (unsigned long long)ce->ino, ce->mode, ce->nlink, ce->gen);
    }
out:
    printf("%s  (parents=%u published=%llu unlinked_sets=%llu containers=%u "
           "pending_reap=%llu unreferenced=%llu skipped=%llu scanned=%llu)\n",
           errors == pre_errors ? "OK" : "ERRORS", parents.n,
           (unsigned long long)published, (unsigned long long)unlinked_sets,
           containers.n, (unsigned long long)pending,
           (unsigned long long)unreferenced, (unsigned long long)skipped,
           (unsigned long long)scanned);
    free(parents.v);
    free(containers.v);
}

/* ─── Directory entries (D-0964) ───────────────────────────────────────────
 *
 * Every directory's entries are walked — shortform in the dinode, and the
 * data blocks of block-, leaf- and node-format directories — and every entry's
 * inode number is resolved against the inobt (the allocated set built from
 * the same records the inode-btree pass validated) and the dinode it names.
 * An entry naming an inode the inobt calls free, or whose dinode carries no
 * mode, is a dangling entry: it lists on every node and resolves on none, and
 * rm cannot remove it.  That is the durable outcome of a lost directory
 * update (D-0963 published a stale name set), and before this pass the checker
 * reported such a volume CLEAN because it never parsed a name.
 *
 * The counts are printed so a run that walked nothing cannot read as clean:
 * zero directories, or a root directory never walked, is itself an error.
 * Reporting only — a repair that removes a name has to maintain the block's
 * bestfree table and the leaf hash index, and it destroys the evidence the
 * pass exists to surface.
 */
#define MXFS_DIR3_BLOCK_MAGIC   0x4D444233u   /* MDB3 */
#define MXFS_DIR3_DATA_MAGIC    0x4D444433u   /* MDD3 */
#define MXFS_BMAP_CRC_MAGIC     0x4D424D33u   /* MBM3 */
#define DE_DATA_HDR_SIZE      64            /* struct xfs_dir3_data_hdr */
#define DE_BLK_HDR_OWNER_OFF  40            /* xfs_dir3_blk_hdr.owner */
#define DE_BLK_HDR_CRC_OFF    4
#define DE_LBLOCK_HDR_SIZE    72            /* long-form btree block header */
#define DE_LBLOCK_CRC_OFF     64
#define DE_FREE_TAG           0xffff
#define DE_LEAF_SPACE_BYTES   (1ULL << 35)  /* XFS_DIR2_LEAF_OFFSET */
#define DE_DI_BIG_NEXTENTS    0x18
#define DE_MAX_DIRENT_ERRORS  64            /* per volume, then a count */

struct de_u64list {
    uint64_t *v;
    uint32_t n, cap;
    bool oom;
};

static void de_push(struct de_u64list *l, uint64_t val)
{
    if (l->n == l->cap) {
        uint32_t ncap = l->cap ? l->cap * 2 : 1024;
        uint64_t *nv = realloc(l->v, (size_t)ncap * sizeof(*nv));

        if (!nv) {
            l->oom = true;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n++] = val;
}

static int de_cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

static bool de_allocated(const struct de_u64list *set, uint64_t ino)
{
    return bsearch(&ino, set->v, set->n, sizeof(uint64_t), de_cmp_u64) != NULL;
}

/* one data extent of a directory's data fork */
struct de_extent {
    uint64_t startoff;      /* fsblocks */
    uint64_t startblock;    /* fsbno */
    uint32_t blockcount;
};

struct de_extlist {
    struct de_extent *v;
    uint32_t n, cap;
    bool oom;
};

struct de_stats {
    uint64_t dirs, entries, blocks, dangling, mode0, ftype_bad;
    uint64_t dot_bad, dotdot_bad, blocks_bad, dirs_skipped, errors_shown;
    bool root_seen;
};

static void de_ext_push(struct de_extlist *l, uint64_t startoff,
                        uint64_t startblock, uint32_t blockcount)
{
    if (l->n == l->cap) {
        uint32_t ncap = l->cap ? l->cap * 2 : 16;
        struct de_extent *nv = realloc(l->v, (size_t)ncap * sizeof(*nv));

        if (!nv) {
            l->oom = true;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    l->v[l->n].startoff = startoff;
    l->v[l->n].startblock = startblock;
    l->v[l->n].blockcount = blockcount;
    l->n++;
}

/* decode one packed xfs_bmbt_rec (two be64) into the list; unwritten
 * extents are not directory data */
static void de_ext_decode(struct de_extlist *l, const uint8_t *rec)
{
    uint64_t l0 = get_be64(rec), l1 = get_be64(rec + 8);

    if (l0 >> 63)
        return;
    de_ext_push(l, (l0 >> 9) & ((1ULL << 54) - 1),
                ((l0 & 0x1ff) << 43) | (l1 >> 21),
                (uint32_t)(l1 & ((1U << 21) - 1)));
}

static int de_ext_cmp(const void *a, const void *b)
{
    const struct de_extent *x = a, *y = b;

    return x->startoff < y->startoff ? -1 : x->startoff > y->startoff;
}

/* logical fsb offset -> physical fsbno through the sorted extent list */
static bool de_ext_map(const struct de_extlist *l, uint64_t off, uint64_t *pb)
{
    uint32_t lo = 0, hi = l->n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const struct de_extent *e = &l->v[mid];

        if (off < e->startoff)
            hi = mid;
        else if (off >= e->startoff + e->blockcount)
            lo = mid + 1;
        else {
            *pb = e->startblock + (off - e->startoff);
            return true;
        }
    }
    return false;
}

/* fsbno -> device byte offset */
static uint64_t de_fsb_offset(const struct xfs_geo *geo, uint64_t fsbno,
                              bool *ok)
{
    uint32_t agno = (uint32_t)(fsbno >> geo->agblklog);
    uint32_t agbno = (uint32_t)(fsbno & ((1ULL << geo->agblklog) - 1));

    *ok = agno < geo->agcount && agbno < geo->agblocks;
    return geo->xfs_off +
           ((uint64_t)agno * geo->agblocks + agbno) * geo->blocksize;
}

/* walk a bmbt block (BMA3) collecting leaf records */
static void de_walk_bmbt(int fd, const struct xfs_geo *geo, uint64_t dirino,
                         uint64_t fsbno, int depth, struct de_extlist *l,
                         struct de_stats *st)
{
    uint8_t *blk;
    bool ok;
    uint64_t off = de_fsb_offset(geo, fsbno, &ok);

    if (depth > MAX_BTREE_DEPTH || !ok) {
        err("dirents: directory %llu bmbt block fsb %llu out of range (depth %d)",
            (unsigned long long)dirino, (unsigned long long)fsbno, depth);
        return;
    }
    blk = malloc(geo->blocksize);
    if (!blk) {
        l->oom = true;
        return;
    }
    if (read_at(fd, blk, geo->blocksize, off) < 0 ||
        get_be32(blk) != MXFS_BMAP_CRC_MAGIC) {
        err("dirents: directory %llu bmbt block fsb %llu unreadable or not BMA3",
            (unsigned long long)dirino, (unsigned long long)fsbno);
        free(blk);
        return;
    }
    if (!xfs_verify_crc(blk, geo->blocksize, DE_LBLOCK_CRC_OFF))
        err("dirents: directory %llu bmbt block fsb %llu CRC mismatch",
            (unsigned long long)dirino, (unsigned long long)fsbno);
    if (get_be64(blk + 56) != dirino)
        err("dirents: directory %llu bmbt block fsb %llu owner is %llu",
            (unsigned long long)dirino, (unsigned long long)fsbno,
            (unsigned long long)get_be64(blk + 56));
    {
        uint16_t level = get_be16(blk + 4);
        uint16_t numrecs = get_be16(blk + 6);
        uint32_t maxrecs = (geo->blocksize - DE_LBLOCK_HDR_SIZE) / 16;

        if (level == 0) {
            if (numrecs > maxrecs)
                numrecs = maxrecs;
            for (uint16_t i = 0; i < numrecs; i++)
                de_ext_decode(l, blk + DE_LBLOCK_HDR_SIZE + (size_t)i * 16);
        } else {
            /* keys (be64 startoff) then pointers (be64 fsbno) */
            size_t ptr_off = DE_LBLOCK_HDR_SIZE + (size_t)maxrecs * 8;

            if (numrecs > maxrecs)
                numrecs = maxrecs;
            for (uint16_t i = 0; i < numrecs; i++)
                de_walk_bmbt(fd, geo, dirino,
                             get_be64(blk + ptr_off + (size_t)i * 8),
                             depth + 1, l, st);
        }
    }
    free(blk);
}

/* the data fork's extents: inline list, or the bmbt rooted in the dinode */
static int de_collect_extents(int fd, const struct xfs_geo *geo,
                              uint64_t dirino, const uint8_t *dip,
                              struct de_extlist *l, struct de_stats *st)
{
    uint8_t forkoff = dip[DS_DI_FORKOFF];
    size_t dfork = forkoff ? (size_t)forkoff * 8
                           : (size_t)geo->inodesize - DS_DI_LITERAL;
    const uint8_t *fork = dip + DS_DI_LITERAL;
    uint64_t nextents = geo->has_nrext64 ? get_be64(dip + DE_DI_BIG_NEXTENTS)
                                         : get_be32(dip + DS_DI_NEXTENTS);

    if (dip[DS_DI_FORMAT] == DS_FMT_EXTENTS) {
        if (nextents * 16 > dfork) {
            err("dirents: directory %llu has %llu extents but a %zu-byte fork",
                (unsigned long long)dirino, (unsigned long long)nextents,
                dfork);
            return -1;
        }
        for (uint64_t i = 0; i < nextents; i++)
            de_ext_decode(l, fork + i * 16);
        return 0;
    }
    if (dip[DS_DI_FORMAT] == XFS_DINODE_FMT_BTREE) {
        uint16_t level = get_be16(fork), numrecs = get_be16(fork + 2);
        uint32_t maxrecs = dfork >= 4 ? (uint32_t)((dfork - 4) / 16) : 0;
        size_t ptr_off = 4 + (size_t)maxrecs * 8;

        if (level == 0 || numrecs > maxrecs || maxrecs == 0) {
            err("dirents: directory %llu bmbt root level %u numrecs %u "
                "(fork %zu bytes)", (unsigned long long)dirino, level,
                numrecs, dfork);
            return -1;
        }
        for (uint16_t i = 0; i < numrecs; i++)
            de_walk_bmbt(fd, geo, dirino,
                         get_be64(fork + ptr_off + (size_t)i * 8), 1, l, st);
        return 0;
    }
    err("dirents: directory %llu data fork format %u is not local, extents "
        "or btree", (unsigned long long)dirino, dip[DS_DI_FORMAT]);
    return -1;
}

static const char *de_ftype_name(uint8_t ft)
{
    static const char *names[] = { "unknown", "file", "dir", "chr", "blk",
                                   "fifo", "sock", "symlink", "whiteout" };

    return ft < 9 ? names[ft] : "invalid";
}

static uint8_t de_mode_ftype(uint16_t mode)
{
    switch (mode & DS_S_IFMT) {
    case 0x8000: return 1;
    case 0x4000: return 2;
    case 0x2000: return 3;
    case 0x6000: return 4;
    case 0x1000: return 5;
    case 0xC000: return 6;
    case 0xA000: return 7;
    default:     return 0;
    }
}

static void de_report(struct de_stats *st, const char *fmt, ...)
{
    va_list ap;
    char msg[512];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    errors++;
    if (st->errors_shown < DE_MAX_DIRENT_ERRORS) {
        printf("  ERROR: %s\n", msg);
    } else if (st->errors_shown == DE_MAX_DIRENT_ERRORS) {
        printf("  ERROR: (further directory-entry errors counted, not listed)\n");
    }
    st->errors_shown++;
}

/* resolve one entry: the allocated set, then the dinode it names */
static void de_check_entry(int fd, const struct xfs_geo *geo,
                           const struct de_u64list *set, uint64_t dirino,
                           const uint8_t *name, uint8_t namelen, uint64_t ino,
                           int ftype, struct de_stats *st, uint8_t *dip)
{
    uint16_t mode;
    bool dot = namelen == 1 && name[0] == '.';
    bool dotdot = namelen == 2 && name[0] == '.' && name[1] == '.';

    st->entries++;
    if (dot && ino != dirino) {
        st->dot_bad++;
        de_report(st, "directory %llu: '.' names %llu",
                  (unsigned long long)dirino, (unsigned long long)ino);
        return;
    }
    if (!de_allocated(set, ino)) {
        st->dangling++;
        de_report(st, "directory %llu: entry '%.*s' names inode %llu which "
                  "the inobt holds FREE (dangling entry)",
                  (unsigned long long)dirino, (int)namelen, name,
                  (unsigned long long)ino);
        return;
    }
    if (ds_read_dinode(fd, geo, ino, dip) < 0) {
        st->dangling++;
        de_report(st, "directory %llu: entry '%.*s' names inode %llu whose "
                  "dinode cannot be read (dangling entry)",
                  (unsigned long long)dirino, (int)namelen, name,
                  (unsigned long long)ino);
        return;
    }
    if (dip[0x04] != 3 || get_be64(dip + 0x98) != ino ||
        !xfs_verify_crc(dip, geo->inodesize, 0x64)) {
        st->mode0++;
        de_report(st, "directory %llu: entry '%.*s' names inode %llu whose "
                  "dinode is not a valid v3 dinode for that number (version "
                  "%u di_ino %llu crc %s)", (unsigned long long)dirino,
                  (int)namelen, name, (unsigned long long)ino, dip[0x04],
                  (unsigned long long)get_be64(dip + 0x98),
                  xfs_verify_crc(dip, geo->inodesize, 0x64) ? "ok" : "BAD");
        return;
    }
    mode = get_be16(dip + DS_DI_MODE);
    if (mode == 0) {
        st->mode0++;
        de_report(st, "directory %llu: entry '%.*s' names inode %llu whose "
                  "dinode has mode 0 (freed; dangling entry)",
                  (unsigned long long)dirino, (int)namelen, name,
                  (unsigned long long)ino);
        return;
    }
    if (dotdot && (mode & DS_S_IFMT) != DS_S_IFDIR) {
        st->dotdot_bad++;
        de_report(st, "directory %llu: '..' names %llu which is not a "
                  "directory (mode 0%o)", (unsigned long long)dirino,
                  (unsigned long long)ino, mode);
        return;
    }
    if (ftype > 0 && ftype != de_mode_ftype(mode)) {
        st->ftype_bad++;
        de_report(st, "directory %llu: entry '%.*s' -> inode %llu has ftype "
                  "%s but the dinode mode 0%o is a %s",
                  (unsigned long long)dirino, (int)namelen, name,
                  (unsigned long long)ino, de_ftype_name((uint8_t)ftype), mode,
                  de_ftype_name(de_mode_ftype(mode)));
    }
}

/* shortform directory: header (count, i8count, parent), then entries */
static void de_walk_shortform(int fd, const struct xfs_geo *geo,
                              const struct de_u64list *set, uint64_t dirino,
                              const uint8_t *dip, struct de_stats *st,
                              uint8_t *tdip)
{
    uint8_t forkoff = dip[DS_DI_FORKOFF];
    size_t dfork = forkoff ? (size_t)forkoff * 8
                           : (size_t)geo->inodesize - DS_DI_LITERAL;
    const uint8_t *sf = dip + DS_DI_LITERAL, *end = sf + dfork, *p;
    uint8_t count, i8count, inolen;
    uint64_t parent;
    uint64_t di_size = get_be64(dip + DS_DI_SIZE);

    if (dfork < 2 + 4) {
        de_report(st, "directory %llu: shortform fork of %zu bytes",
                  (unsigned long long)dirino, dfork);
        return;
    }
    count = sf[0];
    i8count = sf[1];
    inolen = i8count ? 8 : 4;
    parent = inolen == 8 ? get_be64(sf + 2) : get_be32(sf + 2);
    if (di_size > dfork) {
        de_report(st, "directory %llu: shortform di_size %llu exceeds the "
                  "%zu-byte fork", (unsigned long long)dirino,
                  (unsigned long long)di_size, dfork);
        return;
    }
    /* the parent is the shortform '..' */
    de_check_entry(fd, geo, set, dirino, (const uint8_t *)"..", 2, parent, 2,
                   st, tdip);
    p = sf + 2 + inolen;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t namelen;
        size_t esize;
        uint64_t ino;
        int ftype = -1;

        if (p + 3 > end) {
            de_report(st, "directory %llu: shortform entry %u runs past the "
                      "fork", (unsigned long long)dirino, i);
            return;
        }
        namelen = p[0];
        esize = 3 + (size_t)namelen + (geo->has_ftype ? 1 : 0) + inolen;
        if (namelen == 0 || p + esize > end) {
            de_report(st, "directory %llu: shortform entry %u (namelen %u) "
                      "runs past the fork", (unsigned long long)dirino, i,
                      namelen);
            return;
        }
        if (geo->has_ftype) {
            ftype = p[3 + namelen];
            if (ftype >= 9) {
                de_report(st, "directory %llu: shortform entry %u has ftype "
                          "%d, out of range (rest not walked)",
                          (unsigned long long)dirino, i, ftype);
                return;
            }
        }
        ino = inolen == 8 ? get_be64(p + esize - 8) : get_be32(p + esize - 4);
        de_check_entry(fd, geo, set, dirino, p + 3, namelen, ino, ftype, st,
                       tdip);
        p += esize;
    }
    /* the entries must consume exactly the advertised shortform payload */
    if ((size_t)(p - sf) != di_size)
        de_report(st, "directory %llu: shortform entries end at %zu bytes "
                  "but di_size is %llu", (unsigned long long)dirino,
                  (size_t)(p - sf), (unsigned long long)di_size);
}

/* one directory data block (XDB3 or XDD3) already in memory */
static void de_walk_data_block(int fd, const struct xfs_geo *geo,
                               const struct de_u64list *set, uint64_t dirino,
                               uint64_t dboff, const uint8_t *blk,
                               size_t dbsize, struct de_stats *st,
                               uint8_t *tdip)
{
    uint32_t magic = get_be32(blk);
    size_t data_end = dbsize, p;

    if (magic != MXFS_DIR3_BLOCK_MAGIC && magic != MXFS_DIR3_DATA_MAGIC) {
        st->blocks_bad++;
        de_report(st, "directory %llu: data block at offset %llu has magic "
                  "0x%08x, not XDB3/XDD3 (not walked)",
                  (unsigned long long)dirino, (unsigned long long)dboff,
                  magic);
        return;
    }
    if (!xfs_verify_crc((void *)blk, dbsize, DE_BLK_HDR_CRC_OFF)) {
        st->blocks_bad++;
        de_report(st, "directory %llu: data block at offset %llu CRC "
                  "mismatch (not walked)", (unsigned long long)dirino,
                  (unsigned long long)dboff);
        return;
    }
    if (get_be64(blk + DE_BLK_HDR_OWNER_OFF) != dirino) {
        st->blocks_bad++;
        de_report(st, "directory %llu: data block at offset %llu is owned by "
                  "%llu (not walked)", (unsigned long long)dirino,
                  (unsigned long long)dboff,
                  (unsigned long long)get_be64(blk + DE_BLK_HDR_OWNER_OFF));
        return;
    }
    if (memcmp(blk + 24, geo->uuid, 16) != 0) {
        st->blocks_bad++;
        de_report(st, "directory %llu: data block at offset %llu carries "
                  "another filesystem's uuid (not walked)",
                  (unsigned long long)dirino, (unsigned long long)dboff);
        return;
    }
    if (magic == MXFS_DIR3_BLOCK_MAGIC) {
        /* block format: leaf entries (8 bytes each) and the tail
         * (count, stale: two be32) sit at the end of the block; count
         * includes the stale slots */
        uint32_t lcount = get_be32(blk + dbsize - 8);
        uint32_t lstale = get_be32(blk + dbsize - 4);

        if (lcount > (dbsize - DE_DATA_HDR_SIZE - 8) / 8 || lstale > lcount) {
            st->blocks_bad++;
            de_report(st, "directory %llu: block-format tail count %u stale "
                      "%u does not fit (not walked)",
                      (unsigned long long)dirino, lcount, lstale);
            return;
        }
        data_end = dbsize - 8 - (size_t)lcount * 8;
    }
    st->blocks++;
    p = DE_DATA_HDR_SIZE;
    while (p < data_end) {
        if (p + 8 > data_end) {
            st->blocks_bad++;
            de_report(st, "directory %llu: block at offset %llu has %zu "
                      "trailing bytes that are no record",
                      (unsigned long long)dirino, (unsigned long long)dboff,
                      data_end - p);
            return;
        }
        if (get_be16(blk + p) == DE_FREE_TAG) {
            uint16_t len = get_be16(blk + p + 2);

            if (len < 8 || (len & 7) || p + len > data_end ||
                get_be16(blk + p + len - 2) != p) {
                st->blocks_bad++;
                de_report(st, "directory %llu: block at offset %llu has an "
                          "unused span of %u bytes at %zu whose tag is %u "
                          "(rest not walked)", (unsigned long long)dirino,
                          (unsigned long long)dboff, len, p,
                          len >= 8 && p + len <= data_end
                              ? get_be16(blk + p + len - 2) : 0);
                return;
            }
            p += len;
            continue;
        }
        {
            uint64_t ino = get_be64(blk + p);
            uint8_t namelen = blk[p + 8];
            size_t esize = 8 + 1 + (size_t)namelen + (geo->has_ftype ? 1 : 0) + 2;
            int ftype = -1;

            esize = (esize + 7) & ~(size_t)7;
            if (namelen == 0 || p + esize > data_end) {
                st->blocks_bad++;
                de_report(st, "directory %llu: block at offset %llu entry at "
                          "%zu (namelen %u) runs past the data area (rest "
                          "not walked)", (unsigned long long)dirino,
                          (unsigned long long)dboff, p, namelen);
                return;
            }
            if (geo->has_ftype) {
                ftype = blk[p + 9 + namelen];
                if (ftype >= 9) {
                    st->blocks_bad++;
                    de_report(st, "directory %llu: block at offset %llu "
                              "entry at %zu has ftype %d, out of range "
                              "(rest not walked)", (unsigned long long)dirino,
                              (unsigned long long)dboff, p, ftype);
                    return;
                }
            }
            /* the entry's tag must point back at itself */
            if (get_be16(blk + p + esize - 2) != p) {
                st->blocks_bad++;
                de_report(st, "directory %llu: block at offset %llu entry at "
                          "%zu tag is %u (rest not walked)",
                          (unsigned long long)dirino,
                          (unsigned long long)dboff, p,
                          get_be16(blk + p + esize - 2));
                return;
            }
            de_check_entry(fd, geo, set, dirino, blk + p + 9, namelen, ino,
                           ftype, st, tdip);
            p += esize;
        }
    }
}

/* every data-space directory block of a block/leaf/node directory */
static void de_walk_blocks(int fd, const struct xfs_geo *geo,
                           const struct de_u64list *set, uint64_t dirino,
                           const uint8_t *dip, struct de_stats *st,
                           uint8_t *tdip)
{
    struct de_extlist ext = { 0 };
    size_t dbsize = (size_t)geo->blocksize << geo->dirblklog;
    uint32_t dbfsb = 1U << geo->dirblklog;
    uint64_t leaf_fsb = DE_LEAF_SPACE_BYTES / geo->blocksize;
    uint8_t *buf;

    if (de_collect_extents(fd, geo, dirino, dip, &ext, st) < 0 || ext.oom) {
        if (ext.oom)
            err("dirents: out of memory collecting directory %llu extents",
                (unsigned long long)dirino);
        st->dirs_skipped++;
        free(ext.v);
        return;
    }
    buf = malloc(dbsize);
    if (!buf) {
        err("dirents: out of memory for a %zu-byte directory block", dbsize);
        st->dirs_skipped++;
        free(ext.v);
        return;
    }
    qsort(ext.v, ext.n, sizeof(*ext.v), de_ext_cmp);
    for (uint32_t i = 1; i < ext.n; i++) {
        const struct de_extent *a = &ext.v[i - 1], *b = &ext.v[i];

        if (a->startoff + a->blockcount > b->startoff) {
            st->blocks_bad++;
            de_report(st, "directory %llu: data extents [%llu+%u] and "
                      "[%llu+%u] overlap (directory not walked)",
                      (unsigned long long)dirino,
                      (unsigned long long)a->startoff, a->blockcount,
                      (unsigned long long)b->startoff, b->blockcount);
            st->dirs_skipped++;
            free(buf);
            free(ext.v);
            return;
        }
    }
    /* a directory block is dbfsb filesystem blocks and may span extents:
     * every mapped data-space filesystem block names the directory block
     * it belongs to, and each directory block is assembled once through
     * the map.  A block with any unmapped member is partial: reported,
     * never walked.  Holes between whole directory blocks are legal. */
    {
        uint64_t last_db = UINT64_MAX;

        for (uint32_t i = 0; i < ext.n; i++) {
            const struct de_extent *e = &ext.v[i];

            for (uint64_t b = 0; b < e->blockcount; b++) {
                uint64_t fsb_off = e->startoff + b;
                uint64_t db = fsb_off - fsb_off % dbfsb;
                bool complete = true;

                if (fsb_off >= leaf_fsb)
                    break;              /* leaf / free index space */
                if (db == last_db)
                    continue;
                last_db = db;
                for (uint32_t k = 0; k < dbfsb; k++) {
                    uint64_t pb;
                    bool ok = false;

                    if (de_ext_map(&ext, db + k, &pb)) {
                        uint64_t off = de_fsb_offset(geo, pb, &ok);

                        if (ok && read_at(fd, buf + (size_t)k * geo->blocksize,
                                          geo->blocksize, off) == 0)
                            continue;
                    }
                    complete = false;
                    break;
                }
                if (!complete) {
                    st->blocks_bad++;
                    de_report(st, "directory %llu: directory block at fsb "
                              "offset %llu is partially mapped or unreadable "
                              "(not walked)", (unsigned long long)dirino,
                              (unsigned long long)db);
                    continue;
                }
                de_walk_data_block(fd, geo, set, dirino, db, buf, dbsize, st,
                                   tdip);
            }
        }
    }
    free(buf);
    free(ext.v);
}

/* collect the allocated set and the directory list from one inobt leaf */
static void de_collect_leaf(int fd, const struct xfs_geo *geo, uint32_t agno,
                            const uint8_t *blk, uint16_t numrecs,
                            struct de_u64list *set, struct de_u64list *dirs)
{
    size_t chunk_bytes = 64 * (size_t)geo->inodesize;
    uint8_t *chunk = malloc(chunk_bytes);

    if (!chunk) {
        set->oom = true;
        return;
    }
    for (uint16_t r = 0; r < numrecs; r++) {
        const uint8_t *rec = blk + BTREE_REC_OFF + r * 16;
        uint32_t startino  = get_be32(rec + 0);
        uint16_t holemask  = get_be16(rec + 4);
        uint64_t free_mask = get_be64(rec + 8);
        bool have_chunk;

        if ((startino >> geo->inopblog) >= geo->agblocks)
            continue;
        have_chunk = read_at(fd, chunk, chunk_bytes,
                             inode_disk_offset(geo, agno, startino)) == 0;
        /* an unreadable chunk hides every directory in it: an error, so
         * the walk's coverage cannot silently shrink to CLEAN */
        if (!have_chunk)
            err("dirents: AG %u inode chunk at agino %u unreadable; its "
                "directories cannot be walked", agno, startino);
        for (int i = 0; i < 64; i++) {
            uint64_t ino;

            if (holemask & (1U << (i / 4)))
                continue;
            if (free_mask & (1ULL << i))
                continue;
            ino = ((uint64_t)agno << (geo->agblklog + geo->inopblog)) |
                  (startino + i);
            de_push(set, ino);
            if (have_chunk) {
                const uint8_t *dip = chunk + (size_t)i * geo->inodesize;

                if (get_be16(dip) == MXFS_DINODE_MAGIC &&
                    (get_be16(dip + DS_DI_MODE) & DS_S_IFMT) == DS_S_IFDIR)
                    de_push(dirs, ino);
            }
        }
    }
    free(chunk);
}

static void de_walk_inobt(int fd, const struct xfs_geo *geo, uint32_t agno,
                          uint32_t agbno, int depth, struct de_u64list *set,
                          struct de_u64list *dirs)
{
    uint8_t *blk;

    if (depth > MAX_BTREE_DEPTH)
        return;
    blk = malloc(geo->blocksize);
    if (!blk) {
        set->oom = true;
        return;
    }
    if (read_ag_block(fd, geo, agno, agbno, blk) < 0 ||
        get_be32(blk + 0x00) != MXFS_IBT_CRC_MAGIC) {
        free(blk);
        return;
    }
    {
        uint16_t level   = get_be16(blk + 0x04);
        uint16_t numrecs = get_be16(blk + 0x06);

        if (level == 0) {
            de_collect_leaf(fd, geo, agno, blk, numrecs, set, dirs);
        } else if (numrecs <= sbtree_node_maxrecs(geo->blocksize, 4)) {
            uint32_t ptr_off = sbtree_ptr_off(geo->blocksize, 4);

            for (uint16_t i = 0; i < numrecs; i++) {
                uint32_t child = get_be32(blk + ptr_off + i * 4);

                if (child == XFS_NULLAGBLOCK || child >= geo->agblocks)
                    continue;
                de_walk_inobt(fd, geo, agno, child, depth + 1, set, dirs);
            }
        }
    }
    free(blk);
}

static void check_dirents(int fd, const struct xfs_geo *geo)
{
    int pre_errors = errors;
    struct de_u64list set = { 0 }, dirs = { 0 };
    struct de_stats st = { 0 };
    uint8_t *dip = malloc(geo->inodesize);
    uint8_t *tdip = malloc(geo->inodesize);

    /* under -v the per-directory lines print during the walk, so the
     * verdict line is printed whole at the end; otherwise the header shows
     * progress the way the other passes do */
    if (!verbose) {
        printf("Directory entries ....... ");
        fflush(stdout);
    }
    if (!dip || !tdip) {
        err("dirents: out of memory");
        goto out;
    }
    for (uint32_t agno = 0; agno < geo->agcount; agno++) {
        uint8_t agi_buf[512];
        uint64_t agi_off = geo->xfs_off +
                           (uint64_t)agno * geo->agblocks * geo->blocksize +
                           1024;
        uint32_t ino_root, ino_level;

        if (read_at(fd, agi_buf, 512, agi_off) < 0 ||
            get_be32(agi_buf + 0x00) != MXFS_AGI_MAGIC)
            continue;
        ino_root  = get_be32(agi_buf + 0x14);
        ino_level = get_be32(agi_buf + 0x18);
        if (ino_level >= 1 && ino_root < geo->agblocks)
            de_walk_inobt(fd, geo, agno, ino_root, 0, &set, &dirs);
    }
    if (set.oom || dirs.oom) {
        err("dirents: out of memory, audit incomplete");
        goto out;
    }
    qsort(set.v, set.n, sizeof(uint64_t), de_cmp_u64);

    for (uint32_t d = 0; d < dirs.n; d++) {
        uint64_t dirino = dirs.v[d];

        if (ds_read_dinode(fd, geo, dirino, dip) < 0) {
            de_report(&st, "directory %llu: dinode re-read failed",
                      (unsigned long long)dirino);
            st.dirs_skipped++;
            continue;
        }
        st.dirs++;
        if (dirino == geo->rootino)
            st.root_seen = true;
        {
            uint64_t e0 = st.entries, b0 = st.blocks, d0 = st.dangling +
                          st.mode0, x0 = st.blocks_bad;

            if (dip[DS_DI_FORMAT] == DS_FMT_LOCAL)
                de_walk_shortform(fd, geo, &set, dirino, dip, &st, tdip);
            else
                de_walk_blocks(fd, geo, &set, dirino, dip, &st, tdip);
            /* one line per directory under -v: a harness asserts the
             * walk's count against what it created */
            info("dirents: directory %llu format=%s entries=%llu blocks=%llu "
                 "dangling=%llu bad_blocks=%llu",
                 (unsigned long long)dirino,
                 dip[DS_DI_FORMAT] == DS_FMT_LOCAL ? "shortform"
                 : dip[DS_DI_FORMAT] == DS_FMT_EXTENTS ? "extents" : "btree",
                 (unsigned long long)(st.entries - e0),
                 (unsigned long long)(st.blocks - b0),
                 (unsigned long long)(st.dangling + st.mode0 - d0),
                 (unsigned long long)(st.blocks_bad - x0));
        }
    }
    if (st.dirs == 0)
        err("dirents: no directory was walked (the allocated set holds %u "
            "inodes)", set.n);
    else if (!st.root_seen)
        err("dirents: the root directory %llu was not walked",
            (unsigned long long)geo->rootino);
out:
    printf("%s%s  (dirs=%llu entries=%llu blocks=%llu dangling=%llu mode0=%llu "
           "ftype_mismatch=%llu bad_blocks=%llu dirs_skipped=%llu "
           "allocated=%u)\n",
           verbose ? "Directory entries ....... " : "",
           errors == pre_errors ? "OK" : "ERRORS",
           (unsigned long long)st.dirs, (unsigned long long)st.entries,
           (unsigned long long)st.blocks, (unsigned long long)st.dangling,
           (unsigned long long)st.mode0, (unsigned long long)st.ftype_bad,
           (unsigned long long)st.blocks_bad,
           (unsigned long long)st.dirs_skipped, set.n);
    free(dip);
    free(tdip);
    free(set.v);
    free(dirs.v);
}

/* ─── Usage ─── */

/*
 * C7 version gate — offline format upgrade (-U / --upgrade-protogate).
 *
 * Stamps a legacy MXFS format with the protocol gate so pre-gate kernels can
 * no longer mount it and gate-aware kernels admit it RW:
 *   1. proves the cluster is offline: the device is opened O_EXCL (fails if
 *      locally mounted) and every ACTIVE disklock heartbeat record must NOT
 *      advance across a 3 s recheck (a live remote mount ⇒ refuse);
 *   2. writes the envelope gate (MXFS_FORMAT_F_PROTOGATE +
 *      cluster_proto_gen) FIRST — an interrupted upgrade then reads as the
 *      explicit "half-upgraded, run chk_mxfs -U" state on gate-aware
 *      kernels, never a silently lost gate;
 *   3. sets XFS_SB_FEAT_INCOMPAT_MXFS_PROTOGATE (bit 30) in every SECONDARY
 *      superblock, then the PRIMARY last — the single-sector primary write
 *      is the atomic moment old kernels get locked out.
 * Idempotent: rerunning completes/repairs any interrupted state.
 */
#define CHK_SB_INCOMPAT_MXFS_PROTOGATE  (1u << 30)

/* ─── SHA-256 (FIPS 180-4), self-contained ──────────────────────────────────
 *
 * The ruling asked for a cryptographic digest over the archived
 * evidence: the two-seed CRC32C verdict digest is a fine wrong-token detector
 * but is not tamper-resistant, and an archive that outlives the filesystem it
 * describes is an audit artefact.  chk_mxfs is deliberately a single-file
 * build with no library dependencies, so the hash comes with it.
 */
struct sha256_ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   n;
};

static const uint32_t sha256_k[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define SHR32(x,n)  ((x) >> (n))
#define ROR32(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7) ^ ROR32(w[i-15],18) ^ SHR32(w[i-15],3);
        uint32_t s1 = ROR32(w[i-2],17) ^ ROR32(w[i-2],19) ^ SHR32(w[i-2],10);

        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6];  h=c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);

        t1 = h + S1 + ch + sha256_k[i] + w[i];
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g;  c->h[7]+=h;
}

static void sha256_init(struct sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->n = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;

    c->len += len;
    while (len) {
        size_t take = 64 - c->n;

        if (take > len)
            take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) {
            sha256_block(c, c->buf);
            c->n = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    uint8_t zero = 0;
    uint8_t lenb[8];
    int i;

    sha256_update(c, &pad, 1);
    while (c->n != 56)
        sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        lenb[i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_update(c, lenb, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

static void sha256_hex(const uint8_t d[32], char out[65])
{
    static const char hx[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 32; i++) {
        out[i*2]   = hx[d[i] >> 4];
        out[i*2+1] = hx[d[i] & 0xF];
    }
    out[64] = 0;
}

/*
 * --show-quarantine — read the terminal recovery verdicts off the platter.
 *
 * D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376, design-consult ruling
 * step 1 of the repair state machine ("validate and display": print volume
 * UUID, slice/slot, victim identity, incarnation, PR key, fence kind, refusal
 * reason, quarantine domain and digest; require confirmation tied to that
 * digest).  This command is the DISPLAY half, shipped on its own because the
 * operator currently has no way at all to see a verdict when the quarantine
 * is what stops them mounting.
 *
 * Strictly read-only.  It does NOT need the cluster offline — it is most
 * useful precisely when a node cannot mount — so it reads with O_DIRECT: the
 * local block-device page cache can hold sectors this node cached before a
 * peer rewrote them, and a buffered re-read would return that stale copy.
 */
static int do_show_quarantine(const char *device)
{
    struct mxfs_ondisk_super sup;
    uint8_t *aligned = NULL;
    uint8_t supbuf[MXFS_SUPER_SIZE];
    int fd = -1, dfd = -1;
    uint32_t slot, slice_count;
    int n_guard = 0, n_active = 0, n_withdrawn = 0, n_other = 0;
    int n_outofrange = 0, n_readable = 0, n_unreadable = 0, n_sweepguard = 0;
    int n_inprogress = 0;   /* (D-379 item 5) */
    int n_released = 0;
    int rc = 4;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n",
                device, strerror(errno));
        return 4;
    }
    if (read_at(fd, supbuf, MXFS_SUPER_SIZE, 0) < 0) {
        fprintf(stderr, "chk_mxfs: cannot read the MXFS envelope\n");
        goto out;
    }
    memcpy(&sup, supbuf, sizeof(sup));
    if (sup.magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "chk_mxfs: no MXFS envelope on %s\n", device);
        goto out;
    }
    slice_count = sup.xfs_log_node_count;

    dfd = open(device, O_RDONLY | O_DIRECT);
    if (dfd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s O_DIRECT: %s\n",
                device, strerror(errno));
        goto out;
    }
    if (posix_memalign((void **)&aligned, 4096, 4096) != 0) {
        fprintf(stderr, "chk_mxfs: out of memory\n");
        goto out;
    }

    printf("chk_mxfs v%s -- terminal recovery quarantines on %s\n",
           CHK_MXFS_VERSION, device);
    printf("volume uuid  %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
           "%02x%02x%02x%02x%02x%02x\n",
           sup.fs_uuid[0], sup.fs_uuid[1], sup.fs_uuid[2], sup.fs_uuid[3],
           sup.fs_uuid[4], sup.fs_uuid[5], sup.fs_uuid[6], sup.fs_uuid[7],
           sup.fs_uuid[8], sup.fs_uuid[9], sup.fs_uuid[10], sup.fs_uuid[11],
           sup.fs_uuid[12], sup.fs_uuid[13], sup.fs_uuid[14], sup.fs_uuid[15]);
    printf("log slices   %u  (slot index == slice index; slots %u..%u bear no "
           "journal)\n",
           slice_count, slice_count, MXFS_DISKLOCK_HB_SLOTS - 1);

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint64_t off = sup.disklock_offset +
                       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
        const struct chk_hb_hdr *h = (const void *)aligned;
        ssize_t got;

        /* O_DIRECT needs offset, length and buffer all block-aligned; the
         * disklock region is sector-based, so read a 4096 window containing
         * the sector when the offset is not itself 4096-aligned. */
        {
            uint64_t base = off & ~(uint64_t)4095;
            uint64_t delta = off - base;

            got = pread(dfd, aligned, 4096, (off_t)base);
            if (got != 4096) {
                err("heartbeat slot %u: O_DIRECT read failed: %s",
                    slot, strerror(errno));
                n_unreadable++;
                continue;
            }
            if (delta)
                memmove(aligned, aligned + delta, 512);
        }

        if (h->magic != MXFS_DISKLOCK_MAGIC) {
            bool nonzero = false;
            int b;

            for (b = 0; b < 512; b++)
                if (aligned[b] != 0) { nonzero = true; break; }
            if (nonzero && slot >= slice_count)
                n_outofrange++;
            continue;
        }

        if (slot >= slice_count)
            n_outofrange++;

        switch (h->flags) {
        case MXFS_DISKLOCK_FLAG_ACTIVE:
            n_active++;
            if (verbose)
                printf("  slot %2u: ACTIVE node=%u incarnation=%llu\n",
                       slot, h->node_id, (unsigned long long)h->epoch);
            break;
        case MXFS_DISKLOCK_FLAG_WITHDRAWN_C:
            n_withdrawn++;
            printf("  slot %2u: WITHDRAWN node=%u — a dirty journal slice "
                   "awaiting fence+replay (transient)\n", slot, h->node_id);
            break;
        case MXFS_DISKLOCK_FLAG_RETIRE_PENDING_C:
            n_withdrawn++;
            printf("  slot %2u: RETIRE_PENDING node=%u — clean release "
                   "awaiting PR-key retirement proof (transient; a live "
                   "peer settles it)\n", slot, h->node_id);
            break;
        case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C: {
            int gr = chk_print_guard(slot, aligned, sup.fs_uuid,
                                     (uint16_t)slice_count);

            if (gr == 2) {
                n_sweepguard++;
                if (slot >= slice_count)
                    n_outofrange--;   /* legitimate up here — see below */
            } else if (gr == 3) {
                n_inprogress++;       /* recovery guard, not a verdict */
            } else {
                n_guard++;
                if (gr == 1)
                    n_readable++;
            }
            /* a readable guard may name an obligation list */
            if (gr == 1 || gr == 3) {
                struct chk_recov_obl ob;

                if (chk_print_obl_record(slot, aligned, &ob) == 1) {
                    chk_print_obl_list(dfd, sup.rman_offset, slot, aligned, &ob);
                    chk_print_obl_proof(dfd, sup.rman_offset, slot, aligned, &ob);
                }
            }
            break;
        }
        case 0:  /* MXFS_DISKLOCK_FLAG_EMPTY */
            /* a CLEANLY RELEASED slot keeps the MXLK magic and
             * carries flags == EMPTY.  It is free, not damaged — reporting it
             * as an "unknown record" made a healthy fully-departed cluster
             * look like it had 31 corrupt sectors. */
            n_released++;
            if (verbose)
                printf("  slot %2u: released (clean departure, node %u)\n",
                       slot, h->node_id);
            break;
        default:
            n_other++;
            err("heartbeat slot %u: unknown record flags=%u node=%u",
                slot, h->flags, h->node_id);
            break;
        }
    }

    printf("\n── summary ────────────────────────────────────────────────────\n");
    printf("  live members            %d\n", n_active);
    printf("  quarantined verdicts    %d  (%d readable, %d corrupt/absent)\n",
           n_guard, n_readable, n_guard - n_readable);
    printf("  withdrawn slices        %d\n", n_withdrawn);
    printf("  recoveries in progress  %d  (RECOVERY GUARD without a terminal "
           "verdict)\n", n_inprogress);
    printf("  bucket-sweep guards     %d  (transient; slots >= %u are their "
           "normal home)\n", n_sweepguard, slice_count);
    printf("  released slots          %d  (clean departures; free to claim)\n",
           n_released);
    printf("  unknown records         %d\n", n_other);
    printf("  unreadable sectors      %d\n", n_unreadable);
    if (n_outofrange > 0)
        printf("  OUT-OF-RANGE occupants  %d MEMBER-shaped record(s) at or "
               "above slot %u — a\n"
               "                          FORMAT/PROTOCOL VIOLATION; this "
               "volume has no journal\n"
               "                          slice for them.  (Bucket-sweep "
               "guards up here are normal\n"
               "                          and are not counted.)\n",
               n_outofrange, slice_count);
    printf("  usable RW slices        %d of %u\n",
           (int)slice_count - n_guard, slice_count);

    if (n_guard) {
        printf("\n  A quarantined slice's committed transactions were never "
               "applied and\n"
               "  cannot be applied safely.  Its slot therefore stays "
               "unclaimable, and\n"
               "  the cluster runs that many members short.\n"
               "  DO NOT reformat to free it: mkfs_mxfs -f erases the verdict "
               "above, and\n"
               "  at 32 slices there is no larger format (mkfs_mxfs refuses "
               "-n > 32).\n"
               "  The repair path that accepts the loss and releases the slot "
               "is not\n"
               "  implemented yet (D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-"
               "ADMISSION-376).\n");
        rc = 4;
    } else {
        printf("\n  No terminal recovery quarantine on this volume.\n");
        rc = 0;
    }
    if (n_inprogress) {
        /*
         * (D-379 item 5): a guard at stage 1 whose fence certificate
         * is kind 0/6 (NONE / KEY_ABSENT_UNPROVEN) is a recovery that cannot
         * advance by itself; while it stands the mount admission barrier
         * refuses EVERY new mount of this volume (it requires the slice
         * REPLAYED), not merely one slot.  Say so and name the remedy.
         */
        printf("\n  %d recovery guard(s) are IN PROGRESS (no terminal verdict). "
               "While a\n"
               "  guard stands, the mount admission barrier refuses every new "
               "mount until\n"
               "  the slice is replayed — this blocks the whole volume, not one "
               "slot.\n"
               "  A live recovery OWNER advances it.  If the guard's stage stays "
               "at 1 with\n"
               "  fence kind 0 (NONE) or 6 (KEY_ABSENT_UNPROVEN) it is STUCK: "
               "the victim's PR\n"
               "  key is gone and nothing can prove exclusion.  Remedy: bring "
               "the victim\n"
               "  back so its key is registered again, then mount a peer that "
               "can PREEMPT\n"
               "  AND ABORT it (0.40.0 retains the key on dirty departures).  "
               "There is no\n"
               "  operator override: single_node_exclusive=1 used to certify "
               "this as fence\n"
               "  kind 17 and no longer does, because asserting that no other "
               "INITIATOR can\n"
               "  write says nothing about writes the target already accepted "
               "from the dead\n"
               "  INCARNATION, and replaying against those corrupts silently.  "
               "See D-0355.\n",
               n_inprogress);
        if (rc == 0)
            rc = 5;
    }

out:
    free(aligned);
    if (dfd >= 0)
        close(dfd);
    if (fd >= 0)
        close(fd);
    return rc;
}

/* ─── Exclusion proofs for the offline quarantine repair ────────────────────
 *
 * ruling: "'every node unmounted' is necessary but NOT sufficient …
 * absence of fresh heartbeat records is not proof of exclusion."  Three
 * independent proofs are required before anything destructive happens, and
 * every one of them fails CLOSED:
 *
 *   LOCAL   the device opens O_EXCL (no local mount, no other opener).
 *   REMOTE  no ACTIVE heartbeat record advances across a recheck window, AND
 *           no slot other than the quarantined one is occupied at all — a
 *           stale non-advancing ACTIVE record is a CRASHED node whose slice is
 *           dirty, which is a different refusal but an equally hard one.
 *   LUN     SCSI PERSISTENT RESERVE IN / READ KEYS reports no registrant.
 *           A registered initiator can write to this LUN right now whatever
 *           its heartbeat says.  If the LUN answers "no PR support", exclusion
 *           cannot be proved here and the repair refuses.
 */
/* PR READ KEYS: mxfs_off_pr_read_keys, tools/mxfs_offline.h */

/* ─── Backing-device disjointness for --archive-to ──────────────────────────
 *
 * ruling: the archive destination must be "proven disjoint from every
 * backing device of the repair target; inability to establish disjointness is
 * an error".  Resolve both sides to their set of LEAF block devices by walking
 * /sys/dev/block/<maj>:<min>/slaves recursively — that unwinds device-mapper,
 * LVM, MD and multipath — and refuse on any overlap.  "Another partition on
 * the same failing disk" is NOT independent preservation, so the comparison is
 * against leaves, not against the logical device.
 */
#define CHK_LEAF_MAX 64
struct chk_leafset {
    char name[CHK_LEAF_MAX][64];
    int  n;
    int  overflow;
};

static void chk_leaf_add(struct chk_leafset *s, const char *name)
{
    int i;

    for (i = 0; i < s->n; i++)
        if (strcmp(s->name[i], name) == 0)
            return;
    if (s->n >= CHK_LEAF_MAX) {
        s->overflow = 1;
        return;
    }
    snprintf(s->name[s->n], sizeof(s->name[0]), "%s", name);
    s->n++;
}

static void chk_collect_leaves(const char *devname, struct chk_leafset *s,
                               int depth)
{
    char path[PATH_MAX];
    DIR *d;
    struct dirent *e;
    int nslaves = 0;

    if (depth > 8) {                 /* pathological stack: cannot prove */
        s->overflow = 1;
        return;
    }
    snprintf(path, sizeof(path), "/sys/class/block/%s/slaves", devname);
    d = opendir(path);
    if (d) {
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.')
                continue;
            nslaves++;
            chk_collect_leaves(e->d_name, s, depth + 1);
        }
        closedir(d);
    }
    if (nslaves == 0) {
        /* A partition's leaf is its whole disk: /sys/class/block/sda1/../ is
         * sda.  Two partitions of one disk must therefore collide. */
        char part[PATH_MAX];
        char real[PATH_MAX];
        char *slash, *base;

        snprintf(part, sizeof(part), "/sys/class/block/%s/partition", devname);
        if (access(part, F_OK) == 0) {
            snprintf(path, sizeof(path), "/sys/class/block/%s", devname);
            if (realpath(path, real)) {
                slash = strrchr(real, '/');
                if (slash) {
                    *slash = 0;
                    base = strrchr(real, '/');
                    if (base) {
                        chk_leaf_add(s, base + 1);
                        return;
                    }
                }
            }
        }
        chk_leaf_add(s, devname);
    }
}

/* maj:min -> kernel block-device name, via /sys/dev/block. */
static int chk_devname_of(dev_t rdev, char *out, size_t outsz)
{
    char link[PATH_MAX], real[PATH_MAX], *base;

    snprintf(link, sizeof(link), "/sys/dev/block/%u:%u",
             major(rdev), minor(rdev));
    if (!realpath(link, real))
        return -1;
    base = strrchr(real, '/');
    if (!base)
        return -1;
    snprintf(out, outsz, "%s", base + 1);
    return 0;
}

/*
 * Find the mount source device for the filesystem holding `dirfd`, using its
 * st_dev and /proc/self/mountinfo.  Returns 0 and fills devname, or -1 when
 * the destination is not backed by a block device at all (tmpfs, overlay, an
 * unresolvable network mount) — which is itself a refusal, never a pass.
 */
static int chk_dest_backing_dev(dev_t st_dev, char *out, size_t outsz,
                                char *fstype, size_t ftsz)
{
    FILE *f = fopen("/proc/self/mountinfo", "re");
    char line[4096];
    int found = -1;

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned maj = 0, min = 0;
        char *sep, *p, *ty, *src;

        if (sscanf(line, "%*d %*d %u:%u", &maj, &min) != 2)
            continue;
        if (makedev(maj, min) != st_dev)
            continue;
        sep = strstr(line, " - ");
        if (!sep)
            continue;
        p = sep + 3;
        ty = strtok(p, " ");
        src = strtok(NULL, " ");
        if (!ty || !src)
            continue;
        snprintf(fstype, ftsz, "%s", ty);
        snprintf(out, outsz, "%s", src);
        found = 0;
        /* keep scanning: the LAST matching entry is the effective mount */
    }
    fclose(f);
    return found;
}

/*
 * Prove the archive destination shares no backing device with the volume being
 * repaired.  Fails closed on anything it cannot resolve.
 */
static int chk_archive_dest_disjoint(const char *device, int destdirfd,
                                     const char *destdirpath)
{
    struct stat tst, dst;
    struct chk_leafset tleaf, dleaf;
    char tname[64], dsrc[PATH_MAX], dtype[64], dname[64];
    struct stat srcst;
    int i, j;

    memset(&tleaf, 0, sizeof(tleaf));
    memset(&dleaf, 0, sizeof(dleaf));

    if (stat(device, &tst) < 0 || !S_ISBLK(tst.st_mode)) {
        fprintf(stderr, "repair: %s is not a block device\n", device);
        return -1;
    }
    if (chk_devname_of(tst.st_rdev, tname, sizeof(tname)) < 0) {
        fprintf(stderr, "repair: cannot resolve %s (%u:%u) in /sys/dev/block — "
                "disjointness of the archive destination cannot be proved\n",
                device, major(tst.st_rdev), minor(tst.st_rdev));
        return -1;
    }
    chk_collect_leaves(tname, &tleaf, 0);

    if (fstat(destdirfd, &dst) < 0) {
        fprintf(stderr, "repair: cannot stat the archive directory\n");
        return -1;
    }
    if (chk_dest_backing_dev(dst.st_dev, dsrc, sizeof(dsrc),
                             dtype, sizeof(dtype)) < 0) {
        fprintf(stderr, "repair: cannot identify the filesystem holding %s in "
                "/proc/self/mountinfo — disjointness cannot be proved\n",
                destdirpath);
        return -1;
    }
    if (stat(dsrc, &srcst) < 0 || !S_ISBLK(srcst.st_mode)) {
        fprintf(stderr, "repair: the archive destination %s is on a %s mount "
                "(source '%s') with no block backing.  A tmpfs or an "
                "unresolvable stack cannot hold durable evidence; choose a "
                "destination on real, independent storage.\n",
                destdirpath, dtype, dsrc);
        return -1;
    }
    if (chk_devname_of(srcst.st_rdev, dname, sizeof(dname)) < 0) {
        fprintf(stderr, "repair: cannot resolve the archive destination's "
                "backing device — disjointness cannot be proved\n");
        return -1;
    }
    chk_collect_leaves(dname, &dleaf, 0);

    if (tleaf.overflow || dleaf.overflow || !tleaf.n || !dleaf.n) {
        fprintf(stderr, "repair: could not fully resolve the backing-device "
                "graph (target leaves %d, destination leaves %d) — "
                "disjointness cannot be proved, refusing\n",
                tleaf.n, dleaf.n);
        return -1;
    }
    for (i = 0; i < tleaf.n; i++)
        for (j = 0; j < dleaf.n; j++)
            if (strcmp(tleaf.name[i], dleaf.name[j]) == 0) {
                fprintf(stderr,
                        "repair: the archive destination %s is backed by %s, "
                        "which also backs the volume being repaired (%s).\n"
                        "        That is not independent preservation — a "
                        "second copy on the same physical device dies with it. "
                        "Choose another destination.\n",
                        destdirpath, tleaf.name[i], device);
                return -1;
            }

    printf("  archive destination : %s on %s (%s)\n", destdirpath, dsrc, dtype);
    printf("  target leaves       :");
    for (i = 0; i < tleaf.n; i++)
        printf(" %s", tleaf.name[i]);
    printf("\n  destination leaves  :");
    for (j = 0; j < dleaf.n; j++)
        printf(" %s", dleaf.name[j]);
    printf("\n  DISJOINT            : yes\n");
    return 0;
}

/* ─── --accept-quarantine-loss: the operator repair path ────────────────────
 *
 * D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376.  A terminal replay
 * refusal is permanent by design: the RECOVERY_GUARD record IS the durable
 * verdict, its slice's committed transactions were never applied and cannot be
 * applied safely, and every gate refuses it.  The cluster therefore runs one
 * member short, forever, and before this there was no way out but mkfs.
 *
 * The way out is not "clear the slot".  It is the operator ACCEPTING that the
 * refused slice's committed transactions are lost.  The command is named for
 * that, and the design-consult ruling fixes its shape:
 *
 *   THE CENTRAL INVARIANT — a quarantined slice remains UNASSIGNABLE until
 *   loss acceptance, slice invalidation, the required consistency repair and
 *   durable verification have ALL completed; only the final guarded
 *   transition may make it reusable.
 *
 * Order, each step durable before the next (ruling §2):
 *   1  validate and DISPLAY the verdict; require --confirm <verdict digest>
 *   2  acquire exclusive maintenance ownership (local O_EXCL + remote
 *      heartbeat quiescence + SCSI-PR "no registrant")
 *   3  REFUSE if any non-quarantined slice is dirty, naming the exact slots
 *   4  MANDATORY verified OFF-VOLUME archive, on proven-disjoint storage
 *   5  record LOSS_ACCEPTED — the administrative point of no return
 *   6  reinitialize the slice; 7 consistency repair; 8 CHECK_COMPLETE;
 *   9  clear the source slot in one atomic generation-checked transition
 *
 * THIS BUILD IMPLEMENTS STEPS 1-4 AND STOPS THERE, deliberately: everything up
 * to and including the archive is non-destructive, so it can be shipped and
 * exercised on a real quarantine without risking a filesystem.  Steps 5-9 are
 * the next landing.  The command reports exactly where it stopped; it never
 * pretends to have repaired anything.
 */

struct chk_quar_ctx {
    struct mxfs_ondisk_super sup;
    uint8_t  sector[512];            /* the guard sector, verbatim */
    uint8_t  superblk[MXFS_SUPER_SIZE];
    uint32_t slot;
    uint64_t sector_off;
    uint64_t digest;
    struct chk_recov_desc    d;
    struct chk_recov_outcome oc;
    int      have_desc, have_outcome;
};


/*
 * Step 2b/3: every heartbeat slot must be either EMPTY, the quarantined guard
 * itself, or a transient bucket-sweep guard.  Anything else blocks the repair,
 * and the reason is reported per slot:
 *   ACTIVE     a member is mounted, or crashed and left an unrecovered slice
 *   WITHDRAWN  a dirty slice awaiting fence+replay
 *   GUARD+desc another recovery lease, or a second quarantine
 * Returns 0 if clear, or the number of blocking slots.
 */
static int chk_repair_table_clear(int dfd, const struct mxfs_ondisk_super *sup,
                                  uint32_t keep_slot)
{
    uint8_t sec[512];
    uint32_t slot;
    int blocking = 0;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        const struct chk_hb_hdr *h = (const void *)sec;
        struct chk_recov_desc d;

        if (slot == keep_slot)
            continue;
        if (mxfs_off_read_sector_direct(dfd, sup->disklock_offset +
                                   (uint64_t)slot * 512, sec) < 0) {
            fprintf(stderr, "  BLOCKED slot %2u: unreadable\n", slot);
            blocking++;
            continue;
        }
        if (h->magic != MXFS_DISKLOCK_MAGIC)
            continue;                               /* empty / ghost */
        switch (h->flags) {
        case MXFS_DISKLOCK_FLAG_ACTIVE:
            fprintf(stderr,
                    "  BLOCKED slot %2u: ACTIVE, node %u, incarnation %llu.\n"
                    "                   Either that node is mounted, or it "
                    "crashed and its journal slice\n"
                    "                   has not been recovered.  Bring the "
                    "cluster up, let it settle,\n"
                    "                   then unmount cleanly everywhere.\n",
                    slot, h->node_id, (unsigned long long)h->epoch);
            blocking++;
            break;
        case MXFS_DISKLOCK_FLAG_WITHDRAWN_C:
            fprintf(stderr,
                    "  BLOCKED slot %2u: WITHDRAWN, node %u — a DIRTY journal "
                    "slice awaiting\n"
                    "                   fence+replay.  A live peer recovers "
                    "it; this tool must not\n"
                    "                   repair around unsettled metadata.\n",
                    slot, h->node_id);
            blocking++;
            break;
        case MXFS_DISKLOCK_FLAG_RETIRE_PENDING_C:
            fprintf(stderr,
                    "  BLOCKED slot %2u: RETIRE_PENDING, node %u — a clean "
                    "release whose PR key\n"
                    "                   is not yet proven retired.  A live "
                    "peer settles it (READ KEYS\n"
                    "                   -> EMPTY, or fence -> WITHDRAWN); "
                    "this tool must not consume it.\n",
                    slot, h->node_id);
            blocking++;
            break;
        case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C:
            memcpy(&d, sec + MXFS_RECOV_DESC_OFF_C, sizeof(d));
            if (d.magic == MXFS_RECOV_DESC_MAGIC_C) {
                fprintf(stderr,
                        "  BLOCKED slot %2u: RECOVERY GUARD carrying a "
                        "descriptor (victim node %u,\n"
                        "                   incarnation %llu%s).  Repair one "
                        "quarantine at a time.\n",
                        slot, d.victim_node,
                        (unsigned long long)d.victim_epoch,
                        (d.flags & MXFS_RECOV_F_QUARANTINED_C) ?
                        ", QUARANTINED" : ", recovery in progress");
                blocking++;
            }
            /* bare guard = bucket sweep, transient, not blocking */
            break;
        default:
            fprintf(stderr, "  BLOCKED slot %2u: unknown record flags=%u\n",
                    slot, h->flags);
            blocking++;
            break;
        }
    }
    return blocking;
}

static int chk_write_archive(const char *archive_path,
                             const char *device,
                             const struct chk_quar_ctx *q)
{
    char dirbuf[PATH_MAX], *dir, *base, filebuf[PATH_MAX];
    int dirfd = -1, fd = -1, rc = -1;
    struct sha256_ctx sc;
    uint8_t sd[32], ss[32];
    char sdhex[65], sshex[65], iso[64];
    time_t now;
    struct tm tmv;
    FILE *f = NULL;
    int i;

    snprintf(dirbuf, sizeof(dirbuf), "%s", archive_path);
    snprintf(filebuf, sizeof(filebuf), "%s", archive_path);
    dir = dirname(dirbuf);
    base = basename(filebuf);

    dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        fprintf(stderr, "repair: cannot open the archive directory %s: %s\n",
                dir, strerror(errno));
        return -1;
    }
    if (chk_archive_dest_disjoint(device, dirfd, dir) < 0)
        goto out;

    /* Hash the canonical immutable evidence: the raw 512-byte guard sector,
     * and separately the pre-repair 4KB MXFS envelope (ruling: include the
     * pre-repair superblock hash in the export). */
    sha256_init(&sc); sha256_update(&sc, q->sector, 512);   sha256_final(&sc, sd);
    sha256_init(&sc); sha256_update(&sc, q->superblk, MXFS_SUPER_SIZE);
    sha256_final(&sc, ss);
    sha256_hex(sd, sdhex);
    sha256_hex(ss, sshex);

    now = time(NULL);
    gmtime_r(&now, &tmv);
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    fd = openat(dirfd, base, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "repair: cannot create %s: %s%s\n", archive_path,
                strerror(errno),
                errno == EEXIST ? "  (this tool never overwrites an archive)" : "");
        goto out;
    }
    f = fdopen(fd, "w");
    if (!f) { fprintf(stderr, "repair: fdopen failed\n"); goto out; }
    fd = -1;                                   /* owned by f now */

    fprintf(f, "MXFS-QUARANTINE-ARCHIVE 1\n");
    fprintf(f, "tool: chk_mxfs v%s\n", CHK_MXFS_VERSION);
    fprintf(f, "captured-utc: %s\n", iso);
    fprintf(f, "device: %s\n", device);
    fprintf(f, "volume-uuid: ");
    for (i = 0; i < 16; i++)
        fprintf(f, "%02x", q->sup.fs_uuid[i]);
    fprintf(f, "\n");
    fprintf(f, "disklock-offset: %llu\n",
            (unsigned long long)q->sup.disklock_offset);
    fprintf(f, "sector-offset: %llu\n", (unsigned long long)q->sector_off);
    fprintf(f, "slot: %u\n", q->slot);
    fprintf(f, "slice-count: %u\n", q->sup.xfs_log_node_count);
    fprintf(f, "slice-bblks: %u\n", q->sup.xfs_log_slice_bblks);
    if (q->have_desc) {
        fprintf(f, "slice: %u\n", q->d.slice_idx);
        fprintf(f, "victim-node: %u\n", q->d.victim_node);
        fprintf(f, "victim-incarnation: %llu\n",
                (unsigned long long)q->d.victim_epoch);
        fprintf(f, "recovery-owner: %u\n", q->d.owner_node);
        fprintf(f, "recovery-gen: %llu\n",
                (unsigned long long)q->d.recovery_gen);
        fprintf(f, "fence-kind: %u\n", q->d.fence_kind);
        fprintf(f, "fence-victim-key: 0x%016llx\n",
                (unsigned long long)q->d.fence_victim_key);
        fprintf(f, "descriptor-flags: 0x%08x\n", q->d.flags);
    }
    if (q->have_outcome) {
        fprintf(f, "refusal-reason: %u (%s)\n", q->oc.reason,
                chk_refusal_reason_name(q->oc.reason));
        fprintf(f, "domain-kind: %u\n", q->oc.domain_kind);
        fprintf(f, "ag-mask: 0x%016llx\n",
                (unsigned long long)q->oc.ag_mask);
        fprintf(f, "refused-items: %u\n", q->oc.refused_items);
        fprintf(f, "malformed-items: %u\n", q->oc.malformed_items);
        fprintf(f, "refused-slice-digest: 0x%016llx\n",
                (unsigned long long)q->oc.slice_digest);
        fprintf(f, "publish-seq: %llu\n",
                (unsigned long long)q->oc.publish_seq);
    } else {
        fprintf(f, "refusal-reason: none-recorded (legacy intent quarantine; "
                   "treat the domain as FSWIDE)\n");
    }
    fprintf(f, "verdict-digest-crc64: %016llx\n",
            (unsigned long long)q->digest);
    fprintf(f, "guard-sector-sha256: %s\n", sdhex);
    fprintf(f, "mxfs-super-sha256: %s\n", sshex);
    fprintf(f, "guard-sector-hex:\n");
    for (i = 0; i < 512; i++) {
        fprintf(f, "%02x", q->sector[i]);
        if ((i & 31) == 31)
            fprintf(f, "\n");
    }
    fprintf(f, "END\n");

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fprintf(stderr, "repair: could not flush the archive: %s\n",
                strerror(errno));
        goto out;
    }
    fclose(f);
    f = NULL;
    if (fsync(dirfd) != 0) {
        fprintf(stderr, "repair: could not fsync the archive directory: %s\n",
                strerror(errno));
        goto out;
    }

    /* Independent verification: reopen, re-read, re-parse the sector out of
     * the hex block and re-derive BOTH digests from what is actually on the
     * destination — never from what we still hold in memory. */
    {
        int vfd = openat(dirfd, base, O_RDONLY);
        char *txt = NULL, *p;
        off_t sz;
        uint8_t back[512];
        int n = 0;
        struct sha256_ctx vc;
        uint8_t vd[32];
        char vdhex[65];

        if (vfd < 0) {
            fprintf(stderr, "repair: cannot reopen the archive to verify it\n");
            goto out;
        }
        sz = lseek(vfd, 0, SEEK_END);
        if (sz <= 0 || sz > (off_t)(1 << 20)) {
            fprintf(stderr, "repair: archive readback size %lld is implausible\n",
                    (long long)sz);
            close(vfd);
            goto out;
        }
        txt = malloc((size_t)sz + 1);
        if (!txt) { close(vfd); goto out; }
        if (pread(vfd, txt, (size_t)sz, 0) != sz) {
            fprintf(stderr, "repair: archive readback failed\n");
            free(txt); close(vfd); goto out;
        }
        close(vfd);
        txt[sz] = 0;
        p = strstr(txt, "guard-sector-hex:\n");
        if (!p) {
            fprintf(stderr, "repair: archive readback has no sector block\n");
            free(txt); goto out;
        }
        p += strlen("guard-sector-hex:\n");
        while (n < 512 && p[0] && p[1]) {
            if (*p == '\n') { p++; continue; }
            {
                char hx[3] = { p[0], p[1], 0 };
                char *end;
                long v = strtol(hx, &end, 16);

                if (end != hx + 2) break;
                back[n++] = (uint8_t)v;
                p += 2;
            }
        }
        free(txt);
        if (n != 512) {
            fprintf(stderr, "repair: archive readback decoded %d of 512 "
                    "sector bytes\n", n);
            goto out;
        }
        if (memcmp(back, q->sector, 512) != 0) {
            fprintf(stderr, "repair: the archive on disk does NOT match the "
                    "guard sector — refusing\n");
            goto out;
        }
        sha256_init(&vc); sha256_update(&vc, back, 512); sha256_final(&vc, vd);
        sha256_hex(vd, vdhex);
        if (strcmp(vdhex, sdhex) != 0) {
            fprintf(stderr, "repair: archive readback SHA-256 mismatch\n");
            goto out;
        }
        printf("  archive written and VERIFIED by readback\n");
        printf("    path                : %s\n", archive_path);
        printf("    guard-sector sha256 : %s\n", vdhex);
        printf("    mxfs-super  sha256  : %s\n", sshex);
    }
    rc = 0;

out:
    if (f) fclose(f);
    if (fd >= 0) close(fd);
    if (dirfd >= 0) close(dirfd);
    return rc;
}

/*
 * --pr-keys — who can write to this LUN right now.
 *
 * MXFS's whole fencing story rests on SCSI persistent reservations, and
 * mxfs_scsipr_create() sets local_key = node_id, so a registered key IS a
 * node identity.  This prints the registration table without touching
 * anything: it is the only way to answer "did every node that left actually
 * stop being able to write?", which a heartbeat table cannot answer.
 * Read-only, safe on a live cluster.
 */
static int do_pr_keys(const char *device)
{
    uint64_t keys[MXFS_OFF_PR_MAX_KEYS];
    int fd, n, unsupported = 0, i;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n",
                device, strerror(errno));
        return 4;
    }
    n = mxfs_off_pr_read_keys(fd, keys, MXFS_OFF_PR_MAX_KEYS, &unsupported);
    close(fd);
    if (unsupported || n < 0) {
        printf("PR keys on %s: NOT SUPPORTED — this LUN does not answer "
               "PERSISTENT RESERVE IN.\n"
               "  Exclusion can never be proved here, so MXFS cannot fence on "
               "this target.\n", device);
        return 4;
    }
    printf("PR keys on %s: %d registered\n", device, n);
    for (i = 0; i < n; i++)
        printf("  0x%016llx   (node_id %llu)\n",
               (unsigned long long)keys[i], (unsigned long long)keys[i]);
    if (n == 0)
        printf("  none — no initiator can write to this LUN\n");
    return 0;
}

static int do_accept_quarantine_loss(const char *device, long slice_arg,
                                     const char *confirm, const char *archive)
{
    struct chk_quar_ctx q;
    int fd = -1, dfd = -1, rc = 4;
    const struct chk_hb_hdr *h;
    uint32_t want32;
    uint64_t given = 0;
    char *endp;
    int blocking;

    memset(&q, 0, sizeof(q));

    if (!confirm || !archive) {
        fprintf(stderr,
            "repair: --accept-quarantine-loss requires BOTH --confirm <digest> "
            "and --archive-to <path>.\n"
            "        Run `chk_mxfs --show-quarantine %s` first: it prints the "
            "verdict you are\n"
            "        accepting the loss of, and the VERDICT DIGEST you must "
            "quote back.\n", device);
        return 2;
    }

    /* ── step 2, LOCAL half: O_EXCL fails while anything has the device ── */
    fd = open(device, O_RDWR | O_EXCL);
    if (fd < 0) {
        fprintf(stderr, "repair: cannot open %s exclusively: %s "
                "(is it mounted here?)\n", device, strerror(errno));
        return 4;
    }
    dfd = open(device, O_RDONLY | O_DIRECT);
    if (dfd < 0) {
        fprintf(stderr, "repair: cannot open %s O_DIRECT: %s\n",
                device, strerror(errno));
        goto out;
    }
    if (read_at(fd, q.superblk, MXFS_SUPER_SIZE, 0) < 0) {
        fprintf(stderr, "repair: cannot read the MXFS envelope\n");
        goto out;
    }
    memcpy(&q.sup, q.superblk, sizeof(q.sup));
    if (q.sup.magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "repair: no MXFS envelope on %s\n", device);
        goto out;
    }
    if (slice_arg < 0 || (uint64_t)slice_arg >= MXFS_DISKLOCK_HB_SLOTS) {
        fprintf(stderr, "repair: slice %ld is out of range 0..%d\n",
                slice_arg, MXFS_DISKLOCK_HB_SLOTS - 1);
        goto out;
    }
    q.slot = (uint32_t)slice_arg;
    q.sector_off = q.sup.disklock_offset + (uint64_t)q.slot * 512;

    printf("chk_mxfs v%s -- ACCEPT QUARANTINE LOSS on %s slice %u\n",
           CHK_MXFS_VERSION, device, q.slot);
    printf("\nThis operation DISCARDS the committed transactions in that "
           "journal slice.\nThey were never applied and cannot be applied "
           "safely; accepting the loss is\nthe only way to make the slice "
           "usable again.  Nothing is destroyed until every\ncheck below "
           "passes and the evidence is archived off this volume.\n\n");

    /* ── step 1: validate and DISPLAY, then demand the digest back ── */
    if (mxfs_off_read_sector_direct(dfd, q.sector_off, q.sector) < 0) {
        fprintf(stderr, "repair: cannot read heartbeat slot %u\n", q.slot);
        goto out;
    }
    h = (const void *)q.sector;
    if (h->magic != MXFS_DISKLOCK_MAGIC ||
        h->flags != (uint32_t)MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C) {
        fprintf(stderr, "repair: heartbeat slot %u is not a RECOVERY GUARD "
                "(magic 0x%08X flags %u) — there is no quarantine here\n",
                q.slot, h->magic, h->flags);
        goto out;
    }
    memcpy(&q.d,  q.sector + MXFS_RECOV_DESC_OFF_C,    sizeof(q.d));
    memcpy(&q.oc, q.sector + MXFS_RECOV_OUTCOME_OFF_C, sizeof(q.oc));
    if (q.d.magic != MXFS_RECOV_DESC_MAGIC_C) {
        fprintf(stderr, "repair: slot %u carries no recovery descriptor.  A "
                "bare guard is the AGI\n        unlinked-bucket sweep's "
                "transient working record, not a quarantine.\n", q.slot);
        goto out;
    }
    want32 = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch, &q.d,
                                offsetof(struct chk_recov_desc, crc32c));
    if (q.d.version != MXFS_RECOV_DESC_VERSION_C || want32 != q.d.crc32c) {
        fprintf(stderr, "repair: the descriptor at slot %u does not validate "
                "(version %u, crc 0x%08X vs 0x%08X).\n"
                "        Refusing: a corrupt verdict must be investigated, "
                "not accepted.\n",
                q.slot, q.d.version, q.d.crc32c, want32);
        goto out;
    }
    q.have_desc = 1;
    if (!(q.d.flags & MXFS_RECOV_F_QUARANTINED_C)) {
        fprintf(stderr, "repair: slot %u holds a recovery lease IN PROGRESS, "
                "not a terminal quarantine.\n        Let the cluster finish "
                "it.\n", q.slot);
        goto out;
    }
    if (q.oc.magic == MXFS_RECOV_OUTCOME_MAGIC_C) {
        want32 = chk_recov_body_crc(h->fs_gen, h->node_id, h->epoch, &q.oc,
                                    offsetof(struct chk_recov_outcome, crc32c));
        if (want32 != q.oc.crc32c) {
            fprintf(stderr, "repair: the outcome record at slot %u does not "
                    "validate — refusing\n", q.slot);
            goto out;
        }
        q.have_outcome = 1;
    }
    if (q.d.slice_idx != q.slot)
        printf("  NOTE: the descriptor names slice %u while sitting in slot "
               "%u.\n", q.d.slice_idx, q.slot);

    chk_print_guard(q.slot, q.sector, q.sup.fs_uuid,
                    (uint16_t)q.sup.xfs_log_node_count);
    q.digest = chk_verdict_digest(q.sup.fs_uuid, q.slot, q.sector);

    given = strtoull(confirm, &endp, 16);
    if (*endp != 0 || given != q.digest) {
        fprintf(stderr,
            "\nrepair: --confirm %s does not match this verdict.\n"
            "        Expected %016llX (printed as VERDICT DIGEST above).\n"
            "        The digest is bound to the volume uuid, the slot and the "
            "complete guard\n        sector, so quoting the wrong one means "
            "you are about to accept the loss of\n        a DIFFERENT "
            "verdict, or of one that has changed since you read it.\n",
            confirm, (unsigned long long)q.digest);
        goto out;
    }
    printf("\n  verdict digest CONFIRMED: %016llX\n",
           (unsigned long long)q.digest);

    /* ── step 2, REMOTE and LUN halves (tools/mxfs_offline.h) ── */
    printf("\n── proving exclusion ──────────────────────────────────────────\n");
    if (mxfs_off_prove_no_writer(fd, dfd, q.sup.disklock_offset) < 0)
        goto out;

    /* ── step 3: every other slice must be settled ── */
    printf("\n── proving every other slice is settled ───────────────────────\n");
    blocking = chk_repair_table_clear(dfd, &q.sup, q.slot);
    if (blocking) {
        fprintf(stderr, "\nrepair: %d slot(s) block this repair (above).  The "
                "final consistency check\n        must run on a SETTLED "
                "metadata image, or an apparent inconsistency may\n"
                "        simply be work another slice has not replayed yet.\n",
                blocking);
        goto out;
    }
    printf("  every other heartbeat slot is empty or a transient sweep "
           "guard\n");

    /* ── step 4: the mandatory, verified, off-volume archive ── */
    printf("\n── archiving the verdict off this volume ──────────────────────\n");
    if (chk_write_archive(archive, device, &q) < 0) {
        fprintf(stderr, "\nrepair: the archive could not be written and "
                "verified.  Nothing was changed.\n");
        goto out;
    }

    printf("\n── STOPPING HERE ─────────────────────────────────────────────\n");
    printf("Steps 1-4 of the repair passed and the verdict is archived.  The\n"
           "destructive half (accept the loss durably, reinitialize journal\n"
           "slice %u, run the consistency repair over the quarantine domain,\n"
           "then release the slot) is NOT implemented in this build.\n\n"
           "Slice %u is still quarantined and slot %u is still unclaimable.\n"
           "Nothing on this volume was modified.\n",
           q.have_desc ? q.d.slice_idx : q.slot,
           q.have_desc ? q.d.slice_idx : q.slot, q.slot);
    rc = 3;

out:
    if (dfd >= 0) close(dfd);
    if (fd >= 0) close(fd);
    return rc;
}

static int do_upgrade_protogate(int fd)
{
    struct mxfs_ondisk_super sup;
    uint8_t buf[MXFS_SUPER_SIZE];
    uint8_t sec[512];
    uint64_t hb_ts[64];
    uint64_t hb_epoch[64];
    bool hb_active[64];
    uint32_t agcount, agblocks, blocksize;
    uint64_t xfs_off;
    uint32_t agno, slot, nlive = 0;

    /* ── envelope ── */
    if (read_at(fd, buf, MXFS_SUPER_SIZE, 0) < 0)
        return 4;
    memcpy(&sup, buf, sizeof(sup));
    if (sup.magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "upgrade: no MXFS envelope on this device\n");
        return 4;
    }

    /* ── offline proof: no ACTIVE heartbeat may advance across 3 s ── */
    for (slot = 0; slot < 64; slot++) {
        struct mxfs_disklock_heartbeat_hdr {
            uint32_t magic, flags, node_id, fs_gen;
            uint64_t timestamp_ms, epoch;
        } __attribute__((packed)) *h = (void *)sec;

        hb_active[slot] = false;
        if (read_at(fd, sec, 512,
                    sup.disklock_offset + (uint64_t)slot * 512) < 0)
            return 4;
        if (h->magic == 0x4D584C4B /* MXLK */ && h->flags == 1 /* ACTIVE */) {
            hb_active[slot] = true;
            hb_ts[slot] = h->timestamp_ms;
            hb_epoch[slot] = h->epoch;
        }
    }
    printf("upgrade: rechecking heartbeat liveness (3 s)...\n");
    sleep(3);
    for (slot = 0; slot < 64; slot++) {
        struct mxfs_disklock_heartbeat_hdr {
            uint32_t magic, flags, node_id, fs_gen;
            uint64_t timestamp_ms, epoch;
        } __attribute__((packed)) *h = (void *)sec;

        if (!hb_active[slot])
            continue;
        if (read_at(fd, sec, 512,
                    sup.disklock_offset + (uint64_t)slot * 512) < 0)
            return 4;
        if (h->magic == 0x4D584C4B && h->flags == 1 &&
            (h->timestamp_ms != hb_ts[slot] || h->epoch != hb_epoch[slot])) {
            fprintf(stderr,
                    "upgrade: heartbeat slot %u is LIVE (node %u) — a node "
                    "still has this filesystem mounted; unmount everywhere "
                    "first\n", slot, h->node_id);
            nlive++;
        }
    }
    if (nlive)
        return 4;

    /* ── step 2: envelope gate first ── */
    /* gen 7 needs the recovery manifest REGION, which only mkfs can
     * lay out (it sits between disklock and the XFS data; there is no room to
     * carve it in place).  Refuse rather than gate a volume that cannot hold
     * a victim's manifest. */
    if (!(sup.flags & MXFS_FORMAT_F_RMAN)) {
        fprintf(stderr,
                "upgrade: this volume has no recovery manifest region "
                "(MXFS_FORMAT_F_RMAN); protocol gen %u requires it and it can "
                "only be created by mkfs_mxfs — re-mkfs\n",
                (unsigned)MXFS_PROTO_GEN);
        return 4;
    }
    /* gen 8 needs the TCP authority ledger region too. */
    if (!(sup.flags & MXFS_FORMAT_F_TAUTH)) {
        fprintf(stderr,
                "upgrade: this volume has no TCP authority ledger region "
                "(MXFS_FORMAT_F_TAUTH); protocol gen %u requires it and it can "
                "only be created by mkfs_mxfs — re-mkfs\n",
                (unsigned)MXFS_PROTO_GEN);
        return 4;
    }
    /* gen 12 needs the PR registrant ledger region too. */
    if (!(sup.flags & MXFS_FORMAT_F_PRKEY64)) {
        fprintf(stderr,
                "upgrade: this volume has no PR registrant ledger region "
                "(MXFS_FORMAT_F_PRKEY64); protocol gen %u requires it and it "
                "can only be created by mkfs_mxfs — re-mkfs\n",
                (unsigned)MXFS_PROTO_GEN);
        return 4;
    }
    /* gen 13 needs the bootstrap record region too. */
    if (!(sup.flags & MXFS_FORMAT_F_BOOTSTRAP)) {
        fprintf(stderr,
                "upgrade: this volume has no bootstrap record region "
                "(MXFS_FORMAT_F_BOOTSTRAP); protocol gen %u requires it and it "
                "can only be created by mkfs_mxfs — re-mkfs\n",
                (unsigned)MXFS_PROTO_GEN);
        return 4;
    }
    /* 0.88.0: gen 20 needs the slice lifecycle region too. */
    if (!(sup.flags & MXFS_FORMAT_F_SLIFE)) {
        fprintf(stderr,
                "upgrade: this volume has no slice lifecycle region "
                "(MXFS_FORMAT_F_SLIFE); protocol gen %u requires it and it "
                "can only be created by mkfs_mxfs — re-mkfs\n",
                (unsigned)MXFS_PROTO_GEN);
        return 4;
    }
    if ((sup.flags & MXFS_FORMAT_F_PROTOGATE) &&
        sup.cluster_proto_gen == MXFS_PROTO_GEN) {
        printf("upgrade: envelope already gated (proto_gen=%u)\n",
               sup.cluster_proto_gen);
    } else {
        struct mxfs_ondisk_super *s = (void *)buf;

        s->flags |= MXFS_FORMAT_F_PROTOGATE;
        s->cluster_proto_gen = MXFS_PROTO_GEN;
        if (mxfs_fix_crc_and_write(fd, buf, MXFS_SUPER_SIZE,
                                   offsetof(struct mxfs_ondisk_super, crc),
                                   0) < 0)
            return 4;
        printf("upgrade: envelope gated (proto_gen=%u)\n",
               (unsigned)MXFS_PROTO_GEN);
    }

    /* ── step 3: XFS superblocks, secondaries first, primary LAST ── */
    xfs_off = sup.xfs_data_offset;
    if (read_at(fd, sec, 512, xfs_off) < 0)
        return 4;
    if (get_be32(sec + 0) != MXFS_SB_MAGIC) {
        fprintf(stderr, "upgrade: no XFS superblock at data offset\n");
        return 4;
    }
    blocksize = get_be32(sec + 4);
    agblocks  = get_be32(sec + 0x54);
    agcount   = get_be32(sec + 0x58);
    if (!blocksize || !agblocks || !agcount || agcount > 1u << 20) {
        fprintf(stderr, "upgrade: implausible geometry\n");
        return 4;
    }
    for (agno = agcount; agno-- > 0; ) {  /* agcount-1 .. 0: primary last */
        uint64_t off = xfs_off +
                       (uint64_t)agno * agblocks * blocksize;
        uint32_t incompat;

        if (read_at(fd, sec, 512, off) < 0)
            return 4;
        if (get_be32(sec + 0) != MXFS_SB_MAGIC) {
            fprintf(stderr, "upgrade: AG %u superblock bad magic — run a "
                    "full check first\n", agno);
            return 4;
        }
        incompat = get_be32(sec + 0xD8);
        if (incompat & CHK_SB_INCOMPAT_MXFS_PROTOGATE)
            continue;
        put_be32(sec + 0xD8, incompat | CHK_SB_INCOMPAT_MXFS_PROTOGATE);
        if (xfs_fix_crc_and_write(fd, sec, 512, 0xE0, off) < 0)
            return 4;
    }
    printf("upgrade: XFS INCOMPAT_MXFS_PROTOGATE set on %u superblock "
           "copies (primary last)\n", agcount);
    printf("upgrade: COMPLETE — pre-gate kernels can no longer mount this "
           "filesystem\n");
    return 0;
}

/*
 * (D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510 negative arm):
 * print where an inode lives on the IMAGE — absolute byte offset of its
 * dinode and of the inode cluster buffer that contains it, envelope-aware
 * (xfs_data_offset added).  The harness zeroes the dinode magic there,
 * offline, to prove a SYNCINIT ICREATE replay REFUSES a non-verifying
 * cluster instead of re-initialising it.  Read-only; no geometry check.
 */
static int do_ino_offset(const char *device, unsigned long long ino)
{
    struct mxfs_ondisk_super sup;
    uint8_t buf[MXFS_SUPER_SIZE];
    uint8_t sb[512];
    int fd;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n", device,
                strerror(errno));
        return 4;
    }
    if (read_at(fd, buf, MXFS_SUPER_SIZE, 0) < 0) {
        close(fd);
        return 4;
    }
    memcpy(&sup, buf, sizeof(sup));
    if (sup.magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "ino-offset: no MXFS envelope on this device\n");
        close(fd);
        return 4;
    }
    if (read_at(fd, sb, 512, sup.xfs_data_offset) < 0) {
        close(fd);
        return 4;
    }
    close(fd);
    if (get_be32(sb + 0) != MXFS_SB_MAGIC) {
        fprintf(stderr, "ino-offset: no XFS superblock at %llu\n",
                (unsigned long long)sup.xfs_data_offset);
        return 4;
    }
    {
        uint32_t blocksize  = get_be32(sb + 4);
        uint32_t agblocks   = get_be32(sb + 0x54);
        uint32_t agcount    = get_be32(sb + 0x58);
        uint32_t inodesize  = get_be16(sb + 0x68);
        uint8_t  inopblog   = sb[0x7B];
        uint8_t  agblklog   = sb[0x7C];
        uint32_t inoalignmt = get_be32(sb + 0xB4);
        uint32_t agino_bits = agblklog + inopblog;
        uint32_t agno  = (uint32_t)(ino >> agino_bits);
        uint32_t agino = (uint32_t)(ino & ((1ULL << agino_bits) - 1));
        uint32_t agbno = agino >> inopblog;
        uint32_t off_in_blk = (agino & ((1U << inopblog) - 1)) * inodesize;
        /* v5 inode cluster: XFS_INODE_BIG_CLUSTER_SIZE scaled by the inode
         * size over XFS_DINODE_MIN_SIZE (xfs_ialloc_setup_geometry) */
        uint32_t cluster_bytes = 8192 * (inodesize / 256);
        uint32_t bpc = cluster_bytes >= blocksize ? cluster_bytes / blocksize : 1;
        uint32_t cl_agbno = agbno - (agbno % bpc);
        uint64_t ag_base = sup.xfs_data_offset +
                           (uint64_t)agno * agblocks * blocksize;
        uint64_t dinode_off = ag_base + (uint64_t)agbno * blocksize + off_in_blk;
        uint64_t cluster_off = ag_base + (uint64_t)cl_agbno * blocksize;

        if (agno >= agcount || agbno >= agblocks) {
            fprintf(stderr, "ino-offset: inode %llu is outside the geometry "
                    "(agno=%u/%u agbno=%u/%u)\n", ino, agno, agcount, agbno,
                    agblocks);
            return 4;
        }
        printf("ino=%llu agno=%u agbno=%u agino=%u dinode_off=%llu "
               "cluster_off=%llu cluster_bytes=%u inodesize=%u blocksize=%u "
               "inoalignmt=%u xfs_off=%llu\n",
               ino, agno, agbno, agino, (unsigned long long)dinode_off,
               (unsigned long long)cluster_off, cluster_bytes, inodesize,
               blocksize, inoalignmt,
               (unsigned long long)sup.xfs_data_offset);
    }
    return 0;
}

/*
 * --geometry: the envelope offsets and the XFS geometry, and no verdict.
 *
 * 0.89.7.  The full check opens the device O_EXCL, so a node whose own
 * module holds the device is refused; a harness that only needs agcount,
 * agblocks, inopblog or xfs_data_offset from a live node used to take them
 * from `-v` and now gets rc 4 and nothing to parse (tcp_death_replay,
 * closure_reuse_directed, closure_footprint_shapes, typeflip_dead_incarn
 * at s69).  Those values are mkfs-time constants — resize_mxfs is their
 * only other writer, and it runs offline under its own exclusive open — so
 * the image the page cache holds from the first buffered read IS the
 * current value, and the stale-image hazard the full check refuses under
 * does not apply.  Hence: a plain read-only open, no exclusion, no cache
 * drop.  The listing still carries icount/ifree/fdblocks, which are the
 * platter's values at the last unmount and not live — a caller wanting a
 * live count has the wrong tool.
 */
static int do_geometry(const char *device)
{
    struct mxfs_ondisk_super super;
    struct xfs_geo geo;
    int fd, rc = 0;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n", device,
                strerror(errno));
        return 4;
    }
    verbose = true;
    printf("chk_mxfs v%s -- geometry of %s (mkfs-time constants; the counts "
           "on this listing are the platter's at its last unmount, not "
           "live)\n", CHK_MXFS_VERSION, device);
    memset(&super, 0, sizeof(super));
    memset(&geo, 0, sizeof(geo));
    if (check_mxfs_super(fd, &super) < 0 ||
        check_xfs_superblock(fd, &super, &geo) < 0)
        rc = 4;
    close(fd);
    return rc;
}

/*
 * --query-only with --free-query: the platter's answer for the queried
 * extents and nothing else — no verdict, no exclusion.
 *
 * 0.89.7 (ledger D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE-AND-REPORT-IT-AS-
 * MXFS, s70): tests/d_intents_2tcp_open_efi.sh asked its free queries of the
 * host image ~/disk.img, which on the qnap rig is the OTHER rig's
 * filesystem, and asserted "every obligation extent reads FREE on the
 * platter" from that well-formed answer about the wrong device.  The query
 * belongs on a node against the resolved LUN, and the node that has the
 * answer is mounted, where the ordinary check is refused (O_EXCL).  So this
 * mode opens read-only without exclusion, drops the device's cached pages
 * first (the module's bios bypass that cache; a block is read once here, so
 * the first read is the platter's), reads the geometry and only the AGs the
 * queries name — their AGF and their BNO btree into the cross-tree free map
 * — and prints the FREE-QUERY lines.  It is a point read of a live
 * filesystem: an extent can be reallocated after it printed FREE, which is
 * the caller's question to bound (the harness runs it with the churn off).
 */
static int do_free_query_live(const char *device)
{
    struct mxfs_ondisk_super super;
    struct xfs_geo geo;
    struct stat dst;
    int fd, q;

    if (free_query_n == 0) {
        fprintf(stderr, "chk_mxfs: --query-only needs at least one --free-query\n");
        return 2;
    }
    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n", device,
                strerror(errno));
        return 4;
    }
    if (fstat(fd, &dst) == 0 && S_ISBLK(dst.st_mode) &&
        ioctl(fd, BLKFLSBUF, 0) < 0) {
        fprintf(stderr, "chk_mxfs: cannot drop %s's cached pages (BLKFLSBUF: "
                "%s); a query through a page cache the module's writes bypass "
                "is not a read of the platter, so it is refused\n", device,
                strerror(errno));
        close(fd);
        return 4;
    }
    printf("chk_mxfs v%s -- free query on %s (a point read of the live "
           "platter; no verdict)\n", CHK_MXFS_VERSION, device);
    memset(&super, 0, sizeof(super));
    memset(&geo, 0, sizeof(geo));
    if (check_mxfs_super(fd, &super) < 0 ||
        check_xfs_superblock(fd, &super, &geo) < 0) {
        close(fd);
        return 4;
    }
    xtree_init(&geo);
    for (q = 0; q < free_query_n; q++) {
        uint32_t agno = free_query[q].agno;
        struct ag_info agi;
        int seen = 0, p;

        for (p = 0; p < q; p++)
            if (free_query[p].agno == agno)
                seen = 1;
        if (seen || agno >= geo.agcount)
            continue;
        memset(&agi, 0, sizeof(agi));
        check_xfs_ag_headers(fd, &geo, agno, &agi);
        if (agi.agf_ok && agi.bno_root < agi.agf_length && agi.bno_level >= 1)
            walk_freespace_btree(fd, &geo, agno, agi.bno_root,
                                 MXFS_ABTB_CRC_MAGIC, "BNO", true,
                                 agi.bno_level - 1, agi.agf_length);
        else
            printf("  AG %u: BNO btree not walked (AGF errors); its queries "
                   "answer UNKNOWN\n", agno);
    }
    xtree_free_query_report(&geo);
    free(xtree_chunk);
    free(xtree_free);
    xtree_chunk = NULL;
    xtree_free = NULL;
    close(fd);
    return errors ? 4 : 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-a|-p|-y|-n|-U] /dev/sdX\n", prog);
    fprintf(stderr, "  -v   verbose: show detailed info for each check\n");
    fprintf(stderr, "  --geometry\n"
                    "       print the envelope offsets and the XFS geometry "
                    "(agcount, agblocks,\n"
                    "       inopblog, ...) and exit; mkfs-time constants, so "
                    "safe on a node that\n"
                    "       has the device mounted.  The ordinary check is "
                    "refused there (O_EXCL).\n");
    fprintf(stderr, "  -n   check only, no modifications (default)\n");
    fprintf(stderr, "  -a   auto-repair safe fixes\n");
    fprintf(stderr, "  -p   preen: same as -a (for boot scripts)\n");
    fprintf(stderr, "  -y   repair all, answer yes to everything\n");
    fprintf(stderr, "  -U   upgrade-protogate: stamp the C7 version gate "
                    "(offline, all nodes unmounted)\n");
    fprintf(stderr, "  -Q, --show-quarantine\n"
                    "       print every terminal recovery quarantine verdict "
                    "on this volume\n"
                    "       (read-only, O_DIRECT; safe while the cluster is "
                    "up).  Exit 4 if any\n"
                    "       quarantine exists.\n");
    fprintf(stderr, "  --bootstrap\n"
                    "       print the whole-cluster bootstrap record: its "
                    "state, term, owner host\n"
                    "       boot and key, and the escrow.  Read-only and "
                    "O_DIRECT, safe on a live\n"
                    "       cluster and on a node that has the volume "
                    "mounted -- which is where a\n"
                    "       mount refused by a claimed term has to be "
                    "diagnosed.\n");
    fprintf(stderr, "  --pr-keys\n"
                    "       print the SCSI persistent-reservation keys "
                    "registered on this LUN.\n"
                    "       MXFS uses node_id as the key, so each entry names "
                    "a node that can\n"
                    "       write to the shared device right now.  Read-only, "
                    "safe on a live cluster.\n");
    fprintf(stderr, "  --accept-quarantine-loss SLICE --confirm DIGEST "
                    "--archive-to PATH\n"
                    "       accept the loss of a terminally-quarantined "
                    "journal slice's committed\n"
                    "       transactions so its slot can be reused.  OFFLINE "
                    "only: every node must\n"
                    "       be unmounted and no initiator may be registered on "
                    "the LUN.  DIGEST is\n"
                    "       the VERDICT DIGEST printed by --show-quarantine; "
                    "PATH must be on storage\n"
                    "       with no backing device in common with the volume "
                    "being repaired.\n");
    fprintf(stderr, "  --dirshard-hash KEYHEX NAME|hex:NAMEHEX\n"
                    "       print the directory-sharding routing hash "
                    "(SipHash-2-4 under the\n"
                    "       32-hex-digit key) and the shard index for N=16/32/64."
                    "  No device.\n");
    fprintf(stderr, "  --clear-bootstrap\n"
                    "       hand a REFUSED whole-cluster bootstrap record back "
                    "to IDLE after the\n"
                    "       refusal it names has been repaired.  OFFLINE only "
                    "(O_EXCL + no live\n"
                    "       heartbeat); a CLAIMED/SEALED/RECOVERING term is "
                    "never cleared here.\n");
    fprintf(stderr, "  --query-only --free-query AGNO:AGBNO:LEN ...\n"
                    "       the FREE-QUERY answers alone, from a read-only "
                    "open without exclusion\n"
                    "       (safe on a mounted node: the device's cached "
                    "pages are dropped first);\n"
                    "       a point read of the live platter, no verdict.\n");
    fprintf(stderr, "  --free-query AGNO:AGBNO:LEN   (repeatable, up to 16)\n"
                    "       with the ordinary check: report whether the range "
                    "is FREE, ALLOCATED or\n       PARTIAL per the BNO btree "
                    "walk (the platter-side proof that a completed\n       "
                    "obligation extent was freed).  Read-only.\n");
    fprintf(stderr, "  --ino-offset INO\n"
                    "       print the absolute image byte offset of inode "
                    "INO's dinode and of its\n       inode cluster buffer "
                    "(envelope-aware).  Read-only.\n");
    fprintf(stderr, "\nExit codes:\n");
    fprintf(stderr, "  0  filesystem clean\n");
    fprintf(stderr, "  3  quarantine repair: pre-checks passed and the verdict "
                    "was archived,\n     but the destructive half is not "
                    "implemented in this build\n");
    fprintf(stderr, "  1  errors found and corrected\n");
    fprintf(stderr, "  4  errors found, not corrected\n");
    exit(2);
}

/* ─── Main ─── */

int main(int argc, char **argv)
{
    const char *device = NULL;
    int opt;
    const char *progname;

    bool upgrade_protogate = false;
    bool show_quarantine = false;
    bool do_accept = false;
    bool show_pr_keys = false;
    bool show_geometry = false;
    bool show_bootstrap = false;
    bool query_only = false;
    bool clear_bootstrap = false;
    bool ino_offset = false;
    unsigned long long ino_offset_ino = 0;
    long accept_slice = -1;
    const char *accept_confirm = NULL;
    const char *accept_archive = NULL;
    int ai;

    /* Detect if invoked as fsck.mxfs — default to auto-repair mode */
    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];
    if (strcmp(progname, "fsck.mxfs") == 0)
        repair = REPAIR_AUTO;

    /* long-form aliases used by the kernel's refusal messages, plus the
     * three-part repair invocation.  The repair options take arguments, so
     * they are consumed here and removed from argv before getopt runs. */
    {
        int w = 1;

        for (ai = 1; ai < argc; ai++) {
            const char *a = argv[ai];

            if (strcmp(a, "--upgrade-protogate") == 0) {
                argv[w++] = "-U";
            } else if (strcmp(a, "--show-quarantine") == 0) {
                argv[w++] = "-Q";
            } else if (strcmp(a, "--accept-quarantine-loss") == 0 &&
                       ai + 1 < argc) {
                char *endp;

                accept_slice = strtol(argv[++ai], &endp, 10);
                if (*endp != 0) {
                    fprintf(stderr, "chk_mxfs: --accept-quarantine-loss needs "
                            "a slice number\n");
                    return 2;
                }
                do_accept = true;
            } else if (strcmp(a, "--pr-keys") == 0) {
                show_pr_keys = true;
            } else if (strcmp(a, "--geometry") == 0) {
                show_geometry = true;
            } else if (strcmp(a, "--query-only") == 0) {
                query_only = true;
            } else if (strcmp(a, "--dirshard-hash") == 0 && ai + 2 < argc) {
                /* no device — routing hash cross-check */
                return dirshard_hash_cmd(argv[ai + 1], argv[ai + 2]);
            } else if (strcmp(a, "--bootstrap") == 0) {
                show_bootstrap = true;
            } else if (strcmp(a, "--clear-bootstrap") == 0) {
                clear_bootstrap = true;
            } else if (strcmp(a, "--ino-offset") == 0 && ai + 1 < argc) {
                char *endp;

                ino_offset_ino = strtoull(argv[++ai], &endp, 10);
                if (*endp != 0) {
                    fprintf(stderr, "chk_mxfs: --ino-offset needs an inode "
                            "number\n");
                    return 2;
                }
                ino_offset = true;
            } else if (strcmp(a, "--free-query") == 0 && ai + 1 < argc) {
                unsigned int qa, qb, ql;

                if (free_query_n >= CHK_FREE_QUERY_MAX ||
                    sscanf(argv[++ai], "%u:%u:%u", &qa, &qb, &ql) != 3) {
                    fprintf(stderr, "chk_mxfs: --free-query needs AGNO:AGBNO:LEN "
                            "(at most %d queries)\n", CHK_FREE_QUERY_MAX);
                    return 2;
                }
                free_query[free_query_n].agno = qa;
                free_query[free_query_n].agbno = qb;
                free_query[free_query_n].len = ql;
                free_query_n++;
            } else if (strcmp(a, "--confirm") == 0 && ai + 1 < argc) {
                accept_confirm = argv[++ai];
            } else if (strcmp(a, "--archive-to") == 0 && ai + 1 < argc) {
                accept_archive = argv[++ai];
            } else {
                argv[w++] = argv[ai];
            }
        }
        argc = w;
        argv[argc] = NULL;
    }

    while ((opt = getopt(argc, argv, "vapynhUQ")) != -1) {
        switch (opt) {
        case 'v':
            verbose = true;
            break;
        case 'a':
        case 'p':
            repair = REPAIR_AUTO;
            break;
        case 'y':
            repair = REPAIR_ALL;
            break;
        case 'n':
            repair = REPAIR_NONE;
            break;
        case 'U':
            upgrade_protogate = true;
            break;
        case 'Q':
            show_quarantine = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (optind >= argc)
        usage(argv[0]);

    device = argv[optind];

    if (show_pr_keys)
        return do_pr_keys(device);

    if (show_geometry)
        return do_geometry(device);

    if (show_bootstrap)
        return do_bootstrap_show(device);

    if (query_only)
        return do_free_query_live(device);

    if (ino_offset)
        return do_ino_offset(device, ino_offset_ino);

    if (clear_bootstrap)
        return do_clear_bootstrap(device);

    if (show_quarantine)
        return do_show_quarantine(device);

    if (do_accept)
        return do_accept_quarantine_loss(device, accept_slice,
                                         accept_confirm, accept_archive);

    if (upgrade_protogate) {
        /* O_EXCL on a block device fails while it is mounted locally —
         * the local half of the offline proof (the HB scan is the remote
         * half). */
        int ufd = open(device, O_RDWR | O_EXCL);

        if (ufd < 0) {
            fprintf(stderr, "chk_mxfs: cannot open %s exclusively: %s "
                    "(is it mounted?)\n", device, strerror(errno));
            return 4;
        }
        int urc = do_upgrade_protogate(ufd);

        close(ufd);
        return urc;
    }

    printf("chk_mxfs v%s -- checking %s", CHK_MXFS_VERSION, device);
    if (repair == REPAIR_AUTO)
        printf(" (auto-repair)");
    else if (repair == REPAIR_ALL)
        printf(" (repair all)");
    printf("\n");

    /*
     * 0.89.6 (ledger D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS,
     * buffered-reader class; design consult banked in
     * docs/rulings/checker-page-cache-and-exclusion.md): the check reads
     * the platter through this one buffered descriptor, and the kernel's
     * block-device page cache is only dropped at the device's LAST close.
     * The module writes the LUN with bios that never touch that cache, so
     * on a node whose module holds the device open a buffered read returns
     * whatever image the first buffered reader cached, for as long as the
     * mount lasts (measured s67e: three dumps of a slot 3 s apart returned
     * the same stamp while direct reads of the sector advanced).  Two
     * defences, both before the first read:
     *   - O_EXCL: a device this node's module (or any exclusive holder)
     *     has open is refused with EBUSY.  The check is an offline check
     *     and a node whose own mount is up is not offline; a refusal is a
     *     result, a verdict read through that mount's page cache is not.
     *     Another host's mount is not seen here — this is local exclusion,
     *     not cluster quiescence, which the caller still owes.
     *   - BLKFLSBUF: drops the clean pages any plain opener on this node
     *     (a dd, an earlier tool run that is still holding the device)
     *     cached before this run, so the first read of every block goes to
     *     the platter.  It needs CAP_SYS_ADMIN and a failure is an abort on
     *     a block device: a check that cannot say what it read is not a
     *     check.  A regular-file image has no such cache to drop.
     */
    int open_flags = (can_repair() ? O_RDWR : O_RDONLY) | O_EXCL;
    int fd = open(device, open_flags);
    if (fd < 0) {
        /* If O_RDWR fails, fall back to read-only check */
        if ((open_flags & O_RDWR) && errno != EBUSY) {
            fprintf(stderr, "chk_mxfs: cannot open %s read-write: %s, "
                    "falling back to check-only\n", device, strerror(errno));
            repair = REPAIR_NONE;
            fd = open(device, O_RDONLY | O_EXCL);
        }
        if (fd < 0) {
            if (errno == EBUSY)
                fprintf(stderr, "chk_mxfs: %s is held open exclusively on "
                        "this node (mounted, or a mount in progress): the "
                        "check reads the platter, and a node whose module "
                        "holds the device would read its page cache instead; "
                        "unmount here first\n", device);
            else
                fprintf(stderr, "chk_mxfs: cannot open %s: %s\n", device,
                        strerror(errno));
            return 4;
        }
    }
    {
        struct stat dst;
        if (fstat(fd, &dst) < 0) {
            fprintf(stderr, "chk_mxfs: cannot fstat %s: %s\n", device,
                    strerror(errno));
            close(fd);
            return 4;
        }
        if (S_ISBLK(dst.st_mode)) {
            if (ioctl(fd, BLKFLSBUF, 0) < 0) {
                fprintf(stderr, "chk_mxfs: cannot drop %s's cached pages "
                        "(BLKFLSBUF: %s); a read through a page cache the "
                        "module's writes bypass is not a read of the "
                        "platter, so the check is refused%s\n", device,
                        strerror(errno),
                        (errno == EACCES || errno == EPERM)
                            ? " — it needs CAP_SYS_ADMIN (run as root)" : "");
                close(fd);
                return 4;
            }
            printf("  dropped the block device's cached pages before the "
                   "first read (BLKFLSBUF)\n");
        }
    }

    /* 1. MXFS superblock */
    struct mxfs_ondisk_super super;
    memset(&super, 0, sizeof(super));

    if (check_mxfs_super(fd, &super) < 0) {
        close(fd);
        printf("\nchk_mxfs: %d error(s) found\n", errors);
        return 4;
    }

    /* 2. Journal */
    check_journal(fd, &super);

    /* 3. Disklock */
    check_disklock(fd, &super);

    /* 3b. TCP authority ledger */
    check_tauth(fd, &super);
    check_prledger(fd, &super);         /* */
    check_bootstrap(fd, &super);        /* */
    check_slife(fd, &super);            /* 0.88.0 */

    /* 4. XFS superblock */
    struct xfs_geo geo;
    memset(&geo, 0, sizeof(geo));

    if (check_xfs_superblock(fd, &super, &geo) < 0) {
        close(fd);
        printf("\nchk_mxfs: %d error(s) found\n", errors);
        return 4;
    }

    if (geo.agcount == 0 || geo.agblocks == 0 || geo.blocksize == 0) {
        close(fd);
        printf("\nchk_mxfs: %d error(s) found\n", errors);
        return 4;
    }

    /* Allocate per-AG summary array */
    struct ag_summary *ag_summaries = calloc(geo.agcount, sizeof(struct ag_summary));
    if (!ag_summaries) {
        fprintf(stderr, "chk_mxfs: malloc failed for AG summaries\n");
        close(fd);
        return 4;
    }

    /* D-0948: start the cross-tree block-ownership audit before the per-AG
     * walks, which are what populate its two bitmaps. */
    xtree_init(&geo);

    /* 5-7. Per-AG deep validation */
    for (uint32_t ag = 0; ag < geo.agcount; ag++) {
        struct ag_info agi;

        /* 5a. AG headers (AGF + AGI) */
        check_xfs_ag_headers(fd, &geo, ag, &agi);

        /* 5b. Free space btrees (BNO/CNT) */
        check_freespace_btrees(fd, &geo, ag, &agi, &ag_summaries[ag]);
        total_bno_freeblks += ag_summaries[ag].bno_freeblks;
        total_agf_freeblks += ag_summaries[ag].agf_freeblks;

        /* 6. Inode btrees (inobt/finobt) */
        check_inode_btrees(fd, &geo, ag, &agi, &ag_summaries[ag]);
        total_inobt_inodes += ag_summaries[ag].inobt_total;
        total_inobt_free += ag_summaries[ag].inobt_free;
    }

    /* 7. Inode spot-check */
    check_inode_spotcheck(fd, &geo);

    /* 7b. Orphan inode audit (bucketless nlink=0 leak detection) */
    check_orphan_inodes(fd, &geo);

    /* 7c. Directory sharding: PARENT -> locator -> holder -> manifest block
     * -> containers; no unreferenced containers. */
    check_dirshard(fd, &geo);

    /* 7d. Directory entries: every name resolves to an allocated inode
     * with a live dinode (D-0964: a dangling entry naming a freed inode
     * passed CLEAN before this pass existed). */
    check_dirents(fd, &geo);

    /* 8. Summary report */
    xtree_report(&geo);
    print_summary(fd, &geo, ag_summaries);

    free(ag_summaries);

    /* fsync if we wrote repairs */
    if (repaired > 0)
        fsync(fd);

    close(fd);

    printf("\nchk_mxfs: ");
    if (errors == 0 && repaired == 0) {
        printf("filesystem clean\n");
        return 0;
    } else if (repaired > 0 && errors <= repaired) {
        printf("%d error(s) found, %d corrected\n", errors, repaired);
        return 1;
    } else if (repaired > 0) {
        printf("%d error(s) found, %d corrected, %d remaining\n",
               errors, repaired, errors - repaired);
        return 4;
    } else {
        printf("%d error(s) found", errors);
        if (repair == REPAIR_NONE)
            printf(" (run with -a or -y to repair)");
        printf("\n");
        return 4;
    }
}
