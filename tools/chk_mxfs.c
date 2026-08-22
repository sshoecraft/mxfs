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
#include <mxfs/mxfs_common.h>

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

/* XFS on-disk constants */
#define XFS_SB_MAGIC            0x58465342  /* "XFSB" */
#define XFS_AGF_MAGIC           0x58414746  /* "XAGF" */
#define XFS_AGI_MAGIC           0x58414749  /* "XAGI" */
#define XFS_DINODE_MAGIC        0x494E      /* "IN" */

/* V5 CRC btree magic numbers (from kernel xfs_format.h) */
#define XFS_ABTB_CRC_MAGIC     0x41423342  /* "AB3B" bnobt */
#define XFS_ABTC_CRC_MAGIC     0x41423343  /* "AB3C" cntbt */
#define XFS_IBT_CRC_MAGIC      0x49414233  /* "IAB3" inobt */
#define XFS_FIBT_CRC_MAGIC     0x46494233  /* "FIB3" finobt */

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

    /* Region non-overlapping checks:
     * Expected layout: [super 4KB] [journal] [disklock] [XFS data]
     * Check each pair for overlap.
     */
    {
        struct {
            const char *name;
            uint64_t start;
            uint64_t end;
        } regions[4];

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

        for (int i = 0; i < 4; i++) {
            for (int j = i + 1; j < 4; j++) {
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
    info("xfs_data_offset=%llu", (unsigned long long)s->xfs_data_offset);

    return 0;
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
 * record is the ONLY copy of the verdict, and until the sess377 repair path
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

#define MXFS_RECOV_DESC_OFF_C       40      /* 40B header, then the body union */
#define MXFS_RECOV_OUTCOME_OFF_C    (MXFS_RECOV_DESC_OFF_C + 120)

#define MXFS_RECOV_DESC_MAGIC_C     0x5643524Du  /* "MRCV" LE */
#define MXFS_RECOV_DESC_VERSION_C   2
#define MXFS_RECOV_OUTCOME_MAGIC_C  0x4F435652u  /* "RVCO" LE */

#define MXFS_RECOV_F_QUARANTINED_C  0x00000001u

#define MXFS_RECOV_OUTCOME_TERMINAL_REFUSED_C           1u
#define MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE_C    1u
#define MXFS_RECOV_REFUSAL_PHYSICALLY_TORN_C            2u
#define MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE_C   3u
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
 * (sess377 ruling: "a generic yes must not be able to clear the wrong victim
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
    case MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE_C:
        return "LEGACY_INTENT_QUARANTINE (backfilled verdict, inherited)";
    default:
        return "UNKNOWN";
    }
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

    /* sess377: a RECOVERY_GUARD with NO descriptor body is NOT a damaged
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
        printf("     recovery          owner=%u term=%u gen=%llu stage=%u "
               "flags=0x%08X%s\n",
               d.owner_node, d.owner_term,
               (unsigned long long)d.recovery_gen, d.stage, d.flags,
               (d.flags & MXFS_RECOV_F_QUARANTINED_C) ? " QUARANTINED" : "");
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

    printf("     VERDICT DIGEST    %016llX\n",
           (unsigned long long)chk_verdict_digest(fsuuid, slot, sec));
    if (slice_count_hint && slot >= slice_count_hint)
        printf("     NOTE: this slot is at or above the volume's slice count "
               "(%u) — it bears no journal.\n", slice_count_hint);
    return (desc_ok && (oc_ok || !oc_present)) ? 1 : 0;
}

/* Decode the §7.C MEPOCH record at offset 456 of one HB slot.  The
 * record is self-validating (own magic + crc32c over bytes 0..39);
 * returns the committed epoch (0 if absent/PREPARED), errs on a
 * corrupt record. */
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

        /* sess377: `flags` is an ENUM (1 ACTIVE, 2 WITHDRAWN, 3
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
            break;
        case MXFS_DISKLOCK_FLAG_WITHDRAWN_C:
            withdrawn++;
            info("disklock HB slot %d: WITHDRAWN (node_id=%u) — dirty slice "
                 "awaiting fence+replay", i, node_id);
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

    if (sb_magic != XFS_SB_MAGIC) {
        err("XFS superblock magic: expected 0x%08X, got 0x%08X",
            XFS_SB_MAGIC, sb_magic);
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
    info("sectsize=%u, inodesize=%u, inopblock=%u",
         sectsize, inodesize, inopblock);
    info("features_ro_compat=0x%08X (finobt=%s)",
         features_ro_compat,
         (features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT) ? "yes" : "no");

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

    if (agf_magic != XFS_AGF_MAGIC) {
        err("AG %u: AGF magic expected 0x%08X, got 0x%08X",
            agno, XFS_AGF_MAGIC, agf_magic);
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

        if (can_repair() && agf_magic == XFS_AGF_MAGIC) {
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

    if (agi_magic != XFS_AGI_MAGIC) {
        err("AG %u: AGI magic expected 0x%08X, got 0x%08X",
            agno, XFS_AGI_MAGIC, agi_magic);
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

        if (can_repair() && agi_magic == XFS_AGI_MAGIC) {
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
        /* Internal node — keys start at BTREE_REC_OFF, pointers after keys.
         * For short-form btree internal nodes:
         *   Keys: numrecs * 8 bytes at offset BTREE_REC_OFF
         *   Ptrs: numrecs * 4 bytes at offset BTREE_REC_OFF + numrecs * 8
         * Each key is [startblock(be32)][blockcount(be32)] (8 bytes).
         * Each ptr is [agbno(be32)] (4 bytes).
         */
        uint32_t ptr_off = BTREE_REC_OFF + numrecs * 8;

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
    put_be32(blk + 0x00, XFS_ABTB_CRC_MAGIC);
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
    put_be32(blk + 0x00, XFS_ABTC_CRC_MAGIC);
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
                                         XFS_ABTB_CRC_MAGIC, "BNO", true,
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
                                         XFS_ABTC_CRC_MAGIC, "CNT", false,
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
            info("AG %u %s rec %u: startino=%u count=%u freecount=%u holemask=0x%04X",
                 agno, name, i, startino, count, freecount, holemask);
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
        /* Internal node.
         * Inobt internal keys: [startino(be32)] = 4 bytes each.
         * Inobt internal ptrs: [agbno(be32)] = 4 bytes each.
         * Keys at BTREE_REC_OFF, ptrs at BTREE_REC_OFF + numrecs * 4.
         */
        uint32_t ptr_off = BTREE_REC_OFF + numrecs * 4;

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
                   XFS_IBT_CRC_MAGIC, "inobt",
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
                             XFS_IBT_CRC_MAGIC) == 0) {
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
                       XFS_FIBT_CRC_MAGIC, "finobt",
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
                                 XFS_FIBT_CRC_MAGIC) == 0) {
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
    if (di_magic != XFS_DINODE_MAGIC) {
        err("inode %llu (%s): magic expected 0x%04X, got 0x%04X",
            (unsigned long long)ino, label, XFS_DINODE_MAGIC, di_magic);
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
        if (get_be16(ibuf + 0x00) != XFS_DINODE_MAGIC) {
            err("AG %u unlinked bucket %d: agino %u has bad inode magic 0x%04X",
                agno, bucket, agino, get_be16(ibuf + 0x00));
            break;
        }
        orphan_push(members, ((uint64_t)agno << (geo->agblklog + geo->inopblog))
                             | agino);
        /* sess389: -v names every chain member — the on-disk AGI chain-walk
         * audit (RULE-5 ruling) needs the ino/mode/nlink/gen of each
         * leftover so its unlink trail can be found in the nodes' logs. */
        if (verbose)
            info("  AG %u unlinked bucket %d: member ino=%llu agino=%u "
                 "mode=0%o nlink=%u gen=%u next=0x%x",
                 agno, bucket,
                 (unsigned long long)(((uint64_t)agno <<
                        (geo->agblklog + geo->inopblog)) | agino),
                 agino, get_be16(ibuf + 0x02), get_be32(ibuf + 0x10),
                 get_be32(ibuf + 0x44), get_be32(ibuf + 0x60));
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
            if (get_be16(dip + 0x00) != XFS_DINODE_MAGIC) {
                err("AG %u orphan audit: allocated agino %u bad magic 0x%04X",
                    agno, startino + i, get_be16(dip + 0x00));
                continue;
            }
            if (get_be16(dip + 0x02) != 0 &&    /* di_mode */
                get_be32(dip + 0x10) == 0)      /* di_nlink */
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
        get_be32(blk + 0x00) != XFS_IBT_CRC_MAGIC) {
        free(blk);
        return;
    }
    {
        uint16_t level   = get_be16(blk + 0x04);
        uint16_t numrecs = get_be16(blk + 0x06);

        if (level == 0) {
            orphan_collect_leaf(fd, geo, agno, blk, numrecs, cand, scanned);
        } else {
            uint32_t ptr_off = BTREE_REC_OFF + numrecs * 4;

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
            get_be32(agi_buf + 0x00) != XFS_AGI_MAGIC) {
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

/* ─── Usage ─── */

/*
 * sess42 C7 version gate — offline format upgrade (-U / --upgrade-protogate).
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
 * The sess377 ruling asked for a cryptographic digest over the archived
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
 * D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376, sess377 RULE-5 ruling
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
        case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD_C: {
            int gr = chk_print_guard(slot, aligned, sup.fs_uuid,
                                     (uint16_t)slice_count);

            if (gr == 2) {
                n_sweepguard++;
                if (slot >= slice_count)
                    n_outofrange--;   /* legitimate up here — see below */
            } else {
                n_guard++;
                if (gr == 1)
                    n_readable++;
            }
            break;
        }
        case 0:  /* MXFS_DISKLOCK_FLAG_EMPTY */
            /* sess377: a CLEANLY RELEASED slot keeps the MXLK magic and
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
 * sess377 ruling: "'every node unmounted' is necessary but NOT sufficient …
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
#define CHK_PR_MAX_KEYS 64

/*
 * PERSISTENT RESERVE IN, service action 0x00 (READ KEYS).  Returns the number
 * of registered keys, or -1 if the command could not be issued / the device
 * does not implement PR (which the caller must treat as "cannot prove").
 */
static int chk_pr_read_keys(int fd, uint64_t *keys, int max, int *unsupported)
{
    unsigned char cdb[10];
    unsigned char sense[32];
    unsigned char data[8 + CHK_PR_MAX_KEYS * 8];
    sg_io_hdr_t io;
    uint32_t list_len;
    int n, i;

    *unsupported = 0;
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0x5E;                      /* PERSISTENT RESERVE IN */
    cdb[1] = 0x00;                      /* READ KEYS */
    cdb[7] = (unsigned char)(sizeof(data) >> 8);
    cdb[8] = (unsigned char)(sizeof(data) & 0xFF);

    memset(&io, 0, sizeof(io));
    memset(sense, 0, sizeof(sense));
    memset(data, 0, sizeof(data));
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.mx_sb_len = sizeof(sense);
    io.dxfer_len = sizeof(data);
    io.dxferp = data;
    io.cmdp = cdb;
    io.sbp = sense;
    io.timeout = 20000;

    if (ioctl(fd, SG_IO, &io) < 0) {
        *unsupported = 1;
        return -1;
    }
    if (io.masked_status != 0 || io.host_status != 0) {
        /* ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE = no PR support. */
        *unsupported = 1;
        return -1;
    }
    list_len = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
               ((uint32_t)data[6] << 8) | (uint32_t)data[7];
    n = (int)(list_len / 8);
    if (n > max)
        n = max;
    for (i = 0; i < n; i++) {
        uint64_t k = 0;
        int b;

        for (b = 0; b < 8; b++)
            k = (k << 8) | data[8 + i * 8 + b];
        keys[i] = k;
    }
    return n;
}

/* ─── Backing-device disjointness for --archive-to ──────────────────────────
 *
 * sess377 ruling: the archive destination must be "proven disjoint from every
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
 * that, and the sess377 RULE-5 ruling fixes its shape:
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
#define CHK_REPAIR_HB_RECHECK_MS   10000

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

/* Aligned O_DIRECT read of one 512-byte disklock sector. */
static int chk_read_sector_direct(int dfd, uint64_t off, uint8_t *out512)
{
    uint8_t *buf = NULL;
    uint64_t base = off & ~(uint64_t)4095;
    uint64_t delta = off - base;
    int rc = -1;

    if (posix_memalign((void **)&buf, 4096, 4096) != 0)
        return -1;
    if (pread(dfd, buf, 4096, (off_t)base) == 4096) {
        memcpy(out512, buf + delta, 512);
        rc = 0;
    }
    free(buf);
    return rc;
}

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
        if (chk_read_sector_direct(dfd, sup->disklock_offset +
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
    uint64_t keys[CHK_PR_MAX_KEYS];
    int fd, n, unsupported = 0, i;

    fd = open(device, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "chk_mxfs: cannot open %s: %s\n",
                device, strerror(errno));
        return 4;
    }
    n = chk_pr_read_keys(fd, keys, CHK_PR_MAX_KEYS, &unsupported);
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
    uint64_t hb_ts[MXFS_DISKLOCK_HB_SLOTS];
    uint64_t hb_ep[MXFS_DISKLOCK_HB_SLOTS];
    uint8_t  hb_live[MXFS_DISKLOCK_HB_SLOTS];
    uint64_t keys[CHK_PR_MAX_KEYS];
    uint32_t slot;
    int nkeys, unsupported = 0, moved = 0, blocking;

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
    if (chk_read_sector_direct(dfd, q.sector_off, q.sector) < 0) {
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

    /* ── step 2, REMOTE half: no ACTIVE heartbeat may advance ── */
    printf("\n── proving exclusion ──────────────────────────────────────────\n");
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint8_t sec[512];
        const struct chk_hb_hdr *hh = (const void *)sec;

        hb_live[slot] = 0;
        if (chk_read_sector_direct(dfd, q.sup.disklock_offset +
                                   (uint64_t)slot * 512, sec) < 0)
            continue;
        if (hh->magic == MXFS_DISKLOCK_MAGIC &&
            hh->flags == MXFS_DISKLOCK_FLAG_ACTIVE) {
            hb_live[slot] = 1;
            hb_ts[slot] = hh->timestamp_ms;
            hb_ep[slot] = hh->epoch;
        }
    }
    printf("  rechecking heartbeat liveness for %d ms ...\n",
           CHK_REPAIR_HB_RECHECK_MS);
    usleep((useconds_t)CHK_REPAIR_HB_RECHECK_MS * 1000);
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        uint8_t sec[512];
        const struct chk_hb_hdr *hh = (const void *)sec;

        if (!hb_live[slot])
            continue;
        if (chk_read_sector_direct(dfd, q.sup.disklock_offset +
                                   (uint64_t)slot * 512, sec) < 0)
            continue;
        if (hh->magic == MXFS_DISKLOCK_MAGIC &&
            hh->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
            (hh->timestamp_ms != hb_ts[slot] || hh->epoch != hb_ep[slot])) {
            fprintf(stderr, "  LIVE: heartbeat slot %u (node %u) is still "
                    "beating — a node has this\n        filesystem mounted.  "
                    "Unmount everywhere first.\n", slot, hh->node_id);
            moved++;
        }
    }
    if (moved)
        goto out;
    printf("  no heartbeat advanced: no node is mounted\n");

    /* ── step 2, LUN half: SCSI PR must show no registrant ── */
    nkeys = chk_pr_read_keys(fd, keys, CHK_PR_MAX_KEYS, &unsupported);
    if (unsupported || nkeys < 0) {
        fprintf(stderr,
            "  CANNOT PROVE: this LUN does not answer PERSISTENT RESERVE IN, "
            "so there is no\n        way to show that no initiator can write "
            "to it right now.  A quiet\n        heartbeat table is not proof "
            "of exclusion.  Refusing.\n");
        goto out;
    }
    if (nkeys > 0) {
        int i;

        fprintf(stderr, "  REGISTERED: %d initiator key(s) are still "
                "registered on this LUN and can\n        write to it right "
                "now regardless of their heartbeats:\n", nkeys);
        for (i = 0; i < nkeys; i++)
            fprintf(stderr, "          0x%016llx\n",
                    (unsigned long long)keys[i]);
        fprintf(stderr, "        Fence or deregister them, then re-run.\n");
        goto out;
    }
    printf("  SCSI PR: no registered initiator — nothing can write to this "
           "LUN\n");

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
    if (get_be32(sec + 0) != XFS_SB_MAGIC) {
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
        if (get_be32(sec + 0) != XFS_SB_MAGIC) {
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

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-a|-p|-y|-n|-U] /dev/sdX\n", prog);
    fprintf(stderr, "  -v   verbose: show detailed info for each check\n");
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

    int open_flags = can_repair() ? O_RDWR : O_RDONLY;
    int fd = open(device, open_flags);
    if (fd < 0) {
        /* If O_RDWR fails, fall back to read-only check */
        if (open_flags == O_RDWR) {
            fprintf(stderr, "chk_mxfs: cannot open %s read-write: %s, "
                    "falling back to check-only\n", device, strerror(errno));
            repair = REPAIR_NONE;
            fd = open(device, O_RDONLY);
        }
        if (fd < 0) {
            fprintf(stderr, "chk_mxfs: cannot open %s: %s\n", device, strerror(errno));
            return 4;
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

    /* 8. Summary report */
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
