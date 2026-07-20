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

        if (hflags & MXFS_DISKLOCK_FLAG_ACTIVE) {
            active++;
            /* node_id is at offset 8 (uint32_t) */
            uint32_t node_id = *(uint32_t *)(buf + 8);
            info("disklock HB slot %d: ACTIVE (node_id=%u)", i, node_id);
        } else {
            empty++;
            if (verbose)
                info("disklock HB slot %d: inactive", i);
        }
    }

    int dlerrors = errors - pre_errors;
    if (dlerrors == 0) {
        printf("Disklock ................ OK  (%d HB slots, %d active)\n",
               MXFS_DISKLOCK_HB_SLOTS, active);
    } else {
        printf("Disklock ................ ERRORS (%d errors)\n", dlerrors);
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

    /* Check nlink > 0 for allocated inodes */
    uint32_t nlink = get_be32(ibuf + 0x10);
    if (nlink == 0) {
        err("inode %llu (%s): nlink=0 for allocated inode",
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

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] [-a|-p|-y|-n] /dev/sdX\n", prog);
    fprintf(stderr, "  -v   verbose: show detailed info for each check\n");
    fprintf(stderr, "  -n   check only, no modifications (default)\n");
    fprintf(stderr, "  -a   auto-repair safe fixes\n");
    fprintf(stderr, "  -p   preen: same as -a (for boot scripts)\n");
    fprintf(stderr, "  -y   repair all, answer yes to everything\n");
    fprintf(stderr, "\nExit codes:\n");
    fprintf(stderr, "  0  filesystem clean\n");
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

    /* Detect if invoked as fsck.mxfs — default to auto-repair mode */
    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];
    if (strcmp(progname, "fsck.mxfs") == 0)
        repair = REPAIR_AUTO;

    while ((opt = getopt(argc, argv, "vapynh")) != -1) {
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
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (optind >= argc)
        usage(argv[0]);

    device = argv[optind];

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
