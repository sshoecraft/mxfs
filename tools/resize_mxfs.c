/*
 * resize_mxfs — Grow an MXFS filesystem when the underlying device has expanded
 *
 * On-disk layout:
 *   [MXFS super 4KB] [journal region] [disklock region] [XFS data to end]
 *
 * Growing means adding new XFS allocation groups at the end of the XFS data
 * area. The MXFS super, journal, and disklock regions are at fixed offsets
 * at the start of the device and are not moved.
 *
 * Usage: resize_mxfs [-v] [-n] /dev/sdX
 *
 * Steps:
 *   1. Read MXFS super from offset 0 and validate
 *   2. Get new device size via BLKGETSIZE64
 *   3. Read existing XFS superblock at xfs_data_offset
 *   4. Calculate new geometry (new AGs to add)
 *   5. Write AG headers for each new AG
 *   6. Update primary XFS superblock
 *   7. Update MXFS super
 *
 * Standalone — no libmxfs linkage. Uses POSIX I/O directly.
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

/* Version */
#define STRINGIFY2(x) #x
#define STRINGIFY(x)  STRINGIFY2(x)
#define RESIZE_MXFS_VERSION  STRINGIFY(MXFS_VERSION_MAJOR) "." \
                             STRINGIFY(MXFS_VERSION_MINOR) "." \
                             STRINGIFY(MXFS_VERSION_PATCH)

/* XFS on-disk constants */
#define XFS_SB_MAGIC            0x58465342  /* "XFSB" */
#define XFS_AGF_MAGIC           0x58414746  /* "XAGF" */
#define XFS_AGI_MAGIC           0x58414749  /* "XAGI" */
#define XFS_AGFL_MAGIC          0x5841464C  /* "XAFL" */
#define XFS_BNO_MAGIC           0x41423342  /* "AB3B" */
#define XFS_CNT_MAGIC           0x41423343  /* "AB3C" */
#define XFS_INO_MAGIC           0x49414233  /* "IAB3" */
#define XFS_FINO_MAGIC          0x46494233  /* "FIB3" */

#define XFS_BLOCKSIZE           4096
#define XFS_SECTSIZE            512
#define NULLFSINO               0xFFFFFFFFFFFFFFFFULL

/* Minimum blocks for last AG */
#define MIN_AG_BLOCKS           64

/* New AG free-space layout: block 0=headers, 1=BNO, 2=CNT, 3=INO, 4=FINO */
#define NEW_AG_HEADER_BLOCKS    5

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

/* ─── Big-endian read helpers ─── */

static uint16_t get_be16(const void *p)
{
    const uint8_t *b = p;
    return (uint16_t)((uint16_t)b[0] << 8 | b[1]);
}

static uint32_t get_be32(const void *p)
{
    const uint8_t *b = p;
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
           (uint32_t)b[2] << 8 | (uint32_t)b[3];
}

static uint64_t get_be64(const void *p)
{
    const uint8_t *b = p;
    return (uint64_t)b[0] << 56 | (uint64_t)b[1] << 48 |
           (uint64_t)b[2] << 40 | (uint64_t)b[3] << 32 |
           (uint64_t)b[4] << 24 | (uint64_t)b[5] << 16 |
           (uint64_t)b[6] << 8 | (uint64_t)b[7];
}

/* ─── Big-endian write helpers ─── */

static void put_be16(void *p, uint16_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)(v);
}

static void put_be32(void *p, uint32_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static void put_be64(void *p, uint64_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

/* ─── XFS CRC helper ─── */

/*
 * XFS stores CRC as native uint32_t (little-endian on x86).
 * Seed ~0U, with final complement (~crc).
 */
static void xfs_set_crc(void *buf, size_t len, size_t crc_off)
{
    uint32_t *field = (uint32_t *)((uint8_t *)buf + crc_off);
    *field = 0;
    *field = ~crc32c(~0U, buf, len);
}

/* ─── Helpers ─── */

static bool opt_verbose;
static bool opt_dryrun;

static void pr_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

static void pr_verbose(const char *fmt, ...)
{
    va_list ap;
    if (!opt_verbose)
        return;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

static void pr_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static const char *human_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes >= (uint64_t)1024 * 1024 * 1024)
        snprintf(buf, buflen, "%.2f GB", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buf, buflen, "%.2f MB", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, buflen, "%.2f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, buflen, "%llu B", (unsigned long long)bytes);
    return buf;
}

/*
 * Read a buffer from fd at the given offset.
 * Uses posix_memalign for O_DIRECT compatibility.
 */
static int read_sectors(int fd, uint64_t offset, void *buf, uint64_t len)
{
    void *aligned;
    uint64_t done = 0;
    ssize_t ret;

    if (posix_memalign(&aligned, 4096, len) != 0) {
        pr_err("resize_mxfs: posix_memalign failed for %llu bytes\n",
               (unsigned long long)len);
        return -1;
    }

    while (done < len) {
        uint64_t chunk = len - done;
        if (chunk > 1048576)
            chunk = 1048576;

        ret = pread(fd, (char *)aligned + done, chunk, offset + done);
        if (ret < 0) {
            pr_err("resize_mxfs: pread at offset %llu failed: %s\n",
                   (unsigned long long)(offset + done), strerror(errno));
            free(aligned);
            return -1;
        }
        if (ret == 0) {
            pr_err("resize_mxfs: unexpected EOF at offset %llu\n",
                   (unsigned long long)(offset + done));
            free(aligned);
            return -1;
        }
        done += ret;
    }

    memcpy(buf, aligned, len);
    free(aligned);
    return 0;
}

/*
 * Write a buffer to fd at the given offset.
 * Uses pwrite with aligned memory for O_DIRECT compatibility.
 */
static int write_sectors(int fd, uint64_t offset, const void *buf, uint64_t len)
{
    void *aligned;
    ssize_t ret;
    uint64_t done = 0;

    if (opt_dryrun)
        return 0;

    if (posix_memalign(&aligned, 4096, len) != 0) {
        pr_err("resize_mxfs: posix_memalign failed for %llu bytes\n",
               (unsigned long long)len);
        return -1;
    }

    memcpy(aligned, buf, len);

    while (done < len) {
        uint64_t chunk = len - done;
        if (chunk > 1048576)
            chunk = 1048576;

        ret = pwrite(fd, (char *)aligned + done, chunk, offset + done);
        if (ret < 0) {
            pr_err("resize_mxfs: pwrite at offset %llu failed: %s\n",
                   (unsigned long long)(offset + done), strerror(errno));
            free(aligned);
            return -1;
        }
        done += ret;
    }

    free(aligned);
    return 0;
}

/* ─── XFS superblock field read/write ─── */

/*
 * Parsed XFS superblock fields needed for resize.
 */
struct xfs_sb_info {
    uint32_t magic;
    uint32_t blocksize;
    uint64_t dblocks;
    uint8_t  uuid[16];
    uint64_t logstart;
    uint64_t rootino;
    uint64_t rbmino;
    uint64_t rsumino;
    uint32_t agblocks;
    uint32_t agcount;
    uint32_t logblocks;
    uint16_t versionnum;
    uint8_t  blocklog;
    uint8_t  sectlog;
    uint8_t  inodelog;
    uint8_t  inopblog;
    uint8_t  agblklog;
    uint8_t  imax_pct;
    uint64_t icount;
    uint64_t ifree;
    uint64_t fdblocks;
    uint32_t inoalignmt;
    uint8_t  dirblklog;
    uint32_t logsunit;
    uint32_t features2;
    uint32_t bad_features2;
    uint32_t feat_compat;
    uint32_t feat_ro_compat;
    uint32_t feat_incompat;
    uint32_t feat_log_incompat;
    uint32_t spino_align;
    uint16_t sectsize;
    uint16_t inodesize;
    uint16_t inopblock;
};

/*
 * Parse XFS superblock from raw 512-byte sector buffer.
 */
static void parse_xfs_sb(const uint8_t *sec, struct xfs_sb_info *sb)
{
    sb->magic       = get_be32(sec + 0);
    sb->blocksize   = get_be32(sec + 4);
    sb->dblocks     = get_be64(sec + 8);
    memcpy(sb->uuid, sec + 32, 16);
    sb->logstart    = get_be64(sec + 48);
    sb->rootino     = get_be64(sec + 56);
    sb->rbmino      = get_be64(sec + 64);
    sb->rsumino     = get_be64(sec + 72);
    sb->agblocks    = get_be32(sec + 84);
    sb->agcount     = get_be32(sec + 88);
    sb->logblocks   = get_be32(sec + 96);
    sb->versionnum  = get_be16(sec + 100);
    sb->sectsize    = get_be16(sec + 102);
    sb->inodesize   = get_be16(sec + 104);
    sb->inopblock   = get_be16(sec + 106);
    sb->blocklog    = sec[120];
    sb->sectlog     = sec[121];
    sb->inodelog    = sec[122];
    sb->inopblog    = sec[123];
    sb->agblklog    = sec[124];
    sb->imax_pct    = sec[127];
    sb->icount      = get_be64(sec + 128);
    sb->ifree       = get_be64(sec + 136);
    sb->fdblocks    = get_be64(sec + 144);
    sb->inoalignmt  = get_be32(sec + 180);
    sb->dirblklog   = sec[192];
    sb->logsunit    = get_be32(sec + 196);
    sb->features2   = get_be32(sec + 200);
    sb->bad_features2 = get_be32(sec + 204);
    sb->feat_compat = get_be32(sec + 208);
    sb->feat_ro_compat = get_be32(sec + 212);
    sb->feat_incompat = get_be32(sec + 216);
    sb->feat_log_incompat = get_be32(sec + 220);
    sb->spino_align = get_be32(sec + 228);
}

/*
 * Write the full XFS superblock sector (512 bytes) from parsed fields.
 * Used for the primary SB and secondary SB copies in new AGs.
 *
 * For secondary SBs: inprogress=1, icount/ifree/fdblocks=0,
 * rootino/rbmino/rsumino=NULLFSINO.
 */
static void build_xfs_sb_sector(uint8_t *sec, const struct xfs_sb_info *sb,
                                bool primary)
{
    memset(sec, 0, 512);

    put_be32(sec + 0, XFS_SB_MAGIC);
    put_be32(sec + 4, sb->blocksize);
    put_be64(sec + 8, sb->dblocks);
    /* rblocks[16], rextents[24] = 0 */
    memcpy(sec + 32, sb->uuid, 16);
    put_be64(sec + 48, sb->logstart);
    put_be64(sec + 56, primary ? sb->rootino : NULLFSINO);
    put_be64(sec + 64, primary ? sb->rbmino : NULLFSINO);
    put_be64(sec + 72, primary ? sb->rsumino : NULLFSINO);
    put_be32(sec + 80, 1); /* rextsize */
    put_be32(sec + 84, sb->agblocks);
    put_be32(sec + 88, sb->agcount);
    /* rbmblocks[92] = 0 */
    put_be32(sec + 96, sb->logblocks);
    put_be16(sec + 100, sb->versionnum);
    put_be16(sec + 102, sb->sectsize);
    put_be16(sec + 104, sb->inodesize);
    put_be16(sec + 106, sb->inopblock);
    /* fname[108] = 0, 12 bytes */
    sec[120] = sb->blocklog;
    sec[121] = sb->sectlog;
    sec[122] = sb->inodelog;
    sec[123] = sb->inopblog;
    sec[124] = sb->agblklog;
    sec[125] = 0;  /* rextslog */
    sec[126] = primary ? 0 : 1;  /* inprogress */
    sec[127] = sb->imax_pct;
    put_be64(sec + 128, primary ? sb->icount : 0);
    put_be64(sec + 136, primary ? sb->ifree : 0);
    put_be64(sec + 144, sb->fdblocks);
    /* frextents[152] = 0 */
    put_be64(sec + 160, NULLFSINO);  /* uquotino */
    put_be64(sec + 168, NULLFSINO);  /* gquotino */
    put_be16(sec + 176, 0);  /* qflags */
    sec[178] = 0;  /* flags */
    sec[179] = 0;  /* shared_vn */
    put_be32(sec + 180, sb->inoalignmt);
    put_be32(sec + 184, 0);  /* unit */
    put_be32(sec + 188, 0);  /* width */
    sec[192] = sb->dirblklog;
    sec[193] = 0;  /* logsectlog */
    put_be16(sec + 194, 0);  /* logsectsize */
    put_be32(sec + 196, sb->logsunit);
    put_be32(sec + 200, sb->features2);
    put_be32(sec + 204, sb->bad_features2);
    put_be32(sec + 208, sb->feat_compat);
    put_be32(sec + 212, sb->feat_ro_compat);
    put_be32(sec + 216, sb->feat_incompat);
    put_be32(sec + 220, sb->feat_log_incompat);
    /* crc at 224 — computed below */
    put_be32(sec + 228, sb->spino_align);
    put_be64(sec + 232, NULLFSINO);  /* pquotino */
    put_be64(sec + 240, 0);  /* lsn */
    /* meta_uuid[248] = 0 */

    xfs_set_crc(sec, 512, 224);
}

/* ─── New AG structure writers ─── */

/*
 * Write the AGF sector (512 bytes) for a new AG.
 */
static void write_agf_sector(uint8_t *sec, uint32_t agno, uint32_t aglen,
                              uint32_t freeblks, const uint8_t *uuid)
{
    memset(sec, 0, 512);

    put_be32(sec + 0x00, XFS_AGF_MAGIC);
    put_be32(sec + 0x04, 1);          /* versionnum */
    put_be32(sec + 0x08, agno);       /* seqno */
    put_be32(sec + 0x0C, aglen);      /* length */
    put_be32(sec + 0x10, 1);          /* roots[0] = bnoroot */
    put_be32(sec + 0x14, 2);          /* roots[1] = cntroot */
    put_be32(sec + 0x18, 0);          /* roots[2] = rmaproot (disabled) */
    put_be32(sec + 0x1C, 1);          /* levels[0] = bnolevel */
    put_be32(sec + 0x20, 1);          /* levels[1] = cntlevel */
    put_be32(sec + 0x24, 0);          /* levels[2] = rmaplevel */

    /* AGFL: for new AGs (non-AG0, non-log), blocks 4-7 are AGFL blocks.
     * But we are NOT preallocating AGFL blocks for new AGs — keep it simple.
     * Set flfirst=0, fllast=0, flcount=0 (empty AGFL). */
    put_be32(sec + 0x28, 0);          /* flfirst */
    put_be32(sec + 0x2C, 0);          /* fllast */
    put_be32(sec + 0x30, 0);          /* flcount */

    put_be32(sec + 0x34, freeblks);   /* freeblks */
    put_be32(sec + 0x38, freeblks);   /* longest */
    put_be32(sec + 0x3C, 0);          /* btreeblks */

    memcpy(sec + 0x40, uuid, 16);     /* uuid */

    /* spare64, lsn = 0 (already zeroed by memset) */

    xfs_set_crc(sec, 512, 0xD8);     /* crc */
}

/*
 * Write the AGI sector (512 bytes) for a new AG (no allocated inodes).
 */
static void write_agi_sector(uint8_t *sec, uint32_t agno, uint32_t aglen,
                              const uint8_t *uuid)
{
    int i;

    memset(sec, 0, 512);

    put_be32(sec + 0x00, XFS_AGI_MAGIC);
    put_be32(sec + 0x04, 1);             /* versionnum */
    put_be32(sec + 0x08, agno);          /* seqno */
    put_be32(sec + 0x0C, aglen);         /* length */
    put_be32(sec + 0x10, 0);             /* count = 0 (no inodes) */
    put_be32(sec + 0x14, 3);             /* root = inobt at block 3 */
    put_be32(sec + 0x18, 1);             /* level = 1 */
    put_be32(sec + 0x1C, 0);             /* freecount = 0 */
    put_be32(sec + 0x20, 0xFFFFFFFF);    /* newino = NULLAGINO */
    put_be32(sec + 0x24, 0xFFFFFFFF);    /* dirino = NULLAGINO */

    /* unlinked[64] = all 0xFFFFFFFF */
    for (i = 0; i < 64; i++)
        put_be32(sec + 0x28 + i * 4, 0xFFFFFFFF);

    memcpy(sec + 0x128, uuid, 16);      /* uuid */

    /* finobt fields */
    put_be32(sec + 0x148, 4);           /* free_root = finobt at block 4 */
    put_be32(sec + 0x14C, 1);           /* free_level = 1 */

    xfs_set_crc(sec, 512, 0x138);        /* crc */
}

/*
 * Write the AGFL sector (512 bytes) for a new AG (empty free list).
 */
static void write_agfl_sector(uint8_t *sec, uint32_t agno, const uint8_t *uuid)
{
    int i;

    memset(sec, 0, 512);

    put_be32(sec + 0x00, XFS_AGFL_MAGIC);
    put_be32(sec + 0x04, agno);          /* seqno */
    memcpy(sec + 0x08, uuid, 16);        /* uuid */
    /* lsn[0x18] = 0 */
    /* crc at 0x20 — computed below */

    /* All AGFL entries = 0xFFFFFFFF (NULLAGBLOCK) */
    for (i = 0; i < 119; i++)
        put_be32(sec + 0x24 + i * 4, 0xFFFFFFFF);

    xfs_set_crc(sec, 512, 0x20);         /* crc */
}

/*
 * Write a V5 short-form btree block (4096 bytes).
 * Matches mkfs_mxfs.c write_btree_block() layout exactly.
 */
static void write_btree_block(uint8_t *blk, uint32_t magic,
                               uint32_t agno, uint64_t blkno_abs,
                               uint16_t numrecs,
                               const uint8_t *rec_data, size_t rec_len,
                               const uint8_t *uuid)
{
    memset(blk, 0, XFS_BLOCKSIZE);

    /* V5 short-form btree header */
    put_be32(blk + 0x00, magic);              /* magic */
    put_be16(blk + 0x04, 0);                  /* level = 0 (leaf) */
    put_be16(blk + 0x06, numrecs);            /* numrecs */
    put_be32(blk + 0x08, 0xFFFFFFFF);         /* leftsib = null */
    put_be32(blk + 0x0C, 0xFFFFFFFF);         /* rightsib = null */
    put_be64(blk + 0x10, blkno_abs * 8);      /* blkno in 512B sectors */
    /* lsn[0x18] = 0 */
    memcpy(blk + 0x20, uuid, 16);             /* uuid */
    put_be32(blk + 0x30, agno);               /* owner */

    /* records at 0x38 */
    if (numrecs > 0 && rec_data && rec_len > 0)
        memcpy(blk + 0x38, rec_data, rec_len);

    xfs_set_crc(blk, XFS_BLOCKSIZE, 0x34);    /* crc */
}

/*
 * Write all structures for one new AG.
 *
 * fd:              file descriptor
 * agno:            AG number
 * aglen:           number of blocks in this AG
 * agblocks_std:    standard agblocks (for SB copies)
 * xfs_data_offset: byte offset of XFS data start on device
 * sb:              parsed XFS superblock (with updated fields for new geometry)
 * uuid:            filesystem UUID
 */
static int write_new_ag(int fd, uint32_t agno, uint32_t aglen,
                         uint64_t xfs_data_offset,
                         const struct xfs_sb_info *sb,
                         const uint8_t *uuid)
{
    uint8_t *block;
    uint64_t ag_byte_offset;
    uint32_t free_start;
    uint32_t freeblks;
    uint8_t rec[8];

    block = calloc(1, XFS_BLOCKSIZE);
    if (!block) {
        pr_err("resize_mxfs: failed to allocate AG buffer\n");
        return -1;
    }

    ag_byte_offset = xfs_data_offset +
                     (uint64_t)agno * sb->agblocks * XFS_BLOCKSIZE;

    /* Free space starts after header blocks */
    free_start = NEW_AG_HEADER_BLOCKS;
    freeblks = aglen - NEW_AG_HEADER_BLOCKS;

    pr_verbose("  AG %u: offset=%llu aglen=%u free_start=%u freeblks=%u\n",
               agno, (unsigned long long)ag_byte_offset, aglen,
               free_start, freeblks);

    /* Block 0: SB + AGF + AGI + AGFL (4 sectors in one 4KB block) */
    memset(block, 0, XFS_BLOCKSIZE);

    /* SB sector (secondary copy) */
    build_xfs_sb_sector(block + 0, sb, false);

    /* AGF sector */
    write_agf_sector(block + 512, agno, aglen, freeblks, uuid);

    /* AGI sector */
    write_agi_sector(block + 1024, agno, aglen, uuid);

    /* AGFL sector */
    write_agfl_sector(block + 1536, agno, uuid);

    if (write_sectors(fd, ag_byte_offset, block, XFS_BLOCKSIZE) < 0)
        goto fail;

    /* Block 1: BNO btree root — one record for all free space */
    memset(rec, 0, sizeof(rec));
    put_be32(rec + 0, free_start);  /* startblock */
    put_be32(rec + 4, freeblks);    /* blockcount */

    write_btree_block(block, XFS_BNO_MAGIC, agno,
                      (uint64_t)agno * sb->agblocks + 1,
                      1, rec, 8, uuid);

    if (write_sectors(fd, ag_byte_offset + XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
        goto fail;

    /* Block 2: CNT btree root — same single free extent record */
    write_btree_block(block, XFS_CNT_MAGIC, agno,
                      (uint64_t)agno * sb->agblocks + 2,
                      1, rec, 8, uuid);

    if (write_sectors(fd, ag_byte_offset + 2 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
        goto fail;

    /* Block 3: INO btree root — empty (no inodes in new AG) */
    write_btree_block(block, XFS_INO_MAGIC, agno,
                      (uint64_t)agno * sb->agblocks + 3,
                      0, NULL, 0, uuid);

    if (write_sectors(fd, ag_byte_offset + 3 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
        goto fail;

    /* Block 4: FINO btree root — empty (no inode chunks, so no free inodes) */
    write_btree_block(block, XFS_FINO_MAGIC, agno,
                      (uint64_t)agno * sb->agblocks + 4,
                      0, NULL, 0, uuid);

    if (write_sectors(fd, ag_byte_offset + 4 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
        goto fail;

    free(block);
    return 0;

fail:
    free(block);
    return -1;
}

/* ─── MXFS super CRC helper ─── */

/*
 * MXFS super CRC: crc32c(~0U, buf, 4096) with crc field zeroed, NOT complemented.
 */
static uint32_t mxfs_super_crc(const struct mxfs_ondisk_super *sup)
{
    struct mxfs_ondisk_super tmp;
    memcpy(&tmp, sup, sizeof(tmp));
    tmp.crc = 0;
    return crc32c(~0U, &tmp, sizeof(tmp));
}

/* ─── Usage ─── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-v] [-n] [-V] DEVICE\n"
            "\n"
            "Grow an MXFS filesystem after the underlying device has been expanded.\n"
            "\n"
            "  -v    Verbose output\n"
            "  -n    Dry run (show what would be done, don't write)\n"
            "  -V    Print version and exit\n",
            prog);
}

/* ─── Main ─── */

int main(int argc, char *argv[])
{
    const char *device = NULL;
    int opt, fd;
    struct stat st;
    bool is_blkdev;
    uint64_t new_device_size;
    char hbuf1[64], hbuf2[64], hbuf3[64], hbuf4[64];

    /* MXFS super */
    struct mxfs_ondisk_super msup;
    uint32_t computed_crc;

    /* XFS superblock */
    uint8_t xfs_sb_raw[512];
    struct xfs_sb_info sb;

    /* Resize geometry */
    uint64_t new_xfs_data_size;
    uint64_t new_dblocks;
    uint32_t old_agcount;
    uint32_t new_agcount;
    uint32_t new_last_agblocks;
    uint64_t added_freeblks;
    uint32_t agno;

    while ((opt = getopt(argc, argv, "vnV")) != -1) {
        switch (opt) {
        case 'v':
            opt_verbose = true;
            break;
        case 'n':
            opt_dryrun = true;
            break;
        case 'V':
            printf("resize_mxfs version %s\n", RESIZE_MXFS_VERSION);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    device = argv[optind];

    /* Validate device/file exists */
    if (stat(device, &st) < 0) {
        pr_err("resize_mxfs: %s: %s\n", device, strerror(errno));
        return 1;
    }

    is_blkdev = S_ISBLK(st.st_mode);
    if (!is_blkdev && !S_ISREG(st.st_mode)) {
        pr_err("resize_mxfs: %s: not a block device or regular file\n", device);
        return 1;
    }

    /* Open device for reading first (validation phase) */
    fd = open(device, O_RDWR);
    if (fd < 0) {
        pr_err("resize_mxfs: %s: %s\n", device, strerror(errno));
        return 1;
    }

    /* ─── Step 1: Get new device size ─── */

    if (is_blkdev) {
        if (ioctl(fd, BLKGETSIZE64, &new_device_size) < 0) {
            pr_err("resize_mxfs: %s: cannot get device size: %s\n",
                   device, strerror(errno));
            close(fd);
            return 1;
        }
    } else {
        new_device_size = (uint64_t)st.st_size;
    }

    /* ─── Step 2: Read and validate MXFS super ─── */

    if (read_sectors(fd, 0, &msup, sizeof(msup)) < 0) {
        close(fd);
        return 1;
    }

    if (msup.magic != MXFS_FORMAT_MAGIC) {
        pr_err("resize_mxfs: %s: bad MXFS magic (0x%08x, expected 0x%08x)\n",
               device, msup.magic, MXFS_FORMAT_MAGIC);
        close(fd);
        return 1;
    }

    if (msup.version != MXFS_FORMAT_VERSION) {
        pr_err("resize_mxfs: %s: unsupported MXFS version %u (expected %u)\n",
               device, msup.version, MXFS_FORMAT_VERSION);
        close(fd);
        return 1;
    }

    computed_crc = mxfs_super_crc(&msup);
    if (msup.crc != computed_crc) {
        pr_err("resize_mxfs: %s: MXFS super CRC mismatch "
               "(on-disk 0x%08x, computed 0x%08x)\n",
               device, msup.crc, computed_crc);
        close(fd);
        return 1;
    }

    pr_verbose("MXFS super validated: magic=0x%08x version=%u crc=0x%08x\n",
               msup.magic, msup.version, msup.crc);
    pr_verbose("  device_size=%llu xfs_data_offset=%llu xfs_data_size=%llu\n",
               (unsigned long long)msup.device_size,
               (unsigned long long)msup.xfs_data_offset,
               (unsigned long long)msup.xfs_data_size);

    /* ─── Step 3: Check new size > old size ─── */

    if (new_device_size <= msup.device_size) {
        pr_err("resize_mxfs: %s: new device size (%s) is not larger than "
               "current size (%s)\n",
               device,
               human_size(new_device_size, hbuf1, sizeof(hbuf1)),
               human_size(msup.device_size, hbuf2, sizeof(hbuf2)));
        close(fd);
        return 1;
    }

    /* ─── Step 4: Read existing XFS superblock ─── */

    if (read_sectors(fd, msup.xfs_data_offset, xfs_sb_raw, 512) < 0) {
        close(fd);
        return 1;
    }

    parse_xfs_sb(xfs_sb_raw, &sb);

    if (sb.magic != XFS_SB_MAGIC) {
        pr_err("resize_mxfs: %s: bad XFS magic at offset %llu "
               "(0x%08x, expected 0x%08x)\n",
               device, (unsigned long long)msup.xfs_data_offset,
               sb.magic, XFS_SB_MAGIC);
        close(fd);
        return 1;
    }

    if (sb.blocksize != XFS_BLOCKSIZE) {
        pr_err("resize_mxfs: %s: unexpected XFS blocksize %u (expected %u)\n",
               device, sb.blocksize, XFS_BLOCKSIZE);
        close(fd);
        return 1;
    }

    pr_verbose("XFS superblock at offset %llu:\n",
               (unsigned long long)msup.xfs_data_offset);
    pr_verbose("  dblocks=%llu agcount=%u agblocks=%u fdblocks=%llu\n",
               (unsigned long long)sb.dblocks, sb.agcount,
               sb.agblocks, (unsigned long long)sb.fdblocks);

    /* ─── Step 5: Calculate new geometry ─── */

    /*
     * New AGs are appended after the existing data area. The existing AGs
     * (including the old last AG) are untouched. We compute how many new
     * full AGs fit in the new space, with the final new AG getting the
     * remainder (if large enough).
     */

    old_agcount = sb.agcount;

    {
        uint64_t max_xfs_blocks;    /* max blocks from xfs_data_offset to end */
        uint64_t new_ag_start;      /* block offset where new AGs begin */
        uint64_t avail_for_new;     /* blocks available for new AGs */
        uint32_t full_new_ags;
        uint32_t remainder;

        max_xfs_blocks = (new_device_size - msup.xfs_data_offset) / XFS_BLOCKSIZE;

        if (max_xfs_blocks <= sb.dblocks) {
            pr_err("resize_mxfs: %s: new XFS data area (%llu blocks) is not "
                   "larger than current (%llu blocks)\n",
                   device,
                   (unsigned long long)max_xfs_blocks,
                   (unsigned long long)sb.dblocks);
            close(fd);
            return 1;
        }

        /*
         * In XFS, AG offsets are computed as agno * agblocks. The old last AG
         * may be shorter than agblocks, creating an address-space gap. New AGs
         * must start at old_agcount * agblocks, not at old dblocks.
         */
        new_ag_start = (uint64_t)old_agcount * sb.agblocks;

        if (max_xfs_blocks <= new_ag_start) {
            pr_err("resize_mxfs: %s: new device too small for additional AGs\n",
                   device);
            close(fd);
            return 1;
        }

        avail_for_new = max_xfs_blocks - new_ag_start;

        if (avail_for_new < MIN_AG_BLOCKS) {
            pr_err("resize_mxfs: %s: not enough new space (%llu blocks)\n",
                   device, (unsigned long long)avail_for_new);
            close(fd);
            return 1;
        }

        full_new_ags = (uint32_t)(avail_for_new / sb.agblocks);
        remainder = (uint32_t)(avail_for_new -
                    (uint64_t)full_new_ags * sb.agblocks);

        /* If remainder is too small for an AG, drop it */
        if (remainder > 0 && remainder < MIN_AG_BLOCKS)
            remainder = 0;

        new_agcount = old_agcount + full_new_ags + (remainder > 0 ? 1 : 0);

        if (new_agcount <= old_agcount) {
            pr_err("resize_mxfs: %s: not enough new space for additional AGs\n",
                   device);
            close(fd);
            return 1;
        }

        /* The last new AG gets the remainder, or a full agblocks if no remainder */
        new_last_agblocks = (remainder > 0) ? remainder : sb.agblocks;

        /* Total dblocks = (new_agcount-1) * agblocks + last AG size.
         * The last AG of the *entire* filesystem is either:
         * - new_last_agblocks (if we added a partial AG), or
         * - agblocks (if all new AGs are full-size) */
        new_dblocks = (uint64_t)(new_agcount - 1) * sb.agblocks +
                      new_last_agblocks;
        new_xfs_data_size = new_dblocks * XFS_BLOCKSIZE;

        /* Calculate total free blocks from new AGs */
        added_freeblks = 0;
        for (agno = old_agcount; agno < new_agcount; agno++) {
            uint32_t this_aglen;
            if (agno == new_agcount - 1 && remainder > 0)
                this_aglen = remainder;
            else
                this_aglen = sb.agblocks;
            added_freeblks += this_aglen - NEW_AG_HEADER_BLOCKS;
        }
    }

    /* ─── Print resize plan ─── */

    pr_info("resize_mxfs v%s — growing %s\n", RESIZE_MXFS_VERSION, device);
    pr_info("Old device size: %s\n",
            human_size(msup.device_size, hbuf1, sizeof(hbuf1)));
    pr_info("New device size: %s\n",
            human_size(new_device_size, hbuf2, sizeof(hbuf2)));
    pr_info("Old XFS data: %s (%u AGs)\n",
            human_size(msup.xfs_data_size, hbuf1, sizeof(hbuf1)),
            old_agcount);
    pr_info("New XFS data: %s (%u AGs)\n",
            human_size(new_xfs_data_size, hbuf2, sizeof(hbuf2)),
            new_agcount);
    pr_info("Adding %u new AG%s (AG %u",
            new_agcount - old_agcount,
            (new_agcount - old_agcount) > 1 ? "s" : "",
            old_agcount);
    if (new_agcount - old_agcount > 1)
        pr_info(" - AG %u", new_agcount - 1);
    pr_info(")\n");

    for (agno = old_agcount; agno < new_agcount; agno++) {
        uint32_t this_aglen;
        if (agno == new_agcount - 1)
            this_aglen = new_last_agblocks;
        else
            this_aglen = sb.agblocks;
        pr_info("  AG %u: %u blocks, %u free\n",
                agno, this_aglen, this_aglen - NEW_AG_HEADER_BLOCKS);
    }

    pr_info("Updating XFS superblock: dblocks %llu -> %llu\n",
            (unsigned long long)sb.dblocks,
            (unsigned long long)new_dblocks);
    pr_info("Updating MXFS super: device_size %s -> %s\n",
            human_size(msup.device_size, hbuf3, sizeof(hbuf3)),
            human_size(new_device_size, hbuf4, sizeof(hbuf4)));

    if (opt_dryrun) {
        pr_info("resize_mxfs: dry run — no changes written\n");
        close(fd);
        return 0;
    }

    /* ─── Step 6: Reopen with O_DIRECT if possible ─── */

    close(fd);

    fd = open(device, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        fd = open(device, O_RDWR | O_SYNC);
        if (fd < 0) {
            pr_err("resize_mxfs: cannot reopen %s for writing: %s\n",
                   device, strerror(errno));
            return 1;
        }
    }

    /* ─── Step 7: Update XFS superblock fields for new geometry ─── */

    sb.dblocks = new_dblocks;
    sb.agcount = new_agcount;
    sb.fdblocks += added_freeblks;

    /* ─── Step 8: Write new AG structures ─── */

    pr_info("Writing new AG structures...\n");

    for (agno = old_agcount; agno < new_agcount; agno++) {
        uint32_t this_aglen;
        if (agno == new_agcount - 1)
            this_aglen = new_last_agblocks;
        else
            this_aglen = sb.agblocks;

        if (write_new_ag(fd, agno, this_aglen, msup.xfs_data_offset,
                         &sb, sb.uuid) < 0) {
            pr_err("resize_mxfs: failed writing AG %u\n", agno);
            close(fd);
            return 1;
        }
    }

    /* ─── Step 9: Update primary XFS superblock ─── */

    pr_info("Updating primary XFS superblock...\n");

    {
        uint8_t header_block[XFS_BLOCKSIZE];

        /* Read the full first block (SB + AGF + AGI + AGFL) */
        if (read_sectors(fd, msup.xfs_data_offset, header_block,
                         XFS_BLOCKSIZE) < 0) {
            close(fd);
            return 1;
        }

        /* Rebuild just the SB sector (first 512 bytes) with updated fields */
        build_xfs_sb_sector(header_block, &sb, true);

        if (write_sectors(fd, msup.xfs_data_offset, header_block,
                          XFS_BLOCKSIZE) < 0) {
            pr_err("resize_mxfs: failed updating primary XFS superblock\n");
            close(fd);
            return 1;
        }
    }

    /* ─── Step 10: Update secondary SB copies in existing AGs (1 to old_agcount-1) ─── */

    pr_info("Updating secondary XFS superblock copies...\n");

    for (agno = 1; agno < old_agcount; agno++) {
        uint8_t header_block[XFS_BLOCKSIZE];
        uint64_t ag_offset = msup.xfs_data_offset +
                             (uint64_t)agno * sb.agblocks * XFS_BLOCKSIZE;

        /* Read existing AG header block to preserve AGF/AGI/AGFL */
        if (read_sectors(fd, ag_offset, header_block, XFS_BLOCKSIZE) < 0) {
            close(fd);
            return 1;
        }

        /* Rebuild just the SB sector (first 512 bytes) as secondary */
        build_xfs_sb_sector(header_block, &sb, false);

        if (write_sectors(fd, ag_offset, header_block, XFS_BLOCKSIZE) < 0) {
            pr_err("resize_mxfs: failed updating SB copy in AG %u\n", agno);
            close(fd);
            return 1;
        }
    }

    /* ─── Step 11: Update MXFS super ─── */

    pr_info("Updating MXFS superblock...\n");

    msup.device_size = new_device_size;
    msup.xfs_data_size = new_xfs_data_size;
    msup.crc = 0;
    msup.crc = mxfs_super_crc(&msup);

    if (write_sectors(fd, 0, &msup, MXFS_SUPER_SIZE) < 0) {
        pr_err("resize_mxfs: failed updating MXFS superblock\n");
        close(fd);
        return 1;
    }

    /* Sync */
    if (fsync(fd) < 0)
        pr_err("resize_mxfs: warning: fsync failed: %s\n", strerror(errno));

    close(fd);

    pr_info("resize_mxfs: done\n");

    return 0;
}
