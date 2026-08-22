/*
 * mkfs.mxfs — Format a block device for MXFS (Multinode XFS)
 *
 * Creates the on-disk layout:
 *   [MXFS super 4KB] [journal region] [disklock region] [XFS data to end]
 *
 * Usage: mkfs.mxfs [-f] [-v] /dev/sdX
 *
 * Steps:
 *   1. Get device size
 *   2. Calculate region offsets
 *   3. Write MXFS on-disk superblock at offset 0
 *   4. Format journal region (super + slot headers)
 *   5. Zero disklock region
 *   6. Format XFS natively (at xfs_data_offset)
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
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <mxfs/mxfs_super.h>
#include <mxfs/mxfs_common.h>

/* ─── Constants from libmxfs headers (duplicated to stay standalone) ─── */

/* Journal layout (from journal.h) */
#define MXFS_JOURNAL_MAGIC              0x4D584A4C  /* "MXJL" */
#define MXFS_JOURNAL_VERSION            1
#define MXFS_JOURNAL_SECTOR_SIZE        512
#define MXFS_JOURNAL_SLOT_SIZE_SECTORS  2048        /* 1 MB per slot */
#define MXFS_JOURNAL_SLOT_FLAG_CLEAN    0x00

/* Disklock layout (from disklock.h) */
#define MXFS_DISKLOCK_RECORD_SIZE       512
#define MXFS_DISKLOCK_MAX_SLOTS         65536
#define MXFS_DISKLOCK_HB_SLOTS          64
#define MXFS_DISKLOCK_HB_SIZE           (MXFS_DISKLOCK_HB_SLOTS * \
                                         MXFS_DISKLOCK_RECORD_SIZE)
#define MXFS_DISKLOCK_REGION_SIZE       (MXFS_DISKLOCK_HB_SIZE + \
                                         (uint64_t)MXFS_DISKLOCK_MAX_SLOTS * \
                                         MXFS_DISKLOCK_RECORD_SIZE)

/* Default max nodes */
#define MXFS_MAX_NODES                  64

/* Minimum device size: reserve ~96MB + at least 100MB for XFS */
#define MXFS_MIN_DEVICE_SIZE            (200ULL * 1024 * 1024)

/* Align down to 4KB boundary */
#define ALIGN_DOWN_4K(x)                ((x) & ~(uint64_t)4095)

/* Align up to 4KB boundary */
#define ALIGN_UP_4K(x)                  (((x) + 4095) & ~(uint64_t)4095)

/* Version */
#define STRINGIFY2(x) #x
#define STRINGIFY(x)  STRINGIFY2(x)
#define MKFS_MXFS_VERSION  STRINGIFY(MXFS_VERSION_MAJOR) "." \
                           STRINGIFY(MXFS_VERSION_MINOR) "." \
                           STRINGIFY(MXFS_VERSION_PATCH)

/* ─── XFS on-disk constants ─── */

#define XFS_SB_MAGIC            0x58465342  /* "XFSB" */
#define XFS_AGF_MAGIC           0x58414746  /* "XAGF" */
#define XFS_AGI_MAGIC           0x58414749  /* "XAGI" */
#define XFS_AGFL_MAGIC          0x5841464C  /* "XAFL" */
#define XFS_BNO_MAGIC           0x41423342  /* "AB3B" */
#define XFS_CNT_MAGIC           0x41423343  /* "AB3C" */
#define XFS_INO_MAGIC           0x49414233  /* "IAB3" */
#define XFS_FINO_MAGIC          0x46494233  /* "FIB3" */
#define XFS_DINODE_MAGIC        0x494E      /* "IN" */

#define XFS_BLOCKSIZE           4096
#define XFS_BLOCKLOG            12
#define XFS_SECTSIZE            512
#define XFS_SECTLOG             9
#define XFS_INODESIZE           512
#define XFS_INODELOG            9
#define XFS_INOPBLOCK           8
#define XFS_INOPBLOG            3
#define XFS_INOALIGNMT          8
#define XFS_SPINO_ALIGN         4
#define XFS_IMAX_PCT            25
#define XFS_REXTSIZE            1
#define XFS_DIRBLKLOG           0
#define XFS_INODES_PER_CHUNK    64
#define XFS_INODE_CHUNK_BLOCKS  8   /* 64 * 512 / 4096 */

/* Feature flags.
 * ATTRBIT (0x0010) is preset at format time (sess353, #94 closure + GPT
 * ruling): FEATURES2 already advertises ATTR2, and leaving ATTRBIT unset
 * makes the kernel perform a LAZY per-node xfs_add_attr + whole-SB log on
 * the first xattr-bearing create — an uncoordinated cluster-wide SB feature
 * transition that diverges peers' in-core superblocks and false-refuses
 * foreign replay of the transitioning node's slice.  Stock mkfs.xfs presets
 * this bit; so do we.  The kernel refuses a cluster mount without it. */
#define XFS_SB_VERSIONNUM      0xB4B5
#define XFS_SB_FEATURES2       0x018A  /* LAZYSBCOUNT|ATTR2|PROJID32|CRC */
#define XFS_SB_FEAT_RO_COMPAT_FINOBT  (1 << 0)  /* free inode btree */
/* sess42 C7: FTYPE|SPINODES + MXFS_PROTOGATE (bit 30).  The PROTOGATE
 * incompat bit makes every pre-gate mxfs kernel REFUSE the mount outright
 * (inherited upstream unknown-incompat check) — the preventative half of
 * the C7 version gate; see include/mxfs/mxfs_super.h. */
#define XFS_SB_FEAT_INCOMPAT   (0x03 | (1u << 30))

/* Null filesystem inode */
#define NULLFSINO              0xFFFFFFFFFFFFFFFFULL

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

/* ─── UUID generation ─── */

static int gen_uuid(uint8_t *uuid)
{
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t ret;

    if (fd < 0) {
        fprintf(stderr, "mkfs.mxfs: cannot open /dev/urandom: %s\n",
                strerror(errno));
        return -1;
    }

    ret = read(fd, uuid, 16);
    close(fd);

    if (ret != 16) {
        fprintf(stderr, "mkfs.mxfs: short read from /dev/urandom\n");
        return -1;
    }

    /* UUID version 4 */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    /* UUID variant 1 */
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    return 0;
}

/* ─── Helpers ─── */

static bool verbose;

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
    if (!verbose)
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

/* Ceiling of log2(v), v must be > 0 */
static uint32_t ceil_log2(uint32_t v)
{
    uint32_t r = 0;
    uint32_t t = 1;

    while (t < v) {
        t <<= 1;
        r++;
    }
    return r;
}

/*
 * Write a buffer to fd at the given offset.
 * Uses pwrite with O_DIRECT alignment via posix_memalign.
 */
static int write_sectors(int fd, uint64_t offset, const void *buf, uint64_t len)
{
    void *aligned;
    ssize_t ret;
    uint64_t done = 0;

    if (posix_memalign(&aligned, 4096, len) != 0) {
        pr_err("mkfs.mxfs: posix_memalign failed for %llu bytes\n",
               (unsigned long long)len);
        return -1;
    }

    memcpy(aligned, buf, len);

    while (done < len) {
        uint64_t chunk = len - done;
        if (chunk > 1048576)
            chunk = 1048576;  /* 1MB at a time */

        ret = pwrite(fd, (char *)aligned + done, chunk, offset + done);
        if (ret < 0) {
            pr_err("mkfs.mxfs: pwrite at offset %llu failed: %s\n",
                   (unsigned long long)(offset + done), strerror(errno));
            free(aligned);
            return -1;
        }
        done += ret;
    }

    free(aligned);
    return 0;
}

/*
 * Zero a region on disk, writing in 1MB chunks.
 *
 * v0.3.30: prefer BLKZEROOUT ioctl (uses SCSI WRITE SAME with UNMAP — kernel
 * verifies the device actually accepts and durably persists zeros).  pwrite
 * fallback for devices that don't support the ioctl.  After writes, read
 * back a sample (every 4MB) and verify content is zeros — catches
 * VM/iSCSI/LIO setups that silently drop writes (sess19 root cause: pwrite
 * returned success but disklock region retained pre-mkfs ASCII text).
 */
static int zero_region(int fd, uint64_t offset, uint64_t len)
{
    void *zbuf;
    void *vbuf;
    uint64_t done = 0;
    uint64_t chunk;
    uint64_t verify_off;
    ssize_t ret;
    int rc = 0;

    /* Try BLKZEROOUT first — kernel-level zero with WRITE SAME / discard.
     * Issue it in bounded chunks: one BLKZEROOUT over the whole region
     * becomes a single strictly-serialized WRITE SAME at the iSCSI target
     * (SCST blocks the device and drains all outstanding commands around
     * it).  A 33MB single command can starve past the initiator's 60s
     * timeout under concurrent CAW load, escalating to ABORT_TASK →
     * LUN_RESET → nexus loss, which wedges the target until host reboot
     * (sess14/sess15 root cause).  4MB chunks complete in well under the
     * timeout individually; total cost is the same. */
    {
        uint64_t zdone = 0;
        int zrc = 0;
        while (zdone < len) {
            uint64_t zchunk = len - zdone;
            if (zchunk > 4194304)
                zchunk = 4194304;
            uint64_t range[2] = { offset + zdone, zchunk };
            zrc = ioctl(fd, BLKZEROOUT, range);
            if (zrc != 0)
                break;
            zdone += zchunk;
        }
        if (zrc == 0 && zdone == len) {
            pr_verbose("  BLKZEROOUT %llu bytes at %llu OK (4MB chunks)\n",
                       (unsigned long long)len,
                       (unsigned long long)offset);
            goto verify;
        }
        /* ioctl unsupported or failed mid-region — fall through to pwrite
         * for the whole region (pwrite re-zeros from the start; idempotent) */
    }

    if (posix_memalign(&zbuf, 4096, 1048576) != 0) {
        pr_err("mkfs.mxfs: posix_memalign failed for zero buffer\n");
        return -1;
    }
    memset(zbuf, 0, 1048576);

    while (done < len) {
        chunk = len - done;
        if (chunk > 1048576)
            chunk = 1048576;

        ret = pwrite(fd, zbuf, chunk, offset + done);
        if (ret < 0) {
            pr_err("mkfs.mxfs: zero pwrite at offset %llu failed: %s\n",
                   (unsigned long long)(offset + done), strerror(errno));
            free(zbuf);
            return -1;
        }
        done += ret;
    }

    free(zbuf);

verify:
    /* fsync to flush any buffering (esp. when O_DIRECT was unavailable) */
    if (fsync(fd) < 0) {
        pr_err("mkfs.mxfs: zero_region fsync failed: %s\n", strerror(errno));
        return -1;
    }

    /* Read-back verify every 4MB.  Catches setups where the kernel reports
     * write success but the underlying device silently drops the data
     * (observed on this LIO/qemu test setup in sess19).  4MB stride keeps
     * total verify cost <1s for 33MB regions while sampling ~9 points. */
    if (posix_memalign(&vbuf, 4096, 4096) != 0) {
        pr_err("mkfs.mxfs: posix_memalign for verify failed\n");
        return -1;
    }

    for (verify_off = 0; verify_off < len; verify_off += (4 * 1024 * 1024)) {
        const unsigned char *p;
        size_t i;
        size_t bytes_to_check = (len - verify_off > 4096) ? 4096
                                                          : (len - verify_off);

        ret = pread(fd, vbuf, bytes_to_check, offset + verify_off);
        if (ret < 0) {
            pr_err("mkfs.mxfs: zero_region verify pread @%llu: %s\n",
                   (unsigned long long)(offset + verify_off),
                   strerror(errno));
            free(vbuf);
            return -1;
        }
        if ((size_t)ret < bytes_to_check) {
            pr_err("mkfs.mxfs: zero_region verify short read @%llu (%zd/%zu)\n",
                   (unsigned long long)(offset + verify_off),
                   ret, bytes_to_check);
            free(vbuf);
            return -1;
        }
        p = (const unsigned char *)vbuf;
        for (i = 0; i < bytes_to_check; i++) {
            if (p[i] != 0) {
                pr_err("mkfs.mxfs: zero_region verify FAIL @%llu byte %zu = "
                       "0x%02x (storage silently dropped writes — try "
                       "'blkdiscard --zeroout %s' first or use a different "
                       "backend)\n",
                       (unsigned long long)(offset + verify_off + i),
                       i, p[i], "/dev/<device>");
                rc = -1;
                goto out;
            }
        }
    }

    pr_verbose("  verified %llu bytes at %llu are zero\n",
               (unsigned long long)len,
               (unsigned long long)offset);

out:
    free(vbuf);
    return rc;
}

/* ─── Journal formatting ─── */

/*
 * Journal super — 512 bytes at journal_offset.
 * Matches struct mxfs_journal_super from journal.h.
 */
struct journal_super {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    slot_count;
    uint32_t    slot_size_sectors;
    uint32_t    sector_size;
    uint32_t    crc;
    uint8_t     fs_uuid[16];
    uint8_t     reserved[472];
};

/*
 * Per-slot header — 512 bytes at slot start.
 * Matches struct mxfs_journal_slot_hdr from journal.h.
 */
struct journal_slot_hdr {
    uint32_t    magic;
    uint32_t    flags;
    uint32_t    owner;
    uint32_t    head_sector;
    uint32_t    tail_sector;
    uint32_t    crc;
    uint64_t    seq_head;
    uint64_t    seq_tail;
    uint8_t     reserved[472];
};

static int format_journal(int fd, uint64_t journal_offset,
                           uint32_t max_nodes, const uint8_t *uuid)
{
    struct journal_super jsup;
    struct journal_slot_hdr shdr;
    uint64_t slot_offset;
    uint32_t i;

    pr_verbose("  Formatting journal at offset %llu (%u slots)\n",
               (unsigned long long)journal_offset, max_nodes);

    /* Write journal superblock */
    memset(&jsup, 0, sizeof(jsup));
    jsup.magic = MXFS_JOURNAL_MAGIC;
    jsup.version = MXFS_JOURNAL_VERSION;
    jsup.slot_count = max_nodes;
    jsup.slot_size_sectors = MXFS_JOURNAL_SLOT_SIZE_SECTORS;
    jsup.sector_size = MXFS_JOURNAL_SECTOR_SIZE;
    memcpy(jsup.fs_uuid, uuid, 16);

    /* CRC covers entire 512-byte sector with crc field zeroed */
    jsup.crc = 0;
    jsup.crc = crc32c(~0U, &jsup, sizeof(jsup));

    if (write_sectors(fd, journal_offset, &jsup, 512) < 0)
        return -1;

    /* Write slot headers — each slot is SLOT_SIZE_SECTORS * 512 bytes.
     * Slots start after the journal super sector. */
    for (i = 0; i < max_nodes; i++) {
        slot_offset = journal_offset + 512 +
                      (uint64_t)i * MXFS_JOURNAL_SLOT_SIZE_SECTORS *
                      MXFS_JOURNAL_SECTOR_SIZE;

        memset(&shdr, 0, sizeof(shdr));
        shdr.magic = MXFS_JOURNAL_MAGIC;
        shdr.flags = MXFS_JOURNAL_SLOT_FLAG_CLEAN;
        shdr.owner = 0;  /* unclaimed */
        shdr.head_sector = 1;  /* first usable sector in slot */
        shdr.tail_sector = 1;
        shdr.seq_head = 0;
        shdr.seq_tail = 0;

        shdr.crc = 0;
        shdr.crc = crc32c(~0U, &shdr, sizeof(shdr));

        if (write_sectors(fd, slot_offset, &shdr, 512) < 0)
            return -1;

        pr_verbose("    Slot %u at offset %llu\n", i,
                   (unsigned long long)slot_offset);
    }

    return 0;
}

/* ─── MXFS superblock ─── */

static int write_mxfs_super(int fd, uint64_t super_offset,
                             uint64_t device_size, uint64_t xfs_data_size,
                             uint64_t journal_offset, uint64_t journal_size,
                             uint64_t disklock_offset, uint64_t disklock_size,
                             uint64_t xfs_data_offset,
                             uint32_t max_nodes,
                             uint32_t log_node_count,
                             uint32_t log_slice_bblks,
                             const uint8_t *uuid)
{
    struct mxfs_ondisk_super sup;

    memset(&sup, 0, sizeof(sup));
    sup.magic = MXFS_FORMAT_MAGIC;
    sup.version = MXFS_FORMAT_VERSION;
    /* sess42 C7 version gate: every new format is protocol-gated — members
     * must run code speaking exactly cluster_proto_gen (see mxfs_super.h). */
    sup.flags = MXFS_FORMAT_F_PROTOGATE;
    sup.cluster_proto_gen = MXFS_PROTO_GEN;
    memcpy(sup.fs_uuid, uuid, 16);
    sup.device_size = device_size;
    sup.xfs_data_size = xfs_data_size;
    sup.journal_offset = journal_offset;
    sup.journal_size = journal_size;
    sup.disklock_offset = disklock_offset;
    sup.disklock_size = disklock_size;
    sup.max_nodes = max_nodes;
    sup.journal_slot_sectors = MXFS_JOURNAL_SLOT_SIZE_SECTORS;
    sup.xfs_data_offset = xfs_data_offset;
    sup.xfs_log_node_count = log_node_count;
    sup.xfs_log_slice_bblks = log_slice_bblks;

    /* CRC32C with crc field zeroed */
    sup.crc = 0;
    sup.crc = crc32c(~0U, &sup, sizeof(sup));

    pr_verbose("  Writing MXFS super at offset %llu (CRC=0x%08x)\n",
               (unsigned long long)super_offset, sup.crc);

    return write_sectors(fd, super_offset, &sup, MXFS_SUPER_SIZE);
}

/* ─── Native XFS formatting ─── */

/*
 * XFS geometry calculated from the data region size.
 */
struct xfs_geom {
    uint64_t dblocks;       /* total data blocks */
    uint32_t agcount;       /* number of allocation groups */
    uint32_t agblocks;      /* blocks per AG (except possibly last) */
    uint32_t last_agblocks; /* blocks in last AG */
    uint32_t agblklog;      /* ceil(log2(agblocks)) */
    uint32_t log_ag;        /* AG containing the log */
    uint32_t logblocks;     /* log size in blocks */
    uint64_t logstart;      /* log start in absolute FSB */
    uint64_t rootino;       /* root inode number */
    uint64_t rbmino;        /* realtime bitmap inode */
    uint64_t rsumino;       /* realtime summary inode */
    uint64_t fdblocks;      /* total free data blocks */
    uint8_t  uuid[16];      /* filesystem UUID */
};

/*
 * Calculate AG layout: free blocks, free extents, and AGFL block numbers.
 *
 * AG 0 has two free extents due to the inode chunk at block 16 (8-block aligned):
 *   gap: blocks 9-15 (between AGFL and inode chunk)
 *   main: blocks 24+ (after inode chunk)
 *
 * Other AGs have a single free extent starting after their last used block.
 */
static void calc_ag_layout(const struct xfs_geom *geom, uint32_t agno,
                           uint32_t *out_aglen, uint32_t *out_freeblks,
                           uint32_t *out_free_start, uint32_t *out_free_len,
                           uint32_t *out_free2_start, uint32_t *out_free2_len,
                           uint32_t agfl_blocks[4])
{
    uint32_t aglen;
    uint32_t log_in_ag = 0;

    /* AG length */
    if (agno == geom->agcount - 1)
        aglen = geom->last_agblocks;
    else
        aglen = geom->agblocks;

    *out_aglen = aglen;
    *out_free2_start = 0;
    *out_free2_len = 0;

    if (agno == 0) {
        /*
         * AG 0 layout:
         *   0:     SB+AGF+AGI+AGFL (1 block)
         *   1-4:   BNO, CNT, INO, FINO btree roots
         *   5-8:   AGFL blocks
         *   9-15:  free gap (7 blocks)
         *   16-23: inode chunk (8 blocks, aligned to INOALIGNMT=8)
         *   24+:   main free space
         */
        agfl_blocks[0] = 5;
        agfl_blocks[1] = 6;
        agfl_blocks[2] = 7;
        agfl_blocks[3] = 8;

        /* Two free extents */
        *out_free_start = 9;
        *out_free_len = 7;   /* blocks 9-15 */
        *out_free2_start = 24;
        *out_free2_len = aglen - 24;
        *out_freeblks = 7 + (aglen - 24);
    } else if (agno == geom->log_ag) {
        /* Log AG: log starts at block 5, AGFL blocks after log */
        log_in_ag = geom->logblocks;
        uint32_t after_log = 5 + log_in_ag;
        agfl_blocks[0] = after_log;
        agfl_blocks[1] = after_log + 1;
        agfl_blocks[2] = after_log + 2;
        agfl_blocks[3] = after_log + 3;

        uint32_t used = 5 + log_in_ag + 4;
        *out_free_start = used;
        *out_free_len = aglen - used;
        *out_freeblks = aglen - used;
    } else {
        /* Normal AG: AGFL blocks 5-8 */
        agfl_blocks[0] = 5;
        agfl_blocks[1] = 6;
        agfl_blocks[2] = 7;
        agfl_blocks[3] = 8;

        uint32_t used = 5 + 4;  /* 5 metadata + 4 AGFL */
        *out_free_start = used;
        *out_free_len = aglen - used;
        *out_freeblks = aglen - used;
    }
}

/*
 * Write the superblock sector (512 bytes) for one AG.
 */
static void write_sb_sector(uint8_t *sec, const struct xfs_geom *geom,
                            uint32_t agno)
{
    bool primary = (agno == 0);

    memset(sec, 0, 512);

    /* [0] magic */
    put_be32(sec + 0, XFS_SB_MAGIC);
    /* [4] blocksize */
    put_be32(sec + 4, XFS_BLOCKSIZE);
    /* [8] dblocks */
    put_be64(sec + 8, geom->dblocks);
    /* [16] rblocks = 0 */
    /* [24] rextents = 0 */
    /* [32] uuid */
    memcpy(sec + 32, geom->uuid, 16);
    /* [48] logstart */
    put_be64(sec + 48, geom->logstart);
    /* [56] rootino */
    put_be64(sec + 56, primary ? geom->rootino : NULLFSINO);
    /* [64] rbmino */
    put_be64(sec + 64, primary ? geom->rbmino : NULLFSINO);
    /* [72] rsumino */
    put_be64(sec + 72, primary ? geom->rsumino : NULLFSINO);
    /* [80] rextsize */
    put_be32(sec + 80, XFS_REXTSIZE);
    /* [84] agblocks */
    put_be32(sec + 84, geom->agblocks);
    /* [88] agcount */
    put_be32(sec + 88, geom->agcount);
    /* [92] rbmblocks = 0 */
    /* [96] logblocks */
    put_be32(sec + 96, geom->logblocks);
    /* [100] versionnum */
    put_be16(sec + 100, XFS_SB_VERSIONNUM);
    /* [102] sectsize */
    put_be16(sec + 102, XFS_SECTSIZE);
    /* [104] inodesize */
    put_be16(sec + 104, XFS_INODESIZE);
    /* [106] inopblock */
    put_be16(sec + 106, XFS_INOPBLOCK);
    /* [108] fname — 12 bytes, leave zero */
    /* [120] blocklog */
    sec[120] = XFS_BLOCKLOG;
    /* [121] sectlog */
    sec[121] = XFS_SECTLOG;
    /* [122] inodelog */
    sec[122] = XFS_INODELOG;
    /* [123] inopblog */
    sec[123] = XFS_INOPBLOG;
    /* [124] agblklog */
    sec[124] = (uint8_t)geom->agblklog;
    /* [125] rextslog = 0 */
    sec[125] = 0;
    /* [126] inprogress: 0 for primary, 1 for secondary */
    sec[126] = primary ? 0 : 1;
    /* [127] imax_pct */
    sec[127] = XFS_IMAX_PCT;
    /* [128] icount (8 bytes) */
    put_be64(sec + 128, primary ? 64 : 0);
    /* [136] ifree (8 bytes) */
    put_be64(sec + 136, primary ? 61 : 0);
    /* [144] fdblocks (8 bytes) */
    put_be64(sec + 144, geom->fdblocks);
    /* [152] frextents = 0 */
    /* [160] uquotino = NULLFSINO */
    put_be64(sec + 160, NULLFSINO);
    /* [168] gquotino = NULLFSINO */
    put_be64(sec + 168, NULLFSINO);
    /* [176] qflags = 0 */
    put_be16(sec + 176, 0);
    /* [178] flags = 0 */
    sec[178] = 0;
    /* [179] shared_vn = 0 */
    sec[179] = 0;
    /* [180] inoalignmt */
    put_be32(sec + 180, XFS_INOALIGNMT);
    /* [184] unit = 0 */
    put_be32(sec + 184, 0);
    /* [188] width = 0 */
    put_be32(sec + 188, 0);
    /* [192] dirblklog */
    sec[192] = XFS_DIRBLKLOG;
    /* [193] logsectlog = 0 */
    sec[193] = 0;
    /* [194] logsectsize = 0 */
    put_be16(sec + 194, 0);
    /* [196] logsunit = 1 */
    put_be32(sec + 196, 1);
    /* [200] features2 */
    put_be32(sec + 200, XFS_SB_FEATURES2);
    /* [204] bad_features2 */
    put_be32(sec + 204, XFS_SB_FEATURES2);
    /* [208] features_compat = 0 */
    put_be32(sec + 208, 0);
    /* [212] features_ro_compat = FINOBT */
    put_be32(sec + 212, XFS_SB_FEAT_RO_COMPAT_FINOBT);
    /* [216] features_incompat */
    put_be32(sec + 216, XFS_SB_FEAT_INCOMPAT);
    /* [220] features_log_incompat = 0 */
    put_be32(sec + 220, 0);
    /* [224] crc — computed below (native uint32_t) */
    /* [228] spino_align */
    put_be32(sec + 228, XFS_SPINO_ALIGN);
    /* [232] pquotino = NULLFSINO */
    put_be64(sec + 232, NULLFSINO);
    /* [240] lsn = 0 */
    put_be64(sec + 240, 0);
    /* [248] meta_uuid = all zeros */

    /* Compute CRC — native uint32_t at offset 224 */
    xfs_set_crc(sec, 512, 224);
}

/*
 * Write the AGF sector (512 bytes).
 */
static void write_agf_sector(uint8_t *sec, const struct xfs_geom *geom,
                             uint32_t agno, uint32_t aglen,
                             uint32_t freeblks, uint32_t longest)
{
    memset(sec, 0, 512);

    /* Layout verified against mkfs.xfs reference image:
     * roots[3] at 0x10, levels[3] at 0x1C — NO spare between them.
     */

    /* [0x00] magic */
    put_be32(sec + 0x00, XFS_AGF_MAGIC);
    /* [0x04] versionnum = 1 */
    put_be32(sec + 0x04, 1);
    /* [0x08] seqno */
    put_be32(sec + 0x08, agno);
    /* [0x0C] length */
    put_be32(sec + 0x0C, aglen);
    /* [0x10] roots[0] = bnoroot = 1 */
    put_be32(sec + 0x10, 1);
    /* [0x14] roots[1] = cntroot = 2 */
    put_be32(sec + 0x14, 2);
    /* [0x18] roots[2] = rmaproot = 0 (disabled) */
    put_be32(sec + 0x18, 0);
    /* [0x1C] levels[0] = bnolevel = 1 */
    put_be32(sec + 0x1C, 1);
    /* [0x20] levels[1] = cntlevel = 1 */
    put_be32(sec + 0x20, 1);
    /* [0x24] levels[2] = rmaplevel = 0 */
    put_be32(sec + 0x24, 0);
    /* [0x28] flfirst = 1 */
    put_be32(sec + 0x28, 1);
    /* [0x2C] fllast = 4 */
    put_be32(sec + 0x2C, 4);
    /* [0x30] flcount = 4 */
    put_be32(sec + 0x30, 4);
    /* [0x34] freeblks */
    put_be32(sec + 0x34, freeblks);
    /* [0x38] longest = longest contiguous free extent */
    put_be32(sec + 0x38, longest);
    /* [0x3C] btreeblks = 0 */
    put_be32(sec + 0x3C, 0);
    /* [0x40] uuid */
    memcpy(sec + 0x40, geom->uuid, 16);
    /* [0x50] rmap_blocks = 0 */
    /* [0x54] refcount_blocks = 0 */
    /* [0x58] refcount_root = 0 */
    /* [0x5C] refcount_level = 0 */
    /* [0x60-0xCF] spare64[14] = zeros */
    /* [0xD0] lsn = 0 */

    /* [0xD8] crc — native uint32_t */
    xfs_set_crc(sec, 512, 0xD8);
}

/*
 * Write the AGI sector (512 bytes).
 */
static void write_agi_sector(uint8_t *sec, const struct xfs_geom *geom,
                             uint32_t agno, uint32_t aglen)
{
    bool ag0 = (agno == 0);
    int i;

    memset(sec, 0, 512);

    /* [0x00] magic */
    put_be32(sec + 0x00, XFS_AGI_MAGIC);
    /* [0x04] versionnum = 1 */
    put_be32(sec + 0x04, 1);
    /* [0x08] seqno */
    put_be32(sec + 0x08, agno);
    /* [0x0C] length */
    put_be32(sec + 0x0C, aglen);
    /* [0x10] count */
    put_be32(sec + 0x10, ag0 ? 64 : 0);
    /* [0x14] root = 3 (inobt root block) */
    put_be32(sec + 0x14, 3);
    /* [0x18] level = 1 */
    put_be32(sec + 0x18, 1);
    /* [0x1C] freecount */
    put_be32(sec + 0x1C, ag0 ? 61 : 0);
    /* [0x20] newino = 128 (inode chunk at block 16, first agino = 16*8 = 128) */
    put_be32(sec + 0x20, ag0 ? 128 : 0xFFFFFFFF);
    /* [0x24] dirino = 0xFFFFFFFF */
    put_be32(sec + 0x24, 0xFFFFFFFF);
    /* [0x28] unlinked[64] = all 0xFFFFFFFF */
    for (i = 0; i < 64; i++)
        put_be32(sec + 0x28 + i * 4, 0xFFFFFFFF);
    /* [0x128] uuid */
    memcpy(sec + 0x128, geom->uuid, 16);

    /* [0x13C] pad32 = 0 */
    /* [0x140] lsn = 0 */

    /* [0x148] free_root = 4 (finobt root block, one after inobt at block 3) */
    put_be32(sec + 0x148, 4);
    /* [0x14C] free_level = 1 */
    put_be32(sec + 0x14C, 1);
    /* [0x150] ino_blocks = 0 */
    /* [0x154] fino_blocks = 0 */

    /* [0x138] crc — native uint32_t (must be computed after all fields are set) */
    xfs_set_crc(sec, 512, 0x138);
}

/*
 * Write the AGFL sector (512 bytes).
 */
static void write_agfl_sector(uint8_t *sec, const struct xfs_geom *geom,
                              uint32_t agno, const uint32_t agfl_blocks[4])
{
    int i;

    memset(sec, 0, 512);

    /* [0x00] magic */
    put_be32(sec + 0x00, XFS_AGFL_MAGIC);
    /* [0x04] seqno */
    put_be32(sec + 0x04, agno);
    /* [0x08] uuid */
    memcpy(sec + 0x08, geom->uuid, 16);
    /* [0x18] lsn = 0 */
    /* [0x20] crc — computed below */

    /* [0x24] bno[0] = 0xFFFFFFFF (unused, before flfirst) */
    put_be32(sec + 0x24, 0xFFFFFFFF);
    /* [0x28] bno[1] through bno[4] = AGFL blocks */
    put_be32(sec + 0x28, agfl_blocks[0]);
    put_be32(sec + 0x2C, agfl_blocks[1]);
    put_be32(sec + 0x30, agfl_blocks[2]);
    put_be32(sec + 0x34, agfl_blocks[3]);
    /* [0x38+] bno[5-118] = all 0xFFFFFFFF */
    for (i = 5; i < 119; i++)
        put_be32(sec + 0x24 + i * 4, 0xFFFFFFFF);

    /* [0x20] crc — native uint32_t */
    xfs_set_crc(sec, 512, 0x20);
}

/*
 * Write a V5 short-form btree block (4096 bytes).
 * magic: block magic number
 * agno: allocation group number
 * blkno_abs: absolute block number (for daddr calculation)
 * numrecs: number of records
 * rec_data: record data bytes
 * rec_len: total length of record data
 */
static void write_btree_block(uint8_t *blk, uint32_t magic,
                              uint32_t agno, uint64_t blkno_abs,
                              uint16_t numrecs,
                              const uint8_t *rec_data, size_t rec_len,
                              const uint8_t *uuid)
{
    memset(blk, 0, XFS_BLOCKSIZE);

    /* V5 short-form btree header (56 bytes) */
    /* [0x00] magic */
    put_be32(blk + 0x00, magic);
    /* [0x04] level = 0 (leaf) */
    put_be16(blk + 0x04, 0);
    /* [0x06] numrecs */
    put_be16(blk + 0x06, numrecs);
    /* [0x08] leftsib = 0xFFFFFFFF (null) */
    put_be32(blk + 0x08, 0xFFFFFFFF);
    /* [0x0C] rightsib = 0xFFFFFFFF (null) */
    put_be32(blk + 0x0C, 0xFFFFFFFF);
    /* [0x10] blkno = disk address in 512-byte sectors */
    put_be64(blk + 0x10, blkno_abs * 8);
    /* [0x18] lsn = 0 */
    /* [0x20] uuid */
    memcpy(blk + 0x20, uuid, 16);
    /* [0x30] owner = agno */
    put_be32(blk + 0x30, agno);

    /* [0x38] records start here */
    if (numrecs > 0 && rec_data && rec_len > 0)
        memcpy(blk + 0x38, rec_data, rec_len);

    /* [0x34] crc — native uint32_t */
    xfs_set_crc(blk, XFS_BLOCKSIZE, 0x34);
}

/*
 * Write a single inode (512 bytes) into a buffer.
 * For the root directory (ino 128): mode, nlink, inline dir data.
 * For rbmino/rsumino (129,130): allocated but empty.
 * For free inodes (131-191): unallocated.
 */
/*
 * Inode types for write_inode().
 */
#define INODE_ROOT      0   /* Root directory */
#define INODE_RBMINO    1   /* Realtime bitmap */
#define INODE_RSUMINO   2   /* Realtime summary */
#define INODE_FREE      3   /* Free/unallocated inode */

static void write_inode(uint8_t *buf, uint64_t ino, const uint8_t *uuid,
                        int itype, time_t now)
{
    memset(buf, 0, XFS_INODESIZE);

    /* [0x00] magic */
    put_be16(buf + 0x00, XFS_DINODE_MAGIC);
    /* [0x04] version = 3 (V3 inode, always for CRC-enabled XFS) */
    buf[0x04] = 3;

    if (itype == INODE_ROOT) {
        /* Root directory inode */
        /* [0x02] mode = 040755 = 0x41ED */
        put_be16(buf + 0x02, 0x41ED);
        /* [0x05] format = 1 (LOCAL) */
        buf[0x05] = 1;
        /* [0x10] nlink = 2 */
        put_be32(buf + 0x10, 2);
        /* [0x28] mtime */
        put_be32(buf + 0x28, (uint32_t)now);
        /* [0x30] ctime */
        put_be32(buf + 0x30, (uint32_t)now);
        /* [0x38] size = 6 (short-form dir header) */
        put_be64(buf + 0x38, 6);
        /* [0x53] aformat = 2 (EXTENTS) */
        buf[0x53] = 2;
    } else if (itype == INODE_RBMINO || itype == INODE_RSUMINO) {
        /* Realtime bitmap / summary inodes — allocated, regular file, EXTENTS format */
        /* [0x02] mode = 0100000 = 0x8000 (S_IFREG, no permissions) */
        put_be16(buf + 0x02, 0x8000);
        /* [0x05] format = 2 (EXTENTS) */
        buf[0x05] = 2;
        /* [0x10] nlink = 1 */
        put_be32(buf + 0x10, 1);
        /* [0x28] mtime */
        put_be32(buf + 0x28, (uint32_t)now);
        /* [0x30] ctime */
        put_be32(buf + 0x30, (uint32_t)now);
        /* [0x53] aformat = 2 (EXTENTS) */
        buf[0x53] = 2;
    } else {
        /* Free inode — minimal fields only */
        /* mode=0, format=0, everything else zero */
    }

    /* V3 extension (common to all inodes) */
    /* [0x60] next_unlinked = 0xFFFFFFFF */
    put_be32(buf + 0x60, 0xFFFFFFFF);

    if (itype != INODE_FREE) {
        /* [0x68] changecount = 2 */
        put_be64(buf + 0x68, 2);
        /* [0x90] crtime */
        put_be32(buf + 0x90, (uint32_t)now);
    }

    /* [0x98] ino = self */
    put_be64(buf + 0x98, ino);
    /* [0xA0] uuid */
    memcpy(buf + 0xA0, uuid, 16);

    /* Data fork at 0xB0 */
    if (itype == INODE_ROOT) {
        /* Short-form directory:
         * [0xB0] count = 0 (no entries besides . and ..)
         * [0xB1] i8count = 0 (4-byte parent inos)
         * [0xB2] parent = rootino (128) as big-endian 32-bit
         */
        buf[0xB0] = 0;
        buf[0xB1] = 0;
        put_be32(buf + 0xB2, 128);
    }
    /* RBMINO/RSUMINO with EXTENTS format and 0 extents: data fork is empty (all zeros) */

    /* Compute CRC at offset 0x64 */
    xfs_set_crc(buf, XFS_INODESIZE, 0x64);
}

/*
 * format_xfs_native — Write a minimal XFS v5 filesystem.
 *
 * fd: file descriptor open for writing (O_RDWR)
 * data_size: size of XFS data region in bytes (must be multiple of 4096)
 * base_offset: byte offset on device where XFS data starts
 * uuid: filesystem UUID (16 bytes, pre-generated)
 *
 * Returns 0 on success, -1 on error.
 */
static int format_xfs_native(int fd, uint64_t data_size, uint64_t base_offset,
                             const uint8_t *uuid, uint32_t *log_node_count_io,
                             uint32_t *logblocks_out)
{
    uint32_t log_node_count = *log_node_count_io;   /* 0 = auto-size */
    struct xfs_geom geom;
    uint8_t *block;     /* 4KB working buffer */
    uint8_t *ichunk;    /* 32KB inode chunk buffer */
    uint32_t agno;
    time_t now;
    int rc = -1;

    memset(&geom, 0, sizeof(geom));

    /* Use pre-generated UUID */
    memcpy(geom.uuid, uuid, 16);

    /* ─── Geometry calculation ─── */

    geom.dblocks = data_size / XFS_BLOCKSIZE;

    /*
     * D-LOG-SLICE-SHARED-MULTIWRITER (sess219): the internal log is carved
     * into log_node_count per-node slices, the slice index IS the heartbeat
     * slot (identity, no modulo), and the kernel refuses admission of any
     * slot >= log_node_count.  So the count formatted here is the cluster's
     * hard node limit for this filesystem, and every slice must be viable:
     *
     *  - each slice needs ~64MB (16384 fsb).  sess21: 32MB slices keep the
     *    log tail under constant pressure (rsync wedge); mkfs.xfs has
     *    enforced a 64MB minimum since xfsprogs 5.19.
     *  - XFS caps the whole internal log at 2GiB-10MiB (XFS_MAX_LOG_BYTES,
     *    xfs_fs.h) = 521728 fsb, so at most 32 slices fit; at count=32 each
     *    slice shaves to 16304 fsb (63.7MB) to stay under the cap.
     *  - the log must fit in ONE AG, so AG size is derived FROM the log
     *    requirement (fewer, larger AGs on small devices) — never the other
     *    way around.  If the device cannot host every slice, mkfs FAILS
     *    with the numbers; it never silently shrinks slices (the pre-sess219
     *    AG-fit clamp did, reintroducing the sess36 wedge).
     */
    {
        const uint32_t max_log_fsb = (uint32_t)
            (((2ULL << 30) - (10ULL << 20)) / XFS_BLOCKSIZE); /* 521728 */
        const uint32_t slice_want_fsb = 16384;                /* 64MB */
        uint32_t count = log_node_count;
        uint32_t slice_fsb;

        if (count == 0) {
            /* auto: largest power-of-two count <= 32 whose log stays
             * within 1/8 of the data region; tiny devices fall to a
             * single legacy-sized slice. */
            for (count = 32; count >= 2; count >>= 1) {
                slice_fsb = slice_want_fsb;
                if ((uint64_t)count * slice_fsb > max_log_fsb)
                    slice_fsb = max_log_fsb / count;
                if ((uint64_t)count * slice_fsb <= geom.dblocks / 8)
                    break;
            }
            if (count < 2)
                count = 1;
            log_node_count = count;
            *log_node_count_io = count;
        }

        if (count > 1) {
            slice_fsb = slice_want_fsb;
            if ((uint64_t)count * slice_fsb > max_log_fsb)
                slice_fsb = max_log_fsb / count;
            geom.logblocks = count * slice_fsb;
        } else {
            /* single slice: legacy sizing, dblocks/2048 in [1024, 65536] */
            geom.logblocks = (uint32_t)(geom.dblocks / 2048);
            if (geom.logblocks < 1024)
                geom.logblocks = 1024;
            if (geom.logblocks > 65536)
                geom.logblocks = 65536;
        }
    }

    /*
     * XFS convention: agblocks is the standard (maximum) AG size.
     * All AGs except the last have exactly agblocks blocks.
     * The last AG has <= agblocks blocks (the runt).
     * agcount = ceil(dblocks / agblocks).
     *
     * Target ~262144 blocks per AG (~1GB) — but the log AG must contain the
     * whole log (5 header blocks + log + 4 AGFL + 16 btree-root slack), so
     * on devices where a 1GB AG cannot, use fewer, larger AGs.
     */
    geom.agcount = (uint32_t)((geom.dblocks + 262143) / 262144);
    {
        uint64_t log_ag_need = (uint64_t)geom.logblocks + 5 + 4 + 16;
        uint64_t max_agcount = geom.dblocks / log_ag_need;

        if (max_agcount < 2) {
            pr_err("mkfs.mxfs: device too small for %u log slices: the log "
                   "needs %llu blocks (%llu MB) inside one AG and the device "
                   "has only %llu blocks (%llu MB) total; use -n with a "
                   "smaller slice count or a bigger device\n",
                   log_node_count,
                   (unsigned long long)log_ag_need,
                   (unsigned long long)(log_ag_need * XFS_BLOCKSIZE >> 20),
                   (unsigned long long)geom.dblocks,
                   (unsigned long long)(geom.dblocks * XFS_BLOCKSIZE >> 20));
            return -1;
        }
        if (geom.agcount > max_agcount)
            geom.agcount = (uint32_t)max_agcount;
    }
    if (geom.agcount < 2)
        geom.agcount = 2;

    /* agblocks = ceil(dblocks / agcount) — guarantees last AG <= agblocks */
    geom.agblocks = (uint32_t)((geom.dblocks + geom.agcount - 1) / geom.agcount);
    geom.last_agblocks = (uint32_t)(geom.dblocks - (uint64_t)(geom.agcount - 1) * geom.agblocks);

    /* Ensure last AG has at least 64 blocks */
    if (geom.last_agblocks < 64) {
        geom.agcount--;
        if (geom.agcount < 2)
            geom.agcount = 2;
        geom.agblocks = (uint32_t)((geom.dblocks + geom.agcount - 1) / geom.agcount);
        geom.last_agblocks = (uint32_t)(geom.dblocks - (uint64_t)(geom.agcount - 1) * geom.agblocks);
    }

    /*
     * sess389 (D-RSYNC-LAP-PACE-AG-SHARING-388, RULE-5 ruling): the kernel
     * gives every node the home AG (node_slot % agcount), so with fewer AGs
     * than nodes, slots >= agcount share a home AG pairwise and their dirops
     * ping-pong the AG EX grant.  Measured 25 AGs / 32 nodes: the 14 shared-AG
     * nodes were exactly the rsync_paired lap-2+ failures (34-60s+ vs 14-27s
     * exclusive); 64 AGs on the same rig: all 32 nodes 14-30s across 8 laps.
     * The log must fit one AG, so agcount is capped at dblocks/log_ag_need;
     * the lever is device size (or fewer slices).  Correctness does not depend
     * on this — say so loudly and compute the minimum size that fixes it.
     */
    if (log_node_count > 0 && geom.agcount < log_node_count) {
        uint64_t log_ag_need = (uint64_t)geom.logblocks + 5 + 4 + 16;
        uint64_t need_blocks = log_ag_need * (uint64_t)log_node_count;
        uint32_t shared = log_node_count - geom.agcount;

        pr_err("mkfs.mxfs: WARNING: agcount %u < node count %u — %u node slot(s) "
                "(>= %u) will SHARE a home AG with a lower slot and pace "
                "degrades under contention (correctness unaffected).  "
                "Sizing rule: agcount >= nodes (2x for the perf class).  "
                "The %u-slice log (%llu blocks) must fit one AG, so this needs "
                "a device of at least %llu blocks (%llu MB) for %u AGs "
                "(%llu MB for 2x); this device has %llu blocks (%llu MB).\n",
                geom.agcount, log_node_count, shared, geom.agcount,
                log_node_count, (unsigned long long)geom.logblocks,
                (unsigned long long)need_blocks,
                (unsigned long long)(need_blocks * XFS_BLOCKSIZE >> 20),
                log_node_count,
                (unsigned long long)(need_blocks * 2 * XFS_BLOCKSIZE >> 20),
                (unsigned long long)geom.dblocks,
                (unsigned long long)(geom.dblocks * XFS_BLOCKSIZE >> 20));
    }

    geom.agblklog = ceil_log2(geom.agblocks);

    /* Log placement: middle AG */
    geom.log_ag = geom.agcount / 2;

    /* Verify the log fits its AG (log starts at block 5 of the log AG,
     * after SB+AGF+AGI+AGFL, BNO, CNT, INO, FINO; +4 AGFL +16 slack).
     * With multiple slices this must never shrink — a shrunken slice is
     * the sess36 wedge — so a misfit is a hard error.  A single legacy
     * slice may still shrink to fit tiny devices. */
    {
        uint32_t log_ag_len = (geom.log_ag == geom.agcount - 1) ?
                               geom.last_agblocks : geom.agblocks;
        if (5 + geom.logblocks + 4 + 16 > log_ag_len) {
            if (log_node_count > 1) {
                pr_err("mkfs.mxfs: internal error: %u-slice log (%u blocks) "
                       "does not fit AG %u (%u blocks) — AG sizing should "
                       "have prevented this\n",
                       log_node_count, geom.logblocks, geom.log_ag,
                       log_ag_len);
                return -1;
            }
            geom.logblocks = log_ag_len - 5 - 4 - 16;
        }
    }

    /* Log start: block 5 of the log AG.
     * XFS encodes absolute FSBs as (agno << agblklog) | agbno — a packed
     * bitfield, NOT agno * agblocks + agbno.  The kernel's XFS_FSB_TO_AGNO
     * macro uses >> agblklog to extract the AG number. */
    geom.logstart = ((uint64_t)geom.log_ag << geom.agblklog) | 5;

    /* Inode numbers: inode chunk at block 16 (8-aligned), 8 inodes/block = startino 128 */
    geom.rootino = 128;
    geom.rbmino = 129;
    geom.rsumino = 130;

    /* Calculate fdblocks (sum of all AG freeblks).
     * AGFL blocks are reserved for btree allocation and are NOT counted
     * as free — they don't appear in AGF.freeblks or BNO btree records.
     * The mount path validates fdblocks == sum(AGF.freeblks). */
    geom.fdblocks = 0;
    for (agno = 0; agno < geom.agcount; agno++) {
        uint32_t aglen, freeblks, free_start, free_len, free2_start, free2_len;
        uint32_t agfl[4];
        calc_ag_layout(&geom, agno, &aglen, &freeblks,
                       &free_start, &free_len, &free2_start, &free2_len, agfl);
        geom.fdblocks += freeblks;
    }

    pr_verbose("  XFS geometry:\n");
    pr_verbose("    dblocks=%llu agcount=%u agblocks=%u last_agblocks=%u\n",
               (unsigned long long)geom.dblocks, geom.agcount,
               geom.agblocks, geom.last_agblocks);
    pr_verbose("    agblklog=%u log_ag=%u logblocks=%u logstart=%llu\n",
               geom.agblklog, geom.log_ag, geom.logblocks,
               (unsigned long long)geom.logstart);
    pr_verbose("    rootino=%llu fdblocks=%llu\n",
               (unsigned long long)geom.rootino,
               (unsigned long long)geom.fdblocks);

    pr_verbose("  XFS UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-"
               "%02x%02x-%02x%02x%02x%02x%02x%02x\n",
               geom.uuid[0], geom.uuid[1], geom.uuid[2], geom.uuid[3],
               geom.uuid[4], geom.uuid[5], geom.uuid[6], geom.uuid[7],
               geom.uuid[8], geom.uuid[9], geom.uuid[10], geom.uuid[11],
               geom.uuid[12], geom.uuid[13], geom.uuid[14], geom.uuid[15]);

    /* Allocate working buffers */
    block = calloc(1, XFS_BLOCKSIZE);
    ichunk = calloc(1, XFS_INODE_CHUNK_BLOCKS * XFS_BLOCKSIZE);
    if (!block || !ichunk) {
        pr_err("mkfs.mxfs: failed to allocate format buffers\n");
        goto out;
    }

    now = time(NULL);

    /* ─── Write per-AG structures ─── */

    for (agno = 0; agno < geom.agcount; agno++) {
        uint32_t aglen, freeblks, free_start, free_len, free2_start, free2_len;
        uint32_t agfl[4];
        uint64_t ag_byte_offset = base_offset + (uint64_t)agno * geom.agblocks * XFS_BLOCKSIZE;

        calc_ag_layout(&geom, agno, &aglen, &freeblks,
                       &free_start, &free_len, &free2_start, &free2_len, agfl);

        pr_verbose("  AG %u: aglen=%u freeblks=%u free=[%u+%u]",
                   agno, aglen, freeblks, free_start, free_len);
        if (free2_len > 0)
            pr_verbose(" [%u+%u]", free2_start, free2_len);
        pr_verbose("\n");

        /* ─── Block 0: SB + AGF + AGI + AGFL (4 sectors in one 4KB block) ─── */
        memset(block, 0, XFS_BLOCKSIZE);

        write_sb_sector(block + 0, &geom, agno);
        /* longest = the larger free extent; if two extents, free2_len is the bigger one */
        {
            uint32_t longest = free_len;
            if (free2_len > longest)
                longest = free2_len;
            write_agf_sector(block + 512, &geom, agno, aglen, freeblks, longest);
        }
        write_agi_sector(block + 1024, &geom, agno, aglen);
        write_agfl_sector(block + 1536, &geom, agno, agfl);

        if (write_sectors(fd, ag_byte_offset, block, XFS_BLOCKSIZE) < 0)
            goto out;

        /* ─── Block 1: BNO btree root ─── */
        if (free2_len > 0) {
            /* AG 0: two free extents (gap before inode chunk + main free space) */
            uint8_t rec2[16];

            /* BNO btree: records sorted by startblock */
            memset(rec2, 0, sizeof(rec2));
            put_be32(rec2 + 0, free_start);    /* extent 1: startblock */
            put_be32(rec2 + 4, free_len);      /* extent 1: blockcount */
            put_be32(rec2 + 8, free2_start);   /* extent 2: startblock */
            put_be32(rec2 + 12, free2_len);    /* extent 2: blockcount */

            write_btree_block(block, XFS_BNO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 1,
                              2, rec2, 16, geom.uuid);
        } else {
            /* Single free extent */
            uint8_t rec[8];
            memset(rec, 0, sizeof(rec));
            put_be32(rec + 0, free_start);     /* startblock */
            put_be32(rec + 4, free_len);       /* blockcount */

            write_btree_block(block, XFS_BNO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 1,
                              1, rec, 8, geom.uuid);
        }

        if (write_sectors(fd, ag_byte_offset + XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
            goto out;

        /* ─── Block 2: CNT btree root ─── */
        if (free2_len > 0) {
            /* AG 0: two free extents, CNT btree sorted by blockcount (ascending) */
            uint8_t rec2[16];
            memset(rec2, 0, sizeof(rec2));

            /* Smaller extent first (gap: 7 blocks), then larger (main free space) */
            put_be32(rec2 + 0, free_start);    /* extent 1: startblock (smaller) */
            put_be32(rec2 + 4, free_len);      /* extent 1: blockcount */
            put_be32(rec2 + 8, free2_start);   /* extent 2: startblock (larger) */
            put_be32(rec2 + 12, free2_len);    /* extent 2: blockcount */

            write_btree_block(block, XFS_CNT_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 2,
                              2, rec2, 16, geom.uuid);
        } else {
            /* Single free extent */
            uint8_t rec[8];
            memset(rec, 0, sizeof(rec));
            put_be32(rec + 0, free_start);     /* startblock */
            put_be32(rec + 4, free_len);       /* blockcount */

            write_btree_block(block, XFS_CNT_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 2,
                              1, rec, 8, geom.uuid);
        }

        if (write_sectors(fd, ag_byte_offset + 2 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
            goto out;

        /* ─── Block 3: INO btree root ─── */
        if (agno == 0) {
            /* AG 0: one inobt record for the inode chunk at block 16 */
            uint8_t ino_rec[16];
            memset(ino_rec, 0, sizeof(ino_rec));
            /* startino = 128 (block 16 * 8 inodes/block) */
            put_be32(ino_rec + 0, 128);
            /* holemask = 0 */
            put_be16(ino_rec + 4, 0);
            /* count = 64 */
            ino_rec[6] = 64;
            /* freecount = 61 */
            ino_rec[7] = 61;
            /* free bitmap: 0xFFFFFFFFFFFFFFF8 (inodes 0-2 allocated, 3-63 free) */
            put_be64(ino_rec + 8, 0xFFFFFFFFFFFFFFF8ULL);

            write_btree_block(block, XFS_INO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 3,
                              1, ino_rec, 16, geom.uuid);
        } else {
            /* Other AGs: empty inobt */
            write_btree_block(block, XFS_INO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 3,
                              0, NULL, 0, geom.uuid);
        }

        if (write_sectors(fd, ag_byte_offset + 3 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
            goto out;

        /* ─── Block 4: FINO btree root (free inode btree) ─── */
        if (agno == 0) {
            /* AG 0: finobt has same record as inobt (the chunk has 61 free inodes) */
            uint8_t fino_rec[16];
            memset(fino_rec, 0, sizeof(fino_rec));
            /* startino = 128 (block 16 * 8 inodes/block) */
            put_be32(fino_rec + 0, 128);
            /* holemask = 0 */
            put_be16(fino_rec + 4, 0);
            /* count = 64 */
            fino_rec[6] = 64;
            /* freecount = 61 */
            fino_rec[7] = 61;
            /* free bitmap: 0xFFFFFFFFFFFFFFF8 (inodes 0-2 allocated, 3-63 free) */
            put_be64(fino_rec + 8, 0xFFFFFFFFFFFFFFF8ULL);

            write_btree_block(block, XFS_FINO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 4,
                              1, fino_rec, 16, geom.uuid);
        } else {
            /* Other AGs: empty finobt (no inode chunks, so no free inodes) */
            write_btree_block(block, XFS_FINO_MAGIC, agno,
                              (uint64_t)agno * geom.agblocks + 4,
                              0, NULL, 0, geom.uuid);
        }

        if (write_sectors(fd, ag_byte_offset + 4 * XFS_BLOCKSIZE, block, XFS_BLOCKSIZE) < 0)
            goto out;

        /* ─── Inode chunk (AG 0, blocks 16-23) ─── */
        if (agno == 0) {
            int i;
            memset(ichunk, 0, XFS_INODE_CHUNK_BLOCKS * XFS_BLOCKSIZE);

            /* Inode 0 (ino 128): root directory */
            write_inode(ichunk + 0 * XFS_INODESIZE, 128, geom.uuid, INODE_ROOT, now);

            /* Inode 1 (ino 129): rbmino — allocated, empty extents */
            write_inode(ichunk + 1 * XFS_INODESIZE, 129, geom.uuid, INODE_RBMINO, now);

            /* Inode 2 (ino 130): rsumino — allocated, empty extents */
            write_inode(ichunk + 2 * XFS_INODESIZE, 130, geom.uuid, INODE_RSUMINO, now);

            /* Inodes 3-63 (ino 131-191): free inodes */
            for (i = 3; i < XFS_INODES_PER_CHUNK; i++)
                write_inode(ichunk + i * XFS_INODESIZE,
                            128 + (uint64_t)i, geom.uuid, INODE_FREE, now);

            if (write_sectors(fd, ag_byte_offset + 16 * XFS_BLOCKSIZE,
                              ichunk, XFS_INODE_CHUNK_BLOCKS * XFS_BLOCKSIZE) < 0)
                goto out;
        }
    }

    /* ─── Zero the log area ─── */
    /* geom.logstart is a packed FSB (agno << agblklog | agbno) for the SB.
     * Physical byte offset uses the linear formula: (agno * agblocks + agbno) * blocksize.
     * These differ when agblocks != 2^agblklog. */
    {
        uint64_t log_phys_byte = base_offset +
            ((uint64_t)geom.log_ag * geom.agblocks + 5) * XFS_BLOCKSIZE;

        pr_verbose("  Zeroing log: %u blocks at AG %u block 5 (byte offset %llu)\n",
                   geom.logblocks, geom.log_ag,
                   (unsigned long long)log_phys_byte);

        if (zero_region(fd, log_phys_byte,
                        (uint64_t)geom.logblocks * XFS_BLOCKSIZE) < 0)
            goto out;
    }

    if (logblocks_out)
        *logblocks_out = geom.logblocks;
    rc = 0;
    pr_verbose("  XFS format complete\n");

out:
    free(block);
    free(ichunk);
    return rc;
}

/* ─── Usage ─── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-f] [-n count] [-d size] [-v] [-V] DEVICE\n"
            "\n"
            "Format a block device for MXFS (Multinode XFS).\n"
            "\n"
            "  -f          Force — skip confirmation prompt\n"
            "  -n COUNT    Per-node XFS log slices = max cluster nodes for\n"
            "              this FS (1-32; default: auto-sized from device)\n"
            "  -d SIZE     Cap the XFS data area at SIZE bytes (K/M/G/T suffix;\n"
            "              default: the whole device).  Like mkfs.xfs -d size=;\n"
            "              used to reproduce a smaller-device geometry (agcount)\n"
            "              on a larger LUN.\n"
            "  -v          Verbose output\n"
            "  -V          Print version and exit\n"
            "\n"
            "Creates: [super 4KB] [journal 64MB] [disklock 32MB] [XFS data to end]\n",
            prog);
}

/* ─── Main ─── */

int main(int argc, char *argv[])
{
    const char *device = NULL;
    bool force = false;
    int opt, fd;
    uint64_t device_size;
    uint64_t disklock_offset, journal_offset, xfs_data_offset;
    uint64_t journal_size, disklock_size, xfs_data_size;
    uint32_t max_nodes = MXFS_MAX_NODES;
    uint32_t log_node_count = 0;    /* 0 = auto-size from the device;
                                     * D-LOG-SLICE-SHARED-MULTIWRITER: the
                                     * old fixed default of 4 silently gave
                                     * a 32-node cluster 8 writers per log
                                     * slice */
    uint8_t uuid[16];
    char hbuf[64], hbuf2[64];
    struct stat st;
    uint64_t data_cap = 0;              /* -d: XFS data-area cap, 0 = whole device */

    while ((opt = getopt(argc, argv, "fn:d:vV")) != -1) {
        switch (opt) {
        case 'f':
            force = true;
            break;
        case 'd': {
            /* sess389: data-area cap (geometry reproduction).  Accepts a
             * plain byte count or K/M/G/T suffix. */
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);

            if (end == optarg || v == 0) {
                pr_err("mkfs.mxfs: -d SIZE must be a positive number "
                       "(optional K/M/G/T suffix)\n");
                return 1;
            }
            switch (*end) {
            case 'k': case 'K': v <<= 10; end++; break;
            case 'm': case 'M': v <<= 20; end++; break;
            case 'g': case 'G': v <<= 30; end++; break;
            case 't': case 'T': v <<= 40; end++; break;
            default: break;
            }
            if (*end != '\0') {
                pr_err("mkfs.mxfs: -d: bad size suffix '%s'\n", end);
                return 1;
            }
            data_cap = (uint64_t)v;
            break;
        }
        case 'n':
            log_node_count = (uint32_t)atoi(optarg);
            if (log_node_count < 1 || log_node_count > 32) {
                pr_err("mkfs.mxfs: -n must be 1-32 (XFS caps the internal "
                       "log at 2GiB-10MiB, so at most 32 ~64MB per-node "
                       "slices fit; the slice count is the cluster's hard "
                       "node limit for this filesystem)\n");
                return 1;
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'V':
            printf("mkfs.mxfs version %s\n", MKFS_MXFS_VERSION);
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

    /* Validate device exists and is a block device */
    if (stat(device, &st) < 0) {
        pr_err("mkfs.mxfs: %s: %s\n", device, strerror(errno));
        return 1;
    }
    if (!S_ISBLK(st.st_mode)) {
        pr_err("mkfs.mxfs: %s: not a block device\n", device);
        return 1;
    }

    /* Get device size */
    fd = open(device, O_RDWR | O_EXCL);
    if (fd < 0) {
        if (errno == EBUSY)
            pr_err("mkfs.mxfs: %s: device is busy (mounted?)\n", device);
        else
            pr_err("mkfs.mxfs: %s: %s\n", device, strerror(errno));
        return 1;
    }

    if (ioctl(fd, BLKGETSIZE64, &device_size) < 0) {
        pr_err("mkfs.mxfs: %s: cannot get device size: %s\n",
               device, strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);

    if (device_size < MXFS_MIN_DEVICE_SIZE) {
        pr_err("mkfs.mxfs: %s: device too small (%s, minimum %s)\n",
               device,
               human_size(device_size, hbuf, sizeof(hbuf)),
               human_size(MXFS_MIN_DEVICE_SIZE, hbuf2, sizeof(hbuf2)));
        return 1;
    }

    /* ─── Calculate offsets ─── */

    /* Journal: super sector + max_nodes slots */
    journal_size = MXFS_JOURNAL_SECTOR_SIZE +
                   (uint64_t)max_nodes * MXFS_JOURNAL_SLOT_SIZE_SECTORS *
                   MXFS_JOURNAL_SECTOR_SIZE;

    disklock_size = MXFS_DISKLOCK_REGION_SIZE;

    /* New layout: [MXFS super 4KB] [journal] [disklock] [XFS data to end] */
    journal_offset = MXFS_SUPER_SIZE;
    disklock_offset = ALIGN_UP_4K(journal_offset + journal_size);
    xfs_data_offset = ALIGN_UP_4K(disklock_offset + disklock_size);
    xfs_data_size = device_size - xfs_data_offset;
    if (data_cap) {
        if (data_cap > xfs_data_size) {
            pr_err("mkfs.mxfs: -d %s exceeds the device's XFS data area (%s)\n",
                   human_size(data_cap, hbuf, sizeof(hbuf)),
                   human_size(xfs_data_size, hbuf2, sizeof(hbuf2)));
            return 1;
        }
        pr_info("  -d: capping XFS data area at %s (device has %s)\n",
                human_size(data_cap, hbuf, sizeof(hbuf)),
                human_size(xfs_data_size, hbuf2, sizeof(hbuf2)));
        xfs_data_size = data_cap;
    }

    if (xfs_data_size < 16 * 1024 * 1024) {
        pr_err("mkfs.mxfs: %s: device too small for XFS data "
               "(only %s available)\n",
               device, human_size(xfs_data_size, hbuf, sizeof(hbuf)));
        return 1;
    }

    /* ─── Print layout ─── */

    pr_info("\nmkfs.mxfs %s\n\n", MKFS_MXFS_VERSION);
    pr_info("  Device:     %s (%s)\n",
            device, human_size(device_size, hbuf, sizeof(hbuf)));
    pr_info("  MXFS super: 0 - %llu (4 KB)\n",
            (unsigned long long)(MXFS_SUPER_SIZE - 1));
    pr_info("  Journal:    %llu - %llu (%s, %u slots)\n",
            (unsigned long long)journal_offset,
            (unsigned long long)(disklock_offset - 1),
            human_size(journal_size, hbuf, sizeof(hbuf)),
            max_nodes);
    pr_info("  Disklock:   %llu - %llu (%s)\n",
            (unsigned long long)disklock_offset,
            (unsigned long long)(xfs_data_offset - 1),
            human_size(disklock_size, hbuf, sizeof(hbuf)));
    pr_info("  XFS data:   %llu - %llu (%s)\n",
            (unsigned long long)xfs_data_offset,
            (unsigned long long)(device_size - 1),
            human_size(xfs_data_size, hbuf, sizeof(hbuf)));
    pr_info("\n");

    /* ─── Confirm ─── */

    if (!force) {
        char answer[16];
        fprintf(stdout, "Format %s? All data will be destroyed. [y/N] ", device);
        fflush(stdout);
        if (!fgets(answer, sizeof(answer), stdin) ||
            (answer[0] != 'y' && answer[0] != 'Y')) {
            pr_info("Aborted.\n");
            return 1;
        }
    }

    /* ─── Step 1: Open device for formatting ─── */

    fd = open(device, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        /* Fallback without O_DIRECT */
        fd = open(device, O_RDWR | O_SYNC);
        if (fd < 0) {
            pr_err("mkfs.mxfs: cannot open %s: %s\n",
                   device, strerror(errno));
            return 1;
        }
    }

    /* Generate filesystem UUID upfront (used by journal, XFS, and MXFS super) */
    if (gen_uuid(uuid) < 0) {
        close(fd);
        return 1;
    }

    /* ─── Step 2: Format journal region ─── */

    pr_info("Formatting journal...\n");
    if (format_journal(fd, journal_offset, max_nodes, uuid) < 0) {
        close(fd);
        return 1;
    }

    /* ─── Step 3: Zero disklock region ─── */

    pr_info("Zeroing disklock region...\n");
    pr_verbose("  Zeroing %llu bytes at offset %llu\n",
               (unsigned long long)disklock_size,
               (unsigned long long)disklock_offset);

    if (zero_region(fd, disklock_offset, disklock_size) < 0) {
        close(fd);
        return 1;
    }

    /* ─── Step 3b: Zero the transport self-test scratch sector ───
     *
     * The 4K-alignment gap between the end of the journal region and
     * disklock_offset is dead space no reader ever touches (journal_size is
     * always ≡ 4608 mod 4096, so the gap is always 3584 bytes).  Its LAST
     * sector (disklock_offset - 512) is reserved as a scratch LBA for raw
     * SG_IO transport verification (tests/caw/dlm_lock_correctness.sh:
     * fua_verify / caw_verify), so capability probes never have to write
     * into the journal, disklock, or XFS regions of a live device.  Zero it
     * so the reservation starts defined rather than as stale disk garbage.
     */
    if (disklock_offset - (journal_offset + journal_size) >= 512) {
        static const uint8_t zsec[512];
        pr_verbose("  Scratch sector (transport self-test) at offset %llu\n",
                   (unsigned long long)(disklock_offset - 512));
        if (write_sectors(fd, disklock_offset - 512, zsec, 512) < 0) {
            close(fd);
            return 1;
        }
    }

    /* ─── Step 4: Format XFS natively ─── */

    pr_info("Formatting XFS (%s at offset %llu)...\n",
            human_size(xfs_data_size, hbuf, sizeof(hbuf)),
            (unsigned long long)xfs_data_offset);

    uint32_t xfs_logblocks = 0;

    if (format_xfs_native(fd, xfs_data_size, xfs_data_offset, uuid,
                           &log_node_count, &xfs_logblocks) < 0) {
        pr_err("mkfs.mxfs: XFS format failed\n");
        close(fd);
        return 1;
    }

    /* ─── Step 5: Write MXFS superblock at offset 0 ─── */

    pr_info("Writing MXFS superblock...\n");
    {
        /* blocks → basic blocks (512B): multiply by blocksize/512 */
        uint32_t slice_blocks = xfs_logblocks / log_node_count;
        uint32_t log_slice_bblks = slice_blocks * (XFS_BLOCKSIZE / 512);

        pr_info("  XFS log: %u per-node slices (%u blocks = %s each)\n",
                log_node_count, slice_blocks,
                human_size((uint64_t)slice_blocks * XFS_BLOCKSIZE,
                           hbuf, sizeof(hbuf)));

    if (write_mxfs_super(fd, 0, device_size, xfs_data_size,
                          journal_offset, journal_size,
                          disklock_offset, disklock_size,
                          xfs_data_offset,
                          max_nodes,
                          log_node_count, log_slice_bblks,
                          uuid) < 0) {
        close(fd);
        return 1;
    }
    } /* end log_slice_bblks scope */

    /* Sync everything */
    if (fsync(fd) < 0)
        pr_err("mkfs.mxfs: warning: fsync failed: %s\n", strerror(errno));

    close(fd);

    pr_info("\n%s formatted successfully (%s usable)\n\n",
            device, human_size(xfs_data_size, hbuf, sizeof(hbuf)));

    return 0;
}
