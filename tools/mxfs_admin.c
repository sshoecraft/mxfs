/*
 * MXFS — Multinode XFS
 * mxfs_admin: show and change MXFS filesystem parameters offline
 *
 * The MXFS counterpart of xfs_admin.  xfs_admin is a script that hands each
 * option to xfs_db / xfs_repair; those read the wrong sectors on an MXFS
 * device (the XFS superblock sits behind the MXFS envelope), so this is a
 * standalone program that reads and writes the structures itself, in the
 * same style as mkfs_mxfs and chk_mxfs.
 *
 *   -l            print the label
 *   -L LABEL      set the label (at most 12 bytes; "--" clears it)
 *   -u            print the UUID
 *   -c NAME       set the cluster name (mount then needs -o cluster=NAME);
 *                 -c "" clears it
 *   -O dirshard   make directory sharding available (docs/dir-sharding.md)
 *   -i            print every MXFS setting
 *
 * The print options only read, and work on a mounted filesystem.  Every
 * change first proves that no node can write the device
 * (tools/mxfs_offline.h: O_EXCL, a quiet heartbeat table across a recheck,
 * no SCSI-PR registrant) and refuses otherwise.
 *
 * Label writes follow xfs_db's label command (xfsprogs db/sb.c): the label
 * lives in every allocation group's superblock, so every one is rewritten
 * and its CRC recomputed, not just the primary.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>

#include <mxfs/mxfs_super.h>
#include <mxfs/mxfs_dirshard.h>
#include <mxfs/mxfs_common.h>
#include "mxfs_offline.h"

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define MXFS_ADMIN_VERSION STRINGIFY(MXFS_VERSION_MAJOR) "." \
                           STRINGIFY(MXFS_VERSION_MINOR) "." \
                           STRINGIFY(MXFS_VERSION_PATCH)

/* XFS superblock (xfs_dsb), big-endian except the CRC */
#define MXFS_SB_MAGIC            0x4D585342  /* "MXSB" */
#define XFS_SB_OFF_BLOCKSIZE    4
#define XFS_SB_OFF_UUID         32
#define XFS_SB_OFF_AGBLOCKS     84
#define XFS_SB_OFF_AGCOUNT      88
#define XFS_SB_OFF_SECTSIZE     102
#define XFS_SB_OFF_FNAME        108
#define XFS_SB_FNAME_LEN        12
#define XFS_SB_OFF_INCOMPAT     216
#define XFS_SB_OFF_CRC          224

/* ─── CRC32C (Castagnoli), as mkfs_mxfs and the kernel compute it ─── */

static uint32_t crc32c_table[256];
static bool crc32c_initialized;

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t i;

    if (!crc32c_initialized) {
        uint32_t n, j, c;

        for (n = 0; n < 256; n++) {
            c = n;
            for (j = 0; j < 8; j++)
                c = (c & 1) ? (c >> 1) ^ 0x82F63B78 : c >> 1;
            crc32c_table[n] = c;
        }
        crc32c_initialized = true;
    }
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ p[i]) & 0xFF];
    return crc;
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* XFS keeps the CRC in CPU order, seed ~0, complemented. */
static void xfs_set_crc(uint8_t *buf, size_t len)
{
    uint32_t *field = (uint32_t *)(buf + XFS_SB_OFF_CRC);

    *field = 0;
    *field = ~crc32c(~0U, buf, len);
}

static bool xfs_crc_ok(uint8_t *buf, size_t len)
{
    uint32_t *field = (uint32_t *)(buf + XFS_SB_OFF_CRC);
    uint32_t stored = *field, want;

    *field = 0;
    want = ~crc32c(~0U, buf, len);
    *field = stored;
    return stored == want;
}

/* ─── the device ─── */

struct admin_dev {
    const char *path;
    int fd;                         /* O_RDONLY, or O_RDWR|O_EXCL to change */
    struct mxfs_ondisk_super sup;
    uint8_t sb[512];                /* the primary XFS superblock sector */
    uint32_t blocksize, agblocks, agcount, sectsize;
};

static int read_full(int fd, void *buf, size_t len, uint64_t off)
{
    ssize_t n = pread(fd, buf, len, (off_t)off);

    return n == (ssize_t)len ? 0 : -1;
}

static int write_full(int fd, const void *buf, size_t len, uint64_t off)
{
    ssize_t n = pwrite(fd, buf, len, (off_t)off);

    return n == (ssize_t)len ? 0 : -1;
}

static uint64_t ag_sb_offset(const struct admin_dev *d, uint32_t agno)
{
    return d->sup.xfs_data_offset +
           (uint64_t)agno * d->agblocks * d->blocksize;
}

static int dev_open(struct admin_dev *d, const char *path, bool change)
{
    uint32_t stored, want;

    memset(d, 0, sizeof(*d));
    d->path = path;
    d->fd = open(path, change ? (O_RDWR | O_EXCL) : O_RDONLY);
    if (d->fd < 0) {
        fprintf(stderr, "mxfs_admin: cannot open %s%s: %s%s\n", path,
                change ? " exclusively" : "", strerror(errno),
                change && errno == EBUSY ? " (is it mounted here?)" : "");
        return -1;
    }
    if (read_full(d->fd, &d->sup, sizeof(d->sup), 0) < 0 ||
        d->sup.magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "mxfs_admin: %s carries no MXFS envelope\n", path);
        return -1;
    }
    stored = d->sup.crc;
    d->sup.crc = 0;
    want = crc32c(~0U, &d->sup, sizeof(d->sup));
    d->sup.crc = stored;
    if (stored != want) {
        fprintf(stderr, "mxfs_admin: the MXFS envelope CRC does not match "
                "(stored 0x%08X, computed 0x%08X); run chk_mxfs\n",
                stored, want);
        return -1;
    }
    if (d->sup.flags & ~MXFS_FORMAT_F_KNOWN) {
        fprintf(stderr, "mxfs_admin: the envelope carries flags 0x%x this "
                "tool does not know; it is older than the format\n",
                d->sup.flags & ~MXFS_FORMAT_F_KNOWN);
        return -1;
    }
    if (read_full(d->fd, d->sb, sizeof(d->sb), d->sup.xfs_data_offset) < 0 ||
        get_be32(d->sb) != MXFS_SB_MAGIC) {
        fprintf(stderr, "mxfs_admin: no XFS superblock at the envelope's data "
                "offset %llu\n", (unsigned long long)d->sup.xfs_data_offset);
        return -1;
    }
    d->blocksize = get_be32(d->sb + XFS_SB_OFF_BLOCKSIZE);
    d->agblocks = get_be32(d->sb + XFS_SB_OFF_AGBLOCKS);
    d->agcount = get_be32(d->sb + XFS_SB_OFF_AGCOUNT);
    d->sectsize = get_be16(d->sb + XFS_SB_OFF_SECTSIZE);
    if (d->sectsize != 512 || !d->blocksize || !d->agblocks || !d->agcount) {
        fprintf(stderr, "mxfs_admin: unexpected XFS geometry (sectsize %u "
                "blocksize %u agblocks %u agcount %u)\n", d->sectsize,
                d->blocksize, d->agblocks, d->agcount);
        return -1;
    }
    if (!xfs_crc_ok(d->sb, sizeof(d->sb))) {
        fprintf(stderr, "mxfs_admin: the primary XFS superblock CRC does not "
                "match; run chk_mxfs\n");
        return -1;
    }
    return 0;
}

/* The exclusion proof, run once before the first change. */
static int dev_prove_offline(struct admin_dev *d)
{
    int dfd, rc;

    dfd = open(d->path, O_RDONLY | O_DIRECT);
    if (dfd < 0) {
        fprintf(stderr, "mxfs_admin: cannot open %s O_DIRECT: %s\n",
                d->path, strerror(errno));
        return -1;
    }
    printf("proving no node can write %s:\n", d->path);
    rc = mxfs_off_prove_no_writer(d->fd, dfd, d->sup.disklock_offset);
    close(dfd);
    if (rc < 0)
        fprintf(stderr, "mxfs_admin: refusing to change %s\n", d->path);
    return rc;
}

static int envelope_write(struct admin_dev *d)
{
    d->sup.crc = 0;
    d->sup.crc = crc32c(~0U, &d->sup, sizeof(d->sup));
    if (write_full(d->fd, &d->sup, sizeof(d->sup), 0) < 0 || fsync(d->fd)) {
        fprintf(stderr, "mxfs_admin: writing the MXFS envelope failed: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Apply @edit to every allocation group's superblock and rewrite it with its
 * CRC recomputed.  Each secondary is verified before it is touched: one that
 * does not validate is reported and left alone, since rewriting it would
 * stamp a good CRC over bad contents.
 */
static int for_each_sb(struct admin_dev *d,
                       void (*edit)(uint8_t *sec, const void *arg),
                       const void *arg)
{
    uint8_t sec[512];
    uint32_t agno, bad = 0;

    for (agno = 0; agno < d->agcount; agno++) {
        uint64_t off = ag_sb_offset(d, agno);

        if (read_full(d->fd, sec, sizeof(sec), off) < 0 ||
            get_be32(sec) != MXFS_SB_MAGIC || !xfs_crc_ok(sec, sizeof(sec))) {
            fprintf(stderr, "mxfs_admin: AG %u superblock does not validate; "
                    "left unchanged (run chk_mxfs)\n", agno);
            bad++;
            continue;
        }
        edit(sec, arg);
        xfs_set_crc(sec, sizeof(sec));
        if (write_full(d->fd, sec, sizeof(sec), off) < 0) {
            fprintf(stderr, "mxfs_admin: writing AG %u superblock failed: "
                    "%s\n", agno, strerror(errno));
            return -1;
        }
        if (agno == 0)
            memcpy(d->sb, sec, sizeof(sec));
    }
    if (fsync(d->fd)) {
        fprintf(stderr, "mxfs_admin: fsync failed: %s\n", strerror(errno));
        return -1;
    }
    return bad ? -1 : 0;
}

/* ─── the options ─── */

static void print_label(const struct admin_dev *d)
{
    char label[XFS_SB_FNAME_LEN + 1];

    memcpy(label, d->sb + XFS_SB_OFF_FNAME, XFS_SB_FNAME_LEN);
    label[XFS_SB_FNAME_LEN] = '\0';
    printf("label = \"%s\"\n", label);
}

static void print_uuid(const struct admin_dev *d)
{
    const uint8_t *u = d->sb + XFS_SB_OFF_UUID;

    printf("UUID = %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
           "%02x%02x%02x%02x%02x%02x\n",
           u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
           u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void cluster_name_of(const struct admin_dev *d, char *out)
{
    if (d->sup.flags & MXFS_FORMAT_F_CLUSTER_NAME) {
        memcpy(out, d->sup.cluster_name, MXFS_CLUSTER_NAME_LEN);
        out[MXFS_CLUSTER_NAME_LEN - 1] = '\0';
    } else {
        strcpy(out, "(none)");
    }
}

static void print_info(const struct admin_dev *d)
{
    char name[MXFS_CLUSTER_NAME_LEN];
    uint32_t incompat = get_be32(d->sb + XFS_SB_OFF_INCOMPAT);

    cluster_name_of(d, name);
    printf("device             %s\n", d->path);
    print_label(d);
    print_uuid(d);
    printf("cluster name       %s\n", name);
    printf("envelope version   %u\n", d->sup.version);
    printf("protocol gen       %u\n", d->sup.cluster_proto_gen);
    printf("envelope flags     0x%08x\n", d->sup.flags);
    printf("node limit         %u (per-node log slices)\n",
           d->sup.xfs_log_node_count);
    printf("max nodes          %u (at format time)\n", d->sup.max_nodes);
    printf("device size        %llu bytes\n",
           (unsigned long long)d->sup.device_size);
    printf("XFS data           %llu bytes at offset %llu\n",
           (unsigned long long)d->sup.xfs_data_size,
           (unsigned long long)d->sup.xfs_data_offset);
    printf("XFS geometry       blocksize %u, %u AGs of %u blocks\n",
           d->blocksize, d->agcount, d->agblocks);
    printf("directory sharding %s\n",
           (d->sup.flags & MXFS_FORMAT_F_DIRSHARD) &&
           (incompat & MXFS_DIRSHARD_SB_INCOMPAT) ? "available" :
           !(d->sup.flags & MXFS_FORMAT_F_DIRSHARD) &&
           !(incompat & MXFS_DIRSHARD_SB_INCOMPAT) ? "off" :
           "GATES DISAGREE (run chk_mxfs)");
}

static void edit_label(uint8_t *sec, const void *arg)
{
    memset(sec + XFS_SB_OFF_FNAME, 0, XFS_SB_FNAME_LEN);
    memcpy(sec + XFS_SB_OFF_FNAME, arg, strlen(arg));
}

static void edit_dirshard_on(uint8_t *sec, const void *arg)
{
    (void)arg;
    put_be32(sec + XFS_SB_OFF_INCOMPAT,
             get_be32(sec + XFS_SB_OFF_INCOMPAT) | MXFS_DIRSHARD_SB_INCOMPAT);
}

static int set_label(struct admin_dev *d, const char *label)
{
    char val[XFS_SB_FNAME_LEN + 1];

    /* xfs_db's spelling of an empty label */
    if (!strcmp(label, "--") || !strcmp(label, "\"\"") || !strcmp(label, "''"))
        label = "";
    if (strlen(label) > XFS_SB_FNAME_LEN) {
        fprintf(stderr, "mxfs_admin: a label is at most %d bytes\n",
                XFS_SB_FNAME_LEN);
        return -1;
    }
    snprintf(val, sizeof(val), "%s", label);
    if (for_each_sb(d, edit_label, val) < 0)
        return -1;
    printf("writing all %u superblocks\nnew label = \"%s\"\n", d->agcount, val);
    return 0;
}

static int set_cluster_name(struct admin_dev *d, const char *name)
{
    char before[MXFS_CLUSTER_NAME_LEN];

    if (name[0] && !mxfs_cluster_name_valid(name)) {
        fprintf(stderr, "mxfs_admin: a cluster name is 1-%d characters of "
                "A-Z a-z 0-9 . _ -\n", MXFS_CLUSTER_NAME_LEN - 1);
        return -1;
    }
    cluster_name_of(d, before);
    memset(d->sup.cluster_name, 0, sizeof(d->sup.cluster_name));
    if (name[0]) {
        snprintf(d->sup.cluster_name, sizeof(d->sup.cluster_name), "%s", name);
        d->sup.flags |= MXFS_FORMAT_F_CLUSTER_NAME;
    } else {
        d->sup.flags &= ~MXFS_FORMAT_F_CLUSTER_NAME;
    }
    if (envelope_write(d) < 0)
        return -1;
    printf("cluster name %s -> %s\n", before, name[0] ? name : "(none)");
    if (name[0])
        printf("every node must now mount with -o cluster=%s\n", name);
    return 0;
}

/* Both gates, the XFS superblocks first: until the envelope flag lands the
 * kernel still treats the feature as off, so a stop part-way leaves a
 * filesystem that mounts exactly as before (chk_mxfs reports the mismatch). */
static int set_dirshard_on(struct admin_dev *d)
{
    if ((d->sup.flags & MXFS_FORMAT_F_DIRSHARD) &&
        (get_be32(d->sb + XFS_SB_OFF_INCOMPAT) & MXFS_DIRSHARD_SB_INCOMPAT)) {
        printf("directory sharding is already available\n");
        return 0;
    }
    if (d->sup.cluster_proto_gen < 18) {
        fprintf(stderr, "mxfs_admin: this format (protocol gen %u) predates "
                "directory sharding\n", d->sup.cluster_proto_gen);
        return -1;
    }
    if (for_each_sb(d, edit_dirshard_on, NULL) < 0)
        return -1;
    d->sup.flags |= MXFS_FORMAT_F_DIRSHARD;
    if (envelope_write(d) < 0)
        return -1;
    printf("directory sharding is available; creating a sharded directory "
           "also needs the\nmxfs module parameter dirshard_mkdir_enable=1\n");
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "Usage: mxfs_admin [-liuV] [-L label] [-c name] [-O dirshard] DEVICE\n"
        "\n"
        "Show or change MXFS filesystem parameters.  Changes are refused\n"
        "unless no node can write the device (all nodes unmounted, no\n"
        "heartbeat advancing, no SCSI-PR registrant).\n"
        "\n"
        "  -l          print the label\n"
        "  -L LABEL    set the label (at most 12 bytes; -- clears it)\n"
        "  -u          print the UUID\n"
        "  -c NAME     set the cluster name; every mount must then pass\n"
        "              -o cluster=NAME.  -c \"\" clears it\n"
        "  -O dirshard make directory sharding available (experimental)\n"
        "  -i          print every MXFS setting\n"
        "  -V          print the version and exit\n");
}

int main(int argc, char *argv[])
{
    struct admin_dev d;
    const char *label = NULL, *cluster = NULL;
    bool show_label = false, show_uuid = false, show_info = false;
    bool dirshard_on = false, change;
    int opt, rc = 0;

    while ((opt = getopt(argc, argv, "liuVL:c:O:")) != -1) {
        switch (opt) {
        case 'l': show_label = true; break;
        case 'i': show_info = true; break;
        case 'u': show_uuid = true; break;
        case 'L': label = optarg; break;
        case 'c': cluster = optarg; break;
        case 'O':
            if (strcmp(optarg, "dirshard") && strcmp(optarg, "dirshard=1")) {
                fprintf(stderr, "mxfs_admin: -O knows only 'dirshard'\n");
                return 1;
            }
            dirshard_on = true;
            break;
        case 'V':
            printf("mxfs_admin version %s\n", MXFS_ADMIN_VERSION);
            return 0;
        default:
            usage();
            return 1;
        }
    }
    if (optind != argc - 1 ||
        !(show_label || show_uuid || show_info || label || cluster ||
          dirshard_on)) {
        usage();
        return 1;
    }
    change = label || cluster || dirshard_on;

    if (dev_open(&d, argv[optind], change) < 0)
        return 1;
    if (change && dev_prove_offline(&d) < 0) {
        close(d.fd);
        return 1;
    }
    if (label && set_label(&d, label) < 0)
        rc = 1;
    if (!rc && cluster && set_cluster_name(&d, cluster) < 0)
        rc = 1;
    if (!rc && dirshard_on && set_dirshard_on(&d) < 0)
        rc = 1;
    if (show_label && !show_info)
        print_label(&d);
    if (show_uuid && !show_info)
        print_uuid(&d);
    if (show_info)
        print_info(&d);
    close(d.fd);
    return rc;
}
