/*
 * MXFS — Multinode XFS
 * Proving that no node can write a device, for the offline tools
 *
 * A tool that rewrites on-disk state must first prove that nothing else is
 * writing it.  "Every node unmounted" is necessary but not sufficient, and a
 * quiet heartbeat table is not proof of exclusion.  Three independent proofs,
 * each failing CLOSED:
 *
 *   LOCAL   the device opened O_EXCL (no local mount, no other opener) —
 *           the caller does that open and passes the descriptor in.
 *   REMOTE  no ACTIVE heartbeat record advances across a recheck window.
 *   LUN     SCSI PERSISTENT RESERVE IN / READ KEYS reports no registrant.  A
 *           registered initiator can write to this LUN right now whatever its
 *           heartbeat says.  A block device that does not answer PR cannot be
 *           proven exclusive, so the proof fails.  A regular file (an image)
 *           has no SCSI target and skips this half, saying so.
 *
 * Header-only so every tool carries the same proof; chk_mxfs (offline
 * quarantine repair) and mxfs_admin both include it.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_TOOLS_OFFLINE_H
#define MXFS_TOOLS_OFFLINE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

/* Heartbeat table layout (dlm/disklock.h) */
#define MXFS_OFF_HB_SLOTS        64
#define MXFS_OFF_HB_RECORD_SIZE  512
#define MXFS_OFF_HB_MAGIC        0x4D584C4B  /* "MXLK" */
#define MXFS_OFF_HB_FLAG_ACTIVE  1

/* A live node rewrites its heartbeat record far more often than this, so a
 * record that has not moved across the window belongs to no running node. */
#define MXFS_OFF_HB_RECHECK_MS   10000

#define MXFS_OFF_PR_MAX_KEYS     64

struct mxfs_off_hb_hdr {
    uint32_t magic, flags, node_id, fs_gen;
    uint64_t timestamp_ms, epoch, lock_count;
} __attribute__((packed));

/* Aligned O_DIRECT read of one 512-byte sector: the heartbeat table must be
 * read from the platter, never from this host's page cache. */
static inline int mxfs_off_read_sector_direct(int dfd, uint64_t off,
                                              uint8_t *out512)
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
 * PERSISTENT RESERVE IN, service action 0x00 (READ KEYS).  Returns the number
 * of registered keys, or -1 if the command could not be issued / the device
 * does not implement PR (which the caller must treat as "cannot prove").
 */
static inline int mxfs_off_pr_read_keys(int fd, uint64_t *keys, int max,
                                        int *unsupported)
{
    unsigned char cdb[10];
    unsigned char sense[32];
    unsigned char data[8 + MXFS_OFF_PR_MAX_KEYS * 8];
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

/*
 * The REMOTE and LUN proofs.  fd is the caller's O_EXCL descriptor (the LOCAL
 * proof), dfd an O_DIRECT descriptor on the same device.  Prints what it
 * proved and every reason it could not; returns 0 only when all proofs hold.
 */
static inline int mxfs_off_prove_no_writer(int fd, int dfd,
                                           uint64_t disklock_offset)
{
    uint64_t hb_ts[MXFS_OFF_HB_SLOTS], hb_ep[MXFS_OFF_HB_SLOTS];
    uint64_t keys[MXFS_OFF_PR_MAX_KEYS];
    int hb_live[MXFS_OFF_HB_SLOTS];
    int slot, moved = 0, nkeys, unsupported, i;
    struct stat st;

    for (slot = 0; slot < MXFS_OFF_HB_SLOTS; slot++) {
        uint8_t sec[512];
        const struct mxfs_off_hb_hdr *hh = (const void *)sec;

        hb_live[slot] = 0;
        if (mxfs_off_read_sector_direct(dfd, disklock_offset +
                                        (uint64_t)slot * MXFS_OFF_HB_RECORD_SIZE,
                                        sec) < 0)
            continue;
        if (hh->magic == MXFS_OFF_HB_MAGIC &&
            hh->flags == MXFS_OFF_HB_FLAG_ACTIVE) {
            hb_live[slot] = 1;
            hb_ts[slot] = hh->timestamp_ms;
            hb_ep[slot] = hh->epoch;
        }
    }
    printf("  rechecking heartbeat liveness for %d ms ...\n",
           MXFS_OFF_HB_RECHECK_MS);
    usleep((useconds_t)MXFS_OFF_HB_RECHECK_MS * 1000);
    for (slot = 0; slot < MXFS_OFF_HB_SLOTS; slot++) {
        uint8_t sec[512];
        const struct mxfs_off_hb_hdr *hh = (const void *)sec;

        if (!hb_live[slot])
            continue;
        if (mxfs_off_read_sector_direct(dfd, disklock_offset +
                                        (uint64_t)slot * MXFS_OFF_HB_RECORD_SIZE,
                                        sec) < 0)
            continue;
        if (hh->magic == MXFS_OFF_HB_MAGIC &&
            hh->flags == MXFS_OFF_HB_FLAG_ACTIVE &&
            (hh->timestamp_ms != hb_ts[slot] || hh->epoch != hb_ep[slot])) {
            fprintf(stderr, "  LIVE: heartbeat slot %d (node %u) is still "
                    "beating — a node has this\n        filesystem mounted.  "
                    "Unmount everywhere first.\n", slot, hh->node_id);
            moved++;
        }
    }
    if (moved)
        return -1;
    printf("  no heartbeat advanced: no node is mounted\n");

    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        printf("  SCSI PR: not applicable to an image file\n");
        return 0;
    }
    nkeys = mxfs_off_pr_read_keys(fd, keys, MXFS_OFF_PR_MAX_KEYS, &unsupported);
    if (unsupported || nkeys < 0) {
        fprintf(stderr,
            "  CANNOT PROVE: this LUN does not answer PERSISTENT RESERVE IN, "
            "so there is no\n        way to show that no initiator can write "
            "to it right now.  A quiet\n        heartbeat table is not proof "
            "of exclusion.  Refusing.\n");
        return -1;
    }
    if (nkeys > 0) {
        fprintf(stderr, "  REGISTERED: %d initiator key(s) are still "
                "registered on this LUN and can\n        write to it right "
                "now regardless of their heartbeats:\n", nkeys);
        for (i = 0; i < nkeys; i++)
            fprintf(stderr, "          0x%016llx\n",
                    (unsigned long long)keys[i]);
        fprintf(stderr, "        Fence or deregister them, then re-run.\n");
        return -1;
    }
    printf("  SCSI PR: no registered initiator — nothing can write to this "
           "LUN\n");
    return 0;
}

#endif /* MXFS_TOOLS_OFFLINE_H */
