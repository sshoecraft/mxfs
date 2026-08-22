/*
 * caw_slotdump — dump the on-disk CAW DLM lock slot table of an MXFS device.
 *
 * The CAW slot table IS the lock authority for a caw-transport cluster
 * (mxfs_v5_dlm_is_caw: "the on-disk slot is the single truth"), so when a
 * node reports peer-held AG locks that no peer believes it holds
 * (P5G-AGLOCK-BOUNDED-BUSY vs P12-AGBAST-RX holders=0), the slot table on
 * the platter is the arbiter.  This tool reads it with the SAME transport
 * semantics the kernel uses — SCSI READ(16)+FUA via SG_IO — so the image
 * it prints is what every node's find_slot/read_slot would see, not a
 * page-cache artifact.
 *
 * Usage:
 *   caw_slotdump <device> [--type ag|inode|iclus|extent|journal|super]
 *                          [--held-only] [--all] [--max N]
 *
 *   default: print every slot bound to a resource (live or tombstone) that
 *            has any holder/waiter bit set, plus the heartbeat table so
 *            bitmap bit N can be mapped to a node_id.
 *   --held-only : only slots with a nonzero holder bitmap
 *   --all       : every non-zero slot, tombstones and idle bindings included
 *   --type X    : filter by resource type
 *   --max N     : stop after printing N slots
 *   --slot N    : print ONLY slot N (still a READ(16)+FUA of that sector) and
 *                 exit.  A plain `dd iflag=direct` of the same sector is NOT
 *                 equivalent: this target stack drops the FUA bit, so a direct
 *                 read can return a stale platter image -- sess375 had a slot
 *                 poller act on a tombstone that had been superseded, and bind
 *                 its resource one probe slot too far as a result.
 *
 * Layout (dlm_caw.h / disklock.h):
 *   slot table byte offset = super->disklock_offset + 64*512 (HB region)
 *   65536 slots x 512 bytes.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

#include <mxfs/mxfs_super.h>

#define SECTOR_SIZE          512
#define TIMEOUT_MS           30000
#define CAW_MAGIC            0x4D584357u   /* "MXCW" */
#define CAW_MAX_SLOTS        65536u
#define HB_SLOTS             64
#define HB_RECORD_SIZE       512
#define SPAN_SLOTS           64            /* 32KB per READ(16) */

/* Mirrors struct mxfs_resource_id (include/mxfs/mxfs_common.h). */
struct resid {
    uint64_t volume;
    uint64_t ino;
    uint64_t offset;
    uint32_t ag_number;
    uint8_t  type;
    uint8_t  pad[3];
};

/* Mirrors struct mxfs_caw_lock_slot (dlm/dlm_caw.h) — kept in sync by the
 * _Static_assert below; the kernel header drags in pal.h so tools carry a
 * layout copy the same way chk_mxfs carries the disklock layout. */
struct caw_slot {
    uint32_t magic;
    uint32_t generation;
    struct resid resource;
    uint64_t holders_ex;
    uint64_t holders_pw;
    uint64_t holders_pr;
    uint64_t holders_cw;
    uint64_t holders_cr;
    uint64_t waiters;
    uint8_t  granted_mode;
    uint8_t  waiter_mode;
    uint8_t  revoke;        /* sticky anonymous revoke (LIVELOCK-488) */
    uint8_t  pad0;
    uint32_t ex_grant_streak;
    uint64_t last_modified_ms;
    uint64_t yield_to;
    uint64_t yield_set_ms;
    uint64_t waiters_ex;
    uint32_t dir_epoch;
    uint8_t  last_ex_slot;
    uint8_t  pad3[3];
    uint64_t dir_block0_fsb;
    uint32_t dir_block0_gen;
    uint32_t pad4;
    uint64_t open_holders;
    uint64_t ex_grant_epoch;
    uint64_t resource_lineage;
    uint8_t  reserved[336];
};
_Static_assert(sizeof(struct caw_slot) == SECTOR_SIZE,
               "caw_slot layout drifted from 512 bytes");

static const char *type_name(uint8_t t)
{
    switch (t) {
    case 1: return "INODE";
    case 2: return "EXTENT";
    case 3: return "AG";
    case 4: return "JOURNAL";
    case 5: return "SUPER";
    case 6: return "ICLUS";
    default: return "?";
    }
}

static const char *mode_name(uint8_t m)
{
    static const char *n[] = { "NL", "CR", "CW", "PR", "PW", "EX" };
    return m < 6 ? n[m] : "??";
}

static int do_scsi_read_fua(int fd, uint64_t lba, void *buf, uint32_t blocks)
{
    unsigned char cdb[16] = {0};
    unsigned char sense[64];
    sg_io_hdr_t hdr;

    cdb[0]  = 0x88;                  /* READ(16) */
    cdb[1]  = 0x08;                  /* FUA */
    cdb[2]  = (uint8_t)(lba >> 56);
    cdb[3]  = (uint8_t)(lba >> 48);
    cdb[4]  = (uint8_t)(lba >> 40);
    cdb[5]  = (uint8_t)(lba >> 32);
    cdb[6]  = (uint8_t)(lba >> 24);
    cdb[7]  = (uint8_t)(lba >> 16);
    cdb[8]  = (uint8_t)(lba >> 8);
    cdb[9]  = (uint8_t)(lba);
    cdb[10] = (uint8_t)(blocks >> 24);
    cdb[11] = (uint8_t)(blocks >> 16);
    cdb[12] = (uint8_t)(blocks >> 8);
    cdb[13] = (uint8_t)(blocks);

    memset(&hdr, 0, sizeof(hdr));
    memset(sense, 0, sizeof(sense));
    hdr.interface_id = 'S';
    hdr.cmd_len = sizeof(cdb);
    hdr.cmdp = cdb;
    hdr.dxferp = buf;
    hdr.dxfer_len = blocks * SECTOR_SIZE;
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.sbp = sense;
    hdr.mx_sb_len = sizeof(sense);
    hdr.timeout = TIMEOUT_MS;

    if (ioctl(fd, SG_IO, &hdr) < 0) {
        fprintf(stderr, "SG_IO ioctl: %s\n", strerror(errno));
        return -1;
    }
    if (hdr.status != 0 || hdr.host_status != 0 || hdr.driver_status != 0) {
        fprintf(stderr, "SG_IO bad status lba=%llu: scsi=%d host=%d drv=%d\n",
                (unsigned long long)lba, hdr.status, hdr.host_status,
                hdr.driver_status);
        return -1;
    }
    return 0;
}

static void print_bits(const char *label, uint64_t v)
{
    if (!v)
        return;
    printf(" %s=0x%llx[", label, (unsigned long long)v);
    bool first = true;
    for (int b = 0; b < 64; b++) {
        if (v & (1ULL << b)) {
            printf("%s%d", first ? "" : ",", b);
            first = false;
        }
    }
    printf("]");
}

int main(int argc, char **argv)
{
    const char *dev = NULL;
    int want_type = -1;
    bool held_only = false, all = false, recov = false;
    long max_print = -1;
    long only_slot = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--held-only") == 0)
            held_only = true;
        else if (strcmp(argv[i], "--all") == 0)
            all = true;
        else if (strcmp(argv[i], "--recov") == 0)
            recov = true;
        else if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc)
            only_slot = (long)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc)
            max_print = atol(argv[++i]);
        else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            if (!strcmp(t, "inode")) want_type = 1;
            else if (!strcmp(t, "extent")) want_type = 2;
            else if (!strcmp(t, "ag")) want_type = 3;
            else if (!strcmp(t, "journal")) want_type = 4;
            else if (!strcmp(t, "super")) want_type = 5;
            else if (!strcmp(t, "iclus")) want_type = 6;
            else { fprintf(stderr, "unknown type %s\n", t); return 2; }
        } else if (!dev)
            dev = argv[i];
        else {
            fprintf(stderr, "usage: %s <device> [--type T] [--held-only] "
                    "[--all] [--max N]\n", argv[0]);
            return 2;
        }
    }
    if (!dev) {
        fprintf(stderr, "usage: %s <device> [--type T] [--held-only] "
                "[--all] [--max N]\n", argv[0]);
        return 2;
    }

    int fd = open(dev, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
        return 1;
    }

    /* MXFS superblock: 4KB at byte 0 = 8 sectors at LBA 0. */
    uint8_t sbuf[MXFS_SUPER_SIZE];
    if (do_scsi_read_fua(fd, 0, sbuf, MXFS_SUPER_SIZE / SECTOR_SIZE) < 0)
        return 1;
    struct mxfs_ondisk_super *sb = (struct mxfs_ondisk_super *)sbuf;
    if (sb->magic != MXFS_FORMAT_MAGIC) {
        fprintf(stderr, "not an MXFS device (magic 0x%08x)\n", sb->magic);
        return 1;
    }

    /* volume_id = FNV-1a64 over fs_uuid — what make_ag_resource stamps. */
    uint64_t vid = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 16; i++) {
        vid ^= sb->fs_uuid[i];
        vid *= 0x100000001b3ULL;
    }

    uint64_t dloff = sb->disklock_offset;
    uint64_t table_off = dloff + (uint64_t)HB_SLOTS * HB_RECORD_SIZE;

    if (only_slot >= 0) {
        /* One sector, same FUA path the kernel's read_slot uses. */
        static struct caw_slot one;
        uint64_t lba = (table_off + (uint64_t)only_slot * SECTOR_SIZE) /
                       SECTOR_SIZE;
        if (do_scsi_read_fua(fd, lba, &one, 1) < 0)
            return 1;
        printf("slot=%ld magic=0x%08x type=%s ag=%u ino=%llu gen=%u\n",
               only_slot, one.magic, type_name(one.resource.type),
               one.resource.ag_number,
               (unsigned long long)one.resource.ino, one.generation);
        close(fd);
        return 0;
    }

    printf("device=%s disklock_offset=%llu slot_table_offset=%llu "
           "volume_id=0x%016llx\n", dev,
           (unsigned long long)dloff, (unsigned long long)table_off,
           (unsigned long long)vid);

    /* Heartbeat table: map bitmap bit -> node_id. */
    printf("--- heartbeat slots (bit -> node) ---\n");
    uint8_t hb[HB_RECORD_SIZE];
    for (int i = 0; i < HB_SLOTS; i++) {
        uint64_t lba = (dloff + (uint64_t)i * HB_RECORD_SIZE) / SECTOR_SIZE;
        if (do_scsi_read_fua(fd, lba, hb, 1) < 0)
            continue;
        uint32_t magic = *(uint32_t *)(hb + 0);
        uint32_t flags = *(uint32_t *)(hb + 4);
        uint32_t node_id = *(uint32_t *)(hb + 8);
        if (magic == 0 && flags == 0 && node_id == 0)
            continue;
        printf("hb[%02d] magic=0x%08x flags=%u node_id=%u epoch=%llu",
               i, magic, flags, node_id,
               (unsigned long long)*(uint64_t *)(hb + 24));
        /* sess346 32B provenance carve at byte 424 (disklock.h layout
         * asserts).  Only decode when its own magic matches — pre-carve
         * records carry zeros/garbage there. */
        if (*(uint32_t *)(hb + 424) == 0x5650584Du /* MXPV */)
            printf(" prov{prev_node=%u prev_epoch=%llu seq=%llu chain=%u}",
                   *(uint32_t *)(hb + 428),
                   (unsigned long long)*(uint64_t *)(hb + 432),
                   (unsigned long long)*(uint64_t *)(hb + 440),
                   *(uint32_t *)(hb + 448));
        printf("\n");
        if (!recov)
            continue;
        /*
         * --recov: decode the sess64 recovery GUARD descriptor (byte 40,
         * 120B) and the sess323 terminal outcome record (byte 160, 96B)
         * per struct mxfs_disklock_heartbeat / mxfs_recov_body layout in
         * dlm/disklock.h.  Offsets are load-bearing: desc sits at the
         * union (40), outcome immediately after the 120B desc (160).
         */
        uint32_t dmagic = *(uint32_t *)(hb + 40);
        /* ACTIVE records carry the evict ring in the union — decoding
         * desc/outcome bytes there prints garbage.  Only GUARD records
         * (or stray MRCV magic, which is itself reportable) qualify. */
        if (flags != 3 && dmagic != 0x5643524Du)
            continue;
        if (flags == 3 /* RECOVERY_GUARD */ || dmagic == 0x5643524Du) {
            printf("  desc  magic=0x%08x%s stage=%u vepoch=%llu "
                   "rgen=%llu vnode=%u onode=%u vslot=%u dflags=0x%x\n",
                   dmagic, dmagic == 0x5643524Du ? "(MRCV)" : "(?)",
                   *(uint16_t *)(hb + 40 + 6),
                   (unsigned long long)*(uint64_t *)(hb + 40 + 8),
                   (unsigned long long)*(uint64_t *)(hb + 40 + 24),
                   *(uint32_t *)(hb + 40 + 40),
                   *(uint32_t *)(hb + 40 + 44),
                   *(uint16_t *)(hb + 40 + 56),
                   *(uint32_t *)(hb + 40 + 52));
        }
        uint32_t omagic = *(uint32_t *)(hb + 160);
        bool ozero = true;
        for (int z = 160; z < 256; z++)
            if (hb[z]) { ozero = false; break; }
        if (ozero) {
            printf("  outcome ALL-ZERO (no verdict / legacy intent)\n");
        } else {
            printf("  outcome magic=0x%08x%s ver=%u outcome=%u reason=%u "
                   "domain=%u vslot=%u vepoch=%llu agmask=0x%llx seq=%llu "
                   "onode=%u refused=%u malformed=%u oflags=0x%x crc=0x%08x\n",
                   omagic, omagic == 0x4F435652u ? "(RVCO)" : "(?)",
                   *(uint16_t *)(hb + 164), *(uint16_t *)(hb + 166),
                   *(uint16_t *)(hb + 168), *(uint16_t *)(hb + 170),
                   *(uint16_t *)(hb + 172),
                   (unsigned long long)*(uint64_t *)(hb + 176),
                   (unsigned long long)*(uint64_t *)(hb + 200),
                   (unsigned long long)*(uint64_t *)(hb + 216),
                   *(uint32_t *)(hb + 232),
                   *(uint32_t *)(hb + 240), *(uint32_t *)(hb + 244),
                   *(uint32_t *)(hb + 248), *(uint32_t *)(hb + 252));
        }
    }

    if (recov) {
        close(fd);
        return 0;
    }

    printf("--- lock slots ---\n");
    static struct caw_slot span[SPAN_SLOTS];
    long printed = 0;
    unsigned long live = 0, tomb = 0, nonempty = 0;

    for (uint32_t base = 0; base < CAW_MAX_SLOTS; base += SPAN_SLOTS) {
        uint64_t lba = (table_off + (uint64_t)base * SECTOR_SIZE) /
                       SECTOR_SIZE;
        if (do_scsi_read_fua(fd, lba, span, SPAN_SLOTS) < 0)
            return 1;
        for (uint32_t k = 0; k < SPAN_SLOTS; k++) {
            struct caw_slot *s = &span[k];
            bool is_zero = s->magic == 0 && s->resource.type == 0 &&
                           s->generation == 0;
            if (is_zero)
                continue;
            nonempty++;
            if (s->magic == CAW_MAGIC)
                live++;
            else
                tomb++;

            uint64_t holders = s->holders_ex | s->holders_pw |
                               s->holders_pr | s->holders_cw | s->holders_cr;
            if (want_type >= 0 && s->resource.type != want_type)
                continue;
            if (held_only && !holders)
                continue;
            if (!all && !holders && !s->waiters && !s->waiters_ex &&
                !s->yield_to && !s->open_holders)
                continue;
            if (max_print >= 0 && printed >= max_print)
                continue;
            printed++;

            printf("slot=%u %s gen=%u type=%s vol=0x%016llx",
                   base + k,
                   s->magic == CAW_MAGIC ? "LIVE" : "TOMB",
                   s->generation, type_name(s->resource.type),
                   (unsigned long long)s->resource.volume);
            /* sess375: ag ALWAYS — the closure classifier is AG-scoped for
             * every resource type, so an audit that can only see the AG of
             * type=ag slots cannot check an inode strip against the mask. */
            printf(" ag=%u", s->resource.ag_number);
            if (s->resource.type == 1 || s->resource.type == 6)
                printf(" ino=%llu", (unsigned long long)s->resource.ino);
            printf(" gmode=%s wmode=%s revoke=%u", mode_name(s->granted_mode),
                   mode_name(s->waiter_mode), s->revoke);
            print_bits("ex", s->holders_ex);
            print_bits("pw", s->holders_pw);
            print_bits("pr", s->holders_pr);
            print_bits("cw", s->holders_cw);
            print_bits("cr", s->holders_cr);
            print_bits("wait", s->waiters);
            print_bits("wait_ex", s->waiters_ex);
            print_bits("yield", s->yield_to);
            print_bits("open", s->open_holders);
            printf(" last_ex_slot=%u ex_epoch=%llu lineage=0x%llx lmod=%llu\n",
                   s->last_ex_slot,
                   (unsigned long long)s->ex_grant_epoch,
                   (unsigned long long)s->resource_lineage,
                   (unsigned long long)s->last_modified_ms);
        }
    }
    printf("--- summary: nonempty=%lu live=%lu tomb=%lu printed=%ld ---\n",
           nonempty, live, tomb, printed);
    close(fd);
    return 0;
}
