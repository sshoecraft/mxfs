/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS TCP durable-authority ledger — the SHADOW-PAGE STORE
 * (docs/tcp-authority-ledger.md step 2; layout in include/mxfs/mxfs_tauth.h).
 *
 * Kernel and usermode (pal/linux/user.c) — the only dependencies are the
 * PAL block-device calls, mxfs_pal_crc32c and mxfs_pal_alloc.  No policy
 * lives here: the store knows pages, copies, sequence numbers and crcs; the
 * authority protocol (step 3+) owns the entries.
 *
 * Contract:
 *   read   both copies are read and validated; the highest valid committed
 *          seq wins.  No valid copy => -EUCLEAN: the page is UNKNOWN and the
 *          caller MUST fail closed (never "free").  I/O failure => -EIO.
 *   write  the caller supplies the full page image with its entries; the
 *          store stamps seq = highest valid seq on the platter + 1, writes
 *          the copy that does NOT hold that highest seq (so the only valid
 *          copy is never overwritten), FUA + flush, then re-reads the copy
 *          it wrote and requires it to validate.  Only after that does the
 *          transition count as durable (invariant 1: durable-before-deliver
 *          is the caller's job, built on this return).
 *   Every I/O is one whole 4 KiB page (sector-aligned: the PAL trap).
 */
#ifndef MXFS_TAUTH_STORE_H
#define MXFS_TAUTH_STORE_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_tauth.h"

struct mxfs_tauth_store {
    mxfs_bdev_t    *dev;
    uint64_t        base;           /* tauth_offset from the envelope */
    uint64_t        size;
    uint32_t        npages;         /* from the region header (v2 geometry) */
    uint64_t        hash_seed;      /* from the region header */
    uint32_t        fs_gen;
    uint8_t         fs_uuid[16];
    uint32_t        local_node;     /* stamped into page headers */
    uint64_t        local_inc;
    /* counters (forensic, read by the unit test and P-lines) */
    uint64_t        reads, writes, torn_seen, repairs, unknown,
                    conflicts, lost_races;   /* step 4 */
    /* (D-0347, conditional commit) */
    uint64_t        stale_bases,    /* write refused: the platter moved past
                                     * the image the caller patched */
                    ticket_busy,    /* spare copy under a LIVE ticket */
                    ticket_takeovers, /* abandoned ticket of a fenced writer */
                    ticket_resumes, /* our own abandoned ticket */
                    stolen,         /* publish CAW lost: protocol/fencing fault */
                    superseded;     /* readback shows a later commit: ours landed */
    /* (D-0349 instrumented): per-phase commit cost in ms — totals + max */
    uint64_t        ph_ticket_ms, ph_ticket_max, ph_body_ms, ph_body_max,
                    ph_publish_ms, ph_publish_max, ph_flush_ms, ph_flush_max,
                    ph_read_ms, ph_read_max, ph_commits;
    uint64_t        nonce_state;                /* write_nonce generator */
    /* may a ticket left by {node, inc} be taken over? Only when
     * that incarnation is durably fenced from the LUN (recovery-purged
     * after the SCSI-PR fence).  Absent = never (writes on such a page
     * return -EBUSY, reads are unaffected). */
    bool            (*fenced_cb)(void *data, uint32_t node, uint64_t inc);
    void           *fenced_data;
};

/* Open: validates the region header (either copy) against the fs identity.
 * -ENODEV: region absent (base/size 0); -EINVAL: geometry mismatch;
 * -EUCLEAN: no valid region header (unformatted or corrupt); -EIO. */
int  mxfs_tauth_store_open(struct mxfs_tauth_store *s, mxfs_bdev_t *dev,
                           uint64_t base, uint64_t size,
                           const uint8_t fs_uuid[16],
                           uint32_t local_node, uint64_t local_inc);

/* Read page_id into *pg (4 KiB, caller-owned, page-aligned allocation not
 * required).  *copy_out (optional) = which copy won.  0 / -EUCLEAN / -EIO. */
int  mxfs_tauth_page_read(struct mxfs_tauth_store *s, uint32_t page_id,
                          struct mxfs_tauth_page *pg, int *copy_out);

/* Durably commit *pg as the next version of page pg->hdr.page_id — a
 * CONDITIONAL commit (D-0347): pg->hdr.seq / write_nonce name the
 * committed image the caller derived *pg from (0/0 = the page had no valid
 * copy); the commit lands only if the platter still holds exactly that
 * image.  -ESTALE = it moved (re-read, re-derive); -EBUSY = the spare copy
 * is under another live writer's ticket; -EIO = uncertain (poison +
 * reconcile).  Concurrent writers get exactly one winner (sector-0 ticket
 * via SCSI COMPARE AND WRITE, body written under it, atomic publish).
 * The store rewrites hdr.seq / writer identity / stamp / crc.  Optional fault
 * knob: when `torn_after_bytes` > 0 only that many bytes of the page are
 * written (then the call returns -EIO WITHOUT the flush/verify) — the
 * usermode test uses it to manufacture a torn copy. */
int  mxfs_tauth_page_write(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
                           uint64_t authority_epoch, uint64_t config_epoch,
                           uint32_t torn_after_bytes);

/* Sweep every page: counts pages with 2 / 1 / 0 valid copies.  Returns 0,
 * or -EUCLEAN when any page has no valid copy (the region cannot serve as
 * complete negative authority), or -EIO. */
int  mxfs_tauth_store_verify(struct mxfs_tauth_store *s, uint32_t *two,
                             uint32_t *one, uint32_t *none);

/*
 * Visit every page of [first, first + count) with the SAME selection rule
 * as mxfs_tauth_page_read (both copies; highest valid committed seq wins;
 * two valid divergent images with one seq = conflicted), reading the copies
 * in bulk runs instead of one page per I/O.  This is the fence-time
 * manifest collector's read path: the prover must see every page of the
 * region, including pages served by a dead authority that this node has
 * never loaded, and the region is 0.4 % of the device.
 *
 * cb(data, page_id, pg, rc) per page: rc 0 with the committed image;
 * -EUCLEAN with pg NULL (no valid copy, or conflicted: the page is UNKNOWN);
 * -EIO with pg NULL (a copy unreadable and no valid alternative).  The
 * callback must not call back into the store.  Returns 0 once every page was
 * visited, else -EINVAL / -ENOMEM.
 */
typedef void (*mxfs_tauth_page_cb)(void *data, uint32_t page_id,
                                   const struct mxfs_tauth_page *pg, int rc);
int  mxfs_tauth_store_scan(struct mxfs_tauth_store *s, uint32_t first,
                           uint32_t count, mxfs_tauth_page_cb cb, void *data);

#endif /* MXFS_TAUTH_STORE_H */
