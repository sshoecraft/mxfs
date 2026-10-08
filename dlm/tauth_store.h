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
                    superseded,     /* readback shows a later commit: ours landed */
                    span_commits,   /* single commits made in one swap (span_commit) */
                    target_refused; /* a write bounced RESERVATION CONFLICT:
                                     * this initiator's key is off the LUN.  A
                                     * bulk pass stops when this moves, rather
                                     * than send one refused command per page
                                     * until the heartbeat closes the authority */
    /* (D-0349 instrumented): per-phase commit cost in ms — totals + max */
    uint64_t        ph_ticket_ms, ph_ticket_max, ph_body_ms, ph_body_max,
                    ph_publish_ms, ph_publish_max, ph_flush_ms, ph_flush_max,
                    ph_read_ms, ph_read_max, ph_commits;
    uint64_t        nonce_state;                /* write_nonce generator */
    /*
     * Every swap's target write and every FUA write on this device is durable
     * on every replica when it completes, so a flush after one adds nothing.
     * Set by the mount for a DRBD device (dlm/v5_mount.c): the emulated swap
     * writes its target with FUA (pal/linux/drbd.c), DRBD replicates a FUA
     * write as DP_FUA and completes it once the peer's disk holds it, and an
     * empty flush there completes on the LOCAL flush alone
     * (mxfs_pal_bdev_write_scatter_fua says why), so the commit's three
     * flushes cost a local cache flush each, under guest load up to tens of
     * ms, and made nothing durable that was not already.  Off everywhere
     * else: a SCSI target may drop FUA (the LIO trap), and there the flushes
     * are the durability.
     */
    bool            fua_durable;
    /*
     * Commit a single page in ONE swap that compares the spare's sector 0 and
     * writes the whole image (mxfs_pal_bdev_compare_and_write_span), instead
     * of ticket swap, body and publish swap.  The ticket exists because a
     * SCSI COMPARE AND WRITE covers sector 0 alone, so the body has to land
     * outside any swap and the copy has to read as invalid meanwhile; where
     * every swap is emulated (the DRBD attachment), one swap covers the page,
     * and a copy torn by a crash mid-write fails its CRC, leaving the other
     * copy the truth, as an abandoned ticket does.  Mutual exclusion is the
     * same compare on the same sector the ticket swap made: whoever changes
     * the spare's sector 0 first wins, and a live ticket of an older writer
     * still answers -EBUSY from step 2.  Set by the mount for a DRBD device;
     * cleared by the first commit that is answered -EOPNOTSUPP.  A batched
     * commit (page_write_many, the group commit) keeps the ticket protocol.
     */
    bool            span_commit;
    /*
     * TEST knob, set only by the usermode ledger tests: the next ticket swap
     * answers ticket_fail_once_rc.  With ticket_fail_landed the swap is
     * issued and only its answer is lost (the ticket stands on the spare);
     * without, it is never issued.  0 = off; its use disarms it.
     */
    int             ticket_fail_once_rc;
    bool            ticket_fail_landed;
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

/*
 * A BATCHED COMMIT: up to MXFS_TAUTH_WRITE_BATCH pages, each committed exactly
 * as mxfs_tauth_page_write commits one (the same conditional commit, the same
 * result in its own w[i].rc), with each step taken for every page before the
 * next step starts: every ticket swap queued together, ONE flush, every body
 * written together, ONE flush, every publish swap queued together, ONE flush,
 * every published copy read back.  A page's own steps keep the single
 * commit's order, so a crash leaves each page exactly as a crash during its
 * own commit would; the pages only share the barriers.  A page that fails a
 * step drops out of the steps after it.  The single commit pays the three
 * flushes and two coordination swaps per page — through DRBD, a replicated
 * round trip each — and a recovery's ledger purge committed its pages one by
 * one.  No test knob: torn writes are the single commit's.
 * Returns 0 with every w[i].rc set; -EINVAL (nothing set: n out of range or no
 * store), -ENOMEM (every rc -ENOMEM, nothing written).
 */
#define MXFS_TAUTH_WRITE_BATCH 32u
struct mxfs_tauth_wreq {
    struct mxfs_tauth_page *pg;         /* in and out, as mxfs_tauth_page_write's */
    uint64_t                authority_epoch;
    int                     rc;         /* out: what mxfs_tauth_page_write returns */
};
int  mxfs_tauth_page_write_many(struct mxfs_tauth_store *s, struct mxfs_tauth_wreq *w,
                                int n, uint64_t config_epoch);

/*
 * THE BATCHED COMMIT IN THREE CALLS, for committers that each hold one page
 * and share only the barriers (the ledger's group commit).  A commit is:
 *
 *   mxfs_tauth_page_write_base      steps 1-2 for one page: both copies read,
 *                                   the caller's base token checked, the spare
 *                                   and its ticket chosen (into *ws)
 *   mxfs_tauth_page_write_barriers  steps 3-5 for every page of the batch
 *                                   whose w[i].rc is 0: the ticket swaps
 *                                   queued together, ONE flush, every body
 *                                   written, ONE flush, the publish swaps
 *                                   queued together, ONE flush
 *   mxfs_tauth_page_write_readback  step 6 for one page
 *
 * which is mxfs_tauth_page_write_many with each page's reads in its own
 * committer's thread, where they run in parallel as single commits' do: in
 * one thread, a batch of N cost 3N reads in series.  `fua_body` writes the
 * bodies FUA, as the single commit does; without it the body is made durable
 * by the flush after it alone (what page_write_many does, except on a
 * fua_durable device, where that flush is local and the bodies go FUA).  Each
 * call returns what mxfs_tauth_page_write would have returned at that point.
 */
struct mxfs_tauth_wslot {
    struct mxfs_tauth_ticket tk;
    uint8_t  spare0[MXFS_TAUTH_TICKET_BYTES];   /* the spare's sector 0 as read:
                                                 * the ticket swap's compare value */
    uint64_t off;                               /* the spare copy */
    uint64_t next;                              /* the seq this commit publishes */
    unsigned target;                            /* which copy is the spare */
};
int  mxfs_tauth_page_write_base(struct mxfs_tauth_store *s, struct mxfs_tauth_page *pg,
                                struct mxfs_tauth_wslot *ws);
void mxfs_tauth_page_write_barriers(struct mxfs_tauth_store *s, struct mxfs_tauth_wreq *w,
                                    struct mxfs_tauth_wslot *const *ws, int n,
                                    uint64_t config_epoch, bool fua_body);
int  mxfs_tauth_page_write_readback(struct mxfs_tauth_store *s,
                                    const struct mxfs_tauth_page *pg,
                                    const struct mxfs_tauth_wslot *ws);

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
