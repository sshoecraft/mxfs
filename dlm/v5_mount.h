/*
 * MXFS — Multinode XFS
 * v5 DLM→XFS Integration Shim
 *
 * Wires the portable DLM engine (dlm.c, dlm_caw.c, peer.c, discovery.c,
 * lease.c, disklock.c, scsipr.c, journal.c) into kernel XFS v5.
 *
 * Replaces dlm/mount.c from mxfs.1 which depended on the custom cache
 * layer (block_cache, inode_cache, dir_cache, alloc).  v5 uses kernel
 * XFS natively — the DLM hooks into xfs_ilock/iunlock and xfs_alloc.
 *
 * This header is used by BOTH the DLM code (PAL world) and the XFS
 * kernel code.  It avoids including XFS headers — all XFS interaction
 * goes through opaque pointers.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_DLM_V5_MOUNT_H
#define MXFS_DLM_V5_MOUNT_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"
#include "../include/mxfs/mxfs_dlm.h"

/* ─── DLM transport selection ─── */

#define MXFS_V5_TRANSPORT_CAW   0
#define MXFS_V5_TRANSPORT_TCP   1
#define MXFS_V5_TRANSPORT_AUTO  2

/* ─── Opaque v5 DLM context ─── */

struct mxfs_v5_dlm;

/* ─── Init options ─── */

struct mxfs_v5_dlm_opts {
    int             transport;          /* MXFS_V5_TRANSPORT_* */
    uint16_t        dlm_port;           /* TCP port (default 7600) */
    uint16_t        discovery_port;     /* UDP port (default 7601) */
    uint64_t        journal_offset;     /* from MXFS on-disk super */
    uint64_t        disklock_offset;    /* from MXFS on-disk super */
    uint32_t        max_nodes;          /* from MXFS on-disk super */
    void            *bdev;              /* struct block_device * (kernel) */
    uint8_t         volume_uuid[16];    /* XFS superblock UUID */
    /*
     * v5 sess33: cap on locally-tracked held CAW DLM locks.  0 = use
     * MXFS_CAW_MAX_HELD compile-time default.  Filled by xfs_super.c
     * fill_super from mxfs_cache_caps.dlm_lock (auto-sized at module
     * load from cache_mem_pct module param + host RAM).
     */
    int             max_dlm_lock_caw;
    /*
     * v0.5.0: dead-node detection window in ms.  0 = compile-time default
     * (MXFS_DISKLOCK_DEAD_THRESHOLD × HB interval = 62 s, the production-
     * conservative value).  Test rigs set this low (e.g. 15000) so crash
     * recovery — lock purge + foreign-slice replay — fires promptly.
     * Filled from the lease_timeout_ms module param.
     */
    uint32_t        lease_timeout_ms;
};

/* ─── Lifecycle ─── */

/*
 * Initialize all DLM subsystems.
 * Returns opaque context on success, NULL on failure.
 * The caller (XFS mount code) stores this in mp->m_mxfs_dlm.
 */
struct mxfs_v5_dlm *mxfs_v5_dlm_init(const struct mxfs_v5_dlm_opts *opts);

/*
 * Shut down all DLM subsystems and free the context.
 */
void mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx);

/*
 * v0.11.74: detach the SCSI PR registration from the ctx before
 * shutdown and return its key (0 if none/no PR).  The caller owns the
 * deferred unregister, issued via mxfs_pal_scsi_pr_unregister_bdev
 * AFTER the unmount log record is on disk — unregistering inside
 * shutdown fenced the node's own final log write on WE-RO targets.
 */
uint64_t mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx);

/*
 * sess9 (ccloop a864): owning FS force-shut-down (still mounted) — leave the
 * cluster: fence all new acquires (inode + AG return -ESHUTDOWN) and stop the
 * disklock heartbeat so peers' dead-node purge reclaims our slots.  Sleeps
 * (<=5s thread join); process context only.  Idempotent.
 */
void mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx);
/* sess9 (ccloop c7ee71c6) D2: called by the elected replayer after the
 * dead node's slice is durably replayed — shared purges + zeroing the
 * dead HB slot (the cluster-wide "replay done" signal). */
void mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx,
                                   uint32_t dead_slot);
bool mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx);

/* ─── Inode lock interface ─── */

int  mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino,
                             uint8_t mode);
/* sess58: short per-call retry budget; caller loops + re-yields cached AGs. */
int  mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino,
                             uint8_t mode, int retries);
void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* ccloop cc87fed3 sess8: use in place of mxfs_v5_dlm_inode_unlock when the
 * caller has already verified nlink==0 and is doing destructive inactivation
 * (a genuine free, not an idle-gap release).  CAW transport piggybacks a
 * dir_epoch/last_ex_slot clear onto the unlock's own tombstone CAS so a
 * reused ino doesn't inherit a stale cross-node-handoff signal; zero extra
 * I/O.  TCP transport: identical to the plain unlock (no epoch concept). */
void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess7 FIX-20b: phantom-grant reconcile (mirror-bypassing gen=0 release). */
int  mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx,
                                             uint64_t ino);
/* sess1(a9a03929): gen-aware release — -ESTALE = a newer tenure owns the
 * resource; caller must re-arm its BAST instead of assuming released. */
int  mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t expected_gen);
void mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino);
int  mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                int *nslots_out);
/* ccloop a864 sess3: duplicate-immune self-EX check (full-chain scan).  1 if
 * this node holds `ino` EX on disk (any live slot), else 0.  CAW only.
 * *nslots_out = live-slot count; *hex_or_out = OR of holders_ex.  Read-only. */
int  mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                      int *nslots_out, uint64_t *hex_or_out);
/* ccloop a864 sess3: unconditional scan-based self-release (orphan-bit reclaim).
 * CAW only.  Caller holds the DEMOTING claim.  Returns #slots cleared. */
int  mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino);

/* sess55: producer bridge for the inode-eviction ring (called from xfs_ifree). */
void mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen);

/* sess80: producer bridge for a dir-modify eviction-ring entry (called from the
 * dir-modify chokepoints xfs_dir_createname/removename/replace). */
void mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino);

/* sess56: register the eviction-ring consumer (the XFS-layer callback that
 * flags a stale NL-cached inode / bumps a peer-modified dir's gen).  Forwards
 * to the disklock layer. */
void mxfs_v5_dlm_set_evict_cb(struct mxfs_v5_dlm *ctx,
                              void (*cb)(void *data, uint64_t ino,
                                         uint32_t gen, uint32_t type),
                              void *data);

/* ─── AG lock interface ─── */

int  mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno);
int  mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno);
void mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx, uint32_t agno);
int  mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno);
/* ccloop c7ee71c6 sess6: orphan-grant NAK — when a bast arrives for an AG the
 * FS layer does not hold (holders=0, !cached, nothing scheduled), tell the
 * master to drop its zombie GRANTED entry for us.  Guarded: no-op if the
 * local dlm table holds any entry (incl. an in-flight acquire).  TCP only. */
int  mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno);
/* sess19: read shared on-disk AG slot generation (cross-node coherency epoch) */
int  mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno,
                                    uint64_t *out_gen);
int  mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess42: raw held mode (MXFS_LOCK_NL/PR/EX) — phantom-lock callers compare
 * against the mode they believe they hold (NOT hardcoded EX, which
 * false-negatives a valid PR). */
uint8_t mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess37: 1=this node masters the inode resource, 0=no, -1=no TCP dlm. */
int mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess61 (sess10 plan): reliable per-grant generation token this node holds for
 * `ino` on TCP (0 if not held / CAW).  Dir-EX fast-path tenure-change signal. */
uint32_t mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* interactive session 2026-07-13: resource-scoped (CAW-only; 0/no-op on TCP)
 * orphan-strand wall-clock trackers for `ino` — survives VFS inode eviction,
 * unlike an xfs_inode field.  See dlm_caw.h's grant_meta struct comment. */
uint64_t mxfs_v5_dlm_inode_orphan_clock_get(struct mxfs_v5_dlm *ctx,
                                            uint64_t ino, bool starve);
void mxfs_v5_dlm_inode_orphan_clock_set(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                        bool starve, uint64_t val);
uint8_t mxfs_v5_dlm_inode_granted_mode(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* sess63: did this node's held EX grant for `ino` arrive as a cross-node handoff
 * (a DIFFERENT node held EX since we last did)?  *gen_out gets the grant_gen for
 * once-per-episode consumption.  Reliable replacement for the lossy evict-ring.
 * v0.6.0: served on BOTH transports (TCP master mirror / CAW slot dir_epoch). */
bool mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                     uint32_t *gen_out);
/* sess64 (GPT design): cross-node handoff epoch for `ino`'s held grant
 * (0 if not held).  Level-triggered staleness signal for the XFS layer.
 * TCP: monotonic (compare >).  CAW (v0.6.0): slot-carried, can restart on
 * slot reclamation (compare !=; see mxfs_v5_dlm_transport_caw). */
uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino);
/* ccloop(3e02e7dd) sess3: canonical dir logical-block0 record, write-once per
 * incarnation `gen` (dp->i_generation) — see docs/canonical_block0_fix_plan.md
 * and the dir_block0_fsb comment in struct mxfs_caw_lock_slot.  CAW-only
 * (TCP has no equivalent yet; returns false / no-op — TCP already passes its
 * criteria without this mechanism).  Query: true + *fsb_out iff a canonical
 * block0 is published for incarnation `gen`.  Publish: WRITE-ONCE, a no-op
 * if already published for `gen`. */
bool mxfs_v5_dlm_inode_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen, uint64_t *fsb_out);
void mxfs_v5_dlm_inode_set_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                      uint64_t fsb, uint32_t gen);
/* v0.6.0: true iff this mount coordinates via the CAW (disk-slot) transport. */
bool mxfs_v5_dlm_transport_caw(struct mxfs_v5_dlm *ctx);
/* sess-tcp: true iff this mount runs the TCP DLM transport (grants live in the
 * dlm.c local mirror, so mxfs_v5_dlm_inode_held is a cheap in-mem lookup — the
 * dir-EX held verify can run un-throttled, unlike the CAW 512B slot read). */
bool mxfs_v5_dlm_is_tcp(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_ag_ex_count(struct mxfs_v5_dlm *ctx, uint32_t agno,
                             int *nslots_out);

/* ─── Non-blocking lock ─── */

int  mxfs_v5_dlm_inode_lock_try(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                 uint8_t mode);

/* ─── BAST notification callback ─── */

/*
 * Called by v5_bast_cb when another node needs a lock we're caching.
 * data = opaque pointer (struct xfs_mount * in practice).
 * ino = inode number of the contested resource.
 * mode = lock mode the remote node requested.
 */
typedef void (*mxfs_v5_bast_notify_fn)(void *data, uint64_t ino,
                                        uint8_t mode);

void mxfs_v5_dlm_set_bast_notify(struct mxfs_v5_dlm *ctx,
                                   mxfs_v5_bast_notify_fn fn, void *data);

/*
 * ICLUSTER ops (ccloop 72513a13 sess3, ICLUSTER PLAN in DLM_PLAN.md).
 * One on-disk resource per XFS inode cluster; base_ino must already be
 * the cluster base (ino & ~(inodes_per_cluster-1)).  Refcounting across
 * the covered inodes lives in the xfs-side mediating layer — these move
 * only the on-disk slot.  The BAST callback receives the cluster BASE.
 */
int mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                           uint8_t mode);
int mxfs_v5_dlm_iclus_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                                 uint32_t expected_gen, bool is_free);
int mxfs_v5_dlm_iclus_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t base_ino);
void mxfs_v5_dlm_set_iclus_bast_notify(struct mxfs_v5_dlm *ctx,
                                       mxfs_v5_bast_notify_fn fn, void *data);

/*
 * Per-AG BAST notify.  Called by v5_bast_cb when a peer requests an AG
 * lock this node holds in cached state (no active local holders).
 */
typedef void (*mxfs_v5_ag_bast_notify_fn)(void *data, uint32_t agno,
                                           uint8_t mode);

void mxfs_v5_dlm_set_ag_bast_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_ag_bast_notify_fn fn,
                                      void *data);

/*
 * Called once when the DLM transitions from single-node to multi-node
 * (first peer discovered).  The XFS layer must flush all dirty data
 * to disk before the peer can read our allocated clusters — otherwise
 * the peer, or even this node after a subsequent DLM reload, will
 * read pre-allocation zeros and trip xfs_inode_buf_verify.
 */
typedef void (*mxfs_v5_peer_joined_notify_fn)(void *data);

void mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx,
                                          mxfs_v5_peer_joined_notify_fn fn,
                                          void *data);

/*
 * sess131 self-fence notification.  Fired once when the disklock heartbeat
 * thread detects the device was re-mkfs'd under this live mount (on-disk
 * MXFS super fs_uuid no longer matches the mounted volume).  The XFS layer
 * must force-shutdown the filesystem — every further write from this node
 * is ghost pollution of the new cluster generation.
 */
typedef void (*mxfs_v5_fence_notify_fn)(void *data);

void mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx,
                                  mxfs_v5_fence_notify_fn fn,
                                  void *data);

/*
 * v0.5.0 dead-node notification (foreign-slice replay trigger).  Fired from
 * the disklock heartbeat thread after a dead peer's CAW/disklock/DLM state
 * has been purged, ONLY on the elected survivor (lowest live heartbeat slot,
 * see mxfs_disklock_lowest_live_slot).  dead_slot is the dead node's
 * heartbeat slot == its per-node XFS log slice index.  Runs in heartbeat
 * context — the body must not block; queue work and return.
 */
typedef void (*mxfs_v5_dead_node_notify_fn)(void *data, uint32_t dead_slot);

void mxfs_v5_dlm_set_dead_node_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_dead_node_notify_fn fn,
                                      void *data);

/*
 * sess67 ASYMMETRIC MDS metadata-RPC (Phase 1, see ASYMMETRIC_MDS_PLAN.md).
 * Max concurrent in-flight metadata RPCs from this node (one per blocked
 * client VFS thread).  The unlink_visibility workload is sequential per node,
 * so a modest table suffices.
 */
#define MXFS_MD_MAX_PENDING 64

struct mxfs_md_req;
struct mxfs_md_reply;

/*
 * Server-side handler up-call into the XFS layer.  Invoked on the MDS when an
 * MXFS_MSG_MD_* request arrives.  name1/name2 point at the inline names parsed
 * from the request.  The handler runs the real XFS transaction and fills
 * *reply (rc + child ino/gen/attrs + post-op parent gen).  Must not block
 * indefinitely; runs in the peer recv-thread context.
 */
typedef void (*mxfs_v5_md_request_fn)(void *data,
                                      const struct mxfs_md_req *req,
                                      const char *name1, const char *name2,
                                      struct mxfs_md_reply *reply);

void mxfs_v5_dlm_set_md_request_fn(struct mxfs_v5_dlm *ctx,
                                   mxfs_v5_md_request_fn fn, void *data);

/*
 * Client-side: forward a metadata op to the MDS and block for the reply.
 * type = MXFS_MSG_MD_*; req carries the fixed fields; name1/name2 inline.
 * Returns 0 on a completed RPC (check reply->rc for the op result), or
 * negative errno on transport/timeout failure.
 */
int mxfs_v5_dlm_md_request(struct mxfs_v5_dlm *ctx, uint16_t type,
                           const struct mxfs_md_req *req,
                           const char *name1, const char *name2,
                           struct mxfs_md_reply *reply);

/* Resolve the MDS node_id (static v1: occupant of disklock slot 0). 0 if unknown. */
mxfs_node_id_t mxfs_v5_dlm_mds_node_id(struct mxfs_v5_dlm *ctx);

/* ─── Query ─── */

bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx);
/* sess67 ASYMMETRIC MDS (Phase 1) — see ASYMMETRIC_MDS_PLAN.md */
bool mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx);
int  mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx);

#endif /* MXFS_DLM_V5_MOUNT_H */
