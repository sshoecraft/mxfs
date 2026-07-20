/*
 * MXFS — Multinode XFS
 * v5 DLM→XFS Integration Shim
 *
 * Wires the portable DLM engine into kernel XFS v5.
 * Replaces dlm/mount.c from mxfs.1 (which used the custom cache layer).
 *
 * Phase 1: CAW transport lifecycle — init/shutdown, peer discovery.
 * Phase 2: Inode/AG lock hooks (stubs).
 * Phase 3: BAST flush callbacks (stubs).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/moduleparam.h>
#endif

#include "v5_mount.h"
#include "../pal/pal.h"   /* v0.3.110: for mxfs_sock_t / TCP DLM */
#include "../include/mxfs/mxfs_dlm.h"   /* DLM message types/structs */
#include "../include/mxfs/mxfs_ports.h"
#include "net2_wire.h"    /* NET2 step 1: wire-format static asserts must
                           * compile in the kernel build too (gate 1) */
#include "dlm.h"
#include "peer.h"

/*
 * v0.3.110 (sess26): module param to force DLM transport.
 * 0 = auto/use sb (default = CAW), 1 = force TCP.
 * Sess27 set to 1 to test TCP DLM path once fully implemented.
 */
#ifdef __KERNEL__
static int mxfs_force_transport;
module_param_named(force_transport, mxfs_force_transport, int, 0644);
MODULE_PARM_DESC(force_transport,
                 "Force DLM transport: 0=auto (default CAW), 1=TCP");

/* sess1 (ccloop 46efd8b6): A/B gate for the stale-HB evict-ring monotonic
 * consume fix (see the ROOT FIX note in disklock.c).  Param lives here
 * because disklock.c also builds user-mode. */
extern int mxfs_evict_ring_monotonic;
module_param_named(evict_ring_monotonic, mxfs_evict_ring_monotonic, int, 0644);
MODULE_PARM_DESC(evict_ring_monotonic,
                 "consume peer evict-rings only on forward head_seq (stale-HB replay guard); 1=on");
#endif

/*
 * sess39 (ccloop 4cb2d0a2) ROOT FIX for the 8/tcp dir_reuse_coherency loss.
 *
 * PROVEN ROOT (RULE 4, instrumented): under the N-node create storm a peer's
 * TCP connection transiently STALLS for several seconds (observed: all 7 peers
 * of one node drop at t=366.2s and reconnect at t=373s — a ~7s flap, the node
 * was alive throughout).  The v5 TCP disconnect handler
 * (v5_peer_disconnect_cb_tcp) reacted IMMEDIATELY: mxfs_dlm_purge_node() +
 * mxfs_lease_unregister_node() + v5_refresh_active_nodes() (8->7).  This
 * (a) makes the master FORGET the flapping node still holds dir EX, so the
 * next requester is granted a CONCURRENT EX (the flapping node never got a
 * BAST), and (b) remaps mastership for the duration of the flap (split brain).
 * When a dir modification races into that multi-second window a peer's dirent
 * is durably lost (the classic readdir=799).  This is the DLM-layer cause the
 * 37 prior sessions of dir-block read/write/release heuristics were chasing
 * downstream — the freshness tokens lie because the node genuinely still holds
 * a (now duplicate) EX grant.  Bypasses the careful stabilization/cooldown
 * machinery in libmxfs mount.c (that path is NOT used by the v5 TCP DLM).
 *
 * FIX: do NOT treat a TCP disconnect as immediate death.  Mark the peer
 * SUSPECT and let it reconnect (peers re-announce via discovery within ~2s).
 * A grace-checker thread declares death (the original purge+unregister+refresh)
 * only if the peer fails to reconnect within tcp_death_grace_ms.  A reconnect
 * (v5_peer_connect_cb_tcp) cancels the pending death.  Genuine node death is
 * still caught promptly (grace, well under the 62s disklock / 75s lease
 * windows and under the 120s DLM lock-wait), and the dead node's locks are
 * recovered exactly as before.  Set tcp_death_grace_ms=0 for the old
 * immediate-death behavior (A/B).
 */
static int mxfs_tcp_death_grace_ms = 40000;	/* sess45 (ccloop 4cb2d0a2): 15000->40000.  Under 8 VMs on one oversubscribed host, a CPU-starved-but-ALIVE node can stall >15s (no lease renewal, no TCP) and be FALSELY declared dead → its peers remaster → split-brain when it returns (8/tcp dir_reuse FLAP MASS loss).  A longer grace tolerates the starvation stall; genuine death is still caught (lease backstop + the rejoin self-fence below makes a returning node re-validate its grants). */
#ifdef __KERNEL__
module_param_named(tcp_death_grace_ms, mxfs_tcp_death_grace_ms, int, 0644);
MODULE_PARM_DESC(tcp_death_grace_ms,
                 "Grace window (ms) before a transiently-disconnected TCP "
                 "peer is declared dead (0=immediate, legacy)");
#endif

/*
 * sess39: membership-settle gate window (ms).  EX acquires are frozen for this
 * long after the active-node set changes, so the workload never runs while
 * mastership is still converging (cluster formation 1->N ramp, or a real
 * death) — the proven split-brain window.  Referenced by dlm.c
 * (dlm_membership_settling).  0 = gate disabled (legacy).
 */
int mxfs_memb_settle_ms = 20000;	/* sess45 (ccloop 4cb2d0a2): 6000->20000.  The 6s window let a node's LOCAL view go "stable" before it learned of a late-joining peer (lease propagation lag) during the 1->N formation ramp → it computed master=hash%count on a stale count → split-brain MASS loss.  20s outlasts formation + flap reconverge.  Multi-node only; single-node never gates. */
#ifdef __KERNEL__
module_param_named(memb_settle_ms, mxfs_memb_settle_ms, int, 0644);
MODULE_PARM_DESC(memb_settle_ms,
                 "Freeze EX grants for this many ms after a membership change "
                 "so mastership converges before exclusive work (0=off)");
#endif
#include "dlm_caw.h"
#include "disklock.h"
#include "discovery.h"
#include "lease.h"
#include "scsipr.h"
#include "journal.h"

/*
 * Instr gate for diagnostic probes — mirrors caw_instr_on() in dlm_caw.c.
 * mxfs_instr_enabled lives in the xfs overlay (xfs_mxfs_dlm.c) and is
 * linked into mxfs.ko alongside this file; user-mode dlm builds (no
 * overlay) compile the gate out.  Pure logging, no side effects.
 */
#ifdef __KERNEL__
extern int mxfs_instr_enabled;
#define vm_instr_on() (unlikely(mxfs_instr_enabled))
#else
#define vm_instr_on() (0)
#endif

/* ─── v5 DLM context ─── */

struct mxfs_v5_dlm {
    /* Identity */
    mxfs_node_id_t              node_id;
    uint8_t                     node_uuid[16];
    mxfs_volume_id_t            volume_id;
    uint8_t                     volume_uuid[16];

    /* Transport */
    int                         transport;
    struct mxfs_dlm_caw_ctx     *dlm_caw;
    /* v0.3.111 (sess27): TCP DLM fields for transport=TCP */
    struct mxfs_dlm_ctx         *dlm;            /* TCP DLM engine */
    struct mxfs_peer_ctx        *peer;           /* TCP peer manager */
    uint16_t                    dlm_port;        /* TCP port for DLM */
    uint16_t                    discovery_port;  /* UDP port for discovery */

    /* Subsystems */
    struct mxfs_scsipr_ctx      *scsipr;
    struct mxfs_disklock_ctx    *disklock;
    struct mxfs_discovery_ctx   *discovery;
    struct mxfs_lease_ctx       *lease;
    struct mxfs_journal_ctx     *journal;

    /* Device */
    mxfs_bdev_t                 *dev;

    /* Config */
    uint64_t                    disklock_offset;
    uint64_t                    journal_offset;
    uint32_t                    max_nodes;
    int                         node_slot;
    int                         max_dlm_lock_caw;   /* v5 sess33 */
    uint32_t                    lease_timeout_ms;   /* v0.5.0 dead-detect window, 0=default */

    /*
     * sess67 ASYMMETRIC MDS (Phase 1, see ASYMMETRIC_MDS_PLAN.md): one node
     * per filesystem owns the XFS log and runs ALL metadata transactions;
     * other nodes forward create/unlink/rename to it.  Static v1 rule: the
     * MDS is the node holding disklock slot 0 (the first mounter / mkfs node).
     * is_mds is computed once node_slot is claimed.  mds_node_slot is the
     * slot the MDS occupies (always 0 in v1); clients resolve slot->node_id
     * via discovery when the metadata-RPC wiring lands (Phase 1 step 4).
     */
    bool                        is_mds;
    int                         mds_node_slot;

    /* State */
    bool                        mounted;
    /* RULE-4 instrumentation (2026-07-14): latches true the first time
     * is_single_node() observes multi-node.  If it is ever observed true
     * AGAIN afterward, that is a real regression (not a hypothesis) and
     * gets logged — see mxfs_v5_dlm_is_single_node(). */
    bool                        ever_multi;
    /* sess9 (ccloop a864) shutdown withdrawal: set once when the owning
     * filesystem force-shuts-down.  A withdrawn ctx refuses every NEW lock
     * acquisition (inode + AG) so a dead FS cannot contend/hold cluster
     * locks it can never use (PROVEN r13 32/caw collapse: 27 shut-down
     * nodes' retry loops drove the hot dir slot's CAS gen 512->130k and
     * one acquired the dir EX 6 minutes post-shutdown, starving the
     * survivors).  The withdraw call also stops the disklock heartbeat,
     * so peers' dead-node purge reclaims whatever this node still holds. */
    bool                        withdrawn;

    /* BAST notification callback (Phase 3: lock caching) */
    mxfs_v5_bast_notify_fn      bast_notify_fn;
    void                        *bast_notify_data;

    /* Per-AG BAST notification callback (cached AG DLM) */
    mxfs_v5_ag_bast_notify_fn   ag_bast_notify_fn;
    void                        *ag_bast_notify_data;

    /* ICLUSTER BAST callback (ccloop 72513a13 sess3): receives the
     * CLUSTER BASE ino; the xfs mediating layer fans out to the covered
     * inodes.  Same signature as the per-inode callback. */
    mxfs_v5_bast_notify_fn      iclus_bast_notify_fn;
    void                        *iclus_bast_notify_data;

    /* Peer-joined notification callback — fired once on single→multi
     * transition so the XFS layer can flush dirty state to disk. */
    mxfs_v5_peer_joined_notify_fn   peer_joined_notify_fn;
    void                            *peer_joined_notify_data;

    /*
     * sess67 ASYMMETRIC MDS metadata-RPC (Phase 1, see ASYMMETRIC_MDS_PLAN.md).
     * Synchronous request/reply over the peer mesh: a client thread sends an
     * MXFS_MSG_MD_* request to the MDS and blocks until the matching
     * MXFS_MSG_MD_REPLY arrives (correlated by hdr.seq).  md_request_fn is the
     * server-side up-call into the XFS layer that runs the real transaction.
     */
    mxfs_mutex_t                    *md_rpc_lock;
    mxfs_cond_t                     *md_rpc_cond;
    uint32_t                        md_rpc_seq;
    struct mxfs_md_pending {
        bool                    in_use;
        bool                    done;
        uint32_t                seq;
        struct mxfs_md_reply    reply;
    } md_pending[MXFS_MD_MAX_PENDING];
    mxfs_v5_md_request_fn           md_request_fn;
    void                            *md_request_data;

    /* sess131 self-fence notification — fired once when the disklock
     * heartbeat detects the device was re-mkfs'd under this mount. */
    mxfs_v5_fence_notify_fn         fence_notify_fn;
    void                            *fence_notify_data;

    /* v0.5.0 dead-node notification — fired on the elected survivor
     * after a dead peer's locks are purged; triggers foreign-slice
     * replay of the dead node's XFS log slice. */
    mxfs_v5_dead_node_notify_fn     dead_node_notify_fn;
    void                            *dead_node_notify_data;

    /*
     * sess39 deferred TCP-death (transient-flap tolerance).  A TCP peer
     * disconnect marks the node SUSPECT here instead of declaring it dead
     * immediately; the tcp_death_thread declares death only if the peer
     * fails to reconnect within mxfs_tcp_death_grace_ms.  Indexed by
     * node_id % MXFS_MAX_NODES.  tcp_suspect_since==0 means not suspect.
     * Protected by tcp_suspect_lock.
     */
    mxfs_mutex_t                    *tcp_suspect_lock;
    uint64_t                        tcp_suspect_since[MXFS_MAX_NODES];
    mxfs_node_id_t                  tcp_suspect_node[MXFS_MAX_NODES];
    mxfs_thread_t                   *tcp_death_thread;
    int                             tcp_death_stop;
};

/* ─── Helpers ─── */

static mxfs_node_id_t uuid_to_node_id(const uint8_t *uuid)
{
    uint64_t hash = MXFS_FNV1A_64_INIT;
    int i;

    for (i = 0; i < 16; i++) {
        hash ^= uuid[i];
        hash *= MXFS_FNV1A_64_PRIME;
    }
    return (mxfs_node_id_t)(hash & 0xFFFFFFFF);
}

/* ─── TCP DLM callback bridges (v0.3.111 sess27) ─── */

/*
 * DLM->peer send: forward outgoing DLM control messages via TCP peer.
 */
static int v5_dlm_send_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx,
                              mxfs_node_id_t target,
                              const void *msg, size_t len)
{
    struct mxfs_v5_dlm *ctx = (struct mxfs_v5_dlm *)dlm_ctx->cb_data;

    if (!ctx || !ctx->peer)
        return -ENOTCONN;
    return mxfs_peer_send(ctx->peer, target, msg, len);
}

/*
 * Peer->DLM message dispatch: parse incoming TCP message and hand it
 * to mxfs_dlm_process_remote_*.  BAST messages received here mean a
 * peer wants a lock WE hold — dispatch to the v5 layer notify_fn so
 * the XFS code can flush+release.
 */
static void v5_peer_msg_cb_tcp(void *data, mxfs_node_id_t sender,
                               void *msg, size_t len)
{
    struct mxfs_v5_dlm *ctx = data;
    const struct mxfs_dlm_msg_hdr *hdr;

    if (!ctx || !ctx->dlm || len < sizeof(struct mxfs_dlm_msg_hdr))
        return;

    hdr = (const struct mxfs_dlm_msg_hdr *)msg;
    if (hdr->magic != MXFS_DLM_MAGIC)
        return;

    switch (hdr->type) {
    case MXFS_MSG_LOCK_REQ: {
        const struct mxfs_dlm_lock_req *req = msg;
        if (len >= sizeof(*req))
            mxfs_dlm_process_remote_request(ctx->dlm, sender,
                                            &req->resource,
                                            req->mode, req->flags,
                                            req->hdr.epoch);
        break;
    }
    case MXFS_MSG_LOCK_GRANT:
    case MXFS_MSG_LOCK_DENY: {
        const struct mxfs_dlm_lock_resp *resp = msg;
        if (len >= sizeof(*resp))
            mxfs_dlm_process_remote_grant(ctx->dlm, &resp->resource,
                                          resp->mode, resp->status,
                                          resp->hdr.epoch,
                                          resp->grant_gen,
                                          resp->handoff,
                                          resp->dir_epoch);
        break;
    }
    case MXFS_MSG_LOCK_RELEASE: {
        const struct mxfs_dlm_lock_release *rel = msg;
        if (len >= sizeof(*rel))
            mxfs_dlm_process_remote_release(ctx->dlm, sender,
                                            &rel->resource,
                                            rel->grant_gen);
        break;
    }
    case MXFS_MSG_LOCK_BAST: {
        const struct mxfs_dlm_bast *bast = msg;
        if (len < sizeof(*bast))
            break;
        /* Peer wants a lock we hold — invoke local notify path */
        if (bast->resource.type == MXFS_LTYPE_INODE && ctx->bast_notify_fn)
            ctx->bast_notify_fn(ctx->bast_notify_data,
                                bast->resource.ino,
                                bast->requested_mode);
        else if (bast->resource.type == MXFS_LTYPE_ICLUSTER &&
                 ctx->iclus_bast_notify_fn)
            ctx->iclus_bast_notify_fn(ctx->iclus_bast_notify_data,
                                      bast->resource.ino,
                                      bast->requested_mode);
        else if (bast->resource.type == MXFS_LTYPE_AG && ctx->ag_bast_notify_fn)
            ctx->ag_bast_notify_fn(ctx->ag_bast_notify_data,
                                   bast->resource.ag_number,
                                   bast->requested_mode);
        break;
    }
    case MXFS_MSG_NODE_LEAVE:
        if (ctx->dlm)
            mxfs_dlm_purge_node(ctx->dlm, sender);
        if (ctx->lease)
            mxfs_lease_unregister_node(ctx->lease, sender);
        break;
    default:
        break;
    }
}

/*
 * Refresh DLM active node list from the lease subsystem.  Called on
 * peer connect/disconnect.  Userspace dlm/mount.c stabilizes this
 * over a 3s window; we do the simpler immediate update here — sess27
 * priority is correctness, not low-churn membership.
 */
static void v5_refresh_active_nodes(struct mxfs_v5_dlm *ctx)
{
    mxfs_node_id_t nodes[MXFS_MAX_NODES];
    int count;

    if (!ctx || !ctx->dlm || !ctx->lease)
        return;

    count = mxfs_lease_get_active_nodes(ctx->lease, nodes, MXFS_MAX_NODES);
    /* lease registers self at index 0 with state=ACTIVE in mxfs_lease_create,
     * so the returned list already includes us — no append needed. */
    if (count > 0)
        mxfs_dlm_update_active_nodes(ctx->dlm, nodes, count);
}

/*
 * v0.6.0: membership-count beacon for the CAW transport.  On TCP the beacon
 * lives in mxfs_dlm_update_active_nodes (dlm.c) — but that engine is not
 * instantiated on CAW (ctx->dlm == NULL), so CAW membership (tracked by the
 * lease subsystem, fed by discovery announces + lease expiry) never printed
 * it and the harness convergence gate (run.sh prep greps the LATEST
 * "MXFS-MEMBERSHIP active_count") could not work.  Emit the identical line
 * from the lease view on every CAW membership change.  Low frequency
 * (join/death only).
 */
static void v5_membership_beacon_caw(struct mxfs_v5_dlm *ctx)
{
    mxfs_node_id_t nodes[MXFS_MAX_NODES];
    int count;

    if (!ctx || ctx->dlm || !ctx->lease)
        return;     /* TCP beacons via mxfs_dlm_update_active_nodes */

    count = mxfs_lease_get_active_nodes(ctx->lease, nodes, MXFS_MAX_NODES);
    if (count > 0)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: MXFS-MEMBERSHIP local=%u active_count=%d",
                     ctx->node_id, count);
}

/*
 * BAST callback for TCP DLM.  The DLM engine fires this when an
 * incompatible request arrives for a lock currently held by `owner`.
 *
 * If owner == our local node: dispatch to v5 notify_fn (XFS layer
 * flushes + releases).  Otherwise: forward MXFS_MSG_LOCK_BAST to
 * the holder via peer_send.
 */
static void v5_bast_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx,
                           const struct mxfs_resource_id *resource,
                           mxfs_node_id_t owner,
                           uint8_t requested_mode)
{
    struct mxfs_v5_dlm *ctx = (struct mxfs_v5_dlm *)dlm_ctx->cb_data;
    struct mxfs_dlm_bast bast;
    int retries = 3;
    int rc;

    if (!ctx)
        return;

    if (owner == ctx->node_id) {
        if (resource->type == MXFS_LTYPE_INODE && ctx->bast_notify_fn)
            ctx->bast_notify_fn(ctx->bast_notify_data,
                                resource->ino, requested_mode);
        else if (resource->type == MXFS_LTYPE_AG && ctx->ag_bast_notify_fn)
            ctx->ag_bast_notify_fn(ctx->ag_bast_notify_data,
                                   resource->ag_number, requested_mode);
        return;
    }

    if (!ctx->peer)
        return;

    memset(&bast, 0, sizeof(bast));
    bast.hdr.magic = MXFS_DLM_MAGIC;
    bast.hdr.version = MXFS_DLM_VERSION;
    bast.hdr.type = MXFS_MSG_LOCK_BAST;
    bast.hdr.length = sizeof(bast);
    bast.hdr.sender = ctx->node_id;
    bast.hdr.target = owner;
    bast.hdr.epoch = dlm_ctx->current_epoch;
    bast.resource = *resource;
    bast.requested_mode = requested_mode;

    do {
        rc = mxfs_peer_send(ctx->peer, owner, &bast, sizeof(bast));
        if (rc == 0) {
            /* sess5(a16ec5f2): AG-BAST wire visibility (run31 AG-0
             * starve) — pairs with P5N-AGBAST at the holder. */
            if (resource->type == MXFS_LTYPE_AG)
                pr_warn_ratelimited(
                    "mxfs: P5B-AGBAST-SEND ag=%u target=%u rc=0\n",
                    resource->ag_number, owner);
            return;
        }
        if (--retries > 0)
            mxfs_pal_sleep_ms(50);
    } while (retries > 0);
    if (resource->type == MXFS_LTYPE_AG)
        pr_warn_ratelimited(
            "mxfs: P5B-AGBAST-SEND ag=%u target=%u rc=%d FAILED\n",
            resource->ag_number, owner, rc);
}

/*
 * DLM membership-change callback.  Triggered when DLM resource-master
 * mapping shifts (purge_node, etc).  No-op for v5: we let the XFS
 * cache layer self-recover via per-resource BAST events.
 */
static void v5_membership_cb_tcp(struct mxfs_dlm_ctx *dlm_ctx)
{
    (void)dlm_ctx;
}

/*
 * Peer connection callbacks.  Fire on inbound/outbound TCP state
 * changes.  We refresh the DLM active-node list when membership shifts.
 */
/*
 * sess39: the original disconnect body — declare a TCP peer dead and recover
 * its locks.  Called either immediately (grace==0, legacy) or by the
 * grace-checker thread after the peer fails to reconnect within the grace
 * window.  Idempotent: a second call for an already-purged node is a no-op.
 */
static void v5_tcp_declare_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id)
{
    if (ctx->dlm)
        mxfs_dlm_purge_node(ctx->dlm, node_id);
    if (ctx->lease)
        mxfs_lease_unregister_node(ctx->lease, node_id);
    v5_refresh_active_nodes(ctx);
}

static void v5_peer_connect_cb_tcp(void *data, mxfs_node_id_t node_id)
{
    struct mxfs_v5_dlm *ctx = data;
    int slot = (int)(node_id % MXFS_MAX_NODES);

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: TCP peer %u connected", node_id);

    /* sess45 (ccloop 4cb2d0a2) SELF-FENCE on EVERY reconnect.  This MUST be
     * unconditional — NOT only inside the suspect-cancel branch below.  The
     * split-brain case is precisely a peer that was already DECLARED DEAD
     * (grace expired → tcp_suspect_since cleared) and only THEN reconnects: the
     * suspect-cancel branch is skipped (suspect_since==0), so without this an
     * already-evicted-but-returning node (or its peers) would resume EX work on
     * stale mastership.  Engaging the memb-settle EX freeze here for ANY
     * (re)connect makes both the returning node and its peers defer all EX work
     * until membership re-converges + the lock table re-syncs/purges; the
     * cached-EX verify (P-TCPEX-REACQ) then forces a slow-path re-acquire that
     * reloads, so no stale grant survives the rejoin.  Cheap: a timestamp. */
    if (ctx->dlm)
        ctx->dlm->last_memb_change_ms = mxfs_pal_time_ms();

    /* sess39: a reconnect within the grace window CANCELS a pending death —
     * the disconnect was a transient flap, not a node failure. */
    if (ctx->tcp_suspect_lock) {
        mxfs_pal_mutex_lock(ctx->tcp_suspect_lock);
        if (ctx->tcp_suspect_since[slot] != 0 &&
            ctx->tcp_suspect_node[slot] == node_id) {
            ctx->tcp_suspect_since[slot] = 0;
            /* sess45 (ccloop 4cb2d0a2) SELF-FENCE: a flap just resolved.  Hold
             * the LOCAL EX freeze for memb_settle_ms MORE after the reconnect so
             * membership globally reconverges (peers may have remastered during
             * the gap) before this node resumes exclusive dir/AG work — prevents
             * resuming as a stale master right after rejoining. */
            if (ctx->dlm)
                ctx->dlm->last_memb_change_ms = mxfs_pal_time_ms();
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: TCP peer %u reconnected — cancelling "
                         "pending death (transient flap absorbed); "
                         "EX frozen memb_settle_ms (reconverge)",
                         node_id);
        }
        mxfs_pal_mutex_unlock(ctx->tcp_suspect_lock);
    }

    if (ctx->lease)
        mxfs_lease_register_node(ctx->lease, node_id);
    v5_refresh_active_nodes(ctx);
}

static void v5_peer_disconnect_cb_tcp(void *data, mxfs_node_id_t node_id)
{
    struct mxfs_v5_dlm *ctx = data;
    int slot = (int)(node_id % MXFS_MAX_NODES);

    /*
     * sess39 ROOT FIX: a TCP disconnect under heavy load is usually a
     * transient stall, not a dead node.  Do NOT purge/unregister/refresh
     * immediately (that forgets the peer's held EX -> concurrent grant ->
     * dir lost-update).  Mark SUSPECT and let the grace-checker declare
     * death only if it fails to reconnect within the grace window.
     */
    if (mxfs_tcp_death_grace_ms > 0 && ctx->tcp_suspect_lock) {
        mxfs_pal_mutex_lock(ctx->tcp_suspect_lock);
        if (ctx->tcp_suspect_since[slot] == 0 ||
            ctx->tcp_suspect_node[slot] == node_id) {
            ctx->tcp_suspect_since[slot] = mxfs_pal_time_ms();
            ctx->tcp_suspect_node[slot] = node_id;
        }
        mxfs_pal_mutex_unlock(ctx->tcp_suspect_lock);
        /* sess45 (ccloop 4cb2d0a2) SELF-FENCE: a peer disconnect means the
         * cluster may be reconfiguring AROUND US — peers can mark us suspect and
         * (after their grace) declare us dead and remaster our resources while we
         * still believe we master them.  If we keep granting EX during that
         * window we are a stale second master → split-brain divergent RMW (the
         * 8/tcp dir_reuse MASS loss: a starved-but-alive node keeps writing after
         * peers evicted it).  Engage the LOCAL memb-settle EX freeze by stamping
         * last_memb_change_ms now, so this node defers all EX work until the
         * connectivity event resolves + memb_settle_ms of stability.  Symmetric
         * to the peers' suspect handling; covers the case our OWN active-node
         * view has NOT changed (deferred death) so the gate would otherwise stay
         * disengaged.  Cheap: just a timestamp; shared reads stay unblocked. */
        if (ctx->dlm)
            ctx->dlm->last_memb_change_ms = mxfs_pal_time_ms();
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: TCP peer %u disconnected — deferring death "
                     "%d ms (transient-flap tolerance); EX frozen (self-fence)",
                     node_id, mxfs_tcp_death_grace_ms);
        return;
    }

    /* Legacy immediate-death behavior (grace==0). */
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: TCP peer %u disconnected", node_id);
    v5_tcp_declare_dead(ctx, node_id);
}

/*
 * sess39 grace-checker thread.  Polls the suspect table; for each node that
 * has been suspect (TCP-disconnected) longer than mxfs_tcp_death_grace_ms
 * without reconnecting, declares it dead (purge + recover).  Cancellation on
 * reconnect happens in v5_peer_connect_cb_tcp.
 */
static void v5_tcp_death_worker_fn(void *arg)
{
    struct mxfs_v5_dlm *ctx = arg;

    while (!ctx->tcp_death_stop) {
        int i;
        uint64_t now;

        mxfs_pal_sleep_ms(500);
        if (ctx->tcp_death_stop)
            break;
        if (!ctx->tcp_suspect_lock)
            continue;

        now = mxfs_pal_time_ms();
        for (i = 0; i < MXFS_MAX_NODES; i++) {
            mxfs_node_id_t dead = 0;

            mxfs_pal_mutex_lock(ctx->tcp_suspect_lock);
            if (ctx->tcp_suspect_since[i] != 0 &&
                (now - ctx->tcp_suspect_since[i]) >=
                        (uint64_t)mxfs_tcp_death_grace_ms) {
                dead = ctx->tcp_suspect_node[i];
                ctx->tcp_suspect_since[i] = 0;
            }
            mxfs_pal_mutex_unlock(ctx->tcp_suspect_lock);

            if (dead != 0) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: TCP peer %u did not reconnect within "
                             "%d ms — declaring dead, recovering locks",
                             dead, mxfs_tcp_death_grace_ms);
                v5_tcp_declare_dead(ctx, dead);
            }
        }
    }
}

/* ─── Callbacks ─── */

/*
 * ccloop 72513a13 sess2: liveness oracle for the CAW wait-timeout
 * extension (mxfs_dlm_caw_set_holders_alive_fn).  slot_mask bit i =
 * heartbeat slot i (CAW holder bitmaps and disklock share the 0-63
 * slot space).  True iff EVERY set slot is provably alive per the
 * disklock heartbeat tracker — an advisory cross-thread read; the
 * caller re-asks every poll round, so one-sample staleness is fine.
 */
static bool v5_caw_holders_alive(void *data, uint64_t slot_mask)
{
    struct mxfs_v5_dlm *ctx = data;
    int slot;

    if (!ctx || !ctx->disklock || !slot_mask)
        return false;
    for (slot = 0; slot < 64; slot++) {
        if (!(slot_mask & (1ULL << slot)))
            continue;
        if (!mxfs_disklock_slot_live(ctx->disklock, slot))
            return false;
    }
    return true;
}

static void v5_bast_cb(struct mxfs_dlm_ctx *dlm_ctx,
                        const struct mxfs_resource_id *resource,
                        mxfs_node_id_t owner,
                        uint8_t requested_mode)
{
    /*
     * The DLM context pointer stored by mxfs_dlm_caw_set_bast_cb
     * is our mxfs_v5_dlm struct.
     */
    struct mxfs_v5_dlm *ctx = (struct mxfs_v5_dlm *)dlm_ctx;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "v5_bast: type=%u ino=%llu ag=%u mode=%u",
                 resource->type,
                 (unsigned long long)resource->ino,
                 resource->ag_number, requested_mode);

    /* Dispatch inode BASTs to the XFS-layer cache handler */
    if (resource->type == MXFS_LTYPE_INODE && ctx->bast_notify_fn) {
        ctx->bast_notify_fn(ctx->bast_notify_data,
                            resource->ino, requested_mode);
    }

    /* Dispatch AG BASTs to the cached-AG handler */
    if (resource->type == MXFS_LTYPE_AG && ctx->ag_bast_notify_fn) {
        ctx->ag_bast_notify_fn(ctx->ag_bast_notify_data,
                               resource->ag_number, requested_mode);
    }

    /* ICLUSTER BAST: hand the cluster BASE ino to the fan-out handler */
    if (resource->type == MXFS_LTYPE_ICLUSTER && ctx->iclus_bast_notify_fn) {
        ctx->iclus_bast_notify_fn(ctx->iclus_bast_notify_data,
                                  resource->ino, requested_mode);
    }
}

static void v5_discovery_peer_cb(void *data,
                                  const struct mxfs_discovery_announce *ann)
{
    struct mxfs_v5_dlm *ctx = data;

    if (ann->node_id == ctx->node_id)
        return;

    /* v0.3.111 sess27: discovery announces fire every ~500ms.  Dedup
     * here so we don't repeatedly flush+register the same peer.  The
     * lease subsystem handles reaffirmation via UDP renewals; we only
     * need to react to the *first* sight of a peer. */
    if (ctx->lease && mxfs_lease_has_node(ctx->lease, ann->node_id)) {
        /* still ensure peer is connected at TCP level */
        if (ctx->peer && !mxfs_peer_is_connected(ctx->peer, ann->node_id)) {
            char host[64];
            memcpy(host, ann->hostname, sizeof(host));
            host[sizeof(host) - 1] = '\0';
            mxfs_peer_add(ctx->peer, ann->node_id, ann->node_uuid,
                           host, ann->tcp_port);
            if (ctx->node_id < ann->node_id)
                mxfs_peer_connect(ctx->peer, ann->node_id);
            else
                mxfs_peer_connect_force(ctx->peer, ann->node_id);
        }
        return;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: peer discovered: node_id=%u hostname=%.64s",
                 ann->node_id, ann->hostname);

    if (ctx->lease)
        mxfs_lease_register_node(ctx->lease, ann->node_id);
    v5_membership_beacon_caw(ctx);     /* v0.6.0: no-op on TCP */

    /*
     * If we are about to leave single-node mode, flush XFS dirty state
     * to disk BEFORE the DLM layer starts honouring cross-node locks.
     * In single-node mode XFS freely allocates clusters in memory
     * without forcing them to disk; once a peer appears, those clusters
     * must be on-disk or the peer (and this node's own reload path)
     * will read all-zero cluster content.
     */
    if (ctx->dlm_caw && ctx->dlm_caw->single_node &&
        ctx->peer_joined_notify_fn) {
        ctx->peer_joined_notify_fn(ctx->peer_joined_notify_data);
    }

    if (ctx->dlm_caw)
        mxfs_dlm_caw_set_single_node(ctx->dlm_caw, false);

    /* TCP transport: register peer and connect (lower-ID node initiates,
     * higher-ID falls back to forced connect for asymmetric multicast).
     *
     * CRITICAL: when transitioning out of single-node mode, fire
     * peer_joined_notify_fn FIRST so XFS flushes dirty in-memory state
     * to disk BEFORE update_active_nodes wipes our DLM lock table.
     * Without this, AG locks held in single-node mode become "phantom"
     * holds — XFS perag still has pag_dlm_cached=true but the DLM has
     * no record, leading to indefinite ETIMEDOUT when peers request
     * the AG and our BAST chain has no lock entry to release.
     */
    if (ctx->peer) {
        char host[64];
        int add_rc;
        bool was_single;

        was_single = ctx->dlm ? mxfs_dlm_is_single_node(ctx->dlm) : false;
        if (was_single && ctx->peer_joined_notify_fn) {
            ctx->peer_joined_notify_fn(ctx->peer_joined_notify_data);
        }

        memcpy(host, ann->hostname, sizeof(host));
        host[sizeof(host) - 1] = '\0';

        add_rc = mxfs_peer_add(ctx->peer, ann->node_id, ann->node_uuid,
                                host, ann->tcp_port);
        (void)add_rc;
        if (ctx->node_id < ann->node_id) {
            mxfs_peer_connect(ctx->peer, ann->node_id);
        } else if (!mxfs_peer_is_connected(ctx->peer, ann->node_id)) {
            mxfs_peer_connect_force(ctx->peer, ann->node_id);
        }
        v5_refresh_active_nodes(ctx);
    }
}

/*
 * sess131 self-fence: the disklock heartbeat thread found the on-disk MXFS
 * super no longer matches our volume (device re-mkfs'd under this live
 * mount).  Relay to the XFS layer, which force-shuts-down the filesystem.
 * The heartbeat thread has already stopped writing.
 */
static void v5_self_fence_cb(void *data)
{
    struct mxfs_v5_dlm *ctx = data;

    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P131-SELF-FENCE node %u: volume identity changed "
                 "under live mount — forcing filesystem shutdown",
                 ctx->node_id);
    if (ctx->fence_notify_fn)
        ctx->fence_notify_fn(ctx->fence_notify_data);
}

static void v5_lease_expire_cb(void *data, mxfs_node_id_t dead_node)
{
    struct mxfs_v5_dlm *ctx = data;
    int dead_slot = -1;

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: node %u lease expired — purging locks", dead_node);

    if (ctx->disklock) {
        dead_slot = mxfs_disklock_find_node_slot(ctx->disklock, dead_node);
        if (dead_slot >= 0 && ctx->dlm_caw)
            mxfs_dlm_caw_purge_node(ctx->dlm_caw, (uint8_t)dead_slot);
        mxfs_disklock_purge_node(ctx->disklock, dead_node);
    }

    if (ctx->dlm) {
        mxfs_dlm_purge_node(ctx->dlm, dead_node);
        v5_refresh_active_nodes(ctx);
    }
    v5_membership_beacon_caw(ctx);     /* v0.6.0: no-op on TCP */

    /*
     * v0.5.0 foreign-slice replay election.  The dead node's
     * fsync-acknowledged metadata may exist only in its per-node XFS log
     * slice; one survivor must replay it NOW or readers serve stale data
     * until some future mount claims the slice.  Lowest live heartbeat
     * slot wins; replay is LSN-gated/idempotent, so a divergent election
     * view merely duplicates work.  This runs in the heartbeat thread —
     * the notify body queues work and returns.
     */
    if (ctx->disklock && dead_slot >= 0 && ctx->dead_node_notify_fn) {
        int low = mxfs_disklock_lowest_live_slot(ctx->disklock, dead_slot);

        if (low >= 0 && low == ctx->disklock->local_slot) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: elected (slot %d) to replay dead node %u's "
                         "log slice %d", low, dead_node, dead_slot);
            ctx->dead_node_notify_fn(ctx->dead_node_notify_data,
                                     (uint32_t)dead_slot);
        } else {
            mxfs_pal_log(MXFS_LOG_INFO,
                         "mxfs: not elected for dead-slice replay "
                         "(lowest live slot %d, local %d)",
                         low, ctx->disklock->local_slot);
        }
    }
}

/* ─── Init ─── */

struct mxfs_v5_dlm *mxfs_v5_dlm_init(const struct mxfs_v5_dlm_opts *opts)
{
    struct mxfs_v5_dlm *ctx;
    int ret;
    int node_slot;
    uint64_t dead_mask;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));

    ctx->transport = opts->transport;
#ifdef __KERNEL__
    if (mxfs_force_transport == 1) {
        ctx->transport = MXFS_V5_TRANSPORT_TCP;
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: force_transport=1 → TCP transport");
    }
#endif
    ctx->disklock_offset = opts->disklock_offset;
    ctx->journal_offset = opts->journal_offset;
    ctx->max_nodes = opts->max_nodes;
    ctx->max_dlm_lock_caw = opts->max_dlm_lock_caw;
    ctx->lease_timeout_ms = opts->lease_timeout_ms;
    memcpy(ctx->volume_uuid, opts->volume_uuid, 16);
    ctx->volume_id = mxfs_uuid_to_volume_id(opts->volume_uuid, 16);

    /* Generate node UUID */
    mxfs_pal_get_random_bytes(ctx->node_uuid, 16);
    ctx->node_uuid[6] = (ctx->node_uuid[6] & 0x0F) | 0x40;
    ctx->node_uuid[8] = (ctx->node_uuid[8] & 0x3F) | 0x80;
    ctx->node_id = uuid_to_node_id(ctx->node_uuid);

    /* Wrap the XFS-owned block device for DLM I/O (shared, not re-opened) */
    ctx->dev = mxfs_pal_bdev_wrap(opts->bdev);
    if (!ctx->dev) {
        mxfs_pal_log(MXFS_LOG_ERR, "mxfs: DLM failed to wrap block device");
        goto err_free;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: DLM init: node_id=%u transport=%s",
                 ctx->node_id,
                 ctx->transport == MXFS_V5_TRANSPORT_CAW ? "caw" : "tcp");

    if (ctx->transport != MXFS_V5_TRANSPORT_CAW &&
        ctx->transport != MXFS_V5_TRANSPORT_TCP) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: unsupported transport=%d", ctx->transport);
        goto err_free;
    }

    /*
     * v0.3.111 (sess27): TCP DLM transport.  Bypasses kernel SCSI CAW
     * entirely (root cause #2 of sess26 — kernel scsi_execute_cmd path
     * reports CAS-success without persisting writes under stress).
     *
     * TCP path: peer subsystem owns the listen socket + per-peer recv
     * threads; DLM engine owns the lock state machine + master election;
     * we wire DLM->peer (send_cb), peer->DLM (peer_msg_cb), and
     * DLM->XFS (bast_cb) here.  Discovery announcements register peers
     * dynamically via v5_discovery_peer_cb.
     */
    if (ctx->transport == MXFS_V5_TRANSPORT_TCP) {
        uint16_t dlm_port = opts->dlm_port ? opts->dlm_port : MXFS_PORT_DLM;
        uint16_t disc_port = opts->discovery_port ? opts->discovery_port : MXFS_PORT_DISCOVERY;

        ctx->dlm = mxfs_dlm_create(ctx->node_id);
        if (!ctx->dlm) {
            mxfs_pal_log(MXFS_LOG_ERR, "mxfs: TCP DLM create failed");
            goto err_free;
        }

        ctx->dlm->send_cb = v5_dlm_send_cb_tcp;
        ctx->dlm->bast_cb = v5_bast_cb_tcp;
        ctx->dlm->membership_cb = v5_membership_cb_tcp;
        ctx->dlm->cb_data = ctx;

        ctx->peer = mxfs_peer_init(ctx->node_id, ctx->node_uuid,
                                   dlm_port, ctx->volume_id);
        if (!ctx->peer) {
            mxfs_pal_log(MXFS_LOG_ERR, "mxfs: peer init failed");
            mxfs_dlm_destroy(ctx->dlm);
            ctx->dlm = NULL;
            goto err_free;
        }
        mxfs_peer_set_msg_cb(ctx->peer, v5_peer_msg_cb_tcp, ctx);
        mxfs_peer_set_disconnect_cb(ctx->peer, v5_peer_disconnect_cb_tcp, ctx);
        mxfs_peer_set_connect_cb(ctx->peer, v5_peer_connect_cb_tcp, ctx);

        /* sess39: deferred TCP-death grace-checker.  Created before peer
         * start so any disconnect that fires immediately is handled. */
        ctx->tcp_suspect_lock = mxfs_pal_mutex_create();
        ctx->tcp_death_stop = 0;
        if (ctx->tcp_suspect_lock)
            ctx->tcp_death_thread =
                mxfs_pal_thread_create(v5_tcp_death_worker_fn, ctx);

        ret = mxfs_peer_start(ctx->peer);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: peer start failed: %d", ret);
            mxfs_peer_shutdown(ctx->peer);
            ctx->peer = NULL;
            mxfs_dlm_destroy(ctx->dlm);
            ctx->dlm = NULL;
            goto err_free;
        }

        /* MXFS (2-node tcp): SCSI PR registration is a PREREQUISITE for the
         * SCST target to ACCEPT COMPARE AND WRITE — the disklock slot-claim
         * is a CAW (opcode 0x89).  The CAW-transport path registers +
         * reserves PR before claim_slot (and treats a claim failure as
         * fatal, so it must succeed there); the TCP path historically
         * skipped PR entirely, so the target rejected the slot-claim CAW with
         * ILLEGAL REQUEST / INVALID FIELD IN CDB (sense 0x5/0x24) ->
         * claim_slot returned -EIO -> ctx->node_slot stayed 0 on EVERY node.
         * With node_slot==0 cluster-wide, AG affinity (node_slot %% agcount)
         * sent ALL nodes' inode allocations into AG 0, so concurrent
         * cross-node create/free in one shared dir corrupted AG 0's inobt
         * freemask -> EFSCORRUPTED FS shutdown (the dlm_fairness wedge).
         * Register PR here too so the slot-claim CAW is accepted and each
         * node claims a UNIQUE slot / preferred AG.  Type-5 (WRITE EXCLUSIVE
         * - REGISTRANTS ONLY) lets every registrant do I/O, so this is safe
         * for all nodes. */
        if (!ctx->scsipr) {
            ctx->scsipr = mxfs_scsipr_create(ctx->dev, "mxfs", ctx->node_id);
            if (ctx->scsipr) {
                if (mxfs_scsipr_register(ctx->scsipr)) {
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: TCP SCSI PR register failed — "
                                 "slot-claim CAW may be rejected");
                    mxfs_scsipr_destroy(ctx->scsipr);
                    ctx->scsipr = NULL;
                } else {
                    mxfs_scsipr_reserve(ctx->scsipr);
                }
            }
        }

        /* Disklock heartbeat still useful for slot identity + dead-node
         * detection (purges TCP DLM locks of crashed nodes that the TCP
         * disconnect callback never fires for, e.g. kernel panic). */
        if (ctx->disklock_offset > 0) {
            ctx->disklock = mxfs_disklock_create(ctx->dev,
                                                  ctx->disklock_offset,
                                                  ctx->node_id);
            if (ctx->disklock) {
                mxfs_disklock_set_fs_identity(ctx->disklock,
                                              ctx->volume_uuid);
                mxfs_disklock_set_fence_cb(ctx->disklock,
                                           v5_self_fence_cb, ctx);
                mxfs_disklock_set_dead_timeout_ms(ctx->disklock,
                                                  ctx->lease_timeout_ms);
                node_slot = mxfs_disklock_claim_slot(ctx->disklock);
                if (node_slot >= 0) {
                    ctx->node_slot = node_slot;
                } else {
                    /* Defense-in-depth: a failed CAW claim must NEVER leave
                     * every node at slot 0 (all nodes -> AG 0 -> inobt
                     * corruption).  Derive a deterministic per-node slot from
                     * node_id so distinct nodes still land on distinct
                     * preferred AGs even if the slot-claim CAW is unavailable. */
                    ctx->node_slot =
                        (int)(ctx->node_id % MXFS_DISKLOCK_HB_SLOTS);
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: claim_slot failed (%d) — fallback "
                                 "node_slot=%d derived from node_id %u",
                                 node_slot, ctx->node_slot, ctx->node_id);
                }
                /* sess67 ASYMMETRIC MDS: static v1 — MDS = disklock slot 0. */
                ctx->mds_node_slot = 0;
                ctx->is_mds = (ctx->node_slot == ctx->mds_node_slot);
                ret = mxfs_disklock_start_heartbeat(ctx->disklock);
                if (ret)
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: TCP+disklock heartbeat start failed: %d",
                                 ret);
                mxfs_disklock_set_expire_cb(ctx->disklock,
                                             v5_lease_expire_cb, ctx);
            }
        }

        /* Discovery: announce ourselves so peers discover us, and listen
         * for peer announcements via v5_discovery_peer_cb. */
        ctx->discovery = mxfs_discovery_create(
            ctx->node_id, ctx->node_uuid, ctx->volume_uuid,
            ctx->volume_id,
            dlm_port,
            "239.66.83.1",
            disc_port,
            false);
        if (ctx->discovery) {
            mxfs_discovery_set_peer_cb(ctx->discovery,
                                        v5_discovery_peer_cb, ctx);
            /* transport=1 (TCP) so peer announcement matches */
            mxfs_discovery_set_transport(ctx->discovery, 1);
            ret = mxfs_discovery_start(ctx->discovery);
            if (ret)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: discovery start failed: %d", ret);
        }

        /* Lease — node death detection via UDP keepalive */
        ctx->lease = mxfs_lease_create(ctx->node_id, ctx->volume_uuid,
                                        "239.66.83.1", MXFS_PORT_LEASE_V5, false);
        if (ctx->lease) {
            mxfs_lease_set_expire_cb(ctx->lease, v5_lease_expire_cb, ctx);
            ret = mxfs_lease_start(ctx->lease);
            if (ret)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: lease start failed: %d", ret);
        }

        ctx->mounted = true;

        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: TCP DLM initialized (port=%u node_id=%u slot=%d)",
                     dlm_port, ctx->node_id, ctx->node_slot);
        return ctx;
    }

    if (ctx->disklock_offset == 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: CAW transport requires disklock region");
        goto err_free;
    }

    /* 1. SCSI PR.  On CAW this is LOAD-BEARING, not optional: the cluster
     * runs under a WRITE-EXCLUSIVE-REGISTRANTS-ONLY reservation, so a node
     * whose registration failed still mounts "successfully" and then EVERY
     * write returns EBADE the moment any peer takes the reservation —
     * proven at 4/caw formation, where a UA-consumed REGISTER left node1
     * silently unfenced-out of the whole run.  A device with no PR support
     * at all (-EOPNOTSUPP → register returns 0) keeps the old best-effort
     * behavior; an actual register FAILURE aborts the mount so the error
     * is visible at mount time instead of as unattributable write EIO. */
    ctx->scsipr = mxfs_scsipr_create(ctx->dev, "mxfs", ctx->node_id);
    if (ctx->scsipr) {
        ret = mxfs_scsipr_register(ctx->scsipr);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: CAW mount: SCSI PR register failed (%d) — "
                         "refusing to join unfenced", ret);
            goto err_scsipr;
        }
        mxfs_scsipr_reserve(ctx->scsipr);
    }

    /* 2. Disklock — claim heartbeat slot */
    ctx->disklock = mxfs_disklock_create(ctx->dev, ctx->disklock_offset,
                                          ctx->node_id);
    if (!ctx->disklock) {
        mxfs_pal_log(MXFS_LOG_ERR, "mxfs: disklock create failed");
        goto err_scsipr;
    }

    /* sess131: install generation identity BEFORE claim/heartbeat so the
     * claim record carries fs_gen and pre-mkfs ghost records are filtered
     * from the very first scan; fence_cb fires if the device is re-mkfs'd
     * under this mount. */
    mxfs_disklock_set_fs_identity(ctx->disklock, ctx->volume_uuid);
    mxfs_disklock_set_fence_cb(ctx->disklock, v5_self_fence_cb, ctx);
    mxfs_disklock_set_dead_timeout_ms(ctx->disklock, ctx->lease_timeout_ms);

    node_slot = mxfs_disklock_claim_slot(ctx->disklock);
    if (node_slot < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: disklock claim_slot failed: %d", node_slot);
        goto err_disklock;
    }
    ctx->node_slot = node_slot;

    /* sess67 ASYMMETRIC MDS: static v1 — MDS = disklock slot 0. */
    ctx->mds_node_slot = 0;
    ctx->is_mds = (ctx->node_slot == ctx->mds_node_slot);
    mxfs_pal_log(MXFS_LOG_WARN, "mxfs: MDS-IDENTITY node_slot=%d is_mds=%d (asymmetric Phase1)",
                 ctx->node_slot, ctx->is_mds);

    /* 3. CAW DLM engine */
    ctx->dlm_caw = mxfs_dlm_caw_create(ctx->dev, ctx->disklock_offset,
                                          ctx->node_id, (uint8_t)node_slot,
                                          ctx->volume_uuid,
                                          ctx->max_dlm_lock_caw);
    if (!ctx->dlm_caw) {
        mxfs_pal_log(MXFS_LOG_ERR, "mxfs: CAW DLM create failed");
        goto err_disklock;
    }

    mxfs_dlm_caw_set_bast_cb(ctx->dlm_caw, v5_bast_cb, ctx);
    /* ccloop 72513a13 sess2: liveness oracle for the CAW wait-timeout
     * extension — CAW holder bits and disklock heartbeat slots share the
     * same 0-63 slot space. */
    mxfs_dlm_caw_set_holders_alive_fn(ctx->dlm_caw, v5_caw_holders_alive,
                                       ctx);

    /* 4. Purge our own stale locks (in case a previous instance of us
     * died while holding the slot and we just re-claimed it). */
    dead_mask = 1ULL << node_slot;
    {
        int npurged = mxfs_dlm_caw_purge_dead_nodes(ctx->dlm_caw, dead_mask);
        if (npurged > 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: cleaned %d stale own-slot lock entries", npurged);
    }

    /* 5. Start CAW DLM */
    ret = mxfs_dlm_caw_start(ctx->dlm_caw);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR, "mxfs: CAW DLM start failed: %d", ret);
        goto err_caw;
    }
    mxfs_dlm_caw_set_single_node(ctx->dlm_caw, true);

    /* 6. Disklock heartbeat — start BEFORE the cross-instance stale
     * purge below so concurrent peer mounts see our heartbeat advance
     * and don't mistake us for dead. */
    ret = mxfs_disklock_start_heartbeat(ctx->disklock);
    if (ret)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: disk heartbeat start failed: %d", ret);
    mxfs_disklock_set_expire_cb(ctx->disklock, v5_lease_expire_cb, ctx);

    /*
     * 6.5. Cross-instance stale-slot purge.
     *
     * Snapshot all OTHER ACTIVE heartbeat slots, wait long enough for
     * an alive node to write a fresh heartbeat (5 × interval = 10 s),
     * rescan: any slot whose timestamp didn't advance is a previous
     * crashed instance.  Purge its CAW bits — otherwise they're stuck
     * orphan forever (lease-expiry only fires for peers we currently
     * see; previous-instance bits never get cleaned).  Without this
     * a previous mount that held root_dir EX deadlocks the next mount
     * indefinitely on first cross-node access.
     *
     * timestamp_ms is from ktime_get_boottime_ns which resets on
     * reboot, so absolute-age comparison is unsound across crashes —
     * snapshot+wait+rescan is the only reliable detector.
     */
    {
        uint64_t stale_mask = 0;
        int npurged;

        mxfs_disklock_get_stale_slot_mask(ctx->disklock,
                                          MXFS_DISKLOCK_HB_INTERVAL_MS * 5,
                                          node_slot, &stale_mask);
        if (stale_mask) {
            npurged = mxfs_dlm_caw_purge_dead_nodes(ctx->dlm_caw, stale_mask);
            if (npurged > 0)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: cleaned %d stale cross-instance lock entries (mask 0x%llx)",
                             npurged, (unsigned long long)stale_mask);
        }
    }

    /* 7. Discovery */
    ctx->discovery = mxfs_discovery_create(
        ctx->node_id, ctx->node_uuid, ctx->volume_uuid,
        ctx->volume_id,
        opts->dlm_port ? opts->dlm_port : MXFS_PORT_DLM,
        "239.66.83.1",
        opts->discovery_port ? opts->discovery_port : MXFS_PORT_DISCOVERY,
        false);
    if (ctx->discovery) {
        mxfs_discovery_set_peer_cb(ctx->discovery,
                                    v5_discovery_peer_cb, ctx);
        mxfs_discovery_set_transport(ctx->discovery, 0);
        ret = mxfs_discovery_start(ctx->discovery);
        if (ret)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: discovery start failed: %d", ret);
    }

    /* 8. Lease */
    ctx->lease = mxfs_lease_create(ctx->node_id, ctx->volume_uuid,
                                    "239.66.83.1", MXFS_PORT_LEASE_V5, false);
    if (ctx->lease) {
        mxfs_lease_set_expire_cb(ctx->lease, v5_lease_expire_cb, ctx);
        ret = mxfs_lease_start(ctx->lease);
        if (ret)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: lease start failed: %d", ret);
    }

    /* 9. Journal */
    ctx->journal = mxfs_journal_create(ctx->node_id);
    if (ctx->journal && ctx->journal_offset > 0) {
        mxfs_journal_open(ctx->journal, ctx->dev, ctx->journal_offset);
        mxfs_journal_claim_slot(ctx->journal);
    }

    ctx->mounted = true;

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: DLM initialized (CAW, slot=%d, node_id=%u)",
                 node_slot, ctx->node_id);

    return ctx;

err_caw:
    mxfs_dlm_caw_destroy(ctx->dlm_caw);
err_disklock:
    mxfs_disklock_destroy(ctx->disklock);
err_scsipr:
    if (ctx->scsipr) {
        mxfs_scsipr_unregister(ctx->scsipr);
        mxfs_scsipr_destroy(ctx->scsipr);
    }
    mxfs_pal_bdev_close_clone(ctx->dev);
err_free:
    mxfs_pal_free(ctx);
    return NULL;
}

/* ─── Shutdown ─── */

/*
 * sess9 (ccloop a864): the owning filesystem has been FORCE-SHUT-DOWN but is
 * still mounted (unmount comes later, from userspace).  Withdraw from the
 * cluster NOW:
 *   - fence every new lock acquisition (inode + AG) via ctx->withdrawn — a
 *     dead FS's retry loops must not contend slots or win tenures it can
 *     never use (r13 32/caw collapse: a shut-down node acquired the hot dir
 *     EX 6 minutes post-shutdown; 27 dead nodes' churn starved the living);
 *   - stop OUR disklock heartbeat so peers' existing dead-node detection
 *     (fire_dead -> expire_cb -> purge) reclaims whatever we still hold —
 *     the same well-tested path that handles a crashed node.  We do NOT
 *     release_all here: that would write slots concurrently with still-
 *     running lock users on this node (unmount quiesces first; we can't).
 * Sleeps (heartbeat thread join, <=5s) — call from process context (the
 * xfs-side hook defers to a workqueue).
 */
void mxfs_v5_dlm_shutdown_withdraw(struct mxfs_v5_dlm *ctx)
{
    if (!ctx || ctx->withdrawn)
        return;

    ctx->withdrawn = true;
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P-WITHDRAW — FS shut down; leaving cluster DLM "
                 "(acquires fenced, heartbeat stopping; peers will purge "
                 "our slots)");
    /* sess10 (ccloop 72513a13): a withdrawn node's FS can never serve
     * another BAST, but its grants stay in every master's table — peers'
     * conflicting requests then starve to terminal -ETIMEDOUT and force-
     * shut down too (the 32/tcp fio cascade: 1 dirty-cancel + 5 rc=-110
     * dominoes on ino=128).  Wire-release everything we hold FIRST so
     * peers promote immediately; the dead FS has no valid cache to
     * protect.  TCP path only — on CAW the disklock slot purge (below,
     * via heartbeat stop) already clears our on-disk holder bits. */
    if (ctx->dlm)
        mxfs_dlm_withdraw_release_all(ctx->dlm);
    if (ctx->disklock)
        mxfs_disklock_stop_heartbeat(ctx->disklock);
}

bool mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx)
{
    return ctx && ctx->withdrawn;
}

void mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx)
{
    if (!ctx)
        return;

    mxfs_pal_log(MXFS_LOG_INFO, "mxfs: DLM shutting down");
    ctx->mounted = false;

    if (ctx->dlm)
        ctx->dlm->shutting_down = true;

    /* sess39: stop the deferred-TCP-death grace-checker before tearing down
     * the lease/dlm it touches. */
    if (ctx->tcp_death_thread) {
        ctx->tcp_death_stop = 1;
        mxfs_pal_thread_join(ctx->tcp_death_thread);
        ctx->tcp_death_thread = NULL;
    }
    if (ctx->tcp_suspect_lock) {
        mxfs_pal_mutex_destroy(ctx->tcp_suspect_lock);
        ctx->tcp_suspect_lock = NULL;
    }

    if (ctx->dlm_caw)
        mxfs_dlm_caw_release_all(ctx->dlm_caw);
    if (ctx->dlm)
        mxfs_dlm_release_all(ctx->dlm);

    if (ctx->journal) {
        mxfs_journal_release_slot(ctx->journal);
        mxfs_journal_destroy(ctx->journal);
    }

    if (ctx->lease) {
        mxfs_lease_stop(ctx->lease);
        mxfs_lease_destroy(ctx->lease);
    }

    if (ctx->discovery) {
        mxfs_discovery_stop(ctx->discovery);
        mxfs_discovery_destroy(ctx->discovery);
    }

    if (ctx->disklock) {
        mxfs_disklock_stop_heartbeat(ctx->disklock);
        mxfs_disklock_destroy(ctx->disklock);
    }

    if (ctx->dlm_caw) {
        mxfs_dlm_caw_stop(ctx->dlm_caw);
        mxfs_dlm_caw_destroy(ctx->dlm_caw);
    }

    if (ctx->peer) {
        mxfs_peer_shutdown(ctx->peer);
        ctx->peer = NULL;
    }

    if (ctx->dlm) {
        mxfs_dlm_destroy(ctx->dlm);
        ctx->dlm = NULL;
    }

    if (ctx->scsipr) {
        mxfs_scsipr_unregister(ctx->scsipr);
        mxfs_scsipr_destroy(ctx->scsipr);
    }

    if (ctx->dev)
        mxfs_pal_bdev_close_clone(ctx->dev);

    mxfs_pal_free(ctx);
    mxfs_pal_log(MXFS_LOG_INFO, "mxfs: DLM shutdown complete");
}

/* ─── Lock helpers ─── */

static void make_inode_resource(struct mxfs_resource_id *res,
                                 mxfs_volume_id_t volume_id, uint64_t ino)
{
    memset(res, 0, sizeof(*res));
    res->type = MXFS_LTYPE_INODE;
    res->volume = volume_id;
    res->ino = ino;
}

/* ccloop 72513a13 sess3 (ICLUSTER PLAN): resource for a whole XFS inode
 * cluster.  base_ino MUST already be the cluster base (caller masks with
 * inodes_per_cluster-1); the distinct type keeps these slots disjoint
 * from per-inode (directory) slots even at equal ino values. */
static void make_iclus_resource(struct mxfs_resource_id *res,
                                mxfs_volume_id_t volume_id, uint64_t base_ino)
{
    memset(res, 0, sizeof(*res));
    res->type = MXFS_LTYPE_ICLUSTER;
    res->volume = volume_id;
    res->ino = base_ino;
}

static void make_ag_resource(struct mxfs_resource_id *res,
                              mxfs_volume_id_t volume_id, uint32_t agno)
{
    memset(res, 0, sizeof(*res));
    res->type = MXFS_LTYPE_AG;
    res->volume = volume_id;
    res->ag_number = agno;
}

/* ─── Lock operations ─── */

int mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *ctx, uint64_t ino,
                            uint8_t mode)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    if (!ctx)
        return 0;
    if (ctx->withdrawn)     /* sess9: shut-down FS — never contend */
        return -ESHUTDOWN;

    make_inode_resource(&res, ctx->volume_id, ino);

    /*
     * sess3(ccloop a9a03929) ROOT FIX (RULE 4, PROVEN run61 t6 119.7s):
     * -EEXIST from the DLM means THIS NODE already has a WAITING/BLOCKED
     * request in flight for this inode (a concurrent same-node acquire
     * path — e.g. a demoter-reentry drain read racing a user thread, or
     * xfs_inactive's direct EX).  That in-flight request WILL resolve
     * within its own pending-wait/retry budget (grant, or timeout + table
     * cleanup), after which this request can proceed (possibly via the
     * normal held-mode upgrade path).  The old behavior bubbled -EEXIST
     * to mxfs_dlm_ilock_begin, whose 3x50ms retry gave up in 155ms and
     * force-shut-down the FS (run61: ino=131 mode=EX rc=-17 x3 ->
     * SHUTDOWN_CORRUPT_INCORE while the in-flight PR legitimately waited
     * out a peer's EX tenure).  Wait it out HERE so every caller
     * (ilock_begin, xfs_inactive's direct EX, the dir EX helpers) is
     * covered.  Bounded ~60s = the in-flight request's own worst-case
     * budget (60 x 1s dlm_lock retries); a genuinely wedged DLM still
     * fails through to the caller.
     */
    {
        int inflight_waits = 0;

retry_inflight:
        if (ctx->dlm) {
            ret = mxfs_dlm_lock(ctx->dlm, &res, mode, 0, &granted);
        } else if (ctx->dlm_caw) {
            /*
             * Do NOT short-circuit on single_node here.  caw_lock has its
             * own single_node fast path that calls mem_lock_track so the
             * lock can be flushed to disk when peer discovery transitions
             * us out of single_node.
             */
            ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted);
        } else {
            return 0;
        }

        if (ret == -EEXIST && inflight_waits < 3000) {
            inflight_waits++;
            if (inflight_waits == 1 || (inflight_waits % 250) == 0)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P3A-EEXIST-WAIT ino=%llu mode=%u waits=%d "
                             "(own request in flight; waiting it out)",
                             (unsigned long long)ino, mode, inflight_waits);
            mxfs_pal_sleep_ms(20);
            goto retry_inflight;
        }
    }

    if (ret)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: DLM inode lock failed: ino=%llu mode=%u rc=%d",
                     (unsigned long long)ino, mode, ret);
    /* sess52(ccloop) PHANTOM-EX probe: the caller (ilock_begin) treats rc==0 as
     * "grant obtained at the requested mode" and publishes i_dlm_mode=mode — but
     * it IGNORES `granted`.  If the DLM granted a LOWER mode than requested
     * (granted < mode) while returning success, the XFS layer caches a phantom
     * EX it does not actually hold (PROVEN dir_reuse loss: held=0 dlm_mode=EX
     * dir modify).  Log every partial grant so we can confirm/refute this is the
     * phantom source. */
    if (ret == 0 && granted < mode)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P52-PARTIAL-GRANT ino=%llu requested=%u granted=%u "
                     "(rc=0 but lower mode granted; caller will publish phantom EX)",
                     (unsigned long long)ino, mode, granted);
    return ret;
}

/*
 * sess58 (ccloop 8ddb16a2): inode lock with a caller-supplied per-call retry
 * budget.  Used by the TCP inode-acquire slow path so it returns every
 * ~retries seconds and the caller can re-run its cooperative cached-AG yield
 * DURING the acquire — breaking the proven inode<->AG ABBA deadlock that wedged
 * tcp_dlm_scaling to a dirty-trans_cancel shutdown.  TCP transport only; the
 * CAW transport keeps its own (full-budget) poll + deadlock avoidance.
 */
int mxfs_v5_dlm_inode_lock_retries(struct mxfs_v5_dlm *ctx, uint64_t ino,
                            uint8_t mode, int retries)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    if (!ctx)
        return 0;

    make_inode_resource(&res, ctx->volume_id, ino);

    if (ctx->dlm) {
        ret = mxfs_dlm_lock_retries(ctx->dlm, &res, mode, 0, &granted, retries);
    } else if (ctx->dlm_caw) {
        /* CAW: no short-budget variant — use the normal blocking acquire. */
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted);
    } else {
        return 0;
    }

    return ret;
}

void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    mxfs_v5_dlm_inode_unlock_gen(ctx, ino, 0);
}

/*
 * ccloop cc87fed3 sess8: dlm_scaling@32 op-rate collapse fix.  Use in place
 * of mxfs_v5_dlm_inode_unlock() when the caller has already verified the
 * inode is genuinely FREED (VFS_I(ip)->i_nlink == 0) and is doing destructive
 * inactivation -- never for a normal idle-gap release (that path must keep
 * inheriting dir_epoch/last_ex_slot across the gap; see
 * mxfs_dlm_caw_unlock_gen's own is_free comment for the full mechanism).
 *
 * sess7 tried this as a SEPARATE call issued right after the plain unlock
 * returned (mxfs_v5_dlm_inode_note_freed_epoch_reset, now removed): besides
 * silently never firing (find_slot's rc==0 "found" contract only matches a
 * LIVE slot, never the tombstone the unlock had just written -- confirmed
 * live via P144-DIAG reason=noslot on 2190/2190 calls), a corrected version
 * of that approach measurably regressed dlm_scaling@32 from 27/32 to 0/32 by
 * adding a synchronous extra read+CAS round-trip to every free, confirming
 * the TRAP-1 warning already on record (mxfs_dlm_caw_purge_node header).
 * The is_free parameter threaded straight into the unlock call below costs
 * NOTHING extra -- CAW piggybacks the clear onto the tombstone CAS the
 * unlock already performs.
 */
void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;
    extern int mxfs_caw_epoch_free_reset;

    if (!ctx)
        return;

    make_inode_resource(&res, ctx->volume_id, ino);

    if (ctx->dlm)
        mxfs_dlm_unlock_gen(ctx->dlm, &res, 0);
    else if (ctx->dlm_caw)
        mxfs_dlm_caw_unlock_gen(ctx->dlm_caw, &res, 0,
                                !!mxfs_caw_epoch_free_reset);
}

/* sess7 FIX-20b: phantom-grant reconcile — mirror-bypassing gen=0 release to
 * the remote master.  TCP only (CAW's slot protocol has no master mirror to
 * diverge from).  See mxfs_dlm_send_unconditional_release. */
int mxfs_v5_dlm_inode_release_unconditional(struct mxfs_v5_dlm *ctx,
                                            uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_send_unconditional_release(ctx->dlm, &res);
}

/* sess1(ccloop a9a03929) gen-aware release: expected_gen != 0 releases ONLY
 * that tenure; -ESTALE means a re-acquire (newer gen) owns the resource now
 * and the caller must re-arm its BAST instead of treating the lock as
 * released.  TCP-only semantics: on CAW expected_gen is ignored (the CAW slot
 * protocol has no async local-mirror lifecycle to race). */
int mxfs_v5_dlm_inode_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                 uint32_t expected_gen)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return 0;

    make_inode_resource(&res, ctx->volume_id, ino);

    /* sess135 P135: name the call site of every inode unlock for the hot
     * low-numbered inodes — pairs with P135-SLOTWR (caller=caw_unlock) to
     * identify which release path strips the holder bit WITHOUT the drain
     * pipeline (the P108 slot-loss producer). */
    if (ino <= 256 && vm_instr_on())
        mxfs_pal_log(MXFS_LOG_WARN,
            "mxfs: P135-INO-UNLOCK ino=%llu caller=%pS",
            (unsigned long long)ino, __builtin_return_address(0));

    if (ctx->dlm)
        return mxfs_dlm_unlock_gen(ctx->dlm, &res, expected_gen);
    else if (ctx->dlm_caw) {
        /* v0.6.2: honor the tenure anchor on CAW too (the old comment's
         * "no async local-mirror lifecycle to race" was disproven — see
         * mxfs_v5_dlm_inode_grant_gen).  expected_gen was captured at the
         * caller's release DECISION; the gen-aware worker refuses
         * (-ESTALE) when a local re-acquire won a newer tenure at ANY
         * point up to and during the CAS loop — the caller re-arms its
         * BAST (stranded path) instead of eating the fresh grant's bit. */
        return mxfs_dlm_caw_unlock_gen(ctx->dlm_caw, &res, expected_gen, false);
    }
    return 0;
}

/* ─── ICLUSTER resource ops (ccloop 72513a13 sess3, ICLUSTER PLAN) ───
 * Thin type-swapped twins of the inode ops.  The xfs-side mediating layer
 * (mxfs_iclus, sess4 sweep design) owns the release decision; these only
 * move the on-disk slot.  base_ino must be the cluster base. */

int mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                           uint8_t mode)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;
    int inflight_waits = 0;

    if (!ctx)
        return 0;
    if (ctx->withdrawn)
        return -ESHUTDOWN;

    make_iclus_resource(&res, ctx->volume_id, base_ino);

retry_inflight:
    if (ctx->dlm) {
        ret = mxfs_dlm_lock(ctx->dlm, &res, mode, 0, &granted);
    } else if (ctx->dlm_caw) {
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted);
    } else {
        return 0;
    }
    /* same in-flight semantics as mxfs_v5_dlm_inode_lock (sess3 a9a03929) */
    if (ret == -EEXIST && inflight_waits < 3000) {
        inflight_waits++;
        if (inflight_waits == 1 || (inflight_waits % 250) == 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P3A-EEXIST-WAIT iclus=%llu mode=%u waits=%d",
                         (unsigned long long)base_ino, mode, inflight_waits);
        mxfs_pal_sleep_ms(20);
        goto retry_inflight;
    }
    if (ret)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: DLM iclus lock failed: base=%llu mode=%u rc=%d",
                     (unsigned long long)base_ino, mode, ret);
    if (ret == 0 && granted < mode)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P52-PARTIAL-GRANT iclus=%llu requested=%u granted=%u",
                     (unsigned long long)base_ino, mode, granted);
    return ret;
}

int mxfs_v5_dlm_iclus_unlock_gen(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                                 uint32_t expected_gen, bool is_free)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return 0;
    make_iclus_resource(&res, ctx->volume_id, base_ino);
    if (ctx->dlm)
        return mxfs_dlm_unlock_gen(ctx->dlm, &res, expected_gen);
    else if (ctx->dlm_caw)
        return mxfs_dlm_caw_unlock_gen(ctx->dlm_caw, &res, expected_gen,
                                       is_free);
    return 0;
}

int mxfs_v5_dlm_iclus_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t base_ino)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return MXFS_LOCK_EX;    /* TCP/single-node: trust local mirror */
    make_iclus_resource(&res, ctx->volume_id, base_ino);
    return mxfs_dlm_caw_granted_mode(ctx->dlm_caw, &res);
}

void mxfs_v5_dlm_set_iclus_bast_notify(struct mxfs_v5_dlm *ctx,
                                       mxfs_v5_bast_notify_fn fn, void *data)
{
    if (!ctx)
        return;
    ctx->iclus_bast_notify_fn = fn;
    ctx->iclus_bast_notify_data = data;
}

/* sess58 RULE-4 concurrent-EX discriminator for INODE locks (mirrors
 * mxfs_v5_dlm_ag_ex_count, but for an inode resource).  Reads the entire CAW
 * probe chain for this inode RAW and returns popcount(OR of holders_ex across
 * all live slots).  popcount>1 == two distinct nodes hold the inode EX
 * simultaneously (broken cluster exclusion → concurrent shortform-dir
 * lost-update).  *nslots_out = live-slot count (>1 == slot claim-race).
 * Returns popcount, or <0 on error / 0 for TCP/single-node. */
int mxfs_v5_dlm_inode_ex_count(struct mxfs_v5_dlm *ctx, uint64_t ino,
                               int *nslots_out)
{
    struct mxfs_resource_id res;

    if (nslots_out)
        *nslots_out = 0;
    if (!ctx || !ctx->dlm_caw)
        return 0;   /* TCP/unknown: not measurable */
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_ex_count(ctx->dlm_caw, &res, nslots_out);
}

/* ccloop a864 sess3: duplicate-immune "does THIS node hold `ino` EX on disk"
 * check.  1 if our bit is set in holders_ex across any live slot (full-chain
 * scan, immune to the hinted find_slot's dup blind spot), else 0.  CAW only
 * (returns 0 on TCP/unknown).  *nslots_out = live-slot count; *hex_or_out = OR
 * of holders_ex.  Read-only. */
int mxfs_v5_dlm_inode_self_held_scan(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                     int *nslots_out, uint64_t *hex_or_out)
{
    struct mxfs_resource_id res;

    if (nslots_out)
        *nslots_out = 0;
    if (hex_or_out)
        *hex_or_out = 0;
    if (!ctx || !ctx->dlm_caw)
        return 0;   /* TCP/unknown: not measurable */
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_self_held_scan(ctx->dlm_caw, &res, nslots_out,
                                       hex_or_out);
}

/* ccloop a864 sess3: unconditional scan-based self-release for inode `ino`.
 * CAW only (no-op/0 on TCP).  Recovery for an orphaned on-disk holder bit the
 * normal release left set.  Caller holds the DEMOTING claim.  Returns #slots
 * cleared, <0 on error. */
int mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_force_release_self(ctx->dlm_caw, &res);
}

/*
 * sess61 (sess10 plan): the reliable per-grant generation token THIS node holds
 * for inode `ino` on the TCP DLM (ctx->dlm).  Returns 0 if not held, or on CAW
 * (CAW has atomic slot mutual-exclusion and does not exhibit the fast-path
 * stale-base RMW bug, so the grant_gen tenure check is TCP-only).  The XFS layer
 * caches this at slow-path acquire and re-checks it on the dir-EX fast-path
 * serve: a changed value means the lock changed hands (a peer was granted) since
 * we cached it -> force a reload-on-reacquire before the RMW.
 */
uint32_t mxfs_v5_dlm_inode_grant_gen(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm)
        return mxfs_dlm_grant_gen(ctx->dlm, &res);
    /* v0.6.2: the "CAW has no lifecycle to race" assumption was DISPROVEN
     * (P106-STALE-EX + dland dual-writer capture): a bast release racing a
     * local slow-path re-acquire cleared the fresh grant's slot bit exactly
     * as on TCP run42-t4.  Serve the CAW grant-episode token so the
     * gen-aware release (unlock_gen below) can refuse a newer tenure. */
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_grant_seq32(ctx->dlm_caw, &res);
    return 0;
}

/* interactive session 2026-07-13: CAW-only (0/no-op on TCP — TCP's
 * per-inode wall-clock fields don't suffer the VFS-eviction defeat this
 * exists for, since orphan_live there is legitimately bounded by the 6s
 * ACQUIRE_WAIT retry gap per mxfs_dlm_bast_process's TCP/CAW split). */
uint64_t mxfs_v5_dlm_inode_orphan_clock_get(struct mxfs_v5_dlm *ctx,
                                            uint64_t ino, bool starve)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_orphan_clock_get(ctx->dlm_caw, &res, starve);
}

void mxfs_v5_dlm_inode_orphan_clock_set(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                        bool starve, uint64_t val)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return;
    make_inode_resource(&res, ctx->volume_id, ino);
    mxfs_dlm_caw_orphan_clock_set(ctx->dlm_caw, &res, starve, val);
}

/* sess4(a9a03929) FIX-1 support: highest mode this node's local mirror holds
 * for `ino` (MXFS_LOCK_NL if no DLM).
 *
 * ccloop cc87fed3 sess3 (RULE 4 PROVEN): this was TCP-only (`!ctx->dlm` ->
 * unconditional MXFS_LOCK_NL), unlike every sibling accessor in this file
 * (mxfs_v5_dlm_inode_held_rawmode, _grant_handoff, _dir_epoch,
 * _orphan_clock_get), which all fall back to ctx->dlm_caw.  Both of this
 * function's callers gate a SAFETY admit on the result: mxfs_ilock_admit_ioend
 * (FIX-25, xfs_mxfs_dlm.c) requires g2 to read back EX or PR before letting
 * the xfs-conv ioend-completion kworker finish an in-flight unwritten-extent
 * conversion during a BAST/DEMOTING release-flush; P79-NESTADMIT
 * (mxfs_dlm_ilock_begin) requires the same to admit a nested re-entrant
 * hold.  On CAW this always read back NL, so BOTH admits were permanently
 * dead code on the CAW transport — proven live on test7
 * (fence_during_write@8/caw): mxfs_dlm_bast_process (PID 3816) parked
 * >1900s inside filemap_write_and_wait_range waiting on a folio whose
 * writeback completion (xfs_end_io -> xfs_iomap_write_unwritten, PID 5402)
 * needed EX and blocked in mxfs_dlm_ilock_begin's DEMOTING wait
 * (xfs_mxfs_dlm.c:21105, addr2line-confirmed) because admit_ioend's g2 query
 * always returned NL — zero "P25-IOEND-ADMIT" lines ever printed across the
 * full stall despite state/mode/task all satisfying every OTHER condition
 * (P73-WAITSTALL: req=5(EX) mode=3(PR) state=3(DEMOTING) relflush=0).
 * mxfs_dlm_caw_held() can't be reused directly — it collapses to a boolean,
 * which would let a PR-only local hold be misread as EX and incorrectly
 * upgrade ip->i_dlm_mode; mxfs_dlm_caw_granted_mode() (new, same file)
 * preserves the real mode via the same node_held_mode() bitmap lookup
 * mxfs_dlm_caw_held() uses internally. */
uint8_t mxfs_v5_dlm_inode_granted_mode(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return MXFS_LOCK_NL;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm)
        return mxfs_dlm_granted_mode(ctx->dlm, &res);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_granted_mode(ctx->dlm_caw, &res);
    return MXFS_LOCK_NL;
}

/* sess63: did THIS node's held EX grant for `ino` arrive as a cross-node
 * handoff (a DIFFERENT node held EX since we last did)?  *gen_out gets the
 * grant_gen so the caller consumes the handoff exactly once per grant episode.
 * CAW transport: returns false (CAW's atomic slot mutual-exclusion has no
 * stale-cached-EX gap and no master to track prior owner). */
bool mxfs_v5_dlm_inode_grant_handoff(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                     uint32_t *gen_out)
{
    struct mxfs_resource_id res;

    if (gen_out)
        *gen_out = 0;
    if (!ctx)
        return false;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm)
        return mxfs_dlm_grant_was_handoff(ctx->dlm, &res, gen_out);
    /* v0.6.0: CAW analog — handoff bit + epoch observed at our last grant
     * CAS of this resource (slot field dir_epoch/last_ex_slot). */
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_grant_handoff(ctx->dlm_caw, &res, gen_out);
    return false;
}

/* sess64 (GPT design): the MONOTONIC cross-node handoff epoch for `ino`'s
 * currently-held grant (0 if not held / no DLM).  The XFS layer keeps
 * i_dlm_dir_valid_epoch and refreshes its cached dir base whenever this
 * moves past (TCP, monotonic) or away from (CAW — slot reclamation can
 * restart the counter) the stamped value.  v0.6.0: CAW serves this from
 * the slot's dir_epoch observed at our last grant. */
uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm)
        return mxfs_dlm_grant_dir_epoch(ctx->dlm, &res);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_grant_dir_epoch(ctx->dlm_caw, &res);
    return 0;
}

/* ccloop(3e02e7dd) sess3: canonical dir block0 — CAW-only (see v5_mount.h). */
bool mxfs_v5_dlm_inode_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen, uint64_t *fsb_out)
{
    struct mxfs_resource_id res;

    if (fsb_out)
        *fsb_out = 0;
    if (!ctx || !ctx->dlm_caw)
        return false;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_grant_dir_block0(ctx->dlm_caw, &res, gen, fsb_out);
}

void mxfs_v5_dlm_inode_set_dir_block0(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                      uint64_t fsb, uint32_t gen)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return;
    make_inode_resource(&res, ctx->volume_id, ino);
    mxfs_dlm_caw_set_dir_block0(ctx->dlm_caw, &res, fsb, gen);
}

/* v0.6.0: does this mount coordinate via the CAW (disk-slot) transport?
 * The XFS epoch-adopt gate needs this: TCP epochs are monotonic (compare
 * with >), CAW slot epochs can restart on slot reclamation (compare
 * with !=). */
bool mxfs_v5_dlm_transport_caw(struct mxfs_v5_dlm *ctx)
{
    return ctx && !ctx->dlm && ctx->dlm_caw;
}

/*
 * sess55: producer bridge for the inode-eviction ring.  The XFS layer calls
 * this from xfs_ifree() (via mxfs_dlm_note_inode_freed) when it frees an inode;
 * we stage {ino, gen} into the disklock heartbeat ring so passively-caching
 * peers can invalidate any stale NL-cached copy of the reused number.
 * Non-blocking; no-op when disklock isn't active (single-node / no disklock).
 */
void mxfs_v5_dlm_note_inode_freed(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t gen)
{
    if (!ctx || !ctx->disklock)
        return;

    mxfs_disklock_note_freed(ctx->disklock, ino, gen,
                             MXFS_EVICT_TYPE_INODE_FREE);
}

/*
 * sess80: producer bridge for the dir-modify eviction-ring entry.  The XFS
 * layer calls this (via mxfs_dlm_note_dir_modified) after committing a dirent
 * add/remove to directory `ino`; passively-caching peers bump that dir's
 * i_dlm_dir_gen and FUA-re-read its stale-but-clean cached dir blocks on the
 * next readdir.  Non-blocking; no-op when disklock isn't active.
 */
void mxfs_v5_dlm_note_dir_modified(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    if (!ctx || !ctx->disklock)
        return;

    mxfs_disklock_note_freed(ctx->disklock, ino, 0,
                             MXFS_EVICT_TYPE_DIR_MODIFY);
}

/*
 * sess56: register the XFS-layer consumer for the inode-eviction ring.  The
 * disklock heartbeat monitor invokes `cb(data, ino, gen, type)` for each entry
 * a peer publishes.  No-op when disklock isn't active.
 */
void mxfs_v5_dlm_set_evict_cb(struct mxfs_v5_dlm *ctx,
                              void (*cb)(void *data, uint64_t ino,
                                         uint32_t gen, uint32_t type),
                              void *data)
{
    if (!ctx || !ctx->disklock)
        return;

    mxfs_disklock_set_evict_cb(ctx->disklock, cb, data);
}

int mxfs_v5_dlm_inode_lock_try(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                uint8_t mode)
{
    struct mxfs_resource_id res;
    uint8_t granted;

    if (!ctx)
        return 0;

    make_inode_resource(&res, ctx->volume_id, ino);

    if (ctx->dlm)
        return mxfs_dlm_lock(ctx->dlm, &res, mode,
                              MXFS_LKF_NOQUEUE, &granted);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode,
                                  MXFS_LKF_NOQUEUE, &granted);
    return 0;
}

/* ─── BAST notification ─── */

void mxfs_v5_dlm_set_bast_notify(struct mxfs_v5_dlm *ctx,
                                   mxfs_v5_bast_notify_fn fn, void *data)
{
    if (!ctx)
        return;
    ctx->bast_notify_fn = fn;
    ctx->bast_notify_data = data;
}

void mxfs_v5_dlm_set_ag_bast_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_ag_bast_notify_fn fn,
                                      void *data)
{
    if (!ctx)
        return;
    ctx->ag_bast_notify_fn = fn;
    ctx->ag_bast_notify_data = data;
}

void mxfs_v5_dlm_set_fence_notify(struct mxfs_v5_dlm *ctx,
                                  mxfs_v5_fence_notify_fn fn,
                                  void *data)
{
    if (!ctx)
        return;
    ctx->fence_notify_fn = fn;
    ctx->fence_notify_data = data;
}

void mxfs_v5_dlm_set_dead_node_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_dead_node_notify_fn fn,
                                      void *data)
{
    if (!ctx)
        return;
    ctx->dead_node_notify_fn = fn;
    ctx->dead_node_notify_data = data;
}

void mxfs_v5_dlm_set_peer_joined_notify(struct mxfs_v5_dlm *ctx,
                                          mxfs_v5_peer_joined_notify_fn fn,
                                          void *data)
{
    bool already_multi = false;

    if (!ctx)
        return;
    ctx->peer_joined_notify_fn = fn;
    ctx->peer_joined_notify_data = data;

    /*
     * v0.3.111 sess27: discovery may have already received a peer
     * announcement BEFORE this callback was wired (init starts
     * discovery before XFS calls cache_init).  If we're already
     * multi-node when the cb registers, fire it now so the XFS
     * layer drops pag_dlm_cached / i_dlm_stale entries that were
     * acquired in single-node mode.  Without this, the lock-table
     * purge from the first update_active_nodes call leaves
     * phantom AG-cached entries that loop on ETIMEDOUT.
     */
    if (ctx->dlm)
        already_multi = !mxfs_dlm_is_single_node(ctx->dlm);
    else if (ctx->dlm_caw)
        already_multi = !ctx->dlm_caw->single_node;

    if (already_multi && fn) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: peer_joined cb registered post-multi — "
                     "firing now to flush stale single-node state");
        fn(data);
    }
}

int mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    if (!ctx)
        return 0;
    if (ctx->withdrawn)     /* sess9: shut-down FS — never contend */
        return -ESHUTDOWN;

    make_ag_resource(&res, ctx->volume_id, agno);

    if (ctx->dlm)
        ret = mxfs_dlm_lock(ctx->dlm, &res, MXFS_LOCK_EX, 0, &granted);
    else if (ctx->dlm_caw)
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_EX, 0,
                                  &granted);
    else
        return 0;

    if (ret)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: DLM AG lock failed: ag=%u rc=%d", agno, ret);
    return ret;
}

/*
 * sess19 (ccloop 4eef1f39): read the shared on-disk CAW slot generation for an
 * AG (cross-node free-space coherency epoch).  CAW transport only — the TCP DLM
 * path returns -ENODEV so the caller falls back to a conservative local bump.
 */
int mxfs_v5_dlm_ag_read_generation(struct mxfs_v5_dlm *ctx, uint32_t agno,
                                   uint64_t *out_gen)
{
    struct mxfs_resource_id res;

    if (!ctx || !out_gen)
        return -EINVAL;
    if (!ctx->dlm_caw)
        return -ENODEV;
    make_ag_resource(&res, ctx->volume_id, agno);
    return mxfs_dlm_caw_read_generation(ctx->dlm_caw, &res, out_gen);
}

/*
 * sess77: non-blocking AG EX acquire.  Passes MXFS_LKF_NOQUEUE so the CAW
 * layer returns -EAGAIN immediately if a peer holds the AG instead of
 * registering as a waiter and polling up to 120s.  Used by the allocator's
 * XFS_ALLOC_FLAG_TRYLOCK first pass (dialloc / block alloc) so a contended
 * AG is skipped rather than blocked on while inode ILOCKs are held — this
 * breaks the distributed ILOCK-vs-AG-DLM hold-and-wait deadlock.
 */
int mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    if (!ctx)
        return 0;
    if (ctx->withdrawn)     /* sess9: shut-down FS — never contend */
        return -ESHUTDOWN;

    make_ag_resource(&res, ctx->volume_id, agno);

    if (ctx->dlm)
        ret = mxfs_dlm_lock(ctx->dlm, &res, MXFS_LOCK_EX,
                            MXFS_LKF_NOQUEUE, &granted);
    else if (ctx->dlm_caw)
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_EX,
                                MXFS_LKF_NOQUEUE, &granted);
    else
        return 0;

    /* -EAGAIN / -EWOULDBLOCK: peer holds it; caller skips this AG. */
    return ret;
}

int mxfs_v5_dlm_ag_held(struct mxfs_v5_dlm *ctx, uint32_t agno)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return 1;   /* TCP/unknown: don't assert */
    make_ag_resource(&res, ctx->volume_id, agno);
    return mxfs_dlm_caw_held(ctx->dlm_caw, &res);
}

/* sess107 RULE-4: cheap on-disk ownership read for an INODE resource.
 * Returns 1 if THIS node currently holds the inode lock on disk, 0 if not,
 * <0 on I/O error.  Mirror of mxfs_v5_dlm_ag_held.  Used by the dir-EX
 * fast-path to detect a STALE cached i_dlm_mode==EX (in-memory EX while the
 * on-disk CAW slot was already released — the proven stale-cached-EX
 * mutual-exclusion violation, sess106). */
/* sess42 (ccloop 8ddb16a2): return the RAW held mode (MXFS_LOCK_NL/PR/EX) this
 * node owns on `ino` per the transport's authority.  TCP keeps grants in the
 * dlm.c local mirror (mxfs_dlm_held_mode returns the actual granted mode); CAW
 * keeps them in the on-disk slot table (held/not-held only -> map held to EX so
 * a >=PR or >=EX comparison both succeed for a real CAW holder).  Callers that
 * need a phantom-lock check must compare against the mode they BELIEVE they
 * hold, NOT a hardcoded EX — the old `>= EX ? 1 : 0` collapse false-negatived a
 * legitimately-held PR (held_mode=PR < EX) and made the P108 verify
 * spuriously demote valid PR readers, producing the ino=128 parent-dir
 * re-acquire storm + 65s dir_reuse stall. */
uint8_t mxfs_v5_dlm_inode_held_rawmode(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return MXFS_LOCK_EX;   /* unknown: assume held, don't assert/demote */
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm)
        return mxfs_dlm_held_mode(ctx->dlm, &res);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_held(ctx->dlm_caw, &res) ? MXFS_LOCK_EX
                                                     : MXFS_LOCK_NL;
    return MXFS_LOCK_EX;   /* unknown transport: don't assert */
}

/* sess37 DIAGNOSTIC: is THIS node the DLM master for the inode resource?
 * 1=yes (our local table is authoritative for all holders), 0=no (our local
 * table only holds our own replicated grant, which can go stale if a master
 * revocation didn't demote it), -1=no TCP dlm.  Used at the dir-write clobber
 * detect to settle whether the genuine-EX clobber happens on the master (true
 * double-grant = master bug) or a non-master (stale local DLM entry not demoted
 * on revoke = the real_mode=5 itself is stale local state). */
int mxfs_v5_dlm_inode_master_self(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm)
        return -1;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_is_resource_master(ctx->dlm, &res) ? 1 : 0;
}

void mxfs_v5_dlm_inode_dump_slot(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return;
    make_inode_resource(&res, ctx->volume_id, ino);
    mxfs_dlm_caw_dump_slot(ctx->dlm_caw, &res);
}

int mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    if (!ctx)
        return 1;
    /* Back-compat EX-phantom check used by the P106/P135/tcpex callers, which
     * all validate an EX hold.  Delegates to the raw-mode helper above. */
    return (mxfs_v5_dlm_inode_held_rawmode(ctx, ino) >= MXFS_LOCK_EX) ? 1 : 0;
}

bool mxfs_v5_dlm_is_tcp(struct mxfs_v5_dlm *ctx)
{
    return ctx && ctx->dlm != NULL;
}

/* sess52 RULE-4: popcount(holders_ex) for this AG across the whole CAW probe
 * chain.  >1 == transient concurrent-EX (two nodes EX the same AG) — the
 * unproven root of the bnobt gen-current-but-disk-stale lost-update.
 * *nslots_out = live-slot count for the AG (>1 == claim-race).  Returns
 * popcount, or <0 on error / 0 for TCP/single-node. */
int mxfs_v5_dlm_ag_ex_count(struct mxfs_v5_dlm *ctx, uint32_t agno,
                            int *nslots_out)
{
    struct mxfs_resource_id res;

    if (nslots_out)
        *nslots_out = 0;
    if (!ctx || !ctx->dlm_caw)
        return 0;   /* TCP/unknown: not measurable */
    make_ag_resource(&res, ctx->volume_id, agno);
    return mxfs_dlm_caw_ex_count(ctx->dlm_caw, &res, nslots_out);
}

void mxfs_v5_dlm_ag_unlock(struct mxfs_v5_dlm *ctx, uint32_t agno)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return;

    make_ag_resource(&res, ctx->volume_id, agno);

    if (ctx->dlm)
        mxfs_dlm_unlock(ctx->dlm, &res);
    else if (ctx->dlm_caw)
        mxfs_dlm_caw_unlock(ctx->dlm_caw, &res);
}

bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *ctx)
{
    bool result;

    if (!ctx)
        return true;
    if (ctx->dlm)
        result = mxfs_dlm_is_single_node(ctx->dlm);
    else if (ctx->dlm_caw)
        result = ctx->dlm_caw->single_node;
    else
        return true;

    /* RULE-4 instrumentation: prove or refute "single_node silently
     * regresses to true after real multi-node operation" without adding
     * cost to the hot (false) path — one bool check either way. */
    if (!result)
        ctx->ever_multi = true;
    else if (ctx->ever_multi)
        pr_warn_ratelimited(
            "mxfs: P-SINGLENODE-REGRESSION node=%u ctx=%p dlm=%p dlm_caw=%p "
            "single_node observed true again after having gone multi-node\n",
            ctx->node_id, ctx, ctx->dlm, ctx->dlm_caw);

    return result;
}

int mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *ctx)
{
    if (!ctx)
        return 0;
    return ctx->node_slot;
}

/*
 * sess67 ASYMMETRIC MDS (Phase 1).  Is this node the metadata server for the
 * filesystem?  A single-node mount is trivially its own MDS.  Static v1 rule
 * otherwise: MDS == disklock slot 0.  The XFS layer calls this (via
 * mp->m_mxfs_dlm) to decide whether to run a metadata transaction locally or
 * forward it to the MDS.  Until the metadata-RPC wiring lands (Phase 1 step
 * 4), every node still runs locally — this accessor is the gate that wiring
 * will switch on.
 */
bool mxfs_v5_dlm_is_mds(struct mxfs_v5_dlm *ctx)
{
    if (!ctx)
        return true;
    if (mxfs_v5_dlm_is_single_node(ctx))
        return true;
    return ctx->is_mds;
}

int mxfs_v5_dlm_get_mds_node_slot(struct mxfs_v5_dlm *ctx)
{
    if (!ctx)
        return 0;
    return ctx->mds_node_slot;
}
