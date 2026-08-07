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
/*
 * sess58 (D-FOREIGN-REPLAY step 4a, GPT review item 6A) — bounded fence
 * retry on the settle/mount-barrier path.  The dominant fence failure is a
 * transient SCSI READ KEYS error, and on the mount barrier an unfenced slot
 * is not a mere leaked grant: its grants stall xfs_log_mount_finish for the
 * full CAW wait timeout and then fail the mount.  5 x 1000 ms is negligible
 * against that and against the 62 s dead-confirm window already paid to
 * reach this point.
 */
#define V5_FENCE_RETRIES        5
#define V5_FENCE_RETRY_MS       1000

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
    uint32_t                    log_node_count;     /* sess65: XFS log slice divisor */

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

    /* sess11 (ccloop c7ee71c6) withdraw@2: identities that died this
     * mount (withdrawn / fenced / departed cleanly).  A force-shut-down
     * zombie stays MOUNTED with its discovery+lease threads running; its
     * ~500ms announces re-register it into the lease, and nothing in the
     * P163 recovery path ever unregistered it — so hash%active_nodes
     * mastership kept routing to a node that drops all master traffic
     * (PROVEN: survivor retried ino=128 PR against master=dead for 184s,
     * rc=-110, force-shutdown).  Node ids derive from per-MOUNT random
     * uuids, so a dead id never legitimately returns — a rejoining node
     * mints a fresh id.  Fixed append ring; benign races (plain aligned
     * u32 loads/stores, refresh-filter is the airtight backstop). */
#define MXFS_V5_DEAD_SET 32
    mxfs_node_id_t              dead_nodes[MXFS_V5_DEAD_SET];
    unsigned int                dead_next;

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
     * sess132 (GPT sess130 ruling, step 5): DLM-stuck notification — fired
     * when the CAW layer proves it can no longer clear this node's bits out
     * of the on-disk slot table.  Peers block behind those bits, so it is a
     * cluster-wide liveness fault and the mount above must stop writing.
     * Forwarded verbatim from mxfs_dlm_caw_set_owed_stuck_fn; the CAW layer
     * has already recorded the failure before this fires.
     */
    mxfs_v5_dlm_stuck_notify_fn     dlm_stuck_notify_fn;
    void                            *dlm_stuck_notify_data;

    /*
     * sess132: local membership-view generation, bumped on every CAW
     * membership change and pushed into the CAW ctx so its escalation
     * diagnostics can name the view they fired in.  NOT a cluster-committed
     * epoch — see mship_view in dlm_caw.h.
     */
    uint64_t                        mship_view;

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

    /*
     * sess53 (D-FOREIGN-REPLAY step 4a) — DEFERRED CROSS-INSTANCE STALE SET.
     *
     * Mount step 6.5 used to purge the CAW bits of every heartbeat slot
     * that failed to advance.  Those bits are not garbage: they are the
     * authority manifest of a crashed instance's UNREPLAYED journal
     * slice, and replay needs them to decide which buffer images it may
     * legally apply.  Purging them at mount destroys that record before
     * anyone reads it — which is precisely how a foreign replay ends up
     * applying ungated images.
     *
     * So 6.5 now only RECORDS the mask here, and the post-recovery
     * settle routes each surviving bit through the full D2 path
     * (re-verify frozen -> SCSI-PR fence -> slice recovery), which
     * replays the slice and only then reclaims the grants.  A stale bit
     * is never dropped on the mount path without its slice being
     * recovered first.
     *
     * mount_stale_mask is written once (single-threaded mount context)
     * and consumed once by the settle.  mount_stale_node pins WHICH
     * incarnation was seen frozen in each slot: the settle must fence,
     * and fencing the wrong node because the slot was re-claimed in the
     * meantime would shoot a healthy member.  A slot only proceeds if
     * the same node id is still there (GPT sess52 ruling item 5).
     *
     * mount_stale_epoch pins WHICH INCARNATION of that node (sess86).  A node
     * id alone is not an identity: the same node can die, reboot and reclaim
     * the same slot inside the settle's own confirmation window, and a
     * recovery published against "node N in slot S" would then be published
     * against the LIVE incarnation.  This array is filled by
     * mxfs_disklock_confirm_dead_mask with the baseline incarnation it held
     * frozen across the whole window — the only incarnation that was actually
     * proven dead — and is what the pending marker names.
     */
    uint64_t                        mount_stale_mask;
    mxfs_node_id_t                  mount_stale_node[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_epoch_t                    mount_stale_epoch[MXFS_DISKLOCK_HB_SLOTS];

    /*
     * sess61 (GPT sess57 review item 6B) — PEER DEATHS DURING OUR MOUNT.
     *
     * mount_stale_mask above is a SNAPSHOT taken at step 6.5.  A peer that
     * was healthy then can freeze at any point afterwards, and the window
     * that follows is long: log recovery, the barrier's 62 s confirmation,
     * and xfs_log_mount_finish's intent + iunlink replay all run inside it.
     *
     * The heartbeat monitor detects those deaths perfectly well — it is
     * running from step 6 — and calls v5_lease_expire_cb.  But the XFS-side
     * slice-replay hook (dead_node_notify_fn) is only registered by
     * mxfs_dlm_cache_init, which runs AFTER xfs_mountfs returns.  With no
     * hook, that callback used to fall through to the legacy immediate
     * purge: CAW manifest cleared, lock records cleared, heartbeat sector
     * ZEROED — and the zeroed sector is the cluster-wide "slice replayed"
     * broadcast.  Every peer would then run its deferred local purge for a
     * slice nobody replayed.  That is the exact D2 violation the deferred-
     * purge protocol exists to prevent (sess9: ifree destaged, dirent
     * remove abandoned with the log -> durable dangling dirent), plus the
     * destruction of the authority manifest the foreign-replay gate reads.
     *
     * So a death seen in this window is now fenced, noted, and made
     * durably recovery-pending — and its slot recorded HERE.  Nothing is
     * purged.  The mount barrier folds whatever has arrived into its own
     * inline replay round; anything that arrives after the barrier is
     * dispatched by the post-mountfs settle, once the replay hook exists.
     *
     * Written by the heartbeat monitor thread, drained by the mount
     * thread, so unlike mount_stale_mask it needs real mutual exclusion.
     * mphase_lock is created before the heartbeat starts and destroyed
     * after it is joined.
     */
    mxfs_mutex_t                    *mphase_lock;
    uint64_t                        mphase_dead_mask;
    mxfs_node_id_t                  mphase_dead_node[MXFS_DISKLOCK_HB_SLOTS];

    /*
     * sess54: the settle's phase 3 must watch a candidate slot for the
     * FULL dead threshold (62 s by default) before it may fence, because
     * anything shorter is a weaker death criterion than the one the
     * running cluster itself uses.  That wait does not belong on the
     * mount thread: phase 3 only STARTS an asynchronous slice recovery
     * (mark pending -> elect -> notify), so blocking fill_super for 62 s
     * buys nothing and would add 62 s to every node's mount on a cold
     * restart after a whole-cluster crash (RULE 0).  It runs here
     * instead, and mxfs_v5_dlm_shutdown joins it.
     *
     * settle_stop is honoured only while WAITING.  Once the confirm
     * returns "dead" the fence -> mark-pending sequence runs to
     * completion: stopping between a successful fence and the recovery
     * being made pending would strand that slice's grants with nobody
     * left to replay them.
     */
    mxfs_thread_t                   *settle_thread;
    volatile int                    settle_stop;

    /*
     * sess93 — THE RECOVERY EXECUTION LEASE, held across the whole replay.
     *
     * GPT ruling (RULE 5, sess93, correction 1): "claim ONCE before replay and
     * hold the auth across replay + completion; re-claiming in
     * recovery_complete makes ownership ambiguous and can mask lost context."
     *
     * mxfs_v5_dlm_recovery_acquire() claims the certified descriptor and parks
     * the returned tuple here; the replay gate, every destructive step and
     * mxfs_v5_dlm_recovery_complete() all present THIS auth, so a takeover that
     * happens while we work is detected as -EBUSY instead of silently
     * overwriting a successor's work.
     *
     * Written by whichever thread drives the recovery for a slot — the foreign
     * replay workqueue, the mount thread, or the settle worker — and never by
     * two at once for the same slot: a slot has exactly one elected replayer,
     * and the on-disk claim CAS is what makes that true cluster-wide.
     * recov_auth_mask is the per-slot validity bit.
     */
    uint64_t                        recov_auth_mask;
    struct mxfs_recov_auth          recov_auth[MXFS_DISKLOCK_HB_SLOTS];

    /*
     * sess93 — RECOVERY_BLOCKED_FENCE, one per victim slot.  Set at every
     * refusal point, cleared only when the recovery actually publishes.  See
     * the block comment in v5_mount.h: a fail-closed recovery is
     * indistinguishable from a hang unless something says so.
     */
    struct mxfs_recov_blocked       blocked[MXFS_DISKLOCK_HB_SLOTS];
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
static void v5_refresh_active_nodes(struct mxfs_v5_dlm *ctx);
static bool v5_node_is_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id);
static void v5_note_dead_node(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id);

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

    /*
     * sess9 (ccloop c7ee71c6) D2: a withdrawn node must not serve MASTER
     * duties.  Granting a lock during the withdraw-recovery window would
     * hand a peer a resource whose durable state may still be torn
     * (our slice unreplayed).  Drop request/convert/release traffic —
     * requesters retry inside their 60 s budgets and re-route once the
     * recovery purge remasters our resources (a few seconds).
     */
    if (ctx->withdrawn &&
        (hdr->type == MXFS_MSG_LOCK_REQ ||
         hdr->type == MXFS_MSG_LOCK_CONVERT ||
         hdr->type == MXFS_MSG_LOCK_RELEASE))
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
        /* v0.11.79 (D6): a clean-departing peer said goodbye.  Drop it from
         * membership NOW: clear any suspect entry (its imminent TCP close is
         * expected, not a death), purge its (already-released) grants, and
         * refresh the active view so EX work never grinds the 40s death
         * grace against a node that is simply gone. */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: P-GOODBYE-RX node %u departed cleanly", sender);
        if (ctx->tcp_suspect_lock) {
            int gslot = (int)(sender % MXFS_MAX_NODES);

            mxfs_pal_mutex_lock(ctx->tcp_suspect_lock);
            if (ctx->tcp_suspect_node[gslot] == sender)
                ctx->tcp_suspect_since[gslot] = 0;
            mxfs_pal_mutex_unlock(ctx->tcp_suspect_lock);
        }
        if (ctx->dlm)
            mxfs_dlm_purge_node(ctx->dlm, sender);
        if (ctx->lease)
            mxfs_lease_unregister_node(ctx->lease, sender);
        v5_note_dead_node(ctx, sender);   /* sess11: id never returns */
        v5_refresh_active_nodes(ctx);
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
/* sess11: see dead_nodes in the ctx.  Membership entry points MUST treat a
 * retired identity as if it never spoke again. */
static bool v5_node_is_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id)
{
    int i;

    if (!node_id)
        return false;
    for (i = 0; i < MXFS_V5_DEAD_SET; i++)
        if (ctx->dead_nodes[i] == node_id)
            return true;
    return false;
}

static void v5_note_dead_node(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id)
{
    if (!node_id || v5_node_is_dead(ctx, node_id))
        return;
    ctx->dead_nodes[ctx->dead_next++ % MXFS_V5_DEAD_SET] = node_id;
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P164-DEAD-NOTE node=%u — identity retired; its "
                 "announces/connects are ignored from now on", node_id);
}

static void v5_refresh_active_nodes(struct mxfs_v5_dlm *ctx)
{
    mxfs_node_id_t nodes[MXFS_MAX_NODES];
    int count;

    if (!ctx || !ctx->dlm || !ctx->lease)
        return;

    count = mxfs_lease_get_active_nodes(ctx->lease, nodes, MXFS_MAX_NODES);
    /* lease registers self at index 0 with state=ACTIVE in mxfs_lease_create,
     * so the returned list already includes us — no append needed.
     *
     * sess11: deliberately NO dead_nodes filtering here.  A dying node
     * leaves the lease (and thus mastership) ONLY at recovery completion
     * (v5_recovered_cb / mxfs_v5_dlm_recovery_complete unregister it) —
     * filtering at refresh time would remaster its resources the moment
     * it is fenced, re-opening the fence→replay-complete torn window the
     * D2 deferred-purge protocol closes.  The dead set only gates
     * RE-registration (announce/connect), which cannot occur before the
     * unregister that makes it matter. */
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

    /*
     * sess132: publish the view to the CAW layer for its escalation
     * diagnostics.  Bumped even when the count could not be read (count <= 0
     * still means "membership changed"), because the generation's job is to
     * separate one view from the next, not to certify the count.
     */
    ctx->mship_view++;
    if (ctx->dlm_caw)
        mxfs_dlm_caw_set_membership(ctx->dlm_caw, ctx->mship_view,
                                    count > 0 ? (uint32_t)count : 0);
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
/* v0.11.80 (D4): hardware-fence a dead/departed node's PR registration
 * BEFORE purging its locks and remastering — a TCP-dead-but-disk-alive
 * peer (partition, stall-then-revive) must lose its write access first,
 * so its next journal write bounces EBADE (WE-RO) and the D1 machinery
 * shuts it down cleanly.  fence_node does READ KEYS classification (no
 * blind preempt of absent keys).  Returns false when OUR OWN key turned
 * out to be gone: this node may itself be the fenced one — it self-fences
 * (freeze via fence_notify) and the caller must NOT continue recovery.
 *
 * sess58: it also returns false on ANY other fence error.  Until then only
 * -ESTALE produced false, so a transient READ KEYS failure — the very
 * failure mxfs_scsipr_fence_node logs as "cannot classify; skipping
 * preempt" — was reported to the caller as a SUCCESSFUL fence.  The caller
 * then replayed that node's journal slice, which is precisely the thing
 * every comment on this path says must not happen to a node that may still
 * be writing.  A fence that did not provably happen is a failed fence.
 *
 * The two zero-returns inside mxfs_scsipr_fence_node that mean "this
 * topology cannot do per-node PR" (P-PR-ADVISORY / -EOPNOTSUPP) still count
 * as fenced here, deliberately: on those rigs D1 (EBADE on write) plus the
 * lease/disklock exclusion carry the fencing duty, and treating them as
 * failures would make every recovery on a tcm_loop rig unresolvable. */
static int v5_pr_fence_dead_node_rc(struct mxfs_v5_dlm *ctx,
                                    mxfs_node_id_t dead_node)
{
    mxfs_node_id_t live[MXFS_MAX_NODES];
    struct mxfs_fence_result fres;
    int nlive = 0, i, fret;

    memset(&fres, 0, sizeof(fres));

    if (!ctx->scsipr)
        return 0;
    /* live member count INCLUDING self, EXCLUDING the victim (the lease
     * may still list a hard-dead node as ACTIVE during the TCP grace). */
    if (ctx->lease) {
        nlive = mxfs_lease_get_active_nodes(ctx->lease, live, MXFS_MAX_NODES);
        for (i = 0; i < nlive; i++) {
            if (live[i] == dead_node) {
                nlive--;
                break;
            }
        }
    }
    if (nlive < 1)
        nlive = 1;      /* self is always live here */
    fret = mxfs_scsipr_fence_node(ctx->scsipr, dead_node, nlive, &fres);
    /*
     * sess71 TRANSITIONAL: the typed outcome is now produced but the
     * replay gates still consume the int, so behaviour here is unchanged
     * except that RESERVATION CONFLICT and "victim key already absent" no
     * longer masquerade as a completed fence.  Log the kind on every
     * attempt so the rig shows which outcome each fence actually reached
     * before the gates start refusing on it (D-FENCED-STAGE-WITHOUT-
     * PROVEN-EXCLUSION / D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION).
     */
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P236-FENCEKIND node=%u kind=%s(%d) proves_excl=%d "
                 "gen=%u rc=%d",
                 dead_node, mxfs_fence_kind_name(fres.kind), (int)fres.kind,
                 mxfs_fence_kind_proves_exclusion(fres.kind) ? 1 : 0,
                 fres.pr_generation, fres.rc);
    if (fret == -ESTALE) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P-PR-SELFFENCE own PR key gone while fencing "
                     "node %u — freezing this node (no auto-re-register)",
                     dead_node);
        if (ctx->fence_notify_fn)
            ctx->fence_notify_fn(ctx->fence_notify_data,
                                 MXFS_SELF_FENCE_PR_KEY_LOST_FENCING);
        return -ESTALE;
    }
    if (fret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P227-FENCEFAIL node=%u rc=%d — the preempt did "
                     "not provably happen, so this node is NOT fenced and "
                     "its slice must not be replayed",
                     dead_node, fret);
        return fret;
    }
    return 0;
}

static bool v5_pr_fence_dead_node(struct mxfs_v5_dlm *ctx,
                                  mxfs_node_id_t dead_node)
{
    return v5_pr_fence_dead_node_rc(ctx, dead_node) == 0;
}

const char *mxfs_recov_blocked_reason(uint32_t reason)
{
    switch (reason) {
    case MXFS_RBLK_NONE:            return "none";
    case MXFS_RBLK_NO_PR:           return "NO_PR";
    case MXFS_RBLK_FENCE_UNPROVEN:  return "FENCE_UNPROVEN";
    case MXFS_RBLK_CERT_UNRECORDED: return "CERT_UNRECORDED";
    case MXFS_RBLK_NO_INTENT:       return "NO_INTENT";
    case MXFS_RBLK_NO_CERTIFICATE:  return "NO_CERTIFICATE";
    case MXFS_RBLK_OWNED_ELSEWHERE: return "OWNED_ELSEWHERE";
    case MXFS_RBLK_EXCL_LAPSED:     return "EXCL_LAPSED";
    case MXFS_RBLK_SELF_FENCED:     return "SELF_FENCED";
    case MXFS_RBLK_NO_INCARNATION:  return "NO_INCARNATION";
    default:                        return "?";
    }
}

/*
 * Record — or refresh — why a slot's recovery is blocked.  first_ms is set once
 * and kept: how LONG a slice has been unrecoverable is the number an operator
 * acts on, and restamping it on every retry would hide exactly that.  attempts
 * counts the retries, which is what distinguishes a transient from a wedge.
 */
static void v5_blocked_set(struct mxfs_v5_dlm *ctx, int slot, uint32_t reason,
                           mxfs_node_id_t victim, mxfs_epoch_t victim_epoch,
                           int rc, const struct mxfs_fence_result *fres)
{
    struct mxfs_recov_blocked *b;
    uint64_t now = mxfs_pal_time_ms();

    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return;
    b = &ctx->blocked[slot];

    if (b->reason == MXFS_RBLK_NONE || b->victim_node != victim) {
        memset(b, 0, sizeof(*b));
        b->first_ms = now;
    }
    b->reason       = reason;
    b->last_rc      = rc;
    b->victim_node  = victim;
    b->victim_epoch = victim_epoch;
    b->victim_key   = (uint64_t)victim;   /* scsipr.c: key == node id */
    b->victim_slot  = (uint16_t)slot;
    b->last_ms      = now;
    b->attempts++;
    if (fres) {
        b->fence_kind    = (uint16_t)fres->kind;
        b->resv_type     = (uint16_t)fres->resv_type;
        b->pr_generation = fres->pr_generation;
    }
}

static void v5_blocked_clear(struct mxfs_v5_dlm *ctx, int slot)
{
    if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
        return;
    memset(&ctx->blocked[slot], 0, sizeof(ctx->blocked[slot]));
}

int mxfs_v5_dlm_blocked_iter(struct mxfs_v5_dlm *ctx, int prev,
                             struct mxfs_recov_blocked *out)
{
    int slot;

    if (!ctx || !out)
        return -1;
    for (slot = prev + 1; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (ctx->blocked[slot].reason != MXFS_RBLK_NONE) {
            *out = ctx->blocked[slot];
            return slot;
        }
    }
    return -1;
}

/*
 * ── sess93: THE PROVER ───────────────────────────────────────────────────
 *
 * v5_pr_fence_dead_node_rc above is the BARE fence: it issues a PREEMPT AND
 * ABORT and throws the typed outcome away.  That is all a caller with no
 * heartbeat slot can do, and it is what D-FENCED-STAGE-WITHOUT-PROVEN-
 * EXCLUSION / D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION are about: exclusion
 * was proved by ONE node (measured sess73: 1 PREEMPT_ABORT_DONE, 30 losers)
 * and consumed by ANOTHER (the replayer is elected by lowest_live_slot, and
 * in the captured run was a loser that dispatched replay 22 ms after its own
 * proves_excl=0).  The proof had nowhere to go, so nothing consumed it.
 *
 * This function is the missing half.  It runs the sess74/75/76 fence-evidence
 * protocol, whose entry points shipped in 0.11.415/416 with ZERO callers:
 *
 *   fence_intent   durable BEFORE the P&A is issued, so a prover death leaves
 *                  "an attempt was made" on the platter instead of a silently
 *                  consumed victim key
 *   PREEMPT AND ABORT
 *   fence_certify  FENCING -> FENCED + UNOWNED in one CAS; refuses to record
 *                  anything that does not prove exclusion
 *
 * GPT ruling (RULE 5, sess93, Q1) — ONE DURABLE INTENT, ONE ISSUING PROVER,
 * ONE COMMAND RESULT, ONE POSSIBLE CERTIFICATE.  The alternative I proposed —
 * let all 31 survivors issue the P&A and let only the intent winner certify —
 * was REFUTED as unsound: a loser can remove the key before the intent owner
 * issues its command, the owner then observes KEY_ABSENT_UNPROVEN, and the
 * loser that actually got PREEMPT_ABORT_DONE is forbidden to certify.  That
 * converts a provable fence into an unrecoverable one.  So a node that does
 * not own the intent issues NO PREEMPT AND ABORT.
 *
 * Three-valued return, because the two callers need different distinctions and
 * collapsing them costs real diagnosis:
 *
 *   0    a certificate for this victim now exists — ours, or one that was
 *        already there.  The slice is fenceable.
 *   > 0  NO certificate.  The death is real and should still be recorded, but
 *        nothing about this slice may be acted on.  v5_settle_resolve routes
 *        such a slot into its residue, so the mount barrier's sess58 item-6A
 *        gate can abort the mount cleanly instead of walking into a 60 s CAW
 *        stall on grants nobody is allowed to release.
 *   < 0  hard stop: our own PR key is gone (we are the fenced node), or this
 *        detector never observed an incarnation and is therefore not a fencing
 *        authority for this victim.
 *
 * 0 does NOT mean "this slice may be replayed".  Nothing here authorises
 * replay; the authority is the certificate, and the only thing that reads it
 * is mxfs_disklock_recovery_replay_authorized(), which every destructive step
 * asks separately (GPT correction 4: the gate must sit below the dispatcher,
 * or a future caller can bypass the dispatcher and recreate the defect).
 *
 * Runs on the heartbeat-monitor thread and on the mount/settle threads.  No
 * call it makes sleeps: fence_intent and fence_certify are CAS + I/O only.
 * fence_takeover, which does sleep MXFS_RECOV_ABANDON_MS, is deliberately NOT
 * called from here (see mxfs_v5_dlm_recovery_acquire).
 */
static int v5_pr_fence_prove(struct mxfs_v5_dlm *ctx, mxfs_node_id_t dead_node,
                             int dead_slot, mxfs_epoch_t dead_epoch)
{
    struct mxfs_recov_fence_auth fauth;
    struct mxfs_fence_result fres;
    mxfs_node_id_t live[MXFS_MAX_NODES];
    uint16_t slice_cnt, slice_idx;
    int nlive = 0, i, rc, fret;

    if (!ctx->disklock || dead_slot < 0 ||
        dead_slot >= MXFS_DISKLOCK_HB_SLOTS)
        return v5_pr_fence_dead_node_rc(ctx, dead_node);

    /*
     * GPT ruling Q3: a victim incarnation of 0 means NOBODY OBSERVED THIS
     * DEATH.  "The lease-only event may mark suspicion or pending work, but
     * it must not create a certified guard, issue a victim-specific fence,
     * authorise replay, release grants, or zero a victim sector."  Issuing a
     * bare P&A here would be exactly the loser-consumes-the-key hazard from
     * Q1, against a victim we cannot even name an incarnation for.
     */
    if (!dead_epoch) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P238-FENCE-NOINC slot=%d node=%u — this detector "
                     "never observed an incarnation stop, so it is not a "
                     "fencing authority for this victim: no PREEMPT AND ABORT "
                     "is issued and no certificate can be produced.  The "
                     "heartbeat monitor owns this slot's death and will supply "
                     "the (slot, node, incarnation) tuple",
                     dead_slot, dead_node);
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_NO_INCARNATION, dead_node,
                       dead_epoch, -ENODATA, NULL);
        return -ENODATA;
    }

    if (!ctx->scsipr) {
        /*
         * No PR context at all.  GPT ruling Q2: this must fail closed —
         * no foreign replay, no grant release, no sector zeroing — and the
         * gate is what enforces it.  Say so once, here, where the reason is
         * still attributable, rather than leaving the refusal to look like a
         * missing descriptor much later.
         */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P238-FENCE-NOPR slot=%d node=%u — no SCSI PR "
                     "context, so exclusion cannot be proved and this slice "
                     "cannot be replayed by anyone.  Recovery is BLOCKED, not "
                     "silently skipped",
                     dead_slot, dead_node);
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_NO_PR, dead_node, dead_epoch,
                       0, NULL);
        return 1;
    }

    slice_cnt = (uint16_t)ctx->log_node_count;
    slice_idx = slice_cnt ? (uint16_t)(dead_slot % slice_cnt) : 0;
    if (!slice_cnt) {
        /* An unsliced FS has no per-node journal, so there is no foreign
         * slice to protect — but fence_intent needs a slice descriptor to
         * validate.  Name the single slice explicitly. */
        slice_cnt = 1;
        slice_idx = 0;
    }

    memset(&fauth, 0, sizeof(fauth));
    /* victim_key == node id (scsipr.c: `victim_key = (uint64_t)victim_node`),
     * so the key the attempt is about is known BEFORE the fence runs.  That is
     * what lets the intent be made durable first without splitting READ KEYS
     * out of mxfs_scsipr_fence_node. */
    rc = mxfs_disklock_recovery_fence_intent(ctx->disklock, dead_slot,
                                             dead_node, dead_epoch,
                                             (uint64_t)dead_node,
                                             slice_idx, slice_cnt, 0, &fauth);
    switch (rc) {
    case 0:
        break;                  /* the attempt is OURS — issue the P&A */
    case -EEXIST:
        /*
         * Somebody already certified this victim.  GPT correction 5: -EEXIST
         * is a STATE-MACHINE HINT, not evidence — do not treat it as "fenced".
         * We simply have nothing to prove; the fresh central gate makes the
         * decision when something destructive is attempted.
         */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P238-FENCE-DONE slot=%d node=%u — this victim is "
                     "already certified fenced by another prover; issuing no "
                     "second PREEMPT AND ABORT.  Authorisation is still "
                     "decided by the replay gate, not by this result",
                     dead_slot, dead_node);
        return 0;
    case -EBUSY:
        /* Another prover holds the fencing-attempt lease.  We issue nothing
         * (Q1).  If we are also the elected replayer we will wait for its
         * certificate in mxfs_v5_dlm_recovery_acquire. */
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_NO_CERTIFICATE, dead_node,
                       dead_epoch, -EBUSY, NULL);
        return 1;
    case -ENOENT:
        /* Sector already CONSUMABLE: the recovery was published. */
        return 0;
    default:
        /*
         * -ESTALE (the sector no longer names this victim), -EPROTO, or I/O.
         * The attempt is NOT durable, so the P&A must not be issued: a
         * preempt whose result cannot be recorded consumes the victim key and
         * destroys this slice's only route to a provable recovery.
         */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P238-FENCE-NOINTENT slot=%d node=%u epoch=%llu "
                     "rc=%d — the fencing intent is not durable, so no "
                     "PREEMPT AND ABORT is issued (an unrecordable preempt "
                     "consumes the victim key and leaves the slice provably "
                     "unrecoverable)",
                     dead_slot, dead_node, (unsigned long long)dead_epoch, rc);
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_NO_INTENT, dead_node,
                       dead_epoch, rc, NULL);
        return 1;
    }

    /* live member count INCLUDING self, EXCLUDING the victim — same rule as
     * the bare fence above. */
    memset(&fres, 0, sizeof(fres));
    if (ctx->lease) {
        nlive = mxfs_lease_get_active_nodes(ctx->lease, live, MXFS_MAX_NODES);
        for (i = 0; i < nlive; i++) {
            if (live[i] == dead_node) {
                nlive--;
                break;
            }
        }
    }
    if (nlive < 1)
        nlive = 1;

    fret = mxfs_scsipr_fence_node(ctx->scsipr, dead_node, nlive, &fres);
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P236-FENCEKIND node=%u kind=%s(%d) proves_excl=%d "
                 "gen=%u rc=%d [prover slot=%d term=%u]",
                 dead_node, mxfs_fence_kind_name(fres.kind), (int)fres.kind,
                 mxfs_fence_kind_proves_exclusion(fres.kind) ? 1 : 0,
                 fres.pr_generation, fres.rc, dead_slot, fauth.fence_term);

    if (fret == -ESTALE) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P-PR-SELFFENCE own PR key gone while fencing "
                     "node %u — freezing this node (no auto-re-register)",
                     dead_node);
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_SELF_FENCED, dead_node,
                       dead_epoch, -ESTALE, &fres);
        if (ctx->fence_notify_fn)
            ctx->fence_notify_fn(ctx->fence_notify_data,
                                 MXFS_SELF_FENCE_PR_KEY_LOST_FENCING);
        return -ESTALE;
    }

    if (mxfs_fence_kind_proves_exclusion(fres.kind)) {
        rc = mxfs_disklock_recovery_fence_certify(ctx->disklock, dead_slot,
                                                  &fauth,
                                                  (uint16_t)fres.kind,
                                                  (uint16_t)fres.resv_type,
                                                  fres.victim_key,
                                                  fres.pr_generation);
        if (rc == 0) {
            v5_blocked_clear(ctx, dead_slot);
            return 0;
        }
        /*
         * Proved but not recorded.  This is the hole GPT named as the largest
         * unaddressed issue in the protocol: the victim key is already
         * consumed, so a successor's retry can only ever reach
         * KEY_ABSENT_UNPROVEN.  Fail closed and say exactly that — do not let
         * it read as an ordinary transient.
         */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P238-FENCE-UNRECORDED slot=%d node=%u rc=%d — "
                     "exclusion was PROVED but the certificate is not durable. "
                     "The victim key is consumed, so no successor can prove it "
                     "again: this slice is BLOCKED and needs operator action",
                     dead_slot, dead_node, rc);
        v5_blocked_set(ctx, dead_slot, MXFS_RBLK_CERT_UNRECORDED, dead_node,
                       dead_epoch, rc, &fres);
        return 1;
    }

    /*
     * The attempt did not prove exclusion (RACE_LOST, KEY_ABSENT_UNPROVEN,
     * NO_RESERVATION, ADVISORY_TOPOLOGY, VIEW_TRUNCATED, ERROR...).  The
     * intent stays standing at FENCING, which is precisely the state that
     * makes "the result is uncertain" distinguishable from "fencing never
     * started".  Nothing is certified, so nothing downstream is authorised —
     * which is the correct outcome (GPT Q2: the safe result of "cannot
     * distinguish dead from partitioned writer" is loss of availability).
     */
    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P238-FENCE-UNPROVEN slot=%d node=%u epoch=%llu "
                 "kind=%s(%d) rc=%d — the fencing attempt is durable but "
                 "proved NO exclusion, so this slice may not be replayed, its "
                 "grants may not be released and its sector may not be zeroed. "
                 "Recovery is BLOCKED on unproven exclusion",
                 dead_slot, dead_node, (unsigned long long)dead_epoch,
                 mxfs_fence_kind_name(fres.kind), (int)fres.kind, fret);
    v5_blocked_set(ctx, dead_slot, MXFS_RBLK_FENCE_UNPROVEN, dead_node,
                   dead_epoch, fret, &fres);
    return 1;
}

static void v5_tcp_declare_dead(struct mxfs_v5_dlm *ctx, mxfs_node_id_t node_id)
{
    if (!v5_pr_fence_dead_node(ctx, node_id))
        return;
    v5_note_dead_node(ctx, node_id);      /* sess11: fenced = retired */
    if (ctx->dlm)
        mxfs_dlm_purge_node(ctx->dlm, node_id);
    if (ctx->lease)
        mxfs_lease_unregister_node(ctx->lease, node_id);
    v5_refresh_active_nodes(ctx);
}

/*
 * sess42 C7 version gate — the disklock monitor confirmed a LIVE
 * protocol-incompatible member (feature block missing/mismatched/corrupt,
 * re-validated on a priority read of the same incarnation).  A member that
 * does not speak our coordination protocol cannot be reasoned with (it will
 * not honour open_holders bits, replay tagging, or purge rules), so the
 * only safe response is to revoke its disk access NOW: SCSI-PR fence makes
 * its next write fail with a reservation conflict → it force-shuts-down →
 * the normal death pipeline (fence/replay/purge) retires it.  The fence is
 * NOT followed by note_dead here — the slot goes through ordinary death
 * detection so its journal slice is replayed exactly like any crash.
 */
static void v5_vergate_cb(void *data, int slot, mxfs_node_id_t node_id,
                          mxfs_epoch_t epoch, int state)
{
    struct mxfs_v5_dlm *ctx = data;
    bool ok;

    ok = v5_pr_fence_dead_node(ctx, node_id);
    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P-VERGATE-FENCE slot=%d node=%u epoch=%llu state=%d "
                 "pr_fence=%s",
                 slot, node_id, (unsigned long long)epoch, state,
                 ok ? "ok" : "FAILED");
}

static void v5_peer_connect_cb_tcp(void *data, mxfs_node_id_t node_id)
{
    struct mxfs_v5_dlm *ctx = data;
    int slot = (int)(node_id % MXFS_MAX_NODES);

    /* sess11: a retired identity reconnecting (zombie peer manager) must
     * not re-register or cancel a pending death. */
    if (v5_node_is_dead(ctx, node_id)) {
        pr_warn_ratelimited(
            "mxfs: P164-DEAD-REJECT connect node=%u — retired identity ignored\n",
            node_id);
        return;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: TCP peer %u connected", node_id);

    /*
     * sess5 (ccloop-4dd7) pve9 split-brain ROOT FIX: an inbound/fallback
     * TCP connect can be this node's FIRST sight of any peer — the
     * accepting node's own discovery of the initiator arrives LATER and
     * early-returns on mxfs_lease_has_node (we register the node below),
     * so the discovery-path single→multi transition NEVER runs here.
     * Without it, the refresh below exits single-node and WIPES the DLM
     * lock table while the XFS layer still believes it holds its single-
     * node grants (pag_dlm_cached etc.) — phantom holds; both nodes then
     * self-master the same resources with ZERO BASTs and split-brain the
     * shared LUN (pve9-1/pve9-2: divergent root dirs within seconds).
     * Mirror the discovery path's ordering: XFS flush + perag/inode DLM
     * cache invalidation (peer_joined_notify) FIRST, then registration/
     * refresh.  was_single gates re-connect flaps to a no-op.
     */
    if (ctx->dlm && mxfs_dlm_is_single_node(ctx->dlm) &&
        ctx->peer_joined_notify_fn) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: TCP peer %u connected while SINGLE-NODE — running deferred single→multi transition (inbound-connect-first join)",
                     node_id);
        ctx->peer_joined_notify_fn(ctx->peer_joined_notify_data);
    }

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

    /* v0.11.79 (D6): a peer that already broadcast NODE_LEAVE was
     * unregistered from the lease and purged — its socket close is the
     * expected tail of a CLEAN departure, not a death.  Skip the suspect
     * marking and the EX self-fence entirely.  A merely-SUSPECT node (lease
     * misses) still has_node==true, so the fast TCP death path is intact
     * for real failures. */
    if (ctx->lease && !mxfs_lease_has_node(ctx->lease, node_id)) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: TCP peer %u closed after clean departure — no death grace",
                     node_id);
        return;
    }

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
    int selfcheck_ticks = 0;

    while (!ctx->tcp_death_stop) {
        int i;
        uint64_t now;

        mxfs_pal_sleep_ms(500);
        if (ctx->tcp_death_stop)
            break;

        /* v0.11.80 (D8): periodic PR self-check (~30s).  READ KEYS is a
         * cheap PR IN; catches a target that silently dropped our
         * registration (measured on QNAP QTS: purges ALL registrations
         * on session events with no PRgen bump) before a write bounces.
         * Unambiguous preemption → self-fence, never re-register. */
        if (++selfcheck_ticks >= 60) {
            selfcheck_ticks = 0;
            if (ctx->scsipr && ctx->lease && ctx->mounted) {
                mxfs_node_id_t live[MXFS_MAX_NODES];
                int nlive = mxfs_lease_get_active_nodes(ctx->lease, live,
                                                        MXFS_MAX_NODES);
                int scret;

                if (nlive < 1)
                    nlive = 1;
                scret = mxfs_scsipr_self_check(ctx->scsipr, nlive);
                {
                    /* D8 RULE-4 probe: every tick's verdict, first 20 */
                    static int d8_tick_logs;

                    if (d8_tick_logs < 20) {
                        d8_tick_logs++;
                        mxfs_pal_log(MXFS_LOG_WARN,
                                     "mxfs: P-D8-TICK nlive=%d ret=%d",
                                     nlive, scret);
                    }
                }
                if (scret == -ESTALE) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mxfs: P-PR-SELFFENCE self-check found own "
                                 "PR key preempted — freezing this node "
                                 "(no auto-re-register)");
                    if (ctx->fence_notify_fn)
                        ctx->fence_notify_fn(ctx->fence_notify_data,
                                             MXFS_SELF_FENCE_PR_KEY_PREEMPTED);
                    return;
                }
            }
        }

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

            if (dead != 0 && ctx->peer &&
                mxfs_peer_is_connected(ctx->peer, dead)) {
                /* ccloop c7ee71c6 sess12: never declare dead a peer the
                 * peer layer holds an ACTIVE socket to.  The proven
                 * incident was an outbound reconnect that skipped
                 * connect_cb (fixed in peer_connect_impl), but ANY
                 * future silent re-establish path must not let this
                 * timer kill a live connection: a wrong death here
                 * purges the lock table (phantom grants at masters),
                 * P164-retires a LIVE identity with no rejoin path,
                 * and forks membership → divergent hash-mastership.
                 * A truly half-dead ACTIVE socket cannot hide: its
                 * next send/recv errors, re-arms the suspect entry,
                 * and the next grace cycle reaps it. */
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: TCP peer %u suspect grace expired but "
                             "peer socket is ACTIVE — cancelling death "
                             "(late/silent reconnect)", dead);
                dead = 0;
            }
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

    /* sess11: a retired identity (withdrawn/fenced/departed) keeps
     * announcing every ~500ms until its zombie mount is unmounted —
     * never let it back into the lease or the peer mesh. */
    if (v5_node_is_dead(ctx, ann->node_id)) {
        pr_warn_ratelimited(
            "mxfs: P164-DEAD-REJECT announce node=%u — retired identity ignored\n",
            ann->node_id);
        return;
    }

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
 * sess131 self-fence: a disklock heartbeat detector says this mount must stop
 * writing.  Relay to the XFS layer, which force-shuts-down the filesystem.
 * The heartbeat thread has already stopped writing.
 *
 * sess79: `reason` distinguishes the detectors.  This function used to state
 * "volume identity changed under live mount" unconditionally, which is true
 * only for MXFS_SELF_FENCE_FS_IDENTITY; on a SLOT_TAKEOVER it told the
 * operator their shared LUN had been reformatted when in fact the LUN is
 * intact and the node was simply fenced by a peer.
 */
static void v5_self_fence_cb(void *data, int reason)
{
    struct mxfs_v5_dlm *ctx = data;

    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P131-SELF-FENCE node %u reason=%s — %s; forcing "
                 "filesystem shutdown",
                 ctx->node_id, mxfs_self_fence_reason_name(reason),
                 mxfs_self_fence_reason_desc(reason));
    if (ctx->fence_notify_fn)
        ctx->fence_notify_fn(ctx->fence_notify_data, reason);
}

/* v0.11.78 (D7): lease-beacon view-signature glue.  TCP-only in effect —
 * on the CAW branch ctx->dlm is NULL, the provider returns 0 and the RX
 * report is a no-op, so wiring is unconditionally safe. */
static uint64_t v5_view_sig_provider(void *data, uint32_t *count)
{
    struct mxfs_v5_dlm *ctx = data;

    return mxfs_dlm_get_view_sig(ctx->dlm, count);
}

static void v5_view_report_cb(void *data, mxfs_node_id_t node,
                              uint32_t count, uint64_t hash)
{
    struct mxfs_v5_dlm *ctx = data;

    mxfs_dlm_report_peer_view(ctx->dlm, node, count, hash);
}

/*
 * sess9 D2 slice-recovery entry point (factored out of v5_lease_expire_cb
 * in sess53 so the mount-time settle can reuse it verbatim).
 *
 * Marks the dead slot recovery-pending, elects a survivor to replay its
 * XFS log slice, and re-runs the election for any other pending slot
 * that may have just lost its elected replayer.  The dead node's CAW
 * grants stay FROZEN throughout — they are released only by
 * mxfs_v5_dlm_recovery_complete once the slice has actually been
 * replayed, which is the whole point of the deferred-purge protocol.
 *
 * Caller must have fenced the node and must have verified
 * ctx->disklock && dead_slot >= 0 && ctx->dead_node_notify_fn.
 * Idempotent: a slot already pending returns immediately.
 */
/*
 * sess61 (GPT item 6B): the ELECT + NOTIFY half, split out so the mount
 * window can defer it.  Requires the slot to be already fenced and durably
 * marked recovery-pending.  Caller must have verified ctx->disklock and
 * ctx->dead_node_notify_fn.
 */
static void v5_dispatch_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot,
                                       mxfs_node_id_t dead_node)
{
    int low;
    int p;
    mxfs_node_id_t pn;

    low = mxfs_disklock_lowest_live_slot(ctx->disklock, dead_slot);
    if (low >= 0 && low == ctx->disklock->local_slot) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: elected (slot %d) to replay dead node %u's "
                     "log slice %d", low, dead_node, dead_slot);
        ctx->dead_node_notify_fn(ctx->dead_node_notify_data,
                                 (uint32_t)dead_slot);
    } else {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: not elected for dead-slice replay "
                     "(lowest live slot %d, local %d) — deferring "
                     "local purge until the slot is reclaimed",
                     low, ctx->disklock->local_slot);
    }

    /*
     * Re-election sweep: if the node that just died was itself the
     * elected replayer of an EARLIER pending slot, that slot would
     * wedge forever.  Recompute the election for every other pending
     * slot against the shrunken live set; replay is LSN-gated and
     * idempotent, so a duplicate election costs only duplicate work.
     */
    for (p = mxfs_disklock_recovery_pending_iter(ctx->disklock, -1, &pn);
         p >= 0;
         p = mxfs_disklock_recovery_pending_iter(ctx->disklock, p, &pn)) {
        if (p == dead_slot)
            continue;
        low = mxfs_disklock_lowest_live_slot(ctx->disklock, p);
        if (low >= 0 && low == ctx->disklock->local_slot) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: re-elected (slot %d) to replay pending "
                         "slice %d (node %u) after replayer death",
                         low, p, pn);
            ctx->dead_node_notify_fn(ctx->dead_node_notify_data,
                                     (uint32_t)p);
        }
    }
}

static void v5_start_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot,
                                    mxfs_node_id_t dead_node,
                                    mxfs_epoch_t victim_epoch)
{
    if (mxfs_disklock_recovery_is_pending(ctx->disklock, dead_slot))
        return;
    mxfs_disklock_mark_recovery_pending(ctx->disklock, dead_slot,
                                        dead_node, victim_epoch);
    v5_dispatch_slice_recovery(ctx, dead_slot, dead_node);
}

/*
 * sess61 (GPT sess57 review item 6B) — a peer died while WE were mounting.
 *
 * Same first half as v5_start_slice_recovery (the node is already fenced by
 * our caller; make its slice recovery durably pending so nothing is lost),
 * but the second half — elect a replayer and hand the slot to the XFS
 * slice-replay hook — cannot run: that hook is registered by
 * mxfs_dlm_cache_init, which runs after xfs_mountfs returns, and the replay
 * it drives forces the log and pushes the AIL, both illegal while
 * xfs_log_mount_finish has recovered intents outstanding.
 *
 * So record the slot and let the mount drive it: the recovery barrier folds
 * in whatever has arrived by the time it runs its inline replay round, and
 * mxfs_v5_dlm_mount_settle dispatches the remainder once the mount is live.
 *
 * What must NOT happen here is the legacy immediate purge.  Its disklock
 * half zeroes the dead node's heartbeat sector, and a zeroed sector is the
 * cluster-wide "this slice has been replayed" broadcast — every peer would
 * then release its deferred local purge for a slice nobody replayed, which
 * is the D2 torn-view defect (sess9) plus the loss of the authority
 * manifest the foreign-replay gate reads.
 *
 * Heartbeat-monitor context.  CORRECTION (sess66): an earlier version of this
 * comment claimed mark_recovery_pending "does device I/O".  It does NOT —
 * disklock.c:1775 only takes ctx->lock and sets recovery_pending/pending_node/
 * pending_epoch in memory.  That matters far beyond this comment: the pending
 * marker is PER-NODE VOLATILE STATE, not a durable cluster-visible
 * reservation.  A node that never witnessed the death has none, and if every
 * witness reboots it is gone entirely.
 *
 * What actually reserves the victim's slot in the window before a durable
 * recovery descriptor exists is the victim's own stale ACTIVE sector:
 * mxfs_disklock_claim_slot's free-slot scan (disklock.c:2811) takes a slot
 * only when it is NOT ACTIVE (or has bad magic / a foreign fs_gen), so an
 * ACTIVE-but-not-ticking record is never claimable no matter how stale it
 * looks.  Any future change that lets a claimant reclaim an "abandoned"
 * ACTIVE slot removes the ONLY protection this window has.
 */
static void v5_defer_slice_recovery(struct mxfs_v5_dlm *ctx, int dead_slot,
                                    mxfs_node_id_t dead_node,
                                    mxfs_epoch_t victim_epoch)
{
    bool first;

    if (!mxfs_disklock_recovery_is_pending(ctx->disklock, dead_slot))
        mxfs_disklock_mark_recovery_pending(ctx->disklock, dead_slot,
                                            dead_node, victim_epoch);

    if (!ctx->mphase_lock || dead_slot >= MXFS_DISKLOCK_HB_SLOTS)
        return;

    mxfs_pal_mutex_lock(ctx->mphase_lock);
    first = !(ctx->mphase_dead_mask & (1ULL << dead_slot));
    ctx->mphase_dead_mask |= (1ULL << dead_slot);
    ctx->mphase_dead_node[dead_slot] = dead_node;
    mxfs_pal_mutex_unlock(ctx->mphase_lock);

    if (first)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P233-MPHASE-DEATH slot=%d node=%u died during "
                     "our mount — fenced and marked recovery-pending, but "
                     "the slice-replay hook does not exist yet.  Its grants "
                     "stay FROZEN (nothing purged) until the mount barrier "
                     "or the post-mount settle recovers the slice; a "
                     "cluster lock it still holds can stall this mount.",
                     dead_slot, dead_node);
}

/*
 * sess86 — the shared node-death body, reached from two detectors with very
 * different evidence:
 *
 *   - the disklock heartbeat monitor, which WATCHED one incarnation stop and
 *     passes (dead_slot, dead_epoch) as arguments; and
 *   - the lease layer, which only knows a node id stopped renewing and passes
 *     (-1, 0).
 *
 * dead_slot < 0 means "resolve it here".
 *
 * ORDERING CHANGED, sess93: the slot is now resolved BEFORE the fence, not
 * after.  The fencing intent must be durable before the PREEMPT AND ABORT is
 * issued (sess74 blocker 1), and the intent lives in the victim's own
 * heartbeat sector — so the prover cannot run without the slot.  The lookup is
 * a pure read of slot_node_id[]/the platter and changes nothing; the old
 * "after the fence" ordering was historical, not load-bearing.
 *
 * DIVERGENCE FROM THE SESS86 PLAN, deliberately: the lease path does NOT
 * resolve the victim incarnation via mxfs_disklock_node_epoch().  That
 * function returns node_track[slot].last_epoch, which is "who is in this slot
 * NOW", not "who died" — the exact category error this whole change exists to
 * remove from mark_recovery_pending.  Feeding it here would name a live
 * successor as the victim AND mark it inc_valid, so recovery_begin's
 * incarnation test would MATCH and publish a guard against a live member with
 * every appearance of having been verified.  Passing 0 instead takes the
 * P237-RECOV-INC-UNOBSERVED arm: same outcome as before this campaign, but
 * labelled as unproven rather than fabricated.
 *
 * And 0 is not merely the safe answer, it is the TRUE one wherever the value
 * is consumed: v5_start_slice_recovery returns early when the slot is already
 * recovery-pending, so dead_epoch only reaches the marker when the monitor has
 * NOT declared this death — i.e. when the lease really is the sole witness and
 * really never observed an incarnation stop.
 */
static void v5_handle_node_death(struct mxfs_v5_dlm *ctx,
                                 mxfs_node_id_t dead_node, int dead_slot,
                                 mxfs_epoch_t dead_epoch)
{
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: node %u (slot %d inc %llu) lease expired/died — "
                 "fencing; recovery starting",
                 dead_node, dead_slot, (unsigned long long)dead_epoch);

    if (ctx->disklock && dead_slot < 0)
        dead_slot = mxfs_disklock_find_node_slot(ctx->disklock, dead_node);

    /*
     * sess9 (ccloop c7ee71c6) D2: DO NOT purge here.  The dead node's
     * journal slice may carry committed-but-partially-destaged
     * transactions (PROVEN drc@16 r13: ifree destaged, dirent-remove
     * abandoned with the log → durable dangling dirent) — releasing its
     * grants before the slice is replayed hands every peer that torn
     * view.  Instead: mark recovery pending; the elected survivor
     * replays the slice, then runs mxfs_v5_dlm_recovery_complete (shared
     * purges + zeroing the dead HB slot); every other survivor's monitor
     * sees the zeroed slot and runs its deferred LOCAL purge
     * (v5_recovered_cb).  Grants held by the dead node stay frozen for
     * the few seconds this takes — conflicting acquires simply wait
     * inside their 60 s budgets, so the sess10 -ETIMEDOUT domino (which
     * motivated the old instant withdraw_release_all) cannot re-form.
     *
     * Both the disklock monitor (2 s scans) and the lease layer (600 s)
     * register this callback — the pending flag doubles as the
     * duplicate-invocation guard.
     */
    if (ctx->disklock && dead_slot >= 0) {
        /*
         * sess93: run the PROVER, not the bare fence.  It makes the fencing
         * intent durable, issues the PREEMPT AND ABORT only if this node owns
         * that intent, and certifies the result into the victim's own sector
         * so the elected replayer — very often a different node — can consume
         * the proof (GPT ruling Q1).
         *
         * A negative return is a hard stop: either our own PR key is gone (we
         * are the fenced node) or this detector never observed an incarnation
         * and is therefore not a fencing authority for this victim.  In the
         * latter case we deliberately do NOT mark the slice pending either: an
         * epoch-0 marker would make v5_start_slice_recovery's is_pending guard
         * swallow the heartbeat monitor's later REAL detection, and the real
         * one is the only one that can ever produce a certificate.
         */
        if (v5_pr_fence_prove(ctx, dead_node, dead_slot, dead_epoch) < 0)
            return;

        /* sess11: from the moment the fence lands, this identity must never
         * re-enter membership — its zombie mount keeps announcing until the
         * operator unmounts it.  (Lease unregistration itself is deferred to
         * recovery completion: mastership must stay frozen on the dead node
         * until its slice is replayed, per the D2 deferred-purge protocol.) */
        v5_note_dead_node(ctx, dead_node);

        if (ctx->dead_node_notify_fn) {
            v5_start_slice_recovery(ctx, dead_slot, dead_node, dead_epoch);
        } else {
            /*
             * sess61 (GPT item 6B): a heartbeat slot means a JOURNAL
             * SLICE, and a journal slice may never be purged before it
             * is replayed — no matter who lacks a replay hook.  This
             * arm is the mount window (hook registered only after
             * xfs_mountfs) and any user-mode holder of a slot.
             */
            v5_defer_slice_recovery(ctx, dead_slot, dead_node, dead_epoch);
        }
        return;
    }

    /*
     * Fallback — the node owns NO heartbeat slot, so it owns no journal
     * slice and there is nothing to replay: a pre-claim death, or a
     * peer known only to the TCP/lease layer.  Purging its in-memory
     * and on-disk records immediately is safe and is the only way they
     * ever go away.
     *
     * sess93: this arm keeps the BARE fence.  There is no victim sector to
     * carry a certificate — that is what "owns no slot" means — so the
     * fence-evidence channel does not exist here and cannot be the authority.
     * Nothing downstream replays a journal slice on the strength of it; the
     * purge below is of in-memory grants and lock records only.
     */
    if (!v5_pr_fence_dead_node(ctx, dead_node))
        return;
    v5_note_dead_node(ctx, dead_node);

    if (ctx->disklock)
        mxfs_disklock_purge_node(ctx->disklock, dead_node);
    if (ctx->dlm) {
        mxfs_dlm_purge_node(ctx->dlm, dead_node);
        v5_refresh_active_nodes(ctx);
    }
    v5_membership_beacon_caw(ctx);     /* v0.6.0: no-op on TCP */
}

/*
 * Lease-layer expiry: node-scoped, no slot and no observed incarnation.
 * See v5_handle_node_death for why 0 is passed rather than a resolved epoch.
 */
static void v5_lease_expire_cb(void *data, mxfs_node_id_t dead_node)
{
    v5_handle_node_death((struct mxfs_v5_dlm *)data, dead_node, -1, 0);
}

/*
 * Disklock heartbeat-monitor expiry: the monitor watched THIS incarnation stop
 * in THIS slot and hands both down.  Never re-resolve either here — a
 * read-back races the victim's own rejoin.
 */
static void v5_disklock_expire_cb(void *data, mxfs_node_id_t dead_node,
                                  int dead_slot, mxfs_epoch_t dead_epoch)
{
    v5_handle_node_death((struct mxfs_v5_dlm *)data, dead_node, dead_slot,
                         dead_epoch);
}

/*
 * sess9 (ccloop c7ee71c6) D2: deferred LOCAL purge, fired by the disklock
 * monitor when a recovery-pending slot reads reclaimed (the elected
 * replayer zeroed it after replaying the slice, or the dead node itself
 * remounted with a new epoch — its own mount recovery replayed it).
 * Runs in the heartbeat thread, same context the old expire-time purge
 * used.
 */
static void v5_recovered_cb(void *data, int slot, mxfs_node_id_t dead_node)
{
    struct mxfs_v5_dlm *ctx = data;

    (void)slot;
    /* sess11: recovery is complete — NOW the dead identity leaves the
     * membership view.  Without this the lease still lists it, refresh
     * pushes the same node list, and hash%active_nodes mastership keeps
     * routing 1/N of all resources to a node that drops master traffic
     * (PROVEN withdraw@2: 184s of P-LKTIMEOUT-REMOTE on ino=128 →
     * rc=-110 → survivor force-shutdown). */
    v5_note_dead_node(ctx, dead_node);
    if (ctx->lease)
        mxfs_lease_unregister_node(ctx->lease, dead_node);
    if (ctx->dlm) {
        mxfs_dlm_purge_node(ctx->dlm, dead_node);
        v5_refresh_active_nodes(ctx);
    }
    v5_membership_beacon_caw(ctx);     /* v0.6.0: no-op on TCP */
}

/*
 * sess9 (ccloop c7ee71c6) D2: called by the elected replayer (XFS-side
 * foreign-replay worker) once the dead node's slice is durably replayed.
 * Order matters: shared purges first (CAW lock table, disklock lock
 * records), local grant purge, THEN zero the dead HB slot — the zeroing
 * is the cluster-wide "replay done" signal that releases every peer's
 * deferred local purge (their monitors poll the slot).  Process context;
 * sleeping I/O throughout.
 */
/*
 * sess54 — settle phase 3, off the mount thread.
 *
 * Waits out the full cluster death threshold on the slots mount step 6.5
 * deferred, then fences and starts slice recovery for whichever are still
 * provably the same frozen incarnation.
 *
 * Why this is not on the mount thread: it only STARTS recovery (mark
 * pending -> elect replayer -> notify); the replay itself is asynchronous
 * either way.  Blocking fill_super for the 62 s confirmation would delay
 * the mount without making anything safer, and on a cold restart after a
 * whole-cluster crash every node would pay it (RULE 0).  Access to
 * whatever the dead peer held is gated by its unreclaimed CAW grants for
 * exactly as long in both arrangements — nothing steals a grant on
 * timeout; acquire exhaustion returns an error and leaves the lock held.
 *
 * Why the confirmation is a dedicated detector and not a re-run of the
 * mount probe: see mxfs_disklock_confirm_dead_mask.  Short-window probes
 * re-baseline, so chaining them can miss an advance that lands on a
 * boundary and declare a live-but-slow node dead.
 *
 * Cancellation is honoured ONLY during the wait.  Once a slot is
 * confirmed, fence -> note dead -> mark pending runs to completion even
 * if an unmount is in progress: stopping after a successful fence but
 * before the recovery is pending would strand that slice's grants with
 * no elected replayer and nobody left to notice.
 */
/*
 * sess56 (D-FOREIGN-REPLAY step 4a — MOUNT ORDERING FIX): shared core of
 * the mount-path recovery barrier and the asynchronous settle worker.
 *
 * Confirms which of the slots recorded at mount step 6.5 are still the
 * same frozen incarnation, fences each confirmed node, notes it dead, and
 * marks its slice recovery pending.  NOTHING is purged here: the on-disk
 * CAW table is the durable authority manifest of every slice in the
 * cohort, so clearing slot A's bits before slice B has been replayed would
 * strip evidence B's replay gate still needs.  The purges are the caller's
 * final step, once the whole cohort is durably replayed.
 *
 * dispatch=true  (settle worker): elect a replayer per slot and hand it to
 *                the registered notify hook — the replay is asynchronous.
 * dispatch=false (mount barrier): mark recovery pending only and return the
 *                mask.  The notify hook is not registered yet at that point
 *                and, more importantly, the caller's own xfs_mountfs is
 *                about to take cluster locks these slots' grants can block,
 *                so the replay must happen synchronously, here, by us.
 *
 * Returns the confirmed+fenced mask.  ctx->mount_stale_mask is left holding
 * only the residue that could not be resolved (fence failure), which the
 * settle worker retries.
 */
static uint64_t v5_settle_resolve(struct mxfs_v5_dlm *ctx, bool dispatch)
{
    uint64_t cand = 0;
    uint64_t confirmed = 0;
    uint64_t resolved = 0;
    uint64_t residue = 0;
    uint32_t samples;
    int nrecov = 0;
    int slot;
    int rc;

    if (!ctx || !ctx->disklock || !ctx->mount_stale_mask)
        return 0;

    /*
     * A slot whose occupant we could not identify at 6.5 is not a fence
     * candidate: fencing is per NODE, and we would not know whom to shoot.
     * Its grants stay frozen, which is the safe direction.
     */
    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (!(ctx->mount_stale_mask & (1ULL << slot)))
            continue;
        if (ctx->mount_stale_node[slot] == 0) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P225-SETTLE-NOID slot=%d frozen but its node "
                         "id was unreadable at mount — cannot fence an "
                         "unknown node, leaving its grants frozen", slot);
            continue;
        }
        cand |= (1ULL << slot);
    }
    if (!cand) {
        ctx->mount_stale_mask = 0;
        return 0;
    }

    samples = ctx->disklock->dead_threshold ?
              ctx->disklock->dead_threshold :
              MXFS_DISKLOCK_DEAD_THRESHOLD;

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P225-SETTLE-VERIFY confirming stale mask 0x%llx over "
                 "%u heartbeat samples (%u ms) before fencing (%s)",
                 (unsigned long long)cand, samples,
                 samples * MXFS_DISKLOCK_HB_INTERVAL_MS,
                 dispatch ? "settle worker" : "mount barrier");

    /*
     * sess86: out_epoch receives the BASELINE incarnation confirm held frozen
     * across the whole window.  That — not a re-read of the sector, which by
     * now may belong to the victim's own reboot — is the incarnation this
     * cohort proved dead, and therefore the only one the pending markers below
     * may name.
     */
    rc = mxfs_disklock_confirm_dead_mask(ctx->disklock, cand,
                                         ctx->mount_stale_node, samples,
                                         &ctx->settle_stop, &confirmed,
                                         ctx->mount_stale_epoch);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P225-SETTLE-VERIFYFAIL rc=%d — deferred slots "
                     "stay frozen, unreplayed", rc);
        return 0;
    }

    if (ctx->settle_stop && !confirmed) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P225-SETTLE-CANCELLED unmount during the "
                     "confirmation window — deferred slots stay frozen");
        return 0;
    }

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        mxfs_node_id_t was = ctx->mount_stale_node[slot];

        if (!(cand & (1ULL << slot)))
            continue;

        if (!(confirmed & (1ULL << slot))) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P225-SETTLE-ALIVE slot=%d node=%u did not "
                         "stay frozen as that incarnation — not dead, "
                         "leaving it alone", slot, was);
            continue;
        }

        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P225-SETTLE-RECOVER slot=%d node=%u confirmed "
                     "dead across %u samples — fencing and starting slice "
                     "recovery (its grants stay frozen until replay "
                     "completes)", slot, was, samples);

        /*
         * sess58 (GPT review item 6A): retry before giving up.  The
         * dominant fence failure is a transient SCSI READ KEYS error, and
         * on the mount-barrier path a residue slot is not merely a leaked
         * grant — it is a slot whose grants will stall xfs_log_mount_finish
         * for the full CAW wait timeout and then fail the mount.  A few
         * seconds spent retrying is cheap against that, and against the
         * 62 s confirmation window already paid to get here.
         */
        {
            int tries = 0;
            int frc = -EIO;

            while (tries < V5_FENCE_RETRIES) {
                if (tries)
                    mxfs_pal_sleep_ms(V5_FENCE_RETRY_MS);
                tries++;
                /*
                 * sess93: the PROVER, not the bare fence.  This site has the
                 * slot and — crucially — ctx->mount_stale_epoch[slot], the
                 * baseline incarnation confirm_dead_mask held frozen across
                 * the whole 62 s window.  That is a genuinely OBSERVED death
                 * of a NAMED incarnation, so it is a fencing authority under
                 * the sess93 Q3 ruling exactly as the heartbeat monitor is.
                 */
                frc = v5_pr_fence_prove(ctx, was, slot,
                                        ctx->mount_stale_epoch[slot]);
                if (frc == 0)
                    break;
                /* A self-fence verdict is terminal: our own PR key is
                 * gone, so WE are the fenced node.  Retrying cannot help
                 * and must not paper over it.  So is -ENODATA: without an
                 * observed incarnation we are not a fencing authority for
                 * this victim at all, and no number of retries changes
                 * that. */
                if (frc == -ESTALE || frc == -ENODATA)
                    break;
            }
            if (frc) {
                mxfs_pal_log(MXFS_LOG_ERR,
                             "mxfs: P225-SETTLE-FENCEFAIL slot=%d node=%u "
                             "rc=%d after %d attempt(s) — cannot fence, so "
                             "its slice must NOT be replayed (it may still "
                             "be writing).  Grants left frozen.",
                             slot, was, frc, tries);
                residue |= (1ULL << slot);
                continue;
            }
        }

        v5_note_dead_node(ctx, was);
        if (dispatch) {
            v5_start_slice_recovery(ctx, slot, was,
                                    ctx->mount_stale_epoch[slot]);
        } else if (!mxfs_disklock_recovery_is_pending(ctx->disklock, slot)) {
            /*
             * Mount barrier: record the durable pending marker (so a crash
             * mid-cohort leaves the slice re-detectable by the survivors'
             * re-election sweep) and let the caller replay it inline.  No
             * election: we are the node whose mount recovery is about to
             * collide with these grants, so we cannot wait on anyone else
             * to clear them.  Replay is LSN-gated and idempotent, so a
             * concurrent duplicate replay costs only duplicate work.
             */
            mxfs_disklock_mark_recovery_pending(ctx->disklock, slot, was,
                                                ctx->mount_stale_epoch[slot]);
        }
        resolved |= (1ULL << slot);
        nrecov++;
    }

    ctx->mount_stale_mask = residue;

    if (nrecov)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P225-SETTLE resolved %d pre-existing dead "
                     "instance(s) (mask 0x%llx, residue 0x%llx)", nrecov,
                     (unsigned long long)resolved,
                     (unsigned long long)residue);

    return resolved;
}

static void v5_settle_worker_fn(void *arg)
{
    (void)v5_settle_resolve((struct mxfs_v5_dlm *)arg, true);
}

/*
 * sess53 (D-FOREIGN-REPLAY step 4a) — MOUNT RECLAIM SETTLE.
 *
 * The closing half of the two-phase mount reclaim:
 *
 *   step 4    kept our previous incarnation's EX/PW bits, because log
 *             recovery replays buffer images that were authored under
 *             exactly that authority, and opened the adopt window.
 *   step 6.5  recorded, rather than purged, the crashed peers' bits,
 *             because those are the authority manifests of journal
 *             slices nobody has replayed yet.
 *   settle    reclaims what is now provably dead, and routes what is
 *             merely unreplayed into the real recovery path.
 *
 * sess56 SPLIT (mount-ordering fix).  These phases used to run as one
 * unit after xfs_mountfs returned.  That was an inversion: xfs_mountfs
 * itself takes blocking cluster locks (xlog_recover_finish's intent
 * replay and iunlink processing bottom out in xfs_free_extent ->
 * blocking AG EX), so both the retained own-slot bits and the deferred
 * peer grants could block the very recovery whose completion was their
 * only release path.  Phases 1-2 and the cohort resolution now run from
 * the pre-xfs_mountfs barrier (mxfs_dlm_mount_recovery_barrier); only
 * phase 3's retry of the unresolved residue is left here.
 *
 *   1. mxfs_v5_dlm_settle_own_slot — own slot, SKIP_TRACKED.  Whatever
 *      recovery genuinely needed has by now ADOPTED (fast path ->
 *      caw_adopt_retained -> tracked); the rest are the dead
 *      incarnation's leftovers and are released.  This CASes per slot,
 *      so it interleaves safely with a concurrent adopt: whichever
 *      writes first wins and the loser re-reads.  Then close the adopt
 *      window — order is load-bearing, closing it before the purge
 *      would let an acquire read a retained bit and return success on
 *      it with no CAS, while the purge was clearing that very bit
 *      underneath.  After the purge every remaining bit of ours is
 *      tracked, so the plain fast path is sound again.
 *
 *   2. mxfs_v5_dlm_mount_recovery_cohort / _cohort_complete — the
 *      deferred stale peers, resolved synchronously on the mount path.
 *
 *   3. mxfs_v5_dlm_mount_settle (here) — whatever the barrier could not
 *      resolve (fence failure) is handed to v5_settle_worker_fn for an
 *      asynchronous retry.  Those slots' CAW grants are NOT touched:
 *      they are released by mxfs_v5_dlm_recovery_complete once the slice
 *      has actually been replayed.
 *
 * This path is not redundant with the disklock monitor.  The monitor
 * only declares a node dead once it has first seen that node's heartbeat
 * ADVANCE (equal_samples is gated on nt->live, which needs
 * changed_samples >= LIVE_THRESHOLD).  A node that was already frozen
 * before we mounted never becomes live, so the monitor never fires for
 * it and its grants would stay stuck-orphan forever.
 *
 * Returns 0 on success, or a negative errno if the own-slot reclaim
 * could not be performed (the mount continues — the failure leaks slots
 * rather than corrupting, and is logged loudly).
 */
int mxfs_v5_dlm_settle_own_slot(struct mxfs_v5_dlm *ctx)
{
    int npurged;
    int rc = 0;

    if (!ctx || !ctx->dlm_caw)
        return 0;

    /* ── Phase 1: reclaim our own un-adopted leftovers ───────────── */
    npurged = mxfs_dlm_caw_purge_dead_nodes_ex(ctx->dlm_caw,
                                               1ULL << ctx->node_slot,
                                               MXFS_CAW_PURGE_SKIP_TRACKED);
    if (npurged < 0) {
        /*
         * Two failures reach here.  -EOVERFLOW: the held table
         * overflowed, so "untracked" no longer implies "dead" and the
         * purge refused to guess.  -EIO (sess59 item 6D): part of the
         * table was unreadable or unwritable, so the reclaim cannot be
         * proven complete.  Either way, leaving the bits costs us slots
         * that peers will block on; clearing them could strip authority
         * from a live holder.  Take the leak, and make it visible.
         */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P226-SETTLE-DEGRADED own-slot reclaim refused "
                     "(%d) — retained authority bits from the previous "
                     "incarnation are LEAKED for this mount; peers will "
                     "block on them until this node unmounts", npurged);
        rc = npurged;
    } else if (npurged > 0) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P225-SETTLE reclaimed %d un-adopted authority "
                     "entries from our previous incarnation", npurged);
    }

    /* ── Phase 2: close the adopt window ─────────────────────────── */
    mxfs_dlm_caw_set_adopt_window(ctx->dlm_caw, false);
    mxfs_pal_log(MXFS_LOG_WARN, "mxfs: P225-ADOPT-WINDOW closed");

    return rc;
}

/*
 * sess56 — mount-path cohort resolution.  Confirm + fence + mark-pending
 * every cross-instance slot recorded at step 6.5, synchronously, and hand
 * the resolved mask back so the caller can replay each slice before any
 * cluster lock is taken.  No purge and no async dispatch: see
 * v5_settle_resolve.
 */
int mxfs_v5_dlm_mount_recovery_cohort(struct mxfs_v5_dlm *ctx,
                                      uint64_t *out_slots)
{
    if (out_slots)
        *out_slots = 0;
    if (!ctx || !ctx->dlm_caw || !ctx->disklock || !ctx->mount_stale_mask)
        return 0;

    ctx->settle_stop = 0;
    if (out_slots)
        *out_slots = v5_settle_resolve(ctx, false);
    else
        (void)v5_settle_resolve(ctx, false);
    return 0;
}

/*
 * sess58 (GPT review item 6A) — is the barrier's unresolved residue safe to
 * carry past this point in the mount?
 *
 * A residue slot is one we confirmed dead over the full heartbeat window but
 * could NOT fence.  We must not replay its slice (it may still be writing),
 * so its grants stay on disk.  If any of them still names a resource,
 * xfs_log_mount_finish's intent replay / iunlink processing can block on it
 * for the whole CAW wait timeout and then fail — mount recovery blocked by a
 * grant whose only release path is a settle that runs after mount recovery
 * finishes.  The caller fails the mount instead of walking into that.
 *
 * Returns 0 when nothing in the residue can block (safe to proceed and leave
 * it to the post-mount settle), 1 when it can, or a negative errno when the
 * table could not be read — which is treated as 1 by the caller, because an
 * unread slot may hold anything.  *out_residue / *out_nslots / *out_nex are
 * filled for the caller's diagnostics.
 */
int mxfs_v5_dlm_mount_residue_blocking(struct mxfs_v5_dlm *ctx,
                                       uint64_t *out_residue,
                                       int *out_nslots, int *out_nex)
{
    int nslots;
    int nex = 0;

    if (out_residue)
        *out_residue = 0;
    if (out_nslots)
        *out_nslots = 0;
    if (out_nex)
        *out_nex = 0;
    if (!ctx || !ctx->dlm_caw || !ctx->mount_stale_mask)
        return 0;

    if (out_residue)
        *out_residue = ctx->mount_stale_mask;

    nslots = mxfs_dlm_caw_footprint_scan(ctx->dlm_caw, ctx->mount_stale_mask,
                                         &nex);
    if (nslots < 0)
        return nslots;
    if (out_nslots)
        *out_nslots = nslots;
    if (out_nex)
        *out_nex = nex;
    return nslots ? 1 : 0;
}

/*
 * sess62 (GPT sess57 review item 6B) — hand the mount the peers that died
 * WHILE it was running.
 *
 * v5_defer_slice_recovery records a slot here when the heartbeat monitor
 * declares a peer dead during our mount.  Such a slot is already fenced and
 * already durably marked recovery-pending, with its CAW grants FROZEN and
 * untouched — exactly the state v5_settle_resolve leaves its own cohort in,
 * so a caller may replay it inline with no further preparation.
 *
 * take() removes the record; whatever the caller does not durably replay
 * and publish MUST be handed back with defer(), or the slot loses its only
 * in-memory route to a replayer election and waits for a survivor's
 * re-election sweep instead — which on a single-survivor cluster is never.
 * Both are idempotent, and the OR-back cannot lose a death that arrived in
 * between.  mphase_dead_node[] is deliberately never cleared, so identity
 * survives a take/defer round trip.
 */
static uint64_t v5_take_late_deaths(struct mxfs_v5_dlm *ctx,
                                    mxfs_node_id_t *nodes)
{
    uint64_t mask;

    if (!ctx || !ctx->mphase_lock)
        return 0;

    mxfs_pal_mutex_lock(ctx->mphase_lock);
    mask = ctx->mphase_dead_mask;
    ctx->mphase_dead_mask = 0;
    if (nodes)
        memcpy(nodes, ctx->mphase_dead_node, sizeof(ctx->mphase_dead_node));
    mxfs_pal_mutex_unlock(ctx->mphase_lock);

    return mask;
}

uint64_t mxfs_v5_dlm_mount_take_late_deaths(struct mxfs_v5_dlm *ctx)
{
    return v5_take_late_deaths(ctx, NULL);
}

void mxfs_v5_dlm_mount_defer_late_deaths(struct mxfs_v5_dlm *ctx,
                                         uint64_t slots)
{
    if (!ctx || !ctx->mphase_lock || !slots)
        return;

    mxfs_pal_mutex_lock(ctx->mphase_lock);
    ctx->mphase_dead_mask |= slots;
    mxfs_pal_mutex_unlock(ctx->mphase_lock);
}

/*
 * sess62 (item 6B) — the mount is live now, so the slots the barrier could
 * not fold into its bounded replay rounds can finally reach the real
 * recovery path: mxfs_dlm_cache_init registered the slice-replay hook just
 * above our caller, and the log force / AIL push that hook's replay performs
 * is legal once xfs_log_mount_finish has completed.
 *
 * v5_dispatch_slice_recovery, NOT v5_start_slice_recovery: these slots are
 * already durably recovery-pending, so start's already-pending guard would
 * return without ever electing a replayer.
 *
 * A slot that is no longer pending was replayed and published by the barrier
 * after all (it handed back everything it did not publish, but a concurrent
 * survivor may also have completed it) — nothing left to dispatch.
 */
static void v5_dispatch_late_deaths(struct mxfs_v5_dlm *ctx)
{
    mxfs_node_id_t nodes[MXFS_DISKLOCK_HB_SLOTS];
    mxfs_node_id_t pn;
    uint64_t mask;
    int slot;

    if (!ctx->disklock)
        return;

    if (!ctx->dead_node_notify_fn) {
        /*
         * No hook even here.  Leave the record in place: the teardown
         * P233-MPHASE-UNDISPATCHED warning is then accurate, and the
         * slices stay frozen + pending on disk, which is the safe
         * direction.
         */
        return;
    }

    mask = v5_take_late_deaths(ctx, nodes);
    if (!mask)
        return;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        if (!(mask & (1ULL << slot)))
            continue;
        if (!mxfs_disklock_recovery_is_pending(ctx->disklock, slot))
            continue;
        /*
         * sess86: name the victim from the LIVE marker, not from the
         * mphase snapshot.  The snapshot was taken when the death was
         * recorded; if that recovery completed and the slot was re-armed
         * for a successor since, the snapshot names the wrong node.  The
         * dispatch itself is slot-scoped and correct either way, but a
         * fence-adjacent log line that names the wrong node is how this
         * campaign's incarnation defects stayed invisible for so long.
         */
        pn = mxfs_disklock_pending_node(ctx->disklock, slot);
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P233-MPHASE-DISPATCH slot=%d node=%u (recorded "
                     "as %u) — peer died during our mount and its slice is "
                     "still unreplayed; electing a replayer now that the "
                     "mount is live",
                     slot, pn, nodes[slot]);
        v5_dispatch_slice_recovery(ctx, slot, pn ? pn : nodes[slot]);
    }
}

int mxfs_v5_dlm_mount_settle(struct mxfs_v5_dlm *ctx)
{
    int rc = 0;

    if (!ctx || !ctx->dlm_caw)
        return 0;

    /* ── Phase 3a: peers that died DURING the mount (sess62, item 6B) ── */
    v5_dispatch_late_deaths(ctx);

    /* ── Phase 3b: retry whatever the mount barrier left unresolved ── */
    if (!ctx->mount_stale_mask || !ctx->disklock)
        return rc;

    if (!ctx->dead_node_notify_fn) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P225-SETTLE-NOREPLAY stale mask 0x%llx but no "
                     "slice-replay hook registered — deferred slots stay "
                     "frozen (grants NOT reclaimed, which is the safe "
                     "direction: nothing may read them unreplayed)",
                     (unsigned long long)ctx->mount_stale_mask);
        ctx->mount_stale_mask = 0;
        return rc;
    }

    ctx->settle_stop = 0;
    ctx->settle_thread = mxfs_pal_thread_create(v5_settle_worker_fn, ctx);
    if (!ctx->settle_thread) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P225-SETTLE-NOTHREAD stale mask 0x%llx but the "
                     "settle worker could not be started — deferred slots "
                     "stay frozen (grants NOT reclaimed)",
                     (unsigned long long)ctx->mount_stale_mask);
        ctx->mount_stale_mask = 0;
        rc = rc ? rc : -ENOMEM;
    }

    return rc;
}

/*
 * sess59 (GPT sess57 review item 6D): this sequence contains IRREVERSIBLE
 * publication points and used to run them with no failure checks at all.
 *
 * The two irreversible acts are the CAW authority purge (removes the dead
 * node's grant bits, which are the manifest each slice's foreign-replay
 * gate reads) and the disklock purge (zeroes the dead node's lock records
 * AND its heartbeat sector — the cluster-wide "slice replayed, run your
 * deferred purges" broadcast).  Ordering and failure handling now:
 *
 *   1. CAW purge.  On failure STOP: the pending marker stays set, the HB
 *      sector stays ACTIVE, so the survivors' re-election sweep re-arms
 *      this whole completion later.  Publishing anyway would tell peers
 *      the node is gone while its authority bits still block acquires
 *      with nobody left to reclaim them.
 *   2. Durable flush.  The CAW purge must be ON THE PLATTER before the
 *      broadcast is issued.  The reverse order survives a target power
 *      loss as "node gone, grants still held, no pending marker" — an
 *      unrecoverable wedge.  The order used here fails as "node still
 *      looks alive" instead, which the death detector simply redoes.
 *   3. disklock purge (the broadcast).  Returns < 0 when it could not
 *      prove completeness; on failure the pending marker again stays set.
 *   4. Only after a proven purge: clear the local pending marker and
 *      beacon.
 *
 * Returns 0 when the recovery is published, or a negative errno when it
 * is not — in which case NOTHING was published and the caller must leave
 * the slot's recovery outstanding.
 */
/*
 * ── sess93: ACQUIRE THE RECOVERY EXECUTION LEASE ─────────────────────────
 *
 * THE gate.  Every destructive step of a foreign-slice recovery — the log
 * replay itself, the CAW authority purge, each milestone advance, and the
 * heartbeat-sector zero that broadcasts "this slice is recovered" — must be
 * authorised by a certificate proving the victim was excluded from the LUN.
 * Until sess93 nothing asked, which is D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION
 * and D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION.
 *
 * GPT ruling (RULE 5, sess93), correction 1: claim ONCE, before the replay,
 * and HOLD the auth across replay and completion.  Re-claiming later makes
 * ownership ambiguous and can mask lost context.  So the tuple is parked in
 * ctx->recov_auth[slot] and every later step presents it.
 *
 * Return values, all of which mean "do not replay, purge or publish":
 *   0         authorised — this node holds the execution lease
 *   -ENODATA  no pending victim identity for this slot (nothing to recover)
 *   -ENOENT   no descriptor: never fenced, or already published
 *   -EPERM    a descriptor exists but is NOT certified — fencing either never
 *             proved exclusion or has not finished.  This is the WAIT state:
 *             the caller re-arms and asks again (GPT Q1: "there is no safety
 *             timeout after which replay becomes allowed").
 *   -EBUSY    another node owns the execution lease and we could not prove it
 *             dead
 *   -ESTALE   the descriptor names a different victim or incarnation
 *
 * MUST NOT run on the heartbeat-monitor thread: the takeover arm below sleeps
 * MXFS_RECOV_ABANDON_MS inside mxfs_disklock_recovery_takeover().  Its callers
 * are the foreign-replay workqueue, the mount thread and the settle worker.
 */
/*
 * sess93 — is the exclusion this recovery rests on STILL TRUE?
 *
 * The certificate in the victim's sector is a durable record of an eviction
 * event.  MEASURED (tests/pr_reregister_probe.sh) that the evicted node can
 * re-register and write seconds later, so the record does not stay true on its
 * own.  GPT ranked this re-check "detect-only; useful, but not safety
 * enforcement" — it cannot prevent a write that races it — and was explicit
 * about what to do when it fires: "do not continue replay.  Enter a
 * failed/blocked state."  So a refusal here is TERMINAL for the recovery, and
 * the cached execution lease is dropped with it.
 *
 * Returns 0 when the exclusion still holds, or the scsipr verdict.  A rig with
 * no PR context returns 0: there is nothing to re-check, and the certificate
 * gate has already refused that configuration upstream.
 */
static int v5_exclusion_recheck(struct mxfs_v5_dlm *ctx, mxfs_node_id_t victim,
                                uint32_t dead_slot, const char *site)
{
    struct mxfs_fence_result fres;
    int rc;

    if (!ctx->scsipr || !victim)
        return 0;

    rc = mxfs_scsipr_exclusion_holds(ctx->scsipr, (uint64_t)victim, &fres);
    if (rc == 0)
        return 0;

    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P239-EXCL-LAPSED site=%s slot=%u victim=%u kind=%s(%d) "
                 "rc=%d — the exclusion this recovery was authorised by no "
                 "longer holds.  NOTHING further is replayed, purged or "
                 "published for this slice; its grants stay frozen",
                 site, dead_slot, victim, mxfs_fence_kind_name(fres.kind),
                 (int)fres.kind, rc);

    v5_blocked_set(ctx, (int)dead_slot,
                   fres.kind == MXFS_FENCE_KIND_SELF_PREEMPTED ?
                       MXFS_RBLK_SELF_FENCED : MXFS_RBLK_EXCL_LAPSED,
                   victim,
                   mxfs_disklock_pending_epoch(ctx->disklock, (int)dead_slot),
                   rc, &fres);

    if (fres.kind == MXFS_FENCE_KIND_SELF_PREEMPTED) {
        /* Our own key is gone: we are the fenced node, and continuing to
         * recover somebody else would be one dead node replaying another's
         * journal.  Same verdict the fence path gives. */
        if (ctx->fence_notify_fn)
            ctx->fence_notify_fn(ctx->fence_notify_data,
                                 MXFS_SELF_FENCE_PR_KEY_LOST_FENCING);
    }
    return rc;
}

int mxfs_v5_dlm_recovery_acquire(struct mxfs_v5_dlm *ctx, uint32_t dead_slot)
{
    struct mxfs_recov_desc desc;
    mxfs_node_id_t dead_node;
    mxfs_epoch_t dead_epoch;
    struct mxfs_recov_auth auth;
    unsigned int stage;
    uint64_t bit;
    int rc;

    if (!ctx || !ctx->disklock || dead_slot >= MXFS_DISKLOCK_HB_SLOTS)
        return -EINVAL;
    bit = 1ULL << dead_slot;

    dead_node = mxfs_disklock_pending_node(ctx->disklock, (int)dead_slot);
    dead_epoch = mxfs_disklock_pending_epoch(ctx->disklock, (int)dead_slot);
    if (!dead_node)
        return -ENODATA;

    /*
     * Already holding it?  Revalidate against the platter rather than trust
     * the cached tuple — the whole point of the lease is that a takeover while
     * we worked must be visible, and only a fresh read can show it.
     */
    if (ctx->recov_auth_mask & bit) {
        rc = mxfs_disklock_recovery_replay_authorized(ctx->disklock,
                                                      (int)dead_slot,
                                                      dead_node, dead_epoch,
                                                      &ctx->recov_auth[dead_slot],
                                                      "reacquire");
        if (rc == 0) {
            rc = v5_exclusion_recheck(ctx, dead_node, dead_slot, "reacquire");
            if (rc) {
                ctx->recov_auth_mask &= ~bit;
                return rc;
            }
            return 0;
        }
        ctx->recov_auth_mask &= ~bit;
    }

    memset(&auth, 0, sizeof(auth));
    rc = mxfs_disklock_recovery_claim(ctx->disklock, (int)dead_slot,
                                      dead_node, dead_epoch, &auth);
    if (rc >= 0) {
        ctx->recov_auth[dead_slot] = auth;
        ctx->recov_auth_mask |= bit;
        /* Re-check BEFORE announcing the grant.  An earlier cut logged
         * "this slice may now be replayed" and then revoked it microseconds
         * later on the same line of evidence — a log that states a permission
         * it does not have is worse than no log. */
        stage = (unsigned int)rc;
        rc = v5_exclusion_recheck(ctx, dead_node, dead_slot, "claim");
        if (rc) {
            ctx->recov_auth_mask &= ~bit;
            return rc;
        }
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P238-RECOV-LEASE slot=%u node=%u inc=%llu stage=%u "
                     "— execution lease acquired against a CERTIFIED fence and "
                     "the exclusion still holds; this slice may now be replayed",
                     dead_slot, dead_node, (unsigned long long)dead_epoch,
                     stage);
        return 0;
    }

    if (rc == -EBUSY) {
        /*
         * Someone else owns the execution lease.  GPT correction 2, and the
         * mechanism D-RECOVERY-TAKEOVER-UNREACHABLE needs: owner alive → wait;
         * owner PROVED DEAD → take over; owner status unknown → stay blocked.
         *
         * "Proved dead" here is exactly mxfs_disklock_recovery_takeover()'s
         * documented precondition — we already confirmed that node's session
         * dead AND fenced it from the LUN — because v5_note_dead_node() is set
         * only on the far side of a completed fence.  Elapsed time is NOT a
         * proof and is never used as one; the ABANDON_MS wait inside takeover
         * re-proves only that nothing changed on the sector meanwhile.
         */
        memset(&desc, 0, sizeof(desc));
        if (mxfs_disklock_recovery_read(ctx->disklock, (int)dead_slot,
                                        &desc) == 0 &&
            desc.owner_node && desc.owner_node != MXFS_RECOV_OWNER_NONE &&
            v5_node_is_dead(ctx, desc.owner_node)) {
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P238-RECOV-TAKEOVER slot=%u node=%u owner=%u "
                         "stage=%u — the elected replayer died mid-recovery "
                         "and we proved it dead; attempting takeover (blocks "
                         "%u ms re-proving the descriptor is abandoned)",
                         dead_slot, dead_node, desc.owner_node, desc.stage,
                         MXFS_RECOV_ABANDON_MS);
            memset(&auth, 0, sizeof(auth));
            rc = mxfs_disklock_recovery_takeover(ctx->disklock,
                                                 (int)dead_slot, &auth);
            if (rc >= 0) {
                ctx->recov_auth[dead_slot] = auth;
                ctx->recov_auth_mask |= bit;
                stage = (unsigned int)rc;
                rc = v5_exclusion_recheck(ctx, dead_node, dead_slot,
                                          "takeover");
                if (rc) {
                    ctx->recov_auth_mask &= ~bit;
                    return rc;
                }
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P238-RECOV-TAKEN slot=%u node=%u stage=%u "
                             "— recovery taken over from a dead owner; RESUME "
                             "from this stage, do not re-run earlier ones",
                             dead_slot, dead_node, stage);
                return 0;
            }
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P238-RECOV-TAKEOVER-REFUSED slot=%u node=%u "
                         "rc=%d — the owner is not abandoned after all (it "
                         "advanced the descriptor, or a third node took it); "
                         "leaving the recovery to whoever holds it",
                         dead_slot, dead_node, rc);
            return -EBUSY;
        }
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: P238-RECOV-OWNED slot=%u node=%u owner=%u — "
                     "another survivor owns this recovery and we have NOT "
                     "proved it dead; waiting rather than racing it",
                     dead_slot, dead_node, desc.owner_node);
        v5_blocked_set(ctx, (int)dead_slot, MXFS_RBLK_OWNED_ELSEWHERE,
                       dead_node, dead_epoch, -EBUSY, NULL);
        ctx->blocked[dead_slot].owner_node = desc.owner_node;
        return -EBUSY;
    }

    if (rc == -EPERM) {
        /*
         * The WAIT state.  A descriptor exists but carries no proof: either a
         * prover holds a live fencing attempt (stage=FENCING) or every attempt
         * so far reached a kind that proves nothing.  Both are refusals, and
         * the difference is for the admin, not for the gate — GPT Q1: after an
         * operational threshold "change what the admin sees, not what is
         * authorized".  disklock's P236-CLAIM-UNCERTIFIED already prints the
         * exact reason on every call.
         *
         * ONE case is actionable rather than merely waitable: the prover DIED
         * with the intent durable.  Nobody is going to finish that attempt, so
         * the slice would wait forever.  Take the attempt lease over and issue
         * a NEW PREEMPT AND ABORT — never certify the dead prover's result,
         * which sess74 ruled an unsound inference.  Same precondition as the
         * execution takeover: we must ALREADY have proved that prover dead.
         */
        memset(&desc, 0, sizeof(desc));
        if (mxfs_disklock_recovery_read(ctx->disklock, (int)dead_slot,
                                        &desc) == 0 &&
            desc.stage == MXFS_RECOV_STAGE_FENCING &&
            desc.fence_prover_node &&
            desc.fence_prover_node != ctx->node_id &&
            v5_node_is_dead(ctx, desc.fence_prover_node)) {
            struct mxfs_recov_fence_auth fauth;
            int frc;

            memset(&fauth, 0, sizeof(fauth));
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P238-FENCE-TAKEOVER slot=%u node=%u prover=%u "
                         "term=%u — the prover died holding the fencing "
                         "attempt; taking the attempt lease over to issue a "
                         "NEW PREEMPT AND ABORT (its result is ours to "
                         "certify; the dead prover's never was)",
                         dead_slot, dead_node, desc.fence_prover_node,
                         desc.fence_term);
            frc = mxfs_disklock_recovery_fence_takeover(ctx->disklock,
                                                        (int)dead_slot,
                                                        (uint64_t)dead_node,
                                                        &fauth);
            if (frc == 0) {
                /*
                 * The attempt is ours now.  v5_pr_fence_prove's fence_intent
                 * call resumes it (owner and fence_prover_node are both us
                 * after the takeover CAS) and then issues the P&A + certify.
                 *
                 * If the victim key is already gone, no exclusion can be
                 * proved and the slice stays unreplayable.  sess74: that is
                 * the correct outcome, not a bug to optimise away — and it is
                 * exactly the crash hole GPT flagged (a P&A that completed
                 * before the prover died left its proof only in volatile
                 * memory).
                 */
                (void)v5_pr_fence_prove(ctx, dead_node, (int)dead_slot,
                                        dead_epoch);
            } else if (frc != -EEXIST) {
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P238-FENCE-TAKEOVER-REFUSED slot=%u "
                             "node=%u rc=%d — the fencing attempt is not "
                             "abandoned after all; leaving it alone",
                             dead_slot, dead_node, frc);
                return -EPERM;
            }
            /* -EEXIST means somebody certified while we waited: either way,
             * re-ask the claim rather than assume. */
            memset(&auth, 0, sizeof(auth));
            rc = mxfs_disklock_recovery_claim(ctx->disklock, (int)dead_slot,
                                              dead_node, dead_epoch, &auth);
            if (rc >= 0) {
                ctx->recov_auth[dead_slot] = auth;
                ctx->recov_auth_mask |= bit;
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P238-RECOV-LEASE slot=%u node=%u inc=%llu "
                             "stage=%d — execution lease acquired after a "
                             "fencing-attempt takeover",
                             dead_slot, dead_node,
                             (unsigned long long)dead_epoch, rc);
                return 0;
            }
            return rc < 0 ? rc : -EPERM;
        }
        v5_blocked_set(ctx, (int)dead_slot, MXFS_RBLK_NO_CERTIFICATE,
                       dead_node, dead_epoch, -EPERM, NULL);
        ctx->blocked[dead_slot].prover_node = desc.fence_prover_node;
        ctx->blocked[dead_slot].fence_term = (uint16_t)desc.fence_term;
        return -EPERM;
    }
    return rc;
}

/*
 * sess93 — release a lease we no longer hold on disk, or are done with.  The
 * on-disk descriptor is authoritative; this only drops our cached copy so the
 * next acquire re-reads the platter instead of presenting a stale tuple.
 */
void mxfs_v5_dlm_recovery_release(struct mxfs_v5_dlm *ctx, uint32_t dead_slot)
{
    if (!ctx || dead_slot >= MXFS_DISKLOCK_HB_SLOTS)
        return;
    ctx->recov_auth_mask &= ~(1ULL << dead_slot);
}

int mxfs_v5_dlm_recovery_complete(struct mxfs_v5_dlm *ctx, uint32_t dead_slot)
{
    mxfs_node_id_t dead_node;
    mxfs_epoch_t dead_epoch;
    struct mxfs_recov_auth auth;
    int rc;

    /* sess10 (ccloop c7ee71c6): both bail paths below were SILENT — a
     * withdraw_recovery_test FAIL showed the elected replayer finish the
     * slice replay yet never print P163-RECOVERY-COMPLETE, with nothing
     * wedged; name the exit taken so the next run is decisive. */
    if (!ctx || !ctx->disklock || dead_slot >= MXFS_DISKLOCK_HB_SLOTS) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P163-COMPLETE-BAIL slot=%u ctx=%d disklock=%d",
                     dead_slot, ctx ? 1 : 0,
                     (ctx && ctx->disklock) ? 1 : 0);
        return -EINVAL;
    }
    /*
     * sess86: capture the victim identity ONCE, here, and use that snapshot
     * for the rest of the function.  Everything below — recovery_begin, the
     * purges, the broadcast — can run for seconds, during which the monitor
     * may legitimately re-arm this slot's marker for a SUCCESSOR.  Re-reading
     * pending_node/pending_epoch later would silently retarget the completion
     * onto that successor and retire a marker whose slice was never replayed.
     * The compare-and-clear at the end is what turns that race into a loud
     * P237-PENDING-REARMED instead of a lost recovery.
     */
    dead_node = mxfs_disklock_pending_node(ctx->disklock, (int)dead_slot);
    dead_epoch = mxfs_disklock_pending_epoch(ctx->disklock, (int)dead_slot);
    if (!dead_node) {
        /* Not marked pending (legacy path already purged) — nothing to
         * complete. */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P163-COMPLETE-NOPEND slot=%u pending=%d — "
                     "no pending node recorded; completion skipped",
                     dead_slot,
                     mxfs_disklock_recovery_is_pending(ctx->disklock,
                                                      (int)dead_slot) ? 1 : 0);
        return 0;
    }

    /*
     * ── 0. Lay down the DURABLE FENCE record (sess65, GPT rule 1) ──
     *
     * The ACTIVE→GUARD{FENCED} CAS must be on the platter BEFORE the first
     * purge.  Purging first is a crash hole: the heartbeat still reads ACTIVE
     * — so every peer believes the victim is a live member — while half the
     * authority evidence its own replay gate needs is already destroyed, and
     * nothing on disk records that a recovery was ever in flight.
     *
     * Reaching this function means the victim's slice has been durably
     * replayed (every caller flushes first), so the descriptor goes straight
     * on to IMAGES_REPLAYED.
     */
    {
        rc = mxfs_v5_dlm_recovery_acquire(ctx, dead_slot);
        if (rc == -ENOENT || rc == -ESTALE) {
            /*
             * sess93: recovery_claim collapses several on-disk states into
             * -ENOENT/-ESTALE, and the correct response differs completely
             * between them.  Classify before deciding — retiring the marker on
             * the wrong one loses a recovery, and refusing on the wrong one
             * livelocks against a rejoined member.
             */
            int st = mxfs_disklock_recovery_slot_status(ctx->disklock,
                                                        (int)dead_slot,
                                                        dead_node, dead_epoch);
            if (st == MXFS_RECOV_SLOT_CONSUMABLE) {
                /* Already zeroed: another survivor published this recovery.
                 * Nothing left for us to purge or broadcast — drop our pending
                 * marker and report success honestly. */
                mxfs_disklock_clear_recovery_pending(ctx->disklock,
                                                     (int)dead_slot, dead_node,
                                                     dead_epoch);
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P234-COMPLETE-ALREADY slot=%u node=%u — the "
                             "slot is already CONSUMABLE; another survivor "
                             "published this recovery",
                             dead_slot, dead_node);
                return 0;
            }
            if (st == MXFS_RECOV_SLOT_SUPERSEDED) {
                /*
                 * sess86: the victim itself reclaimed this slot and its own
                 * mount recovery replayed the ENTIRE slice (claim pass-1 sets
                 * slice_adopted = false).  The recovery we were holding is
                 * discharged — by someone else, but discharged.
                 *
                 * Retire the marker and return 0.  NOT the refusal arm below:
                 * that leaves the marker set for a retry, and every retry
                 * would re-derive the same supersession against a node that is
                 * now LIVE — a livelock whose each iteration attempts a guard
                 * on a healthy member.  Nothing is purged and nothing is
                 * broadcast: the successor owns the slot now and its sector is
                 * not ours to zero.
                 */
                rc = mxfs_disklock_clear_recovery_pending(ctx->disklock,
                                                          (int)dead_slot,
                                                          dead_node, dead_epoch);
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P237-COMPLETE-SUPERSEDED slot=%u node=%u "
                             "inc=%llu clear=%d — the victim rejoined and "
                             "replayed its own slice; our pending recovery is "
                             "discharged, nothing purged, nothing published",
                             dead_slot, dead_node,
                             (unsigned long long)dead_epoch, rc);
                return 0;
            }
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P238-COMPLETE-UNFENCED slot=%u node=%u inc=%llu "
                         "state=%d — this slice carries NO fence certificate, "
                         "so nothing may be purged, released or published.  "
                         "The slice replay that got us here was not authorised "
                         "either; the pending marker and heartbeat record stay "
                         "set",
                         dead_slot, dead_node, (unsigned long long)dead_epoch,
                         st);
            return -EPERM;
        }
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P238-COMPLETE-UNAUTHORIZED slot=%u node=%u "
                         "rc=%d — no recovery execution lease against a proven "
                         "exclusion, so NOTHING is purged and nothing is "
                         "published; the pending marker and heartbeat record "
                         "stay set for a retry",
                         dead_slot, dead_node, rc);
            return rc;
        }
        auth = ctx->recov_auth[dead_slot];

        /*
         * GPT correction 4: the gate belongs immediately above every
         * destructive primitive, not only at the dispatcher.  This is the last
         * point before the CAW authority purge — the first irreversible step.
         */
        rc = mxfs_disklock_recovery_replay_authorized(ctx->disklock,
                                                      (int)dead_slot,
                                                      dead_node, dead_epoch,
                                                      &auth, "complete-start");
        if (rc < 0) {
            mxfs_v5_dlm_recovery_release(ctx, dead_slot);
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P238-COMPLETE-REFUSED slot=%u node=%u rc=%d — "
                         "the gate refused at the last point before the "
                         "irreversible purge; nothing is published",
                         dead_slot, dead_node, rc);
            return rc;
        }

        /*
         * sess93 — and once more here, at the true point of no return.  The
         * certificate was written before the replay; the CAW authority purge
         * and the sector zero below it are irreversible.  If the victim came
         * back while we replayed, this is the last place it can be caught.
         */
        rc = v5_exclusion_recheck(ctx, dead_node, dead_slot, "complete");
        if (rc) {
            mxfs_v5_dlm_recovery_release(ctx, dead_slot);
            return rc;
        }

        rc = mxfs_disklock_recovery_advance(ctx->disklock, (int)dead_slot,
                                            MXFS_RECOV_STAGE_IMAGES_REPLAYED,
                                            &auth);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P234-COMPLETE-REPLAYEDFAIL slot=%u node=%u "
                         "rc=%d — the replay milestone is not durable; "
                         "recovery is NOT published",
                         dead_slot, dead_node, rc);
            return rc;
        }
    }

    /* ── 1. CAW authority purge (irreversible; must succeed) ── */
    if (ctx->dlm_caw) {
        rc = mxfs_dlm_caw_purge_node(ctx->dlm_caw, (uint8_t)dead_slot);
        if (rc < 0) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "mxfs: P230-COMPLETE-CAWFAIL slot=%u node=%u rc=%d "
                         "— the dead node's CAW authority bits could not be "
                         "purged, so its recovery is NOT published; the "
                         "pending marker and heartbeat record stay set and "
                         "the completion will be retried",
                         dead_slot, dead_node, rc);
            return rc;
        }
    }

    /* ── 2. The purge must be durable before the broadcast ── */
    rc = mxfs_pal_bdev_flush(ctx->dev);
    if (rc) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P230-COMPLETE-FLUSHFAIL slot=%u node=%u rc=%d "
                     "— cannot certify the replayed slice and the CAW purge "
                     "are on the platter, so the recovery is NOT published",
                     dead_slot, dead_node, rc);
        return rc;
    }

    /*
     * ── 2b. The grants are gone AND durable: record the milestone ──
     *
     * This is the stage that makes the slot eligible to become CONSUMABLE —
     * mxfs_disklock_purge_node's freeze gate refuses to zero the sector below
     * it.  It goes here, after the flush, because it asserts a fact about the
     * platter, not about our intent.
     */
    rc = mxfs_disklock_recovery_advance(ctx->disklock, (int)dead_slot,
                                        MXFS_RECOV_STAGE_GRANTS_RELEASED,
                                        &auth);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P234-COMPLETE-RELEASEDFAIL slot=%u node=%u rc=%d "
                     "— the CAW purge is durable but the milestone that "
                     "authorises the broadcast is not; recovery is NOT "
                     "published and the descriptor keeps the slot frozen",
                     dead_slot, dead_node, rc);
        return rc;
    }

    /* sess11: drop the dead identity from the lease BEFORE refreshing, or
     * the refresh re-reads the same stale list and mastership never
     * leaves the dead node (see v5_recovered_cb).  Elected replayer runs
     * this; every other survivor runs the identical pair in
     * v5_recovered_cb when its monitor sees the zeroed slot. */
    v5_note_dead_node(ctx, dead_node);
    if (ctx->lease)
        mxfs_lease_unregister_node(ctx->lease, dead_node);
    if (ctx->dlm) {
        mxfs_dlm_purge_node(ctx->dlm, dead_node);
        v5_refresh_active_nodes(ctx);
    }

    /* ── 3. Zero the dead node's lock records + HB sector — the broadcast ── */
    rc = mxfs_disklock_purge_node(ctx->disklock, dead_node);
    if (rc < 0) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P230-COMPLETE-PURGEFAIL slot=%u node=%u rc=%d "
                     "— the broadcast (dead heartbeat zero) could not be "
                     "proven complete; recovery stays pending and peers keep "
                     "their deferred purges armed",
                     dead_slot, dead_node, rc);
        return rc;
    }

    /* ── 4. Published.  Local bookkeeping last. ── */
    /* sess93: the sector is zeroed, so the execution lease it lived in no
     * longer exists.  Drop our cached tuple rather than let a later acquire
     * present a token for a descriptor that is gone. */
    mxfs_v5_dlm_recovery_release(ctx, dead_slot);
    v5_blocked_clear(ctx, (int)dead_slot);
    rc = mxfs_disklock_clear_recovery_pending(ctx->disklock, (int)dead_slot,
                                              dead_node, dead_epoch);
    if (rc == -ESTALE)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P237-COMPLETE-REARMED slot=%u node=%u inc=%llu — "
                     "this recovery published, but the slot was re-armed for "
                     "another victim while it ran; that one is still owed and "
                     "its marker is deliberately left standing",
                     dead_slot, dead_node, (unsigned long long)dead_epoch);
    v5_membership_beacon_caw(ctx);
    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P163-RECOVERY-COMPLETE slot=%u node=%u — slice "
                 "replayed, shared purges done, dead slot zeroed (peers "
                 "will run their deferred purges)",
                 dead_slot, dead_node);
    return 0;
}

/*
 * sess56 — the deferred half of the mount-path cohort.
 *
 * Called only once EVERY slice in the cohort has been durably replayed.
 * Purging per slot as each slice finished would violate GPT's cross-slice
 * evidence rule: the on-disk CAW table is the shared authority manifest,
 * and slice B's replay gate may still need bits that belong to slot A.
 * A crash between the replays and this call leaves every bit intact, so
 * the next mount re-detects the whole cohort and re-replays it — which is
 * safe because replay is LSN-gated and idempotent.
 *
 * sess59 (GPT item 6D): a slot whose completion could not be PUBLISHED
 * (CAW purge, flush or heartbeat zero failed) is left out of
 * *out_published and the function returns the first error.  Its pending
 * marker and heartbeat record are still on disk, so the survivors'
 * re-election sweep — or the next mount — will find and redo it.  One
 * slot failing never stops the others: each is independently recoverable.
 */
int mxfs_v5_dlm_mount_cohort_complete(struct mxfs_v5_dlm *ctx,
                                      uint64_t slots,
                                      uint64_t *out_published)
{
    uint64_t published = 0;
    int first_err = 0;
    int slot;

    if (out_published)
        *out_published = 0;
    if (!ctx || !slots)
        return 0;

    for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
        int rc;

        if (!(slots & (1ULL << slot)))
            continue;
        rc = mxfs_v5_dlm_recovery_complete(ctx, (uint32_t)slot);
        if (rc) {
            if (!first_err)
                first_err = rc;
            continue;
        }
        published |= (1ULL << slot);
    }

    if (out_published)
        *out_published = published;
    if (first_err)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P230-COHORT-PARTIAL requested=0x%llx "
                     "published=0x%llx first_err=%d — the unpublished "
                     "slices stay pending and will be retried",
                     (unsigned long long)slots,
                     (unsigned long long)published, first_err);
    return first_err;
}

/* ── sess43: recovery-guard passthroughs (unclaimed-bucket sweep) ── */

int mxfs_v5_dlm_local_slot(struct mxfs_v5_dlm *ctx)
{
    if (!ctx || !ctx->disklock)
        return -1;
    return mxfs_disklock_get_slot(ctx->disklock);
}

int mxfs_v5_dlm_slot_unclaimed(struct mxfs_v5_dlm *ctx, int slot)
{
    if (!ctx || !ctx->disklock)
        return -EINVAL;
    return mxfs_disklock_slot_unclaimed(ctx->disklock, slot);
}

int mxfs_v5_dlm_guard_slot(struct mxfs_v5_dlm *ctx, int slot)
{
    if (!ctx || !ctx->disklock)
        return -EINVAL;
    return mxfs_disklock_guard_slot(ctx->disklock, slot);
}

int mxfs_v5_dlm_guard_refresh(struct mxfs_v5_dlm *ctx)
{
    if (!ctx || !ctx->disklock)
        return -EINVAL;
    return mxfs_disklock_guard_refresh(ctx->disklock);
}

void mxfs_v5_dlm_unguard_slot(struct mxfs_v5_dlm *ctx)
{
    if (ctx && ctx->disklock)
        mxfs_disklock_unguard(ctx->disklock);
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

    /* sess61 item 6B: must exist before the heartbeat monitor can fire
     * v5_lease_expire_cb (step 6 below), and on EVERY transport — the
     * mount-window death path is not TCP-specific. */
    ctx->mphase_lock = mxfs_pal_mutex_create();
    if (!ctx->mphase_lock) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: DLM init: mount-phase lock alloc failed");
        mxfs_pal_free(ctx);
        return NULL;
    }

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
    ctx->log_node_count = opts->log_node_count;
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
                    /* v0.11.75: the device HAS PR but refused our
                     * REGISTER — peers may hold/enforce WE-RO while we
                     * are unfenced, so every write (incl. the journal)
                     * can bounce EBADE at any moment while the mount
                     * looks healthy (proven on the QNAP physical rig).
                     * Parity with the CAW branch: abort the mount.
                     * A device with NO PR support returns 0 from
                     * register (via -EOPNOTSUPP) and proceeds as
                     * before. */
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mxfs: TCP SCSI PR register failed — "
                                 "aborting mount (node would be unfenced "
                                 "under a possible WE-RO reservation)");
                    mxfs_scsipr_destroy(ctx->scsipr);
                    ctx->scsipr = NULL;
                    mxfs_peer_shutdown(ctx->peer);
                    ctx->peer = NULL;
                    mxfs_dlm_destroy(ctx->dlm);
                    ctx->dlm = NULL;
                    goto err_free;
                }
                mxfs_scsipr_reserve(ctx->scsipr);
                /* v0.11.80 (D8): provisioning-time conformance probe —
                 * says at mount whether per-node PR is real on this
                 * target/topology or advisory-only. */
                mxfs_scsipr_probe(ctx->scsipr);
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
                                             v5_disklock_expire_cb, ctx);
                /* sess9 D2: deferred-purge release when the dead slot
                 * reads reclaimed (slice replay done). */
                mxfs_disklock_set_recovered_cb(ctx->disklock,
                                               v5_recovered_cb, ctx);

                /* sess42 C7 version gate (TCP transport shares the LUN, so
                 * the same disk-level admission applies).  On refusal:
                 * withdraw cleanly (this path built peer+dlm already). */
                mxfs_disklock_set_vergate_cb(ctx->disklock,
                                             v5_vergate_cb, ctx);
                ret = mxfs_disklock_join_gate(ctx->disklock, 0);
                if (ret) {
                    mxfs_pal_log(MXFS_LOG_ERR,
                                 "mxfs: C7 version gate refused join (%d) — "
                                 "aborting cluster mount (tcp)", ret);
                    mxfs_disklock_stop_heartbeat(ctx->disklock);
                    mxfs_disklock_release_slot(ctx->disklock);
                    mxfs_disklock_destroy(ctx->disklock);
                    ctx->disklock = NULL;
                    if (ctx->peer) {
                        mxfs_peer_shutdown(ctx->peer);
                        ctx->peer = NULL;
                    }
                    if (ctx->dlm) {
                        mxfs_dlm_destroy(ctx->dlm);
                        ctx->dlm = NULL;
                    }
                    goto err_scsipr;
                }
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
            /* v0.11.78 (D7): view-signature piggyback — peers prove
             * membership convergence instead of the 20s settle window. */
            mxfs_lease_set_view_provider(ctx->lease,
                                         v5_view_sig_provider, ctx);
            mxfs_lease_set_view_report_cb(ctx->lease,
                                          v5_view_report_cb, ctx);
            ret = mxfs_lease_start(ctx->lease);
            if (ret)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: lease start failed: %d", ret);
        }

        ctx->mounted = true;

        /* Print BEFORE the settle gate below: run.sh's convergence awk
         * resets its beacon window at this line, and the joiner's only
         * MXFS-MEMBERSHIP beacon fires DURING the gate (the join
         * callbacks) — printing after would orphan that beacon and hard-
         * fail prep ("no beacon this incarnation"). */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: TCP DLM initialized (port=%u node_id=%u slot=%d)",
                     dlm_port, ctx->node_id, ctx->node_slot);

        /* sess158: unconditional post-init beacon (see the CAW-branch
         * comment).  A peer that joined DURING mount init already
         * beaconed via mxfs_dlm_update_active_nodes BEFORE the init line
         * above, leaving the harness convergence window empty for this
         * incarnation.  The engine's active set is fed from the lease
         * view (v5_lease_refresh_active), so the lease is the same
         * membership source — emit the canonical line from it directly
         * (v5_membership_beacon_caw deliberately no-ops when the TCP
         * engine exists). */
        if (ctx->lease) {
            mxfs_node_id_t bnodes[MXFS_MAX_NODES];
            int bcount = mxfs_lease_get_active_nodes(ctx->lease, bnodes,
                                                     MXFS_MAX_NODES);

            if (bcount > 0)
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: MXFS-MEMBERSHIP local=%u active_count=%d",
                             ctx->node_id, bcount);
        }

        /*
         * sess5 (ccloop-4dd7) MEMBERSHIP-SETTLE GATE (pve9 n1_seed loss):
         * the disklock slot table is ground truth of liveness — if OTHER
         * ACTIVE slots exist at mount time, an existing cluster owns this
         * LUN, and returning before DLM membership includes those nodes
         * lets the first local write self-grant on a stale base and
         * durably clobber the existing members' state (the joiner's touch
         * beat the peer-connect transition by ~1s and lost pve9-1's
         * unflushed root dirent).  Wait (bounded) until the lease view
         * covers every active foreign slot; dead slots simply time the
         * gate out and the heartbeat monitor evicts them later.
         */
        if (ctx->disklock && ctx->lease) {
            uint64_t fmask = 0;

            if (mxfs_disklock_get_stale_slot_mask(ctx->disklock, 0,
                                                  ctx->node_slot,
                                                  &fmask) == 0 && fmask) {
                int foreign = 0, want, have = 0, waited = 0;
                bool ghost_checked = false;
                mxfs_node_id_t mnodes[MXFS_MAX_NODES];
                uint64_t m;

                for (m = fmask; m; m &= (m - 1))
                    foreign++;
                want = foreign + 1;
                while (waited < 15000) {
                    have = mxfs_lease_get_active_nodes(ctx->lease, mnodes,
                                                       MXFS_MAX_NODES);
                    if (have >= want)
                        break;
                    /* v0.11.76 (D5): not settled after 2s — one-time
                     * liveness rescan separates live peers (heartbeat
                     * advancing) from ghosts (ACTIVE flag, frozen
                     * timestamp: crash leftovers) and stops waiting for
                     * lease entries the ghosts will never produce.
                     * All-live joins settle in <2s and never pay this. */
                    if (waited >= 2000 && !ghost_checked) {
                        uint64_t stale = 0;

                        ghost_checked = true;
                        if (mxfs_disklock_get_stale_slot_mask(
                                ctx->disklock, 5000, ctx->node_slot,
                                &stale) == 0 && (stale &= fmask)) {
                            int nstale = 0;

                            for (m = stale; m; m &= (m - 1))
                                nstale++;
                            foreign -= nstale;
                            want = foreign + 1;
                            mxfs_pal_log(MXFS_LOG_WARN,
                                         "mxfs: P-MEMB-GATE-GHOSTS %d frozen foreign slot(s) discounted (crash leftovers; monitor will evict)",
                                         nstale);
                        }
                        waited += 5000;
                        continue;
                    }
                    mxfs_pal_sleep_ms(250);
                    waited += 250;
                }
                if (have >= want)
                    mxfs_pal_log(MXFS_LOG_INFO,
                                 "mxfs: membership settled at mount: %d active slot(s) on LUN, lease sees %d node(s) after %dms",
                                 foreign, have, waited);
                else
                    mxfs_pal_log(MXFS_LOG_WARN,
                                 "mxfs: P-MEMB-SETTLE-TIMEOUT %d active foreign slot(s) on LUN but lease sees only %d node(s) after %dms — proceeding (slots may be dead; monitor will evict)",
                                 foreign, have, waited);
            }
        }
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
        /* v0.11.80 (D8): provisioning-time conformance probe */
        mxfs_scsipr_probe(ctx->scsipr);
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

    /*
     * 4. Reclaim our own stale locks — a previous instance of us may have
     * died holding this slot, which we just re-claimed.
     *
     * sess53 (D-FOREIGN-REPLAY step 4a): the reclaim now RETAINS our
     * previous incarnation's EX/PW bits.  Those bits are the authority
     * manifest that our own log slice was written under: xlog_recover
     * runs later in this same mount (inside xfs_mountfs) and replays
     * buffer images that are only legal to apply because that authority
     * was held.  Purging them here — before recovery has even started —
     * is what left foreign replay unable to tell a legally-authored image
     * from an ungated one.
     *
     * PR/CR bits carry no write authority and are still dropped, which
     * is what makes this safe: a retained bit is now unambiguously an
     * EX-class claim, so a later acquire that finds one is adopting real
     * authority rather than tripping over a stale read lock.
     *
     * The window opened here is closed by mxfs_v5_dlm_mount_settle()
     * once recovery is durable; while it is open, an acquire that finds
     * an untracked bit of ours CASes to adopt it (see caw_adopt_retained).
     */
    dead_mask = 1ULL << node_slot;
    {
        int npurged = mxfs_dlm_caw_purge_dead_nodes_ex(ctx->dlm_caw,
                                                       dead_mask,
                                                       MXFS_CAW_PURGE_KEEP_EX);
        int retained = mxfs_dlm_caw_retained_count(ctx->dlm_caw);

        if (npurged > 0 || retained > 0)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: own-slot reclaim: dropped %d stale PR/CR "
                         "entries, RETAINED %d EX/PW authority entries for "
                         "log recovery", npurged, retained);

        if (retained > 0) {
            mxfs_dlm_caw_set_adopt_window(ctx->dlm_caw, true);
            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P225-ADOPT-WINDOW open (retained=%d) — "
                         "acquires will adopt retained authority by CAS "
                         "until the post-recovery settle", retained);
        }
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
    mxfs_disklock_set_expire_cb(ctx->disklock, v5_disklock_expire_cb, ctx);
    /* sess9 D2: deferred-purge release when the dead slot reads
     * reclaimed (slice replay done). */
    mxfs_disklock_set_recovered_cb(ctx->disklock, v5_recovered_cb, ctx);

    /*
     * sess42 C7 version gate: admission.  Every live current-generation
     * member must publish an EQUAL protocol generation in its HB feature
     * block.  A live incompatible incumbent ⇒ we WITHDRAW (release our
     * slot cleanly and abort the mount — the caller fails closed); after
     * admission the monitor's per-pass validation + v5_vergate_cb fence
     * any incompatible late joiner.
     */
    mxfs_disklock_set_vergate_cb(ctx->disklock, v5_vergate_cb, ctx);
    ret = mxfs_disklock_join_gate(ctx->disklock, 0);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: C7 version gate refused join (%d) — "
                     "aborting cluster mount", ret);
        mxfs_disklock_stop_heartbeat(ctx->disklock);
        mxfs_disklock_release_slot(ctx->disklock);
        mxfs_dlm_caw_stop(ctx->dlm_caw);    /* started at step 5 */
        goto err_caw;
    }

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

        mxfs_disklock_get_stale_slot_mask(ctx->disklock,
                                          MXFS_DISKLOCK_HB_INTERVAL_MS * 5,
                                          node_slot, &stale_mask);
        /*
         * sess53 (D-FOREIGN-REPLAY step 4a): RECORD, do not purge.
         *
         * These bits belong to crashed instances whose journal slices
         * have NOT been replayed yet.  They are the authority manifest
         * those slices were written under — dropping them here leaves
         * the eventual foreign replay with no way to tell which buffer
         * images were authored under real authority, which is the defect
         * this campaign exists to close.  It is also strictly out of
         * order: reclaiming a dead node's grants before its slice is
         * replayed is the same D2 violation the lease-expiry path was
         * fixed for in sess9 (a peer that acquires the freed lock reads
         * the crashed node's torn, half-destaged view).
         *
         * mxfs_v5_dlm_mount_settle() consumes this mask after recovery
         * and routes each still-frozen slot through fence -> slice
         * recovery, which reclaims the grants as its final step.
         */
        ctx->mount_stale_mask = stale_mask;
        if (stale_mask) {
            int s, nstale = 0;

            for (s = 0; s < MXFS_DISKLOCK_HB_SLOTS; s++) {
                if (!(stale_mask & (1ULL << s)))
                    continue;
                ctx->mount_stale_node[s] =
                    mxfs_disklock_get_slot_node_id(ctx->disklock, s);
                nstale++;
            }

            mxfs_pal_log(MXFS_LOG_WARN,
                         "mxfs: P225-STALE-DEFERRED mask=0x%llx — %d "
                         "cross-instance slot(s) held authority at mount; "
                         "deferring reclaim to post-recovery settle",
                         (unsigned long long)stale_mask, nstale);
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

    /* Print BEFORE the settle gate — see the TCP-branch comment (run.sh
     * convergence awk resets its beacon window at this line). */
    mxfs_pal_log(MXFS_LOG_INFO,
                 "mxfs: DLM initialized (CAW, slot=%d, node_id=%u)",
                 node_slot, ctx->node_id);

    /* sess158: unconditional post-init beacon.  Discovery is live before
     * the init print, so a peer announce arriving mid-init emits its
     * MXFS-MEMBERSHIP beacon BEFORE the line above — and the harness
     * convergence awk (which resets its window at "DLM initialized")
     * never sees a beacon for this incarnation even though the cluster
     * converged.  Guarantee at least one beacon after the init line with
     * the current lease view; later membership changes re-beacon as
     * before. */
    v5_membership_beacon_caw(ctx);

    /* sess5: same membership-settle gate as the TCP branch — the joiner
     * race (mount returns before the lease view covers the LUN's active
     * slots; first local write self-grants on a stale base) is transport-
     * independent. */
    if (ctx->disklock && ctx->lease) {
        uint64_t fmask = 0;

        if (mxfs_disklock_get_stale_slot_mask(ctx->disklock, 0,
                                              ctx->node_slot,
                                              &fmask) == 0 && fmask) {
            int foreign = 0, want, have = 0, waited = 0;
            bool ghost_checked = false;
            mxfs_node_id_t mnodes[MXFS_MAX_NODES];
            uint64_t m;

            for (m = fmask; m; m &= (m - 1))
                foreign++;
            want = foreign + 1;
            while (waited < 15000) {
                have = mxfs_lease_get_active_nodes(ctx->lease, mnodes,
                                                   MXFS_MAX_NODES);
                if (have >= want)
                    break;
                /* v0.11.76 (D5): same one-time ghost discrimination as
                 * the TCP branch — see there. */
                if (waited >= 2000 && !ghost_checked) {
                    uint64_t stale = 0;

                    ghost_checked = true;
                    if (mxfs_disklock_get_stale_slot_mask(
                            ctx->disklock, 5000, ctx->node_slot,
                            &stale) == 0 && (stale &= fmask)) {
                        int nstale = 0;

                        for (m = stale; m; m &= (m - 1))
                            nstale++;
                        foreign -= nstale;
                        want = foreign + 1;
                        mxfs_pal_log(MXFS_LOG_WARN,
                                     "mxfs: P-MEMB-GATE-GHOSTS %d frozen foreign slot(s) discounted (crash leftovers; monitor will evict)",
                                     nstale);
                    }
                    waited += 5000;
                    continue;
                }
                mxfs_pal_sleep_ms(250);
                waited += 250;
            }
            if (have >= want)
                mxfs_pal_log(MXFS_LOG_INFO,
                             "mxfs: membership settled at mount: %d active slot(s) on LUN, lease sees %d node(s) after %dms",
                             foreign, have, waited);
            else
                mxfs_pal_log(MXFS_LOG_WARN,
                             "mxfs: P-MEMB-SETTLE-TIMEOUT %d active foreign slot(s) on LUN but lease sees only %d node(s) after %dms — proceeding (slots may be dead; monitor will evict)",
                             foreign, have, waited);
        }
    }

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
    if (ctx->mphase_lock)
        mxfs_pal_mutex_destroy(ctx->mphase_lock);
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
                 "mxfs: P-WITHDRAW — FS shut down; declaring voluntary "
                 "death (acquires fenced, grants FROZEN until peers "
                 "replay our journal slice)");
    /*
     * sess9 (ccloop c7ee71c6) D2: withdraw_release_all REMOVED.  It
     * wire-released every grant so peers promoted IMMEDIATELY — straight
     * into our torn, unreplayed state (our log was just abandoned by the
     * force-shutdown with buffers only partially destaged).  PROVEN
     * drc@16 r13: t1's mid-rm shutdown released 155 grants, peers
     * consumed a dirent→freed-inode tear, and the cluster served
     * persistent lookup ENOENTs on live files.
     *
     * The sess10 -ETIMEDOUT domino that motivated the instant release
     * came from death-DETECTION latency (62 s stale window / 600 s
     * lease), not from the freeze itself.  The WITHDRAWN stamp below
     * collapses detection to one monitor scan (~2-4 s); peers then
     * fence us, the elected survivor replays our slice, and only after
     * that do grants flow (deferred-purge protocol).  Conflicting
     * acquires ride their 60 s budgets through the few-second window.
     */
    if (ctx->disklock)
        mxfs_disklock_withdraw(ctx->disklock);
    /* sess11: stop discovery announces — a dead identity must not keep
     * advertising itself (peers' P164 gates reject it anyway; a corpse
     * has no business soliciting connections).  Lease RENEWALS keep
     * running on purpose: they hold our entry ACTIVE in every survivor's
     * lease until recovery completion unregisters it, which is exactly
     * the D2 freeze — mastership must not migrate off us before our
     * journal slice is replayed.  (Stopping renewals here made survivors
     * mark us SUSPECT ~2s in and remaster 4s BEFORE replay completed —
     * measured 253.74 vs 258.00 on withdraw@2.)  Post-unregister the
     * renewals are ignored as unknown-node until unmount stops them.
     * Idempotent; process context (same workqueue that joins the HB
     * thread). */
    if (ctx->discovery)
        mxfs_discovery_stop(ctx->discovery);
}

bool mxfs_v5_dlm_is_withdrawn(struct mxfs_v5_dlm *ctx)
{
    return ctx && ctx->withdrawn;
}

void mxfs_v5_dlm_shutdown(struct mxfs_v5_dlm *ctx)
{
    bool depart_clean;

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
    /*
     * sess54: the settle worker may be part way through the deferred
     * dead-confirm.  settle_stop breaks it out between heartbeat samples
     * (<= MXFS_DISKLOCK_HB_INTERVAL_MS), but a slot it has ALREADY
     * confirmed is fenced and made recovery-pending before it returns —
     * that sequence is deliberately not interruptible, so this join can
     * take a fence round-trip longer.  It must still be a full join:
     * the worker dereferences ctx throughout.
     */
    if (ctx->settle_thread) {
        ctx->settle_stop = 1;
        mxfs_pal_thread_join(ctx->settle_thread);
        ctx->settle_thread = NULL;
    }
    if (ctx->tcp_suspect_lock) {
        mxfs_pal_mutex_destroy(ctx->tcp_suspect_lock);
        ctx->tcp_suspect_lock = NULL;
    }

    /*
     * sess9 (ccloop c7ee71c6) D2: a withdrawn (post-force-shutdown)
     * teardown must NOT wire-release its grants either — our journal
     * slice may still be unreplayed, and releasing here hands peers the
     * same torn state the withdraw path froze (mirrors the D3/D6
     * !withdrawn gates below).  Peers' recovery (fence → elected replay
     * → purge) reclaims everything; local table teardown below frees the
     * memory regardless.
     *
     * sess131 (GPT sess130 ruling, step 4): the CAW half of that is no
     * longer a call from here.  A bare release_all at this point cannot
     * be correct at any position in this function: it runs while the
     * BAST threads are still producing releases, so it races producers
     * it cannot see, and anything it fails to clear is published into a
     * registry whose collector this function is about to join.  The
     * release now happens INSIDE mxfs_dlm_caw_stop, in the exclusive
     * window between "every producer has stopped" and "the drain runs",
     * which is the only place the claim it supports can be proven.  The
     * D2 suppression survives verbatim, expressed as the flag stop()
     * reads — and unlike before it is now actually honoured, because
     * mxfs_dlm_caw_destroy no longer issues a release of its own.
     *
     * caw_stop is also pulled EARLY, ahead of the GOODBYE below and
     * ahead of the lease/discovery/heartbeat teardown: its drain does
     * real slot I/O and needs this node still to be a live member while
     * it runs.  Its verdict is then what gates the clean departure.
     */
    if (ctx->dlm_caw) {
        mxfs_dlm_caw_set_release_on_stop(ctx->dlm_caw, !ctx->withdrawn);
        mxfs_dlm_caw_stop(ctx->dlm_caw);
    }
    if (ctx->dlm && !ctx->withdrawn)
        mxfs_dlm_release_all(ctx->dlm);

    /*
     * sess131: THE clean-departure predicate, computed once and used by
     * both consumers below (the GOODBYE broadcast and the heartbeat slot
     * release).  Both authorise peers to reclaim this node WITHOUT the
     * fence → slice-replay → purge protocol, so both require the same
     * proof: not withdrawn, AND the CAW teardown established that this
     * node's slot bits are actually gone.  Before this, "not withdrawn"
     * was the whole test, and a mount whose release_all silently failed
     * to clear a slot departed as cleanly as one that succeeded.
     */
    depart_clean = !ctx->withdrawn &&
                   mxfs_dlm_caw_departed_clean(ctx->dlm_caw);
    if (!ctx->withdrawn && !depart_clean)
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: P259-DEPART-UNCLEAN node %u — CAW teardown could "
                     "not account for this node's slot bits; suppressing the "
                     "GOODBYE and keeping the heartbeat record ACTIVE so peers "
                     "fence and replay this node instead of reclaiming it",
                     ctx->node_id);

    if (ctx->journal) {
        mxfs_journal_release_slot(ctx->journal);
        mxfs_journal_destroy(ctx->journal);
    }

    /* v0.11.79 (D6): clean departure says GOODBYE.  All grants are released
     * and the journal slot is clean at this point, so peers can drop us from
     * membership NOW instead of riding the TCP-disconnect suspect path
     * (40s death grace + EX freeze + retry storm against a master that is
     * simply gone).  A withdrawn/fenced teardown must NOT claim clean
     * departure — peers have to treat it as a death and recover (mirrors
     * the D3 !withdrawn gate on the disklock slot release below).
     *
     * sess131: `depart_clean` replaces the bare !withdrawn — see where it
     * is computed above. */
    if (ctx->peer && ctx->dlm && depart_clean) {
        struct mxfs_dlm_node_msg leave;

        memset(&leave, 0, sizeof(leave));
        leave.hdr.magic = MXFS_DLM_MAGIC;
        leave.hdr.version = MXFS_DLM_VERSION;
        leave.hdr.type = MXFS_MSG_NODE_LEAVE;
        leave.hdr.length = sizeof(leave);
        leave.hdr.sender = ctx->node_id;
        leave.hdr.epoch = mxfs_dlm_get_epoch(ctx->dlm);
        leave.volume_id = ctx->volume_id;
        mxfs_peer_broadcast(ctx->peer, &leave, sizeof(leave));
        mxfs_pal_log(MXFS_LOG_INFO,
                     "mxfs: P-GOODBYE-SENT clean departure broadcast (node %u)",
                     ctx->node_id);
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
        /* v0.11.76 (D3): clean departure clears our heartbeat record so
         * later mounts don't ghost-count it in the settle gate and the
         * peers' auto-monitor doesn't keep evicting it.  A withdrawn
         * (post-shutdown) teardown keeps it ACTIVE — peers must still
         * detect the death and recover the slice.
         *
         * sess131: so does a teardown that could not account for its CAW
         * bits.  Clearing the record tells peers there is nothing to
         * recover; leaving it ACTIVE routes this node through the normal
         * death path, which is precisely what an unproven departure
         * needs. */
        if (depart_clean)
            mxfs_disklock_release_slot(ctx->disklock);
        mxfs_disklock_destroy(ctx->disklock);
    }

    if (ctx->dlm_caw) {
        /* sess131: stop() already ran, far above, while this node was
         * still a live member — its drain needed that.  The call here is
         * gone rather than left as a no-op second stop, so the ordering
         * is legible; destroy() makes its own idempotent stop() call for
         * the paths that never went through this function. */
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

    /*
     * sess61 item 6B: the heartbeat monitor is the only other writer of
     * mphase_dead_mask and it was stopped + joined above (disklock
     * stop_heartbeat/destroy), so the lock has no remaining users.
     *
     * Anything still recorded is a slice that stays fenced, grant-frozen
     * and durably recovery-pending on disk — a survivor's re-election
     * sweep or the next mount's step 6.5 finds it.  Say so rather than
     * dropping the record silently.
     */
    if (ctx->mphase_dead_mask)
        mxfs_pal_log(MXFS_LOG_WARN,
                     "mxfs: P233-MPHASE-UNDISPATCHED mask=0x%llx at DLM "
                     "teardown — peer(s) died during this mount and their "
                     "slices were never dispatched for replay.  They stay "
                     "fenced, grant-frozen and recovery-pending on disk; "
                     "the next mount or a survivor's re-election sweep "
                     "recovers them.",
                     (unsigned long long)ctx->mphase_dead_mask);
    if (ctx->mphase_lock)
        mxfs_pal_mutex_destroy(ctx->mphase_lock);

    mxfs_pal_free(ctx);
    mxfs_pal_log(MXFS_LOG_INFO, "mxfs: DLM shutdown complete");
}

uint64_t mxfs_v5_dlm_detach_pr_key(struct mxfs_v5_dlm *ctx)
{
    uint64_t key;

    if (!ctx || !ctx->scsipr)
        return 0;

    key = mxfs_scsipr_key(ctx->scsipr);
    mxfs_scsipr_abandon(ctx->scsipr);
    ctx->scsipr = NULL;
    return key;
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
                            uint8_t mode, struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    mxfs_grant_result_init(gres);	/* sess97: fail closed */

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
            ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted, gres);
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
                            uint8_t mode, int retries,
                            struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    mxfs_grant_result_init(gres);	/* sess97: fail closed */

    if (!ctx)
        return 0;

    make_inode_resource(&res, ctx->volume_id, ino);

    if (ctx->dlm) {
        ret = mxfs_dlm_lock_retries(ctx->dlm, &res, mode, 0, &granted, retries);
    } else if (ctx->dlm_caw) {
        /* CAW: no short-budget variant — use the normal blocking acquire. */
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted, gres);
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
                                !!mxfs_caw_epoch_free_reset, 0);
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
    return mxfs_v5_dlm_inode_unlock_open(ctx, ino, expected_gen, 0);
}

/* sess41 (GPT audit C1): release with an atomic open-holder bit change —
 * open_op rides the release CAS (see mxfs_dlm_caw_unlock_gen).  TCP: the
 * op is ignored until the TCP open-tracking increment (C9) — that
 * transport's exposure is ledgered under D-CROSSNODE-OPEN-UNLINK. */
int mxfs_v5_dlm_inode_unlock_open(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                  uint32_t expected_gen, int open_op)
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
        return mxfs_dlm_caw_unlock_gen(ctx->dlm_caw, &res, expected_gen, false,
                                       open_op);
    }
    return 0;
}

/* ─── CAW tenure-token (PW/EX grant-epoch) selftest ───
 *
 * sess170/171 (D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID verification vehicle,
 * RULE-5 approved sess170): drives the REAL kernel CAW lock/convert/unlock
 * paths against a geometry-reserved, unallocatable inode key (computed by
 * the debugfs trigger; agno >= agcount so no allocation path can ever mint
 * it, node-slot-derived so concurrent per-node runs never contend) and
 * asserts the tenure-token contract end to end on the live slot table:
 *
 *   arm 1 — convert-path preservation + fresh-tenure re-mint:
 *     lock PW            -> proving, T1 != 0        (fresh mint)
 *     convert PW->EX     -> proving, epoch == T1    (P274-GEP-PRESERVE)
 *     convert EX->PW     -> downgrade keeps token   (round-trip proves it)
 *     convert PW->EX     -> proving, epoch == T1
 *     unlock             -> tombstone carries the token (sess108)
 *     lock EX            -> proving, T3 != T1       (re-mint = NEW tenure)
 *     unlock
 *   arm 2 — held-mode ACQUIRE upgrade (compat-add single-CAS path):
 *     lock PW            -> proving, T4 != T3, != 0
 *     lock EX while held -> proving, epoch == T4    (P109-CLR-UPGRADE)
 *     unlock
 *
 * Inequality assertions prove only "a new tenure token was minted", never
 * WHICH site minted it (ruling condition A1); site attribution comes from
 * the instance-qualified probes (rk=/id= carry the reserved ino).  Every
 * failure path best-effort-unlocks so a FAIL never strands a held grant.
 * ONE verdict line per run, run-id qualified:
 *   mxfs: P274-PWTEST <PASS|FAIL> run=%u ino=%llu t1=.. t3=.. t4=.. step=%s rc=%d
 * The caller (debugfs write handler) serializes runs; the static run
 * counter needs no atomicity beyond that gate.
 */
int mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    static unsigned int pw_selftest_run;
    struct mxfs_resource_id res;
    struct mxfs_grant_result gres;
    uint64_t t1 = 0, t3 = 0, t4 = 0;
    const char *step = "init";
    uint8_t granted = 0;
    unsigned int run;
    bool held = false;
    int rc;

    if (!ctx)
        return -ENODEV;
    if (!ctx->dlm_caw)
        return -EOPNOTSUPP;     /* tenure tokens are CAW-transport only */
    if (ctx->withdrawn)
        return -ESHUTDOWN;

    run = ++pw_selftest_run;
    make_inode_resource(&res, ctx->volume_id, ino);

    mxfs_pal_log(MXFS_LOG_WARN, "mxfs: P274-PWTEST START run=%u ino=%llu",
                 run, (unsigned long long)ino);

    /* ── arm 1 ── */
    step = "a1-lock-pw";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_PW, 0, &granted,
                           &gres);
    if (rc)
        goto fail;
    held = true;
    if (!mxfs_grant_result_proving(&gres)) {
        rc = -EREMOTEIO;
        goto fail;
    }
    t1 = gres.grant_epoch;

    step = "a1-convert-ex";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_convert(ctx->dlm_caw, &res, MXFS_LOCK_EX, &gres);
    if (rc)
        goto fail;
    if (!mxfs_grant_result_proving(&gres) || gres.grant_epoch != t1) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a1-convert-pw";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_convert(ctx->dlm_caw, &res, MXFS_LOCK_PW, &gres);
    if (rc)
        goto fail;
    /* Defensive only — the reconvert below is the real downgrade check. */
    if (mxfs_grant_result_proving(&gres) && gres.grant_epoch != t1) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a1-reconvert-ex";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_convert(ctx->dlm_caw, &res, MXFS_LOCK_EX, &gres);
    if (rc)
        goto fail;
    if (!mxfs_grant_result_proving(&gres) || gres.grant_epoch != t1) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a1-unlock";
    rc = mxfs_dlm_caw_unlock(ctx->dlm_caw, &res);
    if (rc)
        goto fail;
    held = false;

    step = "a1-relock-ex";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_EX, 0, &granted,
                           &gres);
    if (rc)
        goto fail;
    held = true;
    if (!mxfs_grant_result_proving(&gres)) {
        rc = -EREMOTEIO;
        goto fail;
    }
    t3 = gres.grant_epoch;
    if (t3 == t1) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a1-unlock2";
    rc = mxfs_dlm_caw_unlock(ctx->dlm_caw, &res);
    if (rc)
        goto fail;
    held = false;

    /* ── arm 2 ── */
    step = "a2-lock-pw";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_PW, 0, &granted,
                           &gres);
    if (rc)
        goto fail;
    held = true;
    if (!mxfs_grant_result_proving(&gres)) {
        rc = -EREMOTEIO;
        goto fail;
    }
    t4 = gres.grant_epoch;
    if (t4 == 0 || t4 == t3) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a2-acquire-ex";
    mxfs_grant_result_init(&gres);
    rc = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_EX, 0, &granted,
                           &gres);
    if (rc)
        goto fail;
    if (!mxfs_grant_result_proving(&gres) || gres.grant_epoch != t4) {
        rc = -EREMOTEIO;
        goto fail;
    }

    step = "a2-unlock";
    rc = mxfs_dlm_caw_unlock(ctx->dlm_caw, &res);
    if (rc)
        goto fail;
    held = false;

    mxfs_pal_log(MXFS_LOG_WARN,
                 "mxfs: P274-PWTEST PASS run=%u ino=%llu t1=%llu t3=%llu "
                 "t4=%llu step=done rc=0",
                 run, (unsigned long long)ino,
                 (unsigned long long)t1, (unsigned long long)t3,
                 (unsigned long long)t4);
    return 0;

fail:
    if (held)
        mxfs_dlm_caw_unlock(ctx->dlm_caw, &res);    /* best effort */
    if (rc >= 0)
        rc = -EREMOTEIO;
    mxfs_pal_log(MXFS_LOG_ERR,
                 "mxfs: P274-PWTEST FAIL run=%u ino=%llu t1=%llu t3=%llu "
                 "t4=%llu step=%s rc=%d",
                 run, (unsigned long long)ino,
                 (unsigned long long)t1, (unsigned long long)t3,
                 (unsigned long long)t4, step, rc);
    return rc;
}

/* ─── ICLUSTER resource ops (ccloop 72513a13 sess3, ICLUSTER PLAN) ───
 * Thin type-swapped twins of the inode ops.  The xfs-side mediating layer
 * (mxfs_iclus, sess4 sweep design) owns the release decision; these only
 * move the on-disk slot.  base_ino must be the cluster base. */

int mxfs_v5_dlm_iclus_lock(struct mxfs_v5_dlm *ctx, uint64_t base_ino,
                           uint8_t mode, struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;
    int inflight_waits = 0;

    mxfs_grant_result_init(gres);	/* sess97: fail closed */

    if (!ctx)
        return 0;
    if (ctx->withdrawn)
        return -ESHUTDOWN;

    make_iclus_resource(&res, ctx->volume_id, base_ino);

retry_inflight:
    if (ctx->dlm) {
        ret = mxfs_dlm_lock(ctx->dlm, &res, mode, 0, &granted);
    } else if (ctx->dlm_caw) {
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode, 0, &granted, gres);
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
                                       is_free, 0);
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
int mxfs_v5_dlm_inode_force_release_self(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                         const struct mxfs_forcerel_attest *att)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm_caw)
        return 0;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_force_release_self(ctx->dlm_caw, &res, att);
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

/* sess40 open tracking (D-CROSSNODE-OPEN-UNLINK): peer protected-activity
 * bitmap for an inode.  Valid only while the caller holds a grant on the
 * inode (see mxfs_dlm_caw_open_holders contract).
 * sess41 (GPT audit C5): FAIL-CLOSED rc contract — 0 + *oh_out on success,
 * -EOPNOTSUPP when this transport has no open tracking (TCP until the C9
 * increment; the caller may proceed, that exposure is ledgered), any other
 * -errno = the bitmap could not be read and the caller MUST defer. */
int mxfs_v5_dlm_inode_open_holders(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                   uint64_t *oh_out)
{
    struct mxfs_resource_id res;

    if (oh_out)
        *oh_out = 0;
    if (!ctx || !oh_out)
        return -EINVAL;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_open_holders(ctx->dlm_caw, &res, oh_out);
    return -EOPNOTSUPP;
}

/* sess40: lazy-clear of THIS node's open bit (evict with no protected
 * activity / reap revalidation). */
void mxfs_v5_dlm_inode_open_clear(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm_caw)
        mxfs_dlm_caw_open_clear(ctx->dlm_caw, &res);
}

/* sess46 (iclus open tracking): durable standalone SET of this node's open
 * bit.  0 = durably on disk; any error must gate the caller's ICLUSTER
 * release (publication-before-release).  -EOPNOTSUPP on a transport with
 * no slot registry (TCP until C9 lands) — the caller's config gate keeps
 * routed open tracking off there. */
int mxfs_v5_dlm_inode_open_set(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return -EINVAL;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_open_set(ctx->dlm_caw, &res);
    return -EOPNOTSUPP;
}

/* sess46: B6 open-bit read for a routed freer (holds CLUSTER EX, no
 * per-inode claim).  0 → *oh_out valid (0 bits only when *authoritative);
 * negative → caller must defer (fail closed). */
int mxfs_v5_dlm_inode_open_probe(struct mxfs_v5_dlm *ctx, uint64_t ino,
                                 uint64_t *oh_out, bool *authoritative)
{
    struct mxfs_resource_id res;

    if (oh_out)
        *oh_out = 0;
    if (authoritative)
        *authoritative = false;
    if (!ctx || !oh_out || !authoritative)
        return -EINVAL;
    make_inode_resource(&res, ctx->volume_id, ino);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_open_probe(ctx->dlm_caw, &res, oh_out,
                                       authoritative);
    return -EOPNOTSUPP;
}

/* sess40: this node's open-holder bit value (for masking self out). */
uint64_t mxfs_v5_dlm_node_bit(struct mxfs_v5_dlm *ctx)
{
    if (!ctx)
        return 0;
    return 1ULL << mxfs_v5_dlm_get_node_slot(ctx);
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
                                uint8_t mode, struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;

    mxfs_grant_result_init(gres);	/* sess97: fail closed */

    if (!ctx)
        return 0;

    make_inode_resource(&res, ctx->volume_id, ino);

    if (ctx->dlm)
        return mxfs_dlm_lock(ctx->dlm, &res, mode,
                              MXFS_LKF_NOQUEUE, &granted);
    if (ctx->dlm_caw)
        return mxfs_dlm_caw_lock(ctx->dlm_caw, &res, mode,
                                  MXFS_LKF_NOQUEUE, &granted, gres);
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

/*
 * sess132: the CAW → v5 → XFS escalation chain.  See the contract on the
 * typedef in v5_mount.h — in particular that the XFS handler may run in the
 * owed worker's context and must therefore queue rather than act.
 */
static void v5_owed_stuck_cb(void *data)
{
    struct mxfs_v5_dlm *ctx = data;

    if (!ctx || !ctx->dlm_stuck_notify_fn)
        return;
    ctx->dlm_stuck_notify_fn(ctx->dlm_stuck_notify_data);
}

void mxfs_v5_dlm_set_dlm_stuck_notify(struct mxfs_v5_dlm *ctx,
                                      mxfs_v5_dlm_stuck_notify_fn fn,
                                      void *data)
{
    if (!ctx)
        return;
    ctx->dlm_stuck_notify_fn = fn;
    ctx->dlm_stuck_notify_data = data;
    /*
     * Register with the CAW layer only once there is something to forward to,
     * so an escalation can never reach a NULL upper handler.  Idempotent: the
     * CAW setter simply overwrites, and refuses outright once teardown has
     * closed admission.
     */
    if (ctx->dlm_caw)
        mxfs_dlm_caw_set_owed_stuck_fn(ctx->dlm_caw,
                                       fn ? v5_owed_stuck_cb : NULL,
                                       fn ? ctx : NULL);
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

int mxfs_v5_dlm_ag_lock(struct mxfs_v5_dlm *ctx, uint32_t agno,
                        struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    /* sess110: init BEFORE every early return — a caller that reads the
     * result after -ESHUTDOWN or a no-transport 0 must see non-proving. */
    mxfs_grant_result_init(gres);

    if (!ctx)
        return 0;
    if (ctx->withdrawn)     /* sess9: shut-down FS — never contend */
        return -ESHUTDOWN;

    make_ag_resource(&res, ctx->volume_id, agno);

    if (ctx->dlm)
        ret = mxfs_dlm_lock(ctx->dlm, &res, MXFS_LOCK_EX, 0, &granted);
    else if (ctx->dlm_caw)
        ret = mxfs_dlm_caw_lock(ctx->dlm_caw, &res, MXFS_LOCK_EX, 0,
                                  &granted, gres);
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
 * sess48's mxfs_v5_dlm_ag_grant_epoch() lived here and was DELETED in sess110
 * (step 5.3 ruling blocker 5).  It re-read the slot's ex_grant_epoch in a
 * SECOND I/O after the acquire had already returned, and a second read cannot
 * establish that the epoch it saw belongs to the grant this caller holds — any
 * release+regrant in the window (this node's own bast drain, or a peer taking
 * and returning the AG) hands back a nonzero, current, and WRONG epoch, which
 * then gets stamped into durable log records as write authority.  The epoch is
 * now threaded out of the granting CAS itself through struct mxfs_grant_result
 * on mxfs_v5_dlm_ag_lock / _nb, and the consumer additionally checks that the
 * result's kind/resource match the AG it asked for.
 */

/*
 * sess165 (foreign-replay step 5, shadow evaluator) — CONSUMER-side victim
 * manifest reads.  See the header contract: these evaluate a fenced victim's
 * recorded authority during untrusted log replay; they never produce an epoch
 * for this node's own writes, which is what the deleted accessor above did.
 */
int mxfs_v5_dlm_victim_ag_manifest_read(struct mxfs_v5_dlm *ctx, uint32_t agno,
                                        uint32_t victim_slot,
                                        bool *out_holds_ex,
                                        uint64_t *out_ex_grant_epoch)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return -EINVAL;
    if (!ctx->dlm_caw)
        return -ENODEV;
    make_ag_resource(&res, ctx->volume_id, agno);
    return mxfs_dlm_caw_victim_manifest_read(ctx->dlm_caw, &res, victim_slot,
                                             out_holds_ex, out_ex_grant_epoch);
}

int mxfs_v5_dlm_victim_inode_manifest_read(struct mxfs_v5_dlm *ctx,
                                           uint64_t ino, uint32_t victim_slot,
                                           bool *out_holds_ex,
                                           uint64_t *out_ex_grant_epoch)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return -EINVAL;
    if (!ctx->dlm_caw)
        return -ENODEV;
    make_inode_resource(&res, ctx->volume_id, ino);
    return mxfs_dlm_caw_victim_manifest_read(ctx->dlm_caw, &res, victim_slot,
                                             out_holds_ex, out_ex_grant_epoch);
}

int mxfs_v5_dlm_victim_recovery_read(struct mxfs_v5_dlm *ctx, uint32_t slot,
                                     uint16_t *out_stage,
                                     uint64_t *out_victim_epoch,
                                     uint32_t *out_victim_node)
{
    struct mxfs_recov_desc desc;
    int rc;

    if (!ctx || !out_stage || !out_victim_epoch || !out_victim_node)
        return -EINVAL;
    if (!ctx->disklock)
        return -ENODEV;
    rc = mxfs_disklock_recovery_read(ctx->disklock, (int)slot, &desc);
    if (rc)
        return rc;
    *out_stage = desc.stage;
    *out_victim_epoch = desc.victim_epoch;
    *out_victim_node = desc.victim_node;
    return 0;
}

/*
 * sess77: non-blocking AG EX acquire.  Passes MXFS_LKF_NOQUEUE so the CAW
 * layer returns -EAGAIN immediately if a peer holds the AG instead of
 * registering as a waiter and polling up to 120s.  Used by the allocator's
 * XFS_ALLOC_FLAG_TRYLOCK first pass (dialloc / block alloc) so a contended
 * AG is skipped rather than blocked on while inode ILOCKs are held — this
 * breaks the distributed ILOCK-vs-AG-DLM hold-and-wait deadlock.
 */
int mxfs_v5_dlm_ag_lock_nb(struct mxfs_v5_dlm *ctx, uint32_t agno,
                           struct mxfs_grant_result *gres)
{
    struct mxfs_resource_id res;
    uint8_t granted;
    int ret;

    /* sess110: see mxfs_v5_dlm_ag_lock — non-proving before any early exit. */
    mxfs_grant_result_init(gres);

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
                                MXFS_LKF_NOQUEUE, &granted, gres);
    else
        return 0;

    /* -EAGAIN / -EWOULDBLOCK: peer holds it; caller skips this AG. */
    return ret;
}

/*
 * ccloop c7ee71c6 sess6: orphan-grant NAK (see dlm.c
 * mxfs_dlm_release_orphan_if_unheld for the full anatomy).  Called from the
 * AG bast-notify when the FS layer provably does not hold the AG yet a
 * master keeps BASTing us — the divergence left by the membership-change
 * table purge.  TCP engine only: CAW has no remote master table to diverge
 * (the on-disk slot is the single truth).
 */
int mxfs_v5_dlm_ag_orphan_nak(struct mxfs_v5_dlm *ctx, uint32_t agno)
{
    struct mxfs_resource_id res;

    if (!ctx || !ctx->dlm)
        return 0;
    if (ctx->withdrawn)
        return 0;
    make_ag_resource(&res, ctx->volume_id, agno);
    return mxfs_dlm_release_orphan_if_unheld(ctx->dlm, &res);
}

/*
 * ccloop c7ee71c6 sess20: is this mount running the CAW (disk-slot) engine?
 * The on-disk slot table is the single authority there, so mxfs_v5_dlm_ag_held
 * is a real answer rather than the "don't assert" 1 it returns for TCP — a
 * caller that wants to ACT on held state (the stranded-AG repair) must know
 * which it is talking to.
 */
int mxfs_v5_dlm_is_caw(struct mxfs_v5_dlm *ctx)
{
    return (ctx && ctx->dlm_caw && !ctx->dlm) ? 1 : 0;
}

/*
 * ccloop c7ee71c6 sess20 — NON-BLOCKING ownership query.
 *
 * mxfs_v5_dlm_inode_held() is NOT safe from atomic context on CAW: the slot
 * table lives on the shared device, so it bottoms out in
 * find_slot -> read_slot -> mxfs_pal_scsi_read_fua_bdev -> blk_execute_rq ->
 * wait_for_completion_io_timeout -> schedule().  Calling it under a spinlock
 * produces "BUG: scheduling while atomic" — captured on all 16 nodes of the
 * 16/caw soak, from mxfs_submit_partial_inode_write (which holds
 * pag->pag_ici_lock across its slot loop) via the sess19 dir_nl_require_grant
 * guard, on xfsaild and on the mxfs kworkers.
 *
 * Returns 1 held / 0 not held when the answer is available WITHOUT I/O
 * (TCP keeps grants in the in-memory mirror), and -EWOULDBLOCK when it is not.
 * Callers in atomic context must treat -EWOULDBLOCK as "unknown" and fall back
 * to a decision that needs no I/O — never as "not held".
 */
int mxfs_v5_dlm_inode_held_nb(struct mxfs_v5_dlm *ctx, uint64_t ino)
{
    struct mxfs_resource_id res;

    if (!ctx)
        return -EWOULDBLOCK;
    if (ctx->dlm) {
        uint8_t mode = MXFS_LOCK_NL;
        int rc;

        /*
         * ccloop c7ee71c6 sess21 — MUST be mxfs_dlm_held_mode_NB.
         *
         * The sess20 form called the blocking mxfs_dlm_held_mode here,
         * which takes ctx->table_rwlock == struct rw_semaphore and, under
         * contention, schedules.  Callers of this function run inside
         * spin_lock(&pag->pag_ici_lock), so that slept in atomic context
         * and wedged the whole 32-node TCP cluster (see the ROOT comment
         * on mxfs_dlm_held_mode_nb in dlm/dlm.c).  This function's entire
         * contract is "never block", and only the _nb form honours it.
         */
        make_inode_resource(&res, ctx->volume_id, ino);
        rc = mxfs_dlm_held_mode_nb(ctx->dlm, &res, &mode);
        if (rc < 0)
            return -EWOULDBLOCK;    /* table busy: cannot tell without waiting */
        return mode != MXFS_LOCK_NL ? 1 : 0;
    }
    return -EWOULDBLOCK;    /* CAW: the on-disk slot is the only authority */
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
 * sess94 step 5.2 (D-FOREIGN-REPLAY-UNGATED-IMAGES): this mount's identity
 * triple for the authority token stamped on every buffer log record.
 *
 * Delegates to the disklock, which owns all three fields — do NOT read
 * ctx->node_slot here instead.  ctx->node_slot is 0 in a freshly allocated
 * context and 0 is also a legitimate claimed slot (the MDS), so it cannot
 * distinguish "unclaimed" from "slot 0"; the disklock's local_slot is -1
 * until the claim succeeds and therefore can.
 */
bool mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *ctx, uint32_t *slot,
                                uint32_t *node, uint64_t *epoch)
{
    mxfs_node_id_t n = 0;
    mxfs_epoch_t   e = 0;
    uint32_t       s = 0;

    if (slot)
        *slot = 0;
    if (node)
        *node = 0;
    if (epoch)
        *epoch = 0;

    if (!ctx || !ctx->disklock)
        return false;
    if (!mxfs_disklock_mount_identity(ctx->disklock, &s, &n, &e))
        return false;

    if (slot)
        *slot = s;
    if (node)
        *node = (uint32_t)n;
    if (epoch)
        *epoch = (uint64_t)e;
    return true;
}

/* sess32: pass-2 (fresh) HB claim — the inherited log slice may carry an
 * already-recovered incarnation's records; mount recovery must not re-apply
 * their images (see mxfs_disklock_slice_adopted). */
bool mxfs_v5_dlm_slice_adopted(struct mxfs_v5_dlm *ctx)
{
    if (!ctx || !ctx->disklock)
        return false;
    return mxfs_disklock_slice_adopted(ctx->disklock);
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
