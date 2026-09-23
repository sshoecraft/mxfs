/*
 * MXFS — Multinode XFS
 * Distributed Lock Manager protocol definitions
 *
 * The DLM is the single coordination mechanism for MXFS. Node liveness,
 * fencing, journal recovery, and cache coherency all derive from lock state.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_DLM_H
#define MXFS_DLM_H

#include "mxfs_common.h"

/*
 * Lock modes — standard DLM 6-mode compatibility matrix
 *
 *        NL  CR  CW  PR  PW  EX
 *   NL    Y   Y   Y   Y   Y   Y
 *   CR    Y   Y   Y   Y   Y   N
 *   CW    Y   Y   Y   N   N   N
 *   PR    Y   Y   N   Y   N   N
 *   PW    Y   Y   N   N   N   N
 *   EX    Y   N   N   N   N   N
 */
enum mxfs_lock_mode {
	MXFS_LOCK_NL = 0,   /* null — placeholder, no access */
	MXFS_LOCK_CR,        /* concurrent read */
	MXFS_LOCK_CW,        /* concurrent write */
	MXFS_LOCK_PR,        /* protected read — shared read lock */
	MXFS_LOCK_PW,        /* protected write — upgradeable */
	MXFS_LOCK_EX,        /* exclusive */
	MXFS_LOCK_MODE_COUNT,
};

/*
 * THE single test for "this mode authorizes a durable write image".
 *
 * sess105 design-consult ruling: one helper everywhere.  The tree previously mixed
 * `>= MXFS_LOCK_PW` (ordering-based) with `== EX || == PW` (exact); they agree
 * only because of the current enum order, which is NOT part of the contract.
 * MXFS_LOCK_CW is deliberately excluded: concurrent-write is not a protected
 * tenure and can never mint an ex_grant_epoch.
 */
static inline bool mxfs_mode_can_write(uint8_t mode)
{
	return mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW;
}

/* Lock resource types */
enum mxfs_lock_type {
	MXFS_LTYPE_INODE = 1,
	MXFS_LTYPE_EXTENT,
	MXFS_LTYPE_AG,
	MXFS_LTYPE_JOURNAL,
	MXFS_LTYPE_SUPER,       /* superblock lock — mount/unmount coordination */
	/* ccloop 72513a13 sess3 (ICLUSTER PLAN, DLM_PLAN.md): one resource
	 * per XFS inode cluster (res.ino = cluster base ino).  Regular-file
	 * dinode coherence batches ~32 inodes onto one slot; directories
	 * stay on MXFS_LTYPE_INODE.  Namespaced separately so a cluster
	 * base ino can never collide with a directory's per-inode slot. */
	MXFS_LTYPE_ICLUSTER,
};

/*
 * sess97 step 5.3(b) — immutable provenance of ONE successful durable grant.
 *
 * The sess96 design-consult ruling rejected reading the grant epoch back out of a
 * cache after the fact.  A cache can only establish "this epoch came from
 * SOME grant on this resource"; what an authority certificate needs is "this
 * epoch came from THIS acquire, whose authority is now being installed".  The
 * refuting interleaving is a full EX->NL->EX cycle: acquire A grants epoch 10
 * and stalls; the grant is released; acquire B grants 11 and stores it; A
 * resumes, reads 11, wins i_dlm_lock, and installs EX at epoch 11 off its own
 * stale completion.  A `mode > i_dlm_mode` guard does not catch that — it only
 * catches the case where EX is ALREADY installed.
 *
 * So the epoch is threaded OUT of the granting CAS itself, captured from the
 * exact slot image that was successfully CAS-ed to disk, before any later
 * operation on that slot can be confused with it.  Every field below is filled
 * from that one image.  `valid` is set only by a CAS that actually stamped
 * ex_grant_epoch (EX/PW class), so a PR grant, a mode-preserving no-op, or a
 * failed/retried CAS can never be read back as exclusive authority.
 *
 * Consumers must treat this as immutable: fill once at the granting CAS, copy
 * by value, never mutate afterwards.
 *
 * sess105: `valid` was a BOOLEAN, and its false case conflated two opposite
 * meanings — "not applicable" (we held a read grant; nothing was authorized
 * and nothing is wrong) and "broken/incomplete authorization record" (we held
 * a WRITING grant but the slot carried no epoch).  The sess104 measurement
 * had 2863 refusals all landing in that one bucket, so it proved nothing.
 * The classification now happens at SNAPSHOT CONSTRUCTION, where `held` and
 * `ex_grant_epoch` are one coherent image, and is carried as a tagged status.
 */
enum mxfs_grant_auth_status {
	/* Never filled: the result went unused, or a transport (TCP) that
	 * mints no durable epoch produced it.  The init value. */
	MXFS_GAUTH_UNSET = 0,
	/* THE proving case: a writing mode with a nonzero grant epoch. */
	MXFS_GAUTH_WRITE_EPOCH,
	/* We hold a non-writing mode.  Correctly non-proving and BENIGN —
	 * a read grant authorizes no write image.  Expected to dominate on
	 * any read-heavy workload. */
	MXFS_GAUTH_NONWRITE_MODE,
	/* Writing mode but ex_grant_epoch == 0.  This is a REAL GAP: the
	 * snapshot is incomplete.  Candidates (sess104 ruling): tombstone /
	 * epoch-namespace restart; write mode published before the epoch;
	 * the acquisition observed between publication steps; a snapshot
	 * coherence bug.  Never silently merged with the benign case. */
	MXFS_GAUTH_WRITE_ZERO_EPOCH,
	/* No backing resource at all — nothing was acquired to describe. */
	MXFS_GAUTH_NO_RESOURCE,
	/*
	 * sess432 (D-0353, design-consult ruling): the CAW single-node fast path — the
	 * grant lives in memory only, no slot image was touched, no epoch was
	 * minted.  NON-PROVING for journal replay (its images carry epoch 0),
	 * but a legitimate tenure while the DLM stays single-node: the cached
	 * hint may be reused within the same single-node era and must never
	 * survive the single->multi join barrier.  Kept distinct from UNSET so
	 * the acquire path never has to treat epoch==0 as both "invalid" and
	 * "valid in a special mode".
	 */
	MXFS_GAUTH_SINGLE_NODE,
	MXFS_GAUTH_STATUS_MAX
};

struct mxfs_grant_result {
	uint64_t	resource;	/* exact resource id: ino, or cluster base ino */
	uint64_t	grant_epoch;	/* ex_grant_epoch stamped by THIS CAS */
	/*
	 * sess176 (sess175 lineage ruling): the slot's resource_lineage in
	 * the SAME image that carried grant_epoch — the binding identity the
	 * token producer stamps beside the epoch.  Zero = binding predates
	 * the lineage scheme (legacy slot granted by an old build); such
	 * grants remain usable but their records are not enforceable under
	 * the future v3 lineage gate.  EQUALITY semantics only.
	 */
	uint64_t	resource_lineage;
	uint32_t	generation;	/* slot generation of the granting image */
	uint8_t		kind;		/* enum mxfs_lock_type of the backing slot */
	uint8_t		mode;		/* mode THIS NODE holds in that image */
	uint8_t		status;		/* enum mxfs_grant_auth_status */
	/*
	 * 1 when the grant was not minted by this operation's CAS but OBSERVED
	 * already held in the slot image this acquire read.  Still first-hand
	 * evidence — the same image shows our holder bit and the epoch — but a
	 * different provenance, kept distinguishable so a later ruling can
	 * tighten the policy without losing the measurement.
	 */
	uint8_t		reaffirm;
};

static inline void mxfs_grant_result_init(struct mxfs_grant_result *g)
{
	if (g) {
		g->resource = 0;
		g->grant_epoch = 0;
		g->resource_lineage = 0;
		g->generation = 0;
		g->kind = 0;
		g->mode = 0;
		g->status = MXFS_GAUTH_UNSET;
		g->reaffirm = 0;
	}
}

/*
 * The one predicate that says "this result proves exclusive write authority".
 * Everything else is a classified refusal — see enum mxfs_grant_auth_status
 * for why the refusal REASON must never be collapsed back into a boolean.
 */
static inline bool mxfs_grant_result_proving(const struct mxfs_grant_result *g)
{
	return g && g->status == MXFS_GAUTH_WRITE_EPOCH && g->grant_epoch != 0;
}

/*
 * ─── sess121 (GPT sess118 ruling item 7) — the force-release precondition ───
 *
 * "mxfs_dlm_caw_force_release_self needs an EXPLICIT precondition — same defect
 * across more slots if it can run while this mount still issues dependent I/O."
 *
 * The DLM cannot check that condition itself.  Dependent-use lifetime is known
 * only to the layer that admitted the use (XFS holders, pins, writeback), so
 * the requirement has to arrive from above.  Until sess121 it arrived as a
 * SENTENCE IN A COMMENT, which is not a precondition: a second caller added
 * later satisfies it by accident or not at all, and the failure is silent
 * corruption across every slot on the resource's probe chain.
 *
 * So the caller now STATES what it established, in the same terms the ruling
 * uses, and the DLM REFUSES the release when the statement is not a complete
 * one.  That does not let the DLM verify the facts — nothing can, from here —
 * but it converts "a future caller forgets" from silent corruption into an
 * -EINVAL and a P252-FORCEREL-PRECOND probe naming the site.
 *
 * The evidence fields must be filled from VALUES THE CALLER ACTUALLY READ, not
 * from literals.  A caller that hardcodes them has written a false statement,
 * and the point of the struct is that the falsehood is then legible at the call
 * site instead of hidden in a helper three layers down.
 *
 * It lives in this header rather than dlm_caw.h because it crosses the XFS/DLM
 * boundary: the attesting caller is in the XFS layer, which reaches the DLM
 * through the v5_mount facade and must not include the CAW header directly.
 */
enum mxfs_forcerel_basis {
	MXFS_FORCEREL_BASIS_NONE     = 0,   /* never valid — refuses */
	/*
	 * Dependent activity on this resource has STOPPED and DRAINED, and new
	 * dependent activity is blocked for the duration of the release.  All
	 * four evidence fields below must be true.
	 */
	MXFS_FORCEREL_BASIS_QUIESCED = 1,
	/*
	 * The mount is terminally fenced or shutting down: it will issue no
	 * further dependent I/O regardless of what is still admitted, so
	 * quiescence is moot.  The ruling names this as the one exemption.
	 */
	MXFS_FORCEREL_BASIS_TERMINAL = 2,
};

struct mxfs_forcerel_attest {
	uint32_t    basis;              /* enum mxfs_forcerel_basis */
	const char *site;               /* caller identity, for the refusal probe */
	/* Evidence — required (and checked) when basis == QUIESCED. */
	bool        no_local_grant;     /* this mount believes it holds nothing */
	bool        no_dependent_users; /* holder/pin counts are zero */
	bool        new_users_blocked;  /* the local acquire path is held off */
	bool        writeback_drained;  /* this tenure's dirty state is destaged */
};

/*
 * D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488 (sess273 ruling): the
 * outcome of an on-disk lock release is TRI-STATE, not an errno.  A caller
 * that surrendered in-core tenure before the release must know whether the
 * platter bit is provably gone (RELEASED), provably still ours (STILL_HELD
 * — re-arm tenure and retry the release), or unprovable (UNKNOWN — the
 * release CAW may or may not have committed; quarantine, never guess).
 * UNKNOWN is deliberately the zero value so an unset out-param fails closed.
 */
enum mxfs_unlock_state {
	MXFS_UNLOCK_UNKNOWN = 0,   /* outcome unprovable — quarantine */
	MXFS_UNLOCK_RELEASED,      /* bit provably clear on the platter */
	MXFS_UNLOCK_STILL_HELD,    /* bit provably still ours — retry release */
};

/* Lock state machine */
enum mxfs_lock_state {
	MXFS_LSTATE_UNLOCKED = 0,
	MXFS_LSTATE_WAITING,      /* request sent, awaiting grant */
	MXFS_LSTATE_GRANTED,
	MXFS_LSTATE_CONVERTING,   /* mode upgrade/downgrade in flight */
	MXFS_LSTATE_BLOCKED,      /* blocked by incompatible holder */
	/*
	 * sess422 (tcp-authority-ledger step 3d/3e, master-side only):
	 * PENDING_DURABLE — the master DECIDED this grant and is committing
	 * it to the authority ledger.  Counts as a holder in every
	 * compatibility check, is never returned to a local caller and never
	 * sent until the page transition verified on the platter.
	 * PENDING_RELEASE — the holder released; the record is being retired
	 * (one transition with its successors).  Still a holder for NEW
	 * arrivals (they queue), excluded only from successor selection.
	 */
	MXFS_LSTATE_PENDING_DURABLE,
	MXFS_LSTATE_PENDING_RELEASE,
};

/* Lock flags */
#define MXFS_LKF_NOQUEUE    (1 << 0)  /* don't queue if can't grant immediately */
#define MXFS_LKF_CONVERT    (1 << 1)  /* mode conversion, not new lock request */
#define MXFS_LKF_CANCEL     (1 << 2)  /* cancel a pending request */
#define MXFS_LKF_ORPHAN     (1 << 3)  /* keep lock on process exit */
#define MXFS_LKF_RECOVERY   (1 << 4)  /* lock acquired during recovery phase */
#define MXFS_LKF_TRYLOCK    (1 << 5)  /* non-blocking attempt */
/*
 * D-AGLOCK-...-LIVELOCK-488: a NOQUEUE request that must leave PERSISTENT
 * demand behind when it loses.  Plain NOQUEUE is a SILENT probe (dialloc's
 * first pass relies on that -- its blocking second pass generates the
 * demand); NOQUEUE|DEMAND is for callers that retry in a bounded loop and
 * would otherwise never displace a lazily-cached remote holder.  The
 * transport sets the on-disk sticky revoke bit and multicasts a BAST hint
 * before returning -EAGAIN.
 */
#define MXFS_LKF_DEMAND     (1 << 6)  /* NOQUEUE: leave a sticky revoke behind */

/* ─── Peer-to-peer DLM messages (daemon <-> daemon over TCP) ─── */

enum mxfs_dlm_msg_type {
	MXFS_MSG_LOCK_REQ = 1,
	MXFS_MSG_LOCK_GRANT,
	MXFS_MSG_LOCK_DENY,
	MXFS_MSG_LOCK_RELEASE,
	MXFS_MSG_LOCK_CONVERT,
	MXFS_MSG_LOCK_BAST,        /* blocking AST — request holder to downgrade */
	MXFS_MSG_LEASE_RENEW,
	MXFS_MSG_LEASE_ACK,
	MXFS_MSG_LEASE_EXPIRE,
	MXFS_MSG_NODE_JOIN,
	MXFS_MSG_NODE_LEAVE,
	MXFS_MSG_NODE_ALIVE,       /* heartbeat piggyback on lease renewal */
	MXFS_MSG_JOURNAL_RECOVER,
	MXFS_MSG_JOURNAL_DONE,
	MXFS_MSG_CACHE_INVAL,
	/* sess422 (step 3e): master -> releaser, after the release transition
	 * is durable.  The releaser keeps pending-release state (and retries
	 * the LOCK_RELEASE) until this arrives. */
	MXFS_MSG_LOCK_RELEASE_ACK,
	MXFS_MSG_PAGE_HANDOFF,      /* sess423 step 4: ledger page handoff */
	/*
	 * Master -> requester, when a remote request cannot be granted now and
	 * is queued behind a conflicting holder.  Before this existed the
	 * master answered such a request with SILENCE, and silence is also
	 * what a request that never arrived produces, so a requester whose
	 * acquire budget ran out could not tell "queued behind a holder that
	 * is draining" from "nothing will ever answer me" — and the acquire
	 * path's decision to keep waiting rather than fail depends on exactly
	 * that distinction.  Carried in a lock_resp; mode is the blocking
	 * holder's mode, req_id the request being acknowledged.
	 */
	MXFS_MSG_LOCK_QUEUED,
	/*
	 * Requester -> master: the logical acquisition named by {hdr.sender,
	 * owner_inc, acq_seq} is abandoned.  Carried in a lock_cancel.  The
	 * master removes the waiter it may hold for it, retires a grant it
	 * decided for it that the requester will never install, remembers the
	 * acquisition so a late re-send cannot recreate it, and answers with a
	 * cancel_ack saying which of those it found.  Abandonment is otherwise
	 * invisible to the master: the requester's one-second re-sends simply
	 * stop, and a waiter or a committed grant it had for that wait stays
	 * a blocker for everyone else — with delivery suppressed, for ever.
	 */
	MXFS_MSG_LOCK_CANCEL,
	MXFS_MSG_LOCK_CANCEL_ACK,

	/*
	 * sess67 ASYMMETRIC MDS (Phase 1, see ASYMMETRIC_MDS_PLAN.md).
	 * Metadata-mutation RPCs: a non-MDS (client) node forwards a directory
	 * metadata operation to the MDS node, which runs the real XFS
	 * transaction and replies.  Carried over the TCP peer mesh (dlm/peer.c),
	 * which CAW mode now starts solely for these RPCs.  Range >= 64 so they
	 * never collide with the lock/lease/journal control range above.
	 */
	MXFS_MSG_MD_CREATE = 64,   /* create a regular file / mknod */
	MXFS_MSG_MD_MKDIR,
	MXFS_MSG_MD_REMOVE,        /* unlink */
	MXFS_MSG_MD_RMDIR,
	MXFS_MSG_MD_RENAME,
	MXFS_MSG_MD_SYMLINK,
	MXFS_MSG_MD_LINK,
	MXFS_MSG_MD_REPLY = 96,    /* generic reply (rc + result attrs) */
};

#define MXFS_DLM_MAGIC      0x4D584653  /* "MXFS" in ASCII */
#define MXFS_DLM_VERSION    1

/* Wire protocol header — all DLM messages start with this */
struct mxfs_dlm_msg_hdr {
	uint32_t        magic;
	uint16_t        version;
	uint16_t        type;       /* mxfs_dlm_msg_type */
	uint32_t        length;     /* total message length including header */
	uint32_t        seq;        /* sender's sequence number */
	mxfs_node_id_t  sender;
	mxfs_node_id_t  target;     /* 0 = broadcast */
	mxfs_epoch_t    epoch;
};

/* Lock request */
struct mxfs_dlm_lock_req {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 mode;    /* requested mxfs_lock_mode */
	uint8_t                 pad[3];
	uint32_t                flags;   /* MXFS_LKF_* */
	/* sess422 (tcp-authority-ledger step 3b): the requester's identity as
	 * the ledger records it — {node (hdr.sender), mount incarnation,
	 * heartbeat slot} — and a per-requester request id so a retried
	 * request returns the already-durable grant instead of minting
	 * another (idempotent retries). */
	uint64_t                owner_inc;
	uint32_t                req_id;
	uint16_t                owner_slot;
	uint16_t                pad2;
	/*
	 * The LOGICAL ACQUISITION this request belongs to, monotonic per mount
	 * and qualified by {hdr.sender, owner_inc} so it cannot collide across
	 * a requester's restarts.  req_id above names one TRANSPORT ATTEMPT and
	 * is minted afresh for every one-second re-send; acq_seq names the wait
	 * those attempts all belong to and is stable across every re-send and
	 * every restart of the acquire classifier.
	 *
	 * The distinction is not cosmetic.  Without it the master could only
	 * read a re-send as a NEW request, so it destroyed the requester's
	 * queue entry and inserted another one every second — discarding the
	 * entry's queue position and its first-enqueue time, and re-firing a
	 * blocking notification at a holder that was already draining.
	 * Measured on 2 nodes / TCP during a single 244 s acquire behind one
	 * live holder: 238 blocking notifications fired at the holder against
	 * 234 re-sends by the requester, for ONE logical wait.
	 *
	 * Zero means "a sender that does not mint acquisitions" and is treated
	 * exactly as the old code treated every request.
	 */
	uint64_t                acq_seq;
};

/* Lock grant/deny response */
struct mxfs_dlm_lock_resp {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 mode;    /* granted mode (may differ from request) */
	uint8_t                 status;  /* mxfs_error */
	uint8_t                 handoff; /* sess63: 1 = this EX grant is a cross-node
	                                  * handoff (a DIFFERENT node held EX since
	                                  * the grantee last did).  Was pad[0]; wire
	                                  * size unchanged. */
	uint8_t                 pad[1];
	/* sess-tcp double-grant fix: per-grant generation token.  The master
	 * stamps each grant with a monotonic gen; the granted node echoes it in
	 * its LOCK_RELEASE so the master can ignore a stale release that was
	 * issued for a now-superseded grant episode (Bug-51 safe re-affirm). */
	uint32_t                grant_gen;
	/* sess64 (GPT design): per-resource MONOTONIC cross-node handoff epoch.
	 * The master bumps it once per cross-node EX handoff and stamps every
	 * grant with the current value; the grantee compares it level-triggered
	 * (> its valid_epoch) to decide whether its cached dir base is stale.
	 * All cluster nodes run the same build, so growing this wire struct is
	 * safe (no mixed-version peers within a mount). */
	uint32_t                dir_epoch;
	/* sess422 (step 3b): the DURABLE grant id {authority_epoch,
	 * grant_seq64} the ledger minted for this grant (0/0 on DENY and on a
	 * shared-mode grant, which records a holder bit, not a grant id), the
	 * record's resource lineage, and the request id this answers. */
	uint64_t                authority_epoch;
	uint64_t                grant_seq64;
	uint64_t                lineage;
	uint32_t                req_id;
	uint32_t                pad2;
	/*
	 * 0.89.0 (D-0977): the record's open-holder marks at the moment this
	 * grant was decided (one bit per heartbeat slot).  On an exclusive
	 * grant it is the snapshot the grantee's destructive-inactivation
	 * guard reads: every peer that had the inode open published its mark
	 * inside the release that preceded this grant, and no peer can
	 * publish a new one while the EX is held, so the snapshot can only be
	 * too conservative (a later clear defers one more reap retry), never
	 * too permissive.  Zero on DENY.
	 */
	uint64_t                open_holders;
};

/* Lock release */
struct mxfs_dlm_lock_release {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint32_t                grant_gen;  /* gen the releaser believes it holds */
	uint32_t                rel_id;     /* sess422: releaser's release id (ACK echo) */
	/* sess422 (step 3e): full validation of the release — the ledger
	 * clears the record only for {node, inc, grant_id} (exclusive) or
	 * {lineage, slot, node, inc} (shared). */
	uint64_t                authority_epoch;
	uint64_t                grant_seq64;
	uint64_t                owner_inc;
	uint64_t                lineage;
	uint16_t                owner_slot;
	uint8_t                 mode;       /* mode held (shared vs exclusive) */
	/*
	 * 0.84.13: 1 when the releaser's ACQUISITION of this resource and mode
	 * has ended — the wait that took the grant claimed it and retired its
	 * record — so any LOCK_REQ still in flight that carries that
	 * acquisition's acq_seq is stale and the master must not queue it as a
	 * fresh request.  0 (the pre-0.84.13 wire value) says nothing: the
	 * acquisition may still be live (a grant kept for a wait released under
	 * it before the claim re-sends the same name and must be served).
	 */
	uint8_t                 acq_done;
	/*
	 * 0.89.0 (D-0977): the releaser's open-holder mark change, applied by
	 * the master inside the same durable ledger transition that retires
	 * this grant (MXFS_TAUTH_OPEN_*: +1 the file is still open or mapped
	 * on the releaser, -1 it is not, -2 the genuine free erases every
	 * node's mark, 0 leave it).  Publication is inseparable from release:
	 * a release the ledger refuses applies no mark, and a mark the ledger
	 * applied is durable before the ACK.  Was padding.
	 */
	int8_t                  open_op;
	uint8_t                 pad2[3];
};

/* sess422 (step 3e): master -> releaser once the release transition is
 * durable (or was already superseded: status MXFS_OK either way, the
 * releaser holds nothing).  MXFS_ERR_LEDGER = the master could not retire
 * the record; the releaser keeps its pending-release state and retries. */
struct mxfs_dlm_release_ack {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint32_t                grant_gen;
	uint32_t                rel_id;
	uint64_t                authority_epoch;
	uint64_t                grant_seq64;
	uint8_t                 status;     /* mxfs_error */
	uint8_t                 pad[7];
};

/*
 * Abandonment of a logical acquisition (see MXFS_MSG_LOCK_CANCEL).  The
 * identity is {hdr.sender, owner_inc, acq_seq}; mode is an attribute the
 * master's entry must also match, never a substitute for the identity.
 * cancel_id is this transmission's nonce, echoed by the ack so a retry can
 * be told from a first send.
 */
struct mxfs_dlm_lock_cancel {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint64_t                owner_inc;
	uint64_t                acq_seq;
	uint32_t                cancel_id;
	uint8_t                 mode;
	uint8_t                 pad[3];
};

/* What the master found for a cancelled acquisition, in the ack. */
enum mxfs_cancel_outcome {
	MXFS_CANCEL_ABSENT = 1,         /* nothing held for it; remembered */
	MXFS_CANCEL_WAITER_REMOVED,     /* a queued waiter was removed */
	MXFS_CANCEL_GRANT_RETIRED,      /* a delivered-or-lost grant retired */
	MXFS_CANCEL_GRANT_RETIRING,     /* a grant still committing will be
					 * retired when it lands, not delivered */
	MXFS_CANCEL_NOT_MASTER,         /* not the master under this view */
};

struct mxfs_dlm_cancel_ack {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint64_t                owner_inc;
	uint64_t                acq_seq;
	uint32_t                cancel_id;
	uint8_t                 outcome;    /* mxfs_cancel_outcome */
	uint8_t                 pad[3];
};

/*
 * sess423 (tcp-authority-ledger step 4): ledger PAGE HANDOFF.  Page
 * authority moves only through a durable PREPARED -> ACTIVE pair; these
 * messages are the liveness side (a lost message is recovered by reading
 * the page, never by thawing).  kinds:
 *   FREEZE_REQ  requester -> the page's authority: "under configuration
 *               config_id you and I agree I own page; freeze and prepare
 *               it to me {hdr.sender, target_inc}"
 *   FROZEN      authority -> target: "PREPARED to {target_node,target_inc}
 *               is durable at prepared_seq" (also sent unsolicited by the
 *               eager pass at a view change)
 *   DEFER       authority -> requester: views differ / a transfer to a
 *               live third node is in flight; retry later (never
 *               authorises anything)
 *   NOT_OWNER   sender is not the page's authority; auth_* name whom the
 *               platter shows so the requester re-routes
 */
enum mxfs_dlm_handoff_kind {
	MXFS_HANDOFF_FREEZE_REQ = 1,
	MXFS_HANDOFF_FROZEN,
	MXFS_HANDOFF_DEFER,
	MXFS_HANDOFF_NOT_OWNER,
};

/* FROZEN flag: the sender is leaving the cluster and this hand-off is its
 * clean-departure transfer.  The receiver excludes the sender from its
 * hand-off routing from this message on (the goodbye that drops it from
 * the membership follows on the same stream), so the page is served, not
 * relayed back to a node that is going away.  0.75.20. */
#define MXFS_HANDOFF_F_DEPARTING 0x01

struct mxfs_dlm_page_handoff {
	struct mxfs_dlm_msg_hdr hdr;
	uint32_t                page;
	uint8_t                 kind;       /* mxfs_dlm_handoff_kind */
	uint8_t                 flags;      /* MXFS_HANDOFF_F_* */
	uint8_t                 pad[2];
	uint32_t                target_node;
	uint32_t                auth_node;
	uint64_t                target_inc;
	uint64_t                config_id;
	uint64_t                prepared_seq;
	uint64_t                auth_inc;
};

/* Blocking AST — tell a holder to downgrade or release */
struct mxfs_dlm_bast {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 requested_mode; /* mode the waiter needs */
	uint8_t                 pad[3];
};

/* Lease renewal */
struct mxfs_dlm_lease_msg {
	struct mxfs_dlm_msg_hdr hdr;
	uint64_t                lease_duration_ms;
	uint32_t                lock_count;  /* locks held — informational */
	uint32_t                pad;
};

/* Cache invalidation */
struct mxfs_dlm_cache_inval {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint64_t                range_start;  /* byte offset */
	uint64_t                range_len;    /* 0 = entire resource */
};

/*
 * sess67 ASYMMETRIC MDS (Phase 1) — metadata-mutation RPC.
 *
 * A client (non-MDS) node forwards a directory metadata op to the MDS, which
 * runs the real XFS transaction and replies.  Names are carried inline after
 * the fixed part: name1 (name1_len bytes, NUL-terminated) then name2
 * (name2_len bytes, NUL-terminated).
 *   create/mkdir/remove/rmdir : name1 = entry in parent_ino.
 *   rename                    : name1 in parent_ino (src), name2 in
 *                               newparent_ino (dst); flags = RENAME_*.
 *   symlink                   : name1 = new entry in parent_ino,
 *                               name2 = link target path.
 *   link                      : name1 = new entry in parent_ino,
 *                               link_ino = existing inode to hard-link.
 * parent_gen/newparent_gen let the MDS reject a request that raced an inode
 * recycle (staleness guard).  uid/gid are advisory (Phase 1 runs as the
 * MDS's creds; full cred marshalling is a later refinement).
 */
#define MXFS_MD_NAME_MAX 255

struct mxfs_md_req {
	struct mxfs_dlm_msg_hdr hdr;
	uint64_t                parent_ino;
	uint64_t                parent_gen;
	uint64_t                newparent_ino;   /* rename dst parent (0 = unused) */
	uint64_t                newparent_gen;
	uint64_t                link_ino;        /* link(2) target inode (else 0) */
	uint32_t                mode;            /* create/mkdir/symlink mode */
	uint32_t                rdev;            /* mknod dev (else 0) */
	uint32_t                uid;
	uint32_t                gid;
	uint32_t                flags;           /* rename flags (RENAME_*) */
	uint16_t                name1_len;
	uint16_t                name2_len;
	/* char name1[name1_len + 1]; char name2[name2_len + 1]; follow */
};

struct mxfs_md_reply {
	struct mxfs_dlm_msg_hdr hdr;
	int32_t                 rc;              /* 0 ok, else -errno */
	uint32_t                pad;
	uint64_t                child_ino;       /* created/affected inode */
	uint64_t                child_gen;
	uint64_t                parent_gen;      /* parent dir gen AFTER op (inval) */
	uint64_t                newparent_gen;
	uint32_t                child_mode;
	uint32_t                child_nlink;
	uint64_t                child_size;
};

/* Journal recovery notification */
struct mxfs_dlm_journal_msg {
	struct mxfs_dlm_msg_hdr hdr;
	mxfs_node_id_t          dead_node;    /* node whose journal to replay */
	uint32_t                journal_slot;
};

/* Node join/leave */
struct mxfs_dlm_node_msg {
	struct mxfs_dlm_msg_hdr hdr;
	char                    name[MXFS_NODE_NAME_MAX];
	uint16_t                port;
	uint8_t                 pad[2];
	mxfs_volume_id_t        volume_id; /* multi-LUN: identifies which mount */
	/* sess426 (D-0350): the sender's mount incarnation (disklock epoch).
	 * On NODE_LEAVE the receiver's takeover of the pages the departing
	 * node left needs it, and the heartbeat slot may already be released
	 * or unmonitored by the time the GOODBYE is processed (0 = unknown:
	 * the receiver falls back to the slot lookup). */
	uint64_t                incarnation;
};

/* ─── Timing parameters ─── */

#define MXFS_LEASE_DURATION_MS     5000
#define MXFS_LEASE_RENEW_MS        2000   /* renew at 2/5 of lease duration */
#define MXFS_NODE_TIMEOUT_MS      15000   /* 3 missed renewals = dead */
#define MXFS_LOCK_WAIT_TIMEOUT_MS 60000
/*
 * sess-tcp (PROVEN root, lost DLM grant/release msg): a per-attempt acquire
 * wait, SHORTER than the 60s membership/dead-node timeout.  An intermittently
 * dropped grant/release notification on a contended dir-EX handoff left the
 * waiter blocked the full 60s before its (manual) retry recovered.  Bound each
 * pending_wait in the lock-acquire path to this, and retry on -ETIMEDOUT in
 * mxfs_dlm_lock: the retry re-fires the BAST and re-checks compatibility, so a
 * lost grant is recovered in ~this many ms (the holder has since released ->
 * the retry grants immediately) instead of 60s.  6s >> a healthy handoff
 * (<1s) and covers the release-fence drain (<=30s via its own retries), so it
 * does not spuriously churn healthy waits.
 */
/*
 * sess36 (ccloop): lowered 6000 -> 1000.  A contended dir-EX handoff can be
 * stranded by a subtle master-side queue-vs-grant race (the requester queues
 * its waiter in the instant the holder owns no grant -> no BAST is captured;
 * the holder then re-acquires and nothing re-fires the BAST) — PROVEN on the
 * dir_reuse 2/tcp test: P37-RREL promoted=0, ~6.3s idle, then the requester's
 * own ACQUIRE_WAIT retry re-fires the BAST and wins immediately.  At 6000ms
 * that cost the 24-round test ~60s (over its 300s budget); at 1000ms each
 * residual stall costs ~1s.  A HEALTHY contended handoff (~200ms: BAST -> drain
 * -> release -> grant) is woken by the grant signal long before 1000ms, so this
 * never churns a healthy wait.  The retry count below is raised so the TOTAL
 * budget (retries * this) stays ~60s, still covering a release-fence drain.
 */
#define MXFS_LOCK_ACQUIRE_WAIT_MS  1000

/*
 * One DEGRADED_UNCONFIRMED remote lock wait, as exported to the mount's
 * debugfs (dlm/dlm.h, the acquisition table and its status-delivery
 * contract).  confirm_ms is the ISSUE time of the attempt the master last
 * confirmed, which is the absence clock's anchor; receipt_ms is when that
 * confirmation arrived; degraded_ms is when the bound was crossed.
 */
struct mxfs_dlm_acq_state {
	struct mxfs_resource_id resource;
	uint64_t                acq_seq;
	uint64_t                first_ms;
	uint64_t                last_ms;
	uint64_t                receipt_ms;
	uint64_t                confirm_ms;
	uint64_t                degraded_ms;
	uint32_t                retx;
	uint32_t                rejected;
	mxfs_node_id_t          master;
	uint8_t                 mode;
	int                     owner_pid;
};
#define MXFS_BAST_TIMEOUT_MS      10000   /* time for holder to respond to BAST */

#endif /* MXFS_DLM_H */
