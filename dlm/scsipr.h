/*
 * MXFS — Multinode XFS
 * Portable SCSI-3 Persistent Reservations for I/O fencing
 *
 * Hardware-level I/O fencing using SCSI-3 PR. With WRITE EXCLUSIVE -
 * REGISTRANTS ONLY (type 5), all registered nodes can perform I/O
 * while unregistered nodes are fenced off by storage target hardware.
 *
 * Ported from kernel/mxfs_scsipr.{c,h} — kernel pr_ops replaced
 * with PAL SCSI PR functions.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_SCSIPR_H
#define MXFS_LIBMXFS_SCSIPR_H

#include "../pal/pal.h"
#include "../include/mxfs/mxfs_common.h"

/*
 * CAPACITY OF A REGISTRATION-TABLE SNAPSHOT.
 *
 * PR registrations are per-I_T NEXUS, not per node: a multipath node holds
 * one descriptor per path, all carrying the same key.  Measured on the
 * 32-node CAW rig (sess72, `sg_persist --in --read-full-status`): 64
 * descriptors for 32 nodes — two per node, one per iSCSI session, all_tg_pt
 * clear.
 *
 * Every consumer in this file was sizing its buffer by MXFS_MAX_NODES (64),
 * which put that rig EXACTLY at capacity with zero headroom, and the PAL
 * clamped silently.  One extra descriptor — a stale registration from a node
 * that died without unregistering, a third path, a 33rd node — truncated the
 * view with no indication.  That is the dangerous direction: every consumer
 * here decides from key ABSENCE, and a truncated view manufactures absence.
 * `own_present == false` is the self-fence signature, so truncation freezes a
 * HEALTHY node (mxfs_scsipr_self_check ⇒ -ESTALE ⇒ fence_notify_fn).
 *
 * Size by nexuses, not nodes, and leave room for stale descriptors that the
 * target has not yet reaped.  Consumers must ALSO check the view for
 * truncation rather than trusting this bound to be generous enough.
 */
#define MXFS_PR_MAX_PATHS_PER_NODE  8
#define MXFS_PR_MAX_KEYS            (MXFS_MAX_NODES * MXFS_PR_MAX_PATHS_PER_NODE)

struct mxfs_scsipr_ctx {
    mxfs_bdev_t     *dev;
    char            dev_name[MXFS_PATH_MAX];
    uint64_t        local_key;
    bool            reserved;
    /* v0.11.80 (D4): tracks whether OUR key is (believed) registered.
     * Set by a successful register, cleared by unregister — makes
     * destroy's safety-net unregister idempotent (the old
     * unregister-then-destroy pairs issued a second PROUT for an
     * already-removed key). */
    bool            registered;
    /* v0.11.80 (D8): one-shot latch so the periodic self-check logs the
     * advisory-topology condition once per episode, not every tick. */
    bool            advisory_logged;
};

/*
 * WHAT A FENCE ATTEMPT ACTUALLY PROVED (sess71).
 *
 * Until sess71 mxfs_scsipr_fence_node() returned an int that callers
 * collapsed to `== 0`, and FIVE semantically different outcomes returned 0:
 * PR unsupported, advisory topology, sole-survivor ambiguity, victim key
 * already absent, and a real completed preempt.  Only the last bounds the
 * victim's ability to write, yet all five authorised in-place XFS log replay
 * of the victim's slice onto the shared LUN.  Name the outcome instead, and
 * make "may I replay?" a question about the NAME.
 *
 * These values are written to the on-disk recovery descriptor, so they are
 * explicit and MUST NOT be renumbered.
 */
enum mxfs_fence_kind {
    /* ── nothing was proved; replay is NOT authorised ── */
    MXFS_FENCE_KIND_NONE                = 0,  /* not attempted / bad args */
    MXFS_FENCE_KIND_ERROR               = 1,  /* transport or target failure */
    MXFS_FENCE_KIND_UNSUPPORTED         = 2,  /* target has no PR at all */
    MXFS_FENCE_KIND_ADVISORY_TOPOLOGY   = 3,  /* fewer keys than live members */
    MXFS_FENCE_KIND_NOT_REGISTERED      = 4,  /* we hold no key; cannot fence */
    MXFS_FENCE_KIND_SELF_PREEMPTED      = 5,  /* OUR key is gone — self-fence */
    MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN = 6,  /* victim key absent, but nobody
                                               * proved its task set aborted */
    MXFS_FENCE_KIND_RACE_LOST           = 7,  /* our 0x05 hit RESERVATION
                                               * CONFLICT — we did nothing */
    MXFS_FENCE_KIND_NO_RESERVATION      = 8,  /* no WE-RO reservation held, so
                                               * deregistration excludes nobody */
    MXFS_FENCE_KIND_VIEW_TRUNCATED      = 9,  /* the target holds more
                                               * registration descriptors than
                                               * we could read: absence of any
                                               * key is unknowable, so nothing
                                               * may be concluded from it */

    /* ── exclusion PROVED; replay is authorised ── */
    MXFS_FENCE_KIND_PREEMPT_ABORT_DONE  = 16, /* our PREEMPT AND ABORT (0x05)
                                               * completed AND the post-state
                                               * was verified */
};

/*
 * The single predicate every replay gate must use.  A kind authorises
 * replay only if it establishes that the victim (a) cannot begin new
 * writes and (b) has no surviving in-flight task set.
 */
static inline bool mxfs_fence_kind_proves_exclusion(enum mxfs_fence_kind k)
{
    return k == MXFS_FENCE_KIND_PREEMPT_ABORT_DONE;
}

const char *mxfs_fence_kind_name(enum mxfs_fence_kind k);

/*
 * The outcome of one fence attempt, with the evidence that dates it.
 *
 * pr_generation is the PR GENERATION counter the target reported on the
 * VERIFYING read (after the preempt).  It increments on every registration
 * change, so it stamps the observation: a later reader that sees a different
 * generation knows the key set has changed since the fence and that this
 * evidence no longer describes the current registration table.
 */
struct mxfs_fence_result {
    enum mxfs_fence_kind    kind;
    uint64_t                victim_key;
    uint32_t                pr_generation;
    uint32_t                resv_type;      /* MXFS_PAL_PR_TYPE_* observed */
    int                     rc;             /* errno when kind == ERROR */
};

/* Lifecycle */
struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
                                            const char *dev_name,
                                            mxfs_node_id_t node_id);
void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx);

/* This node's registered key (0 if none) */
uint64_t mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx);

/* Free the context WITHOUT unregistering.  For teardown paths that must
 * defer the PROUT unregister until after the filesystem's final log
 * write: a non-holder that unregisters early bounces its own unmount
 * record off the peer's WE-RO reservation (EBADE log-error shutdown on
 * every clean umount — physical-rig QNAP battery). */
void mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx);

/* Register this node's key (idempotent, uses REGISTER_AND_IGNORE) */
int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx);

/* Acquire WRITE EXCLUSIVE - REGISTRANTS ONLY reservation */
int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx);

/* Preempt a dead node's key.  abort=true issues PREEMPT AND ABORT (0x05),
 * which is what an I/O fence requires; see the contract in pal.h.
 * Returns 0 on a completed service action, -EBUSY on RESERVATION CONFLICT
 * (we did nothing), other negative on failure. */
int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key,
                        bool abort);

/* v0.11.80 (D4): fence a dead node's registration with SPC hygiene.
 * READ KEYS first: preempt only a key that is actually registered
 * (a blind preempt of an absent key is a RESERVATION CONFLICT per
 * SPC).  live_members = count of live cluster members INCLUDING self,
 * EXCLUDING the victim — used to classify the topology: when fewer
 * keys than live members are registered, per-node PR is unusable on
 * this rig (e.g. every VM shares ONE host I_T nexus, so each node's
 * REGISTER overwrites the previous one's — measured on the tcm_loop
 * VM rig) and PR is ADVISORY.
 *
 * sess71: the outcome is reported through *out, NOT through the return
 * value.  `out->kind` says what was proved; feed it to
 * mxfs_fence_kind_proves_exclusion() to decide whether the victim's
 * journal slice may be replayed.  The int return remains only so callers
 * can distinguish a transport failure from a classified refusal; it is
 * NOT a fence verdict and must never be tested with `== 0` for that
 * purpose.  out may not be NULL.
 *
 * On MXFS_FENCE_KIND_SELF_PREEMPTED the caller must SELF-FENCE and NEVER
 * auto-re-register. */
int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
                           mxfs_node_id_t victim_node, int live_members,
                           struct mxfs_fence_result *out);

/*
 * sess93 — DOES THE EXCLUSION STILL HOLD?  A DETECTOR, NOT A FENCE.
 *
 * mxfs_scsipr_fence_node() proves exclusion at an INSTANT.  MEASURED on the rig
 * (tests/pr_reregister_probe.sh): a PREEMPT-AND-ABORTed node re-registered with
 * a fresh key and wrote to the shared LUN seconds later.  So a certificate is
 * evidence of a completed EVICTION EVENT, not evidence that the host remains
 * fenced (GPT RULE-5 ruling, sess93 follow-up).
 *
 * This re-reads the reservation (must still be held, still WE-RO) and the key
 * table (victim absent, our own key present, view not truncated) so a victim
 * that came back is CAUGHT rather than silently sharing metadata with its own
 * replayer.  It cannot PREVENT a write that races the check — GPT ranked it
 * "detect-only; useful, but not safety enforcement" — so callers must treat a
 * refusal as terminal for the recovery, never as a retryable hiccup.
 *
 *   0        the exclusion still holds
 *   -EPERM   it has lapsed (out->kind says how: NO_RESERVATION,
 *            VIEW_TRUNCATED, or KEY_ABSENT_UNPROVEN for a re-registered victim)
 *   -ESTALE  OUR key is gone — we are the fenced node; self-fence
 *   other    transport/target error; unknown is refused
 */
int mxfs_scsipr_exclusion_holds(struct mxfs_scsipr_ctx *ctx,
                                uint64_t victim_key,
                                struct mxfs_fence_result *out);

/* Unregister this node's key on clean shutdown */
int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx);

/* Read all currently registered keys.  generation and total (both optional)
 * receive the PR GENERATION counter and the number of descriptors the TARGET
 * holds — see pal.h.  *total > *count means the view is TRUNCATED and no
 * conclusion may be drawn from a key being absent from keys[]. */
int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
                           int max_keys, int *count, uint32_t *generation,
                           int *total);

/* Read the currently held reservation (see pal.h).  Thin pass-through so
 * the fence path can verify that deregistration actually excludes. */
int mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx,
                                 struct mxfs_pal_pr_reservation *out);

/* v0.11.80 (D8): periodic own-registration audit.  0 = fine/advisory,
 * -ESTALE = unambiguous preemption (caller must self-fence, never
 * re-register), other negative = transient READ KEYS failure. */
int mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members);

/* v0.11.80 (D8): provisioning-time conformance probe — call once after
 * register+reserve; logs whether per-node PR is actually usable on this
 * target/topology (own key visible ⇒ active; not visible ⇒ advisory). */
int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx);

#endif /* MXFS_LIBMXFS_SCSIPR_H */
