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

/*
 * THE RESERVATION TYPE MXFS ESTABLISHES.
 *
 * sess381 (D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381).
 * This was WRITE EXCLUSIVE - REGISTRANTS ONLY (0x05) until proto-gen 5, and
 * that is a SINGLE-HOLDER type: SPC releases it when the holder's
 * registration is removed, and MXFS retires its own registration
 * unconditionally at put_super.  MEASURED on a healthy 32-node cluster: one
 * node's routine 0.49-second clean unmount took the LUN from a held
 * reservation to NONE, with 31 nodes still mounted and registered, nothing
 * ever re-reserved, and the next peer death was consequently unfenceable
 * (kind=NO_RESERVATION(8), recovery blocked, filesystem permanently
 * unmountable).
 *
 * Under WRITE EXCLUSIVE - ALL REGISTRANTS (0x07) every registrant IS a
 * reservation holder, so the reservation survives until the LAST registration
 * goes.  The I/O policy is identical (registrants write, non-registrants do
 * not), and a matching-scope/type RESERVE from any registrant completes GOOD,
 * so the reservation is self-healing instead of owned by one node.  All three
 * properties MEASURED on this target — see
 * tests/pr_all_registrants_semantics.sh.
 *
 * Mixed generations are excluded cluster-wide by MXFS_PROTO_GEN (5), because
 * a gen-4 binary hard-requires type 0x05 in its fence path, its admission gate
 * and its certificate re-check, and would read a live WR_EX_AR reservation as
 * "no reservation held".
 */
#define MXFS_SCSIPR_RESV_TYPE   MXFS_PAL_PR_TYPE_WR_EX_AR

/*
 * Does a reservation of this type exclude NON-REGISTRANTS from writing?
 *
 * That — not "is it the type we would have created" — is the question every
 * exclusion proof actually rests on, so the fence path and the certificate
 * re-check accept both Write Exclusive forms.  Only the ADMISSION gate insists
 * on MXFS_SCSIPR_RESV_TYPE, because that is where policy belongs: a stale
 * single-holder reservation left behind by an older generation still excludes,
 * but a mount must not join a cluster that will lose its fence on the next
 * unmount.
 */
static inline bool mxfs_pr_type_excludes_nonregistrants(uint32_t type)
{
    return type == MXFS_PAL_PR_TYPE_WR_EX_RO ||
           type == MXFS_PAL_PR_TYPE_WR_EX_AR;
}

static inline const char *mxfs_pr_type_name(uint32_t type)
{
    switch (type) {
    case MXFS_PAL_PR_TYPE_WR_EX_RO: return "WE-RO";
    case MXFS_PAL_PR_TYPE_WR_EX_AR: return "WE-AR";
    case 0:                         return "none";
    default:                        return "other";
    }
}

struct mxfs_scsipr_ctx {
    mxfs_bdev_t     *dev;
    char            dev_name[MXFS_PATH_MAX];
    uint64_t        local_key;
    bool            reserved;
    /* sess381: the type of the reservation this mount last OBSERVED in force
     * (0 = none seen).  Recorded so the preempt CDB carries the type actually
     * held rather than a hardcoded one, and so the admission log can report
     * what it SAW before it acted, not what it created. */
    uint32_t        resv_type_seen;
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
    MXFS_FENCE_KIND_NO_RESERVATION      = 8,  /* no Write Exclusive reservation held, so
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
    MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE = 17, /* no PR proof exists, but the
                                               * operator asserted exclusive
                                               * bdev access (module param
                                               * single_node_exclusive=1) AND
                                               * cluster membership was
                                               * single-node when the fence
                                               * ran: no second initiator can
                                               * hold in-flight writes, so
                                               * exclusion holds by topology,
                                               * not by reservation (sess180
                                               * ruling, dirty-slice defect) */
};

/*
 * The single predicate every replay gate must use.  A kind authorises
 * replay only if it establishes that the victim (a) cannot begin new
 * writes and (b) has no surviving in-flight task set.
 */
static inline bool mxfs_fence_kind_proves_exclusion(enum mxfs_fence_kind k)
{
    return k == MXFS_FENCE_KIND_PREEMPT_ABORT_DONE ||
           k == MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE;
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
/*
 * HOW FAR THE ATTEMPT GOT — the COMMAND-SUBMISSION BOUNDARY (sess381).
 *
 * `kind` says what was PROVED.  It does not say whether a state-changing
 * command reached the target, and that is the question a retry decision
 * actually turns on.  D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381:
 * mxfs_scsipr_fence_node() returns NO_RESERVATION (among others) BEFORE the
 * PROUT PREEMPT AND ABORT is issued — nothing is consumed, the victim key is
 * intact, the attempt is perfectly retryable — yet the caller recorded it as a
 * terminal "exclusion not proved" and the filesystem became permanently
 * unmountable.
 *
 * Deriving this from `kind` would be wrong and the sess381 RULE-5 ruling says
 * so explicitly: a future refactor could detect reservation loss AFTER
 * submission, and the reason would then lie.  The phase is set at the call
 * site, on the two lines that bracket the command.
 */
enum mxfs_fence_phase {
    /* No state-changing command was submitted.  Safe to retry: a later
     * attempt has strictly more information and consumed nothing. */
    MXFS_FENCE_PHASE_PRECOMMAND = 0,
    /* A PREEMPT-family CDB was handed to the transport.  Named for what it
     * actually establishes: a transport handoff does NOT prove target
     * execution, and a timeout here does NOT mean nothing happened.  This
     * phase must never be treated as retryable-as-harmless. */
    MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED = 1,
    /* Submitted, completed, and verified after the fact.  NOTE this is still
     * not FENCED: certification is a separate durable step that can fail on
     * its own. */
    MXFS_FENCE_PHASE_VERIFIED   = 2,
};

struct mxfs_fence_result {
    enum mxfs_fence_kind    kind;
    uint64_t                victim_key;
    uint32_t                pr_generation;
    uint32_t                resv_type;      /* MXFS_PAL_PR_TYPE_* observed */
    int                     rc;             /* errno when kind == ERROR */
    uint8_t                 phase;          /* enum mxfs_fence_phase */
};

static inline const char *mxfs_fence_phase_name(uint8_t p)
{
    switch (p) {
    case MXFS_FENCE_PHASE_PRECOMMAND: return "PRECOMMAND";
    case MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED: return "MAY_HAVE_SUBMITTED";
    case MXFS_FENCE_PHASE_VERIFIED:   return "VERIFIED";
    default:                          return "?";
    }
}

/*
 * Is this attempt safe to repeat?
 *
 * TRUE only when no state-changing command was submitted.  It says nothing
 * about whether a retry will SUCCEED — that depends on whether the missing
 * precondition comes back — only that repeating it cannot make anything worse
 * and cannot un-exclude anybody.
 */
static inline bool mxfs_fence_attempt_is_retryable(const struct mxfs_fence_result *r)
{
    return r && r->phase == MXFS_FENCE_PHASE_PRECOMMAND;
}

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

/* Acquire the reservation this build fences under (MXFS_SCSIPR_RESV_TYPE) */
int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx);

/*
 * Read and LOG the reservation state that already exists, changing nothing.
 * Call this BEFORE register/reserve so the mount's own log says whether the
 * cluster was already armed or whether this mount armed it — the admission
 * gate cannot answer that, because it runs after our own RESERVE (sess381).
 * Returns 0 and fills *out (optional) on success.
 */
int mxfs_scsipr_observe_reservation(struct mxfs_scsipr_ctx *ctx,
                                    struct mxfs_pal_pr_reservation *out);

/* What mxfs_scsipr_check_reservation_health() found. */
enum mxfs_resv_health {
    MXFS_RESV_HEALTH_OK          = 0, /* the expected reservation is in force */
    MXFS_RESV_HEALTH_ABSENT      = 1, /* NO reservation at all — exclusion is
                                       * gone for the whole cluster */
    MXFS_RESV_HEALTH_WRONG_TYPE  = 2, /* a reservation is held but not ours */
    MXFS_RESV_HEALTH_SELF_GONE   = 3, /* our own registration is missing */
    MXFS_RESV_HEALTH_UNKNOWN     = 4, /* could not be established — NOT "ok" */
    MXFS_RESV_HEALTH_REPAIRED    = 5, /* it was ABSENT and this call re-established
                                       * it.  Deliberately NOT folded into OK:
                                       * a silent repair is the failure mode the
                                       * ruling warned about, because it hides
                                       * that there was an interval in which
                                       * non-registrants could write. */
};

/*
 * Is the exclusion invariant still true RIGHT NOW?
 *
 * sess381 (D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381): the admission
 * gate proves this ONCE, at mount, and nothing re-checked it afterwards — so a
 * reservation lost after admission left every mounted node believing fencing
 * was armed until the next peer death discovered otherwise.  Measured: 31 nodes
 * ran for 30 minutes on an unreserved LU and none of them noticed.
 *
 * `repair` = true asks it to re-establish the reservation when it finds it
 * ABSENT.  Only ONE node in the cluster should pass true — re-reserving is a
 * write to a cluster-wide invariant, and it must not be raced.  Note that a
 * repair restores FUTURE exclusion; it proves nothing about the interval during
 * which non-registrants could write, which is why the caller must report this
 * as a safety event rather than as routine self-heal.
 *
 * *out_gen / *out_count (optional) carry the PR generation and registrant count
 * observed, for the operator-facing event.
 */
int mxfs_scsipr_check_reservation_health(struct mxfs_scsipr_ctx *ctx,
                                         bool repair,
                                         uint32_t *out_gen, int *out_count);
const char *mxfs_resv_health_name(int h);

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
/*
 * `arm_submit` (sess381) is called on the LAST LINE before the PREEMPT AND
 * ABORT is handed to the transport, and only if every pre-command check has
 * passed.  Its job is to make "a command may have run" durable so that a crash
 * anywhere from here on is read conservatively.  If it returns nonzero the
 * command is NOT issued and the result comes back at phase PRECOMMAND — an
 * unrecordable preempt is indistinguishable from one that never happened, and
 * consumes the victim key either way.  Pass NULL only where there is no
 * durable attempt record to arm (the bare, non-certifying fence).
 */
int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
                           mxfs_node_id_t victim_node, int live_members,
                           int (*arm_submit)(void *), void *arm_data,
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
 * This re-reads the reservation (must still be held, still a Write Exclusive
 * form) and the key
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

/* sess277: target-authoritative "am I the fenced node?" probe — PR IN /
 * READ FULL STATUS primary, READ KEYS fallback.  1 = fenced (own key
 * provably absent), 0 = still registered, <0 = unknown (NEVER a verdict).
 * Callable while fenced: PR IN is permitted to unregistered initiators. */
int mxfs_scsipr_fenced_check(struct mxfs_scsipr_ctx *ctx);

/* v0.11.80 (D8): provisioning-time conformance probe — call once after
 * register+reserve; logs whether per-node PR is actually usable on this
 * target/topology (own key visible ⇒ active; not visible ⇒ advisory). */
int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx);

/*
 * ADMISSION-TIME FENCING-CAPABILITY VALIDATION (sess378).
 *
 * Answers, BEFORE this mount is admitted to the cluster and before it does any
 * normal I/O, whether this device can actually produce the evidence recovery
 * will later demand.  Until this existed, the first time anyone learned that
 * PR was absent, that persistence was not active, that the reservation was not
 * WR_EX_RO, that the key view was truncated, or that PREEMPT AND ABORT could
 * not be issued at all, was AFTER a peer had died — at which point that peer's
 * slice is unrecoverable and everyone else is blocked on its grants.
 *
 * The abort leg is not hypothetical: sess378 proved MXFS had been running for
 * months on a stack where dm silently downgraded PREEMPT AND ABORT to PREEMPT,
 * and nothing anywhere detected it.
 *
 * Returns 0 if the mount may be admitted read-write.  Returns a negative errno
 * otherwise, having logged a typed P303-FENCECAP-* reason.  -EOPNOTSUPP means
 * the target cannot report capabilities at all.
 */
int mxfs_scsipr_validate_admission(struct mxfs_scsipr_ctx *ctx);

#endif /* MXFS_LIBMXFS_SCSIPR_H */
