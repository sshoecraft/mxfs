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
/* sess452: single-use ABSENT answers remembered per (key, bracket); one per
 * heartbeat slot is the most any lap can consume. */
#define MXFS_SCSIPR_ABSENT_USES     64

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
    case MXFS_PAL_PR_TYPE_WR_EX:    return "WE";
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
    /*
     * "Is this key carried by a LIVE member's heartbeat record, other than the
     * dead incarnation being fenced?"  Installed by the DLM layer, which owns
     * the slot table; scsipr cannot answer it alone.  Consulted in the
     * PRECOMMAND section of mxfs_scsipr_fence_node so that EVERY caller is
     * covered — the guard lives at the primitive the four fence paths funnel
     * through, not at the call sites, because an invariant enforced at N
     * callers has N chances to be forgotten.  NULL leaves behaviour unchanged.
     */
    int             (*key_live_fn)(void *data, uint64_t key,
                                   mxfs_node_id_t excl_node,
                                   mxfs_node_id_t *live_node, int *live_slot);
    void            *key_live_data;
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
    bool            nexus_reused;   /* sess439: the plain REGISTER conflicted and
                                     * REGISTER(rk=key, sark=key) proved this
                                     * nexus ALREADY held our derived key (same
                                     * boot, earlier registration) */
    /*
     * The SOLE-SURVIVOR EXCLUSIVE-WRITE GATE is in force: this nexus holds a
     * single-holder WRITE EXCLUSIVE (type 1) reservation it installed with
     * PREEMPT AND ABORT rk=own sark=0 (mxfs_scsipr_gate_sole_survivor), and
     * the all-registrants reservation has not been restored yet
     * (mxfs_scsipr_gate_restore).  While set, the reservation-health check
     * and the key-state bracket treat the type-1 reservation held by OUR key
     * as the fencing reservation: it excludes strictly more than WE-AR does.
     */
    bool            gate_held;
    /*
     * sess452 (0.59.2, design-consult STOP-SHIP #2 blockers 1 and 4): the key-state
     * SNAPSHOT is the last completed BRACKET — READ KEYS (A), READ
     * RESERVATION, READ KEYS (B) with one PR generation across all three —
     * and it is produced by a dedicated probe thread (or, on the mount
     * thread only, synchronously), never by the heartbeat thread.
     *   snap_lock   guards every snap_* field (short sections, no I/O);
     *   probe_lock  serializes bracket EXECUTION (the PR INs);
     *   snap_state  0 = the B view is complete and usable, <0 = errno of the
     *               command that failed (every answer is UNKNOWN);
     *   snap_proof  own key present in A AND B, fencing reservation in
     *               force, generations equal: absence from the B view is a
     *               fencing-grade proof; snap_why names the missing leg;
     *   snap_seq    bracket sequence number; an ABSENT answer is handed out
     *               at most ONCE per (key, seq) — the destructive CAS that
     *               consumes it can never reuse a proof;
     *   snap_inval_seq  bumped by every local PROUT (register / reserve /
     *               preempt / unregister) and by the reservation-conflict
     *               callback; a bracket that started before the bump is
     *               discarded at commit.
     */
    mxfs_mutex_t   *snap_lock;
    mxfs_mutex_t   *probe_lock;
    uint64_t        snap_ms;
    int             snap_state;
    uint32_t        snap_gen;
    bool            snap_own_present;
    bool            snap_resv_ok;
    bool            snap_proof;
    const char     *snap_why;
    int             snap_n;
    uint64_t       *snap_keys;      /* MXFS_PR_MAX_KEYS entries: the B view */
    uint64_t       *bkt_keys_a;     /* bracket scratch (probe_lock) */
    uint64_t       *bkt_keys_b;
    uint64_t        snap_seq;
    uint64_t        snap_inval_seq;
    uint64_t        snap_unprovable_log_ms;
    struct { uint64_t key; uint64_t seq; } absent_used[MXFS_SCSIPR_ABSENT_USES];
    int             absent_used_next;
    /* the probe thread (blocker 4): PR INs never run on the heartbeat */
    mxfs_thread_t  *probe_thread;
    int             probe_stop;
    int             probe_kick;
    uint64_t        probe_last_ms;
    uint64_t        probe_brackets;     /* telemetry: brackets run */
    uint64_t        probe_discarded;    /* brackets discarded by invalidation */
    /* v0.11.80 (D8): one-shot latch so the periodic self-check logs the
     * advisory-topology condition once per episode, not every tick. */
    bool            advisory_logged;

    /*
     * sess454 (0.61.0, design-consult design ruling D6): THE SINGLE-USE ABSENCE
     * PROOF TOKEN.  mxfs_scsipr_settle_absent() runs a fresh bracket under
     * probe_lock and, when it proves the key absent, mints ONE token
     * {id, key, bracket seq, invalidation seq} here (under snap_lock) and
     * hands the caller only the opaque id.  The destructive CAS consumes it
     * through mxfs_scsipr_proof_consume() immediately before the write: the
     * token must be the live one, unused, for that key, and no local PROUT
     * or reservation loss may have bumped snap_inval_seq since the mint.
     * Consumption is unconditional — a CAS that fails still spends the
     * proof.  Identity and used-state never leave this struct.
     */
    uint64_t        token_ctr;
    uint64_t        token_id;       /* 0 = no live token */
    uint64_t        token_key;
    uint64_t        token_seq;
    uint64_t        token_inval;
    bool            token_used;

    /*
     * sess454 (0.61.0, D8): probe-thread lifecycle.  probe_stop/probe_kick/
     * probe_exited are read and written through mxfs_pal_flag_get/set only.
     * A stop whose bounded join times out QUARANTINES the whole context:
     * nothing is freed, the module is pinned, the ctx sits on the
     * quarantine list until the thread's own exit lets a later reaper free
     * it, and no further clustered mount is admitted on this host meanwhile.
     */
    int             probe_exited;
    bool            quarantined;
    bool            module_pinned;
    struct mxfs_scsipr_ctx *quarantine_next;
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
    MXFS_FENCE_KIND_PREEMPT_ABORT_DONE  = 16, /* RETIRED 0.89.16 — never
                                               * minted again and refused
                                               * wherever a certificate is
                                               * consumed.  It meant "our
                                               * PREEMPT AND ABORT (0x05)
                                               * completed AND the post-state
                                               * was verified", but a second
                                               * producer stamped it on an
                                               * outcome derived from PR-ledger
                                               * state with no operation run,
                                               * so a durable 16 cannot be
                                               * classified.  Kept so an older
                                               * record and an older log line
                                               * still decode; superseded by
                                               * ..._PROVEN_V1 below */
    MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE = 17, /* REVOKED 0.89.18.  No PR
                                               * proof existed; the operator
                                               * asserted exclusive bdev access
                                               * (single_node_exclusive=1) and
                                               * membership was single-node
                                               * when the fence ran, so no
                                               * second INITIATOR could hold
                                               * in-flight writes and exclusion
                                               * was taken to hold by topology.
                                               * That is the ADMISSION half
                                               * only: the victim is a previous
                                               * INCARNATION whose already
                                               * accepted writes the target may
                                               * still be finishing, and no
                                               * parameter value observes that.
                                               * Nothing mints it and every
                                               * reader refuses it; the code
                                               * point is not reused */
    MXFS_FENCE_KIND_NO_VICTIM_KEY       = 18, /* sess438: the victim's 64-bit
                                               * PR key was never frozen from
                                               * a valid identity block of the
                                               * exact dead incarnation, so
                                               * there is nothing to PREEMPT;
                                               * NOTHING was issued.  Never
                                               * falls back to node_id */
    MXFS_FENCE_KIND_SELF_SUCCESSION_DONE = 19, /* sess439 (docs/whole-cluster-
                                               * restart.md §5.2): the victim
                                               * is a PREVIOUS BOOT of the
                                               * prover's own host; under a
                                               * SELF_SUCCESSION fence intent
                                               * on the victim's slot the
                                               * prover REGISTERed AND IGNOREd
                                               * the old key on its own paths
                                               * and READ FULL STATUS proved
                                               * the old key absent on EVERY
                                               * transport ID and the new key
                                               * present on every successor
                                               * path.  Exclusion holds by the
                                               * boot boundary + nexus
                                               * reinstatement (the old task
                                               * set died with the old
                                               * session) + verified removal.
                                               * PROVES exclusion; consumed by
                                               * the slice-recovery owner by
                                               * intent, never inferred from
                                               * key absence */
    MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE = 20, /* THE SOLE-SURVIVOR EXCLUSIVE-
                                               * WRITE GATE (D-0904).  The
                                               * victim's registration was
                                               * already gone (a target that
                                               * purges a registration with its
                                               * iSCSI session: QNAP TS-453
                                               * Pro, measured 2026-09-04), so
                                               * no PREEMPT AND ABORT could
                                               * name it.  The prover, the ONLY
                                               * live member, issued PREEMPT
                                               * AND ABORT rk=own sark=0
                                               * type=WRITE EXCLUSIVE (1)
                                               * against the all-registrants
                                               * reservation: SPC-4 5.9.10.4.4
                                               * releases it, removes every
                                               * OTHER registration (aborting
                                               * their task sets) and installs
                                               * a single-holder WE for the
                                               * prover's nexus.  Verified by
                                               * READ KEYS (own key only) and
                                               * READ RESERVATION (type 1 held
                                               * by own key).  Under type 1 no
                                               * other nexus — registered or
                                               * not, the victim re-registered
                                               * or not — can write, which is
                                               * a stronger exclusion than a
                                               * key preempt gives (it also
                                               * closes the replay-window
                                               * re-registration hazard).  The
                                               * gate is restored to WE-AR
                                               * when the recovery publishes.
                                               * PROVES exclusion */
    MXFS_FENCE_KIND_KEY_HELD_BY_LIVE_MEMBER = 22, /* the victim's key is ALSO
                                               * carried by a LIVE member's
                                               * heartbeat record right now.
                                               * The PR key is derived per
                                               * BOOT from {host, boot, LUN}
                                               * and a host has one I_T nexus,
                                               * so a successor incarnation
                                               * mounting in the same kernel
                                               * re-registers the identical
                                               * key its dead predecessor left
                                               * behind as the fence target.
                                               * A PREEMPT AND ABORT naming it
                                               * cannot reach only the dead
                                               * incarnation: the target has
                                               * no way to tell them apart, so
                                               * it would strip the LIVE
                                               * member's registration and
                                               * abort its outstanding task
                                               * set.  Nothing is issued and
                                               * this proves NO exclusion —
                                               * the caller must serialise the
                                               * succession (dispose of the
                                               * predecessor before the
                                               * successor registers) rather
                                               * than fence a live node. */
    MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT = 21, /* 0.75.71: the victim is a
                                               * PREVIOUS BOOT of a host that
                                               * is LIVE AGAIN under a later
                                               * boot, and its registration is
                                               * already gone (a target that
                                               * purges a registration with
                                               * its iSCSI session).  The
                                               * prover verified, in this
                                               * order: the victim's identity
                                               * block frozen for the exact
                                               * dead incarnation; a live
                                               * member (heartbeat advancing,
                                               * or the prover itself) whose
                                               * identity carries the victim's
                                               * host_uuid under a DIFFERENT
                                               * boot_uuid; no record on the
                                               * table carrying the victim's
                                               * boot_uuid advanced across a
                                               * heartbeat interval (no clone,
                                               * no snapshot-resumed copy
                                               * heartbeating); and READ
                                               * RESERVATION + READ KEYS under
                                               * our own registration showed a
                                               * Write Exclusive form that
                                               * excludes non-registrants held,
                                               * our key present, the view
                                               * complete and the victim key
                                               * absent.  Exclusion holds by
                                               * the boot boundary (the OS
                                               * instance that issued the
                                               * victim's I/O is gone from its
                                               * host) plus the reservation
                                               * (an unregistered nexus cannot
                                               * write, and a fenced or lost
                                               * registration is never
                                               * re-registered by this code).
                                               * PROVES exclusion */
    /*
     * 0.89.16 — THE COMPLETED PREEMPT AND ABORT, AS A VERSIONED PROOF PROFILE.
     *
     * Semantically this is what kind 16 was supposed to mean: our PERSISTENT
     * RESERVE OUT / PREEMPT AND ABORT NAMED a registration that was in the
     * target's table, completed, and the post-state was verified — so the
     * command's own defined completion aborted that registration's task sets.
     * It is a fresh code point rather than a tightened 16 because a kind is a
     * durable identifier of a CONSTRUCTION CONTRACT, and 16's contract was
     * never unique: the bootstrap-owner takeover also stamps 16 on an outcome
     * derived from PR-LEDGER STATE with no operation run at all.  Tightening
     * what 16 means from here on would not repair the 16s already on a
     * platter, and a reader cannot tell the two producers apart.  So 16 is
     * RETIRED — never minted again, refused wherever a certificate is
     * consumed — and this profile takes its place.
     *
     * The rule that makes the identifier worth anything: this profile's
     * meaning is never widened or reassigned.  If its rules are found unsound,
     * consumption of THIS value is disabled; if the rules change incompatibly,
     * a new value is allocated.  Design record:
     * docs/rulings/fence-certificate-proof-profiles-and-legacy-revocation.md
     */
    MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1 = 23,
    /*
     * 0.89.33 — THE WITNESSED LOGICAL UNIT RESET, AS A VERSIONED PROOF
     * PROFILE.  This is the route for the case a PREEMPT AND ABORT cannot
     * reach: the target has already purged the victim's registration, so
     * there is no descriptor left for a command to NAME, and every fence
     * attempt classifies KEY_ABSENT_UNPROVEN however many times it is
     * retried.
     *
     * THE CONSTRUCTION CONTRACT, and a certificate of this kind asserts the
     * whole of it.  Every clause is a fact the prover established, in this
     * order, and any one of them missing means no certificate — not a weaker
     * one:
     *
     *   1. ADMISSION.  mxfs_scsipr_lu_reset_admit() admitted the reset: an
     *      excluding Write Exclusive form held, the registration table read
     *      COMPLETE held exactly one descriptor, that descriptor was proved
     *      to be OUR OWN nexus by an idempotent RESERVE, the census was
     *      bracketed by an unmoved PR generation, and the victim's key was
     *      absent.  This is the admission half of exclusion, and it is also
     *      what makes an LU-scope reset a defensible thing to issue at all:
     *      no other initiator's registration is on the unit to have its work
     *      stranded.
     *   2. THE OPERATION RAN AND THE TARGET ANSWERED IT.  One LOGICAL UNIT
     *      RESET, witnessed — the transport incarnation unchanged across the
     *      call, the reset issued, and the target's task-management response
     *      received (MXFS_PAL_LURESET_WITNESSED, nothing weaker; an
     *      INDETERMINATE verdict is never a witness).  A logical unit reset's
     *      defined effect is to terminate the tasks in the task set of EVERY
     *      I_T nexus attached to that unit, and the victim's accepted work is
     *      in one of them whatever became of its registration.  THIS is the
     *      retirement witness, and it is why the basis stays
     *      MXFS_RETIRE_BASIS_TARGET_OP: a target operation ran to completion
     *      and its own specification retires the tasks.
     *   3. THE AUDITED-KERNEL PIN.  The witness's per-operation meaning does
     *      not come from a protocol correlator — libiscsi does not match the
     *      Initiator Task Tag on a task-management response — it comes from
     *      the enforced one-TMF-per-session serialization around it.  A
     *      serialization invariant, unlike a tag, degrades silently into an
     *      inference if a later version ever allows two in flight, with no
     *      change to the value the caller reads.  So the release the witness
     *      was taken on must be one this build has audited, and anything else
     *      is refused: mxfs_fence_lu_reset_kernel_audited().
     *   4. THE POST-RESET BARRIER HELD.  The reset terminated the ISSUER's
     *      own tasks too, so the prover re-established the command path with
     *      a controlled probe, re-ran the WHOLE admission assertion set,
     *      checked the PR generation did not move across the reset, and then
     *      proved its own storage authority had survived by waiting for a
     *      heartbeat ISSUED AFTER the reset to land.  A witnessed reset plus
     *      a lapsed lease is exactly the state that must leave a resumable
     *      durable intent and NO certificate.
     *
     * WHAT IT DOES NOT ASSERT.  Nothing about a bystander INITIATOR's
     * in-flight reads: a non-registrant may still READ under a Write
     * Exclusive reservation, no operation enumerates the nexuses merely
     * logged in, and such a read is terminated by the reset and recovered by
     * its own error handler.  That is a liveness cost of the route, not a
     * correctness claim, and the admission gate is what bounds it.
     *
     * The rule that makes the identifier worth anything is the same one
     * kind 23 carries: this profile's meaning is never widened or
     * reassigned.  If its rules are found unsound, consumption of THIS value
     * is disabled; if they change incompatibly, a new value is allocated.
     * It has exactly ONE producer — mxfs_scsipr_fence_by_lu_reset() — which
     * is what kind 16 never had.
     */
    MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1 = 24,
};

/*
 * DID THIS ATTEMPT, JUST NOW, PROVE ANYTHING?  A question about a FRESH result
 * still sitting in the caller's stack — nothing more.
 *
 * IT IS NOT AN AUTHORISATION GATE AND NO DURABLE AUTHORITY MAY FLOW THROUGH
 * IT.  Callers use it to decide whether an attempt got far enough to be worth
 * certifying; the certificate constructor and every consuming reader ask
 * mxfs_fence_durable_kind_supported() instead.  0.89.17 moved the constructor
 * off it for the reason the list below makes plain: it still admits 19, 20 and
 * 21, which consumption revokes, so a build reading this as permission could
 * seal a certificate it would then refuse to read — and a sealed descriptor is
 * -EEXIST to every later prover, so that slice could never be certified again.
 *
 * 0.89.16: kind 16 is NOT in this list any more.  It is retired, for the
 * reason written at MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1 — its code point
 * had two producers and only one of them ran an operation, so a durable 16
 * cannot be classified.  A fresh attempt never produces one.
 *
 * 0.89.18: kind 17 is gone from it too, and nothing produces one any more.
 * The operator's single-node assertion answers a question about ADMISSION —
 * that no second INITIATOR can be holding writes — and a fresh attempt that
 * has only that has proved nothing about the writes the target had already
 * accepted from the incarnation being recovered.  An operator parameter may
 * select an operating mode; it cannot stand in for an operation the target
 * performed.
 */
static inline bool mxfs_fence_kind_proves_exclusion(enum mxfs_fence_kind k)
{
    return k == MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1 ||
           k == MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1 ||   /* 0.89.33 */
           k == MXFS_FENCE_KIND_SELF_SUCCESSION_DONE ||    /* sess439 */
           k == MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE ||    /* D-0904 */
           k == MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT;    /* 0.75.71 */
}

/*
 * WHICH DURABLE RECORD A FENCE KIND WAS READ OUT OF.  The record family is
 * durable information too, and it matters: the same code point was written by
 * different producers into different records, and one of those producers did
 * not run an operation.
 */
enum mxfs_fence_record_family {
    MXFS_FENCE_RECORD_RECOVERY_DESC = 0,   /* struct mxfs_recov_desc */
    MXFS_FENCE_RECORD_BOOTSTRAP_OWNER = 1, /* struct mxfs_bootstrap_rec */
};

/*
 * MAY A DURABLE CERTIFICATE OF THIS KIND AUTHORISE REPLAY IN THIS BUILD?
 *
 * This is the one place that answers it, and every reader that did not mint
 * the certificate goes through it — the recovery-descriptor consumer, the
 * bootstrap-owner acceptance check, the mount-time takeover check.  The
 * question is NOT "did some attempt once prove exclusion"
 * (mxfs_fence_kind_proves_exclusion answers that about a FRESH result); it is
 * "can this build classify the record into a proof contract it still
 * supports".  A kind is a durable identifier of a construction contract, so a
 * contract that has been rejected is REVOKED for consumption as well as for
 * minting — an older build having written the record is not evidence that the
 * older build was right.
 *
 * Returns false with *why naming the revoked class.  Refusal is the default
 * for anything this build cannot classify, including a kind it has never
 * heard of.  Design record:
 * docs/rulings/fence-certificate-proof-profiles-and-legacy-revocation.md
 */
bool mxfs_fence_durable_kind_supported(enum mxfs_fence_record_family family,
                                       uint16_t kind, const char **why);

/*
 * The reservation type a certificate of this kind must have been verified
 * under, or 0 when the kind's exclusion does not rest on a reservation
 * (SINGLE_NODE_EXCLUSIVE: topology; SELF_SUCCESSION_DONE: the boot boundary).
 * A PREEMPT_ABORT_DONE certificate needs a Write Exclusive form that excludes
 * non-registrants (either accepted, see mxfs_pr_type_excludes_nonregistrants);
 * an EXCLUSIVE_WRITE_GATE certificate needs exactly the single-holder type it
 * installed.
 */
static inline bool mxfs_fence_kind_resv_type_ok(enum mxfs_fence_kind k,
                                                uint32_t resv_type)
{
    switch (k) {
    case MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1:
    case MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1:     /* the reset retires the
                                                     * work already accepted;
                                                     * the reservation is what
                                                     * keeps the unregistered
                                                     * victim from starting
                                                     * any more */
    case MXFS_FENCE_KIND_PREEMPT_ABORT_DONE:        /* retired; still decoded */
    case MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT:    /* the reservation is what
                                                     * keeps the unregistered
                                                     * old nexus out */
        return mxfs_pr_type_excludes_nonregistrants(resv_type);
    case MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE:
        return resv_type == MXFS_PAL_PR_TYPE_WR_EX;
    default:
        return true;
    }
}

/*
 * sess439 self-succession, successor side: replace THIS host's previous
 * boot's key `old_key` with ctx->local_key on our own nexus by
 * REGISTER(rk=old_key, sark=local_key) — a nexus-local compare-and-swap that
 * fences nobody (needs no on-LUN intent; the old session's task set died
 * with the nexus).  Verified by READ KEYS exactly like a fresh REGISTER.
 * -ENOKEY: the nexus does not hold old_key (classification stale; refuse).
 */
int mxfs_scsipr_register_succeed(struct mxfs_scsipr_ctx *ctx, uint64_t old_key);

const char *mxfs_fence_kind_name(enum mxfs_fence_kind k);

/* sess439: did the last mxfs_scsipr_register find our own derived key already
 * registered on this nexus (same boot) rather than registering it fresh? */
bool mxfs_scsipr_nexus_reused(struct mxfs_scsipr_ctx *ctx);

/* sess439: the mount is being refused but the registration on this nexus is
 * a RETAINED fence target (P302) that must outlive the refusal: forget that
 * we are registered so the teardown does not unregister it. */
void mxfs_scsipr_retain_key(struct mxfs_scsipr_ctx *ctx);

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
 * Deriving this from `kind` would be wrong and the sess381 design-consult ruling says
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

/*
 * WHAT ESTABLISHED THAT THE TARGET IS DONE WITH THE VICTIM'S ALREADY-ACCEPTED
 * WRITES (0.89.13).
 *
 * Exclusion has two halves and they are separate facts.  ADMISSION — the dead
 * incarnation cannot obtain permission for a NEW write — is what a
 * registration table and a reservation establish.  RETIREMENT — the target
 * has finished with the commands it ALREADY TOOK from that incarnation's
 * nexus — is a property of the target, and no SPC command reports it after
 * the fact.  A certificate authorises replaying the victim's journal slice,
 * so a command that executes after it lands under the replay as an unordered
 * write into metadata the replay is rewriting.  A kind that proves only
 * admission therefore needs a retirement basis before it may certify, and
 * which basis it used is part of what the attempt recorded.
 *
 * TARGET_OP is the only one left: a correctly scoped target operation ran to
 * completion and its own specification retires the tasks (a PREEMPT AND ABORT
 * that named a registration still present covers that registration's nexuses).
 *
 * QUALIFIED_CONTRACT was the weak one — no operation was run, and the
 * deployment had asserted the ordering for this exact target, firmware and
 * LUN.  0.89.16 WITHDREW IT.  A contract is an environmental assertion and
 * never a witness: the module cannot detect a target that violates it, and the
 * only support the shipped clause ever had was four probe laps that observed
 * no late write, which characterises a target rather than bounding it.  The
 * value is kept so an older log line or an older on-disk record still decodes,
 * and it is never produced or accepted again — see mxfs_scsipr_retire_proof().
 */
enum mxfs_retire_basis {
    MXFS_RETIRE_BASIS_NONE = 0,
    MXFS_RETIRE_BASIS_TARGET_OP = 1,
    MXFS_RETIRE_BASIS_QUALIFIED_CONTRACT = 2,  /* withdrawn 0.89.16 */
};

static inline const char *mxfs_retire_basis_name(uint8_t b)
{
    switch (b) {
    case MXFS_RETIRE_BASIS_TARGET_OP:           return "completed-target-op";
    case MXFS_RETIRE_BASIS_QUALIFIED_CONTRACT:
        return "qualified-contract(withdrawn)";
    default:                                    return "none";
    }
}

/*
 * WHAT WAS OBSERVED ABOUT THE VICTIM'S REGISTRATION, kept strictly apart from
 * what is CLAIMED about its work (0.89.15 design-consult ruling,
 * docs/rulings/retirement-proof-obligation-and-observed-transition-classes.md).
 *
 * An observation is a fact this initiator can state.  None of them is a
 * retirement claim on its own, and the mapping from one to the other is the
 * deployment's clause — never an inference made here.  In particular
 * "no MXFS successor record exists" is NOT "the registration disappeared
 * through nexus loss", and "the successor registered under a different boot"
 * is NOT "the nexus that carried the victim's writes was lost": an iSCSI
 * connection, an iSCSI session, a SCSI I_T nexus and an MXFS boot identity are
 * four identifiers with four different lifetimes.
 */
enum mxfs_retire_observation {
    MXFS_RETIRE_OBS_UNKNOWN = 0,
    /* the victim's registration was still in the table, so a command could
     * name it */
    MXFS_RETIRE_OBS_REGISTRATION_PRESENT = 1,
    /* the victim's key is absent and no durable ledger record of ours names
     * it as a replaced predecessor */
    MXFS_RETIRE_OBS_NO_MXFS_SUCCESSOR = 2,
    /* a durable ledger record says THIS host replaced that key from the SAME
     * boot: the nexus may never have been lost at all */
    MXFS_RETIRE_OBS_REPLACEMENT_SAME_BOOT = 3,
    /* ... from a DIFFERENT boot.  Still a replacement, and a host lifetime
     * boundary is not a target-side ordering witness */
    MXFS_RETIRE_OBS_REPLACEMENT_DIFFERENT_BOOT = 4,
    /* 0.89.33.  The victim's key is absent AND the complete registration
     * table holds exactly one descriptor, proved to be our own nexus, under
     * an excluding reservation, with the PR generation unmoved across the
     * bracket — i.e. this initiator is the SOLE REGISTRANT on the unit.
     *
     * It is a strictly stronger observation than NO_MXFS_SUCCESSOR and is
     * kept apart from it for the reason this whole enum exists: absence on
     * its own says nothing about retirement, but sole registration is the
     * premise an LU-SCOPE operation needs, because the scope of that
     * operation is every nexus on the unit and this is what says no other
     * initiator's registered work is there to be destroyed by it.  It still
     * makes no retirement claim by itself — the reset does that. */
    MXFS_RETIRE_OBS_SOLE_REGISTRANT_VICTIM_ABSENT = 5,
};

static inline const char *mxfs_retire_observation_name(uint8_t o)
{
    switch (o) {
    case MXFS_RETIRE_OBS_REGISTRATION_PRESENT:
        return "victim-registration-present";
    case MXFS_RETIRE_OBS_NO_MXFS_SUCCESSOR:
        return "no-mxfs-successor-observed";
    case MXFS_RETIRE_OBS_REPLACEMENT_SAME_BOOT:
        return "mxfs-replacement-same-boot";
    case MXFS_RETIRE_OBS_REPLACEMENT_DIFFERENT_BOOT:
        return "mxfs-replacement-different-boot";
    case MXFS_RETIRE_OBS_SOLE_REGISTRANT_VICTIM_ABSENT:
        return "sole-registrant-victim-absent";
    default:
        return "unknown";
    }
}

/*
 * THE EXACT PROPOSITION THE CERTIFICATE ASSERTS about the victim's work, so a
 * later reader judges the claim and not a human-readable label.  A claim is
 * always paired with the observation whose premises it needs.
 */
enum mxfs_retire_claim {
    MXFS_RETIRE_CLAIM_NONE = 0,
    /* our PREEMPT AND ABORT named the victim's own registration and
     * completed: the abort scope is the one the standard defines for it */
    MXFS_RETIRE_CLAIM_PREEMPT_ABORT_NAMED_VICTIM = 1,
    /* WITHDRAWN 0.89.16.  The deployment asserted that on this LUN a
     * registration which disappears with no MXFS replacement does so only
     * after the commands accepted on its nexus have completed or aborted,
     * effects ordered.  Never produced again; kept so an older record or log
     * line still decodes */
    MXFS_RETIRE_CLAIM_CONTRACT_UNREPLACED_ABSENCE = 2,
    /* 0.89.33.  One LOGICAL UNIT RESET was issued by this initiator and
     * witnessed: the target answered it with a task-management response on a
     * transport incarnation unchanged across the call.  The claim is the
     * operation's own defined effect — the tasks in the task set of every
     * I_T nexus attached to the logical unit are terminated — which reaches
     * the victim's accepted work whether or not any registration still names
     * it.  Paired with MXFS_RETIRE_OBS_SOLE_REGISTRANT_VICTIM_ABSENT, whose
     * sole-registrant half is the premise that makes the LU scope
     * defensible, and never with a weaker observation. */
    MXFS_RETIRE_CLAIM_LU_RESET_WITNESSED_ALL_TASKS = 3,
};

static inline const char *mxfs_retire_claim_name(uint8_t c)
{
    switch (c) {
    case MXFS_RETIRE_CLAIM_PREEMPT_ABORT_NAMED_VICTIM:
        return "preempt-abort-named-the-victim-registration";
    case MXFS_RETIRE_CLAIM_CONTRACT_UNREPLACED_ABSENCE:
        return "contract-unreplaced-registration-absence";
    case MXFS_RETIRE_CLAIM_LU_RESET_WITNESSED_ALL_TASKS:
        return "witnessed-lu-reset-terminated-all-tasks-on-the-unit";
    default:
        return "none";
    }
}

struct mxfs_fence_result {
    enum mxfs_fence_kind    kind;
    uint64_t                victim_key;
    uint32_t                pr_generation;
    uint32_t                resv_type;      /* MXFS_PAL_PR_TYPE_* observed */
    int                     rc;             /* errno when kind == ERROR */
    uint8_t                 phase;          /* enum mxfs_fence_phase */
    uint8_t                 retire_basis;   /* enum mxfs_retire_basis */
    uint8_t                 retire_claim;   /* enum mxfs_retire_claim */
    uint8_t                 retire_obs;     /* enum mxfs_retire_observation */
};

/*
 * IS THERE A RETIREMENT BASIS FOR THIS ATTEMPT?  Since 0.89.16 this call has
 * exactly one answer — NONE — and it exists to say so in the caller's own
 * words rather than to be deleted.
 *
 * The deployment contract it used to evaluate (five colon-separated fields:
 * <vendor>:<product>:<revision>:<lun designator>:<clause>, matched against
 * what the LUN reports through INQUIRY and its device identification VPD page)
 * asserted an ordering between a registration leaving the target's table and
 * the commands accepted on that registration's nexus finishing.  A clause is a
 * CONDITIONAL, its premise is an observation, and no initiator can establish
 * that premise: the target never reports WHY a registration disappeared.  The
 * only support the shipped clause had was four probe laps that saw no late
 * write in a bounded window.  Since a certificate minted on it authorises
 * replaying a foreign journal slice, and a write the target had not finished
 * would land under that replay as an unordered logical write into metadata the
 * replay is rewriting, the qualification is withdrawn: this build accepts no
 * clause, and no configuration value re-enables the route.
 *
 * `contract` is still passed so the refusal can NAME a configured contract and
 * report it as rejected.  `obs` is what was observed about the victim's
 * registration and is reported with the refusal.  Always returns
 * MXFS_RETIRE_BASIS_NONE, always sets *claim_out to MXFS_RETIRE_CLAIM_NONE,
 * and always fills `why` with the reason the caller must log before refusing
 * to certify.  The one basis that still certifies —
 * MXFS_RETIRE_BASIS_TARGET_OP — is set by the fence path that actually ran the
 * operation (mxfs_scsipr_fence_node on a completed PREEMPT AND ABORT that
 * named a registration still present), never here.
 */
enum mxfs_retire_basis
mxfs_scsipr_retire_proof(struct mxfs_scsipr_ctx *ctx,
                         const char *contract,
                         enum mxfs_retire_observation obs,
                         enum mxfs_retire_claim *claim_out,
                         char *why, size_t whysz);

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
/* sess438: the key is the 64-bit per-boot key selected through the PR
 * registrant ledger (dlm/prledger.h), never a node id.  Legacy callers with
 * no ledger pass the node id cast up — such a mount is excluded from any
 * gen-12 cluster by the proto gate, so the two key spaces never meet. */
struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
                                            const char *dev_name,
                                            uint64_t local_key);

/* sess438: is `key` registered on this LU right now (READ KEYS)?  Used by the
 * ledger's collision check exactly once per candidate before REGISTER.  A
 * truncated or unreadable table answers TRUE (fail closed: redraw/refuse). */
bool mxfs_scsipr_key_present(struct mxfs_scsipr_ctx *ctx, uint64_t key);

/*
 * sess451 (D-377 / D-0356 design-consult STOP-SHIP blocker 3, merge criteria 2, 5,
 * 6): the TRI-STATE answer to "is this PR key registered on the LUN right
 * now?", for callers whose next act on ABSENT is destructive (publishing a
 * released heartbeat slot EMPTY = consumable).  ABSENT is a fencing-grade
 * proof and is answered ONLY when ALL of:
 *   - the READ KEYS view is COMPLETE (a truncated table cannot establish
 *     absence — the sess72 rule);
 *   - our own key is in that view (we are a registrant, so the view was
 *     taken from inside the protected domain);
 *   - a reservation of the type this build fences under is in force (a
 *     de-registered initiator is excluded only WHILE a reservation exists;
 *     if the departing node was the last registrant, its unregister may
 *     have dropped the reservation and the gap has no protection);
 *   - the key is not in the view.
 * Everything else — no PR support (-EOPNOTSUPP is NOT "nothing can
 * collide" on a shared LUN), transport / unit-attention / timeout error,
 * overflow, our own key missing, no or wrong-type reservation — is UNKNOWN,
 * never ABSENT.  PRESENT needs only the key in a complete view.
 *
 * sess452 (0.59.2, design-consult STOP-SHIP #2): the proof is now COHERENT and
 * FRESH, and the commands that produce it never run on the heartbeat:
 *   - a proof is a BRACKET: READ KEYS (A) → READ RESERVATION → READ KEYS
 *     (B), all three reporting the SAME PR generation, our key in A and
 *     B, the fencing reservation in force; absence is judged from B.  Our
 *     registration being preempted between two commands moves the
 *     generation, so the bracket cannot manufacture a proof across it;
 *   - PRESENT may be served from a bracket up to MXFS_SCSIPR_PRESENT_TTL_MS
 *     old; ABSENT only from one at most MXFS_SCSIPR_ABSENT_FRESH_MS old,
 *     taken after the last local PR mutation, and at most ONCE per (key,
 *     bracket) — the destructive CAS that consumes an ABSENT can never act
 *     on a reused proof.  A stale or consumed proof answers UNKNOWN and
 *     schedules a new bracket;
 *   - mxfs_scsipr_key_state() is ASYNC: it reads the table and kicks the
 *     probe thread (mxfs_scsipr_probe_start) — no PR I/O on the caller;
 *     the heartbeat monitor uses it.  mxfs_scsipr_key_state_sync() runs a
 *     bracket inline — MOUNT THREAD ONLY (admission barrier, P305).
 *   - every local PROUT invalidates the snapshot
 *     (mxfs_scsipr_snap_invalidate, also called by the reservation-
 *     conflict path), and a bracket that started before an invalidation
 *     is discarded at commit.
 */
enum mxfs_scsipr_key_state {
    MXFS_SCSIPR_KEY_ABSENT  = 0,
    MXFS_SCSIPR_KEY_PRESENT = 1,
    MXFS_SCSIPR_KEY_UNKNOWN = 2,
};
#define MXFS_SCSIPR_PRESENT_TTL_MS      2000
#define MXFS_SCSIPR_ABSENT_FRESH_MS     5000
#define MXFS_SCSIPR_PROBE_MIN_GAP_MS    250
int  mxfs_scsipr_key_state(struct mxfs_scsipr_ctx *ctx, uint64_t key);
int  mxfs_scsipr_key_state_sync(struct mxfs_scsipr_ctx *ctx, uint64_t key);
/* sess452: a FRESH bracket proving OUR registration is live inside the
 * fencing reservation (own key in A and B, reservation in force, one
 * generation).  0 = proven; -EPROTO the bracket completed without proof
 * (why logged); <0 the command that failed.  MOUNT THREAD ONLY — the P305
 * same-boot settlement's precondition for clearing a record naming our key. */
int  mxfs_scsipr_own_registration_proven(struct mxfs_scsipr_ctx *ctx);
void mxfs_scsipr_snap_invalidate(struct mxfs_scsipr_ctx *ctx, const char *why);

/*
 * sess454 (0.61.0, design-consult design ruling D1 + D6): SETTLE-ABSENT — the only
 * path that may turn "key absent" into a destructive write.
 *
 * The caller (the mount thread at P305, or the retire settle worker) holds
 * the host-wide departure mutex (asserted).  Under probe_lock this runs ONE
 * fresh bracket, and, if the bracket is a fencing-grade proof in which
 * `key` is absent, mints the single-use token and invokes `cas_fn` — still
 * under probe_lock, so no bracket and no local PROUT (every local PROUT
 * takes the departure mutex) can interleave between proof and CAS.  The
 * CAS callback must call mxfs_scsipr_proof_consume(ctx, token) immediately
 * before its compare-and-write and must not write if that returns nonzero.
 * A peer's PREEMPT that lands meanwhile moves the PR generation / raises
 * the reservation-conflict callback, which bumps snap_inval_seq and makes
 * the consume fail: UNKNOWN, never success.
 *
 * *out names the outcome; the int return is the command rc of the bracket
 * (0 also when it yielded no proof).
 */
enum mxfs_scsipr_settle {
    MXFS_SCSIPR_SETTLE_UNKNOWN = 0,     /* no proof (why logged) / consume refused */
    MXFS_SCSIPR_SETTLE_PRESENT = 1,     /* key registered in a complete view */
    MXFS_SCSIPR_SETTLE_DONE    = 2,     /* proof + CAS landed */
    MXFS_SCSIPR_SETTLE_MOVED   = 3,     /* proof, but the record moved (CAS lost) */
    MXFS_SCSIPR_SETTLE_DEFERRED = 4,    /* proof, CAS not attempted (no CAW, etc.) */
};
enum mxfs_scsipr_cas_result {
    MXFS_SCSIPR_CAS_DONE     = 0,
    MXFS_SCSIPR_CAS_MOVED    = 1,
    MXFS_SCSIPR_CAS_DEFERRED = 2,
};
typedef int (*mxfs_scsipr_settle_cas_fn)(void *data, uint64_t token);
int  mxfs_scsipr_settle_absent(struct mxfs_scsipr_ctx *ctx, uint64_t key,
                               mxfs_scsipr_settle_cas_fn cas_fn, void *cas_data,
                               enum mxfs_scsipr_settle *out);
int  mxfs_scsipr_proof_consume(struct mxfs_scsipr_ctx *ctx, uint64_t token);

/*
 * sess454 (0.61.0, D1(2)/(3)): THE HOST-WIDE DEPARTURE MUTEX lives here,
 * because what it serializes is PR state: every local PROUT (register,
 * register-succeed, reserve, preempt, unregister), the RETIRE_PENDING
 * settlements, and a departing mount's late phase.  Re-entrant by owner:
 * a PROUT issued while the caller already holds it nests; one issued
 * without it takes it (and says so, P-PR-DEPARTURE-UNHELD — that is the
 * assertion the ruling asks for, made self-correcting).  Lock order:
 * departure mutex -> probe_lock -> snap_lock -> (disklock ctx->lock).
 */
int  mxfs_scsipr_departure_init(void);
void mxfs_scsipr_departure_exit(void);
void mxfs_scsipr_departure_lock(void);
int  mxfs_scsipr_departure_trylock(void);   /* 1 = acquired (or nested) */
void mxfs_scsipr_departure_unlock(void);
bool mxfs_scsipr_departure_held(void);

/*
 * sess454 (0.61.0, D8): probe-thread stop is BOUNDED.  0 = joined; -ETIMEDOUT
 * = the thread is stuck in a SCSI command and the context is now
 * QUARANTINED (see the ctx fields): the caller must treat the departure as
 * DIRTY (no unregister, slot retained) and must not free anything the
 * thread can reach.  mxfs_scsipr_quarantine_active() refuses a new
 * clustered mount on this host while any quarantined thread has not exited;
 * mxfs_scsipr_quarantine_reap() frees the ones that have.
 */
#define MXFS_SCSIPR_JOIN_MS     5000
int  mxfs_scsipr_probe_stop(struct mxfs_scsipr_ctx *ctx);
bool mxfs_scsipr_quarantine_active(void);
int  mxfs_scsipr_quarantine_reap(void);
int  mxfs_scsipr_probe_start(struct mxfs_scsipr_ctx *ctx);
void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx);

/* This node's registered key (0 if none) */
uint64_t mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx);
/* sess438: install the ledger-selected key before REGISTER (-EBUSY after). */
int mxfs_scsipr_set_key(struct mxfs_scsipr_ctx *ctx, uint64_t key);

/*
 * Install the "is this key held by a live member right now?" guard consulted
 * before any PREEMPT AND ABORT.  `fn` returns 1 when some LIVE record other
 * than the incarnation being fenced carries `key` (and fills live_node /
 * live_slot), 0 when none does, and <0 when it cannot tell — which the fence
 * treats as "cannot tell" and refuses, because preempting a key that may be a
 * live member's is exactly the outcome the guard exists to prevent.
 */
void mxfs_scsipr_set_key_live_guard(struct mxfs_scsipr_ctx *ctx,
                                    int (*fn)(void *data, uint64_t key,
                                              mxfs_node_id_t excl_node,
                                              mxfs_node_id_t *live_node,
                                              int *live_slot),
                                    void *data);

/* Free the context WITHOUT unregistering.  For teardown paths that must
 * defer the PROUT unregister until after the filesystem's final log
 * write: a non-holder that unregisters early bounces its own unmount
 * record off the peer's WE-RO reservation (EBADE log-error shutdown on
 * every clean umount — physical-rig QNAP battery). */
void mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx);

/* Register this node's key (idempotent, uses REGISTER_AND_IGNORE) */
/*
 * sess433: plain REGISTER; -EEXIST (P305-PR-PREDECESSOR-KEY-PRESENT) when
 * this nexus already holds a predecessor incarnation's retained key, unless
 * replace_predecessor (the operator's single_node_exclusive assertion) is
 * set, in which case the key is replaced and P305-...-REPLACED is logged.
 */
int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx, bool replace_predecessor);

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

/* 0.85.1: a joiner preempts the single-holder Write Exclusive (1) gate of a
 * holder the caller proved dead (frozen heartbeat over a full dead window,
 * key attributed by the PR ledger) so its own ledger publish can land.
 * PREEMPT AND ABORT rk=own sark=holder with the all-registrants type, then a
 * readback: 0 = no WE(1) in force any more (the readback state is recorded);
 * -ENOKEY = we are not registered; -EBUSY = WE(1) still held; other negative
 * = the PROUT or the readback failed. */
int mxfs_scsipr_preempt_dead_gate_holder(struct mxfs_scsipr_ctx *ctx,
                                         uint64_t holder_key);

/*
 * ── THE SOLE-SURVIVOR EXCLUSIVE-WRITE GATE (D-0904) ─────────────────────
 *
 * For the victim whose registration the TARGET already removed (its iSCSI
 * session died and the target purges registrations with the session — the
 * QNAP TS-453 Pro does, ~34 s after the session drop, PR generation
 * unchanged; SCST and LIO keep them), so mxfs_scsipr_fence_node() can only
 * ever answer KEY_ABSENT_UNPROVEN.  The CALLER must have established that
 * this node is the only live member (lease membership minus the victim == 1
 * AND no other live heartbeat slot): PREEMPT AND ABORT with sark=0 evicts
 * EVERY other registrant, so on a wider membership it would fence live
 * peers.
 *
 * Observation first (PRECOMMAND, nothing consumed, safe to repeat):
 *   - READ KEYS must be complete; our key must be registered on exactly ONE
 *     nexus (with two nexuses — multipath — sark=0 would remove our own
 *     sibling registration and the holder would be one path, not the node:
 *     refused, kind ERROR rc=-ENOTUNIQ); the victim key must still be
 *     absent (present -> kind NONE: the ordinary key preempt applies);
 *   - READ RESERVATION must show WE-AR (the type this build establishes), or
 *     the gate's own type-1 reservation held by our key with no other
 *     registrant (a previous attempt's PROUT completed but the certificate
 *     did not land: verified again, nothing issued).
 * Then arm_submit (the durable command-submission boundary, exactly as for
 * the key preempt), the PROUT, and the verify: READ KEYS = our key only,
 * READ RESERVATION = Write Exclusive (1) held by our key.  Only that
 * post-state yields MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE; anything else is
 * ERROR at phase MAY_HAVE_SUBMITTED.
 *
 * out->victim_key is the victim's frozen key (the certificate must name the
 * victim even though no command named it); out->resv_type = WE (1);
 * out->pr_generation = the verifying read's generation.
 */
int mxfs_scsipr_gate_sole_survivor(struct mxfs_scsipr_ctx *ctx,
                                   mxfs_node_id_t victim_node,
                                   uint64_t victim_key,
                                   int (*arm_submit)(void *), void *arm_data,
                                   struct mxfs_fence_result *out);

/*
 * Does the gate still hold RIGHT NOW?  The kind-20 counterpart of
 * mxfs_scsipr_exclusion_holds(): a Write Exclusive (1) reservation held by
 * OUR key, our key registered.  Other registrations are irrelevant (they
 * cannot write under type 1).  0 = holds; -EPERM lapsed (out->kind says
 * why: NO_RESERVATION = released or a different type/holder,
 * SELF_PREEMPTED = our key gone (-ESTALE)); other negative = I/O.
 */
int mxfs_scsipr_gate_holds(struct mxfs_scsipr_ctx *ctx,
                           struct mxfs_fence_result *out);

/*
 * Restore the all-registrants reservation after the recovery the gate
 * authorised has PUBLISHED: PREEMPT (0x04) rk=own sark=own type=WE-AR
 * converts the single-holder reservation back to WE-AR atomically (SPC-4
 * 5.9.10.4.3 preempting one's own reservation; measured on the QNAP: no
 * unreserved gap), verified by READ RESERVATION.  Own-key-on-one-nexus is
 * re-checked first for the same sibling-nexus reason as the gate.  A
 * reservation that is already WE-AR clears gate_held without a command; a
 * LUN with NO reservation gets a plain RESERVE type 7.  0 = WE-AR verified
 * in force; negative = still gated (caller retries).
 */
int mxfs_scsipr_gate_restore(struct mxfs_scsipr_ctx *ctx);
bool mxfs_scsipr_gate_is_held(struct mxfs_scsipr_ctx *ctx);

/*
 * ── THE SOLE-INITIATOR ADMISSION GATE FOR A LOGICAL UNIT RESET ──────────
 *
 * A LOGICAL UNIT RESET reaches work whose originating iSCSI session is gone,
 * which is the whole reason MXFS wants it: a target that purges a
 * registration together with the session has destroyed the evidence PREEMPT
 * AND ABORT needs before the first fence attempt is made.  But its scope is
 * the LOGICAL UNIT, so it terminates the tasks of EVERY I_T nexus attached to
 * that unit, not only the dead node's — and an initiator whose command is
 * terminated at the target sees no completion for it until its own error
 * handler recovers the command.  That cost is measured, on this rig, in the
 * queue's own bystander record: ten resets six seconds apart stranded exactly
 * one of a peer's O_DIRECT writes, and libiscsi's timeout ladder rescued it
 * 538 s later with the write retried and completed — an in-flight stall, not a
 * permanent hang and not a lost byte.  So this gate is not standing between
 * the cluster and a wedge; it is the rule that says WHEN AN LU-SCOPE
 * OPERATION IS THE RIGHT TOOL AT ALL, and it refuses in both directions:
 *
 *   - Another initiator is REGISTERED.  Then its work is live work, and the
 *     precisely-scoped PREEMPT AND ABORT can retire one nexus's tasks without
 *     touching anyone else's.  An LU reset here would strand a legitimate
 *     member's I/O for nothing this gate's caller needs.
 *   - The VICTIM is registered.  Same answer, and stronger: the ordinary key
 *     preempt is the fence for a registered victim, and it produces a
 *     certificate that names the victim.
 *
 * What it proves, and it is TARGET-ENFORCED rather than asserted — no part of
 * it rests on a deployment declaring how the LUN is cabled:
 *
 *   1. A reservation is in force whose type refuses media-access WRITES from
 *      non-registrants (READ RESERVATION; both Write Exclusive forms qualify,
 *      mxfs_pr_type_excludes_nonregistrants).
 *   2. The target's registration table, read COMPLETE (never truncated —
 *      truncation manufactures absence), holds exactly ONE descriptor, and it
 *      carries our key.  One descriptor per I_T nexus, so this also excludes a
 *      multipath sibling whose in-flight work an LU reset would strand.
 *   3. That descriptor is OURS and not merely a re-use of our key value by
 *      some other nexus: a matching-scope/type RESERVE completes GOOD only
 *      for an I_T nexus registered with the key in the command, and returns
 *      RESERVATION CONFLICT otherwise.  This is issued only AFTER step 1 saw
 *      a matching reservation already in force, so it can never create one —
 *      a gate that silently re-armed the cluster's exclusion would hide the
 *      interval in which non-registrants could write.
 *   4. The census is BRACKETED: the same complete view, with the same PR
 *      generation, before and after that RESERVE.  A registration that
 *      appeared under the gate bumps the generation and refuses the admission.
 *
 * WHAT IT DOES NOT PROVE, stated because the gate must not be read as more:
 * a non-registrant may still READ under a Write Exclusive reservation, and no
 * operation available to an initiator enumerates the nexuses that are merely
 * logged in.  A non-registrant reader's in-flight READ is terminated by the
 * reset and recovered by its own error handler, exactly as the bystander
 * record measured.
 *
 * Nothing here retires anything and nothing here issues a reset: this decides
 * admission only, and the reset is a separate step the caller takes only on
 * `admitted`.
 */
enum mxfs_lu_reset_admission_verdict {
    MXFS_LURESET_ADMIT_OK                  = 0,
    MXFS_LURESET_REFUSE_NOT_REGISTERED     = 1, /* this mount holds no key */
    MXFS_LURESET_REFUSE_NO_RESERVATION     = 2, /* nothing excludes anybody */
    MXFS_LURESET_REFUSE_RESV_TYPE          = 3, /* held, but not an excluding
                                                 * type */
    MXFS_LURESET_REFUSE_VIEW_TRUNCATED     = 4, /* the table is bigger than we
                                                 * can read: absence unproven */
    MXFS_LURESET_REFUSE_SELF_GONE          = 5, /* our key is not registered —
                                                 * WE are the excluded node */
    MXFS_LURESET_REFUSE_MULTI_NEXUS        = 6, /* our key on >1 nexus */
    MXFS_LURESET_REFUSE_OTHER_REGISTRANT   = 7, /* someone else is registered */
    MXFS_LURESET_REFUSE_VICTIM_REGISTERED  = 8, /* preempt-and-abort applies */
    MXFS_LURESET_REFUSE_NOT_A_REGISTRANT   = 9, /* RESERVE conflicted: the one
                                                 * descriptor is not ours */
    MXFS_LURESET_REFUSE_RACED              = 10,/* the census moved */
    MXFS_LURESET_REFUSE_IO                 = 11,/* the target could not be
                                                 * asked — never "clear" */
};

struct mxfs_lu_reset_admission {
    bool     admitted;
    uint8_t  refusal;          /* enum mxfs_lu_reset_admission_verdict */
    int      rc;               /* the errno that produced a refusal, or 0 */
    uint64_t victim_key;       /* echoed, so the log names what was asked */
    uint32_t pr_generation;    /* of the bracketing views (equal, or refused) */
    uint32_t resv_type;        /* MXFS_PAL_PR_TYPE_* observed in force */
    int      own_n;            /* registrations carrying OUR key */
    int      other_n;          /* registrations carrying anything else */
    bool     victim_present;   /* the victim's key is registered */
};

const char *mxfs_lu_reset_refusal_name(int r);

/*
 * Decide admission.  Returns 0 whenever the question was ANSWERED — including
 * every refusal, which is a decision and not a failure — and negative only
 * when the caller could not be given an answer at all (bad arguments, no
 * memory).  Read out->admitted, never the return value, for the verdict.
 */
int mxfs_scsipr_lu_reset_admit(struct mxfs_scsipr_ctx *ctx,
                               mxfs_node_id_t victim_node,
                               uint64_t victim_key,
                               struct mxfs_lu_reset_admission *out);

/*
 * ── THE POST-RESET CONVERGENCE BARRIER, STORAGE HALF ────────────────────
 *
 * An LU-scope reset terminates the tasks of every I_T nexus attached to the
 * unit — INCLUDING THE ISSUER'S OWN.  So the node that issued it comes out the
 * other side with its own in-flight commands stranded, its own error handler
 * about to recover them, and no right to assume anything about the state it
 * left behind.  This is what it must establish before it writes one byte of
 * replay or one byte of recovery commit.
 *
 * WHAT THIS IS NOT, both rejected by the design ruling in
 * docs/rulings/lu-reset-needs-a-post-reset-convergence-barrier-not-a-pre-reset-drain.md:
 *
 *   - NOT a pre-reset drain.  Waiting for in-flight I/O to finish before
 *     issuing the reset is waiting for exactly the commands the reset exists to
 *     terminate; and the gate must never be able to block the reset itself, an
 *     abort, an EH retry or transport recovery.
 *   - NOT a completion filter.  A pre-reset command may have COMPLETED, after
 *     an error-handler retry, on the far side of the reset.  Discarding that
 *     completion because of when it was submitted does not produce a safe
 *     filesystem retry; it produces an I/O error and a shutdown.  Submission
 *     time does not say whether the command executed.
 *
 * WHAT IT ESTABLISHES, in order, each one target-enforced:
 *
 *   1. THE COMMAND PATH CAME BACK, and it is proved by a CONTROLLED PROBE
 *      issued as the first command after the reset — never the heartbeat
 *      renewal, never a replay write, never the recovery commit.  A reset
 *      leaves a UNIT ATTENTION pending on every nexus, and the first command
 *      to arrive is answered with it INSTEAD of being executed; whatever
 *      command that is, its result describes the reset and not itself.  Making
 *      it a PR IN means the condition is consumed by something whose only job
 *      is to be consumed.  The probe is bounded, and a probe that does not
 *      answer inside its bound is a REFUSAL — the path has not come back
 *      promptly, which is a decision, not a reason to keep waiting.
 *
 *   2. THE WHOLE ADMISSION ASSERTION SET STILL HOLDS.  Not a cheaper re-check:
 *      mxfs_scsipr_lu_reset_admit() itself is re-run, so the reservation type,
 *      the complete census, the own-nexus proof and the bracket are all
 *      re-established against the target after the reset rather than carried
 *      over from before it.
 *
 *   3. THE PR GENERATION DID NOT MOVE ACROSS THE RESET.  This is the check
 *      that catches the hazard peculiar to THIS target: a reset can be followed
 *      by error-handler transport recovery, and a target that purges
 *      registrations together with the iSCSI session purges OURS when the
 *      session is re-established — after which a health worker's re-REGISTER
 *      would restore an admission set that looks identical while describing a
 *      registration that did not exist continuously.  A LOGICAL UNIT RESET
 *      does not bump the PR generation and a PERSISTENT RESERVE OUT does, so
 *      an unchanged generation across the reset says no registration was
 *      destroyed and recreated under it.  A moved generation fails closed even
 *      when the re-admission passed.
 *
 * WHAT IT DELIBERATELY LEAVES TO THE CALLER.  Storage authority is not a
 * property of the LUN and is not decided here.  The reset can strand the
 * ISSUING node's own heartbeat write for far longer than its authority lease,
 * and a node that keeps replaying after its lease has lapsed is a second
 * authority.  The caller must, after this returns converged and before any
 * replay or recovery-commit write, renew authority through its own synchronous
 * path and STOP if the lease lapsed — leaving the durable reset intent
 * resumable by a later authority holder rather than pretending it survived.
 * That renewal is also what proves the issuer's own coordination I/O has
 * CONVERGED: the heartbeat path is single-outstanding, so a fresh beat cannot
 * complete until the pre-reset one has been resolved by the error handler.
 *
 * NOTHING HERE IS A CLAIM ABOUT WRITABLE MEDIA.  A PR IN that completes proves
 * the command path, not that a write would be accepted.
 */
enum mxfs_lu_reset_convergence_verdict {
    MXFS_LURESET_CONVERGED                 = 0,
    MXFS_LURESET_CONV_PROBE_TIMEOUT        = 1, /* the path did not answer
                                                 * inside the bound */
    MXFS_LURESET_CONV_PROBE_FAILED         = 2, /* it answered with an error */
    MXFS_LURESET_CONV_ADMISSION_LOST       = 3, /* the assertion set no longer
                                                 * holds; read `readmit` */
    MXFS_LURESET_CONV_GENERATION_MOVED     = 4, /* a PROUT ran across the reset:
                                                 * the registration is not the
                                                 * one that was admitted */
};

struct mxfs_lu_reset_convergence {
    bool     converged;
    uint8_t  refusal;          /* enum mxfs_lu_reset_convergence_verdict */
    int      rc;               /* the errno that produced a refusal, or 0 */
    uint32_t probe_ms;         /* wall of the controlled probe alone */
    uint32_t total_ms;         /* wall of the whole barrier */
    int      probe_tries;      /* how many probes were needed */
    uint32_t gen_before;       /* the generation the admission was made under */
    uint32_t gen_after;        /* what the target reports now */
    struct mxfs_lu_reset_admission readmit;   /* the full re-run, verbatim */
};

const char *mxfs_lu_reset_convergence_name(int r);

/*
 * Run the barrier.  `gen_before` is the pr_generation the PRE-reset admission
 * recorded; passing a generation the caller did not actually observe defeats
 * check 3, so it is an argument rather than cached state.  Returns 0 whenever
 * the question was ANSWERED — every refusal is a decision — and negative only
 * when no answer could be produced at all.  Read out->converged, never the
 * return value.
 */
int mxfs_scsipr_lu_reset_converge(struct mxfs_scsipr_ctx *ctx,
                                  mxfs_node_id_t victim_node,
                                  uint64_t victim_key,
                                  uint32_t gen_before,
                                  struct mxfs_lu_reset_convergence *out);

/*
 * ── IS THIS KERNEL ONE THE LU-RESET WITNESS WAS AUDITED ON? ──────────────
 *
 * `ioctl(SG_SCSI_RESET, DEVICE|NO_ESCALATE)` returning 0 is a TARGET
 * task-management response, but nothing on the wire ties that response to
 * this request: iscsi_tmf_rsp() does not validate the Initiator Task Tag.
 * The per-operation association comes from an enforced ONE-TMF-PER-SESSION
 * serialization — every entry point takes eh_mutex then frwd_lock and
 * refuses unless tmf_state == TMF_INITIAL; a timed-out TMF fails the
 * connection rather than returning to TMF_INITIAL, so the
 * stale-late-response window never opens on a connection that later reports
 * success; and a reconnect across the wait is reported as -ENOTCONN rather
 * than swallowed.
 *
 * THAT IS WHY THIS FUNCTION EXISTS.  A tag keeps working when concurrency is
 * added.  A serialization invariant silently weakens into an inference if a
 * later version ever allows two in flight — WITH NO CHANGE TO THE VALUE THE
 * CALLER READS.  So a durable certificate minted from that value must name
 * the releases the invariant was read on and refuse every other one, rather
 * than assume the behaviour travels.
 *
 * Refusal is the default, including for a release this build has never heard
 * of.  On false, *why names what was rejected.
 */
bool mxfs_fence_lu_reset_kernel_audited(const char *krel, const char **why);

/*
 * ── THE WITNESSED-LU-RESET FENCE: THE ONE PRODUCER OF KIND 24 ────────────
 *
 * The route for a victim whose registration the target has already purged,
 * which is where a PREEMPT AND ABORT has nothing to name and every attempt
 * classifies KEY_ABSENT_UNPROVEN however often it is retried.  It runs the
 * whole construction contract written at
 * MXFS_FENCE_KIND_LU_RESET_WITNESSED_V1, in order, and mints a certifiable
 * result ONLY when every clause held:
 *
 *   admit → arm the durable intent → witness one LU reset → verify the
 *   report was taken on the audited kernel → post-reset barrier (command
 *   path, whole re-admission, unmoved generation, and the issuer's own
 *   storage authority) → certify.
 *
 * EVERY REFUSAL AFTER THE RESET WAS ISSUED IS A REFUSAL, NEVER A RETRY.  The
 * reset happened; what did not happen is the proof that this node may act on
 * it.  out->result.kind is then a non-proving kind, no replay byte and no
 * recovery-commit byte may follow, and the durable intent the caller armed is
 * left for a later authority holder to resume.  A caller that re-drives this
 * on a refusal would be issuing a second LU-scope reset on a unit whose state
 * it has not established.
 *
 * THE KERNEL PIN IS CHECKED BEFORE THE COMMAND BOUNDARY as well as after.
 * Before, because issuing a reset whose witness this build could not use
 * destroys a bystander's in-flight I/O for nothing; after, because the report
 * states the release the helper actually ran on and it must be the same one.
 *
 * `authority` is the caller's barrier — the storage layer cannot ask whether
 * this node still holds cluster authority, and a node that replays after its
 * lease lapsed is a second authority over the slice.  It returns 0 when
 * replay may proceed, -EPERM when the caller must STOP and leave the intent
 * resumable, and another negative when it could not be asked; it is handed
 * the pre-reset generation and the timestamp taken immediately before the
 * reset, and it fills `conv` with the storage half it ran on the way.  A
 * NULL authority is a refusal, not a default-allow: there is no such thing as
 * a certificate minted with the authority half unasked.
 */
enum mxfs_lu_reset_fence_verdict {
    MXFS_LURESET_FENCE_CERTIFIED           = 0,
    MXFS_LURESET_FENCE_BAD_ARGS            = 1, /* incl. a NULL authority */
    MXFS_LURESET_FENCE_NO_LUN_ID           = 2, /* no VPD designator: the
                                                 * wrong unit could be reset */
    MXFS_LURESET_FENCE_KERNEL_UNAUDITED    = 3, /* refused BEFORE issuing */
    MXFS_LURESET_FENCE_NOT_ADMITTED        = 4, /* read out->admit */
    MXFS_LURESET_FENCE_ARM_FAILED          = 5, /* the durable intent could
                                                 * not be made durable, so
                                                 * nothing was issued */
    MXFS_LURESET_FENCE_NOT_WITNESSED       = 6, /* REFUSED/NOT_RUN: nothing
                                                 * crossed the boundary */
    MXFS_LURESET_FENCE_INDETERMINATE       = 7, /* it may have been issued and
                                                 * the outcome is unknown */
    MXFS_LURESET_FENCE_KERNEL_MOVED        = 8, /* the report's release is not
                                                 * the one that was pinned */
    MXFS_LURESET_FENCE_BARRIER_REFUSED     = 9, /* reset done, authority or
                                                 * convergence did not hold */
    MXFS_LURESET_FENCE_BARRIER_UNASKABLE   = 10,/* reset done, the barrier
                                                 * could not be evaluated */
};

const char *mxfs_lu_reset_fence_verdict_name(int v);

typedef int (*mxfs_lu_reset_authority_fn)(void *data,
                                          uint32_t gen_before,
                                          uint64_t reset_issued_ms,
                                          struct mxfs_lu_reset_convergence *conv);

struct mxfs_lu_reset_fence_req {
    mxfs_node_id_t victim_node;
    uint64_t       victim_key;
    uint64_t       epoch;        /* the fencing epoch, echoed into the record */
    const char    *lun_id;       /* VPD page 0x83 designator of the unit, or
                                  * NULL to read it from the unit now.  An
                                  * unidentified LUN is a refusal either
                                  * way — never a reset issued blind */
    int          (*arm_submit)(void *);  /* make the intent durable, or NULL */
    void          *arm_data;
    mxfs_lu_reset_authority_fn authority;
    void          *authority_data;
};

struct mxfs_lu_reset_fence {
    struct mxfs_fence_result         result;  /* what the caller certifies */
    struct mxfs_lu_reset_admission   admit;   /* the pre-reset gate, verbatim */
    struct mxfs_lu_reset_convergence conv;    /* the storage half, verbatim */
    uint8_t  verdict;          /* enum mxfs_lu_reset_fence_verdict */
    uint8_t  pal_verdict;      /* enum mxfs_pal_lu_reset_verdict */
    bool     admit_run;        /* the admission gate was actually asked.  A
                                * refusal ahead of it leaves `admit` zeroed,
                                * and a zeroed admission reads "admitted" —
                                * so a skipped gate must not be mistakable
                                * for one that considered and agreed */
    bool     reset_issued;     /* the command boundary was crossed */
    bool     certified;        /* kind 24 with all three retire fields set */
    uint32_t reset_ms;         /* the witnessed reset's own wall */
    uint32_t total_ms;         /* admit through certify */
    uint64_t reset_issued_ms;  /* the anchor handed to the barrier */
    char     krel[68];         /* the release the report was taken on */
    char     why[256];         /* leads with the finding: it can be truncated */
};

/*
 * Returns 0 whenever the question was ANSWERED — every refusal is a decision,
 * not a failure — and negative only when no answer could be produced at all.
 * Read out->certified, never the return value.
 */
int mxfs_scsipr_fence_by_lu_reset(struct mxfs_scsipr_ctx *ctx,
                                  const struct mxfs_lu_reset_fence_req *req,
                                  struct mxfs_lu_reset_fence *out);

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
                           mxfs_node_id_t victim_node, uint64_t victim_key,
                           int live_members,
                           int (*arm_submit)(void *), void *arm_data,
                           struct mxfs_fence_result *out);

/*
 * sess93 — DOES THE EXCLUSION STILL HOLD?  A DETECTOR, NOT A FENCE.
 *
 * mxfs_scsipr_fence_node() proves exclusion at an INSTANT.  MEASURED on the rig
 * (tests/pr_reregister_probe.sh): a PREEMPT-AND-ABORTed node re-registered with
 * a fresh key and wrote to the shared LUN seconds later.  So a certificate is
 * evidence of a completed EVICTION EVENT, not evidence that the host remains
 * fenced (design-consult ruling, sess93 follow-up).
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
