/*
 * MXFS — Multinode XFS
 * Portable SCSI-3 Persistent Reservations for I/O fencing
 *
 * Ported from kernel/mxfs_scsipr.c — all pr_ops calls replaced
 * with PAL SCSI PR functions. The PAL layer handles platform-specific
 * details (SG_IO on Linux userspace, pr_ops in kernel, IOKit on macOS).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "scsipr.h"

struct mxfs_scsipr_ctx *mxfs_scsipr_create(mxfs_bdev_t *dev,
                                            const char *dev_name,
                                            mxfs_node_id_t node_id)
{
    struct mxfs_scsipr_ctx *ctx;

    if (!dev)
        return NULL;

    ctx = mxfs_pal_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->dev = dev;
    ctx->local_key = (uint64_t)node_id;
    ctx->reserved = false;

    if (dev_name)
        snprintf(ctx->dev_name, sizeof(ctx->dev_name), "%s", dev_name);
    else
        snprintf(ctx->dev_name, sizeof(ctx->dev_name), "(unknown)");

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: initialized for '%s' key=0x%llx",
                 ctx->dev_name, (unsigned long long)ctx->local_key);

    return ctx;
}

void mxfs_scsipr_destroy(struct mxfs_scsipr_ctx *ctx)
{
    if (!ctx)
        return;

    /* v0.11.80 (D4): safety-net unregister only if the key is still
     * believed registered — the normal teardown paths unregister
     * explicitly first, and re-issuing PROUT for an absent key is a
     * spec-level RESERVATION CONFLICT (observed as bare conflicts on
     * the QNAP battery). */
    if (ctx->local_key && ctx->registered) {
        int ret = mxfs_scsipr_unregister(ctx);
        if (ret)
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: unregister on shutdown failed: %d", ret);
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: shutdown for '%s'", ctx->dev_name);

    mxfs_pal_free(ctx);
}

uint64_t mxfs_scsipr_key(struct mxfs_scsipr_ctx *ctx)
{
    return ctx ? ctx->local_key : 0;
}

void mxfs_scsipr_abandon(struct mxfs_scsipr_ctx *ctx)
{
    if (!ctx)
        return;

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: abandoned for '%s' (deferred unregister)",
                 ctx->dev_name);

    mxfs_pal_free(ctx);
}

int mxfs_scsipr_register(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_register(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping register",
                     ctx->dev_name);
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "mxfs: SCSI persistent reservation register failed "
                     "on '%s': %d (hardware fencing unavailable)",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->registered = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: registered key 0x%llx on '%s'",
                 (unsigned long long)ctx->local_key, ctx->dev_name);

    return 0;
}

int mxfs_scsipr_reserve(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
                                   MXFS_SCSIPR_RESV_TYPE);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping reserve",
                     ctx->dev_name);
        return 0;
    }

    if (ret == -EBUSY) {
        /*
         * RESERVATION CONFLICT.
         *
         * sess381: this used to return 0 with "another node holds the
         * reservation; with type 5 we only need to be registered to do I/O".
         * That is a statement about I/O permission and it silently discarded
         * the one signal that says the reservation in force is the WRONG TYPE.
         * Under an all-registrants type a conflict from a registered requester
         * is abnormal by SPC — every registrant is a holder, and a
         * matching-scope/type RESERVE from a holder completes GOOD (MEASURED
         * rc=0 from a second nexus).  So read back and classify instead of
         * assuming.
         */
        struct mxfs_pal_pr_reservation resv;
        int rr = mxfs_scsipr_read_reservation(ctx, &resv);

        if (rr == 0 && resv.held && resv.type == MXFS_SCSIPR_RESV_TYPE) {
            /* The right reservation is in force and we are a registrant, so
             * we are a holder of it.  Benign, but not expected — record it. */
            ctx->resv_type_seen = resv.type;
            ctx->reserved = true;
            mxfs_pal_log(MXFS_LOG_INFO,
                         "scsipr: P304-RESV-CONFLICT-BENIGN '%s' RESERVE "
                         "returned CONFLICT but a %s reservation IS in force "
                         "(gen=%u); we are registered, hence a holder",
                         ctx->dev_name, mxfs_pr_type_name(resv.type),
                         resv.generation);
            return 0;
        }
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P304-RESV-CONFLICT '%s' RESERVE(%s) was REFUSED "
                     "and the reservation actually in force is held=%d "
                     "type=0x%x (%s) [readback rc=%d].  A registered requester "
                     "cannot conflict with a matching all-registrants "
                     "reservation, so this LU carries an incompatible "
                     "reservation (most likely a stale single-holder WE-RO "
                     "left by an older protocol generation, or a foreign "
                     "initiator).  Fencing on this LU is NOT what this build "
                     "expects; refusing to pretend it is",
                     ctx->dev_name, mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE),
                     (rr == 0) ? (int)resv.held : -1,
                     (rr == 0) ? resv.type : 0,
                     (rr == 0) ? mxfs_pr_type_name(resv.type) : "unreadable",
                     rr);
        return -EBUSY;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: reserve failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = true;
    ctx->resv_type_seen = MXFS_SCSIPR_RESV_TYPE;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: %s reservation acquired on '%s'",
                 mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE), ctx->dev_name);

    return 0;
}

/*
 * OBSERVE BEFORE ACTING (sess381).
 *
 * The admission gate used to run immediately after mxfs_scsipr_reserve() and
 * then assert "a reservation is held" — validating a reservation it had just
 * created one line earlier.  It was structurally incapable of reporting the
 * disarmed state, and it proved it: a node mounting onto a LUN with NO
 * reservation at all logged "P303-FENCECAP-OK ... WE-RO held" while two
 * independent observers read "none held" immediately before and after.
 *
 * This call is what a mount makes FIRST, before REGISTER and RESERVE, purely
 * to record what was already there.  It changes nothing.
 */
int mxfs_scsipr_observe_reservation(struct mxfs_scsipr_ctx *ctx,
                                    struct mxfs_pal_pr_reservation *out)
{
    struct mxfs_pal_pr_reservation resv;
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_scsipr_read_reservation(ctx, &resv);
    if (ret) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P304-PREOBSERVE '%s' READ RESERVATION rc=%d — "
                     "the pre-existing reservation state is UNKNOWN",
                     ctx->dev_name, ret);
        if (out)
            memset(out, 0, sizeof(*out));
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "scsipr: P304-PREOBSERVE '%s' held=%d type=0x%x (%s) "
                 "holder_key=0x%llx gen=%u — state observed BEFORE this mount "
                 "registered or reserved anything",
                 ctx->dev_name, (int)resv.held, resv.type,
                 mxfs_pr_type_name(resv.type),
                 (unsigned long long)resv.key, resv.generation);

    if (resv.held)
        ctx->resv_type_seen = resv.type;
    if (out)
        *out = resv;
    return 0;
}

int mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx,
                                 struct mxfs_pal_pr_reservation *out)
{
    if (!ctx || !ctx->dev || !out)
        return -EINVAL;
    return mxfs_pal_scsi_pr_read_reservation(ctx->dev, out);
}

static int mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx,
                                  uint64_t want_key, bool *out_present,
                                  bool *out_self, int *out_count,
                                  uint32_t *out_gen);

int mxfs_scsipr_check_reservation_health(struct mxfs_scsipr_ctx *ctx,
                                         bool repair,
                                         uint32_t *out_gen, int *out_count)
{
    struct mxfs_pal_pr_reservation resv;
    bool self_present = false, dummy = false;
    uint32_t gen = 0;
    int count = 0, ret;

    if (!ctx || !ctx->dev)
        return MXFS_RESV_HEALTH_UNKNOWN;
    if (!ctx->local_key || !ctx->registered)
        return MXFS_RESV_HEALTH_UNKNOWN;

    ret = mxfs_scsipr_read_reservation(ctx, &resv);
    if (ret) {
        /* Could not answer the question.  That is NOT "healthy" — a caller
         * that treats an I/O error as OK is exactly the blindness this
         * function exists to remove. */
        if (out_gen)
            *out_gen = 0;
        if (out_count)
            *out_count = 0;
        return MXFS_RESV_HEALTH_UNKNOWN;
    }
    gen = resv.generation;

    /* The registrant view is part of the invariant: a reservation that is held
     * while OUR key is gone means we are the excluded one, not that all is
     * well. */
    if (mxfs_scsipr_probe_keys(ctx, ctx->local_key, &self_present, &dummy,
                               &count, &gen) != 0)
        self_present = true;    /* unknown — do not manufacture a self-fence */

    if (out_gen)
        *out_gen = gen;
    if (out_count)
        *out_count = count;

    if (!self_present)
        return MXFS_RESV_HEALTH_SELF_GONE;

    if (resv.held && resv.type == MXFS_SCSIPR_RESV_TYPE) {
        ctx->resv_type_seen = resv.type;
        return MXFS_RESV_HEALTH_OK;
    }
    if (resv.held)
        return MXFS_RESV_HEALTH_WRONG_TYPE;

    if (repair) {
        int rr = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key,
                                          MXFS_SCSIPR_RESV_TYPE);

        if (rr == 0 || rr == -EBUSY) {
            /* Re-read rather than trusting the status: -EBUSY here means
             * somebody else re-established it in the same window, which is a
             * fine outcome but only if it is the RIGHT type. */
            if (mxfs_scsipr_read_reservation(ctx, &resv) == 0 && resv.held &&
                resv.type == MXFS_SCSIPR_RESV_TYPE) {
                ctx->reserved = true;
                ctx->resv_type_seen = resv.type;
                if (out_gen)
                    *out_gen = resv.generation;
                /* NOT "OK" — see the enum.  The caller must be able to tell a
                 * cluster that was always armed from one that had a hole. */
                return MXFS_RESV_HEALTH_REPAIRED;
            }
        }
    }
    return MXFS_RESV_HEALTH_ABSENT;
}

const char *mxfs_resv_health_name(int h)
{
    switch (h) {
    case MXFS_RESV_HEALTH_OK:         return "OK";
    case MXFS_RESV_HEALTH_ABSENT:     return "ABSENT";
    case MXFS_RESV_HEALTH_WRONG_TYPE: return "WRONG_TYPE";
    case MXFS_RESV_HEALTH_SELF_GONE:  return "SELF_GONE";
    case MXFS_RESV_HEALTH_REPAIRED:   return "REPAIRED";
    default:                          return "UNKNOWN";
    }
}

const char *mxfs_fence_kind_name(enum mxfs_fence_kind k)
{
    switch (k) {
    case MXFS_FENCE_KIND_NONE:                return "NONE";
    case MXFS_FENCE_KIND_ERROR:               return "ERROR";
    case MXFS_FENCE_KIND_UNSUPPORTED:         return "UNSUPPORTED";
    case MXFS_FENCE_KIND_ADVISORY_TOPOLOGY:   return "ADVISORY_TOPOLOGY";
    case MXFS_FENCE_KIND_NOT_REGISTERED:      return "NOT_REGISTERED";
    case MXFS_FENCE_KIND_SELF_PREEMPTED:      return "SELF_PREEMPTED";
    case MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN: return "KEY_ABSENT_UNPROVEN";
    case MXFS_FENCE_KIND_RACE_LOST:           return "RACE_LOST";
    case MXFS_FENCE_KIND_NO_RESERVATION:      return "NO_RESERVATION";
    case MXFS_FENCE_KIND_VIEW_TRUNCATED:      return "VIEW_TRUNCATED";
    case MXFS_FENCE_KIND_PREEMPT_ABORT_DONE:  return "PREEMPT_ABORT_DONE";
    case MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE: return "SINGLE_NODE_EXCLUSIVE";
    }
    return "?";
}

int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key,
                        bool abort)
{
    uint32_t type;
    int ret;

    if (!ctx || !ctx->dev || victim_key == 0)
        return -EINVAL;

    /*
     * sess381 RULE-5 ruling: NEVER issue a PREEMPT whose SARK is our own key.
     * SPC protects the issuing nexus's own registration from its own PREEMPT
     * while removing OTHER registrations carrying the same key — so it is not
     * a self-fence, and with MXFS's one-key-across-two-nexuses scheme it
     * silently kills our sibling path instead.  A victim key equal to ours is
     * an identity collision (D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377), not
     * a fence.
     */
    if (victim_key == ctx->local_key) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P304-PREEMPT-SELFKEY '%s' refusing PREEMPT%s "
                     "with SARK == our own key 0x%llx — this cannot fence "
                     "anyone (our own registration is protected from it) and "
                     "would remove our sibling nexus.  Node identity collision",
                     ctx->dev_name, abort ? " AND ABORT" : "",
                     (unsigned long long)victim_key);
        return -EINVAL;
    }

    /*
     * The PROUT carries the type of the reservation ACTUALLY IN FORCE, not a
     * hardcoded one — a type mismatch is a scope/type error at the target
     * (sess381).  Fall back to the type this build establishes when nothing
     * has been observed yet.
     */
    type = ctx->resv_type_seen ? ctx->resv_type_seen : MXFS_SCSIPR_RESV_TYPE;

    ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, victim_key,
                                   abort, type);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR preempt support",
                     ctx->dev_name);
        return ret;
    }

    if (ret == -EBUSY) {
        /* RESERVATION CONFLICT: the SARK was not registered, so this
         * command did nothing at all.  Not an error, not a fence. */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: preempt%s of key 0x%llx on '%s': RESERVATION "
                     "CONFLICT — key not registered; no registration removed "
                     "and no task set aborted by us",
                     abort ? "-abort" : "",
                     (unsigned long long)victim_key, ctx->dev_name);
        return ret;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: preempt%s of key 0x%llx failed on '%s': %d",
                     abort ? "-abort" : "",
                     (unsigned long long)victim_key, ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: preempted%s key 0x%llx on '%s'",
                 abort ? "-and-aborted" : "",
                 (unsigned long long)victim_key, ctx->dev_name);

    return 0;
}

/*
 * Snapshot the LUN's registration table and answer the only two questions
 * every classifier in this file asks of it: is the victim registered, and are
 * we?  Both are questions about ABSENCE, which is precisely what a truncated
 * view manufactures — so a partial table is reported as -EOVERFLOW rather
 * than answered.  Callers must translate that into "unknown", never into
 * "absent".  See MXFS_PR_MAX_KEYS in scsipr.h for why the old
 * MXFS_MAX_NODES-sized buffers were too small on a multipath rig.
 *
 * Pass victim_key = 0 when only own-registration matters; MXFS never
 * registers key 0, so it can never match.
 */
static int mxfs_scsipr_probe_keys(struct mxfs_scsipr_ctx *ctx,
                                  uint64_t victim_key,
                                  bool *victim_present, bool *own_present,
                                  int *count, uint32_t *generation)
{
    uint64_t *keys;
    int total = 0, n = 0, i, ret;

    *victim_present = false;
    *own_present = false;
    *count = 0;

    /* MXFS_PR_MAX_KEYS u64s is 4KB — far past what may sit on a kernel
     * stack, and this also runs on the heartbeat thread. */
    keys = mxfs_pal_alloc(sizeof(*keys) * MXFS_PR_MAX_KEYS);
    if (!keys)
        return -ENOMEM;

    ret = mxfs_scsipr_read_keys(ctx, keys, MXFS_PR_MAX_KEYS, &n, generation,
                                &total);
    if (ret) {
        mxfs_pal_free(keys);
        return ret;
    }

    if (total > n) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-VIEW-TRUNC '%s' target holds %d "
                     "registration descriptor(s), we could read %d (cap %d) — "
                     "key absence is unknowable from a partial table; "
                     "refusing to classify",
                     ctx->dev_name, total, n, MXFS_PR_MAX_KEYS);
        mxfs_pal_free(keys);
        return -EOVERFLOW;
    }

    for (i = 0; i < n; i++) {
        if (victim_key && keys[i] == victim_key)
            *victim_present = true;
        if (keys[i] == ctx->local_key)
            *own_present = true;
    }
    *count = n;

    mxfs_pal_free(keys);
    return 0;
}

int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
                           mxfs_node_id_t victim_node, int live_members,
                           int (*arm_submit)(void *), void *arm_data,
                           struct mxfs_fence_result *out)
{
    uint64_t victim_key = (uint64_t)victim_node;
    struct mxfs_pal_pr_reservation resv;
    uint32_t gen = 0;
    int count = 0, ret;
    bool victim_present = false, own_present = false;

    if (!out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    out->kind = MXFS_FENCE_KIND_NONE;
    out->victim_key = victim_key;
    /*
     * sess381: PRECOMMAND until the exact line that submits.  Everything from
     * here to the arm_submit() call below is pure observation — READ KEYS,
     * READ RESERVATION, classification — so every return in between is
     * "nothing was submitted, nothing was consumed, this is safe to repeat".
     * That is the property D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381
     * exists because nobody recorded.
     */
    out->phase = MXFS_FENCE_PHASE_PRECOMMAND;

    if (!ctx || !ctx->dev || !victim_key)
        return -EINVAL;

    /* SPC hygiene: READ KEYS before PREEMPT.  Preempting a key that is
     * not registered is a RESERVATION CONFLICT by spec; classify first. */
    ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
                                 &own_present, &count, &gen);
    if (ret == -EOPNOTSUPP) {
        /* No PR support: we cannot exclude the victim from the LUN at
         * all.  Naming it is the whole point — the caller decides, and
         * it must not decide "fenced". */
        out->kind = MXFS_FENCE_KIND_UNSUPPORTED;
        return 0;
    }
    if (ret == -EOVERFLOW) {
        /* More descriptors than we can read.  We cannot tell whether the
         * victim is registered, and — worse — cannot tell whether OUR key
         * is still there, so neither preempting nor self-fencing is
         * defensible.  Refuse, loudly and durably. */
        out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
        out->rc = ret;
        return 0;
    }
    if (ret) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-FENCE read_keys failed on '%s': %d "
                     "(cannot classify; skipping preempt)",
                     ctx->dev_name, ret);
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }
    out->pr_generation = gen;

    /* Topology sanity: per-node PR needs one registration per live
     * member.  Fewer keys than live members means the rig cannot hold
     * per-node registrations (shared I_T nexus: each node's REGISTER
     * overwrites the previous one's — measured on the tcm_loop VM rig,
     * where ALL VMs funnel through one host block device) or the target
     * purged registrations wholesale.  In that state key-bookkeeping
     * proves nothing about fencing: no preempt (removing the single
     * shared registration would fence EVERYONE incl. us), no self-fence
     * (our key being "missing" is expected, not a preemption).  PR is
     * ADVISORY here — D1 (EBADE on write = fencing event) plus
     * lease/disklock exclusion carry the fencing duty. */
    if (count < live_members) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-ADVISORY '%s' has %d key(s) for %d live "
                     "member(s) — per-node PR not usable on this topology; "
                     "skipping preempt/self-fence (D1+lease fencing apply)",
                     ctx->dev_name, count, live_members);
        out->kind = MXFS_FENCE_KIND_ADVISORY_TOPOLOGY;
        return 0;
    }

    if (!own_present) {
        if (ctx->registered && live_members >= 2) {
            /* UNAMBIGUOUS preemption: every other live member's key is
             * accounted for and OURS specifically vanished (another node
             * preempted us, or the target removed exactly us).  We may
             * be FENCED: every write can bounce off a WE-RO reservation
             * we are no longer part of.  NEVER auto-re-register (that
             * would resurrect a deliberately-fenced node) — the caller
             * must self-fence. */
            mxfs_pal_log(MXFS_LOG_ERR,
                         "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                         "'%s' (%d key(s) present, %d live) — node was "
                         "preempted",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         count, live_members);
            out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
            return -ESTALE;
        }
        if (ctx->registered) {
            /* Sole survivor with our key gone: nobody live is left to
             * have excluded us on purpose, and a lone stale key (the
             * victim's, or a shared-nexus overwrite) cannot prove a
             * preemption.  Log and rely on D1: if the target really
             * fenced us, the next write bounces EBADE and shuts us
             * down reactively. */
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                         "'%s' (%d key(s), sole survivor) — ambiguous; "
                         "relying on reactive D1 fencing",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         count);
            out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
            return 0;
        }
        /* We never registered (PR not in use for this mount) — a PREEMPT
         * from an unregistered initiator is itself a conflict; leave
         * fencing to lease/disklock exclusion. */
        out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
        return 0;
    }

    /*
     * A reservation must be HELD for deregistration to exclude anyone.
     * Under WE-RO the target rejects writes from non-registrants at
     * command-processing time — but only while the reservation exists.
     * With no reservation, an unregistered initiator writes freely and
     * the victim's missing key means precisely nothing.  Establish this
     * BEFORE the preempt so the refusal is attributable.
     */
    ret = mxfs_scsipr_read_reservation(ctx, &resv);
    if (ret && ret != -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-FENCE read_reservation failed on '%s': %d "
                     "— cannot establish that deregistration excludes",
                     ctx->dev_name, ret);
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }
    if (ret == -EOPNOTSUPP || !resv.held ||
        !mxfs_pr_type_excludes_nonregistrants(resv.type)) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-NORESV '%s' held=%d type=0x%x (%s; want a "
                     "Write Exclusive form, 0x%x or 0x%x)%s — removing a "
                     "registration excludes nobody without a reservation; NOT "
                     "a fence, and NOTHING WAS ISSUED: no PREEMPT reached the "
                     "target, no state was consumed, the victim key is intact "
                     "and this attempt is RETRYABLE once a reservation is back",
                     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
                     (ret == -EOPNOTSUPP) ? 0 : resv.type,
                     (ret == -EOPNOTSUPP) ? "unreadable"
                                          : mxfs_pr_type_name(resv.type),
                     MXFS_PAL_PR_TYPE_WR_EX_RO, MXFS_PAL_PR_TYPE_WR_EX_AR,
                     (ret == -EOPNOTSUPP) ? " [READ RESERVATION unsupported]"
                                          : "");
        out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
        return 0;
    }
    out->resv_type = resv.type;
    ctx->resv_type_seen = resv.type;

    if (!victim_present) {
        /*
         * sess71: this used to return 0 — "fenced elsewhere or never
         * registered" — and it is the COMMON path at 32 nodes, where up
         * to 31 survivors race to fence one victim and 30 of them arrive
         * to find the key already gone.
         *
         * Key absence bounds only what the victim may START.  It does not
         * establish that anybody ever aborted the task set the victim had
         * ALREADY started, and under the old plain-PREEMPT fence nobody
         * ever did.  A loser cannot re-derive the winner's guarantee from
         * the registration table; it has to consume the winner's durably
         * published evidence.  Name it unproven and let the caller do that.
         */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-FENCE-ABSENT victim key 0x%llx already "
                     "absent on '%s' (gen=%u) — exclusion NOT proved here; "
                     "caller must consume published fence evidence",
                     (unsigned long long)victim_key, ctx->dev_name, gen);
        out->kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
        return 0;
    }

    /*
     * THE COMMAND-SUBMISSION BOUNDARY (sess381).  Everything above observed;
     * everything below may change target state.  Make that durable FIRST, and
     * do not submit if it cannot be made durable: a preempt whose having
     * happened cannot later be established consumes the victim key and leaves
     * the slice provably unrecoverable, which is strictly worse than not
     * fencing at all.
     */
    if (arm_submit) {
        ret = arm_submit(arm_data);
        if (ret) {
            mxfs_pal_log(MXFS_LOG_ERR,
                         "scsipr: P304-FENCE-NOARM '%s' victim key 0x%llx rc=%d "
                         "— the command-submission boundary could not be made "
                         "durable, so NO PREEMPT AND ABORT was issued.  Nothing "
                         "was consumed and this attempt is still retryable",
                         ctx->dev_name, (unsigned long long)victim_key, ret);
            out->kind = MXFS_FENCE_KIND_ERROR;
            out->rc = ret;
            return 0;
        }
    }
    out->phase = MXFS_FENCE_PHASE_MAY_HAVE_SUBMITTED;

    /* PREEMPT AND ABORT — the abort is the point (sess71). */
    ret = mxfs_scsipr_preempt(ctx, victim_key, true);
    if (ret == -EBUSY) {
        /* Another initiator preempted the key between our READ KEYS and
         * our PROUT.  We performed nothing. */
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-FENCE-RACE lost the preempt-abort race "
                     "for node %u (key 0x%llx) on '%s' — exclusion NOT "
                     "proved here",
                     victim_node, (unsigned long long)victim_key,
                     ctx->dev_name);
        out->kind = MXFS_FENCE_KIND_RACE_LOST;
        return 0;
    }
    if (ret) {
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }

    /*
     * VERIFY the post-state.  SPC says PREEMPT AND ABORT does not complete
     * until the victim's task set is aborted, so a successful return is the
     * abort evidence — but the registration removal still has to be
     * confirmed against the table, because that is what keeps the victim
     * excluded from here on.  GPT (sess71, item 6): "verify after completion
     * that no descriptor with that key remains."
     */
    count = 0;
    ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
                                 &own_present, &count, &gen);
    if (ret == -EOVERFLOW) {
        /* The preempt-abort completed, but we cannot confirm the victim
         * holds no surviving descriptor — which is the half of the claim
         * that keeps it excluded from here on.  Do not upgrade an
         * unverifiable post-state into proved exclusion. */
        out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
        out->rc = ret;
        return 0;
    }
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-FENCE-VERIFY read_keys failed on '%s': %d "
                     "— the preempt-abort completed but its result is "
                     "unverified; NOT claiming exclusion",
                     ctx->dev_name, ret);
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }
    out->pr_generation = gen;

    if (victim_present || !own_present) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-FENCE-VERIFY '%s' post-state wrong after "
                     "preempt-abort of node %u: victim_present=%d "
                     "own_present=%d keys=%d gen=%u — NOT claiming exclusion",
                     ctx->dev_name, victim_node, victim_present, own_present,
                     count, gen);
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = -EPROTO;
        return -EPROTO;
    }

    mxfs_pal_log(MXFS_LOG_WARN,
                 "scsipr: P-PR-FENCE preempt-and-aborted dead node %u "
                 "(key 0x%llx) on '%s' — task set aborted, registration "
                 "removed, %s reservation held, gen=%u: EXCLUSION PROVED",
                 victim_node, (unsigned long long)victim_key,
                 ctx->dev_name, mxfs_pr_type_name(resv.type), gen);
    out->kind = MXFS_FENCE_KIND_PREEMPT_ABORT_DONE;
    out->phase = MXFS_FENCE_PHASE_VERIFIED;
    return 0;
}

/*
 * ── sess93: IS THE EXCLUSION STILL TRUE? ─────────────────────────────────
 *
 * mxfs_scsipr_fence_node() proves exclusion AT AN INSTANT.  MEASURED on the rig
 * (tests/pr_reregister_probe.sh), that instant is all it proves: a node whose
 * key was PREEMPT-AND-ABORTed re-registered with a fresh key and wrote to the
 * shared LUN seconds later — step 3 of the probe was REFUSED (exclusion real),
 * step 4b was ACCEPTED (exclusion expired).  The certificate authorises roughly
 * eight seconds of in-place foreign log replay over shared XFS metadata, and
 * for that whole window MXFS's only defence is the victim's own cooperative
 * self-fence — which assumes the victim is healthy enough to schedule, the
 * exact assumption a fence exists to drop (D-FENCED-VICTIM-MAY-REREGISTER).
 *
 * This is the RE-CHECK: does the exclusion hold RIGHT NOW?  It is deliberately
 * a DETECTOR, not a preventer — a write can still race between this call and
 * the operation it guards.  What it buys is that a victim which came back stays
 * caught instead of silently sharing the metadata with its own replayer, and
 * that the recovery stops rather than publishing over it.  GPT (RULE-5 ruling
 * sess93, requirement C): "reservation-health failure should stop further
 * destructive recovery."
 *
 * Both halves are required and neither is sufficient:
 *   - the WE-RO reservation must STILL be held and STILL be WE-RO, or removing
 *     a registration excludes nobody; and
 *   - the victim's key must STILL be absent from a COMPLETE key view, because
 *     a truncated view cannot establish absence at all (sess72).
 *
 * Returns 0 when the exclusion still holds.  On refusal, *out (optional)
 * carries the kind that explains why, using the same vocabulary as the fence.
 */
int mxfs_scsipr_validate_admission(struct mxfs_scsipr_ctx *ctx)
{
    struct mxfs_pal_pr_caps caps;
    struct mxfs_pal_pr_reservation resv;
    bool self_present = false, dummy = false;
    uint32_t gen = 0;
    int count = 0, ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    if (!ctx->local_key) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-UNREGISTERED '%s' — this mount "
                     "holds no PR key, so it can neither be fenced nor fence "
                     "anyone; it must not be admitted read-write",
                     ctx->dev_name);
        return -EPERM;
    }

    /* 1. What the target says it can do — one command, never issued before
     *    sess378.  Capability, persistence state and the supported reservation
     *    types all come back together. */
    ret = mxfs_pal_scsi_pr_report_capabilities(ctx->dev, &caps);
    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-NOCAPS '%s' — the target does not "
                     "answer PERSISTENT RESERVE IN / REPORT CAPABILITIES, so "
                     "this mount cannot establish that fencing works before it "
                     "needs it",
                     ctx->dev_name);
        return ret;
    }
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-ERROR '%s' rc=%d — REPORT "
                     "CAPABILITIES failed; fencing capability is UNKNOWN",
                     ctx->dev_name, ret);
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "scsipr: P303-FENCECAP '%s' ptpl_c=%d ptpl_a=%d crh=%d "
                 "sip_c=%d atp_c=%d tmv=%d type_mask=0x%04x we_ro=%d we_ar=%d "
                 "abort_capable=%d",
                 ctx->dev_name, (int)caps.ptpl_c, (int)caps.ptpl_a,
                 (int)caps.crh, (int)caps.sip_c, (int)caps.atp_c,
                 (int)caps.tmv, (unsigned)caps.type_mask, (int)caps.we_ro,
                 (int)caps.we_ar, (int)caps.abort_capable);

    if (!caps.abort_capable) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-NOABORT '%s' — no underlying SCSI "
                     "device can be reached, so PREEMPT AND ABORT cannot be "
                     "issued and a fence could never abort a victim's "
                     "in-flight writes.  This is the exact condition that went "
                     "undetected for months (dm drops the abort flag)",
                     ctx->dev_name);
        return -EPERM;
    }
    if (!caps.tmv || !caps.we_ar) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-NOWEAR '%s' tmv=%d mask=0x%04x "
                     "we_ro=%d we_ar=%d — the target does not offer WRITE "
                     "EXCLUSIVE - ALL REGISTRANTS (type 0x07), the reservation "
                     "type every MXFS exclusion proof is written against from "
                     "protocol generation 5 on.  The single-holder type this "
                     "build no longer uses loses the reservation on the "
                     "holder's clean unmount and disarms fencing for the whole "
                     "cluster (sess381)",
                     ctx->dev_name, (int)caps.tmv, (unsigned)caps.type_mask,
                     (int)caps.we_ro, (int)caps.we_ar);
        return -EPERM;
    }
    if (!caps.ptpl_a) {
        /* APTPL is set by the REGISTER; this is the target CONFIRMING it is
         * actually active.  Without it the whole cross-boot recovery story
         * changes silently (see D-PR-REGISTRATION-NOT-PERSISTENT-APTPL). */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-NOPERSIST '%s' ptpl_c=%d ptpl_a=0 "
                     "— PR state is NOT persisting through power loss, so "
                     "registrations do not survive a target restart and "
                     "cross-boot exclusion cannot be relied on",
                     ctx->dev_name, (int)caps.ptpl_c);
        return -EPERM;
    }

    /* 2. The reservation MXFS establishes must actually be HELD.  With no
     *    reservation, an unregistered initiator writes freely and key absence
     *    proves nothing.
     *
     *    sess381: this check is only worth anything because the caller now
     *    OBSERVES the reservation before it registers or reserves (see
     *    mxfs_scsipr_observe_reservation()).  Run after our own RESERVE, as
     *    it must be, this asserts a postcondition — that we are covered — and
     *    the P304-PREOBSERVE line above it is what says whether the cluster
     *    was already armed or whether this mount armed it. */
    ret = mxfs_scsipr_read_reservation(ctx, &resv);
    if (ret && ret != -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-RESVERR '%s' rc=%d", ctx->dev_name,
                     ret);
        return ret;
    }
    if (ret == -EOPNOTSUPP || !resv.held) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-NORESV '%s' held=%d — no "
                     "reservation is in force, so nothing is excluded from "
                     "this LU and a fence would prove nothing",
                     ctx->dev_name,
                     (ret == -EOPNOTSUPP) ? -1 : (int)resv.held);
        return -EPERM;
    }
    if (resv.type != MXFS_SCSIPR_RESV_TYPE) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-WRONGTYPE '%s' type=0x%x (%s), "
                     "want 0x%x (%s) — a reservation IS in force and it does "
                     "exclude non-registrants, but it is not the type this "
                     "protocol generation requires.  A single-holder "
                     "reservation is released by its holder's clean unmount, "
                     "which disarms fencing cluster-wide, so this mount must "
                     "not join under one.  Most likely a stale reservation "
                     "left by a crashed node running an older protocol "
                     "generation: bring every node down, clear it, and remount",
                     ctx->dev_name, resv.type, mxfs_pr_type_name(resv.type),
                     MXFS_SCSIPR_RESV_TYPE,
                     mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE));
        return -EPERM;
    }
    ctx->resv_type_seen = resv.type;

    /* 3. Our own key must be visible in a COMPLETE view.  A truncated view can
     *    never prove absence, so an exclusion proof read out of one is void. */
    ret = mxfs_scsipr_probe_keys(ctx, ctx->local_key, &self_present, &dummy,
                                 &count, &gen);
    if (ret == -EOVERFLOW) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-TRUNCATED '%s' — the target holds "
                     "more registrants than this build can read back, so no "
                     "future exclusion proof on this mount could be sound",
                     ctx->dev_name);
        return -EPERM;
    }
    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-KEYSERR '%s' rc=%d", ctx->dev_name,
                     ret);
        return ret;
    }
    if (!self_present) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P303-FENCECAP-SELFABSENT '%s' key=0x%llx "
                     "registrants=%d gen=%u — this mount's own key is not in "
                     "the target's registration table, so it is already "
                     "excluded from the LU it is about to join",
                     ctx->dev_name, (unsigned long long)ctx->local_key,
                     count, gen);
        return -EPERM;
    }

    mxfs_pal_log(MXFS_LOG_INFO,
                 "scsipr: P303-FENCECAP-OK '%s' registrants=%d gen=%u "
                 "resv=%s — fencing capability validated at admission: "
                 "all-registrants reservation held (it survives any single "
                 "node's departure), persistence active, key view complete, "
                 "own key present, PREEMPT AND ABORT issuable",
                 ctx->dev_name, count, gen,
                 mxfs_pr_type_name(MXFS_SCSIPR_RESV_TYPE));
    return 0;
}

int mxfs_scsipr_exclusion_holds(struct mxfs_scsipr_ctx *ctx,
                                uint64_t victim_key,
                                struct mxfs_fence_result *out)
{
    struct mxfs_pal_pr_reservation resv;
    struct mxfs_fence_result local;
    bool victim_present = false, own_present = false;
    uint32_t gen = 0;
    int count = 0, ret;

    if (!out)
        out = &local;
    memset(out, 0, sizeof(*out));
    out->kind = MXFS_FENCE_KIND_NONE;
    out->victim_key = victim_key;
    /*
     * sess381: PRECOMMAND until the exact line that submits.  Everything from
     * here to the arm_submit() call below is pure observation — READ KEYS,
     * READ RESERVATION, classification — so every return in between is
     * "nothing was submitted, nothing was consumed, this is safe to repeat".
     * That is the property D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381
     * exists because nobody recorded.
     */
    out->phase = MXFS_FENCE_PHASE_PRECOMMAND;

    if (!ctx || !ctx->dev || !victim_key)
        return -EINVAL;
    if (!ctx->local_key) {
        out->kind = MXFS_FENCE_KIND_NOT_REGISTERED;
        return -EPERM;
    }

    ret = mxfs_scsipr_read_reservation(ctx, &resv);
    if (ret && ret != -EOPNOTSUPP) {
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }
    if (ret == -EOPNOTSUPP || !resv.held ||
        !mxfs_pr_type_excludes_nonregistrants(resv.type)) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P239-EXCL-NORESV '%s' held=%d type=0x%x (%s) — "
                     "the reservation the certificate was issued under is no "
                     "longer in force; nothing is excluded from this LU any "
                     "more",
                     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
                     (ret == -EOPNOTSUPP) ? 0 : resv.type,
                     (ret == -EOPNOTSUPP) ? "unreadable"
                                          : mxfs_pr_type_name(resv.type));
        out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
        return -EPERM;
    }
    out->resv_type = resv.type;
    ctx->resv_type_seen = resv.type;

    ret = mxfs_scsipr_probe_keys(ctx, victim_key, &victim_present,
                                 &own_present, &count, &gen);
    if (ret == -EOVERFLOW) {
        /* sess72: more descriptors than we can read means absence is not
         * establishable.  Unknown is refused. */
        out->kind = MXFS_FENCE_KIND_VIEW_TRUNCATED;
        out->rc = ret;
        return -EPERM;
    }
    if (ret) {
        out->kind = MXFS_FENCE_KIND_ERROR;
        out->rc = ret;
        return ret;
    }
    out->pr_generation = gen;

    if (!own_present) {
        /* Our own key is gone: WE are the fenced node.  Same verdict the
         * fence path gives, and it is terminal — the caller must self-fence,
         * not carry on recovering somebody else. */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P239-EXCL-SELFGONE '%s' our key 0x%llx is absent "
                     "while re-checking victim 0x%llx — we are the fenced node",
                     ctx->dev_name, (unsigned long long)ctx->local_key,
                     (unsigned long long)victim_key);
        out->kind = MXFS_FENCE_KIND_SELF_PREEMPTED;
        return -ESTALE;
    }
    if (victim_present) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P239-EXCL-RETURNED '%s' victim key 0x%llx is "
                     "REGISTERED AGAIN (gen=%u, %d keys) — the exclusion this "
                     "recovery was authorised by has LAPSED.  The victim can "
                     "write to this LU right now; no further destructive "
                     "recovery step may run",
                     ctx->dev_name, (unsigned long long)victim_key, gen, count);
        out->kind = MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN;
        return -EPERM;
    }

    out->kind = MXFS_FENCE_KIND_PREEMPT_ABORT_DONE;
    return 0;
}

int mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members)
{
    int count = 0, ret;
    bool own_present = false, victim_present = false;

    if (!ctx || !ctx->dev)
        return -EINVAL;
    if (!ctx->registered)
        return 0;       /* not participating in PR — nothing to check */

    ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
                                 &count, NULL);
    if (ret == -EOPNOTSUPP)
        return 0;
    if (ret == -EOVERFLOW) {
        /*
         * The table is bigger than we can read, so "our key is missing"
         * cannot be distinguished from "our key is past the truncation
         * point".  This branch ends in a node freeze, and a partial view
         * is exactly how a HEALTHY node would be made to look preempted:
         * a saturated count also satisfies the count >= live_members
         * guard below, so the topology escape hatch would not catch it.
         * Never self-fence on a view that cannot see itself.
         */
        return 0;
    }
    if (ret) {
        /* Transient READ KEYS failure — retry next tick, but never
         * silently: a persistently failing self-check looks identical
         * to a healthy one otherwise. */
        static int d8_rk_fail_logs;

        if (d8_rk_fail_logs < 8) {
            d8_rk_fail_logs++;
            mxfs_pal_log(MXFS_LOG_WARN,
                         "scsipr: P-PR-SELFCHECK read_keys failed on '%s': %d",
                         ctx->dev_name, ret);
        }
        return ret;
    }

    if (own_present) {
        ctx->advisory_logged = false;
        return 0;
    }

    /* Same classification as fence_node: self-fence only on the
     * UNAMBIGUOUS preemption signature. */
    if (count >= live_members && live_members >= 2) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-OWNKEY-GONE own key 0x%llx missing on "
                     "'%s' (self-check: %d key(s), %d live) — node was "
                     "preempted",
                     (unsigned long long)ctx->local_key, ctx->dev_name,
                     count, live_members);
        return -ESTALE;
    }
    if (!ctx->advisory_logged) {
        ctx->advisory_logged = true;
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-ADVISORY '%s' self-check: own key gone, "
                     "%d key(s) for %d live member(s) — per-node PR not "
                     "trustworthy on this topology; D1+lease fencing apply",
                     ctx->dev_name, count, live_members);
    }
    return 0;
}

/*
 * sess276/277 — AM I THE FENCED NODE?  Target-authoritative, callable
 * from a node whose media READS may be arbitrarily stale (the sess276
 * victim's heartbeat re-reads were 51 generations behind the platter,
 * which is why mxfs_scsipr_self_check's READ-KEYS path never fired for
 * it: this rig's CAW transport never ran self_check at all, and a
 * media-read based check provably cannot work on a wedged initiator).
 *
 * Primary: PR IN / READ FULL STATUS — per-I_T-nexus, generated by the
 * target at command time, permitted to an unregistered initiator.
 * Fallback (-EOPNOTSUPP only): READ KEYS own-key scan, which carries a
 * key-reuse ambiguity but is still target-generated.
 *
 * Returns 1 = our key is provably ABSENT (we are fenced);
 *         0 = our key is present (still registered);
 *        <0 = could not be answered (caller must treat as UNKNOWN,
 *             never as either verdict).
 */
int mxfs_scsipr_fenced_check(struct mxfs_scsipr_ctx *ctx)
{
    uint32_t gen = 0;
    int present = 0;
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;
    if (!ctx->registered || !ctx->local_key)
        return -ENOENT;     /* never registered — fencing is not the story */

    ret = mxfs_pal_scsi_pr_read_full_status(ctx->dev, ctx->local_key,
                                            &present, &gen);
    if (ret == 0) {
        if (!present)
            mxfs_pal_log(MXFS_LOG_ERR,
                         "scsipr: P277-PR-FULLSTATUS own key 0x%llx ABSENT "
                         "on '%s' (pr_gen=%u) — target says this node is "
                         "fenced",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         gen);
        return present ? 0 : 1;
    }

    if (ret == -EOPNOTSUPP) {
        bool own_present = false, victim_present = false;
        int count = 0;

        ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
                                     &count, &gen);
        if (ret)
            return ret;     /* incl. -EOVERFLOW: truncation ⇒ unknown */
        if (!own_present)
            mxfs_pal_log(MXFS_LOG_ERR,
                         "scsipr: P277-PR-READKEYS own key 0x%llx absent "
                         "on '%s' (%d key(s), pr_gen=%u) — fenced "
                         "(full-status unsupported; key-reuse ambiguity "
                         "accepted as fallback)",
                         (unsigned long long)ctx->local_key, ctx->dev_name,
                         count, gen);
        return own_present ? 0 : 1;
    }

    return ret;
}

int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx)
{
    int count = 0, ret;
    bool own_present = false, victim_present = false;

    if (!ctx || !ctx->dev || !ctx->registered)
        return 0;

    ret = mxfs_scsipr_probe_keys(ctx, 0, &victim_present, &own_present,
                                 &count, NULL);
    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-PROBE '%s': READ KEYS unsupported — "
                     "PR state not verifiable (advisory)", ctx->dev_name);
        return 0;
    }
    if (ret == -EOVERFLOW) {
        /* Provisioning-time signal that MXFS_PR_MAX_KEYS is too small for
         * this target's nexus count — the one place it is cheap to notice
         * before a fence or a self-check has to refuse. */
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-PROBE '%s': registration table exceeds the "
                     "%d-descriptor snapshot cap — PR classification will "
                     "refuse until MXFS_PR_MAX_KEYS is raised",
                     ctx->dev_name, MXFS_PR_MAX_KEYS);
        return 0;
    }
    if (ret)
        return ret;

    if (!own_present)
        /* Register reported success but our key is not visible: the
         * target either shares one I_T nexus across nodes (each
         * register overwrites the last) or silently drops
         * registrations.  Fencing must not trust PR here. */
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: P-PR-PROBE '%s': own key 0x%llx NOT visible "
                     "after successful register (%d key(s)) — per-node PR "
                     "unusable on this target/topology (advisory only)",
                     ctx->dev_name,
                     (unsigned long long)ctx->local_key, count);
    else
        mxfs_pal_log(MXFS_LOG_INFO,
                     "scsipr: P-PR-PROBE '%s': own key 0x%llx visible, "
                     "%d key(s) registered — per-node PR active",
                     ctx->dev_name,
                     (unsigned long long)ctx->local_key, count);
    return 0;
}

int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->dev)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_unregister(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping unregister",
                     ctx->dev_name);
        ctx->registered = false;
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: unregister failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = false;
    ctx->registered = false;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: unregistered key 0x%llx from '%s'",
                 (unsigned long long)ctx->local_key, ctx->dev_name);

    return 0;
}

int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
                           int max_keys, int *count, uint32_t *generation,
                           int *total)
{
    int ret;

    if (!ctx || !ctx->dev || !keys || !count || max_keys <= 0)
        return -EINVAL;

    *count = 0;
    if (total)
        *total = 0;

    ret = mxfs_pal_scsi_pr_read_keys(ctx->dev, keys, max_keys, count,
                                     generation, total);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR read_keys support",
                     ctx->dev_name);
        return ret;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: read_keys failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: read_keys on '%s': %d keys",
                 ctx->dev_name, *count);

    return 0;
}
