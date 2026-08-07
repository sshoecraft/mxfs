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

    ret = mxfs_pal_scsi_pr_reserve(ctx->dev, ctx->local_key);

    if (ret == -EOPNOTSUPP) {
        mxfs_pal_log(MXFS_LOG_WARN,
                     "scsipr: '%s' has no PR support, skipping reserve",
                     ctx->dev_name);
        return 0;
    }

    if (ret == -EBUSY) {
        /*
         * Another node holds the reservation. With type 5
         * (WRITE EXCLUSIVE - REGISTRANTS ONLY), we only need
         * to be registered to do I/O. The reservation holder
         * is irrelevant for data access.
         */
        mxfs_pal_log(MXFS_LOG_DEBUG,
                     "scsipr: '%s' reservation held by another node "
                     "(we are registered)", ctx->dev_name);
        return 0;
    }

    if (ret) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: reserve failed on '%s': %d",
                     ctx->dev_name, ret);
        return ret;
    }

    ctx->reserved = true;
    mxfs_pal_log(MXFS_LOG_DEBUG,
                 "scsipr: reservation acquired on '%s'", ctx->dev_name);

    return 0;
}

int mxfs_scsipr_read_reservation(struct mxfs_scsipr_ctx *ctx,
                                 struct mxfs_pal_pr_reservation *out)
{
    if (!ctx || !ctx->dev || !out)
        return -EINVAL;
    return mxfs_pal_scsi_pr_read_reservation(ctx->dev, out);
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
    }
    return "?";
}

int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key,
                        bool abort)
{
    int ret;

    if (!ctx || !ctx->dev || victim_key == 0)
        return -EINVAL;

    ret = mxfs_pal_scsi_pr_preempt(ctx->dev, ctx->local_key, victim_key,
                                   abort);

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
        resv.type != MXFS_PAL_PR_TYPE_WR_EX_RO) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P-PR-NORESV '%s' held=%d type=0x%x (want 0x%x, "
                     "WE-RO)%s — removing a registration excludes nobody "
                     "without a reservation; NOT a fence",
                     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
                     (ret == -EOPNOTSUPP) ? 0 : resv.type,
                     MXFS_PAL_PR_TYPE_WR_EX_RO,
                     (ret == -EOPNOTSUPP) ? " [READ RESERVATION unsupported]"
                                          : "");
        out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
        return 0;
    }
    out->resv_type = resv.type;

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
                 "removed, WE-RO reservation held, gen=%u: EXCLUSION PROVED",
                 victim_node, (unsigned long long)victim_key,
                 ctx->dev_name, gen);
    out->kind = MXFS_FENCE_KIND_PREEMPT_ABORT_DONE;
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
        resv.type != MXFS_PAL_PR_TYPE_WR_EX_RO) {
        mxfs_pal_log(MXFS_LOG_ERR,
                     "scsipr: P239-EXCL-NORESV '%s' held=%d type=0x%x — the "
                     "WE-RO reservation the certificate was issued under is no "
                     "longer in force; nothing is excluded from this LU any "
                     "more",
                     ctx->dev_name, (ret == -EOPNOTSUPP) ? -1 : (int)resv.held,
                     (ret == -EOPNOTSUPP) ? 0 : resv.type);
        out->kind = MXFS_FENCE_KIND_NO_RESERVATION;
        return -EPERM;
    }
    out->resv_type = resv.type;

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
