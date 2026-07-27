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

/* Preempt a dead node's key */
int mxfs_scsipr_preempt(struct mxfs_scsipr_ctx *ctx, uint64_t victim_key);

/* v0.11.80 (D4): fence a dead node's registration with SPC hygiene.
 * READ KEYS first: preempt only a key that is actually registered
 * (a blind preempt of an absent key is a RESERVATION CONFLICT per
 * SPC).  live_members = count of live cluster members INCLUDING self,
 * EXCLUDING the victim — used to classify the topology: when fewer
 * keys than live members are registered, per-node PR is unusable on
 * this rig (e.g. every VM shares ONE host I_T nexus, so each node's
 * REGISTER overwrites the previous one's — measured on the tcm_loop
 * VM rig) and PR is ADVISORY: no preempt, no self-fence; reactive
 * fencing via D1 (EBADE on write) + lease/disklock still applies.
 * Returns 0 when the victim is gone (fenced, never there, or
 * advisory topology), -ESTALE only in the UNAMBIGUOUS case: every
 * other live member's key is visible and OURS specifically is not —
 * we were preempted; caller must SELF-FENCE and NEVER auto-re-register. */
int mxfs_scsipr_fence_node(struct mxfs_scsipr_ctx *ctx,
                           mxfs_node_id_t victim_node, int live_members);

/* Unregister this node's key on clean shutdown */
int mxfs_scsipr_unregister(struct mxfs_scsipr_ctx *ctx);

/* Read all currently registered keys */
int mxfs_scsipr_read_keys(struct mxfs_scsipr_ctx *ctx, uint64_t *keys,
                           int max_keys, int *count);

/* v0.11.80 (D8): periodic own-registration audit.  0 = fine/advisory,
 * -ESTALE = unambiguous preemption (caller must self-fence, never
 * re-register), other negative = transient READ KEYS failure. */
int mxfs_scsipr_self_check(struct mxfs_scsipr_ctx *ctx, int live_members);

/* v0.11.80 (D8): provisioning-time conformance probe — call once after
 * register+reserve; logs whether per-node PR is actually usable on this
 * target/topology (own key visible ⇒ active; not visible ⇒ advisory). */
int mxfs_scsipr_probe(struct mxfs_scsipr_ctx *ctx);

#endif /* MXFS_LIBMXFS_SCSIPR_H */
