/*
 * MXFS — Multinode XFS
 * Portable on-disk lock state persistence
 *
 * Persists DLM lock state and node heartbeats to a reserved region
 * on the shared block device. Uses PAL bdev_read/bdev_write for
 * sector-aligned atomic I/O visible to all nodes immediately.
 *
 * Ported from kernel/mxfs_disklock.c — kernel file I/O replaced
 * with PAL block device I/O, delayed_work replaced with PAL thread.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "disklock.h"
#include "scsipr.h"     /* the fence certificate stores enum
						 * mxfs_fence_kind and is validated with
						 * mxfs_fence_kind_proves_exclusion() — the ONE
						 * predicate every replay gate must use */
#include "../include/mxfs/mxfs_super.h"
#include "../include/mxfs/mxfs_tauth.h"    /* ledger-manifest slot_idx bound */
#include "recov_obl_done.h"                 /* 0.85.0: the completion proof */

/*
 * Instr gate for diagnostic probes — mirrors caw_instr_on() in dlm_caw.c.
 * mxfs_instr_enabled lives in the xfs overlay (xfs_mxfs_dlm.c) and is
 * linked into mxfs.ko alongside this file; user-mode dlm builds (no
 * overlay) compile the gate out.  Pure logging, no side effects.
 */
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/moduleparam.h>
extern int mxfs_instr_enabled;
#define dl_instr_on() (unlikely(mxfs_instr_enabled))

/*
 * (ruling, Hazards section 7): deterministic fault injection
 * for the CLOSURE GATE.  The ruling requires POSITIVE observation of each
 * refusal path, and none of them occur naturally on a healthy rig — a gate
 * that never fails proves only that it was never asked.  Each knob is a
 * CONSUMABLE count: writing N arms the next N hits of its site, each hit
 * decrements, 0 disarms.  TEST ONLY — all default 0 and stay 0 in production.
 */
static int mxfs_dl_inject_closure_read;
module_param_named(dl_inject_closure_read, mxfs_dl_inject_closure_read,
		   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_read,
		 "TEST ONLY: fail the next N closure-gate heartbeat sector "
		 "reads with -EIO (consumable; 0=off)");

static int mxfs_dl_inject_closure_crc;
module_param_named(dl_inject_closure_crc, mxfs_dl_inject_closure_crc,
		   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_crc,
		 "TEST ONLY: make the next N closure-gate predicate "
		 "evaluations read the descriptor as unparseable (-EPROTO), "
		 "as a torn/miscrc'd record would (consumable; 0=off)");

static int mxfs_dl_inject_closure_mask;
module_param_named(dl_inject_closure_mask, mxfs_dl_inject_closure_mask,
		   int, 0644);
MODULE_PARM_DESC(dl_inject_closure_mask,
		 "TEST ONLY: perturb the ag_mask the next N closure-gate "
		 "REVALIDATIONS read, so the expected-vs-platter compare "
		 "fails and the purge must stop -ESTALE (consumable; 0=off)");

/* (D-FENCED-VICTIM-NONCONTAINMENT-498 verification): pause THIS
 * node's heartbeat thread ONCE for N ms while its data path keeps running —
 * the false-death shape.  > the 62 s expiry makes the peers fence a
 * LIVE node with a real certificate and replay its slice; the victim then
 * must self-withdraw on its bounced writes (P277) and stop.  Consumed on
 * use (one-shot).  TEST ONLY. */
static int mxfs_dl_inject_hb_pause_ms;
module_param_named(dl_inject_hb_pause_ms, mxfs_dl_inject_hb_pause_ms,
		   int, 0644);
MODULE_PARM_DESC(dl_inject_hb_pause_ms,
		 "TEST ONLY: pause the disklock heartbeat thread once for N "
		 "ms (false-death injection; one-shot, 0=off)");

/* 0.89.20 TEST ONLY: skip the heartbeat's pre-issue AUTHORITY check for
 * exactly one cycle, so a beat issued after this node's authority lease had
 * already lapsed actually reaches mxfs_disklock_authority_renew.  That
 * renewal guard — refuse, and close the epoch, when the anchor is already
 * past the deadline — is defence in depth and no live path reaches it,
 * because the pre-issue check stops the heartbeat first.  A guard that
 * nothing can exercise is a guard nobody knows works.  One-shot. */
static int mxfs_dbg_hb_skip_auth_check;
module_param_named(dbg_hb_skip_auth_check, mxfs_dbg_hb_skip_auth_check,
		   int, 0644);
MODULE_PARM_DESC(dbg_hb_skip_auth_check,
		 "TEST ONLY: skip the heartbeat's pre-issue authority check "
		 "once, so a stale-anchored renewal reaches the guard that "
		 "must refuse it (one-shot, 0=off)");

/* 0.89.20 TEST ONLY: the beat reaches the target and its COMPLETION is then
 * withheld for N ms.  The ordering the issue-time anchor exists for: the
 * update is visible to peers, they age it while this node waits, and only
 * afterwards is the success delivered.  A deadline anchored at completion
 * would grant authority measured from an instant that had already passed for
 * everyone else.  One-shot. */
static int mxfs_dbg_hb_completion_delay_ms;
module_param_named(dbg_hb_completion_delay_ms, mxfs_dbg_hb_completion_delay_ms,
		   int, 0644);
MODULE_PARM_DESC(dbg_hb_completion_delay_ms,
		 "TEST ONLY: withhold a landed heartbeat's completion for N "
		 "ms, so the renewal must still derive its deadline from when "
		 "the beat was issued (one-shot, 0=off)");

/*
 * 0.75.90 TEST ONLY (D-0932, D-0933 part 2): hold this prover for N ms in the
 * window where its fencing intent is DURABLE on the platter but no PREEMPT AND
 * ABORT has been issued — i.e. a descriptor at stage FENCING naming this node
 * as fence_prover_node and nothing done under it yet.
 *
 * That window is the entire premise of the attempt-takeover path: a peer may
 * only take the attempt over once it can prove the holder's incarnation is
 * REVOKED, and until then the slice waits.  Killing a prover parked here leaves
 * exactly the on-disk state a prover that died mid-attempt leaves — a REAL
 * descriptor written by a real prover, not a forged one.
 *
 * It exists because the window is otherwise unreachable on a two-node rig.
 * Measured (chain s583f, both laps, all four journals): P238-FENCE-HOLDER-SLOT,
 * verdict=REVOKED and P238-FENCE-TAKEOVER are all ZERO, because two symmetric
 * survivors make every victim a previous boot of a live host and
 * boot-succession proves exclusion before any attempt is left standing.
 *
 * Writable at 0644 so a harness can arm it on ONE node at runtime, via
 * /sys/module/mxfs/parameters/, without reloading the module or giving the two
 * nodes different insmod arguments.  Never set in production.
 */
static int mxfs_dl_fence_postintent_pause_ms;
module_param_named(dl_fence_postintent_pause_ms,
		   mxfs_dl_fence_postintent_pause_ms, int, 0644);
MODULE_PARM_DESC(dl_fence_postintent_pause_ms,
		 "TEST ONLY: hold the prover N ms after its fencing intent is "
		 "durable and before the PREEMPT AND ABORT is issued (0=off)");

/*
 * 0.89.16 TEST ONLY: stamp this fence KIND on the durable certificate instead
 * of the one the attempt actually proved.
 *
 * It exists to produce the one state this build cannot otherwise reach: a
 * descriptor on the platter carrying a proof contract that has since been
 * REVOKED — the certificate an older build wrote and a corrected build has to
 * refuse.  This build refuses to MINT those kinds, so without an injection
 * nothing ever puts one on a platter, and the refusal at the CONSUMING end is
 * a branch nobody has seen fire.
 *
 * It is deliberately narrow and it cannot loosen anything.  Every check the
 * constructor makes still runs, against the kind the attempt actually proved;
 * only the value written into the descriptor is replaced, and the values worth
 * injecting are exactly the ones the consuming side then refuses — so an
 * injected lap is strictly more conservative than an uninjected one.  The
 * substitution is printed with the certificate, so no lap can mistake an
 * injected kind for a measured one.  Never set in production.
 */
static int mxfs_dl_fence_cert_kind_inject;
module_param_named(dl_fence_cert_kind_inject, mxfs_dl_fence_cert_kind_inject,
		   int, 0644);
MODULE_PARM_DESC(dl_fence_cert_kind_inject,
		 "TEST ONLY: write this fence kind into the durable "
		 "certificate instead of the proved one, so the consuming side "
		 "meets a revoked proof contract (0=off)");

/* Consume one armed injection: true and decrement while the knob is >0. */
static inline bool dl_inject_take(int *knob)
{
	if (*knob > 0) {
		(*knob)--;
		return true;
	}
	return false;
}
#else
#define dl_instr_on() (0)
#define dl_inject_take(k) (false)
static int mxfs_dl_inject_hb_pause_ms;	/* user-mode: never armed */
static int mxfs_dbg_hb_skip_auth_check;	/* user-mode: never armed */
static int mxfs_dbg_hb_completion_delay_ms;	/* user-mode: never armed */
static int mxfs_dl_fence_cert_kind_inject;	/* user-mode: never armed */
#endif

/*
 * ROOT FIX of the 32/caw budget-timeout family
 * (cache_coherency / crash_consistency / dir_reuse verify convoys) — instrumented
 * PROVEN chain: the heartbeat monitor scan reads peer HB sectors with a
 * PLAIN, CACHEABLE read (see the note at the dead-detect confirm —
 * only DEAD detection got the FUA re-check).  Under storm load the block
 * layer / SCST per-initiator cache returns STALE heartbeat sectors, so a
 * peer's evict-ring head_seq is observed JUMPING BACKWARD (stale) and then
 * forward again (fresh).  The old consume condition (`h != last_evict_seq`)
 * fired on BOTH directions: a backward jump wrap-clamped (h - pos > c) into
 * replaying up to the full 28-entry ring of ALREADY-CONSUMED DIR_MODIFY /
 * INODE_FREE entries, and the following fresh read replayed the overlap
 * again.  Each replayed DIR_MODIFY bumps i_dlm_dir_gen and arms
 * MXFS_IF_DIR_RELOAD on every node caching the dir ("gen-bump is
 * idempotent" is FALSE for the counter) — measured live at 32/caw: during
 * the PURE-READ rename_visibility verify, test20's hot-dir dir_gen advanced
 * 197->859 (~6/s) with ZERO writers anywhere, 689 reload_inode calls ALL
 * with identical dinode fields, P138-WAIT mode=5 (EX) = 0 cluster-wide —
 * i.e. the entire per-op release+reacquire+reload+block-re-read convoy
 * (~0.25s/op, 1920 ops -> 470s wall vs 300s budget) was manufactured by
 * stale-HB ring replay, not by any real coherency traffic.
 *
 * Fix: consume the ring MONOTONICALLY — only when head_seq is genuinely
 * AHEAD of our cursor in wrap-safe int32 distance; never move the cursor
 * backward; a backward/behind observation is a stale read and is skipped
 * (counted + logged).  Peer reboot (head_seq restart) re-baselines via
 * evict_seen=false at fire_dead.  A/B: evict_ring_monotonic=0 restores the
 * old any-difference behavior.
 */
int mxfs_evict_ring_monotonic = 1;

/* Compile-time size verification */
_Static_assert(sizeof(struct mxfs_disklock_record) == 512,
	       "disklock record must be exactly 512 bytes");
_Static_assert(sizeof(struct mxfs_disklock_heartbeat) == 512,
	       "disklock heartbeat must be exactly 512 bytes");

/* FNV-1a 32-bit hash over a resource ID */
static uint32_t resource_hash(const struct mxfs_resource_id *res)
{
	uint32_t hash = 2166136261u;
	const uint8_t *data = (const uint8_t *)res;
	size_t len = sizeof(*res);
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= data[i];
		hash *= 16777619u;
	}
	return hash;
}

/* Compare two resource IDs for equality */
static bool resource_equal(const struct mxfs_resource_id *a,
			    const struct mxfs_resource_id *b)
{
	return a->volume == b->volume &&
	       a->ino == b->ino &&
	       a->offset == b->offset &&
	       a->ag_number == b->ag_number &&
	       a->type == b->type;
}

/* Compute absolute offset for a lock record slot */
static uint64_t lock_slot_offset(struct mxfs_disklock_ctx *ctx, uint32_t slot)
{
	return ctx->base_offset + MXFS_DISKLOCK_HB_SIZE +
	       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
}

/* Compute absolute offset for a heartbeat slot */
static uint64_t hb_slot_offset(struct mxfs_disklock_ctx *ctx,
				mxfs_node_id_t node)
{
	return ctx->base_offset +
	       (uint64_t)(node % MXFS_DISKLOCK_HB_SLOTS) *
	       MXFS_DISKLOCK_RECORD_SIZE;
}

/* Read a single 512-byte sector */
static int read_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset,
			void *buf)
{
	return mxfs_pal_bdev_read(ctx->dev, offset, buf,
				   MXFS_DISKLOCK_RECORD_SIZE);
}

static bool hb_guard_abandoned(struct mxfs_disklock_ctx *ctx, int slot,
			       const struct mxfs_disklock_heartbeat *first);

/* Write a single 512-byte sector */
static int write_sector(struct mxfs_disklock_ctx *ctx, uint64_t offset,
			  const void *buf)
{
	return mxfs_pal_bdev_write(ctx->dev, offset, buf,
				    MXFS_DISKLOCK_RECORD_SIZE);
}

static int write_sector_fua(struct mxfs_disklock_ctx *ctx, uint64_t offset,
			      const void *buf)
{
	return mxfs_pal_bdev_write_fua(ctx->dev, offset, buf,
					MXFS_DISKLOCK_RECORD_SIZE);
}

/*
 * a heartbeat record from a different mkfs generation.  Only
 * meaningful once the mount layer has installed our identity; tools and
 * legacy paths (have_fs_identity == false) treat every record as native.
 */
static bool hb_gen_foreign(const struct mxfs_disklock_ctx *ctx,
			   const struct mxfs_disklock_heartbeat *hb)
{
	return ctx->have_fs_identity && hb->fs_gen != ctx->fs_gen;
}

/*
 * ── MOUNT INCARNATION (D-MOUNT-INCARNATION-CONSTANT-ZERO) ───────────────────
 *
 * `epoch` names ONE published slot tenancy.  It is an OPAQUE, nonzero,
 * cryptographically random 64-bit identity compared for EQUALITY ONLY — never
 * ordered.  A larger value does not mean "newer": a resurrected older record
 * must fail closed, not be reasoned about numerically.
 *
 * Lifecycle (design review-consult ruling):
 *   - drawn BEFORE the first claim publication, so the first durable ACTIVE
 *     record, its feature CRC and every descriptor carry the same value;
 *   - immutable for the life of that published tenancy — transient rewrites
 *     of a still-owned record reuse it;
 *   - losing the slot TERMINATES the incarnation; that value may never
 *     establish a new tenancy, so every claim draws a fresh one.
 *
 * ZERO IS NEVER A WILDCARD.  Under the MXFS_PROTO_GEN 3 gate it has exactly
 * one meaning — "no valid published incarnation" (vacant / purged /
 * uninitialised / legacy).  Every authoritative recovery transition fails
 * closed on zero or on mismatch; only non-authoritative paths (identifying a
 * sector as empty, diagnostic decode, quarantining or purging a legacy record
 * after independent proof) may accept it.
 */
#define MXFS_INCARNATION_DRAWS  16

static mxfs_epoch_t hb_draw_incarnation(void)
{
	mxfs_epoch_t e = 0;
	int i;

	/*
	 * mxfs_pal_get_random_bytes() returns void and cannot report failure.
	 * Its ONLY failure mode is the user-space backend zero-filling the buffer
	 * when /dev/urandom will not open, so a bounded draw-until-nonzero loop
	 * IS the fail-closed detector for it: 16 consecutive all-zero draws from
	 * a working RNG has probability 2^-1024.  Never fall back to a clock —
	 * a timestamp has too little collision resistance exactly in the cases an
	 * incarnation exists to survive (VM snapshot restore, stuck RTC, rapid
	 * reboot, pre-NTP boot).
	 */
	for (i = 0; i < MXFS_INCARNATION_DRAWS; i++) {
		mxfs_pal_get_random_bytes(&e, sizeof(e));
		if (e != 0)
			return e;
	}
	return 0;                   /* caller MUST fail the mount/claim closed */
}

/* A published incarnation is valid iff nonzero. */
static inline bool inc_valid(mxfs_epoch_t e)
{
	return e != 0;
}

/*
 * (D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO, ruling item 1):
 * rebase a tracked slot's cached incarnation from a sector we just read.
 * A ZERO on the sector never overwrites a known nonzero incarnation — no
 * member at this proto_gen writes one, so it is a torn/spliced sector or a
 * foreign writer, and the slot is flagged inconsistent (P-HB-INC-ZERO)
 * rather than silently re-baselined to "unknown" (which later published a
 * recovery under an unobserved incarnation).
 */
static void hb_rebase_epoch(struct mxfs_disklock_ctx *ctx,
			    struct mxfs_disklock_node_track *nt, int slot,
			    const struct mxfs_disklock_heartbeat *rhb,
			    const char *arm)
{
	if (inc_valid(rhb->epoch) || !inc_valid(nt->last_epoch)) {
		nt->last_epoch = rhb->epoch;
		nt->inc_zero_logged = false;
		return;
	}
	ctx->hb_inc_zero_retained++;
	if (nt->inc_zero_logged)
		return;
	nt->inc_zero_logged = true;
	mxfs_pal_log(MXFS_LOG_ERR,
		     "mxfs: P-HB-INC-ZERO slot=%d node=%u arm=%s flags=0x%x ts=%llu "
		     "cached_inc=%llu — ACTIVE-looking record with a ZERO incarnation; "
		     "retaining the cached incarnation, slot inconsistent",
		     slot, rhb->node_id, arm, rhb->flags,
		     (unsigned long long)rhb->timestamp_ms,
		     (unsigned long long)nt->last_epoch);
}

/*
 * The REQUIRED-match test.  Both sides must name a real published incarnation
 * AND name the same one.  Zero on either side is a REFUSAL, never a
 * match-anything.  Use this everywhere the old `epoch == 0 || a == b` and
 * `epoch && a == b` idioms appeared.
 */
static inline bool inc_eq(mxfs_epoch_t a, mxfs_epoch_t b)
{
	return a != 0 && b != 0 && a == b;
}

/*
 * — the OTHER equality, deliberately named apart from inc_eq.
 *
 * inc_eq() is the CROSS-SOURCE incarnation proof: "these two independently
 * obtained values name the same KNOWN incarnation".  Zero must fail there:
 * zero is never a wildcard, and two unknowns do not identify each other.
 *
 * recov_tok_eq() is the DESCRIPTOR-TOKEN identity: "this token carries exactly
 * the value that was copied out of THIS descriptor".  Zero equals zero there,
 * because it proves only that both encoded the same UNKNOWN — the binding
 * comes from the rest of the descriptor identity (slot, victim node, recovery
 * generation, term, and the owner check that precedes it), never from this
 * field alone.
 *
 * Using inc_eq() for the second meaning made any descriptor whose victim_epoch
 * is legitimately 0 un-advanceable BY ITS OWN OWNER — and recovery_begin()
 * creates exactly that on the P237-RECOV-INC-UNOBSERVED arm, for a caller that
 * never observed the victim's incarnation.  inc_eq(0,0) is false, so the owner
 * failed its own authentication, mxfs_disklock_recovery_advance() returned
 * -EBUSY for ever, the milestone ladder stopped at FENCED, the freeze gate
 * refused to zero the sector, and the dead node's grants stayed frozen with a
 * silent unbounded retry behind them.  MEASURED on the 32-node rig, 
 * slot 4 held RECOVERY_GUARD/stage=2 for 12 minutes and 11 retries while
 * P234-RECOV-NOTOURS printed two IDENTICAL owner tuples as the "evidence" of a
 * takeover that never happened.
 */
static inline bool recov_tok_eq(uint64_t a, uint64_t b)
{
	return a == b;
}

/*
 * C7 version gate — HB feature block (see disklock.h).
 *
 * The crc binds the declaration to the claimant INCARNATION: it covers the
 * feature fields AND the record's identity (fs_gen, node_id, epoch), all
 * serialized little-endian into a packed scratch, so a feature payload
 * spliced next to a different incarnation's header never validates.
 */
static uint32_t hb_feature_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
			       mxfs_epoch_t epoch,
			       const struct mxfs_hb_feature *ft)
{
	struct {
		uint32_t magic;
		uint16_t proto_gen;
		uint16_t feat_flags;
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) b;

	b.magic      = ft->magic;
	b.proto_gen  = ft->proto_gen;
	b.feat_flags = ft->feat_flags;
	b.fs_gen     = fs_gen;
	b.node_id    = (uint32_t)node_id;
	b.epoch      = (uint64_t)epoch;
	return mxfs_pal_crc32c(~0U, &b, sizeof(b));
}

/* Stamp the outgoing record's feature block (identity fields must be set).
 * takes the ctx so ctx->snlocal is carried in feat_flags on EVERY
 * record this incarnation writes — the marker is write-time provenance and
 * must be uniform across the tenure (ruling item 1). */
static void hb_feature_fill(const struct mxfs_disklock_ctx *ctx,
			    struct mxfs_disklock_heartbeat *hb)
{
	hb->feat.magic      = MXFS_HB_FEAT_MAGIC;
	hb->feat.proto_gen  = (uint16_t)MXFS_PROTO_GEN;
	hb->feat.feat_flags = (ctx->snlocal ? MXFS_HB_FEAT_SNLOCAL : 0) |
			      (ctx->claim_fresh ? MXFS_HB_FEAT_ADOPTED : 0) |
			      (ctx->bootstrap_pending ?
				   MXFS_HB_FEAT_BOOTSTRAP_PENDING : 0) |  /* */
						  (ctx->transport_tcp ? MXFS_HB_FEAT_TCP : 0); /* 0.75.0 */
	hb->feat.crc32c     = hb_feature_crc(hb->fs_gen, hb->node_id,
					     hb->epoch, &hb->feat);
}

/*
 * the identity block's crc binds it to the record it sits in —
 * {slot, flags, fs_gen, node_id, epoch} — as well as to its own fields, so a
 * block copied to another slot, another record role (ACTIVE → GUARD), another
 * mkfs generation or another incarnation does not validate.  Corruption and
 * transplant detection only; authenticity comes from the single-writer slot.
 */
static uint32_t hb_ident_crc(uint32_t slot, uint32_t flags, uint32_t fs_gen,
			     mxfs_node_id_t node_id, mxfs_epoch_t epoch,
			     const struct mxfs_hb_identity *id)
{
	struct {
		uint32_t magic;
		uint16_t ver;
		uint16_t key_gen;
		uint8_t  host_uuid[16];
		uint8_t  boot_uuid[16];
		uint64_t pr_key;
		uint32_t host_src;
		uint32_t slot;
		uint32_t flags;
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) b;

	b.magic   = id->magic;
	b.ver     = id->ver;
	b.key_gen = id->key_gen;
	memcpy(b.host_uuid, id->host_uuid, 16);
	memcpy(b.boot_uuid, id->boot_uuid, 16);
	b.pr_key  = id->pr_key;
	b.host_src = id->host_src;
	b.slot    = slot;
	b.flags   = flags;
	b.fs_gen  = fs_gen;
	b.node_id = (uint32_t)node_id;
	b.epoch   = (uint64_t)epoch;
	return mxfs_pal_crc32c(~0U, &b, sizeof(b));
}

/* Stamp the outgoing record's identity block (flags/identity fields must be
 * set).  A ctx without an installed identity (tools, legacy paths) writes a
 * zeroed block, which never validates. */
static void hb_ident_fill(const struct mxfs_disklock_ctx *ctx,
			  struct mxfs_disklock_heartbeat *hb, uint32_t slot)
{
	if (!ctx->own_ident_set) {
		memset(&hb->ident, 0, sizeof(hb->ident));
		return;
	}
	hb->ident = ctx->own_ident;
	hb->ident.crc32c = hb_ident_crc(slot, hb->flags, hb->fs_gen, hb->node_id,
					hb->epoch, &hb->ident);
}

bool mxfs_hb_identity_valid(const struct mxfs_disklock_heartbeat *hb,
			    uint32_t slot)
{
	if (hb->ident.magic != MXFS_HB_IDENT_MAGIC ||
	    hb->ident.ver != MXFS_HB_IDENT_VERSION ||
	    hb->ident.pr_key == 0)
		return false;
	return hb->ident.crc32c == hb_ident_crc(slot, hb->flags, hb->fs_gen,
						hb->node_id, hb->epoch,
						&hb->ident);
}

/*
 * 0.75.77 (D-0933, measured s565): a RECOVERY_GUARD keeps the victim's
 * identity block byte for byte, but the guard writers move `flags` without
 * re-binding the identity crc (only the retirement paths re-bind), and the
 * crc covers the flags — so the block of every guard record read
 * 'identity block invalid' at admission (P-ADMIT-VICTIM-UNFROZEN x6 per
 * node) although it was the victim's own, intact, and exactly what a fence
 * of that victim needs.  Validate it under the state the victim's own writer
 * could have bound it to: ACTIVE at claim, WITHDRAWN or RETIRE_PENDING at a
 * departure.  Every other binding (slot, fs_gen, node, epoch, the block
 * itself) is checked unchanged, so a block copied from another record or
 * another incarnation still fails.  A non-guard record is judged as before.
 */
bool mxfs_hb_guard_identity_valid(const struct mxfs_disklock_heartbeat *hb,
				  uint32_t slot)
{
	static const uint32_t bound_as[] = { MXFS_DISKLOCK_FLAG_ACTIVE,
					     MXFS_DISKLOCK_FLAG_WITHDRAWN,
					     MXFS_DISKLOCK_FLAG_RETIRE_PENDING };
	unsigned int i;

	if (hb->flags != MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
		return mxfs_hb_identity_valid(hb, slot);
	if (hb->ident.magic != MXFS_HB_IDENT_MAGIC ||
	    hb->ident.ver != MXFS_HB_IDENT_VERSION ||
	    hb->ident.pr_key == 0)
		return false;
	for (i = 0; i < sizeof(bound_as) / sizeof(bound_as[0]); i++)
		if (hb->ident.crc32c == hb_ident_crc(slot, bound_as[i], hb->fs_gen,
						     hb->node_id, hb->epoch,
						     &hb->ident))
			return true;
	return false;
}

/*
 * OBSERVE a peer record's identity.  Only ACTIVE and WITHDRAWN
 * records name their own writer as the slot's incarnation (a GUARD names the
 * guard writer and is never consulted).  The observation is keyed by the
 * exact (node_id, epoch); a different key for a tuple already frozen is a
 * protocol violation and poisons the tuple: no fence by key will ever be
 * issued for it from this node.
 */
static void hb_ident_observe(struct mxfs_disklock_ctx *ctx, uint32_t slot,
			     const struct mxfs_disklock_heartbeat *rhb)
{
	struct mxfs_disklock_ident_obs *o = &ctx->ident_obs[slot];

	/* a RETIRE_PENDING record is the writer's own final image
	 * (release_slot re-binds the identity crc to the new flags), so it
	 * names its incarnation's key exactly like ACTIVE/WITHDRAWN — and a
	 * peer that first sees the slot in that state must still be able to
	 * freeze the key for the expiry fence. */
	if (rhb->magic != MXFS_DISKLOCK_MAGIC ||
	    (rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
	     rhb->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN &&
	     rhb->flags != MXFS_DISKLOCK_FLAG_RETIRE_PENDING) ||
		hb_gen_foreign(ctx, rhb) || !inc_valid(rhb->epoch) ||
		!mxfs_hb_identity_valid(rhb, slot))
		return;
	if (o->valid && o->node == rhb->node_id && inc_eq(o->epoch, rhb->epoch)) {
		if (o->key != rhb->ident.pr_key || o->key_gen != rhb->ident.key_gen) {
			if (!o->conflict)
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P-PRKEY-CONFLICT slot=%u node=%u inc=%llu "
				    "frozen=0x%llx/gen%u now=0x%llx/gen%u — ONE incarnation "
				    "published TWO PR keys; protocol violation.  No fence "
				    "by key will be issued for this incarnation from here",
				    slot, rhb->node_id, (unsigned long long)rhb->epoch,
				    (unsigned long long)o->key, o->key_gen,
				    (unsigned long long)rhb->ident.pr_key,
				    rhb->ident.key_gen);
			o->conflict = true;
		}
		return;
	}
	o->node = rhb->node_id;
	o->epoch = rhb->epoch;
	o->key = rhb->ident.pr_key;
	o->key_gen = rhb->ident.key_gen;
	memcpy(o->host_uuid, rhb->ident.host_uuid, 16);   /* */
	memcpy(o->boot_uuid, rhb->ident.boot_uuid, 16);
	o->valid = true;
	o->conflict = false;
}

/* fire_dead: FREEZE the victim's key into the death snapshot for exactly the
 * tuple being declared dead.  Done before expire_cb so the fencer reads the
 * snapshot, never the (possibly successor-rebased) observation. */
static void hb_ident_freeze_victim(struct mxfs_disklock_ctx *ctx,
				   uint32_t slot, mxfs_node_id_t node,
				   mxfs_epoch_t epoch)
{
	const struct mxfs_disklock_ident_obs *o = &ctx->ident_obs[slot];
	bool match = o->valid && !o->conflict && o->node == node &&
		     inc_eq(o->epoch, epoch);

	ctx->pending_key_node[slot]  = node;
	ctx->pending_key_epoch[slot] = epoch;
	ctx->pending_key[slot]       = match ? o->key : 0;
	ctx->pending_key_gen[slot]   = match ? o->key_gen : 0;
	if (match) {
		memcpy(ctx->pending_host[slot], o->host_uuid, 16);  /* */
		memcpy(ctx->pending_boot[slot], o->boot_uuid, 16);
	} else {
		memset(ctx->pending_host[slot], 0, 16);
		memset(ctx->pending_boot[slot], 0, 16);
	}
	if (!match)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-PRKEY-VICTIM-UNKNOWN slot=%u node=%u inc=%llu "
			     "obs{valid=%d conflict=%d node=%u inc=%llu} — no PR "
			     "key frozen for this exact incarnation; a fence of it "
			     "from this node will be REFUSED (NO_VICTIM_KEY)",
			     slot, node, (unsigned long long)epoch, o->valid,
			     o->conflict, o->node, (unsigned long long)o->epoch);
}

bool mxfs_disklock_victim_identity(struct mxfs_disklock_ctx *ctx, int slot,
				   mxfs_node_id_t node, mxfs_epoch_t epoch,
				   uint8_t host_uuid[16], uint8_t boot_uuid[16])
{
	bool ok = false;

	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return false;
	mxfs_pal_mutex_lock(ctx->lock);
	if (ctx->pending_key_node[slot] == node &&
	    inc_eq(ctx->pending_key_epoch[slot], epoch) &&
	    ctx->pending_key[slot]) {
		if (host_uuid)
			memcpy(host_uuid, ctx->pending_host[slot], 16);
		if (boot_uuid)
			memcpy(boot_uuid, ctx->pending_boot[slot], 16);
		ok = true;
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	return ok;
}

bool mxfs_disklock_host_live_other_boot(struct mxfs_disklock_ctx *ctx,
					const uint8_t host_uuid[16],
					const uint8_t boot_uuid[16],
					mxfs_node_id_t *live_node,
					int *live_slot)
{
	bool found = false;
	uint32_t slot;

	if (!ctx || !host_uuid || !boot_uuid)
		return false;
	mxfs_pal_mutex_lock(ctx->lock);
	if (ctx->own_ident_set &&
	    memcmp(ctx->own_ident.host_uuid, host_uuid, 16) == 0 &&
	    memcmp(ctx->own_ident.boot_uuid, boot_uuid, 16) != 0) {
		if (live_node)
			*live_node = ctx->local_node;
		if (live_slot)
			*live_slot = ctx->local_slot;
		found = true;
	}
	for (slot = 0; !found && slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		const struct mxfs_disklock_ident_obs *o = &ctx->ident_obs[slot];

		if ((int)slot == ctx->local_slot || !ctx->monitored[slot] ||
		    !ctx->node_track[slot].live || !o->valid || o->conflict ||
		    o->node != ctx->slot_node_id[slot])
			continue;
		if (memcmp(o->host_uuid, host_uuid, 16) == 0 &&
		    memcmp(o->boot_uuid, boot_uuid, 16) != 0) {
			if (live_node)
				*live_node = o->node;
			if (live_slot)
				*live_slot = (int)slot;
			found = true;
		}
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	return found;
}

int mxfs_disklock_key_live_elsewhere(struct mxfs_disklock_ctx *ctx,
				     uint64_t key, mxfs_node_id_t excl_node,
				     mxfs_node_id_t *live_node,
				     int *live_slot)
{
	int found = 0;
	uint32_t slot;

	if (!ctx || !key)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->lock);

	/*
	 * This node's own registration first.  A fencer preempting a key equal to
	 * its own would preempt itself; the DLM layer already refuses that case
	 * separately, but the primitive must not depend on the caller having done
	 * it.
	 */
	if (ctx->own_ident_set && ctx->own_ident.pr_key == key &&
	    ctx->local_node != excl_node) {
		if (live_node)
			*live_node = ctx->local_node;
		if (live_slot)
			*live_slot = ctx->local_slot;
		found = 1;
	}

	for (slot = 0; !found && slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		const struct mxfs_disklock_ident_obs *o = &ctx->ident_obs[slot];

		if ((int)slot == ctx->local_slot || !ctx->monitored[slot] ||
		    !ctx->node_track[slot].live || !o->valid || o->conflict ||
		    o->node != ctx->slot_node_id[slot])
			continue;
		if (o->key != key)
			continue;
		/*
		 * Exclude the incarnation being fenced, by NODE.  A mount's node_id is
		 * derived from a per-mount uuid (uuid_to_node_id at DLM init), so a
		 * successor on the victim's host carries a DIFFERENT node_id while
		 * carrying the SAME per-boot PR key — it is therefore not excluded
		 * here and is correctly reported.  Excluding by node rather than by
		 * liveness alone also keeps a legitimate fence working if the victim's
		 * record has not yet been marked not-live, which matters because this
		 * guard fails closed and a false positive would stall recovery.
		 */
		if (o->node == excl_node)
			continue;
		if (live_node)
			*live_node = o->node;
		if (live_slot)
			*live_slot = (int)slot;
		found = 1;
	}

	mxfs_pal_mutex_unlock(ctx->lock);
	return found;
}

int mxfs_disklock_boot_advancing(struct mxfs_disklock_ctx *ctx,
				 const uint8_t boot_uuid[16], bool *advancing,
				 int *records)
{
	struct mxfs_disklock_heartbeat *a, *b;
	uint32_t slot;
	int rc = 0, n = 0;

	if (!ctx || !ctx->dev || !boot_uuid || !advancing)
		return -EINVAL;
	*advancing = false;
	a = mxfs_pal_alloc(sizeof(*a) * MXFS_DISKLOCK_HB_SLOTS);
	b = mxfs_pal_alloc(sizeof(*b));
	if (!a || !b) {
		rc = -ENOMEM;
		goto out;
	}
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, &a[slot], sizeof(a[slot]));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			goto out;
	}
	mxfs_pal_sleep_ms(2500);            /* > one heartbeat interval (2 s) */
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		const struct mxfs_disklock_heartbeat *r = &a[slot];
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

		if (r->magic != MXFS_DISKLOCK_MAGIC ||
		    (r->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
		     r->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN &&
		     r->flags != MXFS_DISKLOCK_FLAG_RETIRE_PENDING) ||
			!mxfs_hb_identity_valid(r, slot) ||
			memcmp(r->ident.boot_uuid, boot_uuid, 16) != 0)
			continue;
		n++;
		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, b, sizeof(*b));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			goto out;
		if (b->magic == MXFS_DISKLOCK_MAGIC && b->node_id == r->node_id &&
		    inc_eq(b->epoch, r->epoch) &&
		    b->timestamp_ms != r->timestamp_ms) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P238-BOOT-ADVANCING slot=%u node=%u inc=%llu — "
				     "a record carrying the victim's boot_uuid is "
				     "heartbeating (clone / snapshot-resumed copy); no boot "
				     "boundary can be claimed for that boot",
				     slot, r->node_id, (unsigned long long)r->epoch);
			*advancing = true;
		}
	}
	rc = 0;
out:
	if (records)
		*records = n;
	mxfs_pal_free(a);
	mxfs_pal_free(b);
	return rc;
}

int mxfs_disklock_deaths_undeclared(struct mxfs_disklock_ctx *ctx,
				    unsigned int *window_ms)
{
	int n = 0;
	uint32_t slot;

	if (window_ms)
		*window_ms = 0;
	if (!ctx)
		return 0;
	mxfs_pal_mutex_lock(ctx->lock);
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		const struct mxfs_disklock_node_track *nt = &ctx->node_track[slot];

		if ((int)slot == ctx->local_slot || !ctx->monitored[slot] ||
		    nt->live || nt->last_timestamp == 0 ||
		    ctx->recovery_pending[slot])
			continue;
		n++;
	}
	if (window_ms)
		*window_ms = (unsigned int)ctx->dead_threshold *
			     MXFS_DISKLOCK_HB_INTERVAL_MS;
	mxfs_pal_mutex_unlock(ctx->lock);
	return n;
}

uint64_t mxfs_disklock_victim_key(struct mxfs_disklock_ctx *ctx, int slot,
				  mxfs_node_id_t node, mxfs_epoch_t epoch,
				  uint32_t *key_gen)
{
	uint64_t key = 0;

	if (key_gen)
		*key_gen = 0;
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return 0;
	mxfs_pal_mutex_lock(ctx->lock);
	if (ctx->pending_key_node[slot] == node &&
	    inc_eq(ctx->pending_key_epoch[slot], epoch)) {
		key = ctx->pending_key[slot];
		if (key_gen)
			*key_gen = ctx->pending_key_gen[slot];
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	return key;
}

int mxfs_disklock_set_identity(struct mxfs_disklock_ctx *ctx,
			       const uint8_t host_uuid[16],
			       const uint8_t boot_uuid[16],
			       uint32_t host_src, uint64_t pr_key,
			       uint32_t key_gen)
{
	if (!ctx || !host_uuid || !boot_uuid || !pr_key)
		return -EINVAL;
	if (ctx->local_slot >= 0)
		return -EBUSY;
	memset(&ctx->own_ident, 0, sizeof(ctx->own_ident));
	ctx->own_ident.magic   = MXFS_HB_IDENT_MAGIC;
	ctx->own_ident.ver     = MXFS_HB_IDENT_VERSION;
	ctx->own_ident.key_gen = (uint16_t)key_gen;
	memcpy(ctx->own_ident.host_uuid, host_uuid, 16);
	memcpy(ctx->own_ident.boot_uuid, boot_uuid, 16);
	ctx->own_ident.pr_key  = pr_key;
	ctx->own_ident.host_src = host_src;
	ctx->own_ident_set = true;
	return 0;
}

#define MXFS_HBFEAT_OK        0
#define MXFS_HBFEAT_LEGACY    1   /* pre-gate writer: all-zero tail */
#define MXFS_HBFEAT_MISMATCH  2   /* gate-aware, different proto_gen */
#define MXFS_HBFEAT_CORRUPT   3   /* bad magic or crc */
#define MXFS_HBFEAT_TRANSPORT 4   /* 0.75.0: valid block, other DLM transport */

static int hb_feature_state(const struct mxfs_disklock_heartbeat *hb)
{
	if (hb->feat.magic == 0 && hb->feat.proto_gen == 0 &&
	    hb->feat.feat_flags == 0 && hb->feat.crc32c == 0)
		return MXFS_HBFEAT_LEGACY;
	if (hb->feat.magic != MXFS_HB_FEAT_MAGIC)
		return MXFS_HBFEAT_CORRUPT;
	if (hb->feat.crc32c != hb_feature_crc(hb->fs_gen, hb->node_id,
					      hb->epoch, &hb->feat))
		return MXFS_HBFEAT_CORRUPT;
	if (hb->feat.proto_gen != (uint16_t)MXFS_PROTO_GEN)
		return MXFS_HBFEAT_MISMATCH;
	return MXFS_HBFEAT_OK;
}

/*
 * did this victim record durably classify itself single-node-local?
 * Fail-closed: only a VALID feature block (crc binds it to the record's own
 * identity triple) may assert the marker — LEGACY, MISMATCH and CORRUPT
 * tails all read as "not snlocal", so a torn or foreign-generation record
 * can never unlock the untagged-replay path.
 */
static bool hb_victim_snlocal(const struct mxfs_disklock_heartbeat *hb)
{
	return hb_feature_state(hb) == MXFS_HBFEAT_OK &&
	       (hb->feat.feat_flags & MXFS_HB_FEAT_SNLOCAL);
}

/*
 * did this victim record durably classify its claim as a pass-2
 * fresh claim (slice ADOPTED)?  Same fail-closed rule as snlocal: only a
 * VALID feature block may assert it.
 */
static bool hb_victim_adopted(const struct mxfs_disklock_heartbeat *hb)
{
	return hb_feature_state(hb) == MXFS_HBFEAT_OK &&
	       (hb->feat.feat_flags & MXFS_HB_FEAT_ADOPTED);
}

/*
 * 0.75.0: does this record's VALID feature block name the other DLM
 * transport?  A record that cannot vote (LEGACY / CORRUPT / other proto_gen)
 * is not a mismatch here — the version gate already owns those.
 */
static bool hb_transport_mismatch(const struct mxfs_disklock_ctx *ctx,
				  const struct mxfs_disklock_heartbeat *hb)
{
	if (hb_feature_state(hb) != MXFS_HBFEAT_OK)
		return false;
	return !!(hb->feat.feat_flags & MXFS_HB_FEAT_TCP) != ctx->transport_tcp;
}

int mxfs_disklock_scan_transport(mxfs_bdev_t *dev, uint64_t base_offset,
				 uint32_t fs_gen,
				 struct mxfs_disklock_transport_census *c)
{
	struct mxfs_disklock_heartbeat *hb;
	uint32_t slot;
	int rc = 0;

	if (!dev || !c)
		return -EINVAL;
	memset(c, 0, sizeof(*c));
	c->first_tcp = -1;
	c->first_caw = -1;
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

		rc = mxfs_pal_bdev_read(dev, off, hb, sizeof(*hb));
		if (rc < 0)
			break;          /* fail closed: the caller refuses on an unread table */
		if (hb->magic != MXFS_DISKLOCK_MAGIC)
			continue;
		if (hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
		    hb->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN)
			continue;       /* empty, guard, retire-pending: not a tenure's own word */
		if (hb->fs_gen == 0 || hb->fs_gen != fs_gen)
			continue;       /* pre-mkfs ghost / legacy */
		if (hb_feature_state(hb) != MXFS_HBFEAT_OK) {
			c->n_unknown++;
			continue;
		}
		if (hb->feat.feat_flags & MXFS_HB_FEAT_TCP) {
			if (c->first_tcp < 0)
				c->first_tcp = (int)slot;
			c->n_tcp++;
		} else {
			if (c->first_caw < 0)
				c->first_caw = (int)slot;
			c->n_caw++;
		}
	}
	mxfs_pal_free(hb);
	return rc < 0 ? rc : 0;
}

/*
 * ── (#92): CLAIM PROVENANCE — parsing/derivation side ────────────
 *
 * See the block comment above struct mxfs_hb_provenance in disklock.h for
 * the protocol.  The crc mirrors hb_feature_crc: it covers the provenance
 * fields AND the record's identity triple, serialized little-endian into a
 * packed scratch, so a provenance block spliced next to a different
 * incarnation's header never validates.
 */
static uint32_t hb_prov_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
			    mxfs_epoch_t epoch,
			    const struct mxfs_hb_provenance *pv)
{
	struct {
		uint32_t magic;
		uint32_t prev_node;
		uint64_t prev_epoch;
		uint64_t slot_seq;
		uint32_t chain_len;
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) b;

	b.magic      = pv->magic;
	b.prev_node  = pv->prev_node;
	b.prev_epoch = (uint64_t)pv->prev_epoch;
	b.slot_seq   = pv->slot_seq;
	b.chain_len  = pv->chain_len;
	b.fs_gen     = fs_gen;
	b.node_id    = (uint32_t)node_id;
	b.epoch      = (uint64_t)epoch;
	return mxfs_pal_crc32c(~0U, &b, sizeof(b));
}

/* Fail-closed validity: only a block whose magic AND identity-bound crc
 * both check may feed the lineage test.  Pre-carve records carry zeros
 * here (magic 0 ⇒ invalid ⇒ conservative fire). */
static bool hb_prov_valid(const struct mxfs_disklock_heartbeat *hb)
{
	return hb->prov.magic == MXFS_HB_PROV_MAGIC &&
	       hb->prov.crc32c == hb_prov_crc(hb->fs_gen, hb->node_id,
					      hb->epoch, &hb->prov);
}

/*
 * (#92): does this record read as the CLEAN RELEASE STAMP of the
 * expected occupant?  mxfs_disklock_release_slot() CAS-writes the node's
 * own final ACTIVE image with flags flipped to EMPTY, so a clean departure
 * leaves {magic, node_id, epoch, fs_gen} intact under FLAG_EMPTY.
 * the release now writes RETIRE_PENDING and the EMPTY image is
 * produced by whoever proves the PR key absent (hb_retire_settle on a peer,
 * or retire_complete_self); the stamp's shape is unchanged.  An
 * expected epoch we never observed (0) degrades to the node-scoped test —
 * safe here because the ONLY consequence of a match is a clean retire
 * (no fence, no recovery, no slot write).  node == 0 never matches: a
 * snapshot that names nobody identifies nothing.
 */
static bool hb_clean_empty_match(const struct mxfs_disklock_ctx *ctx,
				 const struct mxfs_disklock_heartbeat *hb,
				 mxfs_node_id_t node, mxfs_epoch_t epoch)
{
	if (hb->magic != MXFS_DISKLOCK_MAGIC)
		return false;
	if (hb->flags != MXFS_DISKLOCK_FLAG_EMPTY)
		return false;
	if (hb_gen_foreign(ctx, hb))
		return false;
	if (node == 0 || hb->node_id != node)
		return false;
	if (!inc_valid(epoch))
		return true;            /* degrade to node scope */
	return inc_eq(hb->epoch, epoch);
}

/*
 * ── RETIRE_PENDING settlement ───────────────────────────────────
 *
 * See MXFS_DISKLOCK_FLAG_RETIRE_PENDING in disklock.h.  A record in this
 * state is the departing node's own final image with the flag moved; the
 * identity block (and its crc, re-bound to the flags) still names the key
 * that must be gone before the slot may be consumed.
 */

/* Re-bind an identity block we are about to re-flag: the crc covers flags,
 * and a peer completing (or expiring) the retirement keeps every other
 * field byte for byte — same rule as a recovery GUARD: only `flags` moves. */
static void hb_ident_rebind(struct mxfs_disklock_heartbeat *hb, uint32_t slot)
{
	if (hb->ident.magic != MXFS_HB_IDENT_MAGIC)
		return;                 /* zeroed block never validates anyway */
	hb->ident.crc32c = hb_ident_crc(slot, hb->flags, hb->fs_gen, hb->node_id,
					hb->epoch, &hb->ident);
}

static bool hb_retire_pending(const struct mxfs_disklock_ctx *ctx,
			      const struct mxfs_disklock_heartbeat *hb)
{
	return hb->magic == MXFS_DISKLOCK_MAGIC &&
	       hb->flags == MXFS_DISKLOCK_FLAG_RETIRE_PENDING &&
	       !hb_gen_foreign(ctx, hb);
}

/*
 * (0.60.0, design-consult review #3 condition 8 / hazard H8): every
 * settlement of a RETIRE_PENDING record — EMPTY, WITHDRAWN, the P305 own
 * settle, the self-complete and the departing node's WITHDRAWN re-stamp —
 * is an exact-image COMPARE AND WRITE.  Until 0.59.3 an -EOPNOTSUPP from the
 * CAS fell back to a plain FUA write of the wanted image: an unconditional
 * overwrite of a sector that may have moved since the confirming read (a
 * claimant's ACTIVE record, a peer's settlement), which is precisely the race
 * the CAS exists to lose safely.  Admission already refuses a device whose
 * lock-slot CAS is not operational (P311-CAW-ADMISSION-REFUSED, D-0359), so
 * this is reachable only on runtime CAW loss — and then the record must stay
 * byte-for-byte unchanged.  Logged once per slot; the caller treats it as
 * "not settled this lap".  The same rule covers every other exact-image
 * record write (heartbeat, release, withdraw stamp, recovery milestone):
 * the /read-verify-write and FUA+read-back stand-ins for a
 * missing CAW are gone (0.60.0, D7 companion).  claim_slot_noncaw stays:
 * it writes only an EMPTY sector, before admission, and P311 then refuses
 * the mount.
 */
static void hb_cas_nocaw_locked(struct mxfs_disklock_ctx *ctx, uint32_t slot,
				const char *what)
{
	bool first;

	/* ctx->lock held by the caller */
	first = slot < MXFS_DISKLOCK_HB_SLOTS && !ctx->retire_nocaw_logged[slot];
	if (slot < MXFS_DISKLOCK_HB_SLOTS)
		ctx->retire_nocaw_logged[slot] = true;
	if (first)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P304-CAS-NOCAW slot=%u op=%s — COMPARE AND WRITE "
			     "reported unsupported on a record write that must be "
			     "an exact-image CAS; refusing to emulate it with an "
			     "unconditional write.  The record is left unchanged "
			     "(fail closed) until CAW works again",
			     slot, what);
}

static void hb_cas_nocaw(struct mxfs_disklock_ctx *ctx, uint32_t slot,
			 const char *what)
{
	mxfs_pal_mutex_lock(ctx->lock);
	hb_cas_nocaw_locked(ctx, slot, what);
	mxfs_pal_mutex_unlock(ctx->lock);
}

/*
 * (0.61.6, review #5 condition 4): every exact-image record CAS of
 * the writer classes above goes through hb_caw(), so the runtime-CAW-loss
 * arm (module param dbg_cas_nocaw_ops, a bitmask of HB_CAW_OP_*) can make
 * ONE class report -EOPNOTSUPP on a healthy LUN without issuing the command
 * — tests/cas_nocaw_arms.sh then asserts the fail-closed disposition of that
 * class and that the sector stays byte-identical.  In production the mask
 * reads 0 and this is exactly the PAL call.  The op names are the `what`
 * strings P304-CAS-NOCAW already prints.
 */
enum {
	HB_CAW_OP_HEARTBEAT     = 1u << 0,
	HB_CAW_OP_RELEASE       = 1u << 1,
	HB_CAW_OP_WITHDRAW      = 1u << 2,   /* voluntary own WITHDRAWN stamp */
	HB_CAW_OP_WITHDRAWN     = 1u << 3,   /* peer expiry RETIRE_PENDING -> WITHDRAWN */
	HB_CAW_OP_RESTAMP       = 1u << 4,
	HB_CAW_OP_COMPLETE_SELF = 1u << 5,
	HB_CAW_OP_EMPTY         = 1u << 6,   /* peer settle -> EMPTY */
	HB_CAW_OP_SETTLE_OWN    = 1u << 7,   /* P305 own settle -> EMPTY */
	HB_CAW_OP_MILESTONE     = 1u << 8,   /* recov_cas_durable */
	HB_CAW_OP_GUARD         = 1u << 9,
	HB_CAW_OP_GUARD_REFRESH = 1u << 10,
	HB_CAW_OP_GUARD_ZERO    = 1u << 11,
};

static int hb_caw(struct mxfs_disklock_ctx *ctx, unsigned int op,
		  const char *what, uint64_t off,
		  const void *expect, const void *want)
{
	if (mxfs_pal_dbg_cas_nocaw(op, what))
		return -EOPNOTSUPP;
	return mxfs_pal_bdev_compare_and_write(ctx->dev, off, expect, want);
}

/* the settlement vocabulary is exported (disklock.h) so the mount
 * thread can act on it; the short names stay for the monitor's arms. */
#define HB_RETIRE_EMPTY     MXFS_DISKLOCK_RETIRE_EMPTY
#define HB_RETIRE_WAITING   MXFS_DISKLOCK_RETIRE_WAITING
#define HB_RETIRE_WITHDRAWN MXFS_DISKLOCK_RETIRE_WITHDRAWN
#define HB_RETIRE_CHANGED   MXFS_DISKLOCK_RETIRE_CHANGED

/*
 * (design-consult STOP-SHIP blocker 1): after a CAS mismatch the caller may
 * classify ONLY the sector's current image, never the stale RETIRE_PENDING
 * one.  A peer that lost the CAS to another settler (record now EMPTY) or
 * to a claimant (record now ACTIVE for a NEW incarnation) and then fell
 * through with the pending image would run "WITHDRAWN/other → fire_dead":
 * false death processing, a fence and a replay against a slot a new
 * incarnation already owns.  So CHANGED always carries a fresh FUA image
 * in *rhb, or a negative rc that no caller classifies.
 */
static int hb_retire_reread(struct mxfs_disklock_ctx *ctx, uint64_t off,
			    struct mxfs_disklock_heartbeat *rhb)
{
	int rc;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
	mxfs_pal_mutex_unlock(ctx->lock);
	return rc ? rc : HB_RETIRE_CHANGED;
}

static const char *hb_key_state_name(int st)
{
	switch (st) {
	case MXFS_DISKLOCK_KEY_ABSENT:  return "ABSENT";
	case MXFS_DISKLOCK_KEY_PRESENT: return "PRESENT";
	default:                        return "UNKNOWN";
	}
}

/*
 * Settle a RETIRE_PENDING record.  `rhb` holds the plain read that showed
 * the flag; on return it holds the sector's current image (a FUA confirm,
 * then whatever CAS landed, then a re-read if the CAS was lost).
 * Heartbeat-thread context, or the mount thread via
 * mxfs_disklock_retire_settle_slot (immediate = no grace).
 *
 * The key that must be gone is named by the record's own identity block,
 * failing that by the frozen death-time observation of this EXACT
 * incarnation.  Neither → UNKNOWN (blocker 3: an unnamed key is not "no
 * key"; publishing EMPTY there would destroy the only fencing evidence).
 * A valid identity that disagrees with a frozen observation of the same
 * incarnation is a protocol violation: UNKNOWN, loudly.  (design-consult
 * STOP-SHIP #2 blocker 2): a valid identity recording key 0 is NOT
 * "nothing to retire" — a clustered incarnation must have registered a
 * nonzero validated key, so key 0 is an invalid record: UNKNOWN, never
 * ABSENT (0.59.1 published such a record EMPTY on no evidence).  The only
 * settlements of a key-0 record are the departing mount's own
 * retire_complete_self under a single-node/override admission, and P305's
 * topology settle under single_node_exclusive.  Then the tri-state lookup
 * decides (the ASYNC callback for the monitor, the SYNC one for
 * an immediate settlement on the mount thread; there is no OWN):
 *   ABSENT                → CAS to EMPTY (consumable)
 *   PRESENT, in grace     → WAITING (monitor) / WITHDRAWN (immediate)
 *   PRESENT, past grace   → CAS to WITHDRAWN (fence pipeline owns it)
 *   UNKNOWN               → WAITING, forever if need be; escalate per grace
 */
static int hb_retire_settle(struct mxfs_disklock_ctx *ctx, uint32_t slot,
			    uint64_t off, struct mxfs_disklock_heartbeat *rhb,
			    bool immediate)
{
	struct mxfs_disklock_heartbeat *want;
	uint64_t key = 0, now, seen, grace;
	int kstate = MXFS_DISKLOCK_KEY_UNKNOWN;
	bool key_known = false, first_sight;
	const char *kreason;
	int rc;

	/* FUA confirm: the plain monitor read is cacheable. */
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc)
		return rc;
	if (!hb_retire_pending(ctx, rhb))
		return HB_RETIRE_CHANGED;

	{
		const struct mxfs_disklock_ident_obs *o = &ctx->ident_obs[slot];
		bool ident_ok = mxfs_hb_identity_valid(rhb, slot);
		bool obs_ok;

		mxfs_pal_mutex_lock(ctx->lock);
		obs_ok = o->valid && !o->conflict && o->node == rhb->node_id &&
			 inc_eq(o->epoch, rhb->epoch);
		if (ident_ok && obs_ok && o->key != rhb->ident.pr_key) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P304-RETIRE-KEY-CONFLICT slot=%u node=%u "
				     "inc=%llu ident_key=0x%llx frozen_key=0x%llx — the "
				     "release record and the frozen observation name "
				     "different keys for one incarnation; the key is "
				     "UNKNOWN (this record will never be published EMPTY "
				     "on that evidence)",
				     slot, rhb->node_id, (unsigned long long)rhb->epoch,
				     (unsigned long long)rhb->ident.pr_key,
				     (unsigned long long)o->key);
			kreason = "key-conflict";
		} else if (ident_ok) {
			key = rhb->ident.pr_key;
			key_known = true;
			kreason = "ident";
		} else if (obs_ok) {
			key = o->key;
			key_known = true;
			kreason = "frozen-obs";
		} else {
			kreason = "unnamed";
		}
		mxfs_pal_mutex_unlock(ctx->lock);
	}
	if (key_known && key == 0) {
		/* (blocker 2): the record's identity names key 0.  A
		 * clustered incarnation never has key 0 (fence-capability
		 * admission requires a registered key), so this is not "no key to
		 * retire" — it is a record nobody can prove anything about. */
		kstate = MXFS_DISKLOCK_KEY_UNKNOWN;
		kreason = "key0-invalid";
	} else if (key_known && !immediate) {
		/* monitor: the async table decides PRESENT (grace/WITHDRAWN);
		 * anything else goes to the settle worker below (D1). */
		mxfs_disklock_key_state_fn fn = ctx->key_state_fn;

		if (fn) {
			kstate = fn(ctx->key_state_data, key);
			if (kstate < MXFS_DISKLOCK_KEY_ABSENT ||
			    kstate > MXFS_DISKLOCK_KEY_UNKNOWN)
				kstate = MXFS_DISKLOCK_KEY_UNKNOWN;
		} else {
			kreason = "no-key-state-fn";
		}
	}

	want = mxfs_pal_alloc(sizeof(*want));
	if (!want)
		return -ENOMEM;
	*want = *rhb;

	now = mxfs_pal_time_ms();
	mxfs_pal_mutex_lock(ctx->lock);
	first_sight = ctx->retire_seen_ms[slot] == 0 ||
		      ctx->retire_seen_node[slot] != rhb->node_id ||
		      !inc_eq(ctx->retire_seen_epoch[slot], rhb->epoch);
	if (first_sight) {
		ctx->retire_seen_ms[slot]    = now;
		ctx->retire_seen_node[slot]  = rhb->node_id;
		ctx->retire_seen_epoch[slot] = rhb->epoch;
		ctx->retire_unknown_log_ms[slot] = 0;
	}
	seen = ctx->retire_seen_ms[slot];
	mxfs_pal_mutex_unlock(ctx->lock);
	if (first_sight)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P304-RETIRE-PENDING-SEEN slot=%u node=%u inc=%llu "
			     "key=0x%llx state=%s via=%s immediate=%d — clean release "
			     "awaiting proof that its PR key is retired",
			     slot, rhb->node_id, (unsigned long long)rhb->epoch,
			     (unsigned long long)key, hb_key_state_name(kstate),
			     kreason, immediate);

	/*
	 * (0.61.0, D1): the destructive EMPTY publication is never made
	 * here from a table answer.  A key the monitor's table does not show
	 * PRESENT (ABSENT candidate or UNKNOWN) is handed to the settle worker,
	 * which proves absence with a fresh bracket under the departure mutex
	 * and CASes inside that proof; the mount thread (immediate) does the
	 * same inline.  PRESENT from the table keeps the grace/WITHDRAWN rule.
	 */
	if (key_known && key != 0 &&
	    (immediate || kstate != MXFS_DISKLOCK_KEY_PRESENT)) {
		if (!ctx->settle_absent_fn) {
			kreason = "no-settle-fn";
			kstate = MXFS_DISKLOCK_KEY_UNKNOWN;
		} else {
			rc = ctx->settle_absent_fn(ctx->settle_absent_data, slot, key,
						   rhb, immediate);
			if (rc == MXFS_DISKLOCK_RETIRE_PRESENT) {
				kstate = MXFS_DISKLOCK_KEY_PRESENT;   /* fall to the rule */
			} else if (rc == HB_RETIRE_WAITING && !immediate) {
				kstate = MXFS_DISKLOCK_KEY_UNKNOWN;   /* enqueued: the
													   * UNKNOWN arm below
													   * keeps the stalled
													   * escalation */
			} else {
				goto out;   /* EMPTY / CHANGED / WAITING (no proof) / <0 */
			}
		}
	}

	if (kstate == MXFS_DISKLOCK_KEY_UNKNOWN) {
		/*
		 * No PR evidence either way: never EMPTY (would publish a
		 * consumable slot beside a possibly write-capable registration),
		 * never WITHDRAWN (would age a lack of evidence into a recovery
		 * action that assumes a usable PR context).  The record stays
		 * RETIRE_PENDING; the admission barrier holds on it; say so once
		 * per grace so a stalled departure is diagnosable.
		 */
		if (now - seen >= MXFS_DISKLOCK_RETIRE_GRACE_MS &&
		    now - ctx->retire_unknown_log_ms[slot] >=
			MXFS_DISKLOCK_RETIRE_GRACE_MS) {
			ctx->retire_unknown_log_ms[slot] = now;
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P304-RETIRE-UNKNOWN-STALLED slot=%u node=%u "
				     "inc=%llu key=0x%llx via=%s waited=%llu ms — the PR "
				     "key cannot be classified from this node (no PR "
				     "context, READ KEYS failing, truncated view, our own "
				     "registration or the fencing reservation not in "
				     "force, or an unnamed key); the record stays "
				     "RETIRE_PENDING, this slot is NOT consumable and "
				     "admission holds on it until a node with PR "
				     "evidence settles it",
				     slot, rhb->node_id, (unsigned long long)rhb->epoch,
				     (unsigned long long)key, kreason,
				     (unsigned long long)(now - seen));
		}
		rc = HB_RETIRE_WAITING;
		goto out;
	}

	/* PRESENT */
	grace = immediate ? MXFS_DISKLOCK_RETIRE_MOUNT_GRACE_MS :
			    MXFS_DISKLOCK_RETIRE_GRACE_MS;
	if (now - seen < grace) {
		/*
		 * D-0965: the mount thread used to withdraw a PRESENT key at once
		 * ("settle NOW rather than admit and wait").  Measured 2/2 laps on
		 * the 2-node TCP rig (s49ctl): the key was PRESENT because the
		 * record's own host was remounting in the same boot and had just
		 * re-registered the identical per-boot key, 0.2-3 s before it
		 * could settle its predecessor's record; the peer stamped the
		 * record WITHDRAWN 817 ms after first sight, froze the predecessor
		 * as a victim and PREEMPT-AND-ABORTed the key, which removed the
		 * live successor's registration and refused its mount
		 * (P303-FENCECAP-SELFABSENT).  The target cannot tell "the
		 * departure never unregistered" from "the successor registered the
		 * same key", and the live-member guard cannot see a successor that
		 * has not claimed a slot yet.  What safety requires is only that
		 * this mount does not go writable beside the registration: hold
		 * admission (P-ADMIT-RETIRE-PENDING-HELD, the barrier re-sweeps)
		 * and give the same first-sight grace the monitor gives; a
		 * successor settles EMPTY within a second, a departure that truly
		 * never finished is withdrawn after the grace as before.  Ruled by
		 * design consult (design review, 2026-09-18): expiry authorises recovery,
		 * it proves nothing; the grace starts at first sight and is never
		 * reset by a barrier round.  The mount thread's grace is the
		 * shorter MXFS_DISKLOCK_RETIRE_MOUNT_GRACE_MS: its wait, the
		 * withdraw's fence and the replay must all fit the admission
		 * barrier's bound (measured: the full grace expired at 29.3 s of
		 * the 30 s bound; see the constant).
		 */
		if (immediate &&
		    now - ctx->retire_present_log_ms[slot] >= grace) {
			ctx->retire_present_log_ms[slot] = now;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: P304-RETIRE-PRESENT-GRACE slot=%u node=%u "
				     "inc=%llu key=0x%llx via=%s seen=%llu ms ago — the "
				     "key is still registered after a clean release; a "
				     "same-boot successor re-registers the identical key "
				     "before it can settle this record, so admission is "
				     "held for the grace instead of withdrawing and "
				     "fencing at once",
				     slot, rhb->node_id, (unsigned long long)rhb->epoch,
				     (unsigned long long)key, kreason,
				     (unsigned long long)(now - seen));
		}
		rc = HB_RETIRE_WAITING;
		goto out;
	}

	/* Key still present past the grace (or the mount thread is not
	 * willing to wait beside it): the departure never finished.  Hand the
	 * record to the withdraw pipeline — fence the key, replay the
	 * (clean) slice, purge the slot.  Only `flags` moves. */
	want->flags = MXFS_DISKLOCK_FLAG_WITHDRAWN;
	hb_ident_rebind(want, slot);
	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_WITHDRAWN, "withdrawn", off, rhb, want);
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == -EOPNOTSUPP) {
		hb_cas_nocaw(ctx, slot, "withdrawn");
		rc = HB_RETIRE_WAITING;
	} else if (rc == 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P304-RETIRE-EXPIRED-WITHDRAWN slot=%u node=%u "
			     "inc=%llu key=0x%llx via=%s immediate=%d after %llu ms — "
			     "the PR key is still registered; stamping WITHDRAWN so "
			     "the cluster fences the key and recovers the slot",
			     slot, rhb->node_id, (unsigned long long)rhb->epoch,
			     (unsigned long long)key, kreason, immediate,
			     (unsigned long long)(now - seen));
		*rhb = *want;
		ctx->retire_seen_ms[slot] = 0;
		rc = HB_RETIRE_WITHDRAWN;
	} else if (rc == -EAGAIN) {
		rc = hb_retire_reread(ctx, off, rhb);
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P304-RETIRE-EXPIRE-WRITEFAIL slot=%u rc=%d — "
			     "retrying next lap", slot, rc);
	}
out:
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_retire_settle_slot(struct mxfs_disklock_ctx *ctx,
				     uint32_t slot, bool immediate)
{
	struct mxfs_disklock_heartbeat *rhb;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	rhb = mxfs_pal_alloc(sizeof(*rhb));
	if (!rhb)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == 0 && !hb_retire_pending(ctx, rhb))
		rc = -ENOENT;
	if (rc == 0)
		rc = hb_retire_settle(ctx, slot, off, rhb, immediate);
	mxfs_pal_free(rhb);
	return rc;
}

/*
 * (#92): derive THIS tenancy's provenance from the record the
 * claim is about to consume, and remember it in ctx->own_prov for every
 * subsequent own-record write of this incarnation.  Called with the claim
 * identity (local_node, fs_gen, epoch) already final.
 *
 *   own-stamp reclaim (pass 1)      → predecessor is our own DIRTY record:
 *                                     continue the seq (peers' lineage
 *                                     windows must exclude it), chain = 0,
 *                                     no prev stamp.
 *   fresh claim of a clean EMPTY    → prev = the released stamp,
 *   with valid provenance             seq = prev.seq + 1,
 *                                     chain = min(prev.chain + 1, cap).
 *   anything else (garbage, foreign
 *   generation, zeroed, pre-carve)  → RANDOM 64-bit seq restart, chain 0.
 */
static void hb_prov_derive(struct mxfs_disklock_ctx *ctx,
			   const struct mxfs_disklock_heartbeat *consumed,
			   bool fresh_claim)
{
	struct mxfs_hb_provenance *pv = &ctx->own_prov;

	memset(pv, 0, sizeof(*pv));
	pv->magic = MXFS_HB_PROV_MAGIC;
	if (!fresh_claim && hb_prov_valid(consumed)) {
		pv->slot_seq  = consumed->prov.slot_seq + 1;
		pv->chain_len = 0;
	} else if (fresh_claim &&
		   consumed->magic == MXFS_DISKLOCK_MAGIC &&
		   consumed->flags == MXFS_DISKLOCK_FLAG_EMPTY &&
		   !hb_gen_foreign(ctx, consumed) &&
		   hb_prov_valid(consumed)) {
		pv->prev_node  = (uint32_t)consumed->node_id;
		pv->prev_epoch = (uint64_t)consumed->epoch;
		pv->slot_seq   = consumed->prov.slot_seq + 1;
		pv->chain_len  = consumed->prov.chain_len < MXFS_HB_PROV_CHAIN_CAP ?
				 consumed->prov.chain_len + 1 :
				 MXFS_HB_PROV_CHAIN_CAP;
	} else {
		mxfs_pal_get_random_bytes(&pv->slot_seq, sizeof(pv->slot_seq));
		pv->chain_len = 0;
	}
	pv->crc32c = hb_prov_crc(ctx->fs_gen, ctx->local_node, ctx->epoch, pv);
}

/*
 * ── DURABLE RECOVERY DESCRIPTOR — parsing side ──────────────────
 *
 * See the state-machine comment above MXFS_RECOV_DESC_MAGIC in disklock.h.
 * Three predicates, deliberately different in strictness:
 *
 *   recov_desc_of()      the STRICT reader.  Returns the descriptor only when
 *                        it is a RECOVERY_GUARD record carrying a descriptor
 *                        of a version we understand whose crc validates
 *                        against the record's (victim) identity.  Everything
 *                        that INTERPRETS the recovery — stage tests, owner
 *                        tests, takeover — must use this.
 *   recov_lease_covers_{node,inc}()
 *                        the CONSERVATIVE freeze test.  True for any sector
 *                        that even claims to carry a descriptor, including a
 *                        torn one or one written by a future protocol
 *                        generation.  Everything that would DESTROY or REUSE
 *                        the slot must use this: refusing to act on a
 *                        descriptor we cannot read is correct (the slice
 *                        underneath is mid-recovery), guessing is not.
 *   recov_desc_names_{node,inc}()
 *                        strict identity test, for resolving "whose slot is
 *                        this?" — a torn descriptor names nobody.  The _inc
 *                        form is the AUTHORITATIVE one (required incarnation
 *                        match); _node is for callers whose authority comes
 *                        from elsewhere.  There is deliberately no
 *                        optional-epoch form: zero is never a wildcard.
 *
 * The crc binds the descriptor to the record's identity triple exactly as
 * hb_feature_crc binds the feature block, so a descriptor payload spliced
 * next to a different victim's header never validates.
 */
static uint32_t recov_desc_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
			       mxfs_epoch_t epoch,
			       const struct mxfs_recov_desc *d)
{
	struct {
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) id;
	uint32_t crc;

	id.fs_gen  = fs_gen;
	id.node_id = (uint32_t)node_id;
	id.epoch   = (uint64_t)epoch;
	/* Bytes 0..75: every descriptor field except the crc itself.  The
	 * structure is naturally aligned end to end (asserted in disklock.h), so
	 * this covers no padding. */
	crc = mxfs_pal_crc32c(~0U, d, offsetof(struct mxfs_recov_desc, crc32c));
	return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

static bool recov_desc_present(const struct mxfs_disklock_heartbeat *hb)
{
	return hb->magic == MXFS_DISKLOCK_MAGIC &&
	       hb->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
	       hb->recov.desc.magic == MXFS_RECOV_DESC_MAGIC;
}

static const struct mxfs_recov_desc *
recov_desc_of(const struct mxfs_disklock_heartbeat *hb)
{
	const struct mxfs_recov_desc *d = &hb->recov.desc;

	if (!recov_desc_present(hb))
		return NULL;
	if (d->version != MXFS_RECOV_DESC_VERSION)
		return NULL;            /* a generation we do not speak */
	if (d->crc32c != recov_desc_crc(hb->fs_gen, hb->node_id, hb->epoch, d))
		return NULL;
	/*
	 * (§6.2): the owner kind and the owner slot must agree.  A
	 * bootstrap owner has NO slot (MXFS_RECOV_NO_SLOT); a member owner's
	 * slot is in range (0 = unowned / relinquished is in range too).  A
	 * descriptor that contradicts itself is not a descriptor we act on —
	 * it fails closed exactly like a bad crc.
	 */
	if (d->flags & MXFS_RECOV_F_OWNER_BOOTSTRAP) {
		if (d->owner_slot != MXFS_RECOV_NO_SLOT)
			return NULL;
	} else if (d->owner_slot >= MXFS_DISKLOCK_HB_SLOTS) {
		return NULL;
	}
	return d;
}

/*
 * every owner-field write goes through here so the owner kind
 * (MXFS_RECOV_F_OWNER_BOOTSTRAP) and owner_slot can never disagree, and an
 * ordinary member taking a bootstrap owner's descriptor over clears the kind.
 */
static void recov_desc_set_owner_slot(const struct mxfs_disklock_ctx *ctx,
				      struct mxfs_recov_desc *d)
{
	if (ctx->owner_bootstrap) {
		d->owner_slot = MXFS_RECOV_NO_SLOT;
		d->flags |= MXFS_RECOV_F_OWNER_BOOTSTRAP;
	} else {
		d->owner_slot = (uint16_t)ctx->local_slot;
		d->flags &= ~MXFS_RECOV_F_OWNER_BOOTSTRAP;
	}
}

/*
 * the terminal outcome record (disklock.h) gets the SAME identity
 * binding as the descriptor — crc32c over its own bytes folded with the
 * sector's {fs_gen, node_id, epoch} — so an outcome spliced next to a
 * different victim's header never validates.
 */
static uint32_t recov_outcome_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
				  mxfs_epoch_t epoch,
				  const struct mxfs_recov_outcome *oc)
{
	struct {
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) id;
	uint32_t crc;

	id.fs_gen  = fs_gen;
	id.node_id = (uint32_t)node_id;
	id.epoch   = (uint64_t)epoch;
	crc = mxfs_pal_crc32c(~0U, oc, offsetof(struct mxfs_recov_outcome, crc32c));
	return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

/*
 * The STRICT outcome reader.  Returns the outcome record only when the
 * sector is a RECOVERY_GUARD record and the outcome bytes carry our magic,
 * a version we speak, and a crc that validates against the record's victim
 * identity.  A descriptor written by a build that never had outcome records
 * presents zeroed bytes here and reads as "no outcome", never as garbage.
 */
static const struct mxfs_recov_outcome *
recov_outcome_of(const struct mxfs_disklock_heartbeat *hb)
{
	const struct mxfs_recov_outcome *oc = &hb->recov.outcome;

	if (!recov_desc_present(hb))
		return NULL;
	if (oc->magic != MXFS_RECOV_OUTCOME_MAGIC)
		return NULL;
	if (oc->version != MXFS_RECOV_OUTCOME_VERSION)
		return NULL;
	if (oc->crc32c != recov_outcome_crc(hb->fs_gen, hb->node_id,
					    hb->epoch, oc))
		return NULL;
	return oc;
}

/*
 * (ruling item 8): distinguish "no outcome was ever written" (all
 * zero — the intent-quarantine path and pre-outcome builds) from "an outcome
 * was written but does not validate" (torn/corrupt — must fail closed).
 * recov_outcome_of() answers "valid?"; this answers "any bytes at all?".
 */
static bool recov_outcome_present(const struct mxfs_disklock_heartbeat *hb)
{
	const unsigned char *p = (const unsigned char *)&hb->recov.outcome;
	size_t i;

	for (i = 0; i < sizeof(hb->recov.outcome); i++)
		if (p[i])
			return true;
	return false;
}

/*
 * (D-0493): is this heartbeat record a TERMINAL RECOVERY GUARD — the
 * recovery owner's durable "this slice will never be recovered" verdict that
 * a live cluster runs beside until operator repair?  Contract in disklock.h.
 *
 * The same identity binding as closure_gate_predicate, without a disklock
 * context (the survivor scan runs before one exists): the descriptor must be
 * a RECOVERY_GUARD record of THIS filesystem generation, crc-bound to the
 * sector's own {fs_gen, node, epoch}, naming this very slot and the record's
 * own tuple as the victim, QUARANTINED, and carrying an outcome that either
 * validates as a canonical TERMINAL_REFUSED verdict (0) or is the exact
 * legacy all-zero region of the intent-path quarantine (-ENODATA; terminal,
 * no domain evidence — the admission barrier terminalizes it FSWIDE).  A
 * QUARANTINED descriptor whose outcome bytes are non-zero but do not
 * validate is a torn verdict (-EBADMSG) and every consumer fails closed on
 * it.  -EAGAIN is a live (sub-terminal) descriptor — a victim, not a
 * verdict.
 */
int mxfs_hb_terminal_guard_classify(const struct mxfs_disklock_heartbeat *hb,
				    uint32_t slot, uint32_t fs_gen,
				    const struct mxfs_recov_outcome **oc_out)
{
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_outcome *oc;

	if (oc_out)
		*oc_out = NULL;
	if (!hb || !recov_desc_present(hb))
		return -ENOENT;
	if (hb->fs_gen != fs_gen)
		return -ESTALE;
	d = recov_desc_of(hb);
	if (!d)
		return -EPROTO;
	if (d->victim_slot != (uint16_t)slot ||
	    d->victim_node != hb->node_id ||
	    !inc_eq(d->victim_epoch, hb->epoch) ||
	    d->victim_fs_gen != hb->fs_gen)
		return -EPROTO;
	if (!(d->flags & MXFS_RECOV_F_QUARANTINED))
		return -EAGAIN;
	oc = recov_outcome_of(hb);
	if (!oc)
		return recov_outcome_present(hb) ? -EBADMSG : -ENODATA;
	if (oc->victim_slot != (uint16_t)slot ||
	    oc->outcome != MXFS_RECOV_OUTCOME_TERMINAL_REFUSED ||
	    (oc->domain_kind != MXFS_RECOV_DOMAIN_FSWIDE &&
	     oc->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK) ||
		(oc->domain_kind == MXFS_RECOV_DOMAIN_FSWIDE && oc->ag_mask != 0) ||
		(oc->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK && oc->ag_mask == 0))
		return -EBADMSG;
	if (oc_out)
		*oc_out = oc;
	return 0;
}

/*
 * (item 5 increment 2): the STRICT obligation-record reader, same
 * shape as recov_outcome_of — the record counts only on a descriptor sector,
 * with our magic/version and a crc that validates against the sector's
 * victim identity (recov_obl.h: mxfs_recov_obl_rec_check).  A sector written
 * by a build that never had the record presents zeroes and reads as "no
 * record"; anything else that fails is "present but invalid", which every
 * consumer must treat as QUARANTINE, never as count 0 (ruling STOP-SHIP 4).
 */
static const struct mxfs_recov_obl *
recov_obl_of(const struct mxfs_disklock_heartbeat *hb)
{
	const struct mxfs_recov_obl *ob = &hb->recov.obl;

	if (!recov_desc_present(hb))
		return NULL;
	if (mxfs_recov_obl_rec_check(ob, hb->fs_gen, (uint32_t)hb->node_id,
				     (uint64_t)hb->epoch, NULL))
		return NULL;
	return ob;
}

static bool recov_obl_present(const struct mxfs_disklock_heartbeat *hb)
{
	const unsigned char *p = (const unsigned char *)&hb->recov.obl;
	size_t i;

	for (i = 0; i < sizeof(hb->recov.obl); i++)
		if (p[i])
			return true;
	return false;
}

/* 0.85.0: the OPEN-obligation observer (defined with the proof code). */
static void recov_obl_observe(struct mxfs_disklock_ctx *ctx, int slot,
			      const struct mxfs_disklock_heartbeat *hb);

/*
 * (design-consult ruling Q2/Q5.1): the STRUCTURAL verdict of one already-read
 * heartbeat sector — the single place that decides what a sector's recovery
 * object structurally IS, so the monitor and the synchronous readers cannot
 * disagree about it.  Semantic validation (outcome kinds, reasons, AG-mask
 * validity for the mounted filesystem) is XFS-layer policy and lives behind
 * the outcome callback; nothing of that sort belongs here.
 *
 * Two gates were missing from every consumer except the pending sweep and are
 * added here so ALL of them inherit them:
 *
 *   - the GENERATION gate, FIRST.  A sector whose fs_gen is not ours is a
 *     pre-mkfs ghost: it is outside this filesystem's recovery namespace, so
 *     it is neither a verdict nor corruption of one.  Measured a
 *     ghost record quarantined a freshly-formatted filesystem because this
 *     reader looked at its bytes at all.
 *   - the DESCRIPTOR IDENTITY gate.  The descriptor crc binds the SECTOR's
 *     {fs_gen, node_id, epoch}, which travel with a byte-copied record, so
 *     victim_slot is the only binding to the slot the sector was read from.
 *     A misplaced record must not be read as this slot's verdict.
 */
static int recov_outcome_structural(const struct mxfs_disklock_ctx *ctx,
				    const struct mxfs_disklock_heartbeat *hb,
				    int slot,
				    const struct mxfs_recov_outcome **oc_out)
{
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_outcome *oc;

	if (oc_out)
		*oc_out = NULL;

	if (!recov_desc_present(hb)) {
		/* No descriptor of ours.  A foreign-generation sector that carries
		 * one still reports -ESTALE rather than -ENOENT: "wrong generation"
		 * is evidence, "nothing there" is not. */
		return hb_gen_foreign(ctx, hb) && hb->recov.desc.magic ==
				MXFS_RECOV_DESC_MAGIC ? -ESTALE : -ENOENT;
	}
	if (hb_gen_foreign(ctx, hb))
		return -ESTALE;
	d = recov_desc_of(hb);
	if (!d)
		return -EPROTO;         /* descriptor bytes present but unparseable */
	if (d->victim_slot != (uint16_t)slot)
		return -EPROTO;         /* misplaced/copied record: names another slot */
	if (!(d->flags & MXFS_RECOV_F_QUARANTINED))
		return -EAGAIN;         /* live descriptor, no verdict yet */
	oc = recov_outcome_of(hb);
	if (oc) {
		if (oc_out)
			*oc_out = oc;
		return 0;
	}
	/* QUARANTINED with no valid outcome: intent-path quarantine wrote no
	 * outcome bytes at all (-ENODATA — terminal, but no domain evidence);
	 * anything nonzero that fails validation is corruption the consumer
	 * must fail closed on (-EBADMSG, ruling item 8). */
	return recov_outcome_present(hb) ? -EBADMSG : -ENODATA;
}

/*
 * ── Descriptor victim identification: TWO APIs, never one optional epoch ────
 *
 * An optional-epoch argument recreates exactly the wildcard bug this work
 * exists to kill (ruling Q3: "prefer separate APIs for 'inspect a legacy or
 * empty record' vs 'prove a live incarnation'"), so the node-scoped and the
 * incarnation-scoped questions are separate functions and every caller must
 * state which one it means.
 *
 * _node() is NON-AUTHORITATIVE: "is this slot's descriptor about that node at
 * all?".  Legitimate only where the caller's authority comes from elsewhere —
 * e.g. a purge already justified by independent fencing/protocol proof.  It
 * may NEVER gate replay, descriptor adoption, fence certification or recovery
 * advancement.
 *
 * _inc() is the AUTHORITATIVE test: this descriptor names exactly that
 * (node, incarnation).  Zero on either side is a refusal.
 */
static bool recov_desc_names_node(const struct mxfs_disklock_heartbeat *hb,
				  mxfs_node_id_t node)
{
	const struct mxfs_recov_desc *d = recov_desc_of(hb);

	return d && d->victim_node == node;
}

static bool recov_desc_names_inc(const struct mxfs_disklock_heartbeat *hb,
				 mxfs_node_id_t node, mxfs_epoch_t epoch)
{
	const struct mxfs_recov_desc *d = recov_desc_of(hb);

	return d && d->victim_node == node && inc_eq(d->victim_epoch, epoch);
}

static bool recov_lease_covers_node(const struct mxfs_disklock_heartbeat *hb,
				    mxfs_node_id_t node)
{
	if (!recov_desc_present(hb))
		return false;
	/* Present but unreadable: the sector IS a recovery lease and this is the
	 * victim's own slot, so it can only be about this victim.  Treat it as
	 * covering — frozen until someone who can read it finishes the job. */
	if (!recov_desc_of(hb))
		return true;
	return recov_desc_names_node(hb, node);
}

static bool recov_lease_covers_inc(const struct mxfs_disklock_heartbeat *hb,
				   mxfs_node_id_t node, mxfs_epoch_t epoch)
{
	if (!recov_desc_present(hb))
		return false;
	if (!recov_desc_of(hb))
		return true;            /* unreadable lease on the victim's own slot */
	return recov_desc_names_inc(hb, node, epoch);
}

/*
 * The split broadcast predicate (design-consult ruling, rule 3).
 *
 * "The slot no longer carries the dead stamp" used to mean BOTH "the victim
 * is fenced" AND "the victim's grants have been released" — one bit carrying
 * two independent facts.  With the descriptor, a fenced victim's slot reads
 * RECOVERY_GUARD while its authority is deliberately held frozen, so the
 * ONLY transition that may release a peer's deferred local purge is the
 * final zeroing (CONSUMABLE).
 */
static bool hb_still_dead_stamp(const struct mxfs_disklock_heartbeat *hb,
				mxfs_node_id_t pn, mxfs_epoch_t pe)
{
	if (hb->magic != MXFS_DISKLOCK_MAGIC)
		return false;                       /* zeroed => CONSUMABLE */
	/*
	 * A pending incarnation we never observed (pe == 0: we marked the slot
	 * pending without ever having seen a fresh heartbeat from it) degrades to
	 * the node-scoped test.  That direction is the safe one HERE: a true only
	 * keeps the deferred local purge armed, and the CONSUMABLE zeroing at the
	 * end of recovery releases the barrier regardless of this predicate.
	 */
	if (!inc_valid(pe))
		return hb->node_id == pn || recov_lease_covers_node(hb, pn);
	/*
	 * The victim's own stamp intact — now a REQUIRED match.  A same-node
	 * record at a DIFFERENT incarnation is a SUCCESSOR tenancy, not our
	 * victim: the node rejoined and its own mount replayed the slice, so the
	 * barrier must lift.  That is the designed rejoin release, and it only
	 * became real once incarnations stopped being a constant zero.
	 */
	if (hb->node_id == pn && inc_eq(hb->epoch, pe))
		return true;
	/*
	 * (D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN, chain-9
	 * s436i on 0.41.10): a same-node record whose incarnation is NOT VALID
	 * (zero) is not a successor tenancy — no claim ever publishes epoch 0
	 * (hb_draw_incarnation fails closed), so it is a torn/stale/pre-0.11.420
	 * image of OUR victim.  Reading it as "the node rejoined and replayed"
	 * released the deferred purge on all 31 survivors two seconds after the
	 * death (P163-RECOVERED with NO replay, pending marker cleared, every
	 * later acquire -ENODATA): the victim's slice was abandoned and its
	 * grants purged.  Keep the barrier armed; the successor arm below needs
	 * a VALID different incarnation.
	 */
	if (hb->node_id == pn && !inc_valid(hb->epoch))
		return true;
	return recov_lease_covers_inc(hb, pn, pe); /* fenced, recovery in flight */
}

/*
 * self-fence probe: re-read the on-disk MXFS superblock and compare
 * its fs_uuid against the volume this mount belongs to.  Returns 1 if the
 * device was re-formatted under us (fence!), 0 if identity still matches,
 * negative on I/O error (do NOT fence on transient read failure).  `buf`
 * is a caller-provided 512-byte sector buffer (the super's magic and
 * fs_uuid both live in the first sector of the device).
 */
static int fs_identity_changed(struct mxfs_disklock_ctx *ctx, void *buf)
{
	const struct mxfs_ondisk_super *sup = buf;
	int rc;

	rc = mxfs_pal_bdev_read(ctx->dev, 0, buf, MXFS_DISKLOCK_RECORD_SIZE);
	if (rc < 0)
		return rc;

	if (sup->magic != MXFS_FORMAT_MAGIC)
		return 1;       /* super destroyed/replaced — not our volume */
	if (memcmp(sup->fs_uuid, ctx->fs_uuid, 16) != 0)
		return 1;       /* re-mkfs'd: new uuid */
	return 0;
}

/*
 * Find a lock record slot for a resource+owner.
 * Uses linear probing from the hash base.
 *
 * Returns the slot index if found, or -1 if not found.
 * If not found and empty_out is non-NULL, *empty_out is set to the
 * first empty slot encountered (for insertion).
 */
static int find_lock_slot(struct mxfs_disklock_ctx *ctx,
			   const struct mxfs_resource_id *resource,
			   mxfs_node_id_t owner, int *empty_out)
{
	uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
	uint8_t buf[512];
	int first_empty = -1;
	int result = -1;
	uint32_t i;

	for (i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
		uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
		uint64_t offset = lock_slot_offset(ctx, slot);
		struct mxfs_disklock_record *rec;
		int rc;

		rc = read_sector(ctx, offset, buf);
		if (rc < 0)
			break;

		rec = (struct mxfs_disklock_record *)buf;

		if (rec->magic != MXFS_DISKLOCK_MAGIC ||
		    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
			if (first_empty < 0)
				first_empty = (int)slot;
			/* Linear probing: no record past first gap */
			break;
		}

		if (resource_equal(&rec->resource, resource) &&
		    rec->owner == owner) {
			result = (int)slot;
			break;
		}
	}

	if (empty_out)
		*empty_out = first_empty;
	return result;
}

/*
 * Validate existing lockstate region by checking magic on first records.
 */
static int validate_lockstate(struct mxfs_disklock_ctx *ctx)
{
	uint8_t buf[512];
	struct mxfs_disklock_heartbeat *hb;
	struct mxfs_disklock_record *rec;
	int rc;

	/* Check first heartbeat slot */
	rc = read_sector(ctx, hb_slot_offset(ctx, 0), buf);
	if (rc < 0)
		return rc;

	hb = (struct mxfs_disklock_heartbeat *)buf;
	if (hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    hb->magic != MXFS_DISKLOCK_MAGIC) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: corrupt heartbeat at slot 0 "
			     "(magic=%08x, expected=%08x)",
			     hb->magic, MXFS_DISKLOCK_MAGIC);
		return -EIO;
	}

	/* Check first lock record slot */
	rc = read_sector(ctx, lock_slot_offset(ctx, 0), buf);
	if (rc < 0)
		return rc;

	rec = (struct mxfs_disklock_record *)buf;
	if (rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    rec->magic != MXFS_DISKLOCK_MAGIC) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: corrupt lock record at slot 0 "
			     "(magic=%08x, expected=%08x)",
			     rec->magic, MXFS_DISKLOCK_MAGIC);
		return -EIO;
	}

	return 0;
}

/*
 * ── OWN-SLOT WRITES ARE COMPARE-AND-WRITE ───────────────────────────
 *
 * D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD.  See the hb_img comment in
 * disklock.h for the defect; measured on the 32-node rig by
 * tests/hb_guard_clobber_probe.sh (guard destroyed 0.8 s after it was laid
 * into a live node's slot, victim logged nothing).
 *
 * Is `cur` still OUR live record?  Only we ever write this content: our
 * node_id, our mkfs generation, our mount incarnation, flags ACTIVE.  A
 * recovery guard keeps our node_id but moves `flags`; a purge zeroes the
 * sector; a successor claimant writes its own node_id.  So this predicate is
 * exactly "no foreign writer has touched our slot".
 */
static bool hb_own_record(const struct mxfs_disklock_ctx *ctx,
			  const struct mxfs_disklock_heartbeat *cur)
{
	return cur->magic == MXFS_DISKLOCK_MAGIC &&
	       cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	       cur->node_id == ctx->local_node &&
	       cur->epoch == ctx->epoch &&
	       !hb_gen_foreign(ctx, cur);
}

/* Name what a foreign own-slot image is, for the self-fence log. */
static const char *hb_foreign_kind(const struct mxfs_disklock_ctx *ctx,
				   const struct mxfs_disklock_heartbeat *cur)
{
	if (cur->magic != MXFS_DISKLOCK_MAGIC)
		return "sector PURGED/zeroed (our slice was recovered and retired)";
	if (hb_gen_foreign(ctx, cur))
		return "foreign mkfs generation (device re-formatted under us)";
	if (cur->node_id != ctx->local_node)
		return "another node CLAIMED our slot";
	if (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
		return "a survivor laid a RECOVERY GUARD on us — our journal slice "
		       "is being replayed RIGHT NOW";
	if (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN)
		return "our record was stamped WITHDRAWN by someone else";
	if (cur->flags == MXFS_DISKLOCK_FLAG_RETIRE_PENDING)
		return "our record reads RETIRE_PENDING (our own release stamp)";
	if (cur->flags == MXFS_DISKLOCK_FLAG_EMPTY)
		return "our record reads EMPTY (retirement already completed)";
	if (cur->epoch != ctx->epoch)
		return "a different incarnation of this node owns the slot";
	return "unrecognised foreign image";
}

/*
 * Compare-and-write `want` into our own heartbeat slot from ctx->hb_img.
 *
 * Returns:
 *    0        written; hb_img now equals `want`.
 *   -EPERM    MISCOMPARE and the sector is NOT ours — a recovery/purge/
 *             successor owns it.  The caller MUST self-fence: everything we
 *             write from here on is pollution of a slice somebody else is
 *             replaying, and our exclusion has already been asserted.
 *   -EAGAIN   MISCOMPARE but the sector still holds OUR live record, i.e. our
 *             cached image had drifted (an earlier write whose completion we
 *             never saw did land).  Re-synced; the caller retries next cycle.
 *   <0        I/O error.  The write outcome is INDETERMINATE, so hb_img is
 *             invalidated and the next call re-establishes it by reading.
 *
 * A lost race is never retried in here: on -EAGAIN the content we would write
 * is already one cycle stale, and on -EPERM retrying is the bug.
 */
static int hb_cas_own_slot(struct mxfs_disklock_ctx *ctx, uint64_t off,
			   const struct mxfs_disklock_heartbeat *want,
			   struct mxfs_disklock_heartbeat *scratch)
{
	int rc;

	/* Bootstrap / post-indeterminate: re-establish the compare source. */
	if (!ctx->hb_img_valid) {
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, scratch, sizeof(*scratch));
		if (rc < 0)
			return rc;
		if (!hb_own_record(ctx, scratch))
			return -EPERM;
		ctx->hb_img = *scratch;
		ctx->hb_img_valid = true;
	}

	rc = hb_caw(ctx, HB_CAW_OP_HEARTBEAT, "heartbeat", off, &ctx->hb_img, want);

	if (rc == -EOPNOTSUPP) {
		/*
		 * (0.60.0, review-#3 D7 companion): until 0.59.3 this arm
		 * read-verify-wrote the heartbeat — a CAS emulation with a window in
		 * which a peer's GUARD/settlement lands and is overwritten by our
		 * ACTIVE image.  A clustered RW mount is only admitted on a device
		 * whose lock-slot CAS is operational (P311, D-0359; the TCP
		 * transport is refused for clustered RW at the durability-domain
		 * admission), so this is runtime CAW loss, and the ruling is that
		 * it fails closed: no heartbeat lands, the lease runs out, and the
		 * peers fence us on the ordinary stale window.  Logged once.
		 */
		hb_cas_nocaw_locked(ctx, (uint32_t)ctx->local_slot, "heartbeat");
		goto indeterminate;
	}

	if (rc == 0) {
		ctx->hb_img = *want;
		return 0;
	}

	if (rc == -EAGAIN) {
		/* Somebody else wrote our sector.  Who? */
		int rrc = mxfs_pal_bdev_read_prio(ctx->dev, off, scratch,
						  sizeof(*scratch));
		if (rrc < 0) {
			ctx->hb_img_valid = false;
			return rrc;
		}
		if (hb_own_record(ctx, scratch)) {
			/* Still ours: our cached image drifted, not a takeover. */
			ctx->hb_img = *scratch;
			ctx->hb_img_valid = true;
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P236-HB-CAS-RESYNC slot=%d node=%u — own-slot CAS "
			    "MISCOMPARE but the sector still holds OUR live record "
			    "(ts=%llu); re-synced the compare image and retrying. This "
			    "means a previous own-slot write completed without us seeing "
			    "it — investigate if it repeats.",
			    ctx->local_slot, ctx->local_node,
			    (unsigned long long)scratch->timestamp_ms);
			return -EAGAIN;
		}
		ctx->hb_img_valid = false;
		mxfs_pal_log(MXFS_LOG_ERR,
		    "mxfs: P236-HB-FOREIGN-WRITE slot=%d node=%u — own-slot CAS "
		    "MISCOMPARE: %s (magic=%08x flags=%u node=%u fs_gen=%u epoch=%llu)",
		    ctx->local_slot, ctx->local_node, hb_foreign_kind(ctx, scratch),
		    scratch->magic, scratch->flags, scratch->node_id, scratch->fs_gen,
		    (unsigned long long)scratch->epoch);
		return -EPERM;
	}

indeterminate:
	/* The write may or may not have landed — the compare source is unknown. */
	ctx->hb_img_valid = false;
	return rc;
}

/*
 * (ruling, part D): heartbeat-stall watchdog.
 *
 * The false-death incident fenced a node whose heartbeat had not
 * landed for the full 62s lease while the node looked alive — and nothing
 * named WHERE the heartbeat cycle was stuck (thread wedge vs ctx->lock
 * starvation vs a write parked in the saturated device queue vs the
 * monitor's 63 peer reads).  P-HB-SLOW only reports after a cycle
 * COMPLETES; a cycle that never completes is exactly the one that kills.
 *
 * The heartbeat thread publishes its stage at each phase boundary
 * (hb_stage_set); this watchdog polls every 2s and, when a non-SLEEP
 * stage is older than 8s (4x the 2s heartbeat interval — a healthy full
 * cycle is milliseconds), logs P278-HB-STALL with the stage and dumps the
 * heartbeat task's kernel stack so the blocked wait site is captured
 * WHILE it is blocked.  Re-logs every 30s while the same stall persists.
 * Diagnostic only: it never fences, never writes, and reads the stage
 * pair racily (a torn read costs one poll).
 */
#define MXFS_HB_STALL_POLL_MS   2000
#define MXFS_HB_STALL_MS        8000
#define MXFS_HB_STALL_RELOG_MS  30000

static void hb_stage_set(struct mxfs_disklock_ctx *ctx, int stage)
{
	ctx->hb_stage = stage;
	ctx->hb_stage_ms = mxfs_pal_time_ms();
}

static const char *hb_stage_name(int stage)
{
	switch (stage) {
	case MXFS_HB_STAGE_SLEEP:    return "SLEEP";
	case MXFS_HB_STAGE_IDCHECK:  return "IDCHECK";
	case MXFS_HB_STAGE_LOCKWAIT: return "LOCKWAIT";
	case MXFS_HB_STAGE_CASWRITE: return "CASWRITE";
	case MXFS_HB_STAGE_MONITOR:  return "MONITOR";
	default:                     return "UNKNOWN";
	}
}

static void disklock_hb_watchdog_fn(void *arg)
{
	struct mxfs_disklock_ctx *ctx = arg;
	uint64_t stall_entered = 0;   /* hb_stage_ms of the stall being tracked */
	uint64_t last_log_ms = 0;

	while (ctx->running) {
		int stage = ctx->hb_stage;
		uint64_t entered = ctx->hb_stage_ms;
		uint64_t now = mxfs_pal_time_ms();

		if (stage != MXFS_HB_STAGE_SLEEP && entered != 0 &&
		    now - entered > MXFS_HB_STALL_MS) {
			if (entered != stall_entered ||
			    now - last_log_ms >= MXFS_HB_STALL_RELOG_MS) {
				stall_entered = entered;
				last_log_ms = now;
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P278-HB-STALL node %u slot %d stage=%s "
				    "age_ms=%llu hb_pid=%d — heartbeat cycle stuck; "
				    "dumping heartbeat task stack",
				    ctx->local_node, ctx->local_slot,
				    hb_stage_name(stage),
				    (unsigned long long)(now - entered), ctx->hb_pid);
				mxfs_pal_dump_task_stack(ctx->hb_pid);
			}
		} else {
			stall_entered = 0;
		}

		/* Condvar timed wait, not msleep: msleep parks this worker in
		 * uninterruptible (D) sleep, which precond_readiness's D-state
		 * scan flags as a stuck task.  The shutdown broadcast also wakes
		 * us immediately on stop. */
		mxfs_pal_mutex_lock(ctx->shutdown_lock);
		if (ctx->running)
			mxfs_pal_cond_timedwait(ctx->shutdown_cond,
						ctx->shutdown_lock,
						MXFS_HB_STALL_POLL_MS);
		mxfs_pal_mutex_unlock(ctx->shutdown_lock);
	}
}

/*
 * (#92 races 6/7 closure): test-only monitor blackout.  While
 * mxfs_monitor_blind=1 the heartbeat thread suppresses ONLY the peer
 * observation pass — its own heartbeat CAS, self-fence, reservation-
 * conflict relay and shutdown handling all stay live — so a test can
 * make one observer miss a peer's ACTIVE->EMPTY->ACTIVE tenancy change
 * without the observer's own record ever going stale (no P225 barrier
 * on other mounts, no fencing risk, no suspend-window arithmetic).
 * The knob is a stretched monitor interval, nothing more.
 *
 * The gate is taken at the scan BOUNDARY only: a pass already in flight
 * finishes untouched, and the first suppressed pass logs an ACK the
 * test must wait for before it starts choreography.  Auto-clears after
 * MXFS_HB_BLIND_MAX_MS or on heartbeat-thread exit; an auto-clear means
 * the run is INVALID (reason is logged, the test asserts reason=user).
 * Param lives in v5_mount.c (this file also builds user-mode).
 */
int mxfs_monitor_blind;
#define MXFS_HB_BLIND_MAX_MS 120000

static struct {
	bool     active;    /* hb thread acked the request */
	uint32_t gen;       /* activation generation */
	uint32_t skips;     /* peer scans suppressed this activation */
	uint32_t hb_ok;     /* successful own-hb writes while blind */
	uint64_t t0;        /* activation time, ms */
} hb_blind;

static void hb_blind_clear(const char *reason)
{
	mxfs_monitor_blind = 0;
	hb_blind.active = false;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P163T-BLIND-CLEAR reason=%s gen=%u skips=%u hb_ok=%u",
		     reason, hb_blind.gen, hb_blind.skips, hb_blind.hb_ok);
}

/* Returns true when this cycle's peer scan must be suppressed. */
/* ─── the local authority lease ───────────────────────────────────────────
 *
 * The gate a fenced-but-unaware node needs.  Everything here is deliberately
 * unable to reach the LUN, unable to block, and unable to be reopened.
 */

struct mxfs_authority *mxfs_authority_alloc(void)
{
	struct mxfs_authority *auth = mxfs_pal_alloc(sizeof(*auth));

	if (!auth)
		return NULL;
	memset(auth, 0, sizeof(*auth));
	mxfs_atomic32_set(&auth->state, MXFS_AUTH_NOT_ADMITTED);
	mxfs_atomic32_set(&auth->refcnt, 1);
	auth->slot = -1;
	return auth;
}

struct mxfs_authority *mxfs_authority_get(struct mxfs_authority *auth)
{
	if (auth)
		mxfs_atomic32_inc(&auth->refcnt);
	return auth;
}

void mxfs_authority_put(struct mxfs_authority *auth)
{
	if (auth && mxfs_atomic32_dec(&auth->refcnt) == 0)
		mxfs_pal_free(auth);
}

static void auth_note_closed(struct mxfs_authority *auth, int reason,
			     const char *why, uint64_t now, uint64_t deadline)
{
	auth->close_reason = reason;
	auth->closed_at_ms = now;
	mxfs_atomic32_set(&auth->withdraw_pending, 1);
	mxfs_pal_log(MXFS_LOG_ERR,
		     "mxfs: P290-AUTH-CLOSED node %u slot %d incarnation=%llu "
		     "reason=%s deadline_ms=%llu now_ms=%llu overdue_ms=%lld "
		     "last_ok_ms=%llu — %s.  This node's authority over the "
		     "shared LUN is CLOSED: every further mutation is refused "
		     "locally, without asking the target and without waiting to "
		     "be told, and only a fresh coordinated admission under a new "
		     "incarnation can restore it",
		     auth->node, auth->slot,
		     (unsigned long long)auth->incarnation,
		     mxfs_self_fence_reason_name(reason),
		     (unsigned long long)deadline, (unsigned long long)now,
		     (long long)(deadline ? (int64_t)(now - deadline) : 0),
		     (unsigned long long)auth->last_ok_ms, why);
}

bool mxfs_authority_ok(struct mxfs_authority *auth)
{
	uint64_t deadline, now;
	int32_t was;

	/*
	 * A CLUSTERED MOUNT ALWAYS HAS ONE.  Reaching this with no authority
	 * object means the caller could not establish which incarnation it was
	 * writing for, and there is no safe answer to that but no.
	 */
	if (!auth)
		return false;

	/*
	 * The fast path is the whole point: this runs on every mutating
	 * submission, so it is one atomic read and, in the common case, one
	 * compare.  Never a lock, never an allocation, never the LUN.
	 */
	switch (mxfs_atomic32_get(&auth->state)) {
	case MXFS_AUTH_CLOSED:
		return false;
	case MXFS_AUTH_NOT_ADMITTED:
		/*
		 * Mount is still establishing itself and no beat has landed yet.
		 * Refusing here would make the filesystem unmountable; the window is
		 * bounded by the mount, which either lands a beat or fails.  It is
		 * NOT the "unknown timestamp reads as fresh" case the ruling warns
		 * about: once a beat has landed this state is never returned to.
		 */
		return true;
	default:
		break;
	}

	deadline = auth->deadline_ms;
	now = mxfs_pal_time_ms();
	if (now <= deadline)
		return true;

	/*
	 * EXPIRED, AND THE CALLER IS THE ONE WHO FOUND OUT.  Correctness must not
	 * depend on the pump having run — a timer and a heartbeat thread can be
	 * stalled along with the rest of the VM, which is exactly the state this
	 * gate exists for.  So close it here, from whatever context noticed.
	 * Exactly one caller wins the transition and logs.
	 */
	was = mxfs_atomic32_cmpxchg(&auth->state, MXFS_AUTH_ADMITTED,
				    MXFS_AUTH_CLOSED);
	if (was == MXFS_AUTH_ADMITTED)
		auth_note_closed(auth, MXFS_SELF_FENCE_AUTHORITY_LEASE_EXPIRED,
				 "the authority lease expired before this operation "
				 "reached the device", now, deadline);
	return false;
}

void mxfs_authority_renew(struct mxfs_authority *auth, uint64_t anchor_ms,
			  uint64_t last_ok_ms)
{
	uint64_t deadline;
	int32_t state;

	if (!auth)
		return;
	auth->last_ok_ms = last_ok_ms;
	state = mxfs_atomic32_get(&auth->state);
	if (state == MXFS_AUTH_CLOSED)
		return;                 /* sticky: a working heartbeat is not a grant */

	/*
	 * A RENEWAL IS ONLY ACCEPTED WHILE THE PREVIOUS AUTHORITY IS STILL VALID.
	 * The anchor is the instant this beat was ISSUED; if authority had already
	 * lapsed by then, the beat was sent by a node that no longer held the LUN
	 * and its success says nothing — a heartbeat CAS succeeds perfectly well
	 * against a target that has released its reservation and stopped refusing
	 * anyone, which is precisely the state the measured defect leaves behind.
	 */
	if (state == MXFS_AUTH_ADMITTED && anchor_ms > auth->deadline_ms) {
		if (mxfs_atomic32_cmpxchg(&auth->state, MXFS_AUTH_ADMITTED,
					  MXFS_AUTH_CLOSED) == MXFS_AUTH_ADMITTED)
			auth_note_closed(auth, MXFS_SELF_FENCE_AUTHORITY_LEASE_EXPIRED,
					 "a heartbeat landed, but it was ISSUED after "
					 "this node's authority had already lapsed, so "
					 "it renews nothing",
					 mxfs_pal_time_ms(), auth->deadline_ms);
		return;
	}

	deadline = anchor_ms + (uint64_t)MXFS_DISKLOCK_AUTH_LEASE_MS;
	/* Never move a deadline backwards: a reordered renewal must not shorten
	 * authority a later one already extended. */
	if (deadline > auth->deadline_ms) {
		auth->deadline_ms = deadline;
		auth->anchor_ms = anchor_ms;
	}
	if (state == MXFS_AUTH_NOT_ADMITTED &&
	    mxfs_atomic32_cmpxchg(&auth->state, MXFS_AUTH_NOT_ADMITTED,
				  MXFS_AUTH_ADMITTED) == MXFS_AUTH_NOT_ADMITTED)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P290-AUTH-ADMITTED node %u slot %d "
			     "incarnation=%llu lease_ms=%d anchor_ms=%llu "
			     "deadline_ms=%llu — this node's first heartbeat landed; "
			     "it now holds authority over the shared LUN until that "
			     "deadline, and must stop writing at it whether or not "
			     "anything has told it to",
			     auth->node, auth->slot,
			     (unsigned long long)auth->incarnation,
			     MXFS_DISKLOCK_AUTH_LEASE_MS,
			     (unsigned long long)anchor_ms,
			     (unsigned long long)deadline);
}

void mxfs_authority_close(struct mxfs_authority *auth, int reason,
			  const char *why)
{
	if (!auth)
		return;
	if (mxfs_atomic32_cmpxchg(&auth->state, MXFS_AUTH_NOT_ADMITTED,
				  MXFS_AUTH_CLOSED) == MXFS_AUTH_NOT_ADMITTED ||
		mxfs_atomic32_cmpxchg(&auth->state, MXFS_AUTH_ADMITTED,
				      MXFS_AUTH_CLOSED) == MXFS_AUTH_ADMITTED)
		auth_note_closed(auth, reason, why, mxfs_pal_time_ms(),
				 auth->deadline_ms);
}

bool mxfs_authority_take_withdraw(struct mxfs_authority *auth, int *reason_out)
{
	/*
	 * 0.89.67: two consumers may race for one withdrawal — the PR worker's
	 * pump and the dedicated withdraw thread — so the take is an exchange
	 * and exactly one of them notifies.
	 */
	if (!auth || mxfs_atomic32_xchg(&auth->withdraw_pending, 0) == 0)
		return false;
	if (reason_out)
		*reason_out = auth->close_reason;
	return true;
}

/*
 * The disklock-context face of the same object.  A context always has one —
 * it is created with the context and outlives it — so these never have to
 * answer for its absence; a NULL context is "this build has no disklock at
 * all", which is the user-mode and single-node case.
 */
bool mxfs_disklock_authority_ok(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return true;            /* no disklock: nothing to own */
	return mxfs_authority_ok(ctx->auth);
}

void mxfs_disklock_authority_renew(struct mxfs_disklock_ctx *ctx,
				   uint64_t anchor_ms)
{
	if (!ctx)
		return;
	ctx->auth->node = ctx->local_node;
	ctx->auth->slot = ctx->local_slot;
	ctx->auth->incarnation = (uint64_t)ctx->epoch;
	mxfs_authority_renew(ctx->auth, anchor_ms, ctx->hb_last_ok_ms);
}

void mxfs_disklock_authority_close(struct mxfs_disklock_ctx *ctx, int reason,
				   const char *why)
{
	if (!ctx)
		return;
	mxfs_authority_close(ctx->auth, reason, why);
}

bool mxfs_disklock_authority_take_withdraw(struct mxfs_disklock_ctx *ctx,
					   int *reason_out)
{
	if (!ctx)
		return false;
	return mxfs_authority_take_withdraw(ctx->auth, reason_out);
}

struct mxfs_authority *mxfs_disklock_authority(struct mxfs_disklock_ctx *ctx)
{
	return ctx ? ctx->auth : NULL;
}

static bool hb_blind_gate(struct mxfs_disklock_ctx *ctx, int hb_rc)
{
	if (!mxfs_monitor_blind) {
		if (hb_blind.active)
			hb_blind_clear("user");
		return false;
	}
	if (!hb_blind.active) {
		hb_blind.active = true;
		hb_blind.gen++;
		hb_blind.skips = 0;
		hb_blind.hb_ok = 0;
		hb_blind.t0 = mxfs_pal_time_ms();
		mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: P163T-BLIND-ACK gen=%u slot=%d",
			     hb_blind.gen, ctx->local_slot);
	}
	if (mxfs_pal_time_ms() - hb_blind.t0 > MXFS_HB_BLIND_MAX_MS) {
		hb_blind_clear("timeout");
		return false;
	}
	hb_blind.skips++;
	if (hb_rc == 0)
		hb_blind.hb_ok++;
	mxfs_pal_log(MXFS_LOG_DEBUG, "mxfs: P163T-BLIND-SKIP gen=%u skips=%u hb_rc=%d",
		     hb_blind.gen, hb_blind.skips, hb_rc);
	return true;
}

/* Heartbeat thread: writes heartbeat, sleeps, repeats */
/*
 * 0.89.34 — THE HEARTBEAT PAYLOAD, IN ONE PLACE.
 *
 * Everything a peer reads out of our slot is built here, because there is now
 * more than one thing that can issue a beat: the heartbeat loop, and the
 * post-reset authority barrier, which must renew the lease from whatever
 * thread it happens to be running on.  Two copies of this fill would diverge
 * silently — a field left zeroed reads to a peer as "an older build wrote
 * this" rather than as a bug — so the payload is shared and only the beat's
 * mechanics are not.
 */
static void hb_payload_fill(struct mxfs_disklock_ctx *ctx,
			    struct mxfs_disklock_heartbeat *hb)
{
	memset(hb, 0, sizeof(*hb));
	hb->magic = MXFS_DISKLOCK_MAGIC;
	hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
	hb->node_id = ctx->local_node;
	hb->fs_gen = ctx->fs_gen;
	hb->timestamp_ms = mxfs_pal_time_ms();
	hb->epoch = ctx->epoch;
	hb->lock_count = ctx->lock_count;
	hb_feature_fill(ctx, hb);       /* C7 */
	hb->prov = ctx->own_prov;       /* #92: constant per tenure */
	hb_ident_fill(ctx, hb, (uint32_t)ctx->local_slot);   /* */

	/*
	 * publish the inode-eviction ring.  Copy the staging ring in
	 * its physical circular layout; peers reconstruct the logically-recent
	 * entries from head_seq/count.  magic flags the ring as populated
	 * (a node running an older build leaves this zeroed → peers skip).
	 */
	mxfs_pal_mutex_lock(ctx->evict_lock);
	hb->evict.magic = MXFS_EVICT_RING_MAGIC;
	hb->evict.head_seq = ctx->evict_head_seq;
	hb->evict.count = ctx->evict_count;
	hb->evict.pad = 0;
	memcpy(hb->evict.entry, ctx->evict_stage, sizeof(ctx->evict_stage));
	mxfs_pal_mutex_unlock(ctx->evict_lock);
}

/*
 * 0.89.34 — ONE BEAT, ISSUED BY WHOEVER NEEDS IT, RIGHT NOW.
 *
 * WHY THIS EXISTS.  The post-reset authority barrier proves its half by
 * observing a heartbeat ISSUED AFTER THE RESET LAND.  It used to wait for the
 * heartbeat thread to produce one — and the production caller of that barrier
 * IS the heartbeat thread: peer death is declared from the monitor stage of
 * this very loop, and the fence runs inside that dispatch.  So the barrier
 * waited for a beat only it could issue, no beat landed, the lease ran out at
 * exactly its deadline, and the surviving node shut its filesystem down.
 * Measured on the 2/tcp rig: P278-HB-STALL stage=MONITOR with the heartbeat
 * task's own stack inside mxfs_v5_dlm_lu_reset_barrier, monitor_ms=30487,
 * wait_ms=30241 against a 30000 ms lease.
 *
 * The proof the barrier needs does not require the beat to come from any
 * particular thread.  It goes through the same single-outstanding
 * compare-and-write under the same mutex, so it still cannot land until the
 * beat the reset stranded has been resolved, and it still renews from an
 * anchor taken before it was issued.  Issuing it here is therefore the same
 * proof with one fewer dependency — on another thread's schedule.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO.  It does not drive the heartbeat stage
 * machine, and it runs neither the self-fence nor the conflict callback.
 * Those are the loop's cycle policy, not properties of a beat; the loop sees
 * the same condition on its next cycle and acts on it there.  A -EPERM here
 * simply means no renewal happened, which leaves the caller's lease to expire
 * on its own and refuse — the safe direction.
 *
 * Returns 0 when the beat landed and the lease was renewed.
 */
int mxfs_disklock_beat_now(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *hb;
	struct mxfs_disklock_heartbeat *rhb;
	uint64_t offset, t0;
	int rc;

	if (!ctx || !ctx->running || ctx->fenced)
		return -ENODEV;

	/* Both buffers are 512 B and the kernel stack frame limit is 1024. */
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;
	rhb = mxfs_pal_alloc(sizeof(*rhb));
	if (!rhb) {
		mxfs_pal_free(hb);
		return -ENOMEM;
	}

	hb_payload_fill(ctx, hb);
	offset = ctx->base_offset +
		 (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;

	/*
	 * The anchor, and the same pre-issue check the loop makes: the heartbeat
	 * sector is a mutation of the shared LUN like any other, and a node whose
	 * authority has already lapsed must not write it — a peer may already have
	 * fenced this node and laid a recovery guard on this very slot.
	 */
	t0 = mxfs_pal_time_ms();
	if (!mxfs_disklock_authority_ok(ctx)) {
		mxfs_pal_free(rhb);
		mxfs_pal_free(hb);
		return -EPERM;
	}

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_cas_own_slot(ctx, offset, hb, rhb);
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == 0) {
		ctx->hb_last_ok_ms = mxfs_pal_time_ms();
		/* Anchored at the ISSUE instant, never the completion: a
		 * completion-anchored deadline can be younger than the one this
		 * node's peers are able to observe. */
		mxfs_disklock_authority_renew(ctx, t0);
	}
	mxfs_pal_log(rc == 0 ? MXFS_LOG_WARN : MXFS_LOG_ERR,
		     "mxfs: P278-BEAT-NOW node %u slot %d rc=%d issued_ms=%llu "
		     "last_ok_ms=%llu — a beat issued directly by the caller "
		     "rather than by the heartbeat thread%s",
		     ctx->local_node, ctx->local_slot, rc,
		     (unsigned long long)t0,
		     (unsigned long long)ctx->hb_last_ok_ms,
		     rc == 0 ? "; the lease is renewed from the issue instant" :
			       "; NOTHING was renewed");
	mxfs_pal_free(rhb);
	mxfs_pal_free(hb);
	return rc;
}

static void disklock_hb_fn(void *arg)
{
	struct mxfs_disklock_ctx *ctx = arg;
	struct mxfs_disklock_heartbeat *hb;
	struct mxfs_disklock_heartbeat *rhb;
	uint64_t offset;
	int rc;
	/* P-HB-SLOW cycle clocks (persist across loop iterations) */
	uint64_t hb_t0 = 0, hb_tlock = 0, hb_t1 = 0;
	uint64_t hb_last_ok_ms = 0, hb_mon_ms = 0;

	mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat thread started");

	/* Heap-allocate both 512-byte heartbeat buffers to avoid
	 * exceeding the 1024-byte kernel stack frame limit */
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: failed to alloc heartbeat buffer");
		return;
	}

	rhb = mxfs_pal_alloc(sizeof(*rhb));
	if (!rhb) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: failed to alloc monitor buffer");
		mxfs_pal_free(hb);
		return;
	}

	while (ctx->running) {
		hb_stage_set(ctx, MXFS_HB_STAGE_IDCHECK);
		if (unlikely(mxfs_dl_inject_hb_pause_ms > 0)) {
			int ms = mxfs_dl_inject_hb_pause_ms;

			mxfs_dl_inject_hb_pause_ms = 0;     /* one-shot */
			/* 0.89.66: the authority deadline the last landed beat set, so
			 * a lap whose victim never calls the gate (no writer, so no
			 * P290-AUTH-CLOSED line) still has the deadline to measure a
			 * peer's handoff against. */
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-HB-INJECT-PAUSE node %u slot %d ms=%d "
				     "deadline_ms=%llu last_ok_ms=%llu — "
				     "heartbeat thread pausing (TEST ONLY, false-death "
				     "injection)", ctx->local_node, ctx->local_slot, ms,
				     (unsigned long long)(ctx->auth ? ctx->auth->deadline_ms : 0),
				     (unsigned long long)(ctx->auth ? ctx->auth->last_ok_ms : 0));
			while (ms > 0 && ctx->running) {
				mxfs_pal_sleep_ms(ms > 1000 ? 1000 : ms);
				ms -= 1000;
			}
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-HB-INJECT-PAUSE node %u slot %d resumed",
				     ctx->local_node, ctx->local_slot);
		}
		/*
		 * self-fence: before writing anything, verify the device
		 * still carries OUR volume's superblock.  If it was re-mkfs'd under
		 * this live mount, every further write from us is ghost pollution
		 * of the new cluster generation — stop heartbeating immediately and
		 * tell the mount layer to force-shutdown.  rhb doubles as the 512B
		 * super read buffer (overwritten by the monitor pass below anyway).
		 */
		if (ctx->have_fs_identity && !ctx->fenced) {
			rc = fs_identity_changed(ctx, rhb);
			if (rc == 1) {
				ctx->fenced = true;
				mxfs_pal_log(MXFS_LOG_ERR,
					     "mxfs: P131-SELF-FENCE node %u slot %d: device "
					     "reformatted under live mount (super fs_uuid "
					     "mismatch) — stopping heartbeat, forcing "
					     "shutdown",
					     ctx->local_node, ctx->local_slot);
				if (ctx->fence_cb)
					ctx->fence_cb(ctx->fence_cb_data,
						      MXFS_SELF_FENCE_FS_IDENTITY);
				break;
			}
		}

		hb_payload_fill(ctx, hb);

		offset = ctx->base_offset +
			 (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;

		/* (D-RELABORT-...-SELFFENCE instrumented): time every hb write and
		 * track the age since the last SUCCESSFUL one.  test21 was fenced
		 * after its hb failed to land for the FULL 62s lease while the node
		 * looked alive — this names the outage as it grows (write stuck in
		 * the saturated device queue vs mutex held vs hard failure), at zero
		 * cost on the healthy path (one log only when late/slow/failed). */
		hb_t0 = mxfs_pal_time_ms();
		/*
		 * CHECK THE LEASE BEFORE SENDING ANOTHER BEAT.  A thread that was
		 * stalled — parked, descheduled, stuck in a long device wait — comes
		 * back here first, and if its authority lapsed while it was away it
		 * must not go on writing to the shared LUN as though nothing had
		 * happened.  The heartbeat sector is a mutation of that LUN like any
		 * other and gets no "internal I/O" exemption: a peer may already have
		 * fenced this node and laid a recovery guard on this very slot.
		 *
		 * hb_t0 is also THE ANCHOR for the renewal below, captured here
		 * before the lock and before the CAS is issued, so the lease can only
		 * expire earlier than a peer's view of it, never later.
		 */
		/*
		 * TEST ONLY, one-shot: skip the pre-issue check for exactly one
		 * cycle.  It exists to reach the guard inside authority_renew, which
		 * refuses a renewal whose beat was ISSUED after authority had already
		 * lapsed.  That guard is defence in depth and no live path can reach
		 * it — the check just below stops the heartbeat before such a beat
		 * can be sent — so the only way to exercise it is to take the primary
		 * check away for one cycle and let a stale-anchored renewal actually
		 * arrive.  Nothing else is weakened: the renewal still meets every
		 * test it would normally meet.
		 */
		if (unlikely(mxfs_dbg_hb_skip_auth_check)) {
			mxfs_dbg_hb_skip_auth_check = 0;    /* one-shot */
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-DBG-HB-SKIP-AUTH node %u slot %d — TEST: "
				     "the pre-issue authority check is skipped for this "
				     "one cycle, so a beat issued after the lease lapsed "
				     "reaches the renewal guard",
				     ctx->local_node, ctx->local_slot);
		} else if (!mxfs_disklock_authority_ok(ctx)) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P290-AUTH-HB-STOP node %u slot %d — authority "
				     "is closed; stopping the heartbeat rather than "
				     "refreshing a slot this node no longer owns",
				     ctx->local_node, ctx->local_slot);
			break;
		}
		hb_stage_set(ctx, MXFS_HB_STAGE_LOCKWAIT);
		mxfs_pal_mutex_lock(ctx->lock);
		hb_stage_set(ctx, MXFS_HB_STAGE_CASWRITE);
		hb_tlock = mxfs_pal_time_ms();
		/* CAS, never a blind write — see hb_cas_own_slot.  rhb is
		 * free again here (the identity check above finished with it). */
		rc = hb_cas_own_slot(ctx, offset, hb, rhb);
		mxfs_pal_mutex_unlock(ctx->lock);
		/*
		 * TEST ONLY, one-shot: the beat REACHED THE TARGET and its completion
		 * is then delayed.  This is the ordering the issue-time anchor exists
		 * for — the update is visible to peers, they age it while we wait, and
		 * only afterwards do we get told it succeeded.  An implementation that
		 * anchored the deadline at completion would hand this node authority
		 * it never proved, measured from an instant that had already passed
		 * for everyone else.  Delaying here, AFTER the CAS and BEFORE hb_t1,
		 * is what makes hb_t1 late while hb_t0 stays honest.
		 */
		if (unlikely(mxfs_dbg_hb_completion_delay_ms > 0 && rc == 0)) {
			int ms = mxfs_dbg_hb_completion_delay_ms;

			mxfs_dbg_hb_completion_delay_ms = 0;        /* one-shot */
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-DBG-HB-COMPLETION-DELAY node %u slot %d "
				     "ms=%d issued_ms=%llu — TEST: this beat is ON THE "
				     "TARGET and its completion is being withheld; peers "
				     "can see it and age it while this node waits",
				     ctx->local_node, ctx->local_slot, ms,
				     (unsigned long long)hb_t0);
			while (ms > 0 && ctx->running) {
				mxfs_pal_sleep_ms(ms > 1000 ? 1000 : ms);
				ms -= 1000;
			}
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-DBG-HB-COMPLETION-DELAY-END node %u slot %d "
				     "issued_ms=%llu delivered_ms=%llu — TEST: the "
				     "completion is delivered now; the renewal below must "
				     "still derive its deadline from issued_ms",
				     ctx->local_node, ctx->local_slot,
				     (unsigned long long)hb_t0,
				     (unsigned long long)mxfs_pal_time_ms());
		}
		hb_t1 = mxfs_pal_time_ms();

		/*
		 * self-fence.  Our slot no longer holds our record: a survivor
		 * has fenced us and owns our journal slice.  Every further write from
		 * this mount — heartbeat, metadata, log — corrupts a recovery already
		 * in flight, and our exclusion has already been asserted to the
		 * cluster.  Stop heartbeating and force the filesystem down.
		 */
		if (rc == -EPERM) {
			ctx->fenced = true;
			/* Close authority FIRST: the shutdown below is asynchronous, and
			 * between the two nothing else may be admitted to the LUN. */
			mxfs_disklock_authority_close(ctx, MXFS_SELF_FENCE_SLOT_TAKEOVER,
			    "a survivor laid a recovery guard on this node's own "
			    "heartbeat slot");
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P236-SELF-FENCE node %u slot %d: our heartbeat "
				     "slot was taken over by a recovery — stopping "
				     "heartbeat, forcing shutdown",
				     ctx->local_node, ctx->local_slot);
			if (ctx->fence_cb)
				ctx->fence_cb(ctx->fence_cb_data,
					      MXFS_SELF_FENCE_SLOT_TAKEOVER);
			break;
		}

		/* (ruling, part A): RESERVATION CONFLICT on the
		 * own-slot write is the target telling a fenced-but-alive victim
		 * its registration is gone — the ONE fencing signal that cannot
		 * be served from stale media.  Relay to the v5 layer, which
		 * counts conflicts and runs the PR IN inspection that decides
		 * withdraw.  Keep heartbeating meanwhile: the writes bounce
		 * harmlessly, and a transient target hiccup must not kill a
		 * healthy node from here. */
		if (rc == -EBADE && ctx->conflict_cb)
			ctx->conflict_cb(ctx->conflict_cb_data);

		if (rc < 0)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "disklock: heartbeat write failed: %d "
				     "(age_since_last_ok_ms=%llu)", rc,
				     (unsigned long long)(hb_last_ok_ms ?
					 hb_t1 - hb_last_ok_ms : 0));
		else {
			hb_last_ok_ms = ctx->hb_last_ok_ms = hb_t1;
			/* Renew from hb_t0 — the instant this beat was ISSUED — and not
			 * from hb_t1, its completion.  See the lease comment in
			 * disklock.h: a completion-anchored deadline can be younger than
			 * the one this node's peers are able to observe. */
			mxfs_disklock_authority_renew(ctx, hb_t0);
		}
		if (hb_t1 - hb_t0 > 2000 ||
		    (hb_last_ok_ms && hb_t1 - hb_last_ok_ms >
		     2 * MXFS_DISKLOCK_HB_INTERVAL_MS))
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P-HB-SLOW slot=%d write_ms=%llu lockwait_ms=%llu rc=%d age_since_last_ok_ms=%llu prev_cycle_monitor_ms=%llu",
			    ctx->local_slot,
			    (unsigned long long)(hb_t1 - hb_tlock),
			    (unsigned long long)(hb_tlock - hb_t0), rc,
			    (unsigned long long)(hb_last_ok_ms ?
				hb_t1 - hb_last_ok_ms : 0),
				(unsigned long long)hb_mon_ms);

		/* Bug 99: check running after each I/O call so
		 * stop_heartbeat is not blocked behind N disk reads */
		if (!ctx->running)
			break;

		/* --- Monitor: read remote heartbeat slots --- */
		if (hb_blind_gate(ctx, rc)) {
			hb_mon_ms = 0;
			goto hb_blind_sleep;
		}
		hb_stage_set(ctx, MXFS_HB_STAGE_MONITOR);
		{
			uint32_t slot;
			/* this pass's protected-victim mask (see disklock.h) */
			uint64_t prot_mask = 0;
			bool prot_complete = true;
			uint64_t prot_gen0;

			mxfs_pal_mutex_lock(ctx->prot_lock);
			prot_gen0 = ctx->protected_gen;
			mxfs_pal_mutex_unlock(ctx->prot_lock);

			for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
				struct mxfs_disklock_node_track *nt;
				uint64_t off;
				int rr;
				int crr;	/* confirm-before-evict re-read rc */
				/*
				 * the death that fire_dead declares is named
				 * EXPLICITLY — {victim_node, victim_epoch} — instead of being
				 * read back out of slot_node_id[]/node_track[] by the
				 * consumer.  Both of those are rebased onto the SUCCESSOR
				 * before the predecessor's death is dispatched (the
				 * auto-monitor re-arm clobbers slot_node_id, and the
				 * epoch-change arm used to adopt the new incarnation), so a
				 * read-back names the LIVE node as the victim.
				 */
				mxfs_node_id_t victim_node;
				mxfs_epoch_t victim_epoch = 0;
				/* Rebase state: the successor incarnation to resume tracking
				 * once the predecessor's death has been dispatched. */
				bool rebase_inc = false;
				mxfs_epoch_t rebase_epoch = 0;
				uint64_t rebase_ts = 0;
				mxfs_node_id_t rebase_node = 0;

				if (!ctx->running) {
					prot_complete = false;
					break;
				}

				if ((int)slot == ctx->local_slot)
					continue;

				nt = &ctx->node_track[slot];
				victim_node = ctx->slot_node_id[slot];
				off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

				mxfs_pal_mutex_lock(ctx->lock);
				rr = mxfs_pal_bdev_read(ctx->dev, off,
							 rhb, sizeof(*rhb));
				/* observe the writer's PR key while the record is
				 * fresh; frozen per exact incarnation (see hb_ident_observe). */
				if (rr == 0)
					hb_ident_observe(ctx, slot, rhb);
				mxfs_pal_mutex_unlock(ctx->lock);

				/*
				 * protected-victim mask.  Any validated descriptor
				 * at stage >= SNAPSHOTTING protects this slot's CAW authority
				 * bits; an unreadable record keeps last pass's answer.
				 */
				if (rr == 0) {
					const struct mxfs_recov_desc *pdsc = recov_desc_of(rhb);

					if (pdsc && pdsc->stage >= MXFS_RECOV_STAGE_FENCING)
						prot_mask |= 1ULL << slot;
					/* 0.85.0: the OPEN-obligation observer sees every
					 * readable sector every pass (see recov_obl_observe) */
					recov_obl_observe(ctx, (int)slot, rhb);
				} else {
					prot_mask |= ctx->protected_mask & (1ULL << slot);
				}

				/*
				 * D2: a slot in recovery-pending
				 * is owned by the recovery protocol — the elected
				 * replayer zeroes it only AFTER the dead node's log
				 * slice is durably replayed.  Watch for that transition
				 * (or a rejoin: same node, new epoch — its own mount
				 * recovery replayed the slice) and only then run the
				 * DEFERRED local purge via recovered_cb.  FUA-confirm
				 * before releasing the barrier: a stale cached read must
				 * not unfreeze the dead node's grants early.
				 */
				{
					bool pend;
					mxfs_node_id_t pn;
					mxfs_epoch_t pe;

					mxfs_pal_mutex_lock(ctx->lock);
					pend = ctx->recovery_pending[slot];
					pn = ctx->pending_node[slot];
					pe = ctx->pending_epoch[slot];
					mxfs_pal_mutex_unlock(ctx->lock);

					if (pend) {
						/*
						 * the predicate SPLITS (design review rule 3).
						 * A RECOVERY_GUARD carrying a descriptor that names
						 * this victim means FENCED, not RECOVERED — its
						 * grants are deliberately frozen and the deferred
						 * local purge must stay armed.  Only the final
						 * zeroing (CONSUMABLE) releases it.
						 */
						bool still_dead_stamp = (rr == 0) &&
						    hb_still_dead_stamp(rhb, pn, pe);

						/*
						 * (#92, ruling item 4): the pending victim's
						 * slot reads as its OWN CLEAN RELEASE STAMP — the
						 * death was declared from a stale read that raced
						 * mxfs_disklock_release_slot, and the node in fact
						 * unmounted cleanly.  The stamp keeps
						 * hb_still_dead_stamp() TRUE forever (node+epoch
						 * intact under EMPTY), so without this arm the
						 * barrier never lifts: no replayer can fence an
						 * EMPTY slot (fence_intent → -ESTALE, the observed
						 * P238-FENCE-NOINTENT rc=-116 livelock).  FUA-confirm,
						 * then run the DEDICATED unlatch: clear the pending
						 * marker and fire the clean-departure callback —
						 * NOT recovered_cb (there was no recovery; the P163
						 * purge path retires the identity, which a cleanly
						 * departed node must keep).
						 */
						/*
						 * the pending victim's slot reads as its
						 * own RETIRE_PENDING release stamp — settle it
						 * first.  Key absent → the record becomes EMPTY and
						 * the clean-departure arm below unlatches; key
						 * present past grace → WITHDRAWN, and the recovery
						 * pipeline (whose recovery_begin refused the
						 * RETIRE_PENDING image with -ESTALE) proceeds on
						 * its next attempt.
						 */
						if (rr == 0 && still_dead_stamp &&
						    hb_retire_pending(ctx, rhb) &&
						    rhb->node_id == pn) {
							int rs = hb_retire_settle(ctx, slot, off, rhb,
										  false);

							/* anything but EMPTY (WAITING,
							 * WITHDRAWN, CHANGED, error) is left for the
							 * next lap's plain read to classify — the
							 * WITHDRAWN arm below picks a WITHDRAWN up
							 * then (one-lap latency, by design). */
							if (rs != HB_RETIRE_EMPTY)
								continue;
						}

						if (rr == 0 && still_dead_stamp &&
						    hb_clean_empty_match(ctx, rhb, pn, pe)) {
							mxfs_pal_mutex_lock(ctx->lock);
							crr = mxfs_pal_bdev_read_prio(ctx->dev, off,
										      rhb, sizeof(*rhb));
							mxfs_pal_mutex_unlock(ctx->lock);
							if (crr == 0 &&
							    hb_clean_empty_match(ctx, rhb, pn, pe)) {
								mxfs_disklock_clear_recovery_pending(
								    ctx, (int)slot, pn, pe);
								mxfs_pal_log(MXFS_LOG_WARN,
								    "mxfs: P163-CLEAN-DEPART-PEND slot=%u "
								    "node=%u inc=%llu — pending victim's slot "
								    "is its own clean release stamp (FUA "
								    "confirmed); unlatching WITHOUT recovery",
								    slot, pn, (unsigned long long)pe);
								if (ctx->clean_depart_cb)
									ctx->clean_depart_cb(
									    ctx->clean_depart_cb_data,
									    (int)slot, pn, pe);
								mxfs_pal_mutex_lock(ctx->lock);
								nt->last_epoch      = 0;
								nt->last_timestamp  = 0;
								nt->live            = false;
								nt->changed_samples = 0;
								nt->equal_samples   = 0;
								nt->evict_seen      = false;
								nt->seq_seen        = false;
								ctx->monitored[slot] = false;
								mxfs_pal_mutex_unlock(ctx->lock);
							}
							continue;
						}

						/*
						 * a GUARD record carrying a VALID terminal
						 * outcome + F_QUARANTINED is the recovery owner's
						 * durable "this slice will NEVER be recovered"
						 * verdict (ruling).  Import it — once per
						 * (victim_epoch, publish_seq) — so this node
						 * quarantines the victim's domain instead of timing
						 * out into its own shutdown.  The deferred local
						 * purge stays armed: quarantine is terminal, the
						 * slot never becomes CONSUMABLE on its own.
						 */
						if (rr == 0 && still_dead_stamp) {
							const struct mxfs_recov_outcome *oc = NULL;
							const struct mxfs_recov_desc *qd =
							    recov_desc_of(rhb);
							int src = recov_outcome_structural(ctx, rhb,
											   (int)slot, &oc);

							/*
							 * (design-consult ruling Q1): the old arm fired
							 * the import cb only when
							 * oc->outcome == TERMINAL_REFUSED.  That filter
							 * was itself a BYPASS of the one validator: a
							 * crc-valid record carrying an unknown outcome
							 * kind was skipped silently, pass after pass, so
							 * a QUARANTINED slot never quarantined any live
							 * peer and the D-513 park/timeout shape returned.
							 * Every structurally readable outcome now reaches
							 * the callback, which owns the semantic verdict
							 * and fails closed on anything it rejects.
							 */
							if (src == 0) {
								bool fresh;

								mxfs_pal_mutex_lock(ctx->lock);
								fresh = !inc_eq(
									ctx->outcome_seen_epoch[slot],
									oc->victim_epoch) ||
									oc->publish_seq >
									    ctx->outcome_seen_seq[slot];
								if (fresh) {
									ctx->outcome_seen_epoch[slot] =
									    oc->victim_epoch;
									ctx->outcome_seen_seq[slot] =
									    oc->publish_seq;
								}
								mxfs_pal_mutex_unlock(ctx->lock);

								if (fresh) {
									mxfs_pal_log(MXFS_LOG_ERR,
									    "mxfs: P241-RECOV-TERMINAL-IMPORT "
									    "slot=%u victim=%u/%llu reason=%u "
									    "domain=%u ag_mask=0x%llx seq=%llu "
									    "— peer %u published a terminal "
									    "verdict; handing it to the validator",
									    slot, oc->victim_node,
									    (unsigned long long)oc->victim_epoch,
									    oc->reason, oc->domain_kind,
									    (unsigned long long)oc->ag_mask,
									    (unsigned long long)oc->publish_seq,
									    oc->owner_node);
									if (ctx->recov_outcome_cb)
										ctx->recov_outcome_cb(
										    ctx->recov_outcome_cb_data,
										    (int)slot, oc);
								}
							}

							/*
							 * (ruling item 8): QUARANTINED
							 * with outcome bytes that DO NOT validate is a
							 * persistent corruption of a terminal verdict —
							 * it must never be silently skipped pass after
							 * pass.  Alert once per slot, and fire the
							 * import cb with oc == NULL EVERY pass (the
							 * fail-closed fswide contract; there is no
							 * (epoch, seq) to dedup on, importers are
							 * idempotent).  The all-zero outcome region
							 * (intent-path quarantine) is NOT this case —
							 * it is a legitimate terminal state with no
							 * domain evidence, handled by the read_outcome
							 * -ENODATA arm at import time.
							 *
							 * -EPROTO joins -EBADMSG here.  A
							 * descriptor whose bytes do not parse, or whose
							 * victim_slot names a different slot, is exactly
							 * as unreadable as a torn verdict, and the
							 * synchronous readers already fail closed on it.
							 * -ESTALE (pre-mkfs ghost) does NOT: it is not
							 * this filesystem's recovery object at all.
							 */
							if (src == -EBADMSG || src == -EPROTO) {
								bool first;

								mxfs_pal_mutex_lock(ctx->lock);
								first = !ctx->outcome_badcrc_alerted[slot];
								ctx->outcome_badcrc_alerted[slot] = true;
								mxfs_pal_mutex_unlock(ctx->lock);

								if (first)
									mxfs_pal_log(MXFS_LOG_ERR,
									    "mxfs: P241-RECOV-OUTCOME-BADCRC "
									    "slot=%u victim=%u rc=%d — PERSISTENT: "
									    "quarantined/guarded slot carries "
									    "unreadable verdict state; no domain "
									    "evidence exists, failing closed "
									    "FSWIDE until operator action",
									    slot, qd ? qd->victim_node : 0, src);
								if (ctx->recov_outcome_cb)
									ctx->recov_outcome_cb(
									    ctx->recov_outcome_cb_data,
									    (int)slot, NULL);
							}
						}

						if (rr == 0 && !still_dead_stamp) {
							mxfs_pal_mutex_lock(ctx->lock);
							crr = mxfs_pal_bdev_read_prio(ctx->dev, off,
										      rhb, sizeof(*rhb));
							mxfs_pal_mutex_unlock(ctx->lock);
							if (crr == 0 &&
							    !hb_still_dead_stamp(rhb, pn, pe)) {
								bool successor =
								    rhb->magic == MXFS_DISKLOCK_MAGIC &&
								    rhb->flags ==
									MXFS_DISKLOCK_FLAG_ACTIVE &&
									!hb_gen_foreign(ctx, rhb);

								mxfs_disklock_clear_recovery_pending(
								    ctx, (int)slot, pn, pe);
								mxfs_pal_log(MXFS_LOG_WARN,
								    "mxfs: P163-RECOVERED slot=%u node=%u — "
								    "dead slice replay complete (slot "
								    "reclaimed); running deferred local purge",
								    slot, pn);
								if (ctx->recovered_cb)
									ctx->recovered_cb(ctx->recovered_cb_data,
											  (int)slot, pn);
								/*
								 * retire the victim's tracking state
								 * with the victim.  Leaving last_epoch
								 * pinned to the departed incarnation makes
								 * the NEXT occupant of this slot read as an
								 * epoch change against a node that is already
								 * fully recovered — a spurious second death,
								 * whose first act is a per-node fence.
								 *
								 * If a successor already holds the slot,
								 * inherit the slot's membership standing so
								 * it enters dead-detection immediately (an
								 * ACTIVE record proves ownership, not
								 * liveness).  Otherwise forget the slot
								 * entirely and let the auto-monitor
								 * re-baseline on whoever claims it next.
								 */
								mxfs_pal_mutex_lock(ctx->lock);
								nt->changed_samples = 0;
								nt->equal_samples   = 0;
								nt->evict_seen      = false;
								nt->seq_seen        = false; /* #92 */
								if (successor) {
									nt->last_epoch     = rhb->epoch;
									nt->last_timestamp = rhb->timestamp_ms;
									nt->last_change_ms = mxfs_pal_time_ms();
									nt->live           = true;
									ctx->monitored[slot]    = true;
									ctx->slot_node_id[slot] = rhb->node_id;
								} else {
									nt->last_epoch     = 0;
									nt->last_timestamp = 0;
									nt->live           = false;
									ctx->monitored[slot]    = false;
								}
								mxfs_pal_mutex_unlock(ctx->lock);
							}
						}
						continue;
					}
				}

				/*
				 * D2: explicit WITHDRAWN stamp =
				 * voluntary death declaration by a force-shutdown FS.
				 * Confirmed via a cache-piercing re-read (same
				 * discipline as the stale-HB dead-confirm below), it
				 * skips the 31-sample window entirely — peers must start
				 * fence+replay within seconds, with the withdrawn node's
				 * grants frozen meanwhile.  This replaces the old
				 * withdraw_release_all instant-promotion (which handed
				 * peers the withdrawn node's TORN, unreplayed state —
				 * PROVEN drc@16 r13 dirent→freed-inode dangle).
				 */
				/* fire on FIRST SIGHT — no prior-liveness
				 * requirement.  A WITHDRAWN record left by a node that died
				 * (or unmounted) before this monitor ever tracked it is
				 * still a dirty slice needing fence+replay; requiring
				 * `monitored && live` made a no-survivor withdrawn slice
				 * permanently unreachable (the !monitored arm below just
				 * skips it).  The recovery_pending latch above prevents
				 * re-fire once recovery starts, and the WITHDRAWN record
				 * itself names the victim — no tracking state is needed. */
				/*
				 * RETIRE_PENDING on first sight, tracked or not
				 * (same reasoning as the WITHDRAWN arm below: the record
				 * names its own writer).  Settled to EMPTY → the clean-
				 * departure arm below retires the tracking; expired to
				 * WITHDRAWN → the WITHDRAWN arm below fires the death; still
				 * within grace → nothing else may classify this slot this
				 * lap (in particular it must not count toward the stale
				 * window: the release stopped the heartbeat on purpose).
				 */
				if (rr == 0 && hb_retire_pending(ctx, rhb)) {
					int rs = hb_retire_settle(ctx, slot, off, rhb, false);

					if (rs < 0 || rs == HB_RETIRE_WAITING)
						continue;
					/* EMPTY / WITHDRAWN / CHANGED: rhb is the sector's
					 * CURRENT image (CHANGED re-reads it after a
					 * lost CAS — never the stale pending image); fall
					 * through and classify it. */
				}

				if (rr == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
				    rhb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN &&
				    !hb_gen_foreign(ctx, rhb)) {
					mxfs_pal_mutex_lock(ctx->lock);
					crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
								      sizeof(*rhb));
					mxfs_pal_mutex_unlock(ctx->lock);
					if (crr == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
					    rhb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P163-WITHDRAW-SEEN slot=%u node=%u — "
						    "peer declared voluntary death (FS shutdown); "
						    "initiating recovery now",
						    slot, rhb->node_id);
						/* The WITHDRAWN record is the victim's OWN final
						 * record, so its stamp names the victim directly —
						 * no successor is involved and nothing is rebased. */
						hb_rebase_epoch(ctx, nt, slot, rhb, "withdrawn");
						victim_node = rhb->node_id;
						victim_epoch = nt->last_epoch;
						goto fire_dead;
					}
				}

				/*
				 * (D-0519): a CERTIFIED FENCE DESCRIPTOR on first
				 * sight.  The node that expires a RETIRE_PENDING record (or
				 * sees a WITHDRAWN stamp) fences within milliseconds and
				 * rewrites the sector as a RECOVERY_GUARD carrying the
				 * certificate — chain 72 unknown arm: EXPIRED-WITHDRAWN
				 * 5169.000, WITHDRAW-SEEN .008, FENCE-INTENT .0084, so the
				 * WITHDRAWN image existed for ~8 ms.  Every other peer's 2 s
				 * lap missed it and, until now, classified the GUARD record
				 * as "inactive" below: 31 equal samples, 62 s, then the
				 * death — the elected replayer included ("heartbeat expired
				 * after 31 checks" at 5230.6, recovery complete at 5262 —
				 * 93 s after the fence, while the victim's own remount was
				 * refused P300-CLAIM-EXHAUSTED for want of that slot).  The
				 * certificate names the victim (node, incarnation) and
				 * proves its exclusion; nothing is learned by waiting.
				 * FUA-confirm, then fire the death exactly as the WITHDRAWN
				 * arm does: expire_cb marks it pending, v5_handle_node_death
				 * finds the certificate (P238-FENCE-DONE) and dispatches
				 * the election.  Once per (victim, incarnation) per slot;
				 * an attempt still at stage < FENCED is the prover's, and
				 * carries no exclusion proof yet — the stale window remains
				 * the backstop for that and for a refused pending mark.
				 */
				if (rr == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
				    rhb->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
				    !hb_gen_foreign(ctx, rhb)) {
					const struct mxfs_recov_desc *fd = recov_desc_of(rhb);
					bool fresh = false;

					if (fd && fd->stage >= MXFS_RECOV_STAGE_FENCED &&
					    fd->victim_node && fd->victim_slot == slot &&
					    inc_valid(fd->victim_epoch)) {
						mxfs_pal_mutex_lock(ctx->lock);
						fresh = ctx->fenced_seen_node[slot] != fd->victim_node ||
							!inc_eq(ctx->fenced_seen_epoch[slot],
								fd->victim_epoch);
						mxfs_pal_mutex_unlock(ctx->lock);
					}
					if (fresh) {
						mxfs_pal_mutex_lock(ctx->lock);
						crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
									      sizeof(*rhb));
						mxfs_pal_mutex_unlock(ctx->lock);
						fd = crr == 0 ? recov_desc_of(rhb) : NULL;
						if (fd && fd->stage >= MXFS_RECOV_STAGE_FENCED &&
						    fd->victim_node && fd->victim_slot == slot &&
						    inc_valid(fd->victim_epoch)) {
							mxfs_node_id_t vn = fd->victim_node;
							mxfs_epoch_t ve = fd->victim_epoch;

							mxfs_pal_mutex_lock(ctx->lock);
							ctx->fenced_seen_node[slot]  = vn;
							ctx->fenced_seen_epoch[slot] = ve;
							mxfs_pal_mutex_unlock(ctx->lock);
							mxfs_pal_log(MXFS_LOG_WARN,
							    "mxfs: P163-FENCED-SEEN slot=%u node=%u inc=%llu "
							    "prover=%u stage=%u — a peer certified this "
							    "incarnation's fence (FUA confirmed); declaring "
							    "the death now instead of after %d silent samples",
							    slot, vn, (unsigned long long)ve,
							    fd->fence_prover_node, fd->stage,
							    ctx->dead_threshold);
							/* The certificate is the authority on the
							 * incarnation (its crc covers the victim
							 * identity); no header rebase needed. */
							nt->last_epoch = ve;
							nt->inc_zero_logged = false;
							victim_node = vn;
							victim_epoch = ve;
							goto fire_dead;
						}
					}
				}

				/*
				 * (#92, ruling item 2): CLEAN DEPARTURE.  A tracked
				 * slot reading FLAG_EMPTY with the stamp of the occupant we
				 * were monitoring is mxfs_disklock_release_slot's clean
				 * unmount, not a death.  Before this arm the EMPTY record
				 * fell into the inactive branch below, accumulated
				 * equal_samples, and fired the FULL death machinery —
				 * expire_cb → per-node fence → recovery election — against
				 * a node that said goodbye properly (the 31-way
				 * mass-unmount false-death storm).  FUA-confirm the stamp
				 * (a successor's claim CAS may have landed between the
				 * plain read and now), then retire the tracking state
				 * quietly: no fence, no expire_cb, no pending latch, and
				 * the sector is left untouched (peers still need the stamp
				 * for their own matching; the next claimant consumes it).
				 */
				if (rr == 0 && ctx->monitored[slot] &&
				    hb_clean_empty_match(ctx, rhb, victim_node,
							 nt->last_epoch)) {
					mxfs_pal_mutex_lock(ctx->lock);
					crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
								      sizeof(*rhb));
					mxfs_pal_mutex_unlock(ctx->lock);
					if (crr == 0 &&
					    hb_clean_empty_match(ctx, rhb, victim_node,
								 nt->last_epoch)) {
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P163-CLEAN-DEPART slot=%u node=%u "
						    "inc=%llu — clean slot release observed (FUA "
						    "confirmed); retiring tracking WITHOUT recovery",
						    slot, victim_node,
						    (unsigned long long)nt->last_epoch);
						if (ctx->clean_depart_cb)
							ctx->clean_depart_cb(ctx->clean_depart_cb_data,
									     (int)slot, victim_node,
									     nt->last_epoch);
						nt->last_epoch      = 0;
						nt->last_timestamp  = 0;
						nt->live            = false;
						nt->changed_samples = 0;
						nt->equal_samples   = 0;
						nt->evict_seen      = false;
						nt->seq_seen        = false;
						ctx->monitored[slot] = false;
						continue;
					}
					/* Confirm refuted the EMPTY (successor claimed it, or
					 * the read failed): fall through and classify whatever
					 * the confirm read actually returned. */
				}

				if (rr < 0 ||
				    rhb->magic != MXFS_DISKLOCK_MAGIC ||
				    rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
				    hb_gen_foreign(ctx, rhb)) {
					/*
					 * Inactive / garbage / foreign-generation slot (
					 * pre-mkfs ghost writers must never become tracked
					 * members).  Only run the dead-detection state machine
					 * for slots we were already monitoring; an unclaimed
					 * slot is simply skipped.
					 */
					if (!ctx->monitored[slot])
						continue;
					nt->equal_samples++;
					nt->changed_samples = 0;
					goto check_dead;
				}

				/*
				 * ACTIVE peer heartbeat observed.  In CAW mode the
				 * explicit mxfs_disklock_monitor_node() wiring exists ONLY in
				 * the TCP dlm/mount.c peer-connect path — v5_mount.c (CAW)
				 * never calls it, so monitored[] stayed all-false and the
				 * inode-eviction ring (INODE_FREE + DIR_MODIFY) was NEVER
				 * consumed cross-node (producer staged fine, consumer dispatch
				 * = 0 — proven via P-EVICT-STAGE vs P-EVICT-DISPATCH).  Self-
				 * heal: auto-monitor any active peer slot we see.  Idempotent —
				 * only initialises the slot→node mapping on first sight; the
				 * dead-detection state in node_track was zeroed at create and
				 * is driven below.
				 */
				if (!ctx->monitored[slot]) {
					ctx->monitored[slot] = true;
					ctx->slot_node_id[slot] = rhb->node_id;
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P-EVICT-AUTOMON slot=%u node=%u (CAW auto-monitor)",
					    slot, rhb->node_id);
				}

				/*
				 * consume the peer's inode-eviction ring.  For each
				 * {ino, gen} the peer published since we last scanned, invoke
				 * the XFS-layer callback to invalidate a stale NL-cached copy.
				 * All arithmetic on the publish counter is unsigned so it is
				 * wrap-safe; if we fell behind by more than the ring depth we
				 * clamp to the oldest available entry (rare — the ring depth
				 * dwarfs frees-per-HB-interval; a true gap just means a few
				 * extra entries get re-checked harmlessly, or are missed and
				 * caught by the VFS-lookup staleness trap).
				 */
				if (ctx->evict_cb &&
				    rhb->evict.magic == MXFS_EVICT_RING_MAGIC) {
					uint32_t h = rhb->evict.head_seq;
					uint16_t c = rhb->evict.count;
					uint32_t pos;

					if (c > MXFS_EVICT_RING_ENTRIES)
						c = MXFS_EVICT_RING_ENTRIES;

					if (!nt->evict_seen) {
						/* First sighting: adopt head as baseline; do not
						 * replay pre-existing history. */
						nt->last_evict_seq = h;
						nt->evict_seen = true;
					} else if ((int32_t)(h - nt->last_evict_seq) > 0 ||
						   (!mxfs_evict_ring_monotonic &&
						    h != nt->last_evict_seq)) {
						pos = nt->last_evict_seq;
						if ((uint32_t)(h - pos) > c)
							pos = h - c;        /* fell behind > ring depth */
						while (pos != h) {
							uint32_t idx = pos % MXFS_EVICT_RING_ENTRIES;
							uint64_t ino = rhb->evict.entry[idx].ino;
							uint32_t gen = rhb->evict.entry[idx].gen;
							uint32_t type = rhb->evict.entry[idx].type;

							if (ino) {
								if (dl_instr_on())
									mxfs_pal_log(MXFS_LOG_DEBUG,
									    "mxfs: P-EVICT-DISPATCH slot=%u ino=%llu type=%u seq=%u head=%u",
									    slot, (unsigned long long)ino, type,
									    pos, h);
								ctx->evict_cb(ctx->evict_cb_data, ino, gen,
									      type);
							}
							pos++;
						}
						nt->last_evict_seq = h;
					} else if (h != nt->last_evict_seq) {
						/*
						 * head_seq observed BEHIND our cursor: a stale
						 * cached heartbeat read (see the monotonic
						 * fix note above).  Do NOT replay, do NOT move
						 * the cursor back — the next fresh read resumes
						 * exactly where we left off.  Counted for the
						 * Instrumented proof that stale HB reads occur.
						 */
						static uint32_t dl_stale_hb_skips;

						dl_stale_hb_skips++;
						if (dl_stale_hb_skips <= 50 ||
						    (dl_stale_hb_skips & 1023) == 0)
							mxfs_pal_log(MXFS_LOG_WARN,
							    "mxfs: P-EVICT-STALEHB slot=%u h=%u cursor=%u skips=%u — stale cached HB read, ring replay suppressed",
							    slot, h, nt->last_evict_seq,
							    dl_stale_hb_skips);
					}
				}

				/*
				 * Epoch change = the slot changed hands (the occupant
				 * rebooted, or a different node claimed a released slot).
				 *
				 * .  This arm used to adopt the SUCCESSOR incarnation
				 * into nt->last_epoch and then jump to fire_dead, leaving
				 * every consumer that read node_track back to name the LIVE
				 * successor as the victim.  Under required incarnation
				 * matching that is not a cosmetic mislabel — it lays a
				 * recovery guard on a live member and freezes it.  The victim
				 * is captured HERE, before anything is rebased, and the
				 * successor is picked up again only after the death has been
				 * dispatched (see the rebase block at fire_dead).
				 */
				/*
				 * (D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO, measured
				 * by tests/d_recov_zero_epoch_verify.sh on 0.41.8): a ZERO
				 * epoch on a slot whose incarnation we know is NOT a change
				 * of hands.  inc_eq(0, X) is false, so this arm used to
				 * declare the restart ('detected epoch change from X to 0'),
				 * fire the death and REBASE the cache to 0 at rebase_only —
				 * every detector then held inc 0, P238-FENCE-NOINC refused
				 * fencing authority, and when the real epoch reappeared it
				 * read as yet another restart: the slice stayed frozen
				 * forever ('NOT replayed — no proven exclusion (-61)' every
				 * 30 s).  A zero is an unreadable/spliced sector (no member
				 * at this proto_gen writes one): retain the cached
				 * incarnation (hb_rebase_epoch logs P-HB-INC-ZERO once) and
				 * fall through to the timestamp arms — a record that no
				 * longer advances expires on the CACHED incarnation and
				 * keeps its fencing authority; a later valid read equal to
				 * the cache is the same incarnation, not a successor.
				 */
				if (nt->last_epoch != 0 && !inc_valid(rhb->epoch)) {
					hb_rebase_epoch(ctx, nt, slot, rhb, "epoch-change");
				} else if (nt->last_epoch != 0 &&
				    !inc_eq(rhb->epoch, nt->last_epoch)) {
					bool already;

					victim_epoch = nt->last_epoch;
					/* victim_node is the PRE-scan snapshot: the auto-monitor
					 * re-arm above may already have retargeted
					 * slot_node_id[] at the successor. */
					rebase_inc   = true;
					rebase_epoch = rhb->epoch;
					rebase_ts    = rhb->timestamp_ms;
					rebase_node  = rhb->node_id;

					mxfs_pal_mutex_lock(ctx->lock);
					already = ctx->recovery_pending[slot] &&
						  ctx->pending_node[slot] == victim_node &&
						  inc_eq(ctx->pending_epoch[slot], victim_epoch);
					mxfs_pal_mutex_unlock(ctx->lock);

					if (already) {
						/*
						 * We already declared this exact incarnation dead and
						 * its recovery is in flight.  Re-declaring it would
						 * re-enter the expire path, whose FIRST act is a
						 * per-NODE fence — and the node is live again as the
						 * successor.  Just resume tracking the successor.
						 */
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P237-SLOT-REOCCUPIED slot=%u node=%u "
						    "victim_inc=%llu new_inc=%llu new_node=%u — "
						    "successor tenancy observed while the "
						    "predecessor's recovery is still pending; "
						    "tracking the successor, NOT re-declaring the "
						    "death",
						    slot, victim_node,
						    (unsigned long long)victim_epoch,
						    (unsigned long long)rebase_epoch, rebase_node);
						/* #92: the tracked seq names the PREDECESSOR;
						 * drop it so the fresh-HB block re-seeds from the
						 * successor's own provenance. */
						nt->seq_seen = false;
						goto rebase_only;
					}

					/*
					 * (#92, ruling items 8+9): the successor's
					 * provenance can PROVE the predecessor departed cleanly
					 * even though we never saw the intermediate EMPTY (the
					 * release and the re-claim both landed inside one
					 * monitor interval).  The successor's chain covers every
					 * tenancy back to the last dirty consume: tracked seq S
					 * within [S' - chain, S' - 1] of the new record means
					 * the tenancy we were tracking ended in a clean release
					 * that a later claim consumed.  Unsigned arithmetic is
					 * wrap-safe; seq_seen gates against an untracked
					 * predecessor (pre-carve record or mid-tenure join),
					 * which conservatively fires instead.
					 */
					if (nt->seq_seen && hb_prov_valid(rhb) &&
					    rhb->prov.chain_len > 0) {
						uint64_t d = rhb->prov.slot_seq - nt->last_seq;

						if (d >= 1 && d <= rhb->prov.chain_len) {
							mxfs_pal_log(MXFS_LOG_WARN,
							    "mxfs: P163-CLEAN-DEPART-LINEAGE slot=%u "
							    "node=%u inc=%llu — successor (node=%u "
							    "inc=%llu seq=%llu chain=%u) proves the "
							    "predecessor's clean release; retiring it "
							    "WITHOUT recovery",
							    slot, victim_node,
							    (unsigned long long)victim_epoch,
							    rebase_node,
							    (unsigned long long)rebase_epoch,
							    (unsigned long long)rhb->prov.slot_seq,
							    rhb->prov.chain_len);
							if (ctx->clean_depart_cb)
								ctx->clean_depart_cb(
								    ctx->clean_depart_cb_data,
								    (int)slot, victim_node, victim_epoch);
							/* Seed the tracked seq from the successor —
							 * rebase_only resets everything else but
							 * deliberately not these two. */
							nt->last_seq = rhb->prov.slot_seq;
							nt->seq_seen = true;
							goto rebase_only;
						}
					}

					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: node in slot %u has restarted "
					    "(detected epoch change from %llu to %llu), "
					    "reclaiming its resources",
					    slot, (unsigned long long)victim_epoch,
					    (unsigned long long)rebase_epoch);
					goto fire_dead;
				}

				if (rhb->timestamp_ms != nt->last_timestamp) {
					/* Heartbeat is fresh */
					nt->changed_samples++;
					nt->equal_samples = 0;
					nt->last_timestamp = rhb->timestamp_ms;
					nt->last_change_ms = mxfs_pal_time_ms();
					hb_rebase_epoch(ctx, nt, slot, rhb, "fresh");
					/* #92: record the occupant's slot_seq once per
					 * tenancy (provenance is constant per incarnation, so
					 * the first valid sighting is the whole story).  Every
					 * nt reset clears seq_seen so a new tenancy re-seeds. */
					if (!nt->seq_seen && hb_prov_valid(rhb)) {
						nt->last_seq = rhb->prov.slot_seq;
						nt->seq_seen = true;
					}

					if (nt->changed_samples >= MXFS_DISKLOCK_LIVE_THRESHOLD &&
					    !nt->live) {
						nt->live = true;
						mxfs_pal_log(MXFS_LOG_DEBUG,
						    "disklock: node %u (slot %u) is LIVE",
						    rhb->node_id, slot);
					}
				} else {
					/* Heartbeat is stale */
					nt->equal_samples++;
					nt->changed_samples = 0;
				}

				/*
				 * C7 version gate — per-pass validation of every LIVE
				 * current-generation record (not just live-transitions: an
				 * epoch change, a slot reuse, or a peer that was live before
				 * our boot must all be caught; the read is already in hand so
				 * this costs one crc32c per live slot per pass).  A live
				 * incarnation without a valid equal-generation feature block
				 * is protocol-incompatible: confirm on a priority re-read of
				 * the SAME incarnation (transient corruption / stale cache
				 * must not shoot a healthy node), then fence it exactly once
				 * per (slot, epoch).  Fencing only arms after our own join
				 * gate admitted us — a joiner facing an established
				 * incompatible cluster withdraws instead (join_gate).
				 */
				if (nt->live && ctx->vergate_cb && ctx->vergate_admitted &&
				    rhb->magic == MXFS_DISKLOCK_MAGIC &&
				    rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
				    !hb_gen_foreign(ctx, rhb) &&
				    (hb_feature_state(rhb) != MXFS_HBFEAT_OK ||
				     hb_transport_mismatch(ctx, rhb)) &&   /* 0.75.0 */
					!(ctx->vergate_fenced[slot] &&
					  ctx->vergate_fenced_epoch[slot] == rhb->epoch)) {
					int vfst;

					mxfs_pal_mutex_lock(ctx->lock);
					crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
								      sizeof(*rhb));
					mxfs_pal_mutex_unlock(ctx->lock);
					vfst = (crr == 0) ? hb_feature_state(rhb) : MXFS_HBFEAT_OK;
					/* 0.75.0: a valid block on the other DLM transport is
					 * as incompatible as a foreign proto_gen — the two lock
					 * managers exclude nothing from each other. */
					if (crr == 0 && vfst == MXFS_HBFEAT_OK &&
					    hb_transport_mismatch(ctx, rhb))
						vfst = MXFS_HBFEAT_TRANSPORT;
					if (crr == 0 && vfst != MXFS_HBFEAT_OK &&
					    rhb->magic == MXFS_DISKLOCK_MAGIC &&
					    rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
					    !hb_gen_foreign(ctx, rhb) &&
					    rhb->epoch == nt->last_epoch) {
						ctx->vergate_fenced[slot] = true;
						ctx->vergate_fenced_epoch[slot] = rhb->epoch;
						mxfs_pal_log(MXFS_LOG_ERR,
						    "mxfs: P-VERGATE slot=%u node=%u epoch=%llu "
						    "state=%d (1=legacy 2=mismatch 3=corrupt "
						    "4=transport) "
						    "proto_gen=%u ours=%u — live protocol-"
						    "incompatible member, fencing",
						    slot, rhb->node_id,
						    (unsigned long long)rhb->epoch, vfst,
						    rhb->feat.proto_gen, (unsigned)MXFS_PROTO_GEN);
						ctx->vergate_cb(ctx->vergate_cb_data, (int)slot,
								rhb->node_id, rhb->epoch, vfst);
					}
				}

check_dead:
				/* Reached by fall-through or by the inactive/garbage goto:
				 * the occupant we were tracking simply stopped.  No successor
				 * is in play, so the victim IS what node_track still holds. */
				victim_epoch = nt->last_epoch;
				/*
				 * 0.75.70: a record that was ALREADY frozen when this mount
				 * began monitoring it never became live, and this arm used to
				 * require live — so a crash leftover found at mount was
				 * monitored forever and never declared dead.  Measured on the
				 * two-node TCP rig after both nodes were reset with their
				 * mounts in flight (tests/evidence/20260908T232151Z_restart_s558,
				 * boot journals): four stale ACTIVE records auto-monitored at
				 * mount, 'slot N stale ... will purge' for each, and 21
				 * minutes later zero deaths, zero fences, no recovery, no
				 * bootstrap node, every ledger page request parked.  A
				 * record we have watched stay frozen for the whole dead
				 * window is dead by the same standard as one we watched
				 * stop; the baseline (last_timestamp) must exist, and the
				 * FUA confirm below still applies.
				 */
				if (nt->equal_samples >= ctx->dead_threshold &&
				    !nt->live && nt->last_timestamp != 0)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-HB-GHOST-DEAD slot=%u node=%u inc=%llu eq=%d — "
					    "frozen since first sight (never live); declaring the "
					    "death on the ordinary path",
					    slot, victim_node, (unsigned long long)victim_epoch,
					    nt->equal_samples);
				if (nt->equal_samples >= ctx->dead_threshold &&
				    (nt->live || nt->last_timestamp != 0)) {
					/*
					 * the monitor read above (mxfs_pal_bdev_read) is
					 * a plain, cacheable read.  Under heavy storm load the
					 * guest block layer / SCST per-initiator cache can return
					 * a STALE heartbeat sector, so a LIVE-but-busy peer looks
					 * frozen and we falsely evict it — triggering an expensive
					 * purge_node (65536-slot FUA scan) + journal replay that
					 * starves the whole cluster (zsl / posix_multi16 verify
					 * hang).  Before evicting, CONFIRM with a FUA, cache-
					 * bypassing priority re-read.  If the heartbeat actually
					 * advanced, it was a stale-read false alarm — do not evict.
					 * Epoch-change reboots reach fire_dead via goto and skip
					 * this confirm (definite restart, no false positive).
					 */
					mxfs_pal_mutex_lock(ctx->lock);
					crr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb,
								      sizeof(*rhb));
					mxfs_pal_mutex_unlock(ctx->lock);
					if (crr == 0 &&
					    rhb->magic == MXFS_DISKLOCK_MAGIC &&
					    rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
					    !hb_gen_foreign(ctx, rhb) &&
					    rhb->timestamp_ms != nt->last_timestamp) {
						mxfs_pal_log(MXFS_LOG_DEBUG,
						    "mxfs: P-HBFALSE slot=%u last_ts=%llu fua_ts=%llu "
						    "eq=%d — stale cached heartbeat read, NOT evicting",
						    slot,
						    (unsigned long long)nt->last_timestamp,
						    (unsigned long long)rhb->timestamp_ms,
						    nt->equal_samples);
						nt->equal_samples = 0;
						nt->changed_samples++;
						nt->last_timestamp = rhb->timestamp_ms;
						nt->last_change_ms = mxfs_pal_time_ms();
						hb_rebase_epoch(ctx, nt, slot, rhb, "fua-confirm");
						continue;
					}
					/*
					 * (#92, ruling item 3): the confirm read shows
					 * the victim's own CLEAN RELEASE STAMP — the release
					 * landed between the plain read (which still said
					 * ACTIVE/stale) and this confirm.  The old arm only
					 * cancelled on ACTIVE + advanced timestamp, so this
					 * window still fired death on a clean unmount.  Same
					 * clean retire as the monitor arm: no fence, no
					 * expire_cb, no pending latch.
					 */
					/* the confirm read found the victim's own
					 * RETIRE_PENDING stamp (release landed inside the stale
					 * window).  Settle: EMPTY → clean retire below; still
					 * within grace → not a death, re-arm the window;
					 * WITHDRAWN → fall through to fire_dead. */
					if (crr == 0 && hb_retire_pending(ctx, rhb) &&
					    rhb->node_id == victim_node) {
						int rs = hb_retire_settle(ctx, slot, off, rhb,
									  false);

						/* (blocker 1): CHANGED means the sector
						 * moved under us — a peer settled it or a claimant
						 * took it.  Whatever it holds now is by definition
						 * not a stale-dead sector for victim_node: never
						 * fire_dead on it from here; the next lap's plain
						 * read classifies the new image (rebase / clean
						 * depart / withdraw).  Only the EMPTY and WITHDRAWN
						 * images WE produced for this exact victim fall
						 * through. */
						if (rs < 0 || rs == HB_RETIRE_WAITING ||
						    rs == HB_RETIRE_CHANGED) {
							nt->equal_samples = 0;
							continue;
						}
					}
					if (crr == 0 &&
					    hb_clean_empty_match(ctx, rhb, victim_node,
								 victim_epoch)) {
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P163-CLEAN-DEPART-CONFIRM slot=%u node=%u "
						    "inc=%llu — dead-confirm read found the clean "
						    "release stamp; retiring tracking WITHOUT "
						    "recovery",
						    slot, victim_node,
						    (unsigned long long)victim_epoch);
						if (ctx->clean_depart_cb)
							ctx->clean_depart_cb(ctx->clean_depart_cb_data,
									     (int)slot, victim_node,
									     victim_epoch);
						nt->last_epoch      = 0;
						nt->last_timestamp  = 0;
						nt->live            = false;
						nt->changed_samples = 0;
						nt->equal_samples   = 0;
						nt->evict_seen      = false;
						nt->seq_seen        = false;
						ctx->monitored[slot] = false;
						continue;
					}
fire_dead:
					/*
					 * 0.89.66: the three clocks of the death, so the window
					 * is measured rather than assumed.  last_stamp_ms is the
					 * victim's own beat stamp (ITS clock) — its authority
					 * deadline is that plus the lease.  last_seen_ms is OUR
					 * pass that last saw the stamp change (our clock) — the
					 * dead window starts there; now_ms is where it ended.  A
					 * death reached by one of the gotos above (withdrawn
					 * stamp, certificate, epoch change) prints the same
					 * fields with checks well short of the threshold, which
					 * is how a reader tells the cooperative path from the
					 * silent one.
					 */
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: node in slot %u is no longer responding "
					    "(heartbeat expired after %d checks), initiating "
					    "recovery [threshold=%u last_stamp_ms=%llu "
					    "last_seen_ms=%llu now_ms=%llu]",
					    slot, nt->equal_samples, ctx->dead_threshold,
					    (unsigned long long)nt->last_timestamp,
					    (unsigned long long)nt->last_change_ms,
					    (unsigned long long)mxfs_pal_time_ms());
					nt->live = false;
					nt->changed_samples = 0;
					nt->equal_samples = 0;
					ctx->monitored[slot] = false;
					/* the peer died/rebooted — its
					 * evict-ring head_seq restarts.  Drop our cursor baseline
					 * so the monotonic consume guard re-baselines on next
					 * sight instead of ignoring the reborn ring forever. */
					nt->evict_seen = false;
					nt->seq_seen = false;       /* #92: tenancy over */

					/* Bug 108: never use rhb->node_id here.  When the
					 * heartbeat sector has been zeroed (by
					 * disklock_purge_node) or the read failed, rhb->node_id
					 * is 0.  victim_node is the pre-scan snapshot of
					 * slot_node_id[], which monitor_node()/the auto-monitor
					 * set — and, unlike slot_node_id[] itself, it cannot have
					 * been retargeted at a successor earlier in this pass
					 * . */
					/* freeze the victim's PR key into the death
					 * snapshot for exactly this tuple BEFORE the callback
					 * (and before rebase_only may adopt a successor). */
					mxfs_pal_mutex_lock(ctx->lock);
					hb_ident_freeze_victim(ctx, slot, victim_node,
							       victim_epoch);
					mxfs_pal_mutex_unlock(ctx->lock);
					if (ctx->expire_cb)
						ctx->expire_cb(ctx->expire_cb_data, victim_node,
							       (int)slot, victim_epoch);
				}
rebase_only:
				/*
				 * — REBASE ONTO THE SUCCESSOR.
				 *
				 * fire_dead has just torn down this slot's tracking state
				 * (live = false, monitored = false).  When the death was
				 * detected *because* a successor incarnation appeared, that
				 * teardown must not leave the successor untracked: an ACTIVE
				 * record proves OWNERSHIP, not LIVENESS.  A node that claimed
				 * the slot and then died before its first heartbeat tick
				 * would otherwise never accumulate the changed_samples needed
				 * to become live, and check_dead — which requires nt->live —
				 * would never fire for it.  Its slice would be abandoned
				 * silently, with the predecessor's marker already cleared.
				 *
				 * So the successor inherits the slot's membership standing
				 * (live = true) rather than re-earning it, and enters the
				 * dead-detection state machine immediately: if it never
				 * advances its timestamp, equal_samples climbs to
				 * dead_threshold and it is declared dead on the normal path,
				 * FUA-confirmed like any other eviction.
				 */
				if (rebase_inc) {
					nt->last_epoch     = rebase_epoch;
					nt->last_timestamp = rebase_ts;
					nt->last_change_ms = mxfs_pal_time_ms();
					nt->equal_samples  = 0;
					nt->changed_samples = 0;
					nt->live           = true;
					nt->evict_seen     = false;   /* successor ring restarts */
					ctx->monitored[slot]    = true;
					ctx->slot_node_id[slot] = rebase_node;
				}
				continue;  /* after check_dead/fire_dead/rebase_only labels */
			}

			if (prot_complete) {
				/* commit under prot_lock.  An out-of-pass
				 * publication (local proof / sync refresh) that landed while
				 * this pass was reading moved the gen — some of the sectors
				 * above predate it, so the candidate is DISCARDED and the
				 * next pass recomputes from the platter.  The check, the
				 * install and the callback are one critical section. */
				mxfs_pal_mutex_lock(ctx->prot_lock);
				if (prot_gen0 == ctx->protected_gen &&
				    prot_mask != ctx->protected_mask) {
					uint64_t was = ctx->protected_mask;

					ctx->protected_mask = prot_mask;
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P-RMAN-PROTECT mask=0x%llx was=0x%llx — victim "
					    "slots whose CAW EX/PW authority is write-protected "
					    "(recovery descriptor present, stage >= FENCING) changed",
					    (unsigned long long)prot_mask, (unsigned long long)was);
					if (ctx->protect_cb)
						ctx->protect_cb(ctx->protect_cb_data, prot_mask);
				}
				mxfs_pal_mutex_unlock(ctx->prot_lock);
			}
		}

		/* monitor-pass duration for the same P-HB-SLOW attribution
		 * (32 peer reads share ctx->lock with the hb write). */
		hb_mon_ms = mxfs_pal_time_ms() - hb_t1;
		if (hb_mon_ms > 2 * MXFS_DISKLOCK_HB_INTERVAL_MS)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "mxfs: P-HB-MONSLOW slot=%d monitor_ms=%llu",
			    ctx->local_slot, (unsigned long long)hb_mon_ms);

		/* Use condvar timed wait so mxfs_disklock_stop_heartbeat()
		 * can wake us immediately instead of waiting up to 2s */
hb_blind_sleep:
		hb_stage_set(ctx, MXFS_HB_STAGE_SLEEP);
		mxfs_pal_mutex_lock(ctx->shutdown_lock);
		if (ctx->running)
			mxfs_pal_cond_timedwait(ctx->shutdown_cond,
						ctx->shutdown_lock,
						MXFS_DISKLOCK_HB_INTERVAL_MS);
		mxfs_pal_mutex_unlock(ctx->shutdown_lock);
	}

	/* Fence-path breaks leave ctx->running true with this thread gone —
	 * park the stage at SLEEP so the watchdog does not report a stall
	 * against a deliberately exited heartbeat. */
	hb_stage_set(ctx, MXFS_HB_STAGE_SLEEP);

	if (hb_blind.active)
		hb_blind_clear("shutdown");

	mxfs_pal_free(rhb);
	mxfs_pal_free(hb);

	mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat thread exiting");
}

struct mxfs_disklock_ctx *mxfs_disklock_create(mxfs_bdev_t *dev,
						uint64_t disklock_offset,
						mxfs_node_id_t local_node,
						struct mxfs_authority *auth)
{
	struct mxfs_disklock_ctx *ctx;
	int rc;

	if (!dev)
		return NULL;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	/*
	 * Before anything else: without an authority object this context cannot
	 * answer the one question every mutating submission asks it, and the gate
	 * fails closed on a missing one rather than guessing.
	 */
	ctx->auth = auth ? mxfs_authority_get(auth) : mxfs_authority_alloc();
	if (!ctx->auth) {
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}
	ctx->dev = dev;
	ctx->base_offset = disklock_offset;
	ctx->local_node = local_node;
	ctx->local_slot = -1;
	ctx->guard_slot = -1;
	ctx->running = false;
	/*
	 * Draw the mount incarnation before ANY field of ours can be published.
	 * There must be no window in which this ctx could write an ACTIVE record
	 * carrying a zero incarnation — under proto_gen 3 that record would be
	 * indistinguishable from a legacy writer and would be fenced.  A claim
	 * later redraws for its own tenancy (see mxfs_disklock_claim_slot).
	 */
	ctx->epoch = hb_draw_incarnation();
	if (!inc_valid(ctx->epoch)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: no entropy for a mount incarnation — "
			     "refusing to create a disklock context (failing closed; "
			     "a zero incarnation is not a valid identity)");
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}
	ctx->lock_count = 0;
	ctx->hb_thread = NULL;
	memset(ctx->node_track, 0, sizeof(ctx->node_track));
	memset(ctx->monitored, 0, sizeof(ctx->monitored));
	memset(ctx->slot_node_id, 0, sizeof(ctx->slot_node_id));
	ctx->expire_cb = NULL;
	ctx->expire_cb_data = NULL;
	ctx->dead_threshold = MXFS_DISKLOCK_DEAD_THRESHOLD;
	ctx->evict_cb = NULL;
	ctx->evict_cb_data = NULL;
	ctx->evict_head_seq = 0;
	ctx->evict_count = 0;
	memset(ctx->evict_stage, 0, sizeof(ctx->evict_stage));

	ctx->lock = mxfs_pal_mutex_create();
	if (!ctx->lock) {
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->shutdown_lock = mxfs_pal_mutex_create();
	if (!ctx->shutdown_lock) {
		mxfs_pal_mutex_destroy(ctx->lock);
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->shutdown_cond = mxfs_pal_cond_create();
	if (!ctx->shutdown_cond) {
		mxfs_pal_mutex_destroy(ctx->shutdown_lock);
		mxfs_pal_mutex_destroy(ctx->lock);
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->evict_lock = mxfs_pal_mutex_create();
	if (!ctx->evict_lock) {
		mxfs_pal_cond_destroy(ctx->shutdown_cond);
		mxfs_pal_mutex_destroy(ctx->shutdown_lock);
		mxfs_pal_mutex_destroy(ctx->lock);
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->purge_lock = mxfs_pal_mutex_create();
	if (!ctx->purge_lock) {
		mxfs_pal_mutex_destroy(ctx->evict_lock);
		mxfs_pal_cond_destroy(ctx->shutdown_cond);
		mxfs_pal_mutex_destroy(ctx->shutdown_lock);
		mxfs_pal_mutex_destroy(ctx->lock);
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->prot_lock = mxfs_pal_mutex_create();
	if (!ctx->prot_lock) {
		mxfs_pal_mutex_destroy(ctx->purge_lock);
		mxfs_pal_mutex_destroy(ctx->evict_lock);
		mxfs_pal_cond_destroy(ctx->shutdown_cond);
		mxfs_pal_mutex_destroy(ctx->shutdown_lock);
		mxfs_pal_mutex_destroy(ctx->lock);
		mxfs_authority_put(ctx->auth);
		mxfs_pal_free(ctx);
		return NULL;
	}

	rc = validate_lockstate(ctx);
	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: lockstate validation returned %d "
			     "(may be freshly initialized)", rc);
		/* Not fatal — region may be empty/new */
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: initialized for node %u "
		     "(offset=%llu, region size=%llu bytes, %u lock slots)",
		     local_node,
		     (unsigned long long)disklock_offset,
		     (unsigned long long)MXFS_DISKLOCK_REGION_SIZE,
		     MXFS_DISKLOCK_MAX_SLOTS);

	return ctx;
}

void mxfs_disklock_set_snlocal(struct mxfs_disklock_ctx *ctx, bool snlocal)
{
	if (!ctx)
		return;
	/*
	 * Write-time provenance only (ruling item 1): the marker must be
	 * uniform across every record an incarnation ever writes, so it can only
	 * be set before the first claim stamps a record.  Flipping it mid-tenure
	 * would retroactively re-classify records already on the platter.
	 */
	if (ctx->local_slot >= 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: set_snlocal(%d) REFUSED — slot %d already "
			     "claimed; the snlocal marker is write-time provenance "
			     "and cannot change mid-tenure",
			     snlocal ? 1 : 0, ctx->local_slot);
		return;
	}
	ctx->snlocal = snlocal;
}

void mxfs_disklock_set_transport_tcp(struct mxfs_disklock_ctx *ctx, bool tcp)
{
	if (!ctx)
		return;
	/* Write-time provenance like snlocal: uniform across the tenure, so it
	 * can only be set before the claim stamps the first record. */
	if (ctx->local_slot >= 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: set_transport_tcp(%d) REFUSED — slot %d "
			     "already claimed; the transport marker is write-time "
			     "provenance and cannot change mid-tenure",
			     tcp ? 1 : 0, ctx->local_slot);
		return;
	}
	ctx->transport_tcp = tcp;
}

void mxfs_disklock_set_slot_limit(struct mxfs_disklock_ctx *ctx, uint32_t limit)
{
	if (!ctx)
		return;
	/*
	 * Claim-time bound only (D-LOG-SLICE-SHARED-MULTIWRITER): it decides
	 * which slots a claim may take, so changing it after the claim cannot
	 * retroactively legitimize the slot already held.  Set it before
	 * mxfs_disklock_claim_slot, like snlocal.
	 */
	if (ctx->local_slot >= 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: set_slot_limit(%u) REFUSED — slot %d already "
			     "claimed; the claim bound cannot change mid-tenure",
			     limit, ctx->local_slot);
		return;
	}
	ctx->slot_limit = limit;
}

void mxfs_disklock_destroy(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return;

	mxfs_disklock_stop_heartbeat(ctx);

	if (ctx->shutdown_cond)
		mxfs_pal_cond_destroy(ctx->shutdown_cond);
	if (ctx->shutdown_lock)
		mxfs_pal_mutex_destroy(ctx->shutdown_lock);
	if (ctx->evict_lock)
		mxfs_pal_mutex_destroy(ctx->evict_lock);
	if (ctx->purge_lock)
		mxfs_pal_mutex_destroy(ctx->purge_lock);
	if (ctx->prot_lock)
		mxfs_pal_mutex_destroy(ctx->prot_lock);
	mxfs_pal_mutex_destroy(ctx->lock);
	/*
	 * The authority object is NOT freed with the context.  The mount holds
	 * its own reference and keeps it until every producer of this incarnation
	 * is gone, which is long after this point.
	 */
	mxfs_authority_put(ctx->auth);
	mxfs_pal_free(ctx);

	mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: shutdown complete");
}

int mxfs_disklock_start_heartbeat(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx || !ctx->dev)
		return -EINVAL;

	if (ctx->running) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: heartbeat already running");
		return 0;
	}

	ctx->running = true;

	ctx->hb_thread = mxfs_pal_thread_create(disklock_hb_fn, ctx);
	if (!ctx->hb_thread) {
		ctx->running = false;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: failed to start heartbeat thread");
		return -ENOMEM;
	}

	/* part D: stall watchdog.  Diagnostic only — a node without
	 * one is fully functional, so creation failure is not fatal. */
	ctx->hb_pid = mxfs_pal_thread_pid(ctx->hb_thread);
	ctx->hb_watchdog = mxfs_pal_thread_create(disklock_hb_watchdog_fn, ctx);
	if (!ctx->hb_watchdog)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: heartbeat watchdog failed to start "
			     "(stall diagnostics unavailable this mount)");

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: heartbeat started (interval=%u ms)",
		     MXFS_DISKLOCK_HB_INTERVAL_MS);

	return 0;
}

void mxfs_disklock_stop_heartbeat(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return;

	ctx->running = false;

	/* Wake heartbeat thread from its condvar timed wait */
	mxfs_pal_mutex_lock(ctx->shutdown_lock);
	mxfs_pal_cond_broadcast(ctx->shutdown_cond);
	mxfs_pal_mutex_unlock(ctx->shutdown_lock);

	if (ctx->hb_thread) {
		/* Bug 99: timed join first — the running flag + condvar signal
		 * above normally end the thread within one heartbeat cycle
		 * (~2s); 5s covers scheduling jitter without stalling teardown.
		 *
		 *  (2026-07-18): but NEVER abandon the thread on
		 * timeout.  An abandoned kthread still executes module code and
		 * still owns an in-flight 512-byte heartbeat bio; rmmod then
		 * unmaps the module text, and when the slow command finally
		 * completes, bio_endio jumps into freed memory (the recurring
		 * "Unable to access opcode bytes at 0xffffffffc1..." panics —
		 * 4-20 per node in serial-log history, end_clone_bio frames on
		 * the dm-multipath rig).  The stuck write is bounded by the
		 * guest SCSI command timeout + error handling (~180s + EH), so
		 * a blocking join is slow-but-terminating in the worst case —
		 * a slow unmount beats a delayed crash. */
		if (mxfs_pal_thread_join_timeout(ctx->hb_thread, 5000)) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "disklock: heartbeat thread still in disk I/O "
				     "after 5s — waiting it out (bounded by the SCSI "
				     "command timeout; do NOT abandon)");
			mxfs_pal_thread_join(ctx->hb_thread);
		}
		ctx->hb_thread = NULL;
	}

	/* part D: the watchdog wakes from its 2s poll sleep and sees
	 * running==false; its whole loop body is log-only, so a blocking join
	 * is bounded at one poll interval. */
	if (ctx->hb_watchdog) {
		mxfs_pal_thread_join(ctx->hb_watchdog);
		ctx->hb_watchdog = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "disklock: heartbeat stopped");
}

int mxfs_disklock_release_slot(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || ctx->local_slot < 0) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: P278-RELEASE-EINVAL ctx=%d dev=%d slot=%d — "
			     "release_slot has nothing to operate on",
			     ctx != NULL, ctx && ctx->dev != NULL,
			     ctx ? ctx->local_slot : -1);
		return -EINVAL;
	}
	if (ctx->running) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: P278-RELEASE-EBUSY slot=%d — heartbeat still "
			     "running; stop_heartbeat first",
			     ctx->local_slot);
		return -EBUSY;      /* stop_heartbeat first — no racing rewrites */
	}

	/*
	 * (D-532 ruling): the clean release retires this incarnation's
	 * only fenceable identity, so every recovery lease it owns must be
	 * durably given back FIRST.  If that cannot be proven, the slot is NOT
	 * cleanly released: it stays ACTIVE, the heartbeat has stopped, peers
	 * (or the next mount) prove death by expiry + fence and take the
	 * recovery over — recoverable.  The alternative — a descriptor owned
	 * by a retired incarnation — is the D-532 permanent-unmount state.
	 */
	rc = mxfs_disklock_recovery_relinquish_owned(ctx);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P236-RELEASE-DEFERRED-OWNED-RECOVERY slot=%d "
			     "node=%u rc=%d — a recovery lease give-back did not "
			     "land; leaving our member record ACTIVE so this "
			     "incarnation stays provable-dead (D-532)",
			     ctx->local_slot, ctx->local_node, rc);
		return rc;
	}

	cur  = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}

	off = ctx->base_offset +
	      (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: P278-RELEASE-READFAIL slot=%d rc=%d — cannot "
			     "read our record back; leaving it untouched",
			     ctx->local_slot, rc);
		goto out;
	}

	/*
	 * Only clear a record that is still OURS — an evicted/re-claimed slot
	 * belongs to someone else's story now.
	 *
	 * magic+node_id alone was NOT that test.  A recovery guard keeps
	 * the victim's magic and node_id byte for byte and only moves `flags`
	 * (mxfs_disklock_recovery_begin rule 2), so this path used to sail past
	 * the check and blind-write flags=0 straight over a live recovery
	 * descriptor — the same clobber the heartbeat did, just once at unmount.
	 * hb_own_record() tests flags/epoch/fs_gen too, and the clear is a CAS
	 * from the exact image we just read, so a recovery that lands inside the
	 * read→write window loses nothing either.
	 */
	if (!hb_own_record(ctx, cur)) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P236-RELEASE-REFUSED slot=%d node=%u — %s; "
			     "leaving the sector untouched",
			     ctx->local_slot, ctx->local_node,
			     hb_foreign_kind(ctx, cur));
		rc = -ESTALE;
		goto out;
	}

	/*
	 * (D-0356 / D-377): NOT EMPTY.  The slot is released as
	 * RETIRE_PENDING — our own final image, flag moved, identity crc
	 * re-bound — and becomes consumable only once our PR key is proven
	 * absent (a peer's READ KEYS, or our own retire_complete_self when no
	 * key exists).  Writing EMPTY here published a reusable slot BEFORE
	 * the key that still authorises this initiator was retired; a crash or
	 * a failed unregister in that window left a key nothing names.
	 */
	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_RETIRE_PENDING;
	hb_ident_fill(ctx, want, (uint32_t)ctx->local_slot);

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_RELEASE, "release", off, cur, want);
	if (rc == -EOPNOTSUPP)          /* (0.60.0, D7): fail closed */
		hb_cas_nocaw_locked(ctx, (uint32_t)ctx->local_slot, "release");
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == 0) {
		ctx->hb_img_valid = false;      /* the slot is no longer ours */
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: P304-RETIRE-PENDING-RELEASED heartbeat slot %d "
			     "(clean teardown; consumable once the PR key is proven "
			     "retired)",
			     ctx->local_slot);
	} else if (rc == -EAGAIN) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P236-RELEASE-RACE slot=%d node=%u — the "
			     "sector changed between our read and our CAS (a recovery "
			     "took the slot); not clearing it",
			     ctx->local_slot, ctx->local_node);
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: slot %d release write failed: %d",
			     ctx->local_slot, rc);
	}
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_write_grant(struct mxfs_disklock_ctx *ctx,
			       const struct mxfs_resource_id *resource,
			       mxfs_node_id_t owner,
			       uint8_t mode, mxfs_epoch_t epoch)
{
	uint8_t buf[512];
	struct mxfs_disklock_record *rec;
	int empty_slot = -1;
	int existing;
	int target_slot;
	uint64_t offset;
	int rc;

	if (!ctx || !resource || !ctx->dev)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->lock);

	existing = find_lock_slot(ctx, resource, owner, &empty_slot);

	if (existing >= 0) {
		target_slot = existing;
	} else if (empty_slot >= 0) {
		target_slot = empty_slot;
	} else {
		/*
		 * find_lock_slot stopped at the first gap — search further
		 * for any free slot from the hash base.
		 */
		uint32_t base = resource_hash(resource) % MXFS_DISKLOCK_MAX_SLOTS;
		int found = 0;
		uint32_t i;

		for (i = 0; i < MXFS_DISKLOCK_MAX_SLOTS; i++) {
			uint32_t slot = (base + i) % MXFS_DISKLOCK_MAX_SLOTS;
			uint64_t soffset = lock_slot_offset(ctx, slot);

			rc = read_sector(ctx, soffset, buf);
			if (rc < 0)
				continue;

			rec = (struct mxfs_disklock_record *)buf;
			if (rec->magic != MXFS_DISKLOCK_MAGIC ||
			    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE) {
				target_slot = (int)slot;
				found = 1;
				break;
			}
		}
		if (!found) {
			mxfs_pal_log(MXFS_LOG_ERR, "disklock: no free lock slots");
			mxfs_pal_mutex_unlock(ctx->lock);
			return -ENOSPC;
		}
	}

	/* Build the record */
	memset(buf, 0, sizeof(buf));
	rec = (struct mxfs_disklock_record *)buf;
	rec->magic = MXFS_DISKLOCK_MAGIC;
	rec->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
	rec->resource = *resource;
	rec->owner = owner;
	rec->mode = mode;
	rec->state = (uint8_t)MXFS_LSTATE_GRANTED;
	rec->granted_at_ms = mxfs_pal_time_ms();
	rec->epoch = epoch;

	offset = lock_slot_offset(ctx, (uint32_t)target_slot);
	rc = write_sector(ctx, offset, buf);

	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: write_grant failed at slot %d: %d",
			     target_slot, rc);
		return rc;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: wrote grant vol=%llu ino=%llu "
		     "owner=%u mode=%u slot=%d",
		     (unsigned long long)resource->volume,
		     (unsigned long long)resource->ino,
		     owner, mode, target_slot);

	return 0;
}

int mxfs_disklock_clear_grant(struct mxfs_disklock_ctx *ctx,
			       const struct mxfs_resource_id *resource,
			       mxfs_node_id_t owner)
{
	uint8_t buf[512];
	int slot;
	uint64_t offset;
	int rc;

	if (!ctx || !resource || !ctx->dev)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->lock);

	slot = find_lock_slot(ctx, resource, owner, NULL);
	if (slot < 0) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: clear_grant: no record for "
			     "vol=%llu ino=%llu owner=%u",
			     (unsigned long long)resource->volume,
			     (unsigned long long)resource->ino,
			     owner);
		mxfs_pal_mutex_unlock(ctx->lock);
		return -ENOENT;
	}

	memset(buf, 0, sizeof(buf));

	offset = lock_slot_offset(ctx, (uint32_t)slot);
	rc = write_sector(ctx, offset, buf);

	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: clear_grant failed at slot %d: %d",
			     slot, rc);
		return rc;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: cleared grant vol=%llu ino=%llu "
		     "owner=%u slot=%d",
		     (unsigned long long)resource->volume,
		     (unsigned long long)resource->ino,
		     owner, slot);

	return 0;
}

/*
 * ── the purge publication is an EXACT-IMAGE CAS, never a plain
 *    write (design review refusal 4) ──
 *
 * Zeroing a sector in mxfs_disklock_purge_node() is a PUBLICATION.  On a lock
 * record it releases the dead node's grant; on the heartbeat sector it
 * declares the node consumable and hands the slot back to the claim scan.
 * The code did read_sector() then write_sector() — a read-modify-write with
 * no interlock against the other survivors running the identical purge for
 * the same dead node (six call sites; mount.c's peer-death handlers run one
 * on EVERY survivor).  The losing interleaving needs no exotic timing:
 *
 *     P1 reads slot S      -> the dead node's ACTIVE grant
 *     P2 reads slot S      -> the same image
 *     P2 writes zero       -> S is free
 *     live node E claims S -> writes its own ACTIVE grant
 *     P1 writes zero       -> E's LIVE grant is destroyed
 *
 * E then believes it holds a lock that no longer exists on disk, so the same
 * resource can be granted twice.  The heartbeat variant is worse: the late
 * zero erases a LIVE node's heartbeat record, every peer declares that node
 * dead, and the cluster fences it and replays its journal slice while it is
 * still writing to the LUN.
 *
 * CAS closes it — we only zero the exact image whose predicate we evaluated.
 * -EAGAIN (MISCOMPARE) means the sector moved under us, so the decision was
 * derived from a stale image and must be re-derived from the new one.
 *
 * -EOPNOTSUPP means mxfs_bdev_to_sdev() found no SCSI device behind the bdev
 * at all, so this is not a shared LUN and no second purger can exist.  Fall
 * back to the plain write and COUNT it, rather than failing every purge on a
 * single-node/user-mode device.
 */
#define MXFS_PURGE_CAS_RETRIES  4

static int purge_cas_zero(struct mxfs_disklock_ctx *ctx, uint64_t off,
			  const void *expect, const void *zerobuf,
			  int *nonatomic)
{
	int rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expect, zerobuf);

	if (rc == -EOPNOTSUPP) {
		/* (design-consult ruling, D-PURGE-NONATOMIC-PUBLICATION stop-ship
		 * 5): the plain read-then-write fallback IS the defect.  Without an
		 * atomic primitive nothing here can be proven a publication of the
		 * image we evaluated, so the purge is INCOMPLETE and nothing is
		 * published — counted, logged once per purge, never written. */
		if ((*nonatomic)++ == 0)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "disklock: P235-PURGE-NOCAW off=%llu — no SCSI "
				     "COMPARE AND WRITE behind this device; refusing "
				     "the non-atomic zero, purge stays INCOMPLETE",
				     (unsigned long long)off);
	}
	return rc;
}

/*
 * Does `hb` carry a recovery lease covering `node_id`, and does its
 * descriptor permit THIS node to consume the victim's state right now?
 * -ENOENT = no covering lease (not a refusal), 0 = permitted, anything
 * else = covered but frozen.  Shared by the phase-0 freeze gate, the
 * mid-scan authority revalidation, and purge_hb_zeroable so the three
 * decisions can never drift apart.
 */
static int purge_recov_gate(struct mxfs_disklock_ctx *ctx,
			    const struct mxfs_disklock_heartbeat *hb,
			    mxfs_node_id_t node_id)
{
	const struct mxfs_recov_desc *d;

	if (hb->magic != MXFS_DISKLOCK_MAGIC ||
	    !recov_lease_covers_node(hb, node_id))
		return -ENOENT;
	d = recov_desc_of(hb);
	if (!d)
		return -EPROTO;                 /* torn/newer protocol — never guess */
	if (d->flags & MXFS_RECOV_F_QUARANTINED)
		return -EPERM;                  /* terminal */
	if (d->stage < MXFS_RECOV_STAGE_GRANTS_RELEASED)
		return -EBUSY;                  /* authority not released yet */
	if (d->owner_node != ctx->local_node ||
	    !inc_eq(d->owner_epoch, ctx->epoch))
		return -EBUSY;                  /* the owner's act, not ours */
	return 0;
}

/*
 * May `hb` — a freshly read heartbeat sector image — be zeroed as part of
 * purging `node_id`?  0 = yes, -ENOENT = not this victim's sector (keep
 * scanning), anything else = it IS this victim's sector but is frozen.
 *
 * this repeats the phase-0 freeze gate on the image the CAS then
 * publishes against.  Phase 0 decides from a read taken BEFORE the 65536-
 * record scan, and the old zero pass re-checked only "does the descriptor
 * name this victim" — not its stage or owner.  A descriptor that advanced,
 * changed owner or became unreadable in between was therefore published
 * anyway, defeating the gate.  Deciding here and CASing this exact image
 * makes "the gate says consumable" and "the sector is zeroed" one step.
 */
static int purge_hb_zeroable(struct mxfs_disklock_ctx *ctx,
			     const struct mxfs_disklock_heartbeat *hb,
			     mxfs_node_id_t node_id)
{
	if (hb->magic != MXFS_DISKLOCK_MAGIC)
		return -ENOENT;

	/* Plain member record: ACTIVE, or the voluntary WITHDRAWN stamp. */
	if ((hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
	     hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) &&
		hb->node_id == node_id)
		return 0;

	/* A recovery lease over this victim: zeroing it IS the CONSUMABLE
	 * publication, so it is ours to make only at GRANTS_RELEASED and only
	 * while we still own the recovery. */
	return purge_recov_gate(ctx, hb, node_id);
}

/*
 * (design review item 6D): this used to swallow EVERY I/O
 * failure and always return a success-shaped count.
 *
 * Two of the failures it swallowed are load-bearing.  Zeroing the dead
 * node's heartbeat sector IS the cluster-wide "slice replay done"
 * broadcast — the thing that releases every peer's deferred purge — and a
 * failed write there left the record ACTIVE while the caller went on to
 * log RECOVERY-COMPLETE.  And a read failure on a lock-record sector
 * meant we could not prove the sector was not an ACTIVE grant owned by
 * the dead node, yet the sector was skipped and counted as clean.
 *
 * An incomplete purge is not a purge.  Report:
 *   >= 0  every sector was readable, every ACTIVE record owned by
 *         node_id was zeroed, and the heartbeat sector is provably not
 *         ACTIVE/WITHDRAWN for this node (either zeroed here or already
 *         gone).  Value is the lock-record count, as before.
 *   < 0   the purge could not be proven complete.  The caller must NOT
 *         treat this node's recovery as published.
 */
int mxfs_disklock_purge_node(struct mxfs_disklock_ctx *ctx,
			      mxfs_node_id_t node_id)
{
	uint8_t *buf;
	uint8_t *zerobuf;
	int purged = 0;
	int rd_fail = 0;
	int wr_fail = 0;
	int hb_rd_fail = 0;
	int hb_wr_fail = 0;
	int hb_found = 0;
	int nonatomic = 0;
	uint32_t first_rd_fail = 0;
	int first_rc = 0;
	uint32_t slot;
	int rc;
	int gate_found = 0;
	int gate_slot = -1;
	uint64_t gate_off = 0;
	uint64_t gate_check_ms = 0;
	/*
	 * (budget, chain 32 on 0.51.0): the record scan read the table
	 * ONE 512-byte sector at a time — 65536 synchronous reads, ~8 s per
	 * dead node, 265 s of a 545 s whole-cluster bootstrap (31 victims) and
	 * the same cost on every ordinary death.  The scan now reads
	 * PURGE_BATCH records per I/O (the seal-time manifest collector's
	 * pattern) and falls back to per-sector reads for a batch that fails,
	 * so the rd_fail accounting and the per-record CAS-zero are unchanged.
	 * scan_ms/total_ms are reported on the P-PURGE-DONE line.
	 */
	enum { PURGE_BATCH = 128 };
	uint8_t *batch;
	uint32_t bslot = 0, bvalid = 0;         /* batch covers [bslot, bslot+bvalid) */
	int batch_rc = -ENOMEM;
	uint64_t t_start, t_scan0 = 0, t_scan1 = 0;

	if (!ctx || !ctx->dev)
		return -EINVAL;

	t_start = mxfs_pal_time_ms();
	buf = mxfs_pal_alloc(512);
	zerobuf = mxfs_pal_alloc(512);
	batch = mxfs_pal_alloc((size_t)PURGE_BATCH * MXFS_DISKLOCK_RECORD_SIZE);
	if (!buf || !zerobuf) {
		mxfs_pal_free(buf);
		mxfs_pal_free(zerobuf);
		mxfs_pal_free(batch);
		return -ENOMEM;
	}

	/*
	 * (D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION): the whole purge used
	 * to run under ONE ctx->lock hold — a 65536-sector FUA scan that starved
	 * the heartbeat writer for ~35s (P-HB-SLOW lockwait_ms=34978), more than
	 * half the 62s lease.  Now purge_lock serializes concurrent purges
	 * (the heartbeat writer NEVER takes it) and ctx->lock is taken per-I/O,
	 * so the hb writer interleaves freely.  Order: purge_lock -> ctx->lock,
	 * never the reverse.
	 */
	mxfs_pal_mutex_lock(ctx->purge_lock);

	/*
	 * ── phase 0: the VICTIM-MANIFEST FREEZE gate (design review rule 4) ──
	 *
	 * Locate the victim's heartbeat sector and decide whether its state may
	 * be consumed AT ALL — before a single record is zeroed.  The old order
	 * (purge the 65536 lock records, then look at the heartbeat) destroys
	 * the authority manifest the foreign-replay token gate reads and only
	 * afterwards discovers it was not allowed to.
	 *
	 * The gate refuses when the sector carries a recovery descriptor that is
	 *   - unreadable (torn, or a newer protocol generation) — never guess;
	 *   - QUARANTINED — terminal; losing the slot's capacity is the correct
	 *     failure, silently publishing undischarged obligations is not;
	 *   - below GRANTS_RELEASED — the recovery has not released the victim's
	 *     authority yet, so nothing about it is consumable;
	 *   - owned by another survivor — the final zero is the recovery owner's
	 *     act, serialized with its stage CASes.
	 */
	{
		uint32_t s;

		for (s = 0; s < MXFS_DISKLOCK_HB_SLOTS; s++) {
			uint64_t hb_off = ctx->base_offset +
					  (uint64_t)s * MXFS_DISKLOCK_RECORD_SIZE;
			struct mxfs_disklock_heartbeat *chb;

			mxfs_pal_mutex_lock(ctx->lock);
			rc = read_sector(ctx, hb_off, buf);
			mxfs_pal_mutex_unlock(ctx->lock);
			if (rc < 0)
				continue;       /* counted for real in the zeroing pass */
			chb = (struct mxfs_disklock_heartbeat *)buf;
			rc = purge_recov_gate(ctx, chb, node_id);
			if (rc == -ENOENT)
				continue;       /* no covering lease on this sector */
			if (rc) {
				const struct mxfs_recov_desc *d = recov_desc_of(chb);

				mxfs_pal_log(MXFS_LOG_WARN,
				    "disklock: P234-PURGE-FROZEN node=%u slot=%u stage=%d "
				    "owner=%u rc=%d — the victim's authority manifest is "
				    "frozen by a live recovery descriptor; NOTHING purged "
				    "and nothing may be published",
				    node_id, s, d ? (int)d->stage : -1,
				    d ? (unsigned)d->owner_node : 0u, rc);   /* was %d (node ids >2^31 printed negative) */
				mxfs_pal_mutex_unlock(ctx->purge_lock);
				mxfs_pal_free(buf);
				mxfs_pal_free(zerobuf);
				return rc;
			}
			gate_found = 1;
			gate_off = hb_off;
			gate_slot = (int)s;
			gate_check_ms = mxfs_pal_time_ms();
			break;
		}
	}

	/* test hook, point 1: the freeze gate passed; nothing zeroed
	 * yet.  (A pause here is how the concurrent-purger arm parks the owner
	 * so a non-owner's attempt lands mid-scan.) */
	if (ctx->dbg_purge_hook)
		ctx->dbg_purge_hook(ctx->dbg_purge_hook_data, 1, gate_slot);

	t_scan0 = mxfs_pal_time_ms();
	for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS; slot++) {
		uint64_t offset = lock_slot_offset(ctx, slot);
		struct mxfs_disklock_record *rec;

		/* test hook, point 2: a nonzero return forces the first
		 * mid-scan authority re-derivation NOW (the descriptor was changed
		 * under us by the hook), instead of after the 2 s cadence. */
		if (slot == 0 && gate_found && ctx->dbg_purge_hook &&
		    ctx->dbg_purge_hook(ctx->dbg_purge_hook_data, 2, gate_slot))
			gate_check_ms = 0;

		/*
		 * Amortized authority revalidation (~every 2s of scan): with
		 * ctx->lock no longer held across the scan, the recovery
		 * descriptor can move while we work.  Re-derive the phase-0 gate
		 * from its sector so a purge whose authority was lost mid-scan
		 * stops publishing instead of finishing on stale authority.
		 */
		if (gate_found &&
		    mxfs_pal_time_ms() - gate_check_ms > 2000) {
			gate_check_ms = mxfs_pal_time_ms();
			mxfs_pal_mutex_lock(ctx->lock);
			rc = read_sector(ctx, gate_off, buf);
			mxfs_pal_mutex_unlock(ctx->lock);
			if (rc == 0) {
				rc = purge_recov_gate(ctx,
					(const struct mxfs_disklock_heartbeat *)buf, node_id);
				if (rc == -ENOENT) {
					/* Lease gone: consumed/published elsewhere.  The plain
					 * member-record purge needs no descriptor authority. */
					gate_found = 0;
				} else if (rc) {
					mxfs_pal_log(MXFS_LOG_ERR,
					    "disklock: P234-PURGE-REFROZE-MIDSCAN node=%u "
					    "slot=%u purged=%d rc=%d — recovery descriptor "
					    "changed under the scan; purge STOPPED and recovery "
					    "is NOT published",
					    node_id, slot, purged, rc);
					/* (D-PURGE-NONATOMIC midscan arm): report the
					 * stop through the same P229-PURGE-INCOMPLETE path the
					 * final-gate refreeze takes, so every non-published
					 * purge carries the one INCOMPLETE line. */
					hb_wr_fail = rc;
					goto purge_done;
				}
			}
			/* Unreadable gate sector: keep scanning; the zeroing pass
			 * counts I/O failures for real and refuses publication. */
		}

		/* batched read; a failed batch degrades to per-sector
		 * reads for its range so every unreadable record is still counted */
		if (batch && slot >= bslot + bvalid) {
			bslot = slot;
			bvalid = MXFS_DISKLOCK_MAX_SLOTS - slot < PURGE_BATCH ?
				 MXFS_DISKLOCK_MAX_SLOTS - slot : PURGE_BATCH;
			mxfs_pal_mutex_lock(ctx->lock);
			batch_rc = mxfs_pal_bdev_read(ctx->dev, lock_slot_offset(ctx, bslot),
						      batch,
						      bvalid * MXFS_DISKLOCK_RECORD_SIZE);
			mxfs_pal_mutex_unlock(ctx->lock);
		}
		if (batch && batch_rc == 0) {
			memcpy(buf, batch + (size_t)(slot - bslot) * MXFS_DISKLOCK_RECORD_SIZE,
			       MXFS_DISKLOCK_RECORD_SIZE);
			rc = 0;
		} else {
			mxfs_pal_mutex_lock(ctx->lock);
			rc = read_sector(ctx, offset, buf);
			mxfs_pal_mutex_unlock(ctx->lock);
		}
		if (rc < 0) {
			/* Unreadable: may be an ACTIVE grant owned by the dead
			 * node.  Keep scanning (one bad sector must not abandon
			 * the other 65535) but remember that this pass is not a
			 * proof of completeness. */
			if (!rd_fail) {
				first_rd_fail = slot;
				first_rc = rc;
			}
			rd_fail++;
			continue;
		}

		rec = (struct mxfs_disklock_record *)buf;

		if (rec->magic == MXFS_DISKLOCK_MAGIC &&
		    rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		    rec->owner == node_id) {
			int tries;

			/* CAS the exact image we just validated.  On MISCOMPARE
			 * the sector changed under us — re-read and re-decide, because
			 * the new occupant may be a LIVE node (see purge_cas_zero). */
			for (tries = 0; ; tries++) {
				mxfs_pal_mutex_lock(ctx->lock);
				rc = purge_cas_zero(ctx, offset, buf, zerobuf, &nonatomic);
				mxfs_pal_mutex_unlock(ctx->lock);
				if (rc == 0) {
					purged++;
					break;
				}
				if (rc != -EAGAIN) {
					mxfs_pal_log(MXFS_LOG_ERR,
						     "disklock: purge write failed at slot %u: %d",
						     slot, rc);
					wr_fail++;
					break;
				}
				if (tries >= MXFS_PURGE_CAS_RETRIES) {
					mxfs_pal_log(MXFS_LOG_ERR,
						     "disklock: P235-PURGE-CONTENDED slot=%u "
						     "node=%u — the record still names the dead "
						     "node after %d CAS retries; this purge is "
						     "NOT complete",
						     slot, node_id, tries);
					wr_fail++;
					break;
				}
				mxfs_pal_mutex_lock(ctx->lock);
				rc = read_sector(ctx, offset, buf);
				mxfs_pal_mutex_unlock(ctx->lock);
				if (rc < 0) {
					/* Cannot prove the sector is not still the dead node's. */
					if (!rd_fail) {
						first_rd_fail = slot;
						first_rc = rc;
					}
					rd_fail++;
					break;
				}
				if (rec->magic != MXFS_DISKLOCK_MAGIC ||
				    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
				    rec->owner != node_id)
					break;      /* no longer the dead node's — nothing to do */
			}
		}
	}

	t_scan1 = mxfs_pal_time_ms();
	/* test hook, point 3: record scan done, before the final
	 * heartbeat gate/CAS — the second historical hole's exact window. */
	if (ctx->dbg_purge_hook)
		ctx->dbg_purge_hook(ctx->dbg_purge_hook_data, 3, gate_slot);

	/* Clear the node's heartbeat record — scan for actual slot */
	{
		uint32_t hb_slot;
		struct mxfs_disklock_heartbeat *phb;

		for (hb_slot = 0; hb_slot < MXFS_DISKLOCK_HB_SLOTS; hb_slot++) {
			uint64_t hb_off = ctx->base_offset +
					  (uint64_t)hb_slot * MXFS_DISKLOCK_RECORD_SIZE;
			mxfs_pal_mutex_lock(ctx->lock);
			rc = read_sector(ctx, hb_off, buf);
			mxfs_pal_mutex_unlock(ctx->lock);
			if (rc < 0) {
				/* An unread HB sector could be this node's — we cannot
				 * claim the broadcast was made. */
				hb_rd_fail++;
				continue;
			}
			phb = (struct mxfs_disklock_heartbeat *)buf;
			/* D2: also clear a WITHDRAWN stamp — zeroing the dead
			 * node's HB sector is the cluster-wide "slice replay done"
			 * signal that releases every peer's deferred local purge.
			 *
			 * and a RECOVERY_GUARD whose descriptor names the victim.
			 * That sector IS the recovery record, so zeroing it is exactly
			 * the CONSUMABLE transition.
			 *
			 * the gate is re-derived HERE, from the image the CAS
			 * publishes against — phase 0 alone is not enough, because it
			 * decides before the 65536-record scan and the descriptor can
			 * move in between. */
			rc = purge_hb_zeroable(ctx, phb, node_id);
			if (rc == -ENOENT)
				continue;                       /* not this victim's sector */
			if (rc < 0) {
				/* It IS the victim's sector, but the gate re-evaluated on
				 * this image refuses.  Phase 0 let us through, so the state
				 * moved under us: report incompleteness — never publish. */
				mxfs_pal_log(MXFS_LOG_ERR,
					     "disklock: P235-PURGE-REFROZE node=%u slot=%u "
					     "rc=%d — the victim's recovery descriptor changed "
					     "between the freeze gate and the publication; the "
					     "slot is NOT zeroed and recovery is NOT published",
					     node_id, hb_slot, rc);
				hb_found = 1;
				hb_wr_fail = rc;
				break;
			}
			{
				int tries;

				hb_found = 1;
				for (tries = 0; ; tries++) {
					mxfs_pal_mutex_lock(ctx->lock);
					rc = purge_cas_zero(ctx, hb_off, buf, zerobuf, &nonatomic);
					mxfs_pal_mutex_unlock(ctx->lock);
					if (rc == 0)
						break;
					if (rc != -EAGAIN) {
						mxfs_pal_log(MXFS_LOG_ERR,
							     "disklock: purge heartbeat failed "
							     "for node %u slot %u: %d",
							     node_id, hb_slot, rc);
						hb_wr_fail = rc;
						break;
					}
					if (tries >= MXFS_PURGE_CAS_RETRIES) {
						mxfs_pal_log(MXFS_LOG_ERR,
							     "disklock: P235-PURGE-CONTENDED-HB "
							     "node=%u slot=%u — the sector still needs "
							     "publishing after %d CAS retries; "
							     "recovery is NOT published",
							     node_id, hb_slot, tries);
						hb_wr_fail = -EAGAIN;
						break;
					}
					mxfs_pal_mutex_lock(ctx->lock);
					rc = read_sector(ctx, hb_off, buf);
					mxfs_pal_mutex_unlock(ctx->lock);
					if (rc < 0) {
						hb_rd_fail++;
						hb_wr_fail = rc;
						break;
					}
					/* Re-derive the whole decision from the new image. */
					rc = purge_hb_zeroable(ctx, phb, node_id);
					if (rc == -ENOENT)
						break;      /* already published by another survivor */
					if (rc < 0) {
						mxfs_pal_log(MXFS_LOG_ERR,
							     "disklock: P235-PURGE-REFROZE node=%u "
							     "slot=%u rc=%d — descriptor changed under "
							     "the publication CAS; NOT published",
							     node_id, hb_slot, rc);
						hb_wr_fail = rc;
						break;
					}
				}
				break;
			}
		}
	}

purge_done:
	mxfs_pal_mutex_unlock(ctx->purge_lock);

	mxfs_pal_free(buf);
	mxfs_pal_free(zerobuf);
	mxfs_pal_free(batch);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: P-PURGE-DONE node=%u purged=%d scan_ms=%llu "
		     "total_ms=%llu batched=%d rec_unread=%d",
		     node_id, purged,
		     (unsigned long long)(t_scan1 ? t_scan1 - t_scan0 : 0),
		     (unsigned long long)(mxfs_pal_time_ms() - t_start),
		     batch ? 1 : 0, rd_fail);

	if (rd_fail || wr_fail || hb_wr_fail || (!hb_found && hb_rd_fail)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P229-PURGE-INCOMPLETE node=%u purged=%d "
			     "rec_unread=%d (first slot=%u rc=%d) rec_wrfail=%d "
			     "hb_found=%d hb_unread=%d hb_wrfail=%d nonatomic=%d — "
			     "this node's recovery MUST NOT be published as complete",
			     node_id, purged, rd_fail, first_rd_fail, first_rc,
			     wr_fail, hb_found, hb_rd_fail, hb_wr_fail, nonatomic);
		return hb_wr_fail ? hb_wr_fail : -EIO;
	}

	if (nonatomic)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "disklock: P235-PURGE-NONATOMIC node=%u sectors=%d — the "
			     "device has no SCSI COMPARE AND WRITE, so %d of this "
			     "purge's publications were plain writes; safe only "
			     "because a non-SCSI bdev cannot be a shared LUN",
			     node_id, nonatomic, nonatomic);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: purged %d lock records for dead node %u",
		     purged, node_id);

	return purged;
}

int mxfs_disklock_read_all(struct mxfs_disklock_ctx *ctx,
			    struct mxfs_disklock_record *records,
			    int max, int *count)
{
	uint8_t buf[512];
	int found = 0;
	uint32_t slot;

	if (!ctx || !records || !count || !ctx->dev)
		return -EINVAL;

	/* (P-HB-SLOW lockwait_ms=26726 root, D-RELABORT-...-SELFFENCE):
	 * do NOT hold ctx->lock across the whole multi-slot read loop — under
	 * device saturation 64 reads x ~400ms = a ~25s continuous hold that
	 * starves the heartbeat writer toward the 62s lease (the test21
	 * self-fence).  Per-slot lock/unlock (the monitor pass precedent)
	 * bounds the writer's wait to ONE read; slot reads are 512B
	 * device-atomic and need no cross-slot mutual exclusion. */
	for (slot = 0; slot < MXFS_DISKLOCK_MAX_SLOTS && found < max; slot++) {
		uint64_t offset = lock_slot_offset(ctx, slot);
		struct mxfs_disklock_record *rec;
		int rc;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = read_sector(ctx, offset, buf);
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			continue;

		rec = (struct mxfs_disklock_record *)buf;

		if (rec->magic == MXFS_DISKLOCK_MAGIC &&
		    rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE) {
			memcpy(&records[found], rec, sizeof(*rec));
			found++;
		}
	}

	*count = found;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: read_all found %d active lock records", found);
	return 0;
}

/*
 * D2 — voluntary death declaration ("withdraw").
 * The owning FS has force-shut down; its journal slice may hold committed
 * transactions whose buffers were only partially destaged (PROVEN drc@16
 * r13: ifree destaged, dirent-remove abandoned → durable dangling
 * dirent).  Peers MUST replay that slice before they touch anything we
 * held, and they must find out NOW, not after the 62 s stale-sample
 * window.  Stop our heartbeat, then stamp our own HB slot WITHDRAWN
 * (magic/node/fs_gen/epoch kept so the monitor can attribute and
 * generation-check it).  Peers' monitors treat a confirmed WITHDRAWN
 * stamp as instant death → fence → elected slice replay → purge; our
 * grants stay frozen until the replay lands.
 *
 * Sleeps (heartbeat thread join) — process context only.  If the stamp
 * write fails the peers still converge via the normal 62 s stale window;
 * the stamp is a latency optimization for correctness that is enforced
 * by the deferred-purge protocol regardless.
 */
void mxfs_disklock_withdraw(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *hb, *cur;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || ctx->local_slot < 0)
		return;

	mxfs_disklock_stop_heartbeat(ctx);

	hb = mxfs_pal_alloc(sizeof(*hb));
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!hb || !cur) {
		mxfs_pal_free(hb);
		mxfs_pal_free(cur);
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: withdraw stamp alloc failed — peers will "
			     "detect death via the stale-heartbeat window");
		return;
	}

	off = ctx->base_offset +
	      (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;

	/*
	 * the stamp used to be a BLIND write.  If a survivor had already
	 * declared us dead and laid a recovery guard/descriptor on our slot (the
	 * TCP-dead-but-disk-alive case this whole pipeline exists for), the
	 * "voluntary death" stamp destroyed the recovery it was trying to trigger
	 * — including a fence certificate whose SCSI-PR key is already consumed
	 * and unrecoverable.  Read first, refuse if the slot is no longer ours,
	 * and CAS from the exact image so a guard landing inside the window wins.
	 */
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	if (rc == 0 && !hb_own_record(ctx, cur)) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P236-WITHDRAW-REFUSED slot=%d node=%u — %s; the "
			     "recovery that owns our slot already knows we are dead, "
			     "so the stamp is unnecessary and would destroy it",
			     ctx->local_slot, ctx->local_node,
			     hb_foreign_kind(ctx, cur));
		mxfs_pal_free(hb);
		mxfs_pal_free(cur);
		return;
	}

	memset(hb, 0, sizeof(*hb));
	hb->magic = MXFS_DISKLOCK_MAGIC;
	hb->flags = MXFS_DISKLOCK_FLAG_WITHDRAWN;
	hb->node_id = ctx->local_node;
	hb->fs_gen = ctx->fs_gen;
	hb->timestamp_ms = mxfs_pal_time_ms();
	hb->epoch = ctx->epoch;
	hb_feature_fill(ctx, hb);       /* C7 */
	hb->prov = ctx->own_prov;
	hb_ident_fill(ctx, hb, (uint32_t)ctx->local_slot);   /* the
									 * WITHDRAWN record may be the only one a
									 * late monitor sees; it must carry the key */

	mxfs_pal_mutex_lock(ctx->lock);
	if (rc == 0) {
		rc = hb_caw(ctx, HB_CAW_OP_WITHDRAW, "withdraw", off, cur, hb);
		if (rc == -EOPNOTSUPP)      /* (0.60.0, D7): fail closed —
									 * peers declare us on the stale window */
			hb_cas_nocaw_locked(ctx, (uint32_t)ctx->local_slot, "withdraw");
	} else {
		/* The read failed — we cannot see the slot, but a peer that never
		 * gets a death signal waits the full 62 s stale window over a node
		 * that is already gone.  Stamp it; the risk is the earlier one
		 * and strictly smaller than never declaring death at all. */
		rc = write_sector_fua(ctx, off, hb);
	}
	ctx->hb_img_valid = false;
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_free(cur);
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P163-WITHDRAW-STAMP slot=%d node=%u rc=%d — "
		     "voluntary death declared; peers will fence, replay our "
		     "slice, then purge",
		     ctx->local_slot, ctx->local_node, rc);
	mxfs_pal_free(hb);
}

/*
 * (D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-LEAVES-UNFENCEABLE-STALE-
 * REGISTRANT-0356 / D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377): the clean
 * departure released this slot (record kept, flags=EMPTY) and THEN the late
 * PR unregister could not prove the key gone.  slot=RELEASED + key=PRESENT
 * is unfenceable: nothing names the incarnation the key belongs to, so no
 * peer ever PREEMPTs it and this initiator keeps write privilege after the
 * filesystem is gone.  Re-stamp our own released record WITHDRAWN (identity,
 * epoch, fs_gen and the PR key via hb_ident_fill kept) so the peers'
 * monitor takes the D2 path on first sight: fence the key with
 * PREEMPT AND ABORT, replay the (clean) slice, purge the slot.  The record
 * is the durable "storage authority retirement pending" handoff of the
 * ruling's two-phase departure.
 *
 * CAS from the exact released image: if a joiner already claimed the slot
 * (P236-RESTAMP-REFUSED), the key still names nobody — the caller alerts an
 * INDETERMINATE departure and the operator remedy (sg_persist preempt-abort
 * from a live peer, D-0356 item 3) stands.
 */
int mxfs_disklock_restamp_withdrawn_after_release(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *hb, *cur;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || ctx->local_slot < 0)
		return -EINVAL;
	if (ctx->running)
		return -EBUSY;

	hb = mxfs_pal_alloc(sizeof(*hb));
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!hb || !cur) {
		mxfs_pal_free(hb);
		mxfs_pal_free(cur);
		return -ENOMEM;
	}
	off = ctx->base_offset +
	      (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	if (rc) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P303-RESTAMP-READFAIL slot=%d node=%u rc=%d — "
			     "cannot read our released record back; not stamping",
			     ctx->local_slot, ctx->local_node, rc);
		goto out;
	}
	/* our own RELEASED record (mxfs_disklock_release_slot keeps identity and
	 * epoch, only flags -> RETIRE_PENDING) or, if the release never
	 * landed, our own ACTIVE record — anything else is someone else's story.
	 * An EMPTY image with our stamp means a peer already proved the key
	 * absent and completed the retirement: nothing left to fence. */
	if (!(cur->magic == MXFS_DISKLOCK_MAGIC &&
	      (cur->flags == MXFS_DISKLOCK_FLAG_RETIRE_PENDING ||
	       cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE) &&
		  cur->node_id == ctx->local_node &&
		  cur->epoch == ctx->epoch &&
		  !hb_gen_foreign(ctx, cur))) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P303-RESTAMP-REFUSED slot=%d node=%u — %s; the "
			     "released slot is no longer ours to stamp; departure "
			     "stays INDETERMINATE",
			     ctx->local_slot, ctx->local_node,
			     hb_foreign_kind(ctx, cur));
		rc = -ESTALE;
		goto out;
	}

	memset(hb, 0, sizeof(*hb));
	hb->magic = MXFS_DISKLOCK_MAGIC;
	hb->flags = MXFS_DISKLOCK_FLAG_WITHDRAWN;
	hb->node_id = ctx->local_node;
	hb->fs_gen = ctx->fs_gen;
	hb->timestamp_ms = mxfs_pal_time_ms();
	hb->epoch = ctx->epoch;
	hb_feature_fill(ctx, hb);
	hb->prov = ctx->own_prov;
	hb_ident_fill(ctx, hb, (uint32_t)ctx->local_slot);

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_RESTAMP, "restamp", off, cur, hb);
	ctx->hb_img_valid = false;
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == -EOPNOTSUPP)          /* no plain-write emulation */
		hb_cas_nocaw(ctx, (uint32_t)ctx->local_slot, "restamp");
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P303-RETIRE-PENDING-RESTAMPED slot=%d node=%u epoch=%llu "
		     "rc=%d — released slot re-stamped WITHDRAWN because the PR key "
		     "could not be proven retired; peers fence the key, replay the "
		     "clean slice and purge the slot",
		     ctx->local_slot, ctx->local_node,
		     (unsigned long long)ctx->epoch, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(hb);
	return rc;
}

int mxfs_disklock_retire_complete_self(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || ctx->local_slot < 0)
		return -EINVAL;
	if (ctx->running)
		return -EBUSY;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset +
	      (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	if (rc)
		goto out;
	if (!(hb_retire_pending(ctx, cur) &&
	      cur->node_id == ctx->local_node && cur->epoch == ctx->epoch)) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P304-RETIRE-SELF-REFUSED slot=%d node=%u — %s; "
			     "leaving the sector untouched",
			     ctx->local_slot, ctx->local_node,
			     hb_foreign_kind(ctx, cur));
		rc = -ESTALE;
		goto out;
	}
	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_EMPTY;
	hb_ident_rebind(want, (uint32_t)ctx->local_slot);

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_COMPLETE_SELF, "complete-self", off, cur, want);
	ctx->hb_img_valid = false;
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == -EOPNOTSUPP)          /* no plain-write emulation */
		hb_cas_nocaw(ctx, (uint32_t)ctx->local_slot, "complete-self");
	mxfs_pal_log(rc ? MXFS_LOG_WARN : MXFS_LOG_INFO,
		     "mxfs: P304-RETIRE-COMPLETED-SELF slot=%d node=%u rc=%d — "
		     "no PR key to retire; released slot published EMPTY",
		     ctx->local_slot, ctx->local_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

void mxfs_disklock_set_key_state_fn(struct mxfs_disklock_ctx *ctx,
				    mxfs_disklock_key_state_fn fn,
				    void *data)
{
	ctx->key_state_fn = fn;
	ctx->key_state_data = data;
}

void mxfs_disklock_set_key_state_sync_fn(struct mxfs_disklock_ctx *ctx,
					 mxfs_disklock_key_state_fn fn)
{
	ctx->key_state_sync_fn = fn;
}

void mxfs_disklock_set_settle_absent_fn(struct mxfs_disklock_ctx *ctx,
					mxfs_disklock_settle_absent_fn fn,
					void *data)
{
	ctx->settle_absent_fn = fn;
	ctx->settle_absent_data = data;
}

/* (0.61.0, D1/D6): see disklock.h.  Caller holds the departure
 * mutex and the scsipr probe_lock (mxfs_scsipr_settle_absent's callback). */
int mxfs_disklock_retire_cas_empty(struct mxfs_disklock_ctx *ctx, uint32_t slot,
				   struct mxfs_disklock_heartbeat *expect,
				   mxfs_disklock_validate_fn validate_fn,
				   void *validate_data)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || !expect || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc)
		goto out;
	if (memcmp(cur, expect, sizeof(*cur)) != 0 || !hb_retire_pending(ctx, cur)) {
		*expect = *cur;
		rc = HB_RETIRE_CHANGED;
		goto out;
	}
	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_EMPTY;
	hb_ident_rebind(want, slot);

	/* D6: the proof is validated ADJACENT to the write — nothing but the
	 * CAS itself between the consume and the platter. */
	if (validate_fn && validate_fn(validate_data) != 0) {
		rc = HB_RETIRE_WAITING;
		goto out;
	}
	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_EMPTY, "empty", off, cur, want);
	if (rc == 0)
		ctx->retire_seen_ms[slot] = 0;
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == -EOPNOTSUPP) {
		hb_cas_nocaw(ctx, slot, "empty");
		rc = HB_RETIRE_WAITING;
	} else if (rc == 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P304-RETIRE-COMPLETED-BY-PEER slot=%u node=%u "
			     "inc=%llu key=0x%llx — the key is proven retired inside "
			     "one coherent bracket under the departure mutex; released "
			     "slot published EMPTY (consumable)",
			     slot, cur->node_id, (unsigned long long)cur->epoch,
			     (unsigned long long)cur->ident.pr_key);
		*expect = *want;
		rc = HB_RETIRE_EMPTY;
	} else if (rc == -EAGAIN) {
		rc = hb_retire_reread(ctx, off, expect);
	} else {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P304-RETIRE-COMPLETE-WRITEFAIL slot=%u rc=%d — "
			     "retrying next lap", slot, rc);
	}
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

/* see disklock.h.  Mount thread, under the departure lock. */
int mxfs_disklock_retire_settle_own(struct mxfs_disklock_ctx *ctx,
				    uint32_t slot, mxfs_node_id_t node,
				    mxfs_epoch_t epoch, uint64_t key,
				    const char *proof)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot >= MXFS_DISKLOCK_HB_SLOTS || !proof)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc)
		goto out;
	if (!(hb_retire_pending(ctx, cur) && cur->node_id == node &&
	      inc_eq(cur->epoch, epoch) && mxfs_hb_identity_valid(cur, slot) &&
	      cur->ident.pr_key == key)) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P305-RETIRE-OWN-CHANGED slot=%u node=%u inc=%llu "
			     "key=0x%llx — the sector no longer holds that exact "
			     "RETIRE_PENDING record (%s; flags=0x%x node=%u inc=%llu "
			     "ident_key=0x%llx); nothing written",
			     slot, node, (unsigned long long)epoch,
			     (unsigned long long)key, hb_foreign_kind(ctx, cur),
			     cur->flags, cur->node_id, (unsigned long long)cur->epoch,
			     (unsigned long long)cur->ident.pr_key);
		rc = MXFS_DISKLOCK_RETIRE_CHANGED;
		goto out;
	}
	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_EMPTY;
	hb_ident_rebind(want, slot);
	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_SETTLE_OWN, "settle-own", off, cur, want);
	ctx->retire_seen_ms[slot] = 0;
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == -EOPNOTSUPP)          /* no plain-write emulation */
		hb_cas_nocaw(ctx, slot, "settle-own");
	if (rc == 0) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P305-RETIRE-SETTLED-OWN slot=%u node=%u inc=%llu "
			     "key=0x%llx proof=%s — this boot's previous incarnation's "
			     "clean release settled by its successor; record "
			     "published EMPTY (consumable)",
			     slot, node, (unsigned long long)epoch,
			     (unsigned long long)key, proof);
		rc = MXFS_DISKLOCK_RETIRE_EMPTY;
	} else if (rc == -EAGAIN) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P305-RETIRE-OWN-CAS-LOST slot=%u node=%u inc=%llu "
			     "— the sector moved under the settle; re-classify",
			     slot, node, (unsigned long long)epoch);
		rc = MXFS_DISKLOCK_RETIRE_CHANGED;
	} else {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P305-RETIRE-OWN-WRITEFAIL slot=%u rc=%d", slot, rc);
	}
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

void mxfs_disklock_set_recovered_cb(struct mxfs_disklock_ctx *ctx,
				    mxfs_disklock_recovered_cb cb, void *data)
{
	ctx->recovered_cb = cb;
	ctx->recovered_cb_data = data;
}

void mxfs_disklock_set_clean_depart_cb(struct mxfs_disklock_ctx *ctx,
				       mxfs_disklock_clean_depart_cb cb,
				       void *data)
{
	ctx->clean_depart_cb = cb;
	ctx->clean_depart_cb_data = data;
}

void mxfs_disklock_set_vergate_cb(struct mxfs_disklock_ctx *ctx,
				  mxfs_disklock_vergate_cb cb, void *data)
{
	ctx->vergate_cb = cb;
	ctx->vergate_cb_data = data;
}

void mxfs_disklock_set_recov_outcome_cb(struct mxfs_disklock_ctx *ctx,
					mxfs_disklock_recov_outcome_cb cb,
					void *data)
{
	ctx->recov_outcome_cb = cb;
	ctx->recov_outcome_cb_data = data;
}

int mxfs_disklock_protected_mask_refresh(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *rhb;
	uint64_t mask = 0;
	uint32_t slot;
	int rc = 0;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	rhb = mxfs_pal_alloc(sizeof(*rhb));
	if (!rhb)
		return -ENOMEM;
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		int rr;

		if ((int)slot == ctx->local_slot)
			continue;
		mxfs_pal_mutex_lock(ctx->lock);
		rr = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rr == 0) {
			const struct mxfs_recov_desc *d = recov_desc_of(rhb);

			if (d && d->stage >= MXFS_RECOV_STAGE_FENCING)
				mask |= 1ULL << slot;
		} else {
			mask |= ctx->protected_mask & (1ULL << slot);
			rc = rr;
		}
	}
	mxfs_pal_free(rhb);
	mxfs_pal_mutex_lock(ctx->prot_lock);
	if (mask != ctx->protected_mask) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "mxfs: P-RMAN-PROTECT mask=0x%llx was=0x%llx (synchronous refresh)",
		    (unsigned long long)mask, (unsigned long long)ctx->protected_mask);
		ctx->protected_mask = mask;
	}
	ctx->protected_gen++;           /* invalidates any overlapping pass */
	if (ctx->protect_cb)
		ctx->protect_cb(ctx->protect_cb_data, ctx->protected_mask);
	mxfs_pal_mutex_unlock(ctx->prot_lock);
	return rc;
}

void mxfs_disklock_protected_mask_add(struct mxfs_disklock_ctx *ctx, int slot)
{
	uint64_t bit;

	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return;
	bit = 1ULL << slot;
	mxfs_pal_mutex_lock(ctx->prot_lock);
	ctx->protected_gen++;           /* invalidates any overlapping pass */
	if (!(ctx->protected_mask & bit)) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "mxfs: P-RMAN-PROTECT mask=0x%llx was=0x%llx (local proof: slot %d "
		    "descriptor at stage >= FENCING is durable / lease claimed against "
		    "it; protected ahead of the monitor pass)",
		    (unsigned long long)(ctx->protected_mask | bit),
		    (unsigned long long)ctx->protected_mask, slot);
		ctx->protected_mask |= bit;
		if (ctx->protect_cb)
			ctx->protect_cb(ctx->protect_cb_data, ctx->protected_mask);
	}
	mxfs_pal_mutex_unlock(ctx->prot_lock);
}

void mxfs_disklock_set_protect_cb(struct mxfs_disklock_ctx *ctx,
				  void (*cb)(void *data, uint64_t mask),
				  void *data)
{
	if (!ctx)
		return;
	ctx->protect_cb = cb;
	ctx->protect_cb_data = data;
	/* hand the consumer a FRESH view at once: a mount must be protected
	 * before its first CAW write, not one heartbeat interval later */
	if (cb)
		(void)mxfs_disklock_protected_mask_refresh(ctx);
}

uint64_t mxfs_disklock_protected_mask(const struct mxfs_disklock_ctx *ctx)
{
	return ctx ? ctx->protected_mask : 0;
}

/*
 * C7 — join-time admission gate (contract in disklock.h).
 *
 * Classify every non-self HB slot once; slots that are ACTIVE, current
 * fs_gen, and carry a bad feature block are SUSPECTS.  A suspect only
 * blocks admission if it is provably LIVE (timestamp/epoch progression
 * across re-reads spanning >1 HB interval); an unchanged suspect after two
 * rechecks is a pre-gate corpse — the normal death/recovery pipeline owns
 * it, admission proceeds.  A live incompatible incumbent ⇒ -EPROTO: the
 * caller must WITHDRAW this mount (asymmetric policy: joiners never fence
 * established members; the established side's monitor fences intruders).
 */
int mxfs_disklock_join_gate(struct mxfs_disklock_ctx *ctx,
			    uint32_t timeout_ms)
{
	/* one allocation: the record buffer and the per-slot suspect state
	 * (1.1 KB on the stack otherwise) */
	struct join_gate_scratch {
		struct mxfs_disklock_heartbeat hb;
		uint64_t ts[MXFS_DISKLOCK_HB_SLOTS];
		mxfs_epoch_t epoch[MXFS_DISKLOCK_HB_SLOTS];
		uint8_t sus[MXFS_DISKLOCK_HB_SLOTS];   /* 0=no, 1=suspect */
	} *scr;
	struct mxfs_disklock_heartbeat *rhb;
	uint64_t *sus_ts;
	mxfs_epoch_t *sus_epoch;
	uint8_t *sus;
	uint32_t slot, nsus = 0, recheck, waited = 0;
	int rc, fst;

	if (timeout_ms == 0)
		timeout_ms = 12000;

	scr = mxfs_pal_alloc(sizeof(*scr));
	if (!scr)
		return -ENOMEM;
	rhb = &scr->hb;
	sus_ts = scr->ts;
	sus_epoch = scr->epoch;
	sus = scr->sus;
	memset(sus, 0, sizeof(scr->sus));

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off;

		if ((int)slot == ctx->local_slot)
			continue;
		off = ctx->base_offset +
		      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0) {
			/* Fail closed on unreadable slots: cannot admit against an
			 * unknown.  One retry below via the suspect path. */
			sus[slot] = 1;
			sus_ts[slot] = 0;
			sus_epoch[slot] = 0;
			nsus++;
			continue;
		}
		if (rhb->magic != MXFS_DISKLOCK_MAGIC ||
		    rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
		    hb_gen_foreign(ctx, rhb))
			continue;           /* empty / withdrawn corpse / ghost */
		fst = hb_feature_state(rhb);
		/* 0.75.0: a valid block on the other DLM transport is a suspect
		 * too — a live one makes this joiner withdraw exactly like a
		 * foreign proto_gen would. */
		if (fst == MXFS_HBFEAT_OK && hb_transport_mismatch(ctx, rhb))
			fst = MXFS_HBFEAT_TRANSPORT;
		if (fst == MXFS_HBFEAT_OK)
			continue;
		sus[slot] = 1;
		sus_ts[slot] = rhb->timestamp_ms;
		sus_epoch[slot] = rhb->epoch;
		nsus++;
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P-VERGATE-JOIN-SUSPECT slot=%u node=%u epoch=%llu "
		    "state=%d (1=legacy 2=mismatch 3=corrupt 4=transport) — "
		    "awaiting liveness verdict",
		    slot, rhb->node_id, (unsigned long long)rhb->epoch, fst);
	}

	for (recheck = 0; nsus > 0 && recheck < 2; recheck++) {
		uint32_t nap = MXFS_DISKLOCK_HB_INTERVAL_MS + 1000;

		if (waited + nap > timeout_ms)
			break;
		mxfs_pal_sleep_ms(nap);
		waited += nap;

		for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
			uint64_t off;

			if (!sus[slot])
				continue;
			off = ctx->base_offset +
			      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
			mxfs_pal_mutex_lock(ctx->lock);
			rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
			mxfs_pal_mutex_unlock(ctx->lock);
			if (rc < 0)
				continue;       /* still unreadable — stays suspect */
			if (rhb->magic != MXFS_DISKLOCK_MAGIC ||
			    rhb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
			    hb_gen_foreign(ctx, rhb)) {
				sus[slot] = 0;  /* resolved: corpse cleared/withdrawn */
				nsus--;
				continue;
			}
			fst = hb_feature_state(rhb);
			if (fst == MXFS_HBFEAT_OK && hb_transport_mismatch(ctx, rhb))
				fst = MXFS_HBFEAT_TRANSPORT;            /* 0.75.0 */
			if (fst == MXFS_HBFEAT_OK) {
				sus[slot] = 0;  /* compatible incarnation took the slot */
				nsus--;
				continue;
			}
			if (sus_ts[slot] == 0 && sus_epoch[slot] == 0) {
				/* First read of this slot failed earlier: this read is the
				 * BASELINE, not progression.  Stay suspect one more round. */
				sus_ts[slot] = rhb->timestamp_ms;
				sus_epoch[slot] = rhb->epoch;
				continue;
			}
			if (rhb->timestamp_ms != sus_ts[slot] ||
			    rhb->epoch != sus_epoch[slot]) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "mxfs: P-VERGATE-JOIN slot=%u node=%u epoch=%llu "
				    "state=%d proto_gen=%u ours=%u — LIVE protocol-"
				    "incompatible incumbent; withdrawing (join refused)",
				    slot, rhb->node_id,
				    (unsigned long long)rhb->epoch, fst,
				    rhb->feat.proto_gen, (unsigned)MXFS_PROTO_GEN);
				mxfs_pal_free(scr);
				return -EPROTO;
			}
		}
	}

	mxfs_pal_free(scr);
	if (nsus > 0) {
		/* Unchanged across both rechecks (>1 HB interval each): pre-gate
		 * corpses.  The death pipeline owns them; the monitor's per-pass
		 * validation catches any that later turn out to be slow-writers. */
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P-VERGATE-JOIN %u suspect slot(s) classified dead "
		    "corpses — admitted; monitor enforcement armed", nsus);
	}
	ctx->vergate_admitted = true;
	return 0;
}

void mxfs_disklock_mark_recovery_pending(struct mxfs_disklock_ctx *ctx,
					 int slot, mxfs_node_id_t node,
					 mxfs_epoch_t victim_epoch)
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return;
	/*
	 * victim_epoch is an ARGUMENT.  This used to read
	 * node_track[slot].last_epoch back, and the monitor's epoch-change arm
	 * rebases that onto the SUCCESSOR before dispatching the predecessor's
	 * death — so the marker named the live node as the victim, and under
	 * required incarnation matching that match succeeds.
	 */
	mxfs_pal_mutex_lock(ctx->lock);
	ctx->recovery_pending[slot] = true;
	ctx->pending_node[slot] = node;
	ctx->pending_epoch[slot] = victim_epoch;
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P163-RECOVERY-PENDING slot=%d node=%u epoch=%llu — "
		     "purge deferred until slice replay completes%s",
		     slot, node, (unsigned long long)victim_epoch,
		     inc_valid(victim_epoch) ? "" :
			 " (incarnation UNOBSERVED — node-scoped)");
}

/*
 * (docs/whole-cluster-restart.md §6.4): the whole-cluster bootstrap
 * owner names its victims from the SEALED MANIFEST, not from a monitor death
 * snapshot — no monitor ran (nobody was alive to run one).  The manifest entry
 * was built by the survivor scan from the victim's own identity block, frozen
 * across two full dead windows on the reader's clock; freezing it here as the
 * pending-key snapshot is the same act hb_ident_freeze_victim performs at
 * fire_dead, so the fencer (v5_pr_fence_prove) reads exactly the key the
 * victim published.  A zero key freezes nothing: the fence is then REFUSED
 * (NO_VICTIM_KEY), which is the fail-closed direction.
 */
void mxfs_disklock_mark_recovery_pending_ident(struct mxfs_disklock_ctx *ctx,
					       int slot, mxfs_node_id_t node,
					       mxfs_epoch_t victim_epoch,
					       uint64_t pr_key,
					       uint32_t key_gen,
					       const uint8_t host_uuid[16],
					       const uint8_t boot_uuid[16])
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return;
	mxfs_pal_mutex_lock(ctx->lock);
	ctx->pending_key_node[slot]  = node;
	ctx->pending_key_epoch[slot] = victim_epoch;
	ctx->pending_key[slot]       = pr_key;
	ctx->pending_key_gen[slot]   = pr_key ? key_gen : 0;
	if (pr_key && host_uuid && boot_uuid) {
		memcpy(ctx->pending_host[slot], host_uuid, 16);
		memcpy(ctx->pending_boot[slot], boot_uuid, 16);
	} else {
		memset(ctx->pending_host[slot], 0, 16);
		memset(ctx->pending_boot[slot], 0, 16);
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-BOOT-VICTIM-FROZEN slot=%d node=%u inc=%llu "
		     "key=0x%llx gen=%u — victim identity frozen from its own "
		     "published identity block (the sealed manifest after a total "
		     "outage, or the record found at admission), not from a "
		     "monitor death snapshot",
		     slot, node, (unsigned long long)victim_epoch,
		     (unsigned long long)pr_key, key_gen);
	mxfs_disklock_mark_recovery_pending(ctx, slot, node, victim_epoch);
}

bool mxfs_disklock_recovery_is_pending(struct mxfs_disklock_ctx *ctx, int slot)
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return false;
	return ctx->recovery_pending[slot];
}

/*
 * COMPARE-and-clear.  The pending marker is a promise about ONE
 * incarnation.  An unconditional clear lets the completion of victim A retire
 * a marker that has since been re-armed for victim B on the same slot — B's
 * slice is then never replayed and nothing records that it was owed.  The
 * window is real: A's recovery runs for seconds (fence + replay + purge +
 * flush), and the slot becomes claimable the moment A's sector is zeroed.
 */
int mxfs_disklock_clear_recovery_pending(struct mxfs_disklock_ctx *ctx,
					 int slot, mxfs_node_id_t node,
					 mxfs_epoch_t victim_epoch)
{
	mxfs_node_id_t hadn;
	mxfs_epoch_t hade;
	int rc;

	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->lock);
	hadn = ctx->pending_node[slot];
	hade = ctx->pending_epoch[slot];
	if (!ctx->recovery_pending[slot]) {
		rc = -ENOENT;
	} else if (hadn != node) {
		rc = -ESTALE;
	} else if (inc_valid(victim_epoch) && inc_valid(hade) &&
		   !inc_eq(hade, victim_epoch)) {
		/*
		 * Same node, different incarnation: the marker was re-armed for a
		 * SUCCESSOR while our recovery ran.  Leave it — the successor's slice
		 * still owes a replay.
		 */
		rc = -ESTALE;
	} else {
		ctx->recovery_pending[slot] = false;
		/* the descriptor is gone with the pending marker — re-arm
		 * the item-8 corrupt-outcome alert for the slot's next occupant. */
		ctx->outcome_badcrc_alerted[slot] = false;
		rc = 0;
	}
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == -ESTALE)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P237-PENDING-REARMED slot=%d — completion for "
			     "node=%u inc=%llu did NOT clear the marker, which now "
			     "names node=%u inc=%llu; that recovery is still owed",
			     slot, node, (unsigned long long)victim_epoch,
			     hadn, (unsigned long long)hade);
	return rc;
}

mxfs_node_id_t mxfs_disklock_pending_node(struct mxfs_disklock_ctx *ctx,
					  int slot)
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return 0;
	return ctx->pending_node[slot];
}

int mxfs_disklock_recovery_pending_iter(struct mxfs_disklock_ctx *ctx,
					int prev, mxfs_node_id_t *node)
{
	int slot;

	if (!ctx)
		return -1;
	for (slot = prev + 1; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		if (ctx->recovery_pending[slot]) {
			if (node)
				*node = ctx->pending_node[slot];
			return slot;
		}
	}
	return -1;
}

mxfs_epoch_t mxfs_disklock_pending_epoch(struct mxfs_disklock_ctx *ctx,
					 int slot)
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return 0;
	return ctx->pending_epoch[slot];
}

/* ── DURABLE RECOVERY DESCRIPTOR — the milestone state machine ── */

/*
 * Replace a heartbeat sector by compare-and-write from the EXACT image the
 * caller observed, and make the result durable before returning.
 *
 * Durability is not optional here: the whole point of the FENCED milestone is
 * that it is on the platter before the first CAW purge destroys the evidence
 * a successor would need (design review rule 1).  On a transport without CAW the write
 * is FUA'd and confirmed by a cache-piercing read-back of the descriptor we
 * just wrote — the same discipline claim_slot_noncaw and guard_slot use.
 *
 * A lost race is reported as -EAGAIN and NEVER retried here: the caller must
 * re-read and re-decide, because the sector may now be owned by a successor
 * that has already advanced past our stage.
 */
static int recov_cas_durable(struct mxfs_disklock_ctx *ctx, int slot,
			     const struct mxfs_disklock_heartbeat *expect,
			     const struct mxfs_disklock_heartbeat *want)
{
	uint64_t off;
	int rc;

	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_MILESTONE, "recovery-milestone", off, expect, want);
	if (rc == -EOPNOTSUPP)
		/* (0.60.0, D7 companion): the FUA-write + read-back
		 * stand-in (0.11.x-0.59.3) could land a milestone over a successor
		 * that had already advanced the descriptor; the recovery stays at
		 * its current stage (fail closed) and the caller re-decides. */
		hb_cas_nocaw_locked(ctx, (uint32_t)slot, "recovery-milestone");
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == 0)
		rc = mxfs_pal_bdev_flush(ctx->dev);
	return rc;
}

/* Stamp `d` into `want` and seal it against the record's (victim) identity. */
static void recov_desc_seal(struct mxfs_disklock_heartbeat *want)
{
	want->recov.desc.crc32c = recov_desc_crc(want->fs_gen, want->node_id,
						 want->epoch, &want->recov.desc);
}

/*
 * the manifest pointer record gets the SAME identity binding as the
 * descriptor and the outcome — crc32c over its own bytes folded with the
 * sector's {fs_gen, node_id, epoch} — so a pointer spliced next to a
 * different victim's header never validates.
 */
static uint32_t recov_mptr_crc(uint32_t fs_gen, mxfs_node_id_t node_id,
			       mxfs_epoch_t epoch,
			       const struct mxfs_recov_manifest_ptr *mp)
{
	struct {
		uint32_t fs_gen;
		uint32_t node_id;
		uint64_t epoch;
	} __attribute__((packed)) id;
	uint32_t crc;

	id.fs_gen  = fs_gen;
	id.node_id = (uint32_t)node_id;
	id.epoch   = (uint64_t)epoch;
	crc = mxfs_pal_crc32c(~0U, mp,
			      offsetof(struct mxfs_recov_manifest_ptr, crc32c));
	crc = mxfs_pal_crc32c(crc, &mp->writer_epoch, sizeof(mp->writer_epoch));
	return mxfs_pal_crc32c(crc, &id, sizeof(id));
}

/* The STRICT manifest-pointer reader: RECOVERY_GUARD record, our magic, a
 * version we speak, crc valid against the record's victim identity.  A
 * descriptor from a build that never wrote a pointer presents zeroes here
 * and reads as "no pointer", never as garbage. */
static const struct mxfs_recov_manifest_ptr *
recov_mptr_of(const struct mxfs_disklock_heartbeat *hb)
{
	const struct mxfs_recov_manifest_ptr *mp = &hb->recov.mptr;

	if (!recov_desc_present(hb))
		return NULL;
	if (mp->magic != MXFS_RECOV_MPTR_MAGIC ||
	    mp->version != MXFS_RECOV_MPTR_VERSION)
		return NULL;
	if (mp->crc32c != recov_mptr_crc(hb->fs_gen, hb->node_id, hb->epoch, mp))
		return NULL;
	return mp;
}

static void recov_mptr_seal(struct mxfs_disklock_heartbeat *want)
{
	want->recov.mptr.crc32c = recov_mptr_crc(want->fs_gen, want->node_id,
						 want->epoch, &want->recov.mptr);
}

/* crc32c over the manifest header's sealed fields (bytes 0..83). */
static uint32_t rman_hdr_crc(const struct mxfs_rman_hdr *h)
{
	return mxfs_pal_crc32c(~0U, h, offsetof(struct mxfs_rman_hdr, hdr_crc32c));
}

static uint64_t rman_slot_off(const struct mxfs_disklock_ctx *ctx, int slot)
{
	return ctx->rman_offset + (uint64_t)slot * MXFS_RMAN_SLOT_BYTES;
}

/* Monotonic owner liveness stamp: never equal to, never behind, the previous
 * one — survivors detect abandonment by ABSENCE OF CHANGE, so a clock that
 * stalls or steps backwards must not be mistaken for a live owner. */
static uint64_t recov_stamp_after(uint64_t prev)
{
	uint64_t now = mxfs_pal_time_ms();

	return now > prev ? now : prev + 1;
}

/*
 * (design-consult ruling item 7) — the authorization tuple.
 *
 * recov_auth_issue() hands the caller the identity of the recovery it now owns;
 * recov_auth_holds() is the check every stage-changing op runs against the
 * sector it just read.  The owner_term member is what closes the ABA hole:
 * {owner_node, owner_epoch} alone repeat exactly when A is taken over by B and
 * then takes it back within the same session, so a slow A worker holding a
 * pre-B auth would otherwise pass and resume writing under B's (or its own
 * newer) authority.
 *
 * A NULL auth is accepted only where the caller has no prior claim to check —
 * it degrades to the earlier owner-identity test and is never used by the
 * coordinator.
 */
static void recov_auth_issue(struct mxfs_recov_auth *auth,
			     const struct mxfs_recov_desc *d)
{
	if (!auth)
		return;
	auth->victim_node  = d->victim_node;
	auth->victim_epoch = d->victim_epoch;
	auth->recovery_gen = d->recovery_gen;
	auth->owner_term   = d->owner_term;
	auth->victim_slot  = d->victim_slot;
	auth->stage        = d->stage;
}

static bool recov_auth_holds(const struct mxfs_disklock_ctx *ctx,
			     const struct mxfs_recov_desc *d,
			     const struct mxfs_recov_auth *auth)
{
	if (d->owner_node != ctx->local_node ||
	    !inc_eq(d->owner_epoch, ctx->epoch))
		return false;
	if (!auth)
		return true;
	/*
	 * every field below is a TOKEN field — recov_auth_issue copied it
	 * verbatim out of this descriptor — so the test is exact encoded equality,
	 * not an incarnation proof (see recov_tok_eq()).  victim_slot is compared
	 * because the issuer has always copied it and nothing ever checked it: a
	 * stale auth could otherwise pass against a DIFFERENT slot's descriptor
	 * that happened to share victim node, generation and term.  That hazard is
	 * not zero-specific — it applied to nonzero incarnations too.
	 */
	return d->victim_slot  == auth->victim_slot &&
	       d->victim_node  == auth->victim_node &&
	       recov_tok_eq(d->victim_epoch, auth->victim_epoch) &&
	       d->recovery_gen == auth->recovery_gen &&
	       d->owner_term   == auth->owner_term;
}

int mxfs_disklock_recovery_begin(struct mxfs_disklock_ctx *ctx, int slot,
				 mxfs_node_id_t victim,
				 mxfs_epoch_t victim_epoch,
				 uint16_t slice_idx, uint16_t slice_count,
				 uint32_t flags,
				 struct mxfs_recov_auth *out_auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim)
		return -EINVAL;

	/*
	 * ── THIS FUNCTION IS OUT OF THE LIVE RECOVERY PATH ───────────
	 *
	 * It creates a descriptor that reaches MXFS_RECOV_STAGE_FENCED directly,
	 * with fence_kind = MXFS_FENCE_KIND_NONE and no certificate.  That is
	 * exactly the state every gate in this file refuses, and until it
	 * was the ONLY descriptor the cluster ever published — which is why
	 * D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION survived the /75/76
	 * campaign: the certificate was designed, given a wire format and a
	 * proto_gen bump, and then never invoked (0 callers).
	 *
	 * FENCED is now reached only through fence_intent() -> the PREEMPT AND
	 * ABORT -> fence_certify(), and the execution lease only through
	 * recovery_claim / recovery_takeover.  design-consult ruling (design-consult,,
	 * correction 3): "recovery_begin() must leave the live recovery path — do
	 * not retain it as a fallback.  Once certified descriptors exist its
	 * -EBUSY behaviour is incompatible, and its direct production of
	 * FENCED/NONE violates the protocol."
	 *
	 * The refusal is here, at the entry, rather than left to code review: a
	 * function that can mint an uncertified fence record is one edit away from
	 * reintroducing the defect, and a loud -EPROTO at the call is far cheaper
	 * to diagnose than a slice replayed against a live writer.
	 */
	mxfs_pal_log(MXFS_LOG_ERR,
	    "disklock: P238-RECOV-BEGIN-RETIRED slot=%d victim=%u — "
	    "recovery_begin() is retired: it mints a FENCED descriptor with NO "
	    "fence certificate, which every replay gate must refuse.  Use "
	    "fence_intent + PREEMPT AND ABORT + fence_certify to reach FENCED, "
	    "then recovery_claim/recovery_takeover for the execution lease",
	    slot, victim);
	return -EPROTO;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	if (recov_desc_present(cur)) {
		d = recov_desc_of(cur);
		if (!d) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-UNREADABLE slot=%d victim=%u — the slot "
			    "carries a recovery descriptor this build cannot validate "
			    "(torn, or a newer protocol generation); refusing to touch it",
			    slot, victim);
			rc = -EPROTO;
			goto out;
		}
		if (d->victim_node != victim) {
			rc = -ESTALE;
			goto out;
		}
		if (d->owner_node == ctx->local_node &&
		    inc_eq(d->owner_epoch, ctx->epoch)) {
			recov_auth_issue(out_auth, d);
			rc = 0;             /* already ours — resume from d->stage */
			goto out;
		}
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P234-RECOV-OWNED slot=%d victim=%u owner=%u gen=%llu "
		    "stage=%u — another survivor owns this recovery; not publishing",
		    slot, victim, d->owner_node,
		    (unsigned long long)d->recovery_gen, d->stage);
		rc = -EBUSY;
		goto out;
	}

	if (cur->magic != MXFS_DISKLOCK_MAGIC) {
		/* Zeroed sector: the recovery was already published by someone. */
		rc = -ENOENT;
		goto out;
	}
	if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
	     cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
		cur->node_id != victim || hb_gen_foreign(ctx, cur)) {
		rc = -ESTALE;
		goto out;
	}
	/*
	 * ── SUPERSESSION, not "drift" ────────────────────────────────
	 *
	 * This used to warn and then adopt the sector's incarnation, publishing a
	 * recovery for whoever happened to occupy the slot.  With a constant-zero
	 * epoch the branch was unreachable; with real incarnations it is the
	 * common reboot case, and adopting means laying a RECOVERY_GUARD on a LIVE
	 * member — freezing its authority and, via the self-fence check in
	 * hb_cas_own_slot, forcing its filesystem down.
	 *
	 * A same-node, later, ACTIVE incarnation on this slot can only have got
	 * there through the claim pass-1 own-stamp reclaim, which matches on
	 * node_id alone.  That path sets slice_adopted = false, so the successor's
	 * own mount recovery replayed the ENTIRE slice — including every record we
	 * were about to replay.  The recovery is discharged; it is simply not ours
	 * to publish.
	 *
	 * Everything else fails closed.  Supersession requires ALL of: a valid
	 * feature block at the CURRENT proto_gen (a record we cannot fully
	 * interpret proves nothing), flags == ACTIVE (a WITHDRAWN successor is
	 * itself dead and owes its own replay — do not let its presence retire the
	 * predecessor's marker), both incarnations nonzero (zero is never a
	 * wildcard), and the two differing.  node_id, fs_gen and magic were
	 * already proven above.
	 */
	if (inc_valid(victim_epoch) && !inc_eq(cur->epoch, victim_epoch)) {
		int fst = hb_feature_state(cur);

		if (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		    fst == MXFS_HBFEAT_OK &&
		    inc_valid(cur->epoch)) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P237-RECOV-SUPERSEDED slot=%d victim=%u "
			    "victim_inc=%llu slot_inc=%llu — the victim itself reclaimed "
			    "this slot and its own mount recovery replayed the slice; "
			    "retiring our pending recovery instead of guarding a LIVE "
			    "member",
			    slot, victim, (unsigned long long)victim_epoch,
			    (unsigned long long)cur->epoch);
			rc = MXFS_RECOVERY_SUPERSEDED;
			goto out;
		}
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P237-RECOV-INC-MISMATCH slot=%d victim=%u "
		    "victim_inc=%llu slot_inc=%llu flags=0x%x featstate=%d — the "
		    "slot no longer carries the incarnation we were asked to recover "
		    "and this is NOT a provable supersession; refusing to publish",
		    slot, victim, (unsigned long long)victim_epoch,
		    (unsigned long long)cur->epoch, cur->flags, fst);
		rc = -ESTALE;
		goto out;
	}
	if (!inc_valid(victim_epoch))
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P237-RECOV-INC-UNOBSERVED slot=%d victim=%u "
		    "on-disk=%llu%s — the caller never observed the victim's "
		    "incarnation; the descriptor carries the SECTOR's value "
		    "byte for byte (rule 2)%s",
		    slot, victim, (unsigned long long)cur->epoch,
		    inc_valid(cur->epoch) ? "" : " (ZERO)",
		    inc_valid(cur->epoch) ? "" :
		    " — which is NOT an incarnation: no member at this proto_gen "
		    "writes a zero; a torn/spliced sector or a foreign writer "
		    "(D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO)");

	/*
	 * Rule 2: the victim's identity is NEVER overwritten.  Everything the
	 * victim wrote — node_id, fs_gen, epoch, its last timestamp, lock_count,
	 * the §7.C mepoch authority record and the version-gate feature block —
	 * is carried through byte for byte.  Only `flags` changes, and the
	 * previously-dead evict-ring bytes become the descriptor.
	 */
	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
	memset(&want->recov, 0, sizeof(want->recov));
	want->recov.desc.magic          = MXFS_RECOV_DESC_MAGIC;
	want->recov.desc.version        = MXFS_RECOV_DESC_VERSION;
	want->recov.desc.stage          = MXFS_RECOV_STAGE_FENCED;
	want->recov.desc.victim_epoch   = cur->epoch;
	want->recov.desc.owner_epoch    = ctx->epoch;
	/*
	 * The recovery TRANSACTION identity (rule 6).  1, not a counter, and
	 * deliberately so: a descriptor is created at most once per victim
	 * incarnation (begin() refuses when one already exists, and the sector is
	 * only ever zeroed after GRANTS_RELEASED — after which the slot belongs to
	 * a future incarnation with a different victim_epoch).  So the transaction
	 * is named by {victim_node, victim_epoch, victim_slot, recovery_gen}, and
	 * this field exists to stay CONSTANT while owner_term moves.  Do NOT turn
	 * it back into a takeover counter — that is the ABA hole design review rejected.
	 */
	want->recov.desc.recovery_gen   = 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(0);
	want->recov.desc.victim_node    = victim;
	want->recov.desc.owner_node     = ctx->local_node;
	want->recov.desc.victim_fs_gen  = cur->fs_gen;
	want->recov.desc.flags          = flags |
	    (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ?
		 MXFS_RECOV_F_VICTIM_WITHDREW : 0) |
		(hb_victim_snlocal(cur) ? MXFS_RECOV_F_VICTIM_SNLOCAL : 0) |
		(hb_victim_adopted(cur) ? MXFS_RECOV_F_VICTIM_ADOPTED : 0);   /* */
	want->recov.desc.victim_slot    = (uint16_t)slot;
	recov_desc_set_owner_slot(ctx, &want->recov.desc);   /* */
	want->recov.desc.slice_idx      = slice_idx;
	want->recov.desc.slice_count    = slice_count;
	want->recov.desc.stage_seq      = 1;
	want->recov.desc.owner_term     = 1;
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0) {
		recov_auth_issue(out_auth, &want->recov.desc);
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P234-RECOV-FENCED slot=%d victim=%u epoch=%llu "
		    "slice=%u/%u owner=%u gen=%llu term=1 — durable recovery "
		    "descriptor laid down; the victim's authority is now FROZEN "
		    "until GRANTS_RELEASED",
		    slot, victim, (unsigned long long)cur->epoch,
		    slice_idx, slice_count, ctx->local_node,
		    (unsigned long long)want->recov.desc.recovery_gen);
	} else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-BEGIN-FAIL slot=%d victim=%u rc=%d — no "
		    "fence record; nothing may be purged or published",
		    slot, victim, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

/*
 * 0.85.0: the milestone advance, shared by the generic entry point and the
 * IMAGES_REPLAYED+census entry point.  `rec` / `census_zero` are consulted
 * only for stage == IMAGES_REPLAYED: the record (OPEN case) or the
 * CENSUS_ZERO flag rides in the same compare-and-write as the milestone, so
 * a descriptor can never be at IMAGES_REPLAYED with its census undecided.
 */
static int recov_advance_impl(struct mxfs_disklock_ctx *ctx, int slot,
			      unsigned int stage,
			      const struct mxfs_recov_auth *auth,
			      const struct mxfs_recov_obl *rec,
			      bool census_zero)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    stage == MXFS_RECOV_STAGE_NONE || stage > MXFS_RECOV_STAGE_MAX)
		return -EINVAL;
	if ((rec || census_zero) && stage != MXFS_RECOV_STAGE_IMAGES_REPLAYED)
		return -EINVAL;
	if (rec && (rec->flags & (MXFS_RECOV_OBL_F_TERMINAL |
				  MXFS_RECOV_OBL_F_DONE)))
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	/*
	 * the milestone ladder starts at FENCED, and the ONLY way to
	 * reach FENCED is fence_certify().  Without this, a caller holding no
	 * auth (NULL degrades to the owner-identity test) could advance its own
	 * FENCING intent straight to FENCED — manufacturing a "fence" with
	 * fence_kind still NONE.  The gate would catch it, but the state machine
	 * must not be able to produce the lie in the first place.
	 */
	if (d->stage < MXFS_RECOV_STAGE_FENCED ||
	    stage <= MXFS_RECOV_STAGE_FENCED) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-RECOV-ADVANCE-PREFENCE slot=%d victim=%u %u->%u — "
		    "the milestone ladder begins at a CERTIFIED FENCED descriptor; "
		    "only mxfs_disklock_recovery_fence_certify() may reach it",
		    slot, d->victim_node, d->stage, stage);
		rc = -EPERM;
		goto out;
	}
	/* (design review item 15): the manifest pointer is part of the
	 * certificate at EVERY stage >= FENCED; a milestone may not advance
	 * over a descriptor that lost it. */
	if (!recov_mptr_of(cur)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-ADVANCE-NOPTR slot=%d victim=%u %u->%u — the "
		    "certified descriptor carries no valid fence-time manifest "
		    "pointer; refusing to advance",
		    slot, d->victim_node, d->stage, stage);
		rc = -EPERM;
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		/*
		 * — say WHICH test failed, and never assert a takeover we did
		 * not observe.  The old wording claimed "we were taken over" for every
		 * failure and printed only the owner tuple as its evidence; when the
		 * token comparison was what failed, that produced two IDENTICAL tuples
		 * offered as proof of a takeover, and cost a full rig investigation to
		 * see through.  An owner mismatch IS a takeover; a token mismatch is a
		 * stale/foreign auth; both mean the same thing for publication, and
		 * neither may be guessed at in the log.
		 */
		bool owner_ok = (d->owner_node == ctx->local_node) &&
				inc_eq(d->owner_epoch, ctx->epoch);

		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-NOTOURS slot=%d victim=%u stage->%u kind=%s "
		    "— descriptor owner=%u/%llu gen=%llu term=%u vslot=%u vnode=%u "
		    "vepoch=%llu; we are %u/%llu holding auth gen=%llu term=%u "
		    "vslot=%u vnode=%u vepoch=%llu.  NOTHING we did may be published",
		    slot, d->victim_node, stage,
		    owner_ok ? "TOKEN-MISMATCH (stale or foreign auth)"
			     : "TAKEOVER (descriptor owner is not us)",
			d->owner_node, (unsigned long long)d->owner_epoch,
			(unsigned long long)d->recovery_gen, d->owner_term,
			d->victim_slot, d->victim_node,
			(unsigned long long)d->victim_epoch,
			ctx->local_node, (unsigned long long)ctx->epoch,
			auth ? (unsigned long long)auth->recovery_gen : 0ULL,
			auth ? auth->owner_term : 0u,
			auth ? auth->victim_slot : 0u,
			auth ? auth->victim_node : 0u,
			auth ? (unsigned long long)auth->victim_epoch : 0ULL);
		rc = -EBUSY;
		goto out;
	}
	if (d->flags & MXFS_RECOV_F_QUARANTINED) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-QUARANTINED slot=%d victim=%u — this slice "
		    "carries an obligation this build cannot discharge; the milestone "
		    "state machine is terminal here and the slot never becomes "
		    "consumable without operator action",
		    slot, d->victim_node);
		rc = -EPERM;
		goto out;
	}
	/*
	 * (item 5 increment 2, ruling STOP-SHIP 2 and 4): the
	 * obligation gates.  OBLIGATIONS_DONE is the authorization boundary of
	 * real completion; this build has no completion-proof API, so the
	 * generic advance can NEVER reach it (a later increment adds the proof-
	 * carrying entry point).  GRANTS_RELEASED — the purge milestone — is
	 * refused while a valid NON-terminal record still names open
	 * obligations, and refused outright over record bytes that fail to
	 * validate: an unreadable record is never "no obligations".
	 */
	if (stage == MXFS_RECOV_STAGE_OBLIGATIONS_DONE) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-OBLIGATIONS-NOPROOF slot=%d victim=%u %u->%u "
		    "— OBLIGATIONS_DONE needs durable completion evidence and this "
		    "build carries no completion; refusing",
		    slot, d->victim_node, d->stage, stage);
		rc = -EPERM;
		goto out;
	}
	if (stage >= MXFS_RECOV_STAGE_GRANTS_RELEASED &&
	    d->stage < MXFS_RECOV_STAGE_OBLIGATIONS_DONE) {
		const struct mxfs_recov_obl *ob = recov_obl_of(cur);

		if (!ob && recov_obl_present(cur)) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-OBL-CORRUPT slot=%d victim=%u %u->%u — "
			    "the obligation record does not validate; the purge "
			    "milestone is refused (fail closed)",
			    slot, d->victim_node, d->stage, stage);
			rc = -EPROTO;
			goto out;
		}
		if (ob && ob->count && !(ob->flags & MXFS_RECOV_OBL_F_TERMINAL)) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-OBLIGATIONS-OPEN slot=%d victim=%u "
			    "%u->%u count=%u ag_mask=0x%llx seq=%u — the victim's "
			    "obligations are not completed; the purge milestone is "
			    "refused",
			    slot, d->victim_node, d->stage, stage, ob->count,
			    (unsigned long long)ob->obl_ag_mask, ob->pub_seq);
			rc = -EPERM;
			goto out;
		}
		/*
		 * 0.85.0: neither a record nor the CENSUS_ZERO discriminator — the
		 * census of this descriptor was never decided (an IMAGES_REPLAYED
		 * written by a path that carried no verdict).  "No record" is never
		 * "no obligations": refuse the purge milestone, fail closed.
		 */
		if (!ob && !recov_obl_present(cur) &&
		    !(d->flags & MXFS_RECOV_F_CENSUS_ZERO)) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-OBL-UNDECIDED slot=%d victim=%u %u->%u "
			    "— the descriptor carries neither an obligation record nor "
			    "the zero-census flag; its census was never decided, so the "
			    "purge milestone is refused (fail closed)",
			    slot, d->victim_node, d->stage, stage);
			rc = -EPERM;
			goto out;
		}
	}
	if (stage <= d->stage) {
		rc = 0;                 /* monotonic: already at or past this stage */
		goto out;
	}
	/*
	 * 0.85.0: the census verdict rides in the IMAGES_REPLAYED CAS.  A fresh
	 * advance to that stage must decide it; a record already in the sector
	 * below IMAGES_REPLAYED can only be terminal evidence, which the
	 * QUARANTINED gate above already refused — anything else is a protocol
	 * error, never silently overwritten.
	 */
	if (stage == MXFS_RECOV_STAGE_IMAGES_REPLAYED) {
		if (!rec && !census_zero) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-REPLAYED-NOCENSUS slot=%d victim=%u — "
			    "IMAGES_REPLAYED requested without a census verdict; refusing "
			    "(the caller must use the census-carrying entry point)",
			    slot, d->victim_node);
			rc = -EINVAL;
			goto out;
		}
		if (recov_obl_of(cur)) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P234-RECOV-REPLAYED-RECORD-EXISTS slot=%d victim=%u "
			    "— the sector already carries a valid obligation record below "
			    "IMAGES_REPLAYED; refusing to overwrite it",
			    slot, d->victim_node);
			rc = -EEXIST;
			goto out;
		}
	}

	*want = *cur;
	want->recov.desc.stage          = (uint16_t)stage;
	want->recov.desc.stage_seq      = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	if (stage == MXFS_RECOV_STAGE_IMAGES_REPLAYED) {
		if (rec) {
			want->recov.obl = *rec;
			want->recov.obl.crc32c = mxfs_recov_obl_rec_crc(want->fs_gen,
									want->node_id,
									want->epoch,
									&want->recov.obl);
		} else {
			/* the flag IS the verdict; stale bytes from a prior life of
			 * this sector must not read as a corrupt record later */
			memset(&want->recov.obl, 0, sizeof(want->recov.obl));
			want->recov.desc.flags |= MXFS_RECOV_F_CENSUS_ZERO;
		}
	}
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P234-RECOV-STAGE slot=%d victim=%u %u->%u seq=%llu%s",
		    slot, d->victim_node, d->stage, stage,
		    (unsigned long long)want->recov.desc.stage_seq,
		    stage != MXFS_RECOV_STAGE_IMAGES_REPLAYED ? "" :
		    rec ? " (OPEN obligation record published)" : " (census zero)");
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-STAGE-FAIL slot=%d victim=%u %u->%u rc=%d — "
		    "the milestone is NOT durable; the caller must not act as if it is",
		    slot, d->victim_node, d->stage, stage, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_advance(struct mxfs_disklock_ctx *ctx, int slot,
				   unsigned int stage,
				   const struct mxfs_recov_auth *auth)
{
	return recov_advance_impl(ctx, slot, stage, auth, NULL, false);
}

int mxfs_disklock_recovery_advance_obl(struct mxfs_disklock_ctx *ctx, int slot,
				       const struct mxfs_recov_auth *auth,
				       const struct mxfs_recov_obl *rec)
{
	if (rec && rec->count == 0)
		rec = NULL;             /* an empty record IS the zero census */
	return recov_advance_impl(ctx, slot, MXFS_RECOV_STAGE_IMAGES_REPLAYED,
				  auth, rec, rec == NULL);
}

/*
 * fill `want`'s outcome region as a TERMINAL REFUSED record bound
 * to descriptor `d` and the record's victim identity.  Shared by the lease
 * holder's publish path and the leaseless legacy backfill so the two can
 * never diverge in what a terminal record carries.  Touches ONLY the
 * outcome region; the caller owns any descriptor-side change (flag, stamp,
 * seal).  Deterministic for fixed inputs — the backfill path depends on
 * that (racing backfillers write identical bytes).
 */
static void recov_outcome_fill(struct mxfs_disklock_heartbeat *want,
			       const struct mxfs_recov_desc *d,
			       uint16_t reason, uint16_t domain_kind,
			       uint64_t ag_mask, bool digest_valid,
			       uint64_t slice_digest, uint64_t publish_seq,
			       uint32_t refused, uint32_t malformed)
{
	struct mxfs_recov_outcome *oc = &want->recov.outcome;

	memset(oc, 0, sizeof(*oc));
	oc->magic           = MXFS_RECOV_OUTCOME_MAGIC;
	oc->version         = MXFS_RECOV_OUTCOME_VERSION;
	oc->outcome         = MXFS_RECOV_OUTCOME_TERMINAL_REFUSED;
	oc->reason          = reason;
	oc->domain_kind     = domain_kind;
	oc->victim_slot     = d->victim_slot;
	oc->owner_slot      = d->owner_slot;
	oc->victim_epoch    = d->victim_epoch;
	oc->owner_epoch     = d->owner_epoch;
	oc->recovery_gen    = d->recovery_gen;
	oc->ag_mask         = domain_kind == MXFS_RECOV_DOMAIN_AG_MASK ?
			      ag_mask : 0;
	/* Ruling item 5: a failed forensic reread must not gate the verdict.
	 * Publish with the DIGEST_VALID flag clear and the digest zeroed. */
	oc->flags           = digest_valid ?
			      MXFS_RECOV_OUTCOME_F_DIGEST_VALID : 0;
	oc->slice_digest    = digest_valid ? slice_digest : 0;
	oc->publish_seq     = publish_seq;
	oc->victim_node     = d->victim_node;
	oc->victim_fs_gen   = d->victim_fs_gen;
	oc->owner_node      = d->owner_node;
	oc->owner_term      = d->owner_term;
	oc->refused_items   = refused;
	oc->malformed_items = malformed;
	oc->crc32c = recov_outcome_crc(want->fs_gen, want->node_id,
				       want->epoch, oc);
}

/*
 * (ruling): durably publish TERMINAL REFUSED for the victim
 * this auth covers.  Contract in disklock.h.  Authority discipline is
 * recovery_advance's; the write is quarantine-flag + outcome record in one
 * CAS, with the stage deliberately untouched.
 */
static int recov_publish_refusal_body(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    const struct mxfs_recov_refusal_info *info,
				    const struct mxfs_recov_obl *obl,
				    struct mxfs_recov_outcome *oc_out)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_outcome *old_oc;
	struct mxfs_recov_outcome *oc;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !info)
		return -EINVAL;
	/* a record published next to a terminal outcome is evidence
	 * only and MUST say so — an ordinary open-obligation record here would
	 * block the very refusal path it rides on (ruling STOP-SHIP 9). */
	if (obl && !(obl->flags & MXFS_RECOV_OBL_F_TERMINAL))
		return -EINVAL;
	/* ruling: LEGACY_INTENT is NOT a publishable reason here.  No
	 * recovery auth can ever exist over a QUARANTINED descriptor (the
	 * claim path's certificate evaluator refuses it before the owner-
	 * reacquire check), so the legacy backfill is leaseless by
	 * construction and goes through
	 * mxfs_disklock_recovery_backfill_legacy(), never this path. */
	if (info->reason != MXFS_RECOV_REFUSAL_POLICY_REFUSED_COMPLETE &&
	    info->reason != MXFS_RECOV_REFUSAL_PHYSICALLY_TORN &&
	    info->reason != MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED &&
	    info->reason != MXFS_RECOV_REFUSAL_MANIFEST_INVALID &&
	    info->reason != MXFS_RECOV_REFUSAL_ASSEMBLY_DISCONTINUITY &&
	    info->reason != MXFS_RECOV_REFUSAL_DBG_INJECTED &&
	    info->reason != MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED &&
	    info->reason != MXFS_RECOV_REFUSAL_OBLIGATION_UNRECONCILABLE)
		return -EINVAL;
	if (info->domain_kind != MXFS_RECOV_DOMAIN_FSWIDE &&
	    info->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK)
		return -EINVAL;
	/* An empty AG mask quarantines nothing — that is not a refusal domain,
	 * it is a bug in the caller's collection pass.  Refuse it rather than
	 * publish a terminal record that enforces nothing. */
	if (info->domain_kind == MXFS_RECOV_DOMAIN_AG_MASK && info->ag_mask == 0)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		bool owner_ok = (d->owner_node == ctx->local_node) &&
				inc_eq(d->owner_epoch, ctx->epoch);

		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-NOTOURS slot=%d victim=%u op=refusal "
		    "kind=%s — descriptor owner=%u/%llu gen=%llu term=%u; we are "
		    "%u/%llu holding auth gen=%llu term=%u.  NOTHING we did may be "
		    "published",
		    slot, d->victim_node,
		    owner_ok ? "TOKEN-MISMATCH (stale or foreign auth)"
			     : "TAKEOVER (descriptor owner is not us)",
			d->owner_node, (unsigned long long)d->owner_epoch,
			(unsigned long long)d->recovery_gen, d->owner_term,
			ctx->local_node, (unsigned long long)ctx->epoch,
			auth ? (unsigned long long)auth->recovery_gen : 0ULL,
			auth ? auth->owner_term : 0u);
		rc = -EBUSY;
		goto out;
	}
	if (d->flags & MXFS_RECOV_F_QUARANTINED) {
		old_oc = recov_outcome_of(cur);
		if (old_oc &&
		    old_oc->outcome == MXFS_RECOV_OUTCOME_TERMINAL_REFUSED &&
		    old_oc->reason == info->reason &&
		    old_oc->domain_kind == info->domain_kind &&
		    old_oc->ag_mask == info->ag_mask) {
			/* Idempotent: this refusal already landed.  Hand back the
			 * CANONICAL record — the caller imports what the cluster reads,
			 * not its local draft (whose digest/seq may differ). */
			if (oc_out)
				*oc_out = *old_oc;
			rc = 0;
			goto out;
		}
		/* Quarantined by a DIFFERENT verdict (or corrupt/absent outcome
		 * bytes).  Terminal state never gets rewritten — the first
		 * durable verdict wins.  (The QUARANTINED-with-all-zero-outcome
		 * legacy shape is NOT publishable here either: no auth can exist
		 * over a quarantined descriptor, so that state is only reachable
		 * through the leaseless backfill API.) */
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P241-RECOV-TERMINAL-CONFLICT slot=%d victim=%u — "
		    "descriptor already quarantined with %s; refusing to "
		    "overwrite a terminal verdict (ours: reason=%u domain=%u)",
		    slot, d->victim_node,
		    old_oc ? "a different outcome record" :
		    (recov_outcome_present(cur) ? "corrupt outcome bytes" :
						  "no outcome record"),
			info->reason, info->domain_kind);
		rc = -EPERM;
		goto out;
	}

	*want = *cur;
	want->recov.desc.flags         |= MXFS_RECOV_F_QUARANTINED;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	recov_desc_seal(want);

	old_oc = recov_outcome_of(cur);
	recov_outcome_fill(want, d, info->reason, info->domain_kind,
			   info->ag_mask, info->digest_valid, info->slice_digest,
			   old_oc ? old_oc->publish_seq + 1 : 1,
			   info->refused, info->malformed);
	oc = &want->recov.outcome;
	/*
	 * the obligation record rides in the SAME CAS as the verdict,
	 * re-sealed against this very sector's identity (the writer sealed it
	 * against the sector it read; the victim is dead, so the identity is
	 * the same — but the seal is recomputed rather than trusted).
	 */
	if (obl) {
		want->recov.obl = *obl;
		want->recov.obl.crc32c = mxfs_recov_obl_rec_crc(want->fs_gen,
								want->node_id,
								want->epoch,
								&want->recov.obl);
	}

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0 && oc_out)
		*oc_out = *oc;
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P241-RECOV-TERMINAL slot=%d victim=%u/%llu — slice "
		    "replay REFUSED (reason=%u domain=%u ag_mask=0x%llx refused=%u "
		    "malformed=%u digest=%llx dvalid=%d seq=%llu); victim domain "
		    "quarantined cluster-wide, slot frozen until operator action",
		    slot, d->victim_node, (unsigned long long)d->victim_epoch,
		    info->reason, info->domain_kind,
		    (unsigned long long)oc->ag_mask, info->refused, info->malformed,
		    (unsigned long long)oc->slice_digest, (int)info->digest_valid,
		    (unsigned long long)oc->publish_seq);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P241-RECOV-TERMINAL-FAIL slot=%d victim=%u rc=%d — "
		    "the refusal is NOT durable; the caller must keep its retry "
		    "path armed and must not act as if it landed",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_publish_refusal(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    const struct mxfs_recov_refusal_info *info,
				    struct mxfs_recov_outcome *oc_out)
{
	return recov_publish_refusal_body(ctx, slot, auth, info, NULL, oc_out);
}

int mxfs_disklock_recovery_publish_refusal_obl(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    const struct mxfs_recov_auth *auth,
				    const struct mxfs_recov_refusal_info *info,
				    const struct mxfs_recov_obl *obl,
				    struct mxfs_recov_outcome *oc_out)
{
	return recov_publish_refusal_body(ctx, slot, auth, info, obl, oc_out);
}

/* slot-relative byte offset of the obligation zone (recov_obl.h) */
static uint64_t rman_obl_off(const struct mxfs_disklock_ctx *ctx, int slot)
{
	return rman_slot_off(ctx, slot) + MXFS_RMAN_OBL_OFF;
}

/*
 * (item 5 increment 2): make the victim's RECOVER extent list durable
 * in its rman slot zone and hand back the sealed record.  Contract in
 * disklock.h; layout and write protocol in recov_obl.h.
 */
int mxfs_disklock_recovery_obl_write(struct mxfs_disklock_ctx *ctx, int slot,
				     const struct mxfs_recov_auth *auth,
				     struct mxfs_recov_obl_ext *ext,
				     uint32_t count,
				     const struct mxfs_recov_obl_geom *geom,
				     uint64_t census_digest, uint16_t flags,
				     struct mxfs_recov_obl *out_rec)
{
	struct mxfs_disklock_heartbeat *cur = NULL;
	struct mxfs_rman_obl_hdr *hdr = NULL;
	uint8_t *buf = NULL;
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_obl *old;
	uint64_t base, off, seq, mask = 0;
	uint32_t byte_len = 0, io_len = 0, ecrc = 0;
	bool fsw = false;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth || !out_rec || !geom || (count && !ext) ||
	    (flags & ~MXFS_RECOV_OBL_F_ALL) || (flags & MXFS_RECOV_OBL_F_DONE))
		return -EINVAL;     /* DONE is set only by advance_obl_done */
	if (count > MXFS_RECOV_OBL_MAX_EXTENTS)
		return -EOVERFLOW;
	if (count && !ctx->rman_offset)
		return -ENODEV;
	memset(out_rec, 0, sizeof(*out_rec));

	cur = mxfs_pal_alloc(sizeof(*cur));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	if (!cur || !hdr) {
		rc = -ENOMEM;
		goto out;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;
	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (d->stage < MXFS_RECOV_STAGE_FENCED) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P226-OBL-WRITE-PREFENCE slot=%d victim=%u stage=%u — "
		    "an obligation list needs a CERTIFIED descriptor", slot,
		    d->victim_node, d->stage);
		rc = -EPERM;
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-NOTOURS slot=%d victim=%u op=obl-write — "
		    "descriptor owner=%u/%llu gen=%llu term=%u; we are %u/%llu.  "
		    "NOTHING we did may be published",
		    slot, d->victim_node, d->owner_node,
		    (unsigned long long)d->owner_epoch,
		    (unsigned long long)d->recovery_gen, d->owner_term,
		    ctx->local_node, (unsigned long long)ctx->epoch);
		rc = -EBUSY;
		goto out;
	}

	/* canonical form + geometry + mask (in place; refusal => quarantine) */
	rc = mxfs_recov_obl_canonicalize(ext, count, geom, &mask, &fsw);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P226-OBL-NONCANONICAL slot=%d victim=%u count=%u rc=%d "
		    "— the extent list is malformed/overlapping/oversized; nothing "
		    "written (the caller must quarantine)",
		    slot, d->victim_node, count, rc);
		goto out;
	}
	flags &= ~(MXFS_RECOV_OBL_F_FSWIDE | MXFS_RECOV_OBL_F_LIST);
	if (fsw)
		flags |= MXFS_RECOV_OBL_F_FSWIDE;
	if (count)
		flags |= MXFS_RECOV_OBL_F_LIST;

	/*
	 * Publication sequence: strictly greater than any record this sector
	 * carries and any sealed header this slot/victim carries — so a
	 * successor's rewrite is distinguishable from a dead owner's partial
	 * one (same discipline as the manifest writer).  Only a header that
	 * validates for THIS recovery case contributes.
	 */
	seq = 1;
	old = recov_obl_of(cur);
	if (old && old->pub_seq >= seq)
		seq = (uint64_t)old->pub_seq + 1;
	base = rman_obl_off(ctx, slot);
	if (count) {
		rc = mxfs_pal_bdev_read_prio(ctx->dev, base, hdr, sizeof(*hdr));
		if (rc == 0 && hdr->magic == MXFS_RMAN_OBL_MAGIC &&
		    hdr->version == MXFS_RMAN_OBL_VERSION &&
		    hdr->hdr_crc32c == mxfs_rman_obl_hdr_crc(hdr) &&
		    hdr->victim_slot == (uint16_t)slot &&
		    hdr->victim_node == d->victim_node &&
		    hdr->victim_fs_gen == d->victim_fs_gen && hdr->seq >= seq)
			seq = hdr->seq + 1;
		if (rc)
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "disklock: P226-OBL-HDR-PREREAD slot=%d rc=%d — could not read "
			    "the old list header; seq continues from the record only",
			    slot, rc);
		if (seq == 0 || seq > 0xFFFFFFFFULL) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P226-OBL-SEQ-EXHAUSTED slot=%d — publication "
			    "sequence wrapped; refusing to write (fail closed)", slot);
			rc = -EOVERFLOW;
			goto out;
		}

		/* 1. entries, zero-padded to whole 4 KiB blocks, + flush */
		byte_len = count * (uint32_t)sizeof(*ext);
		io_len = (byte_len + MXFS_RMAN_IO_ALIGN - 1) & ~(MXFS_RMAN_IO_ALIGN - 1);
		buf = mxfs_pal_alloc(io_len);
		if (!buf) {
			rc = -ENOMEM;
			goto out;
		}
		memset(buf, 0, io_len);
		memcpy(buf, ext, byte_len);
		ecrc = mxfs_recov_obl_list_crc(ext, count);
		rc = mxfs_pal_bdev_write(ctx->dev,
					 base + (MXFS_RMAN_OBL_ENTRIES_OFF - MXFS_RMAN_OBL_OFF),
					 buf, io_len);
		if (rc == 0)
			rc = mxfs_pal_bdev_flush(ctx->dev);
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P226-OBL-WRITE-FAIL slot=%d victim=%u step=entries "
			    "rc=%d", slot, d->victim_node, rc);
			goto out;
		}

		/* 2. the header LAST, crc'd, FUA + flush */
		memset(hdr, 0, sizeof(*hdr));
		hdr->magic           = MXFS_RMAN_OBL_MAGIC;
		hdr->version         = MXFS_RMAN_OBL_VERSION;
		hdr->flags           = flags;
		hdr->seq             = seq;
		hdr->recovery_gen    = d->recovery_gen;
		hdr->victim_epoch    = (uint64_t)d->victim_epoch;
		hdr->victim_node     = d->victim_node;
		hdr->victim_fs_gen   = d->victim_fs_gen;
		hdr->victim_slot     = (uint16_t)slot;
		hdr->slice_idx       = d->slice_idx;
		hdr->slice_count     = d->slice_count;
		hdr->entry_bytes     = (uint16_t)sizeof(*ext);
		hdr->count           = count;
		hdr->byte_len        = byte_len;
		hdr->entries_crc32c  = ecrc;
		hdr->publisher_node  = ctx->local_node;
		hdr->publisher_epoch = (uint64_t)ctx->epoch;
		hdr->publisher_term  = d->owner_term;
		hdr->agcount         = geom->agcount;
		hdr->census_digest   = census_digest;
		hdr->obl_ag_mask     = mask;
		hdr->stamp_ms        = mxfs_pal_time_ms();
		hdr->agblocks        = geom->agblocks;
		hdr->hdr_crc32c      = mxfs_rman_obl_hdr_crc(hdr);
		rc = mxfs_pal_bdev_write_fua(ctx->dev, base, hdr, sizeof(*hdr));
		if (rc == 0)
			rc = mxfs_pal_bdev_flush(ctx->dev);
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P226-OBL-WRITE-FAIL slot=%d victim=%u step=header "
			    "rc=%d", slot, d->victim_node, rc);
			goto out;
		}
	}

	/* the record the descriptor CAS will carry, sealed to this sector */
	out_rec->magic         = MXFS_RECOV_OBL_MAGIC;
	out_rec->version       = MXFS_RECOV_OBL_VERSION;
	out_rec->flags         = flags;
	out_rec->obl_ag_mask   = mask;
	out_rec->count         = count;
	out_rec->list_crc32c   = count ? ecrc : 0;
	out_rec->census_digest = census_digest;
	out_rec->pub_seq       = count ? (uint32_t)seq : 0;
	out_rec->crc32c = mxfs_recov_obl_rec_crc(cur->fs_gen, (uint32_t)cur->node_id,
						 (uint64_t)cur->epoch, out_rec);
	mxfs_pal_log(MXFS_LOG_DEBUG,
	    "disklock: P226-OBL-WRITE slot=%d victim=%u/%llu gen=%llu count=%u "
	    "ag_mask=0x%llx fswide=%d terminal=%d seq=%llu list_crc=0x%08x "
	    "census=0x%llx bytes=%u — obligation list durable (UNPUBLISHED until "
	    "a descriptor CAS carries the record)",
	    slot, d->victim_node, (unsigned long long)d->victim_epoch,
	    (unsigned long long)d->recovery_gen, count,
	    (unsigned long long)mask, (int)fsw,
	    (flags & MXFS_RECOV_OBL_F_TERMINAL) ? 1 : 0,
	    (unsigned long long)(count ? seq : 0), ecrc,
	    (unsigned long long)census_digest, byte_len);
	rc = 0;
out:
	mxfs_pal_free(buf);
	mxfs_pal_free(hdr);
	mxfs_pal_free(cur);
	return rc;
}

/*
 * the consumer.  Contract in disklock.h.  Every failure after "a
 * record is present" is -EPROTO = QUARANTINE for the caller; only an all-zero
 * record region is -ENOENT.
 */
int mxfs_disklock_recovery_read_obl(struct mxfs_disklock_ctx *ctx, int slot,
				    struct mxfs_recov_obl *rec_out,
				    struct mxfs_recov_obl_ext *ext_out,
				    uint32_t *count_out)
{
	struct mxfs_disklock_heartbeat *cur = NULL;
	struct mxfs_rman_obl_hdr *hdr = NULL;
	struct mxfs_recov_obl_ext *ents = NULL;
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_obl *rec;
	const char *why = "ok";
	uint64_t base, off;
	uint32_t io_len;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !rec_out)
		return -EINVAL;
	memset(rec_out, 0, sizeof(*rec_out));
	if (count_out)
		*count_out = 0;

	cur = mxfs_pal_alloc(sizeof(*cur));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	if (!cur || !hdr) {
		rc = -ENOMEM;
		goto out;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;
	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	rec = &cur->recov.obl;
	rc = mxfs_recov_obl_rec_check(rec, cur->fs_gen, (uint32_t)cur->node_id,
				      (uint64_t)cur->epoch, &why);
	if (rc) {
		if (rc != -ENOENT)
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P226-OBL-READ-INVALID slot=%d victim=%u — record: "
			    "%s (rc=%d); treat as QUARANTINE", slot, d->victim_node,
			    why, rc);
		goto out;
	}
	*rec_out = *rec;
	if (rec->count == 0) {
		rc = 0;
		goto out;
	}
	if (!ctx->rman_offset) {
		why = "record names a list but the device has no rman region";
		rc = -EPROTO;
		goto bad;
	}
	base = rman_obl_off(ctx, slot);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, base, hdr, sizeof(*hdr));
	if (rc < 0) {
		why = "list header unreadable";
		goto bad;
	}
	rc = mxfs_rman_obl_hdr_check(hdr, rec, d->victim_node,
				     (uint64_t)d->victim_epoch, d->victim_fs_gen,
				     d->victim_slot, d->recovery_gen, &why);
	if (rc) {
		rc = -EPROTO;           /* a missing list under a record is corruption */
		goto bad;
	}
	io_len = (hdr->byte_len + MXFS_RMAN_IO_ALIGN - 1) & ~(MXFS_RMAN_IO_ALIGN - 1);
	ents = mxfs_pal_alloc(io_len);
	if (!ents) {
		rc = -ENOMEM;
		goto out;
	}
	rc = mxfs_pal_bdev_read(ctx->dev,
				base + (MXFS_RMAN_OBL_ENTRIES_OFF - MXFS_RMAN_OBL_OFF),
				ents, io_len);
	if (rc < 0) {
		why = "list entries unreadable";
		goto bad;
	}
	rc = mxfs_recov_obl_list_check(ents, hdr->count, hdr, rec, &why);
	if (rc) {
		rc = -EPROTO;
		goto bad;
	}
	if (ext_out)
		memcpy(ext_out, ents, (size_t)hdr->count * sizeof(*ents));
	if (count_out)
		*count_out = hdr->count;
	rc = 0;
	goto out;
bad:
	mxfs_pal_log(MXFS_LOG_ERR,
	    "disklock: P226-OBL-READ-INVALID slot=%d victim=%u seq=%u count=%u — "
	    "list: %s (rc=%d); treat as QUARANTINE", slot, d->victim_node,
	    rec->pub_seq, rec->count, why, rc);
out:
	mxfs_pal_free(ents);
	mxfs_pal_free(hdr);
	mxfs_pal_free(cur);
	return rc;
}

/*
 * ── 0.85.0: the COMPLETION PROOF and OBLIGATIONS_DONE (recov_obl_done.h) ──
 *
 * D-FOREIGN-SLICE-INTENTS-ABANDONED, real EFI completion on the TCP
 * transport.  The custodian (the recovery-lease owner at IMAGES_REPLAYED with
 * an OPEN record) completes every listed extent in its own live
 * transactions, forces its log, writes the allocation metadata home and
 * flushes, then makes THIS proof durable and advances the descriptor in one
 * compare-and-write.  Nothing here acquires a filesystem lock; the engine
 * that does lives in the filesystem layer (xfs_mxfs_recov_obl.c).
 */

/* Read the sector and, for an OPEN record, its list header; both validated.
 * Returns 0 with *d / *rec / hdr filled, or the read_obl-class error. */
static int recov_obl_case_load(struct mxfs_disklock_ctx *ctx, int slot,
			       struct mxfs_disklock_heartbeat *cur,
			       struct mxfs_rman_obl_hdr *hdr,
			       const struct mxfs_recov_desc **d_out,
			       const struct mxfs_recov_obl **rec_out,
			       const char **why)
{
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_obl *rec;
	uint64_t off;
	int rc;

	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0) {
		*why = "sector unreadable";
		return rc;
	}
	d = recov_desc_of(cur);
	if (!d) {
		*why = "not a recovery descriptor";
		return recov_desc_present(cur) ? -EPROTO : -ESTALE;
	}
	rec = &cur->recov.obl;
	rc = mxfs_recov_obl_rec_check(rec, cur->fs_gen, (uint32_t)cur->node_id,
				      (uint64_t)cur->epoch, why);
	if (rc)
		return rc == -ENOENT ? -ENOENT : -EPROTO;
	if (!mxfs_recov_obl_is_open(rec)) {
		*why = "record is not an OPEN case";
		return -EPROTO;
	}
	if (rec->flags & MXFS_RECOV_OBL_F_FSWIDE) {
		*why = "FSWIDE record never enters completion";
		return -EPROTO;
	}
	if (!ctx->rman_offset) {
		*why = "no rman region";
		return -ENODEV;
	}
	rc = mxfs_pal_bdev_read_prio(ctx->dev, rman_obl_off(ctx, slot), hdr,
				     sizeof(*hdr));
	if (rc < 0) {
		*why = "list header unreadable";
		return rc;
	}
	rc = mxfs_rman_obl_hdr_check(hdr, rec, d->victim_node,
				     (uint64_t)d->victim_epoch, d->victim_fs_gen,
				     d->victim_slot, d->recovery_gen, why);
	if (rc)
		return -EPROTO;
	*d_out = d;
	*rec_out = rec;
	return 0;
}

static uint64_t rman_obl_done_off(const struct mxfs_disklock_ctx *ctx, int slot)
{
	return rman_slot_off(ctx, slot) + MXFS_RMAN_OBL_DONE_OFF;
}

int mxfs_disklock_recovery_obl_done_write(struct mxfs_disklock_ctx *ctx,
					  int slot,
					  const struct mxfs_recov_auth *auth,
					  struct mxfs_rman_obl_done *proof)
{
	struct mxfs_disklock_heartbeat *cur = NULL;
	struct mxfs_rman_obl_hdr *hdr = NULL;
	struct mxfs_rman_obl_done *old = NULL, *back = NULL;
	const struct mxfs_recov_desc *d = NULL;
	const struct mxfs_recov_obl *rec = NULL;
	const char *why = "ok";
	uint64_t base, seq = 1;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth || !proof)
		return -EINVAL;
	if (proof->n_sparse) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-SPARSE slot=%d n_sparse=%u — a proof may "
		    "not carry a partially free extent; the case is terminal, not "
		    "done", slot, proof->n_sparse);
		return -EINVAL;
	}
	cur = mxfs_pal_alloc(sizeof(*cur));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	old = mxfs_pal_alloc(sizeof(*old));
	back = mxfs_pal_alloc(sizeof(*back));
	if (!cur || !hdr || !old || !back) {
		rc = -ENOMEM;
		goto out;
	}
	rc = recov_obl_case_load(ctx, slot, cur, hdr, &d, &rec, &why);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-NOCASE slot=%d rc=%d — %s; no proof written",
		    slot, rc, why);
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-NOTOURS slot=%d victim=%u op=obl-done-write "
		    "— descriptor owner=%u/%llu gen=%llu term=%u; we are %u/%llu.  "
		    "NOTHING we did may be published",
		    slot, d->victim_node, d->owner_node,
		    (unsigned long long)d->owner_epoch,
		    (unsigned long long)d->recovery_gen, d->owner_term,
		    ctx->local_node, (unsigned long long)ctx->epoch);
		rc = -EBUSY;
		goto out;
	}
	if (d->stage != MXFS_RECOV_STAGE_IMAGES_REPLAYED ||
	    (d->flags & MXFS_RECOV_F_QUARANTINED)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-STAGE slot=%d victim=%u stage=%u flags=0x%x "
		    "— a proof is written only over IMAGES_REPLAYED; refusing",
		    slot, d->victim_node, d->stage, d->flags);
		rc = -EPERM;
		goto out;
	}
	if (proof->count != rec->count ||
	    proof->n_empty + proof->n_full != rec->count) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-COUNT slot=%d proof count=%u empty=%u "
		    "full=%u vs record count=%u — refusing",
		    slot, proof->count, proof->n_empty, proof->n_full, rec->count);
		rc = -EINVAL;
		goto out;
	}

	base = rman_obl_done_off(ctx, slot);
	/* sequence: above any earlier proof block of this slot (a reused slot's
	 * old proof never matches a new case, but the ordering is still kept) */
	if (mxfs_pal_bdev_read_prio(ctx->dev, base, old, sizeof(*old)) == 0 &&
	    old->magic == MXFS_RMAN_OBL_DONE_MAGIC && old->seq >= seq)
		seq = old->seq + 1;

	/* bind the identity; the caller filled the outcome, counters and uuid */
	proof->magic         = MXFS_RMAN_OBL_DONE_MAGIC;
	proof->version       = MXFS_RMAN_OBL_DONE_VERSION;
	proof->flags         = 0;
	proof->length        = MXFS_RMAN_OBL_DONE_BYTES;
	proof->rman_slot     = (uint32_t)slot;
	proof->recovery_gen  = d->recovery_gen;
	proof->victim_epoch  = (uint64_t)d->victim_epoch;
	proof->victim_node   = d->victim_node;
	proof->victim_fs_gen = d->victim_fs_gen;
	proof->pub_seq       = rec->pub_seq;
	proof->list_crc32c   = rec->list_crc32c;
	proof->hdr_crc32c    = hdr->hdr_crc32c;
	proof->obl_ag_mask   = rec->obl_ag_mask;
	proof->owner_term    = d->owner_term;
	proof->stage_seq     = d->stage_seq;
	proof->rcpt_digest   = 0;   /* retained custody: no transfer receipts */
	proof->completer_node  = ctx->local_node;
	proof->completer_slot  = (uint32_t)ctx->local_slot;
	proof->completer_epoch = (uint64_t)ctx->epoch;
	proof->stamp_ms      = mxfs_pal_time_ms();
	proof->seq           = seq;
	memset(proof->pad, 0, sizeof(proof->pad));

	/* phase 1: the body, UNCOMMITTED, durable */
	proof->crc32c = mxfs_rman_obl_done_crc(cur->fs_gen, (uint32_t)cur->node_id,
					       (uint64_t)cur->epoch, proof);
	rc = mxfs_pal_bdev_write_fua(ctx->dev, base, proof, sizeof(*proof));
	if (rc == 0)
		rc = mxfs_pal_bdev_flush(ctx->dev);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-WRITE-FAIL slot=%d step=body rc=%d", slot, rc);
		goto out;
	}
	/* phase 2: COMMITTED, durable, read back */
	proof->flags = MXFS_RMAN_OBL_DONE_F_COMMITTED;
	proof->crc32c = mxfs_rman_obl_done_crc(cur->fs_gen, (uint32_t)cur->node_id,
					       (uint64_t)cur->epoch, proof);
	rc = mxfs_pal_bdev_write_fua(ctx->dev, base, proof, sizeof(*proof));
	if (rc == 0)
		rc = mxfs_pal_bdev_flush(ctx->dev);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-WRITE-FAIL slot=%d step=commit rc=%d", slot, rc);
		goto out;
	}
	rc = mxfs_pal_bdev_read_prio(ctx->dev, base, back, sizeof(*back));
	if (rc == 0)
		rc = mxfs_rman_obl_done_check(back, rec, hdr, cur->fs_gen,
					      (uint32_t)cur->node_id,
					      (uint64_t)cur->epoch, (uint32_t)slot,
					      d->recovery_gen, &why);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-OBL-DONE-READBACK slot=%d rc=%d — %s; the proof is "
		    "NOT evidence", slot, rc, why);
		rc = rc > 0 ? -EIO : rc;
		goto out;
	}
	mxfs_pal_log(MXFS_LOG_DEBUG,
	    "disklock: P-OBL-DONE-WRITE slot=%d victim=%u/%llu gen=%llu seq=%llu "
	    "count=%u n_empty=%u n_full=%u ag_mask=0x%llx term=%u stage_seq=%llu "
	    "— completion proof COMMITTED and read back",
	    slot, d->victim_node, (unsigned long long)d->victim_epoch,
	    (unsigned long long)d->recovery_gen, (unsigned long long)seq,
	    proof->count, proof->n_empty, proof->n_full,
	    (unsigned long long)proof->obl_ag_mask, proof->owner_term,
	    (unsigned long long)proof->stage_seq);
	rc = 0;
out:
	mxfs_pal_free(back);
	mxfs_pal_free(old);
	mxfs_pal_free(hdr);
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_disklock_recovery_advance_obl_done(struct mxfs_disklock_ctx *ctx,
					    int slot,
					    const struct mxfs_recov_auth *auth)
{
	struct mxfs_disklock_heartbeat *cur = NULL, *want = NULL;
	struct mxfs_rman_obl_hdr *hdr = NULL;
	struct mxfs_rman_obl_done *proof = NULL;
	const struct mxfs_recov_desc *d = NULL;
	const struct mxfs_recov_obl *rec = NULL;
	const char *why = "ok";
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	proof = mxfs_pal_alloc(sizeof(*proof));
	if (!cur || !want || !hdr || !proof) {
		rc = -ENOMEM;
		goto out;
	}
	rc = recov_obl_case_load(ctx, slot, cur, hdr, &d, &rec, &why);
	if (rc == -EPROTO) {
		/* monotonic re-entry: a DONE record under a DONE descriptor */
		const struct mxfs_recov_desc *dd = recov_desc_of(cur);
		const struct mxfs_recov_obl *rr = recov_obl_of(cur);

		if (dd && rr && dd->stage >= MXFS_RECOV_STAGE_OBLIGATIONS_DONE &&
		    (rr->flags & MXFS_RECOV_OBL_F_DONE) &&
		    recov_auth_holds(ctx, dd, auth)) {
			rc = 0;
			goto out;
		}
	}
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-OBL-DONE-NOCASE slot=%d rc=%d — %s; "
		    "OBLIGATIONS_DONE refused", slot, rc, why);
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-NOTOURS slot=%d victim=%u op=obl-done — "
		    "descriptor owner=%u/%llu gen=%llu term=%u; we are %u/%llu.  "
		    "NOTHING we did may be published",
		    slot, d->victim_node, d->owner_node,
		    (unsigned long long)d->owner_epoch,
		    (unsigned long long)d->recovery_gen, d->owner_term,
		    ctx->local_node, (unsigned long long)ctx->epoch);
		rc = -EBUSY;
		goto out;
	}
	if (d->flags & MXFS_RECOV_F_QUARANTINED) {
		rc = -EPERM;
		goto out;
	}
	if (d->stage != MXFS_RECOV_STAGE_IMAGES_REPLAYED) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-OBL-DONE-STAGE slot=%d victim=%u stage=%u — "
		    "OBLIGATIONS_DONE is reached only from IMAGES_REPLAYED; refusing",
		    slot, d->victim_node, d->stage);
		rc = -EPERM;
		goto out;
	}
	rc = mxfs_pal_bdev_read_prio(ctx->dev, rman_obl_done_off(ctx, slot), proof,
				     sizeof(*proof));
	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-OBL-DONE-NOPROOF slot=%d rc=%d — the proof "
		    "block is unreadable; OBLIGATIONS_DONE refused", slot, rc);
		goto out;
	}
	rc = mxfs_rman_obl_done_check(proof, rec, hdr, cur->fs_gen,
				      (uint32_t)cur->node_id, (uint64_t)cur->epoch,
				      (uint32_t)slot, d->recovery_gen, &why);
	if (rc == 0 && (proof->owner_term != d->owner_term ||
			proof->stage_seq != d->stage_seq)) {
		why = "proof was authorized under another lease term / stage_seq";
		rc = -EPROTO;
	}
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-OBLIGATIONS-NOPROOF slot=%d victim=%u rc=%d "
		    "— %s; OBLIGATIONS_DONE refused (the custodian must complete and "
		    "prove again)", slot, d->victim_node, rc, why);
		rc = (rc == -ENOENT || rc == -EINPROGRESS) ? -ENOENT : -EPROTO;
		goto out;
	}

	*want = *cur;
	want->recov.desc.stage          = MXFS_RECOV_STAGE_OBLIGATIONS_DONE;
	want->recov.desc.stage_seq      = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	want->recov.obl.flags          |= MXFS_RECOV_OBL_F_DONE;
	want->recov.obl.crc32c = mxfs_recov_obl_rec_crc(want->fs_gen,
							want->node_id,
							want->epoch,
							&want->recov.obl);
	recov_desc_seal(want);
	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P234-RECOV-OBLIGATIONS-DONE slot=%d victim=%u/%llu "
		    "count=%u n_empty=%u n_full=%u ag_mask=0x%llx seq=%llu — every "
		    "obligation completed and proven; the freeze may lift",
		    slot, d->victim_node, (unsigned long long)d->victim_epoch,
		    proof->count, proof->n_empty, proof->n_full,
		    (unsigned long long)rec->obl_ag_mask,
		    (unsigned long long)want->recov.desc.stage_seq);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P234-RECOV-STAGE-FAIL slot=%d victim=%u %u->%u rc=%d — "
		    "the milestone is NOT durable; the caller must not act as if it is",
		    slot, d->victim_node, d->stage,
		    MXFS_RECOV_STAGE_OBLIGATIONS_DONE, rc);
out:
	mxfs_pal_free(proof);
	mxfs_pal_free(hdr);
	mxfs_pal_free(want);
	mxfs_pal_free(cur);
	return rc;
}

/*
 * The per-sector OPEN-obligation verdict for the observer: what does this
 * already-read sector owe?  Pure function of the bytes; shared by the monitor
 * pass and the registration-time scan so the two cannot disagree.
 */
static void recov_obl_observe(struct mxfs_disklock_ctx *ctx, int slot,
			      const struct mxfs_disklock_heartbeat *hb)
{
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_obl *rec;
	int state = MXFS_OBL_NONE;
	uint32_t vnode = 0, seq = 0;
	uint64_t vepoch = 0, mask = 0;
	bool fsw = false;

	if (!ctx->recov_obl_cb)
		return;
	d = recov_desc_of(hb);
	if (d && d->stage >= MXFS_RECOV_STAGE_IMAGES_REPLAYED &&
	    d->stage < MXFS_RECOV_STAGE_OBLIGATIONS_DONE &&
	    !(d->flags & MXFS_RECOV_F_QUARANTINED)) {
		vnode = d->victim_node;
		vepoch = (uint64_t)d->victim_epoch;
		rec = recov_obl_of(hb);
		if (rec) {
			if (mxfs_recov_obl_is_open(rec)) {
				state = MXFS_OBL_OPEN;
				seq = rec->pub_seq;
				mask = rec->obl_ag_mask;
				fsw = (rec->flags & MXFS_RECOV_OBL_F_FSWIDE) != 0;
			}
		} else if (recov_obl_present(hb) ||
			   !(d->flags & MXFS_RECOV_F_CENSUS_ZERO)) {
			state = MXFS_OBL_INVALID;
			fsw = true;
		}
	}
	ctx->recov_obl_cb(ctx->recov_obl_cb_data, slot, state, vnode, vepoch,
			  seq, mask, fsw);
}

int mxfs_disklock_set_recov_obl_cb(struct mxfs_disklock_ctx *ctx,
				   mxfs_disklock_recov_obl_cb cb, void *data)
{
	struct mxfs_disklock_heartbeat *hb;
	int slot, rc = 0;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	ctx->recov_obl_cb = cb;
	ctx->recov_obl_cb_data = data;
	if (!cb)
		return 0;
	/* synchronous scan: the freeze must exist before the first allocation */
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		int rr;

		mxfs_pal_mutex_lock(ctx->lock);
		rr = mxfs_pal_bdev_read_prio(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rr) {
			rc = rr;            /* the consumer keeps fail-closed defaults */
			continue;
		}
		recov_obl_observe(ctx, slot, hb);
	}
	mxfs_pal_free(hb);
	return rc;
}

/*
 * (design-consult ruling): the shared state+verdict predicate behind
 * every closure gate.  Evaluated on a freshly read image of the victim's
 * heartbeat sector — never on a cached or amortized copy.
 *
 * `check_auth` selects the two callers' authority contracts.  The PUBLISHER
 * (leased) path passes true together with its live recov_auth: the purge is
 * that owner's act, and a NULL auth would silently degrade recov_auth_holds
 * to a bare owner-identity test.  The SCRUB (leaseless) path passes false —
 * no recovery lease over a quarantined descriptor is obtainable by anyone,
 * so the only thing that path may rely on is that a TERMINAL verdict is
 * irreversible public state; mxfs_disklock_terminal_gate_check carries the
 * extra fail-closed conditions it needs instead.
 *
 * victim_slot is checked against `slot` on every call: the descriptor is a
 * byte-copied record, so that field is the only binding between the sector
 * it was found in and the victim it names.
 *
 * 0 = the victim's out-of-closure domain is well defined; *victim / *ag_mask
 * are filled from THIS image.
 */
static int closure_gate_predicate(struct mxfs_disklock_ctx *ctx,
			      const struct mxfs_disklock_heartbeat *hb,
			      int slot,
			      const struct mxfs_recov_auth *auth,
			      bool check_auth,
			      mxfs_node_id_t *victim, uint64_t *ag_mask)
{
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_outcome *oc;

	/*
	 * (design-consult review items 4+5): the IDENTITY BINDING, and the reason
	 * the leaseless form is sound at all.
	 *
	 * recov_desc_of() is the strict reader: it requires the sector to be a
	 * RECOVERY_GUARD record (never an ACTIVE heartbeat) and validates the
	 * descriptor's crc against the sector's own {fs_gen, node_id, epoch}
	 * triple.  So a slot whose occupant is LIVE cannot present a descriptor
	 * here at all — the platter read itself, not a cached monitor opinion, is
	 * what proves the slot has no live tenant.  A descriptor spliced beside a
	 * different victim's header does not validate.
	 *
	 * On top of that the checks below bind the verdict to THIS filesystem and
	 * THIS incarnation: a pre-mkfs ghost sector, or a descriptor naming a
	 * different node/incarnation/slot than the record it sits in, authorizes
	 * nothing.  Without them a stale terminal record for an earlier occupant
	 * of a slot could authorize stripping a LATER occupant's grants — the DLM
	 * bit is indexed by slot, so it would name the wrong node.
	 */
	if (hb_gen_foreign(ctx, hb))
		return -ESTALE;
	if (dl_inject_take(&mxfs_dl_inject_closure_crc)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P299-INJECT-GATE-CRC slot=%d — closure-gate descriptor "
		    "forced unparseable", slot);
		return -EPROTO;
	}
	d = recov_desc_of(hb);
	if (!d)
		return recov_desc_present(hb) ? -EPROTO : -ESTALE;
	if (d->victim_slot != (uint16_t)slot ||
	    d->victim_node != hb->node_id ||
	    !inc_eq(d->victim_epoch, hb->epoch) ||
	    d->victim_fs_gen != hb->fs_gen)
		return -EPROTO;
	if (check_auth && !recov_auth_holds(ctx, d, auth))
		return -EBUSY;
	if (!(d->flags & MXFS_RECOV_F_QUARANTINED))
		return -EINVAL;         /* not terminal — this is the full purge's job */
	oc = recov_outcome_of(hb);
	if (!oc)
		return -EBADMSG;        /* quarantined without a readable verdict */
	if (oc->outcome != MXFS_RECOV_OUTCOME_TERMINAL_REFUSED ||
	    oc->domain_kind != MXFS_RECOV_DOMAIN_AG_MASK ||
	    oc->ag_mask == 0)
		return -EOPNOTSUPP;     /* FSWIDE (or malformed domain): no
								 * out-of-closure set exists */
	if (victim)
		*victim = d->victim_node;
	if (ag_mask)
		*ag_mask = oc->ag_mask;
	return 0;
}

/*
 * One authoritative read of slot's heartbeat sector into a caller-owned 512 B
 * buffer.  Every gate evaluation below starts here — the ruling forbids
 * amortizing or caching the image a destructive CAS is authorized from.
 */
static int closure_read_gate_sector(struct mxfs_disklock_ctx *ctx, int slot,
				    uint8_t *buf)
{
	uint64_t off = ctx->base_offset +
		       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	int rc;

	if (dl_inject_take(&mxfs_dl_inject_closure_read)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P299-INJECT-GATE-READ slot=%d — closure-gate sector "
		    "read forced to -EIO", slot);
		return -EIO;
	}
	mxfs_pal_mutex_lock(ctx->lock);
	rc = read_sector(ctx, off, buf);
	mxfs_pal_mutex_unlock(ctx->lock);
	return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_closure_gate_snapshot(struct mxfs_disklock_ctx *ctx, int slot,
					const struct mxfs_recov_auth *auth,
					mxfs_node_id_t *victim,
					uint64_t *ag_mask)
{
	uint8_t *buf;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth || !victim || !ag_mask)
		return -EINVAL;
	buf = mxfs_pal_alloc(512);
	if (!buf)
		return -ENOMEM;
	rc = closure_read_gate_sector(ctx, slot, buf);
	if (rc == 0)
		rc = closure_gate_predicate(ctx,
			(const struct mxfs_disklock_heartbeat *)buf, slot,
			auth, true, victim, ag_mask);
	mxfs_pal_free(buf);
	return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_closure_gate_revalidate(struct mxfs_disklock_ctx *ctx,
					  int slot,
					  const struct mxfs_recov_auth *auth,
					  mxfs_node_id_t victim,
					  uint64_t ag_mask)
{
	mxfs_node_id_t v2 = 0;
	uint64_t m2 = 0;
	uint8_t *buf;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth)
		return -EINVAL;
	buf = mxfs_pal_alloc(512);
	if (!buf)
		return -ENOMEM;
	rc = closure_read_gate_sector(ctx, slot, buf);
	if (rc == 0)
		rc = closure_gate_predicate(ctx,
			(const struct mxfs_disklock_heartbeat *)buf, slot,
			auth, true, &v2, &m2);
	/*
	 * An unreadable gate sector is NOT a pass.  let the scan carry on
	 * through one; under the ruling every destructive CAS must be
	 * authorized by a gate image we actually read, so I/O failure propagates
	 * and the caller stops with retry-required.
	 */
	if (rc == 0 && dl_inject_take(&mxfs_dl_inject_closure_mask)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P299-INJECT-GATE-MASK slot=%d — closure-gate revalidate "
		    "ag_mask perturbed 0x%llx->0x%llx", slot,
		    (unsigned long long)m2, (unsigned long long)(m2 ^ 1ULL));
		m2 ^= 1ULL;
	}
	if (rc == 0 && (v2 != victim || m2 != ag_mask))
		rc = -ESTALE;
	mxfs_pal_free(buf);
	return rc;
}

/* Contract in disklock.h. */
int mxfs_disklock_terminal_gate_check(struct mxfs_disklock_ctx *ctx, int slot,
				      mxfs_node_id_t *victim,
				      uint64_t *ag_mask)
{
	uint8_t *buf;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim || !ag_mask)
		return -EINVAL;
	/*
	 * FAIL CLOSED on liveness, in TWO independent ways (design-consult review item 4:
	 * an advisory tracker alone is not enough, because an UNMONITORED slot
	 * reads as "not live" and that must never mean "known dead").
	 *
	 *  1. Here: our own monitor's opinion.  It is advisory and incomplete, so
	 *     it is used only to REFUSE, never to authorize — a slot it calls
	 *     live (our own included) stops us dead.
	 *  2. Authoritatively, in closure_gate_predicate below: the platter
	 *     sector must be a RECOVERY_GUARD record whose descriptor crc binds
	 *     to its own {fs_gen, node_id, epoch}.  A live tenant writes ACTIVE
	 *     heartbeats there, which cannot present a descriptor at all.  THAT
	 *     is the proof; the monitor check is the belt around it.
	 *
	 * An unmonitored slot therefore does not get stripped on a tracker
	 * technicality — it gets stripped only if the platter itself still shows
	 * a guarded, quarantined, terminally-refused victim of this filesystem.
	 */
	if (mxfs_disklock_slot_live(ctx, slot))
		return -EBUSY;
	buf = mxfs_pal_alloc(512);
	if (!buf)
		return -ENOMEM;
	rc = closure_read_gate_sector(ctx, slot, buf);
	if (rc == 0)
		rc = closure_gate_predicate(ctx,
			(const struct mxfs_disklock_heartbeat *)buf, slot,
			NULL, false, victim, ag_mask);
	mxfs_pal_free(buf);
	return rc;
}

/*
 * (design-consult ruling): leaseless backfill of the LEGACY intent-path
 * quarantine.  Contract in disklock.h.  A descriptor QUARANTINED with an
 * ALL-ZERO outcome region is terminal state from a pre-outcome build; no
 * recovery auth can ever exist over it (the claim path's certificate
 * evaluator refuses quarantined descriptors before the owner-reacquire
 * check), so the synthesized verdict is written WITHOUT authority — but
 * under the tightest possible predicate, with the descriptor bytes
 * preserved exactly (owner/epoch/gen/term/stage/flags/stamp untouched)
 * and deterministic outcome bytes, so racing backfillers write identical
 * records and the full-record CAS makes the race benign.
 */
int mxfs_disklock_recovery_backfill_legacy(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    struct mxfs_recov_outcome *oc_out)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_outcome *oc;
	uint64_t off;
	int tries, rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	for (tries = 0; tries < 5; tries++) {
		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			goto out;

		if (!recov_desc_present(cur)) {
			rc = -ENOENT;       /* no recovery descriptor on this slot */
			goto out;
		}
		if (hb_gen_foreign(ctx, cur)) {
			/* (design-consult ruling Q2): a pre-mkfs ghost is not this
			 * filesystem's recovery object, so it is not "inherited
			 * emptiness" to terminalize either.  Backfill is a WRITE; a
			 * foreign generation may never authorize one.  The classifier
			 * cannot reach this arm any more (read_outcome gates first), but
			 * this is the function that mutates, so it carries its own gate. */
			rc = -ESTALE;
			goto out;
		}
		d = recov_desc_of(cur);
		if (!d) {
			rc = -EPROTO;       /* descriptor bytes present, unparseable */
			goto out;
		}
		if (d->victim_slot != (uint16_t)slot) {
			/* (review): the descriptor CRC binds the
			 * SECTOR's fs_gen/node_id/epoch — bytes that travel with a
			 * byte-copied record — so victim_slot is the only binding
			 * to the slot this sector was read from.  A mismatch is a
			 * misplaced or copied record: never backfill it and never
			 * treat it as legacy emptiness.  (No reason/scope predicate
			 * exists to check beyond this: a legacy descriptor is
			 * exactly QUARANTINED flag + all-zero outcome region.) */
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P241-RECOV-BACKFILL-IDENT slot=%d victim=%u "
			    "victim_slot=%u — descriptor's victim identity does not "
			    "match the sector it was read from; refusing backfill "
			    "(fail closed)",
			    slot, d->victim_node, d->victim_slot);
			rc = -EPROTO;
			goto out;
		}
		if (!(d->flags & MXFS_RECOV_F_QUARANTINED)) {
			/* Live descriptor: not legacy-terminal state.  A live recovery
			 * publishes a real verdict with real evidence under its lease;
			 * backfill fills inherited emptiness only. */
			rc = -EAGAIN;
			goto out;
		}
		oc = recov_outcome_of(cur);
		if (oc) {
			/* A verdict already landed (possibly a racing backfiller's).
			 * First durable verdict wins — hand back the canonical record
			 * for import. */
			if (oc_out)
				*oc_out = *oc;
			rc = 0;
			goto out;
		}
		if (recov_outcome_present(cur)) {
			/* Nonzero bytes that fail validation: corruption.  Backfill
			 * fills exact emptiness, it never overwrites — fail closed. */
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P241-RECOV-BACKFILL-BADOC slot=%d victim=%u — "
			    "quarantined descriptor carries nonzero outcome bytes that "
			    "fail validation; refusing to overwrite (fail closed)",
			    slot, d->victim_node);
			rc = -EBADMSG;
			goto out;
		}

		/* Eligible: QUARANTINED + outcome region exactly all-zero.  The
		 * intent path recorded no domain evidence, so the synthesized
		 * record is FSWIDE with LEGACY_INTENT provenance (Q1). */
		*want = *cur;
		recov_outcome_fill(want, d,
				   MXFS_RECOV_REFUSAL_LEGACY_INTENT_QUARANTINE,
				   MXFS_RECOV_DOMAIN_FSWIDE,
				   0, false, 0, 1, 0, 0);

		rc = recov_cas_durable(ctx, slot, cur, want);
		if (rc == 0) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P241-RECOV-BACKFILL slot=%d victim=%u — "
			    "descriptor quarantined by the legacy intent path with no "
			    "outcome record; backfilled a synthesized FSWIDE terminal "
			    "verdict so peers converge instead of parking",
			    slot, d->victim_node);
			if (oc_out)
				*oc_out = want->recov.outcome;
			goto out;
		}
		if (rc != -EAGAIN)
			goto out;           /* I/O failure: not durable, caller re-arms */
		/* CAS lost: something changed under us.  Reread and reclassify —
		 * a racing backfiller's identical record imports via the oc branch
		 * above; anything else reclassifies or fails closed. */
	}
	rc = -EAGAIN;
out:
	if (rc < 0 && rc != -EAGAIN)
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P241-RECOV-BACKFILL-FAIL slot=%d rc=%d — legacy "
		    "terminalization did NOT land; the caller must fail closed or "
		    "keep its retry path armed",
		    slot, rc);
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

/*
 * (ruling item 2): synchronous canonical-outcome read.
 * Return-code contract in disklock.h.  No authority needed — a terminal
 * outcome is public state; -EPERM conflict losers and late mounts both
 * import through here instead of trusting a local draft or waiting a
 * monitor lap.
 */
int mxfs_disklock_recovery_read_outcome(struct mxfs_disklock_ctx *ctx,
				    int slot,
				    struct mxfs_recov_outcome *oc_out)
{
	struct mxfs_disklock_heartbeat *cur;
	const struct mxfs_recov_outcome *oc;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !oc_out)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	rc = recov_outcome_structural(ctx, cur, slot, &oc);
	if (rc == 0)
		*oc_out = *oc;
out:
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_disklock_recovery_refresh(struct mxfs_disklock_ctx *ctx, int slot,
				   const struct mxfs_recov_auth *auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (!recov_auth_holds(ctx, d, auth)) {
		rc = -ESTALE;           /* taken over: stop touching it */
		goto out;
	}

	*want = *cur;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_read(struct mxfs_disklock_ctx *ctx, int slot,
				struct mxfs_recov_desc *out)
{
	struct mxfs_disklock_heartbeat *cur;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == 0) {
		d = recov_desc_of(cur);
		if (d) {
			if (out)
				*out = *d;
			rc = 0;
		} else {
			rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
		}
	}
	mxfs_pal_free(cur);
	return rc;
}

/*
 * The abandonment observation both takeover primitives pay: a FULL
 * MXFS_RECOV_ABANDON_MS of wall on this node's clock, after which the
 * descriptor is re-read and compared.  Two properties, both load-bearing:
 *
 *   - It is never SHORTENED.  An interruptible sleep wakes on any pending
 *     signal, and a proof taken over less than the interval would be a
 *     proof of nothing; so the wait loops until the interval has elapsed
 *     on the monotonic clock, whatever woke it.
 *   - It is ABANDONED, never certified, when a fatal signal is pending on
 *     the calling task (a mount(2) that `timeout` is terminating).  The
 *     caller gets -EINTR and takes nothing over; the descriptor is
 *     untouched and the next attempt starts its own observation.  A
 *     worker thread has no signals and pays the interval in full, as
 *     before.  Measured D-0980: the barrier's bound counted only its own
 *     poll sleeps, so the 6 s inside each takeover was invisible to it,
 *     and a mount(2) parked here could not be ended by SIGTERM.
 */
static int recov_abandon_wait(void)
{
	uint64_t t0 = mxfs_pal_time_ms();
	uint64_t now;
	uint32_t left = MXFS_RECOV_ABANDON_MS;

	for (;;) {
		mxfs_pal_sleep_ms_interruptible(left);
		if (mxfs_pal_fatal_signal_pending())
			return -EINTR;
		now = mxfs_pal_time_ms();
		if (now - t0 >= MXFS_RECOV_ABANDON_MS)
			return 0;
		left = MXFS_RECOV_ABANDON_MS - (uint32_t)(now - t0);
	}
}

int mxfs_disklock_recovery_takeover(struct mxfs_disklock_ctx *ctx, int slot,
				    struct mxfs_recov_auth *out_auth)
{
	struct mxfs_disklock_heartbeat *first, *again, *want;
	const struct mxfs_recov_desc *d0, *d1;
	struct mxfs_recov_desc snap;
	uint64_t off;
	unsigned int stage;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	first = mxfs_pal_alloc(sizeof(*first));
	again = mxfs_pal_alloc(sizeof(*again));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!first || !again || !want) {
		rc = -ENOMEM;
		goto out;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, first, sizeof(*first));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d0 = recov_desc_of(first);
	if (!d0) {
		rc = recov_desc_present(first) ? -EPROTO : -ENOENT;
		goto out;
	}
	if (d0->owner_node == ctx->local_node &&
	    inc_eq(d0->owner_epoch, ctx->epoch)) {
		recov_auth_issue(out_auth, d0);
		rc = (int)d0->stage;    /* already ours */
		goto out;
	}
	if (d0->flags & MXFS_RECOV_F_QUARANTINED) {
		rc = -EPERM;
		goto out;
	}
	snap = *d0;

	/*
	 * Rule 5 / the discipline: abandonment is ABSENCE OF CHANGE across
	 * MXFS_RECOV_ABANDON_MS, never clock arithmetic — owner_stamp_ms is the
	 * OWNER's boot-relative time and means nothing on our clock.  Any change
	 * at all (a re-stamp, a stage advance, a takeover by a third node) proves
	 * someone else is driving this recovery.
	 *
	 * This is the SECOND gate, not the first.  A stalled stamp proves only "I
	 * observed no refresh"; the caller must already have confirmed the current
	 * owner's session dead AND fenced from the LUN (header rule 5).  We sleep
	 * MXFS_RECOV_ABANDON_MS here, which is why this call may never run on the
	 * heartbeat monitor thread.  A fatal signal on the caller abandons the
	 * observation (see recov_abandon_wait): nothing is taken over.
	 */
	rc = recov_abandon_wait();
	if (rc)
		goto out;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d1 = recov_desc_of(again);
	if (!d1) {
		rc = recov_desc_present(again) ? -EPROTO : -ENOENT;
		goto out;
	}
	if (d1->victim_node != snap.victim_node ||
	    d1->victim_epoch != snap.victim_epoch ||
	    d1->owner_node != snap.owner_node ||
	    d1->owner_epoch != snap.owner_epoch ||
	    d1->recovery_gen != snap.recovery_gen ||
	    d1->owner_term != snap.owner_term ||
	    d1->stage != snap.stage ||
	    d1->stage_seq != snap.stage_seq ||
	    d1->owner_stamp_ms != snap.owner_stamp_ms) {
		rc = -EBUSY;            /* owner is alive / a third node took over */
		goto out;
	}

	/*
	 * Take ONLY the owner fields.  Victim identity, recovery_gen and stage are
	 * preserved: recovery_gen names the TRANSACTION and must survive the change
	 * of authority (rule 6), and the successor RESUMES from the recorded
	 * milestone rather than re-running an earlier one, because peers may
	 * already have acted on the later one.  owner_term is what moves — it is
	 * the only field that makes a pre-takeover worker's authorization tuple
	 * fail its recheck.
	 */
	stage = d1->stage;
	*want = *again;
	want->recov.desc.owner_node     = ctx->local_node;
	want->recov.desc.owner_epoch    = ctx->epoch;
	recov_desc_set_owner_slot(ctx, &want->recov.desc);   /* */
	want->recov.desc.owner_term     = d1->owner_term + 1;
	want->recov.desc.stage_seq      = d1->stage_seq + 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d1->owner_stamp_ms);
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, again, want);
	if (rc == 0) {
		recov_auth_issue(out_auth, &want->recov.desc);
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P234-RECOV-TAKEOVER slot=%d victim=%u from owner=%u "
		    "gen=%llu term=%u->%u resuming at stage=%u — this is a RECOVERY "
		    "LEASE, not a member slot: no ACTIVE, no fresh journal over the "
		    "victim's slice, no mount on it until the slot is CONSUMABLE",
		    slot, snap.victim_node, snap.owner_node,
		    (unsigned long long)snap.recovery_gen,
		    snap.owner_term, want->recov.desc.owner_term, stage);
		rc = (int)stage;
	}
out:
	mxfs_pal_free(first);
	mxfs_pal_free(again);
	mxfs_pal_free(want);
	return rc;
}

/*
 * ── THE FENCE-EVIDENCE CHANNEL, C side ─────────────────────────────
 *
 * Measured on the rig: a peer death produces exactly ONE node whose
 * PREEMPT AND ABORT completes and 30 whose 0x05 hits RESERVATION CONFLICT,
 * while the replayer is chosen by lowest_live_slot and — in the captured run —
 * was one of the LOSERS, dispatching foreign replay 22 ms after its own
 * proves_excl=0.  Exclusion is proved by one node and consumed by another, so
 * the proof needs a durable channel between them: the victim's own sector.
 *
 * Four calls implement it.  fence_intent lays down the attempt BEFORE the P&A
 * so the attempt is serialised and a crash mid-fence is distinguishable from
 * "never started"; fence_certify turns a proved exclusion into the immutable
 * certificate and releases the descriptor UNOWNED; recovery_claim takes the
 * unowned certified descriptor as the execution lease; replay_authorized is
 * the gate every destructive step must pass.
 *
 * fence_takeover exists for one specific case and no other: the prover died
 * with the intent durable.  A successor may retry the P&A and certify ITS OWN
 * result.  It may NEVER certify the dead prover's — ruled the inference
 * "intent exists + prover died + victim key absent => the intended P&A
 * completed" UNSOUND, because it depends on target-specific registration-
 * removal semantics.  Where the key is already gone and no new accepted
 * exclusion operation can be performed, the slice stays unreplayable.  That is
 * a deliberate loss of capacity, not a bug to be optimised away.
 */

/* Hand the caller the fencing-ATTEMPT lease it now holds. */
static void recov_fence_auth_issue(struct mxfs_recov_fence_auth *auth,
				   const struct mxfs_recov_desc *d)
{
	if (!auth)
		return;
	auth->victim_node  = d->victim_node;
	auth->victim_epoch = d->victim_epoch;
	auth->recovery_gen = d->recovery_gen;
	auth->victim_key   = d->fence_victim_key;
	auth->fence_term   = d->fence_term;
	auth->victim_slot  = d->victim_slot;
}

/*
 * Is this descriptor's FENCING-ATTEMPT lease ours?  Deliberately NOT
 * recov_auth_holds(): that one tests the recovery-EXECUTION lease, and the two
 * authorities are held by different nodes at different stages.  The
 * prover identity is the certificate's own fence_prover_* pair, not the owner
 * fields, so a successor that takes the attempt over cannot pass as the
 * original prover.
 */
static bool recov_fence_auth_holds(const struct mxfs_disklock_ctx *ctx,
				   const struct mxfs_recov_desc *d,
				   const struct mxfs_recov_fence_auth *auth)
{
	if (d->owner_node != ctx->local_node ||
	    !inc_eq(d->owner_epoch, ctx->epoch))
		return false;
	/*
	 * at SNAPSHOTTING the certificate's fence_prover_* bytes are
	 * already immutable (they name who PROVED exclusion) and a successor
	 * that took the attempt lease over after the prover died is the rightful
	 * holder without being the prover.  The lease there is owner_* +
	 * fence_term.  At FENCING a takeover rewrites fence_prover_* to the
	 * successor, so the prover test is the same as the owner test and stays.
	 */
	if (d->stage != MXFS_RECOV_STAGE_SNAPSHOTTING &&
	    (d->fence_prover_node != ctx->local_node ||
	     !inc_eq(d->fence_prover_epoch, ctx->epoch)))
		return false;
	if (!auth)
		return false;           /* the attempt lease is never implicit */
	/*
	 * token identity, exactly as in recov_auth_holds —
	 * recov_fence_auth_issue() copies each of these out of this descriptor, so
	 * an UNKNOWN victim incarnation must compare equal to the UNKNOWN it was
	 * issued from.  The substantive "which incarnation did we actually fence?"
	 * question is NOT asked here; it belongs to the certificate's fence_kind /
	 * fence_victim_key, which mxfs_recov_cert_proves_exclusion() checks with
	 * the cross-source comparator.
	 */
	return d->victim_slot  == auth->victim_slot &&
	       d->victim_node  == auth->victim_node &&
	       recov_tok_eq(d->victim_epoch, auth->victim_epoch) &&
	       d->recovery_gen == auth->recovery_gen &&
	       d->fence_term   == auth->fence_term;
}

bool mxfs_recov_cert_proves_exclusion(const struct mxfs_recov_desc *d,
				      uint32_t fs_gen, int slot,
				      mxfs_node_id_t victim,
				      mxfs_epoch_t victim_epoch,
				      const char **why)
{
	const char *reason = NULL;

	if (!d) {
		reason = "no descriptor";
		goto no;
	}
	/*
	 * Structural validation FIRST, and against the descriptor's OWN identity
	 * fields.  recov_desc_crc() binds the payload to {fs_gen, node_id, epoch}
	 * taken from the record HEADER; recomputing it here from victim_fs_gen /
	 * victim_node / victim_epoch therefore proves two things at once — that
	 * the payload is intact, and that the descriptor's internal identity
	 * agrees with the header it was sealed against.  A payload spliced next to
	 * a different victim's header fails, and so does one whose victim_* fields
	 * were altered.
	 */
	if (d->magic != MXFS_RECOV_DESC_MAGIC) {
		reason = "descriptor magic";
		goto no;
	}
	if (d->version != MXFS_RECOV_DESC_VERSION) {
		reason = "descriptor version not exactly supported";
		goto no;
	}
	if (d->crc32c != recov_desc_crc(d->victim_fs_gen, d->victim_node,
					d->victim_epoch, d)) {
		reason = "crc / descriptor-vs-header identity mismatch";
		goto no;
	}

	/* Identity: this must be the recovery we think it is. */
	if (!victim) {
		reason = "caller named no victim";
		goto no;
	}
	if (d->victim_node != victim) {
		reason = "descriptor names a different victim node";
		goto no;
	}
	if (!d->victim_epoch) {
		reason = "descriptor carries no victim incarnation";
		goto no;
	}
	if (!inc_eq(d->victim_epoch, victim_epoch)) {
		reason = "descriptor names a different victim incarnation";
		goto no;
	}
	if (fs_gen && d->victim_fs_gen != fs_gen) {
		reason = "descriptor belongs to a different mkfs generation";
		goto no;
	}
	if (slot >= 0 && d->victim_slot != (uint16_t)slot) {
		reason = "descriptor names a different slot";
		goto no;
	}
	if (!d->recovery_gen) {
		reason = "recovery_gen is zero";
		goto no;
	}
	if (!d->slice_count || d->slice_idx >= d->slice_count) {
		reason = "slice_idx/slice_count do not name a journal slice";
		goto no;
	}

	/* State: an INTENT is not a fence (rule-1 amendment). */
	if (d->stage < MXFS_RECOV_STAGE_FENCED) {
		reason = d->stage == MXFS_RECOV_STAGE_FENCING ?
		    "fencing ATTEMPT only — no exclusion has been proved yet" :
		    d->stage == MXFS_RECOV_STAGE_SNAPSHOTTING ?
		    "exclusion proved but the fence-time manifest is not sealed yet" :
		    "descriptor carries no fence stage";
		goto no;
	}
	if (d->flags & MXFS_RECOV_F_QUARANTINED) {
		reason = "slice is QUARANTINED";
		goto no;
	}

	/*
	 * The certificate itself, and the question is CLASSIFICATION, not "did
	 * some attempt once prove exclusion".  A fence kind is a durable
	 * identifier of a construction contract; this build authorises replay only
	 * from a contract it still supports, because an older build having written
	 * the record is not evidence that the older build was right.  Every reader
	 * that did not mint the certificate asks the same function, so a revoked
	 * class cannot be honoured by whichever reader was not updated.
	 */
	if (!mxfs_fence_durable_kind_supported(MXFS_FENCE_RECORD_RECOVERY_DESC,
					       d->fence_kind, &reason)) {
		goto no;
	}
	if (!mxfs_fence_kind_resv_type_ok((enum mxfs_fence_kind)d->fence_kind,
					  d->fence_resv_type)) {
		/*
		 * Without a Write Exclusive reservation held at the verifying read,
		 * removing the victim's registration excludes nobody: an unreserved LU
		 * accepts writes from unregistered initiators.
		 * A SINGLE_NODE_EXCLUSIVE certificate's exclusion comes from topology
		 * (operator-asserted exclusive bdev + single-node membership), not
		 * from a reservation, so it carries no resv_type supporting fact.
		 * An EXCLUSIVE_WRITE_GATE certificate rests on exactly the
		 * single-holder Write Exclusive (1) it installed.
		 *
		 * this tested `== WR_EX_RO`, which rejected the
		 * all-registrants form (0x07) MXFS reserves from proto-gen 5 on.  The
		 * question the certificate rests on is whether the type excludes
		 * NON-REGISTRANTS, and both Write Exclusive forms do.
		 */
		reason = "reservation type at the verify does not support this fence kind";
		goto no;
	}
	if (!d->fence_victim_key) {
		reason = "certificate names no victim key";
		goto no;
	}
	if (!d->fence_prover_node || !d->fence_prover_epoch) {
		reason = "certificate names no prover incarnation";
		goto no;
	}
	if (!d->fence_term) {
		reason = "certificate carries no fencing-attempt term";
		goto no;
	}

	if (why)
		*why = "certified";
	return true;
no:
	if (why)
		*why = reason;
	return false;
}

int mxfs_disklock_recovery_fence_intent(struct mxfs_disklock_ctx *ctx, int slot,
					mxfs_node_id_t victim,
					mxfs_epoch_t victim_epoch,
					uint64_t victim_key,
					uint16_t slice_idx,
					uint16_t slice_count,
					uint32_t flags,
					struct mxfs_recov_fence_auth *out_auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim || !victim_key || !slice_count || slice_idx >= slice_count)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	if (recov_desc_present(cur)) {
		d = recov_desc_of(cur);
		if (!d) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P236-FENCE-UNREADABLE slot=%d victim=%u — the slot "
			    "carries a recovery descriptor this build cannot validate; "
			    "refusing to overwrite it with a fencing intent",
			    slot, victim);
			rc = -EPROTO;
			goto out;
		}
		if (d->victim_node != victim ||
		    !inc_eq(d->victim_epoch, victim_epoch)) {
			/*
			 * this exit was silent, and the caller's
			 * P238-FENCE-NOINTENT rc=-116 line cannot say WHICH tuple the
			 * standing descriptor names.  Say it here, once per attempt.
			 */
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P237-FENCE-DESC-FOREIGN slot=%d victim=%u "
			    "victim_inc=%llu desc_node=%u desc_inc=%llu stage=%u — the "
			    "slot's standing descriptor names a different victim tuple; "
			    "not laying a second intent",
			    slot, victim, (unsigned long long)victim_epoch,
			    d->victim_node, (unsigned long long)d->victim_epoch,
			    (unsigned)d->stage);
			rc = -ESTALE;
			goto out;
		}
		if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
			/* Someone already proved it.  Nothing for this prover to do. */
			rc = -EEXIST;
			goto out;
		}
		if (d->stage == MXFS_RECOV_STAGE_SNAPSHOTTING) {
			/*
			 * exclusion is PROVED and durable; what is missing is
			 * the sealed manifest.  Our own attempt lease (original prover
			 * or a SNAPSHOTTING takeover) resumes at the scan; anybody
			 * else's is busy exactly like a FENCING attempt.
			 */
			if (d->owner_node == ctx->local_node &&
			    inc_eq(d->owner_epoch, ctx->epoch)) {
				recov_fence_auth_issue(out_auth, d);
				rc = MXFS_FENCE_INTENT_SNAPSHOT_PENDING;
				goto out;
			}
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P236-FENCE-ATTEMPT-BUSY slot=%d victim=%u owner=%u "
			    "term=%u stage=SNAPSHOTTING — another survivor holds the "
			    "attempt lease and is writing the fence-time manifest; not "
			    "issuing a PREEMPT AND ABORT (exclusion is already proved)",
			    slot, victim, d->owner_node, d->fence_term);
			rc = -EBUSY;
			goto out;
		}
		/* stage == FENCING: an attempt is already recorded. */
		if (d->owner_node == ctx->local_node &&
		    inc_eq(d->owner_epoch, ctx->epoch) &&
		    d->fence_prover_node == ctx->local_node) {
			recov_fence_auth_issue(out_auth, d);
			rc = 0;             /* our own attempt — resume it */
			goto out;
		}
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P236-FENCE-ATTEMPT-BUSY slot=%d victim=%u prover=%u "
		    "term=%u key=%llu — another survivor holds the fencing-attempt "
		    "lease; not issuing a second PREEMPT AND ABORT",
		    slot, victim, d->fence_prover_node, d->fence_term,
		    (unsigned long long)d->fence_victim_key);
		rc = -EBUSY;
		goto out;
	}

	if (cur->magic != MXFS_DISKLOCK_MAGIC) {
		rc = -ENOENT;           /* zeroed: CONSUMABLE, nothing to recover */
		goto out;
	}
	if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
	     cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
		cur->node_id != victim || hb_gen_foreign(ctx, cur)) {
		rc = -ESTALE;
		goto out;
	}

	/*
	 * Rule 2: the victim's identity is never overwritten — only `flags`
	 * changes and the dead evict-ring bytes become the descriptor.  Note the
	 * live-victim race is FAIL-CLOSED by construction: if this node is wrong
	 * about the death, the victim's next ACTIVE heartbeat write clobbers this
	 * intent, and the certify CAS then fails because the sector no longer
	 * matches.  A live node cannot be certified as fenced by accident.
	 */
	/*
	 * — NO ZERO-INCARNATION DESCRIPTOR MAY EVER BE CREATED.
	 *
	 * D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN: a descriptor that
	 * cannot name its victim's incarnation cannot derive authority from
	 * incarnation identity, and the slot/slice-level quarantine that would be
	 * the alternative is not established.  The design-consult ruling's item 3
	 * offered a choice — prove the seven quarantine invariants, or forbid
	 * zero-epoch descriptors at CREATION.  This is the second.
	 *
	 * The only other creator, recovery_begin(), is retired (see its entry
	 * guard), so with this refusal the class becomes unconstructible rather
	 * than merely unlikely.  A sector whose ACTIVE record carries epoch 0 is
	 * a pre-incarnation-landing (pre-0.11.420) writer; treating it as a
	 * fenceable victim would publish a guard naming an incarnation nobody
	 * observed.
	 */
	if (!inc_valid(cur->epoch)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P238-FENCE-ZEROINC slot=%d victim=%u — the victim's own "
		    "record carries incarnation 0, so no certificate could ever name "
		    "what it fenced; refusing to lay a fencing intent.  This slot needs "
		    "a build that publishes a real mount incarnation (0.11.420+)",
		    slot, victim);
		rc = -EPROTO;
		goto out;
	}

	/*
	 * (D-FENCE-INTENT-ADOPTS-SECTOR-INCARNATION-0520, measured by
	 * tests/incarnation_mismatch_probe.sh nonzero on chain 61: a GUARD with
	 * victim_epoch=E2 appeared 0.5 s after the sector was rewritten E1->E2,
	 * while every survivor had declared E1 dead).  This function replaced
	 * recovery_begin() as the only descriptor creator but did NOT inherit
	 * its supersession predicate: it copied cur->epoch into the
	 * descriptor whatever the caller asked for, so a death declared for E1
	 * laid a fencing intent — and issued the PREEMPT AND ABORT of E1's
	 * frozen key — against whichever incarnation the sector carried.  On a
	 * LIVE same-node successor that is a guard on a healthy member (the
	 * exact hazard closed in begin); on anything else it is a
	 * descriptor naming an incarnation nobody observed stop, with E1's
	 * pending recovery left standing forever behind it.
	 *
	 * Same predicate as recovery_slot_status(), deliberately no weaker: a
	 * valid feature block at the CURRENT proto_gen, flags == ACTIVE (a
	 * WITHDRAWN successor is itself dead and owes its own replay), both
	 * incarnations nonzero (cur->epoch is nonzero here; victim_epoch is
	 * nonzero because fence_prove refuses inc 0 at its entry), and the two
	 * differing.  SUPERSEDED retires the caller's pending recovery; the
	 * mismatch arm refuses without touching the sector.
	 */
	if (!inc_eq(cur->epoch, victim_epoch)) {
		int fst = hb_feature_state(cur);

		if (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		    fst == MXFS_HBFEAT_OK) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P237-FENCE-SUPERSEDED slot=%d victim=%u "
			    "victim_inc=%llu slot_inc=%llu — the slot carries a LATER "
			    "ACTIVE incarnation of the same node: the victim reclaimed it "
			    "and its own mount recovery owns the slice; laying no intent "
			    "and retiring the pending recovery instead of guarding a LIVE "
			    "member",
			    slot, victim, (unsigned long long)victim_epoch,
			    (unsigned long long)cur->epoch);
			rc = MXFS_RECOVERY_SUPERSEDED;
			goto out;
		}
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P237-FENCE-INC-MISMATCH slot=%d victim=%u "
		    "victim_inc=%llu slot_inc=%llu flags=0x%x featstate=%d — the slot "
		    "no longer carries the incarnation this prover was asked to fence "
		    "and this is NOT a provable supersession; laying no intent",
		    slot, victim, (unsigned long long)victim_epoch,
		    (unsigned long long)cur->epoch, cur->flags, fst);
		rc = -ESTALE;
		goto out;
	}

	*want = *cur;
	want->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
	memset(&want->recov, 0, sizeof(want->recov));
	want->recov.desc.magic           = MXFS_RECOV_DESC_MAGIC;
	want->recov.desc.version         = MXFS_RECOV_DESC_VERSION;
	want->recov.desc.stage           = MXFS_RECOV_STAGE_FENCING;
	want->recov.desc.victim_epoch    = cur->epoch;
	want->recov.desc.owner_epoch     = ctx->epoch;
	want->recov.desc.recovery_gen    = 1;   /* constant across takeover; see
											 * recovery_begin() for why it is
											 * not a counter */
	want->recov.desc.owner_stamp_ms  = recov_stamp_after(0);
	want->recov.desc.victim_node     = victim;
	want->recov.desc.owner_node      = ctx->local_node;
	want->recov.desc.victim_fs_gen   = cur->fs_gen;
	want->recov.desc.flags           = flags |
	    (cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ?
		 MXFS_RECOV_F_VICTIM_WITHDREW : 0) |
		(hb_victim_snlocal(cur) ? MXFS_RECOV_F_VICTIM_SNLOCAL : 0) |
		(hb_victim_adopted(cur) ? MXFS_RECOV_F_VICTIM_ADOPTED : 0);   /* */
	want->recov.desc.victim_slot     = (uint16_t)slot;
	recov_desc_set_owner_slot(ctx, &want->recov.desc);    /* */
	want->recov.desc.slice_idx       = slice_idx;
	want->recov.desc.slice_count     = slice_count;
	want->recov.desc.stage_seq       = 1;
	/*
	 * owner_term stays 0: this is the fencing-ATTEMPT lease, not the
	 * recovery-EXECUTION lease.  Nothing may be executed under it, and
	 * recovery_advance()/refresh() refuse a pre-FENCED descriptor outright so
	 * an intent cannot be walked up the milestone ladder.
	 */
	want->recov.desc.owner_term      = 0;
	/* Attempt state in the certificate bytes.  fence_kind stays NONE and
	 * fence_resv_type stays 0, which is what makes this read as "not
	 * certified" on every gate. */
	want->recov.desc.fence_kind      = MXFS_FENCE_KIND_NONE;
	want->recov.desc.fence_resv_type = 0;
	want->recov.desc.fence_victim_key  = victim_key;
	want->recov.desc.fence_prover_epoch = ctx->epoch;
	want->recov.desc.fence_stamp_ms  = mxfs_pal_time_ms();
	want->recov.desc.fence_prover_node = ctx->local_node;
	want->recov.desc.fence_pr_gen    = 0;
	want->recov.desc.fence_term      = 1;
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0) {
		recov_fence_auth_issue(out_auth, &want->recov.desc);
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P236-FENCE-INTENT slot=%d victim=%u epoch=%llu key=%llu "
		    "slice=%u/%u prover=%u term=1 — fencing intent is DURABLE; the "
		    "PREEMPT AND ABORT may now be issued.  This authorises NOTHING: "
		    "no replay, no purge, no manifest work, no zeroing",
		    slot, victim, (unsigned long long)cur->epoch,
		    (unsigned long long)victim_key, slice_idx, slice_count,
		    ctx->local_node);
		/* TEST ONLY, see dl_fence_postintent_pause_ms: park here so this
		 * prover can be killed with its attempt standing and nothing issued
		 * under it. */
		if (mxfs_dl_fence_postintent_pause_ms > 0) {
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P236-FENCE-INTENT-HOLD slot=%d victim=%u prover=%u "
			    "ms=%d — TEST ONLY: the intent is durable and NOTHING has been "
			    "issued under it; holding here so this prover can die with the "
			    "fencing attempt still standing",
			    slot, victim, ctx->local_node,
			    mxfs_dl_fence_postintent_pause_ms);
			/* INTERRUPTIBLE: an uninterruptible hold of this length would
			 * park a kernel task in D state for its whole duration. */
			mxfs_pal_sleep_ms_interruptible(
			    (uint32_t)mxfs_dl_fence_postintent_pause_ms);
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P236-FENCE-INTENT-RESUME slot=%d victim=%u — "
			    "proceeding to issue the PREEMPT AND ABORT",
			    slot, victim);
		}
	} else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-INTENT-FAIL slot=%d victim=%u rc=%d — the "
		    "intent is NOT durable; the fence must not be issued (a P&A whose "
		    "result cannot be recorded destroys this slice's only route to "
		    "recovery: the victim key is consumed and no successor can prove "
		    "exclusion)",
		    slot, victim, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_fence_mark_blocked(struct mxfs_disklock_ctx *ctx,
					      int slot,
					      const struct mxfs_recov_fence_auth *auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !auth)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
		rc = -EEXIST;
		goto out;
	}
	if (d->stage != MXFS_RECOV_STAGE_FENCING) {
		rc = -EPROTO;
		goto out;
	}
	if (!recov_fence_auth_holds(ctx, d, auth)) {
		rc = -EBUSY;
		goto out;
	}
	if (d->flags & MXFS_RECOV_F_FENCE_BLOCKED) {
		rc = 0;                 /* already published — idempotent, no write */
		goto out;
	}

	*want = *cur;
	want->recov.desc.flags          = d->flags | MXFS_RECOV_F_FENCE_BLOCKED;
	want->recov.desc.fence_stamp_ms = mxfs_pal_time_ms();
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P304-FENCE-BLOCKED-DURABLE slot=%d victim=%u prover=%u "
		    "term=%u — RECOVERY_BLOCKED is on the platter: the standing "
		    "fencing attempt proved nothing across its bounded series and is "
		    "re-driven slowly from here; the intent stays FENCING under the "
		    "same lease",
		    slot, d->victim_node, ctx->local_node, d->fence_term);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P304-FENCE-BLOCKED-DURABLE-FAIL slot=%d victim=%u "
		    "rc=%d — the blocked verdict could not be made durable; it stays "
		    "in this node's memory and debugfs only",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_fence_arm_submit(struct mxfs_disklock_ctx *ctx,
					    int slot,
					    const struct mxfs_recov_fence_auth *auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !auth)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
		rc = -EEXIST;
		goto out;
	}
	if (d->stage != MXFS_RECOV_STAGE_FENCING) {
		rc = -EPROTO;
		goto out;
	}
	if (!recov_fence_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P304-FENCE-ARM-LEASE-LOST slot=%d victim=%u prover=%u "
		    "term=%u — the fencing-attempt lease is no longer ours; no command "
		    "may be submitted under it",
		    slot, d->victim_node, d->fence_prover_node, d->fence_term);
		rc = -EBUSY;
		goto out;
	}
	if (d->flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN) {
		/*
		 * Already armed — idempotent, no write.  Said out loud since 0.89.63,
		 * because a command that completes a re-driven attempt must be
		 * shown to have a boundary of its own: this IS that boundary, the
		 * one this attempt made and was not told about.
		 */
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P304-FENCE-ARM-STANDING slot=%d victim=%u prover=%u "
		    "term=%u — the command-submission boundary of this attempt is "
		    "already durable; proceeding under it without a second write",
		    slot, d->victim_node, ctx->local_node, d->fence_term);
		rc = 0;
		goto out;
	}

	*want = *cur;
	want->recov.desc.flags          = d->flags |
					  MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN;
	want->recov.desc.fence_stamp_ms = mxfs_pal_time_ms();
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P304-FENCE-ARM slot=%d victim=%u prover=%u term=%u — "
		    "the command-submission boundary is DURABLE.  From this point a "
		    "PREEMPT-family command MAY have reached the target, so no reader "
		    "may treat this attempt as 'nothing was submitted' again",
		    slot, d->victim_node, ctx->local_node, d->fence_term);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P304-FENCE-ARM-FAIL slot=%d victim=%u rc=%d — the "
		    "command-submission boundary is NOT durable, so the command must "
		    "NOT be issued: a preempt nobody can later tell happened is "
		    "indistinguishable from one that did not",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_fence_retryable(struct mxfs_disklock_ctx *ctx,
					   int slot,
					   mxfs_node_id_t *out_victim,
					   mxfs_epoch_t *out_epoch,
					   uint32_t *out_term)
{
	struct mxfs_disklock_heartbeat *cur;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc, ans = 0;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		/* No descriptor, or one we cannot validate.  Neither is a retryable
		 * attempt of ours, and "cannot validate" must not read as "no". */
		rc = recov_desc_present(cur) ? -EPROTO : 0;
		goto out;
	}
	rc = 0;
	if (d->stage == MXFS_RECOV_STAGE_SNAPSHOTTING) {
		/*
		 * our own attempt lease at SNAPSHOTTING is ALWAYS
		 * re-drivable — nothing is submitted to the target there, only the
		 * idempotent scan+seal, and leaving it standing parks the slice
		 * forever.  (The fence-retry worker re-enters v5_pr_fence_prove,
		 * whose fence_intent resumes at the scan.)
		 */
		if (d->owner_node != ctx->local_node ||
		    !inc_eq(d->owner_epoch, ctx->epoch))
			goto out;
		if (out_victim)
			*out_victim = d->victim_node;
		if (out_epoch)
			*out_epoch = d->victim_epoch;
		ans = 1;
		goto out;
	}
	if (d->stage != MXFS_RECOV_STAGE_FENCING)
		goto out;
	if (d->fence_prover_node != ctx->local_node ||
	    !inc_eq(d->fence_prover_epoch, ctx->epoch))
		goto out;               /* somebody else's attempt; takeover, not retry */
	if (out_victim)
		*out_victim = d->victim_node;
	if (out_epoch)
		*out_epoch = d->victim_epoch;
	if (out_term)
		*out_term = d->fence_term;
	/*
	 * 0.89.63: OUR attempt with the submission boundary durable.  The platter
	 * cannot say whether a command was issued under that arm — it is written
	 * before the command so that a crash reads conservatively — so the answer
	 * is neither "re-drive" nor "not ours": it is "ours, armed", and the caller
	 * owns the memory that says whether this incarnation ever crossed the
	 * boundary under it.  Answering 0 here was measured (s133c3, s138m): an
	 * arm whose CAS landed and was reported failed was disarmed as somebody
	 * else's ambiguity and never revisited, and the prover's own mount blocked
	 * behind the victim's frozen grants.
	 */
	if (d->flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN) {
		ans = 2;
		goto out;
	}
	ans = 1;
out:
	mxfs_pal_free(cur);
	return rc < 0 ? rc : ans;
}

int mxfs_disklock_recovery_fence_certify(struct mxfs_disklock_ctx *ctx, int slot,
					 const struct mxfs_recov_fence_auth *auth,
					 uint16_t fence_kind,
					 uint16_t fence_resv_type,
					 uint64_t fence_victim_key,
					 uint32_t fence_pr_gen,
					 uint8_t retire_basis,
					 uint8_t retire_claim,
					 uint8_t retire_obs)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	const char *kwhy = NULL;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !auth)
		return -EINVAL;

	/*
	 * THE CERTIFICATE CAN ONLY EVER SAY THE TRUTH, AND IT HAS TO SAY IT IN A
	 * PROOF CONTRACT THIS BUILD STILL SUPPORTS.  Refuse before touching the
	 * platter — a descriptor that claims an exclusion nobody proved is worse
	 * than no descriptor at all, because every downstream gate trusts it.
	 *
	 * The question asked here is the DURABLE one, through the same classifier
	 * every consuming reader uses.  It used to be the fresh-result predicate
	 * mxfs_fence_kind_proves_exclusion(), which still answers "did this
	 * attempt prove something" for the callers that decide whether to certify
	 * at all — but that is a SECOND, hand-maintained list of code points, and
	 * it still admits classes consumption has revoked.  Two lists drift, and
	 * the drift is not symmetric: a build that can MINT a kind it would REFUSE
	 * to read seals a certificate nothing will ever act on, and a sealed
	 * descriptor answers -EEXIST to every later prover, so the slice it covers
	 * can never be certified by anybody again.  Minting is a subset of
	 * consumption by construction here, not by the two lists happening to
	 * agree.
	 */
	if (!mxfs_fence_durable_kind_supported(MXFS_FENCE_RECORD_RECOVERY_DESC,
					       fence_kind, &kwhy)) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P236-FENCE-NOT-PROVED slot=%d victim=%u kind=%s — "
		    "refusing to make a certificate durable at a kind this build "
		    "would not accept back: %s.  The intent stays in place "
		    "uncertified and the slice stays unreplayable, which is the "
		    "correct outcome",
		    slot, auth->victim_node,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
		    kwhy ? kwhy : "?");
		return -EPERM;
	}
	/*
	 * AND IT CAN ONLY SAY THE WHOLE TRUTH.  Exclusion is the admission half:
	 * the victim cannot be given permission for a NEW write.  A certificate
	 * authorises REPLAY, and replay is only safe if the target is also done
	 * with the writes it had already accepted from that victim — a separate
	 * fact, established by a COMPLETED TARGET OPERATION whose own abort scope
	 * covered them, and by nothing else.
	 *
	 * 0.89.16 removed the second way in.  A deployment used to be able to
	 * assert the ordering for its exact target, firmware and LUN, and a
	 * matching assertion certified.  An assertion is not a witness — the
	 * module cannot detect a target that breaks it, and the shipped clause's
	 * whole support was four probe laps that saw no late write in a bounded
	 * window — so a qualified contract is refused here even if some path still
	 * offers one.  This is the choke point every replay-authorising kind
	 * crosses, so the refusal cannot be routed around.
	 *
	 * 0.89.18 removed the last exception.  It was the operator's single-node
	 * topology assertion, carried here on the grounds that its own retirement
	 * half was an open defect rather than a decided one.  It is decided now:
	 * an operator parameter may select an operating mode, and it may not
	 * create a retirement witness.  The assertion is about whether a second
	 * INITIATOR can be holding writes; the victim is a previous INCARNATION,
	 * whose own accepted commands the target may still be finishing, and no
	 * value of a parameter observes that.  So this gate now has no exception
	 * at all, which is the only shape in which it is a choke point.
	 */
	if (retire_basis != MXFS_RETIRE_BASIS_TARGET_OP) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-NO-RETIREMENT slot=%d victim=%u kind=%s "
		    "basis=%s obs=%s — REFUSING TO CERTIFY.  Exclusion was proved, "
		    "but only a completed target operation that aborted the "
		    "victim's tasks establishes that the target finished the "
		    "writes it had already accepted from it, and none ran.  A "
		    "replay authorised against surviving writes corrupts "
		    "silently, where a refusal only costs availability",
		    slot, auth->victim_node,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
		    mxfs_retire_basis_name(retire_basis),
		    mxfs_retire_observation_name(retire_obs));
		return -EPERM;
	}
	if (!mxfs_fence_kind_resv_type_ok((enum mxfs_fence_kind)fence_kind,
					  fence_resv_type)) {
		/* The resv-type supporting fact belongs to the preempt proof and to
		 * the exclusive-write gate (which needs exactly type 1);
		 * SINGLE_NODE_EXCLUSIVE proves exclusion by topology, without a
		 * reservation (see mxfs_recov_cert_proves_exclusion).
		 *
		 * this tested `== WR_EX_RO` and so refused to certify a
		 * PROVED exclusion taken under the all-registrants type — the worst
		 * possible outcome, because the victim key is already consumed by then
		 * and no successor can prove it again.  MEASURED on the rig as
		 * "P238-FENCE-UNRECORDED ... exclusion was PROVED but the certificate
		 * is not durable ... this slice is BLOCKED". */
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-NO-RESV slot=%d victim=%u kind=%s "
		    "resv_type=0x%02x — a key preempt only excludes while a Write "
		    "Exclusive reservation (0x%02x or 0x%02x) is held, and the "
		    "exclusive-write gate only under type 0x%02x; refusing to certify",
		    slot, auth->victim_node,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
		    fence_resv_type, MXFS_PAL_PR_TYPE_WR_EX_RO,
		    MXFS_PAL_PR_TYPE_WR_EX_AR, MXFS_PAL_PR_TYPE_WR_EX);
		return -EPERM;
	}
	if (!fence_victim_key)
		return -EINVAL;
	if (auth->victim_key && fence_victim_key != auth->victim_key) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-KEY-DRIFT slot=%d victim=%u intended=%llu "
		    "removed=%llu — the key actually preempted is not the key this "
		    "attempt was registered against; refusing to certify",
		    slot, auth->victim_node,
		    (unsigned long long)auth->victim_key,
		    (unsigned long long)fence_victim_key);
		return -EPERM;
	}

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ESTALE;
		goto out;
	}
	if (d->stage >= MXFS_RECOV_STAGE_FENCED) {
		/* Already certified AND sealed.  Nothing left for a prover. */
		rc = -EEXIST;
		goto out;
	}
	if (d->stage == MXFS_RECOV_STAGE_SNAPSHOTTING) {
		/* Already certified; idempotent only for OUR attempt lease. */
		rc = recov_fence_auth_holds(ctx, d, auth) ? 0 : -EEXIST;
		goto out;
	}
	if (!recov_fence_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-LEASE-LOST slot=%d victim=%u prover=%u "
		    "term=%u — the fencing-attempt lease is no longer ours (we hold "
		    "node=%u epoch=%llu term=%u).  The exclusion we proved is real, "
		    "but it is not ours to certify: another prover owns this attempt "
		    "and will certify its own result",
		    slot, d->victim_node, d->fence_prover_node, d->fence_term,
		    ctx->local_node, (unsigned long long)ctx->epoch, auth->fence_term);
		rc = -EBUSY;
		goto out;
	}
	if (!ctx->rman_offset) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-NOREGION slot=%d victim=%u — this node has no "
		    "recovery-manifest region installed, so it can never seal a "
		    "manifest; refusing to certify (the intent stands for a node that "
		    "can)",
		    slot, d->victim_node);
		rc = -ENODEV;
		goto out;
	}

	/*
	 * FENCING -> SNAPSHOTTING.  The certificate bytes become durable
	 * NOW (the P&A result must never live only in volatile memory), but the
	 * descriptor stays OWNED by the prover's attempt lease: the manifest
	 * scan+seal is still to do, and only mxfs_disklock_recovery_fence_seal()
	 * publishes FENCED + UNOWNED + the manifest pointer in one CAS.  Every
	 * existing gate demands stage >= FENCED, so nothing downstream is
	 * authorised by this write; the writer guard's protection of the
	 * victim's CAW bits begins here.
	 */
	*want = *cur;
	want->recov.desc.stage           = MXFS_RECOV_STAGE_SNAPSHOTTING;
	want->recov.desc.stage_seq       = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms  = recov_stamp_after(d->owner_stamp_ms);
	/* 0.74.0: the non-proving series ended in a proof — the blocked verdict
	 * is no longer true and must not outlive it on the platter. */
	want->recov.desc.flags           = d->flags & ~MXFS_RECOV_F_FENCE_BLOCKED;
	want->recov.desc.fence_kind      = fence_kind;
	if (mxfs_dl_fence_cert_kind_inject > 0 &&
	    mxfs_dl_fence_cert_kind_inject != (int)fence_kind) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P236-FENCE-CERT-KIND-INJECTED slot=%d victim=%u "
		    "proved=%s(%u) written=%s(%d) — TEST ONLY: the certificate about "
		    "to become durable carries an INJECTED fence kind, not the one "
		    "this attempt proved.  A lap reading this line is measuring a "
		    "revoked proof contract on purpose",
		    slot, auth->victim_node,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
		    fence_kind,
		    mxfs_fence_kind_name(
			(enum mxfs_fence_kind)mxfs_dl_fence_cert_kind_inject),
			mxfs_dl_fence_cert_kind_inject);
		want->recov.desc.fence_kind =
		    (uint16_t)mxfs_dl_fence_cert_kind_inject;
	}
	want->recov.desc.fence_resv_type = fence_resv_type;
	want->recov.desc.fence_victim_key = fence_victim_key;
	want->recov.desc.fence_stamp_ms  = mxfs_pal_time_ms();
	want->recov.desc.fence_pr_gen    = fence_pr_gen;
	/* fence_prover_node/epoch and fence_term are carried through from the
	 * intent: the certificate names the incarnation that did the work. */
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P236-FENCE-CERTIFIED slot=%d victim=%u epoch=%llu "
		    "kind=%s resv=0x%02x key=%llu pr_gen=%u prover=%u term=%u "
		    "retire_basis=%s claim=%s obs=%s — exclusion is PROVED and durable "
		    "(stage=SNAPSHOTTING).  The fence-time manifest is written next; "
		    "the descriptor becomes UNOWNED/FENCED only when it is sealed",
		    slot, d->victim_node, (unsigned long long)d->victim_epoch,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)fence_kind),
		    fence_resv_type, (unsigned long long)fence_victim_key,
		    fence_pr_gen, ctx->local_node, d->fence_term,
		    mxfs_retire_basis_name(retire_basis),
		    mxfs_retire_claim_name(retire_claim),
		    mxfs_retire_observation_name(retire_obs));
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-CERTIFY-FAIL slot=%d victim=%u rc=%d — the "
		    "exclusion was proved but the certificate is NOT durable.  This "
		    "slice cannot be replayed by anyone: the victim key is consumed, "
		    "so no successor can prove exclusion again",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

void mxfs_disklock_set_rman(struct mxfs_disklock_ctx *ctx, uint64_t rman_offset,
			    uint64_t rman_size)
{
	if (!ctx)
		return;
	if (rman_size < (uint64_t)MXFS_DISKLOCK_HB_SLOTS * MXFS_RMAN_SLOT_BYTES) {
		/* A short region cannot hold every slot's maximum manifest; treat
		 * it as absent so certify refuses rather than writing past it. */
		if (rman_offset || rman_size)
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P-RMAN-REGION-SHORT offset=%llu size=%llu need=%llu "
			    "— recovery-manifest region ignored; this node cannot certify",
			    (unsigned long long)rman_offset,
			    (unsigned long long)rman_size,
			    (unsigned long long)MXFS_DISKLOCK_HB_SLOTS *
				MXFS_RMAN_SLOT_BYTES);
		ctx->rman_offset = 0;
		ctx->rman_size = 0;
		return;
	}
	ctx->rman_offset = rman_offset;
	ctx->rman_size = rman_size;
}

/*
 * Reread the victim sector and confirm the descriptor is at SNAPSHOTTING
 * under OUR attempt lease.  Returns the record in *cur (caller-allocated) so
 * the caller can seal a pointer against the same victim identity.
 */
static int rman_check_lease(struct mxfs_disklock_ctx *ctx, int slot,
			    const struct mxfs_recov_fence_auth *auth,
			    struct mxfs_disklock_heartbeat *cur,
			    const struct mxfs_recov_desc **out_d,
			    const char *site)
{
	const struct mxfs_recov_desc *d;
	uint64_t off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	int rc;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		return rc;
	d = recov_desc_of(cur);
	if (!d)
		return recov_desc_present(cur) ? -EPROTO : -ESTALE;
	if (d->stage >= MXFS_RECOV_STAGE_FENCED)
		return -EEXIST;
	if (d->stage != MXFS_RECOV_STAGE_SNAPSHOTTING)
		return -EPROTO;
	if (!recov_fence_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-LEASE-LOST site=%s slot=%d victim=%u owner=%u "
		    "term=%u — the attempt lease is no longer ours (we hold node=%u "
		    "epoch=%llu term=%u); the manifest is not ours to write",
		    site, slot, d->victim_node, d->owner_node, d->fence_term,
		    ctx->local_node, (unsigned long long)ctx->epoch, auth->fence_term);
		return -EBUSY;
	}
	*out_d = d;
	return 0;
}

int mxfs_disklock_recovery_manifest_write(struct mxfs_disklock_ctx *ctx, int slot,
					  const struct mxfs_recov_fence_auth *auth,
					  const struct mxfs_rman_entry *ents,
					  uint32_t count, uint32_t scan_slots,
					  uint32_t flags,
					  struct mxfs_recov_manifest_ptr *out_ptr)
{
	struct mxfs_disklock_heartbeat *cur = NULL;
	struct mxfs_rman_hdr *hdr = NULL;
	const struct mxfs_recov_desc *d;
	uint64_t base, seq, stamp;
	uint32_t byte_len, ecrc;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth || !out_ptr || (count && !ents) || count > MXFS_RMAN_MAX_ENTRIES)
		return -EINVAL;
	if (!ctx->rman_offset)
		return -ENODEV;

	cur = mxfs_pal_alloc(sizeof(*cur));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	if (!cur || !hdr) {
		rc = -ENOMEM;
		goto out;
	}
	rc = rman_check_lease(ctx, slot, auth, cur, &d, "write");
	if (rc)
		goto out;

	base = rman_slot_off(ctx, slot);
	byte_len = count * (uint32_t)sizeof(struct mxfs_rman_entry);
	stamp = mxfs_pal_time_ms();
	/*
	 * seq: strictly greater than any seq this sector's pointer or the slot's
	 * current header carries, so a takeover's rewrite is distinguishable from
	 * the dead prover's partial one.  Start from the header on the platter.
	 */
	seq = 1;
	{
		const struct mxfs_recov_manifest_ptr *old = recov_mptr_of(cur);

		if (old && old->seq >= seq)
			seq = old->seq + 1;
	}
	rc = mxfs_pal_bdev_read_prio(ctx->dev, base, hdr, sizeof(*hdr));
	/* design review item 13: take the old header's seq ONLY from a fully
	 * sealed, crc-valid header for this very slot/victim identity; a torn,
	 * zeroed or foreign header contributes nothing. */
	if (rc == 0 && hdr->magic == MXFS_RMAN_MAGIC &&
	    hdr->version == MXFS_RMAN_VERSION && hdr->seal == MXFS_RMAN_SEAL &&
	    hdr->hdr_crc32c == rman_hdr_crc(hdr) &&
	    hdr->victim_slot == (uint16_t)slot &&
	    hdr->victim_node == d->victim_node &&
	    hdr->victim_fs_gen == d->victim_fs_gen && hdr->seq >= seq)
		seq = hdr->seq + 1;
	if (rc)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P-RMAN-HDR-PREREAD slot=%d rc=%d — could not read the "
		    "old manifest header; seq continues from the pointer only", slot, rc);
	if (seq == 0 || seq == ~0ULL) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-SEQ-EXHAUSTED slot=%d — manifest sequence "
		    "wrapped; refusing to write (fail closed)", slot);
		rc = -EOVERFLOW;
		goto out;
	}

	/* 1. invalidate: zeroed header, durable, BEFORE any entry byte lands. */
	memset(hdr, 0, sizeof(*hdr));
	rc = mxfs_pal_bdev_write_fua(ctx->dev, base, hdr, sizeof(*hdr));
	if (rc == 0)
		rc = mxfs_pal_bdev_flush(ctx->dev);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-WRITE-FAIL slot=%d victim=%u step=invalidate rc=%d",
		    slot, d->victim_node, rc);
		goto out;
	}

	/* 2. entries + flush.  Block I/O must be whole 4 KiB blocks: the
	 * caller's buffer is zero-padded to MXFS_RMAN_IO_ALIGN (contract in
	 * disklock.h), the crc covers byte_len only. */
	ecrc = ~0U;
	if (byte_len) {
		uint32_t io_len = (byte_len + MXFS_RMAN_IO_ALIGN - 1) &
				  ~(MXFS_RMAN_IO_ALIGN - 1);

		ecrc = mxfs_pal_crc32c(~0U, ents, byte_len);
		rc = mxfs_pal_bdev_write(ctx->dev, base + MXFS_RMAN_ENTRIES_OFF,
					 ents, io_len);
		if (rc == 0)
			rc = mxfs_pal_bdev_flush(ctx->dev);
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "disklock: P-RMAN-WRITE-FAIL slot=%d victim=%u step=entries "
			    "count=%u bytes=%u rc=%d", slot, d->victim_node, count,
			    byte_len, rc);
			goto out;
		}
	}
	if (flags & MXFS_RECOV_MPTR_F_INJECT_TORN)
		ecrc ^= 0xA5A5A5A5u;    /* test knob: the seal lies about the entries */

	/* 3. sealed header (crc + seal in ONE 4 KiB write) + flush. */
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic          = MXFS_RMAN_MAGIC;
	hdr->version        = MXFS_RMAN_VERSION;
	hdr->victim_slot    = (uint16_t)slot;
	hdr->victim_node    = d->victim_node;
	hdr->victim_fs_gen  = d->victim_fs_gen;
	hdr->victim_epoch   = d->victim_epoch;
	hdr->recovery_gen   = d->recovery_gen;
	hdr->fence_term     = d->fence_term;
	hdr->writer_node    = ctx->local_node;
	hdr->writer_epoch   = ctx->epoch;
	hdr->seq            = seq;
	hdr->scan_stamp_ms  = stamp;
	hdr->entry_count    = count;
	hdr->byte_len       = byte_len;
	hdr->entries_crc32c = ecrc;
	hdr->scan_slots     = scan_slots;
	hdr->flags          = flags;
	hdr->hdr_crc32c     = rman_hdr_crc(hdr);
	hdr->seal           = MXFS_RMAN_SEAL;
	rc = mxfs_pal_bdev_write_fua(ctx->dev, base, hdr, sizeof(*hdr));
	if (rc == 0)
		rc = mxfs_pal_bdev_flush(ctx->dev);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P-RMAN-WRITE-FAIL slot=%d victim=%u step=seal rc=%d",
		    slot, d->victim_node, rc);
		goto out;
	}

	/* The lease must STILL be ours after the last byte landed: a takeover
	 * mid-write means a successor is rewriting this slot and our header may
	 * be the one that loses; only the successor's seal CAS may publish. */
	rc = rman_check_lease(ctx, slot, auth, cur, &d, "post-seal");
	if (rc)
		goto out;

	memset(out_ptr, 0, sizeof(*out_ptr));
	out_ptr->magic          = MXFS_RECOV_MPTR_MAGIC;
	out_ptr->version        = MXFS_RECOV_MPTR_VERSION;
	out_ptr->flags          = (uint16_t)flags;
	out_ptr->seq            = seq;
	out_ptr->scan_stamp_ms  = stamp;
	out_ptr->entry_count    = count;
	out_ptr->byte_len       = byte_len;
	out_ptr->entries_crc32c = ecrc;
	out_ptr->hdr_crc32c     = hdr->hdr_crc32c;
	out_ptr->writer_node    = ctx->local_node;
	out_ptr->writer_epoch   = ctx->epoch;
	out_ptr->fence_term     = d->fence_term;
	out_ptr->scan_slots     = scan_slots;
	mxfs_pal_log(MXFS_LOG_DEBUG,
	    "disklock: P-RMAN-SEALED slot=%d victim=%u epoch=%llu term=%u seq=%llu "
	    "entries=%u bytes=%u scan_slots=%u flags=0x%x hdr_crc=0x%08x — the "
	    "fence-time manifest is durably sealed; publishing the pointer next",
	    slot, d->victim_node, (unsigned long long)d->victim_epoch,
	    d->fence_term, (unsigned long long)seq, count, byte_len, scan_slots,
	    flags, hdr->hdr_crc32c);
	rc = 0;
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(hdr);
	return rc;
}

int mxfs_disklock_recovery_fence_seal(struct mxfs_disklock_ctx *ctx, int slot,
				      const struct mxfs_recov_fence_auth *auth,
				      const struct mxfs_recov_manifest_ptr *mp)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !auth || !mp || mp->magic != MXFS_RECOV_MPTR_MAGIC)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		rc = -ENOMEM;
		goto out;
	}
	rc = rman_check_lease(ctx, slot, auth, cur, &d, "seal");
	if (rc == -EEXIST) {
		/* Already FENCED.  Idempotent only if it carries OUR pointer. */
		const struct mxfs_recov_manifest_ptr *have = recov_mptr_of(cur);

		rc = (have && have->seq == mp->seq &&
		      have->fence_term == mp->fence_term &&
		      have->writer_node == ctx->local_node &&
		      inc_eq(have->writer_epoch, ctx->epoch)) ? 0 : -EEXIST;
		goto out;
	}
	if (rc)
		goto out;
	if (mp->fence_term != d->fence_term) {
		rc = -ESTALE;           /* a pointer from a superseded term */
		goto out;
	}

	/*
	 * SNAPSHOTTING -> FENCED, prover -> UNOWNED, and the manifest pointer,
	 * in ONE compare-and-write.  Two writes would leave a window in which
	 * the descriptor is certified but still owned by a prover that is not
	 * going to execute the recovery (the argument), or FENCED
	 * without a pointer (which no gate accepts).
	 */
	*want = *cur;
	want->recov.desc.stage           = MXFS_RECOV_STAGE_FENCED;
	want->recov.desc.stage_seq       = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms  = recov_stamp_after(d->owner_stamp_ms);
	want->recov.desc.owner_node      = MXFS_RECOV_OWNER_NONE;
	want->recov.desc.owner_epoch     = 0;
	want->recov.desc.owner_slot      = 0;
	want->recov.desc.flags          &= ~MXFS_RECOV_F_OWNER_BOOTSTRAP;  /* unowned */
	want->recov.desc.owner_term      = 0;
	recov_desc_seal(want);
	want->recov.mptr = *mp;
	recov_mptr_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P236-FENCE-SEALED slot=%d victim=%u epoch=%llu kind=%s "
		    "prover=%u term=%u manifest{seq=%llu entries=%u bytes=%u "
		    "flags=0x%x} — certificate + sealed fence-time manifest are "
		    "durable (stage=FENCED).  The descriptor is now UNOWNED; the "
		    "elected replayer may claim it",
		    slot, d->victim_node, (unsigned long long)d->victim_epoch,
		    mxfs_fence_kind_name((enum mxfs_fence_kind)d->fence_kind),
		    d->fence_prover_node, d->fence_term,
		    (unsigned long long)mp->seq, mp->entry_count, mp->byte_len,
		    mp->flags);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-FENCE-SEAL-FAIL slot=%d victim=%u rc=%d — the "
		    "manifest is sealed but the pointer is NOT durable; the attempt "
		    "stays at SNAPSHOTTING and is re-driven (idempotent)",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

/*
 * the loader proper.  `xd`/`xmp` non-NULL = the ESCROWED descriptor
 * and manifest pointer of the bootstrap owner's adopted slot K (its sector
 * now holds the owner's ACTIVE record, so nothing can be read from it); the
 * pointer's crc is re-verified against the victim identity it was sealed
 * under, exactly as recov_mptr_of does from the sector.
 */
static int rman_manifest_read_impl(struct mxfs_disklock_ctx *ctx, int slot,
				   mxfs_node_id_t victim,
				   mxfs_epoch_t victim_epoch,
				   const struct mxfs_recov_desc *xd,
				   const struct mxfs_recov_manifest_ptr *xmp,
				   struct mxfs_recov_manifest_ptr *out_ptr,
				   struct mxfs_rman_entry **out_ents,
				   uint32_t *out_count,
				   bool *out_no_caw)
{
	struct mxfs_disklock_heartbeat *cur = NULL;
	struct mxfs_rman_hdr *hdr = NULL;
	struct mxfs_rman_entry *ents = NULL;
	const struct mxfs_recov_desc *d;
	const struct mxfs_recov_manifest_ptr *mp;
	uint64_t base, off;
	const char *why = "?";
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !out_ents || !out_count || !out_no_caw || !victim)
		return -EINVAL;
	*out_ents = NULL;
	*out_count = 0;
	*out_no_caw = false;
	if (!ctx->rman_offset)
		return -ENODEV;

	cur = mxfs_pal_alloc(sizeof(*cur));
	hdr = mxfs_pal_alloc(sizeof(*hdr));
	if (!cur || !hdr) {
		rc = -ENOMEM;
		goto out;
	}
	if (xd) {
		d = xd;
		mp = xmp;
		if (!mp || mp->magic != MXFS_RECOV_MPTR_MAGIC ||
		    mp->version != MXFS_RECOV_MPTR_VERSION ||
		    mp->crc32c != recov_mptr_crc(ctx->fs_gen, victim, victim_epoch, mp)) {
			rc = -EPROTO;
			why = "escrowed manifest pointer does not validate for the victim";
			goto bad;
		}
	} else {
		off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			goto out;
		d = recov_desc_of(cur);
		if (!d) {
			rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
			why = "no valid descriptor";
			goto bad;
		}
		mp = recov_mptr_of(cur);
	}
	if (d->victim_node != victim || !inc_eq(d->victim_epoch, victim_epoch)) {
		rc = -ESTALE;
		why = "descriptor names a different victim";
		goto bad;
	}
	if (d->stage < MXFS_RECOV_STAGE_FENCED) {
		rc = -EPERM;
		why = "not FENCED";
		goto bad;
	}
	if (!mp) {
		rc = -EPROTO;
		why = "certified descriptor carries no valid manifest pointer";
		goto bad;
	}
	if (out_ptr)
		*out_ptr = *mp;

	base = rman_slot_off(ctx, slot);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, base, hdr, sizeof(*hdr));
	if (rc < 0) {
		why = "manifest header unreadable";
		goto bad;
	}
	if (hdr->magic != MXFS_RMAN_MAGIC || hdr->version != MXFS_RMAN_VERSION) {
		rc = -EPROTO; why = "manifest header magic/version"; goto bad;
	}
	if (hdr->seal != MXFS_RMAN_SEAL) {
		rc = -EPROTO; why = "manifest not sealed"; goto bad;
	}
	if (hdr->hdr_crc32c != rman_hdr_crc(hdr)) {
		rc = -EPROTO; why = "manifest header crc"; goto bad;
	}
	if (hdr->hdr_crc32c != mp->hdr_crc32c || hdr->seq != mp->seq ||
	    hdr->entry_count != mp->entry_count || hdr->byte_len != mp->byte_len ||
	    hdr->entries_crc32c != mp->entries_crc32c ||
	    hdr->fence_term != mp->fence_term ||
	    hdr->writer_node != mp->writer_node ||
	    !inc_eq(hdr->writer_epoch, mp->writer_epoch) ||
	    hdr->scan_slots != mp->scan_slots ||
	    (hdr->flags & (MXFS_RECOV_MPTR_F_NO_CAW_TABLE |
			   MXFS_RECOV_MPTR_F_TAUTH_LEDGER)) !=
			(mp->flags & (MXFS_RECOV_MPTR_F_NO_CAW_TABLE |
				      MXFS_RECOV_MPTR_F_TAUTH_LEDGER)) ||
		hdr->victim_slot != (uint16_t)slot || hdr->victim_node != victim ||
		!inc_eq(hdr->victim_epoch, victim_epoch) ||
		hdr->recovery_gen != d->recovery_gen ||
		hdr->victim_fs_gen != d->victim_fs_gen ||
		hdr->fence_term != d->fence_term) {
		rc = -EPROTO; why = "manifest header does not match the pointer/descriptor"; goto bad;
	}
	/* design review item 12: semantic validation, not just crc. */
	if (hdr->entry_count > MXFS_RMAN_MAX_ENTRIES ||
	    (uint64_t)hdr->byte_len !=
		(uint64_t)hdr->entry_count * sizeof(struct mxfs_rman_entry) ||
		(uint64_t)MXFS_RMAN_ENTRIES_OFF + hdr->byte_len > MXFS_RMAN_SLOT_BYTES) {
		rc = -EPROTO; why = "manifest entry geometry"; goto bad;
	}
	if (hdr->flags & ~(MXFS_RECOV_MPTR_F_NO_CAW_TABLE |
			   MXFS_RECOV_MPTR_F_INJECT_TORN |
			   MXFS_RECOV_MPTR_F_TAUTH_LEDGER)) {
		rc = -EPROTO; why = "manifest header flags"; goto bad;
	}
	if ((hdr->flags & MXFS_RECOV_MPTR_F_NO_CAW_TABLE) &&
	    (hdr->flags & MXFS_RECOV_MPTR_F_TAUTH_LEDGER)) {
		rc = -EPROTO; why = "manifest claims both NO_CAW and a ledger source"; goto bad;
	}
	if (hdr->flags & MXFS_RECOV_MPTR_F_NO_CAW_TABLE) {
		if (hdr->entry_count || hdr->scan_slots) {
			rc = -EPROTO; why = "NO_CAW manifest is not empty"; goto bad;
		}
		*out_no_caw = true;
	} else if (hdr->flags & MXFS_RECOV_MPTR_F_TAUTH_LEDGER) {
		/* the ledger geometry is the consumer's to check (it has the
		 * region open); a scan of zero pages is never a complete manifest */
		if (hdr->scan_slots == 0) {
			rc = -EPROTO; why = "ledger manifest scanned no pages"; goto bad;
		}
	} else if (hdr->scan_slots != MXFS_RMAN_MAX_ENTRIES) {
		rc = -EPROTO; why = "manifest did not scan the whole CAW table"; goto bad;
	}
	{
		size_t i;

		for (i = 0; i < sizeof(hdr->pad); i++)
			if (hdr->pad[i]) {
				rc = -EPROTO; why = "manifest header reserved bytes"; goto bad;
			}
	}
	if (hdr->entry_count) {
		uint32_t crc, i, io_len;

		io_len = (hdr->byte_len + MXFS_RMAN_IO_ALIGN - 1) &
			 ~(MXFS_RMAN_IO_ALIGN - 1);
		ents = mxfs_pal_alloc(io_len);
		if (!ents) {
			rc = -ENOMEM;
			goto out;
		}
		rc = mxfs_pal_bdev_read(ctx->dev, base + MXFS_RMAN_ENTRIES_OFF, ents,
					io_len);
		if (rc < 0) {
			why = "manifest entries unreadable";
			goto bad;
		}
		crc = mxfs_pal_crc32c(~0U, ents, hdr->byte_len);
		if (crc != hdr->entries_crc32c) {
			rc = -EPROTO; why = "manifest entries crc"; goto bad;
		}
		/* entries are in strictly increasing slot order by construction;
		 * every field must be in range; no duplicate slot (and the
		 * {type,id} duplicate check is done by the index builder).
		 *
		 * The slot_idx space depends on the manifest's SOURCE: a CAW
		 * manifest indexes the fixed 65536-slot lock table; a ledger
		 * manifest (0.71.0) indexes the TCP authority ledger, page *
		 * entries-per-page + entry, over the scan_slots pages the collector
		 * read — a region sized for this volume, 26426 pages on the QNAP
		 * LUN, so its indexes run to ~819k.  Bounding both by the CAW table
		 * size refused every ledger manifest with an entry past page 2114
		 * (2026-09-04 s502a: P-RMAN-INVALID rc=-71 on a 90-entry manifest,
		 * replay refused, slice quarantined). */
		uint32_t idx_bound = (hdr->flags & MXFS_RECOV_MPTR_F_TAUTH_LEDGER) ?
		    hdr->scan_slots * MXFS_TAUTH_ENTRIES_PER_PAGE : MXFS_RMAN_MAX_ENTRIES;
		uint32_t idx_max = 0;

		for (i = 0; i < hdr->entry_count; i++) {
			const struct mxfs_rman_entry *e = &ents[i];

			if (e->slot_idx >= idx_bound ||
			    (i && e->slot_idx <= ents[i - 1].slot_idx) ||
			    e->type < MXFS_LTYPE_INODE || e->type > MXFS_LTYPE_ICLUSTER ||
			    !e->mode || (e->mode & ~(MXFS_RMAN_MODE_EX | MXFS_RMAN_MODE_PW)) ||
			    e->flags) {
				mxfs_pal_log(MXFS_LOG_ERR,
				    "disklock: P-RMAN-INVALID-ENTRY slot=%d i=%u/%u slot_idx=%u "
				    "prev=%u bound=%u type=%u mode=0x%x flags=0x%x flagsrc=0x%x "
				    "scan=%u",
				    slot, i, hdr->entry_count, e->slot_idx,
				    i ? ents[i - 1].slot_idx : 0, idx_bound, e->type, e->mode,
				    e->flags, hdr->flags, hdr->scan_slots);
				rc = -EPROTO; why = "manifest entry out of range / order"; goto bad;
			}
			idx_max = e->slot_idx;
		}
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P-RMAN-ENTRIES slot=%d entries=%u idx_max=%u bound=%u "
		    "flags=0x%x scan=%u",
		    slot, hdr->entry_count, idx_max, idx_bound, hdr->flags,
		    hdr->scan_slots);
	}
	*out_ents = ents;
	ents = NULL;
	*out_count = hdr->entry_count;
	mxfs_pal_log(MXFS_LOG_DEBUG,
	    "disklock: P-RMAN-LOADED slot=%d victim=%u epoch=%llu seq=%llu "
	    "entries=%u flags=0x%x writer=%u/%llu term=%u — sealed fence-time "
	    "manifest validated against the certificate's pointer",
	    slot, victim, (unsigned long long)victim_epoch,
	    (unsigned long long)hdr->seq, hdr->entry_count, hdr->flags,
	    hdr->writer_node, (unsigned long long)hdr->writer_epoch,
	    hdr->fence_term);
	rc = 0;
	goto out;
bad:
	mxfs_pal_log(MXFS_LOG_ERR,
	    "disklock: P-RMAN-INVALID slot=%d victim=%u epoch=%llu rc=%d — %s; "
	    "no verdict may be taken from this manifest (the replay attempt must "
	    "abort, nothing purged, evidence preserved)",
	    slot, victim, (unsigned long long)victim_epoch, rc, why);
out:
	mxfs_pal_free(ents);
	mxfs_pal_free(cur);
	mxfs_pal_free(hdr);
	return rc;
}

int mxfs_disklock_recovery_manifest_read(struct mxfs_disklock_ctx *ctx, int slot,
					 mxfs_node_id_t victim,
					 mxfs_epoch_t victim_epoch,
					 struct mxfs_recov_manifest_ptr *out_ptr,
					 struct mxfs_rman_entry **out_ents,
					 uint32_t *out_count,
					 bool *out_no_caw)
{
	return rman_manifest_read_impl(ctx, slot, victim, victim_epoch, NULL, NULL,
				       out_ptr, out_ents, out_count, out_no_caw);
}

int mxfs_disklock_recovery_manifest_read_escrow(struct mxfs_disklock_ctx *ctx,
						int slot, mxfs_node_id_t victim,
						mxfs_epoch_t victim_epoch,
						const struct mxfs_recov_desc *d,
						const struct mxfs_recov_manifest_ptr *mptr,
						struct mxfs_recov_manifest_ptr *out_ptr,
						struct mxfs_rman_entry **out_ents,
						uint32_t *out_count,
						bool *out_no_caw)
{
	if (!d || !mptr)
		return -EINVAL;
	return rman_manifest_read_impl(ctx, slot, victim, victim_epoch, d, mptr,
				       out_ptr, out_ents, out_count, out_no_caw);
}

int mxfs_disklock_recovery_mptr_read(struct mxfs_disklock_ctx *ctx, int slot,
				     struct mxfs_recov_manifest_ptr *out)
{
	struct mxfs_disklock_heartbeat *cur;
	const struct mxfs_recov_manifest_ptr *mp;
	int rc;

	if (!ctx || !ctx->dev || !out || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, ctx->base_offset +
				     (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE,
				     cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == 0) {
		mp = recov_mptr_of(cur);
		if (mp)
			*out = *mp;
		else
			rc = -ENOENT;
	}
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_disklock_recovery_fence_takeover(struct mxfs_disklock_ctx *ctx,
					  int slot,
					  uint64_t victim_key,
					  struct mxfs_recov_fence_auth *out_auth)
{
	struct mxfs_disklock_heartbeat *first, *again, *want;
	const struct mxfs_recov_desc *d0, *d1;
	struct mxfs_recov_desc snap;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim_key)
		return -EINVAL;

	first = mxfs_pal_alloc(sizeof(*first));
	again = mxfs_pal_alloc(sizeof(*again));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!first || !again || !want) {
		rc = -ENOMEM;
		goto out;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, first, sizeof(*first));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d0 = recov_desc_of(first);
	if (!d0) {
		rc = recov_desc_present(first) ? -EPROTO : -ENOENT;
		goto out;
	}
	if (d0->stage >= MXFS_RECOV_STAGE_FENCED) {
		rc = -EEXIST;           /* already certified; claim it instead */
		goto out;
	}
	if (d0->stage != MXFS_RECOV_STAGE_FENCING &&
	    d0->stage != MXFS_RECOV_STAGE_SNAPSHOTTING) {
		rc = -EPROTO;
		goto out;
	}
	if (d0->owner_node == ctx->local_node &&
	    inc_eq(d0->owner_epoch, ctx->epoch)) {
		recov_fence_auth_issue(out_auth, d0);
		rc = 0;                 /* already ours */
		goto out;
	}
	if (d0->flags & MXFS_RECOV_F_QUARANTINED) {
		rc = -EPERM;
		goto out;
	}
	snap = *d0;

	/*
	 * Same discipline as recovery_takeover: abandonment is ABSENCE OF CHANGE
	 * across MXFS_RECOV_ABANDON_MS, never clock arithmetic.  And the same
	 * precondition — the caller must ALREADY have confirmed the prover's
	 * session dead.  A stalled stamp proves only "I observed no refresh".
	 *
	 * The stakes differ from an execution takeover, though, and in our favour:
	 * taking an attempt lease authorises nothing.  It authorises issuing a NEW
	 * PREEMPT AND ABORT and certifying THAT result.  If two survivors both get
	 * here, exactly one P&A wins and only that one can certify — the loser's
	 * fence_kind is RACE_LOST and certify refuses it.
	 *
	 * Blocks for MXFS_RECOV_ABANDON_MS; never call this on the HB thread.  A
	 * fatal signal on the caller abandons the observation (recov_abandon_wait):
	 * no attempt lease is taken.
	 */
	rc = recov_abandon_wait();
	if (rc)
		goto out;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d1 = recov_desc_of(again);
	if (!d1) {
		rc = recov_desc_present(again) ? -EPROTO : -ENOENT;
		goto out;
	}
	if (d1->victim_node != snap.victim_node ||
	    d1->victim_epoch != snap.victim_epoch ||
	    d1->owner_node != snap.owner_node ||
	    d1->owner_epoch != snap.owner_epoch ||
	    d1->recovery_gen != snap.recovery_gen ||
	    d1->fence_term != snap.fence_term ||
	    d1->stage != snap.stage ||
	    d1->stage_seq != snap.stage_seq ||
	    d1->owner_stamp_ms != snap.owner_stamp_ms) {
		rc = -EBUSY;            /* the prover is alive, or a third node took it */
		goto out;
	}

	*want = *again;
	want->recov.desc.owner_node        = ctx->local_node;
	want->recov.desc.owner_epoch       = ctx->epoch;
	recov_desc_set_owner_slot(ctx, &want->recov.desc);      /* */
	want->recov.desc.stage_seq         = d1->stage_seq + 1;
	want->recov.desc.owner_stamp_ms    = recov_stamp_after(d1->owner_stamp_ms);
	if (d1->stage == MXFS_RECOV_STAGE_FENCING) {
		/* A NEW fencing attempt: new term, we become the prover of whatever
		 * we prove. */
		want->recov.desc.fence_term        = d1->fence_term + 1;
		want->recov.desc.fence_prover_node = ctx->local_node;
		want->recov.desc.fence_prover_epoch = ctx->epoch;
		want->recov.desc.fence_victim_key  = victim_key;
		want->recov.desc.fence_stamp_ms    = mxfs_pal_time_ms();
		/* 0.74.0: a new prover starts a new non-proving series; the dead
		 * prover's blocked verdict does not carry over. */
		want->recov.desc.flags            &= ~MXFS_RECOV_F_FENCE_BLOCKED;
		/* 0.89.9: the submission marker is per term.  The dead term's "a
		 * command may have run" becomes PRIOR-TERM history (it still forbids
		 * reading key absence as that command's success); the new term has
		 * submitted nothing, so its own marker starts clear and the retry
		 * worker may re-drive a pre-command non-proving attempt.  Before
		 * this the inherited bit left the taken-over attempt ineligible for
		 * retry for good (sweep s71a cuts 3 and 4). */
		if (d1->flags & (MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN |
				 MXFS_RECOV_F_FENCE_PRIOR_TERM_MAY_HAVE_RUN))
			want->recov.desc.flags        |= MXFS_RECOV_F_FENCE_PRIOR_TERM_MAY_HAVE_RUN;
		want->recov.desc.flags            &= ~MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN;
	}
	/* (design review item 3): at SNAPSHOTTING the certificate bytes —
	 * kind, resv, key, prover, pr_gen, stamp AND fence_term — are IMMUTABLE:
	 * they name the one fencing operation that was proved, and no fencing
	 * operation happens here.  The snapshot lease is owner_node/owner_epoch
	 * (+ stage_seq); the dead holder can never present that incarnation
	 * again, so no term bump is needed to close an ABA. */
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, again, want);
	if (rc == 0) {
		recov_fence_auth_issue(out_auth, &want->recov.desc);
		if (d1->stage == MXFS_RECOV_STAGE_FENCING)
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P236-FENCE-ATTEMPT-TAKEOVER slot=%d victim=%u from "
			    "prover=%u term=%u->%u dead_term_armed=%d prior_term_may_have_run=%d "
			    "— the previous prover died with the intent durable.  We may "
			    "retry the PREEMPT AND ABORT and certify OUR result; we may "
			    "NEVER certify theirs, and an absent victim key is never read "
			    "as the dead term's success: it needs a proof of this term "
			    "(self or boot succession, the sole-survivor gate)",
			    slot, snap.victim_node, snap.fence_prover_node,
			    snap.fence_term, want->recov.desc.fence_term,
			    (snap.flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN) ? 1 : 0,
			    (want->recov.desc.flags &
			     MXFS_RECOV_F_FENCE_PRIOR_TERM_MAY_HAVE_RUN) ? 1 : 0);
		else
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P-RMAN-SNAPSHOT-TAKEOVER slot=%d victim=%u from "
			    "owner=%u term=%u->%u — the prover died AFTER proving "
			    "exclusion (certificate durable at SNAPSHOTTING) and before "
			    "sealing the fence-time manifest.  We redo the scan and seal "
			    "under the new term; the P&A is NOT repeated and the "
			    "certificate's prover bytes are unchanged",
			    slot, snap.victim_node, snap.owner_node,
			    snap.fence_term, want->recov.desc.fence_term);
	}
out:
	mxfs_pal_free(first);
	mxfs_pal_free(again);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_claim(struct mxfs_disklock_ctx *ctx, int slot,
				 mxfs_node_id_t victim,
				 mxfs_epoch_t victim_epoch,
				 struct mxfs_recov_auth *out_auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	const char *why = NULL;
	uint64_t off;
	unsigned int stage;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
		goto out;
	}
	if (d->victim_node != victim ||
	    !inc_eq(d->victim_epoch, victim_epoch)) {
		rc = -ESTALE;
		goto out;
	}
	/*
	 * The certificate is checked BEFORE ownership, and that ordering matters:
	 * "-EPERM, not certified" tells the caller to wait for a prover, while
	 * "-EBUSY, owned" tells it another replayer already has the job.  Getting
	 * -EBUSY for an uncertified descriptor would send an elected replayer off
	 * to wait for a recovery that nobody is authorised to run.
	 */
	if (!mxfs_recov_cert_proves_exclusion(d,
		    ctx->have_fs_identity ? ctx->fs_gen : 0,
		    slot, victim, victim_epoch, &why) ||
		(!recov_mptr_of(cur) &&
		 (why = "certified but carries no valid fence-time manifest pointer"))) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P236-CLAIM-UNCERTIFIED slot=%d victim=%u stage=%u "
		    "kind=%u — %s; refusing the claim.  Nothing on this slice may be "
		    "replayed, purged, repaired or published",
		    slot, victim, d->stage, d->fence_kind, why ? why : "?");
		rc = -EPERM;
		goto out;
	}
	if (d->owner_node == ctx->local_node &&
	    inc_eq(d->owner_epoch, ctx->epoch)) {
		recov_auth_issue(out_auth, d);
		rc = (int)d->stage;     /* idempotent: re-acquire our own auth */
		goto out;
	}
	if (d->owner_node != MXFS_RECOV_OWNER_NONE) {
		rc = -EBUSY;
		goto out;
	}

	/*
	 * Claiming an UNOWNED lease is NOT takeover: there is no prior
	 * owner to displace and nothing to prove dead, so there is no abandonment
	 * wait.  The CAS covers the WHOLE record, so the immutable certificate
	 * bytes are carried through byte for byte and any concurrent change to
	 * them loses the race.
	 */
	stage = d->stage;
	*want = *cur;
	want->recov.desc.owner_node     = ctx->local_node;
	want->recov.desc.owner_epoch    = ctx->epoch;
	recov_desc_set_owner_slot(ctx, &want->recov.desc);   /* */
	want->recov.desc.owner_term     = 1;
	want->recov.desc.stage_seq      = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0) {
		recov_auth_issue(out_auth, &want->recov.desc);
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P236-RECOV-CLAIMED slot=%d victim=%u epoch=%llu "
		    "gen=%llu owner=%u term=1 stage=%u — claimed a CERTIFIED unowned "
		    "recovery (proved by node=%u term=%u); this is a recovery lease, "
		    "not a member slot",
		    slot, victim, (unsigned long long)d->victim_epoch,
		    (unsigned long long)d->recovery_gen, ctx->local_node, stage,
		    d->fence_prover_node, d->fence_term);
		rc = (int)stage;
	}
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

/*
 * (D-MOUNT-RECOV-LEASE-STRANDED-BY-DEPARTED-OWNER-UNMOUNTABLE-532,
 * Design-consult ruling): durably GIVE BACK every recovery lease this incarnation
 * still owns, BEFORE the clean member-slot release retires the identity.
 * A mount whose cohort-barrier replay failed abandons its claim here; the
 * descriptor returns to UNOWNED with its stage and certificate preserved,
 * so the next claimant (this node's next incarnation included) proceeds
 * immediately instead of waiting forever on an owner that can never be
 * proved dead (a cleanly departed incarnation has no heartbeat to expire).
 *
 * Caller contract (the ruling's ordering): runs only after the incarnation
 * has stopped submitting recovery work — release_slot already requires the
 * heartbeat stopped and the DLM teardown has joined its workers by then;
 * the mount barrier's replay is synchronous and has returned.
 *
 * Returns 0 iff it can PROVE this incarnation owns no descriptor (none
 * found, or every found one durably given back).  Any read failure or
 * failed give-back returns an error — the caller must then NOT write the
 * clean member release: an owned descriptor with a fenceable owner is
 * recoverable via HB expiry + fence; an unfenceable orphan owner is the
 * D-532 permanent-unmount state.
 */
int mxfs_disklock_recovery_relinquish_owned(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	int slot, rc, tries, owned = 0, given = 0, failed = 0;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	cur  = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

		for (tries = 0; tries < 2; tries++) {
			const struct mxfs_recov_desc *d;

			mxfs_pal_mutex_lock(ctx->lock);
			rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
			mxfs_pal_mutex_unlock(ctx->lock);
			if (rc < 0) {
				/* cannot PROVE we do not own this one */
				failed++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "disklock: P236-RELINQ-READFAIL slot=%d rc=%d — cannot "
				    "prove this incarnation owns no recovery here",
				    slot, rc);
				break;
			}
			d = recov_desc_of(cur);
			if (!d || d->owner_node != ctx->local_node ||
			    !inc_eq(d->owner_epoch, ctx->epoch))
				break;          /* not ours (any more) — nothing to do */

			owned++;
			*want = *cur;
			want->recov.desc.owner_node     = MXFS_RECOV_OWNER_NONE;
			want->recov.desc.owner_epoch    = 0;
			want->recov.desc.owner_slot     = 0;
			want->recov.desc.flags         &= ~MXFS_RECOV_F_OWNER_BOOTSTRAP;  /* */
			want->recov.desc.owner_term     = 0;
			want->recov.desc.stage_seq      = d->stage_seq + 1;
			want->recov.desc.owner_stamp_ms =
			    recov_stamp_after(d->owner_stamp_ms);
			recov_desc_seal(want);

			rc = recov_cas_durable(ctx, slot, cur, want);
			if (rc == 0) {
				given++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "disklock: P236-RECOV-RELINQUISH slot=%d victim=%u "
				    "stage=%u — this departing incarnation (node=%u) gave "
				    "its recovery lease back UNOWNED (stage and certificate "
				    "preserved); the next claimant proceeds without a "
				    "death proof (D-532)",
				    slot, d->victim_node, d->stage, ctx->local_node);
				break;
			}
			if (rc == -EAGAIN && tries == 0) {
				owned--;        /* re-read and re-judge once */
				continue;
			}
			failed++;
			mxfs_pal_log(MXFS_LOG_WARN,
			    "disklock: P236-RELINQ-FAIL slot=%d rc=%d — the give-back "
			    "did not land; the member slot must NOT be cleanly "
			    "released (identity must stay fenceable)",
			    slot, rc);
			break;
		}
		if (failed)
			break;
	}

	if (owned || failed)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P236-RELINQ-SUMMARY node=%u owned=%d given_back=%d "
		    "failed=%d",
		    ctx->local_node, owned, given, failed);

	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return failed ? -EIO : 0;
}

int mxfs_disklock_recovery_relinquish_slot(struct mxfs_disklock_ctx *ctx,
					   int slot,
					   const struct mxfs_recov_auth *auth)
{
	struct mxfs_disklock_heartbeat *cur, *want;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || !auth || slot < 0 ||
	    slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	cur  = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		mxfs_pal_free(cur);
		mxfs_pal_free(want);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;
	d = recov_desc_of(cur);
	if (!d || d->owner_node != ctx->local_node ||
	    !inc_eq(d->owner_epoch, ctx->epoch) ||
	    !recov_tok_eq(d->recovery_gen, auth->recovery_gen) ||
	    d->owner_term != auth->owner_term ||
	    d->victim_slot != auth->victim_slot ||
	    d->victim_node != auth->victim_node) {
		rc = -ENOENT;
		goto out;
	}

	*want = *cur;
	want->recov.desc.owner_node     = MXFS_RECOV_OWNER_NONE;
	want->recov.desc.owner_epoch    = 0;
	want->recov.desc.owner_slot     = 0;
	want->recov.desc.flags         &= ~MXFS_RECOV_F_OWNER_BOOTSTRAP;  /* */
	want->recov.desc.owner_term     = 0;
	want->recov.desc.stage_seq      = d->stage_seq + 1;
	want->recov.desc.owner_stamp_ms = recov_stamp_after(d->owner_stamp_ms);
	recov_desc_seal(want);

	rc = recov_cas_durable(ctx, slot, cur, want);
	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-RECOV-RELINQUISH-SLOT slot=%d victim=%u stage=%u "
		    "gen=%llu term=%u — owner node=%u/%llu gave its recovery lease "
		    "back UNOWNED after the bounded completion deadline (stage and "
		    "certificate preserved); a successor may take it over",
		    slot, d->victim_node, d->stage,
		    (unsigned long long)d->recovery_gen, d->owner_term,
		    ctx->local_node, (unsigned long long)ctx->epoch);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-RELINQ-SLOT-FAIL slot=%d victim=%u rc=%d — the "
		    "give-back did not land",
		    slot, d->victim_node, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_disklock_recovery_slot_status(struct mxfs_disklock_ctx *ctx, int slot,
				       mxfs_node_id_t victim,
				       mxfs_epoch_t victim_epoch)
{
	struct mxfs_disklock_heartbeat *cur;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim)
		return -EINVAL;

	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0)
		goto out;

	if (recov_desc_present(cur)) {
		rc = recov_desc_of(cur) ? MXFS_RECOV_SLOT_DESCRIPTOR
					: MXFS_RECOV_SLOT_UNREADABLE;
		goto out;
	}
	if (cur->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, cur)) {
		rc = MXFS_RECOV_SLOT_CONSUMABLE;
		goto out;
	}
	if ((cur->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
	     cur->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN) ||
		cur->node_id != victim) {
		rc = MXFS_RECOV_SLOT_FOREIGN;
		goto out;
	}
	/*
	 * Same predicate as recovery_begin's supersession arm, and deliberately no
	 * weaker: a valid feature block at the CURRENT proto_gen, flags == ACTIVE
	 * (a WITHDRAWN successor is itself dead and owes its own replay), both
	 * incarnations nonzero, and the two differing.
	 */
	if (inc_valid(victim_epoch) && !inc_eq(cur->epoch, victim_epoch)) {
		if (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		    hb_feature_state(cur) == MXFS_HBFEAT_OK &&
		    inc_valid(cur->epoch))
			rc = MXFS_RECOV_SLOT_SUPERSEDED;
		else
			rc = MXFS_RECOV_SLOT_FOREIGN;
		goto out;
	}
	rc = MXFS_RECOV_SLOT_UNFENCED;
out:
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_disklock_recovery_replay_authorized(struct mxfs_disklock_ctx *ctx,
					     int slot,
					     mxfs_node_id_t victim,
					     mxfs_epoch_t victim_epoch,
					     const struct mxfs_recov_auth *auth,
					     const char *site,
					     uint16_t *out_fence_kind)
{
	struct mxfs_disklock_heartbeat *cur;
	const struct mxfs_recov_desc *d;
	const char *why = NULL;
	uint64_t off;
	int rc;

	if (out_fence_kind)
		*out_fence_kind = MXFS_FENCE_KIND_NONE;
	if (!site)
		site = "?";
	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !victim) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u — bad "
		    "arguments; a gate that cannot identify what it is authorising "
		    "authorises nothing",
		    site, slot, victim);
		return -EINVAL;
	}

	/*
	 * Deliberately a FRESH READ every time, never a cached snapshot.  The
	 * platter is the authority (rule 6) and this gate sits in front of
	 * irreversible work: in-place XFS log replay onto the shared LUN,
	 * destructive manifest repair, sector zeroing.  One extra 512-byte
	 * prio read is not a cost worth trading for that.
	 */
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u rc=%d — "
		    "could not read the victim's sector; authorisation is UNKNOWN and "
		    "unknown is refused",
		    site, slot, victim, rc);
		goto out;
	}

	d = recov_desc_of(cur);
	if (!d) {
		rc = recov_desc_present(cur) ? -EPROTO : -ENOENT;
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u rc=%d — "
		    "%s.  No certificate means no proof that the victim is excluded "
		    "from the LUN, and replaying its journal slice while it can still "
		    "write is how two nodes write the same blocks",
		    site, slot, victim, rc,
		    rc == -EPROTO ? "the descriptor cannot be validated by this build" :
				    "the slot carries no recovery descriptor");
		goto out;
	}

	if (!mxfs_recov_cert_proves_exclusion(d,
		    ctx->have_fs_identity ? ctx->fs_gen : 0,
		    slot, victim, victim_epoch, &why) ||
		(!recov_mptr_of(cur) &&
		 (why = "certified but carries no valid fence-time manifest pointer"))) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u "
		    "epoch=%llu stage=%u kind=%u resv=0x%02x — %s",
		    site, slot, victim, (unsigned long long)victim_epoch,
		    d->stage, d->fence_kind, d->fence_resv_type, why ? why : "?");
		rc = -EPERM;
		goto out;
	}

	/*
	 * Certified.  If the caller holds an execution lease it must still be the
	 * current one — otherwise we were taken over while we worked and nothing
	 * we are about to do may be published.  A NULL auth is a pre-claim probe
	 * and gets the certificate answer only.
	 */
	if (auth && !recov_auth_holds(ctx, d, auth)) {
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P236-REPLAY-REFUSED site=%s slot=%d victim=%u — the "
		    "slice is certified fenced, but the execution lease is now "
		    "owner=%u epoch=%llu term=%u and we hold node=%u epoch=%llu "
		    "gen=%llu term=%u.  We were taken over mid-flight",
		    site, slot, victim, d->owner_node,
		    (unsigned long long)d->owner_epoch, d->owner_term,
		    ctx->local_node, (unsigned long long)ctx->epoch,
		    (unsigned long long)auth->recovery_gen, auth->owner_term);
		rc = -EBUSY;
		goto out;
	}

	if (out_fence_kind)
		*out_fence_kind = d->fence_kind;
	rc = 0;
out:
	mxfs_pal_free(cur);
	return rc;
}

void mxfs_disklock_set_expire_cb(struct mxfs_disklock_ctx *ctx,
				  mxfs_disklock_expire_cb cb, void *data)
{
	ctx->expire_cb = cb;
	ctx->expire_cb_data = data;
}

void mxfs_disklock_set_fs_identity(struct mxfs_disklock_ctx *ctx,
				   const uint8_t *fs_uuid)
{
	mxfs_volume_id_t vid;

	if (!ctx || !fs_uuid)
		return;

	memcpy(ctx->fs_uuid, fs_uuid, 16);
	vid = mxfs_uuid_to_volume_id(fs_uuid, 16);
	ctx->fs_gen = (uint32_t)(vid ^ (vid >> 32));
	if (ctx->fs_gen == 0)
		ctx->fs_gen = 1;        /* 0 means legacy/unset on disk */
	ctx->have_fs_identity = true;
}

/* the same fold, for a caller that has no disklock yet (the bootstrap
 * record is read BEFORE the PR REGISTER, §6.1 waiter rule). */
uint32_t mxfs_disklock_fs_gen_of(const uint8_t *fs_uuid)
{
	mxfs_volume_id_t vid;
	uint32_t gen;

	if (!fs_uuid)
		return 0;
	vid = mxfs_uuid_to_volume_id(fs_uuid, 16);
	gen = (uint32_t)(vid ^ (vid >> 32));
	return gen ? gen : 1;
}

void mxfs_disklock_set_fence_cb(struct mxfs_disklock_ctx *ctx,
				mxfs_disklock_fence_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->fence_cb = cb;
	ctx->fence_cb_data = data;
}

void mxfs_disklock_set_conflict_cb(struct mxfs_disklock_ctx *ctx,
				   mxfs_disklock_conflict_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->conflict_cb = cb;
	ctx->conflict_cb_data = data;
}

void mxfs_disklock_set_dbg_purge_hook(struct mxfs_disklock_ctx *ctx,
				      mxfs_disklock_dbg_purge_hook hook,
				      void *data)
{
	if (!ctx)
		return;
	ctx->dbg_purge_hook = hook;
	ctx->dbg_purge_hook_data = data;
}

void mxfs_disklock_set_evict_cb(struct mxfs_disklock_ctx *ctx,
				mxfs_disklock_evict_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->evict_cb = cb;
	ctx->evict_cb_data = data;
}

/*
 * producer side of the inode-eviction ring.  Record that this node has
 * freed inode `ino` (now at di_gen `gen`).  Non-blocking: append to the in-mem
 * staging ring (overwriting the oldest entry once full — peers detect the gap
 * via the head_seq jump and fall back to a sweep) and bump the publish counter.
 * disklock_hb_fn serialises this into the outgoing heartbeat on its next write.
 */
void mxfs_disklock_note_freed(struct mxfs_disklock_ctx *ctx,
			      uint64_t ino, uint32_t gen, uint32_t type)
{
	uint32_t idx;

	if (!ctx || !ctx->evict_lock)
		return;

	mxfs_pal_mutex_lock(ctx->evict_lock);
	/*
	 * dedup — if the most-recent staged entry is the same (ino,type)
	 * we just published, skip.  A node renaming 20 files in one shared dir
	 * would otherwise stage 20 identical DIR_MODIFY entries and overflow the
	 * 28-deep ring (evicting other peers' useful entries).  One entry per dir
	 * per burst is enough; the consumer's gen-bump is idempotent.
	 */
	if (ctx->evict_head_seq > 0) {
		uint32_t prev = (ctx->evict_head_seq - 1) % MXFS_EVICT_RING_ENTRIES;
		if (ctx->evict_stage[prev].ino == ino &&
		    ctx->evict_stage[prev].type == type) {
			mxfs_pal_mutex_unlock(ctx->evict_lock);
			return;
		}
	}
	idx = ctx->evict_head_seq % MXFS_EVICT_RING_ENTRIES;
	ctx->evict_stage[idx].ino = ino;
	ctx->evict_stage[idx].gen = gen;
	ctx->evict_stage[idx].type = type;
	ctx->evict_head_seq++;
	if (dl_instr_on())
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "mxfs: P-EVICT-STAGE ino=%llu type=%u head_seq=%u",
		    (unsigned long long)ino, type, ctx->evict_head_seq);
	if (ctx->evict_count < MXFS_EVICT_RING_ENTRIES)
		ctx->evict_count++;
	mxfs_pal_mutex_unlock(ctx->evict_lock);
}

void mxfs_disklock_monitor_node(struct mxfs_disklock_ctx *ctx,
				 mxfs_node_id_t node_id)
{
	int slot = mxfs_disklock_find_node_slot(ctx, node_id);

	if (slot < 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: node %u has not started heartbeat yet, "
		    "will retry monitoring", node_id);
		return;
	}

	memset(&ctx->node_track[slot], 0, sizeof(ctx->node_track[slot]));
	ctx->slot_node_id[slot] = node_id;
	ctx->monitored[slot] = true;
	mxfs_pal_log(MXFS_LOG_DEBUG,
	    "disklock: monitoring node %u (slot %d)", node_id, slot);
}

/*
 * v0.5.0: override the dead-declaration window.  The monitor declares a
 * peer dead after dead_threshold consecutive stale heartbeat samples at
 * MXFS_DISKLOCK_HB_INTERVAL_MS each; the compile-time default (62 s) is
 * production-conservative.  Test rigs need fast fail-detect — crash
 * recovery (lock purge + foreign-slice replay) is gated on this.
 * Floor of 2 samples: one stale sample is sampling-phase noise, not death.
 */
void mxfs_disklock_set_dead_timeout_ms(struct mxfs_disklock_ctx *ctx,
				       uint32_t timeout_ms)
{
	uint32_t samples;

	if (!ctx)
		return;
	if (timeout_ms == 0) {
		ctx->dead_threshold = MXFS_DISKLOCK_DEAD_THRESHOLD;
		return;
	}
	samples = timeout_ms / MXFS_DISKLOCK_HB_INTERVAL_MS;
	if (samples < 2)
		samples = 2;
	ctx->dead_threshold = samples;
	mxfs_pal_log(MXFS_LOG_INFO,
	    "disklock: dead-declaration window set to %u ms (%u samples)",
	    samples * MXFS_DISKLOCK_HB_INTERVAL_MS, samples);
}

/*
 * v0.5.0 foreign-slice replay election: return the lowest live heartbeat
 * slot among the survivors (this node's own slot plus every monitored
 * slot whose tracker says live), excluding skip_slot (the dead node).
 * Survivors each compute this from their own monitor view; the node
 * whose local_slot equals the result is the elected replayer.  Double
 * election is correctness-safe (replay is LSN-gated/idempotent), so a
 * transiently divergent view only costs duplicate work.
 *
 * Called from the heartbeat thread (lease-expire path) — the same thread
 * that mutates monitored[]/node_track[], so no locking is needed.
 */
/*  advisory per-slot liveness — see disklock.h. */
bool mxfs_disklock_slot_live(struct mxfs_disklock_ctx *ctx, int slot)
{
	if (!ctx || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return false;
	if (slot == ctx->local_slot)
		return true;
	return ctx->monitored[slot] && ctx->node_track[slot].live;
}

/*
 * — see disklock.h.  Disk truth about slot occupancy, for the
 * recovery coordinator's takeover gate.  Priority read so it pierces every
 * cache layer the way the recovery ops themselves do; a read failure is
 * reported through *out_read_ok and answered "still resident" so a caller
 * that cannot see the sector never concludes departure from silence.
 */
bool mxfs_disklock_slot_holds_incarnation(struct mxfs_disklock_ctx *ctx,
					  int slot, mxfs_node_id_t node,
					  mxfs_epoch_t epoch,
					  bool *out_read_ok)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t off;
	bool held;
	int rc;

	if (out_read_ok)
		*out_read_ok = false;
	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    !node)
		return true;            /* cannot prove departure — fail closed */
	/*
	 * No incarnation named.  This function's entire contract is fail-closed
	 * ("cannot prove departure -> say it is still resident"), but the match
	 * below is an equality test, so a zero `epoch` against a real record
	 * would return FALSE — i.e. actively assert departure — from an argument
	 * that proves nothing.  That is the wrong direction, and it is exactly
	 * the wildcard hazard the incarnation work exists to remove.
	 */
	if (!inc_valid(epoch))
		return true;

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return true;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, hb, sizeof(*hb));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0) {
		mxfs_pal_free(hb);
		return true;            /* unread sector: assume still resident */
	}
	if (out_read_ok)
		*out_read_ok = true;

	held = (hb->magic == MXFS_DISKLOCK_MAGIC &&
		hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		hb->node_id == node &&
		hb->epoch == epoch &&
		!hb_gen_foreign(ctx, hb));
	mxfs_pal_free(hb);
	return held;
}

/*
 * (barrier resolved-elsewhere ruling, P0): is `slot`'s sector in an
 * ENUMERATED terminal state for victim {node, epoch}?  Only two shapes
 * count, from a FRESH read: (1) a recognized ZERO record (magic 0, flags
 * EMPTY, no node — what recovery completion / clean release leave), or
 * (2) a valid ACTIVE record of OUR mkfs generation naming a DIFFERENT
 * incarnation (a successor can only claim after the predecessor's
 * completion).  Everything else — the victim itself in any flag state,
 * WITHDRAWN, a recovery descriptor, a foreign-generation ghost, bad magic,
 * an unread sector — is NOT terminal (fail closed).  *why names the shape.
 */
bool mxfs_disklock_slot_terminal_for(struct mxfs_disklock_ctx *ctx, int slot,
				     mxfs_node_id_t node, mxfs_epoch_t epoch,
				     const char **why)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t off;
	bool term = false;
	int rc;

	if (why)
		*why = "invalid";
	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS || !node)
		return false;
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return false;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, hb, sizeof(*hb));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc < 0) {
		if (why)
			*why = "unread";
		mxfs_pal_free(hb);
		return false;
	}
	if (hb->magic == 0 && hb->flags == MXFS_DISKLOCK_FLAG_EMPTY &&
	    hb->node_id == 0 && hb->epoch == 0) {
		term = true;
		if (why)
			*why = "zero";
	} else if (hb->magic == MXFS_DISKLOCK_MAGIC && !hb_gen_foreign(ctx, hb) &&
		   hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
		   (hb->node_id != node || hb->epoch != epoch)) {
		term = true;
		if (why)
			*why = "successor";
	} else if (why) {
		*why = (hb->magic != MXFS_DISKLOCK_MAGIC) ? "badmagic" :
		       hb_gen_foreign(ctx, hb) ? "foreign" :
		       (hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) ? "withdrawn" :
		       (hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE) ? "victim-active" :
		       "descriptor-or-other";
	}
	mxfs_pal_free(hb);
	return term;
}

int mxfs_disklock_lowest_live_slot(struct mxfs_disklock_ctx *ctx,
				   int skip_slot)
{
	int slot;

	if (!ctx)
		return -1;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		if (slot == skip_slot)
			continue;
		if (slot == ctx->local_slot)
			return slot;
		if (ctx->monitored[slot] && ctx->node_track[slot].live)
			return slot;
	}
	return -1;
}

/*
 * How many live slots sit BELOW ours — 0 means we are the lowest, i.e. the
 * node mxfs_disklock_lowest_live_slot() elects.
 *
 * The election answers "am I the one", which is all a job needs when the
 * elected node is always able to do it.  It is not enough when the job must
 * still get done if that node is gone: every other node then reads "not me"
 * and the work is simply never performed.  A RANK lets the others queue
 * behind the elected node in a fixed, collision-free order instead, each
 * waiting longer than the one below it before stepping in.
 *
 * Same liveness predicate as the election above, deliberately in the same
 * place: a rank derived from a second, drifting copy of "is that slot live"
 * would put two nodes at rank 0.
 */
int mxfs_disklock_live_slot_rank(struct mxfs_disklock_ctx *ctx)
{
	int slot, rank = 0;

	if (!ctx || ctx->local_slot < 0)
		return -1;      /* no slot claimed: we are not in the order at all */

	for (slot = 0; slot < ctx->local_slot &&
		       slot < MXFS_DISKLOCK_HB_SLOTS; slot++)
		if (ctx->monitored[slot] && ctx->node_track[slot].live)
			rank++;
	return rank;
}

/*
 * 0.75.26: retire a recovered incarnation's TRACKING with it, on the node
 * that completed the recovery.  The monitor's P163-RECOVERED path 
 * already does this for a survivor that learns of the completion by seeing
 * the zeroed sector — but the ELECTED replayer clears the pending marker
 * itself (mxfs_disklock_clear_recovery_pending) before its monitor's next
 * pass, so that path never runs for it and node_track[slot].last_epoch /
 * slot_node_id[slot] stay pinned to the dead incarnation.  The slot's next
 * claimant then reads as an epoch change of the retired victim: measured
 * s516f1 on the 2-node TCP rig (test1 always the elected node) — 'P-EVICT-
 * AUTOMON slot=1 node=<successor>' immediately followed by 'node in slot 1
 * has restarted (detected epoch change from <victim inc> to <successor
 * inc>)', a second death of a node recovered four minutes earlier
 * (NO_VICTIM_KEY, refused), the live successor's goodbye ignored as a
 * recovery-pending identity, 40 s of view skew and a REMASTER storm; in
 * s516b the same shape failed a rejoining mount outright (60 REMASTER
 * retries on the root inode, filesystem shut down).
 *
 * Same policy as the monitor path: if a successor already holds the slot,
 * it inherits the slot's membership standing (an ACTIVE record proves
 * ownership, not liveness — it enters dead-detection immediately);
 * otherwise the slot is forgotten and the auto-monitor re-baselines on
 * whoever claims it next.  Only the exact incarnation that was recovered is
 * retired; a slot already re-tracked for someone else is left alone.
 */
void mxfs_disklock_slot_tenancy_retire(struct mxfs_disklock_ctx *ctx, int slot,
				       mxfs_node_id_t node,
				       mxfs_epoch_t victim_epoch)
{
	struct mxfs_disklock_heartbeat *rhb;
	struct mxfs_disklock_node_track *nt;
	bool successor = false;
	int rc = -ENOMEM;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    slot == ctx->local_slot)
		return;
	nt = &ctx->node_track[slot];
	if (ctx->slot_node_id[slot] != node ||
	    (inc_valid(victim_epoch) && inc_valid(nt->last_epoch) &&
	     !inc_eq(nt->last_epoch, victim_epoch))) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-SLOT-TENANCY-KEPT slot=%d node=%u inc=%llu — "
			     "tracking names node=%u inc=%llu, not the recovered "
			     "incarnation; left alone",
			     slot, node, (unsigned long long)victim_epoch,
			     ctx->slot_node_id[slot],
			     (unsigned long long)nt->last_epoch);
		return;
	}
	rhb = mxfs_pal_alloc(sizeof(*rhb));
	if (rhb) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rhb, sizeof(*rhb));
		mxfs_pal_mutex_unlock(ctx->lock);
		successor = rc == 0 && rhb->magic == MXFS_DISKLOCK_MAGIC &&
			    rhb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
			    !hb_gen_foreign(ctx, rhb) && rhb->node_id != 0 &&
			    rhb->node_id != node && inc_valid(rhb->epoch);
	}
	mxfs_pal_mutex_lock(ctx->lock);
	nt->changed_samples = 0;
	nt->equal_samples   = 0;
	nt->evict_seen      = false;
	nt->seq_seen        = false;
	if (successor) {
		nt->last_epoch     = rhb->epoch;
		nt->last_timestamp = rhb->timestamp_ms;
		nt->last_change_ms = mxfs_pal_time_ms();
		nt->live           = true;
		ctx->monitored[slot]    = true;
		ctx->slot_node_id[slot] = rhb->node_id;
	} else {
		nt->last_epoch     = 0;
		nt->last_timestamp = 0;
		nt->live           = false;
		ctx->monitored[slot]    = false;
		ctx->slot_node_id[slot] = 0;
	}
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-SLOT-TENANCY-RETIRED slot=%d node=%u inc=%llu "
		     "successor=%u/%llu — the recovered incarnation's tracking "
		     "is retired with it; the slot's next claimant is a new "
		     "tenancy, not a restart",
		     slot, node, (unsigned long long)victim_epoch,
		     successor ? rhb->node_id : 0,
		     successor ? (unsigned long long)rhb->epoch : 0ULL);
	mxfs_pal_free(rhb);
}

void mxfs_disklock_unmonitor_node(struct mxfs_disklock_ctx *ctx,
				   mxfs_node_id_t node_id)
{
	uint32_t slot;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		if (ctx->monitored[slot] && ctx->slot_node_id[slot] == node_id) {
			ctx->monitored[slot] = false;
			ctx->slot_node_id[slot] = 0;
			memset(&ctx->node_track[slot], 0, sizeof(ctx->node_track[slot]));
			mxfs_pal_log(MXFS_LOG_DEBUG,
			    "disklock: unmonitoring node %u (slot %u)", node_id, slot);
			return;
		}
	}

	mxfs_pal_log(MXFS_LOG_WARN,
	    "mxfs: node %u was not being monitored "
	    "(may have already been removed)", node_id);
}

/*
 * Scan the 64 heartbeat slots on disk to find which slot a given
 * node_id occupies.  Returns the slot index (0-63) or -1 if not found.
 */
int mxfs_disklock_find_node_slot(struct mxfs_disklock_ctx *ctx,
				   mxfs_node_id_t node_id)
{
	struct mxfs_disklock_heartbeat *hb;
	uint32_t slot;
	int found = -1;

	if (!ctx || !ctx->dev)
		return -1;

	/*
	 * Check in-memory mapping first (populated by monitor_node / the
	 * auto-monitor).  D2: do NOT gate on
	 * monitored[] — fire_dead clears it right before invoking expire_cb,
	 * and the expire path needs this lookup to mark recovery pending.
	 * slot_node_id[] persists (cleared only by unmonitor_node on a clean
	 * leave), and a node→slot binding never changes within a generation.
	 */
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		if (ctx->slot_node_id[slot] == node_id)
			return (int)slot;
	}

	/* Fall back to disk scan */
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -1;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		int rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		if (rc < 0)
			continue;
		/* D2: a WITHDRAWN stamp still names its slot — the expire
		 * path must resolve it to mark recovery pending.
		 *
		 * so does a RECOVERY_GUARD whose descriptor names this
		 * victim.  Without that arm a peer that never witnessed the death
		 * resolves slot = -1 and falls into v5_lease_expire_cb's "owns no
		 * heartbeat slot, so owns no journal slice — purge immediately" arm,
		 * which would purge the in-memory grants of a node whose slice is
		 * mid-recovery.  The in-memory slot_node_id[] fast path above masks
		 * this for peers that DID see the death, which is why the disk-scan
		 * arm is the one that has to be right. */
		if (hb->magic == MXFS_DISKLOCK_MAGIC &&
		    (((hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
		       hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) &&
			  hb->node_id == node_id) ||
			 recov_desc_names_node(hb, node_id))) {
			found = (int)slot;
			break;
		}
	}

	mxfs_pal_free(hb);
	return found;
}

/*
 * ASYMMETRIC MDS: resolve which node_id currently occupies a given
 * heartbeat slot (0-63).  Checks the in-memory map first, then reads the slot
 * on disk.  Returns the node_id or 0 if the slot is empty/unreadable.  Used by
 * clients to address the metadata-server node (static v1: MDS = slot 0).
 */
mxfs_node_id_t mxfs_disklock_get_slot_node_id(struct mxfs_disklock_ctx *ctx,
					      int slot)
{
	struct mxfs_disklock_heartbeat *hb;
	mxfs_node_id_t node_id = 0;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return 0;

	if (ctx->slot_node_id[slot])
		return ctx->slot_node_id[slot];

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return 0;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
	if (rc >= 0 && hb->magic == MXFS_DISKLOCK_MAGIC &&
	    hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	    !hb_gen_foreign(ctx, hb))
		node_id = hb->node_id;
	mxfs_pal_free(hb);
	return node_id;
}

/*
 * Claim a unique heartbeat slot (0-63).  Scans all slots; prefers
 * re-claiming our own node_id from a previous mount, otherwise takes
 * the first empty slot.  Returns the slot index or negative errno.
 */
/*
 * (PROVEN BY INSTRUMENT): the slot claim was a non-atomic
 * read-scan + plain FUA write.  Two nodes mounting concurrently (the
 * 4-node criterion harness mounts in parallel) both scanned, both saw
 * the same slot free, both wrote their heartbeat ~0.5s apart — test3
 * and test4 each booted with node_slot=1 / node_bit=2 (MDS-IDENTITY
 * logs), so each saw the OTHER's CAW lock-slot holder bits as its own
 * ("already-held", P15-INSTR slot=50299 h_ex=2).  Result: ZERO mutual
 * exclusion between the two nodes — concurrent EX on the same AG,
 * double inode allocation ("Allocated a known in-use inode"), missing
 * BASTs, stale dinode reloads, FS shutdown (strong_consistency FAIL).
 *
 * Fix: claim the slot with SCSI COMPARE-AND-WRITE from the observed
 * sector image, exactly like the CAW lock slots.  A concurrent claimer
 * miscompares (-EAGAIN), rescans, and takes the next free slot.  Slot
 * uniqueness (invariant: disklock slot 0..63 unique per live node) is
 * then guaranteed by the device's atomic CAW, not by timing luck.
 */
#define MXFS_DISKLOCK_CLAIM_RETRIES 16

/*
 * D-LOG-SLICE-SHARED-MULTIWRITER (ruling, claim-time layer): the
 * exclusive bound on slot numbers a CLAIM may scan.  A slot's journal slice
 * is the identically numbered slice, so a volume formatted with N slices
 * supports at most N members — claiming slot >= N would admit a node with
 * no journal.  Monitor/purge/fence scans deliberately do NOT use this
 * bound: legacy out-of-range occupants must still be seen, declared dead,
 * and fenced.
 */
static uint32_t hb_claim_slot_bound(const struct mxfs_disklock_ctx *ctx)
{
	if (ctx->slot_limit && ctx->slot_limit < MXFS_DISKLOCK_HB_SLOTS)
		return ctx->slot_limit;
	return MXFS_DISKLOCK_HB_SLOTS;
}

/*
 * D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376, design-consult ruling
 * item 1 ("correct the ENOSPC diagnostic; count and report guards").
 *
 * The old message said the cluster was FULL and told the operator to
 * "reformat with more slices (mkfs_mxfs -n)".  Both halves can be wrong and
 * the advice can be actively destructive:
 *
 *   - a slot occupied by a RECOVERY_GUARD is NOT a member.  It is a durable
 *     terminal-refusal verdict awaiting operator repair, and it is the only
 *     copy of that verdict.  Reformatting destroys the very evidence the
 *     quarantine exists to preserve.
 *   - a WITHDRAWN slot is a dirty journal slice awaiting fence+replay, i.e. a
 *     transient state the monitor is already working on — retrying the mount
 *     is the correct response, not reformatting.
 *   - at the maximum supported cluster size the advice is UNFOLLOWABLE:
 *     mkfs_mxfs refuses -n > 32, so a 32-slice volume has no larger format.
 *
 * So classify the table and say what is actually there.  Diagnostic only —
 * this changes no claim decision.  Out-of-range occupants (slot >= slot_max
 * on a volume with fewer slices than MXFS_DISKLOCK_HB_SLOTS) are counted and
 * reported separately: they are a format/protocol violation in their own
 * right and must never be mistaken for admissible members.
 */
static void hb_report_claim_exhausted(struct mxfs_disklock_ctx *ctx,
				      uint32_t slot_max)
{
	struct mxfs_disklock_heartbeat *rec;
	uint32_t slot;
	uint32_t n_active = 0, n_guard = 0, n_withdrawn = 0;
	uint32_t n_other = 0, n_unread = 0, n_outofrange = 0;
	uint32_t n_recovering = 0, n_sweepguard = 0, n_bucketguard_hi = 0;
	int first_guard = -1;
	mxfs_node_id_t first_guard_node = 0;

	rec = mxfs_pal_alloc(sizeof(*rec));
	if (!rec) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: no free heartbeat slot in 0..%u (no memory to "
			     "classify the table)", slot_max - 1);
		return;
	}

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		bool occupied;

		if (mxfs_pal_bdev_read(ctx->dev, off, rec, sizeof(*rec)) < 0) {
			if (slot < slot_max)
				n_unread++;
			continue;
		}
		occupied = (rec->magic == MXFS_DISKLOCK_MAGIC) &&
			   !hb_gen_foreign(ctx, rec);

		if (slot >= slot_max) {
			/* beyond the volume's slice count, exactly ONE kind of
			 * record is legitimate — the unclaimed-bucket sweep's transient
			 * RECOVERY_GUARD.  mxfs_unclaimed_bucket_scan() iterates
			 * b < XFS_AGI_UNLINKED_BUCKETS (64) and uses the bucket index AS
			 * the disklock slot index, so on an N-slice volume buckets
			 * N..63 are always unclaimed and their sweeps guard slots N..63
			 * by design.  A MEMBER-shaped record up here (ACTIVE or
			 * WITHDRAWN) is a different matter: this volume has no journal
			 * slice for it, so it is a format/protocol violation. */
			if (occupied &&
			    rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
			    !recov_desc_present(rec))
				n_bucketguard_hi++;
			else if (occupied && rec->flags != 0)
				n_outofrange++;
			continue;
		}
		if (!occupied)
			continue;
		switch (rec->flags) {
		case MXFS_DISKLOCK_FLAG_ACTIVE:
			n_active++;
			break;
		case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD: {
			/* a RECOVERY_GUARD is TWO different things and the
			 * difference decides what the operator must do.
			 *   - with a valid QUARANTINED descriptor: a terminal verdict.
			 *     Permanent until an operator accepts the loss.
			 *   - with no descriptor at all: the unclaimed-bucket sweep's
			 *     transient working guard (mxfs_unclaimed_bucket_scan takes
			 *     one on any unclaimed slot < 64 to sweep that AGI bucket).
			 *     It clears itself; reporting it as a quarantine would send
			 *     the operator hunting a verdict that does not exist.
			 * recov_desc_present() requires MXFS_RECOV_DESC_MAGIC in the
			 * body, which a sweep guard never writes. */
			const struct mxfs_recov_desc *d = recov_desc_of(rec);

			if (d && (d->flags & MXFS_RECOV_F_QUARANTINED)) {
				n_guard++;
				if (first_guard < 0) {
					first_guard = (int)slot;
					first_guard_node = rec->node_id;
				}
			} else if (d) {
				n_recovering++;
			} else {
				n_sweepguard++;
			}
			break;
		}
		case MXFS_DISKLOCK_FLAG_WITHDRAWN:
		case MXFS_DISKLOCK_FLAG_RETIRE_PENDING:     /* */
			n_withdrawn++;
			break;
		default:
			n_other++;
			break;
		}
	}
	mxfs_pal_free(rec);

	mxfs_pal_log(MXFS_LOG_ERR,
		     "P300-CLAIM-EXHAUSTED no free heartbeat slot in 0..%u — "
		     "this volume has %u log slices, and a slot beyond them would "
		     "have no journal.  Table: %u live member(s), %u quarantined "
		     "recovery verdict(s), %u withdrawn slice(s) awaiting replay, "
		     "%u recovery lease(s) in progress, %u bucket-sweep guard(s), "
		     "%u other, %u unreadable (plus %u bucket-sweep guard(s) above "
		     "the slice count, which are normal).",
		     slot_max - 1, slot_max, n_active, n_guard, n_withdrawn,
		     n_recovering, n_sweepguard, n_other, n_unread,
		     n_bucketguard_hi);
	if (n_outofrange)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "P300-CLAIM-OUTOFRANGE %u occupied slot(s) at or "
			     "above %u — a FORMAT/PROTOCOL VIOLATION: this volume has "
			     "no journal slice for them.  They are not members and were "
			     "not counted as admissible.",
			     n_outofrange, slot_max);

	if (n_guard)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "P300-CLAIM-QUARANTINE %u slot(s) hold a TERMINAL "
			     "REFUSAL VERDICT awaiting operator repair (first: slot %d, "
			     "victim node %u).  Those slices are unreplayable, so this "
			     "volume's usable member count is %u, not %u.  Do NOT "
			     "reformat: mkfs_mxfs -f destroys the verdict, and at 32 "
			     "slices there is no larger format (mkfs_mxfs refuses "
			     "-n > 32).  Read the verdict at "
			     "/sys/kernel/debug/mxfs/<dev>/recovery_blocked on a mounted "
			     "node, or offline with: chk_mxfs --show-quarantine <dev>",
			     n_guard, first_guard, (unsigned)first_guard_node,
			     slot_max - n_guard, slot_max);
	else if (n_withdrawn || n_recovering || n_sweepguard)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "P300-CLAIM-WITHDRAWN %u slot(s) hold a dirty WITHDRAWN "
			     "slice awaiting fence+replay, %u hold a recovery lease in "
			     "progress, %u hold a transient bucket-sweep guard.  A LIVE "
			     "PEER resolves them (it PREEMPT AND ABORTs the departed "
			     "incarnation's retained PR key, then replays): retry the "
			     "mount from a mounted peer's cluster rather than "
			     "reformatting.  With NO other node mounted this state is "
			     "NOT transient: a same-host successor cannot fence its "
			     "predecessor; if no other initiator can write this LUN, "
			     "set single_node_exclusive=1 and retry (fence kind 17), "
			     "otherwise mount a second node first.  See D-379/D-0355.",
			     n_withdrawn, n_recovering, n_sweepguard);
	else
		mxfs_pal_log(MXFS_LOG_ERR,
			     "P300-CLAIM-FULL every slice is held by a live "
			     "member.  The cluster is genuinely at capacity; admitting "
			     "more nodes needs a volume formatted with more slices "
			     "(mkfs_mxfs -n, max 32).");
}

/*
 * Verified non-CAW slot claim — fallback for targets that REJECT the SCSI
 * COMPARE AND WRITE used by the primary claim (this SCST LUN answers opcode
 * 0x89 with ILLEGAL REQUEST / INVALID FIELD IN CDB, sense 0x5/0x24, so the
 * CAW claim returns -EIO and every node would otherwise default to slot 0 ->
 * one shared preferred AG -> concurrent same-AG inode alloc/free corrupts the
 * inobt -> FS shutdown).
 *
 * Unlike the racy earlier plain-write claim (read-scan + blind FUA write,
 * no confirmation — two parallel mounts both took the same slot), this path
 * FUA-WRITES then FUA-READS-BACK and only accepts the slot if our own
 * node_id AND our unique timestamp survived.  A racing claimer that wrote the
 * same slot later wins the read-back; the earlier writer's read-back
 * mismatches and it advances to the next free slot.  The harness also mounts
 * nodes sequentially, so the common path is uncontended.
 */
static int mxfs_disklock_claim_slot_noncaw(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *hb;
	struct mxfs_disklock_heartbeat *rec;
	uint32_t slot;
	uint32_t slot_max = hb_claim_slot_bound(ctx);
	int attempt;
	int rc = -ENOSPC;

	hb = mxfs_pal_alloc(sizeof(*hb));
	rec = mxfs_pal_alloc(sizeof(*rec));
	if (!hb || !rec) {
		mxfs_pal_free(hb);
		mxfs_pal_free(rec);
		return -ENOMEM;
	}

	mxfs_pal_mutex_lock(ctx->lock);

	for (attempt = 0; attempt < MXFS_DISKLOCK_CLAIM_RETRIES; attempt++) {
		int found_slot = -1;
		bool fresh_claim = false;   /* pass-2 = adopted slice */

		/* Pass 1: re-claim our own prior-mount slot (FUA reads). */
		for (slot = 0; slot < slot_max; slot++) {
			uint64_t off = ctx->base_offset +
				       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
			rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
			if (rc < 0)
				continue;
			if (rec->magic == MXFS_DISKLOCK_MAGIC &&
			    rec->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
			    rec->node_id == ctx->local_node &&
			    !hb_gen_foreign(ctx, rec)) {
				found_slot = (int)slot;
				break;
			}
		}

		/* Pass 2: first free / foreign-generation slot (FUA reads). */
		if (found_slot < 0) {
			fresh_claim = true;
			for (slot = 0; slot < slot_max; slot++) {
				uint64_t off = ctx->base_offset +
					       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
				rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
				if (rc < 0)
					continue;
				/* never claim a guarded slot (see CAW pass 2). */
				if (rec->magic == MXFS_DISKLOCK_MAGIC &&
				    !hb_gen_foreign(ctx, rec) &&
				    rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
					continue;
				/* never claim an own-generation WITHDRAWN slot
				 * either.  A WITHDRAWN record is a dirty journal slice whose
				 * owner declared voluntary death — the slice awaits
				 * fence+replay, and claiming it as fresh/ADOPTED silently
				 * discards the committed-but-undestaged transactions it
				 * protects.  The monitor's WITHDRAWN arm recovers it. */
				if (rec->magic == MXFS_DISKLOCK_MAGIC &&
				    !hb_gen_foreign(ctx, rec) &&
				    rec->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P274-CLAIM-WITHDRAWN-SKIP slot=%u node=%u — "
					    "dirty withdrawn slice awaits recovery; claiming a "
					    "different slot",
					    slot, rec->node_id);
					continue;
				}
				/* a RETIRE_PENDING release is consumable only once
				 * its PR key is proven absent — the monitor settles it. */
				if (hb_retire_pending(ctx, rec)) {
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P274-CLAIM-RETIRE-PENDING-SKIP slot=%u node=%u "
					    "— released slot awaits PR-key retirement proof; "
					    "claiming a different slot",
					    slot, rec->node_id);
					continue;
				}
				if (rec->magic != MXFS_DISKLOCK_MAGIC ||
				    rec->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
				    hb_gen_foreign(ctx, rec)) {
					found_slot = (int)slot;
					break;
				}
			}
		}

		if (found_slot < 0) {
			rc = -ENOSPC;
			break;
		}

		/* Write our record with a unique timestamp, then verify. */
		hb_prov_derive(ctx, rec, fresh_claim);          /* #92 */
		memset(hb, 0, sizeof(*hb));
		hb->magic = MXFS_DISKLOCK_MAGIC;
		hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
		hb->node_id = ctx->local_node;
		hb->fs_gen = ctx->fs_gen;
		hb->timestamp_ms = mxfs_pal_time_ms();
		hb->epoch = ctx->epoch;
		ctx->claim_fresh = fresh_claim; /* before the first record */
		hb_feature_fill(ctx, hb);       /* C7 */
		hb->prov = ctx->own_prov;       /* #92 */
		hb_ident_fill(ctx, hb, (uint32_t)found_slot);   /* */

		{
			uint64_t off = ctx->base_offset +
				       (uint64_t)found_slot * MXFS_DISKLOCK_RECORD_SIZE;
			rc = write_sector_fua(ctx, off, hb);
			if (rc < 0)
				continue;            /* write error — rescan & retry */

			/* Settle, then FUA read-back confirm.  node_id + timestamp must
			 * both match (a racing peer that overwrote us later changes both). */
			mxfs_pal_sleep_ms(30);
			rc = mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
			if (rc == 0 &&
			    rec->magic == MXFS_DISKLOCK_MAGIC &&
			    rec->node_id == ctx->local_node &&
			    rec->timestamp_ms == hb->timestamp_ms) {
				ctx->local_slot = found_slot;
				ctx->slice_adopted = fresh_claim;
				/* read-back-verified image is the CAS compare source.
				 * Use `rec` (what the platter actually holds), not `hb`. */
				ctx->hb_img = *rec;
				ctx->hb_img_valid = true;
				mxfs_pal_mutex_unlock(ctx->lock);
				mxfs_pal_free(hb);
				mxfs_pal_free(rec);
				mxfs_pal_log(MXFS_LOG_WARN,
					     "disklock: claimed heartbeat slot %d for node %u "
					     "(non-CAW verified, attempt %d, %s)",
					     found_slot, ctx->local_node, attempt,
					     fresh_claim ? "fresh claim — slice ADOPTED" :
							   "own-stamp reclaim");
				return found_slot;
			}
			/* Lost the race for this slot — rescan (it now reads as a peer's). */
		}
	}

	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_free(hb);
	mxfs_pal_free(rec);
	mxfs_pal_log(MXFS_LOG_ERR,
		     "disklock: non-CAW claim failed: %d", rc);
	/* item 1: the same honest table classification on this path. */
	if (rc == -ENOSPC)
		hb_report_claim_exhausted(ctx, slot_max);
	return rc < 0 ? rc : -ENOSPC;
}

/*
 * (D-0523): the claim WAIT.  See MXFS_DISKLOCK_CLAIM_WAIT_MS in
 * disklock.h for the ruling and the measured budget.
 *
 * Called with ctx->lock held after a full pass-2 scan found no claimable
 * slot.  Re-reads and classifies the whole table (an exact re-read after
 * every sleep — never a decision carried across a sleep), then:
 *   permanent           -> today's P300-CLAIM-* diagnostics, -ENOSPC
 *                          (QUARANTINED verdict, out-of-range member,
 *                          unreadable/other record, genuinely full, the
 *                          operator's single_node_exclusive assertion);
 *   no live OTHER member -> before the wait began: today's -ENOSPC (a
 *                          same-host successor cannot fence; P300-CLAIM-
 *                          WITHDRAWN says so); during the wait: every peer
 *                          fell silent — P300-CLAIM-WAIT-PEERS-LOST,
 *                          -ERESTART (v5_mount re-runs the whole-cluster
 *                          bootstrap in this mount, bounded by
 *                          MXFS_V5_CLAIM_BOOTSTRAP_RESTARTS; a second loss
 *                          fails the mount truthfully);
 *   waitable            -> start the ONE absolute deadline on the first
 *                          call, sleep one scan interval with the lock
 *                          dropped, return 0 = rescan (the caller's pass 1 /
 *                          pass 2 run again and claim by exact-image CAW);
 *   deadline            -> P300-CLAIM-WAIT-GAVE-UP, -ETIMEDOUT (transient —
 *                          never -ENOSPC, which reads as permanent).
 * Liveness is CHANGE: an ACTIVE peer counts as live while its stamp moved
 * within the monitor's dead window (dead_threshold x HB interval); on the
 * first scan every ACTIVE record is provisionally live and must re-stamp
 * within that window.  A sweep guard that stops re-stamping is reported
 * once (P300-CLAIM-WAIT-FROZEN-GUARD) and left to the live sweeper's
 * guard_slot reclaim — never reclassified here.  WITHDRAWN and
 * RETIRE_PENDING records stay byte-identical while a peer works on them, so
 * their progress is only the deadline (ruling: no change-as-progress for
 * them).  The wait consumes none of the MXFS_DISKLOCK_CLAIM_RETRIES, which
 * remain for CAW races on a FOUND slot.
 */
struct hb_claim_wait {
	bool     active;
	uint64_t start_ms;
	uint64_t deadline_ms;
	uint32_t laps;
	uint64_t stamp[MXFS_DISKLOCK_HB_SLOTS];
	uint64_t changed_ms[MXFS_DISKLOCK_HB_SLOTS];
	uint8_t  frozen_reported[MXFS_DISKLOCK_HB_SLOTS];
};

static int hb_claim_wait(struct mxfs_disklock_ctx *ctx, uint32_t slot_max,
			 struct hb_claim_wait *w)
{
	struct mxfs_disklock_heartbeat *rec;
	uint32_t slot;
	uint32_t n_active = 0, n_live = 0, n_guard = 0, n_withdrawn = 0;
	uint32_t n_retire = 0, n_recovering = 0, n_sweep = 0, n_other = 0;
	uint32_t n_unread = 0, n_outofrange = 0, waitable;
	uint64_t now = mxfs_pal_time_ms();
	uint64_t dead_ms = (uint64_t)ctx->dead_threshold *
			   MXFS_DISKLOCK_HB_INTERVAL_MS;
	bool first = !w->active;

	rec = mxfs_pal_alloc(sizeof(*rec));
	if (!rec)
		return -ENOMEM;
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		bool occupied;

		if (mxfs_pal_bdev_read(ctx->dev, off, rec, sizeof(*rec)) < 0) {
			if (slot < slot_max)
				n_unread++;
			continue;
		}
		occupied = (rec->magic == MXFS_DISKLOCK_MAGIC) &&
			   !hb_gen_foreign(ctx, rec);
		if (slot >= slot_max) {
			/* only the sweep's transient guard is legitimate up here */
			if (occupied && rec->flags != 0 &&
			    !(rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
			      !recov_desc_present(rec)))
				n_outofrange++;
			continue;
		}
		if (!occupied)
			continue;
		switch (rec->flags) {
		case MXFS_DISKLOCK_FLAG_ACTIVE:
			n_active++;
			if (rec->node_id == ctx->local_node)
				break;          /* ours would have been reclaimed by pass 1 */
			if (first || w->stamp[slot] != rec->timestamp_ms) {
				w->stamp[slot] = rec->timestamp_ms;
				w->changed_ms[slot] = now;
			}
			if (now - w->changed_ms[slot] <= dead_ms)
				n_live++;
			break;
		case MXFS_DISKLOCK_FLAG_RECOVERY_GUARD: {
			const struct mxfs_recov_desc *d = recov_desc_of(rec);

			if (d && (d->flags & MXFS_RECOV_F_QUARANTINED)) {
				n_guard++;
			} else if (d) {
				n_recovering++;
			} else {
				n_sweep++;
				if (first || w->stamp[slot] != rec->timestamp_ms) {
					w->stamp[slot] = rec->timestamp_ms;
					w->changed_ms[slot] = now;
				} else if (now - w->changed_ms[slot] >
					   3 * MXFS_DISKLOCK_GUARD_REFRESH_MS &&
					   !w->frozen_reported[slot]) {
					w->frozen_reported[slot] = 1;
					mxfs_pal_log(MXFS_LOG_DEBUG,
						     "disklock: P300-CLAIM-WAIT-FROZEN-GUARD "
						     "slot=%u holder=%u age_ms=%llu — the "
						     "bucket-sweep guard stopped re-stamping; "
						     "a live sweeper reclaims it (hb_guard_"
						     "abandoned); still waiting on the deadline",
						     slot, rec->node_id,
						     (unsigned long long)(now - w->changed_ms[slot]));
				}
			}
			break;
		}
		case MXFS_DISKLOCK_FLAG_WITHDRAWN:
			n_withdrawn++;
			break;
		case MXFS_DISKLOCK_FLAG_RETIRE_PENDING:
			n_retire++;
			break;
		default:
			n_other++;
			break;
		}
	}
	mxfs_pal_free(rec);

	waitable = n_sweep + n_recovering + n_withdrawn + n_retire;
	if (n_guard || n_outofrange || n_other || n_unread || !waitable ||
	    ctx->snlocal) {
		if (w->active)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "disklock: P300-CLAIM-WAIT-PERMANENT after %llu ms "
				     "(laps=%u): quarantined=%u outofrange=%u other=%u "
				     "unreadable=%u waitable=%u snlocal=%d — the table "
				     "became permanently unclaimable while waiting",
				     (unsigned long long)(now - w->start_ms), w->laps,
				     n_guard, n_outofrange, n_other, n_unread, waitable,
				     ctx->snlocal ? 1 : 0);
		hb_report_claim_exhausted(ctx, slot_max);
		return -ENOSPC;
	}
	if (!n_live) {
		if (first) {
			hb_report_claim_exhausted(ctx, slot_max);
			return -ENOSPC;
		}
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P300-CLAIM-WAIT-PEERS-LOST after %llu ms "
			     "(laps=%u): %u ACTIVE record(s), none re-stamped within "
			     "the %llu ms dead window — no live peer can resolve the "
			     "%u transient record(s); the mount re-runs the "
			     "whole-cluster bootstrap (P300-CLAIM-WAIT-RESTART-BOOTSTRAP)",
			     (unsigned long long)(now - w->start_ms), w->laps,
			     n_active, (unsigned long long)dead_ms, waitable);
		return -ERESTART;
	}
	if (first) {
		w->active = true;
		w->start_ms = now;
		w->deadline_ms = now + MXFS_DISKLOCK_CLAIM_WAIT_MS;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P300-CLAIM-WAIT-START no free heartbeat slot "
			     "in 0..%u: %u live member(s), %u bucket-sweep guard(s), "
			     "%u recovery lease(s), %u withdrawn slice(s), %u "
			     "retire-pending record(s) — all transient and resolved "
			     "by a live peer; waiting up to %u ms (scan every %u ms) "
			     "instead of failing -28 (D-0523)",
			     slot_max - 1, n_active, n_sweep, n_recovering,
			     n_withdrawn, n_retire, MXFS_DISKLOCK_CLAIM_WAIT_MS,
			     MXFS_DISKLOCK_CLAIM_SCAN_MS);
	} else if (now >= w->deadline_ms) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P300-CLAIM-WAIT-GAVE-UP after %llu ms "
			     "(laps=%u): still %u live member(s), %u sweep guard(s), "
			     "%u lease(s), %u withdrawn, %u retire-pending — the "
			     "transient occupants outlived the measured budget "
			     "(%u ms); failing this mount attempt -110 (transient: "
			     "retry the mount; the peers' recovery is stalled — see "
			     "their P163/P236/P305 lines)",
			     (unsigned long long)(now - w->start_ms), w->laps,
			     n_active, n_sweep, n_recovering, n_withdrawn, n_retire,
			     MXFS_DISKLOCK_CLAIM_WAIT_MS);
		return -ETIMEDOUT;
	} else if ((w->laps % 5) == 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P300-CLAIM-WAIT-SCAN %llu ms (laps=%u): live=%u "
			     "sweep=%u lease=%u withdrawn=%u retire_pending=%u",
			     (unsigned long long)(now - w->start_ms), w->laps,
			     n_live, n_sweep, n_recovering, n_withdrawn, n_retire);
	}
	w->laps++;
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_sleep_ms_interruptible(MXFS_DISKLOCK_CLAIM_SCAN_MS);
	mxfs_pal_mutex_lock(ctx->lock);
	return 0;
}

int mxfs_disklock_claim_slot(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *hb;
	struct mxfs_disklock_heartbeat *expected;
	struct hb_claim_wait *cw;
	uint32_t slot;
	uint32_t slot_max;
	int attempt;
	int rc = -ENOSPC;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	slot_max = hb_claim_slot_bound(ctx);

	/*
	 * A claim establishes a NEW published tenancy, so it draws a NEW
	 * incarnation: losing a slot TERMINATES an incarnation, and that value
	 * may never establish a later tenancy.  Drawing here also covers the
	 * non-CAW fallback — claim_slot_noncaw() is only reachable from this
	 * function.
	 *
	 * This deliberately does NOT enter the pass-1 own-stamp match below.
	 * That match is by node_id ONLY, and must stay that way: it is what lets
	 * a rebooted node re-claim its own slot with slice_adopted=false, i.e.
	 * FULL replay of its PREVIOUS incarnation's log records.  Adding an epoch
	 * equality test there would push every rebooted node onto a pass-2 fresh
	 * claim, whose adopted-slice gate suppresses image replay — silently
	 * abandoning that node's own unreplayed journal slice.
	 */
	/*
	 * (§6.2, design-consult ruling Q2): a whole-cluster bootstrap owner
	 * drew its incarnation ONCE when it claimed the bootstrap record, owned
	 * fence intents and recovery descriptors under it, and must become
	 * ACTIVE under the SAME epoch — a second incarnation here would let a
	 * delayed observer see the provisional owner "die" and a stranger
	 * appear.  The pre-drawn value is consumed exactly once.
	 */
	if (inc_valid(ctx->epoch_predrawn)) {
		ctx->epoch = ctx->epoch_predrawn;
		ctx->epoch_predrawn = 0;
	} else {
		ctx->epoch = hb_draw_incarnation();
	}
	if (!inc_valid(ctx->epoch)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: no entropy for a mount incarnation — "
			     "refusing to claim a heartbeat slot (failing closed)");
		return -EIO;
	}

	hb = mxfs_pal_alloc(sizeof(*hb));
	expected = mxfs_pal_alloc(sizeof(*expected));
	cw = mxfs_pal_alloc(sizeof(*cw));
	if (!hb || !expected || !cw) {
		mxfs_pal_free(hb);
		mxfs_pal_free(expected);
		mxfs_pal_free(cw);
		return -ENOMEM;
	}
	memset(cw, 0, sizeof(*cw));

	mxfs_pal_mutex_lock(ctx->lock);

	/* (D-0523): `attempt` counts CAW races on a FOUND slot only;
	 * a wait lap rescans without consuming one. */
	for (attempt = 0; attempt < MXFS_DISKLOCK_CLAIM_RETRIES; ) {
		int found_slot = -1;
		bool fresh_claim = false;   /* pass-2 = adopted slice */

		/* First pass: look for our own node_id (re-claim from previous
		 * mount).  Keep the read image — it is the CAW compare buffer. */
		for (slot = 0; slot < slot_max; slot++) {
			uint64_t off = ctx->base_offset +
				       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
			rc = mxfs_pal_bdev_read(ctx->dev, off, expected,
						sizeof(*expected));
			if (rc < 0)
				continue;
			if (expected->magic == MXFS_DISKLOCK_MAGIC &&
			    expected->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
			    expected->node_id == ctx->local_node &&
			    !hb_gen_foreign(ctx, expected)) {
				found_slot = (int)slot;
				break;
			}
		}

		/* Second pass: find first empty slot */
		if (found_slot < 0) {
			fresh_claim = true;
			for (slot = 0; slot < slot_max; slot++) {
				uint64_t off = ctx->base_offset +
					       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
				rc = mxfs_pal_bdev_read(ctx->dev, off, expected,
							sizeof(*expected));
				if (rc < 0)
					continue;
				/* NEVER claim a slot carrying a recovery GUARD.
				 * The claim path must not judge guard freshness — the only
				 * sound test needs a timed re-read (see hb_guard_abandoned)
				 * and this path is latency-critical at mount.  Skipping is
				 * always safe: 64 slots, and an ABANDONED guard is reclaimed
				 * by the next live sweeper's guard_slot, so a dead holder
				 * cannot strand the slot permanently. */
				if (expected->magic == MXFS_DISKLOCK_MAGIC &&
				    !hb_gen_foreign(ctx, expected) &&
				    expected->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
					continue;
				/* same rule for WITHDRAWN — the record marks a
				 * dirty journal slice awaiting fence+replay.  Consuming it
				 * here as a fresh claim (slice_adopted) discards the
				 * committed transactions in that slice; skip and let the
				 * monitor's WITHDRAWN arm drive recovery. */
				if (expected->magic == MXFS_DISKLOCK_MAGIC &&
				    !hb_gen_foreign(ctx, expected) &&
				    expected->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P274-CLAIM-WITHDRAWN-SKIP slot=%u node=%u — "
					    "dirty withdrawn slice awaits recovery; claiming a "
					    "different slot",
					    slot, expected->node_id);
					continue;
				}
				/* same rule for RETIRE_PENDING — the key that
				 * authorises the previous occupant may still be registered;
				 * the monitor settles the record after READ KEYS. */
				if (hb_retire_pending(ctx, expected)) {
					mxfs_pal_log(MXFS_LOG_DEBUG,
					    "mxfs: P274-CLAIM-RETIRE-PENDING-SKIP slot=%u node=%u "
					    "— released slot awaits PR-key retirement proof; "
					    "claiming a different slot",
					    slot, expected->node_id);
					continue;
				}
				if (expected->magic != MXFS_DISKLOCK_MAGIC ||
				    expected->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
				    hb_gen_foreign(ctx, expected)) {
					/* foreign-generation (pre-mkfs ghost) records
					 * are claimable — the CAW below overwrites them. */
					found_slot = (int)slot;
					break;
				}
			}
		}

		if (found_slot < 0) {
			/* (D-0523): wait for transient occupants (one
			 * absolute deadline), or fail with the truthful reason. */
			rc = hb_claim_wait(ctx, slot_max, cw);
			if (rc == 0)
				continue;
			mxfs_pal_mutex_unlock(ctx->lock);
			mxfs_pal_free(hb);
			mxfs_pal_free(expected);
			mxfs_pal_free(cw);
			return rc;
		}

		/* Atomically claim: CAW from the observed image to our record. */
		hb_prov_derive(ctx, expected, fresh_claim);     /* #92 */
		memset(hb, 0, sizeof(*hb));
		hb->magic = MXFS_DISKLOCK_MAGIC;
		hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
		hb->node_id = ctx->local_node;
		hb->fs_gen = ctx->fs_gen;
		hb->timestamp_ms = mxfs_pal_time_ms();
		hb->epoch = ctx->epoch;
		ctx->claim_fresh = fresh_claim; /* before the first record */
		hb_feature_fill(ctx, hb);       /* C7 */
		hb->prov = ctx->own_prov;       /* #92 */
		hb_ident_fill(ctx, hb, (uint32_t)found_slot);   /* */

		{
			uint64_t off = ctx->base_offset +
				       (uint64_t)found_slot * MXFS_DISKLOCK_RECORD_SIZE;
			rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expected, hb);
		}

		if (rc == 0) {
			ctx->local_slot = found_slot;
			ctx->slice_adopted = fresh_claim;
			ctx->claim_via_caw = true;      /* D-0359 */
			/* the CAW just made `hb` the exact on-disk image — it is
			 * the compare source for every later own-slot write. */
			ctx->hb_img = *hb;
			ctx->hb_img_valid = true;
			mxfs_pal_mutex_unlock(ctx->lock);
			mxfs_pal_free(hb);
			mxfs_pal_free(expected);
			if (cw->active)
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "disklock: P300-CLAIM-WAIT-DONE slot=%d after "
					     "%llu ms (laps=%u) — the transient occupant "
					     "cleared and the claim landed (D-0523)",
					     found_slot,
					     (unsigned long long)(mxfs_pal_time_ms() -
								  cw->start_ms),
							 cw->laps);
			mxfs_pal_free(cw);
			mxfs_pal_log(MXFS_LOG_WARN,
				     "disklock: claimed heartbeat slot %d for node %u "
				     "(attempt %d, %s)",
				     found_slot, ctx->local_node, attempt,
				     fresh_claim ? "fresh claim — slice ADOPTED" :
						   "own-stamp reclaim");
			return found_slot;
		}

		if (rc == -EAGAIN) {
			/* A peer claimed this slot between our read and our CAW —
			 * the exact race that used to hand two nodes the same
			 * node_slot.  Rescan; the peer's record is now visible. */
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "disklock: P130-CLAIM-RACE slot %d (node %u, "
				     "attempt %d) — rescanning",
				     found_slot, ctx->local_node, attempt);
			attempt++;
			continue;
		}

		break;  /* hard I/O error or -EOPNOTSUPP */
	}

	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_free(hb);
	mxfs_pal_free(expected);
	mxfs_pal_free(cw);

	/* CAW claim unavailable on this target — fall back to the verified
	 * non-CAW claim so we still get a UNIQUE slot (never default to 0). */
	{
		int ncrc = mxfs_disklock_claim_slot_noncaw(ctx);
		if (ncrc >= 0)
			return ncrc;
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: claim_slot failed (CAW rc=%d, non-CAW rc=%d)",
			     rc, ncrc);
		return ncrc < 0 ? ncrc : (rc < 0 ? rc : -ENOSPC);
	}
}

int mxfs_disklock_get_slot(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return -1;
	return ctx->local_slot;
}

const char *mxfs_caw_cap_name(enum mxfs_caw_cap cap)
{
	switch (cap) {
	case MXFS_CAW_CAP_OK:          return "OK";
	case MXFS_CAW_CAP_UNSUPPORTED: return "UNSUPPORTED";
	case MXFS_CAW_CAP_TRANSIENT:   return "TRANSIENT";
	case MXFS_CAW_CAP_VIOLATION:   return "VIOLATION";
	}
	return "?";
}

/*
 * (D-0359 step 1).  See disklock.h.  The negative probe CAWs our own
 * heartbeat slot with a compare image that differs from the on-disk record
 * in one field and a write image IDENTICAL to the on-disk record: a correct
 * target answers MISCOMPARE (-EAGAIN) and writes nothing; a target that
 * reports success installed nothing new either (write == disk), so even the
 * violation case cannot damage the record — but it proves the compare is
 * not enforced, which is disqualifying for a lock table.  The read-back
 * afterwards is the second witness: the record must be byte-identical to
 * the image the claim left.
 */
enum mxfs_caw_cap mxfs_disklock_caw_capability(struct mxfs_disklock_ctx *ctx,
					       int *rc_out)
{
	struct mxfs_disklock_heartbeat *wrong, *back;
	uint64_t off;
	int rc, rrc;
	enum mxfs_caw_cap cap;

	if (rc_out)
		*rc_out = 0;
	if (!ctx || ctx->local_slot < 0 || !ctx->hb_img_valid)
		return MXFS_CAW_CAP_TRANSIENT;
	if (!ctx->claim_via_caw) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P311-CAW-CAP slot=%d UNSUPPORTED — the slot "
			     "claim needed the verified non-CAW fallback: this "
			     "device does not execute COMPARE AND WRITE",
			     ctx->local_slot);
		return MXFS_CAW_CAP_UNSUPPORTED;
	}

	wrong = mxfs_pal_alloc(sizeof(*wrong));
	back = mxfs_pal_alloc(sizeof(*back));
	if (!wrong || !back) {
		mxfs_pal_free(wrong);
		mxfs_pal_free(back);
		return MXFS_CAW_CAP_TRANSIENT;
	}

	mxfs_pal_mutex_lock(ctx->lock);
	off = ctx->base_offset +
	      (uint64_t)ctx->local_slot * MXFS_DISKLOCK_RECORD_SIZE;
	*wrong = ctx->hb_img;
	wrong->timestamp_ms ^= 0x5A5A5A5AULL;   /* compare image differs */
	rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, wrong, &ctx->hb_img);
	rrc = mxfs_pal_bdev_read_prio(ctx->dev, off, back, sizeof(*back));

	if (rc == -EOPNOTSUPP)
		cap = MXFS_CAW_CAP_UNSUPPORTED;
	else if (rc == 0)
		cap = MXFS_CAW_CAP_VIOLATION;       /* mismatch reported success */
	else if (rc == -EAGAIN)
		cap = MXFS_CAW_CAP_OK;
	else
		cap = MXFS_CAW_CAP_TRANSIENT;
	if (cap == MXFS_CAW_CAP_OK) {
		if (rrc < 0)
			cap = MXFS_CAW_CAP_TRANSIENT;
		else if (memcmp(back, &ctx->hb_img, sizeof(*back)) != 0)
			cap = MXFS_CAW_CAP_VIOLATION;   /* miscompare changed the record */
	}
	mxfs_pal_mutex_unlock(ctx->lock);

	mxfs_pal_log(cap == MXFS_CAW_CAP_OK ? MXFS_LOG_WARN : MXFS_LOG_ERR,
		     "disklock: P311-CAW-CAP slot=%d %s — negative probe rc=%d "
		     "(expect -11 MISCOMPARE) readback rc=%d identical=%d "
		     "(claim landed via CAW)",
		     ctx->local_slot, mxfs_caw_cap_name(cap), rc, rrc,
		     rrc < 0 ? -1 :
		     (memcmp(back, &ctx->hb_img, sizeof(*back)) == 0));
	if (rc_out)
		*rc_out = rc;
	mxfs_pal_free(wrong);
	mxfs_pal_free(back);
	return cap;
}

/*
 * the {slot, node_id, incarnation} triple.  See disklock.h.
 *
 * Fails closed and ALL-OR-NOTHING: a partial identity is worse than none,
 * because a consumer that gets a slot but a zero incarnation cannot tell
 * "this mount" from "some earlier tenancy of the same slot", which is
 * exactly the confusion the incarnation exists to prevent.
 */
bool mxfs_disklock_mount_identity(struct mxfs_disklock_ctx *ctx,
				  uint32_t *slot, mxfs_node_id_t *node,
				  mxfs_epoch_t *epoch)
{
	int          s;
	mxfs_epoch_t e;

	if (slot)
		*slot = 0;
	if (node)
		*node = 0;
	if (epoch)
		*epoch = 0;

	if (!ctx)
		return false;

	s = ctx->local_slot;
	e = ctx->epoch;
	if (s < 0 || s >= MXFS_DISKLOCK_HB_SLOTS)
		return false;
	if (!ctx->local_node)
		return false;
	if (!inc_valid(e))
		return false;

	if (slot)
		*slot = (uint32_t)s;
	if (node)
		*node = ctx->local_node;
	if (epoch)
		*epoch = e;
	return true;
}

/* ── recovery GUARD ops (see MXFS_DISKLOCK_FLAG_RECOVERY_GUARD) ── */

/* Staleness by wall delta against the writer's stamp.  Nodes are NTP-synced;
 * an absurdly ahead-of-us stamp (> one stale window) is garbage, not fresh —
 * otherwise a skewed writer could block a slot forever. */
/*
 * Is a recovery GUARD abandoned (its holder died mid-sweep)?
 *
 * CORRECTNESS FIX — the first version of this compared
 * mxfs_pal_time_ms() against hb->timestamp_ms.  That is WRONG across nodes:
 * mxfs_pal_time_ms() is ktime_get_boottime_ns()/1e6, i.e. each node's own
 * UPTIME, so the subtraction mixes the reader's boot clock with the writer's.
 * Two nodes with different uptimes — the normal case — would compute a delta
 * of hours and judge a perfectly FRESH guard stale, which defeats the entire
 * exclusion the guard exists to provide.  (Same trap the heartbeat monitor
 * already avoids, and that tests/hb_live_count.sh documents: HB timestamps
 * are only ever comparable to THEMSELVES.)
 *
 * The only sound test with these clocks is CHANGE: a live holder re-stamps
 * its guard (mxfs_disklock_guard_refresh) as it sweeps, so re-read the record
 * after a refresh interval and see whether the timestamp moved.  Callers are
 * background paths (the unclaimed-bucket scan), so the sleep is affordable —
 * and this is never on the claim fast path, which now skips guards outright
 * rather than judging them.
 */
static bool hb_guard_abandoned(struct mxfs_disklock_ctx *ctx, int slot,
			       const struct mxfs_disklock_heartbeat *first)
{
	struct mxfs_disklock_heartbeat *again;
	uint64_t off;
	bool abandoned = false;
	int rc;

	if (first->node_id == ctx->local_node)
		return false;               /* ours */
	again = mxfs_pal_alloc(sizeof(*again));
	if (!again)
		return false;               /* cannot prove abandoned => leave it */
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_sleep_ms(MXFS_DISKLOCK_GUARD_REFRESH_MS * 3);

	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, again, sizeof(*again));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (rc == 0) {
		if (again->magic != MXFS_DISKLOCK_MAGIC ||
		    again->flags != MXFS_DISKLOCK_FLAG_RECOVERY_GUARD ||
		    hb_gen_foreign(ctx, again)) {
			abandoned = true;       /* guard released/overwritten meanwhile */
		} else if (again->node_id == first->node_id &&
			   again->timestamp_ms == first->timestamp_ms) {
			abandoned = true;       /* holder stopped re-stamping => dead */
		}
	}
	mxfs_pal_free(again);
	return abandoned;
}

int mxfs_disklock_guard_slot(struct mxfs_disklock_ctx *ctx, int slot)
{
	struct mxfs_disklock_heartbeat *cur, *g;
	uint64_t off;
	bool pend;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS ||
	    slot == ctx->local_slot)
		return -EINVAL;
	if (ctx->guard_slot >= 0)
		return -EBUSY;

	cur = mxfs_pal_alloc(sizeof(*cur));
	g = mxfs_pal_alloc(sizeof(*g));
	if (!cur || !g) {
		mxfs_pal_free(cur);
		mxfs_pal_free(g);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	pend = ctx->recovery_pending[slot];
	rc = pend ? 0 : mxfs_pal_bdev_read_prio(ctx->dev, off, cur, sizeof(*cur));
	mxfs_pal_mutex_unlock(ctx->lock);
	if (pend) {
		rc = -EBUSY;            /* recovery protocol owns the slot */
		goto out;
	}
	if (rc < 0)
		goto out;

	/*
	 * rule 4 (victim-manifest freeze): a guard carrying a RECOVERY
	 * DESCRIPTOR is a recovery lease, strictly stronger than this sweep
	 * guard.  It is never takeable — not even when abandoned, which is why
	 * this test precedes hb_guard_abandoned() rather than joining it.  An
	 * abandoned recovery is resumed via mxfs_disklock_recovery_takeover(),
	 * which preserves the victim identity and the milestone; overwriting it
	 * with a sweep guard would destroy both.
	 */
	if (recov_desc_present(cur)) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P234-GUARD-REFUSED slot=%d — slot holds a recovery "
		    "lease (victim mid-recovery); the unclaimed-bucket sweep may not "
		    "take it", slot);
		rc = -EBUSY;
		goto out;
	}

	/* Guardable: empty, foreign-gen ghost, bad magic, or a STALE guard.
	 * NOT guardable: a member (ACTIVE — live or dead-pending-detection),
	 * a WITHDRAWN corpse (death pipeline owns it), or a fresh guard. */
	if (cur->magic == MXFS_DISKLOCK_MAGIC && !hb_gen_foreign(ctx, cur) &&
	    (cur->flags == MXFS_DISKLOCK_FLAG_ACTIVE ||
	     cur->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN ||
	     (cur->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
	      !hb_guard_abandoned(ctx, slot, cur)))) {
		rc = -EBUSY;
		goto out;
	}

	memset(g, 0, sizeof(*g));
	g->magic = MXFS_DISKLOCK_MAGIC;
	g->flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD;
	g->node_id = ctx->local_node;
	g->fs_gen = ctx->fs_gen;
	g->timestamp_ms = mxfs_pal_time_ms();
	g->epoch = ctx->epoch;
	hb_feature_fill(ctx, g);
	hb_ident_fill(ctx, g, slot);    /* names the GUARD WRITER */

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_GUARD, "guard", off, cur, g);
	if (rc == -EOPNOTSUPP) {
		/* (0.60.0, D7 companion): the non-CAW write + settle +
		 * read-back stand-in is gone; a GUARD is laid only by an exact-image
		 * CAS over the victim's record.  Fail closed (no recovery starts). */
		hb_cas_nocaw_locked(ctx, (uint32_t)slot, "guard");
	}
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == 0) {
		ctx->guard_slot = slot;
		ctx->guard_img = *g;
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P99-GUARD slot=%d node=%u — recovery guard held for unclaimed-bucket sweep",
		    slot, ctx->local_node);
	}
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(g);
	return rc;
}

int mxfs_disklock_guard_refresh(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *cur, *g2;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev)
		return -EINVAL;
	if (ctx->guard_slot < 0)
		return -ESTALE;

	cur = mxfs_pal_alloc(sizeof(*cur));
	g2 = mxfs_pal_alloc(sizeof(*g2));
	if (!cur || !g2) {
		mxfs_pal_free(cur);
		mxfs_pal_free(g2);
		return -ENOMEM;         /* guard retained; transient */
	}
	off = ctx->base_offset +
	      (uint64_t)ctx->guard_slot * MXFS_DISKLOCK_RECORD_SIZE;
	*g2 = ctx->guard_img;
	g2->timestamp_ms = mxfs_pal_time_ms();
	if (g2->timestamp_ms <= ctx->guard_img.timestamp_ms)
		g2->timestamp_ms = ctx->guard_img.timestamp_ms + 1;

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_GUARD_REFRESH, "guard-refresh", off, &ctx->guard_img, g2);
	if (rc == -EOPNOTSUPP)          /* (0.60.0, D7): fail closed */
		hb_cas_nocaw_locked(ctx, (uint32_t)ctx->guard_slot, "guard-refresh");
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == 0) {
		ctx->guard_img = *g2;
	} else if (rc == -EAGAIN) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P99-GUARD-LOST slot=%d — record changed under us; sweep must abort",
		    ctx->guard_slot);
		ctx->guard_slot = -1;
		rc = -ESTALE;
	}
	/* other rc: transient IO — guard retained, caller may retry or abort */
	mxfs_pal_free(cur);
	mxfs_pal_free(g2);
	return rc;
}

void mxfs_disklock_unguard(struct mxfs_disklock_ctx *ctx)
{
	struct mxfs_disklock_heartbeat *cur, *z;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || ctx->guard_slot < 0)
		return;
	cur = mxfs_pal_alloc(sizeof(*cur));
	z = mxfs_pal_alloc(sizeof(*z));
	if (!cur || !z) {
		/* Cannot zero now: leave the guard to go stale (62s) — claimable
		 * again after; loud so it is visible. */
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P99-UNGUARD-ENOMEM slot=%d — guard left to expire",
		    ctx->guard_slot);
		ctx->guard_slot = -1;
		mxfs_pal_free(cur);
		mxfs_pal_free(z);
		return;
	}
	off = ctx->base_offset +
	      (uint64_t)ctx->guard_slot * MXFS_DISKLOCK_RECORD_SIZE;
	memset(z, 0, sizeof(*z));

	mxfs_pal_mutex_lock(ctx->lock);
	rc = hb_caw(ctx, HB_CAW_OP_GUARD_ZERO, "guard-zero", off, &ctx->guard_img, z);
	if (rc == -EOPNOTSUPP)          /* (0.60.0, D7): fail closed */
		hb_cas_nocaw_locked(ctx, (uint32_t)ctx->guard_slot, "guard-zero");
	mxfs_pal_mutex_unlock(ctx->lock);

	if (rc == -EAGAIN)
		mxfs_pal_log(MXFS_LOG_DEBUG,
		    "disklock: P99-UNGUARD-RACED slot=%d — successor overwrote a stale guard; theirs now",
		    ctx->guard_slot);
	else if (rc)
		mxfs_pal_log(MXFS_LOG_ERR,
		    "disklock: P99-UNGUARD-IOERR slot=%d rc=%d — guard left to expire",
		    ctx->guard_slot, rc);
	else
		mxfs_pal_log(MXFS_LOG_WARN,
		    "disklock: P99-UNGUARD slot=%d — recovery guard released",
		    ctx->guard_slot);
	ctx->guard_slot = -1;
	mxfs_pal_free(cur);
	mxfs_pal_free(z);
}

int mxfs_disklock_slot_unclaimed(struct mxfs_disklock_ctx *ctx, int slot)
{
	struct mxfs_disklock_heartbeat *rec;
	bool pend;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	if (slot == ctx->local_slot)
		return 0;
	rec = mxfs_pal_alloc(sizeof(*rec));
	if (!rec)
		return -ENOMEM;
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;

	mxfs_pal_mutex_lock(ctx->lock);
	pend = ctx->recovery_pending[slot];
	rc = pend ? 0 : mxfs_pal_bdev_read_prio(ctx->dev, off, rec, sizeof(*rec));
	mxfs_pal_mutex_unlock(ctx->lock);

	if (pend)
		rc = 0;                 /* recovery protocol owns it: not unclaimed */
	else if (rc < 0)
		;                       /* propagate the IO error */
	else if (rec->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, rec))
		rc = 1;                 /* empty / pre-mkfs ghost */
	else if (rec->flags == MXFS_DISKLOCK_FLAG_EMPTY)
		rc = 1;
	else if (recov_lease_covers_node(rec, rec->node_id))
		rc = 0;                 /* a RECOVERY LEASE, never unclaimed —
								 * the slice underneath is mid-recovery even
								 * if its owner stopped re-stamping */
	else if (rec->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
		 hb_guard_abandoned(ctx, slot, rec))
		rc = 1;                 /* dead guard-holder: takeover allowed */
	else
		rc = 0;                 /* ACTIVE / WITHDRAWN / fresh guard */
	mxfs_pal_free(rec);
	return rc;
}

/* true when the HB slot was won by the pass-2 fresh scan — the log
 * slice this node inherits may carry an already-recovered (or foreign)
 * incarnation's dirty records, whose images must not be re-applied at mount
 * (D-FOREIGN-REPLAY-UNGATED-IMAGES: cross-slice LSNs are incomparable). */
bool mxfs_disklock_slice_adopted(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return false;
	return ctx->slice_adopted;
}

int mxfs_disklock_get_stale_slot_mask(struct mxfs_disklock_ctx *ctx,
					uint64_t threshold_ms,
					int skip_slot,
					uint64_t *out_mask)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t snap_ts[64];
	uint32_t snap_node[64];
	bool snap_active[64];
	uint64_t mask = 0;
	uint32_t slot;
	/*
	 * Snapshot+wait+rescan strategy: timestamp_ms is from
	 * ktime_get_boottime_ns which resets on reboot, so absolute-age
	 * comparison is unsound across crashes.  Instead, snapshot all
	 * ACTIVE slots' timestamps now, wait long enough for an alive
	 * heartbeat round (default 2s × 5 = 10s), and rescan: any slot
	 * whose timestamp didn't advance is dead and its CAW bits are
	 * stuck-orphan.  threshold_ms is interpreted as the wait window.
	 */

	if (!ctx || !out_mask || !ctx->dev)
		return -EINVAL;

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;

	/* Snapshot pass.  per-slot lock (see read_all comment) — the
	 * old whole-loop hold starved the heartbeat writer for tens of seconds
	 * under device saturation; this path runs from RUNTIME acquire/join
	 * paths (v5_mount), not just mount. */
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		int rc;

		snap_active[slot] = false;
		if ((int)slot == skip_slot)
			continue;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			continue;
		if (hb->magic != MXFS_DISKLOCK_MAGIC ||
		    hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
		    hb_gen_foreign(ctx, hb))
			continue;

		snap_active[slot] = true;
		snap_ts[slot] = hb->timestamp_ms;
		snap_node[slot] = hb->node_id;
	}

	if (!threshold_ms) {
		/* No-wait path — used when caller knows all peers are dead */
		for (slot = 0; slot < 64; slot++)
			if (snap_active[slot])
				mask |= (1ULL << slot);
		mxfs_pal_free(hb);
		*out_mask = mask;
		return 0;
	}

	/*
	 * Poll for heartbeat advance with early exit, instead of one fixed
	 * sleep(threshold_ms).  A live node rewrites its heartbeat every
	 * MXFS_DISKLOCK_HB_INTERVAL_MS; we only need to observe each active
	 * slot advance ONCE to prove it alive.  A slot that never advances
	 * within the full threshold_ms window is a previous crashed instance
	 * and gets purged.  Correctness is identical to the old fixed-wait
	 * (stale is still declared only after the whole window elapses with
	 * no advance) but the common case — all snapshot-active slots are
	 * live peers — returns in ~one heartbeat interval rather than the
	 * full 10 s, which keeps joining-node mount latency low.
	 */
	{
		bool advanced[64];
		int n_active = 0;
		int n_pending;
		uint64_t waited = 0;
		const uint64_t poll_ms = 500;

		for (slot = 0; slot < 64; slot++) {
			advanced[slot] = false;
			if (snap_active[slot])
				n_active++;
		}

		/* No active slots snapshotted — nothing can be stale, no wait. */
		if (n_active == 0) {
			mxfs_pal_free(hb);
			*out_mask = 0;
			return 0;
		}
		n_pending = n_active;

		while (n_pending > 0 && waited < threshold_ms) {
			mxfs_pal_sleep_ms(poll_ms);
			waited += poll_ms;

			/* per-slot lock (see snapshot-pass comment) — this poll
			 * repeats up to threshold_ms/poll_ms times; the old whole-loop
			 * hold multiplied the heartbeat-writer starvation. */
			for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
				uint64_t off;
				int rc;

				if (!snap_active[slot] || advanced[slot])
					continue;

				off = ctx->base_offset +
				      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
				mxfs_pal_mutex_lock(ctx->lock);
				rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
				mxfs_pal_mutex_unlock(ctx->lock);
				if (rc < 0)
					continue;

				/* Alive iff still our snapshotted node AND timestamp moved. */
				if (hb->magic == MXFS_DISKLOCK_MAGIC &&
				    hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
				    hb->node_id == snap_node[slot] &&
				    hb->timestamp_ms != snap_ts[slot]) {
					advanced[slot] = true;
					n_pending--;
				}
			}
		}

		/* Anything that never advanced across the full window is stale. */
		for (slot = 0; slot < 64; slot++) {
			if (snap_active[slot] && !advanced[slot]) {
				mask |= (1ULL << slot);
				mxfs_pal_log(MXFS_LOG_INFO,
				    "disklock: slot %u stale (node=%u ts unchanged across %llu ms) — will purge",
				    slot, snap_node[slot],
				    (unsigned long long)threshold_ms);
			}
		}
	}

	mxfs_pal_free(hb);
	*out_mask = mask;
	return 0;
}

/* see disklock.h — single-pass WITHDRAWN scan for the mount
 * barrier's step-6.5 cohort.  A WITHDRAWN record is a voluntary death
 * declaration over a DIRTY slice; the old barrier snapshotted ACTIVE
 * slots only, so these slices were recovered ASYNC by the monitor while
 * the mount completed and took locks over unreplayed resources. */
int mxfs_disklock_get_withdrawn_slots(struct mxfs_disklock_ctx *ctx,
				       int skip_slot,
				       uint64_t *out_mask,
				       mxfs_node_id_t *out_node,
				       mxfs_epoch_t *out_epoch)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t mask = 0;
	uint32_t slot;

	if (!ctx || !out_mask || !ctx->dev)
		return -EINVAL;
	*out_mask = 0;

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		int rc;

		if ((int)slot == skip_slot)
			continue;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			continue;
		if (hb->magic != MXFS_DISKLOCK_MAGIC ||
		    hb->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN ||
		    hb_gen_foreign(ctx, hb))
			continue;

		mask |= (1ULL << slot);
		if (out_node)
			out_node[slot] = hb->node_id;
		if (out_epoch)
			out_epoch[slot] = hb->epoch;
	}

	mxfs_pal_free(hb);
	*out_mask = mask;
	return 0;
}

/* see disklock.h.  The admission barrier's requires-recovery
 * sweep.  Unlike get_withdrawn_slots this also reports slots the fence
 * pipeline has already converted to a recovery descriptor — the
 * measured root was exactly that conversion racing the mount's
 * WITHDRAWN-only scan (monitor consumed the stamp during DLM init, the
 * step-6.5 scan found nothing, and the barrier went live over an
 * unreplayed slice). */
int mxfs_disklock_get_recovery_pending_slots(struct mxfs_disklock_ctx *ctx,
					     int skip_slot,
					     uint64_t *out_mask,
					     mxfs_node_id_t *out_node,
					     mxfs_epoch_t *out_epoch,
					     uint64_t *out_retire_mask)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t mask = 0;
	uint32_t slot;

	if (!ctx || !out_mask || !ctx->dev)
		return -EINVAL;
	*out_mask = 0;
	if (out_retire_mask)
		*out_retire_mask = 0;

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		const struct mxfs_recov_desc *d;
		int rc;

		if ((int)slot == skip_slot)
			continue;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0) {
			/* Unread slot: may hold anything — same fail-closed rule as
			 * the (b2) residue gate. */
			mask |= (1ULL << slot);
			continue;
		}
		if (hb->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, hb))
			continue;               /* consumable / pre-mkfs ghost */

		if (hb->flags == MXFS_DISKLOCK_FLAG_WITHDRAWN) {
			mask |= (1ULL << slot);
			if (out_node)
				out_node[slot] = hb->node_id;
			if (out_epoch)
				out_epoch[slot] = hb->epoch;
			continue;
		}
		/*
		 * (design-consult STOP-SHIP blocker 2): a RETIRE_PENDING stamp is
		 * requires-recovery evidence too.  Sequence it guards: a node
		 * writes RETIRE_PENDING, crashes (or its unregister fails) before
		 * its key is gone; a new node mounts on another slot; the old
		 * registration is still write-capable.  Admission must hold until
		 * the record is settled EMPTY under PR proof or converted to
		 * WITHDRAWN and fenced/replayed/purged — the caller settles it via
		 * mxfs_disklock_retire_settle_slot(immediate).
		 */
		if (hb->flags == MXFS_DISKLOCK_FLAG_RETIRE_PENDING) {
			mask |= (1ULL << slot);
			if (out_retire_mask)
				*out_retire_mask |= (1ULL << slot);
			if (out_node)
				out_node[slot] = hb->node_id;
			if (out_epoch)
				out_epoch[slot] = hb->epoch;
			continue;
		}
		if (!recov_desc_present(hb))
			continue;               /* ACTIVE / EMPTY shapes */
		d = recov_desc_of(hb);
		if (!d) {
			/* The sector IS a recovery lease but this build cannot
			 * validate it: the slice underneath is mid-recovery under
			 * evidence we cannot interpret.  Frozen — pending. */
			mask |= (1ULL << slot);
			continue;
		}
		if (d->stage >= MXFS_RECOV_STAGE_GRANTS_RELEASED)
			continue;               /* complete, awaiting slot zeroing */
		mask |= (1ULL << slot);
		if (out_node)
			out_node[slot] = d->victim_node;
		if (out_epoch)
			out_epoch[slot] = d->victim_epoch;
	}

	mxfs_pal_free(hb);
	*out_mask = mask;
	return 0;
}

/* Contract in disklock.h.  Deliberately NOT the admission sweep above with a
 * kind filter: that one skips the caller's own slot and folds WITHDRAWN and
 * RETIRE_PENDING shapes in, which are scheduling concerns.  This answers one
 * question only — which certified gate-kind recoveries are not finished. */
int mxfs_disklock_gate_owed_sweep(struct mxfs_disklock_ctx *ctx,
				  uint64_t *out_owed,
				  uint64_t *out_unreadable,
				  uint64_t *out_malformed,
				  uint64_t *out_terminal,
				  uint64_t *out_terminal_key)
{
	struct mxfs_disklock_heartbeat *hb;
	uint64_t owed = 0, unreadable = 0, malformed = 0, terminal = 0;
	uint32_t slot;
	int examined = 0;

	if (out_owed)
		*out_owed = 0;
	if (out_unreadable)
		*out_unreadable = 0;
	if (out_malformed)
		*out_malformed = 0;
	if (out_terminal)
		*out_terminal = 0;
	if (out_terminal_key)
		memset(out_terminal_key, 0,
		       sizeof(*out_terminal_key) * MXFS_DISKLOCK_HB_SLOTS);
	if (!ctx || !ctx->dev || !out_owed || !out_unreadable)
		return -EINVAL;

	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;

	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS && slot < 64; slot++) {
		uint64_t off = ctx->base_offset +
			       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		const struct mxfs_recov_desc *d;
		int rc;

		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0) {
			unreadable |= (1ULL << slot);
			continue;
		}
		examined++;
		if (hb->magic != MXFS_DISKLOCK_MAGIC || hb_gen_foreign(ctx, hb))
			continue;
		if (!recov_desc_present(hb))
			continue;
		d = recov_desc_of(hb);
		if (!d) {
			/* A recovery lease this build cannot validate: the slice under
			 * it may be mid-recovery under the gate.  Cannot tell. */
			unreadable |= (1ULL << slot);
			continue;
		}
		if (d->fence_kind != MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE)
			continue;
		if (d->flags & MXFS_RECOV_F_QUARANTINED) {
			/* terminal refusal published: owes nothing, but its victim key
			 * must still be absent when the gate is lifted */
			terminal |= (1ULL << slot);
			if (out_terminal_key)
				out_terminal_key[slot] = d->fence_victim_key;
			continue;
		}
		if (d->stage >= MXFS_RECOV_STAGE_GRANTS_RELEASED)
			continue;               /* complete, awaiting slot zeroing */
		if (d->stage < MXFS_RECOV_STAGE_SNAPSHOTTING)
			malformed |= (1ULL << slot);
		owed |= (1ULL << slot);
	}

	mxfs_pal_free(hb);
	*out_owed = owed;
	*out_unreadable = unreadable;
	if (out_malformed)
		*out_malformed = malformed;
	if (out_terminal)
		*out_terminal = terminal;
	return examined ? 0 : -EIO;
}

/*
 * (D-FOREIGN-REPLAY step 4a) — CONTINUOUS, CANCELLABLE DEAD CONFIRM.
 *
 * mxfs_disklock_get_stale_slot_mask() above answers "did this slot advance
 * during ONE window", and it re-baselines on every call.  That is fine for
 * the 10 s mount probe, whose only consumer is a decision to defer.  It is
 * NOT sufficient to justify a hardware fence, and chaining several short
 * calls and AND-ing the results does not fix it: an advance that lands
 * between call N's last poll and call N+1's baseline read is invisible to
 * both — N never sees it, N+1 adopts it as its own baseline — so a node
 * whose heartbeat is merely slow can be declared dead by the chain even
 * though it advanced inside the nominal window.  (design-consult review,
 * item 3.)
 *
 * This entry point keeps ONE baseline for the whole window and samples
 * against it, so "never advanced" means never, continuously.  It also
 * re-checks identity on every sample rather than once at the end: a final
 * node-id comparison cannot see an A -> inactive -> A' reclaim in between,
 * and node ids are UUID-derived, so a rebooted host returns with the SAME
 * id.  The heartbeat's own epoch (mount incarnation) is what distinguishes
 * them, and it is pinned at baseline and enforced every sample.
 *
 * A candidate is dropped — i.e. NOT confirmed dead — on any of:
 *   timestamp advanced, node id changed, epoch changed, record no longer
 *   ACTIVE, fs_gen foreign, or the read failed.  Every ambiguity resolves
 *   toward "leave it alone": a missed fence costs availability, a wrong
 *   fence shoots a healthy member.
 *
 * expect_node[] (optional) pins which incarnation the CALLER saw, so a slot
 * that changed hands before this even started is rejected at baseline.
 *
 * cancel (optional) is polled between samples so an unmount can abandon the
 * wait.  It is deliberately NOT honoured after this returns: the caller's
 * fence -> mark-pending sequence must not be interruptible half way.
 *
 * Returns 0 with *out_confirmed set (0 if cancelled), or a negative errno.
 */
int mxfs_disklock_confirm_dead_mask(struct mxfs_disklock_ctx *ctx,
				    uint64_t candidate_mask,
				    const mxfs_node_id_t *expect_node,
				    uint32_t samples,
				    const volatile int *cancel,
				    uint64_t *out_confirmed,
				    mxfs_epoch_t *out_epoch)
{
	/* one allocation: the record buffer and the per-slot baseline
	 * (1.3 KB on the stack otherwise) */
	struct confirm_scratch {
		struct mxfs_disklock_heartbeat hb;
		uint64_t ts[MXFS_DISKLOCK_HB_SLOTS];
		mxfs_epoch_t epoch[MXFS_DISKLOCK_HB_SLOTS];
		mxfs_node_id_t node[MXFS_DISKLOCK_HB_SLOTS];
	} *scr;
	struct mxfs_disklock_heartbeat *hb;
	uint64_t *base_ts;
	mxfs_epoch_t *base_epoch;
	mxfs_node_id_t *base_node;
	uint64_t live = 0;
	uint32_t slot;
	uint32_t i;

	if (!ctx || !out_confirmed || !ctx->dev)
		return -EINVAL;

	*out_confirmed = 0;
	if (out_epoch) {
		for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++)
			out_epoch[slot] = 0;
	}
	if (!candidate_mask || !samples)
		return 0;

	scr = mxfs_pal_alloc(sizeof(*scr));
	if (!scr)
		return -ENOMEM;
	hb = &scr->hb;
	base_ts = scr->ts;
	base_epoch = scr->epoch;
	base_node = scr->node;

	/* ── Baseline pass ───────────────────────────────────────────── */
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		uint64_t off;
		int rc;

		if (!(candidate_mask & (1ULL << slot)))
			continue;

		off = ctx->base_offset +
		      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
		mxfs_pal_mutex_lock(ctx->lock);
		rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
		mxfs_pal_mutex_unlock(ctx->lock);
		if (rc < 0)
			continue;
		if (hb->magic != MXFS_DISKLOCK_MAGIC ||
		    hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE ||
		    hb_gen_foreign(ctx, hb))
			continue;
		if (expect_node && expect_node[slot] &&
		    hb->node_id != expect_node[slot]) {
			mxfs_pal_log(MXFS_LOG_INFO,
			    "disklock: confirm slot %u baseline node=%u != expected %u "
			    "— slot changed hands, dropping candidate",
			    slot, hb->node_id, expect_node[slot]);
			continue;
		}

		base_ts[slot] = hb->timestamp_ms;
		base_epoch[slot] = hb->epoch;
		base_node[slot] = hb->node_id;
		live |= (1ULL << slot);
	}

	/* ── Sample against that ONE baseline ────────────────────────── */
	for (i = 0; i < samples && live; i++) {
		mxfs_pal_sleep_ms(MXFS_DISKLOCK_HB_INTERVAL_MS);

		if (cancel && *cancel) {
			mxfs_pal_free(scr);
			return 0;
		}

		for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
			uint64_t off;
			const char *why = NULL;
			int rc;

			if (!(live & (1ULL << slot)))
				continue;

			off = ctx->base_offset +
			      (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
			mxfs_pal_mutex_lock(ctx->lock);
			rc = mxfs_pal_bdev_read(ctx->dev, off, hb, sizeof(*hb));
			mxfs_pal_mutex_unlock(ctx->lock);

			if (rc < 0)
				why = "read failed (cannot prove continuity)";
			else if (hb->magic != MXFS_DISKLOCK_MAGIC ||
				 hb->flags != MXFS_DISKLOCK_FLAG_ACTIVE)
				why = "record no longer ACTIVE";
			else if (hb_gen_foreign(ctx, hb))
				why = "fs_gen went foreign";
			else if (hb->node_id != base_node[slot])
				why = "node id changed";
			else if (hb->epoch != base_epoch[slot])
				why = "epoch changed (rejoined)";
			else if (hb->timestamp_ms != base_ts[slot])
				why = "heartbeat advanced";

			if (why) {
				mxfs_pal_log(MXFS_LOG_INFO,
				    "disklock: confirm slot %u node=%u dropped at sample "
				    "%u/%u — %s", slot, base_node[slot], i + 1, samples,
				    why);
				live &= ~(1ULL << slot);
			}
		}
	}

	/*
	 * export the BASELINE incarnation of each confirmed slot.  This
	 * is the incarnation held frozen across the whole window — every sample
	 * proved hb->epoch still equalled it, and any slot whose epoch moved was
	 * dropped above.  It is therefore the only incarnation the caller may
	 * name as the victim; re-reading the sector later would race a rejoin.
	 */
	if (out_epoch) {
		for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
			if (live & (1ULL << slot))
				out_epoch[slot] = base_epoch[slot];
		}
	}
	mxfs_pal_free(scr);

	*out_confirmed = live;
	return 0;
}

/* (§6.2): bootstrap-owner identity plumbing — see disklock.h. */
void mxfs_disklock_set_owner_bootstrap(struct mxfs_disklock_ctx *ctx, bool on)
{
	if (!ctx)
		return;
	ctx->owner_bootstrap = on;
}

void mxfs_disklock_predraw_epoch(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return;
	ctx->epoch_predrawn = ctx->epoch;
}

/* ── (§6.7): same-boot RESUME support ── */

int mxfs_disklock_adopt_epoch(struct mxfs_disklock_ctx *ctx, mxfs_epoch_t epoch)
{
	if (!ctx || !inc_valid(epoch))
		return -EINVAL;
	mxfs_pal_mutex_lock(ctx->lock);
	if (ctx->local_slot >= 0) {
		mxfs_pal_mutex_unlock(ctx->lock);
		return -EBUSY;
	}
	ctx->epoch = epoch;
	ctx->epoch_predrawn = epoch;
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "disklock: P-BOOT-EPOCH-ADOPTED node=%u epoch=%llu — the "
		     "resumed bootstrap term's incarnation is this ctx's own",
		     ctx->local_node, (unsigned long long)epoch);
	return 0;
}

int mxfs_disklock_read_record(struct mxfs_disklock_ctx *ctx, int slot,
			      struct mxfs_disklock_heartbeat *out)
{
	if (!ctx || !ctx->dev || !out || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	return mxfs_pal_bdev_read_prio(ctx->dev, ctx->base_offset +
				       (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE,
				       out, sizeof(*out));
}

int mxfs_disklock_reclaim_own_slot(struct mxfs_disklock_ctx *ctx, int slot)
{
	struct mxfs_disklock_heartbeat *hb;
	int rc;

	if (!ctx || !ctx->dev || slot < 0 || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	if (ctx->local_slot >= 0)
		return -EBUSY;
	hb = mxfs_pal_alloc(sizeof(*hb));
	if (!hb)
		return -ENOMEM;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, ctx->base_offset +
				     (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE,
				     hb, sizeof(*hb));
	if (rc < 0)
		goto out;
	if (!mxfs_hb_feature_bootstrap_pending(hb) || hb_gen_foreign(ctx, hb) ||
	    hb->node_id != ctx->local_node || !inc_eq(hb->epoch, ctx->epoch)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P-BOOT-RECLAIM-STALE slot=%d flags=%u node=%u "
			     "epoch=%llu pending=%d — not our ACTIVE|BOOTSTRAP_PENDING "
			     "record under the resumed incarnation (%u/%llu); nothing "
			     "taken", slot, hb->flags, hb->node_id,
			     (unsigned long long)hb->epoch,
			     mxfs_hb_feature_bootstrap_pending(hb) ? 1 : 0,
			     ctx->local_node, (unsigned long long)ctx->epoch);
		rc = -ESTALE;
		goto out;
	}
	ctx->epoch_predrawn = 0;            /* consumed, as the claim would */
	ctx->claim_fresh = false;           /* FULL replay of our own log */
	ctx->bootstrap_pending = true;
	ctx->own_prov = hb->prov;           /* the same tenancy continues */
	ctx->local_slot = slot;
	ctx->slice_adopted = false;
	ctx->claim_via_caw = true;
	ctx->hb_img = *hb;
	ctx->hb_img_valid = true;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "disklock: P-BOOT-RECLAIMED slot %d for node %u epoch=%llu — "
		     "our own adopted record re-taken for the same-boot resume; "
		     "its slice is FULLY replayed again as our own log",
		     slot, ctx->local_node, (unsigned long long)ctx->epoch);
	rc = slot;
out:
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_free(hb);
	return rc;
}

/* ── (§6.5 shape B): adopt a certified victim slot ── */

bool mxfs_hb_feature_bootstrap_pending(const struct mxfs_disklock_heartbeat *hb)
{
	return hb && hb->magic == MXFS_DISKLOCK_MAGIC &&
	       hb->flags == MXFS_DISKLOCK_FLAG_ACTIVE &&
	       hb->feat.magic == MXFS_HB_FEAT_MAGIC &&
	       (hb->feat.feat_flags & MXFS_HB_FEAT_BOOTSTRAP_PENDING) &&
	       hb->feat.crc32c == hb_feature_crc(hb->fs_gen, hb->node_id,
						 hb->epoch, &hb->feat);
}

void mxfs_disklock_clear_bootstrap_pending(struct mxfs_disklock_ctx *ctx)
{
	if (!ctx)
		return;
	mxfs_pal_mutex_lock(ctx->lock);
	ctx->bootstrap_pending = false;
	mxfs_pal_mutex_unlock(ctx->lock);
}

int mxfs_disklock_claim_victim_slot(struct mxfs_disklock_ctx *ctx, int slot,
				    const struct mxfs_recov_desc *expect_desc,
				    uint32_t *old_crc)
{
	struct mxfs_disklock_heartbeat *hb, *expected;
	const struct mxfs_recov_desc *d;
	uint64_t off;
	int rc;

	if (!ctx || !ctx->dev || !expect_desc || slot < 0 ||
	    slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	if (ctx->local_slot >= 0)
		return -EBUSY;
	if (!inc_valid(ctx->epoch_predrawn) || ctx->epoch_predrawn != ctx->epoch) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P-BOOT-ADOPT-NO-EPOCH slot=%d — the adoption "
			     "must run under the pre-drawn bootstrap epoch (ruling "
			     "STOP-SHIP 8); refusing", slot);
		return -EINVAL;
	}
	hb = mxfs_pal_alloc(sizeof(*hb));
	expected = mxfs_pal_alloc(sizeof(*expected));
	if (!hb || !expected) {
		mxfs_pal_free(hb);
		mxfs_pal_free(expected);
		return -ENOMEM;
	}
	off = ctx->base_offset + (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE;
	mxfs_pal_mutex_lock(ctx->lock);
	rc = mxfs_pal_bdev_read_prio(ctx->dev, off, expected, sizeof(*expected));
	if (rc < 0)
		goto out;
	d = recov_desc_of(expected);
	if (expected->flags != MXFS_DISKLOCK_FLAG_RECOVERY_GUARD ||
	    hb_gen_foreign(ctx, expected) || !d ||
	    d->owner_node != ctx->local_node ||
	    !inc_eq(d->owner_epoch, ctx->epoch) ||
	    d->stage < MXFS_RECOV_STAGE_FENCED ||
	    !(d->flags & MXFS_RECOV_F_OWNER_BOOTSTRAP) ||
	    memcmp(d, expect_desc, sizeof(*d)) != 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P-BOOT-ADOPT-STALE slot=%d flags=%u desc=%s "
			     "owner=%u/%llu stage=%u — the sector is not the exact "
			     "guarded image the escrow holds; nothing written",
			     slot, expected->flags, d ? "valid" : "none",
			     d ? d->owner_node : 0,
			     d ? (unsigned long long)d->owner_epoch : 0ULL,
			     d ? d->stage : 0);
		rc = -ESTALE;
		goto out;
	}
	if (old_crc)
		*old_crc = mxfs_pal_crc32c(~0U, expected, sizeof(*expected));

	/* the epoch is consumed exactly once (claim_slot does the same) */
	ctx->epoch_predrawn = 0;
	ctx->claim_fresh = false;           /* FULL replay of the slice */
	ctx->bootstrap_pending = true;
	hb_prov_derive(ctx, expected, false);
	memset(hb, 0, sizeof(*hb));
	hb->magic = MXFS_DISKLOCK_MAGIC;
	hb->flags = MXFS_DISKLOCK_FLAG_ACTIVE;
	hb->node_id = ctx->local_node;
	hb->fs_gen = ctx->fs_gen;
	hb->timestamp_ms = mxfs_pal_time_ms();
	hb->epoch = ctx->epoch;
	hb_feature_fill(ctx, hb);
	hb->prov = ctx->own_prov;
	hb_ident_fill(ctx, hb, (uint32_t)slot);
	rc = mxfs_pal_bdev_compare_and_write(ctx->dev, off, expected, hb);
	if (rc == 0) {
		ctx->local_slot = slot;
		ctx->slice_adopted = false;
		ctx->claim_via_caw = true;
		ctx->hb_img = *hb;
		ctx->hb_img_valid = true;
		mxfs_pal_log(MXFS_LOG_WARN,
			     "disklock: P-BOOT-ADOPTED slot %d for node %u epoch=%llu "
			     "— certified victim slot adopted as this bootstrap "
			     "owner's ACTIVE|BOOTSTRAP_PENDING record; its slice "
			     "will be FULLY replayed as our own log",
			     slot, ctx->local_node, (unsigned long long)ctx->epoch);
		rc = slot;
	} else {
		ctx->bootstrap_pending = false;
		ctx->epoch_predrawn = ctx->epoch;   /* not consumed */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "disklock: P-BOOT-ADOPT-CAS slot=%d rc=%d — the claim "
			     "CAW did not land; nothing adopted", slot, rc);
	}
out:
	mxfs_pal_mutex_unlock(ctx->lock);
	mxfs_pal_free(hb);
	mxfs_pal_free(expected);
	return rc;
}
