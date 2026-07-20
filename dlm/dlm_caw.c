/*
 * MXFS — Multinode XFS
 * Compare-and-Write (CAW) based DLM
 *
 * Replaces the TCP-based distributed lock manager with a disk-based
 * implementation using SCSI Compare-and-Write (CAW) for atomic lock
 * state transitions on the shared block device.
 *
 * All lock state lives in 512-byte slots on the shared disk. Nodes
 * acquire/release locks via atomic CAW operations — the disk is the
 * master, not any node. This eliminates all TCP peer-to-peer connections
 * for lock coordination and removes the single-point-of-failure master
 * node concept.
 *
 * Lock slots use linear probing from a hash of the resource ID.
 * Each slot stores per-mode holder bitmaps (64-bit, one bit per node)
 * and waiter bitmaps. The 6-mode DLM compatibility matrix (NL/CR/CW/
 * PR/PW/EX) is enforced identically to the TCP DLM.
 *
 * BAST notifications use two complementary paths:
 *   1. UDP multicast — a waiter sends a hint to the multicast group
 *      requesting that holders check their locks. Fast but unreliable.
 *   2. Poll thread — periodically reads held lock slots from disk and
 *      fires the BAST callback if waiters are detected. Reliable but
 *      slower (MXFS_CAW_BAST_POLL_MS interval).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "dlm.h"
#include "dlm_caw.h"
#include "dlm_shared.h"
#include "disklock.h"
#include "discovery.h"

#ifdef __KERNEL__
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
/* mxfs_pal_popcount64 moved to dlm_shared.h (step-3 lift) */

/*
 * v0.3.128 sess30 — caller-level slot-generation verify after CAS.
 * After caw_slot returns CAS-success, FUA-read the slot back and check
 * `slot.generation >= our_new->generation`.  If yes, our write persisted
 * (or peer overwrote with even higher generation, which is also fine —
 * lock state moved forward).  If no, our CAS-success was a lie (kernel
 * SCSI passthrough non-persist, sess26 P49 root cause #2 / sess30
 * Samsung 870 EVO no-FUA finding) — return -EAGAIN to the caw_lock
 * retry loop, which re-reads slot and recomputes desired state.
 *
 * Differs from PAL-level verify:
 *  - Uses generation-field semantics, not byte-level memcmp — correctly
 *    handles "our CAS persisted, peer overwrote" without false-positive.
 *  - Fires only at the caw_slot wrapper boundary, not on every CAW op
 *    submission (PAL verify-poll ran 5 reads × backoff = 0/25 PASS,
 *    sess30 measured).  caw_slot is called per LOGICAL CAS attempt,
 *    not per low-level retry.
 *
 * 0 = no verify (default until validated; same behavior as v0.3.127).
 * 1 = generation verify after every caw_slot success.
 */
static int mxfs_caw_gen_verify;
module_param_named(caw_gen_verify, mxfs_caw_gen_verify, int, 0644);
MODULE_PARM_DESC(caw_gen_verify,
                 "Caller-level CAW generation verify: 0=off (default), "
                 "1=FUA-readback + generation check after each caw_slot "
                 "success; mismatch returns -EAGAIN.");

/*
 * sess2(ccloop 26c41354) FAIR HANDOFF — anti-starvation for the 16-node
 * inode-EX contention.  DEFAULT 0.  When 1: on an INODE-lock release with EX
 * waiters, the releaser sets yield_to to ONE round-robin-chosen next EX waiter
 * (first waiter after the releaser's node bit, wrapping) instead of ALL
 * waiters; and in caw_wait_for_grant a fresh EX waiter that is NOT the chosen
 * one defers its self-promote until its turn.  This replaces the self-promote
 * free-for-all (every waiter races to CAS the instant the lock frees, so an
 * unlucky node's poll cadence never wins) with a bounded O(N) rotation —
 * killing the 16-node victim-node data loss (a starved writer misses the
 * coherency barrier; P131-WAITLONG / SESS50-STARVE).  Deadlock-safe: a dead
 * chosen node is skipped by the existing 5s yield_to stale-clear.  Upgraders
 * (conversion priority, sess130) are exempt; AG locks are untouched.
 */
/* sess6 (ccloop 72513a13): DEFAULT ON.  A/B at 32/cawd, fresh cluster,
 * 32-node one-shot create storm in ONE shared dir: fair=0 free-for-all
 * left 16/32 nodes' creates HUNG >90s (victim-node starvation is fatal at
 * this scale, not just slow); fair=1 completed all 32 in <=2.5s
 * (p50=942ms).  The earlier "fair=1 catastrophic" reading (p90=46s) was
 * measured on a POISONED cluster whose killed runs had leaked stale
 * waiter bits — the 5s stale-ticket clears dominated; on clean state the
 * rotation is sound. */
int mxfs_caw_fair_handoff = 1;
module_param_named(caw_fair_handoff, mxfs_caw_fair_handoff, int, 0644);
MODULE_PARM_DESC(caw_fair_handoff,
                 "round-robin inode-EX lock handoff (anti-starvation) instead "
                 "of the self-promote free-for-all; 0=off, 1=on (default)");

/*
 * sess2(ccloop 26c41354) UNLOCK ANTI-STORM — the CAW UNLOCK retry loop
 * (mxfs_dlm_caw_unlock) tight-loops on -EAGAIN with NO backoff, unlike the
 * acquire path (sess39 desync).  Under a 16-node hot-inode CAS storm (all
 * nodes create+unlink in ONE shared dir, e.g. dir_reuse) the unlock can never
 * win 100 tight retries -> returns -EIO -> the lock stays HELD -> BAST re-fires
 * forever -> the mxfs-ino-bast workqueue spawns 1000+ blocked workers -> load
 * 870 WEDGE (PROVEN this session).  DEFAULT 0.  When 1: on an INODE-lock unlock
 * CAS miscompare, sleep a node-phased + retry-escalating jitter (1..~15ms) to
 * desync the storm so the unlock wins; and if the retry budget is exhausted,
 * keep retrying (wall-clock bounded by MXFS_CAW_WAIT_TIMEOUT_MS) instead of
 * -EIO, because a FAILED unlock wedges the cluster and an unlock MUST complete.
 * AG locks unaffected.
 */
int mxfs_caw_unlock_backoff = 1;	/* sess5 (ccloop 72513a13): DEFAULT ON.
				 * Measured with it off: dir 8388739's holder
				 * completed its in-core release (P70-BP
				 * EXIT=full on every node) yet its slot bit
				 * stayed set — the unlock CAS lost 100 tight
				 * retries against the 8-node waiter-bit churn
				 * and gave up (-EIO swallowed), orphaning the
				 * bit; all 8 nodes' mkdirs then convoyed
				 * 300s+ on a lock NOBODY held in-core (cc
				 * NO_TERMINAL, board cascade).  An unlock
				 * MUST complete; the jittered no-EIO retry is
				 * the designed cure and AG locks are
				 * unaffected. */
module_param_named(caw_unlock_backoff, mxfs_caw_unlock_backoff, int, 0644);
MODULE_PARM_DESC(caw_unlock_backoff,
                 "jittered backoff + no-EIO retry on inode-unlock CAS "
                 "miscompare (anti CAS-storm wedge); 0=off (default), 1=on");

/*
 * v0.10.39: runtime gate for the inode-acquire fresh-handoff fast poll
 * (MXFS_CAW_INODE_FASTPOLL_MS window at 2ms).  Default ON — it removes up
 * to 25ms of exponential-backoff quantization from a BAST-driven handoff
 * (measured 45→30ms per unlink).  A/B lever: under a 31-waiter dir-EX
 * convoy the window adds ~32 slot reads per waiter per wait, suspected of
 * slowing the hot slot's CAS traffic at the target.
 */
int mxfs_caw_inode_fastpoll = 1;
module_param_named(caw_inode_fastpoll, mxfs_caw_inode_fastpoll, int, 0644);
MODULE_PARM_DESC(caw_inode_fastpoll,
                 "fast fixed-interval poll during the first 64ms of an "
                 "inode lock wait; 1=on (default), 0=exponential backoff "
                 "from the first sleep");

/*
 * ccloop cc87fed3 sess7/sess8: dlm_scaling@32 op-rate collapse fix -- clear a
 * freed inode's CAW slot dir_epoch/last_ex_slot so a REUSED ino doesn't
 * inherit a stale cross-node-handoff signal from its predecessor incarnation.
 * sess8: implemented as the is_free parameter to mxfs_dlm_caw_unlock_gen,
 * piggybacking the clear onto the tombstone CAS the unlock already performs
 * (zero extra I/O) -- see that function's own comment for why a separate
 * post-hoc find+read+CAS (the sess7 attempt) both silently never fired AND,
 * once fixed to actually fire, measurably regressed the test by adding a
 * synchronous extra round-trip to the free hot path.  Default ON: the write
 * is guarded to only ever touch an idle tombstone for the EXACT resource
 * being freed (never a live lock, never a probe-chain neighbor), so it
 * cannot corrupt in-flight lock state even if the hypothesis is wrong --
 * worst case is a wasted field clear inside a CAS that was happening anyway.
 * A/B lever for regression isolation if a future session needs to rule this
 * fix out as a suspect.
 */
int mxfs_caw_epoch_free_reset = 1;
module_param_named(caw_epoch_free_reset, mxfs_caw_epoch_free_reset, int, 0644);
MODULE_PARM_DESC(caw_epoch_free_reset,
                 "clear CAW slot dir_epoch/last_ex_slot at inode free so a "
                 "reused ino doesn't inherit a stale handoff signal; 1=on "
                 "(default), 0=off (pre-sess7 behavior, for A/B)");
/*
 * sess40: gate the per-op P13-INSTR GRANT-WAIT/POLL diagnostics behind
 * mxfs.instr.  They fire on EVERY contended inode-DLM acquire (and the
 * POLL variant once per slot-state change inside the wait spin); under
 * 4-node shared-dir contention that is thousands of printk/sec on the
 * lock hot path, which made cache_coherency ~100x slower and timed out
 * the criterion (the same class of slowdown sess36 gated for the xfs
 * overlay).  Pure logging, no side effects.  mxfs_instr_enabled lives in
 * the xfs overlay (xfs_mxfs_dlm.c) and is linked into mxfs.ko alongside
 * this file; user-mode dlm builds (no overlay) compile it out.
 */
extern int mxfs_instr_enabled;
#define caw_instr_on() (unlikely(mxfs_instr_enabled))
#else
#define mxfs_caw_gen_verify 0
#define caw_instr_on() (0)
#endif

/* Compatibility matrix + FNV-1a hash + const holder readers +
 * is_compatible + recompute_granted_mode: lifted to dlm_shared.c
 * (§11 step 3) — one copy shared with dlm.c and the NET2 lock plane. */

static const char * const lock_mode_names[] = {
	"NL", "CR", "CW", "PR", "PW", "EX"
};

static inline const char *mode_name(uint8_t mode)
{
	if (mode < MXFS_LOCK_MODE_COUNT)
		return lock_mode_names[mode];
	return "??";
}

/* ─── Holder bitmap pointer by mode ─── */

static uint64_t *holders_for_mode(struct mxfs_caw_lock_slot *slot, uint8_t mode)
{
	switch (mode) {
	case MXFS_LOCK_EX: return &slot->holders_ex;
	case MXFS_LOCK_PW: return &slot->holders_pw;
	case MXFS_LOCK_PR: return &slot->holders_pr;
	case MXFS_LOCK_CW: return &slot->holders_cw;
	case MXFS_LOCK_CR: return &slot->holders_cr;
	default: return NULL; /* NL has no holders */
	}
}

/* ─── Compatibility check (self-excluding variant; the plain
 *     is_compatible lives in dlm_shared.c) ─── */

static bool compatible_excluding_self(const struct mxfs_caw_lock_slot *slot,
				       uint8_t mode, uint64_t node_bit)
{
	int m;

	for (m = MXFS_LOCK_CR; m <= MXFS_LOCK_EX; m++) {
		uint64_t others = holders_for_mode_const(slot, (uint8_t)m) &
				  ~node_bit;
		if (others != 0 && !lock_compat[m][mode])
			return false;
	}
	return true;
}

/* ─── Determine which mode a given node holds ─── */

static uint8_t node_held_mode(const struct mxfs_caw_lock_slot *slot,
			       uint64_t node_bit)
{
	if (slot->holders_ex & node_bit) return MXFS_LOCK_EX;
	if (slot->holders_pw & node_bit) return MXFS_LOCK_PW;
	if (slot->holders_pr & node_bit) return MXFS_LOCK_PR;
	if (slot->holders_cw & node_bit) return MXFS_LOCK_CW;
	if (slot->holders_cr & node_bit) return MXFS_LOCK_CR;
	return MXFS_LOCK_NL;
}

/* ─── Check if slot has any holders at all ─── */

static bool slot_has_holders(const struct mxfs_caw_lock_slot *slot)
{
	return slot->holders_ex || slot->holders_pw || slot->holders_pr ||
	       slot->holders_cw || slot->holders_cr;
}

/* ─── Recompute waiter_mode from waiter bitmap ─── */

static uint8_t recompute_waiter_mode(const struct mxfs_caw_lock_slot *slot)
{
	/*
	 * sess50 (run14d): derive waiter_mode from the waiter bitmaps so it
	 * can be DOWNGRADED when the exclusive waiter departs.  The old code
	 * preserved the existing waiter_mode whenever any waiter bit was set,
	 * so a leaked-or-departed EX waiter left waiter_mode stuck at EX while
	 * PR waiters kept `waiters` nonzero -> defer_for_waiter deferred every
	 * fresh PR reader forever (16-node posix_semantics wedge: ino=8388738
	 * frozen at waiter_mode=5 h_ex=0 with no live EX requester anywhere).
	 * waiters_ex tracks exclusive-class (EX/PW) waiters precisely; AND with
	 * `waiters` defensively ignores any stale exclusive bit whose node bit
	 * has already cleared from `waiters`.
	 */
	if (slot->waiters == 0)
		return MXFS_LOCK_NL;
	if (slot->waiters_ex & slot->waiters)
		return MXFS_LOCK_EX;
	return MXFS_LOCK_PR;
}

/*
 * v0.10.39: note a grant's mode class in the slot's EX streak counter —
 * inside the same CAS image, so it is exactly as atomic as the grant.
 * The fair-handoff releaser yields one turn to the whole shared class at
 * MXFS_CAW_EX_STREAK_YIELD (PR-reader anti-starvation).
 */
static void caw_grant_streak_note(struct mxfs_caw_lock_slot *slot,
				  uint8_t mode)
{
	if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW)
		slot->ex_grant_streak++;
	else
		slot->ex_grant_streak = 0;
}

/* ─── Slot I/O ─── */

static uint64_t slot_offset(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	return ctx->lock_region_offset +
	       (uint64_t)slot_index * MXFS_CAW_SLOT_SIZE;
}

/*
 * v0.3.30: detect and repair corrupted CAW slots.
 *
 * Background: on VM/LIO/iSCSI setups mkfs's zero_region pwrite-with-O_SYNC is
 * not always durable — the disklock region can retain bytes from a previous
 * filesystem.  Once a CAW slot is claim-empty'd (memset(0) + magic + resource
 * etc), the FIRST write zeros the full 512 bytes via SCSI CAW.  But sess19
 * observed the slot reverting to garbage in unused fields after some minutes
 * (mechanism unconfirmed — possibly LIO write-back-cache flush replaying
 * old content, possibly a path that writes a partially-initialized buffer).
 *
 * Symptom: holders_cw / holders_cr / waiters / granted_mode / waiter_mode /
 * yield_to fields contain ASCII text from prior disk content.  is_compatible()
 * iterates all modes including CW/CR; a non-zero holders_cw bitmap makes
 * EX-acquire wait forever ("no one is holding CW so EX should be compatible"
 * — but holders_cw=0x5028... has many bits set and is_compatible says NO).
 *
 * Detection: granted_mode and waiter_mode are u8 with valid range 0..5
 * (NL..EX).  Anything > MXFS_LOCK_EX is unambiguously corrupt.
 *
 * Repair: CAS the slot, keeping magic/gen/resource and the clean
 * holders_ex/pw/pr fields, zeroing everything else and recomputing derived
 * values.  Bound retries — if we lose the CAS, someone else modified the
 * slot, re-read.  If repair fails after retries, return the read content
 * anyway so callers can make progress (the next CAW operation may overwrite
 * the garbage).
 */
static bool slot_appears_corrupt(const struct mxfs_caw_lock_slot *s)
{
	if (s->magic != MXFS_CAW_MAGIC)
		return false; /* tombstone or empty — not "corrupt" */
	if (s->granted_mode > MXFS_LOCK_EX)
		return true;
	if (s->waiter_mode > MXFS_LOCK_EX)
		return true;
	/* v0.3.83 EX/PW single-holder popcount validity — the check (and
	 * its stale-disk-garbage history) lives in dlm_shared.c. */
	if (!caw_slot_holders_popcount_ok(s))
		return true;
	/*
	 * granted_mode must agree with the highest-occupied holder bitmap.
	 * Disagreement indicates stale fields from prior FS where granted
	 * was preserved but holder bits were re-zeroed (or vice-versa).
	 */
	if (s->granted_mode != recompute_granted_mode(s))
		return true;
	return false;
}

static int caw_repair_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
			    const struct mxfs_caw_lock_slot *corrupt,
			    struct mxfs_caw_lock_slot *repaired_out)
{
	struct mxfs_caw_lock_slot repaired;
	int rc;

	mxfs_pal_log(MXFS_LOG_WARN,
		"mxfs: P-H22-REPAIR slot=%u corrupt_hex=%llx hpw=%llx hpr=%llx "
		"hcw=%llx hcr=%llx gm=%u",
		slot_index,
		(unsigned long long)corrupt->holders_ex,
		(unsigned long long)corrupt->holders_pw,
		(unsigned long long)corrupt->holders_pr,
		(unsigned long long)corrupt->holders_cw,
		(unsigned long long)corrupt->holders_cr,
		corrupt->granted_mode);

	memset(&repaired, 0, sizeof(repaired));
	repaired.magic = corrupt->magic;
	repaired.generation = corrupt->generation + 1;
	repaired.resource = corrupt->resource;
	/* v0.6.0: a repaired slot has UNKNOWN EX history — advance the epoch
	 * (even a garbage base value works: the XFS gate adopts on CHANGE) and
	 * drop the last-EX record so every holder reloads rather than trusting
	 * a base stamped under the pre-corruption history. */
	repaired.dir_epoch = corrupt->dir_epoch + 1;
	repaired.last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
	/*
	 * v0.3.83: repair holder bitmaps when invalid.  Sess19 observed
	 * h_ex/h_pw/h_pr clean while h_cw/h_cr/etc were garbage and trusted
	 * the former.  Sess23 captured the opposite: h_ex/h_pw garbage too
	 * (e0041d00e1000413, popcount=16 — invalid for EX-exclusive).  Detect
	 * by popcount and zero garbage fields instead of preserving them.
	 */
	if (mxfs_pal_popcount64(corrupt->holders_ex) <= 1)
		repaired.holders_ex = corrupt->holders_ex;
	if (mxfs_pal_popcount64(corrupt->holders_pw) <= 1)
		repaired.holders_pw = corrupt->holders_pw;
	/* h_pr / h_cw / h_cr can have multiple legitimate bits.  Without
	 * a known cluster topology at this layer, conservatively preserve
	 * them only when h_ex was clean (suggesting fields are coherent).
	 * Otherwise zero them — let real holders re-acquire.
	 */
	if (mxfs_pal_popcount64(corrupt->holders_ex) <= 1 &&
	    mxfs_pal_popcount64(corrupt->holders_pw) <= 1) {
		repaired.holders_pr = corrupt->holders_pr;
	}
	/* holders_cw / holders_cr / waiters / yield_to / yield_set_ms /
	 * waiter_mode / last_modified_ms — zero out (memset already did this) */
	repaired.granted_mode = recompute_granted_mode(&repaired);
	repaired.waiter_mode = MXFS_LOCK_NL;
	repaired.last_modified_ms = mxfs_pal_time_ms();

	mxfs_pal_log(MXFS_LOG_WARN,
		"mxfs: CAW slot %u corrupt — attempting repair "
		"(corrupt: gm=%u wm=%u w=%llx yt=%llx h_cw=%llx h_cr=%llx; "
		"repaired: gm=%u h_ex=%llx h_pw=%llx h_pr=%llx)",
		slot_index, corrupt->granted_mode, corrupt->waiter_mode,
		(unsigned long long)corrupt->waiters,
		(unsigned long long)corrupt->yield_to,
		(unsigned long long)corrupt->holders_cw,
		(unsigned long long)corrupt->holders_cr,
		repaired.granted_mode,
		(unsigned long long)repaired.holders_ex,
		(unsigned long long)repaired.holders_pw,
		(unsigned long long)repaired.holders_pr);

	rc = mxfs_pal_bdev_compare_and_write(ctx->dev,
					      slot_offset(ctx, slot_index),
					      corrupt, &repaired);
	if (rc == 0) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: CAW slot %u repaired successfully",
			slot_index);
		*repaired_out = repaired;
	}
	return rc;
}

static int read_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
		      struct mxfs_caw_lock_slot *out)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: read_slot %u I/O error %d, "
				     "retry %d/%d (backoff %u ms)",
				     slot_index, rc, attempt,
				     MXFS_CAW_IO_MAX_RETRIES, backoff);
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}

		rc = mxfs_pal_bdev_read_prio(ctx->dev,
					     slot_offset(ctx, slot_index),
					     out, MXFS_CAW_SLOT_SIZE);
		if (rc == 0) {
			/* v0.3.30: detect & repair corrupted slots */
			if (slot_appears_corrupt(out)) {
				int rep_rc = caw_repair_slot(ctx, slot_index,
							      out, out);
				if (rep_rc == 0)
					return 0;
				if (rep_rc == -EAGAIN) {
					/* lost CAS; re-read fresh */
					continue;
				}
				/* repair I/O error: log and return original
				 * content anyway — caller can still try */
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: CAW slot %u repair failed rc=%d",
					slot_index, rep_rc);
			}
			return 0;
		}
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: read_slot %u failed after %d retries: %d",
		     slot_index, MXFS_CAW_IO_MAX_RETRIES + 1, rc);
	return rc;
}

/*
 * ccloop 72513a13 sess3 (RULE-4 PROVEN): probe-chain walks dominated per-op
 * latency — 9.2 FUA slot reads per file CREATE (kprobe count over a 20-create
 * burst), because every open-addressing probe was its own synchronous 512B
 * SCSI READ(16)+FUA (~0.3-0.5ms each) and tombstone churn keeps chains long.
 * Read the chain in SPANS: one READ(16) of up to MXFS_CAW_PROBE_SPAN
 * contiguous slots replaces up to that many probe commands.  Same bytes, same
 * walk order; a corrupt-looking slot in the span is re-read + repaired through
 * read_slot (the existing screening path).  The claim-race protocol is
 * untouched: inserts still CAW against live content and the post-claim
 * skip_idx re-walk still runs.
 */
#define MXFS_CAW_PROBE_SPAN	16

static int read_slot_span(struct mxfs_dlm_caw_ctx *ctx, uint32_t start_idx,
			  uint32_t nslots, struct mxfs_caw_lock_slot *buf)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc = 0;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}
		rc = mxfs_pal_bdev_read_prio(ctx->dev,
					     slot_offset(ctx, start_idx),
					     buf,
					     nslots * MXFS_CAW_SLOT_SIZE);
		if (rc == 0)
			return 0;
	}
	return rc;
}

static int caw_slot(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index,
		     const struct mxfs_caw_lock_slot *compare,
		     const struct mxfs_caw_lock_slot *write)
{
	uint32_t backoff = MXFS_CAW_IO_BACKOFF_MS;
	int attempt;
	int rc;

	for (attempt = 0; attempt <= MXFS_CAW_IO_MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			if (!ctx->running)
				return -ESHUTDOWN;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: caw_slot %u I/O error %d, "
				     "retry %d/%d (backoff %u ms)",
				     slot_index, rc, attempt,
				     MXFS_CAW_IO_MAX_RETRIES, backoff);
			mxfs_pal_sleep_ms(backoff);
			backoff *= 2;
			if (backoff > MXFS_CAW_IO_BACKOFF_MAX_MS)
				backoff = MXFS_CAW_IO_BACKOFF_MAX_MS;
		}

		rc = mxfs_pal_bdev_compare_and_write(ctx->dev,
						     slot_offset(ctx, slot_index),
						     compare, write);
		/* Success — optionally verify slot persistence via FUA-read. */
		if (rc == 0 && mxfs_caw_gen_verify) {
			struct mxfs_caw_lock_slot verify_slot;
			int vrc = mxfs_pal_bdev_read_prio(ctx->dev,
							  slot_offset(ctx, slot_index),
							  &verify_slot,
							  sizeof(verify_slot));
			if (vrc != 0) {
				/* Verify-read I/O error — treat as CAS failure. */
				rc = vrc;
				continue;
			}
			/* slot.generation >= write->generation means our write
			 * landed (or was overwritten by a later writer with even
			 * higher generation — lock state moved forward, which is
			 * fine for the caller's intent of "I made my change").
			 * Lower generation means our write didn't persist. */
			if (verify_slot.generation < write->generation) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P72-INSTR caw gen-verify mismatch "
					"slot=%u expected_gen>=%u got_gen=%u — "
					"non-persist (sess30 root cause)",
					slot_index, write->generation,
					verify_slot.generation);
				rc = -EAGAIN;
			}
		}
		/*
		 * sess135 (ccloop 14d31183) P135-SLOTWR — RULE-4 instrumentation
		 * for the P108 "on-disk slot lost" producer.  A live holder's
		 * bit vanished from the hot shared-dir inode slot within 6ms of
		 * an EX grant (test12 t=58.830→58.836), forcing a reload that
		 * tears the dir (dabuf-map HOLE family).  Every slot mutation
		 * goes through this CAS, so logging every SUCCESSFUL write for
		 * low-numbered inode resources gives the slot's complete
		 * cross-node history, totally ordered by write->generation.
		 * `stripped` = holder bits present in the compare image but
		 * absent from the written image, excluding our own bit —
		 * legitimate only in dead-node purge and slot repair; any other
		 * caller stripping a foreign holder bit is the P108 producer.
		 */
		if (rc == 0) {
			const struct mxfs_resource_id *p135_res =
				write->magic == MXFS_CAW_MAGIC ?
				&write->resource : &compare->resource;

			/* daf50d34 sess2: drop the ino<=256 gate — the mkdir-storm
			 * parents are high inos and BOTH storm forensics were blind
			 * exactly here (no claim-side write history, no foreign-strip
			 * attribution).  caw_instr_on() still gates the volume. */
			if (caw_instr_on() &&
			    p135_res->type == MXFS_LTYPE_INODE) {
				uint64_t p135_cheld =
					compare->magic == MXFS_CAW_MAGIC ?
					(compare->holders_ex |
					 compare->holders_pw |
					 compare->holders_pr) : 0;
				uint64_t p135_wheld =
					write->magic == MXFS_CAW_MAGIC ?
					(write->holders_ex |
					 write->holders_pw |
					 write->holders_pr) : 0;
				uint64_t p135_strip =
					p135_cheld & ~p135_wheld &
					~ctx->node_bit;

				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P135-SLOTWR ino=%llu slot=%u "
				    "gen=%u->%u wmagic=%x "
				    "hex=%llx->%llx hpr=%llx->%llx "
				    "w=%llx->%llx gm=%u->%u yt=%llx "
				    "self=%llx stripped=%llx caller=%pS",
				    (unsigned long long)p135_res->ino,
				    slot_index,
				    compare->generation, write->generation,
				    write->magic,
				    (unsigned long long)compare->holders_ex,
				    (unsigned long long)write->holders_ex,
				    (unsigned long long)compare->holders_pr,
				    (unsigned long long)write->holders_pr,
				    (unsigned long long)compare->waiters,
				    (unsigned long long)write->waiters,
				    compare->granted_mode,
				    write->granted_mode,
				    (unsigned long long)write->yield_to,
				    (unsigned long long)ctx->node_bit,
				    (unsigned long long)p135_strip,
				    __builtin_return_address(0));
				if (p135_strip)
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: P135-FOREIGN-STRIP ino=%llu "
					    "slot=%u stripped=%llx caller=%pS "
					    "(P108 slot-loss producer)",
					    (unsigned long long)p135_res->ino,
					    slot_index,
					    (unsigned long long)p135_strip,
					    __builtin_return_address(0));
			}
		}
		/* Success or MISCOMPARE — return immediately */
		if (rc == 0 || rc == -EAGAIN)
			return rc;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: caw_slot %u failed after %d retries: %d",
		     slot_index, MXFS_CAW_IO_MAX_RETRIES + 1, rc);
	return rc;
}

/* ─── Slot-index hint cache (v0.5.3, see dlm_caw.h) ─── */

static void slot_hint_store(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t slot_idx)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_SLOTHINT_SIZE;

	if (!ctx->slot_hints)
		return;
	mxfs_pal_mutex_lock(ctx->slot_hint_lock);
	ctx->slot_hints[h].resource = *resource;
	ctx->slot_hints[h].slot_idx = slot_idx;
	ctx->slot_hints[h].valid = true;
	mxfs_pal_mutex_unlock(ctx->slot_hint_lock);
}

static bool slot_hint_get(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  uint32_t *slot_idx_out)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_SLOTHINT_SIZE;
	bool hit = false;

	if (!ctx->slot_hints)
		return false;
	mxfs_pal_mutex_lock(ctx->slot_hint_lock);
	if (ctx->slot_hints[h].valid &&
	    memcmp(&ctx->slot_hints[h].resource, resource,
		   sizeof(*resource)) == 0) {
		*slot_idx_out = ctx->slot_hints[h].slot_idx;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->slot_hint_lock);
	return hit;
}

/* ─── v0.6.0 cross-node EX-handoff epoch (see dir_epoch in dlm_caw.h) ─── */

/*
 * Apply the handoff-epoch policy to the slot image we are about to CAS in
 * as part of taking `mode`.  Returns true when the previous EX-class holder
 * was a DIFFERENT node — i.e. anything this node cached under an earlier
 * grant of this resource may be stale.  Call on every grant image (any
 * mode); only EX-class grants advance the epoch / take over last_ex_slot.
 */
static bool caw_grant_epoch_update(struct mxfs_dlm_caw_ctx *ctx,
				   struct mxfs_caw_lock_slot *s, uint8_t mode)
{
	bool handoff = (s->last_ex_slot != MXFS_CAW_EX_SLOT_NONE &&
			s->last_ex_slot != ctx->node_slot);

	if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW) {
		if (handoff)
			s->dir_epoch++;
		s->last_ex_slot = ctx->node_slot;
	}
	return handoff;
}

/*
 * Turn a fully-released slot image into a tombstone IN PLACE.  Keeps
 * generation (CAS lineage) — and, v0.6.0, the resource identity plus the
 * EX-handoff epoch fields: a tombstone is the only carrier of dir_epoch
 * across an idle gap (all holders released, then the resource is claimed
 * again later).  Zeroing them made the first cross-node grant after every
 * idle gap look handoff-free (epoch restarts at 0, last_ex_slot=NONE), so
 * the adopt gate never fired and stale cached dirs survived.  The claim
 * path inherits these fields when it recycles a tombstone whose resource
 * matches; a different resource ignores them (fresh init).
 */
static void caw_tombstone_slot(struct mxfs_caw_lock_slot *s)
{
	uint32_t saved_gen = s->generation;
	struct mxfs_resource_id saved_res = s->resource;
	uint32_t saved_epoch = s->dir_epoch;
	uint8_t saved_lex = s->last_ex_slot;

	memset(s, 0, sizeof(*s));
	s->magic = MXFS_CAW_TOMBSTONE_MAGIC;
	s->generation = saved_gen;
	s->resource = saved_res;
	s->dir_epoch = saved_epoch;
	s->last_ex_slot = saved_lex;
	s->last_modified_ms = mxfs_pal_time_ms();
}

/*
 * Claim-path counterpart: `fresh` is the memset-zero image being built for
 * a claim of `resource` at an insertion point whose CURRENT on-disk content
 * is `prev` (tombstone, ghost, or truly empty — whatever the CAS compare
 * buffer read).  Inherit the epoch lineage when the insertion point is a
 * tombstone of the SAME resource.
 */
static void caw_claim_inherit_epoch(struct mxfs_caw_lock_slot *fresh,
				    const struct mxfs_caw_lock_slot *prev,
				    const struct mxfs_resource_id *resource)
{
	if (prev->magic == MXFS_CAW_TOMBSTONE_MAGIC &&
	    memcmp(&prev->resource, resource, sizeof(*resource)) == 0) {
		fresh->dir_epoch = prev->dir_epoch;
		fresh->last_ex_slot = prev->last_ex_slot;
	}
}

/* Record the grant-time epoch/handoff observation for `resource`. */
static void caw_grant_meta_store(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint32_t dir_epoch, bool handoff,
				 uint64_t dir_block0_fsb, uint32_t dir_block0_gen)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;

	if (!ctx->grant_meta)
		return;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	/* v0.6.2: `releasing` belongs to the unlock that set it — preserve it
	 * across a same-resource store; a collision overwrite drops the old
	 * resource's mark (the unlock's clear no-ops on mismatch; the abort
	 * check below still fires via grant_seq). */
	if (!(ctx->grant_meta[h].valid &&
	      memcmp(&ctx->grant_meta[h].resource, resource,
		     sizeof(*resource)) == 0))
		ctx->grant_meta[h].releasing = false;
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].dir_epoch = dir_epoch;
	ctx->grant_meta[h].handoff = handoff;
	ctx->grant_meta[h].dir_block0_fsb = dir_block0_fsb;
	ctx->grant_meta[h].dir_block0_gen = dir_block0_gen;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

/*
 * v0.6.3 — atomic form of the already-held shortcut's gate + meta store.
 * The v0.6.2 two-section sequence (caw_release_active check, then a separate
 * caw_grant_meta_store) left a window: the shortcut checks `releasing`
 * (false — the unlock hasn't marked yet), the unlock then marks + snapshots
 * grant_seq and passes its retry-0 check, the shortcut's store lands, and the
 * unlock's CAS clears the very bit the shortcut just vouched for.  Because
 * the shortcut grant is MEMORY-ONLY (no slot write), nothing perturbs the
 * unlock's CAS compare buffer — the clear commits and the phantom is born
 * (4/caw run 20260705T205922Z: 68× P106-STALE-EX, 0 anchor fires).  Done in
 * ONE grant_meta_lock section, the store either lands BEFORE the unlock's
 * mark+snapshot (so its entry/loop seq checks abort) or observes `releasing`
 * and refuses (caller waits the release out and re-probes).  Returns true
 * when the grant was recorded, false when a release is in flight.
 */
/* v0.6.3 phantom-genesis instrumentation: the DIVERG guards clear OUR OWN
 * holder bit outside the bast pipeline — a silent phantom-EX genesis when the
 * caller's in-core mode stays cached.  Capped always-on for INODE resources
 * (divergence is an anomaly; a flood is itself diagnostic). */
static int caw_diverg_logged;

static bool caw_grant_meta_store_unless_releasing(struct mxfs_dlm_caw_ctx *ctx,
					const struct mxfs_resource_id *resource,
					uint32_t dir_epoch, bool handoff,
					uint64_t dir_block0_fsb, uint32_t dir_block0_gen)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	bool ours;

	if (!ctx->grant_meta)
		return true;	/* no table — degrade to unconditional store semantics */
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	ours = ctx->grant_meta[h].valid &&
	       memcmp(&ctx->grant_meta[h].resource, resource,
		      sizeof(*resource)) == 0;
	if (ours && ctx->grant_meta[h].releasing) {
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		return false;
	}
	/*
	 * sess4 (ccloop 46efd8b6): NEVER claim a bucket out from under a
	 * FOREIGN resource's in-flight release.  grant_meta is a no-chain
	 * hash table; the old claim path wiped the collided entry INCLUDING
	 * its `releasing` mark and its grant_seq — evaporating both v0.6.2
	 * unlock protections mid-CAS (run 065143Z: 339 anchor-less releases
	 * on one 32-node run).  Report busy instead; the caller's existing
	 * false-handling (P-SHORTCUT-RELWAIT 1ms re-probe) waits the
	 * colliding release out.
	 */
	if (!ours && ctx->grant_meta[h].valid &&
	    ctx->grant_meta[h].releasing) {
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		return false;
	}
	if (!ours)
		ctx->grant_meta[h].releasing = false;
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].dir_epoch = dir_epoch;
	ctx->grant_meta[h].handoff = handoff;
	ctx->grant_meta[h].dir_block0_fsb = dir_block0_fsb;
	ctx->grant_meta[h].dir_block0_gen = dir_block0_gen;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return true;
}

/*
 * v0.6.4 — pre-CAS grant intent.  The v0.6.2/3 unlock abort keys off
 * grant_seq, but every slow-path grant bumped it only AFTER the slot CAS —
 * and between them sit caw_check_exclusion + caw_verify_grant_persisted, a
 * full SCSI read: the fresh bit is live on disk for MILLISECONDS with
 * grant_seq un-bumped.  An unlock whose find_slot read lands in that window
 * sees the bit, passes its entry/in-loop/last-instant seq checks (nothing
 * advanced yet), and CAS-clears the brand-new tenure — no regrant-abort,
 * phantom cached EX born (proven: 4/caw iter-12 test2 ino=133 P106-EXGRANT
 * expop=1 @.538467 → P106-STALE-EX held=0 @.539723, abort count 0, no
 * DIVERG/DUP-SLOT).  Bumping IMMEDIATELY BEFORE every bit-adding CAS attempt
 * restores the implication "unlock read our fresh bit ⇒ unlock's next seq
 * check sees a bump" — the abort fires.  A bump for an attempt that then
 * -EAGAINs is harmless: seq aborts err toward LEAVING the bit set, and the
 * stranded-release path (BAST re-arm) self-heals that direction.  Preserves
 * epoch fields; claims the entry only when foreign/invalid.
 */
static void caw_grant_seq_prebump(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	int spin;

	if (!ctx->grant_meta)
		return;
	/*
	 * sess4 (ccloop 46efd8b6): a colliding FOREIGN resource mid-release
	 * owns this bucket; claiming it would wipe its `releasing` mark and
	 * grant_seq — the v0.6.2 protections — mid-CAS.  Wait it out
	 * (bounded; a release CAS is ms-scale) before claiming.  On timeout
	 * fall through to the old lossy claim — bounded degradation beats a
	 * wedge.
	 */
	for (spin = 0; spin < 500; spin++) {
		bool foreign_rel;

		mxfs_pal_mutex_lock(ctx->grant_meta_lock);
		foreign_rel = ctx->grant_meta[h].valid &&
			      ctx->grant_meta[h].releasing &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) != 0;
		if (!foreign_rel) {
			if (!(ctx->grant_meta[h].valid &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) == 0)) {
				memset(&ctx->grant_meta[h], 0,
				       sizeof(ctx->grant_meta[h]));
				ctx->grant_meta[h].resource = *resource;
				ctx->grant_meta[h].valid = true;
			}
			ctx->grant_meta[h].grant_seq =
				++ctx->grant_seq_counter;
			mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
			return;
		}
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		mxfs_pal_sleep_ms(1);
	}
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	memset(&ctx->grant_meta[h], 0, sizeof(ctx->grant_meta[h]));
	ctx->grant_meta[h].resource = *resource;
	ctx->grant_meta[h].valid = true;
	ctx->grant_meta[h].grant_seq = ++ctx->grant_seq_counter;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

/*
 * v0.6.2 — closure of the unlock-vs-regrant race behind P106-STALE-EX
 * (phantom cached EX → two nodes concurrently RMW one dir block → durable
 * dirent loss; genesis proven: P106-EXREL retry at :264909 vs P106-EXGRANT
 * at :265003, the release CAS then cleared the fresh re-grant).  Two local
 * serialization primitives on the existing grant-meta table:
 *
 *  - `releasing`: set for the lifetime of our unlock's CAS loop.  The
 *    acquire path's ALREADY-HELD shortcut must not trust our on-disk bit
 *    while our own unlock is concurrently clearing it (the bit's presence
 *    is a torn read of a release in flight) — it waits the release out
 *    (bounded) and retries the probe.
 *  - `grant_seq`: bumped by every grant-meta store.  The unlock loop
 *    snapshots it at entry and ABORTS (leaving the slot alone) when it
 *    advances — a local acquire re-granted this resource, so the bit now
 *    belongs to the NEW tenure.  The in-core release that follows in the
 *    caller is then an inverse-phantom (in-core NL, disk held), which the
 *    P135-ORPHAN-RELEASE machinery already self-heals on the next BAST.
 */
static uint64_t caw_grant_meta_seq(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	uint64_t seq = 0;

	if (!ctx->grant_meta)
		return 0;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0)
		seq = ctx->grant_meta[h].grant_seq;
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return seq;
}

static void caw_release_mark(struct mxfs_dlm_caw_ctx *ctx,
			     const struct mxfs_resource_id *resource, bool on)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	int spin;

	if (!ctx->grant_meta)
		return;
	/* sess4 (ccloop 46efd8b6): as in caw_grant_seq_prebump — never claim
	 * a bucket from a colliding FOREIGN resource mid-release (wiping its
	 * releasing mark + grant_seq kills the v0.6.2 protections).  Two
	 * concurrent unlocks colliding on one bucket serialize here. */
	for (spin = 0; on && spin < 500; spin++) {
		bool foreign_rel;

		mxfs_pal_mutex_lock(ctx->grant_meta_lock);
		foreign_rel = ctx->grant_meta[h].valid &&
			      ctx->grant_meta[h].releasing &&
			      memcmp(&ctx->grant_meta[h].resource, resource,
				     sizeof(*resource)) != 0;
		if (!foreign_rel)
			goto locked_apply;
		mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
		mxfs_pal_sleep_ms(1);
	}
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
locked_apply:
	if (on) {
		/* claim the entry if it isn't ours (invalid or collision —
		 * the epoch fields of a colliding victim are lossy by design) */
		if (!(ctx->grant_meta[h].valid &&
		      memcmp(&ctx->grant_meta[h].resource, resource,
			     sizeof(*resource)) == 0)) {
			memset(&ctx->grant_meta[h], 0,
			       sizeof(ctx->grant_meta[h]));
			ctx->grant_meta[h].resource = *resource;
			ctx->grant_meta[h].valid = true;
		}
		ctx->grant_meta[h].releasing = true;
	} else if (ctx->grant_meta[h].valid &&
		   memcmp(&ctx->grant_meta[h].resource, resource,
			  sizeof(*resource)) == 0) {
		ctx->grant_meta[h].releasing = false;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
}

static bool caw_grant_meta_get(struct mxfs_dlm_caw_ctx *ctx,
			       const struct mxfs_resource_id *resource,
			       uint32_t *epoch_out, bool *handoff_out)
{
	uint32_t h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	bool hit = false;

	if (!ctx->grant_meta)
		return false;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0) {
		if (epoch_out)
			*epoch_out = ctx->grant_meta[h].dir_epoch;
		if (handoff_out)
			*handoff_out = ctx->grant_meta[h].handoff;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return hit;
}

uint32_t mxfs_dlm_caw_grant_dir_epoch(struct mxfs_dlm_caw_ctx *ctx,
				      const struct mxfs_resource_id *resource)
{
	uint32_t epoch = 0;

	if (!ctx || !resource)
		return 0;
	caw_grant_meta_get(ctx, resource, &epoch, NULL);
	return epoch;
}

/* ccloop(3e02e7dd) sess3: canonical dir block0 query — see the
 * dir_block0_fsb comment in struct mxfs_caw_lock_slot. */
bool mxfs_dlm_caw_grant_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   uint32_t want_gen, uint64_t *fsb_out)
{
	uint32_t h;
	bool hit = false;

	if (fsb_out)
		*fsb_out = 0;
	if (!ctx || !resource || !ctx->grant_meta)
		return false;
	h = resource_hash_raw(resource) % MXFS_CAW_GRANTMETA_SIZE;
	mxfs_pal_mutex_lock(ctx->grant_meta_lock);
	if (ctx->grant_meta[h].valid &&
	    memcmp(&ctx->grant_meta[h].resource, resource,
		   sizeof(*resource)) == 0 &&
	    ctx->grant_meta[h].dir_block0_gen == want_gen &&
	    ctx->grant_meta[h].dir_block0_fsb != 0) {
		if (fsb_out)
			*fsb_out = ctx->grant_meta[h].dir_block0_fsb;
		hit = true;
	}
	mxfs_pal_mutex_unlock(ctx->grant_meta_lock);
	return hit;
}

bool mxfs_dlm_caw_grant_handoff(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				uint32_t *gen_out)
{
	uint32_t epoch = 0;
	bool handoff = false;

	if (gen_out)
		*gen_out = 0;
	if (!ctx || !resource)
		return false;
	if (!caw_grant_meta_get(ctx, resource, &epoch, &handoff))
		return false;
	if (gen_out)
		*gen_out = epoch;
	return handoff;
}

uint32_t mxfs_dlm_caw_grant_seq32(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	uint64_t seq;

	if (!ctx || !resource)
		return 0;
	seq = caw_grant_meta_seq(ctx, resource);
	if (!seq)
		return 0;
	/* fold to the caller's u32 token; never collapse a live tenure to
	 * the "no tenure" sentinel 0 */
	return (uint32_t)seq ?: 1;
}

/*
 * interactive session 2026-07-13: backed by ctx->orphan_clock, NOT
 * grant_meta — a dedicated table with its own mxfs_pal_spinlock_t (never
 * sleeps), because callers (mxfs_dlm_bast_process via
 * mxfs_v5_dlm_inode_orphan_clock_get/set) run with the caller's own
 * xfs_inode spinlock held.  Sharing grant_meta's mutex would risk
 * scheduling-while-atomic.  Collision handling is a simple claim-on-mismatch
 * (unlike grant_meta's wait-out-foreign-release dance) since these are
 * timing hints, not CAS-protected coherency state — the worst case of a
 * lost sample is one extra ~3s cycle before a force-timeout re-arms, not a
 * correctness bug.
 */
uint64_t mxfs_dlm_caw_orphan_clock_get(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       bool starve)
{
	uint32_t h;
	uint64_t val = 0;

	if (!ctx || !resource || !ctx->orphan_clock)
		return 0;
	h = resource_hash_raw(resource) % MXFS_CAW_ORPHANCLOCK_SIZE;
	mxfs_pal_spinlock_lock(ctx->orphan_clock_lock);
	if (ctx->orphan_clock[h].valid &&
	    memcmp(&ctx->orphan_clock[h].resource, resource,
		   sizeof(*resource)) == 0)
		val = starve ? ctx->orphan_clock[h].bast_starve_since_ns
			     : ctx->orphan_clock[h].orphan_since_ns;
	mxfs_pal_spinlock_unlock(ctx->orphan_clock_lock);
	return val;
}

void mxfs_dlm_caw_orphan_clock_set(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   bool starve, uint64_t val)
{
	uint32_t h;

	if (!ctx || !resource || !ctx->orphan_clock)
		return;
	h = resource_hash_raw(resource) % MXFS_CAW_ORPHANCLOCK_SIZE;
	mxfs_pal_spinlock_lock(ctx->orphan_clock_lock);
	if (!(ctx->orphan_clock[h].valid &&
	      memcmp(&ctx->orphan_clock[h].resource, resource,
		     sizeof(*resource)) == 0)) {
		/* claim the bucket (invalid, or a foreign resource — rare
		 * per MXFS_CAW_ORPHANCLOCK_SIZE's sizing, harmless either
		 * way: the evicted resource's clock just restarts) */
		memset(&ctx->orphan_clock[h], 0,
		       sizeof(ctx->orphan_clock[h]));
		ctx->orphan_clock[h].resource = *resource;
		ctx->orphan_clock[h].valid = true;
	}
	if (starve)
		ctx->orphan_clock[h].bast_starve_since_ns = val;
	else
		ctx->orphan_clock[h].orphan_since_ns = val;
	mxfs_pal_spinlock_unlock(ctx->orphan_clock_lock);
}

/* ─── Find slot for resource (hash + linear probe) ─── */

static int find_slot_skip(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource,
		      uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out,
		      uint32_t *empty_out, uint32_t skip_idx,
		      uint32_t *last_read_out)
{
	uint32_t base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	struct mxfs_caw_lock_slot *span;
	uint32_t span_base = UINT32_MAX, span_n = 0;
	uint32_t i;
	int rc;

	*empty_out = UINT32_MAX;
	if (last_read_out)
		*last_read_out = UINT32_MAX;

	/* NULL span → the per-slot read path below still works unchanged */
	span = mxfs_pal_alloc(MXFS_CAW_PROBE_SPAN * MXFS_CAW_SLOT_SIZE);

	/*
	 * v0.5.3 hint fast path: one content-validated read of the
	 * last-known slot instead of the chain walk.  A hit requires the
	 * hinted slot to STILL hold a live entry for exactly this
	 * resource — peers cannot move a live entry to a different slot,
	 * they can only release it (tombstone) or, after a release, the
	 * resource may get re-claimed elsewhere in the chain; both cases
	 * fail the content check and fall through to the full walk.
	 * Skipped when the caller excludes a slot (skip_idx) — that path
	 * needs the true chain scan semantics.
	 */
	if (skip_idx == UINT32_MAX) {
		uint32_t hint;

		if (slot_hint_get(ctx, resource, &hint)) {
			rc = read_slot(ctx, hint, data_out);
			if (rc == 0 &&
			    data_out->magic == MXFS_CAW_MAGIC &&
			    memcmp(&data_out->resource, resource,
				   sizeof(*resource)) == 0) {
				if (last_read_out)
					*last_read_out = hint;
				*slot_out = hint;
				if (span)
					mxfs_pal_free(span);
				return 0;
			}
			/* stale hint — full walk below refreshes it */
		}
	}

	/*
	 * Open-addressing linear probe.  Deletes write a tombstone (magic =
	 * MXFS_CAW_TOMBSTONE_MAGIC) so that the probe chain remains
	 * traversable past freed slots.  Only a truly-empty slot (magic == 0
	 * — never used) terminates the probe.  An earlier zero-on-delete
	 * design corrupted lookups: a freed slot looked identical to a
	 * never-used slot, so probes terminated early and missed live
	 * entries past the gap, allowing the same resource to be claimed in
	 * two different slots concurrently — i.e. two nodes briefly holding
	 * the same lock EX (bug B in state.md session 8).
	 */
	for (i = 0; i < MXFS_CAW_MAX_SLOTS; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;

		if (span && (span_base == UINT32_MAX || idx < span_base ||
			     idx >= span_base + span_n)) {
			/* refill: never wrap inside one span read */
			uint32_t n = MXFS_CAW_MAX_SLOTS - idx;

			if (n > MXFS_CAW_PROBE_SPAN)
				n = MXFS_CAW_PROBE_SPAN;
			if (read_slot_span(ctx, idx, n, span) == 0) {
				span_base = idx;
				span_n = n;
			} else {
				/* span I/O trouble — this walk degrades to
				 * the per-slot path (its own retries) */
				mxfs_pal_free(span);
				span = NULL;
				span_base = UINT32_MAX;
				span_n = 0;
			}
		}

		if (span && idx >= span_base && idx < span_base + span_n) {
			*data_out = span[idx - span_base];
			if (slot_appears_corrupt(data_out)) {
				/* re-read + repair via the existing path */
				rc = read_slot(ctx, idx, data_out);
				if (rc) {
					mxfs_pal_free(span);
					return rc;
				}
			}
		} else {
			rc = read_slot(ctx, idx, data_out);
			if (rc) {
				if (span)
					mxfs_pal_free(span);
				return rc;
			}
		}
		if (last_read_out)
			*last_read_out = idx;

		if (data_out->magic == MXFS_CAW_MAGIC) {
			if (memcmp(&data_out->resource, resource,
				   sizeof(*resource)) == 0) {
				*slot_out = idx;
				slot_hint_store(ctx, resource, idx);
				if (span)
					mxfs_pal_free(span);
				return 0; /* Found */
			}
			/*
			 * sess131: a live entry whose resource belongs to a
			 * DIFFERENT volume is a pre-mkfs ghost record (an
			 * old-generation node wrote it after the mkfs zero
			 * pass).  Nothing in this generation will ever look
			 * it up or release it — treat it like a tombstone:
			 * recyclable insertion point, probe continues.  The
			 * insert path CAWs against the slot's actual content
			 * (Bug 93), so recycling stays race-safe even if the
			 * ghost is still writing.
			 */
			if (data_out->resource.volume != resource->volume) {
				if (*empty_out == UINT32_MAX && idx != skip_idx)
					*empty_out = idx;
				continue;
			}
			continue; /* live entry for different resource */
		}

		if (data_out->magic == MXFS_CAW_TOMBSTONE_MAGIC) {
			/* Recyclable: prefer the first tombstone seen as
			 * insertion point, but keep probing — the resource
			 * may live further down the chain. */
			if (*empty_out == UINT32_MAX && idx != skip_idx)
				*empty_out = idx;
			continue;
		}

		/* Truly empty (never used).  Probe chain ends here:
		 * nothing past this point can be a live entry for the
		 * resource — find_slot's invariant is that any live entry
		 * is reachable from its hash base via an unbroken chain of
		 * live-or-tombstone slots. */
		if (*empty_out == UINT32_MAX && idx != skip_idx)
			*empty_out = idx;
		break;
	}

	if (span)
		mxfs_pal_free(span);
	return -ENOENT; /* Not found, empty_out has insertion point */
}

static int find_slot(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource,
		      uint32_t *slot_out, struct mxfs_caw_lock_slot *data_out,
		      uint32_t *empty_out)
{
	return find_slot_skip(ctx, resource, slot_out, data_out, empty_out,
			      UINT32_MAX, NULL);
}

/*
 * sess19 (ccloop 4eef1f39): read the current on-disk generation (ABA counter)
 * for a resource's lock slot.  Used as a SHARED cross-node epoch for AG
 * free-space coherency — see pag_dlm_disk_gen_seen in xfs_ag.h.  The caller
 * (AG fresh-acquire path) holds EX when it calls this, so the value is stable
 * (no peer can modify the slot while we hold it).  Returns 0 + *out_gen on
 * success, -ENOENT if the slot does not exist (resource never locked), or a
 * negative I/O error.
 */
int mxfs_dlm_caw_read_generation(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint64_t *out_gen)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx, empty_idx;
	int rc;

	if (!ctx || !resource || !out_gen)
		return -EINVAL;

	slot = kmalloc(sizeof(*slot), GFP_NOFS);
	if (!slot)
		return -ENOMEM;

	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc == 0)
		*out_gen = (uint64_t)slot->generation;
	kfree(slot);
	return rc;
}

/*
 * ccloop(3e02e7dd) sess3: WRITE-ONCE publish of the canonical dir block0 for
 * incarnation `gen` — see the dir_block0_fsb comment in struct
 * mxfs_caw_lock_slot.  Caller holds EX on the inode (the sf->block converter,
 * right after allocating the new block0); the resource's lock-grant state
 * cannot change under us, but the block0 field is published via its own
 * small CAS rather than piggybacked on the acquire CAS, since the fsb is
 * not known until partway through the conversion transaction.  A no-op if a
 * value is already published for this exact gen (first publisher wins); a
 * stored gen from a DIFFERENT incarnation (stale leftover, or unset) is
 * always safely overwritten since only one incarnation is ever live.
 */
void mxfs_dlm_caw_set_dir_block0(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource,
				 uint64_t fsb, uint32_t gen)
{
	struct mxfs_caw_lock_slot *cur, *new;
	uint32_t slot_idx, empty_idx;
	int retry, rc;

	if (!ctx || !resource || ctx->single_node || !fsb)
		return;

	cur = kmalloc(sizeof(*cur), GFP_NOFS);
	new = kmalloc(sizeof(*new), GFP_NOFS);
	if (!cur || !new)
		goto out;

	for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
		rc = find_slot(ctx, resource, &slot_idx, cur, &empty_idx);
		if (rc)
			break;	/* no live slot for a resource we hold EX on —
				 * should not happen; nothing to publish into */
		if (cur->dir_block0_gen == gen && cur->dir_block0_fsb != 0)
			break;	/* already published for this incarnation */
		*new = *cur;
		new->dir_block0_fsb = fsb;
		new->dir_block0_gen = gen;
		new->generation++;
		rc = caw_slot(ctx, slot_idx, cur, new);
		if (rc == -EAGAIN)
			continue;
		if (rc == 0)
			pr_warn_ratelimited(
			    "mxfs: P-BLOCK0-PUBLISH ino=%llu fsb=%llu gen=%u — canonical dir block0 published\n",
			    (unsigned long long)resource->ino,
			    (unsigned long long)fsb, gen);
		break;
	}
out:
	kfree(cur);
	kfree(new);
}

/*
 * sess47: CLAIM-RACE detector (RULE-4 diagnostic for the bnobt stale-pristine
 * clobber).  Scan the ENTIRE probe chain (hash base -> first truly-empty slot,
 * tombstones DON'T terminate) and count LIVE slots whose resource matches
 * `resource`.  The find_slot invariant is exactly-one; >1 means two nodes each
 * claimed a DIFFERENT empty slot for the same resource (each slot internally
 * exclusive, so per-slot exclusion checks P87/CAW-EXCL stay silent) => two
 * nodes hold the resource EX via different slots => one never BASTs the other
 * => stale cached AG buffer written back => corruption.  Gemini-confirmed:
 * must scan the WHOLE chain (the duplicate can be EARLIER OR LATER than ours).
 *
 * Returns the number of live slots found for the resource and, if >1, fills
 * dup_slots[0..min(n,DUPMAX)-1] with their indices.  Bounded scan (caps at
 * MXFS_CAW_CLAIMRACE_SCAN_MAX probes) so a pathological chain can't stall the
 * acquire; logs if the cap is hit.  One probe-chain scan per FRESH claim only
 * (not the hot cached/found path), so the steady-state cost is low.
 */
#define MXFS_CAW_CLAIMRACE_SCAN_MAX 4096
static int caw_count_resource_slots(struct mxfs_dlm_caw_ctx *ctx,
				    const struct mxfs_resource_id *resource,
				    uint32_t *dup_slots, int dupmax,
				    uint64_t *holders_ex_or)
{
	struct mxfs_caw_lock_slot *s;
	uint32_t base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	uint32_t i;
	int n = 0;
	bool capped = false;

	if (holders_ex_or)
		*holders_ex_or = 0;
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -1;

	for (i = 0; i < MXFS_CAW_MAX_SLOTS; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;

		if (i >= MXFS_CAW_CLAIMRACE_SCAN_MAX) {
			capped = true;
			break;
		}
		if (read_slot(ctx, idx, s) != 0)
			continue;
		if (s->magic == MXFS_CAW_MAGIC) {
			if (memcmp(&s->resource, resource,
				   sizeof(*resource)) == 0) {
				if (n < dupmax)
					dup_slots[n] = idx;
				if (holders_ex_or)
					*holders_ex_or |= s->holders_ex;
				n++;
			}
			continue;
		}
		if (s->magic == MXFS_CAW_TOMBSTONE_MAGIC)
			continue;
		/* truly-empty: probe chain ends here */
		break;
	}
	if (capped)
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: CAW-CLAIMRACE-SCAN capped at %d probes "
			"(type=%u ag=%u ino=%llu) — chain longer than scan cap",
			MXFS_CAW_CLAIMRACE_SCAN_MAX, resource->type,
			resource->ag_number,
			(unsigned long long)resource->ino);
	mxfs_pal_free(s);
	return n;
}

/* ─── Local held lock tracking ─── */

static void track_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);

	/* Avoid duplicates */
	for (i = 0; i < ctx->held.count; i++) {
		if (ctx->held.slots[i] == slot_index) {
			mxfs_pal_mutex_unlock(ctx->held.lock);
			return;
		}
	}

	if (ctx->held.count < ctx->max_held)
		ctx->held.slots[ctx->held.count++] = slot_index;
	else
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: disk lock table full (%d entries), "
			     "cannot acquire additional lock",
			     ctx->max_held);

	mxfs_pal_mutex_unlock(ctx->held.lock);
}

static void untrack_held(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_index)
{
	int i;

	mxfs_pal_mutex_lock(ctx->held.lock);

	for (i = 0; i < ctx->held.count; i++) {
		if (ctx->held.slots[i] == slot_index) {
			ctx->held.slots[i] =
				ctx->held.slots[--ctx->held.count];
			break;
		}
	}

	mxfs_pal_mutex_unlock(ctx->held.lock);
}

/* ─── UDP BAST multicast send ─── */

static void caw_send_bast_mcast(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource,
				  uint8_t requested_mode)
{
	struct mxfs_caw_bast_notify msg;

	if (!ctx->bast_mcast_sock)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.magic = MXFS_BAST_MAGIC;
	msg.version = 1;
	msg.resource = *resource;
	msg.requester = ctx->local_node;
	msg.requested_mode = requested_mode;
	memcpy(msg.volume_uuid, ctx->volume_uuid, 16);

	/* Fire and forget — best effort hint */
	mxfs_pal_udp_sendto(ctx->bast_mcast_sock, &msg, sizeof(msg),
			     MXFS_DISCOVERY_MCAST, MXFS_CAW_BAST_PORT);
}

/* ccloop 72513a13 sess3: GRANT NUDGE send — fired after a successful slot
 * CAW that a blocked peer is waiting on (release, tombstone, handoff or a
 * self-grant that leaves other waiters grantable).  Wakes their poll sleep
 * immediately; the disk poll remains the lossless backstop. */
static void caw_send_grant_mcast(struct mxfs_dlm_caw_ctx *ctx,
				 const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_bast_notify msg;

	if (!ctx->bast_mcast_sock)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.magic = MXFS_GRANT_MAGIC;
	msg.version = 1;
	msg.resource = *resource;
	msg.requester = ctx->local_node;
	msg.requested_mode = 0;
	memcpy(msg.volume_uuid, ctx->volume_uuid, 16);

	mxfs_pal_udp_sendto(ctx->bast_mcast_sock, &msg, sizeof(msg),
			     MXFS_DISCOVERY_MCAST, MXFS_CAW_BAST_PORT);
}

/* Snapshot the nudge sequence BEFORE the caller's slot read; the paired
 * caw_nudge_wait() then cannot sleep through a nudge that raced in
 * between (it re-checks the seq under the lock before waiting). */
static uint64_t caw_nudge_prepare(struct mxfs_dlm_caw_ctx *ctx)
{
	uint64_t seq;

	if (!ctx->nudge_lock)
		return 0;
	mxfs_pal_mutex_lock(ctx->nudge_lock);
	seq = ctx->nudge_seq;
	mxfs_pal_mutex_unlock(ctx->nudge_lock);
	return seq;
}

static void caw_nudge_wait(struct mxfs_dlm_caw_ctx *ctx, uint64_t seen_seq,
			   uint32_t ms)
{
	if (!ctx->nudge_lock || !ctx->nudge_cond) {
		mxfs_pal_sleep_ms(ms);
		return;
	}
	mxfs_pal_mutex_lock(ctx->nudge_lock);
	if (ctx->nudge_seq == seen_seq) {
		uint64_t t0 = mxfs_pal_time_ms();

		mxfs_pal_cond_timedwait(ctx->nudge_cond, ctx->nudge_lock, ms);
		if (ctx->nudge_seq == seen_seq &&
		    mxfs_pal_time_ms() - t0 < 1) {
			/* Interruptible wait returned immediately with no
			 * nudge (pending signal).  Burn the interval the way
			 * the old uninterruptible sleep_ms did so the acquire
			 * loop cannot busy-spin slot reads until timeout. */
			mxfs_pal_mutex_unlock(ctx->nudge_lock);
			mxfs_pal_sleep_ms(ms);
			return;
		}
	}
	mxfs_pal_mutex_unlock(ctx->nudge_lock);
}

/* sess39: forward decl — defined just before mxfs_dlm_caw_lock. */
static void caw_check_exclusion(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				const struct mxfs_caw_lock_slot *slot,
				uint8_t mode);
static void caw_verify_grant_persisted(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       uint32_t slot_idx, uint8_t mode);

/*
 * sess48 (ccloop 14d31183) PROVEN ROOT FIX — phantom EX-waiter leak.
 *
 * When a waiter GIVES UP (grant timeout, retry exhaustion) it MUST drop its
 * own bit from slot->waiters.  Otherwise a stale EX-waiter bit makes every
 * peer's defer_for_waiter (mxfs_dlm_caw_lock) defer fresh PR/SHARED acquires
 * FOREVER — proven this session: a 16-node barrier-directory wedge where the
 * slot froze at waiter_mode=EX h_ex=0 h_pr=multi, every blocked thread across
 * all 16 nodes was a SHARED reader (find/ls readdir), and NO thread anywhere
 * in the cluster was actually requesting EX.  The two EX "waiters" were
 * orphaned bits; defer_for_waiter then starved all readers → cluster phase
 * >600s → posix_semantics_multi16 FAIL.
 *
 * The OLD cleanup (in caw_wait_for_grant timeout) was a bounded 10-iteration
 * CAS loop.  Under the 16-node CAS storm on a hot shared-dir slot all 10
 * compare-and-write attempts lose the race to peers' concurrent writes, so the
 * bit is left set permanently; once the contention burst ends the slot
 * generation freezes with the orphan bit still there and nothing ever clears
 * it.  Retry with backoff until a FRESH read confirms our bit is clear (or the
 * slot is gone).  Generously bounded so a genuinely wedged slot cannot pin
 * this thread, but far longer than any real contention burst — the common case
 * exits immediately (bit already clear or CAS wins on the first try).
 */
static void caw_drop_own_waiter(struct mxfs_dlm_caw_ctx *ctx, uint32_t slot_idx)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	int attempt;
	uint32_t backoff = 1;

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return;
	}

	for (attempt = 0; attempt < 1000; attempt++) {
		int rc = read_slot(ctx, slot_idx, cur_slot);

		if (rc)
			break;	/* slot read error — give up */
		if (cur_slot->magic != MXFS_CAW_MAGIC)
			break;	/* slot gone/tombstoned — nothing to clear */
		if (!(cur_slot->waiters & ctx->node_bit))
			break;	/* our bit already clear — done */

		*new_slot = *cur_slot;
		new_slot->waiters &= ~ctx->node_bit;
		new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50: drop our exclusive-waiter bit too */
		new_slot->waiter_mode = recompute_waiter_mode(new_slot);
		new_slot->generation++;
		new_slot->last_modified_ms = mxfs_pal_time_ms();

		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		if (rc == 0)
			break;			/* cleared */
		if (rc != -EAGAIN)
			break;			/* hard error — give up */

		/* Lost the CAS race against a concurrent slot write — back off
		 * and re-read.  We keep trying: leaving our bit set is a
		 * cluster-wide liveness bug, not a best-effort nicety. */
		mxfs_pal_sleep_ms(backoff);
		if (backoff < 8)
			backoff *= 2;
	}

	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
}

/*
 * sess2(ccloop 26c41354) FAIR HANDOFF — pick ONE round-robin next EX waiter.
 * Returns the bit of the first EX waiter strictly after the releaser's own
 * node bit (cyclic over 64 positions), so successive releases rotate through
 * all EX waiters and no node is starved by the self-promote free-for-all in
 * caw_wait_for_grant (16-node victim-node data loss; P131-WAITLONG).  Returns
 * 0 if there are no EX waiters.
 */
static uint64_t caw_pick_next_ex_waiter(uint64_t ex_waiters, uint64_t self_bit)
{
	int self_pos = 0, i;

	if (!ex_waiters)
		return 0;
	if (self_bit) {
		while (self_pos < 63 && !((self_bit >> self_pos) & 1ULL))
			self_pos++;
	}
	for (i = 1; i <= 64; i++) {
		int pos = (self_pos + i) & 63;
		uint64_t b = 1ULL << pos;

		if (ex_waiters & b)
			return b;
	}
	return 0;
}

/*
 * v0.10.36: one poll step of the acquire wait.  Inside the inode
 * fresh-handoff window (first MXFS_CAW_INODE_FASTPOLL_MS of the wait) poll
 * at a fast fixed interval — a BAST-driven handoff completes in ~10-25ms
 * and the exponential backoff parked the waiter up to 25ms past the slot
 * going free (measured 42-46ms/unlink, 32-node dir_reuse rm).  Beyond the
 * window, exponential backoff exactly as before.
 */
static void caw_acquire_poll_sleep(struct mxfs_dlm_caw_ctx *ctx,
				   const struct mxfs_resource_id *resource,
				   uint64_t start, uint32_t *poll_ms)
{
	extern int mxfs_caw_inode_fastpoll;
	/* ccloop 72513a13 sess3: sleep interruptibly on the GRANT-NUDGE
	 * cond so a releaser's multicast wakes us NOW instead of after the
	 * poll interval (kprobe-proven 4.6s/6.0s of an 8-node create phase
	 * was this sleep).  A nudge racing in between the caller's slot
	 * read and this prepare is missed and costs one interval — bounded
	 * by the poll backstop; accepted for a minimal-risk diff. */
	uint64_t seq = caw_nudge_prepare(ctx);

	if (mxfs_caw_inode_fastpoll &&
	    resource->type == MXFS_LTYPE_INODE &&
	    mxfs_pal_time_ms() - start < MXFS_CAW_INODE_FASTPOLL_MS) {
		caw_nudge_wait(ctx, seq, MXFS_CAW_INODE_FASTPOLL_INTERVAL_MS);
		return;
	}
	caw_nudge_wait(ctx, seq, *poll_ms);
	if (*poll_ms < MXFS_CAW_POLL_MAX_MS) {
		*poll_ms *= 2;
		if (*poll_ms > MXFS_CAW_POLL_MAX_MS)
			*poll_ms = MXFS_CAW_POLL_MAX_MS;
	}
}

/* ─── Wait for lock grant (poll disk until compatible or timeout) ─── */

static int caw_wait_for_grant(struct mxfs_dlm_caw_ctx *ctx,
			       uint32_t slot_idx,
			       const struct mxfs_resource_id *resource,
			       uint8_t mode)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint64_t start = mxfs_pal_time_ms();
	uint32_t poll_ms = MXFS_CAW_POLL_INITIAL_MS;
	/* v0.5.3: the registration-time UDP BAST hint is sent ONCE; if that
	 * packet is lost the holder only discovers the waiter via its disk
	 * poll.  Re-send the hint every MXFS_CAW_BAST_RESEND_MS while still
	 * blocked — network-only, no extra disk I/O — so the holder-side
	 * idle disk poll can be relaxed (MXFS_CAW_BAST_POLL_RELAX_MS)
	 * without widening the lost-packet recovery window. */
	uint64_t last_bast_ms = mxfs_pal_time_ms();
	int bast_resends = 0;
	int rc;
	uint32_t prev_magic = 0;
	uint64_t prev_gen = 0;
	uint64_t prev_hex = 0;
	uint64_t prev_hpr = 0;
	uint8_t prev_granted = 0;
	bool first_iter = true;
	bool wait_handoff = false;	/* v0.6.0 EX-handoff epoch observation */
	uint64_t last_stuck_dump_ms = 0;	/* v0.10.43 P-ACQ-STUCK throttle */

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}

	if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P13-INSTR GRANT-WAIT-START ino=%llu slot=%u "
			"want_mode=%u t_ms=%llu",
			(unsigned long long)resource->ino, slot_idx, mode,
			(unsigned long long)start);
	}

	bool slot_seen = false;
	uint64_t ext_last_log_ms = 0;
	/* sess8 (ccloop 72513a13) T1 dead-time anatomy: stamp the FIRST
	 * re-read where the slot was already grantable for `mode`, and count
	 * fair-handoff ticket deferrals taken while grantable.  At grant,
	 * P138-WAIT reports ffw_ms (grantable->grant claim-side latency) and
	 * ytd so the 113ms-p50 inter-tenure gap attributes to (machinery |
	 * ticket-defer | late-arrival) from dmesg alone. */
	uint64_t first_compat_ms = 0;
	int yt_defer = 0;

	for (;;) {
		uint64_t wait_el = mxfs_pal_time_ms() - start;

		if (wait_el >= MXFS_CAW_WAIT_TIMEOUT_MS) {
			/* ccloop 72513a13 sess2 LIVENESS EXTENSION (see
			 * MXFS_CAW_WAIT_HARDCAP_MS in dlm_caw.h): past the
			 * base timeout, keep waiting ONLY while every
			 * blocking holder is provably heartbeating.  Dead
			 * holders get purged by lease expiry (slot bits
			 * cleared -> we promote); a no-holder stall (CAS
			 * storm / waiter-gating) and a live-but-wedged
			 * holder past the hard cap still time out. */
			uint64_t blockers = 0;

			if (slot_seen)
				blockers = (cur_slot->holders_ex |
					    cur_slot->holders_pw |
					    cur_slot->holders_pr |
					    cur_slot->holders_cw |
					    cur_slot->holders_cr) &
					   ~ctx->node_bit;
			if (wait_el >= MXFS_CAW_WAIT_HARDCAP_MS ||
			    !blockers || !ctx->holders_alive_fn ||
			    !ctx->holders_alive_fn(ctx->holders_alive_data,
						   blockers))
				break;
			if (mxfs_pal_time_ms() - ext_last_log_ms > 10000) {
				ext_last_log_ms = mxfs_pal_time_ms();
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P-WAIT-EXTEND type=%u ino=%llu ag=%u want=%u el_ms=%llu blockers=%llx — holders alive; extending past base timeout",
				    resource->type,
				    (unsigned long long)resource->ino,
				    resource->ag_number, mode,
				    (unsigned long long)wait_el,
				    (unsigned long long)blockers);
			}
		}

		if (!ctx->running) {
			rc = -ESHUTDOWN;
			goto out;
		}

		rc = read_slot(ctx, slot_idx, cur_slot);
		if (rc)
			goto out;
		slot_seen = true;

		/* v0.10.43 (RULE-4): when an INODE acquire is stuck far past a
		 * normal handoff, dump the FULL on-disk slot state periodically
		 * (unconditional, ratelimited) so the holderless-slot wedge at
		 * the dir-reuse boundary is diagnosable without instr=1 — shows
		 * whether waiters/waiters_ex/yield_to is what blocks promotion. */
		if (resource->type == MXFS_LTYPE_INODE) {
			uint64_t el = mxfs_pal_time_ms() - start;
			if (el > 15000 &&
			    mxfs_pal_time_ms() - last_stuck_dump_ms > 8000) {
				last_stuck_dump_ms = mxfs_pal_time_ms();
				pr_warn_ratelimited(
				    "mxfs: P-ACQ-STUCK ino=%llu slot=%u want=%u el_ms=%llu magic=%x gen=%llu gm=%u hex=%llx hpw=%llx hpr=%llx w=%llx wex=%llx yt=%llx ysm=%llu streak=%u\n",
				    (unsigned long long)resource->ino, slot_idx,
				    mode, (unsigned long long)el, cur_slot->magic,
				    (unsigned long long)cur_slot->generation,
				    cur_slot->granted_mode,
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pw,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters,
				    (unsigned long long)cur_slot->waiters_ex,
				    (unsigned long long)cur_slot->yield_to,
				    (unsigned long long)cur_slot->yield_set_ms,
				    cur_slot->ex_grant_streak);
			}
		}

		/* v0.5.3: periodic UDP BAST re-send while blocked (see above).
		 * sess8: DO NOT shorten this cadence.  Flat 25ms and a
		 * 4x25ms leading burst both regressed cc@32 (60s -> 84-91s):
		 * most waits are <100ms, so any leading burst multiplies the
		 * whole cluster's hint volume, and the hint flood shares the
		 * recv socket + recv thread with the GRANT nudges — drowning
		 * the very wakeups the handoff depends on. */
		if (mxfs_pal_time_ms() - last_bast_ms >= MXFS_CAW_BAST_RESEND_MS) {
			caw_send_bast_mcast(ctx, resource, mode);
			bast_resends++;
			last_bast_ms = mxfs_pal_time_ms();
		}

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on() &&
		    (first_iter ||
		     cur_slot->magic != prev_magic ||
		     cur_slot->generation != prev_gen ||
		     cur_slot->holders_ex != prev_hex ||
		     cur_slot->holders_pr != prev_hpr ||
		     cur_slot->granted_mode != prev_granted)) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR GRANT-POLL ino=%llu slot=%u "
				"magic=%x gen=%llu hex=%llx hpr=%llx "
				"granted=%u want=%u t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				cur_slot->magic,
				(unsigned long long)cur_slot->generation,
				(unsigned long long)cur_slot->holders_ex,
				(unsigned long long)cur_slot->holders_pr,
				cur_slot->granted_mode, mode,
				(unsigned long long)mxfs_pal_time_ms());
			prev_magic = cur_slot->magic;
			prev_gen = cur_slot->generation;
			prev_hex = cur_slot->holders_ex;
			prev_hpr = cur_slot->holders_pr;
			prev_granted = cur_slot->granted_mode;
			first_iter = false;
		}

		/* Slot cleared? Resource gone */
		if (cur_slot->magic != MXFS_CAW_MAGIC) {
			rc = -ENOENT;
			goto out;
		}

		/* v0.10.44 ROOT FIX (dir_reuse@32 cluster wedge): if the slot
		 * shows OUR OWN bit held in a mode that CONFLICTS with what we
		 * are waiting for, the blocker is us — a STALE SELF-HOLD.  This
		 * happens at the dir-reuse boundary: rank1 frees+recreates the
		 * shared dir inode; a peer that held EX on the freed incarnation
		 * has its in-core DLM state reset to NL (fresh reclaimed inode)
		 * WITHOUT clearing its on-disk holder bit (resource_id carries
		 * no inode-generation, so the reused inode maps to the SAME CAW
		 * slot and inherits the prior tenure's bit).  We can NEVER become
		 * compatible waiting for ourselves — the whole cluster then wedges
		 * 360s on that inode (PROVEN B6: test32 held bit31 EX in slot
		 * 51115, in-core NONE/NL, all 32 nodes starved -> rc=-110).
		 * Return -EDEADLK so mxfs_dlm_ilock_begin routes through the
		 * proven bast_process recovery (drain + clear the on-disk bit +
		 * i_dlm_mode=NL) and retries from a clean NL state — identical to
		 * the main-loop upgrade-deadlock resolver. */
		if (node_held_mode(cur_slot, ctx->node_bit) != MXFS_LOCK_NL &&
		    !is_compatible(cur_slot, mode)) {
			if (resource->type == MXFS_LTYPE_INODE)
				pr_warn_ratelimited(
				    "mxfs: P-SELF-STALE-EDEADLK ino=%llu slot=%u want=%u held=%u hex=%llx hpr=%llx w=%llx — self-hold blocks own acquire; -EDEADLK to clear\n",
				    (unsigned long long)resource->ino, slot_idx,
				    mode,
				    node_held_mode(cur_slot, ctx->node_bit),
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters);
			rc = -EDEADLK;
			goto out;
		}

		if (is_compatible(cur_slot, mode)) {
			if (!first_compat_ms)
				first_compat_ms = mxfs_pal_time_ms();
			/*
			 * sess2(ccloop 26c41354) FAIR HANDOFF: honor the
			 * round-robin EX ticket the releaser set in yield_to.
			 * If a DIFFERENT node is the chosen next (yield_to set,
			 * our bit absent) and we are a FRESH waiter (we hold NL
			 * — an upgrader keeps conversion priority, sess130), do
			 * NOT self-promote: let the chosen EX waiter go first.
			 * This replaces the free-for-all where an unlucky node's
			 * poll cadence never wins (16-node victim-node loss).  A
			 * STALE ticket (>5s: chosen node died) is CAS-cleared
			 * here so no waiter deadlocks.  Inode locks only.
			 */
			if (mxfs_caw_fair_handoff &&
			    resource->type == MXFS_LTYPE_INODE &&
			    cur_slot->yield_to != 0 &&
			    !(cur_slot->yield_to & ctx->node_bit) &&
			    node_held_mode(cur_slot, ctx->node_bit) ==
				MXFS_LOCK_NL) {
				uint64_t yt_now = mxfs_pal_time_real_ms();
				uint64_t yt_age = (yt_now > cur_slot->yield_set_ms) ?
						  (yt_now - cur_slot->yield_set_ms) : 0;

				if (yt_age < MXFS_CAW_YIELD_TIMEOUT_MS) {
					/* not our turn — keep waiting */
					yt_defer++;
					caw_acquire_poll_sleep(ctx, resource,
							       start,
							       &poll_ms);
					continue;
				}
				/* stale ticket (chosen node died OR a persistent
				 * pr_w streak-yield aged out — v0.10.40): clear
				 * + retry.  This is the safety valve that breaks
				 * the EX-starvation deadlock. */
				if (resource->type == MXFS_LTYPE_INODE)
					pr_warn_ratelimited(
					    "mxfs: P-YT-STALECLR ino=%llu yt=%llx age_ms=%llu req_mode=%u\n",
					    (unsigned long long)resource->ino,
					    (unsigned long long)cur_slot->yield_to,
					    (unsigned long long)yt_age,
					    mode);
				*new_slot = *cur_slot;
				new_slot->yield_to = 0;
				new_slot->yield_set_ms = 0;
				new_slot->generation++;
				(void)caw_slot(ctx, slot_idx, cur_slot,
					       new_slot);
				continue;
			}
			/* Try to promote from waiter to holder */
			*new_slot = *cur_slot;
			new_slot->waiters &= ~ctx->node_bit;
			new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50: no longer an exclusive waiter */

			/* Clear our bit from yield_to — we were yielded to and are taking our turn */
			if (new_slot->yield_to & ctx->node_bit)
				new_slot->yield_to &= ~ctx->node_bit;

			{
				uint64_t *hp = holders_for_mode(new_slot, mode);
				if (hp)
					*hp |= ctx->node_bit;
			}
			caw_grant_streak_note(new_slot, mode);
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->waiter_mode =
				recompute_waiter_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			wait_handoff = caw_grant_epoch_update(ctx, new_slot,
							      mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (rc == -EAGAIN)
				continue; /* Someone else changed it, retry */
			if (rc)
				goto out;

			caw_check_exclusion(ctx, resource, new_slot, mode);
			caw_verify_grant_persisted(ctx, resource, slot_idx, mode);
			track_held(ctx, slot_idx);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     wait_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			/* ccloop 72513a13 sess3: our grant CAW just changed
			 * the slot; other queued waiters (e.g. the rest of a
			 * PR class joining a shared grant) should re-read now
			 * rather than after their poll interval. */
			if (new_slot->waiters & ~ctx->node_bit)
				caw_send_grant_mcast(ctx, resource);
			rc = 0; /* Granted */
			/* sess131 P131-WAITLONG: always-on starvation probe —
			 * any grant that waited >1s is a fairness defect
			 * (zero_silent_loss 16-node storm tail analysis). */
			if (caw_instr_on() &&
			    mxfs_pal_time_ms() - start > 1000)
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P131-WAITLONG type=%u ino=%llu ag=%u "
				    "mode=%u elapsed_ms=%llu",
				    resource->type,
				    (unsigned long long)resource->ino,
				    resource->ag_number, mode,
				    (unsigned long long)(mxfs_pal_time_ms() - start));
			if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P13-INSTR GRANT-WAIT-OK ino=%llu "
					"slot=%u mode=%u elapsed_ms=%llu",
					(unsigned long long)resource->ino,
					slot_idx, mode,
					(unsigned long long)(mxfs_pal_time_ms() - start));
			}
			/*
			 * v0.5.6 P138 (always-on, >5ms, ratelimited):
			 * waiter-side total for a contended grant.  Pair with
			 * the holder's P138-BAST line (same ino) to attribute
			 * a slow cross-node lock migration to holder release
			 * vs delivery/discovery dead time.
			 */
			if (resource->type == MXFS_LTYPE_INODE &&
			    mxfs_pal_time_ms() - start > 5) {
				/* sess8: capped (not ratelimited — storm runs
				 * lost most lines) + T1 anatomy fields.
				 * ffw_ms = grantable->grant claim latency;
				 * ytd = ticket deferrals while grantable;
				 * realms = wall clock for cross-node hop
				 * pairing with the releaser's EXIT realns. */
				static int p138_n;
				uint64_t now_ms = mxfs_pal_time_ms();

				if (p138_n++ < 4000)
					pr_warn(
					    "mxfs: P138-WAIT ino=%llu mode=%u elapsed_ms=%llu ffw_ms=%llu ytd=%d poll=%u realms=%llu\n",
						(unsigned long long)resource->ino,
						mode,
						(unsigned long long)(now_ms - start),
						(unsigned long long)(first_compat_ms ?
							now_ms - first_compat_ms : 0),
						yt_defer, poll_ms,
						(unsigned long long)mxfs_pal_time_real_ms());
			}
			goto out;
		}

		caw_acquire_poll_sleep(ctx, resource, start, &poll_ms);
	}

	/* Timeout — clean up waiter bit */
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: disk lock acquisition timed out after %llu ms "
		     "(base %u ms, liveness-extended cap %u ms)",
		     (unsigned long long)(mxfs_pal_time_ms() - start),
		     MXFS_CAW_WAIT_TIMEOUT_MS, MXFS_CAW_WAIT_HARDCAP_MS);
	if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P13-INSTR GRANT-WAIT-TIMEOUT ino=%llu slot=%u "
			"want_mode=%u t_ms=%llu",
			(unsigned long long)resource->ino, slot_idx, mode,
			(unsigned long long)mxfs_pal_time_ms());
	}

	/* sess48: robust cleanup — the old bounded 10-retry CAS loop here could
	 * lose every attempt under a 16-node hot-slot CAS storm, leaking our
	 * EX-waiter bit permanently (phantom-waiter wedge).  Retry until our bit
	 * is confirmed clear. */
	caw_drop_own_waiter(ctx, slot_idx);

	rc = -ETIMEDOUT;

out:
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/* ─── In-memory lock tracking for single-node bypass ─── */

static void mem_lock_track(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t mode)
{
	int i;

	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);

	/* Update existing entry if same resource */
	for (i = 0; i < ctx->mem_lock_count; i++) {
		if (memcmp(&ctx->mem_locks[i].resource, resource,
			   sizeof(*resource)) == 0) {
			ctx->mem_locks[i].mode = mode;
			mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
			return;
		}
	}

	/* Add new entry */
	if (ctx->mem_lock_count < ctx->max_held) {
		ctx->mem_locks[ctx->mem_lock_count].resource = *resource;
		ctx->mem_locks[ctx->mem_lock_count].mode = mode;
		ctx->mem_lock_count++;
	}

	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
}

static void mem_lock_untrack(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource)
{
	int i;

	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);

	for (i = 0; i < ctx->mem_lock_count; i++) {
		if (memcmp(&ctx->mem_locks[i].resource, resource,
			   sizeof(*resource)) == 0) {
			ctx->mem_locks[i] =
				ctx->mem_locks[--ctx->mem_lock_count];
			break;
		}
	}

	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
}

/*
 * sess39: desync the compare-and-write storm on a hot INODE lock slot.
 *
 * Under N-node concurrent same-directory rename, every node read-modify-CAS
 * the SAME inode lock slot in lockstep.  Each MISCOMPARE returns -EAGAIN and
 * the outer loop retries with no delay, so an unlucky node can lose all
 * MXFS_CAW_MAX_RETRIES rounds; the acquire then returns -ETIMEDOUT and
 * mxfs_dlm_ilock_begin force-shuts-down the filesystem (observed: "DLM inode
 * lock unrecoverable ... rc=-110").  A small node-phased jittered sleep
 * breaks the lockstep so each contender gets uncontended CAS windows and the
 * operation converges well within the retry budget.
 *
 * SCOPE: inode locks only.  AG locks under streaming write (dd) retry
 * frequently for non-contention reasons; a cumulative backoff there
 * regressed throughput and hung xfs_ilock (v0.3.46 added / v0.3.50 reverted
 * a global backoff for exactly this reason).  Keeping AG locks on the tight
 * loop preserves that result while fixing the inode-contention livelock.
 *
 * The delay is a true-random draw per attempt (v0.10.35 — the earlier
 * node-phased modulo produced only 7 distinct sequences, phase-locking
 * collision groups at 32 nodes), widening gently with retry count, bounded
 * low and skipped for the first couple of retries so the uncontended
 * common case stays fast.
 */
static void caw_inode_backoff(struct mxfs_dlm_caw_ctx *ctx,
			      const struct mxfs_resource_id *resource,
			      int retry)
{
	uint32_t ms;

	if (!resource || resource->type != MXFS_LTYPE_INODE)
		return;
	if (retry < 2)
		return;	/* keep the uncontended common case tight */

	/*
	 * v0.10.35: TRUE-RANDOM jitter.  The deterministic
	 * (retry + local_node * 5) % 7 phased only 7 distinct sequences —
	 * at 32 nodes, ~5 nodes share each phase and re-collide on every
	 * retry (proven: 32-node rm storm, 31 holders CAS-clearing the same
	 * slot; P138-BAST su tails of 60-101ms from persistent collision
	 * groups gate every unlink at ~45ms).  A random draw per attempt
	 * breaks the phase lock; the window widens gently with retry so a
	 * deep convoy spreads out, capped at 20ms to keep worst-case
	 * recovery snappy.
	 */
	{
		uint32_t cap = 4u + 2u * (uint32_t)retry;
		uint8_t rnd;

		if (cap > 20u)
			cap = 20u;
		mxfs_pal_get_random_bytes(&rnd, sizeof(rnd));
		ms = rnd % cap;		/* 0-inclusive: no mandatory tax */
	}
	if (ms)
		mxfs_pal_sleep_ms(ms);
}

/*
 * sess39: ALWAYS-ON exclusive-grant invariant check.  After we record a
 * grant in `slot`, verify the slot's holder bitmaps obey DLM exclusion:
 *  - if WE hold EX/PW, NO other node may hold ANY mode;
 *  - if WE hold PR/CR/CW, NO node may hold EX/PW.
 * A violation means two nodes believe they hold incompatible modes on the
 * same resource at once — the single fault that would explain the on-disk
 * corruption (double allocation, bmap/iunlink/SB corruption) seen under
 * concurrent same-dir rename.  Cheap (bitmask ops), fires only on the bug,
 * ratelimited; NOT gated on the instr param so it surfaces in production.
 */
static void caw_check_exclusion(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				const struct mxfs_caw_lock_slot *slot,
				uint8_t mode)
{
	uint64_t self = ctx->node_bit;
	uint64_t others_ex = slot->holders_ex & ~self;
	uint64_t others_pw = slot->holders_pw & ~self;
	uint64_t others_pr = slot->holders_pr & ~self;
	uint64_t others_cw = slot->holders_cw & ~self;
	uint64_t others_any = others_ex | others_pw | others_pr | others_cw |
			      (slot->holders_cr & ~self);
	bool	bad = false;

	if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW) {
		if (others_any)
			bad = true;
	} else if (mode == MXFS_LOCK_PR || mode == MXFS_LOCK_CR ||
		   mode == MXFS_LOCK_CW) {
		if (others_ex || others_pw)
			bad = true;
	}

	if (unlikely(bad))
		mxfs_pal_log(MXFS_LOG_ERR,
		    "mxfs: CAW-EXCL-VIOLATION ino=%llu type=%u our_mode=%u "
		    "self=%llx h_ex=%llx h_pw=%llx h_pr=%llx h_cw=%llx h_cr=%llx",
		    (unsigned long long)resource->ino, resource->type, mode,
		    (unsigned long long)self,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->holders_cw,
		    (unsigned long long)slot->holders_cr);
}

/*
 * sess44 P87: decisive DLM-split test.  After an EX/PW grant CAS reports
 * SUCCESS, re-read the slot straight from disk and verify our bit is the
 * ONLY EX holder.  caw_check_exclusion() above only inspects the in-core
 * new_slot we constructed, so it cannot detect a CAS that "succeeded" but
 * did not persist exclusively (the documented sess26 failure: SCSI CAW
 * reports CAS-success without durably persisting).  If our bit is MISSING
 * from the on-disk holders_ex, or another node's bit is also set, two nodes
 * believe they hold the AG EX => concurrent same-AG metadata modify =>
 * bnobt/AGF lost-update (the pristine-revert + xfs_alloc.c:2231 overlap).
 * EX/PW are single-holder modes so the on-disk holders_ex must equal exactly
 * our node_bit.  Ratelimited at the PAL log; fires only on the rare split.
 */
static void caw_verify_grant_persisted(struct mxfs_dlm_caw_ctx *ctx,
				       const struct mxfs_resource_id *resource,
				       uint32_t slot_idx, uint8_t mode)
{
	struct mxfs_caw_lock_slot *vs;
	/* ccloop 72513a13 sess3: this read-back was 1 FUA read per EX grant
	 * — ~1 op per created/unlinked file cluster-wide.  The sess26 target
	 * misbehavior it detects (CAS reports success but does not persist)
	 * is not per-resource: SAMPLE inode grants 1/64 and keep AG grants
	 * (free-space lost-update blast radius) at every-grant.  The counter
	 * race is benign (sampling only). */
	static uint32_t p87_sample;

	if (mode != MXFS_LOCK_EX && mode != MXFS_LOCK_PW)
		return;
	if (resource->type == MXFS_LTYPE_INODE && (p87_sample++ & 63) != 0)
		return;
	vs = mxfs_pal_alloc(sizeof(*vs));
	if (!vs)
		return;
	if (read_slot(ctx, slot_idx, vs) == 0) {
		if ((vs->holders_ex & ctx->node_bit) == 0 ||
		    mxfs_pal_popcount64(vs->holders_ex) != 1) {
			mxfs_pal_log(MXFS_LOG_ERR,
			    "mxfs: P87-CAW-SPLIT slot=%u mode=%u self=%llx "
			    "disk_h_ex=%llx popcnt=%d (post-CAS grant did NOT "
			    "persist exclusively => DLM split / lost-update root)",
			    slot_idx, mode,
			    (unsigned long long)ctx->node_bit,
			    (unsigned long long)vs->holders_ex,
			    mxfs_pal_popcount64(vs->holders_ex));
		}
	}
	mxfs_pal_free(vs);
}

/* ─── mxfs_dlm_caw_lock ─── */

int mxfs_dlm_caw_lock(struct mxfs_dlm_caw_ctx *ctx,
		        const struct mxfs_resource_id *resource,
		        uint8_t mode, uint32_t flags,
		        uint8_t *granted_mode)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint32_t last_read_idx = UINT32_MAX;
	uint8_t our_mode;
	int retry;
	int rc;
	/* ccloop RULE4: prove the hot-slot CAS-storm exhaustion mechanism for
	 * INODE EX-acquire — count CAS -EAGAIN losses per site, dump on
	 * MXFS_CAW_MAX_RETRIES exhaustion (the path that force-shuts-down). */
	int ea_claim = 0, ea_compat = 0, ea_regwait = 0;
	int div_lo = 0, div_hi = 0, yield_bo = 0, yield_stale = 0, wait_enoent = 0;
	int last_our_mode = -1;
	uint8_t last_wmode = 0;
	uint64_t last_hex = 0, last_hpr = 0;
	bool grant_handoff = false;	/* v0.6.0 EX-handoff epoch observation */
	bool claim_handoff = false;	/* claim-empty via same-res tombstone */

	if (!ctx || !resource)
		return -EINVAL;

	if (mode == MXFS_LOCK_NL) {
		if (granted_mode)
			*granted_mode = MXFS_LOCK_NL;
		return 0;
	}

	/* Single-node fast path: no peers, grant in-memory only */
	if (ctx->single_node) {
		mem_lock_track(ctx, resource, mode);
		if (granted_mode)
			*granted_mode = mode;
		return 0;
	}

	/* sess78 DIAGNOSTIC: measure the perf ceiling without per-inode disk
	 * CAW.  Grant INODE-type locks in-memory only (UNSAFE; diag param). */
	{
		extern int mxfs_inode_caw_local;
		extern int mxfs_inode_caw_skip;
		/* Ceiling measurement: grant with NO mem_lock_track (avoids the
		 * O(n^2) linear scan that the caw_local path incurs) and NO disk
		 * CAW.  SOLO no-contention diagnostic only. */
		if (mxfs_inode_caw_skip &&
		    resource->type == MXFS_LTYPE_INODE) {
			if (granted_mode)
				*granted_mode = mode;
			return 0;
		}
		if (mxfs_inode_caw_local &&
		    resource->type == MXFS_LTYPE_INODE) {
			mem_lock_track(ctx, resource, mode);
			if (granted_mode)
				*granted_mode = mode;
			return 0;
		}
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}

	for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
		/*
		 * v0.3.46 attempted exponential backoff (1ms→32ms cap) per
		 * retry to prevent CAS-storm exhaustion.  Reverted v0.3.50:
		 * under sustained dd contention, the cumulative backoff time
		 * causes xfs_ilock requests to hang indefinitely (kernel
		 * hung-task warnings).  CAW exhaustion was a symptom of
		 * underlying coordination races, not the root issue — slowing
		 * the retries just trades one failure for another.
		 *
		 * sess39: that revert was correct for AG locks; re-introduce a
		 * node-phased jittered backoff scoped to INODE locks only, to
		 * desync the same-slot CAS storm that otherwise -ETIMEDOUTs and
		 * shuts the FS down under concurrent same-dir rename.
		 */
		caw_inode_backoff(ctx, resource, retry);

		/* v0.5.3: capture which slot the probe read LAST so the
		 * claim path below can reuse cur_slot as the CAS compare
		 * buffer when the probe terminated at the very slot it is
		 * about to claim (the common no-tombstone case) instead of
		 * re-reading it (was 1 serialized FUA read per create). */
		last_read_idx = UINT32_MAX;
		rc = find_slot_skip(ctx, resource, &slot_idx, cur_slot,
				    &empty_idx, UINT32_MAX, &last_read_idx);

		/* P15-INSTR: AG-only CAW traffic logging — v0.5.3: gated behind
		 * mxfs.instr (was UNGATED: one pr_warn per AG CAW iteration, 1410
		 * lines in one 2-node rsync, printed while holding the lock path —
		 * a measurable slice of the multi-node penalty; sess36 policy). */
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on()) {
			if (rc == 0) {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-iter ag=%u mode=%u retry=%d "
				    "find=found slot=%u gen=%u gm=%u "
				    "h_ex=%llx h_pw=%llx h_pr=%llx "
				    "w=%llx wm=%u yt=%llx ys_ms=%llu",
				    resource->ag_number, mode, retry,
				    slot_idx, cur_slot->generation,
				    cur_slot->granted_mode,
				    (unsigned long long)cur_slot->holders_ex,
				    (unsigned long long)cur_slot->holders_pw,
				    (unsigned long long)cur_slot->holders_pr,
				    (unsigned long long)cur_slot->waiters,
				    cur_slot->waiter_mode,
				    (unsigned long long)cur_slot->yield_to,
				    (unsigned long long)cur_slot->yield_set_ms);
			} else {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-iter ag=%u mode=%u retry=%d "
				    "find=rc%d empty_idx=%u",
				    resource->ag_number, mode, retry,
				    rc, empty_idx);
			}
		}

		if (rc == -ENOENT) {
			/* Resource not in any slot — claim an empty slot */
			if (empty_idx == UINT32_MAX) {
				mxfs_pal_log(MXFS_LOG_ERR,
					     "dlm_caw: no empty slot for "
					     "ino=%llu type=%u",
					     (unsigned long long)resource->ino,
					     resource->type);
				rc = -ENOSPC;
				goto out;
			}

			/* Bug 93: the CAS compare buffer must hold the actual
			 * on-disk content of the empty slot (it may contain
			 * stale/uninitialized non-zero data), not zeros.
			 * v0.5.3: when the probe TERMINATED at empty_idx the
			 * content is already in cur_slot from find_slot_skip's
			 * final read_slot — reuse it.  Only re-read when the
			 * insertion point is an earlier tombstone/ghost slot
			 * (probe read past it, clobbering cur_slot). */
			if (last_read_idx != empty_idx) {
				rc = read_slot(ctx, empty_idx, cur_slot);
				if (rc)
					goto out;
			}
			/* daf50d34 sess2 ROOT FIX (mkdir-storm dirent loss, RULE-4
			 * PROVEN by P135-FOREIGN-STRIP caller=mxfs_dlm_caw_lock+0x459
			 * ×3 in one 5-round storm): the re-read above is a TOCTOU
			 * LAUNDERER.  Between the probe classifying empty_idx as
			 * claimable and this re-read, a PEER's fresh claim of the
			 * same tombstone can land; the re-read then returns the
			 * peer's LIVE slot image, and the CAS below — whose whole
			 * purpose is "replace iff still the empty image I probed" —
			 * succeeds against the CURRENT medium, wiping the peer's
			 * holder bits (write image is memset-fresh) and resetting
			 * generation to 1.  The peer keeps believing it holds EX →
			 * double-EX → its committed dir change is destage-refused
			 * (held=0) → durable dirent loss (node1/node3/node15 storm
			 * family).  A live-magic image at our chosen empty_idx is
			 * always a lost claim race: re-probe instead of claiming
			 * over it (if it is OUR resource the next probe FINDS it;
			 * if a foreign resource landed there the next probe picks a
			 * different empty slot). */
			if (cur_slot->magic == MXFS_CAW_MAGIC) {
				if (caw_instr_on())
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-CLAIM-RACE-LOST type=%u ino=%llu "
					    "slot=%u res_ino=%llu hex=%llx hpr=%llx "
					    "gen=%u — live slot materialized at chosen "
					    "empty idx; re-probing",
					    resource->type,
					    (unsigned long long)resource->ino,
					    empty_idx,
					    (unsigned long long)cur_slot->resource.ino,
					    (unsigned long long)cur_slot->holders_ex,
					    (unsigned long long)cur_slot->holders_pr,
					    cur_slot->generation);
				ea_claim++;
				mxfs_pal_sleep_ms(1);
				continue;
			}
			memset(new_slot, 0, sizeof(*new_slot));
			new_slot->magic = MXFS_CAW_MAGIC;
			new_slot->generation = 1;
			new_slot->resource = *resource;
			new_slot->last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
			caw_claim_inherit_epoch(new_slot, cur_slot, resource);
			{
				uint64_t *hp = holders_for_mode(new_slot,
								mode);
				if (hp)
					*hp = ctx->node_bit;
			}
			caw_grant_streak_note(new_slot, mode);
			new_slot->granted_mode = mode;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			/* handoff CAN be true here: a recycled same-resource
			 * tombstone carries last_ex_slot (idle-gap handoff) */
			claim_handoff = caw_grant_epoch_update(ctx, new_slot,
							       mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, empty_idx, cur_slot, new_slot);
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=claim-empty slot=%u cas_rc=%d",
				    resource->ag_number, retry, empty_idx, rc);
			if (rc == -EAGAIN) {
				ea_claim++;
				continue; /* MISCOMPARE, retry */
			}
			if (rc)
				goto out;

			/*
			 * P49-INSTR (sess26 diagnostic): post-CAS verify-read.
			 * v0.3.108 final: extra SCSI read per CAS-success
			 * doubles the SCSI command count in caw_lock claim
			 * path.  Disabling P49 to reduce SCSI-queue pressure;
			 * the divergence info is preserved in sess26 docs.
			 * Set MXFS_P49_ENABLE=1 to re-enable for diagnosis.
			 */
			if (0 && resource->type == MXFS_LTYPE_AG) {
				struct mxfs_caw_lock_slot verify_slot;
				int v_rc = read_slot(ctx, empty_idx, &verify_slot);
				uint8_t v_our_mode;
				/* v0.3.108: tested msleep(1) before verify
				 * read — no improvement in pass rate.  Async
				 * completion isn't the cause of the
				 * post-CAS divergence we observe. */
				v_our_mode = node_held_mode(&verify_slot,
							    ctx->node_bit);
				if (v_rc != 0 || v_our_mode != mode) {
					const uint8_t *vb = (const uint8_t *)&verify_slot;
					const uint8_t *nb = (const uint8_t *)new_slot;
					const uint8_t *cb = (const uint8_t *)cur_slot;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR cur-slot-bytes 0..31 (compare-buf for CAS): "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    cb[0],cb[1],cb[2],cb[3],
					    cb[4],cb[5],cb[6],cb[7],
					    cb[8],cb[9],cb[10],cb[11],
					    cb[12],cb[13],cb[14],cb[15],
					    cb[16],cb[17],cb[18],cb[19],
					    cb[20],cb[21],cb[22],cb[23],
					    cb[24],cb[25],cb[26],cb[27],
					    cb[28],cb[29],cb[30],cb[31]);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR claim-empty-diverged "
					    "ag=%u slot=%u v_rc=%d "
					    "v_magic=0x%x v_gen=%u "
					    "v_gm=%u v_our_mode=%u expected=%u "
					    "v_h_ex=%llx v_h_pw=%llx v_waiters=%llx "
					    "we_wrote_ex=%llx node_bit=%llx",
					    resource->ag_number, empty_idx,
					    v_rc, verify_slot.magic,
					    verify_slot.generation,
					    verify_slot.granted_mode,
					    v_our_mode, mode,
					    (unsigned long long)
					    verify_slot.holders_ex,
					    (unsigned long long)
					    verify_slot.holders_pw,
					    (unsigned long long)
					    verify_slot.waiters,
					    (unsigned long long)
					    new_slot->holders_ex,
					    (unsigned long long)
					    ctx->node_bit);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR diverged-bytes 0..31: "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    vb[0],vb[1],vb[2],vb[3],
					    vb[4],vb[5],vb[6],vb[7],
					    vb[8],vb[9],vb[10],vb[11],
					    vb[12],vb[13],vb[14],vb[15],
					    vb[16],vb[17],vb[18],vb[19],
					    vb[20],vb[21],vb[22],vb[23],
					    vb[24],vb[25],vb[26],vb[27],
					    vb[28],vb[29],vb[30],vb[31]);
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P49-INSTR we-wrote-bytes 0..31: "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x "
					    "%02x%02x%02x%02x %02x%02x%02x%02x",
					    nb[0],nb[1],nb[2],nb[3],
					    nb[4],nb[5],nb[6],nb[7],
					    nb[8],nb[9],nb[10],nb[11],
					    nb[12],nb[13],nb[14],nb[15],
					    nb[16],nb[17],nb[18],nb[19],
					    nb[20],nb[21],nb[22],nb[23],
					    nb[24],nb[25],nb[26],nb[27],
					    nb[28],nb[29],nb[30],nb[31]);
				}
			}

			/*
			 * sess47 CLAIM-RACE detector: right after claiming a
			 * fresh slot, verify the resource lives in EXACTLY ONE
			 * live slot.  >1 => another node concurrently claimed a
			 * different empty slot for the same resource (the
			 * suspected root of the bnobt stale-pristine clobber).
			 * Detection only this build — proves/refutes before any
			 * fix.  Always-on (fires only on the bug), ratelimited.
			 */
			/* sess84: extended to INODE locks (was AG-only).  The
			 * shortform-dir lost-update (node1.txt durably vanishes
			 * from a shared dir) shows ZERO CAW-EXCL-VIOLATION — that
			 * detector reads ONE slot, so it cannot see a claim-race
			 * where the SAME inode resource lands in TWO live slots
			 * (each with a single, non-conflicting EX holder) →
			 * concurrent EX on the dir inode via different slots. */
			/* v0.5.3 (ccloop 14d31183 scaling_curve): skip the
			 * post-claim chain re-scan when we claimed AT THE HASH
			 * BASE slot.  A racing peer's probe for the same
			 * resource starts at the same base: pre-our-CAW it
			 * targets the SAME base slot (CAW serializes — exactly
			 * one claim wins, the loser re-probes and finds our
			 * live entry); post-our-CAW it finds our live entry at
			 * the chain head and registers as waiter.  Either way
			 * a second live slot for the resource cannot come into
			 * existence, so the scan can only ever return 1 here.
			 * Off-base claims (chain had live/tombstone slots
			 * before our insertion point) keep the full detector —
			 * that is where the sess47/sess84 dup-slot race lives.
			 * Measured: the re-scan was 1441 of 6120 slot reads in
			 * a 705-create rsync (~2 serialized FUA reads per
			 * create), nearly all base-claims. */
			if ((resource->type == MXFS_LTYPE_AG ||
			     resource->type == MXFS_LTYPE_INODE) &&
			    empty_idx != resource_hash_raw(resource) %
					 MXFS_CAW_MAX_SLOTS) {
				uint32_t dup[8];
				uint64_t hex_or = 0;
				int ndup = caw_count_resource_slots(ctx,
					resource, dup, 8, &hex_or);
				if (ndup > 1)
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: CAW-DUP-SLOT type=%u ag=%u "
					    "ino=%llu nslots=%d mine=%u "
					    "slots=[%u,%u,%u,%u] holders_ex_or=%llx "
					    "(claim-race: same resource in >1 live "
					    "slot => concurrent EX via diff slots)",
					    resource->type, resource->ag_number,
					    (unsigned long long)resource->ino,
					    ndup, empty_idx,
					    dup[0], ndup>1?dup[1]:0,
					    ndup>2?dup[2]:0, ndup>3?dup[3]:0,
					    (unsigned long long)hex_or);
			}

			track_held(ctx, empty_idx);
			slot_hint_store(ctx, resource, empty_idx);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     claim_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			if (granted_mode)
				*granted_mode = mode;
			rc = 0;
			goto out;
		}

		if (rc)
			goto out; /* I/O error */

		/* Check if we already hold this lock at the requested mode */
		our_mode = node_held_mode(cur_slot, ctx->node_bit);
		if (our_mode == mode) {
			/*
			 * v0.3.85 (sess25): divergence detection. The "we hold
			 * the requested mode" check returns success without
			 * verifying that no PEER also holds a conflicting mode.
			 * Sess24 P35 captured both T1 and T2 with their bits set
			 * in the EX bitmap simultaneously on AG=0 for ~50s — both
			 * fast-pathed acquires forever, modifying AG-meta in
			 * parallel, producing bnobt LEFT/RIGHT-FAIL.
			 *
			 * Suspected source: single→multi flush_held_to_disk OR's
			 * our bit unconditionally; if peer ran concurrently,
			 * both bits end up set without conflict resolution.  Or
			 * any path where our local belief drifts from disk.
			 *
			 * Fix: when our bit appears set but a peer also holds an
			 * incompatible mode, our bit is provably stale (lock
			 * compatibility table forbids two EX holders, etc.).
			 * Clear our bit via CAW, untrack locally, retry from
			 * top so the acquire goes through the normal conflict-
			 * detection path.
			 */
			if (!compatible_excluding_self(cur_slot, mode,
						       ctx->node_bit)) {
				*new_slot = *cur_slot;
				{
					uint64_t *hp = holders_for_mode(
						new_slot, our_mode);
					if (hp)
						*hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();
				rc = caw_slot(ctx, slot_idx, cur_slot,
					      new_slot);
				if (resource->type == MXFS_LTYPE_AG)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P37-INSTR caw-divergence "
					    "ag=%u retry=%d our_mode=%u "
					    "peer-incompat cas_rc=%d "
					    "h_ex=%llx h_pw=%llx h_pr=%llx",
					    resource->ag_number, retry,
					    our_mode, rc,
					    (unsigned long long)
					    cur_slot->holders_ex,
					    (unsigned long long)
					    cur_slot->holders_pw,
					    (unsigned long long)
					    cur_slot->holders_pr);
				/* P109 Phase 1.1 (NEWARCH): instrument every
				 * on-disk holder-bit clear so the P106-STALE-EX
				 * culprit path can be identified.  This site
				 * clears OUR bit mid-acquire because a peer
				 * holds an incompatible mode (our bit was
				 * stale).  Caller's in-core i_dlm_mode/state
				 * is still set to the previous belief — the
				 * slow-path return path SHOULD reset it but
				 * if there's a race with a concurrent fast-
				 * path acquire on the same inode, we leak a
				 * stale-cached holder. */
				if (caw_instr_on() ||
				    (resource->type == MXFS_LTYPE_INODE &&
				     caw_diverg_logged++ < 50))
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-DIVERG-LO type=%s "
					    "id=%llu our_mode=%u req=%u "
					    "cas_rc=%d slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, rc, slot_idx);
				if (rc == 0)
					untrack_held(ctx, slot_idx);
				if (rc == -EAGAIN || rc == 0) {
					div_lo++;
					last_our_mode = our_mode;
					last_hex = cur_slot->holders_ex;
					last_hpr = cur_slot->holders_pr;
					continue;
				}
				goto out;
			}

			/* v0.6.3: gate + grant record in ONE critical
			 * section (see caw_grant_meta_store_unless_releasing).
			 * A false return means our own unlock is concurrently
			 * clearing this bit — the observed hold is a torn
			 * read of a release in flight; wait it out and
			 * re-probe. */
			if (!caw_grant_meta_store_unless_releasing(ctx,
					resource, cur_slot->dir_epoch, false,
					cur_slot->dir_block0_fsb,
					cur_slot->dir_block0_gen)) {
				static int relwait_logged;

				if (relwait_logged < 20) {
					relwait_logged++;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-SHORTCUT-RELWAIT type=%u "
					    "ino=%llu retry=%d",
					    resource->type,
					    (unsigned long long)resource->ino,
					    retry);
				}
				mxfs_pal_sleep_ms(1);
				continue;
			}
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=already-held our_mode=%u",
				    resource->ag_number, retry, our_mode);
			if (granted_mode)
				*granted_mode = mode;
			rc = 0; /* Already hold it */
			goto out;
		}

		/* Check if we hold a higher mode that subsumes the request */
		if (our_mode != MXFS_LOCK_NL && our_mode >= mode) {
			/*
			 * v0.3.85 (sess25): same divergence check as above for
			 * the higher-mode-subsumes case.
			 */
			if (!compatible_excluding_self(cur_slot, our_mode,
						       ctx->node_bit)) {
				*new_slot = *cur_slot;
				{
					uint64_t *hp = holders_for_mode(
						new_slot, our_mode);
					if (hp)
						*hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();
				rc = caw_slot(ctx, slot_idx, cur_slot,
					      new_slot);
				if (resource->type == MXFS_LTYPE_AG)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "P37-INSTR caw-divergence-higher "
					    "ag=%u retry=%d our_mode=%u "
					    "peer-incompat cas_rc=%d",
					    resource->ag_number, retry,
					    our_mode, rc);
				/* P109 Phase 1.1 (NEWARCH) — divergence guard,
				 * higher-mode-subsumes path.  Same hazard as
				 * DIVERG-LO: clears OUR bit while caller's
				 * in-core mode/state is unchanged. */
				if (caw_instr_on() ||
				    (resource->type == MXFS_LTYPE_INODE &&
				     caw_diverg_logged++ < 50))
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-DIVERG-HI type=%s "
					    "id=%llu our_mode=%u req=%u "
					    "cas_rc=%d slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, rc, slot_idx);
				if (rc == 0)
					untrack_held(ctx, slot_idx);
				if (rc == -EAGAIN || rc == 0) {
					div_lo++;
					last_our_mode = our_mode;
					last_hex = cur_slot->holders_ex;
					last_hpr = cur_slot->holders_pr;
					continue;
				}
				goto out;
			}

			/* v0.6.3: see the already-held gate above. */
			if (!caw_grant_meta_store_unless_releasing(ctx,
					resource, cur_slot->dir_epoch, false,
					cur_slot->dir_block0_fsb,
					cur_slot->dir_block0_gen)) {
				static int relwait_hi_logged;

				if (relwait_hi_logged < 20) {
					relwait_hi_logged++;
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P-SHORTCUT-RELWAIT-HI type=%u "
					    "ino=%llu retry=%d",
					    resource->type,
					    (unsigned long long)resource->ino,
					    retry);
				}
				mxfs_pal_sleep_ms(1);
				continue;
			}
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=already-held-higher our_mode=%u",
				    resource->ag_number, retry, our_mode);
			if (granted_mode)
				*granted_mode = our_mode;
			rc = 0; /* Current mode is sufficient */
			goto out;
		}

		/*
		 * sess50 anti-starvation (PROVEN root of the ~60-120s barrier
		 * dir-visibility stall): continuous PR readers across nodes were
		 * re-granting PR among themselves (slot generation churned ~1650x
		 * over a 69s stall) while a peer's EX request waited forever —
		 * the EX writer could never find a window with zero PR holders,
		 * so its dir modification (e.g. a barrier marker) stayed
		 * invisible.  Fix: for a FRESH acquire (our_mode==NL), if a peer
		 * is already waiting for a mode INCOMPATIBLE with ours, do not
		 * grab the compatible lock — fall through to the waiter-register
		 * path so current holders drain and the waiter gets granted.
		 * Recursion/upgrade (our_mode != NL) is exempt: those callers
		 * already hold the resource and must not deadlock against a peer
		 * waiter.  Same-mode waiters (e.g. PR vs PR) stay compatible and
		 * are allowed in (no starvation there).
		 */
		bool defer_for_waiter =
			(our_mode == MXFS_LOCK_NL) &&
			(mode == MXFS_LOCK_PR || mode == MXFS_LOCK_CR ||
			 mode == MXFS_LOCK_CW) &&
			(cur_slot->waiter_mode == MXFS_LOCK_EX ||
			 cur_slot->waiter_mode == MXFS_LOCK_PW) &&
			((cur_slot->waiters & ~ctx->node_bit) != 0);

		/*
		 * Compatibility check: if we already hold a lower mode
		 * (upgrade case, e.g. PR→EX), exclude ourselves from the
		 * compatibility test.  Otherwise is_compatible sees our
		 * own PR as conflicting with the EX request, triggering a
		 * self-BAST that races with ilock_begin and can leave
		 * i_dlm_state=NONE while EX is held on disk — causing
		 * the next external BAST to release without flush.
		 */
		if (!defer_for_waiter &&
		    ((our_mode != MXFS_LOCK_NL)
		    ? compatible_excluding_self(cur_slot, mode,
						ctx->node_bit)
		    : is_compatible(cur_slot, mode))) {
			/*
			 * Yield-to-priority: if yield_to has bits set for
			 * OTHER nodes (not us), back off to let those nodes
			 * acquire first. This prevents the releasing node
			 * from immediately reacquiring before waiters get
			 * a chance.
			 */
			if (cur_slot->yield_to != 0) {
				uint64_t yield_now = mxfs_pal_time_real_ms();
				uint64_t yield_age =
					(yield_now > cur_slot->yield_set_ms) ?
					(yield_now - cur_slot->yield_set_ms) : 0;

				if (yield_age < MXFS_CAW_YIELD_TIMEOUT_MS) {
					/*
					 * sess130 conversion-priority (PROVEN
					 * livelock, P-CAWEXH yield_bo=100):
					 * an UPGRADER (our_mode != NL, e.g.
					 * PR→EX for unlink) that passed the
					 * compat check is the SOLE holder —
					 * the yield_to waiters it would defer
					 * to are themselves blocked on OUR
					 * held mode, and every peer release
					 * re-arms yield_set_ms so the hint
					 * never goes stale.  Deferring here
					 * livelocks until -ETIMEDOUT →
					 * force-shutdown.  Standard DLM rule:
					 * conversions take priority over new
					 * requests.  Only FRESH acquires
					 * (our_mode == NL) honor yield_to.
					 */
					bool yt_pr_only =
						(cur_slot->yield_to &
						 cur_slot->waiters_ex) == 0;
					bool held_pr_compat =
						(our_mode == MXFS_LOCK_PR ||
						 our_mode == MXFS_LOCK_CR);
					/*
					 * v0.10.41: an upgrader normally keeps
					 * conversion priority (bypasses yield_to).
					 * BUT if the ticket is a pure-PR batch
					 * (the streak anti-starvation yield to the
					 * shared class) and our HELD mode is
					 * PR-compatible, the PR waiters do NOT
					 * block on our held mode (PR+PR share) —
					 * so deferring lets them batch-promote with
					 * NO sess130 livelock, and their PR grant
					 * resets the streak so we upgrade right
					 * after they drain.  This stops PR-reader
					 * (stat/readdir) 360s starvation behind
					 * PR->EX creators at 32 nodes (dir_reuse
					 * B3: test5 comm=stat mode=3 rc=-110). */
					if (!(cur_slot->yield_to &
					      ctx->node_bit) &&
					    (our_mode == MXFS_LOCK_NL ||
					     (yt_pr_only && held_pr_compat))) {
						/*
						 * Fresh acquire, OR an upgrader
						 * yielding to a compatible PR
						 * batch — back off.
						 */
						if (our_mode != MXFS_LOCK_NL &&
						    resource->type ==
						    MXFS_LTYPE_INODE)
							pr_warn_ratelimited(
							    "mxfs: P-UPG-PRYIELD ino=%llu our_mode=%u req=%u yt=%llx wex=%llx\n",
							    (unsigned long long)resource->ino,
							    our_mode, mode,
							    (unsigned long long)cur_slot->yield_to,
							    (unsigned long long)cur_slot->waiters_ex);
						if (resource->type ==
						    MXFS_LTYPE_AG &&
						    caw_instr_on())
							mxfs_pal_log(
							    MXFS_LOG_WARN,
							    "P15-INSTR caw-act "
							    "ag=%u retry=%d "
							    "action=yield-backoff "
							    "yield_age_ms=%llu "
							    "yt=%llx",
							    resource->ag_number,
							    retry,
							    (unsigned long long)
							    yield_age,
							    (unsigned long long)
							    cur_slot->yield_to);
						mxfs_pal_sleep_ms(
						    MXFS_CAW_YIELD_BACKOFF_MS +
						    (ctx->local_node % 10));
						yield_bo++;
						last_our_mode = our_mode;
						last_hex = cur_slot->holders_ex;
						last_hpr = cur_slot->holders_pr;
						continue;
					}
					if (our_mode != MXFS_LOCK_NL &&
					    !(cur_slot->yield_to &
					      ctx->node_bit) &&
					    resource->type == MXFS_LTYPE_INODE &&
					    caw_instr_on())
						pr_warn_ratelimited(
						    "mxfs: P130-YIELD-UPG-BYPASS ino=%llu our_mode=%u req=%u yt=%llx h_pr=%llx h_ex=%llx\n",
						    (unsigned long long)resource->ino,
						    our_mode, mode,
						    (unsigned long long)cur_slot->yield_to,
						    (unsigned long long)cur_slot->holders_pr,
						    (unsigned long long)cur_slot->holders_ex);
				} else {
					/*
					 * yield_to is stale (>5s). Clear it
					 * via CAW to prevent deadlock if the
					 * yielded-to node died.
					 */
					*new_slot = *cur_slot;
					new_slot->yield_to = 0;
					new_slot->yield_set_ms = 0;
					new_slot->generation++;

					rc = caw_slot(ctx, slot_idx,
						      cur_slot, new_slot);
					if (resource->type == MXFS_LTYPE_AG &&
					    caw_instr_on())
						mxfs_pal_log(MXFS_LOG_WARN,
						    "P15-INSTR caw-act ag=%u "
						    "retry=%d "
						    "action=yield-stale-clear "
						    "yield_age_ms=%llu cas_rc=%d",
						    resource->ag_number, retry,
						    (unsigned long long)
						    yield_age, rc);
					/* Win or lose, re-read and retry */
					yield_stale++;
					continue;
				}
			}

			/* Compatible — add ourselves */
			*new_slot = *cur_slot;

			/* If we're in yield_to, clear our bit */
			if (new_slot->yield_to & ctx->node_bit)
				new_slot->yield_to &= ~ctx->node_bit;

			/* If upgrading, clear old mode first */
			if (our_mode != MXFS_LOCK_NL) {
				uint64_t *old_hp = holders_for_mode(new_slot,
								    our_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
				/* P109 Phase 1.1 (NEWARCH) — UPGRADE clears our
				 * old mode bit BUT the SAME CAS also sets our
				 * new mode bit, so at no point is the on-disk
				 * slot reporting "we hold neither" — caller's
				 * in-core state (still at our_mode) won't see a
				 * stale-empty window for this resource.  Lower
				 * hazard than UPGRADE-DDL below; instrument
				 * anyway for completeness. */
				if (caw_instr_on())
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-UPGRADE type=%s "
					    "id=%llu old_mode=%u new_mode=%u "
					    "slot=%u",
					    resource->type == MXFS_LTYPE_INODE ?
						"I" :
					    resource->type == MXFS_LTYPE_AG ?
						"A" : "O",
					    (unsigned long long)(
					      resource->type == MXFS_LTYPE_INODE ?
					        resource->ino :
					        (uint64_t)resource->ag_number),
					    our_mode, mode, slot_idx);
			}

			{
				uint64_t *hp = holders_for_mode(new_slot,
								mode);
				if (hp)
					*hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			grant_handoff = caw_grant_epoch_update(ctx, new_slot,
							       mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=compat-add slot=%u our_mode=%u "
				    "new_gm=%u cas_rc=%d",
				    resource->ag_number, retry, slot_idx,
				    our_mode, new_slot->granted_mode, rc);
			if (rc == -EAGAIN) {
				ea_compat++;
				continue;
			}
			if (rc)
				goto out;

			caw_check_exclusion(ctx, resource, new_slot, mode);
			caw_verify_grant_persisted(ctx, resource, slot_idx, mode);
			track_held(ctx, slot_idx);
			caw_grant_meta_store(ctx, resource,
					     new_slot->dir_epoch,
					     grant_handoff,
					     new_slot->dir_block0_fsb,
					     new_slot->dir_block0_gen);
			/* sess8 (ccloop 72513a13) T1 anatomy: a CONTENDED slot
			 * (ticket installed or EX waiters queued) claimed here
			 * without entering caw_wait_for_grant means the winner
			 * ARRIVED after the release (late-arrival hop) — the
			 * ytself field says whether the releaser's round-robin
			 * ticket had named us while we were absent. */
			if (resource->type == MXFS_LTYPE_INODE &&
			    (cur_slot->yield_to != 0 ||
			     (cur_slot->waiters_ex & ~ctx->node_bit) != 0)) {
				static int p139_n;

				if (p139_n++ < 4000)
					pr_warn(
					    "mxfs: P139-COLDCLAIM ino=%llu mode=%u yt=%llx ytself=%d wex=%llx realms=%llu\n",
					    (unsigned long long)resource->ino,
					    mode,
					    (unsigned long long)cur_slot->yield_to,
					    (cur_slot->yield_to & ctx->node_bit) ? 1 : 0,
					    (unsigned long long)(cur_slot->waiters_ex & ~ctx->node_bit),
					    (unsigned long long)mxfs_pal_time_real_ms());
			}
			if (granted_mode)
				*granted_mode = mode;
			rc = 0;
			goto out;
		}

		/* Incompatible — check flags */
		if (flags & MXFS_LKF_NOQUEUE) {
			rc = -EAGAIN;
			goto out;
		}
		if (flags & MXFS_LKF_TRYLOCK) {
			rc = -EWOULDBLOCK;
			goto out;
		}

		/*
		 * Upgrade-deadlock prevention: if we already hold some mode
		 * and the upgrade is blocked, release our current mode before
		 * waiting.  Otherwise two nodes both holding PR and both
		 * wanting EX deadlock symmetrically — each waits for the
		 * other to release, but neither thread can unlock because
		 * both are stuck inside caw_lock.  Releasing our mode first
		 * lets the other side's compat check pass, break the cycle.
		 * We'll fall through to the waiter-register path and re-
		 * acquire at the higher mode after the other node is done.
		 */
		if (our_mode != MXFS_LOCK_NL) {
			/*
			 * NEWARCH Phase 1.3 (Gemini chokepoint design):
			 *
			 * REMOVED the in-caw_lock release-and-wait.  The old
			 * code cleared our holder bit on disk and registered
			 * us as a waiter — but did so SILENTLY, so the upper
			 * layer's in-core i_dlm_mode stayed at our_mode while
			 * the on-disk truth was "we hold nothing".  Concurrent
			 * same-node ilock_begin callers fast-pathed on that
			 * stale belief → P106-STALE-EX → durable lost-update.
			 *
			 * Return -EDEADLK instead.  The upper layer
			 * (mxfs_dlm_ilock_begin) catches this, drops the lock
			 * through the proper BAST pipeline (state→BAST,
			 * queue bast_process which flushes + invalidates +
			 * clears the on-disk bit + sets i_dlm_mode=NL atomically),
			 * then re-enters caw_lock from a clean NL state.  No
			 * window where the on-disk bit and in-core mode can
			 * diverge.
			 *
			 * caw_lock now has a strict contract: it either
			 * upgrades-in-place atomically (the compat-add path
			 * above clears+adds in the same CAS) OR acquires from
			 * NL.  It never silently demotes.  This is invariant
			 * #1 ("no on-disk unlock without completed drain")
			 * applied to caw_lock itself.
			 */
			if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "P15-INSTR caw-act ag=%u retry=%d "
				    "action=upgrade-deadlk-return our_mode=%u "
				    "req=%u (caller orchestrates release)",
				    resource->ag_number, retry,
				    our_mode, mode);
			if (caw_instr_on())
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P109-CAW-EDEADLK type=%s id=%llu "
				    "our_mode=%u req=%u slot=%u "
				    "(returning -EDEADLK; caller drops through BAST)",
				    resource->type == MXFS_LTYPE_INODE ?
					"I" :
				    resource->type == MXFS_LTYPE_AG ?
					"A" : "O",
				    (unsigned long long)(
				      resource->type == MXFS_LTYPE_INODE ?
				        resource->ino :
				        (uint64_t)resource->ag_number),
				    our_mode, mode, slot_idx);
			rc = -EDEADLK;
			goto out;
		}

		/* Register as waiter */
		*new_slot = *cur_slot;
		new_slot->waiters |= ctx->node_bit;
		if (mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW)
			new_slot->waiters_ex |= ctx->node_bit;   /* sess50: track exclusive waiter */
		if (mode > new_slot->waiter_mode)
			new_slot->waiter_mode = mode;
		new_slot->generation++;

		last_our_mode = our_mode;
		last_wmode = cur_slot->waiter_mode;
		last_hex = cur_slot->holders_ex;
		last_hpr = cur_slot->holders_pr;

		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "P15-INSTR caw-act ag=%u retry=%d "
			    "action=register-waiter slot=%u cas_rc=%d",
			    resource->ag_number, retry, slot_idx, rc);
		if (rc == -EAGAIN) {
			ea_regwait++;
			continue;
		}
		if (rc)
			goto out;

		/* Send UDP BAST multicast (best effort hint) */
		caw_send_bast_mcast(ctx, resource, mode);

		/* Wait for grant */
		rc = caw_wait_for_grant(ctx, slot_idx, resource, mode);
		if (resource->type == MXFS_LTYPE_AG && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "P15-INSTR caw-act ag=%u retry=%d "
			    "action=wait-for-grant-done slot=%u rc=%d",
			    resource->ag_number, retry, slot_idx, rc);
		/* v0.6.0: the promote CAS in caw_wait_for_grant granted exactly
		 * `mode`; report it.  This path left *granted_mode UNSET, so the
		 * caller's uninitialized stack value made P52-PARTIAL-GRANT fire
		 * 1462x in one 4-node dir_reuse run (pure noise, and any future
		 * caller honoring granted_mode would misbehave). */
		if (rc == 0 && granted_mode)
			*granted_mode = mode;
		/*
		 * Slot was cleared while we were waiting (e.g. the last
		 * holder's unlock raced with our waiter-registration CAW, or
		 * a sibling-node lease-expiry purge wiped the slot).  The
		 * resource always exists (inode/AG numbers are durable), so
		 * retry the outer loop — find_slot will either re-locate it
		 * or take the empty-slot claim path.
		 */
		if (rc == -ENOENT) {
			wait_enoent++;
			continue;
		}
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: lock exhausted %d retries for ino=%llu type=%u",
		     MXFS_CAW_MAX_RETRIES,
		     (unsigned long long)resource->ino,
		     resource->type);
	/* ccloop RULE4: dump WHICH CAS site exhausted the retry budget so we
	 * know whether the hot-slot storm is on claim/compat-add/register-waiter,
	 * and the final holder/waiter picture at the moment we give up. */
	if (resource->type == MXFS_LTYPE_INODE)
		pr_warn("mxfs: P-CAWEXH ino=%llu req=%u our_mode=%d ea_claim=%d ea_compat=%d ea_regwait=%d div=%d yield_bo=%d yield_stale=%d wait_enoent=%d last_hex=%llx last_hpr=%llx\n",
			(unsigned long long)resource->ino, mode, last_our_mode,
			ea_claim, ea_compat, ea_regwait, div_lo, yield_bo,
			yield_stale, wait_enoent,
			(unsigned long long)last_hex,
			(unsigned long long)last_hpr);
	/* sess48: we may have registered a waiter bit on the last slot before
	 * exhausting retries — drop it so a stale EX waiter can't starve peer
	 * readers via defer_for_waiter. */
	caw_drop_own_waiter(ctx, slot_idx);
	rc = -ETIMEDOUT;

out:
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/* ─── mxfs_dlm_caw_unlock ─── */

int mxfs_dlm_caw_unlock(struct mxfs_dlm_caw_ctx *ctx,
			   const struct mxfs_resource_id *resource)
{
	return mxfs_dlm_caw_unlock_gen(ctx, resource, 0, false);
}

/*
 * v0.6.2: gen-aware unlock.  expected_gen32 != 0 anchors the abort check at
 * the CALLER's release-decision capture (mxfs_dlm_caw_grant_seq32) instead of
 * unlock entry, closing the window where a local re-grant lands between the
 * caller's compare and this function's snapshot.  expected_gen32 == 0 keeps
 * the entry-time snapshot (unconditional release semantics preserved for
 * eviction/unmount/purge callers).
 *
 * ccloop cc87fed3 sess8: is_free -- when true, this unlock corresponds to a
 * genuinely FREED inode (caller has already verified nlink==0 and is doing
 * destructive inactivation), not an idle-gap release of a still-live inode.
 * If the release ends up writing a tombstone (no other holders/waiters),
 * ALSO clear dir_epoch/last_ex_slot in that SAME CAS -- piggybacking on the
 * unlock this function already performs, zero extra I/O.  Without this, a
 * reused inode number inherits the freed incarnation's last_ex_slot via
 * caw_claim_inherit_epoch, sees a false cross-node handoff on its first EX,
 * and pays the private-subdir FUA-storm coherency path a brand-new inode has
 * no business paying for (dlm_scaling@32 op-rate collapse).  A prior attempt
 * at this fix (P144, now removed) tried to detect+clear the tombstone via a
 * SEPARATE find_slot+read+CAS call issued right after this function returned
 * -- besides being structurally broken (find_slot's rc==0 "found" contract
 * only ever fires for a LIVE slot, so it silently no-op'd 2190/2190 times in
 * a live 32-node run), a corrected standalone version that DID work measurably
 * regressed the same test to 0/32 (from 27/32 with the broken no-op version)
 * by adding a synchronous extra read+CAS round-trip to every single free,
 * confirming the TRAP-1 warning already on record (mxfs_dlm_caw_purge_node
 * header): extra per-free FUA I/O measurably eats the shared aggregate
 * iSCSI-command-rate ceiling that ALL 32 nodes' foreground ops compete for,
 * even off the per-op latency path.  Piggybacking here is the only form of
 * this fix that costs nothing.
 */
int mxfs_dlm_caw_unlock_gen(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint32_t expected_gen32, bool is_free)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint64_t rel_seq0;
	uint64_t unlock_deadline = 0;
	int retry;
	int rc;

	if (!ctx || !resource)
		return -EINVAL;

	/* Single-node fast path: just remove from in-memory tracking */
	if (ctx->single_node) {
		mem_lock_untrack(ctx, resource);
		return 0;
	}

	/* sess78 DIAGNOSTIC: matches the in-memory-only INODE grant above. */
	{
		extern int mxfs_inode_caw_local;
		if (mxfs_inode_caw_local &&
		    resource->type == MXFS_LTYPE_INODE) {
			mem_lock_untrack(ctx, resource);
			return 0;
		}
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}

	/* v0.6.2 unlock-vs-regrant closure: serialize against the local
	 * already-held acquire shortcut and arm the re-grant abort check
	 * (see caw_grant_meta_seq block comment). */
	caw_release_mark(ctx, resource, true);
	rel_seq0 = caw_grant_meta_seq(ctx, resource);
	if (expected_gen32 != 0 &&
	    ((uint32_t)rel_seq0 ?: (rel_seq0 ? 1 : 0)) != expected_gen32) {
		/* a re-grant landed between the caller's capture and here */
		caw_release_mark(ctx, resource, false);
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ESTALE;
	}

	/*
	 * sess3(ccloop 26c41354): under a 16-node hot-shared-dir CAS storm the
	 * INODE unlock CAS keeps miscomparing (peers mutate the slot between our
	 * read and our compare-and-write).  With the fixed 100-retry cap it can
	 * exhaust -> -EIO -> the caller leaves the lock HELD -> the waiting peer
	 * re-BASTs -> mxfs-ino-bast requeues -> kworker storm / load 870 WEDGE.
	 * A miscompare is ALWAYS transient (someone else's CAS just landed; our
	 * bit-clear is still valid on re-read), and unlike acquire, retrying an
	 * unlock longer is SAFE (we still hold the lock, only release later — no
	 * double-grant window).  So when caw_unlock_backoff is set, bound the
	 * INODE-unlock retry by a generous wall clock instead of a tight count:
	 * the lock ALWAYS eventually releases, breaking the re-BAST amplification.
	 */
	/* sess6 (ccloop 72513a13): ICLUSTER unlocks get the same wall-clock
	 * bound.  PROVEN at 32/cawd (cc NO_TERMINAL wedge): the type=6 unlock
	 * kept the tight 100-retry cap, exhausted against 32-node waiter-bit
	 * churn, and the swallowed failure left a stale on-disk cluster EX
	 * (slot-8 bit) that starved all 32 nodes' PR acquires 380s+ (the
	 * holder heartbeats, so P-WAIT-EXTEND extends forever).  Unlock
	 * retry-to-deadline is exactly as safe here as for inodes: we still
	 * hold the grant, releasing later is never a double-grant. */
	if (mxfs_caw_unlock_backoff &&
	    (resource->type == MXFS_LTYPE_INODE ||
	     resource->type == MXFS_LTYPE_ICLUSTER))
		unlock_deadline = mxfs_pal_time_ms() + MXFS_CAW_UNLOCK_DEADLINE_MS;

	for (retry = 0;
	     retry < MXFS_CAW_MAX_RETRIES ||
	     (unlock_deadline && mxfs_pal_time_ms() < unlock_deadline);
	     retry++) {
		if (caw_grant_meta_seq(ctx, resource) != rel_seq0)
			goto regrant_abort;
		caw_inode_backoff(ctx, resource, retry);	/* sess39 */
		rc = find_slot(ctx, resource, &slot_idx, cur_slot, &empty_idx);
		if (rc == -ENOENT) {
			rc = 0; /* Not found — nothing to unlock */
			goto out;
		}
		if (rc)
			goto out;

		/*
		 * sess135 (ccloop 14d31183) P108 root-cause hardening: if our
		 * bit is in NO holder bitmap and NOT in waiters, there is
		 * nothing to unlock — return WITHOUT a CAS.  The prior
		 * unconditional clear+CAS made every stale-BAST cleanup
		 * unlock a gen-bump write (2441/run measured on the hot
		 * shared-dir slot), and its miscompare-retry loop re-read
		 * and re-cleared whatever appeared — including a fresh EX
		 * grant CAS'd in by this node's own concurrent slow-path
		 * acquire (proven: P135-INO-UNLOCK bast_notify 88.3794 →
		 * P106-EXGRANT 88.3806 → strip hex=1->0 88.3814 → P108).
		 */
		if (node_held_mode(cur_slot, ctx->node_bit) == MXFS_LOCK_NL &&
		    !(cur_slot->waiters & ctx->node_bit) &&
		    !(cur_slot->yield_to & ctx->node_bit)) {
			untrack_held(ctx, slot_idx);
			rc = 0;
			goto out;
		}

		*new_slot = *cur_slot;

		/* Clear our bit from ALL holder bitmaps */
		new_slot->holders_ex &= ~ctx->node_bit;
		new_slot->holders_pw &= ~ctx->node_bit;
		new_slot->holders_pr &= ~ctx->node_bit;
		new_slot->holders_cw &= ~ctx->node_bit;
		new_slot->holders_cr &= ~ctx->node_bit;
		new_slot->granted_mode = recompute_granted_mode(new_slot);
		new_slot->generation++;
		new_slot->last_modified_ms = mxfs_pal_time_ms();
		/* P109 Phase 1.1 (NEWARCH) — canonical unlock entry.  Every
		 * call here clears OUR bit in every mode bitmap atomically.
		 * The OK caller is xfs's mxfs_dlm_bast_process (which sets
		 * i_dlm_mode = NL under spinlock BEFORE invoking us); any
		 * non-bast caller of mxfs_dlm_caw_unlock would leak a
		 * stale-cached i_dlm_mode.  Logs cur->granted_mode so the
		 * stale-EX hunt can identify whether unlock was called for
		 * a slot already showing our bit clear. */
		if (caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P109-CLR-UNLOCK type=%s id=%llu "
			    "cur_gm=%u cur_h_ex=%llx cur_h_pr=%llx slot=%u",
			    resource->type == MXFS_LTYPE_INODE ? "I" :
			    resource->type == MXFS_LTYPE_AG ? "A" : "O",
			    (unsigned long long)(
			      resource->type == MXFS_LTYPE_INODE ?
			        resource->ino :
			        (uint64_t)resource->ag_number),
			    cur_slot->granted_mode,
			    (unsigned long long)cur_slot->holders_ex,
			    (unsigned long long)cur_slot->holders_pr,
			    slot_idx);

		/*
		 * Yield-to-priority: if there are waiters, give them
		 * priority over the releasing node by setting yield_to.
		 * This prevents the releasing node from immediately
		 * reacquiring before any waiter gets a chance.
		 */
		if (cur_slot->waiters) {
			uint64_t ex_w = cur_slot->waiters_ex &
					cur_slot->waiters;
			uint64_t pr_w = cur_slot->waiters &
					~cur_slot->waiters_ex;

			if (mxfs_caw_fair_handoff &&
			    resource->type == MXFS_LTYPE_INODE && ex_w) {
				/*
				 * sess2(ccloop 26c41354) FAIR HANDOFF: among EX
				 * waiters hand off to ONE round-robin next (first
				 * after our node bit, wrapping) instead of all.
				 * The chosen node clears yield_to on promote and
				 * picks the next on its own release, bounding each
				 * EX waiter's wait to O(N) handoffs — kills the
				 * self-promote free-for-all (16-node victim-node
				 * loss).  PR-only waiters still batch-grant below.
				 *
				 * v0.10.39 shared-class anti-starvation: the pure
				 * EX round-robin starves PR waiters FOREVER while
				 * EX waiters keep arriving (proven: 32-node
				 * dir_reuse — verify's readdir PR starved 240s
				 * behind 31 creators' dir-EX rotation, rc=-110
				 * shutdown).  Once the slot has granted
				 * MXFS_CAW_EX_STREAK_YIELD consecutive EX-class
				 * tenures, yield ONE turn to the WHOLE shared
				 * class (PR-PR compatible: they all promote
				 * together, and their grant resets the streak
				 * inside the same CAS).
				 */
				bool streak_yield = (pr_w &&
					cur_slot->ex_grant_streak >=
					MXFS_CAW_EX_STREAK_YIELD);
				if (streak_yield)
					new_slot->yield_to = pr_w;
				else
					new_slot->yield_to =
						caw_pick_next_ex_waiter(
							ex_w, ctx->node_bit);
				/* v0.10.42: do NOT reset the streak here.  It
				 * resets ONLY when the PR class actually
				 * promotes (caw_grant_streak_note on a PR
				 * grant).  Resetting on yield (v0.10.40) made
				 * streak-yield fire only ~2x/run so the
				 * v0.10.41 upgrader-defer never engaged and
				 * PR/EX still starved (B3 PR, B4 EX).  Keeping
				 * the streak high fires yield_to=pr_w on every
				 * overlap release; the upgrader-defer then
				 * guarantees pr_w promotes (no B2 EX-deadlock)
				 * and THAT PR grant resets the streak. */
				/* v0.10.40: only (re)arm the stale-clock when the
				 * ticket VALUE changes.  A persistent yield_to
				 * (pr_w that cannot promote while an EX holder
				 * lingers) MUST age out so the acquire-path 5s
				 * stale-clear can break the deadlock — otherwise
				 * every peer release refreshes yield_set_ms and
				 * the hint never goes stale (sess130 livelock,
				 * re-opened for fresh EX waiters by the v0.10.39
				 * streak yield: 32-node dir_reuse r3, 20 nodes
				 * EX-starved 360s -> rc=-110 shutdown). */
				if (new_slot->yield_to != cur_slot->yield_to)
					new_slot->yield_set_ms =
						mxfs_pal_time_real_ms();
				if (streak_yield)
					pr_warn_ratelimited(
					    "mxfs: P-STREAK-YIELD ino=%llu streak=%u pr_w=%llx ex_w=%llx yt=%llx armed=%d\n",
					    (unsigned long long)resource->ino,
					    cur_slot->ex_grant_streak,
					    (unsigned long long)pr_w,
					    (unsigned long long)ex_w,
					    (unsigned long long)new_slot->yield_to,
					    (int)(new_slot->yield_to !=
						  cur_slot->yield_to));
			} else {
				new_slot->yield_to = cur_slot->waiters;
				if (new_slot->yield_to != cur_slot->yield_to)
					new_slot->yield_set_ms =
						mxfs_pal_time_real_ms();
			}
		}

		/* If no holders and no waiters, write a tombstone so the
		 * probe chain remains traversable.  See find_slot.  Keeps
		 * resource + dir_epoch (idle-gap handoff continuity) UNLESS
		 * this release is for a genuinely freed inode (is_free), in
		 * which case that continuity would be a FALSE handoff signal
		 * for whatever unrelated file next reuses this inode number
		 * -- clear it in this same CAS (see this function's own
		 * comment for the full mechanism + why it must be here and
		 * not a separate follow-up call). */
		if (!slot_has_holders(new_slot) && !new_slot->waiters) {
			caw_tombstone_slot(new_slot);
			if (is_free && (new_slot->dir_epoch != 0 ||
			    new_slot->last_ex_slot != MXFS_CAW_EX_SLOT_NONE)) {
				new_slot->dir_epoch = 0;
				new_slot->last_ex_slot = MXFS_CAW_EX_SLOT_NONE;
				pr_warn_ratelimited(
				    "mxfs: P144-EPOCH-FREE-RESET ino=%llu slot=%u — cleared stale dir_epoch/last_ex_slot at inode free (unlock piggyback)\n",
				    (unsigned long long)resource->ino, slot_idx);
			}
		}

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR CAW-UNLOCK ino=%llu slot=%u "
				"cur_hex=%llx cur_hpr=%llx cur_gen=%llu "
				"new_hex=%llx new_hpr=%llx new_gen=%llu "
				"tomb=%d t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				(unsigned long long)cur_slot->holders_ex,
				(unsigned long long)cur_slot->holders_pr,
				(unsigned long long)cur_slot->generation,
				(unsigned long long)new_slot->holders_ex,
				(unsigned long long)new_slot->holders_pr,
				(unsigned long long)new_slot->generation,
				(new_slot->magic == MXFS_CAW_TOMBSTONE_MAGIC),
				(unsigned long long)mxfs_pal_time_ms());
		}

		/* v0.6.3: last-instant anchor re-check.  The already-held
		 * shortcut grants are MEMORY-ONLY (no slot write), so a CAS
		 * miscompare will never surface a mid-loop local re-grant —
		 * this check is the only barrier between such a grant and
		 * our clear committing over it.  find_slot's disk read above
		 * gives the shortcut's store ample time to land. */
		if (caw_grant_meta_seq(ctx, resource) != rel_seq0)
			goto regrant_abort;
		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);

		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on()) {
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P13-INSTR CAW-UNLOCK-RESULT ino=%llu "
				"slot=%u rc=%d t_ms=%llu",
				(unsigned long long)resource->ino, slot_idx,
				rc, (unsigned long long)mxfs_pal_time_ms());
		}

		if (rc == -EAGAIN) {
			/*
			 * sess2(ccloop 26c41354): jittered backoff on the
			 * INODE unlock CAS miscompare (mxfs_caw_unlock_backoff)
			 * to desync the 16-node hot-slot CAS storm so the
			 * unlock wins instead of tight-looping to exhaustion ->
			 * -EIO -> stuck-lock BAST-storm WEDGE (dir_reuse: load
			 * 870, 1000+ mxfs-ino-bast kworkers).  The acquire path
			 * already desyncs (sess39); the unlock lacked it.
			 * Node-phased + retry-escalating so contenders spread.
			 */
			if (mxfs_caw_unlock_backoff &&
			    resource->type == MXFS_LTYPE_INODE)
				mxfs_pal_sleep_ms(1 + (retry & 7) +
						  (ctx->local_node % 8));
			continue;
		}
		if (rc)
			goto out;

		/* v0.6.4 P141: attribute every committed EX-bit clear on an
		 * INODE resource.  Residual P106-STALE-EX events (test4
		 * ino=137 @380.662, prebump build) show a fresh grant's bit
		 * vanishing ~1.3ms after EXGRANT with NO regrant-abort — the
		 * gen-aware loop provably cannot do that (read-after-CAS ⇒
		 * check-after-prebump), so SOME path is stripping the bit.
		 * seq_now vs rel_seq0 discriminates: seq_now advanced ⇒ this
		 * unlock raced a re-grant and the checks missed (ordering
		 * bug); seq unchanged ⇒ this unlock was legitimate and the
		 * phantom's clearer is elsewhere (DIVERG/dead/release-all). */
		if (resource->type == MXFS_LTYPE_INODE &&
		    (cur_slot->holders_ex & ctx->node_bit)) {
			static int p141_n;

			if (p141_n++ < 500)
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P141-UNLK-EXCLR ino=%llu expected=%u rel_seq0=%llu seq_now=%llu retry=%d gen=%llu",
				    (unsigned long long)resource->ino,
				    expected_gen32,
				    (unsigned long long)rel_seq0,
				    (unsigned long long)caw_grant_meta_seq(ctx, resource),
				    retry,
				    (unsigned long long)cur_slot->generation);
		}
		untrack_held(ctx, slot_idx);
		/* ccloop 72513a13 sess3: our clear just committed and peers
		 * were waiting on this slot — nudge them awake instead of
		 * letting them ride out the poll interval. */
		if (cur_slot->waiters & ~ctx->node_bit)
			caw_send_grant_mcast(ctx, resource);
		rc = 0;
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: unlock exhausted %d retries (deadline_ms=%llu) for ino=%llu type=%u",
		     retry,
		     (unsigned long long)unlock_deadline,
		     (unsigned long long)resource->ino,
		     resource->type);
	rc = -EIO;
	goto out;

regrant_abort:
	/* A local acquire re-granted this resource since the release began —
	 * the on-disk bit belongs to the NEW tenure.  Leave it. */
	{
		static int regrant_abort_logged;

		if (regrant_abort_logged < 50) {
			regrant_abort_logged++;
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P-UNLOCK-REGRANT-ABORT type=%u "
			    "ino=%llu ag=%u retry=%d",
			    resource->type,
			    (unsigned long long)resource->ino,
			    resource->ag_number, retry);
		}
	}
	/* gen-anchored callers get -ESTALE (stranded: the release did NOT
	 * happen; re-arm the BAST).  Legacy unconditional callers keep 0. */
	rc = expected_gen32 ? -ESTALE : 0;

out:
	caw_release_mark(ctx, resource, false);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/* ─── mxfs_dlm_caw_held (sess39 read-only diagnostic) ─── */
/* Returns 1 if THIS node currently holds the resource on disk, 0 if not,
 * <0 on I/O error.  One slot read; no modification. */
int mxfs_dlm_caw_held(struct mxfs_dlm_caw_ctx *ctx,
		      const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t our_mode;
	int rc;

	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 1;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return -ENOMEM;
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		/* sess135 P135: a held() miss on a low inode is the P108
		 * trigger — log whether the slot is GONE vs an I/O error. */
		if (resource->type == MXFS_LTYPE_INODE && caw_instr_on())
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P135-HELD-MISS ino=%llu rc=%d "
			    "(no live slot found) self=%llx",
			    (unsigned long long)resource->ino, rc,
			    (unsigned long long)ctx->node_bit);
		mxfs_pal_free(slot);
		return (rc == -ENOENT) ? 0 : rc;
	}
	our_mode = node_held_mode(slot, ctx->node_bit);
	if (our_mode == MXFS_LOCK_NL &&
	    resource->type == MXFS_LTYPE_INODE &&
	    caw_instr_on())
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P135-HELD-MISS ino=%llu slot=%u gen=%u "
		    "hex=%llx hpr=%llx hpw=%llx w=%llx gm=%u yt=%llx "
		    "self=%llx (bit absent from live slot)",
		    (unsigned long long)resource->ino, slot_idx,
		    slot->generation,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->waiters,
		    slot->granted_mode,
		    (unsigned long long)slot->yield_to,
		    (unsigned long long)ctx->node_bit);
	mxfs_pal_free(slot);
	return (our_mode != MXFS_LOCK_NL) ? 1 : 0;
}

/*
 * ccloop cc87fed3 sess3 (RULE 4 PROVEN — fence_during_write@8/caw D-state
 * deadlock): mxfs_dlm_caw_held() above collapses the real per-node mode to a
 * boolean, which is unsafe for a caller (mxfs_v5_dlm_inode_granted_mode ->
 * mxfs_ilock_admit_ioend / P79-NESTADMIT) that upgrades ip->i_dlm_mode to
 * whatever it reads back — collapsing a real PR-only hold to "EX" would let
 * a local writer believe it has exclusive access when the cluster only
 * granted shared/read.  Returns the actual MXFS_LOCK_* mode this node holds
 * on `resource` (NL if not found / no slot / OOM), mirroring
 * mxfs_dlm_granted_mode()'s TCP-side contract exactly so
 * mxfs_v5_dlm_inode_granted_mode can treat both transports uniformly.
 */
uint8_t mxfs_dlm_caw_granted_mode(struct mxfs_dlm_caw_ctx *ctx,
				  const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t our_mode;
	int rc;

	if (!ctx || !resource)
		return MXFS_LOCK_NL;
	if (ctx->single_node)
		return MXFS_LOCK_EX;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return MXFS_LOCK_NL;
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		mxfs_pal_free(slot);
		return MXFS_LOCK_NL;
	}
	our_mode = node_held_mode(slot, ctx->node_bit);
	mxfs_pal_free(slot);
	return our_mode;
}

/* v0.6.4 P142: raw slot image dump for the P106-STALE-EX forensic — called
 * by the XFS dir fast-path ONLY at the phantom moment (cached EX, held==0),
 * so every line is signal.  Logs the exact image the verify path would read
 * (hint short-circuit included) plus the hint value. */
void mxfs_dlm_caw_dump_slot(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint32_t hint = UINT32_MAX;
	int rc;

	if (!ctx || !resource || ctx->single_node)
		return;
	slot = mxfs_pal_alloc(sizeof(*slot));
	if (!slot)
		return;
	slot_hint_get(ctx, resource, &hint);
	rc = find_slot(ctx, resource, &slot_idx, slot, &empty_idx);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P142-STALE-IMG ino=%llu NO-SLOT rc=%d hint=%u empty=%u self=%llx",
		    (unsigned long long)resource->ino, rc, hint, empty_idx,
		    (unsigned long long)ctx->node_bit);
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
		    "mxfs: P142-STALE-IMG ino=%llu slot=%u hint=%u gen=%u hex=%llx hpw=%llx hpr=%llx w=%llx yt=%llx gm=%u epoch=%u lastex=%u self=%llx",
		    (unsigned long long)resource->ino, slot_idx, hint,
		    slot->generation,
		    (unsigned long long)slot->holders_ex,
		    (unsigned long long)slot->holders_pw,
		    (unsigned long long)slot->holders_pr,
		    (unsigned long long)slot->waiters,
		    (unsigned long long)slot->yield_to,
		    slot->granted_mode, slot->dir_epoch, slot->last_ex_slot,
		    (unsigned long long)ctx->node_bit);
	}
	mxfs_pal_free(slot);
}

/* ─── mxfs_dlm_caw_ex_count (sess52 RULE-4 concurrent-EX detector) ─────────
 * The never-run measurement specified at xfs_alloc.c:2201 / state.md:
 * read the ENTIRE probe chain for `resource` RAW (via caw_count_resource_slots,
 * which does NOT trigger slot_appears_corrupt's popcount>1 auto-repair across
 * separate slots) and return popcount(OR of holders_ex across all live slots).
 * popcount>1 == two distinct nodes hold EX on the same AG simultaneously ==
 * the transient concurrent-EX that produces the gen-current-but-disk-stale
 * bnobt write (P88 disk_differs=1 ag_held=1 buf_gen==pag_gen).  *nslots_out
 * receives the live-slot count (>1 == sess47 claim-race: two slots same
 * resource).  Read-only; no slot modification.  Returns the EX popcount, or
 * <0 on error. */
int mxfs_dlm_caw_ex_count(struct mxfs_dlm_caw_ctx *ctx,
			  const struct mxfs_resource_id *resource,
			  int *nslots_out)
{
	uint32_t dup_slots[8];
	uint64_t holders_ex_or = 0;
	int n;

	if (nslots_out)
		*nslots_out = 0;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	n = caw_count_resource_slots(ctx, resource, dup_slots,
				     8, &holders_ex_or);
	if (n < 0)
		return n;
	if (nslots_out)
		*nslots_out = n;
	return (int)mxfs_pal_popcount64(holders_ex_or);
}

/* ─── mxfs_dlm_caw_self_held_scan (ccloop a864 sess3, RULE-4 orphan probe) ───
 * Duplicate-immune "does THIS node hold `resource` EX on disk" check.  Walks
 * the ENTIRE probe chain (via caw_count_resource_slots) instead of the hinted
 * find_slot, so it stays correct even when the resource lives in >1 live slot
 * (claim-race dup) — the exact blind spot that lets the hinted mxfs_dlm_caw_held
 * miss an orphaned EX bit a peer's scan still sees.  Returns 1 if our node_bit
 * is set in holders_ex OR'd across every live slot for the resource, 0 if not,
 * <0 on error.  *nslots_out = live-slot count (>1 => dup); *hex_or_out = OR of
 * holders_ex across them.  Read-only. */
int mxfs_dlm_caw_self_held_scan(struct mxfs_dlm_caw_ctx *ctx,
				const struct mxfs_resource_id *resource,
				int *nslots_out, uint64_t *hex_or_out)
{
	uint32_t dup_slots[8];
	uint64_t holders_ex_or = 0;
	int n;

	if (nslots_out)
		*nslots_out = 0;
	if (hex_or_out)
		*hex_or_out = 0;
	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 1;
	n = caw_count_resource_slots(ctx, resource, dup_slots, 8,
				     &holders_ex_or);
	if (n < 0)
		return n;
	if (nslots_out)
		*nslots_out = n;
	if (hex_or_out)
		*hex_or_out = holders_ex_or;
	return (holders_ex_or & ctx->node_bit) ? 1 : 0;
}

/* ─── mxfs_dlm_caw_force_release_self (ccloop a864 sess3 orphan reclaim) ───
 * UNCONDITIONAL scan-based self-release: walk the WHOLE probe chain and CAS-clear
 * our node_bit from EVERY live slot matching `resource`, in EVERY holder/waiter/
 * yield bitmap.  Unlike mxfs_dlm_caw_unlock_gen this does NOT consult the local
 * grant-meta seq gate and does NOT early-return on a hinted find_slot miss — it
 * is the recovery for an ORPHANED holder bit that the normal release left set
 * (bast_process's unlock ignored its return / aborted on a transient seq change,
 * leaving in-core mode=NL + state stuck DEMOTING while the on-disk bit persists,
 * so every peer BAST is swallowed and the cluster wedges — PROVEN dir_reuse@32:
 * held_raw=5 scan_mine=1 nslots=1, i.e. the bit is cleanly findable but never
 * cleared).  The CALLER MUST have serialized against a legitimate local re-grant
 * (in-core mode==NL with state==DEMOTING, which blocks the same-node acquire fast
 * path) so no fresh grant is clobbered; cross-node, only THIS node ever sets our
 * bit, so clearing it is safe.  Returns #slots cleared, or <0 on error. */
int mxfs_dlm_caw_force_release_self(struct mxfs_dlm_caw_ctx *ctx,
				    const struct mxfs_resource_id *resource)
{
	struct mxfs_caw_lock_slot *cur;
	struct mxfs_caw_lock_slot *new;
	uint32_t base;
	uint32_t i;
	int cleared = 0;

	if (!ctx || !resource)
		return -EINVAL;
	if (ctx->single_node)
		return 0;
	cur = mxfs_pal_alloc(sizeof(*cur));
	new = mxfs_pal_alloc(sizeof(*new));
	if (!cur || !new) {
		mxfs_pal_free(cur);
		mxfs_pal_free(new);
		return -ENOMEM;
	}
	base = resource_hash_raw(resource) % MXFS_CAW_MAX_SLOTS;
	for (i = 0; i < MXFS_CAW_CLAIMRACE_SCAN_MAX; i++) {
		uint32_t idx = (base + i) % MXFS_CAW_MAX_SLOTS;
		int attempt;

		if (read_slot(ctx, idx, cur) != 0)
			continue;
		if (cur->magic == 0)
			break;			/* end of probe chain */
		if (cur->magic != MXFS_CAW_MAGIC)
			continue;		/* tombstone — keep walking */
		if (memcmp(&cur->resource, resource, sizeof(*resource)) != 0)
			continue;		/* live slot, different resource */

		/* live slot for our resource — CAS-clear our bit if present */
		for (attempt = 0; attempt < MXFS_CAW_MAX_RETRIES; attempt++) {
			uint64_t mine = (cur->holders_ex | cur->holders_pw |
					 cur->holders_pr | cur->holders_cw |
					 cur->holders_cr | cur->waiters |
					 cur->yield_to) & ctx->node_bit;
			int rc;

			if (!mine) {
				untrack_held(ctx, idx);
				break;		/* our bit not in this slot */
			}
			*new = *cur;
			new->holders_ex &= ~ctx->node_bit;
			new->holders_pw &= ~ctx->node_bit;
			new->holders_pr &= ~ctx->node_bit;
			new->holders_cw &= ~ctx->node_bit;
			new->holders_cr &= ~ctx->node_bit;
			new->waiters    &= ~ctx->node_bit;
			new->waiters_ex &= ~ctx->node_bit;
			new->yield_to   &= ~ctx->node_bit;
			new->granted_mode = recompute_granted_mode(new);
			new->generation++;
			new->last_modified_ms = mxfs_pal_time_ms();
			rc = caw_slot(ctx, idx, cur, new);
			if (rc == 0) {
				untrack_held(ctx, idx);
				cleared++;
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: CAW-FORCE-REL type=%u ino=%llu slot=%u gen=%u->%u self=%llx (orphan holder bit cleared)",
				    resource->type,
				    (unsigned long long)resource->ino, idx,
				    cur->generation, new->generation,
				    (unsigned long long)ctx->node_bit);
				break;
			}
			if (rc == -EAGAIN) {
				/* CAS miscompare — re-read and retry this slot */
				if (read_slot(ctx, idx, cur) != 0)
					break;
				continue;
			}
			break;			/* I/O error — give up on this slot */
		}
	}
	mxfs_pal_free(cur);
	mxfs_pal_free(new);
	return cleared;
}

/* ─── mxfs_dlm_caw_convert ─── */

int mxfs_dlm_caw_convert(struct mxfs_dlm_caw_ctx *ctx,
			    const struct mxfs_resource_id *resource,
			    uint8_t new_mode)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	uint32_t slot_idx = 0;
	uint32_t empty_idx = UINT32_MAX;
	uint8_t old_mode;
	int retry;
	int rc;

	if (!ctx || !resource)
		return -EINVAL;

	if (new_mode == MXFS_LOCK_NL)
		return mxfs_dlm_caw_unlock(ctx, resource);

	/* Single-node fast path: just update in-memory tracking */
	if (ctx->single_node) {
		mem_lock_track(ctx, resource, new_mode);
		return 0;
	}

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}

	for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
		caw_inode_backoff(ctx, resource, retry);	/* sess39 */
		rc = find_slot(ctx, resource, &slot_idx, cur_slot, &empty_idx);
		if (rc == -ENOENT) {
			rc = -ENOENT; /* Can't convert a lock we don't hold */
			goto out;
		}
		if (rc)
			goto out;

		/* Verify we actually hold the lock */
		old_mode = node_held_mode(cur_slot, ctx->node_bit);
		if (old_mode == MXFS_LOCK_NL) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: convert but node %u not holding "
				     "lock on ino=%llu type=%u",
				     ctx->local_node,
				     (unsigned long long)resource->ino,
				     resource->type);
			rc = -EINVAL;
			goto out;
		}

		/* Same mode — no-op */
		if (old_mode == new_mode) {
			rc = 0;
			goto out;
		}

		/* Downgrade: always compatible with existing holders since
		 * we're reducing our lock strength */
		if (new_mode < old_mode) {
			*new_slot = *cur_slot;
			{
				uint64_t *old_hp = holders_for_mode(new_slot,
								    old_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
			}
			{
				uint64_t *new_hp = holders_for_mode(new_slot,
								    new_mode);
				if (new_hp)
					*new_hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (rc == -EAGAIN)
				continue;
			if (rc == 0)
				caw_grant_meta_store(ctx, resource,
						     new_slot->dir_epoch,
						     false,
						     new_slot->dir_block0_fsb,
						     new_slot->dir_block0_gen);
			goto out;
		}

		/* Upgrade: check compatibility excluding ourselves */
		if (compatible_excluding_self(cur_slot, new_mode,
					       ctx->node_bit)) {
			bool cv_handoff;

			*new_slot = *cur_slot;
			{
				uint64_t *old_hp = holders_for_mode(new_slot,
								    old_mode);
				if (old_hp)
					*old_hp &= ~ctx->node_bit;
			}
			{
				uint64_t *new_hp = holders_for_mode(new_slot,
								    new_mode);
				if (new_hp)
					*new_hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			cv_handoff = caw_grant_epoch_update(ctx, new_slot,
							    new_mode);

			caw_grant_seq_prebump(ctx, resource);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (rc == -EAGAIN)
				continue;
			if (rc == 0)
				caw_grant_meta_store(ctx, resource,
						     new_slot->dir_epoch,
						     cv_handoff,
						     new_slot->dir_block0_fsb,
						     new_slot->dir_block0_gen);
			goto out;
		}

		/* Upgrade not compatible — register as waiter for upgrade */
		*new_slot = *cur_slot;
		new_slot->waiters |= ctx->node_bit;
		if (new_mode == MXFS_LOCK_EX || new_mode == MXFS_LOCK_PW)
			new_slot->waiters_ex |= ctx->node_bit;   /* sess50: track exclusive waiter */
		if (new_mode > new_slot->waiter_mode)
			new_slot->waiter_mode = new_mode;
		new_slot->generation++;

		rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
		if (rc == -EAGAIN)
			continue;
		if (rc)
			goto out;

		/* Send BAST hint */
		caw_send_bast_mcast(ctx, resource, new_mode);

		/* Wait for grant. On success, the waiter-to-holder
		 * promotion in caw_wait_for_grant sets the new mode.
		 * We still need to clear the old mode on success. */
		rc = caw_wait_for_grant(ctx, slot_idx, resource, new_mode);
		if (rc == 0) {
			/* Clear old mode — we now hold new_mode */
			int clear_retry;
			for (clear_retry = 0; clear_retry < 20; clear_retry++) {
				int rc2 = read_slot(ctx, slot_idx, cur_slot);
				if (rc2)
					break;
				*new_slot = *cur_slot;
				{
					uint64_t *old_hp =
						holders_for_mode(new_slot,
								 old_mode);
					if (old_hp)
						*old_hp &= ~ctx->node_bit;
				}
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();

				rc2 = caw_slot(ctx, slot_idx, cur_slot,
					       new_slot);
				if (rc2 != -EAGAIN)
					break;
			}
		}
		goto out;
	}

	mxfs_pal_log(MXFS_LOG_ERR,
		     "dlm_caw: convert exhausted %d retries for ino=%llu type=%u",
		     MXFS_CAW_MAX_RETRIES,
		     (unsigned long long)resource->ino,
		     resource->type);
	/* sess48: drop any waiter bit registered for the upgrade before giving
	 * up, else it lingers as a phantom EX waiter starving peer readers. */
	caw_drop_own_waiter(ctx, slot_idx);
	rc = -ETIMEDOUT;

out:
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	return rc;
}

/* ─── mxfs_dlm_caw_release_all ─── */

void mxfs_dlm_caw_release_all(struct mxfs_dlm_caw_ctx *ctx)
{
	uint32_t *local_slots;
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	int local_count;
	int i;

	if (!ctx)
		return;

	/* Clear in-memory lock tracking regardless of mode */
	if (ctx->mem_lock_mutex) {
		mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
		ctx->mem_lock_count = 0;
		mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: releasing all locks for node %u",
		     ctx->local_node);

	local_slots = mxfs_pal_alloc(256 * sizeof(uint32_t));
	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!local_slots || !cur_slot || !new_slot) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: release_all alloc failed for node %u",
			     ctx->local_node);
		mxfs_pal_free(local_slots);
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return;
	}

	/*
	 * Snapshot held list under lock, then release outside the lock.
	 * Process in batches of 256 to avoid massive stack allocation.
	 */
	for (;;) {
		mxfs_pal_mutex_lock(ctx->held.lock);
		local_count = ctx->held.count;
		if (local_count > 256)
			local_count = 256;
		if (local_count == 0) {
			mxfs_pal_mutex_unlock(ctx->held.lock);
			break;
		}
		memcpy(local_slots, ctx->held.slots,
		       local_count * sizeof(uint32_t));
		mxfs_pal_mutex_unlock(ctx->held.lock);

		for (i = 0; i < local_count; i++) {
			int retry;

			for (retry = 0; retry < 20; retry++) {
				int rc = read_slot(ctx, local_slots[i],
						   cur_slot);
				if (rc)
					break;
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					break;

				*new_slot = *cur_slot;
				new_slot->holders_ex &= ~ctx->node_bit;
				new_slot->holders_pw &= ~ctx->node_bit;
				new_slot->holders_pr &= ~ctx->node_bit;
				new_slot->holders_cw &= ~ctx->node_bit;
				new_slot->holders_cr &= ~ctx->node_bit;
				new_slot->waiters &= ~ctx->node_bit;
				new_slot->waiters_ex &= ~ctx->node_bit;	/* sess50 */
				new_slot->yield_to &= ~ctx->node_bit;
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->waiter_mode =
					recompute_waiter_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();

				if (!slot_has_holders(new_slot) &&
				    !new_slot->waiters)
					caw_tombstone_slot(new_slot);

				rc = caw_slot(ctx, local_slots[i], cur_slot,
					      new_slot);
				/* P109 Phase 1.1 (NEWARCH) — RELEASE-ALL clears
				 * our bit on every tracked slot at umount.  If
				 * this fires mid-run (not at umount) it's an
				 * unexpected bulk-release that would leak stale
				 * cached i_dlm_mode across many inodes at once.
				 * cur_slot still has the resource embedded. */
				{
				static int p141_ra_n;
				if ((caw_instr_on() || p141_ra_n++ < 200) &&
				    retry == 0)
					mxfs_pal_log(MXFS_LOG_WARN,
					    "mxfs: P109-CLR-RELEASE-ALL type=%s "
					    "id=%llu cur_gm=%u slot=%u cas_rc=%d",
					    cur_slot->resource.type ==
					        MXFS_LTYPE_INODE ? "I" :
					    cur_slot->resource.type ==
					        MXFS_LTYPE_AG ? "A" : "O",
					    (unsigned long long)(
					      cur_slot->resource.type ==
					        MXFS_LTYPE_INODE ?
					        cur_slot->resource.ino :
					        (uint64_t)
					        cur_slot->resource.ag_number),
					    cur_slot->granted_mode,
					    local_slots[i], rc);
				}
				if (rc != -EAGAIN)
					break;
			}

			untrack_held(ctx, local_slots[i]);
			mxfs_pal_cond_resched();
		}
	}

	mxfs_pal_free(local_slots);
	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: all locks released for node %u",
		     ctx->local_node);
}

/* ─── mxfs_dlm_caw_purge_node ─── */

int mxfs_dlm_caw_purge_node(struct mxfs_dlm_caw_ctx *ctx,
			       uint8_t dead_slot)
{
	uint64_t dead_mask;

	if (!ctx)
		return -EINVAL;

	if (dead_slot >= 64) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: purge_node: invalid dead_slot %u",
			     dead_slot);
		return -EINVAL;
	}

	/*
	 * sess70 (ccloop 14d31183) zero_silent_loss FIX — eviction-cascade
	 * amplifier (RULE 4 step 2b, PROVEN by the test1 stack:
	 * disklock_hb_fn -> v5_lease_expire_cb -> mxfs_dlm_caw_purge_node ->
	 * read_slot -> blk_execute_rq, D-state for tens of seconds while peers
	 * fenced live nodes and the verify find starved on the dir ilock).
	 * purge_node runs ON the disklock heartbeat thread.  The old body
	 * scanned ALL 65536 CAW slots with ONE FUA read_slot each (~5-60s on
	 * the contended single shared LUN), and while it scanned THIS node
	 * could not write its own heartbeat -> peers evicted IT in turn ->
	 * fence (SCSI PR preempt) -> reservation-conflict log I/O error -> FS
	 * shutdown (test2 t=440: "DLM shutting down" then "reservation
	 * conflict ... op WRITE" then "log error 0x2") -> the whole-cluster
	 * eviction-cascade collapse.  The batched mxfs_dlm_caw_purge_dead_nodes
	 * already scans the table in 32-slot (16 KiB) chunks (<1s) with
	 * IDENTICAL per-slot clear+CAS semantics; a single dead slot is just
	 * the mask (1 << dead_slot).  Delegate so the heartbeat thread is freed
	 * in well under one beat interval and the cascade cannot start.
	 */
	dead_mask = 1ULL << dead_slot;

	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-H22-PURGE-NODE ENTRY dead_slot=%u (batched)",
		     dead_slot);

	return mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask);
}

/* ─── mxfs_dlm_caw_purge_dead_nodes ─── */

int mxfs_dlm_caw_purge_dead_nodes(struct mxfs_dlm_caw_ctx *ctx,
				     uint64_t dead_mask)
{
	struct mxfs_caw_lock_slot *cur_slot;
	struct mxfs_caw_lock_slot *new_slot;
	struct mxfs_caw_lock_slot *batch;
	const uint32_t BATCH_SLOTS = 32;   /* 32 * 512 = 16 KiB, kzalloc/contiguous */
	uint32_t slot;
	int purged = 0;

	if (!ctx || !dead_mask)
		return 0;

	cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
	new_slot = mxfs_pal_alloc(sizeof(*new_slot));
	if (!cur_slot || !new_slot) {
		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);
		return -ENOMEM;
	}
	/* Optional batch buffer to scan the 65536-slot table in 32 KiB
	 * chunks instead of one 512 B read per slot.  The full scan is on
	 * the mount critical path (own-slot purge), so 65536 single-slot
	 * reads cost ~5 s; chunked reads cut that to well under 1 s.  If the
	 * allocation fails we fall back to per-slot reads — correctness is
	 * unchanged either way, only the find phase is batched. */
	batch = mxfs_pal_alloc((size_t)BATCH_SLOTS * MXFS_CAW_SLOT_SIZE);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: mount-time purge for dead_mask 0x%llx",
		     (unsigned long long)dead_mask);
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-H22-PURGE-MASK ENTRY dead_mask=0x%llx",
		     (unsigned long long)dead_mask);

	for (slot = 0; slot < MXFS_CAW_MAX_SLOTS; ) {
		uint32_t chunk = BATCH_SLOTS;
		uint32_t i;
		int batch_rc;

		if (slot + chunk > MXFS_CAW_MAX_SLOTS)
			chunk = MXFS_CAW_MAX_SLOTS - slot;

		/* Find phase: pull the chunk in one I/O when possible. */
		batch_rc = batch ? mxfs_pal_bdev_read_prio(ctx->dev,
					slot_offset(ctx, slot), batch,
					chunk * MXFS_CAW_SLOT_SIZE)
				 : -ENOMEM;

		for (i = 0; i < chunk; i++) {
			uint32_t sidx = slot + i;
			int retry;
			int rc;

			if (batch_rc == 0) {
				/* Cheap in-memory candidacy test against the
				 * batch copy: skip the empty / tombstone /
				 * unrelated majority without a per-slot read. */
				struct mxfs_caw_lock_slot *cand = &batch[i];

				if (cand->magic != MXFS_CAW_MAGIC)
					continue;
				if (!(cand->holders_ex & dead_mask) &&
				    !(cand->holders_pw & dead_mask) &&
				    !(cand->holders_pr & dead_mask) &&
				    !(cand->holders_cw & dead_mask) &&
				    !(cand->holders_cr & dead_mask) &&
				    !(cand->waiters & dead_mask))
					continue;
			} else {
				/* Fallback (no batch buffer or read error):
				 * authoritative per-slot read decides. */
				if (read_slot(ctx, sidx, cur_slot))
					continue;
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					continue;
				if (!(cur_slot->holders_ex & dead_mask) &&
				    !(cur_slot->holders_pw & dead_mask) &&
				    !(cur_slot->holders_pr & dead_mask) &&
				    !(cur_slot->holders_cw & dead_mask) &&
				    !(cur_slot->holders_cr & dead_mask) &&
				    !(cur_slot->waiters & dead_mask))
					continue;
			}

			/* Candidate — purge with an authoritative re-read +
			 * CAS retry (identical to the original per-slot path;
			 * the batch copy is only a candidacy hint). */
			for (retry = 0; retry < 20; retry++) {
				rc = read_slot(ctx, sidx, cur_slot);
				if (rc)
					break;
				if (cur_slot->magic != MXFS_CAW_MAGIC)
					break;
				/* Re-confirm on the authoritative copy — a
				 * concurrent purge may have cleared the bits. */
				if (!(cur_slot->holders_ex & dead_mask) &&
				    !(cur_slot->holders_pw & dead_mask) &&
				    !(cur_slot->holders_pr & dead_mask) &&
				    !(cur_slot->holders_cw & dead_mask) &&
				    !(cur_slot->holders_cr & dead_mask) &&
				    !(cur_slot->waiters & dead_mask))
					break;

				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P-H22-PURGE-MASK SLOT slot=%u "
					"res_type=%u res_ino=%llu res_ag=%u"
					"dead_mask=0x%llx cur_hex=%llx",
					sidx, cur_slot->resource.type,
					(unsigned long long)cur_slot->resource.ino,
					cur_slot->resource.ag_number,
					(unsigned long long)dead_mask,
					(unsigned long long)cur_slot->holders_ex);

				*new_slot = *cur_slot;
				new_slot->holders_ex &= ~dead_mask;
				new_slot->holders_pw &= ~dead_mask;
				new_slot->holders_pr &= ~dead_mask;
				new_slot->holders_cw &= ~dead_mask;
				new_slot->holders_cr &= ~dead_mask;
				new_slot->waiters &= ~dead_mask;
				new_slot->waiters_ex &= ~dead_mask;	/* sess50 */
				new_slot->yield_to &= ~dead_mask;
				new_slot->granted_mode =
					recompute_granted_mode(new_slot);
				new_slot->waiter_mode =
					recompute_waiter_mode(new_slot);
				new_slot->generation++;
				new_slot->last_modified_ms = mxfs_pal_time_ms();

				/* Tombstone the slot if completely empty */
				if (!slot_has_holders(new_slot) &&
				    !new_slot->waiters)
					caw_tombstone_slot(new_slot);

				rc = caw_slot(ctx, sidx, cur_slot, new_slot);
				if (rc == -EAGAIN)
					continue;
				if (rc == 0) {
					/* v0.6.4 P141: a dead-node purge is
					 * the only bit-clear a victim's local
					 * seq machinery can NEVER see.  A
					 * FALSE eviction here (lease glitch
					 * under storm) mints a phantom
					 * cached-EX on a live peer — name
					 * every purge + the stripped bits. */
					static int p141_dead_n;

					if (p141_dead_n++ < 200)
						mxfs_pal_log(MXFS_LOG_WARN,
						    "mxfs: P141-DEAD-EXCLR type=%u ino=%llu ag=%u slot=%u dead_mask=%llx cleared_ex=%llx cleared_pr=%llx self=%llx",
						    cur_slot->resource.type,
						    (unsigned long long)cur_slot->resource.ino,
						    cur_slot->resource.ag_number,
						    sidx,
						    (unsigned long long)dead_mask,
						    (unsigned long long)(cur_slot->holders_ex & dead_mask),
						    (unsigned long long)(cur_slot->holders_pr & dead_mask),
						    (unsigned long long)ctx->node_bit);
					purged++;
				}
				break;
			}
		}

		slot += chunk;
		/* Yield periodically during full scan */
		mxfs_pal_cond_resched();
	}

	mxfs_pal_free(cur_slot);
	mxfs_pal_free(new_slot);
	mxfs_pal_free(batch);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: mount-time purge complete: %d stale lock slots cleared",
		     purged);
	return purged;
}

/* ─── BAST poll thread ─── */

static void bast_poll_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;
	uint32_t *batch;
	uint32_t poll_interval = MXFS_CAW_BAST_POLL_MS;
	uint32_t rot = 0;	/* v0.5.3 rotating scan start (coverage >256 held) */
	int batch_count;
	int i;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: BAST poll thread started (node %u, %u ms interval)",
		     ctx->local_node, MXFS_CAW_BAST_POLL_MS);

	/* Allocate batch buffer for held slot snapshot */
	batch = mxfs_pal_alloc(256 * sizeof(uint32_t));
	if (!batch) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: BAST poll alloc failed, thread exiting");
		return;
	}

	while (ctx->running) {
		bool saw_contention = false;

		mxfs_pal_mutex_lock(ctx->stop_lock);
		mxfs_pal_cond_timedwait(ctx->stop_cond, ctx->stop_lock,
					poll_interval);
		mxfs_pal_mutex_unlock(ctx->stop_lock);
		if (!ctx->running)
			break;

		/* Single-node: no peers can set waiter flags, skip
		 * disk polling entirely to avoid unnecessary I/O. */
		if (ctx->single_node)
			continue;

		/* Snapshot held list under lock.
		 * v0.5.3: rotate the 256-entry window across the full held
		 * list — the old code only ever scanned held.slots[0..255],
		 * so any conflict on a lock past index 255 was invisible to
		 * the disk-poll fallback (latent coverage gap once a node
		 * caches >256 locks, which a single rsync already does). */
		mxfs_pal_mutex_lock(ctx->held.lock);
		batch_count = ctx->held.count;
		if (batch_count > 256) {
			uint32_t start = rot % (uint32_t)ctx->held.count;
			uint32_t first = (uint32_t)ctx->held.count - start;

			if (first > 256)
				first = 256;
			memcpy(batch, ctx->held.slots + start,
			       first * sizeof(uint32_t));
			if (first < 256)
				memcpy(batch + first, ctx->held.slots,
				       (256 - first) * sizeof(uint32_t));
			batch_count = 256;
			rot += 256;
		} else {
			memcpy(batch, ctx->held.slots,
			       batch_count * sizeof(uint32_t));
		}
		mxfs_pal_mutex_unlock(ctx->held.lock);

		for (i = 0; i < batch_count; i++) {
			struct mxfs_caw_lock_slot slot;
			uint8_t our_mode;
			int rc;

			if (!ctx->running)
				break;

			rc = read_slot(ctx, batch[i], &slot);
			if (rc)
				continue;
			if (slot.magic != MXFS_CAW_MAGIC)
				continue;

			our_mode = node_held_mode(&slot, ctx->node_bit);

			/*
			 * sess50 detector: catch an incompatible CO-HOLD that no
			 * waiter exists for.  The waiter-driven BAST below cannot
			 * resolve a state where a peer already HOLDS a mode
			 * incompatible with ours (e.g. we cache PR, a peer holds
			 * EX) — neither side is "waiting", so the dir-read stale
			 * never refreshes (the ~60-120s barrier stall).  Detect it
			 * here in the poll thread (away from the perturbation-
			 * sensitive dir ilock fast path).  Ratelimited, fires only
			 * on the bug.
			 */
			if (our_mode != MXFS_LOCK_NL) {
				uint64_t self = ctx->node_bit;
				uint64_t o_ex = slot.holders_ex & ~self;
				uint64_t o_pw = slot.holders_pw & ~self;
				uint64_t o_pr = slot.holders_pr & ~self;
				uint64_t o_cw = slot.holders_cw & ~self;
				uint64_t o_cr = slot.holders_cr & ~self;
				bool cohold_bad = false;

				if (our_mode == MXFS_LOCK_EX ||
				    our_mode == MXFS_LOCK_PW) {
					if (o_ex | o_pw | o_pr | o_cw | o_cr)
						cohold_bad = true;
				} else { /* PR/CR/CW */
					if (o_ex | o_pw)
						cohold_bad = true;
				}
				if (unlikely(cohold_bad))
					mxfs_pal_log(MXFS_LOG_ERR,
					    "mxfs: SESS50-COHOLD ino=%llu type=%u our_mode=%u "
					    "self=%llx h_ex=%llx h_pw=%llx h_pr=%llx h_cw=%llx h_cr=%llx waiters=%llx wmode=%u",
					    (unsigned long long)slot.resource.ino,
					    slot.resource.type, our_mode,
					    (unsigned long long)self,
					    (unsigned long long)slot.holders_ex,
					    (unsigned long long)slot.holders_pw,
					    (unsigned long long)slot.holders_pr,
					    (unsigned long long)slot.holders_cw,
					    (unsigned long long)slot.holders_cr,
					    (unsigned long long)slot.waiters,
					    slot.waiter_mode);
			}

			/* Check if there are waiters requesting an
			 * incompatible mode to what we hold */
			if (!slot.waiters ||
			    slot.waiter_mode == MXFS_LOCK_NL)
				continue;

			saw_contention = true;

			if (our_mode == MXFS_LOCK_NL)
				continue;

			/* sess50 starvation probe (no extra I/O — uses the slot
			 * already read above): we hold a mode and a peer is
			 * waiting for an incompatible one.  If this fires
			 * repeatedly for the SAME inode during a barrier stall,
			 * the waiter (e.g. an EX writer) is being starved by
			 * continuous compatible re-grants. */
			if (slot.resource.type == MXFS_LTYPE_INODE &&
			    !lock_compat[our_mode][slot.waiter_mode])
				pr_warn_ratelimited("mxfs: SESS50-STARVE ino=%llu our_mode=%u waiter_mode=%u waiters=%llx waiters_ex=%llx h_ex=%llx h_pr=%llx gen=%llu\n",
					(unsigned long long)slot.resource.ino,
					our_mode, slot.waiter_mode,
					(unsigned long long)slot.waiters,
					(unsigned long long)slot.waiters_ex,
					(unsigned long long)slot.holders_ex,
					(unsigned long long)slot.holders_pr,
					(unsigned long long)slot.generation);

			if (!lock_compat[our_mode][slot.waiter_mode]) {
				/* Conflict — fire BAST callback */
				if (ctx->bast_cb) {
					ctx->bast_cb(
						(struct mxfs_dlm_ctx *)
							ctx->cb_data,
						&slot.resource,
						ctx->local_node,
						slot.waiter_mode);
				}
			}
		}

		/*
		 * Adaptive poll interval: fast under contention; otherwise
		 * v0.5.3 relaxes the idle interval when the UDP BAST path is
		 * operational (waiters re-send hints every 100 ms while
		 * blocked, so the disk poll is no longer the lost-packet
		 * recovery path).  When the UDP socket failed to set up the
		 * disk poll IS the only BAST channel — keep the original
		 * 200 ms cadence in that case.
		 */
		poll_interval = saw_contention ?
				MXFS_CAW_BAST_POLL_FAST_MS :
				(ctx->bast_mcast_sock ?
				 MXFS_CAW_BAST_POLL_RELAX_MS :
				 MXFS_CAW_BAST_POLL_MS);
	}

	mxfs_pal_free(batch);
	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST poll thread exiting");
}

/* ─── UDP BAST receive thread ─── */

static void bast_recv_fn(void *data)
{
	struct mxfs_dlm_caw_ctx *ctx = data;
	struct mxfs_caw_bast_notify msg;
	char sender_host[64];
	uint16_t sender_port;
	int len;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: BAST recv thread started (port %u)",
		     MXFS_CAW_BAST_PORT);

	while (ctx->running) {
		memset(&msg, 0, sizeof(msg));
		memset(sender_host, 0, sizeof(sender_host));
		sender_port = 0;

		len = mxfs_pal_udp_recvfrom(ctx->bast_mcast_sock,
					     &msg, sizeof(msg),
					     sender_host, sizeof(sender_host),
					     &sender_port);
		if (len < 0) {
			if (len == -EAGAIN || len == -ETIMEDOUT ||
			    len == -EINTR)
				continue;
			if (!ctx->running)
				break;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: BAST recvfrom failed: %d",
				     len);
			continue;
		}
		if (len == 0) {
			if (!ctx->running)
				break;
			continue;
		}

		if (len < (int)sizeof(msg))
			continue;
		/* ccloop 72513a13 sess3: GRANT NUDGE — wake every blocked
		 * acquirer on this node so they re-read their slot NOW.
		 * Coarse (any nudge wakes all waiters) by design: the
		 * re-check is one slot read, and waiters are few. */
		if (msg.magic == MXFS_GRANT_MAGIC) {
			if (msg.requester == ctx->local_node)
				continue;
			if (memcmp(msg.volume_uuid, ctx->volume_uuid, 16) != 0)
				continue;
			if (ctx->nudge_lock && ctx->nudge_cond) {
				mxfs_pal_mutex_lock(ctx->nudge_lock);
				ctx->nudge_seq++;
				mxfs_pal_cond_broadcast(ctx->nudge_cond);
				mxfs_pal_mutex_unlock(ctx->nudge_lock);
			}
			continue;
		}
		if (msg.magic != MXFS_BAST_MAGIC)
			continue;
		if (msg.requester == ctx->local_node)
			continue; /* Ignore our own */
		if (memcmp(msg.volume_uuid, ctx->volume_uuid, 16) != 0)
			continue; /* Wrong volume */

		/*
		 * A remote node wants a lock on this resource. Fire the
		 * BAST callback — the upper layer will check if we
		 * actually hold a conflicting lock and downgrade/release.
		 */
		if (ctx->bast_cb) {
			ctx->bast_cb((struct mxfs_dlm_ctx *)ctx->cb_data,
				     &msg.resource,
				     ctx->local_node,
				     msg.requested_mode);
		}
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "dlm_caw: BAST recv thread exiting");
}

/* ─── Lifecycle ─── */

struct mxfs_dlm_caw_ctx *mxfs_dlm_caw_create(mxfs_bdev_t *dev,
					        uint64_t disklock_offset,
					        mxfs_node_id_t local_node,
					        uint8_t node_slot,
					        const uint8_t *volume_uuid,
					        int max_held)
{
	struct mxfs_dlm_caw_ctx *ctx;

	if (!dev)
		return NULL;

	if (node_slot >= 64) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: invalid node_slot %u (must be 0-63)",
			     node_slot);
		return NULL;
	}

	/*
	 * v5 sess33: clamp max_held.  0 = use compile-time default;
	 * MXFS_CAW_MAX_SLOTS is the on-disk ceiling and the absolute
	 * upper bound for any value.
	 */
	if (max_held <= 0)
		max_held = MXFS_CAW_MAX_HELD;
	if (max_held > MXFS_CAW_MAX_SLOTS)
		max_held = MXFS_CAW_MAX_SLOTS;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));

	ctx->dev = dev;
	ctx->base_offset = disklock_offset;
	/* Lock region starts after the heartbeat area (64 slots x 512 bytes) */
	ctx->lock_region_offset = disklock_offset + MXFS_DISKLOCK_HB_SIZE;
	ctx->local_node = local_node;
	ctx->node_slot = node_slot;
	ctx->node_bit = 1ULL << node_slot;
	ctx->running = false;
	ctx->max_held = max_held;
	ctx->held.count = 0;
	ctx->bast_cb = NULL;
	ctx->cb_data = NULL;
	ctx->bast_poll_thread = NULL;
	ctx->bast_mcast_sock = NULL;
	ctx->bast_recv_thread = NULL;

	if (volume_uuid)
		memcpy(ctx->volume_uuid, volume_uuid, 16);

	ctx->held.slots = mxfs_pal_alloc((size_t)max_held * sizeof(uint32_t));
	if (!ctx->held.slots) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to alloc held.slots[%d]",
			     max_held);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->mem_locks = mxfs_pal_alloc((size_t)max_held *
					sizeof(*ctx->mem_locks));
	if (!ctx->mem_locks) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to alloc mem_locks[%d]",
			     max_held);
		mxfs_pal_free(ctx->held.slots);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->held.lock = mxfs_pal_mutex_create();
	if (!ctx->held.lock) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create held list mutex");
		mxfs_pal_free(ctx->mem_locks);
		mxfs_pal_free(ctx->held.slots);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->mem_lock_mutex = mxfs_pal_mutex_create();
	if (!ctx->mem_lock_mutex) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create mem_lock mutex");
		mxfs_pal_mutex_destroy(ctx->held.lock);
		mxfs_pal_free(ctx->mem_locks);
		mxfs_pal_free(ctx->held.slots);
		mxfs_pal_free(ctx);
		return NULL;
	}
	ctx->mem_lock_count = 0;
	ctx->single_node = false;

	/* v0.5.3 slot-index hint cache.  Optional: a failed allocation
	 * degrades to the pre-hint full-walk behavior (slot_hints NULL
	 * checks in slot_hint_get/store), it does not fail create. */
	ctx->slot_hints = mxfs_pal_alloc((size_t)MXFS_CAW_SLOTHINT_SIZE *
					 sizeof(*ctx->slot_hints));
	if (ctx->slot_hints) {
		memset(ctx->slot_hints, 0,
		       (size_t)MXFS_CAW_SLOTHINT_SIZE *
		       sizeof(*ctx->slot_hints));
		ctx->slot_hint_lock = mxfs_pal_mutex_create();
		if (!ctx->slot_hint_lock) {
			mxfs_pal_free(ctx->slot_hints);
			ctx->slot_hints = NULL;
		}
	}

	/* v0.6.0 grant-time epoch/handoff observations.  Optional like the
	 * hint cache: allocation failure degrades to epoch=0 answers (no
	 * epoch-driven adopt; ring path still covers), not a create failure. */
	ctx->grant_meta = mxfs_pal_alloc((size_t)MXFS_CAW_GRANTMETA_SIZE *
					 sizeof(*ctx->grant_meta));
	if (ctx->grant_meta) {
		memset(ctx->grant_meta, 0,
		       (size_t)MXFS_CAW_GRANTMETA_SIZE *
		       sizeof(*ctx->grant_meta));
		ctx->grant_meta_lock = mxfs_pal_mutex_create();
		if (!ctx->grant_meta_lock) {
			mxfs_pal_free(ctx->grant_meta);
			ctx->grant_meta = NULL;
		}
	}

	/* interactive session 2026-07-13: resource-scoped orphan-strand
	 * wall-clock table — see the struct comment in dlm_caw.h.  Optional
	 * like grant_meta: allocation failure degrades to get()=0 answers
	 * (the force-timeout escapes simply never fire on this ctx), not a
	 * create failure. */
	ctx->orphan_clock = mxfs_pal_alloc((size_t)MXFS_CAW_ORPHANCLOCK_SIZE *
					   sizeof(*ctx->orphan_clock));
	if (ctx->orphan_clock) {
		memset(ctx->orphan_clock, 0,
		       (size_t)MXFS_CAW_ORPHANCLOCK_SIZE *
		       sizeof(*ctx->orphan_clock));
		ctx->orphan_clock_lock = mxfs_pal_spinlock_create();
		if (!ctx->orphan_clock_lock) {
			mxfs_pal_free(ctx->orphan_clock);
			ctx->orphan_clock = NULL;
		}
	}

	ctx->stop_lock = mxfs_pal_mutex_create();
	ctx->stop_cond = mxfs_pal_cond_create();
	if (!ctx->stop_lock || !ctx->stop_cond) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to create stop condvar");
		mxfs_pal_cond_destroy(ctx->stop_cond);
		mxfs_pal_mutex_destroy(ctx->stop_lock);
		mxfs_pal_mutex_destroy(ctx->held.lock);
		mxfs_pal_free(ctx);
		return NULL;
	}

	/* ccloop 72513a13 sess3: grant-nudge condvar.  Allocation failure is
	 * non-fatal — caw_nudge_wait falls back to plain sleep_ms. */
	ctx->nudge_lock = mxfs_pal_mutex_create();
	ctx->nudge_cond = mxfs_pal_cond_create();
	if (!ctx->nudge_lock || !ctx->nudge_cond) {
		mxfs_pal_cond_destroy(ctx->nudge_cond);
		mxfs_pal_mutex_destroy(ctx->nudge_lock);
		ctx->nudge_lock = NULL;
		ctx->nudge_cond = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: created for node %u (slot %u, bit 0x%llx), "
		     "base_offset=%llu, lock_region_offset=%llu, "
		     "max_slots=%u max_held=%d",
		     local_node, node_slot,
		     (unsigned long long)ctx->node_bit,
		     (unsigned long long)ctx->base_offset,
		     (unsigned long long)ctx->lock_region_offset,
		     MXFS_CAW_MAX_SLOTS, ctx->max_held);

	return ctx;
}

int mxfs_dlm_caw_start(struct mxfs_dlm_caw_ctx *ctx)
{
	int rc;

	if (!ctx)
		return -EINVAL;

	ctx->running = true;

	/* Start BAST poll thread */
	ctx->bast_poll_thread = mxfs_pal_thread_create(bast_poll_fn, ctx);
	if (!ctx->bast_poll_thread) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "dlm_caw: failed to start BAST poll thread");
		ctx->running = false;
		return -ENOMEM;
	}

	/* Setup UDP multicast BAST socket (best effort — works without it) */
	ctx->bast_mcast_sock = mxfs_pal_udp_open(MXFS_CAW_BAST_PORT);
	if (ctx->bast_mcast_sock) {
		mxfs_pal_udp_set_recv_timeout(ctx->bast_mcast_sock, 500);

		rc = mxfs_pal_udp_join_multicast(ctx->bast_mcast_sock,
						  MXFS_DISCOVERY_MCAST);
		if (rc < 0) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "dlm_caw: multicast join failed: %d "
				     "(BAST multicast disabled, poll-only mode)",
				     rc);
			mxfs_pal_udp_close(ctx->bast_mcast_sock);
			ctx->bast_mcast_sock = NULL;
		} else {
			/* Start BAST receive thread */
			ctx->bast_recv_thread =
				mxfs_pal_thread_create(bast_recv_fn, ctx);
			if (!ctx->bast_recv_thread) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "dlm_caw: failed to start BAST "
					     "recv thread (poll-only mode)");
				mxfs_pal_udp_close(ctx->bast_mcast_sock);
				ctx->bast_mcast_sock = NULL;
			} else {
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "dlm_caw: BAST multicast enabled "
					     "on %s:%u",
					     MXFS_DISCOVERY_MCAST,
					     MXFS_CAW_BAST_PORT);
			}
		}
	} else {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "dlm_caw: failed to open BAST UDP socket "
			     "(poll-only mode)");
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: started for node %u", ctx->local_node);
	return 0;
}

void mxfs_dlm_caw_stop(struct mxfs_dlm_caw_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: stopping for node %u", ctx->local_node);

	ctx->running = false;

	/* Wake BAST poll thread from condvar sleep */
	if (ctx->stop_cond)
		mxfs_pal_cond_signal(ctx->stop_cond);

	/* Shut down multicast socket to unblock recv thread */
	if (ctx->bast_mcast_sock)
		mxfs_pal_udp_shutdown(ctx->bast_mcast_sock);

	if (ctx->bast_recv_thread) {
		mxfs_pal_thread_join(ctx->bast_recv_thread);
		ctx->bast_recv_thread = NULL;
	}

	if (ctx->bast_poll_thread) {
		mxfs_pal_thread_join(ctx->bast_poll_thread);
		ctx->bast_poll_thread = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: threads stopped for node %u", ctx->local_node);
}

void mxfs_dlm_caw_destroy(struct mxfs_dlm_caw_ctx *ctx)
{
	if (!ctx)
		return;

	mxfs_dlm_caw_stop(ctx);

	/* Release any remaining held locks */
	mxfs_dlm_caw_release_all(ctx);

	if (ctx->bast_mcast_sock) {
		mxfs_pal_udp_close(ctx->bast_mcast_sock);
		ctx->bast_mcast_sock = NULL;
	}

	if (ctx->stop_cond) {
		mxfs_pal_cond_destroy(ctx->stop_cond);
		ctx->stop_cond = NULL;
	}
	if (ctx->stop_lock) {
		mxfs_pal_mutex_destroy(ctx->stop_lock);
		ctx->stop_lock = NULL;
	}
	if (ctx->nudge_cond) {
		mxfs_pal_cond_destroy(ctx->nudge_cond);
		ctx->nudge_cond = NULL;
	}
	if (ctx->nudge_lock) {
		mxfs_pal_mutex_destroy(ctx->nudge_lock);
		ctx->nudge_lock = NULL;
	}
	if (ctx->held.lock) {
		mxfs_pal_mutex_destroy(ctx->held.lock);
		ctx->held.lock = NULL;
	}
	if (ctx->mem_lock_mutex) {
		mxfs_pal_mutex_destroy(ctx->mem_lock_mutex);
		ctx->mem_lock_mutex = NULL;
	}
	if (ctx->slot_hints) {
		mxfs_pal_free(ctx->slot_hints);
		ctx->slot_hints = NULL;
	}
	if (ctx->slot_hint_lock) {
		mxfs_pal_mutex_destroy(ctx->slot_hint_lock);
		ctx->slot_hint_lock = NULL;
	}
	if (ctx->grant_meta) {
		mxfs_pal_free(ctx->grant_meta);
		ctx->grant_meta = NULL;
	}
	if (ctx->grant_meta_lock) {
		mxfs_pal_mutex_destroy(ctx->grant_meta_lock);
		ctx->grant_meta_lock = NULL;
	}
	if (ctx->orphan_clock) {
		mxfs_pal_free(ctx->orphan_clock);
		ctx->orphan_clock = NULL;
	}
	if (ctx->orphan_clock_lock) {
		mxfs_pal_spinlock_destroy(ctx->orphan_clock_lock);
		ctx->orphan_clock_lock = NULL;
	}

	/* v5 sess33: free heap-allocated arrays */
	if (ctx->held.slots) {
		mxfs_pal_free(ctx->held.slots);
		ctx->held.slots = NULL;
	}
	if (ctx->mem_locks) {
		mxfs_pal_free(ctx->mem_locks);
		ctx->mem_locks = NULL;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "dlm_caw: destroyed for node %u", ctx->local_node);

	mxfs_pal_free(ctx);
}

/* ─── Single-node bypass ─── */

/*
 * Flush all in-memory held locks to disk.
 *
 * Called when transitioning from single-node to multi-node.
 * For each lock held in-memory, claims a disk slot via the normal
 * CAW path (find_slot + CAS new slot or add holder bit).
 *
 * Returns 0 on success, negative errno on first I/O failure.
 */
int mxfs_dlm_caw_flush_held_to_disk(struct mxfs_dlm_caw_ctx *ctx)
{
	int count;

	if (!ctx)
		return -EINVAL;

	/*
	 * v0.3.86 (sess25 root-cause fix): do NOT promote single_node
	 * in-memory locks to disk.  The original design OR'd our holder
	 * bit into each slot — but if peer is also transitioning
	 * single→multi and ran flush_held_to_disk concurrently, BOTH
	 * nodes' bits end up in the EX bitmap.  caw_lock's "already-held"
	 * fast-path then sees our bit and returns success without
	 * conflict detection; xfs cached i_dlm_mode and pag_dlm_cached
	 * stay set; both nodes proceed without coordination.  Sess24 P35
	 * captured this as 50s of dual-cached state on AG=0; sess25
	 * cross-node visibility test reproduced as `d?????????` on T2.
	 *
	 * After this change, disk slots stay empty post-transition, and
	 * the xfs side's mxfs_dlm_peer_joined_flush invalidates cached
	 * i_dlm/pag state, forcing every next acquire through proper
	 * CAW flow with conflict detection.  Any peer holding the
	 * resource won't see our prior single_node hold — but they have
	 * no concurrent acquires in flight (their first multi-mode
	 * acquire is what produces the BAST request), so nothing is
	 * lost.
	 */
	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
	count = ctx->mem_lock_count;
	ctx->mem_lock_count = 0;
	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);

	if (count > 0)
		mxfs_pal_log(MXFS_LOG_INFO,
			     "dlm_caw: dropped %d single_node in-memory locks "
			     "(no disk promotion to avoid OR-bug)", count);
	return 0;
}

/*
 * v0.3.x ORIGINAL: write each in-memory single_node hold to disk.
 * Disabled by sess25 (see comment above).  Kept here as
 * mxfs_dlm_caw_flush_held_to_disk_orig for reference / potential
 * future re-enable if a different fix supersedes the sess25
 * rationale.
 */
static int __maybe_unused mxfs_dlm_caw_flush_held_to_disk_orig(
	struct mxfs_dlm_caw_ctx *ctx)
{
	struct mxfs_resource_id *resources;
	uint8_t *modes;
	int count;
	int i;
	int rc = 0;

	if (!ctx)
		return -EINVAL;

	/* Snapshot the in-memory lock list */
	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
	count = ctx->mem_lock_count;
	if (count == 0) {
		mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
		return 0;
	}

	resources = mxfs_pal_alloc(count * sizeof(*resources));
	modes = mxfs_pal_alloc(count * sizeof(*modes));
	if (!resources || !modes) {
		mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);
		mxfs_pal_free(resources);
		mxfs_pal_free(modes);
		return -ENOMEM;
	}

	for (i = 0; i < count; i++) {
		resources[i] = ctx->mem_locks[i].resource;
		modes[i] = ctx->mem_locks[i].mode;
	}
	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);

	mxfs_pal_log(MXFS_LOG_INFO,
		     "dlm_caw: flushing %d in-memory locks to disk "
		     "(peer joined)", count);

	/* Write each lock to disk via find_slot + CAW */
	for (i = 0; i < count; i++) {
		struct mxfs_caw_lock_slot *cur_slot;
		struct mxfs_caw_lock_slot *new_slot;
		uint32_t slot_idx = 0;
		uint32_t empty_idx = UINT32_MAX;
		int retry;

		cur_slot = mxfs_pal_alloc(sizeof(*cur_slot));
		new_slot = mxfs_pal_alloc(sizeof(*new_slot));
		if (!cur_slot || !new_slot) {
			mxfs_pal_free(cur_slot);
			mxfs_pal_free(new_slot);
			rc = -ENOMEM;
			break;
		}

		for (retry = 0; retry < MXFS_CAW_MAX_RETRIES; retry++) {
			rc = find_slot(ctx, &resources[i], &slot_idx,
				       cur_slot, &empty_idx);

			if (rc == -ENOENT) {
				/* Not on disk yet — claim empty slot */
				if (empty_idx == UINT32_MAX) {
					rc = -ENOSPC;
					break;
				}

				rc = read_slot(ctx, empty_idx, cur_slot);
				if (rc)
					break;
				/* daf50d34 sess2: same claim-race TOCTOU guard as
				 * the main claim-empty arm — a live slot that
				 * materialized at empty_idx since the probe must
				 * not be claimed over (the CAS would wipe the
				 * peer's holders).  Re-probe. */
				if (cur_slot->magic == MXFS_CAW_MAGIC) {
					rc = -EAGAIN;
					continue;
				}
				memset(new_slot, 0, sizeof(*new_slot));
				new_slot->magic = MXFS_CAW_MAGIC;
				new_slot->generation = 1;
				new_slot->resource = resources[i];
				new_slot->last_ex_slot =
					MXFS_CAW_EX_SLOT_NONE;
				caw_claim_inherit_epoch(new_slot, cur_slot,
							&resources[i]);
				{
					uint64_t *hp = holders_for_mode(
						new_slot, modes[i]);
					if (hp)
						*hp = ctx->node_bit;
				}
				new_slot->granted_mode = modes[i];
				new_slot->last_modified_ms =
					mxfs_pal_time_ms();
				caw_grant_epoch_update(ctx, new_slot,
						       modes[i]);

				caw_grant_seq_prebump(ctx, &resources[i]);	/* v0.6.4 */
				rc = caw_slot(ctx, empty_idx,
					      cur_slot, new_slot);
				if (rc == -EAGAIN)
					continue;
				if (rc == 0)
					track_held(ctx, empty_idx);
				break;
			}

			if (rc)
				break;

			/* Slot exists — add our holder bit */
			*new_slot = *cur_slot;
			{
				uint64_t *hp = holders_for_mode(
					new_slot, modes[i]);
				if (hp)
					*hp |= ctx->node_bit;
			}
			new_slot->granted_mode =
				recompute_granted_mode(new_slot);
			new_slot->generation++;
			new_slot->last_modified_ms = mxfs_pal_time_ms();
			caw_grant_epoch_update(ctx, new_slot, modes[i]);

			caw_grant_seq_prebump(ctx, &resources[i]);	/* v0.6.4 */
			rc = caw_slot(ctx, slot_idx, cur_slot, new_slot);
			if (rc == -EAGAIN)
				continue;
			if (rc == 0)
				track_held(ctx, slot_idx);
			break;
		}

		mxfs_pal_free(cur_slot);
		mxfs_pal_free(new_slot);

		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "dlm_caw: flush lock %d/%d to disk "
				     "failed: %d (ino=%llu type=%u)",
				     i, count, rc,
				     (unsigned long long)resources[i].ino,
				     resources[i].type);
			break;
		}
	}

	/* Clear in-memory tracking regardless — we're now in
	 * multi-node mode and all future ops go through disk. */
	mxfs_pal_mutex_lock(ctx->mem_lock_mutex);
	ctx->mem_lock_count = 0;
	mxfs_pal_mutex_unlock(ctx->mem_lock_mutex);

	mxfs_pal_free(resources);
	mxfs_pal_free(modes);

	if (rc == 0)
		mxfs_pal_log(MXFS_LOG_INFO,
			     "dlm_caw: all %d locks flushed to disk", count);
	return rc;
}

void mxfs_dlm_caw_set_single_node(struct mxfs_dlm_caw_ctx *ctx, bool single)
{
	if (!ctx)
		return;

	if (ctx->single_node && !single) {
		/* Transitioning single→multi: flush held locks to disk
		 * so the new peer can see them. */
		mxfs_dlm_caw_flush_held_to_disk(ctx);
	}

	{
		bool was = ctx->single_node;
		ctx->single_node = single;
		if (was != single)
			mxfs_pal_log(MXFS_LOG_INFO,
				     "dlm_caw: single_node = %s",
				     single ? "true" : "false");
	}
}

/* ─── Callbacks ─── */

void mxfs_dlm_caw_set_bast_cb(struct mxfs_dlm_caw_ctx *ctx,
				 mxfs_dlm_bast_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->bast_cb = cb;
	ctx->cb_data = data;
}

void mxfs_dlm_caw_set_holders_alive_fn(struct mxfs_dlm_caw_ctx *ctx,
					bool (*fn)(void *data,
						   uint64_t slot_mask),
					void *data)
{
	if (!ctx)
		return;
	ctx->holders_alive_fn = fn;
	ctx->holders_alive_data = data;
}
