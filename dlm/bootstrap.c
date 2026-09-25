/*
 * MXFS — whole-cluster bootstrap record.  See bootstrap.h.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include "bootstrap.h"
#include "scsipr.h"
#include "disklock.h"       /* the survivor scan reads the HB table */

const char *mxfs_bootstrap_state_name(uint16_t state)
{
	switch (state) {
	case MXFS_BOOTSTRAP_IDLE:               return "IDLE";
	case MXFS_BOOTSTRAP_CLAIMED:            return "CLAIMED";
	case MXFS_BOOTSTRAP_MANIFEST_SEALED:    return "MANIFEST_SEALED";
	case MXFS_BOOTSTRAP_RECOVERING:         return "RECOVERING";
	case MXFS_BOOTSTRAP_RECOVERY_COMPLETE:  return "RECOVERY_COMPLETE";
	case MXFS_BOOTSTRAP_REFUSED:            return "REFUSED";
	default:                                return "?";
	}
}

const char *mxfs_bootstrap_refuse_name(uint32_t reason)
{
	switch (reason) {
	case MXFS_BOOT_REFUSE_TERMINAL_SLICE:   return "TERMINAL_SLICE";
	case MXFS_BOOT_REFUSE_UNCLASSIFIED_KEY: return "UNCLASSIFIED_KEY";
	case MXFS_BOOT_REFUSE_FENCE_UNPROVEN:   return "FENCE_UNPROVEN";
	case MXFS_BOOT_REFUSE_RECONCILE:        return "RECONCILE";
	case MXFS_BOOT_REFUSE_INHERITANCE_UNPROVEN: return "INHERITANCE_UNPROVEN";
	default:                                return "?";
	}
}

uint32_t mxfs_bootstrap_rec_crc(const struct mxfs_bootstrap_rec *r)
{
	struct mxfs_bootstrap_rec t = *r;

	t.crc32c = 0;
	return mxfs_pal_crc32c(~0U, &t, sizeof(t));
}

bool mxfs_bootstrap_rec_valid(const struct mxfs_bootstrap_rec *r)
{
	if (r->magic != MXFS_BOOTSTRAP_MAGIC || r->ver != MXFS_BOOTSTRAP_VERSION)
		return false;
	if (r->state > MXFS_BOOTSTRAP_REFUSED)
		return false;
	if (r->state != MXFS_BOOTSTRAP_IDLE && r->owner_node == 0)
		return false;      /* an owned state names an owner */
	return r->crc32c == mxfs_bootstrap_rec_crc(r);
}

void mxfs_bootstrap_rec_init_idle(struct mxfs_bootstrap_rec *r,
				  const uint8_t fs_uuid[16], uint32_t fs_gen)
{
	memset(r, 0, sizeof(*r));
	r->magic = MXFS_BOOTSTRAP_MAGIC;
	r->ver = MXFS_BOOTSTRAP_VERSION;
	r->state = MXFS_BOOTSTRAP_IDLE;
	memcpy(r->fs_uuid, fs_uuid, 16);
	r->fs_gen = fs_gen;
	r->crc32c = mxfs_bootstrap_rec_crc(r);
}

struct mxfs_bootstrap *mxfs_bootstrap_open(mxfs_bdev_t *dev, uint64_t offset,
					   uint64_t size,
					   const uint8_t fs_uuid[16],
					   uint32_t fs_gen)
{
	struct mxfs_bootstrap *b;

	if (!dev || !offset || !fs_uuid)
		return NULL;
	/* (§6.8, review SS-8): the geometry lives in the super; a
	 * region smaller than this build's map cannot hold the tombstones,
	 * lineage and takeover journal the protocol relies on — refuse */
	if (size < MXFS_BOOT_REGION_BYTES) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-REGION-SMALL size=%llu need=%u — the "
			     "bootstrap region predates protocol gen %u; re-mkfs",
			     (unsigned long long)size, MXFS_BOOT_REGION_BYTES,
			     (unsigned)MXFS_PROTO_GEN);
		return NULL;
	}
	b = mxfs_pal_alloc(sizeof(*b));
	if (!b)
		return NULL;
	memset(b, 0, sizeof(*b));
	b->lock = mxfs_pal_mutex_create();
	if (!b->lock) {
		mxfs_pal_free(b);
		return NULL;
	}
	b->dev = dev;
	b->offset = offset;
	memcpy(b->fs_uuid, fs_uuid, 16);
	b->fs_gen = fs_gen;
	return b;
}

void mxfs_bootstrap_close(struct mxfs_bootstrap *b)
{
	if (!b)
		return;
	if (b->lock)
		mxfs_pal_mutex_destroy(b->lock);
	mxfs_pal_free(b);
}

static int bs_read_locked(struct mxfs_bootstrap *b,
			  struct mxfs_bootstrap_rec *r)
{
	int rc = mxfs_pal_bdev_read_prio(b->dev, b->offset, r, sizeof(*r));

	if (rc)
		return rc;
	if (r->magic == 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-UNFORMATTED off=%llu — the bootstrap "
			     "record carries no magic; mkfs never wrote it (or the "
			     "sector is torn).  Failing closed",
			     (unsigned long long)b->offset);
		return -ENODATA;
	}
	if (!mxfs_bootstrap_rec_valid(r)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-INVALID magic=0x%08x ver=%u state=%u "
			     "owner=%u crc=0x%08x want=0x%08x — refusing",
			     r->magic, r->ver, r->state, r->owner_node, r->crc32c,
			     mxfs_bootstrap_rec_crc(r));
		return -EUCLEAN;
	}
	/* mkfs binds the record to the volume by fs_uuid (the one identity mkfs
	 * and the kernel compute identically); fs_gen is the kernel's folded
	 * form and is recorded at claim, never used to validate. */
	if (memcmp(r->fs_uuid, b->fs_uuid, 16) != 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-FOREIGN-VOLUME — the bootstrap record's "
			     "fs_uuid is not this volume's (a re-mkfs that left the "
			     "region, or a copied sector); refusing");
		return -EXDEV;
	}
	return 0;
}

int mxfs_bootstrap_read(struct mxfs_bootstrap *b,
			struct mxfs_bootstrap_rec *out)
{
	int rc;

	if (!b || !out)
		return -EINVAL;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, out);
	mxfs_pal_mutex_unlock(b->lock);
	return rc;
}

/* CAS from the exact image `cur` to `want`; seals seq/stamp/crc. */
static int bs_cas_locked(struct mxfs_bootstrap *b,
			 const struct mxfs_bootstrap_rec *cur,
			 struct mxfs_bootstrap_rec *want)
{
	int rc;

	want->seq = cur->seq + 1;
	want->stamp_ms = mxfs_pal_time_ms();
	want->crc32c = mxfs_bootstrap_rec_crc(want);
	rc = mxfs_pal_bdev_compare_and_write(b->dev, b->offset, cur, want);
	if (rc == -EOPNOTSUPP)
		rc = mxfs_pal_bdev_write_fua(b->dev, b->offset, want, sizeof(*want));
	/*
	 * 0.89.41: every record write this node makes goes through here, so this
	 * is the one place that can honestly say "a write of ours landed".  The
	 * stamp is the one the record itself carries — the instant the write was
	 * ISSUED — so a reader comparing it against some earlier instant learns
	 * that the write was issued after that instant AND completed, which is
	 * what a post-reset convergence test has to establish.  On failure
	 * nothing is stamped: a term whose writes stop reaching the LUN must age
	 * out, because that is exactly when its peers may take it away.
	 */
	if (rc == 0)
		b->last_ok_ms = want->stamp_ms;
	return rc;
}

static void bs_fill_owner(struct mxfs_bootstrap_rec *r,
			  const struct mxfs_bootstrap_identity *id,
			  uint64_t nonce)
{
	r->owner_node = id->node_id;
	r->owner_key_gen = id->key_gen;
	r->owner_epoch = id->epoch;
	r->owner_pr_key = id->pr_key;
	r->owner_nonce = nonce;
	memcpy(r->owner_host_uuid, id->host_uuid, 16);
	memcpy(r->owner_boot_uuid, id->boot_uuid, 16);
	r->host_src = id->host_src;
}

static bool bs_id_ok(const struct mxfs_bootstrap_identity *id)
{
	return id && id->node_id && id->epoch && id->pr_key;
}

int mxfs_bootstrap_claim(struct mxfs_bootstrap *b,
			 const struct mxfs_bootstrap_identity *id)
{
	struct mxfs_bootstrap_rec *cur, want;
	uint64_t nonce = 0;
	int rc;

	if (!b || !bs_id_ok(id))
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, cur);
	if (rc)
		goto out;
	if (cur->state != MXFS_BOOTSTRAP_IDLE &&
	    cur->state != MXFS_BOOTSTRAP_RECOVERY_COMPLETE) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-BOOT-CLAIM-BUSY state=%s term=%llu owner=%u/%llu "
			     "key=0x%llx seq=%llu owner_stamp_ms=%llu — another "
			     "provisional owner holds the bootstrap; silence never "
			     "authorises a takeover (fence its key first)",
			     mxfs_bootstrap_state_name(cur->state),
			     (unsigned long long)cur->term, cur->owner_node,
			     (unsigned long long)cur->owner_epoch,
			     (unsigned long long)cur->owner_pr_key,
			     (unsigned long long)cur->seq,
			     (unsigned long long)cur->stamp_ms);
		rc = -EBUSY;
		goto out;
	}
	while (!nonce)
		mxfs_pal_get_random_bytes(&nonce, sizeof(nonce));
	want = *cur;
	want.state = MXFS_BOOTSTRAP_CLAIMED;
	want.term = cur->term + 1;
	want.fs_gen = b->fs_gen;
	bs_fill_owner(&want, id, nonce);
	want.victim_bitmap = 0;
	want.complete_bitmap = 0;
	want.ledger_gen = 0;
	want.manifest_hash = 0;
	want.registrants = 0;
	want.registrants_done = 0;
	want.claim_stamp_ms = mxfs_pal_time_ms();
	want.seal_stamp_ms = 0;
	want.complete_stamp_ms = 0;
	want.prev_owner_node = 0;
	want.prev_fence_kind = 0;
	want.prev_owner_epoch = 0;
	want.prev_owner_pr_key = 0;
	/* (§6.8): a fresh claim opens a new recovery EPISODE — every
	 * tombstone / lineage entry proving a term below episode_term belongs to
	 * an older, completed episode and is ignored by validation, so nothing
	 * from the previous episode needs to be erased for correctness */
	want.episode_term = want.term;
	want.lineage_count = 0;
	want.takeover_gen = 0;
	memset(&want.escrow, 0, sizeof(want.escrow));
	want.refused_slot = 0;
	want.refused_reason = 0;
	rc = bs_cas_locked(b, cur, &want);
	if (rc == 0) {
		b->owned = true;
		b->img = want;
		b->nonce = nonce;
	}
	mxfs_pal_log(rc ? MXFS_LOG_WARN : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-CLAIM term=%llu node=%u inc=%llu key=0x%llx "
		     "gen=%u from=%s rc=%d%s",
		     (unsigned long long)want.term, id->node_id,
		     (unsigned long long)id->epoch,
		     (unsigned long long)id->pr_key, id->key_gen,
		     mxfs_bootstrap_state_name(cur->state), rc,
		     rc == -EAGAIN ? " (lost the CAS; re-read and retry)" : "");
out:
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

int mxfs_bootstrap_reseal(struct mxfs_bootstrap *b,
			  const struct mxfs_bootstrap_rec *prev,
			  const struct mxfs_bootstrap_identity *id,
			  const struct mxfs_bootstrap_reseal_args *a)
{
	struct mxfs_bootstrap_rec *cur, want;
	uint64_t nonce = 0, now;
	int rc;

	if (!b || !prev || !a || !bs_id_ok(id))
		return -EINVAL;
	if (a->state != MXFS_BOOTSTRAP_CLAIMED &&
	    a->state != MXFS_BOOTSTRAP_RECOVERING &&
	    a->state != MXFS_BOOTSTRAP_REFUSED)
		return -EINVAL;
	{
		const char *kwhy = NULL;

		if (!mxfs_fence_durable_kind_supported(
			    MXFS_FENCE_RECORD_BOOTSTRAP_OWNER,
			    a->prev_fence_kind, &kwhy)) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-BOOT-TAKEOVER-UNPROVEN kind=%s(%u) — only a "
				     "certified key removal of a proof contract this build "
				     "still supports authorises replacing a bootstrap "
				     "owner; refusing: %s",
				     mxfs_fence_kind_name(a->prev_fence_kind),
				     a->prev_fence_kind, kwhy ? kwhy : "?");
			return -EPERM;
		}
	}
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, cur);
	if (rc)
		goto out;
	if (memcmp(cur, prev, sizeof(*cur)) != 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-TAKEOVER-MOVED term=%llu seq=%llu->%llu — "
			     "the record changed since the post-fence read; a fenced "
			     "owner cannot write, so somebody else is at work",
			     (unsigned long long)cur->term,
			     (unsigned long long)prev->seq,
			     (unsigned long long)cur->seq);
		rc = -EAGAIN;
		goto out;
	}
	if (cur->state == MXFS_BOOTSTRAP_IDLE ||
	    cur->state == MXFS_BOOTSTRAP_RECOVERY_COMPLETE) {
		rc = -ENOENT;       /* nothing to take over: claim instead */
		goto out;
	}
	if (cur->lineage_count >= MXFS_BOOT_LIN_MAX) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-LINEAGE-FULL term=%llu lineage=%u — this "
			     "episode has been taken over %u times; operator repair",
			     (unsigned long long)cur->term, cur->lineage_count,
			     MXFS_BOOT_LIN_MAX);
		rc = -ENOSPC;
		goto out;
	}
	now = mxfs_pal_time_ms();
	while (!nonce)
		mxfs_pal_get_random_bytes(&nonce, sizeof(nonce));
	want = *cur;
	want.state = a->state;
	want.term = cur->term + 1;
	want.fs_gen = b->fs_gen;
	want.prev_owner_node = cur->owner_node;
	want.prev_owner_epoch = cur->owner_epoch;
	want.prev_owner_pr_key = cur->owner_pr_key;
	want.prev_fence_kind = a->prev_fence_kind;
	bs_fill_owner(&want, id, nonce);
	want.victim_bitmap = a->victim_bitmap;
	want.complete_bitmap = a->complete_bitmap;
	want.ledger_gen = a->ledger_gen;
	want.manifest_hash = a->manifest_hash;
	want.registrants = a->registrants;
	want.registrants_done = a->registrants_done;
	want.claim_stamp_ms = now;
	want.seal_stamp_ms = a->state == MXFS_BOOTSTRAP_CLAIMED ? 0 : now;
	want.complete_stamp_ms = a->state == MXFS_BOOTSTRAP_REFUSED ? now : 0;
	want.refused_slot = a->refused_slot;
	want.refused_reason = a->refused_reason;
	memset(&want.escrow, 0, sizeof(want.escrow));
	want.lineage_count = cur->lineage_count + 1;
	want.takeover_gen = cur->takeover_gen + 1;
	/* episode_term carried: the same recovery episode continues */
	rc = bs_cas_locked(b, cur, &want);
	if (rc == 0) {
		b->owned = a->state != MXFS_BOOTSTRAP_REFUSED;
		b->img = want;
		b->nonce = nonce;
	}
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-TAKEOVER term=%llu->%llu prev=%u/%llu "
		     "prev_key=0x%llx kind=%s now=%u/%llu state=%s->%s "
		     "victims=0x%016llx complete=0x%016llx registrants=%u/%u "
		     "lineage=%u rc=%d",
		     (unsigned long long)cur->term, (unsigned long long)want.term,
		     cur->owner_node, (unsigned long long)cur->owner_epoch,
		     (unsigned long long)cur->owner_pr_key,
		     mxfs_fence_kind_name(a->prev_fence_kind), id->node_id,
		     (unsigned long long)id->epoch,
		     mxfs_bootstrap_state_name(cur->state),
		     mxfs_bootstrap_state_name(want.state),
		     (unsigned long long)want.victim_bitmap,
		     (unsigned long long)want.complete_bitmap,
		     want.registrants_done, want.registrants, want.lineage_count,
		     rc);
out:
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

/* Re-read and check that the platter still names us as owner under our
 * term and nonce; refresh b->img from it. */
static int bs_reload_ours_locked(struct mxfs_bootstrap *b,
				 struct mxfs_bootstrap_rec *cur,
				 const char *tag)
{
	int rc;

	if (!b->owned)
		return -ENOENT;
	rc = bs_read_locked(b, cur);
	if (rc)
		return rc;
	if (cur->term != b->img.term || cur->owner_node != b->img.owner_node ||
	    cur->owner_epoch != b->img.owner_epoch ||
	    cur->owner_nonce != b->nonce) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-LOST at=%s ours=term %llu %u/%llu platter="
			     "term %llu %u/%llu state=%s — the record no longer names "
			     "this claim; ceasing to act as bootstrap owner",
			     tag, (unsigned long long)b->img.term, b->img.owner_node,
			     (unsigned long long)b->img.owner_epoch,
			     (unsigned long long)cur->term, cur->owner_node,
			     (unsigned long long)cur->owner_epoch,
			     mxfs_bootstrap_state_name(cur->state));
		b->owned = false;
		return -ESTALE;
	}
	return 0;
}

static int bs_own_cas_locked(struct mxfs_bootstrap *b,
			     const struct mxfs_bootstrap_rec *cur,
			     struct mxfs_bootstrap_rec *want, const char *tag)
{
	int rc = bs_cas_locked(b, cur, want);

	if (rc == 0)
		b->img = *want;
	else if (rc == -EAGAIN)
		/* somebody wrote under us: we may have been taken over */
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-CAS-LOST at=%s term=%llu — re-read and "
			     "re-validate ownership before retrying", tag,
			     (unsigned long long)cur->term);
	return rc;
}

int mxfs_bootstrap_heartbeat(struct mxfs_bootstrap *b)
{
	struct mxfs_bootstrap_rec *cur, want;
	int rc;

	if (!b)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_reload_ours_locked(b, cur, "heartbeat");
	if (rc)
		goto out;
	want = *cur;
	rc = bs_own_cas_locked(b, cur, &want, "heartbeat");
out:
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

static int bs_own_transition(struct mxfs_bootstrap *b, uint16_t from_lo,
			     uint16_t from_hi, uint16_t to, const char *tag,
			     void (*edit)(struct mxfs_bootstrap_rec *, void *),
			     void *arg)
{
	struct mxfs_bootstrap_rec *cur, want;
	int rc;

	if (!b)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_reload_ours_locked(b, cur, tag);
	if (rc)
		goto out;
	if (cur->state < from_lo || cur->state > from_hi) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-BAD-TRANSITION at=%s state=%s — not a "
			     "legal predecessor of %s", tag,
			     mxfs_bootstrap_state_name(cur->state),
			     mxfs_bootstrap_state_name(to));
		rc = -EINVAL;
		goto out;
	}
	want = *cur;
	want.state = to;
	if (edit)
		edit(&want, arg);
	rc = bs_own_cas_locked(b, cur, &want, tag);
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-%s term=%llu node=%u victims=0x%016llx "
		     "complete=0x%016llx registrants=%u/%u rc=%d", tag,
		     (unsigned long long)want.term, want.owner_node,
		     (unsigned long long)want.victim_bitmap,
		     (unsigned long long)want.complete_bitmap,
		     want.registrants_done, want.registrants, rc);
out:
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

struct bs_seal_args {
	uint64_t victim_bitmap;
	uint64_t ledger_gen;
	uint32_t registrants;
	uint64_t manifest_hash;
};

static void bs_seal_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	struct bs_seal_args *a = arg;

	r->victim_bitmap = a->victim_bitmap;
	r->ledger_gen = a->ledger_gen;
	r->registrants = a->registrants;
	r->registrants_done = 0;
	r->manifest_hash = a->manifest_hash;
	r->complete_bitmap = 0;
	r->seal_stamp_ms = mxfs_pal_time_ms();
}

int mxfs_bootstrap_seal(struct mxfs_bootstrap *b, uint64_t victim_bitmap,
			uint64_t ledger_gen, uint32_t registrants,
			uint64_t manifest_hash)
{
	struct bs_seal_args a = { victim_bitmap, ledger_gen, registrants,
				  manifest_hash };

	return bs_own_transition(b, MXFS_BOOTSTRAP_CLAIMED, MXFS_BOOTSTRAP_CLAIMED,
				 MXFS_BOOTSTRAP_MANIFEST_SEALED, "SEALED",
				 bs_seal_edit, &a);
}

static void bs_release_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	(void)arg;
	r->victim_bitmap = 0;
	r->complete_bitmap = 0;
	r->registrants = 0;
	r->registrants_done = 0;
	r->manifest_hash = 0;
	r->ledger_gen = 0;
}

int mxfs_bootstrap_release_claim(struct mxfs_bootstrap *b)
{
	int rc = bs_own_transition(b, MXFS_BOOTSTRAP_CLAIMED,
				   MXFS_BOOTSTRAP_CLAIMED, MXFS_BOOTSTRAP_IDLE,
				   "RELEASED", bs_release_edit, NULL);

	if (rc == 0)
		b->owned = false;
	return rc;
}

int mxfs_bootstrap_set_recovering(struct mxfs_bootstrap *b)
{
	return bs_own_transition(b, MXFS_BOOTSTRAP_MANIFEST_SEALED,
				 MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING, "RECOVERING",
				 NULL, NULL);
}

static void bs_slot_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	int slot = *(int *)arg;

	r->complete_bitmap |= 1ULL << slot;
}

int mxfs_bootstrap_slot_complete(struct mxfs_bootstrap *b, int slot)
{
	if (slot < 0 || slot >= 64)
		return -EINVAL;
	if (b && !(b->img.victim_bitmap & (1ULL << slot))) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-SLOT-NOT-SEALED slot=%d victims=0x%016llx "
			     "— a completion for a slot outside the sealed manifest "
			     "is refused", slot,
			     (unsigned long long)b->img.victim_bitmap);
		return -ENOENT;
	}
	return bs_own_transition(b, MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING, "SLOT-COMPLETE",
				 bs_slot_edit, &slot);
}

static void bs_reg_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	r->registrants_done++;
}

int mxfs_bootstrap_registrant_done(struct mxfs_bootstrap *b)
{
	if (b && b->img.registrants_done >= b->img.registrants)
		return -ENOENT;
	return bs_own_transition(b, MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING, "REGISTRANT-DONE",
				 bs_reg_edit, NULL);
}

static void bs_complete_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	r->complete_stamp_ms = mxfs_pal_time_ms();
}

int mxfs_bootstrap_complete(struct mxfs_bootstrap *b)
{
	uint64_t complete;

	if (!b)
		return -EINVAL;
	/* the platter is re-read inside the transition; this is the local
	 * pre-check so a caller that skipped a slot is told which */
	complete = b->img.complete_bitmap;
	/* (§6.5): the adopted slot K is completed by the owner's OWN
	 * xfs_log_mount (K_REPLAY_OK), never by the foreign completion ladder;
	 * its bit is never zeroed and never CAS'd into complete_bitmap. */
	if (b->img.escrow.state == MXFS_BOOT_ESCROW_K_REPLAY_OK &&
	    b->img.escrow.slot < 64)
		complete |= 1ULL << b->img.escrow.slot;
	if (complete != b->img.victim_bitmap ||
	    b->img.registrants_done != b->img.registrants) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-INCOMPLETE victims=0x%016llx "
			     "complete=0x%016llx registrants=%u/%u — global "
			     "RECOVERY_COMPLETE refused while any sealed victim or "
			     "registrant is unresolved",
			     (unsigned long long)b->img.victim_bitmap,
			     (unsigned long long)b->img.complete_bitmap,
			     b->img.registrants_done, b->img.registrants);
		return -EBUSY;
	}
	return bs_own_transition(b, MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERY_COMPLETE, "COMPLETE",
				 bs_complete_edit, NULL);
}

/* ── the adopted-slice escrow (§6.5 shape B) ── */

const char *mxfs_bootstrap_escrow_name(uint8_t state)
{
	switch (state) {
	case MXFS_BOOT_ESCROW_NONE:             return "NONE";
	case MXFS_BOOT_ESCROW_PREPARED:         return "PREPARED";
	case MXFS_BOOT_ESCROW_K_CLAIMED:        return "K_CLAIMED";
	case MXFS_BOOT_ESCROW_K_REPLAY_OK:      return "K_REPLAY_OK";
	case MXFS_BOOT_ESCROW_K_REPLAY_REFUSED: return "K_REPLAY_REFUSED";
	default:                                return "?";
	}
}

static void bs_escrow_prepare_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	const struct mxfs_bootstrap_escrow *e = arg;

	r->escrow = *e;
	r->escrow.state = MXFS_BOOT_ESCROW_PREPARED;
}

int mxfs_bootstrap_escrow_prepare(struct mxfs_bootstrap *b,
				  const struct mxfs_bootstrap_escrow *e)
{
	struct mxfs_bootstrap_rec *back;
	int rc;

	if (!b || !e || e->slot >= 64)
		return -EINVAL;
	/* (§6.7 resume): a PREPARED escrow for the SAME K and victim may
	 * be re-prepared with the current guarded image — the claim CAW never
	 * landed, and the descriptor's lease fields moved across the unwind's
	 * relinquish + re-acquire while its certificate did not. */
	if (b->img.escrow.state == MXFS_BOOT_ESCROW_PREPARED &&
	    b->img.escrow.slot == e->slot &&
	    b->img.escrow.victim_node == e->victim_node &&
	    b->img.escrow.victim_epoch == e->victim_epoch &&
	    b->img.escrow.victim_key == e->victim_key) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-BOOT-ESCROW-REPREPARE slot=%u — refreshing the "
			     "PREPARED escrow's descriptor image for the resumed claim",
			     e->slot);
	} else if (b->img.escrow.state != MXFS_BOOT_ESCROW_NONE) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-ESCROW-EXISTS state=%s slot=%u — this term "
			     "already adopted a slot; a second adoption in the same "
			     "term is refused (ruling STOP-SHIP 6)",
			     mxfs_bootstrap_escrow_name(b->img.escrow.state),
			     b->img.escrow.slot);
		return -EEXIST;
	}
	rc = bs_own_transition(b, MXFS_BOOTSTRAP_RECOVERING,
			       MXFS_BOOTSTRAP_RECOVERING, MXFS_BOOTSTRAP_RECOVERING,
			       "ESCROW-PREPARED", bs_escrow_prepare_edit,
			       (void *)e);
	if (rc)
		return rc;
	/* read back: the claim CAW that destroys K's guard must never run ahead
	 * of the evidence that authorises it */
	back = mxfs_pal_alloc(sizeof(*back));
	if (!back)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, back);
	if (rc == 0 &&
	    (back->escrow.state != MXFS_BOOT_ESCROW_PREPARED ||
	     back->escrow.slot != e->slot ||
	     memcmp(back->escrow.desc, e->desc, MXFS_BOOT_ESCROW_DESC_BYTES) != 0))
		rc = -EIO;
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(back);
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-ESCROW-READBACK slot=%u victim=%u/%llu key=0x%llx "
		     "rc=%d — %s", e->slot, e->victim_node,
		     (unsigned long long)e->victim_epoch,
		     (unsigned long long)e->victim_key, rc,
		     rc ? "the escrow did not read back; K is NOT claimed" :
			  "K's guard and certificate are escrowed; the claim may "
			  "consume the sector");
	return rc;
}

struct bs_escrow_adv_args {
	uint8_t state;
	int32_t replay_rc;
};

static void bs_escrow_adv_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	struct bs_escrow_adv_args *a = arg;

	r->escrow.state = a->state;
	if (a->state == MXFS_BOOT_ESCROW_K_REPLAY_REFUSED)
		r->escrow.replay_rc = a->replay_rc;
}

int mxfs_bootstrap_escrow_advance(struct mxfs_bootstrap *b, uint8_t state,
				  int32_t replay_rc)
{
	struct bs_escrow_adv_args a = { state, replay_rc };
	uint8_t cur;

	if (!b)
		return -EINVAL;
	cur = b->img.escrow.state;
	if (!((cur == MXFS_BOOT_ESCROW_PREPARED &&
	       state == MXFS_BOOT_ESCROW_K_CLAIMED) ||
		  (cur == MXFS_BOOT_ESCROW_K_CLAIMED &&
		   (state == MXFS_BOOT_ESCROW_K_REPLAY_OK ||
		    state == MXFS_BOOT_ESCROW_K_REPLAY_REFUSED)))) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-ESCROW-BAD-TRANSITION %s -> %s refused",
			     mxfs_bootstrap_escrow_name(cur),
			     mxfs_bootstrap_escrow_name(state));
		return -EINVAL;
	}
	return bs_own_transition(b, MXFS_BOOTSTRAP_RECOVERING,
				 MXFS_BOOTSTRAP_RECOVERING, MXFS_BOOTSTRAP_RECOVERING,
				 state == MXFS_BOOT_ESCROW_K_CLAIMED ? "ESCROW-K-CLAIMED" :
				 state == MXFS_BOOT_ESCROW_K_REPLAY_OK ? "ESCROW-K-REPLAY-OK" :
				 "ESCROW-K-REPLAY-REFUSED",
				 bs_escrow_adv_edit, &a);
}

int mxfs_bootstrap_owner_is(struct mxfs_bootstrap *b, uint32_t node,
			    uint64_t epoch, uint64_t *seq)
{
	struct mxfs_bootstrap_rec *cur;
	int rc;

	if (!b || !node || !epoch)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, cur);
	if (rc == 0) {
		if (cur->state != MXFS_BOOTSTRAP_IDLE &&
		    cur->state != MXFS_BOOTSTRAP_RECOVERY_COMPLETE &&
		    cur->owner_node == node && cur->owner_epoch == epoch) {
			if (seq)
				*seq = cur->seq;        /* change, never age */
			rc = 1;
		} else {
			rc = 0;
		}
	}
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

/* ── refuse / resume / manifest (docs/whole-cluster-restart.md §6) ── */

struct bs_refuse_args {
	uint32_t slot;
	uint32_t reason;
};

static void bs_refuse_edit(struct mxfs_bootstrap_rec *r, void *arg)
{
	struct bs_refuse_args *a = arg;

	r->refused_slot = a->slot;
	r->refused_reason = a->reason;
	r->complete_stamp_ms = mxfs_pal_time_ms();
}

int mxfs_bootstrap_refuse(struct mxfs_bootstrap *b, uint32_t slot,
			  uint32_t reason)
{
	struct bs_refuse_args a = { slot, reason };

	mxfs_pal_log(MXFS_LOG_ERR,
		     "mxfs: P-BOOT-REFUSING slot=%u reason=%s — a sealed victim "
		     "cannot be recovered by this bootstrap; the volume stays "
		     "refused to ACTIVE admission until operator repair "
		     "(chk_mxfs --clear-bootstrap after the verdict is resolved)",
		     slot, mxfs_bootstrap_refuse_name(reason));
	return bs_own_transition(b, MXFS_BOOTSTRAP_CLAIMED,
				 MXFS_BOOTSTRAP_RECOVERING, MXFS_BOOTSTRAP_REFUSED,
				 "REFUSED", bs_refuse_edit, &a);
}

int mxfs_bootstrap_resume(struct mxfs_bootstrap *b,
			  const uint8_t host_uuid[16],
			  const uint8_t boot_uuid[16], uint64_t pr_key,
			  uint32_t key_gen, uint32_t *node_out,
			  uint64_t *epoch_out)
{
	struct mxfs_bootstrap_rec *cur;
	int rc;

	if (!b || !host_uuid || !boot_uuid || !pr_key || !node_out || !epoch_out)
		return -EINVAL;
	cur = mxfs_pal_alloc(sizeof(*cur));
	if (!cur)
		return -ENOMEM;
	mxfs_pal_mutex_lock(b->lock);
	rc = bs_read_locked(b, cur);
	if (rc)
		goto out;
	if (cur->state != MXFS_BOOTSTRAP_CLAIMED &&
	    cur->state != MXFS_BOOTSTRAP_MANIFEST_SEALED &&
	    cur->state != MXFS_BOOTSTRAP_RECOVERING) {
		rc = -ENOENT;
		goto out;
	}
	if (memcmp(cur->owner_host_uuid, host_uuid, 16) != 0 ||
	    memcmp(cur->owner_boot_uuid, boot_uuid, 16) != 0 ||
	    cur->owner_pr_key != pr_key || cur->owner_key_gen != key_gen) {
		rc = -EBUSY;
		goto out;
	}
	b->owned = true;
	b->img = *cur;
	b->nonce = cur->owner_nonce;
	*node_out = cur->owner_node;
	*epoch_out = cur->owner_epoch;
	mxfs_pal_log(MXFS_LOG_WARN,
		     "mxfs: P-BOOT-RESUME term=%llu state=%s node=%u inc=%llu "
		     "key=0x%llx — this boot's earlier claim is resumed under the "
		     "SAME term and provisional identity (no takeover, no fence)",
		     (unsigned long long)cur->term,
		     mxfs_bootstrap_state_name(cur->state), cur->owner_node,
		     (unsigned long long)cur->owner_epoch,
		     (unsigned long long)cur->owner_pr_key);
out:
	mxfs_pal_mutex_unlock(b->lock);
	mxfs_pal_free(cur);
	return rc;
}

uint64_t mxfs_bootstrap_manifest_hash(const struct mxfs_bootstrap_mf_entry *e,
				      unsigned int n)
{
	uint32_t lo = mxfs_pal_crc32c(~0U, e, n * sizeof(*e));
	uint32_t hi = mxfs_pal_crc32c(lo ^ 0xA5A5A5A5u, &n, sizeof(n));

	return ((uint64_t)hi << 32) | lo;
}

static uint32_t bs_mf_sector_crc(const struct mxfs_bootstrap_mf_sector *s)
{
	struct mxfs_bootstrap_mf_sector t = *s;

	t.crc32c = 0;
	return mxfs_pal_crc32c(~0U, &t, sizeof(t));
}

int mxfs_bootstrap_manifest_write(struct mxfs_bootstrap *b,
				  const struct mxfs_bootstrap_mf_entry *e,
				  unsigned int n, uint64_t *hash_out)
{
	if (!b || !b->owned)
		return -ENOENT;
	return mxfs_bootstrap_manifest_write_term(b, b->img.term, e, n, hash_out);
}

int mxfs_bootstrap_manifest_write_term(struct mxfs_bootstrap *b, uint64_t term,
				       const struct mxfs_bootstrap_mf_entry *e,
				       unsigned int n, uint64_t *hash_out)
{
	struct mxfs_bootstrap_mf_sector *s;
	unsigned int i, done = 0, bank;
	int rc = 0;

	if (!b || !e || !hash_out || n > MXFS_BOOT_MF_MAX)
		return -EINVAL;
	bank = MXFS_BOOT_MF_BANK(term);            /* term parity */
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	for (i = 0; i < MXFS_BOOT_MF_SECTORS; i++) {
		unsigned int k, cnt = 0;

		memset(s, 0, sizeof(*s));
		s->magic = MXFS_BOOT_MF_MAGIC;
		s->ver = MXFS_BOOTSTRAP_VERSION;
		s->term = term;
		s->idx = i;
		for (k = 0; k < MXFS_BOOT_MF_PER_SECTOR && done < n; k++, done++)
			s->e[cnt++] = e[done];
		s->count = (uint16_t)cnt;
		s->crc32c = bs_mf_sector_crc(s);
		rc = mxfs_pal_bdev_write_fua(b->dev,
					     b->offset + (uint64_t)(bank + i) *
						 MXFS_BOOTSTRAP_REC_BYTES,
									 s, sizeof(*s));
		if (rc)
			break;
	}
	mxfs_pal_free(s);
	if (rc == 0)
		*hash_out = mxfs_bootstrap_manifest_hash(e, n);
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-MANIFEST-WRITE term=%llu entries=%u hash=0x%016llx "
		     "rc=%d", (unsigned long long)term, n,
		     rc ? 0ULL : (unsigned long long)*hash_out, rc);
	return rc;
}

int mxfs_bootstrap_manifest_read(struct mxfs_bootstrap *b, uint64_t term,
				 uint64_t hash,
				 struct mxfs_bootstrap_mf_entry *e,
				 unsigned int max, unsigned int *n_out)
{
	struct mxfs_bootstrap_mf_sector *s;
	unsigned int i, n = 0, bank;
	int rc = 0;

	if (!b || !e || !n_out)
		return -EINVAL;
	*n_out = 0;
	bank = MXFS_BOOT_MF_BANK(term);            /* term parity */
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	for (i = 0; i < MXFS_BOOT_MF_SECTORS; i++) {
		unsigned int k;

		rc = mxfs_pal_bdev_read_prio(b->dev,
					     b->offset + (uint64_t)(bank + i) *
						 MXFS_BOOTSTRAP_REC_BYTES,
									 s, sizeof(*s));
		if (rc)
			break;
		if (s->magic != MXFS_BOOT_MF_MAGIC || s->ver != MXFS_BOOTSTRAP_VERSION ||
		    s->term != term || s->idx != i ||
		    s->count > MXFS_BOOT_MF_PER_SECTOR ||
		    s->crc32c != bs_mf_sector_crc(s)) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-BOOT-MANIFEST-INVALID sector=%u magic=0x%08x "
				     "ver=%u term=%llu (want %llu) idx=%u count=%u — the "
				     "sealed manifest does not validate; failing closed",
				     i, s->magic, s->ver, (unsigned long long)s->term,
				     (unsigned long long)term, s->idx, s->count);
			rc = -EUCLEAN;
			break;
		}
		for (k = 0; k < s->count; k++) {
			if (n >= max) {
				rc = -EOVERFLOW;
				break;
			}
			e[n++] = s->e[k];
		}
		if (rc)
			break;
	}
	mxfs_pal_free(s);
	if (rc == 0 && mxfs_bootstrap_manifest_hash(e, n) != hash) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-BOOT-MANIFEST-HASH entries=%u have=0x%016llx "
			     "want=0x%016llx — manifest and record disagree; failing "
			     "closed", n,
			     (unsigned long long)mxfs_bootstrap_manifest_hash(e, n),
			     (unsigned long long)hash);
		rc = -EUCLEAN;
	}
	if (rc == 0)
		*n_out = n;
	return rc;
}

/*
 * ── THE SURVIVOR SCAN (docs/whole-cluster-restart.md §6.1) ──
 *
 * A failure detector, not a proof: two reads of the 64 heartbeat sectors on
 * the reader's own clock.  Any record that CHANGED (heartbeat stamp, flags,
 * identity, evict ring — a whole-record compare) between the reads belongs
 * to a live node; a record that did not change across the full window is
 * presumed dead and becomes a manifest entry.  Safety comes from FENCING
 * every presumed victim before any replay (ruling Q1), never from this scan.
 *
 * The window is the same dead threshold the monitor uses; a cluster with any
 * live member shows movement within two heartbeat intervals, so the caller
 * polls early (MXFS_BOOTSTRAP_SCAN_EARLY_MS) and bails to the ordinary path
 * as soon as anything moves.  Occupied records that cannot be read or parsed
 * FAIL CLOSED (counted in *unread; the caller refuses).
 *
 * fs_gen filters pre-mkfs ghosts exactly as the claim path does.  Records
 * beyond `slice_count` are victims without a slice (class 3, fence only).
 */
int mxfs_bootstrap_survivor_scan(mxfs_bdev_t *dev, uint64_t disklock_offset,
				 uint32_t fs_gen, uint32_t slice_count,
				 uint32_t window_ms, uint32_t early_ms,
				 struct mxfs_bootstrap_mf_entry *e,
				 unsigned int max, unsigned int *n_out,
				 uint64_t *victims_out, unsigned int *moved_out,
				 unsigned int *unread_out,
				 unsigned int *noident_out)
{
	struct mxfs_disklock_heartbeat *a, *b;
	uint64_t t0, now;
	unsigned int slot, n = 0, moved = 0, unread = 0, noident = 0, occupied = 0;
	unsigned int terminal = 0;
	uint64_t victims = 0;
	int rc = 0;

	if (!dev || !e || !n_out || !victims_out || !moved_out || !unread_out ||
	    !noident_out)
		return -EINVAL;
	*n_out = 0; *victims_out = 0; *moved_out = 0; *unread_out = 0;
	*noident_out = 0;
	a = mxfs_pal_alloc(sizeof(*a) * MXFS_DISKLOCK_HB_SLOTS);
	b = mxfs_pal_alloc(sizeof(*b));
	if (!a || !b) {
		rc = -ENOMEM;
		goto out;
	}
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		rc = mxfs_pal_bdev_read_prio(dev, disklock_offset +
					     (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE,
					     &a[slot], sizeof(a[slot]));
		if (rc) {
			memset(&a[slot], 0xFF, sizeof(a[slot]));   /* unreadable: never "empty" */
			unread++;
			rc = 0;
		} else if (a[slot].magic == MXFS_DISKLOCK_MAGIC && a[slot].flags != 0 &&
			   a[slot].flags != MXFS_DISKLOCK_FLAG_RETIRE_PENDING &&
			   a[slot].fs_gen == fs_gen) {
			/* 0.75.4: only a member-shaped record can be a live member or
			 * a victim.  A RETIRE_PENDING record is a clean release whose
			 * key retirement is still unproven: it never heartbeats, so
			 * waiting the dead window for it to change proves nothing —
			 * measured on the 2-node rig, the last leaver's remount sat
			 * the full 64 s on its peer's pending record (then refused or,
			 * when the peer happened to remount meanwhile, went on).  The
			 * admission barrier still holds on such a record until it is
			 * settled (P-ADMIT-RETIRE-PENDING-HELD); the victim build
			 * below never counted it either. */
			occupied++;
		}
	}
	if (!occupied) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-BOOT-SCAN-EMPTY no occupied heartbeat record "
			     "(unreadable=%u) — nothing to bootstrap", unread);
		*unread_out = unread;
		goto out;
	}
	/*
	 * Poll: re-read at early_ms cadence; ANY change ends the scan (a
	 * survivor exists).  Only a table frozen for the whole window is a total
	 * outage.  Elapsed time is the reader's monotonic clock.
	 */
	t0 = mxfs_pal_time_ms();
	for (;;) {
		mxfs_pal_sleep_ms(early_ms);
		for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
			if (a[slot].magic != MXFS_DISKLOCK_MAGIC || a[slot].flags == 0 ||
			    a[slot].fs_gen != fs_gen)
				continue;
			rc = mxfs_pal_bdev_read_prio(dev, disklock_offset +
						     (uint64_t)slot * MXFS_DISKLOCK_RECORD_SIZE,
						     b, sizeof(*b));
			if (rc) {
				unread++;
				rc = 0;
				continue;
			}
			if (memcmp(&a[slot], b, sizeof(*b)) != 0) {
				moved++;
				mxfs_pal_log(MXFS_LOG_DEBUG,
					     "mxfs: P-BOOT-SCAN-SURVIVOR slot=%u node=%u inc=%llu "
					     "— record changed during the scan: a live member "
					     "exists; this is not a total outage",
					     slot, a[slot].node_id,
					     (unsigned long long)a[slot].epoch);
			}
		}
		now = mxfs_pal_time_ms();
		if (moved || now - t0 >= window_ms)
			break;
	}
	*moved_out = moved;
	*unread_out = unread;
	if (moved || unread)
		goto out;
	/* frozen for the whole window: build the victim entries */
	for (slot = 0; slot < MXFS_DISKLOCK_HB_SLOTS; slot++) {
		const struct mxfs_disklock_heartbeat *r = &a[slot];
		struct mxfs_bootstrap_mf_entry *me;

		if (r->magic != MXFS_DISKLOCK_MAGIC || r->flags == 0 ||
		    r->fs_gen != fs_gen)
			continue;
		if (r->flags != MXFS_DISKLOCK_FLAG_ACTIVE &&
		    r->flags != MXFS_DISKLOCK_FLAG_WITHDRAWN &&
		    r->flags != MXFS_DISKLOCK_FLAG_RECOVERY_GUARD)
			continue;                       /* not member-shaped */
		if (r->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD &&
		    r->recov.desc.magic != MXFS_RECOV_DESC_MAGIC)
			continue;                       /* transient bucket-sweep guard: no slice, no key */
		if (r->flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD) {
			/*
			 * (D-0493): a guard carrying a TERMINAL verdict is not a
			 * victim.  Its incarnation was fenced (certificate at FENCED)
			 * and its slice durably REFUSED (QUARANTINED + outcome) by a
			 * survivor before the outage; a live cluster runs beside that
			 * record until operator repair, so its presence says nothing
			 * about whether the cluster is up.  Nothing here fences, replays,
			 * adopts or zeroes it — the ordinary path's admission barrier
			 * imports the quarantine before the filesystem is available, and
			 * claim_slot never takes the slot.  Counting it as a victim made
			 * the scan demand a fence key from a record whose identity block
			 * is the guard WRITER's (never consulted, here absent) and refuse
			 * every restart after a clean shutdown that followed a refusal.
			 * A torn verdict (QUARANTINED, outcome bytes present but not
			 * validating) fails closed like an unreadable sector.
			 */
			const struct mxfs_recov_outcome *oc = NULL;
			int trc = mxfs_hb_terminal_guard_classify(r, slot, fs_gen, &oc);

			if (trc == 0 || trc == -ENODATA) {
				terminal++;
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: P-BOOT-SCAN-TERMINAL-GUARD slot=%u "
					     "victim=%u/%llu %s domain=%u ag_mask=0x%llx "
					     "seq=%llu — fenced and quarantined before the "
					     "outage; not a victim: nothing to fence, replay "
					     "or zero (the admission barrier imports the "
					     "quarantine)",
					     slot, r->node_id, (unsigned long long)r->epoch,
					     trc == 0 ? "verdict" : "legacy-quarantine",
					     oc ? oc->domain_kind : 0,
					     (unsigned long long)(oc ? oc->ag_mask : 0),
					     (unsigned long long)(oc ? oc->publish_seq : 0));
				continue;
			}
			if (trc == -EBADMSG) {
				unread++;                   /* torn verdict: fail closed */
				mxfs_pal_log(MXFS_LOG_ERR,
					     "mxfs: P-BOOT-SCAN-GUARD-TORN slot=%u node=%u "
					     "inc=%llu — QUARANTINED descriptor with an "
					     "outcome that does not validate; counted "
					     "unreadable (bootstrap refused)",
					     slot, r->node_id, (unsigned long long)r->epoch);
				continue;
			}
			/* -EAGAIN (sub-terminal descriptor) / -EPROTO: a victim as before */
		}
		if (n >= max) {
			rc = -EOVERFLOW;
			goto out;
		}
		me = &e[n++];
		memset(me, 0, sizeof(*me));
		me->slot = (uint16_t)slot;
		me->cls = slot < slice_count ? MXFS_BOOT_MF_VICTIM_SLICE :
					       MXFS_BOOT_MF_VICTIM_NOSLICE;
		me->rec_flags = (uint8_t)r->flags;
		/* (§6.5): a predecessor term's adopted slice — the next
		 * owner prefers it as its own K */
		if (mxfs_hb_feature_bootstrap_pending(r))
			me->rec_flags |= MXFS_BOOT_MF_RECF_PENDING;
		me->node_id = r->node_id;
		me->epoch = r->epoch;
		me->succ_of = MXFS_BOOT_MF_NO_INDEX;
		/*
		 * THE GUARD-AWARE PREDICATE, because this is the one reader that asks
		 * a GUARDED record for its identity.
		 *
		 * The identity crc covers hb->flags, and a writer that installs a
		 * fencing intent moves the victim's record to RECOVERY_GUARD without
		 * re-binding that crc — only the retirement paths re-bind.  So the
		 * victim's own block, intact and byte for byte what a fence of that
		 * victim needs, reads invalid under the flags-strict test.  Every
		 * other caller of the strict test restricts flags to
		 * ACTIVE/WITHDRAWN/RETIRE_PENDING before asking, so no guard record
		 * ever reaches it; this scan takes guard records as victims on purpose
		 * (a terminal one is excluded above, a sub-terminal one is a victim as
		 * before), which is what made it the one site that could be wrong.
		 *
		 * Asking the strict test here refused the whole bootstrap for exactly
		 * the outage it exists to recover: a total outage with a fencing
		 * intent standing left no node able to mount at all, with both dead
		 * slices unreplayed on the platter (five laps of five, cuts 2-6 of
		 * tests/fence_crash_cuts.sh on the destroyed-victim arm).  The
		 * guard-aware test accepts the crc bound under the states the victim's
		 * OWN writer could have bound it to and checks slot, fs_gen, node,
		 * epoch and the block itself unchanged — so a block copied from
		 * another record or another incarnation still fails here.
		 */
		if (mxfs_hb_guard_identity_valid(r, slot)) {
			me->pr_key = r->ident.pr_key;
			me->key_gen = r->ident.key_gen;
			memcpy(me->host_uuid, r->ident.host_uuid, 16);
			memcpy(me->boot_uuid, r->ident.boot_uuid, 16);
		} else {
			/* Name it.  A bare count cost four laps of reading to attribute
			 * to a slot, and the refusal it feeds aborts the mount. */
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-BOOT-SCAN-NOIDENT slot=%u node=%u inc=%llu "
				     "flags=0x%x ident{magic=0x%x ver=%u key=0x%llx "
				     "gen=%u} — this victim's identity block does not "
				     "validate for its own record, so it carries no key a "
				     "fence could name and the bootstrap cannot proceed",
				     slot, r->node_id, (unsigned long long)r->epoch,
				     r->flags, r->ident.magic, r->ident.ver,
				     (unsigned long long)r->ident.pr_key,
				     r->ident.key_gen);
			noident++;          /* a record with no key: unclassifiable */
		}
		victims |= 1ULL << slot;
	}
	*n_out = n;
	*victims_out = victims;
	*noident_out = noident;
	*unread_out = unread;
	if (n == 0 && terminal)
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: P-BOOT-SCAN-TERMINAL-ONLY %u occupied record(s) "
			     "unchanged for %llu ms, %u of them terminal guard(s) and "
			     "no victim — not an outage; the ordinary path claims a "
			     "slot and admission imports the quarantine(s)",
			     occupied, (unsigned long long)(mxfs_pal_time_ms() - t0),
			     terminal);
	else
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "mxfs: P-BOOT-SCAN-FROZEN %u occupied record(s) unchanged for "
			     "%llu ms — TOTAL OUTAGE: %u victim(s) victims=0x%016llx "
			     "noident=%u terminal_guards=%u torn=%u", occupied,
			     (unsigned long long)(mxfs_pal_time_ms() - t0), n,
			     (unsigned long long)victims, noident, terminal,
			     unread);
out:
	mxfs_pal_free(a);
	mxfs_pal_free(b);
	return rc;
}

/*
 * ── COMPLETION TOMBSTONES, LINEAGE, THE TAKEOVER JOURNAL ──
 * docs/whole-cluster-restart.md §6.8; design-consult review ccmemory
 * docs/history/gpt-review-item5f-takeover-build-plan.md.
 */

const char *mxfs_bootstrap_tomb_kind_name(uint8_t kind)
{
	switch (kind) {
	case MXFS_BOOT_TOMB_DIRECT:     return "DIRECT";
	case MXFS_BOOT_TOMB_INHERITED:  return "INHERITED";
	default:                        return "?";
	}
}

uint32_t mxfs_bootstrap_tomb_crc(const struct mxfs_bootstrap_tomb *t)
{
	struct mxfs_bootstrap_tomb c = *t;

	c.crc32c = 0;
	return mxfs_pal_crc32c(~0U, &c, sizeof(c));
}

uint32_t mxfs_bootstrap_mf_entry_crc(const struct mxfs_bootstrap_mf_entry *e)
{
	return mxfs_pal_crc32c(~0U, e, sizeof(*e));
}

static uint64_t bs_tomb_sector_off(const struct mxfs_bootstrap *b,
				   unsigned int slot)
{
	return b->offset + (uint64_t)(MXFS_BOOT_SEC_TOMB +
				      slot / MXFS_BOOT_TOMB_PER_SECTOR) *
					   MXFS_BOOTSTRAP_REC_BYTES;
}

static bool bs_tomb_valid(const struct mxfs_bootstrap_tomb *t,
			  unsigned int slot, uint64_t episode_term)
{
	return t->magic == MXFS_BOOT_TOMB_MAGIC && t->slot == slot &&
	       (t->kind == MXFS_BOOT_TOMB_DIRECT ||
		t->kind == MXFS_BOOT_TOMB_INHERITED) &&
		   t->term >= episode_term && t->victim_node && t->victim_epoch &&
		   t->crc32c == mxfs_bootstrap_tomb_crc(t);
}

int mxfs_bootstrap_tomb_write(struct mxfs_bootstrap *b,
			      struct mxfs_bootstrap_tomb *t)
{
	if (!b || !b->owned)
		return -ENOENT;
	return mxfs_bootstrap_tomb_write_term(b, b->img.term, t);
}

int mxfs_bootstrap_tomb_write_term(struct mxfs_bootstrap *b, uint64_t term,
				   struct mxfs_bootstrap_tomb *t)
{
	struct mxfs_bootstrap_tomb_sector *cur, *want;
	unsigned int idx, attempt;
	uint64_t off;
	int rc = -EAGAIN;

	if (!b || !t || t->slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	idx = t->slot % MXFS_BOOT_TOMB_PER_SECTOR;
	off = bs_tomb_sector_off(b, t->slot);
	cur = mxfs_pal_alloc(sizeof(*cur));
	want = mxfs_pal_alloc(sizeof(*want));
	if (!cur || !want) {
		rc = -ENOMEM;
		goto out;
	}
	t->magic = MXFS_BOOT_TOMB_MAGIC;
	t->term = term;
	t->crc32c = mxfs_bootstrap_tomb_crc(t);
	/* review SS-7: eight tombstones share a sector and completion workers
	 * run concurrently — only an exact-image CAW of the whole sector keeps
	 * a neighbour's tombstone from being clobbered by a torn read-modify-
	 * write; a lost CAS re-reads and retries */
	for (attempt = 0; attempt < 8; attempt++) {
		rc = mxfs_pal_bdev_read_prio(b->dev, off, cur, sizeof(*cur));
		if (rc)
			break;
		*want = *cur;
		want->t[idx] = *t;
		rc = mxfs_pal_bdev_compare_and_write(b->dev, off, cur, want);
		if (rc == -EOPNOTSUPP)
			rc = mxfs_pal_bdev_write_fua(b->dev, off, want, sizeof(*want));
		if (rc != -EAGAIN)
			break;
	}
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-TOMB kind=%s slot=%u victim=%u/%llu key=0x%llx "
		     "term=%llu obligation=0x%08x proof=0x%08x rc=%d",
		     mxfs_bootstrap_tomb_kind_name(t->kind), t->slot,
		     t->victim_node, (unsigned long long)t->victim_epoch,
		     (unsigned long long)t->victim_key,
		     (unsigned long long)t->term, t->obligation, t->proof_crc, rc);
out:
	mxfs_pal_free(cur);
	mxfs_pal_free(want);
	return rc;
}

int mxfs_bootstrap_tomb_read(struct mxfs_bootstrap *b, unsigned int slot,
			     uint64_t episode_term,
			     struct mxfs_bootstrap_tomb *out)
{
	struct mxfs_bootstrap_tomb_sector *s;
	int rc;

	if (!b || !out || slot >= MXFS_DISKLOCK_HB_SLOTS)
		return -EINVAL;
	s = mxfs_pal_alloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	rc = mxfs_pal_bdev_read_prio(b->dev, bs_tomb_sector_off(b, slot), s,
				     sizeof(*s));
	if (rc == 0) {
		const struct mxfs_bootstrap_tomb *t =
		    &s->t[slot % MXFS_BOOT_TOMB_PER_SECTOR];

		if (bs_tomb_valid(t, slot, episode_term))
			*out = *t;
		else
			rc = -ENOENT;
	}
	mxfs_pal_free(s);
	return rc;
}

uint32_t mxfs_bootstrap_lineage_crc(const struct mxfs_bootstrap_lineage *l)
{
	struct mxfs_bootstrap_lineage c = *l;

	c.crc32c = 0;
	return mxfs_pal_crc32c(~0U, &c, sizeof(c));
}

int mxfs_bootstrap_lineage_write(struct mxfs_bootstrap *b, unsigned int idx,
				 struct mxfs_bootstrap_lineage *l)
{
	int rc;

	if (!b || !l || idx >= MXFS_BOOT_LIN_MAX)
		return -EINVAL;
	l->magic = MXFS_BOOT_LIN_MAGIC;
	l->ver = MXFS_BOOTSTRAP_VERSION;
	l->idx = (uint16_t)idx;
	l->crc32c = mxfs_bootstrap_lineage_crc(l);
	rc = mxfs_pal_bdev_write_fua(b->dev,
				     b->offset + (uint64_t)(MXFS_BOOT_SEC_LINEAGE + idx) *
					 MXFS_BOOTSTRAP_REC_BYTES,
								 l, sizeof(*l));
	mxfs_pal_log(rc ? MXFS_LOG_ERR : MXFS_LOG_WARN,
		     "mxfs: P-BOOT-LINEAGE idx=%u term=%llu owner=%u/%llu key=0x%llx "
		     "state=%s manifest=0x%016llx escrow=%s K=%u fence=%s rc=%d",
		     idx, (unsigned long long)l->term, l->owner_node,
		     (unsigned long long)l->owner_epoch,
		     (unsigned long long)l->owner_pr_key,
		     mxfs_bootstrap_state_name(l->state),
		     (unsigned long long)l->manifest_hash,
		     mxfs_bootstrap_escrow_name(l->escrow.state), l->escrow.slot,
		     mxfs_fence_kind_name(l->fence_kind), rc);
	return rc;
}

int mxfs_bootstrap_lineage_read(struct mxfs_bootstrap *b, unsigned int idx,
				uint64_t term, uint64_t episode_term,
				struct mxfs_bootstrap_lineage *out)
{
	int rc;

	if (!b || !out || idx >= MXFS_BOOT_LIN_MAX)
		return -EINVAL;
	rc = mxfs_pal_bdev_read_prio(b->dev,
				     b->offset + (uint64_t)(MXFS_BOOT_SEC_LINEAGE + idx) *
					 MXFS_BOOTSTRAP_REC_BYTES,
								 out, sizeof(*out));
	if (rc)
		return rc;
	if (out->magic != MXFS_BOOT_LIN_MAGIC || out->ver != MXFS_BOOTSTRAP_VERSION ||
	    out->idx != idx || (term && out->term != term) ||
	    out->term < episode_term || out->episode_term != episode_term ||
	    out->crc32c != mxfs_bootstrap_lineage_crc(out))
		return -ENOENT;
	return 0;
}

const char *mxfs_bootstrap_takeover_stage_name(uint16_t stage)
{
	switch (stage) {
	case MXFS_BOOT_TK_EMPTY:            return "EMPTY";
	case MXFS_BOOT_TK_CONTENDER:        return "CONTENDER";
	case MXFS_BOOT_TK_OLD_FENCE_INTENT: return "OLD_FENCE_INTENT";
	case MXFS_BOOT_TK_OLD_FENCE_DONE:   return "OLD_FENCE_DONE";
	case MXFS_BOOT_TK_K_DESC_DONE:      return "K_DESC_DONE";
	case MXFS_BOOT_TK_CAPSULE_WRITTEN:  return "CAPSULE_WRITTEN";
	case MXFS_BOOT_TK_RECORD_COMMITTED: return "RECORD_COMMITTED";
	default:                            return "?";
	}
}

uint32_t mxfs_bootstrap_takeover_crc(const struct mxfs_bootstrap_takeover *t)
{
	struct mxfs_bootstrap_takeover c = *t;

	c.crc32c = 0;
	return mxfs_pal_crc32c(~0U, &c, sizeof(c));
}

static uint64_t bs_tk_off(const struct mxfs_bootstrap *b)
{
	return b->offset + (uint64_t)MXFS_BOOT_SEC_TAKEOVER * MXFS_BOOTSTRAP_REC_BYTES;
}

int mxfs_bootstrap_takeover_read(struct mxfs_bootstrap *b,
				 struct mxfs_bootstrap_takeover *out,
				 bool *valid)
{
	int rc;

	if (!b || !out || !valid)
		return -EINVAL;
	rc = mxfs_pal_bdev_read_prio(b->dev, bs_tk_off(b), out, sizeof(*out));
	if (rc)
		return rc;
	*valid = out->magic == MXFS_BOOT_TK_MAGIC &&
		 out->ver == MXFS_BOOTSTRAP_VERSION &&
		 out->stage >= MXFS_BOOT_TK_CONTENDER &&
		 out->stage <= MXFS_BOOT_TK_RECORD_COMMITTED &&
		 out->crc32c == mxfs_bootstrap_takeover_crc(out);
	return 0;
}

int mxfs_bootstrap_takeover_cas(struct mxfs_bootstrap *b,
				const struct mxfs_bootstrap_takeover *cur,
				struct mxfs_bootstrap_takeover *want)
{
	int rc;

	if (!b || !cur || !want)
		return -EINVAL;
	want->magic = MXFS_BOOT_TK_MAGIC;
	want->ver = MXFS_BOOTSTRAP_VERSION;
	want->seq = cur->magic == MXFS_BOOT_TK_MAGIC ? cur->seq + 1 : 1;
	want->stamp_ms = mxfs_pal_time_ms();
	want->crc32c = mxfs_bootstrap_takeover_crc(want);
	rc = mxfs_pal_bdev_compare_and_write(b->dev, bs_tk_off(b), cur, want);
	if (rc == -EOPNOTSUPP)
		rc = mxfs_pal_bdev_write_fua(b->dev, bs_tk_off(b), want, sizeof(*want));
	return rc;
}

int mxfs_bootstrap_takeover_clear(struct mxfs_bootstrap *b,
				  const struct mxfs_bootstrap_takeover *cur)
{
	struct mxfs_bootstrap_takeover *z;
	int rc;

	if (!b || !cur)
		return -EINVAL;
	z = mxfs_pal_alloc(sizeof(*z));
	if (!z)
		return -ENOMEM;
	memset(z, 0, sizeof(*z));
	rc = mxfs_pal_bdev_compare_and_write(b->dev, bs_tk_off(b), cur, z);
	if (rc == -EOPNOTSUPP)
		rc = mxfs_pal_bdev_write_fua(b->dev, bs_tk_off(b), z, sizeof(*z));
	mxfs_pal_free(z);
	return rc;
}

/* ─── 0.88.0: SLICE LIFECYCLE (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531) ───
 *
 * See the header comment above the declarations in bootstrap.h.  The zero is
 * written through mxfs_pal_bdev_write_fua — the same primitive the heartbeat
 * and every fencing write use — then flushed, then READ BACK in full: a write
 * returning success is not evidence the bytes are on the platter (the SYNCINIT
 * cluster init learned that the hard way), and the whole point of this record
 * is that the format-time zero was never verified.
 */

/*
 * 64 KiB per I/O.  The readback is a SCSI READ(16) passthrough, which the
 * block layer refuses above the LUN's hardware transfer limit (512 KiB on
 * the 2-node rig's LUN) and which maps the buffer's pages by virtual
 * address, so the buffer must be physically contiguous kmalloc memory —
 * hence mxfs_pal_alloc_io and an order-4 chunk that allocates reliably at
 * mount time.  1024 FUA writes and 1024 FUA reads per 64 MiB slice, once
 * per slice per filesystem incarnation.
 */
#define MXFS_SLIFE_ZERO_CHUNK   (64u << 10)

const char *mxfs_slife_state_name(uint32_t state)
{
	switch (state) {
	case MXFS_SLIFE_INIT_REQUIRED: return "INIT_REQUIRED";
	case MXFS_SLIFE_ZEROING:       return "ZEROING";
	case MXFS_SLIFE_READY:         return "READY";
	default:                       return "INVALID";
	}
}

static uint32_t slife_crc(const struct mxfs_slife_record *r)
{
	struct mxfs_slife_record t = *r;

	t.crc = 0;
	return mxfs_pal_crc32c(~0U, &t, sizeof(t));
}

static int slife_region_ok(uint64_t region_off, uint64_t region_size,
			   uint32_t slice)
{
	if (!region_off || region_size < MXFS_SLIFE_RECORD_SIZE ||
	    region_size % MXFS_SLIFE_RECORD_SIZE)
		return -ENODEV;
	if ((uint64_t)slice * MXFS_SLIFE_RECORD_SIZE + MXFS_SLIFE_RECORD_SIZE >
	    region_size)
		return -ERANGE;
	return 0;
}

int mxfs_slife_read(mxfs_bdev_t *dev, uint64_t region_off,
		    uint64_t region_size, uint32_t slice,
		    const uint8_t fs_uuid[16], struct mxfs_slife_record *out)
{
	uint64_t off;
	int rc;

	if (!dev || !fs_uuid || !out)
		return -EINVAL;
	rc = slife_region_ok(region_off, region_size, slice);
	if (rc)
		return rc;
	off = region_off + (uint64_t)slice * MXFS_SLIFE_RECORD_SIZE;
	rc = mxfs_pal_bdev_read_prio(dev, off, out, sizeof(*out));
	if (rc)
		return rc;
	if (out->magic == 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-UNFORMATTED slice=%u off=%llu — the "
			     "lifecycle record carries no magic; mkfs never wrote it "
			     "(or the sector is torn).  Failing closed",
			     slice, (unsigned long long)off);
		return -ENODATA;
	}
	if (out->magic != MXFS_SLIFE_MAGIC ||
	    out->version != MXFS_SLIFE_VERSION ||
	    out->slice != slice ||
	    out->state < MXFS_SLIFE_INIT_REQUIRED ||
	    out->state > MXFS_SLIFE_READY ||
	    out->crc != slife_crc(out)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-INVALID slice=%u magic=0x%08x ver=%u "
			     "rec_slice=%u state=%u crc=0x%08x want=0x%08x — "
			     "refusing",
			     slice, out->magic, out->version, out->slice,
			     out->state, out->crc, slife_crc(out));
		return -EUCLEAN;
	}
	if (memcmp(out->fs_uuid, fs_uuid, 16) != 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-FOREIGN-VOLUME slice=%u — the lifecycle "
			     "record's fs_uuid is not this volume's (a re-mkfs that "
			     "left the region, or a copied sector); refusing",
			     slice);
		return -EXDEV;
	}
	return 0;
}

static int slife_write(mxfs_bdev_t *dev, uint64_t off,
		       struct mxfs_slife_record *r)
{
	struct mxfs_slife_record back;
	int rc;

	r->when_ms = mxfs_pal_time_ms();
	r->crc = slife_crc(r);
	rc = mxfs_pal_bdev_write_fua(dev, off, r, sizeof(*r));
	if (rc)
		return rc;
	rc = mxfs_pal_bdev_read_prio(dev, off, &back, sizeof(back));
	if (rc)
		return rc;
	if (memcmp(&back, r, sizeof(back)) != 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-READBACK slice=%u state=%s — the FUA "
			     "write of the lifecycle record does not read back; "
			     "failing closed",
			     r->slice, mxfs_slife_state_name(r->state));
		return -EIO;
	}
	return 0;
}

int mxfs_slife_claim_init(mxfs_bdev_t *dev, uint64_t region_off,
			  uint64_t region_size, uint32_t slice,
			  const uint8_t fs_uuid[16], uint64_t node,
			  uint64_t epoch, uint64_t payload_off,
			  uint64_t payload_len, uint32_t *before,
			  uint32_t *after, uint32_t *zero_ms)
{
	struct mxfs_slife_record rec;
	uint64_t off, done, t0;
	uint8_t *zb = NULL, *rb = NULL;
	int rc;

	if (before)
		*before = 0;
	if (after)
		*after = 0;
	if (zero_ms)
		*zero_ms = 0;
	rc = mxfs_slife_read(dev, region_off, region_size, slice, fs_uuid, &rec);
	if (rc)
		return rc;
	if (before)
		*before = rec.state;
	if (rec.state == MXFS_SLIFE_READY) {
		if (after)
			*after = rec.state;
		return 0;
	}
	if (!payload_len || (payload_len % 4096)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-PAYLOAD slice=%u len=%llu — payload "
			     "length is not a multiple of 4096; refusing",
			     slice, (unsigned long long)payload_len);
		return -EINVAL;
	}
	off = region_off + (uint64_t)slice * MXFS_SLIFE_RECORD_SIZE;

	/* 1. ZEROING, durable, before the first zero lands: a crash from here
	 *    on is restarted in full by the next claimant of this slot. */
	rec.state = MXFS_SLIFE_ZEROING;
	rec.owner_node = node;
	rec.owner_epoch = epoch;
	rc = slife_write(dev, off, &rec);
	if (rc)
		return rc;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-SLIFE-ZEROING slice=%u node=%llu epoch=%llu "
		     "payload_off=%llu len=%llu — the slice payload is untrusted "
		     "(state was %s); zeroing it through the FUA path before this "
		     "incarnation mounts its log",
		     slice, (unsigned long long)node, (unsigned long long)epoch,
		     (unsigned long long)payload_off,
		     (unsigned long long)payload_len,
		     mxfs_slife_state_name(before ? *before : 0));

	/* 2. the zero: 1 MiB FUA writes */
	zb = mxfs_pal_alloc_io(MXFS_SLIFE_ZERO_CHUNK);
	rb = mxfs_pal_alloc_io(MXFS_SLIFE_ZERO_CHUNK);
	if (!zb || !rb) {
		rc = -ENOMEM;
		goto out;
	}
	memset(zb, 0, MXFS_SLIFE_ZERO_CHUNK);
	t0 = mxfs_pal_time_ms();
	for (done = 0; done < payload_len; done += MXFS_SLIFE_ZERO_CHUNK) {
		uint32_t len = (uint32_t)((payload_len - done) < MXFS_SLIFE_ZERO_CHUNK ?
					  (payload_len - done) : MXFS_SLIFE_ZERO_CHUNK);

		rc = mxfs_pal_bdev_write_fua(dev, payload_off + done, zb, len);
		if (rc) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-SLIFE-ZERO-IO slice=%u off=%llu rc=%d — "
				     "the zero did not complete; record left ZEROING",
				     slice, (unsigned long long)(payload_off + done), rc);
			goto out;
		}
	}
	/* 3. flush barrier, then prove it: read every byte back */
	rc = mxfs_pal_bdev_flush(dev);
	if (rc) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "mxfs: P-SLIFE-FLUSH slice=%u rc=%d — the flush after "
			     "the zero failed; record left ZEROING", slice, rc);
		goto out;
	}
	for (done = 0; done < payload_len; done += MXFS_SLIFE_ZERO_CHUNK) {
		uint32_t len = (uint32_t)((payload_len - done) < MXFS_SLIFE_ZERO_CHUNK ?
					  (payload_len - done) : MXFS_SLIFE_ZERO_CHUNK);

		rc = mxfs_pal_bdev_read_prio(dev, payload_off + done, rb, len);
		if (rc)
			goto out;
		if (memcmp(rb, zb, len) != 0) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "mxfs: P-SLIFE-ZERO-READBACK slice=%u off=%llu — "
				     "the zeroed payload does not read back as zero; the "
				     "target did not persist the zero.  Record left "
				     "ZEROING, mount refused",
				     slice, (unsigned long long)(payload_off + done));
			rc = -EIO;
			goto out;
		}
	}
	if (zero_ms)
		*zero_ms = (uint32_t)(mxfs_pal_time_ms() - t0);

	/* 4. READY, durable, only now */
	rec.state = MXFS_SLIFE_READY;
	rec.generation++;
	rc = slife_write(dev, off, &rec);
	if (rc)
		goto out;
	if (after)
		*after = rec.state;
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "mxfs: P-SLIFE-READY slice=%u node=%llu epoch=%llu gen=%u "
		     "zeroed=%llu zero_ms=%u — the slice payload is a verified "
		     "zero; the log may be mounted",
		     slice, (unsigned long long)node, (unsigned long long)epoch,
		     rec.generation, (unsigned long long)payload_len,
		     zero_ms ? *zero_ms : 0);
	rc = 0;
out:
	if (rc && after)
		*after = MXFS_SLIFE_ZEROING;
	if (zb)
		mxfs_pal_free_io(zb);
	if (rb)
		mxfs_pal_free_io(rb);
	return rc;
}
