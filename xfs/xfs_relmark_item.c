// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS clean-release marker log item — producer, log item ops, and the
 * untrusted-replay pass-1 table (sess403 design-consult ruling, see xfs_relmark_item.h).
 *
 * Modelled on xfs_icreate_item: one log vector, XFS_ITEM_RELEASE_WHEN_COMMITTED
 * (never AIL-resident), no in-core state beyond the format.  Trusted replay
 * (a node recovering its own log) parses it and does nothing; untrusted replay
 * (foreign shadow xlog / adopted slice) records it in pass 1 so the pass-2
 * authority gate can classify the covered tenure's images REDUNDANT_CLEAN.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_relmark_item.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_log_recover.h"
#include "xfs_error.h"
#include "../dlm/v5_mount.h"	/* mxfs_v5_dlm_mount_identity */
#include <linux/hash.h>

struct kmem_cache	*xfs_relmark_cache;

/* producer-side counters (sysfs/dmesg forensics) */
static atomic64_t mxfs_relmark_published = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_publish_fail = ATOMIC64_INIT(0);
static atomic64_t mxfs_relmark_publish_skip_noid = ATOMIC64_INIT(0);

static inline struct xfs_relmark_item *RELMARK_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_relmark_item, mr_item);
}

STATIC void
xfs_relmark_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += sizeof(struct mxfs_relmark_log_format);
}

STATIC void
xfs_relmark_item_format(
	struct xfs_log_item	*lip,
	struct xlog_format_buf	*lfb)
{
	struct xfs_relmark_item	*mrp = RELMARK_ITEM(lip);

	xlog_format_copy(lfb, XLOG_REG_TYPE_MXFS_RELMARK, &mrp->mr_format,
			 sizeof(struct mxfs_relmark_log_format));
}

STATIC void
xfs_relmark_item_release(
	struct xfs_log_item	*lip)
{
	kvfree(RELMARK_ITEM(lip)->mr_item.li_lv_shadow);
	kmem_cache_free(xfs_relmark_cache, RELMARK_ITEM(lip));
}

static const struct xfs_item_ops xfs_relmark_item_ops = {
	.flags		= XFS_ITEM_RELEASE_WHEN_COMMITTED,
	.iop_size	= xfs_relmark_item_size,
	.iop_format	= xfs_relmark_item_format,
	.iop_release	= xfs_relmark_item_release,
};

/*
 * The marker's log reservation.  One 64-byte vector plus the transaction
 * header; rounded generously (log tickets add their own headroom).  Never a
 * permanent reservation: the marker is a single, self-contained transaction.
 */
static struct xfs_trans_res mxfs_relmark_tres = {
	.tr_logres	= 512,
	.tr_logcount	= 1,
	.tr_logflags	= 0,
};

/*
 * Publish a clean-release marker for the tenure {auth_class, resource,
 * lineage, grant_epoch} this node is about to unlock on the platter.
 *
 * ORDERING CONTRACT (design-consult ruling): the caller has completed the
 * Invariant-1 drain (every image logged under the tenure is written and
 * flushed) AND has passed its last "keep the tenure" arm — after this returns
 * 0 the release is irrevocable; the caller must proceed to the unlock CAS and
 * may never resume writing under this grant epoch (a re-acquire mints a new
 * one).  The marker is forced synchronously, so it is durable before the
 * holder bit clears: a crash between this return and the CAS leaves the bit
 * present (APPLY at replay); a crash after the CAS finds the marker
 * (REDUNDANT_CLEAN).
 *
 * Uses XFS_TRANS_NO_WRITECOUNT: this is internal recovery metadata and must
 * not block behind a filesystem freeze.  A log-space wait here is bounded by
 * AIL progress exactly like the drain's own xfs_log_force(SYNC) calls; the
 * reservation is tiny and is taken as the last step of a release whose
 * dirty state has already been pushed out of the AIL.
 */
int
mxfs_relmark_publish(
	struct xfs_mount	*mp,
	uint16_t		auth_class,
	uint64_t		resource,
	uint64_t		lineage,
	uint64_t		grant_epoch,
	const char		*who)
{
	struct xfs_trans	*tp;
	struct xfs_relmark_item	*mrp;
	uint32_t		oslot = 0, onode = 0;
	uint64_t		oepoch = 0;
	int			error;

	if (!mp || !mp->m_log || xfs_is_shutdown(mp))
		return -EIO;
	if (!grant_epoch) {
		/* a zero epoch proves nothing (sess108); nothing to certify */
		atomic64_inc(&mxfs_relmark_publish_skip_noid);
		return 0;
	}
	if (!mxfs_v5_dlm_mount_identity(mp->m_mxfs_dlm, &oslot, &onode,
					&oepoch)) {
		/*
		 * The tokens this tenure stamped were bound to an identity;
		 * without one here the marker could not be matched to them
		 * (and the tokens themselves were INCOMPLETE).  Count, skip.
		 */
		atomic64_inc(&mxfs_relmark_publish_skip_noid);
		return -ENOENT;
	}

	error = xfs_trans_alloc(mp, &mxfs_relmark_tres, 0, 0,
				XFS_TRANS_NO_WRITECOUNT, &tp);
	if (error) {
		atomic64_inc(&mxfs_relmark_publish_fail);
		pr_warn_ratelimited("mxfs: P-RELMARK-FAIL class=%u res=%llu gepoch=%llu who=%s rc=%d — clean-release marker NOT published (transaction)\n",
			(unsigned)auth_class, (unsigned long long)resource,
			(unsigned long long)grant_epoch, who ? who : "?",
			error);
		return error;
	}

	mrp = kmem_cache_zalloc(xfs_relmark_cache, GFP_KERNEL | __GFP_NOFAIL);
	xfs_log_item_init(mp, &mrp->mr_item, XFS_LI_MXFS_RELMARK,
			  &xfs_relmark_item_ops);
	mrp->mr_format.mrl_type = XFS_LI_MXFS_RELMARK;
	mrp->mr_format.mrl_size = 1;
	mrp->mr_format.mrl_version = cpu_to_be16(MXFS_RELMARK_VERSION);
	mrp->mr_format.mrl_class = cpu_to_be16(auth_class);
	mrp->mr_format.mrl_owner_slot = cpu_to_be32(oslot);
	mrp->mr_format.mrl_owner_node = cpu_to_be32(onode);
	mrp->mr_format.mrl_resource = cpu_to_be64(resource);
	mrp->mr_format.mrl_lineage = cpu_to_be64(lineage);
	mrp->mr_format.mrl_grant_epoch = cpu_to_be64(grant_epoch);
	mrp->mr_format.mrl_owner_epoch = cpu_to_be64(oepoch);

	xfs_trans_add_item(tp, &mrp->mr_item);
	tp->t_flags |= XFS_TRANS_DIRTY;
	set_bit(XFS_LI_DIRTY, &mrp->mr_item.li_flags);
	/* durable BEFORE the caller's unlock CAS — the whole point */
	xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp);
	if (error) {
		atomic64_inc(&mxfs_relmark_publish_fail);
		pr_warn_ratelimited("mxfs: P-RELMARK-FAIL class=%u res=%llu gepoch=%llu who=%s rc=%d — clean-release marker NOT durable (commit)\n",
			(unsigned)auth_class, (unsigned long long)resource,
			(unsigned long long)grant_epoch, who ? who : "?",
			error);
		return error;
	}
	atomic64_inc(&mxfs_relmark_published);
	return 0;
}

void
mxfs_relmark_counters(
	uint64_t		*published,
	uint64_t		*failed,
	uint64_t		*skipped_noid)
{
	if (published)
		*published = atomic64_read(&mxfs_relmark_published);
	if (failed)
		*failed = atomic64_read(&mxfs_relmark_publish_fail);
	if (skipped_noid)
		*skipped_noid = atomic64_read(&mxfs_relmark_publish_skip_noid);
}

/* ───────── untrusted-replay pass-1 table ───────── */

/*
 * Open-addressed, insert-only, linear probe — the same shape as the shadow
 * evaluator's manifest cache.  A slice of ~64 MB cannot hold more than a
 * few hundred thousand 64-byte markers; the table is capped so a corrupt log
 * cannot amplify memory, and everything past the cap is COUNTED (overflow):
 * a token whose marker did not fit simply cannot be certified clean and is
 * refused exactly as before this feature (fail closed).
 */
#define MXFS_RELMARK_TBL_BITS	16
#define MXFS_RELMARK_TBL_SLOTS	(1u << MXFS_RELMARK_TBL_BITS)	/* 64K x 40 B */
#define MXFS_RELMARK_TBL_FILL_CAP \
	(MXFS_RELMARK_TBL_SLOTS - MXFS_RELMARK_TBL_SLOTS / 4)

struct mxfs_relmark_ent {
	uint64_t	resource;
	uint64_t	lineage;
	uint64_t	grant_epoch;
	uint64_t	owner_epoch;
	uint32_t	owner_slot;
	uint16_t	auth_class;	/* 0 = empty slot */
	uint16_t	pad;
};

struct mxfs_relmark_tbl {
	struct mxfs_relmark_ent	*ent;
	uint32_t		n;
	uint32_t		overflow;
	uint32_t		dup;
	uint32_t		malformed;
};

static inline uint32_t
mxfs_relmark_hash(
	uint16_t		auth_class,
	uint64_t		resource,
	uint64_t		grant_epoch)
{
	return hash_64(resource ^ (grant_epoch * 0x9E3779B97F4A7C15ULL) ^
		       ((uint64_t)auth_class << 56), MXFS_RELMARK_TBL_BITS);
}

static struct mxfs_relmark_tbl *
mxfs_relmark_tbl_get(
	struct xlog		*log)
{
	struct mxfs_relmark_tbl	*t = log->l_mxfs_relmark_tbl;

	if (t)
		return t;
	t = kzalloc(sizeof(*t), GFP_NOFS);
	if (!t)
		return NULL;
	t->ent = kvzalloc(array_size(MXFS_RELMARK_TBL_SLOTS, sizeof(*t->ent)),
			  GFP_NOFS);
	if (!t->ent) {
		kfree(t);
		return NULL;
	}
	log->l_mxfs_relmark_tbl = t;
	return t;
}

void
mxfs_relmark_tbl_free(
	struct xlog		*log)
{
	struct mxfs_relmark_tbl	*t = log->l_mxfs_relmark_tbl;

	if (!t)
		return;
	log->l_mxfs_relmark_tbl = NULL;
	kvfree(t->ent);
	kfree(t);
}

uint32_t
mxfs_relmark_tbl_count(
	struct xlog		*log,
	uint32_t		*overflow)
{
	struct mxfs_relmark_tbl	*t = log->l_mxfs_relmark_tbl;

	if (overflow)
		*overflow = t ? t->overflow : 0;
	return t ? t->n : 0;
}

static int
mxfs_relmark_tbl_insert(
	struct xlog				*log,
	const struct mxfs_relmark_log_format	*f)
{
	struct mxfs_relmark_tbl	*t = mxfs_relmark_tbl_get(log);
	struct mxfs_relmark_ent	*e;
	uint16_t		cls = be16_to_cpu(f->mrl_class);
	uint64_t		res = be64_to_cpu(f->mrl_resource);
	uint64_t		gep = be64_to_cpu(f->mrl_grant_epoch);
	uint64_t		lin = be64_to_cpu(f->mrl_lineage);
	uint64_t		oep = be64_to_cpu(f->mrl_owner_epoch);
	uint32_t		osl = be32_to_cpu(f->mrl_owner_slot);
	uint32_t		h, probes;

	if (!t)
		return -ENOMEM;
	h = mxfs_relmark_hash(cls, res, gep);
	for (probes = 0; probes < MXFS_RELMARK_TBL_SLOTS; probes++) {
		e = &t->ent[h];
		if (!e->auth_class)
			break;
		if (e->auth_class == cls && e->resource == res &&
		    e->grant_epoch == gep && e->lineage == lin &&
		    e->owner_epoch == oep && e->owner_slot == osl) {
			t->dup++;	/* aborted-release re-emission: harmless */
			return 0;
		}
		h = (h + 1) & (MXFS_RELMARK_TBL_SLOTS - 1);
	}
	if (probes == MXFS_RELMARK_TBL_SLOTS || t->n >= MXFS_RELMARK_TBL_FILL_CAP) {
		t->overflow++;
		return 0;	/* counted; the token stays refusable */
	}
	e->auth_class = cls;
	e->resource = res;
	e->grant_epoch = gep;
	e->lineage = lin;
	e->owner_epoch = oep;
	e->owner_slot = osl;
	t->n++;
	return 0;
}

bool
mxfs_relmark_lookup(
	struct xlog		*log,
	uint16_t		auth_class,
	uint64_t		resource,
	uint64_t		lineage,
	uint64_t		grant_epoch,
	uint32_t		owner_slot,
	uint64_t		owner_epoch)
{
	struct mxfs_relmark_tbl	*t = log->l_mxfs_relmark_tbl;
	struct mxfs_relmark_ent	*e;
	uint32_t		h, probes;

	if (!t || !grant_epoch)
		return false;
	h = mxfs_relmark_hash(auth_class, resource, grant_epoch);
	for (probes = 0; probes < MXFS_RELMARK_TBL_SLOTS; probes++) {
		e = &t->ent[h];
		if (!e->auth_class)
			return false;
		/* COMPLETE identity — the ruling: never a marker from another
		 * incarnation on the same slot, never a lineage mismatch */
		if (e->auth_class == auth_class && e->resource == resource &&
		    e->grant_epoch == grant_epoch && e->lineage == lineage &&
		    e->owner_epoch == owner_epoch && e->owner_slot == owner_slot)
			return true;
		h = (h + 1) & (MXFS_RELMARK_TBL_SLOTS - 1);
	}
	return false;
}

/* ───────── recovery ops ───────── */

static int
mxfs_relmark_validate(
	struct xlog				*log,
	struct xlog_recover_item		*item,
	const struct mxfs_relmark_log_format	**out)
{
	const struct mxfs_relmark_log_format	*f;

	if (item->ri_buf[0].iov_len < sizeof(*f)) {
		xfs_warn(log->l_mp, "mxfs relmark: short item (%zu < %zu)",
			 item->ri_buf[0].iov_len, sizeof(*f));
		return -EFSCORRUPTED;
	}
	f = item->ri_buf[0].iov_base;
	if (f->mrl_type != XFS_LI_MXFS_RELMARK || f->mrl_size != 1) {
		xfs_warn(log->l_mp, "mxfs relmark: bad type/size 0x%x/%u",
			 f->mrl_type, f->mrl_size);
		return -EFSCORRUPTED;
	}
	if (be16_to_cpu(f->mrl_version) != MXFS_RELMARK_VERSION ||
	    f->mrl_reserved[0] || f->mrl_reserved[1] ||
	    be16_to_cpu(f->mrl_class) == 0 ||
	    be16_to_cpu(f->mrl_class) >= MXFS_AUTH_CLASS_MAX) {
		/*
		 * Unknown version / nonzero reserved / bad class: not a
		 * certificate we can read.  Not a recovery failure either —
		 * the item is inert — but it must never certify anything.
		 */
		*out = NULL;
		return 0;
	}
	*out = f;
	return 0;
}

/*
 * Pass 1: on an UNTRUSTED replay (foreign shadow xlog, adopted slice)
 * collect the marker.  Only committed transactions reach pass 1's
 * commit hook, so an uncommitted/torn marker can never be recorded.
 * Trusted (own-log) replay records nothing.
 */
STATIC int
xlog_recover_relmark_commit_pass1(
	struct xlog			*log,
	struct xlog_recover_item	*item)
{
	const struct mxfs_relmark_log_format *f;
	int				error;

	error = mxfs_relmark_validate(log, item, &f);
	if (error)
		return error;
	if (!f) {
		if (log->l_mxfs_victim_slot != MXFS_XLOG_VICTIM_NONE) {
			struct mxfs_relmark_tbl *t = mxfs_relmark_tbl_get(log);

			if (t)
				t->malformed++;
		}
		return 0;
	}
	if (log->l_mxfs_victim_slot == MXFS_XLOG_VICTIM_NONE)
		return 0;	/* trusted replay: inert */
	return mxfs_relmark_tbl_insert(log, f);
}

/* Pass 2: the marker is recovery metadata, never a filesystem update. */
STATIC int
xlog_recover_relmark_commit_pass2(
	struct xlog			*log,
	struct list_head		*buffer_list,
	struct xlog_recover_item	*item,
	xfs_lsn_t			lsn)
{
	const struct mxfs_relmark_log_format *f;

	return mxfs_relmark_validate(log, item, &f);
}

const struct xlog_recover_item_ops xlog_mxfs_relmark_item_ops = {
	.item_type		= XFS_LI_MXFS_RELMARK,
	.commit_pass1		= xlog_recover_relmark_commit_pass1,
	.commit_pass2		= xlog_recover_relmark_commit_pass2,
};
