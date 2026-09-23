// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS intent/done census for untrusted slice replay — see
 * xfs_mxfs_icensus.h for the contract and docs/dlm-protocol.md
 * ("Intent/done census: fail-before-purge on undischarged obligations").
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
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_log_recover.h"
#include "xfs_error.h"
#include "xfs_mxfs_icensus.h"
#include "../dlm/recov_obl.h"	/* sess462: obligation list entries */

/* An open table larger than this is not a slice any node could have
 * written between two checkpoints; stop tracking and fail closed. */
#define MXFS_ICENSUS_MAX_OPEN	65536u
/* sess461: total extents retained across every open EFI; beyond it the
 * census overflows (fail closed) exactly like the open-table bound. */
#define MXFS_ICENSUS_MAX_EXTENTS 65536u
/* Per-item notices are bounded per log; the counters are not. */
#define MXFS_ICENSUS_NOTICES	200u

struct mxfs_icensus_ent {
	struct list_head	list;
	uint64_t		id;
	uint64_t		ag_mask;
	uint64_t		lsn;
	uint16_t		type;
	/* sess461: whole-transaction verdicts (MXFS_TXNV_*) of the intent's
	 * transaction and, when a done was seen in a NON-admitted
	 * transaction, of that done's transaction (ambiguous: kept open). */
	uint8_t			verdict;
	uint8_t			done_verdict;
	uint8_t			cls;		/* MXFS_ICENSUS_CLS_* */
	bool			fswide;
	bool			malformed;
	bool			ambiguous_done;
	bool			duplicate;	/* a second intent carried this id */
	/* sess461: the EFI's extents (copied out of the log item) so the
	 * completion increments can act on them; NULL for non-EFI classes. */
	uint32_t		nextents;
	struct xfs_extent	*extents;
};

struct mxfs_icensus {
	struct list_head	open;
	uint32_t		nopen;
	uint32_t		nextents;	/* retained extents, all entries */
	uint32_t		intents;
	uint32_t		dones;
	uint32_t		unmatched_dones;
	uint32_t		ambiguous_dones;
	uint32_t		malformed;
	uint32_t		overflow;
	uint32_t		notices;
	uint32_t		recover;
	uint32_t		quarantine;
	uint64_t		recover_mask;
	uint64_t		q_mask;
	bool			q_fswide;
	bool			reported;
	bool			classified;
};

static struct mxfs_icensus *
mxfs_icensus_get(
	struct xlog		*log)
{
	struct mxfs_icensus	*c = log->l_mxfs_icensus;

	if (c)
		return c;
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		/* fail closed: the replay's terminal predicate treats a lost
		 * census as an undischarged FSWIDE obligation */
		log->l_mxfs_icensus_lost = true;
		return NULL;
	}
	INIT_LIST_HEAD(&c->open);
	log->l_mxfs_icensus = c;
	return c;
}

static bool
mxfs_icensus_is_intent(
	unsigned short		t)
{
	switch (t) {
	case XFS_LI_EFI:
	case XFS_LI_RUI:
	case XFS_LI_CUI:
	case XFS_LI_BUI:
	case XFS_LI_ATTRI:
	case XFS_LI_XMI:
	case XFS_LI_EFI_RT:
	case XFS_LI_RUI_RT:
	case XFS_LI_CUI_RT:
		return true;
	default:
		return false;
	}
}

static bool
mxfs_icensus_is_done(
	unsigned short		t)
{
	switch (t) {
	case XFS_LI_EFD:
	case XFS_LI_RUD:
	case XFS_LI_CUD:
	case XFS_LI_BUD:
	case XFS_LI_ATTRD:
	case XFS_LI_XMD:
	case XFS_LI_EFD_RT:
	case XFS_LI_RUD_RT:
	case XFS_LI_CUD_RT:
		return true;
	default:
		return false;
	}
}

/*
 * sess461: did the enclosing transaction's images APPLY?  Only these three
 * verdicts mean the whole transaction was honoured; SKIP/SBCLEAN/PREINC
 * (and UNSET on a trusted replay, which never reaches the census) are not
 * admission.  Ruling SS7: nothing else may be read as executable.
 */
static bool
mxfs_icensus_admitted(
	uint8_t			verdict)
{
	return verdict == MXFS_TXNV_ADMIT ||
	       verdict == MXFS_TXNV_UNTAINTED ||
	       verdict == MXFS_TXNV_SNLOCAL;
}

/*
 * Every intent AND done format in xfs_log_format.h lays out
 * {u16 type, u16 size, u32 nextents|igen|pad, u64 id}: the id sits at byte
 * offset 8 in the 32-bit-packed and the 64-bit variants alike.
 */
#define MXFS_ICENSUS_ID_OFF	8
#define MXFS_ICENSUS_ID_END	16

static bool
mxfs_icensus_item_id(
	struct xlog_recover_item *item,
	uint64_t		*id)
{
	if (item->ri_buf[0].iov_len < MXFS_ICENSUS_ID_END)
		return false;
	memcpy(id, (char *)item->ri_buf[0].iov_base + MXFS_ICENSUS_ID_OFF,
	       sizeof(*id));
	return true;
}

static void
mxfs_icensus_ent_agno(
	struct xfs_mount	*mp,
	struct mxfs_icensus_ent	*e,
	xfs_agnumber_t		agno)
{
	if (agno >= mp->m_sb.sb_agcount || agno >= 64) {
		e->fswide = true;
		return;
	}
	e->ag_mask |= 1ULL << agno;
}

static void
mxfs_icensus_ent_fsb(
	struct xfs_mount	*mp,
	struct mxfs_icensus_ent	*e,
	uint64_t		fsbno)
{
	mxfs_icensus_ent_agno(mp, e, XFS_FSB_TO_AGNO(mp, fsbno));
}

static void
mxfs_icensus_ent_ino(
	struct xfs_mount	*mp,
	struct mxfs_icensus_ent	*e,
	uint64_t		ino)
{
	mxfs_icensus_ent_agno(mp, e, XFS_INO_TO_AGNO(mp, ino));
}

/*
 * sess461: copy an EFI's extents out of the log item.  The three on-disk
 * layouts (native, 32-bit packed, 64-bit padded) differ only in the extent
 * record stride; every extent is validated (xfs_verify_fsbext: non-zero
 * length, inside the filesystem, not crossing an AG) — a bad one marks the
 * entry malformed, and malformed is QUARANTINE.  Retained-extent total is
 * bounded; beyond the bound the census overflows (fail closed).
 */
static void
mxfs_icensus_ent_efi_extents(
	struct xfs_mount	*mp,
	struct mxfs_icensus	*c,
	struct mxfs_icensus_ent	*e,
	uint32_t		n,
	const void		*rec,
	size_t			stride)
{
	uint32_t		i;

	if (n == 0 || c->nextents + n > MXFS_ICENSUS_MAX_EXTENTS) {
		if (n)
			c->overflow++;
		e->fswide = true;
		return;
	}
	e->extents = kcalloc(n, sizeof(*e->extents), GFP_KERNEL);
	if (!e->extents) {
		e->fswide = true;
		return;
	}
	for (i = 0; i < n; i++) {
		const struct xfs_extent *x = rec + i * stride;

		/* the packed 32-bit layout is unaligned; copy field-wise */
		memcpy(&e->extents[i].ext_start, &x->ext_start,
		       sizeof(e->extents[i].ext_start));
		memcpy(&e->extents[i].ext_len, &x->ext_len,
		       sizeof(e->extents[i].ext_len));
		if (!xfs_verify_fsbext(mp, e->extents[i].ext_start,
				       e->extents[i].ext_len)) {
			c->malformed++;
			e->malformed = true;
			e->fswide = true;
		} else {
			mxfs_icensus_ent_fsb(mp, e, e->extents[i].ext_start);
		}
	}
	e->nextents = n;
	c->nextents += n;
}

/*
 * Map an intent's extents/inodes to the AG set it would modify.  Anything
 * that cannot be mapped confidently (size mismatch, realtime, agno beyond
 * the mask) widens the entry to FSWIDE: refusing too much is safe.
 */
static void
mxfs_icensus_ent_domain(
	struct xlog		*log,
	struct mxfs_icensus	*c,
	struct mxfs_icensus_ent	*e,
	struct xlog_recover_item *item)
{
	struct xfs_mount	*mp = log->l_mp;
	void			*base = item->ri_buf[0].iov_base;
	size_t			len = item->ri_buf[0].iov_len;
	uint32_t		n, i;

	switch (e->type) {
	case XFS_LI_EFI: {
		struct xfs_efi_log_format *f = base;

		n = f->efi_nextents;
		if (len == xfs_efi_log_format_sizeof(n)) {
			mxfs_icensus_ent_efi_extents(mp, c, e, n,
					f->efi_extents,
					sizeof(f->efi_extents[0]));
		} else if (len == xfs_efi_log_format32_sizeof(n)) {
			struct xfs_efi_log_format_32 *f32 = base;

			mxfs_icensus_ent_efi_extents(mp, c, e, n,
					f32->efi_extents,
					sizeof(f32->efi_extents[0]));
		} else if (len == xfs_efi_log_format64_sizeof(n)) {
			struct xfs_efi_log_format_64 *f64 = base;

			mxfs_icensus_ent_efi_extents(mp, c, e, n,
					f64->efi_extents,
					sizeof(f64->efi_extents[0]));
		} else {
			goto malformed;
		}
		if (n == 0)
			e->fswide = true;
		return;
	}
	case XFS_LI_RUI: {
		struct xfs_rui_log_format *f = base;

		n = f->rui_nextents;
		if (len != xfs_rui_log_format_sizeof(n))
			goto malformed;
		for (i = 0; i < n; i++)
			mxfs_icensus_ent_fsb(mp, e,
					     f->rui_extents[i].me_startblock);
		if (n == 0)
			e->fswide = true;
		return;
	}
	case XFS_LI_BUI: {
		struct xfs_bui_log_format *f = base;

		n = f->bui_nextents;
		if (len != xfs_bui_log_format_sizeof(n))
			goto malformed;
		for (i = 0; i < n; i++) {
			if (f->bui_extents[i].me_flags & XFS_BMAP_EXTENT_REALTIME)
				e->fswide = true;
			else
				mxfs_icensus_ent_fsb(mp, e,
					     f->bui_extents[i].me_startblock);
			/* the mapped inode's AG changes too */
			mxfs_icensus_ent_ino(mp, e, f->bui_extents[i].me_owner);
		}
		if (n == 0)
			e->fswide = true;
		return;
	}
	case XFS_LI_CUI: {
		struct xfs_cui_log_format *f = base;

		n = f->cui_nextents;
		if (len != xfs_cui_log_format_sizeof(n))
			goto malformed;
		for (i = 0; i < n; i++)
			mxfs_icensus_ent_fsb(mp, e,
					     f->cui_extents[i].pe_startblock);
		if (n == 0)
			e->fswide = true;
		return;
	}
	case XFS_LI_ATTRI: {
		struct xfs_attri_log_format *f = base;

		if (len < sizeof(*f))
			goto malformed;
		mxfs_icensus_ent_ino(mp, e, f->alfi_ino);
		return;
	}
	case XFS_LI_XMI: {
		struct xfs_xmi_log_format *f = base;

		if (len != sizeof(*f))
			goto malformed;
		mxfs_icensus_ent_ino(mp, e, f->xmi_inode1);
		mxfs_icensus_ent_ino(mp, e, f->xmi_inode2);
		return;
	}
	default:
		/* realtime intents: no AG home */
		e->fswide = true;
		return;
	}
malformed:
	c->malformed++;
	e->malformed = true;
	e->fswide = true;
}

static void
mxfs_icensus_ent_free(
	struct mxfs_icensus_ent	*e)
{
	kfree(e->extents);
	kfree(e);
}

void
mxfs_icensus_note(
	struct xlog		*log,
	struct xlog_recover_item *item,
	uint64_t		lsn,
	uint8_t			verdict)
{
	struct mxfs_icensus	*c;
	struct mxfs_icensus_ent	*e, *tmp;
	unsigned short		t = ITEM_TYPE(item);
	uint64_t		id = 0;
	bool			has_id;
	const char		*src = xlog_is_mxfs_foreign_replay(log) ?
					"foreign" : "adopted";

	c = mxfs_icensus_get(log);
	if (!c)
		return;
	has_id = mxfs_icensus_item_id(item, &id);

	if (mxfs_icensus_is_done(t)) {
		c->dones++;
		if (!has_id) {
			/* a done we cannot pair: the intent it retires stays
			 * open (fail closed) and the domain widens */
			c->malformed++;
			xfs_warn(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-MALFORMED done type 0x%x len=%zu lsn=0x%llx — cannot pair, its intent stays open",
				 src, t, item->ri_buf[0].iov_len,
				 (unsigned long long)lsn);
			return;
		}
		list_for_each_entry_safe(e, tmp, &c->open, list) {
			if (e->id != id || e->malformed)
				continue;
			/*
			 * sess461 (ruling SS7): a done inside a transaction
			 * whose images did NOT apply is AMBIGUOUS — honouring
			 * it could suppress required work whose metadata never
			 * reached home; ignoring it could double-free.  Keep
			 * the intent open, tagged; classification quarantines
			 * it.  Only an admitted done retires the obligation.
			 */
			if (!mxfs_icensus_admitted(verdict)) {
				e->ambiguous_done = true;
				e->done_verdict = verdict;
				c->ambiguous_dones++;
				if (c->notices < MXFS_ICENSUS_NOTICES) {
					c->notices++;
					xfs_warn(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-DONE-AMBIGUOUS type 0x%x id=0x%llx lsn=0x%llx done_txn_verdict=%u — the done rides in a transaction that did not apply; its intent (type 0x%x verdict=%u) stays open as QUARANTINE",
						 src, t, (unsigned long long)id,
						 (unsigned long long)lsn,
						 verdict, e->type, e->verdict);
				}
				return;
			}
			list_del(&e->list);
			c->nopen--;
			c->nextents -= e->nextents;
			if (c->notices < MXFS_ICENSUS_NOTICES) {
				c->notices++;
				xfs_notice(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-DONE type 0x%x id=0x%llx retires intent type 0x%x lsn=0x%llx (open=%u)",
					   src, t, (unsigned long long)id,
					   e->type, (unsigned long long)lsn,
					   c->nopen);
			}
			mxfs_icensus_ent_free(e);
			return;
		}
		/* intent before the tail — not an obligation of this slice */
		c->unmatched_dones++;
		return;
	}
	if (!mxfs_icensus_is_intent(t))
		return;

	c->intents++;
	if (c->nopen >= MXFS_ICENSUS_MAX_OPEN) {
		c->overflow++;
		return;
	}
	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		log->l_mxfs_icensus_lost = true;
		return;
	}
	INIT_LIST_HEAD(&e->list);
	e->type = t;
	e->lsn = lsn;
	e->verdict = verdict;
	if (!has_id) {
		c->malformed++;
		e->malformed = true;
		e->fswide = true;
	} else {
		e->id = id;
		/*
		 * A relogged id we already hold is the same obligation.  The
		 * relog of an EFI carries the SAME extents (xfs_efi_relog
		 * copies them); a second intent under one id whose txn verdict
		 * differs, or whose extents differ, is not a relog we can
		 * trust — mark the held entry duplicate (QUARANTINE).
		 */
		list_for_each_entry(tmp, &c->open, list) {
			if (tmp->id == id && !tmp->malformed) {
				if (tmp->verdict != verdict)
					tmp->duplicate = true;
				kfree(e);
				return;
			}
		}
		mxfs_icensus_ent_domain(log, c, e, item);
	}
	list_add_tail(&e->list, &c->open);
	c->nopen++;
	if (c->notices < MXFS_ICENSUS_NOTICES) {
		c->notices++;
		xfs_notice(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-INTENT type 0x%x id=0x%llx lsn=0x%llx verdict=%u nextents=%u ag_mask=0x%llx fswide=%d malformed=%d (open=%u) — not applied, tracked",
			   src, t, (unsigned long long)e->id,
			   (unsigned long long)lsn, verdict, e->nextents,
			   (unsigned long long)e->ag_mask, (int)e->fswide,
			   (int)e->malformed, c->nopen);
	}
}

/* sess461: do two fs-block ranges intersect? */
static bool
mxfs_icensus_ext_overlap(
	const struct xfs_extent	*a,
	const struct xfs_extent	*b)
{
	return a->ext_start < b->ext_start + b->ext_len &&
	       b->ext_start < a->ext_start + a->ext_len;
}

/*
 * sess461: the classification pass.  Runs once; the result is cached on
 * the census.  Ruling SS7 matrix plus the overlap rule: any two RECOVER
 * candidates (within one EFI or across EFIs) that overlap are BOTH
 * quarantined — an exact duplicate extent is malformed source evidence,
 * never "already done".
 */
static void
mxfs_icensus_do_classify(
	struct xlog		*log,
	struct mxfs_icensus	*c)
{
	struct mxfs_icensus_ent	*e, *o;
	uint32_t		i, j;

	c->recover = 0;
	c->quarantine = 0;
	c->recover_mask = 0;
	c->q_mask = 0;
	c->q_fswide = false;

	list_for_each_entry(e, &c->open, list) {
		e->cls = MXFS_ICENSUS_CLS_RECOVER;
		if (e->type != XFS_LI_EFI || e->malformed || e->fswide ||
		    e->duplicate || e->ambiguous_done || !e->extents ||
		    e->nextents == 0 || !mxfs_icensus_admitted(e->verdict))
			e->cls = MXFS_ICENSUS_CLS_QUARANTINE;
	}
	/* overlap sweep among the remaining RECOVER candidates */
	list_for_each_entry(e, &c->open, list) {
		if (e->cls != MXFS_ICENSUS_CLS_RECOVER)
			continue;
		for (i = 0; i < e->nextents; i++) {
			for (j = i + 1; j < e->nextents; j++) {
				if (mxfs_icensus_ext_overlap(&e->extents[i],
							     &e->extents[j]))
					e->cls = MXFS_ICENSUS_CLS_QUARANTINE;
			}
			list_for_each_entry(o, &c->open, list) {
				if (o == e || o->cls != MXFS_ICENSUS_CLS_RECOVER)
					continue;
				for (j = 0; j < o->nextents; j++) {
					if (mxfs_icensus_ext_overlap(
							&e->extents[i],
							&o->extents[j])) {
						e->cls = MXFS_ICENSUS_CLS_QUARANTINE;
						o->cls = MXFS_ICENSUS_CLS_QUARANTINE;
					}
				}
			}
		}
	}
	list_for_each_entry(e, &c->open, list) {
		if (e->cls == MXFS_ICENSUS_CLS_RECOVER) {
			c->recover++;
			c->recover_mask |= e->ag_mask;
		} else {
			c->quarantine++;
			c->q_mask |= e->ag_mask;
			c->q_fswide |= e->fswide;
		}
	}
	if (c->overflow) {
		c->quarantine++;
		c->q_fswide = true;
	}
	c->classified = true;
}

void
mxfs_icensus_classify(
	struct xlog		*log,
	const char		*src,
	uint32_t		*recover,
	uint64_t		*recover_mask,
	uint32_t		*quarantine,
	uint64_t		*q_mask,
	bool			*q_fswide)
{
	struct mxfs_icensus	*c = log->l_mxfs_icensus;
	struct mxfs_icensus_ent	*e;
	uint32_t		rec = 0, q = 0, shown = 0;
	uint64_t		rmask = 0, qmask = 0;
	bool			qfsw = false;

	if (c) {
		if (!c->classified) {
			mxfs_icensus_do_classify(log, c);
			list_for_each_entry(e, &c->open, list) {
				if (shown++ >= 16)
					break;
				xfs_warn(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-CLASS type 0x%x id=0x%llx lsn=0x%llx class=%s verdict=%u done_verdict=%u nextents=%u ext0=%llu+%u ag_mask=0x%llx fswide=%d malformed=%d duplicate=%d ambiguous_done=%d",
					 src, e->type, (unsigned long long)e->id,
					 (unsigned long long)e->lsn,
					 e->cls == MXFS_ICENSUS_CLS_RECOVER ?
						"RECOVER" : "QUARANTINE",
					 e->verdict, e->done_verdict, e->nextents,
					 e->extents ? (unsigned long long)
						e->extents[0].ext_start : 0ULL,
					 e->extents ? e->extents[0].ext_len : 0,
					 (unsigned long long)e->ag_mask,
					 (int)e->fswide, (int)e->malformed,
					 (int)e->duplicate,
					 (int)e->ambiguous_done);
			}
			xfs_notice(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-SPLIT victim_slot=%u open=%u recover=%u recover_mask=0x%llx quarantine=%u q_mask=0x%llx q_fswide=%d ambiguous_dones=%u overflow=%u lost=%d",
				   src, log->l_mxfs_victim_slot, c->nopen,
				   c->recover, (unsigned long long)c->recover_mask,
				   c->quarantine, (unsigned long long)c->q_mask,
				   (int)c->q_fswide, c->ambiguous_dones,
				   c->overflow, (int)log->l_mxfs_icensus_lost);
		}
		rec = c->recover;
		rmask = c->recover_mask;
		q = c->quarantine;
		qmask = c->q_mask;
		qfsw = c->q_fswide;
	}
	if (log->l_mxfs_icensus_lost) {
		q += 1;
		qfsw = true;
	}
	if (recover)
		*recover = rec;
	if (recover_mask)
		*recover_mask = rmask;
	if (quarantine)
		*quarantine = q;
	if (q_mask)
		*q_mask = qmask;
	if (q_fswide)
		*q_fswide = qfsw;
}

uint32_t
mxfs_icensus_undischarged(
	struct xlog		*log,
	const char		*src,
	uint64_t		*ag_mask,
	bool			*fswide,
	uint32_t		*malformed)
{
	struct mxfs_icensus	*c = log->l_mxfs_icensus;
	struct mxfs_icensus_ent	*e;
	uint64_t		mask = 0;
	bool			fsw = false;
	uint32_t		n = 0;

	if (c) {
		list_for_each_entry(e, &c->open, list) {
			mask |= e->ag_mask;
			fsw |= e->fswide;
		}
		n = c->nopen + c->overflow;
		if (c->overflow)
			fsw = true;
	}
	if (log->l_mxfs_icensus_lost) {
		n += 1;
		fsw = true;
	}
	if (ag_mask)
		*ag_mask = mask;
	if (fswide)
		*fswide = fsw;
	if (malformed)
		*malformed = c ? c->malformed : 0;

	if (!c || !c->reported) {
		if (c)
			c->reported = true;
		xfs_notice(log->l_mp,
	"MXFS %s replay: P226-ICENSUS victim_slot=%u intents=%u dones=%u unmatched_dones=%u ambiguous_dones=%u open=%u extents=%u malformed=%u overflow=%u lost=%d fswide=%d ag_mask=0x%llx",
			   src, log->l_mxfs_victim_slot,
			   c ? c->intents : 0, c ? c->dones : 0,
			   c ? c->unmatched_dones : 0,
			   c ? c->ambiguous_dones : 0, c ? c->nopen : 0,
			   c ? c->nextents : 0,
			   c ? c->malformed : 0, c ? c->overflow : 0,
			   (int)log->l_mxfs_icensus_lost, (int)fsw,
			   (unsigned long long)mask);
		if (c && c->nopen) {
			uint32_t shown = 0;

			list_for_each_entry(e, &c->open, list) {
				if (shown++ >= 16)
					break;
				xfs_warn(log->l_mp,
	"MXFS %s replay: P226-ICENSUS-OPEN type 0x%x id=0x%llx lsn=0x%llx verdict=%u nextents=%u ag_mask=0x%llx fswide=%d malformed=%d — obligation undischarged in the slice",
					 src, e->type, (unsigned long long)e->id,
					 (unsigned long long)e->lsn, e->verdict,
					 e->nextents,
					 (unsigned long long)e->ag_mask,
					 (int)e->fswide, (int)e->malformed);
			}
		}
	}
	return n;
}

int
mxfs_icensus_export_recover(
	struct xlog		*log,
	struct mxfs_recov_obl_ext **ext,
	uint32_t		*n)
{
	struct mxfs_icensus	*c = log->l_mxfs_icensus;
	struct mxfs_icensus_ent	*e;
	struct mxfs_recov_obl_ext *out;
	uint64_t		total = 0;
	uint32_t		k = 0, i;

	*ext = NULL;
	*n = 0;
	if (!c)
		return 0;
	if (!c->classified)
		mxfs_icensus_do_classify(log, c);
	list_for_each_entry(e, &c->open, list)
		if (e->cls == MXFS_ICENSUS_CLS_RECOVER)
			total += e->nextents;
	if (total == 0)
		return 0;
	if (total > MXFS_RECOV_OBL_MAX_EXTENTS)
		return -EOVERFLOW;
	out = kvmalloc_array(total, sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;
	list_for_each_entry(e, &c->open, list) {
		if (e->cls != MXFS_ICENSUS_CLS_RECOVER)
			continue;
		for (i = 0; i < e->nextents; i++) {
			out[k].fsbno = e->extents[i].ext_start;
			out[k].agno  = XFS_FSB_TO_AGNO(log->l_mp,
						       e->extents[i].ext_start);
			out[k].len   = e->extents[i].ext_len;
			k++;
		}
	}
	*ext = out;
	*n = k;
	return 0;
}

void
mxfs_icensus_free(
	struct xlog		*log)
{
	struct mxfs_icensus	*c = log->l_mxfs_icensus;
	struct mxfs_icensus_ent	*e, *tmp;

	if (!c)
		return;
	list_for_each_entry_safe(e, tmp, &c->open, list) {
		list_del(&e->list);
		mxfs_icensus_ent_free(e);
	}
	kfree(c);
	log->l_mxfs_icensus = NULL;
}
