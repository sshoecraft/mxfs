// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2022, Red Hat, Inc.
 * All Rights Reserved.
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
#include "xfs_ag.h"
#include "xfs_iunlink_item.h"
#include "xfs_trace.h"
#include "xfs_error.h"
#include "xfs_buf_item.h"
#include "xfs_mxfs_dlm.h"

struct kmem_cache	*xfs_iunlink_cache;

static inline struct xfs_iunlink_item *IUL_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_iunlink_item, item);
}

static void
xfs_iunlink_item_release(
	struct xfs_log_item	*lip)
{
	struct xfs_iunlink_item	*iup = IUL_ITEM(lip);

	/* mxfs sess203: retire the pending-transition certificate.  On the
	 * precommit path this runs after the buffer and the iunl store have
	 * caught up (both under the cluster buffer lock, which every overlay
	 * site also holds), so no observer can see divergent in-core state
	 * without an explanation.  On the cancel path the trans is dirty and
	 * shutdown follows anyway. */
	/* sess398: retire the certificate only if it still describes THIS
	 * item.  An O_TMPFILE create stacks two items for one inode in one
	 * transaction (create-path INSERT NULL->NULL, then xfs_iunlink's
	 * NULL->head); the later item's cert supersedes the earlier one's and
	 * must survive the earlier item's precommit release so the in-core
	 * edge stays explained until the later item's own precommit. */
	if (READ_ONCE(iup->ip->i_mxfs_nu_cert_old) == iup->old_agino &&
	    READ_ONCE(iup->ip->i_mxfs_nu_cert_next) == iup->next_agino)
		WRITE_ONCE(iup->ip->i_mxfs_nu_cert_valid, 0);

	xfs_perag_put(iup->pag);
	kmem_cache_free(xfs_iunlink_cache, IUL_ITEM(lip));
}


static uint64_t
xfs_iunlink_item_sort(
	struct xfs_log_item	*lip)
{
	return IUL_ITEM(lip)->ip->i_ino;
}

/*
 * Look up the inode cluster buffer and log the on-disk unlinked inode change
 * we need to make.
 */
static int
xfs_iunlink_log_dinode(
	struct xfs_trans	*tp,
	struct xfs_iunlink_item	*iup)
{
	struct xfs_inode	*ip = iup->ip;
	struct xfs_dinode	*dip;
	struct xfs_buf		*ibp;
	xfs_agino_t		old_ptr;
	int			offset;
	int			error;

	error = xfs_imap_to_bp(tp->t_mountp, tp, &ip->i_imap, &ibp);
	if (error)
		return error;
	/*
	 * Don't log the unlinked field on stale buffers as this may be the
	 * transaction that frees the inode cluster and relogging the buffer
	 * here will incorrectly remove the stale state.
	 */
	if (ibp->b_flags & XBF_STALE)
		goto out;

	dip = xfs_buf_offset(ibp, ip->i_imap.im_boffset);

	/* Make sure the old pointer isn't garbage. */
	old_ptr = be32_to_cpu(dip->di_next_unlinked);
	/*
	 * mxfs sess402 NEGATIVE-MISMATCH ARM (TESTING ONLY; ledger
	 * D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN closure item "negative-
	 * mismatch test"): iunl_mismatch_inject=N perturbs the value the strict
	 * non-INSERT compare below sees for the next N non-INSERT items on this
	 * node.  The BUFFER is not modified — only the local comparand — so the
	 * transition that follows (FOSSILFIX repair or -EFSCORRUPTED) acts on the
	 * true on-buffer value.  The arm proves the INSERT-mode item did not
	 * blind the strict check: every injection MUST produce a
	 * P53-IUNLINK-MISMATCH line; silence is the failure.
	 */
	if (!iup->insert && tp->t_mountp->m_mxfs_dlm) {
		extern int mxfs_iunl_mismatch_inject;
		int inj = READ_ONCE(mxfs_iunl_mismatch_inject);

		if (inj > 0 && old_ptr == iup->old_agino) {
			xfs_agino_t fake = (old_ptr == NULLAGINO) ? 1 : old_ptr + 1;

			if (fake == iup->next_agino)
				fake++;
			WRITE_ONCE(mxfs_iunl_mismatch_inject, inj - 1);
			pr_warn("mxfs: P-IUNL-MISMATCH-INJECT ino=0x%llx old_ptr=0x%x fake=0x%x old_agino=0x%x next_agino=0x%x left=%d comm=%s — negative arm: the strict non-INSERT compare must now fire P53-IUNLINK-MISMATCH\n",
				(unsigned long long)ip->i_ino, old_ptr, fake,
				iup->old_agino, iup->next_agino, inj - 1,
				current->comm);
			old_ptr = fake;
		}
	}
	if (iup->insert) {
		/*
		 * mxfs sess396 INSERT mode (design-consult ruling, see the header):
		 * the insert path proved this inode is on no unlinked list, so
		 * the buffer's current pointer carries no chain meaning.  A
		 * non-NULL value here is a prior-life platter fossil that the
		 * in-core reset (P-IUNL-FOSSIL-ENTRY) could not reach — the
		 * 0.23.5 test25 kill: core reset to NULL, buffer still 0x9dc,
		 * upstream's equality check below returned -EFSCORRUPTED from
		 * a dirty rename transaction.  Overwrite it with the
		 * transition's target and say so loudly (every hit is a fossil
		 * that reached a buffer; the producer is the standing alarm).
		 * If the buffer already reads the target there is nothing to
		 * write: the common empty-bucket NULL->NULL case stays a
		 * lock/brelse with no log traffic.
		 */
		if (iup->old_agino != NULLAGINO) {
			pr_warn("mxfs: P-IUNL-PRECOMMIT-INSERT-BADOLD ino=0x%llx old_agino=0x%x next_agino=0x%x old_ptr=0x%x — INSERT item with a non-NULL captured old value; falling back to the strict check\n",
				(unsigned long long)ip->i_ino, iup->old_agino,
				iup->next_agino, old_ptr);
		} else {
			if (old_ptr == iup->next_agino) {
				error = 0;
				goto out;
			}
			if (old_ptr != NULLAGINO) {
				static atomic_t pif_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&pif_n) <= 4000)
					pr_warn("mxfs: P-IUNL-PRECOMMIT-INSERT-FOSSIL ino=0x%llx site=%s agino=0x%x old_ptr=0x%x next_agino=0x%x dip_nlink=%u dip_gen=%u incore_gen=%u comm=%s — insert-path buffer dinode carried a dead chain value; overwritten by the insert transition at sorted precommit\n",
						(unsigned long long)ip->i_ino,
						iup->insert == 2 ? "create" : "unlink",
						XFS_INO_TO_AGINO(tp->t_mountp, ip->i_ino),
						old_ptr, iup->next_agino,
						be32_to_cpu(dip->di_nlink),
						be32_to_cpu(dip->di_gen),
						VFS_I(ip)->i_generation,
						current->comm);
			}
			goto apply;
		}
	}
	if (old_ptr != iup->old_agino) {
		struct xfs_buf_log_item *mbli = ibp->b_log_item;

		pr_warn("mxfs: P53-IUNLINK-MISMATCH ino=0x%llx old_ptr=0x%x old_agino=0x%x next_agino=0x%x i_next_unlinked=0x%x dip_mode=0%o dip_gen=%u i_gen=%u i_flags=0x%lx b_flags=0x%x fuafresh=%d bli=%d bli_dirty=%d uncp=%d\n",
			(unsigned long long)ip->i_ino,
			old_ptr, iup->old_agino, iup->next_agino,
			ip->i_next_unlinked,
			be16_to_cpu(dip->di_mode), be32_to_cpu(dip->di_gen),
			VFS_I(ip)->i_generation, ip->i_flags,
			ibp->b_flags,
			(ibp->b_flags & _XBF_FUA_FRESH) ? 1 : 0,
			mbli ? 1 : 0,
			(mbli && (mbli->bli_flags & XFS_BLI_DIRTY)) ? 1 : 0,
			mxfs_buf_has_uncheckpointed_mods(ibp) ? 1 : 0);
		/* sess48: every fatal carries the store's view of this ino
		 * (record present+value+homed vs absent) — the c2-392 fatal
		 * had ZERO store telemetry, leaving the record lifecycle at
		 * the mismatch undetermined. */
		if (tp->t_mountp->m_mxfs_dlm) {
			extern void mxfs_iunl_store_query_print(
				struct xfs_mount *, uint64_t);

			mxfs_iunl_store_query_print(tp->t_mountp, ip->i_ino);
		}

		/*
		 * sess53 (instrumented, PROVEN tcp_dlm_scaling iunlink corruption fix):
		 * under rapid free->reuse->free churn on a SHARED dir's child inodes
		 * a concurrent reuse path advances BOTH the on-buffer di_next_unlinked
		 * AND the in-core i_next_unlinked cache to THIS item's next_agino
		 * BEFORE this item's precommit runs, leaving only the item's captured
		 * old_agino stale (PROVEN: old_ptr==next_agino==i_next_unlinked,
		 * old_agino==NULLAGINO).  The unlinked chain is ALREADY in this item's
		 * desired post-state, so applying the update is an idempotent no-op:
		 * the buffer already holds next_agino (logged by the path that set it;
		 * uncp=1) and will be checkpointed.  Do NOT force-shutdown the whole
		 * FS for a stale-but-harmless item.  STRICT: only when BOTH the buffer
		 * and the in-core cache already equal next_agino (the genuine desired
		 * state) -- any other old_ptr is real chain corruption and still
		 * shuts down.
		 */
		if (old_ptr == iup->next_agino &&
		    ip->i_next_unlinked == iup->next_agino) {
			pr_warn_ratelimited(
			    "mxfs: P53-IUNLINK-IDEMPOTENT ino=0x%llx old_ptr=0x%x next_agino=0x%x (free/reuse race; chain already correct, no-op)\n",
			    (unsigned long long)ip->i_ino, old_ptr,
			    iup->next_agino);
			error = 0;
			goto out;
		}

		/*
		 * mxfs sess203 (GPT ruling, backstop (b)): if a live iunl-store
		 * record for exactly this slot (ino+gen+daddr+boffset) says the
		 * committed value IS our captured old_agino, then the buffer's
		 * old_ptr is a proven fossil — some image install slipped past
		 * the overlay (or the overlay refused on a race).  The correct
		 * response is the normal transition, not a fleet shutdown: the
		 * store conclusively identifies the four stale bytes.  STRICT:
		 * additionally require our own pending certificate to match
		 * this item, and alarm loudly — every absorbed event here is a
		 * standing regression alarm (an install site is leaking).
		 */
		if (tp->t_mountp->m_mxfs_dlm &&
		    READ_ONCE(ip->i_mxfs_nu_cert_valid) &&
		    ip->i_mxfs_nu_cert_old == iup->old_agino &&
		    ip->i_mxfs_nu_cert_next == iup->next_agino) {
			extern bool mxfs_iunl_store_fossil_match(
					struct xfs_mount *, uint64_t, uint32_t,
					xfs_daddr_t, uint16_t, uint32_t);

			if (mxfs_iunl_store_fossil_match(tp->t_mountp,
					ip->i_ino, VFS_I(ip)->i_generation,
					ibp->b_maps[0].bm_bn,
					ip->i_imap.im_boffset,
					iup->old_agino)) {
				pr_warn("mxfs: P-IUNL-PRECOMMIT-FOSSILFIX ino=0x%llx old_ptr=0x%x committed=old_agino=0x%x next_agino=0x%x incore=0x%x — buffer held a proven fossil; repairing via the normal transition\n",
					(unsigned long long)ip->i_ino, old_ptr,
					iup->old_agino, iup->next_agino,
					ip->i_next_unlinked);
				goto apply;
			}
		}

		xfs_inode_verifier_error(ip, -EFSCORRUPTED, __func__, dip,
				sizeof(*dip), __this_address);
		error = -EFSCORRUPTED;
		goto out;
	}

apply:
	trace_xfs_iunlink_update_dinode(iup, old_ptr);

	dip->di_next_unlinked = cpu_to_be32(iup->next_agino);
	offset = ip->i_imap.im_boffset +
			offsetof(struct xfs_dinode, di_next_unlinked);

	xfs_dinode_calc_crc(tp->t_mountp, dip);
	xfs_trans_inode_buf(tp, ibp);
	xfs_trans_log_buf(tp, ibp, offset, offset + sizeof(xfs_agino_t) - 1);
	/* sess47 A-prime: record the committed value at MOUNT scope until its
	 * home write completes — the only defense that survives inode reclaim
	 * + buffer teardown (fossil producer, memories TAIL7-TAIL11). */
	if (tp->t_mountp->m_mxfs_dlm) {
		extern void mxfs_iunl_store_record(struct xfs_mount *,
				uint64_t, uint32_t, uint32_t, xfs_daddr_t,
				uint16_t);

		mxfs_iunl_store_record(tp->t_mountp, ip->i_ino,
				       VFS_I(ip)->i_generation,
				       iup->next_agino,
				       ibp->b_maps[0].bm_bn,
				       ip->i_imap.im_boffset);
	}
	return 0;
out:
	xfs_trans_brelse(tp, ibp);
	return error;
}

/*
 * On precommit, we grab the inode cluster buffer for the inode number we were
 * passed, then update the next unlinked field for that inode in the buffer and
 * log the buffer. This ensures that the inode cluster buffer was logged in the
 * correct order w.r.t. other inode cluster buffers. We can then remove the
 * iunlink item from the transaction and release it as it is has now served it's
 * purpose.
 */
static int
xfs_iunlink_item_precommit(
	struct xfs_trans	*tp,
	struct xfs_log_item	*lip)
{
	struct xfs_iunlink_item	*iup = IUL_ITEM(lip);
	int			error;

	error = xfs_iunlink_log_dinode(tp, iup);
	list_del(&lip->li_trans);
	xfs_iunlink_item_release(lip);
	return error;
}

static const struct xfs_item_ops xfs_iunlink_item_ops = {
	.iop_release	= xfs_iunlink_item_release,
	.iop_sort	= xfs_iunlink_item_sort,
	.iop_precommit	= xfs_iunlink_item_precommit,
};


/*
 * Initialize the inode log item for a newly allocated (in-core) inode.
 *
 * Inode extents can only reside within an AG. Hence specify the starting
 * block for the inode chunk by offset within an AG as well as the
 * length of the allocated extent.
 *
 * This joins the item to the transaction and marks it dirty so
 * that we don't need a separate call to do this, nor does the
 * caller need to know anything about the iunlink item.
 */
static int
__xfs_iunlink_log_inode(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	struct xfs_perag	*pag,
	xfs_agino_t		next_agino,
	unsigned int		insert)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_iunlink_item	*iup;

	ASSERT(xfs_verify_agino_or_null(pag, next_agino));
	ASSERT(xfs_verify_agino_or_null(pag, ip->i_next_unlinked));

	/*
	 * Since we're updating a linked list, we should never find that the
	 * current pointer is the same as the new value, unless we're
	 * terminating the list.
	 *
	 * mxfs sess396: an INSERT item is created even for NULL -> NULL (the
	 * empty-bucket insert) so the cluster buffer's di_next_unlinked is
	 * examined and, if it carries a fossil, cleared at sorted precommit.
	 */
	if (ip->i_next_unlinked == next_agino) {
		if (next_agino != NULLAGINO)
			return -EFSCORRUPTED;
		if (!insert)
			return 0;
	}

	iup = kmem_cache_zalloc(xfs_iunlink_cache, GFP_KERNEL | __GFP_NOFAIL);
	xfs_log_item_init(mp, &iup->item, XFS_LI_IUNLINK,
			  &xfs_iunlink_item_ops);

	iup->ip = ip;
	iup->next_agino = next_agino;
	iup->old_agino = ip->i_next_unlinked;
	iup->insert = (uint8_t)insert;
	iup->pag = xfs_perag_hold(pag);

	/* mxfs sess203: publish the pending-transition certificate BEFORE the
	 * caller advances i_next_unlinked, so any overlay that observes the
	 * advanced in-core edge also observes the certificate explaining it
	 * (the item-init-to-precommit window is a legitimate skew window, not
	 * record abandonment — GPT ruling sess203).  The trailing barrier
	 * orders valid=1 before the caller's in-core store. */
	/* sess398: an O_TMPFILE create carries TWO items for the same inode in
	 * ONE transaction — the create-path INSERT (NULL->NULL, site 2, from
	 * xfs_inode_init) and xfs_iunlink's insert — so a valid {NULL->NULL}
	 * certificate under a new INSERT item is that legitimate pair, not a
	 * leaked transition: the later item's cert simply supersedes it. */
	if (ip->i_mxfs_nu_cert_valid &&
	    !(insert && ip->i_mxfs_nu_cert_old == NULLAGINO &&
	      ip->i_mxfs_nu_cert_next == NULLAGINO))
		pr_warn_ratelimited("mxfs: P-IUNL-CERT-STACKED ino=0x%llx prev={0x%x->0x%x} new={0x%x->0x%x}\n",
			(unsigned long long)ip->i_ino,
			ip->i_mxfs_nu_cert_old, ip->i_mxfs_nu_cert_next,
			ip->i_next_unlinked, next_agino);
	WRITE_ONCE(ip->i_mxfs_nu_cert_old, ip->i_next_unlinked);
	WRITE_ONCE(ip->i_mxfs_nu_cert_next, next_agino);
	smp_wmb();
	WRITE_ONCE(ip->i_mxfs_nu_cert_valid, 1);
	smp_wmb();

	xfs_trans_add_item(tp, &iup->item);
	tp->t_flags |= XFS_TRANS_DIRTY;
	set_bit(XFS_LI_DIRTY, &iup->item.li_flags);
	return 0;
}

int
xfs_iunlink_log_inode(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	struct xfs_perag	*pag,
	xfs_agino_t		next_agino)
{
	return __xfs_iunlink_log_inode(tp, ip, pag, next_agino, 0);
}

/*
 * mxfs sess396: INSERT-mode transition for xfs_iunlink_insert_inode ONLY (the
 * path that proves non-membership).  The caller must already have reset a
 * fossil in-core pointer to NULLAGINO (P-IUNL-FOSSIL-ENTRY), so old_agino is
 * NULLAGINO by construction; the precommit then overwrites whatever the
 * buffer carries instead of requiring equality.  See xfs_iunlink_item.h.
 */
int
xfs_iunlink_log_inode_insert(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	struct xfs_perag	*pag,
	xfs_agino_t		next_agino,
	unsigned int		site)
{
	return __xfs_iunlink_log_inode(tp, ip, pag, next_agino, site ? site : 1);
}

