// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- unlinked-inode store and publication obligations
 */
#define MXFS_TU_ID 24	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

void mxfs_iunl_store_record(struct xfs_mount *mp, uint64_t ino, uint32_t gen,
			    uint32_t next_agino, xfs_daddr_t daddr,
			    uint16_t boffset)
{
	struct mxfs_iunl_rec *r, *n;

	n = kzalloc(sizeof(*n), GFP_NOFS);
	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry(r, &mp->m_mxfs_iunl_list, l) {
		if (r->ino == ino) {
			r->gen = gen;
			r->next_agino = next_agino;
			r->daddr = daddr;
			r->boffset = boffset;
			r->agno = xfs_daddr_to_agno(mp, daddr);
			r->wr_epoch = 0;	/* new write pending again */
			spin_unlock(&mp->m_mxfs_iunl_lock);
			kfree(n);
			return;
		}
	}
	if (!n) {
		/* Lost record = the pre-A-prime exposure for this one write;
		 * loud so an allocation-pressure gap is visible. */
		spin_unlock(&mp->m_mxfs_iunl_lock);
		mxfs_probe("mxfs: P-IUNLSTORE-ENOMEM ino=%llu\n",
			(unsigned long long)ino);
		return;
	}
	n->ino = ino;
	n->gen = gen;
	n->next_agino = next_agino;
	n->daddr = daddr;
	n->boffset = boffset;
	n->agno = xfs_daddr_to_agno(mp, daddr);
	list_add_tail(&n->l, &mp->m_mxfs_iunl_list);
	mp->m_mxfs_iunl_count++;
	spin_unlock(&mp->m_mxfs_iunl_lock);
}
EXPORT_SYMBOL(mxfs_iunl_store_record);

/*
 * diagnostic: report what the store knows about one ino — called
 * from the P53 mismatch site so every fatal carries the record's
 * lifecycle state (present + value + homed?  or absent).
 */
void mxfs_iunl_store_query_print(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_iunl_rec *r;
	bool found = false;

	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry(r, &mp->m_mxfs_iunl_list, l) {
		if (r->ino != ino)
			continue;
		found = true;
		mxfs_probe("mxfs: P-IUNLSTORE-QUERY ino=%llu rec_gen=%u committed=0x%x wr_epoch=%llu agno=%u count=%d\n",
			(unsigned long long)ino, r->gen, r->next_agino,
			(unsigned long long)r->wr_epoch, r->agno,
			mp->m_mxfs_iunl_count);
		break;
	}
	spin_unlock(&mp->m_mxfs_iunl_lock);
	if (!found)
		mxfs_probe("mxfs: P-IUNLSTORE-QUERY ino=%llu NO-RECORD count=%d\n",
			(unsigned long long)ino, mp->m_mxfs_iunl_count);
}
EXPORT_SYMBOL(mxfs_iunl_store_query_print);

/*
 * (design-consult ruling, precommit backstop (b)): does a live record prove
 * that @expect is the committed di_next_unlinked for exactly this slot?
 * Full-proof predicate — ino, incarnation, cluster daddr and byte offset
 * must all match; anything less stays a shutdown at the caller.
 */
bool mxfs_iunl_store_fossil_match(struct xfs_mount *mp, uint64_t ino,
				  uint32_t gen, xfs_daddr_t daddr,
				  uint16_t boffset, uint32_t expect)
{
	struct mxfs_iunl_rec *r;
	bool match = false;

	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry(r, &mp->m_mxfs_iunl_list, l) {
		if (r->ino != ino)
			continue;
		match = r->gen == gen && r->daddr == daddr &&
			r->boffset == boffset && r->next_agino == expect;
		break;
	}
	spin_unlock(&mp->m_mxfs_iunl_lock);
	return match;
}
EXPORT_SYMBOL(mxfs_iunl_store_fossil_match);

/*
 * v5 (design-consult ruling): drop every record scoped to this AG.  Called at
 * every AG EX unlock path AFTER the release drain+flush (Invariant #1),
 * so a stamped record's value is durably home; an UNSTAMPED record here
 * (wr_epoch=0: no payload-verified covering write ever completed) is
 * direct evidence of a drain/admission gap — P-IUNLSTORE-RELLEAK.  Also
 * called at EX acquisition as a belt (why="acquire"): any record found
 * there survived a release without purge — protocol violation.
 */
void mxfs_iunl_store_purge_ag(struct xfs_mount *mp, xfs_agnumber_t agno,
			      const char *why)
{
	struct mxfs_iunl_rec *r, *tmp;
	static atomic_t purge_alive = ATOMIC_INIT(0);
	int dropped = 0, unhomed = 0;

	/* Proof-of-life: 392 soaked with ZERO AGPURGE fleet-wide — prove
	 * the unlock hooks actually execute (vs releases bypassing them). */
	if (atomic_inc_return(&purge_alive) <= 3)
		mxfs_probe("mxfs: P-IUNLSTORE-AGPURGE-ALIVE agno=%u why=%s count=%d\n",
			agno, why, mp->m_mxfs_iunl_count);
	if (!mp->m_mxfs_iunl_count)
		return;
	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry_safe(r, tmp, &mp->m_mxfs_iunl_list, l) {
		if (r->agno != agno)
			continue;
		if (!r->wr_epoch) {
			unhomed++;
			pr_warn_ratelimited("mxfs: P-IUNLSTORE-RELLEAK ino=%llu agno=%u committed=0x%x wr_epoch=0 why=%s — record never payload-verified home at AG release (drain gap evidence)\n",
				(unsigned long long)r->ino, agno,
				r->next_agino, why);
		}
		list_del(&r->l);
		mp->m_mxfs_iunl_count--;
		kfree(r);
		dropped++;
	}
	spin_unlock(&mp->m_mxfs_iunl_lock);
	if (dropped)
		mxfs_probe_ratelimited("mxfs: P-IUNLSTORE-AGPURGE agno=%u dropped=%d unhomed=%d why=%s\n",
			agno, dropped, unhomed, why);
}

/* Home write COMPLETED (target cache, not platter) for [daddr,
 * daddr+bblen): stamp the flush epoch; also lazily drop any record whose
 * stamped epoch a device flush has since moved past — those values are
 * durably home.
 *
 * v4 (388 P-IUNL-DISCRIM decode: WRITE-NOWHERE-IN-TARGET with
 * wr_epoch STAMPED — the covering write completed but carried the
 * FOSSIL, so stamping on mere completion wrongly retired the protecting
 * record): stamp only when the written payload (base/len = the completed
 * buffer image) actually carried this record's committed value for the
 * matching incarnation.  A fossil-carrying write leaves the record live
 * and trips P-IUNLSTORE-FOSSILWR — with the write-side overlay in
 * xfs_buf_submit this should be impossible; its firing is a regression
 * alarm. */
void mxfs_iunl_store_retire_range(struct xfs_mount *mp, xfs_daddr_t daddr,
				  int bblen, void *base, unsigned int len)
{
	struct mxfs_iunl_rec *r, *tmp;
	uint64_t fe = atomic64_read(&mp->m_mxfs_flush_epoch);

	if (!mp->m_mxfs_iunl_count)
		return;
	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry_safe(r, tmp, &mp->m_mxfs_iunl_list, l) {
		struct xfs_dinode *dip;
		unsigned int off;

		if (r->wr_epoch && fe > r->wr_epoch) {
			list_del(&r->l);
			mp->m_mxfs_iunl_count--;
			kfree(r);
			continue;
		}
		if (r->daddr < daddr || r->daddr >= daddr + bblen)
			continue;
		off = (unsigned int)BBTOB(r->daddr - daddr) + r->boffset;
		if (!base || off + sizeof(struct xfs_dinode) > len)
			continue;	/* can't verify — keep record live */
		dip = (struct xfs_dinode *)((char *)base + off);
		/* 389-c1 refinement: a written slot bearing a
		 * DIFFERENT incarnation (gen/magic mismatch — free-time gen
		 * bump or full reuse) also retires the record: once that
		 * image lands and flushes, no pre-commit same-gen image can
		 * be served again (target-side loss was refuted by the
		 * discriminator), and wrong-incarnation images are
		 * ungraftable by design.  Only a SAME-GEN value mismatch is
		 * a true fossil write — record kept, alarm raised. */
		if (be16_to_cpu(dip->di_magic) != MXFS_DINODE_MAGIC ||
		    be32_to_cpu(dip->di_gen) != r->gen ||
		    be32_to_cpu(dip->di_next_unlinked) == r->next_agino) {
			r->wr_epoch = fe;
		} else {
			mxfs_probe_ratelimited("mxfs: P-IUNLSTORE-FOSSILWR ino=%llu daddr=%lld wrote_next=0x%x committed=0x%x gen=%u — completed SAME-GEN write did NOT carry the committed value; record kept\n",
				(unsigned long long)r->ino,
				(long long)r->daddr,
				be32_to_cpu(dip->di_next_unlinked),
				r->next_agino, r->gen);
		}
	}
	spin_unlock(&mp->m_mxfs_iunl_lock);
}
EXPORT_SYMBOL(mxfs_iunl_store_retire_range);

/* ─── media-vs-transit discriminator (memory TAIL18) ─────────────
 *
 * An overlay event means: the image just read for this cluster (via the
 * SCSI FUA read path, which pierces the target cache to media) carries a
 * pre-write di_next_unlinked while our store holds the committed value.
 * Two producers fit that observation:
 *   (a) READ-PATH: the write reached the LIO target's cache but has not
 *       destaged; the FUA read serves pre-destage media (time travel).
 *   (b) WRITE-LOST: the write never reached the target at all.
 * Discriminate at the specimen, sub-ms after the stale image: re-read the
 * same sectors PLAIN (bio — the target-cache-coherent view) and FUA
 * (media view) and decode the same slot.
 *   plain==committed && fua==img       → (a) cache holds it, media stale
 *   plain==img       && fua==img       → (b) write nowhere in the target
 *   plain==committed && fua==committed → destaged in the interim; write
 *                                        landed, original read raced (a)
 */
static void mxfs_iunl_discrim(struct xfs_mount *mp, xfs_daddr_t daddr,
			      int bblen, uint16_t boffset, uint64_t ino,
			      uint32_t gen, uint32_t img_next,
			      uint32_t committed, uint64_t wr_epoch)
{
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);
	extern int mxfs_fua_disable;
	static atomic_t discrim_n = ATOMIC_INIT(0);
	struct xfs_buftarg *btp = mp->m_ddev_targp;
	uint32_t len = BBTOB(bblen);
	struct xfs_dinode *pdip, *fdip;
	uint32_t pnext, fnext;
	const char *verdict;
	uint64_t lba;
	void *pb, *fb;
	int prc, frc;

	if (!btp || !btp->bt_bdev || !len || len > (64u << 10) ||
	    boffset + sizeof(struct xfs_dinode) > len)
		return;
	if (atomic_inc_return(&discrim_n) > 60)
		return;
	pb = kmalloc(len, GFP_NOFS);
	fb = kmalloc(len, GFP_NOFS);
	if (!pb || !fb)
		goto out;
	lba = (uint64_t)daddr + btp->bt_sector_offset;
	/* Plain first: capture the cache view before a destage can homogenize
	 * the two; FUA second gives media as-of-now.  skip the FUA
	 * leg when mxfs_fua_disable is set (fleet default) — a forced FUA
	 * read under the cluster-buffer lock in xfsaild context is the
	 * drain-wedge vector, and site 5 calls from exactly there.
	 * The plain (cache-coherent) view alone still answers in/not-in
	 * target. */
	prc = mxfs_pal_bdev_read_plain_bdev(btp->bt_bdev, lba, pb, len);
	frc = mxfs_fua_disable ? -EOPNOTSUPP :
		mxfs_pal_scsi_read_fua_bdev(btp->bt_bdev, lba, fb, len);
	if (prc) {
		mxfs_probe("mxfs: P-IUNL-DISCRIM ino=%llu read errs plain=%d fua=%d\n",
			(unsigned long long)ino, prc, frc);
		goto out;
	}
	pdip = (struct xfs_dinode *)((char *)pb + boffset);
	fdip = (struct xfs_dinode *)((char *)fb + boffset);
	pnext = be32_to_cpu(pdip->di_next_unlinked);
	fnext = frc ? 0xdead : be32_to_cpu(fdip->di_next_unlinked);
	if (be16_to_cpu(pdip->di_magic) != MXFS_DINODE_MAGIC ||
	    be32_to_cpu(pdip->di_gen) != gen ||
	    (!frc && be32_to_cpu(fdip->di_gen) != gen))
		verdict = "OTHER-INCARNATION";
	else if (frc)
		verdict = (pnext == committed) ? "IN-TARGET-CACHEVIEW" :
			  (pnext == img_next) ? "NOT-IN-TARGET-CACHEVIEW" :
					        "MIXED-CACHEVIEW";
	else if (pnext == committed && fnext == img_next)
		verdict = "READ-PATH-CACHE-HOLDS-WRITE";
	else if (pnext == img_next && fnext == img_next)
		verdict = "WRITE-NOWHERE-IN-TARGET";
	else if (pnext == committed && fnext == committed)
		verdict = "LANDED-ORIGINAL-READ-RACED-DESTAGE";
	else
		verdict = "MIXED";
	/* wr_epoch: 0 ⇒ NO covering write completion since this value was
	 * recorded — the home write was never submitted (local teardown
	 * loss).  Nonzero ⇒ the target ACKNOWLEDGED a covering write after
	 * the record, yet serves the old value — target-side loss. */
	mxfs_probe("mxfs: P-IUNL-DISCRIM ino=%llu daddr=%lld img=0x%x committed=0x%x plain=0x%x fua=0x%x wr_epoch=%llu flush_epoch=%lld verdict=%s\n",
		(unsigned long long)ino, (long long)daddr, img_next,
		committed, pnext, fnext,
		(unsigned long long)wr_epoch,
		(long long)atomic64_read(&mp->m_mxfs_flush_epoch), verdict);
out:
	kfree(pb);
	kfree(fb);
}

/*
 * A fresh platter image for [daddr, daddr+bblen) is about to be (or was
 * just) installed at base/len.  Overlay every live committed value whose
 * incarnation still matches the image; recompute the dinode CRC.  Gen
 * mismatch = the ino was reused since — drop the record loudly.  Returns
 * the number of slots overlaid.
 */
int mxfs_iunl_store_overlay(struct xfs_mount *mp, xfs_daddr_t daddr,
			    int bblen, void *base, unsigned int len)
{
	struct mxfs_iunl_rec *r, *tmp;
	uint32_t d_gen = 0, d_img = 0, d_committed = 0;
	uint16_t d_boffset = 0;
	uint64_t d_ino = 0, d_wr_epoch = 0;
	int hits = 0;

	if (!mp->m_mxfs_iunl_count)
		return 0;
	spin_lock(&mp->m_mxfs_iunl_lock);
	list_for_each_entry_safe(r, tmp, &mp->m_mxfs_iunl_list, l) {
		struct xfs_dinode *dip;

		if (r->daddr < daddr || r->daddr >= daddr + bblen)
			continue;
		if (r->boffset + sizeof(struct xfs_dinode) > len)
			continue;
		dip = (struct xfs_dinode *)((char *)base + r->boffset);
		if (be16_to_cpu(dip->di_magic) != MXFS_DINODE_MAGIC)
			continue;
		if (be32_to_cpu(dip->di_gen) != r->gen) {
			/* v3 (384 ring, GENDROP rec_gen=img_gen+1
			 * autopsy): a gen mismatch does NOT prove reuse — a
			 * stale PRE-REUSE platter image mismatches too, and
			 * with randomized fresh-create gens the ordering is
			 * undecidable.  Dropping here destroyed live coverage
			 * and let the cycle-2 fossil through.  Safe rule:
			 * never graft onto a wrong-incarnation image, never
			 * drop the record — keep and skip.  True-reuse
			 * records self-clean: the next local unlink of the
			 * ino re-records, and the flush cycle retires. */
			mxfs_probe_ratelimited("mxfs: P-IUNLSTORE-GENSKEW ino=%llu rec_gen=%u img_gen=%u — incarnation mismatch; record kept, no graft\n",
				(unsigned long long)r->ino, r->gen,
				be32_to_cpu(dip->di_gen));
			continue;
		}
		if (be32_to_cpu(dip->di_next_unlinked) != r->next_agino) {
			/* v5 (design-consult ruling #4, c3-391 autopsy), refined
			 * (0.11.471 test4 shutdown + design-consult ruling): a
			 * graft against a LIVE in-core inode whose runtime
			 * edge (i_next_unlinked) disagrees with the record
			 * could impose an abandoned past over the runtime's
			 * current graph — the inverted-P53 mechanism.  BUT the
			 * item-init-to-precommit window legitimately skews the
			 * in-core edge AHEAD of the committed value; the
			 * pending-transition certificate published at item
			 * creation names that window.  Decision: skew that a
			 * valid certificate explains (cert.old == record,
			 * cert.next == incore) still grafts — unless the image
			 * already holds the certified post-state, which is
			 * accepted as-is.  Only UNEXPLAINED skew refuses. */
			{
				struct xfs_perag *lpag = xfs_perag_get(mp,
					XFS_INO_TO_AGNO(mp, r->ino));
				bool refuse = false, poststate = false;
				bool pending = false;
				uint32_t incore = 0, cold = 0, cnext = 0;
				unsigned int cvalid = 0;

				if (lpag) {
					struct xfs_inode *lip;

					rcu_read_lock();
					lip = radix_tree_lookup(
						&lpag->pag_ici_root,
						XFS_INO_TO_AGINO(mp, r->ino));
					if (lip && lip->i_ino == r->ino) {
						incore = READ_ONCE(
							lip->i_next_unlinked);
						smp_rmb();
						cvalid = READ_ONCE(
						    lip->i_mxfs_nu_cert_valid);
						smp_rmb();
						cold = READ_ONCE(
						    lip->i_mxfs_nu_cert_old);
						cnext = READ_ONCE(
						    lip->i_mxfs_nu_cert_next);
						if (incore != r->next_agino) {
							if (cvalid &&
							    cold == r->next_agino &&
							    cnext == incore) {
								pending = true;
								poststate =
								  be32_to_cpu(dip->di_next_unlinked) == cnext;
							} else {
								refuse = true;
							}
						}
					}
					rcu_read_unlock();
					xfs_perag_put(lpag);
				}
				if (poststate) {
					mxfs_probe_ratelimited("mxfs: P-IUNLSTORE-POSTSTATE ino=%llu img=0x%x committed=0x%x cert={0x%x->0x%x} — image already holds certified post-state; accepted, no graft\n",
						(unsigned long long)r->ino,
						be32_to_cpu(dip->di_next_unlinked),
						r->next_agino, cold, cnext);
					continue;
				}
				if (refuse) {
					pr_warn_ratelimited("mxfs: P-IUNLSTORE-LIVESKEW ino=%llu incore=0x%x committed=0x%x img=0x%x cert_valid=%u cert={0x%x->0x%x} — unexplained live skew; graft refused\n",
						(unsigned long long)r->ino,
						incore, r->next_agino,
						be32_to_cpu(dip->di_next_unlinked),
						cvalid, cold, cnext);
					continue;
				}
				if (pending)
					mxfs_probe_ratelimited("mxfs: P-IUNLSTORE-PENDGRAFT ino=%llu incore=0x%x committed=0x%x img=0x%x cert={0x%x->0x%x} — skew explained by pending transition; grafting committed value\n",
						(unsigned long long)r->ino,
						incore, r->next_agino,
						be32_to_cpu(dip->di_next_unlinked),
						cold, cnext);
			}
			mxfs_probe("mxfs: P-IUNLSTORE-OVERLAY ino=%llu img_next=0x%x committed=0x%x daddr=%lld — platter image stale; overlaying committed value\n",
				(unsigned long long)r->ino,
				be32_to_cpu(dip->di_next_unlinked),
				r->next_agino, (long long)r->daddr);
			if (!hits) {
				d_ino = r->ino;
				d_gen = r->gen;
				d_img = be32_to_cpu(dip->di_next_unlinked);
				d_committed = r->next_agino;
				d_boffset = r->boffset;
				d_wr_epoch = r->wr_epoch;
			}
			dip->di_next_unlinked = cpu_to_be32(r->next_agino);
			xfs_dinode_calc_crc(mp, dip);
			hits++;
		}
	}
	spin_unlock(&mp->m_mxfs_iunl_lock);
	if (hits)
		mxfs_iunl_discrim(mp, daddr, bblen, d_boffset, d_ino, d_gen,
				  d_img, d_committed, d_wr_epoch);
	return hits;
}
EXPORT_SYMBOL(mxfs_iunl_store_overlay);

/*
 * (D-0524) fault injection: widen the post-commit window of
 * xfs_inactive_ifree (between xfs_trans_commit and mxfs_pubob_free_commit)
 * so a cluster-buffer write completion reliably lands inside it.  0 = off.
 */
int mxfs_freeob_commit_delay_ms;
module_param_named(freeob_commit_delay_ms, mxfs_freeob_commit_delay_ms, int, 0644);
MODULE_PARM_DESC(freeob_commit_delay_ms,
	"D-0524 fault injection: ms to sleep between the ifree commit and the FREE obligation commit (0=off)");
EXPORT_SYMBOL(mxfs_freeob_commit_delay_ms);

void mxfs_pubob_arm(struct xfs_mount *mp, struct xfs_inode *ip)
{
	struct mxfs_pubob *ob, *n;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	n = kzalloc(sizeof(*n), GFP_NOFS);
	spin_lock(&mp->m_mxfs_pubob_lock);
	list_for_each_entry(ob, &mp->m_mxfs_pubob_list, l) {
		if (ob->ino == ip->i_ino) {
			uint8_t okind = ob->kind;

			ob->gen = VFS_I(ip)->i_generation;
			/* the unlink of a chained live life — the entry
			 * becomes an ordinary UNLINK obligation again, the chain
			 * provenance rides along.  Any other kind here is a live
			 * inode that still carried an actionable entry: loud. */
			ob->kind = MXFS_PUBOB_UNLINK;
			spin_unlock(&mp->m_mxfs_pubob_lock);
			if (okind != MXFS_PUBOB_UNLINK && okind != MXFS_PUBOB_CHAIN_LIVE)
				mxfs_probe("mxfs: P-FREEOB-ARM-ANOMALY ino=%llu kind=%u chain=%u — unlink of a live inode whose store entry was still an actionable FREE; reset to UNLINK\n",
					(unsigned long long)ip->i_ino, okind, ob->chain);
			xfs_iflags_set(ip, MXFS_IF_PUBOB);
			xfs_iflags_clear(ip, MXFS_IF_PUBOB_FLUSHED);
			kfree(n);
			return;
		}
	}
	if (!n) {
		spin_unlock(&mp->m_mxfs_pubob_lock);
		/* A lost obligation is exactly the earlier exposure for
		 * this one unlink; loud so allocation pressure is visible. */
		mxfs_probe("mxfs: P88-PUBOB-ENOMEM ino=%llu\n",
			(unsigned long long)ip->i_ino);
		return;
	}
	n->ino = ip->i_ino;
	n->agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
	n->agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	n->gen = VFS_I(ip)->i_generation;
	list_add_tail(&n->l, &mp->m_mxfs_pubob_list);
	mp->m_mxfs_pubob_count++;
	spin_unlock(&mp->m_mxfs_pubob_lock);
	xfs_iflags_set(ip, MXFS_IF_PUBOB);
	xfs_iflags_clear(ip, MXFS_IF_PUBOB_FLUSHED);
}
EXPORT_SYMBOL(mxfs_pubob_arm);

/* Drop the store entry for @ino; returns true if one was found. */
bool mxfs_pubob_drop_ino(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_pubob *ob, *tmp;
	bool found = false;

	if (!mp->m_mxfs_pubob_count)
		return false;
	spin_lock(&mp->m_mxfs_pubob_lock);
	list_for_each_entry_safe(ob, tmp, &mp->m_mxfs_pubob_list, l) {
		if (ob->ino != ino)
			continue;
		list_del(&ob->l);
		mp->m_mxfs_pubob_count--;
		kfree(ob);
		found = true;
		break;
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	return found;
}

/* the entry for @ino, if any (caller holds m_mxfs_pubob_lock). */
struct mxfs_pubob *mxfs_pubob_find_locked(struct xfs_mount *mp,
						 uint64_t ino)
{
	struct mxfs_pubob *ob;

	list_for_each_entry(ob, &mp->m_mxfs_pubob_list, l)
		if (ob->ino == ino)
			return ob;
	return NULL;
}

/*
 * (D-0351) / (D-0524): the ifree is BEGINNING — called from
 * xfs_inactive_ifree under ILOCK EXCL with the AG EX held, BEFORE xfs_ifree.
 * The obligation (an UNLINK entry, a CHAIN_LIVE provenance entry, or none at
 * all when the unlink conversion already landed) becomes FREE_PENDING from
 * this point on, so the entry exists and is authoritative for the whole
 * ifree window; the predecessor is recorded verbatim for mxfs_pubob_free_abort.
 * The allocation may not fail: a free whose obligation could not be recorded
 * is exactly the D-0351 exposure, and the transaction has not modified
 * anything yet when this runs, so __GFP_NOFAIL on a 64-byte GFP_NOFS entry
 * is the honest choice (the kernel guarantees it for small sizes).
 */
void mxfs_pubob_free_pending(struct xfs_mount *mp, struct xfs_inode *ip,
			     uint64_t epoch)
{
	struct mxfs_pubob *ob, *n;
	uint8_t okind;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	n = kzalloc(sizeof(*n), GFP_NOFS | __GFP_NOFAIL);
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (!ob) {
		ob = n;
		n = NULL;
		ob->ino = ip->i_ino;
		ob->agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		ob->agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
		ob->pred = MXFS_PUBOB_PRED_NONE;
		list_add_tail(&ob->l, &mp->m_mxfs_pubob_list);
		mp->m_mxfs_pubob_count++;
	} else {
		ob->pred = ob->kind;
		ob->pred_chain = ob->chain;
		ob->pred_gen = ob->gen;
		ob->pred_epoch = ob->epoch;
	}
	okind = ob->pred;
	ob->kind = MXFS_PUBOB_FREE_PENDING;
	ob->gen = 0;
	ob->epoch = 0;
	ob->pending_epoch = epoch;
	WRITE_ONCE(ip->i_mxfs_freeob, 1);
	xfs_iflags_set(ip, MXFS_IF_PUBOB);
	spin_unlock(&mp->m_mxfs_pubob_lock);
	kfree(n);
	if (okind == MXFS_PUBOB_FREE || okind == MXFS_PUBOB_FREE_PENDING)
		mxfs_probe("mxfs: P-FREEOB-PENDING-ANOMALY ino=%llu pred_kind=%u chain=%u — ifree beginning on an entry that was already an actionable FREE; recorded as the predecessor\n",
			(unsigned long long)ip->i_ino, okind, ob->chain);
	if (!epoch)
		mxfs_probe("mxfs: P-FREEOB-NOEPOCH ino=%llu — ifree beginning with no AG EX tenure epoch\n",
			(unsigned long long)ip->i_ino);
}
EXPORT_SYMBOL(mxfs_pubob_free_pending);

/*
 * The ifree COMMITTED: the obligation owes mode=0 at @gen, under @epoch.
 * (D-0524, ruling S0-4): a successful ifree may NEVER end without a
 * FREE entry, whatever the entry's state was found to be — FREE_PENDING and
 * UNLINK advance, an absent entry is created, FREE is idempotent, and any
 * other kind is a protocol failure.  Everything under the lock; the
 * per-inode byte is a mirror written under the same lock.  The tenure the
 * ifree began under must be the tenure it committed under (the AG EX is held
 * across the whole transaction, holders > 0, so a release cannot have run);
 * a skew is a protocol failure and fails closed.
 */
void mxfs_pubob_free_commit(struct xfs_mount *mp, struct xfs_inode *ip,
			    uint64_t epoch)
{
	struct mxfs_pubob *ob, *n;
	uint8_t okind = 0;
	uint64_t pend_ep = 0;
	bool created = false, skew = false, anomaly = false;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	n = kzalloc(sizeof(*n), GFP_NOFS | __GFP_NOFAIL);
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (!ob) {
		ob = n;
		n = NULL;
		ob->ino = ip->i_ino;
		ob->agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
		ob->agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
		ob->pred = MXFS_PUBOB_PRED_NONE;
		list_add_tail(&ob->l, &mp->m_mxfs_pubob_list);
		mp->m_mxfs_pubob_count++;
		created = true;
	}
	okind = ob->kind;
	pend_ep = ob->pending_epoch;
	switch (okind) {
	case MXFS_PUBOB_FREE_PENDING:
		if (pend_ep && epoch && pend_ep != epoch)
			skew = true;
		break;
	case MXFS_PUBOB_UNLINK:
	case MXFS_PUBOB_FREE:
		break;
	default:
		anomaly = true;
		break;
	}
	if (!created && okind != MXFS_PUBOB_FREE_PENDING)
		ob->pred = MXFS_PUBOB_PRED_NONE;
	ob->kind = MXFS_PUBOB_FREE;
	ob->gen = VFS_I(ip)->i_generation;
	ob->epoch = epoch;
	ob->pending_epoch = 0;
	WRITE_ONCE(ip->i_mxfs_freeob, 2);
	xfs_iflags_set(ip, MXFS_IF_PUBOB);
	spin_unlock(&mp->m_mxfs_pubob_lock);
	kfree(n);
	if (created)
		mxfs_probe("mxfs: P-FREEOB-COMMIT-CREATED ino=%llu gen=%u epoch=%llu — ifree committed with no obligation entry (the pending transition never ran); FREE entry created at the commit\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation,
			(unsigned long long)epoch);
	else if (okind == MXFS_PUBOB_UNLINK)
		mxfs_probe("mxfs: P-FREEOB-COMMIT-NOPENDING ino=%llu gen=%u — ifree committed on an UNLINK entry (the pending transition never ran); advanced to FREE\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation);
	else if (okind == MXFS_PUBOB_FREE)
		mxfs_probe_ratelimited("mxfs: P-FREEOB-COMMIT-IDEMPOTENT ino=%llu gen=%u — ifree committed on an entry already FREE\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation);
	if (!epoch)
		/* design-consult: epoch 0 while freeing = a protocol failure, not an
		 * ordinary obligation — xfsaild can never sanction it; only the
		 * release audit's retiring token can publish it. */
		mxfs_probe("mxfs: P-FREEOB-NOEPOCH ino=%llu gen=%u — ifree committed with no AG EX tenure epoch\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation);
	if (skew || anomaly) {
		pr_err("mxfs: P-FREEOB-COMMIT-PROTOCOL ino=%llu gen=%u kind_at_commit=%u pending_epoch=%llu commit_epoch=%llu — %s; the FREE-PUBLISH bookkeeping cannot be trusted for this AG: shutting down (fail-closed, the journal carries the free)\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_generation,
			okind, (unsigned long long)pend_ep,
			(unsigned long long)epoch,
			skew ? "the AG EX tenure changed inside the ifree transaction" :
			       "the entry was neither pending, unlink nor free at the commit");
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
	}
}
EXPORT_SYMBOL(mxfs_pubob_free_commit);

/*
 * The ifree definitely did NOT commit (the transaction was cancelled clean).
 * (D-0524, ruling S0-3): restore EXACTLY the predecessor state —
 * an UNLINK obligation stays armed, a CHAIN_LIVE provenance is kept, no
 * entry means no entry.  A FREE entry is never touched here (idempotent on
 * the success path).  Under a shutdown the outcome of a failed commit is not
 * knowable from the return code: leave FREE_PENDING in place (fail closed —
 * no release runs on a shut-down mount anyway).
 */
void mxfs_pubob_free_abort(struct xfs_mount *mp, struct xfs_inode *ip)
{
	struct mxfs_pubob *ob;
	bool dropped = false;
	uint8_t restored = MXFS_PUBOB_PRED_NONE;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (!ob || ob->kind != MXFS_PUBOB_FREE_PENDING) {
		spin_unlock(&mp->m_mxfs_pubob_lock);
		return;
	}
	if (xfs_is_shutdown(mp)) {
		spin_unlock(&mp->m_mxfs_pubob_lock);
		pr_warn("mxfs: P-FREEOB-ABORT-SHUTDOWN ino=%llu — ifree outcome unknowable under shutdown; FREE_PENDING kept (fail-closed)\n",
			(unsigned long long)ip->i_ino);
		return;
	}
	restored = ob->pred;
	WRITE_ONCE(ip->i_mxfs_freeob, 0);
	ob->pending_epoch = 0;
	ob->inflight = MXFS_PUBOB_INFLIGHT_NONE;
	switch (ob->pred) {
	case MXFS_PUBOB_UNLINK:
		ob->kind = MXFS_PUBOB_UNLINK;
		ob->gen = ob->pred_gen;
		ob->chain = ob->pred_chain;
		ob->epoch = ob->pred_epoch;
		break;
	case MXFS_PUBOB_CHAIN_LIVE:
		ob->kind = MXFS_PUBOB_CHAIN_LIVE;
		ob->gen = 0;
		ob->chain = ob->pred_chain;
		ob->epoch = ob->pred_epoch;
		xfs_iflags_clear(ip, MXFS_IF_PUBOB | MXFS_IF_PUBOB_FLUSHED);
		break;
	default:
		/* PRED_NONE, or an actionable FREE predecessor (already
		 * anomalous at pending time): nothing this life can owe. */
		list_del(&ob->l);
		mp->m_mxfs_pubob_count--;
		kfree(ob);
		dropped = true;
		xfs_iflags_clear(ip, MXFS_IF_PUBOB | MXFS_IF_PUBOB_FLUSHED);
		break;
	}
	ob = NULL;
	spin_unlock(&mp->m_mxfs_pubob_lock);
	pr_warn_ratelimited("mxfs: P-FREEOB-ABORTED ino=%llu restored=%s — ifree did not commit; obligation restored to its predecessor\n",
		(unsigned long long)ip->i_ino,
		dropped ? "none" :
		restored == MXFS_PUBOB_UNLINK ? "UNLINK" : "CHAIN_LIVE");
}
EXPORT_SYMBOL(mxfs_pubob_free_abort);

/*
 * (D-0524): copy-in publication of the in-flight token.  Called from
 * xfs_iflush_int (ILOCK SHARED + cluster buffer locked) after the dinode
 * image has been staged.  Decides under the lock which image this write
 * carries: the UNLINK conversion (entry UNLINK, nlink 0) or the committed
 * FREE image (entry FREE, in-core mode 0).  Returns true when a token was
 * published — the caller then sets MXFS_IF_PUBOB_FLUSHED, which is only the
 * cheap "there may be a token" hint the completion tests before taking the
 * lock.  Two images of one inode can never be in flight together: every
 * image of an inode goes through its one cluster buffer, copy-in needs that
 * buffer's lock, the completion consumes the token under the buffer lock in
 * xfs_buf_inode_iodone before the buffer is unlocked, and an aborted write
 * consumes it in xfs_iflush_abort — so a token still present here is a
 * protocol failure, reported and overwritten.
 */
bool mxfs_pubob_stage_flush(struct xfs_mount *mp, struct xfs_inode *ip)
{
	struct mxfs_pubob *ob;
	uint8_t tok = MXFS_PUBOB_INFLIGHT_NONE, busy = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    !mp->m_mxfs_pubob_count || VFS_I(ip)->i_nlink != 0)
		return false;
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (ob) {
		if (ob->kind == MXFS_PUBOB_UNLINK)
			tok = MXFS_PUBOB_INFLIGHT_UNLINK;
		else if (ob->kind == MXFS_PUBOB_FREE && VFS_I(ip)->i_mode == 0)
			tok = MXFS_PUBOB_INFLIGHT_FREE;
		if (tok != MXFS_PUBOB_INFLIGHT_NONE) {
			busy = ob->inflight;
			ob->inflight = tok;
		}
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	if (busy)
		pr_warn("mxfs: P-FREEOB-TOKEN-BUSY ino=%llu old=%u new=%u — a previous write's token was never consumed (completion/abort bookkeeping gap); overwritten\n",
			(unsigned long long)ip->i_ino, busy, tok);
	return tok != MXFS_PUBOB_INFLIGHT_NONE;
}
EXPORT_SYMBOL(mxfs_pubob_stage_flush);

/*
 * (D-0524): a staged image did not (or will not) reach the platter —
 * xfs_iflush_abort, an error completion, or the cluster-merge overlay that
 * replaced the staged slot.  Consumes the token only; the entry and the
 * per-inode obligation state are untouched (fail closed: the obligation is
 * still owed and a later copy-in publishes a fresh token).
 */
void mxfs_pubob_flush_abort(struct xfs_mount *mp, struct xfs_inode *ip)
{
	struct mxfs_pubob *ob;

	if (!mp->m_mxfs_dlm || !mp->m_mxfs_pubob_count)
		return;
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (ob)
		ob->inflight = MXFS_PUBOB_INFLIGHT_NONE;
	spin_unlock(&mp->m_mxfs_pubob_lock);
}
EXPORT_SYMBOL(mxfs_pubob_flush_abort);

/*
 * (D-0351 chain): THIS node re-allocates @ip's number for a local
 * create (xfs_iget_recycle, create || deadshell_create; the AG EX is held by
 * the create's dialloc, holders > 0, so the tenure cannot end underneath).
 * XFS_IRECLAIM_RESET_FLAGS has just cleared MXFS_IF_PUBOB on the shell; the
 * store entry, if any, must stop being actionable NOW:
 *   FREE / FREE_PENDING under the SAME tenure the free committed in -> the
 *     entry becomes CHAIN_LIVE with chain+1: provenance that any live image
 *     a later chained free finds at home is one of this node's own lives;
 *   FREE under a DIFFERENT tenure -> the tenure ended with the obligation
 *     open, which the release audit forbids; the create's own platter
 *     validation covers the number.  Drop, loud (protocol failure);
 *   UNLINK / CHAIN_LIVE -> a recyclable freed shell cannot carry an unlink
 *     obligation or already be live.  Drop, loud.
 * The per-inode fields of the previous life are reset here as well
 * (i_mxfs_freeob is not an iflag and survives the recycle otherwise).
 */
void mxfs_pubob_recycle(struct xfs_mount *mp, struct xfs_inode *ip,
			bool deadshell)
{
	struct mxfs_pubob *ob;
	uint64_t epoch;
	uint8_t okind = 0;
	uint64_t oepoch = 0;
	uint16_t chain = 0;
	int verdict = 0;	/* 0 none, 1 chained, 2 broken, 3 anomaly, 4 superseded */

	WRITE_ONCE(ip->i_mxfs_freeob, 0);
	WRITE_ONCE(ip->i_mxfs_freeob_strikes, 0);
	mxfs_freepub_claim_clear(ip, "recycle");
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    !mp->m_mxfs_pubob_count)
		return;
	epoch = mxfs_ag_grant_epoch_of(mp, ip->i_ino);
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (ob) {
		okind = ob->kind;
		oepoch = ob->epoch;
		if ((ob->kind == MXFS_PUBOB_FREE ||
		     ob->kind == MXFS_PUBOB_FREE_PENDING) &&
		    epoch && ob->epoch == epoch && ob->chain < 0xffffu) {
			ob->kind = MXFS_PUBOB_CHAIN_LIVE;
			ob->chain++;
			chain = ob->chain;
			verdict = 1;
		} else {
			list_del(&ob->l);
			mp->m_mxfs_pubob_count--;
			kfree(ob);
			if (okind == MXFS_PUBOB_FREE ||
			    okind == MXFS_PUBOB_FREE_PENDING)
				verdict = 2;
			else if (okind == MXFS_PUBOB_CHAIN_LIVE)
				/* s435/s436: 12 + 16 of these — our chained live
				 * life was unlinked+freed by a PEER (it held the
				 * inode EX; our copy became a dead or stale-linked
				 * shell — deadshell=1 when the CR63 classifier saw
				 * it, 0 when the shell fell through as a stale
				 * LINKED shell) and this create's platter
				 * validation just passed: the peer's own
				 * obligation published the free, the chain
				 * provenance is moot.  A free of OUR live life
				 * always transitions the entry (arm -> UNLINK ->
				 * FREE_PENDING -> FREE), so CHAIN_LIVE here can
				 * only be the peer case. */
				verdict = 4;
			else
				verdict = 3;
		}
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	if (verdict == 4)
		mxfs_probe_ratelimited("mxfs: P-FREEOB-CHAIN-SUPERSEDED ino=%llu deadshell=%d — chained live life was freed by a peer; chain entry dropped\n",
			(unsigned long long)ip->i_ino, deadshell ? 1 : 0);
	if (verdict == 1) {
		static atomic_t chain_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&chain_n);

		/* s435 board: ~12k of these per node in 20 min — the dominant
		 * churn path.  First 200 verbatim, then one in 500 with the
		 * running total, so a sweep is never saturated by them. */
		if (n <= 200 || (n % 500) == 0)
			mxfs_probe("mxfs: P-FREEOB-CHAIN-LIVE ino=%llu chain=%u epoch=%llu n=%d — local re-allocation of a number whose free is still unpublished (same AG EX tenure); the entry is not actionable until this life is freed\n",
				(unsigned long long)ip->i_ino, chain,
				(unsigned long long)epoch, n);
	} else if (verdict == 2) {
		pr_warn("mxfs: P-FREEOB-CHAIN-BROKEN ino=%llu kind=%u ob_epoch=%llu epoch=%llu — re-allocating a number whose free obligation outlived its AG EX tenure (the release audit should have published or refused); entry dropped\n",
			(unsigned long long)ip->i_ino, okind,
			(unsigned long long)oepoch, (unsigned long long)epoch);
	} else if (verdict == 3) {
		mxfs_probe("mxfs: P-FREEOB-RECYCLE-ANOMALY ino=%llu kind=%u deadshell=%d — recycled a freed shell that still carried a non-FREE store entry; entry dropped\n",
			(unsigned long long)ip->i_ino, okind, deadshell ? 1 : 0);
	}
}
EXPORT_SYMBOL(mxfs_pubob_recycle);

/* Lock-free-caller lookup for xfs_iflush (copy-in, buffer locked). */
bool mxfs_pubob_lookup(struct xfs_mount *mp, uint64_t ino, uint8_t *kind,
		       uint32_t *gen, uint64_t *epoch, uint16_t *chain)
{
	struct mxfs_pubob *ob;
	bool found = false;

	if (!mp->m_mxfs_pubob_count)
		return false;
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ino);
	if (ob) {
		*kind = ob->kind;
		*gen = ob->gen;
		*epoch = ob->epoch;
		*chain = ob->chain;
		found = true;
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	return found;
}
EXPORT_SYMBOL(mxfs_pubob_lookup);

/*
 * (0.38.4, design-consult ruling home-free-
 * ledger-settle): a FREE obligation found ALREADY SATISFIED at home (the home
 * dinode is mode 0 — at any gen, per the 0.38.3 classification) is settled
 * BY EQUIVALENCE, not merely discharged.  The freed incarnation's publication
 * ledger (i_mxfs_pub_pending_seq != i_mxfs_pub_durable_seq: the superseded
 * life of the file) would otherwise stay open with nothing able to close it:
 * the flush returns success without a write, the abandoned-publication
 * chokepoint marks it fenced, and an UNLINKED inode gets no BAST-side
 * reload — it goes straight to reclaim, where P237-EVICT-OBLIGATION shuts
 * the node down (measured s432: fio_perf prologue, ino 133, pend=14 dur=0,
 * P55C-FREE-HOME 6 s earlier).  In 0.38.1 the same inode took the FOREIGN
 * branch whose write-poison EXEMPTED P237 — the tripwire was masked, never
 * satisfied.
 *
 * Predicates (all required, else the ledger stays open and P237 stays
 * fail-closed):
 *   - terminal local incarnation: in-core mode 0, nlink 0, a live committed
 *     FREE obligation (i_mxfs_freeob == 2, MXFS_IF_PUBOB);
 *   - the ifree transaction is log-complete: the inode item is UNPINNED
 *     (xfs_iflush_cluster never flushes a pinned inode; the recovery worker
 *     checks it explicitly).  A freed inode takes no further committed
 *     change, so the pending seq snapshotted here is final;
 *   - the caller has verified the home dinode is mode 0 (P55C: the locked
 *     cluster buffer; the worker: a fresh LUN read under a fresh AG EX).
 * Stamps exactly as the adopt-side discharge does (fepoch, wmb, durable,
 * flush) so the ticket check demands a flush after, never before, this.
 * Settle-only: no write, no adopt.
 */
bool mxfs_pubob_settle_home_free(struct xfs_mount *mp, struct xfs_inode *ip,
				 const char *site)
{
	uint64_t pend = READ_ONCE(ip->i_mxfs_pub_pending_seq);
	uint64_t dur = READ_ONCE(ip->i_mxfs_pub_durable_seq);
	static atomic_t settle_n = ATOMIC_INIT(0);
	const char *refuse = NULL;

	if (pend == dur)
		return true;
	if (VFS_I(ip)->i_mode != 0 || VFS_I(ip)->i_nlink != 0)
		refuse = "not-terminal";
	else if (READ_ONCE(ip->i_mxfs_freeob) != 2 ||
		 !xfs_iflags_test(ip, MXFS_IF_PUBOB))
		refuse = "no-committed-free-obligation";
	else if (atomic_read(&ip->i_pincount) != 0)
		refuse = "ifree-pinned";
	if (refuse) {
		if (atomic_inc_return(&settle_n) <= 2000)
			pr_warn("mxfs: P55C-FREE-HOME-UNSETTLED ino=%llu site=%s why=%s pend=%llu dur=%llu mode=0%o nlink=%u freeob=%u pin=%d — home is free but the ledger cannot be settled by equivalence; left open (fail-closed)\n",
				(unsigned long long)ip->i_ino, site, refuse,
				(unsigned long long)pend, (unsigned long long)dur,
				VFS_I(ip)->i_mode, VFS_I(ip)->i_nlink,
				(unsigned)READ_ONCE(ip->i_mxfs_freeob),
				atomic_read(&ip->i_pincount));
		return false;
	}
	WRITE_ONCE(ip->i_mxfs_pub_durable_fepoch,
		   (uint64_t)atomic64_read(&mp->m_mxfs_flush_epoch));
	smp_wmb();
	WRITE_ONCE(ip->i_mxfs_pub_durable_seq, pend);
	WRITE_ONCE(ip->i_mxfs_pub_flush_seq, pend);
	WRITE_ONCE(ip->i_mxfs_pub_fenced, 0);
	if (atomic_inc_return(&settle_n) <= 2000)
		mxfs_probe("mxfs: P55C-FREE-HOME-SETTLED ino=%llu site=%s pend=%llu dur=%llu->%llu — freed incarnation's ledger settled by equivalence (home dinode is free)\n",
			(unsigned long long)ip->i_ino, site,
			(unsigned long long)pend, (unsigned long long)dur,
			(unsigned long long)pend);
	return true;
}
EXPORT_SYMBOL(mxfs_pubob_settle_home_free);

void mxfs_pubob_discharge(struct xfs_mount *mp, struct xfs_inode *ip,
			  const char *why)
{
	struct mxfs_pubob *ob;
	uint16_t kept = 0;
	uint8_t okind = 0, tok = MXFS_PUBOB_INFLIGHT_NONE;
	bool flushed = (why[0] == 'f' && why[1] == 'l');	/* "flushed" */
	bool stale = false, dropped = false;

	/*
	 * (D-0524, design-consult ruling S0-1): every decision here is taken
	 * on the STORE ENTRY under m_mxfs_pubob_lock; the per-inode byte and
	 * flags are written under the same lock.  The old code branched on a
	 * lockless read of i_mxfs_freeob and re-marked FREE_PENDING from the
	 * completion of the PRE-free unlink image, overwriting a FREE the
	 * ifree commit had just recorded (chain 88, test1 shut down).
	 *
	 * "flushed" — a cluster-buffer write completed.  Which image it
	 * carried is the token the copy-in published; the token is consumed
	 * here exactly once.  It discharges only when it still matches the
	 * entry: an UNLINK image discharges an UNLINK entry, a FREE image
	 * discharges a FREE entry.  Anything else is a stale completion (the
	 * ifree began or committed after the copy-in) and changes nothing.
	 *
	 * "home-free" / "foreign" (P55C and the strike recovery: the home
	 * dinode was READ and classified) and "superseded" (reload adopted a
	 * newer incarnation from the platter): the caller holds its own proof
	 * about the home image; they discharge whatever the entry is, as
	 * before.  A FREE_PENDING entry, however, is never discharged by
	 * anyone but the ifree itself (commit -> FREE, abort -> predecessor).
	 */
	spin_lock(&mp->m_mxfs_pubob_lock);
	ob = mxfs_pubob_find_locked(mp, ip->i_ino);
	if (ob) {
		okind = ob->kind;
		if (flushed) {
			tok = ob->inflight;
			ob->inflight = MXFS_PUBOB_INFLIGHT_NONE;
			stale = !((tok == MXFS_PUBOB_INFLIGHT_UNLINK &&
				   okind == MXFS_PUBOB_UNLINK) ||
				  (tok == MXFS_PUBOB_INFLIGHT_FREE &&
				   okind == MXFS_PUBOB_FREE));
		} else if (okind == MXFS_PUBOB_FREE_PENDING) {
			stale = true;
		}
	}
	if (stale) {
		spin_unlock(&mp->m_mxfs_pubob_lock);
		/* the hint bit, if still set, belongs to no token now */
		if (flushed)
			xfs_iflags_clear(ip, MXFS_IF_PUBOB_FLUSHED);
		mxfs_probe_ratelimited("mxfs: P-FREEOB-FLUSH-STALE ino=%llu why=%s token=%u kind=%u — completion does not match the obligation's current state; nothing discharged\n",
			(unsigned long long)ip->i_ino, why, tok, okind);
		return;
	}
	WRITE_ONCE(ip->i_mxfs_freeob, 0);
	xfs_iflags_clear(ip, MXFS_IF_PUBOB | MXFS_IF_PUBOB_FLUSHED);
	/*
	 * (s439 board: all 41 P55C-FREE-FOREIGN were this): the
	 * UNLINK obligation of a CHAINED live life is discharged while the
	 * life goes on — "removed" (a tmpfile linked back: xfs_iunlink_remove)
	 * or "flushed" (its unlink conversion landed).  Dropping the entry
	 * here threw the chain provenance away; the ifree that followed
	 * minted a fresh entry with chain=0, P55C then met this node's own
	 * earlier life at home and called it FOREIGN, and that live image
	 * stayed on the platter under a free inobt bit (P-DIALLOC-DISKLIVE
	 * from the same node, 72 per board).  Provenance outlives the unlink
	 * obligation: the entry reverts to CHAIN_LIVE — not actionable until
	 * this life is freed, exactly what the recycle minted — and the
	 * next free carries chain>0 to P55C (FREE-CHAIN, never FOREIGN).
	 */
	if (ob && ob->chain && ob->kind == MXFS_PUBOB_UNLINK) {
		ob->kind = MXFS_PUBOB_CHAIN_LIVE;
		ob->gen = 0;
		ob->inflight = MXFS_PUBOB_INFLIGHT_NONE;
		kept = ob->chain;
	} else if (ob) {
		list_del(&ob->l);
		mp->m_mxfs_pubob_count--;
		kfree(ob);
		ob = NULL;
		dropped = true;
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);
	mxfs_freepub_claim_clear(ip, why);
	if (kept) {
		static atomic_t kept_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&kept_n);

		/* s442 board: ~900/node — the dominant chained-life
		 * churn path, same pacing as P-FREEOB-CHAIN-LIVE. */
		if (n <= 200 || (n % 500) == 0)
			mxfs_probe("mxfs: P-FREEOB-CHAIN-KEPT ino=%llu chain=%u why=%s n=%d — unlink obligation discharged on a chained live life; chain provenance retained (entry back to CHAIN_LIVE)\n",
				(unsigned long long)ip->i_ino, kept, why, n);
	} else if (dropped && okind == MXFS_PUBOB_FREE && !flushed) {
		static atomic_t sup_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&sup_n);

		/* audit hook (ruling S1-7): a FREE obligation ended by
		 * a caller's own classification of the home dinode, not by
		 * the FREE image's write completion.  Counted so the board
		 * sweep can see how often the FREE-PUBLISH proof came from
		 * P55C/recovery/reload rather than the completion. */
		if (n <= 200 || (n % 500) == 0)
			mxfs_probe("mxfs: P-FREEOB-FREE-DISCHARGED-BY ino=%llu why=%s n=%d\n",
				(unsigned long long)ip->i_ino, why, n);
	}
}
EXPORT_SYMBOL(mxfs_pubob_discharge);

/* the AG EX tenure epoch this node holds for @ino's AG (0 = none). */
uint64_t mxfs_ag_grant_epoch_of(struct xfs_mount *mp, uint64_t ino)
{
	struct xfs_perag *pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
	uint64_t e = 0;

	if (pag) {
		e = READ_ONCE(pag->pag_mxfs_grant_epoch);
		xfs_perag_put(pag);
	}
	return e;
}
EXPORT_SYMBOL(mxfs_ag_grant_epoch_of);

static void mxfs_freeob_recover_fn(struct work_struct *w)
{
	struct xfs_mount *mp = container_of(w, struct xfs_mount, m_mxfs_freeob_work);
	uint64_t	*inos;
	uint32_t	*gens;
	int		n = 0, cap, k;
	struct mxfs_pubob *ob;

	atomic_set(&mp->m_mxfs_freeob_work_armed, 0);
	if (xfs_is_shutdown(mp) || !mp->m_mxfs_pubob_count)
		return;
	spin_lock(&mp->m_mxfs_pubob_lock);
	cap = mp->m_mxfs_pubob_count;
	spin_unlock(&mp->m_mxfs_pubob_lock);
	inos = kmalloc_array(cap, sizeof(*inos), GFP_NOFS);
	gens = kmalloc_array(cap, sizeof(*gens), GFP_NOFS);
	if (!inos || !gens)
		goto out;
	spin_lock(&mp->m_mxfs_pubob_lock);
	list_for_each_entry(ob, &mp->m_mxfs_pubob_list, l) {
		if (ob->kind != MXFS_PUBOB_FREE || n >= cap)
			continue;
		inos[n] = ob->ino;
		gens[n] = ob->gen;
		n++;
	}
	spin_unlock(&mp->m_mxfs_pubob_lock);

	for (k = 0; k < n && !xfs_is_shutdown(mp); k++) {
		struct xfs_perag *pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, inos[k]));
		xfs_agino_t agino = XFS_INO_TO_AGINO(mp, inos[k]);
		uint32_t dnl = 0, dnext = 0, dgen = 0;
		uint16_t dmode = 0;
		struct xfs_inode *ip = NULL;
		int rc;

		if (!pag)
			continue;
		/* only obligations xfsaild actually denied need a fresh tenure */
		rcu_read_lock();
		ip = radix_tree_lookup(&pag->pag_ici_root, agino);
		if (!ip || ip->i_ino != inos[k] ||
		    READ_ONCE(ip->i_mxfs_freeob_strikes) == 0 ||
		    __xfs_iflags_test(ip, XFS_IRECLAIM))
			ip = NULL;
		rcu_read_unlock();
		if (!ip) {
			xfs_perag_put(pag);
			continue;
		}
		rc = mxfs_ag_dlm_lock(mp, pag);
		if (rc) {
			pr_warn_ratelimited("mxfs: P-FREEOB-RECOVER-AGLOCK ino=%llu ag=%u rc=%d\n",
				(unsigned long long)inos[k], pag_agno(pag), rc);
			xfs_perag_put(pag);
			continue;
		}
		rc = mxfs_p87_read_home_dinode(pag, agino, &dnl, &dnext, &dgen, &dmode);
		if (rc == 0 && dmode != 0 && dgen == (uint32_t)(gens[k] - 1u)) {
			uint64_t e = READ_ONCE(pag->pag_mxfs_grant_epoch);

			spin_lock(&mp->m_mxfs_pubob_lock);
			ob = mxfs_pubob_find_locked(mp, inos[k]);
			if (ob && ob->kind == MXFS_PUBOB_FREE && ob->gen == gens[k])
				ob->epoch = e;
			spin_unlock(&mp->m_mxfs_pubob_lock);
			WRITE_ONCE(ip->i_mxfs_freeob_strikes, 0);
			mxfs_probe("mxfs: P-FREEOB-RESCOPED ino=%llu gen=%u ag=%u epoch=%llu — predecessor still on the LUN; free image re-sanctioned under a fresh AG EX tenure\n",
				(unsigned long long)inos[k], gens[k], pag_agno(pag),
				(unsigned long long)e);
			/* the AG holder count keeps the tenure while xfsaild
			 * converts; give it a push and a bounded wait */
			xfs_ail_push_all(mp->m_ail);
			{
				int spins = 0;

				while (READ_ONCE(ip->i_mxfs_freeob) == 2 &&
				       spins++ < 200 && !xfs_is_shutdown(mp))
					msleep(10);
			}
		} else if (rc == 0 && dmode == 0) {
			/* free at home at ANY gen satisfies FREE-PUBLISH;
			 * settle the ledger by equivalence first (settle-
			 * only: no write, no adopt — a peer may have allocated and
			 * freed the number in the lock gap; mode 0 now still proves
			 * the free image requirement was physically satisfied). */
			mxfs_pubob_settle_home_free(mp, ip, "recover");
			mxfs_pubob_discharge(mp, ip, "home-free");
			WRITE_ONCE(ip->i_mxfs_freeob_strikes, 0);
		} else if (rc == 0) {
			mxfs_probe("mxfs: P-FREEOB-FOREIGN ino=%llu gen=%u disk_gen=%u disk_mode=0%o live_shell=%d — home dinode is not this node's freed incarnation under a FRESH tenure; neutralizing the shell (never written)\n",
				(unsigned long long)inos[k], gens[k], dgen, dmode,
				VFS_I(ip)->i_mode != 0 ? 1 : 0);
			if (VFS_I(ip)->i_mode == 0)
				ip->i_mxfs_dead_incarn_gen = dgen ? dgen : 1;
			mxfs_pubob_discharge(mp, ip, "foreign");
			WRITE_ONCE(ip->i_mxfs_freeob_strikes, 0);
		} else {
			pr_warn_ratelimited("mxfs: P-FREEOB-RECOVER-READ ino=%llu rc=%d\n",
				(unsigned long long)inos[k], rc);
		}
		mxfs_ag_dlm_unlock(mp, pag);
		xfs_perag_put(pag);
	}
out:
	kfree(inos);
	kfree(gens);
}

/*
 * D-0946: drive THIS node's outstanding free publication for @ino to the
 * platter, so the number becomes reusable instead of merely being refused.
 *
 * The inode allocator's candidate validator now refuses a number whose own
 * free is still unpublished, because its home dinode still carries our live
 * predecessor image and the create path's recycle gate would (correctly) call
 * that image corruption — on a transaction it has already dirtied, which costs
 * the whole filesystem.  Refusal alone starves, though: the inobt says the
 * number is free, every candidate is refused, and nothing makes the write
 * happen.  This is the progress path that keeps the refusal honest.
 *
 * Called from mxfs_dialloc_two_phase with NO btree cursor and NO AGI buffer
 * held and a CLEAN transaction, but WITH the AG EX held.  That is deliberate,
 * not an oversight: the publication write is only sanctioned under the AG EX
 * tenure, so holding it is what lets the write proceed at all — while holding
 * the AGI, which the publisher needs, would deadlock.
 *
 * The free is committed in core; its dinode image reaches the platter when the
 * inode's cluster buffer destages.  Force the log so the ifree is stable and
 * the inode item unpinned (xfs_iflush_cluster never flushes a pinned inode),
 * then push the AIL so the write happens now rather than at the AIL's own pace.
 *
 * Bounded by @ms.  Returns true when no unpublished-free obligation remains.
 */
/*
 * D-0947: push everything this mount owes the platter, once, and return.
 *
 * The inode allocator needs this to tell its two indistinguishable "no inode
 * magic at the candidate's home" cases apart: an inode cluster we initialised
 * and have not destaged (the log force unpins it, the AIL push writes it, and
 * the home then has its magic) versus a home that belongs to something else,
 * which still has no magic afterwards.  A read alone cannot separate them; the
 * write is what makes the difference observable.
 *
 * Callable only where the caller holds no AGI and no btree cursor and the
 * transaction is clean -- the publisher needs those.
 */
void mxfs_pubob_flush_owed(struct xfs_mount *mp)
{
	if (!mp || xfs_is_shutdown(mp))
		return;
	/*
	 * ASYNCHRONOUS ON PURPOSE.  Every caller is holding the cluster AG EX,
	 * and the D-0946 ruling names a synchronous flush under that grant as
	 * cluster-wide head-of-line blocking whose worst case is exactly this
	 * rig's workload -- rapid unlink/create churn in a small inode
	 * population.  Both of these START the owed writes and return; the
	 * caller refuses its candidate transiently and the ordinary 500-1000 ms
	 * reservation cooldown is the retry delay, by which time the writes have
	 * landed.  Progress is still guaranteed, because the write was kicked.
	 */
	xfs_log_force(mp, 0);
	xfs_ail_push_all(mp->m_ail);
}
EXPORT_SYMBOL(mxfs_pubob_flush_owed);

bool mxfs_pubob_drive_publication(struct xfs_mount *mp, uint64_t ino,
				  unsigned int ms)
{
	uint8_t		kind = 0;
	uint32_t	gen = 0;
	uint64_t	epoch = 0;
	uint16_t	chain = 0;
	unsigned int	waited = 0;

	if (!mp->m_mxfs_pubob_count || xfs_is_shutdown(mp))
		return true;
	mxfs_pubob_flush_owed(mp);
	/*
	 * NO WAITING HERE.  @ms is retained in the signature because the caller
	 * still reports the budget it intended, but this must not sleep: it runs
	 * under the AG EX, and blocking there queues every peer and every local
	 * task behind us.  Report whether the obligation happens to be gone
	 * already -- it often is, the flush having been started by an earlier
	 * refusal -- and otherwise leave it to the caller's cooldown and the
	 * sweep back-off.
	 */
	(void)ms;
	if (!mxfs_pubob_lookup(mp, ino, &kind, &gen, &epoch, &chain) ||
	    (kind != MXFS_PUBOB_FREE &&
	     kind != MXFS_PUBOB_FREE_PENDING &&
	     kind != MXFS_PUBOB_CHAIN_LIVE)) {
		mxfs_probe_ratelimited("mxfs: P946-PUBDRIVE-OK ino=%llu waited_ms=%u — the owed free image is already published; the number is reusable again\n",
			(unsigned long long)ino, waited);
		return true;
	}
	/*
	 * Not an error and not a corruption verdict: the number simply stays
	 * excluded from reuse until the write lands.  Nothing has been dirtied,
	 * the caller re-picks, and the allocator's sweep back-off (never ENOSPC)
	 * covers the case where every candidate is in this state.
	 */
	mxfs_probe_ratelimited("mxfs: P946-PUBDRIVE-KICKED ino=%llu kind=%u gen=%u epoch=%llu chain=%u waited_ms=%u — the owed writes are started but not yet landed; the number stays excluded from reuse until the cooldown expires (nothing waited on under the AG grant, no transaction dirtied)\n",
		(unsigned long long)ino, (unsigned)kind, gen,
		(unsigned long long)epoch, (unsigned)chain, waited);
	return false;
}
EXPORT_SYMBOL(mxfs_pubob_drive_publication);

/* P55C denial: after a bounded number of xfsaild retries, run recovery. */
void mxfs_pubob_free_strike(struct xfs_mount *mp, struct xfs_inode *ip)
{
	uint8_t n = READ_ONCE(ip->i_mxfs_freeob_strikes);

	if (n < 255)
		WRITE_ONCE(ip->i_mxfs_freeob_strikes, n + 1);
	if (n + 1 >= 8 && !atomic_cmpxchg(&mp->m_mxfs_freeob_work_armed, 0, 1))
		queue_work(system_unbound_wq, &mp->m_mxfs_freeob_work);
}
EXPORT_SYMBOL(mxfs_pubob_free_strike);

void mxfs_defer_reap_init(struct xfs_mount *mp)
{
	INIT_WORK(&mp->m_mxfs_freeob_work, mxfs_freeob_recover_fn);
	atomic_set(&mp->m_mxfs_freeob_work_armed, 0);
	spin_lock_init(&mp->m_mxfs_reap_lock);
	INIT_LIST_HEAD(&mp->m_mxfs_reap_list);
	spin_lock_init(&mp->m_mxfs_iunl_lock);
	INIT_LIST_HEAD(&mp->m_mxfs_iunl_list);
	mp->m_mxfs_iunl_count = 0;
	spin_lock_init(&mp->m_mxfs_pubob_lock);
	INIT_LIST_HEAD(&mp->m_mxfs_pubob_list);
	mp->m_mxfs_pubob_count = 0;
	INIT_DELAYED_WORK(&mp->m_mxfs_reap_work, mxfs_reap_worker);
	mp->m_mxfs_reap_count = 0;
	/* mount-settle duties: drain residue on OUR bucket left by a
	 * prior incarnation or an offline chk repair, then the guarded
	 * unclaimed-bucket pass + cold orphan scan.  The delay lets
	 * formation/joins settle; helpers -EAGAIN (and the worker retries)
	 * until the DLM is attached and a slot is held. */
	mp->m_mxfs_reap_duties = 0;
	set_bit(MXFS_REAPF_OWN_RESCAN, &mp->m_mxfs_reap_duties);
	set_bit(MXFS_REAPF_UBSCAN, &mp->m_mxfs_reap_duties);
	mp->m_mxfs_reap_dead = false;
	mxfs_reap_sched(mp, 20000, "mount-settle");
}

void mxfs_defer_reap_destroy(struct xfs_mount *mp)
{
	struct mxfs_reap_entry *e, *tmp;

	WRITE_ONCE(mp->m_mxfs_reap_dead, true);
	cancel_delayed_work_sync(&mp->m_mxfs_reap_work);
	cancel_work_sync(&mp->m_mxfs_freeob_work);	/* (D-0351) */
	{
		struct mxfs_iunl_rec *ir, *irt;

		spin_lock(&mp->m_mxfs_iunl_lock);
		list_for_each_entry_safe(ir, irt, &mp->m_mxfs_iunl_list, l) {
			list_del(&ir->l);
			kfree(ir);
		}
		mp->m_mxfs_iunl_count = 0;
		spin_unlock(&mp->m_mxfs_iunl_lock);
	}
	{
		struct mxfs_pubob *ob, *obt;
		int undischarged = 0;

		spin_lock(&mp->m_mxfs_pubob_lock);
		list_for_each_entry_safe(ob, obt, &mp->m_mxfs_pubob_list, l) {
			undischarged++;
			list_del(&ob->l);
			kfree(ob);
		}
		mp->m_mxfs_pubob_count = 0;
		spin_unlock(&mp->m_mxfs_pubob_lock);
		if (undischarged)
			pr_warn("mxfs: P88-PUBOB-UNMOUNT-PENDING count=%d — obligations die with the mount; a dirty departure's journal slice carries the conversions for replay\n",
				undischarged);
	}
	spin_lock(&mp->m_mxfs_reap_lock);
	list_for_each_entry_safe(e, tmp, &mp->m_mxfs_reap_list, l) {
		mxfs_probe("mxfs: P89-REAP-UNMOUNT-PENDING ino=%llu — zombie stays durable in our bucket; next mount of this slot re-drives it\n",
			(unsigned long long)e->ino);
		list_del(&e->l);
		kfree(e);
	}
	mp->m_mxfs_reap_count = 0;
	spin_unlock(&mp->m_mxfs_reap_lock);
}
