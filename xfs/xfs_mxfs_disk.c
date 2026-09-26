// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- coherent reads of on-disk inodes
 */
#define MXFS_TU_ID 26	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * instrumented DECISIVE PROBE (splits Theory D vs Theory B).
 *
 * On a FRESH AG acquire (we now hold this AG's DLM EX, and have just
 * invalidated our cached AG-meta), FUA-read the AGF then the bnobt root
 * block straight from the medium.  If the bnobt root looks near-pristine
 * (level-0, numrecs<=1 = one giant-free record), sleep 100ms and FUA-read
 * the SAME block AGAIN.  We hold the AG EX the whole time and issue NO
 * local write between the two reads, so a legitimate peer CANNOT modify
 * it.  Therefore:
 *   differs==1  => a PRIOR holder's bnobt write I/O landed on the medium
 *                  AFTER it released the AG (Theory D: release-side
 *                  async-drain leak).  Our first read legitimately saw
 *                  "free" -> the allocator would double-allocate.
 *   differs==0  => the medium is stable during our hold.  If the bnobt is
 *                  pristine here yet a later allocation double-allocs, the
 *                  staleness is on the READ side (Theory B / buffer alias),
 *                  not a release-side I/O leak.
 * The expensive 100ms sleep is capped at 64 samples per mount to bound
 * added latency (~6.4s) and avoid masking the failure outright.  The two
 * cheap FUA reads run on every fresh acquire but cost only microseconds.
 */
static atomic_t mxfs_acqprobe_count = ATOMIC_INIT(0);

void
mxfs_acq_fresh_durability_probe(struct xfs_perag *pag)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buftarg	*tp;
	uint32_t		agno = pag_agno(pag);
	uint32_t		bno_root, bno_level, blen, slen;
	uint64_t		agf_lba, bno_lba;
	void			*agf = NULL, *b1 = NULL, *b2 = NULL;
	struct xfs_btree_block	*bb1, *bb2;
	struct xfs_agf		*a;
	int			n, differs;
	extern int		mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					sector_t, void *, unsigned int);

	if (!mp || !mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	if (atomic_read(&mxfs_acqprobe_count) >= 64)
		return;
	tp = mp->m_ddev_targp;
	slen = mp->m_sb.sb_sectsize;
	blen = mp->m_sb.sb_blocksize;
	if (slen < 512 || (slen & 511) || blen < 512 || (blen & 511))
		return;
	agf = kmalloc(slen, GFP_NOFS);
	b1  = kmalloc(blen, GFP_NOFS);
	b2  = kmalloc(blen, GFP_NOFS);
	if (!agf || !b1 || !b2)
		goto out;

	agf_lba = (uint64_t)XFS_AG_DADDR(mp, agno, XFS_AGF_DADDR(mp)) +
		tp->bt_sector_offset;
	if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, agf_lba, agf, slen))
		goto out;
	a = (struct xfs_agf *)agf;
	if (be32_to_cpu(a->agf_magicnum) != MXFS_AGF_MAGIC)
		goto out;
	bno_root  = be32_to_cpu(a->agf_bno_root);
	bno_level = be32_to_cpu(a->agf_bno_level);

	bno_lba = (uint64_t)XFS_AGB_TO_DADDR(mp, agno, bno_root) +
		tp->bt_sector_offset;
	if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, bno_lba, b1, blen))
		goto out;
	bb1 = (struct xfs_btree_block *)b1;
	if (be32_to_cpu(bb1->bb_magic) != MXFS_ABTB_CRC_MAGIC)
		goto out;
	/* Only the suspicious near-empty case is worth the 100ms sleep. */
	if (!(be16_to_cpu(bb1->bb_level) == 0 &&
	      be16_to_cpu(bb1->bb_numrecs) <= 1))
		goto out;
	n = atomic_inc_return(&mxfs_acqprobe_count);
	if (n > 64)
		goto out;

	msleep(100);
	if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, bno_lba, b2, blen))
		goto out;
	bb2 = (struct xfs_btree_block *)b2;
	differs = memcmp(b1, b2, blen) ? 1 : 0;
	mxfs_probe("mxfs: P-ACQPROBE#%d agno=%u bno_root=%u level=%u nr1=%u nr2=%u differs=%d (differs=1 => peer release-side I/O landed during our EX hold = Theory D)\n",
		n, agno, bno_root, bno_level,
		(unsigned)be16_to_cpu(bb1->bb_numrecs),
		(unsigned)be16_to_cpu(bb2->bb_numrecs), differs);
out:
	kfree(agf);
	kfree(b1);
	kfree(b2);
}

/*
 * P98 discriminator: at a getattr (stat) of a regular file whose
 * in-core di_size is 0, FUA-read THIS inode's on-disk dinode and log the
 * on-disk di_size + mode.  This resolves the long-standing di_size=0
 * cross_write_read fork:
 *   - disk_di_size != 0  => the on-disk inode is CORRECT; our in-core copy
 *     is STALE (read-side: cached in-core inode never refreshed) — fix is
 *     read-side (FUA-refresh the inode at getattr / on iget cache-hit).
 *   - disk_di_size == 0  => the peer-writer's inode is NOT durable on the
 *     medium yet (write-side: writer's fsync/sync didn't destage the
 *     dinode before the reader's FUA-read) — fix is write-side durability.
 * Gated behind mxfs.instr; fires only on the size==0 regular-file anomaly,
 * ratelimited.  Pure diagnostic, no state change.
 */
/*
 * FUA-read this inode's on-disk dinode and return its di_size (pierces the
 * SCST write cache to the medium).  *modep gets the on-disk mode if non-NULL.
 * Returns (u64)-1 on any error / non-inode magic.  Diagnostic helper.
 */
uint64_t
mxfs_inode_disk_di_size(struct xfs_inode *ip, uint16_t *modep, uint32_t *genp)
{
	struct xfs_mount	*mp;
	struct xfs_buftarg	*tp;
	uint32_t		len, boff;
	uint64_t		lba, dsz = (uint64_t)-1;
	void			*tmp;
	extern int		mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					sector_t, void *, unsigned int);

	if (!ip)
		return dsz;
	mp = ip->i_mount;
	if (!mp)
		return dsz;
	tp = mp->m_ddev_targp;
	if (!tp || !tp->bt_bdev || ip->i_imap.im_len == 0)
		return dsz;
	len = BBTOB(ip->i_imap.im_len);
	boff = ip->i_imap.im_boffset;
	if (len == 0 || (len & 511) || (uint32_t)boff + 0x40 > len)
		return dsz;
	lba = (uint64_t)ip->i_imap.im_blkno + tp->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return dsz;
	if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, lba, tmp, len) == 0) {
		const __u8 *dk = (const __u8 *)tmp + boff;

		if (be16_to_cpup((const __be16 *)dk) == MXFS_DINODE_MAGIC) {
			dsz = be64_to_cpup((const __be64 *)(dk + 0x38));
			if (modep)
				*modep = be16_to_cpup((const __be16 *)(dk + 2));
			/* di_gen at 0x5c; guard the 4-byte read within the buf */
			if (genp && (uint32_t)boff + 0x60 <= len)
				*genp = be32_to_cpup((const __be32 *)(dk + 0x5c));
		}
	}
	kfree(tmp);
	return dsz;
}

/*
 * (A)-vs-(B) discriminator for the AG bnobt double-free corruption.
 * Given a bare inode NUMBER (the owner of the extent we are freeing), FUA-read
 * its on-disk dinode and return di_mode (0 = FREE on disk).  If we are freeing
 * an extent owned by inode I at unmount inactivation but disk says I is FREE
 * (di_mode==0) or carries a different generation, then this node is
 * inactivating a STALE cached inode whose blocks a peer already freed
 * (hypothesis B).  If disk di_mode matches a live inode, the bnobt-removal was
 * lost (hypothesis A).  Returns 0xFFFF on any error / bad magic.  *genp gets
 * the on-disk di_gen if non-NULL.  Diagnostic only.
 */
/* capture the inode currently being inactivated (truncated) so the
 * AG bnobt double-free site can identify and FUA-probe it.  Best-effort
 * (same task context drives inactivate->defer->free synchronously). */
uint64_t mxfs_dbg_inactive_ino;
uint32_t mxfs_dbg_inactive_gen;
EXPORT_SYMBOL(mxfs_dbg_inactive_ino);
EXPORT_SYMBOL(mxfs_dbg_inactive_gen);

uint16_t
mxfs_dbg_disk_di_mode(struct xfs_mount *mp, xfs_ino_t ino, uint32_t *genp)
{
	struct xfs_buftarg	*tp;
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;
	uint32_t		off, isize, blen;
	uint64_t		lba;
	void			*tmp;
	uint16_t		mode = 0xFFFF;
	void			*tmp2;
	extern int		mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					sector_t, void *, unsigned int);
	extern int		mxfs_pal_bdev_read_plain_bdev(struct block_device *,
					uint64_t, void *, unsigned int);

	if (!mp)
		return mode;
	tp = mp->m_ddev_targp;
	if (!tp || !tp->bt_bdev)
		return mode;
	agno = XFS_INO_TO_AGNO(mp, ino);
	agbno = XFS_INO_TO_AGBNO(mp, ino);
	off = XFS_INO_TO_OFFSET(mp, ino);
	isize = mp->m_sb.sb_inodesize;
	blen = mp->m_sb.sb_blocksize;
	if (isize < 256 || blen == 0 || (blen & 511) ||
	    off * isize + 0x40 > blen)
		return mode;
	lba = (uint64_t)XFS_AGB_TO_DADDR(mp, agno, agbno) + tp->bt_sector_offset;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return mode;
	/*
	 * the budget rule/instrumented FIX — dlm_scaling@32/tcp
	 * NO_TERMINAL_RECORD (pace ~15 ops/s vs floor 30): P137-INACT-TIME
	 * proved this function IS the per-unlink cost — fua_us p50=46ms
	 * p90=123ms at 32 nodes (24-29ms at 16) with everything else in the
	 * hundreds of µs.  The raw SCSI READ(16)+FUA serializes behind the
	 * whole cluster's O_DSYNC write queue at the target AND — per the
	 * divergence detector's own analysis — returns the STALE
	 * PLATTER view under fua_disable=1 while the coherent cluster view
	 * is the plain-bio one.  The sibling nlink read
	 * (mxfs_dbg_disk_di_nlink_coherent) already switched to the
	 * coherent plain-bio read for exactly both reasons.  Do the same
	 * here: PRIMARY = coherent plain-bio read (fast, and the view the
	 * B1/B2 guards should be deciding on); the old FUA read becomes the
	 * instr-gated secondary of the P103-FUA-DIVERGE detector, roles
	 * swapped, same print.
	 */
	if (mxfs_pal_bdev_read_plain_bdev(tp->bt_bdev, lba, tmp, blen) == 0) {
		const __u8 *dk = (const __u8 *)tmp + off * isize;

		if (be16_to_cpup((const __be16 *)dk) == MXFS_DINODE_MAGIC) {
			mode = be16_to_cpup((const __be16 *)(dk + 2));
			if (genp)
				*genp = be32_to_cpup((const __be32 *)(dk + 0x5c));
		}
	}

	tmp2 = unlikely(mxfs_instr_enabled) ? kmalloc(blen, GFP_NOFS) : NULL;
	if (tmp2) {
		uint16_t fmode = 0xFFFF;
		uint32_t fgen = 0;

		if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, lba, tmp2,
						blen) == 0) {
			const __u8 *fk = (const __u8 *)tmp2 + off * isize;

			if (be16_to_cpup((const __be16 *)fk) == MXFS_DINODE_MAGIC) {
				fmode = be16_to_cpup((const __be16 *)(fk + 2));
				fgen = be32_to_cpup(
					(const __be32 *)(fk + 0x5c));
			}
			if (fmode != mode ||
			    (genp && fgen != *genp)) {
				mxfs_probe_ratelimited(
					"mxfs: P103-FUA-DIVERGE ino=%llu agno=%u fua_mode=0%o fua_gen=%u coh_mode=0%o coh_gen=%u — FUA-platter disagrees with coherent SCST view\n",
					(unsigned long long)ino,
					(unsigned)agno,
					(unsigned)fmode, fgen,
					(unsigned)mode, genp ? *genp : 0);
			}
		}
		kfree(tmp2);
	}

	kfree(tmp);
	return mode;
}

/*
 * read the ON-DISK di_nlink of `ino` from the COHERENT
 * cluster view (plain bio -> SCST write-back cache under fua_disable=1; a FUA
 * read here would hit the stale platter and report a peer's freshly-linked inode
 * as nlink==0).  Used by the clustered destructive-inactivation guard's B3 check
 * to tell a torn/stale in-core copy of a peer's STILL-LINKED live inode
 * (coherent nlink>0 -> skip the destructive free) from a genuinely unlinked
 * inode pending free (nlink==0 -> proceed; covers survivor journal-replay
 * cleanup of a dead peer's unlinked inodes).  Returns the nlink, or 0xFFFFFFFF
 * on read/decode error (treated as "unknown" by the caller -> do not skip).
 * di_nlink is at dinode offset 0x10 (v3 inode core).
 */
uint32_t
mxfs_dbg_disk_di_nlink_coherent(struct xfs_mount *mp, xfs_ino_t ino)
{
	struct xfs_buftarg	*tp;
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;
	uint32_t		off, isize, blen;
	uint64_t		lba;
	void			*tmp;
	uint32_t		nlink = 0xFFFFFFFF;
	extern int		mxfs_pal_bdev_read_plain_bdev(struct block_device *,
					uint64_t, void *, unsigned int);

	if (!mp)
		return nlink;
	tp = mp->m_ddev_targp;
	if (!tp || !tp->bt_bdev)
		return nlink;
	agno = XFS_INO_TO_AGNO(mp, ino);
	agbno = XFS_INO_TO_AGBNO(mp, ino);
	off = XFS_INO_TO_OFFSET(mp, ino);
	isize = mp->m_sb.sb_inodesize;
	blen = mp->m_sb.sb_blocksize;
	if (isize < 256 || blen == 0 || (blen & 511) ||
	    off * isize + 0x40 > blen)
		return nlink;
	lba = (uint64_t)XFS_AGB_TO_DADDR(mp, agno, agbno) + tp->bt_sector_offset;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return nlink;
	if (mxfs_pal_bdev_read_plain_bdev(tp->bt_bdev, lba, tmp, blen) == 0) {
		const __u8 *dk = (const __u8 *)tmp + off * isize;

		if (be16_to_cpup((const __be16 *)dk) == MXFS_DINODE_MAGIC)
			nlink = be32_to_cpup((const __be32 *)(dk + 0x10));
	}
	kfree(tmp);
	return nlink;
}
EXPORT_SYMBOL(mxfs_dbg_disk_di_nlink_coherent);

/*
 * instrumented INODE-DOUBLE-ALLOC DETECTOR.  Read the
 * ON-DISK dinode of `ino` from the COHERENT cluster view (plain bio -> SCST
 * write-back cache; the same image a peer sees) and decode di_mode + di_gen.
 * Used at the inode-allocation site to PROVE design review's "inobt stale at release"
 * hypothesis: immediately after we carve `ino` out of the inobt as FREE, if the
 * coherent disk shows it is already a LIVE inode (mode != 0), a peer already
 * owns that inode number -> the inobt we read was stale -> same-chunk
 * double-allocation (the RELOAD-TYPEFLIP-STALE-SKIP / inobt-corruption root).
 * Returns:
 *   the di_mode (0 for a legitimately-free slot; non-zero = LIVE = double-alloc)
 *   0xFFFF on read error or missing "IN" magic (caller treats as "unknown").
 * Detector-only; no behavior change.
 */
/*
 * D-0947: THE SAME READ, WITH ITS TWO DISTINCT FAILURES SEPARATED.
 *
 * mxfs_dbg_disk_di_mode_coherent() returns 0xFFFF both when the home could not
 * be read AND when it was read perfectly well but holds no inode magic.  For a
 * detector that only printed the value those are interchangeable.  For the
 * inode allocator's candidate validator they are opposites: an unreadable home
 * is a reason to fail the create, while a home with no magic has simply never
 * had a dinode written to it -- which is the safest state a candidate can be
 * in, and is the ordinary state of every inode in a chunk this mount allocated
 * and has not destaged yet.  Conflating them failed 600 consecutive creates
 * with -EIO on a filesystem 7% full.
 *
 *   rc 0   the home was read; *modep and *genp are decoded when *has_magic,
 *          and *has_magic says whether an inode was ever written there;
 *   rc <0  the home could not be read at all, or the geometry is unusable.
 */
/*
 * D-0947 / D-0948 (instrumentation).
 *
 * HYPOTHESIS UNDER TEST: the read below is PLAIN, and on this shared LUN a
 * plain read may be served from a cache that still holds the block's PREVIOUS
 * contents.  If so, every verdict the inode allocator's candidate validator
 * reaches — no-magic, free, LIVE — is derived from a read that is not
 * coherent, which is exactly what this function's name claims it is.
 *
 * That one fact predicts all three observations the two defects rest on:
 *
 *   - 600 consecutive candidates reading "no inode magic" on a filesystem
 *     every one of whose carved chunks was FUA-written and read back OK
 *     (D-0947);
 *   - a home reading as XDD3 — the dir3 data block that PREVIOUSLY owned that
 *     exact address, self-identifying with that address in its own header —
 *     which is precisely what a stale cache of that block would return, on a
 *     filesystem whose free-space btrees chk_mxfs found self-consistent
 *     (D-0948);
 *   - the carve-time readback succeeding every time, because it runs on the
 *     node that has just written the block, whose cache is therefore warm.
 *
 * The discriminator is one extra read.  When the plain read reports no magic,
 * read the SAME LBA again through the SCSI READ(16)+FUA path the rest of MXFS
 * uses for coherency, and say whether the two disagree.  Strictly diagnostic:
 * the verdict handed back to the caller is unchanged, so a wrong hypothesis
 * costs a log line and nothing else.
 */
int mxfs_p949_plain_vs_fua = 1;
module_param_named(p949_plain_vs_fua, mxfs_p949_plain_vs_fua, int, 0644);
MODULE_PARM_DESC(p949_plain_vs_fua,
	"D-0947/D-0948: when a candidate inode home reads with no inode magic, "
	"re-read the same LBA with FUA and report what the home actually holds "
	"(1=on, diagnostic only, never changes the allocator's verdict)");

static char
mxfs_p949_pchar(__u8 c)
{
	return (c >= 0x20 && c < 0x7f) ? (char)c : '.';
}

static void
mxfs_p949_compare_fua(struct xfs_mount *mp, struct block_device *bdev,
		      uint64_t lba, uint32_t blen, uint32_t off, uint32_t isize,
		      xfs_ino_t ino, const void *plainblk)
{
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *, uint64_t,
					       void *, unsigned int);
	static atomic_t p949_agree = ATOMIC_INIT(0);
	const __u8	*pb = (const __u8 *)plainblk;
	const __u8	*pk = pb + off * isize;
	const __u8	*fb, *fk;
	void		*fua;
	int		frc;

	fua = kmalloc(blen, GFP_NOFS);
	if (!fua)
		return;
	frc = mxfs_pal_scsi_read_fua_bdev(bdev, lba, fua, blen);
	if (frc) {
		mxfs_probe_ratelimited("mxfs: P949-FUA-READ-FAIL ino=%llu lba=%llu rc=%d — the plain read said 'no inode magic' and the FUA re-read could not be issued, so the disagreement is untested at this home\n",
			(unsigned long long)ino, (unsigned long long)lba, frc);
		kfree(fua);
		return;
	}
	fb = (const __u8 *)fua;
	fk = fb + off * isize;
	if (be16_to_cpup((const __be16 *)fk) == MXFS_DINODE_MAGIC) {
		/*
		 * The plain read and the FUA read of the same LBA disagree.
		 * Loud and unbudgeted: a rate limit on the positive case is how
		 * a question like this stays open for another campaign.
		 */
		xfs_alert(mp,
"MXFS: P949-PLAIN-STALE ino=%llu lba=%llu — the PLAIN read of this home reports NO inode magic while a FUA read of the SAME LBA reports a dinode (mode=0%o gen=%u); the create-path candidate validator is deciding on a NON-COHERENT read. plain blk[0..3]=%02x%02x%02x%02x home[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
			  (unsigned long long)ino, (unsigned long long)lba,
			  be16_to_cpup((const __be16 *)(fk + 2)),
			  be32_to_cpup((const __be32 *)(fk + 0x5c)),
			  pb[0], pb[1], pb[2], pb[3],
			  pk[0], pk[1], pk[2], pk[3],
			  pk[4], pk[5], pk[6], pk[7]);
		kfree(fua);
		return;
	}
	/*
	 * Both reads agree that no dinode is here.  WHAT IS here decides which
	 * defect this is, and the two answers are far apart.
	 *
	 * All-zero is benign: a home in a carved chunk whose durable init did
	 * not land, holding nothing anybody owns.
	 *
	 * NON-ZERO is not.  The one captured instance of this held `58 44 44
	 * 33` — XDD3, a dir3 data block carrying THIS VERY BLOCK ADDRESS in its
	 * own header — and the eight FUA re-reads that followed all returned
	 * the same bytes and were logged `durable, not transient`.  So the
	 * medium really does hold directory metadata at a block the inode
	 * allocator believes is a free inode's home: an inobt chunk record and
	 * a live directory claiming the same blocks.  chk_mxfs calling the
	 * free-space btrees self-consistent does not contradict that — it never
	 * cross-checks inobt chunk blocks against allocated extents.
	 *
	 * Allocating there would write a dinode over live directory data, so
	 * this case is reported unbudgeted, with the bytes, every time.
	 */
	if (pb[0] | pb[1] | pb[2] | pb[3] | fb[0] | fb[1] | fb[2] | fb[3]) {
		xfs_alert(mp,
"MXFS: P949-HOME-FOREIGN ino=%llu lba=%llu — this home holds no dinode but is NOT empty, on BOTH a plain and a FUA read: the medium carries somebody else's metadata at a block the inode allocator believes is a free inode's home. plain blk[0..3]=%02x%02x%02x%02x ('%c%c%c%c') fua blk[0..3]=%02x%02x%02x%02x ('%c%c%c%c') fua home[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
			  (unsigned long long)ino, (unsigned long long)lba,
			  pb[0], pb[1], pb[2], pb[3],
			  mxfs_p949_pchar(pb[0]),
			  mxfs_p949_pchar(pb[1]),
			  mxfs_p949_pchar(pb[2]),
			  mxfs_p949_pchar(pb[3]),
			  fb[0], fb[1], fb[2], fb[3],
			  mxfs_p949_pchar(fb[0]),
			  mxfs_p949_pchar(fb[1]),
			  mxfs_p949_pchar(fb[2]),
			  mxfs_p949_pchar(fb[3]),
			  fk[0], fk[1], fk[2], fk[3],
			  fk[4], fk[5], fk[6], fk[7]);
	} else if (atomic_inc_return(&p949_agree) <= 16) {
		mxfs_probe("mxfs: P949-HOME-EMPTY ino=%llu lba=%llu — the plain AND the FUA read of this home agree it holds no dinode and its block is all zeroes; a carved chunk whose durable init did not land, owned by nobody\n",
			(unsigned long long)ino, (unsigned long long)lba);
	}
	kfree(fua);
}

int
mxfs_dbg_disk_di_read_coherent(struct xfs_mount *mp, xfs_ino_t ino,
			       uint16_t *modep, uint32_t *genp, bool *magicp)
{
	struct xfs_buftarg	*tp;
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;
	uint32_t		off, isize, blen;
	uint64_t		lba;
	void			*tmp;
	int			rc;
	extern int		mxfs_pal_bdev_read_plain_bdev(struct block_device *,
					uint64_t, void *, unsigned int);

	if (magicp)
		*magicp = false;
	if (!mp)
		return -EINVAL;
	tp = mp->m_ddev_targp;
	if (!tp || !tp->bt_bdev)
		return -EINVAL;
	agno = XFS_INO_TO_AGNO(mp, ino);
	agbno = XFS_INO_TO_AGBNO(mp, ino);
	off = XFS_INO_TO_OFFSET(mp, ino);
	isize = mp->m_sb.sb_inodesize;
	blen = mp->m_sb.sb_blocksize;
	if (isize < 256 || blen == 0 || (blen & 511) ||
	    off * isize + 0x60 > blen)
		return -EINVAL;
	lba = (uint64_t)XFS_AGB_TO_DADDR(mp, agno, agbno) + tp->bt_sector_offset;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	rc = mxfs_pal_bdev_read_plain_bdev(tp->bt_bdev, lba, tmp, blen);
	if (rc == 0) {
		const __u8 *dk = (const __u8 *)tmp + off * isize;

		if (be16_to_cpup((const __be16 *)dk) == MXFS_DINODE_MAGIC) {
			if (magicp)
				*magicp = true;
			if (modep)
				*modep = be16_to_cpup((const __be16 *)(dk + 2));
			if (genp)
				*genp = be32_to_cpup((const __be32 *)(dk + 0x5c));
		} else if (READ_ONCE(mxfs_p949_plain_vs_fua)) {
			mxfs_p949_compare_fua(mp, tp->bt_bdev, lba, blen, off,
					      isize, ino, tmp);
		}
	} else if (rc > 0) {
		rc = -EIO;
	}
	kfree(tmp);
	return rc;
}
EXPORT_SYMBOL(mxfs_dbg_disk_di_read_coherent);

uint16_t
mxfs_dbg_disk_di_mode_coherent(struct xfs_mount *mp, xfs_ino_t ino,
			       uint32_t *genp)
{
	uint16_t	mode = 0xFFFF;
	bool		magic = false;

	if (mxfs_dbg_disk_di_read_coherent(mp, ino, &mode, genp, &magic) || !magic)
		return 0xFFFF;
	return mode;
}
EXPORT_SYMBOL(mxfs_dbg_disk_di_mode_coherent);

/*
 * FUA-read the ON-DISK dinode of `ino` and decode its DATA-fork extent
 * map (EXTENTS format only).  Fills *sb0, *len0, *off0 with the first data extent
 * and *ndext with di_nextents, *fmt with di_format.  Lets the bnobt
 * double-free site (xfs_alloc.c:2244) decide WHICH side is wrong when a live
 * inode is being inactivated yet its block shows free in the bnobt:
 *   - disk extent map ALSO claims the freed block  => bnobt lost-update /
 *     cross-inode double-alloc (the free-space tree is wrong on disk).
 *   - disk extent map does NOT claim it (differs from in-core) => the IN-CORE
 *     inode extent map is STALE vs disk (inode-coherency: a peer reallocated
 *     this inode number with different extents and we never re-read).
 * Returns 0 on a clean decode (out params valid), <0 otherwise.
 */
int
mxfs_dbg_disk_di_first_dext(struct xfs_mount *mp, xfs_ino_t ino,
			    uint64_t *sb0, uint64_t *len0, uint64_t *off0,
			    uint64_t *ndext, uint8_t *fmt)
{
	struct xfs_buftarg	*tp;
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;
	uint32_t		off, isize, blen;
	uint64_t		lba;
	void			*tmp;
	int			rc = -1;
	extern int		mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					sector_t, void *, unsigned int);

	if (sb0) *sb0 = 0;
	if (len0) *len0 = 0;
	if (off0) *off0 = 0;
	if (ndext) *ndext = 0;
	if (fmt) *fmt = 0xFF;
	if (!mp)
		return rc;
	tp = mp->m_ddev_targp;
	if (!tp || !tp->bt_bdev)
		return rc;
	agno = XFS_INO_TO_AGNO(mp, ino);
	agbno = XFS_INO_TO_AGBNO(mp, ino);
	off = XFS_INO_TO_OFFSET(mp, ino);
	isize = mp->m_sb.sb_inodesize;
	blen = mp->m_sb.sb_blocksize;
	if (isize < 256 || blen == 0 || (blen & 511) ||
	    (uint64_t)off * isize + isize > blen)
		return rc;
	lba = (uint64_t)XFS_AGB_TO_DADDR(mp, agno, agbno) + tp->bt_sector_offset;
	tmp = kmalloc(blen, GFP_NOFS);
	if (!tmp)
		return rc;
	if (mxfs_pal_scsi_read_fua_bdev(tp->bt_bdev, lba, tmp, blen) == 0) {
		struct xfs_dinode *dip =
			(struct xfs_dinode *)((char *)tmp + (uint64_t)off * isize);

		if (be16_to_cpu(dip->di_magic) == MXFS_DINODE_MAGIC) {
			if (fmt)
				*fmt = dip->di_format;
			if (ndext)
				*ndext = (uint64_t)xfs_dfork_data_extents(dip);
			if (dip->di_format == XFS_DINODE_FMT_EXTENTS &&
			    xfs_dfork_data_extents(dip) > 0) {
				struct xfs_bmbt_irec	irec;
				xfs_bmbt_disk_get_all(
					(struct xfs_bmbt_rec *)
					XFS_DFORK_DPTR(dip), &irec);
				if (sb0) *sb0 = irec.br_startblock;
				if (len0) *len0 = irec.br_blockcount;
				if (off0) *off0 = irec.br_startoff;
			}
			rc = 0;
		}
	}
	kfree(tmp);
	return rc;
}
EXPORT_SYMBOL(mxfs_dbg_disk_di_first_dext);
