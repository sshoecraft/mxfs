// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode reload from the platter and incarnation poisoning
 */
#define MXFS_TU_ID 19	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * STRANDED-CLAIM DETECTOR.  A live release drain finishes in tens of ms
 * (measured: drain 22-23 ms, healthy claim age at the bail ~150 ms).  A claim
 * older than this at a demote-wait bail is not a drain in progress, it is a
 * claim nothing will clear.  Named once per inode via i_dlm_strand_named so the
 * flood of bails it causes cannot bury the one line that identifies it.
 */
int mxfs_demoter_strand_ms = 5000;
module_param_named(demoter_strand_ms, mxfs_demoter_strand_ms, int, 0644);
MODULE_PARM_DESC(demoter_strand_ms,
	"age (ms) at which a demoter claim seen from the reload demote-wait is reported as STRANDED (0=off)");

int mxfs_reload_demote_wait_ms = 50;
module_param_named(reload_demote_wait_ms, mxfs_reload_demote_wait_ms, int, 0644);
MODULE_PARM_DESC(reload_demote_wait_ms,
	"ms to wait for an active release drain before abandoning a reload (P34J); 0=bail immediately (pre-sess22)");

int mxfs_dir_epoch_adopt;	/* DEFAULT 0 (was 1). PROVEN REGRESSION: epoch_adopt=1 sets genuine_handoff=true, which BYPASSES the P33-DIRGROW-REVERT-SKIP / P43-FMTREVERT-SKIP guards (`if ((dg_inflight||dirty||grant_held) && !genuine_handoff)`) so mxfs_dlm_reload_inode runs xfs_idestroy_fork+xfs_inode_from_disk and ADOPTS a STALE-SMALLER disk dinode (our just-grown dir block not yet destaged) -> SHRINKS the in-core data fork -> a leaf-referenced logical block becomes DELAYSTARTBLOCK(-2)/hole -> xfs_dabuf_map !HOLE_OK (P21H-LEAFHOLE) AND xfs_free_ag_extent ltbno+ltlen>bno (AG double-free) -> FS SHUTDOWN. Only triggers under heavy cross-node handoff churn (8-node: deterministic shutdown ~round 10; 4-node clean). MEASURED: epoch_adopt=1 -> 8/tcp dir_reuse 0/8 SHUTDOWN; epoch_adopt=0 -> 8/8 PASS, 0 RDMISS, 0 shutdown (recovers the mht=300-masked working state). The reload now KEEPS the authoritative in-core fork when dirty/grant-held (correct: our committed-not-destaged grow is authoritative; disk lags). See `docs/history/8node-shutdown-is-agdoublefree-from-epochadopt-stale-reload.md` `docs/history/sess18run-milestone-8tcp-dirreuse-passes-correct-mht300-speed-only-residual.md`. */
module_param_named(dir_epoch_adopt, mxfs_dir_epoch_adopt, int, 0644);
int mxfs_dir_lower_block0_wins;	/* when 1, a block<->block same-incarnation reload REFUSES to adopt a disk block0 HIGHER than our in-core one (deterministic lowest-block0-wins dir-block0 convergence -> node1_f1 preserved). */
module_param_named(dir_lower_block0_wins, mxfs_dir_lower_block0_wins, int, 0644);

/* < > DEFAULT 0: the genuine_handoff legacy edge bit (P63-HANDOFF)
 * "forcing disk-superset adopt" re-introduced the 8/tcp DABUF_MAP_HOLE cascade
 * shutdown (it bypasses the P33/P43 keep-stale guards, adopting a torn/smaller
 * disk dinode that strands the cached leaf).  KEEPER (pre-edge-bit) had
 * ZERO shutdowns.  Off = conservative keep-stale guards own the reload; on =
 * legacy aggressive adopt.  Same family as dir_epoch_adopt (also default 0). */
int mxfs_dir_handoff_adopt = 1;
module_param_named(dir_handoff_adopt, mxfs_dir_handoff_adopt, int, 0644);
MODULE_PARM_DESC(dir_handoff_adopt,
	"Cross-node EX-handoff edge bit forces a disk-superset dir reload-adopt (1=default/original) or defers to the keep-stale guards (0). A/B lever; sess49 REFUTED it as the 8/tcp DABUF_MAP_HOLE cause (gating off left the cascade unchanged).");

int mxfs_reload_wtrylock_spin = 64;
module_param_named(reload_wtrylock_spin, mxfs_reload_wtrylock_spin, int, 0644);
MODULE_PARM_DESC(reload_wtrylock_spin,
                 "Max down_write_trylock attempts in the stale-inode reload "
                 "before deferring (default 64; legacy was 1000)");
/*
 * nlink LEDGER (see xfs_bumplink).  Prints the three points where a
 * directory's link count can move — bump (P180-NLB), reload adopt (P180-NLR),
 * platter publish (P180-NLW) — each with a wall-clock realns so all N nodes'
 * events merge into one ordered ledger.  Default OFF; diagnostic only.
 */
int mxfs_nlink_ledger;
module_param_named(nlink_ledger, mxfs_nlink_ledger, int, 0644);
MODULE_PARM_DESC(nlink_ledger,
		 "Log every directory link-count bump/adopt/publish with a "
		 "cross-node-orderable timestamp (0=off default)");

/* read-attribution probe: count COLD (bio-issued) reads
 * at the xfs_buf_submit_bio chokepoint, split by class, to attribute the
 * 32-node dlm_scaling AG0 inode-cluster read storm.  Gated on mxfs_read_attr_probe. */
int mxfs_read_attr_probe;
/* split reload_inode's cluster-stale by in-core mode to
 * test H1 — is the cache_coherency@32 storm dominated by mode==0 (self-recycle,
 * session-5-addressable) or mode!=0 (genuine peer reads, NOT addressed)?  Gated
 * on read_attr_probe. */
atomic64_t mxfs_reload_stale_mode0;	/* reload cluster-stale with in-core mode==0 */
atomic64_t mxfs_reload_stale_moden;	/* reload cluster-stale with in-core mode!=0 */
atomic64_t mxfs_reload_stale_ndir;	/* subset of moden that are directories */
int mxfs_reload_skip_owned;	/* skip reload stale when no cross-node EX handoff (see param below) */

/* keep VFS i_size on a kept-in-core reload
 * (reload_identical) instead of re-syncing it down to i_disk_size — the
 * re-sync severed a pending append whose setfilesize/unwritten-conversion
 * had not committed yet (drc@32 size=0/nx=0 loss).  PROVEN BY INSTRUMENT live on
 * test16 ino=16777344: reload state=ACQUIRING vfs=16384 disk=0 delayed=4
 * ident=1 keep=0 → revert → P-WU-CLAMP end=4096 vfs=0 2ms later → durable
 * sz=0 (= the drc r3 content mismatch).  keep=1: content 43/43 clean with
 * 5 severs averted.  DEFAULT 1. */
int mxfs_reload_size_keep = 1;
module_param_named(reload_size_keep, mxfs_reload_size_keep, int, 0644);

/* 32-node dir EX-loop root fix: when a handoff reload
 * finds the on-disk dinode IDENTICAL to in-core (di_changecount==i_version,
 * same di_gen/mode/format/nextents/size), skip the destructive fork
 * destroy+adopt — destroying an identical fork only unloads the extent map,
 * which escalates the next xfs_ilock_data_map_shared to ILOCK_EXCL -> DLM EX
 * and ignites a self-sustaining cluster-wide EX rotation on read-only lookups
 * (cache_coherency@32 rename-verify ~630ms/op, 0/32 at the 300s budget).
 * Freshness stamps still run, so the epoch gates converge as on a real adopt.
 * See mxfs_dlm_reload_inode.  Default 1; 0 = always-adopt (pre-sess8 A/B). */
int mxfs_reload_skip_identical = 1;
module_param_named(reload_skip_identical, mxfs_reload_skip_identical, int, 0644);
MODULE_PARM_DESC(reload_skip_identical,
	"skip reload fork destroy/adopt when on-disk dinode is identical to in-core (changecount+gen+fmt+nx+size); 1=on");

/*
 *  — OPTION B: ADOPT AT EX ACQUIRE (design-consult ruling,
 * D-DIRENT-PUBLISH-STALE-BASE-P195-360, gpt_ruling_sess44 in OPEN_DEFECTS).
 *
 * The P195 precursor state — a tenure mutating a dir base whose staleness
 * baselines were never established (valid_epoch=0, cached_gen=0, base_state=1
 * SEEN) — is closed at the AUTHORIZATION boundary instead of detected at the
 * operation boundary.  The contract:
 *
 *   gate      !i_dlm_base_valid                          (sentinel: no baseline)
 *          || i_dlm_dir_valid_epoch != grant_epoch       (!=, NOT >: CAW epochs
 *                                                         move backward across
 *                                                         slot reclamation; wrap/
 *                                                         reset must adopt too)
 *          || i_dlm_cached_grant_gen != grant_gen        (lock changed hands)
 *   arm       the SAME reload pipeline every proven armer uses (P63/gg_refresh):
 *             dir_ex_stale_refresh + dir_ex_handoff -> mxfs_dlm_reload_inode
 *             post_release=true; its keep-guards (P3 changecount time-travel,
 *             P33/P43, P177 obligation merge, P34J demote-wait) stay the
 *             authority on WHETHER the disk image is installed.
 *   stamp     ONLY after the adopt/keep decision is final (reload install
 *             point), via mxfs_dir_base_stamp: WRITE_ONCE epoch+gen, then
 *             smp_store_release(valid=1).  A keep-guard bail stamps nothing —
 *             valid stays 0, so the gate re-fires (level-held retry).
 *   invalidate mxfs_dir_base_invalidate at: EX release/demote drain
 *             (mxfs_dlm_bast_process, before the wire unlock — a same-epoch
 *             re-grant must never skip a needed adopt), phantom-EX bail,
 *             reload commit-to-adopt (aborted install leaves invalid), inode
 *             init/reuse.
 *   dirty     NEVER adopt over this tenure's own dirty state: an armer that
 *             finds dirty_here counts P216-B-DIRTY-SKIP and leaves valid=0
 *             (fail-closed; the write-side backstops reconcile, proven
 *             loss-free by the recalibration).
 *   creator   the publish stamp (first real EX grant of a self-created dir) is
 *             SUBORDINATED to this machinery: with the gate on it always runs
 *             through mxfs_dir_base_stamp (mxfs.creator_baseline_stamp becomes
 *             a legacy A/B lever for the gate-off arm only).  Without it a
 *             fresh publish would read valid=0 at its first fast-path serve
 *             and adopt a not-yet-destaged disk image over the live create.
 */
int mxfs_dir_adopt_at_acquire = 1;
module_param_named(dir_adopt_at_acquire, mxfs_dir_adopt_at_acquire, int, 0644);
MODULE_PARM_DESC(dir_adopt_at_acquire,
	"close P195 at the dir-EX authorization boundary: adopt the disk base when the validity-bit/epoch/grant-gen gate fires, stamp only after install; 0=pre-fix sentinels (A/B)");

/* (design review attribution step 2, D-RSYNC-RENAME-DIRTY-CANCEL-361): micro-
 * revert lever for the ONE unconditional timing change this rework made —
 * the reload's baseline stamp moved from the commit point (pre-install) to
 * the install-complete point.  1 = stamp at the COMMIT point again (the
 * pre-sess45 window shape) so lap A/Bs can separate "stamp relocation as
 * amplifier" from the pre-existing stale-base producer without a binary
 * rollback.  Values stamped are identical in both positions. */
int mxfs_reload_stamp_at_commit;
module_param_named(reload_stamp_at_commit, mxfs_reload_stamp_at_commit, int, 0644);
MODULE_PARM_DESC(reload_stamp_at_commit,
	"stamp the dir-base baseline at the reload commit point (pre-install, pre-sess45 timing) instead of install-complete; 0=install-complete (default)");

/*  — P193: let the dir-EPOCH signal override
 * P6-MIDTENURE-RELOAD-SKIP (see mxfs_dlm_reload_inode).  P6 assumes "no peer
 * can have written since the tenure began"; the epoch is direct proof that one
 * has.  0 = pre-fix precedence for A/B. */
int mxfs_p6_epoch_override = 1;
module_param_named(p6_epoch_override, mxfs_p6_epoch_override, int, 0644);
MODULE_PARM_DESC(p6_epoch_override,
	"P65 dir-epoch staleness overrides the P6 mid-tenure reload skip; 1=on");

/* D-0973: the reload evicts cached bmbt blocks for a regular file's BTREE
 * data fork as well as a directory's.  0 restores directory-only eviction,
 * the A/B arm that isolates the inode flush's unread-fork guard. */
int mxfs_reload_evict_file_bmbt = 1;
module_param_named(reload_evict_file_bmbt, mxfs_reload_evict_file_bmbt, int, 0644);
MODULE_PARM_DESC(reload_evict_file_bmbt,
	"evict a regular file's cached bmbt blocks when a reload adopts a peer's dinode; 1=on, 0=directories only (A/B)");
/*
 * < > WRITE-SIDE TRIPWIRE (instrumented): the 8/tcp dir_reuse shutdown is
 * a DELAYSTARTBLOCK(-2) extent appearing in the DATA fork of dir inode 131 that
 * the leaf then references (xfs_dabuf_map !HOLE_OK shutdown).  A directory must
 * NEVER carry a delalloc extent (dir blocks are XFS_BMAPI_METADATA, allocated
 * immediately).  This helper scans a dir inode's data fork for any
 * DELAYSTARTBLOCK extent and, on the first sighting, logs the full extent shape
 * + a stack trace so the creating path is localized.  Cheap (in-core walk, no
 * I/O, no lock); fires once globally then rate-limits.  Returns the count of
 * delalloc extents found.
 */
int
mxfs_dir_delalloc_tripwire(struct xfs_inode *ip, const char *site)
{
	struct xfs_ifork	*ifp;
	struct xfs_bmbt_irec	rec;
	struct xfs_iext_cursor	cur;
	int			dcount = 0;
	int			k = 0;
	static atomic_t		fired = ATOMIC_INIT(0);

	if (!ip || !S_ISDIR(VFS_I(ip)->i_mode))
		return 0;
	if (ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    ip->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return 0;
	if (xfs_need_iread_extents(&ip->i_df))
		return 0;	/* extents not in core; do not force a read */

	ifp = &ip->i_df;
	{
		/* Detect a GAP in the data region (offsets below the leaf region
		 * XFS_DIR2_LEAF_OFFSET): consecutive data extents that skip a
		 * logical block.  A create-only dir never legitimately has a gap;
		 * a gap = the torn extent map that strands the leaf (the 8/tcp
		 * DABUF_MAP_HOLE root, PROVEN DISK-TORN). */
		xfs_fileoff_t leafoff = 0;
		xfs_fileoff_t prev_end = 0;
		bool first = true;
		int gap = 0;
		if (ip->i_mount && ip->i_mount->m_dir_geo)
			leafoff = ip->i_mount->m_dir_geo->leafblk;
		for (xfs_iext_first(ifp, &cur);
		     xfs_iext_get_extent(ifp, &cur, &rec);
		     xfs_iext_next(ifp, &cur)) {
			if (isnullstartblock(rec.br_startblock))
				dcount++;
			if (leafoff && rec.br_startoff < leafoff) {
				if (!first && rec.br_startoff > prev_end)
					gap++;
				prev_end = rec.br_startoff + rec.br_blockcount;
				first = false;
			}
		}
		dcount += gap * 1000;	/* encode gap count in the high digits */
	}
	if (dcount == 0)
		return 0;

	if (atomic_inc_return(&fired) <= 12) {
		mxfs_probe("mxfs: P-DIR-DELALLOC-TRIP site=%s ino=%llu fmt=%u nextents=%llu disize=%lld dlm_mode=%u dir_gen=%llu loaded_gen=%llu delalloc+gapx1000=%d comm=%s\n",
			site, (unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			(unsigned long long)ip->i_df.if_nextents,
			(long long)ip->i_disk_size, ip->i_dlm_mode,
			(unsigned long long)ip->i_dlm_dir_gen,
			(unsigned long long)ip->i_dlm_dir_loaded_gen,
			dcount, current->comm);
		for (xfs_iext_first(ifp, &cur);
		     xfs_iext_get_extent(ifp, &cur, &rec);
		     xfs_iext_next(ifp, &cur)) {
			mxfs_probe("mxfs:   DELALLOC-TRIP rec[%d] off=%llu blk=%lld len=%llu state=%d%s\n",
				k++, (unsigned long long)rec.br_startoff,
				(long long)rec.br_startblock,
				(unsigned long long)rec.br_blockcount,
				rec.br_state,
				isnullstartblock(rec.br_startblock) ?
					" <<DELALLOC" : "");
		}
		mxfs_probe_stack();
	}
	return dcount;
}

/*
 * < > DECISIVE disk-vs-incore extent probe (instrumented): at a dir
 * DABUF_MAP_HOLE, FUA-read the on-disk inode cluster (pierces every cache) and
 * dump BOTH the durable on-disk extent list AND whether the requested block is
 * mapped on disk.  This settles disk-torn (the gap is durable on the platter ->
 * a node wrote a dir dinode/bmbt missing block N's extent -> WRITE-side fix) vs
 * in-core-torn (disk maps block N fine, only the in-core map dropped it ->
 * reload/evict/flush corrupted in-core -> READ-side fix).  Capped global; gated
 * to the test dir (ino<=256) to bound the FUA traffic.
 */
/* iversion accessor for libxfs probe sites that
 * cannot include <linux/iversion.h> cleanly (P14-DABUF-HOLE). */
u64
mxfs_vfs_inode_iversion(struct inode *vip)
{
	return inode_peek_iversion(vip);
}
EXPORT_SYMBOL(mxfs_vfs_inode_iversion);

/*
 * P242 — EX-EPOCH CHURN TRIPWIRE (instrumented, classifier
 * round 2).  The cluster-merge mask trusts same-tenure provenance
 * (i_mxfs_dirty_seq == i_mxfs_ex_grant_seq); the 297 P239 classifier
 * measured 9 EX-held condemnations with icc>pcc — the mask predicate went
 * stale while the grant never left, exactly the false-positive class
 * consult #3 said must be rooted before any fatal tripwire.  Every site
 * that bumps i_mxfs_ex_grant_seq calls this FIRST: if the inode still has
 * open publication obligations (flush != durable) or a dirty log item,
 * the bump strands that state under a dead epoch and the next merge will
 * condemn it.  The print names the bump site (line), the mode it fired
 * under, and both sequence pairs — the direct evidence for which arm
 * (mid-tenure churn vs dirty-across-release) produces the class.
 */
void
mxfs_ex_epoch_churn_check(struct xfs_inode *ip, int line)
{
	u64 f, d;
	unsigned int fields;

	if (!ip || ip->i_mxfs_dirty_seq == 0)
		return;
	f = READ_ONCE(ip->i_mxfs_pub_flush_seq);
	d = READ_ONCE(ip->i_mxfs_pub_durable_seq);
	fields = ip->i_itemp ? READ_ONCE(ip->i_itemp->ili_fields) : 0;
	if (f == d && !fields)
		return;
	mxfs_probe_ratelimited(
	    "mxfs: P242-EPOCH-CHURN ino=%llu line=%u:%u mode=%u ds=%llu gs=%llu flush=%llu dur=%llu pend=%llu fields=0x%x — EX epoch bumping over open obligations; still-dirty state becomes foreign to the merge mask\n",
		(unsigned long long)ip->i_ino, MXFS_SITE_ARGS(line),
		(unsigned)ip->i_dlm_mode,
		(unsigned long long)ip->i_mxfs_dirty_seq,
		(unsigned long long)ip->i_mxfs_ex_grant_seq,
		(unsigned long long)f, (unsigned long long)d,
		(unsigned long long)READ_ONCE(ip->i_mxfs_pub_pending_seq),
		fields);
}

void
mxfs_dir_hole_disk_probe(struct xfs_inode *ip, xfs_fileoff_t want_bno)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_dinode	*fdip;
	void			*cbuf;
	uint32_t		clen, dsize;
	uint64_t		lba;
	int			rrc, i, disk_nx;
	bool			disk_maps_want = false;
	char			*recs;
	struct xfs_bmbt_irec	*xmap;		/* 64 entries; 1.5 KB off the stack */
	static atomic_t		fired = ATOMIC_INIT(0);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev,
					       uint64_t lba_512, void *buf,
					       uint32_t len);

	/* ungated from ino<=256 — every run's test
	 * dirs land at high inos (4194436, 52953221, 41943172...) and the
	 * probe never fired when it mattered.  The atomic cap bounds cost. */
	if (!ip || !S_ISDIR(VFS_I(ip)->i_mode))
		return;
	if (atomic_inc_return(&fired) > 10)
		return;

	clen = (uint32_t)ip->i_imap.im_len << BBSHIFT;
	cbuf = kmalloc(clen, GFP_NOFS);
	if (!cbuf)
		return;
	lba = (uint64_t)ip->i_imap.im_blkno + mp->m_ddev_targp->bt_sector_offset;
	rrc = mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba, cbuf,
					 clen);
	if (rrc != 0) {
		mxfs_probe("mxfs: P-HOLE-DISK ino=%llu want_bno=%llu FUA_READ_FAILED rc=%d\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)want_bno, rrc);
		kfree(cbuf);
		return;
	}
	fdip = (struct xfs_dinode *)((char *)cbuf + ip->i_imap.im_boffset);
	dsize = xfs_dinode_size(fdip->di_version);
	disk_nx = (be64_to_cpu(fdip->di_flags2) & XFS_DIFLAG2_NREXT64) ?
		(int)be64_to_cpu(fdip->di_big_nextents) :
		(int)be32_to_cpu(fdip->di_nextents);

	mxfs_probe("mxfs: P-HOLE-DISK ino=%llu want_bno=%llu disk_magic=0x%04x disk_fmt=%u disk_nx=%d disk_size=%lld disk_gen=%u incore_nx=%llu incore_gen=%u\n",
		(unsigned long long)ip->i_ino, (unsigned long long)want_bno,
		be16_to_cpu(fdip->di_magic), fdip->di_format, disk_nx,
		(long long)be64_to_cpu(fdip->di_size),
		be32_to_cpu(fdip->di_gen),
		(unsigned long long)ip->i_df.if_nextents,
		VFS_I(ip)->i_generation);

	/* Decode the on-disk inline extent records (EXTENTS format) and report
	 * whether block want_bno is durably mapped on the platter. */
	if (fdip->di_format == XFS_DINODE_FMT_EXTENTS && disk_nx > 0 &&
	    disk_nx <= 64) {
		recs = (char *)fdip + dsize;
		for (i = 0; i < disk_nx; i++) {
			struct xfs_bmbt_irec	r;
			xfs_bmbt_disk_get_all((struct xfs_bmbt_rec *)
					      (recs + i * sizeof(struct xfs_bmbt_rec)),
					      &r);
			if (want_bno >= r.br_startoff &&
			    want_bno < r.br_startoff + r.br_blockcount &&
			    !isnullstartblock(r.br_startblock))
				disk_maps_want = true;
			mxfs_probe("mxfs:   P-HOLE-DISK rec[%d] off=%llu blk=%lld len=%llu state=%d\n",
				i, (unsigned long long)r.br_startoff,
				(long long)r.br_startblock,
				(unsigned long long)r.br_blockcount, r.br_state);
		}
		mxfs_probe("mxfs: P-HOLE-DISK ino=%llu want_bno=%llu DISK_MAPS_WANT=%d => %s\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)want_bno, disk_maps_want ? 1 : 0,
			disk_maps_want ? "IN-CORE-TORN (disk has the block; in-core map dropped it)"
				       : "DISK-TORN (durable gap: the platter dinode itself lacks block's extent)");
	}

	/*
	 * LEAF-vs-MAP PLATTER CONSISTENCY SCAN (instrumented).
	 * The current failing composition (run 053633Z, test3 ino 41943172
	 * bno=43 dlm_mode=PR): a grant-fresh 18-extent map coexists with LEAF
	 * content referencing dablk 43 which the map lacks.  Two roots need
	 * OPPOSITE fixes and this measurement discriminates:
	 *   - The ON-PLATTER leaf also references holes of the ON-PLATTER map
	 *     => the last EX holder destaged a TORN (map, structure) pair —
	 *     writer-side ordering bug.
	 *   - The platter pair is self-consistent => the WALKER used a stale
	 *     CACHED leaf despite gen freshness — reader-side cache leak.
	 * Decode the raw dinode's extent map (EXTENTS inline; BTREE via one
	 * raw read of the single level-0 bmbt child), then raw-read every
	 * LEAF-region dir block and the first FREE block and count references
	 * into map holes.  All reads are raw plain-bdev (coherent SCST cache),
	 * bounded (<=16 extents walked, <=8 dir blocks read).
	 */
	xmap = kmalloc_array(64, sizeof(*xmap), GFP_NOFS);
	if (xmap) {
		int			nmap = 0;
		int			fmt = fdip->di_format;

		if (fmt == XFS_DINODE_FMT_EXTENTS && disk_nx > 0 &&
		    disk_nx <= 64) {
			recs = (char *)fdip + dsize;
			for (i = 0; i < disk_nx; i++)
				xfs_bmbt_disk_get_all((struct xfs_bmbt_rec *)
					(recs + i * sizeof(struct xfs_bmbt_rec)),
					&xmap[nmap++]);
		} else if (fmt == XFS_DINODE_FMT_BTREE && disk_nx > 0 &&
			   disk_nx <= 64) {
			struct xfs_bmdr_block *dfp = (struct xfs_bmdr_block *)
				((char *)fdip + dsize);
			int dmxr = xfs_bmdr_maxrecs(XFS_DFORK_DSIZE(fdip, mp),
						    false);

			/* unconditional entry print — run
			 * 060826Z had fmt=3 headers with ZERO btree-branch
			 * output, which is unreachable by this control flow;
			 * this settles whether the branch executes at all. */
			mxfs_probe("mxfs: P-HOLE-DISK ino=%llu btree_enter level=%u numrecs=%u dmxr=%d dsize_off=%u\n",
				(unsigned long long)ip->i_ino,
				be16_to_cpu(dfp->bb_level),
				be16_to_cpu(dfp->bb_numrecs), dmxr,
				(unsigned)dsize);
			if (be16_to_cpu(dfp->bb_level) == 1 &&
			    be16_to_cpu(dfp->bb_numrecs) == 1 && dmxr > 0) {
				xfs_fsblock_t cfsb = be64_to_cpu(
					*xfs_bmdr_ptr_addr(dfp, 1, dmxr));
				if (xfs_verify_fsbno(mp, cfsb)) {
					uint64_t blba =
						(uint64_t)XFS_FSB_TO_DADDR(mp, cfsb) +
						mp->m_ddev_targp->bt_sector_offset;
					void *lb = kmalloc(mp->m_sb.sb_blocksize,
							   GFP_NOFS);
					int lrc = lb ? mxfs_pal_bdev_read_plain_bdev(
						mp->m_ddev_targp->bt_bdev,
						blba, lb, mp->m_sb.sb_blocksize) : -ENOMEM;

					/* plain-bio read returned -22
					 * (EINVAL from submit_bio_wait) for
					 * every bmbt child on run 065143Z —
					 * fall back to the READ(16) FUA
					 * passthrough that the inode-cluster
					 * read above uses successfully. */
					if (lrc != 0 && lb) {
						int frc =
						  mxfs_pal_scsi_read_fua_bdev(
							mp->m_ddev_targp->bt_bdev,
							blba, lb, mp->m_sb.sb_blocksize);
						mxfs_probe("mxfs: P-HOLE-DISK ino=%llu raw_bmbt_fallback plain_rc=%d fua_rc=%d lba=%llu len=%u\n",
							(unsigned long long)ip->i_ino,
							lrc, frc,
							(unsigned long long)blba,
							(unsigned)mp->m_sb.sb_blocksize);
						if (frc == 0)
							lrc = 0;
					}
					if (lrc == 0) {
						struct xfs_btree_block *cb = lb;
						int nr = be16_to_cpu(cb->bb_numrecs);

						for (i = 0; i < nr && nmap < 64; i++)
							xfs_bmbt_disk_get_all(
								xfs_bmbt_rec_addr(mp, cb, 1 + i),
								&xmap[nmap++]);
						mxfs_probe("mxfs: P-HOLE-DISK ino=%llu raw_bmbt daddr=%lld numrecs=%d lsn=%llu\n",
							(unsigned long long)ip->i_ino,
							(long long)XFS_FSB_TO_DADDR(mp, cfsb),
							nr,
							(unsigned long long)be64_to_cpu(cb->bb_u.l.bb_lsn));
					} else {
						mxfs_probe("mxfs: P-HOLE-DISK ino=%llu raw_bmbt_read_fail rc=%d\n",
							(unsigned long long)ip->i_ino,
							lrc);
					}
					kfree(lb);
				} else {
					mxfs_probe("mxfs: P-HOLE-DISK ino=%llu bad_bmbt_ptr cfsb=%lld\n",
						(unsigned long long)ip->i_ino,
						(long long)cfsb);
				}
			}
			/* DISK_MAPS_WANT verdict for BTREE too (the
			 * inline verdict above is EXTENTS-only, so every
			 * fmt=3 failure shipped without the disk-vs-incore
			 * discrimination it was built for). */
			if (nmap > 0) {
				bool bt_maps = false;

				for (i = 0; i < nmap; i++)
					if (want_bno >= xmap[i].br_startoff &&
					    want_bno < xmap[i].br_startoff +
						       xmap[i].br_blockcount &&
					    !isnullstartblock(
						xmap[i].br_startblock)) {
						bt_maps = true;
						break;
					}
				mxfs_probe("mxfs: P-HOLE-DISK ino=%llu want_bno=%llu DISK_MAPS_WANT=%d => %s\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)want_bno,
					bt_maps ? 1 : 0,
					bt_maps ? "IN-CORE-TORN (disk has the block; in-core map dropped it)"
						: "DISK-TORN (durable gap: the platter dinode itself lacks block's extent)");
			}
		}

		if (nmap > 0 && mp->m_dir_geo) {
			xfs_fileoff_t	leafblk = mp->m_dir_geo->leafblk;
			xfs_fileoff_t	freeblk = mp->m_dir_geo->freeblk;
			int		li, holes_ref = 0, ok_ref = 0,
					blocks_read = 0;

			for (li = 0; li < nmap && blocks_read < 8; li++) {
				xfs_fileoff_t	off = xmap[li].br_startoff;
				xfs_filblks_t	len = xmap[li].br_blockcount;
				xfs_fileoff_t	b;

				if (off + len <= leafblk || off >= freeblk)
					continue;	/* data or free region */
				for (b = (off < leafblk ? leafblk : off);
				     b < off + len && blocks_read < 8; b++) {
					void *dbuf = kmalloc(mp->m_sb.sb_blocksize,
							     GFP_NOFS);
					xfs_daddr_t dd = XFS_FSB_TO_DADDR(mp,
						xmap[li].br_startblock +
						(b - off));

					if (!dbuf)
						break;
					/* plain-bio read EINVALs on
					 * this stack (see raw_bmbt_fallback);
					 * FUA READ(16) passthrough works. */
					if (mxfs_pal_bdev_read_plain_bdev(
						mp->m_ddev_targp->bt_bdev,
						(uint64_t)dd +
						mp->m_ddev_targp->bt_sector_offset,
						dbuf, mp->m_sb.sb_blocksize) == 0 ||
					    mxfs_pal_scsi_read_fua_bdev(
						mp->m_ddev_targp->bt_bdev,
						(uint64_t)dd +
						mp->m_ddev_targp->bt_sector_offset,
						dbuf, mp->m_sb.sb_blocksize) == 0) {
						struct xfs_dir3_icleaf_hdr lh;
						struct xfs_dir2_leaf_entry *ents;
						int e;
						uint16_t lmag = be16_to_cpu(
							((struct xfs_da3_blkinfo *)
							 dbuf)->hdr.magic);

						/* skip da3 NODE blocks
						 * (child ptrs are not dataptrs
						 * — the ghost_db=16384
						 * artifact). */
						if (lmag != XFS_DIR3_LEAF1_MAGIC &&
						    lmag != XFS_DIR3_LEAFN_MAGIC) {
							kfree(dbuf);
							continue;
						}

						blocks_read++;
						xfs_dir2_leaf_hdr_from_disk(
							mp, &lh, dbuf);
						ents = lh.ents;
						for (e = 0; ents &&
						     e < lh.count; e++) {
							uint32_t addr = be32_to_cpu(
								ents[e].address);
							xfs_dir2_db_t db;
							int k;
							bool mapped = false;

							if (addr == cpu_to_be32(
							    XFS_DIR2_NULL_DATAPTR) ||
							    addr == 0xffffffff)
								continue;
							db = xfs_dir2_dataptr_to_db(
								mp->m_dir_geo, addr);
							for (k = 0; k < nmap; k++)
								if ((xfs_fileoff_t)db >=
								    xmap[k].br_startoff &&
								    (xfs_fileoff_t)db <
								    xmap[k].br_startoff +
								    xmap[k].br_blockcount) {
									mapped = true;
									break;
								}
							if (mapped)
								ok_ref++;
							else
								holes_ref++;
						}
					}
					kfree(dbuf);
				}
			}
			mxfs_probe("mxfs: P-HOLE-DISK ino=%llu PLATTER-SCAN nmap=%d leaf_blocks_read=%d refs_ok=%d refs_into_holes=%d => %s\n",
				(unsigned long long)ip->i_ino, nmap,
				blocks_read, ok_ref, holes_ref,
				holes_ref ? "PLATTER-TORN (writer destaged leaf referencing unmapped dablks)"
					  : "PLATTER-CONSISTENT (walker used a stale CACHED structure block)");
		}
	}
	kfree(xmap);
	kfree(cbuf);
}

/*
 *  — P-DACRC: fires at the INSTANT a multinode da3-node
 * read fails its CRC (the crash_consistency torn-read killer: 2 events/run,
 * each failing the EX holder's creates -> ~42 durably missing files).  While
 * the evidence is live, classify the failure:
 *  - lineage crc (crc32c past the 48-byte header, the SAME key P-DIRWR stamps
 *    on every write) of the FAILING image -> match it against the merged
 *    P-DIRWR timeline to name the two writes whose mix it is;
 *  - per-sector crcs -> the exact sector interleave signature;
 *  - an immediate plain-bio re-read (SCST cache view) and FUA re-read
 *    (platter view) of the same daddr with their lineage crcs -> torn ON THE
 *    LUN (both re-reads also mixed) vs torn IN FLIGHT (re-reads clean) vs
 *    cache/platter divergence (plain != fua).
 * Runs in the read-ioend worker (process ctx); capped; multinode only.
 */
void
mxfs_danode_crcfail_probe(struct xfs_buf *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_da3_blkinfo	*bi;
	uint32_t		len, secrc[8];
	uint64_t		lba;
	void			*pl, *fu;
	int			i, nsec, prc = -ENOMEM, frc = -ENOMEM;
	static atomic_t		fired = ATOMIC_INIT(0);
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);

	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!bp->b_addr || bp->b_map_count != 1 || !bp->b_target ||
	    !bp->b_target->bt_bdev)
		return;
	if (atomic_inc_return(&fired) > 16)
		return;

	bi = bp->b_addr;
	len = BBTOB(bp->b_length);
	nsec = min_t(int, len >> 9, 8);
	for (i = 0; i < nsec; i++)
		secrc[i] = crc32c(0, (char *)bp->b_addr + (i << 9), 512);
	mxfs_probe("mxfs: P-DACRC daddr=%lld len=%u magic=0x%04x owner=%llu embcrc=0x%08x lincrc=0x%08x sec=[%08x %08x %08x %08x %08x %08x %08x %08x] comm=%s realns=%llu\n",
		(long long)bp->b_maps[0].bm_bn, len,
		be16_to_cpu(bi->hdr.magic),
		(unsigned long long)be64_to_cpu(bi->owner),
		be32_to_cpu(bi->crc),
		crc32c(0, (char *)bp->b_addr + 48, len - 48),
		secrc[0], secrc[1], secrc[2], secrc[3],
		secrc[4], secrc[5], secrc[6], secrc[7],
		current->comm,
		(unsigned long long)ktime_get_real_ns());

	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	pl = kmalloc(len, GFP_NOFS);
	fu = kmalloc(len, GFP_NOFS);
	if (pl)
		prc = mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
						    lba, pl, len);
	if (fu)
		frc = mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev,
						  lba, fu, len);
	mxfs_probe("mxfs: P-DACRC-RAW daddr=%lld plain_rc=%d plain_magic=0x%04x plain_lincrc=0x%08x plain_eq_buf=%d fua_rc=%d fua_magic=0x%04x fua_lincrc=0x%08x fua_eq_plain=%d realns=%llu\n",
		(long long)bp->b_maps[0].bm_bn,
		prc,
		(prc == 0 && pl) ?
			be16_to_cpu(((struct xfs_da3_blkinfo *)pl)->hdr.magic) : 0,
		(prc == 0 && pl) ? crc32c(0, (char *)pl + 48, len - 48) : 0,
		(prc == 0 && pl &&
		 memcmp(pl, bp->b_addr, len) == 0) ? 1 : 0,
		frc,
		(frc == 0 && fu) ?
			be16_to_cpu(((struct xfs_da3_blkinfo *)fu)->hdr.magic) : 0,
		(frc == 0 && fu) ? crc32c(0, (char *)fu + 48, len - 48) : 0,
		(prc == 0 && frc == 0 && pl && fu &&
		 memcmp(pl, fu, len) == 0) ? 1 : 0,
		(unsigned long long)ktime_get_real_ns());
	kfree(pl);
	kfree(fu);
}

static void
mxfs_incarn_revoke_work_fn(
	struct work_struct	*work)
{
	struct mxfs_incarn_revoke *rv =
		container_of(work, struct mxfs_incarn_revoke, work);
	struct xfs_inode	*ip = rv->ip;
	struct inode		*vi = VFS_I(ip);

	xfs_ilock(ip, XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL);
	xfs_iflags_set(ip, MXFS_IF_INCARN_STALE);
	if (S_ISREG(vi->i_mode)) {
		unmap_mapping_range(vi->i_mapping, 0, 0, 1);
		truncate_inode_pages(vi->i_mapping, 0);
	}
	xfs_iunlock(ip, XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL);
	pr_warn_ratelimited(
		"mxfs: P34H-INCARN-REVOKED ino=%llu gen=%u i_count=%d nrpages=%lu — dead-incarnation mappings zapped, page cache discarded\n",
		(unsigned long long)ip->i_ino, vi->i_generation,
		atomic_read(&vi->i_count), vi->i_mapping->nrpages);
	d_mark_dontcache(vi);
	d_prune_aliases(vi);
	/*
	 * The reference this worker owns is about to go.  If the inode is
	 * already being freed, someone else dropped it: say so with the
	 * state that proves it, before iput trips its BUG on a cleared inode.
	 */
	{
		unsigned long st = mxfs_istate(vi);
		int cnt = atomic_read(&vi->i_count);

		if (cnt < 1 || (st & (I_FREEING | I_CLEAR | I_WILL_FREE)))
			pr_warn("mxfs: P-REVOKE-REF-LOST ino=%llu gen=%u i_count=%d i_state=0x%lx revoke_refs=%d — the revocation's own reference is gone before its release\n",
				(unsigned long long)ip->i_ino, vi->i_generation,
				cnt, st, atomic_read(&ip->i_mxfs_revoke_refs));
	}
	atomic_dec(&ip->i_mxfs_revoke_refs);
	xfs_irele(ip);
	kfree(rv);
}

/*
 * TEST ONLY — the A/B control for the uninserted-poison fix below: 1 restores
 * the pre-0.89.75 behaviour (igrab + queue a revocation even on an object
 * that is not the cache's inode for its number), so the defect and the fix
 * are measured against each other in one build and one boot.  0 (default)
 * is the fix.
 */
static int mxfs_poison_uninserted_legacy;
module_param_named(poison_uninserted_legacy, mxfs_poison_uninserted_legacy,
		   int, 0644);
MODULE_PARM_DESC(poison_uninserted_legacy,
	"TEST: 1 = queue a revocation even for an uninserted poisoned inode (pre-0.89.75 control arm); 0 = fixed (default)");

void
mxfs_incarn_poison(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct mxfs_incarn_revoke *rv;
	bool			queued = false;

	xfs_iflags_set(ip, MXFS_IF_INCARN_STALE);
	/*
	 * (D-0941): count poisonings HERE rather than at the call
	 * sites.  The per-site P34H-INCARN-POISON lines are pr_warn_ratelimited,
	 * so their count saturates at the ratelimit burst -- one failing lap
	 * printed exactly 10, which is DEFAULT_RATELIMIT_BURST, and reading that
	 * as "10 inodes were poisoned" would have been wrong.  The fix for the
	 * unretireable-shell defect is verified by the RATIO of poisonings to
	 * retirement failures, so the numerator has to be a real count.  Capped
	 * printing, uncapped counter, and every line carries the running total.
	 */
	{
		static atomic_t np = ATOMIC_INIT(0);
		int n = atomic_inc_return(&np);

		if (n <= 4000)
			pr_warn("mxfs: P566-POISON-N ino=%llu gen=%u total=%d — shell poisoned; a revocation is about to be queued holding a reference\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation, n);
	}
	/*
	 * Is this object the cache's inode for its number?  A reload inside
	 * xfs_iget_cache_miss runs before the radix insert, and that
	 * function's error exit frees the inode directly, ignoring i_count —
	 * so a revocation queued on an uninserted object outlives it, and the
	 * worker then locks, prunes and releases freed memory: measured as a
	 * page fault in d_mark_dontcache under this worker with the miss
	 * exit driven on demand, and as iput's BUG on I_CLEAR at its final
	 * release in the wild.
	 *
	 * Such an object needs no revocation.  It was allocated by the miss
	 * path that is poisoning it and nothing outside that thread can reach
	 * it: no file was ever opened on it, nothing mapped it, and its page
	 * cache is empty — there is no dead incarnation's data to zap or
	 * discard.  The flag set above is all the containment it needs: if
	 * the miss path goes on to insert it, every gate and the lookup
	 * retire arm see a poisoned shell; if it frees it, nothing is left
	 * pointing at it.  So take no reference and queue nothing.
	 */
	{
		struct xfs_perag	*pag = xfs_perag_get(mp,
					XFS_INO_TO_AGNO(mp, ip->i_ino));
		struct xfs_inode	*cur = NULL;
		static atomic_t		nu = ATOMIC_INIT(0);
		int			n;

		if (pag) {
			mxfs_ici_lock(pag);
			cur = radix_tree_lookup(&pag->pag_ici_root,
					XFS_INO_TO_AGINO(mp, ip->i_ino));
			spin_unlock(&pag->pag_ici_lock);
			xfs_perag_put(pag);
		}
		if (cur != ip) {
			n = atomic_inc_return(&nu);
			if (n <= 4000)
				pr_warn("mxfs: P-POISON-UNINSERTED ino=%llu gen=%u i_count=%d i_state=0x%lx iflags=0x%lx cur=%px ip=%px total=%d caller=%pS — poisoned object is not the cache's inode for its number; flagged, no revocation queued\n",
					(unsigned long long)ip->i_ino,
					VFS_I(ip)->i_generation,
					atomic_read(&VFS_I(ip)->i_count),
					mxfs_istate(VFS_I(ip)),
					(unsigned long)ip->i_flags,
					cur, ip, n, __builtin_return_address(0));
			if (n <= 4)
				dump_stack();
			if (!READ_ONCE(mxfs_poison_uninserted_legacy))
				return;
		}
	}
	if (!mp->m_mxfs_inode_bast_wq)
		return;
	if (!igrab(VFS_I(ip)))
		return;	/* already evicting — eviction discards everything */
	rv = kzalloc(sizeof(*rv), GFP_NOFS | __GFP_NOWARN);
	if (!rv) {
		/* gates + the lookup retire arm still contain the shell;
		 * only the proactive revocation is lost */
		mxfs_probe("mxfs: P34H-REVOKE-NOMEM ino=%llu — deferred revocation skipped\n",
			(unsigned long long)ip->i_ino);
		xfs_irele(ip);
		return;
	}
	rv->ip = ip;
	INIT_WORK(&rv->work, mxfs_incarn_revoke_work_fn);
	/*
	 * Same teardown discipline as the per-inode bast arms (sess37
	 * D-DWORK-TEARDOWN-LASTREF-LEAK): once m_mxfs_arms_off is set the
	 * put_super flush has run (or is running) — an igrab-holding work
	 * queued after it would outlive the drain.  The wq flush at
	 * put_super then runs any queued revocation while pag and DLM are
	 * still alive, and its igrab ref drops there.
	 */
	atomic_inc(&ip->i_mxfs_revoke_refs);
	spin_lock(&mp->m_mxfs_arm_lock);
	if (!mp->m_mxfs_arms_off)
		queued = queue_work(mp->m_mxfs_inode_bast_wq, &rv->work);
	spin_unlock(&mp->m_mxfs_arm_lock);
	if (!queued) {
		atomic_dec(&ip->i_mxfs_revoke_refs);
		xfs_irele(ip);
		kfree(rv);
	}
}

void
mxfs_dlm_reload_inode(
	struct xfs_inode	*ip,
	uint8_t			expect_ftype,
	bool			post_release)
{
	/* The grant-less form: no caller of this signature holds a grant it
	 * took after the previous holder's drain (the consumer refresh runs
	 * before its acquire, the iget paths hold none), so the corpse
	 * verdict below is deferred to the acquire's own reload. */
	mxfs_dlm_reload_inode_under(ip, expect_ftype, post_release, false);
}

void
mxfs_dlm_reload_inode_under(
	struct xfs_inode	*ip,
	uint8_t			expect_ftype,
	bool			post_release,
	bool			under_grant)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_buf		*bp;
	struct xfs_dinode	*dip;
	struct xfs_dinode	*snap = NULL;	/* immutable dinode snapshot */
	bool			kept_protected = false;	/* P91 guard kept stale buf */
	int			error;
	void			*merge_ours = NULL;	/* pre-reload SF snapshot */
	uint32_t		merge_ours_bytes = 0;	/* */
	int			merge_own_dirs = 0;	/* our subdirs the platter lacks */
	/* reliable cross-node EX handoff signal (master-exposed prior EX
	 * owner != us).  When true, a PEER modified this dir since our base loaded
	 * AND our prior tenure was drained at release (Invariant 1), so on-disk is a
	 * strict SUPERSET — the dir keep-stale self-skip guards (which key on the
	 * LOSSY i_dlm_dir_gen evict-ring that drops messages on TCP) must NOT keep
	 * our stale in-core base.  Consumed once per grant episode via
	 * i_dlm_handoff_acted_gen so a 2nd same-tenure reload cannot resurrect. */
	bool			genuine_handoff = false;
	uint32_t		handoff_gg = 0;
	uint32_t		dir_grant_epoch = 0;	/* monotonic cross-node handoff epoch on our held grant */
	uint32_t		dir_grant_gen_pre = 0;	/* Option B: grant gen read BEFORE the dinode read — the stamp uses the PRE-read pair so a value that moves mid-reload leaves the stamp behind and the next authorization re-adopts (conservative direction) */
	bool			b_need_adopt = false;	/* Option B: validity bit was unset at entry (gate armed this reload / level-held retry) */
	bool			b_stamped_early = false;	/* mxfs.reload_stamp_at_commit lever took the pre-install stamp */
	bool			p68_owner_evict = false; /* reload shrank/changed-incarnation -> owner-evict orphaned dir blocks */
	/*  (D-READDIR-PEER-CACHED-DIR-PACE): split the
	 * reload's wall so the ~600 ms seen per NO-OP parent reload during a
	 * readdir of a peer-created directory is attributed rather than guessed.
	 * Timeline evidence: two identical reloads of the shared parent 606 ms
	 * apart, both ending in P-RELOAD-IDENTICAL, per child readdir. */
	u64			rl_t0 = ktime_get_ns();
	u64			rl_tpre = 0;	/* at the dinode buffer read */
	u64			rl_tbp = 0;	/* after the dinode buffer read */
	bool			reload_identical = false; /* on-disk dinode provably identical to in-core — skip the destructive fork adopt (the 32-node dir EX-loop igniter); see the gate above the fork destroy */
	bool			reload_kept_ahead = false; /* (design-consult ruling F3): reload_identical was set because the IN-CORE IS AHEAD of the platter (P3-REFUSE-OLDER-DISK / P34F dirty-data keep / P184 obligation keep) — nothing of ours landed, so the publication ledger must NOT be discharged at the end of this reload (measured: P177 identical=1 pend=1 dur=0 "closed" a laundered unlink conversion; the AGI list then named a LINKED home dinode forever). */
	unsigned long		r_entry_epoch = 0;	/* c7ee71c6 TOCTOU guard vs a racing release drain */

	/*
	 *  (Phase A): a POISONED shell is condemned — a
	 * prior reload proved the disk disowned this incarnation.  Never
	 * re-attempt adoption/certification (the ino-190 reload
	 * livelock was exactly repeated re-adoption attempts on a dead
	 * shell); leave i_dlm_stale set.  Retirement happens at op entry
	 * (-ESTALE + d_prune_aliases) and at the iget lookup-side evict.
	 */
	if (xfs_iflags_test(ip, MXFS_IF_INCARN_STALE))
		return;

	/*
	 *  (instrumented, PROVEN via the 15:21:37 test1
	 * timeline: P146V re-log + bwrite@.255 wrote=1, yet P-SFDIR-REVERT
	 * @.258 adopted a PRE-bwrite snapshot): a reload racing this inode's
	 * ACTIVE release drain reads the platter BEFORE the drain's bwrite
	 * lands, stalls on the locks the drain holds, then adopts its stale
	 * snapshot AFTER — time-traveling in-core state backwards over a
	 * write that just completed.  Never certify against a platter mid-
	 * demote: bail (leave i_dlm_stale set; the caller retries once the
	 * demote completes and then reads the post-drain truth).  The
	 * matching pre-adopt epoch recheck below catches a demote that
	 * STARTS after this entry check.
	 */
	/*
	 *  — HONOUR THE CONTRACT THE COMMENT ABOVE STATES.
	 *
	 * "bail ...; the caller retries once the demote completes" was never
	 * implemented.  No caller retries.  That unimplemented half is the
	 * escape hatch for the silent mkdir loss, proven byte-exact twice
	 * (sfstorm_20260729_003736 r32 ino=44040321 node31_1;
	 *  sfstorm_20260729_005540 r39 ino=56623307 node27_1 — both
	 *  nlink=33 visible=31 on all 32 nodes, mkdir(2) == 0 everywhere):
	 *
	 *   P65-EPOCH-CONVGATE asks for reload+adopt (peer converted the dir)
	 *   P34J bails here because a release drain happens to be active
	 *   -> i_dlm_dir_valid_epoch stays 0 while the master epoch is 2
	 *   -> the op proceeds and commits a dirent onto the superseded base
	 *   -> P32E-DIREPOCH-FENCE then skips EVERY flush of that dirent
	 *      (fired 3x for one inode: from mkdir, xfsaild and a kworker)
	 *   -> the drain exits flushed=1 with pending=17 durable=12
	 *      (P196 cls=UNCOPIED: never even copied into an outgoing image)
	 *   -> P177 discards it at the next adopt.  The name exists nowhere.
	 *
	 * Enforcing at the drain cannot fix this — the retry re-runs a flush
	 * that is fenced further down, which is exactly why re-arm
	 * livelocked.  The repair is to make the ADOPT happen BEFORE the
	 * operation touches the base, i.e. here.
	 *
	 * So: WAIT for the demote instead of abandoning the reload.  Bounded
	 * (default 50 ms; measured drain cost for this shape is 22-23 ms), in
	 * 1 ms sleeps, and on timeout we fall back to the original bail — so
	 * this can never deadlock against a drain that is itself blocked on a
	 * lock we hold, it can only cost the bound.  We are in a sleepable
	 * context (this function does xfs_imap_to_bp below).
	 */
	/*
	 *  retire a trans-free-retained claim BEFORE
	 * paying the demote wait for it.  This is the site where the strand
	 * does its damage — 224 bails on one inode against a claim whose holder
	 * had already exited — so checking here makes the reload self-healing
	 * for any punt whose dwork never came back to run.  It is a single
	 * predictable branch when no punt is outstanding.
	 */
	mxfs_demoter_punt_reclaim_check(ip, 3);
	if (mxfs_foreign_demoter(ip)) {
		unsigned int	waited = 0;

		while (mxfs_reload_demote_wait_ms &&
		       waited < (unsigned int)mxfs_reload_demote_wait_ms &&
		       mxfs_foreign_demoter(ip)) {
			msleep(1);
			waited++;
		}
		/*
		 * the wait itself can outlast the grace, so re-check
		 * before the bail — a claim that became reclaimable DURING the
		 * wait must not cost a bail as well.
		 */
		if (mxfs_foreign_demoter(ip))
			mxfs_demoter_punt_reclaim_check(ip, 4);
		if (mxfs_foreign_demoter(ip)) {
			/*
			 * ccloop c7ee71c6 sess28: name the CLAIMING SITE and the
			 * claim's AGE.  sess28 measured 300/290/224/354 bails on
			 * single inodes on 32-node stragglers while healthy nodes
			 * showed one, and the claim's holder PID no longer existed
			 * — the claim outlives its holder, so
			 * mxfs_foreign_demoter() stays true for the life of the
			 * in-core inode and EVERY reload pays
			 * mxfs.reload_demote_wait_ms and then abandons the reload
			 * with i_dlm_stale still set.
			 *
			 * ccloop c7ee71c6 sess29 — PRINT BOTH SLOTS.  The sess28
			 * spelling printed only slot 1's stamps, which survive that
			 * claim being cleared, so a strand held in SLOT 2 reported
			 * slot 1's stale site and pid.  That produced a measured
			 * contradiction: test23's 224 bails all named line 34955
			 * (mxfs_inode_dlm_defer_bast), whose only unpaired exit is
			 * the P152 punt, on a node whose P152 count was ZERO.  With
			 * both slots printed, `held=` says which claim is actually
			 * keeping foreign_demoter() true and the site is no longer
			 * inferred.
			 *
			 * Only the stamped SCALARS are read — never
			 * ip->i_dlm_demoter/2 themselves, which are bare
			 * task_struct*s held without a reference and dangle once
			 * the holder exits (exactly the observed state).
			 */
			u64 now_ns = ktime_get_ns();
			bool s1 = READ_ONCE(ip->i_dlm_demoter) != NULL;
			bool s2 = READ_ONCE(ip->i_dlm_demoter2) != NULL;

			mxfs_probe_ratelimited(
			    "mxfs: P34J-RELOAD-DEMOTE-BAIL ino=%llu held=%s%s s1_pid=%d s1_comm=%s s1_line=%u:%u s1_age_ms=%llu s1_depth=%d s2_pid=%d s2_comm=%s s2_line=%u:%u s2_age_ms=%llu s2_depth=%d waited_ms=%u — release drain active; deferring reload\n",
				(unsigned long long)ip->i_ino,
				s1 ? "1" : "", s2 ? "2" : "",
				ip->i_dlm_demoter_pid,
				ip->i_dlm_demoter_comm,
				MXFS_SITE_ARGS(ip->i_dlm_demoter_line),
				(unsigned long long)(ip->i_dlm_demoter_set_ns ?
					(now_ns - ip->i_dlm_demoter_set_ns)
						/ NSEC_PER_MSEC : 0ULL),
				ip->i_dlm_demoter_depth,
				ip->i_dlm_demoter2_pid,
				ip->i_dlm_demoter2_comm,
				MXFS_SITE_ARGS(ip->i_dlm_demoter2_line),
				(unsigned long long)(ip->i_dlm_demoter2_set_ns ?
					(now_ns - ip->i_dlm_demoter2_set_ns)
						/ NSEC_PER_MSEC : 0ULL),
				ip->i_dlm_demoter2_depth,
				waited);
			/*
			 * STRANDED-CLAIM DETECTOR.  A live release drain
			 * completes in tens of ms (measured healthy claims
			 * at ~150 ms and the drain itself at 22-23 ms).  A claim
			 * still held after mxfs.demoter_strand_ms is not a drain in
			 * progress — it is a claim nothing will ever clear.  Print
			 * it ONCE per inode, unratelimited, so the strand cannot be
			 * lost in the bail flood, and count it so a run has a
			 * single number to assert on.
			 */
			if (mxfs_demoter_strand_ms > 0 && !ip->i_dlm_strand_named) {
				u64 a1 = (s1 && ip->i_dlm_demoter_set_ns) ?
					 (now_ns - ip->i_dlm_demoter_set_ns) /
						NSEC_PER_MSEC : 0;
				u64 a2 = (s2 && ip->i_dlm_demoter2_set_ns) ?
					 (now_ns - ip->i_dlm_demoter2_set_ns) /
						NSEC_PER_MSEC : 0;
				u64 amax = a1 > a2 ? a1 : a2;

				if (amax >= (u64)mxfs_demoter_strand_ms) {
					ip->i_dlm_strand_named = true;
					atomic64_inc(&mxfs_dem_strand_n);
					mxfs_probe("mxfs: P214-DEMOTER-STRANDED ino=%llu slot=%d pid=%d comm=%s line=%u:%u age_ms=%llu depth=%d punt=0x%x state=%u mode=%u — claim held far past any drain; every reload of this inode now bails\n",
						(unsigned long long)ip->i_ino,
						a1 >= a2 ? 1 : 2,
						a1 >= a2 ? ip->i_dlm_demoter_pid :
							   ip->i_dlm_demoter2_pid,
						a1 >= a2 ? ip->i_dlm_demoter_comm :
							   ip->i_dlm_demoter2_comm,
						MXFS_SITE_ARGS(a1 >= a2 ? ip->i_dlm_demoter_line :
							   ip->i_dlm_demoter2_line),
						amax,
						a1 >= a2 ? ip->i_dlm_demoter_depth :
							   ip->i_dlm_demoter2_depth,
						ip->i_dlm_demoter_punt,
						ip->i_dlm_state, ip->i_dlm_mode);
					/*
					 * REPLAY THE CLAIM RING.  The
					 * strand is an UNBALANCED SET/CLEAR
					 * pair — depth=1 with the slot still
					 * held means one more SET landed than
					 * CLEARs ran — and this ring is the
					 * only record naming BOTH halves by
					 * source line and pid.  Without it the
					 * site is inferred, which is exactly
					 * how the P152 punt was convicted on
					 * circumstantial evidence and then
					 * measured NOT to be the path for this
					 * population (punt=0x0 on 8 of 8
					 * strands, one pid, 8 inodes).
					 * Bounded by i_dlm_strand_named, so it
					 * prints once per inode.
					 */
					{
						int k;

						for (k = 0; k < MXFS_DEMEV_N; k++) {
							int idx = (ip->i_dlm_demev_head + k)
								  % MXFS_DEMEV_N;
							static const char * const opn[] = {
								"SET", "CLEAR",
								"WAIT",
								"SET-REFUSED",
								"CLEAR-NEST",
								"CLEAR-REFUSED",
								"PUNT-RECLAIM" };
							uint8_t o = ip->i_dlm_demev_op[idx];

							if (!ip->i_dlm_demev_cookie[idx])
								continue;
							mxfs_probe("mxfs:   P214-DEMEV[%d] %s line=%u:%u pid=%d state=%u cookie=%u\n",
								k,
								o < ARRAY_SIZE(opn) ?
									opn[o] : "?",
								MXFS_SITE_ARGS(ip->i_dlm_demev_line[idx]),
								ip->i_dlm_demev_pid[idx],
								ip->i_dlm_demev_state[idx],
								ip->i_dlm_demev_cookie[idx]);
						}
					}
				}
			}
			/* Option B: the gate stays armed across this bail
			 * (validity bit remains unset — level-held retry at the
			 * next authorization).  Count it so a run can prove the
			 * P34J escape hatch no longer strands the adopt. */
			if (mxfs_dir_adopt_at_acquire &&
			    S_ISDIR(VFS_I(ip)->i_mode) &&
			    !smp_load_acquire(&ip->i_dlm_base_valid))
				atomic64_inc(&mxfs_b_p34j_defer);
			return;
		}
		/*
		 * The attributable probe.  Every occurrence is a reload that the
		 * old code ABANDONED and this one completes — i.e. an epoch
		 * adopt that now happens before the operation instead of never.
		 */
		{
			static atomic_t p198_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p198_n) <= 20000)
				mxfs_probe("mxfs: P198-RELOAD-DEMOTE-WAITED ino=%llu waited_ms=%u dir_valid_epoch=%u stale_src=%u fmt=%d comm=%s — drain finished; proceeding with the reload the old code abandoned\n",
					(unsigned long long)ip->i_ino, waited,
					ip->i_dlm_dir_valid_epoch,
					ip->i_dlm_stale_src,
					ip->i_df.if_format, current->comm);
		}
	}
	r_entry_epoch = READ_ONCE(ip->i_dlm_epoch);

	/* ICLUSTER (crash_consistency root): routed
	 * files have NO per-inode grant_gen/dir_epoch, so none of the dir
	 * handoff arms below can fire for them — and the keep-stale guards
	 * then serve a PRE-EXISTING in-core inode's old extent map forever
	 * (proven: reused-ino file re-written 8KB O_SYNC; readers'
	 * retained-cluster reload kept the previous incarnation's extents →
	 * wrong content on every foreign node).  The cluster grant_seq IS
	 * the reliable handoff signal: it bumps exactly when a fresh disk
	 * claim follows a coverage gap — the only window a peer could have
	 * held EX.  Acted-once semantics via i_dlm_iclus_seen_seq.  MUST run
	 * for ALL inode types (top of function, not the dir-only arm block).
	 */
	if (mxfs_iclus_routed(ip) && !ip->i_dlm_unpublished) {
		uint64_t iseq = mxfs_iclus_grant_seq(ip->i_mount, ip->i_ino);

		if (iseq != ip->i_dlm_iclus_seen_seq) {
			/* Force-adopt only when SELF-CLEAN (the P65
			 * ea_self_clean discipline): dirty in-core with a
			 * changed seq is an Invariant-1 edge (unpublished
			 * create window, teardown) where adopting the lagging
			 * disk would REVERT our own committed-in-log state —
			 * the proven fork-shrink class.  A clean self
			 * has nothing to lose; disk is the superset. */
			struct xfs_inode_log_item *ic_iip = ip->i_itemp;
			bool ic_self_clean =
				atomic_read(&ip->i_pincount) == 0 &&
				(!ic_iip ||
				 (!ic_iip->ili_fields &&
				  !test_bit(XFS_LI_IN_AIL,
					    &ic_iip->ili_item.li_flags)));

			if (ic_self_clean) {
				genuine_handoff = true;
				mxfs_probe_ratelimited(
				    "mxfs: P-ICLUS-HANDOFF ino=%llu seq=%llu seen=%llu — fresh cluster claim; forcing disk-superset adopt\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)iseq,
					(unsigned long long)ip->i_dlm_iclus_seen_seq);
				ip->i_dlm_iclus_seen_seq = iseq;
			}
		}
	}

	/* Phase 6 instrumentation: log pre-reload in-memory state */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    ip->i_df.if_data && ip->i_disk_size > 6) {
		struct xfs_dir2_sf_hdr *sfh = ip->i_df.if_data;
		struct xfs_dir2_sf_entry *sfe =
			xfs_dir2_sf_firstentry(sfh);
		char name[32];
		int len = min_t(int, sfe->namelen, 31);

		memcpy(name, sfe->name, len);
		name[len] = '\0';
		mxfs_idbg(
			"mxfs: P6-INSTR reload-pre ino=%llu "
			"mem_entries=%u first_entry=\"%s\" "
			"mem_size=%lld",
			(unsigned long long)ip->i_ino,
			sfh->count, name,
			(long long)ip->i_disk_size);
	}

	mxfs_idbg(
		"mxfs: DLM reload inode %llu (stale=%d mode=%u)",
		(unsigned long long)ip->i_ino, ip->i_dlm_stale,
		VFS_I(ip)->i_mode);

	/*
	 * — close the local-unlink reuse hole.
	 * This reload is about to adopt the peer's on-disk incarnation of
	 * this inode number (xfs_inode_from_disk below).  If this node had
	 * previously unlinked an EARLIER incarnation of the same inode#
	 * (setting MXFS_IF_LOCAL_UNLINK via xfs_droplink/iunlink), that flag
	 * is now stale — it describes the dead incarnation, not the peer's
	 * live one we are adopting.  XFS_IRECLAIM_RESET_FLAGS only clears it
	 * on an iget-RECYCLE, never on an in-place DLM reload, so without this
	 * the stale flag makes xfs_inactive's B3 guard wrongly PROCEED and
	 * destructively free the PEER's live blocks (bnobt double-free → FS
	 * shutdown).  A legit local unlink->inactivation holds the inode and
	 * does not take the DLM reload path, so clearing here is safe.
	 *
	 * (design-consult ruling F4): the premise above is no longer true —
	 * the reldefer worker DOES reload this node's own live unlink
	 * (P382-RELDEFER-RELOAD), and the reload may then KEEP the in-core
	 * (reload_identical / kept-ahead: no adopt at all).  Clearing here
	 * stripped the rightful freer's authority, xfs_inactive's B3 guard
	 * skipped the ifree as "torn-live-no-local-unlink", and the inode's AGI
	 * unlinked-list entry was never removed (measured test10/test7).  The
	 * clear now runs at the adopt itself (the `else` after from_disk,
	 * only when !reload_identical), which is exactly the "about to adopt
	 * the peer's incarnation" moment this comment describes.
	 */

	/*
	 * run78 ROOT FIX (instrumented, test4 r3 @76.239): a reload
	 * ran while THIS node's committed dir grow was still logged-not-
	 * destaged (inode item dirty/in AIL) and adopted a far-older same-
	 * generation disk image (P33-FROMDISK-DIRSHRINK nx 9 -> 1), reverting
	 * our own committed fork.  The create path then RMW'd "near-empty"
	 * reused blocks over durable content (P13-STALEREAD / P13-COLLIDE
	 * free-slot double-alloc), the pending-replay re-added dirents onto a
	 * stale base, 25 md5 dirents were durably lost cluster-wide, and the
	 * node died minutes later.  FIX-8 (P34E) guarded only the
	 * kept_protected FUA arm; the same revert reaches from_disk through
	 * every other arm.  Enforce the invariant at the ENTRY: while our
	 * in-core inode carries LOGGED-NOT-DESTAGED core changes (dirty
	 * ili_fields, inode item in AIL, or pinned), the platter is BY
	 * DEFINITION behind us for this inode — there is nothing coherent to
	 * adopt.  A genuine peer-ahead image is only possible when we are
	 * clean (our release fence destages before any peer tenure).  Skip
	 * the reload and clear i_dlm_stale (we are the authority; staleness
	 * re-arms on the next BAST/handoff once we are clean).
	 */
	{
		struct xfs_inode_log_item	*ra_iip = ip->i_itemp;
		bool				ra_self_ahead;

		ra_self_ahead = atomic_read(&ip->i_pincount) > 0 ||
			(ra_iip &&
			 (ra_iip->ili_fields ||
			  test_bit(XFS_LI_IN_AIL, &ra_iip->ili_item.li_flags)));
		/*
		 * FIX-G (PROVEN BY INSTRUMENT, 2/tcp iter s14a test2
		 * shutdown, artifact run_dir_reuse_coherency_20260704T192640Z):
		 * the premise above ("dirty ⇒ platter behind us") INVERTS when
		 * our dirtiness is a STUCK flush surviving across handoffs —
		 * test2 sat ili=0x5/in_ail=1 while the DLM dir gen advanced 13
		 * peer tenures past our loaded base (dgen=68 lgen=55), this
		 * skip looped serving the 13-gen-stale image as "authority",
		 * and a local create RMW'd it into xfs_dir2_data_use_free
		 * EFSCORRUPTED → cluster-visible durable dirent loss + FS
		 * shutdown.  The peer-advance signal is right here:
		 * i_dlm_dir_gen > i_dlm_dir_loaded_gen means peers held EX
		 * AFTER our base loaded, so the platter is NOT behind us for
		 * the dir CONTENT even though our own inode-core mods are
		 * undestaged.  In that state: destage OUR work first
		 * (log_force + targeted AIL drain for this inode), and if that
		 * cleans the ili, fall THROUGH to the normal reload arms
		 * (which adopt/merge the now-genuine disk superset).  If it
		 * cannot be cleaned (the stuck-iflush wedge itself), keep the
		 * old skip but say so loudly — P14-STUCK-ILI names the live
		 * wedge for the next post-mortem instead of a silent loop.
		 */
		/*
		 * Distance >= 3 (not merely "ahead"): an ORDINARY mid-tenure
		 * acquire is routinely 1 gen behind with a dirty ili (our own
		 * in-flight op right after a peer handoff) — destaging THERE
		 * put a log_force(SYNC)+adopt storm on every hot-dir handoff
		 * (2/tcp iter s14c: tds test2 crippled to 4/150 rounds,
		 * 15s/round; 47 destage fires).  The pathological stuck-ili
		 * state accumulates MANY peer tenures against one frozen
		 * loaded_gen (s14a wedge: gap=13).  3 is safely above normal
		 * concurrency jitter and far below the wedge's runaway.
		 */
		if (ra_self_ahead && S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_dir_gen >= (u64)ip->i_dlm_dir_loaded_gen + 3) {
			xfs_log_force(mp, XFS_LOG_SYNC);
			mxfs_ail_drain_inode_sync(ip);
			ra_iip = ip->i_itemp;
			ra_self_ahead = atomic_read(&ip->i_pincount) > 0 ||
				(ra_iip &&
				 (ra_iip->ili_fields ||
				  test_bit(XFS_LI_IN_AIL,
					   &ra_iip->ili_item.li_flags)));
			if (!ra_self_ahead) {
				static atomic_t p14d_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p14d_n) <= 2000)
					mxfs_probe("mxfs: P14-DESTAGE-THEN-RELOAD ino=%llu dgen=%llu lgen=%u — peer tenures since load; own mods destaged, adopting fresh base\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)ip->i_dlm_dir_gen,
						ip->i_dlm_dir_loaded_gen);
			} else {
				static atomic_t p14w_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p14w_n) <= 2000)
					pr_warn("mxfs: P14-STUCK-ILI ino=%llu pin=%d ili=0x%x in_ail=%d dgen=%llu lgen=%u — peer tenures since load but own ili UNDESTAGEABLE; stale-base skip continues (wedge!)\n",
						(unsigned long long)ip->i_ino,
						atomic_read(&ip->i_pincount),
						ra_iip ? ra_iip->ili_fields : 0,
						ra_iip ? test_bit(XFS_LI_IN_AIL,
							&ra_iip->ili_item.li_flags) : 0,
						(unsigned long long)ip->i_dlm_dir_gen,
						ip->i_dlm_dir_loaded_gen);
			}
		}
		if (ra_self_ahead) {
			static atomic_t p34f_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p34f_n) <= 2000)
				mxfs_probe("mxfs: P34F-RELOAD-SELFAHEAD-SKIP ino=%llu pin=%d ili=0x%x in_ail=%d fmt=%d nx=%llu size=%lld post_release=%d dgen=%llu lgen=%u state=%u — undestaged local core mods; reload skipped (in-core authoritative)\n",
					(unsigned long long)ip->i_ino,
					atomic_read(&ip->i_pincount),
					ra_iip ? ra_iip->ili_fields : 0,
					ra_iip ? test_bit(XFS_LI_IN_AIL,
						&ra_iip->ili_item.li_flags) : 0,
					ip->i_df.if_format,
					(unsigned long long)ip->i_df.if_nextents,
					(long long)ip->i_disk_size,
					post_release ? 1 : 0,
					(unsigned long long)ip->i_dlm_dir_gen,
					ip->i_dlm_dir_loaded_gen,
					ip->i_dlm_state);
			ip->i_dlm_stale = false;
			return;
		}
	}

	/*
	 * PROVEN BY INSTRUMENT (runs 120345Z + 121411Z —
	 * i!=1 iext-behind-one-left-merge on test18/26, then P34B-AHEAD ×4
	 * with ir.loaded!=if_nextents ×4): the P34F guard above keys on
	 * IN-CORE dirtiness, but the manufacture state is one step later —
	 * this tenure's dir modifications have already COMPLETED into the
	 * target's volatile write cache (BLI retired, ili clean, nothing
	 * pinned/in-AIL) while the PLATTER still holds the pre-write image
	 * until the release-time flush.  A reload here FUA-reads that stale
	 * platter and adopts/regresses one side of (dinode, leaf, iext),
	 * forking the dir's history against our own committed ops (the
	 * bunmapi i!=1 / iread-count families).  While WE hold the EX grant
	 * and have MODIFIED the inode under this very grant
	 * (i_mxfs_dirty_seq == i_mxfs_ex_grant_seq), no peer can have
	 * written since the tenure began — the disk has NOTHING for us and
	 * every byte it returns is equal-or-older.  Skip the reload
	 * entirely; a fresh EX tenure bumps i_mxfs_ex_grant_seq so the
	 * tenure-START reload (platter coherent: the prior holder's release
	 * flushed) still adopts fully.  Dirs only — the proven family;
	 * regular files keep their existing guard set.
	 */
	/*
	 *  — P193: THE EPOCH SIGNAL OVERRIDES THIS SKIP.
	 *
	 * P6's whole premise is the sentence in the comment above: "no peer can
	 * have written since the tenure began".  The dir EPOCH is direct proof
	 * that a peer HAS written — the master bumps it at the peer's modify
	 * commit and stamps it on our grant.  When P65-EPOCH-CONVGATE
	 * (i_dlm_stale_src == 3) is the caller, the two guards assert
	 * contradictory facts about the same inode, microseconds apart, and P6
	 * currently wins — it returns early AND clears i_dlm_stale, discarding
	 * the flag P65 just set.
	 *
	 * PROVEN CONSEQUENCE (storm run sfstorm_20260728_201959, ROUND 29,
	 * pino=46137485, test24, all four events inside 26 us):
	 *
	 *   250.153345 P26-LKFMT     fmt=0 err=-2 name="node24_1"
	 *   250.153367 P65-EPOCH-CONVGATE grant_epoch=2 valid_epoch=0
	 *                             — peer converted; reload+adopt
	 *   250.153371 P6-MIDTENURE-RELOAD-SKIP fmt=1 nx=0 size=6
	 *                             — "reload has nothing to teach us"
	 *
	 * test24 therefore built node24_1 on a stale EMPTY shortform base while
	 * the platter already held the peer's converted block-format dir.  Its
	 * four P56-DIRWRITEs for this inode all carry `nl=2 sz=6 write=[]`,
	 * including the one from comm=mkdir.  The write-side backstop
	 * (P189-RELOG-BEHIND-DISK, 123 hits that run) then correctly refused to
	 * publish that behind-disk image — which prevents the mass clobber but
	 * silently DROPS the entry.  mkdir(2) returned 0 and node24_1 exists
	 * nowhere: `nlink=33 visible=31 expected=32 missing=[node24_1]` on all
	 * 32 nodes.  Zero MKDIR-RC lines cluster-wide, so this is silent loss,
	 * not a reported failure.
	 *
	 * So: when the epoch gate asked for this reload, honour it.  P65 passes
	 * post_release=true precisely so the reload adopts the peer's BLOCK
	 * image, and its own comment already states that our pre-adopt shortform
	 * dirents are re-added by the create-path union-merge / pending replay.
	 * Lever mxfs.p6_epoch_override=0 restores the pre-fix precedence.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_dlm_mode == MXFS_LOCK_EX &&
	    ip->i_mxfs_dirty_seq != 0 &&
	    ip->i_mxfs_dirty_seq == ip->i_mxfs_ex_grant_seq &&
	    mxfs_p6_epoch_override && ip->i_dlm_stale &&
	    ip->i_dlm_stale_src == 3) {
		/*
		 * The override actually fired: P6 WOULD have skipped, and the
		 * epoch signal overruled it.  This is the attributable probe.
		 *
		 * NOTE, measured: P65-EPOCH-CONVGATE reads 0-1 per storm run,
		 * which made this path look far too rare to A/B.  That is a
		 * RATELIMIT ARTIFACT — P65 uses pr_warn_ratelimited, whereas
		 * this counted pr_warn shows the same decision point is reached
		 * ~68x per run.  Never reason about a probe's frequency without
		 * first checking which of the two forms it uses.
		 */
		static atomic_t p193_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p193_n) <= 2000)
			mxfs_probe("mxfs: P193-P6-EPOCH-OVERRIDE ino=%llu grant_seq=%llu fmt=%d nx=%llu size=%lld post_release=%d comm=%s — P6 mid-tenure skip OVERRULED by the dir-epoch signal; proceeding with reload+adopt\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_mxfs_ex_grant_seq,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				post_release ? 1 : 0, current->comm);
		/* fall through to the real reload */
	} else if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    mxfs_p6_midtenure_skip &&
	    /*
	     * FIX: never swallow staleness that a PEER notification set.
	     * See mxfs_p6_honor_src_mask (pal/linux/xfs_aops.c) for the proof
	     * chain; in short, src 2 and 8 both mean "a peer published to this
	     * directory", src 8 having already CONSUMED MXFS_IF_DIR_RELOAD, so
	     * skipping here destroys the notification and the peer's entry is
	     * never observed.
	     */
	    !((mxfs_p6_honor_src_mask >> (ip->i_dlm_stale_src & 31)) & 1u) &&
	    ip->i_dlm_mode == MXFS_LOCK_EX &&
	    ip->i_mxfs_dirty_seq != 0 &&
	    ip->i_mxfs_dirty_seq == ip->i_mxfs_ex_grant_seq) {
		/*
		 * A/B LEVER mxfs.p6_midtenure_skip (default 1 = current
		 * behaviour; 0 = always perform the real reload).
		 *
		 * Why this lever exists, a token-frequency DIFFERENTIAL
		 * between a node that durably lost 8 dirents (test4) and its 31
		 * healthy peers, both scoped to the same dirent_durability
		 * window, nominated this path outright:
		 *
		 *   P6-MIDTENURE-RELOAD-SKIP   loser 661   peer median 37
		 *                              peer range 25-215   (17.4x, and
		 *                              3x above the highest peer)
		 *
		 * Nothing else came close in that direction; the next largest
		 * were P72-ORPHAN-WAIT (5.8x) and P126-DEMOTE-RACE (5.6x), both
		 * plausibly downstream of the same stall.  The differential was
		 * used precisely because EVERY documented marker of the loss
		 * chain (P32E, P195, P188, P177, P146V, P51, P65, P194) had been
		 * measured to ZERO in a losing window, so the producer had no
		 * probe and picking the next one by intuition had already failed
		 * across five sessions.
		 *
		 * The existing mxfs.p6_epoch_override only overrules this skip
		 * when the epoch gate requested the reload (stale_src == 3), and
		 * the losing windows show epoch == entry_epoch throughout, so
		 * that override cannot engage for this case.  This lever
		 * disables the skip itself, which is the only way to test
		 * whether the skip is the loss producer rather than a
		 * bystander.
		 */
		static atomic_t p6mt_n = ATOMIC_INIT(0);

		/*
		 *  — P197: TEST P6's PREMISE.
		 *
		 * P6 skips the reload because `dirty_seq == ex_grant_seq`, which
		 * it reads as "modified under the CURRENT EX tenure, so no peer
		 * can have written since the tenure began".  ROUND 29 shows that
		 * conclusion being drawn while the platter held a peer-converted
		 * BLOCK dir and our base was an EMPTY shortform — impossible
		 * inside one uninterrupted tenure.
		 *
		 * The equality is a stamp comparison; it cannot see time.  So
		 * compare the WALL CLOCK of the dirtying against the wall clock
		 * of the tenure we are currently in.  dirty_age > tenure_age
		 * means the dirtying happened BEFORE this tenure started — the
		 * premise is false and the skip is unjustified.  Printed for
		 * EVERY skip (not just the rare loss) so it has n in the
		 * hundreds per run instead of the 0-1 that made P65/P195
		 * un-A/B-able.
		 */
		{
			u64 p197_now = ktime_get_ns();
			u64 p197_dage = ip->i_mxfs_dirty_ns ?
				(p197_now - ip->i_mxfs_dirty_ns) / NSEC_PER_MSEC : 0;
			u64 p197_tage = ip->i_dlm_ex_acquire_ns ?
				(p197_now - ip->i_dlm_ex_acquire_ns) / NSEC_PER_MSEC : 0;
			static atomic_t p197_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p197_n) <= 20000)
				mxfs_probe("mxfs: P197-P6-PREMISE ino=%llu premise=%s dirty_age_ms=%llu tenure_age_ms=%llu dirty_ns=%llu acq_ns=%llu egseq=%llu dseq=%llu grant_gen=%u cached_gen=%u dir_epoch_valid=%u stale=%d src=%u fmt=%d nx=%llu comm=%s\n",
					(unsigned long long)ip->i_ino,
					(ip->i_mxfs_dirty_ns &&
					 ip->i_dlm_ex_acquire_ns &&
					 ip->i_mxfs_dirty_ns <
						ip->i_dlm_ex_acquire_ns) ?
						"FALSE-PRE-TENURE-DIRTY" :
					(!ip->i_dlm_ex_acquire_ns ?
						"NO-ACQ-STAMP" : "ok"),
					(unsigned long long)p197_dage,
					(unsigned long long)p197_tage,
					(unsigned long long)ip->i_mxfs_dirty_ns,
					(unsigned long long)ip->i_dlm_ex_acquire_ns,
					(unsigned long long)ip->i_mxfs_ex_grant_seq,
					(unsigned long long)ip->i_mxfs_dirty_seq,
					mxfs_v5_dlm_inode_grant_gen(
						mp->m_mxfs_dlm, ip->i_ino),
					ip->i_dlm_cached_grant_gen,
					ip->i_dlm_dir_valid_epoch,
					ip->i_dlm_stale ? 1 : 0,
					ip->i_dlm_stale_src,
					ip->i_df.if_format,
					(unsigned long long)ip->i_df.if_nextents,
					current->comm);
		}

		/*
		 * H2' MEASUREMENT — measurement only,
		 * no behaviour change.
		 *
		 * This path clears i_dlm_stale and returns WITHOUT reloading, on
		 * the premise "the dir was modified under the CURRENT EX tenure,
		 * so the in-core image is authoritative and the platter has
		 * nothing to teach us".
		 *
		 * That premise is exactly what a P34J RACE BAIL contradicts. The
		 * bail fires because a release DRAIN raced the reload, and it
		 * deliberately DISCARDS the snapshot it had taken ("adopting it
		 * would revert in-core behind a completed write"). It then leaves
		 * i_dlm_stale set on the promise that a later reload re-reads
		 * post-drain truth. If that later reload lands HERE instead, the
		 * staleness is cleared and nothing is re-read — the inode now
		 * looks fresh while carrying the pre-drain image the bail refused
		 * to trust.
		 *
		 * Measured facts that make this the live hypothesis: in a run
		 * that lost 8 dirents, P34J-RELOAD-RACE-BAIL (14) was the only
		 * nonzero mechanism marker in the scoped window while P6-MIDTENURE
		 * fired 693 times; and every bail had epoch == entry_epoch, so
		 * mxfs_p6_epoch_override (which lets the epoch signal beat this
		 * skip) cannot fire for the bailed case — the epoch never moved.
		 *
		 * So count the overlap. p6_skip_after_racebail > 0 means this skip
		 * is clearing staleness on an image a bail discarded.
		 */
		atomic64_inc(&mxfs_p6_skip_total);
		atomic64_inc(&mxfs_p6_src_hist[ip->i_dlm_stale_src <
					       MXFS_P6_SRC_N ?
					       ip->i_dlm_stale_src :
					       MXFS_P6_SRC_N - 1]);
		if (ip->i_dlm_p6skip_n < 0xffff)
			ip->i_dlm_p6skip_n++;
		if (ip->i_dlm_p6skip_n >= 8) {
			long long prev;

			atomic64_inc(&mxfs_p6_repeat_ge8);
			for (;;) {
				prev = atomic64_read(&mxfs_p6_repeat_max);
				if ((long long)ip->i_dlm_p6skip_n <= prev)
					break;
				if (atomic64_cmpxchg(&mxfs_p6_repeat_max, prev,
						     ip->i_dlm_p6skip_n) == prev)
					break;
			}
		}
		if (ip->i_mxfs_racebail_ns) {
			static atomic_t p80n = ATOMIC_INIT(0);
			u64 rb_age_ms = (ktime_get_ns() -
					 ip->i_mxfs_racebail_ns) / NSEC_PER_MSEC;

			atomic64_inc(&mxfs_p6_skip_after_rb);
			if (atomic_inc_return(&p80n) <= 400)
				mxfs_probe("mxfs: P80-P6-SKIP-AFTER-RACEBAIL ino=%llu racebail_age_ms=%llu epoch=%lu valid_epoch=%u fmt=%d size=%lld post_release=%d comm=%s — clearing staleness without reloading an image a race bail discarded\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)rb_age_ms,
					ip->i_dlm_epoch,
					ip->i_dlm_dir_valid_epoch,
					ip->i_df.if_format,
					(long long)ip->i_disk_size,
					post_release ? 1 : 0,
					current->comm);
		}

		if (atomic_inc_return(&p6mt_n) <= 2000)
			mxfs_probe("mxfs: P6-MIDTENURE-RELOAD-SKIP ino=%llu grant_seq=%llu fmt=%d nx=%llu size=%lld post_release=%d state=%u racebail_age_ms=%lld — dir modified under the CURRENT EX tenure; in-core authoritative, reload has nothing to teach us\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_mxfs_ex_grant_seq,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				post_release ? 1 : 0,
				ip->i_dlm_state,
				ip->i_mxfs_racebail_ns ?
				  (long long)((ktime_get_ns() -
					       ip->i_mxfs_racebail_ns) /
					      NSEC_PER_MSEC) : -1);
		ip->i_dlm_stale = false;
		return;
	}

	/*
	 * compute the genuine cross-node handoff signal (once, here, before
	 * any keep-stale guard).  mxfs_v5_dlm_inode_grant_handoff returns the
	 * handoff bit the DLM master stamped on our current EX grant (prior EX owner
	 * != us) plus the grant_gen so we consume it exactly once per grant episode.
	 * This is the lossless replacement for the DIR_MODIFY evict-ring: on TCP the
	 * ring drops messages, so i_dlm_dir_gen can lag and the keep-stale guards
	 * wrongly preserve a base missing the peer's dirents (dir_reuse node1_f1
	 * durable loss).  A handoff means we released EX (drained per Invariant 1)
	 * and a peer then held+modified it — disk is a strict superset, safe to
	 * adopt with no resurrection.  Acted_gen is advanced at the actual adopt
	 * below so a trylock-bailed retry still re-triggers. */
	if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		/* (design review): LEVEL-triggered epoch is the primary signal.
		 * The master bumps a monotonic per-resource dir_epoch on EVERY
		 * cross-node EX handoff and stamps it on each grant; if the epoch on
		 * our held grant exceeds the epoch our base is known coherent with, a
		 * peer modified this dir since — adopt the disk superset.  Unlike the
		 * one-shot handoff bool (consumed via acted_gen, lost ~80% of the time
		 * to fast-path serves / multi-consumer races), a missed intermediate
		 * handoff still leaves grant_epoch > valid_epoch, so this fires
		 * exactly once and never silently drops a handoff. */
		/* epoch query retained for the P64-EPOCH-OBS probe only; the
		 * level-triggered ADOPT trigger is DISABLED pending the design review "disable
		 * fast-path on stale epoch -> slow-path re-acquire" design (an in-place
		 * post_release=false adopt rolls back in-flight mods / frees the wrong
		 * extents -> bnobt + dabuf-HOLE corruption shutdowns).  Observe
		 * only so the next session can see how often epoch != valid on each
		 * path without perturbing behavior. */
		dir_grant_epoch = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
							      ip->i_ino);
		/* Option B: capture the grant-gen HALF of the baseline at
		 * the same pre-read moment, and whether the gate was armed at
		 * entry (valid bit unset).  Both feed the install-point stamp. */
		if (mxfs_dir_adopt_at_acquire) {
			dir_grant_gen_pre = mxfs_v5_dlm_inode_grant_gen(
						mp->m_mxfs_dlm, ip->i_ino);
			b_need_adopt = !smp_load_acquire(&ip->i_dlm_base_valid);
		}
		/* (design review, incarnation-restricted): a post_release
		 * re-acquire whose grant epoch exceeds the epoch our base is coherent
		 * with means a peer modified this dir since.  Drive the disk-superset
		 * adopt — but ONLY bypass the P33/P43 keep-stale guards for the SAME
		 * incarnation (di_gen unchanged).  The legacy edge bit keeps its full
		 * (validated) bypass; the epoch ADDS the ~80% of same-incarnation
		 * handoffs the lossy bit missed (the single-dirent loss) WITHOUT newly
		 * adopting across a free+realloc (different di_gen = reuse), which is
		 * what corrupted the bnobt/dabuf when the epoch bypassed unrestricted.
		 * Gated post_release=1 (post_release=0 in-place adopt = the
		 * xfs_create/dabuf-HOLE corruption). */
		/* epoch-driven adopt CONVERGES the dir-block0 extent-map
		 * split (PROVEN: with it ON all 4 nodes' inode-131 extent[0] agreed
		 * on daddr=120).  Gated on mxfs_dir_epoch_adopt so it can be tested
		 * in ISOLATION from force_block (which caused the 2/tcp corruption). */
		/* v0.6.0: on the CAW transport the epoch is slot-carried and can
		 * RESTART when the slot is reclaimed (last holder unlocked), so a
		 * BACKWARD move equally means "our base's coherence stamp no longer
		 * matches the resource's handoff history" — adopt on != there.
		 * TCP keeps the monotonic > (mirrors can transiently read 0;
		 * /P44 anomaly must not force spurious adopts). */
		/* v0.6.5: on CAW compare against
		 * i_dlm_dir_acq_epoch, NOT valid_epoch.  The modify/evict-path
		 * hooks (mxfs_dir_*_evict tenure-start sync, libxfs read hooks)
		 * sync valid_epoch UP to the master epoch mid-tenure for buffer
		 * stamping — erasing the lag this gate needs, so a genuine
		 * handoff whose reload was fast-path-skipped never adopts and
		 * the stale base survives the whole storm (uv resurrect).
		 * acq_epoch advances ONLY at the reload fall-through (adopt)
		 * point below, so the mismatch is level-held until a real
		 * adopt happens. */
		if (post_release &&
		    (mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) ?
		     (dir_grant_epoch != ip->i_dlm_dir_acq_epoch) :
		     (dir_grant_epoch > ip->i_dlm_dir_valid_epoch))) {
			/* v0.6.4 CAW epoch-consume (PROVEN BY INSTRUMENT, 4/caw uv run
			 * 20260705T232526Z): the level-triggered epoch advance
			 * was OBSERVE-ONLY here, so freshness relied on the
			 * lossy one-shot P63 bit — test4's last two EX grants
			 * consumed neither, its valid_epoch froze at 14 while
			 * the cluster reached 27, P68-EVDECIDE kept its stale
			 * dir block (b_epoch==stale valid_epoch), every unlink
			 * re-logged the 18-entry stale image, and the release
			 * drain durably resurrected test2's removed dirents
			 * (uv dangling dirent -> IGET-FAIL err=-2).  On CAW,
			 * consume the epoch here — adopt — whenever WE have no
			 * undestaged local mods (pin/ili_fields/in-AIL clean):
			 * post-release with a clean self, disk is a true
			 * superset and the adopt cannot roll back anything of
			 * ours.  The 8/tcp regression config stays
			 * excluded on both axes: TCP keeps observe-only (>)
			 * semantics + lossy-bit trigger, and a dirty self
			 * (committed-not-destaged grow) keeps today's
			 * keep-stale guards.  mxfs_dir_epoch_adopt=1 still
			 * force-enables unconditionally for A/B. */
			struct xfs_inode_log_item *ea_iip = ip->i_itemp;
			bool ea_self_clean =
				atomic_read(&ip->i_pincount) == 0 &&
				(!ea_iip ||
				 (!ea_iip->ili_fields &&
				  !test_bit(XFS_LI_IN_AIL,
					    &ea_iip->ili_item.li_flags)));
			/* PROVEN BY INSTRUMENT at 32/tcp drc
			 * (61s repro, round-3): test21 ran a whole round on a
			 * STALE DEAD incarnation of the shared dir — readdir=0
			 * of 128 while 31 peers saw 124 (its 4 creates went
			 * into the orphaned fork = the 4 missing names), with
			 * ZERO P63-HANDOFF lines on the victim: on TCP every
			 * freshness signal was one-shot-lossy (P63 bit
			 * "lost ~80%" per its own header, evict-ring drops
			 * messages, epoch observe-only).  Enable the
			 * level-triggered epoch-consume adopt on TCP with
			 * EXACTLY the guards that validated it on CAW since
			 * v0.6.4: post_release=1 only (gated by the enclosing
			 * if) and a clean self (nothing pinned/dirty/in-AIL),
			 * so the disk is a true superset and the adopt cannot
			 * roll back local state.  The 8/tcp regression
			 * that kept TCP excluded was the UNGUARDED shape
			 * (post_release=0 in-place adopt) — not this one. */
			bool ea_adopt = mxfs_dir_epoch_adopt || ea_self_clean;

			if (ea_adopt)
				genuine_handoff = true;
			mxfs_probe_ratelimited(
				"mxfs: P65-EPOCH-ADOPT ino=%llu grant_epoch=%u acq_epoch=%u valid_epoch=%u post_release=%d fmt=%u adopt=%d clean=%d — epoch advanced (converges dir-block0 extent map)\n",
				(unsigned long long)ip->i_ino, dir_grant_epoch,
				ip->i_dlm_dir_acq_epoch,
				ip->i_dlm_dir_valid_epoch, post_release ? 1 : 0,
				ip->i_df.if_format, ea_adopt ? 1 : 0,
				ea_self_clean ? 1 : 0);
		}
		/* Legacy edge bit: unchanged baseline behavior.
		 * (< > REFUTED as the 8/tcp DABUF_MAP_HOLE cause: gating
		 * it OFF — P63-HANDOFF fired 0× — left the cascade unchanged; the hole
		 * is a reuse-stale-leaf tear, not a handoff-forced fork-shrink.  Kept
		 * as an A/B lever via mxfs_dir_handoff_adopt, default 1 = original.) */
		extern int mxfs_dir_handoff_adopt;
		if (mxfs_dir_handoff_adopt &&
		    mxfs_v5_dlm_inode_grant_handoff(mp->m_mxfs_dlm, ip->i_ino,
						    &handoff_gg) &&
		    handoff_gg != 0 &&
		    handoff_gg != ip->i_dlm_handoff_acted_gen) {
			genuine_handoff = true;
			/* tenure boundary — see epoch-adopt arm. */
			mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
			ip->i_mxfs_ex_grant_seq =
				atomic64_inc_return(&mxfs_ex_epoch);
			mxfs_probe_ratelimited(
				"mxfs: P63-HANDOFF ino=%llu grant_gen=%u acted_gen=%u post_release=%d fmt=%u dir_gen=%u loaded_gen=%u — cross-node EX handoff; forcing disk-superset adopt\n",
				(unsigned long long)ip->i_ino, handoff_gg,
				ip->i_dlm_handoff_acted_gen, post_release ? 1 : 0,
				ip->i_df.if_format, ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen);
		}
	}

	/*
	 * ROOT FIX (instrumented, PROVEN by the s36 run5-iter1 timeline):
	 * if THIS inode's own log item still has mods in flight (dirty /
	 * in-AIL / pinned / ili_fields pending), then no peer can have
	 * modified the inode since — peer modification requires the EX,
	 * and our release fence drains the inode before any handoff
	 * (Invariant 1).  The in-core inode is therefore the freshest
	 * state in the cluster and ANY reload source (cached buffer or
	 * platter) is same-or-older.  Proceeding regresses the fork:
	 * test10 grew the dir nx 22→23 (nlink 1144), its cluster write
	 * was still in flight at the next fastex re-acquire, the P34D
	 * platter adoption rolled the in-core back to nx=22/nlink=1140,
	 * and the fresh bmbt FUA-read (23 records) mismatched → "corrupt
	 * dinode 131 (btree extents)" EUCLEAN mkdir failures; the same
	 * rollback shrinks i_size over just-created dirents (the durable
	 * silent-loss + the iter3 cluster-wide leaf1/node poisoning).
	 * Skip the reload outright; our own state stands.
	 *
	 * SCOPE FIX (PROVEN BY INSTRUMENT — 16-node cross_write_read durable
	 * dirent loss, repro_dirent_capture.sh): this self-skip MUST NOT apply
	 * to a SHORTFORM (LOCAL-format) DIRECTORY.  Proven failure timeline
	 * (dir ino=165): nodeN added its own dirent, RELEASED EX (Invariant 1
	 * drained the dinode — and a shortform dir's ENTIRE content lives in
	 * that dinode literal area, so disk now holds nodeN's entry), a PEER
	 * then acquired EX, added f_9, and drained the dinode (disk now holds
	 * BOTH).  nodeN re-acquires EX (slow path, stale=1) but its log item is
	 * still pinned/dirty (ili_fields=0x4001 pin=1) from its OWN earlier add
	 * that is committed-but-not-yet-checkpointed.  The old condition then
	 * self-skipped, kept the STALE in-core shortform dir (missing f_9), and
	 * xfsaild later flushed it (P36-DINO-WR) → durably CLOBBERED the peer's
	 * f_9.  The invariant ("own mods in flight ⇒ no peer modified
	 * since") is FALSE once we have released and re-acquired: the peer's
	 * intervening modification is on disk.  For shortform dirs that disk
	 * dinode is a strict SUPERSET (our drained entry + peer's), so adopting
	 * it cannot lose our own entry.  The regression it guards was an
	 * EXTENTS/BTREE-format inode (nx 22→23, "btree extents") whose separate
	 * fork blocks can genuinely be in-flight-not-yet-drained at a fastex
	 * re-acquire — that case keeps the skip.  Scope: skip-the-skip only for
	 * LOCAL-format dirs.
	 */
	{
	/*
	 * sess58 ROOT FIX (instrumented, PROVEN by P58-SELFSKIP-STALE-DIR +
	 * P58-STALE-BASE-ADD pino=131 dir_gen=379 loaded_gen=323): the sess49
	 * "skip-the-skip" was scoped to SHORTFORM dirs only.  A BLOCK/LEAF
	 * (non-LOCAL) directory under concurrent multi-node create hit this
	 * self-skip on a post-release reacquire while a peer had grown it
	 * (dir_gen >> loaded_gen) — the skip kept the STALE in-core base, and
	 * the subsequent dirent RMW + release-drain durably ERASED every peer
	 * dirent committed between loaded_gen and dir_gen (the zero_silent_loss
	 * silent dirent loss, e.g. node14_dir1 absent even to its creator).
	 *
	 * Extend the exemption to ALL directories on the POST-RELEASE path: we
	 * released the DLM lock and re-acquired from NL, so Invariant 1 drained
	 * our dir blocks at release — on-disk is a strict SUPERSET (our entries
	 * + the peer's) and adopting it cannot lose our own work.  The sess36
	 * regression (in-flight dir-grow rolled back) was a same-tenure FASTEX
	 * refresh (post_release=false); that path still keeps the skip, so no
	 * regression.  Shortform stays exempt on BOTH paths (its dinode is
	 * always a superset).
	 */
	/*
	 * ROOT FIX (instrumented, PROVEN by the P58-SELFSKIP-STALE-DIR
	 * discriminator: ino=131 fmt=2/3 post_release=0 dir_gen=388
	 * loaded_gen=332 pin=1 self_created=0 ex_pop=1 ex_nslots=1 held=1).
	 * ex_pop=1/held=1 REFUTES concurrent-EX — this node alone holds the
	 * dir-inode EX.  The clobber is a single-holder STALE-BASE
	 * lost-update on the FASTEX (post_release=0) re-acquire that the
	 * post_release exemption did not cover.
	 *
	 * Whenever a NON-self-created dir has i_dlm_dir_gen advanced past
	 * i_dlm_dir_loaded_gen, a PEER committed dir modifications since our
	 * in-core base loaded.  A peer modification requires the peer to hold
	 * the dir-inode EX, which REQUIRES this node to have released it
	 * first — and our release fence drains our dir blocks to the shared
	 * LUN (Invariant 1) before any handoff.  So on-disk is a strict
	 * SUPERSET (our drained entries + the peer's) and reloading it cannot
	 * lose our own work, EVEN THOUGH our log item still shows
	 * pinned/in-AIL (committed-but-not-yet-checkpointed; its content is
	 * already durable).  Keeping the stale in-core base here and RMW'ing
	 * it durably ERASES the peer's gen-(loaded_gen..dir_gen] dirents =
	 * the zero_silent_loss durable dirent loss.
	 *
	 * The regression this self-skip guards is a SAME-TENURE
	 * in-flight dir-grow (we never released; our own un-drained block is
	 * the freshest).  That case does NOT advance i_dlm_dir_gen — the gen
	 * is bumped only by a PEER's commit notify — and on a self-created,
	 * never-BASTed dir the 0->1 arming artifact is excluded by
	 * !i_mxfs_self_created.  So peer_modified_since_load is false in the
	 * scenario and the skip is preserved: no regression.
	 */
	bool peer_modified_since_load = S_ISDIR(VFS_I(ip)->i_mode) &&
		!ip->i_mxfs_self_created &&
		(ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen ||
		 /* the RELIABLE handoff signal — a peer held EX since our
		  * last grant — even when the lossy evict-ring left dir_gen behind. */
		 genuine_handoff);
	/*
	 * sess8 (2/tcp) FIX: the UNCONDITIONAL shortform (LOCAL) exemption was
	 * the resurrection bug.  It forced disk adoption on a SAME-TENURE reload
	 * (post_release=false AND peer NOT modified — e.g. the FASTEX dir-EX
	 * refresh, reload_inode post_release=false) where THIS node holds EX and
	 * has a committed-not-yet-checkpointed DELETE in flight (rm/rename-away).
	 * The on-disk dinode still carries the entry (our delete isn't destaged
	 * yet), so adopting it ROLLED BACK our own delete = the durable dirent
	 * RESURRECTION (dlm_fairness `shared dir drained got=1`, crash_consistency
	 * `got=98`; PROVEN this session NOT a double-grant / NOT split-brain:
	 * P-DOUBLEGRANT=0 + P-STALEMASTER-GRANT=0 at failures).  "disk is a strict
	 * superset" holds only AFTER we released (post_release: Invariant-1 drained
	 * our entries incl. the delete) OR when a PEER genuinely modified
	 * (peer_modified_since_load — which itself requires we released first).  In
	 * the same tenure with no peer modify, OUR in-core (with the delete) is the
	 * freshest state and must NOT be reverted.  Gate shortform on the SAME
	 * condition block/leaf dirs already use safely (sess58/59).  The sess49
	 * shortform case it was added for was post_release=true (release+reacquire),
	 * so that fix is preserved. */
	bool mxfs_dir_disk_superset = S_ISDIR(VFS_I(ip)->i_mode) &&
		(post_release || peer_modified_since_load);
	if (!mxfs_dir_disk_superset && ip->i_itemp &&
	    (test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags) ||
	     test_bit(XFS_LI_DIRTY, &ip->i_itemp->ili_item.li_flags) ||
	     ip->i_itemp->ili_fields ||
	     atomic_read(&ip->i_pincount) > 0)) {
		/* instrumented PROOF: an ALWAYS-ON (rate-
		 * limited) fire for a DIRECTORY whose gen says a peer modified it
		 * since our blocks loaded (dir_gen > loaded_gen).  If this self-skip
		 * keeps a stale block/leaf-dir base after a release+reacquire, the
		 * following RMW erases the peer's committed dirents (the proven
		 * durable lost-update: P58-STALE-BASE-ADD pino=131 dir_gen=109
		 * loaded_gen=12).  exempted SHORTFORM dirs from this skip for
		 * exactly this reason; block/leaf dirs were NOT exempted and that is
		 * the gap.  Fires rarely (only on the stale-skip), so non-perturbing. */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen) {
			static atomic_t p58ss_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p58ss_n) <= 600) {
				/* instrumented DISCRIMINATOR: read the CAW
				 * inode-EX popcount AT the clobber site.  This
				 * self-skip is about to keep a STALE in-core dir
				 * base (dir_gen > loaded_gen: a peer modified the
				 * dir) and the next RMW will erase the peer's
				 * dirents.  ex_pop>1 => a peer holds the dir-inode
				 * EX RIGHT NOW too == mutual-exclusion violation
				 * (hypothesis A: concurrent EX, no reload fix can
				 * help).  ex_pop<=1 => single holder, this is a
				 * stale-FASTEX-base clobber-after-commit
				 * (hypothesis B: the reload/self-skip is the
				 * fixable root).  Fires only on the rare stale
				 * skip, so the synchronous slot read is fine. */
				int p58_exn = 0;
				int p58_exp = mxfs_v5_dlm_inode_ex_count(
					mp->m_mxfs_dlm, ip->i_ino, &p58_exn);

				mxfs_pal_log(MXFS_LOG_DEBUG,
					"mxfs: P58-SELFSKIP-STALE-DIR ino=%llu fmt=%d post_release=%d dir_gen=%llu loaded_gen=%u in_ail=%d dirty=%d fields=0x%x pin=%d self_created=%d ex_pop=%d ex_nslots=%d held=%d",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format, post_release ? 1 : 0,
					(unsigned long long)ip->i_dlm_dir_gen,
					ip->i_dlm_dir_loaded_gen,
					!!test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags),
					!!test_bit(XFS_LI_DIRTY, &ip->i_itemp->ili_item.li_flags),
					ip->i_itemp->ili_fields,
					atomic_read(&ip->i_pincount),
					ip->i_mxfs_self_created ? 1 : 0,
					p58_exp, p58_exn,
					mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm, ip->i_ino));
			}
		}
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited(
				"mxfs: P36-RELOAD-SELFSKIP ino=%llu in_ail=%d dirty=%d fields=0x%x pin=%d — own mods in flight, in-core authoritative\n",
				(unsigned long long)ip->i_ino,
				!!test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags),
				!!test_bit(XFS_LI_DIRTY, &ip->i_itemp->ili_item.li_flags),
				ip->i_itemp->ili_fields,
				atomic_read(&ip->i_pincount));
		ip->i_dlm_stale = false;
		return;
	}
	}

	/*
	 * Invalidate the local buffer cache entry for this inode's
	 * cluster buffer.  The other node wrote updated data to this
	 * LBA on disk, but our buffer cache still has the old copy.
	 * Staling the buffer clears XBF_DONE, forcing xfs_imap_to_bp
	 * to re-read from disk.
	 */
	{
		struct xfs_buf	*stale_bp = NULL;
		bool		reload_owned_skip = false;

		/*
		 * prior-owner skip (mxfs_reload_skip_owned, default off).
		 * SCOPE: only the mode==0 arm — an in-core mode==0 shell means THIS
		 * node locally freed the inode (a peer free sets i_dlm_stale via the
		 * evict-ring, it does NOT zero our in-core mode); a first-read of a
		 * peer's inode has mode!=0 (iget read it from disk).  So mode==0 =
		 * we are RE-CREATING our OWN just-freed inode number.
		 * SIGNAL: mxfs_v5_dlm_inode_grant_handoff returns the CAW slot's
		 * `handoff` bit = "the last EX-class holder was a DIFFERENT node".
		 * When FALSE (self/none was last EX), no peer wrote since our free →
		 * the cached cluster is authoritative → the stale + cache-bypassing
		 * FUA re-read is pure waste (the 32-node storm).  When TRUE (a peer
		 * re-created our freed number, e.g. cross-node dir_reuse), fall
		 * through to the stale => coherent.  (Do NOT gate on the epoch/gen:
		 * CAW epochs restart to 0 on slot reclamation, which false-skipped a
		 * genuine first-read-of-peer-data => cache_coherency@4=0/4, .)
		 */
		if (mxfs_reload_skip_owned && VFS_I(ip)->i_mode == 0 &&
		    !genuine_handoff) {
			uint32_t sk_gg = 0;
			bool sk_peer_ex = mxfs_v5_dlm_inode_grant_handoff(
				mp->m_mxfs_dlm, ip->i_ino, &sk_gg);

			reload_owned_skip = !sk_peer_ex;
		}

		if (xfs_buf_incore(mp->m_ddev_targp, ip->i_imap.im_blkno,
				   ip->i_imap.im_len, 0, &stale_bp) == 0) {
			/*
			 * sess91-class guard (applied here):
			 * never clear XBF_DONE on a cluster buffer carrying
			 * this node's logged-but-not-checkpointed mods to a
			 * co-resident inode — the forced re-read replaces the
			 * buffer content with platter state, the BLI never
			 * re-applies the logged delta, and the eventual AIL
			 * push writes the OLD content back = durable lost
			 * update (P20-CLUSTER-INVAL site=reload li_empty=0
			 * observed immediately before the daddr-0x78 dir
			 * corruption).  Matches the guards in
			 * xfs_iget_recycle / xfs_iget_cache_miss.
			 */
			if (mxfs_buf_has_uncheckpointed_mods(stale_bp)) {
				mxfs_probe_ratelimited(
				    "mxfs: P91-RELOAD-PROTECT ino=0x%llx blkno=0x%llx flags=0x%x — keeping in-core authoritative cluster buffer\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_imap.im_blkno,
				    stale_bp->b_flags);
				kept_protected = true;
			} else if (reload_owned_skip) {
				/*
				 * no cross-node EX handoff -> no peer wrote
				 * this inode -> the cached cluster is already the
				 * authoritative image.  Keep it (do NOT stale, do NOT
				 * clear XBF_DONE, do NOT set kept_protected — that arm
				 * forces a private FUA read at ~L15283): the buffer
				 * stays DONE so xfs_imap_to_bp below cache-HITS it with
				 * NO bio and adopts the unchanged image = coherent
				 * no-op, eliminating the wasteful FUA re-read (storm).
				 */
				mxfs_probe_ratelimited(
				    "mxfs: P-RELOAD-SKIP-OWNED ino=0x%llx blkno=0x%llx flags=0x%x — no peer handoff, kept cached cluster (FUA re-read averted)\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_imap.im_blkno,
				    stale_bp->b_flags);
			} else {
				if (unlikely(mxfs_read_attr_probe)) {
					long long m0, mn;

					if (VFS_I(ip)->i_mode == 0)
						atomic64_inc(&mxfs_reload_stale_mode0);
					else {
						atomic64_inc(&mxfs_reload_stale_moden);
						if (S_ISDIR(VFS_I(ip)->i_mode))
							atomic64_inc(&mxfs_reload_stale_ndir);
					}
					m0 = atomic64_read(&mxfs_reload_stale_mode0);
					mn = atomic64_read(&mxfs_reload_stale_moden);
					if (((m0 + mn) & 255) == 0)
						mxfs_probe("mxfs: RELOAD-STALE-SPLIT mode0=%lld modeN=%lld ndir=%lld last_mode=0%o post_rel=%d comm=%s\n",
							m0, mn,
							(long long)atomic64_read(&mxfs_reload_stale_ndir),
							VFS_I(ip)->i_mode, post_release,
							current->comm);
				}
				if (unlikely(mxfs_dirwr_enabled ||
					     mxfs_instr_enabled))
					mxfs_probe_ratelimited(
					    "mxfs: P20-CLUSTER-INVAL site=reload ino=0x%llx blkno=0x%llx flags=0x%x li_empty=%d pin=%d comm=%s\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_imap.im_blkno,
				    stale_bp->b_flags,
				    list_empty(&stale_bp->b_li_list) ? 1 : 0,
				    xfs_buf_ispinned(stale_bp),
				    current->comm);
				xfs_buf_stale(stale_bp);
				/* v0.3.99: force-clear XBF_DONE so re-read happens */
				stale_bp->b_flags &= ~XBF_DONE;
			}
			xfs_buf_relse(stale_bp);
		}
	}

	/*
	 * sess7(ccloop) FACE-2 FIX: bounded retry on a TRANSIENT reuse-window
	 * read error.  Under dir_reuse (rm-rf + recreate every round) the target
	 * inode's on-disk cluster is being freed/reallocated + rewritten by a
	 * peer, so this read can catch a torn/half-written cluster and fail the
	 * inode-buf verifier (rc=-EIO / -EFSCORRUPTED).  The OLD code bailed
	 * immediately, leaving i_dlm_stale set AND the in-core EXTENT MAP NOT
	 * rebuilt — the caller (e.g. xfs_create's fast-path dir_ex_stale_refresh)
	 * then RMWs/reads the dir through the STALE extent map, hits a stale/
	 * freed dir block, and xfs_trans_read_buf_map force-shuts-down the FS on
	 * the dirty transaction (SHUTDOWN_META_IO_ERROR — the 8/tcp + occasional
	 * 4/tcp dir_reuse mass shutdown; PROVEN: imap_to_bp rc=-5 ino=131 ->
	 * dir_create_child err=-5 -> Metadata I/O Error).  The reuse window is
	 * sub-ms; retry the read briefly so the reload SUCCEEDS and rebuilds the
	 * extent map to the current incarnation.  Bounded (~30ms) so a genuine
	 * hard error still bails gracefully as before.  Mirrors the sess9
	 * transient-imap retry in the durable path (~L3439). */
	{
		int rtry;

		rl_tpre = ktime_get_ns();	/* phase split */
		for (rtry = 0; rtry < 10; rtry++) {
			error = xfs_imap_to_bp(mp, NULL, &ip->i_imap, &bp);
			if (error != -EIO && error != -EFSCORRUPTED)
				break;
			msleep(3);
		}
		rl_tbp = ktime_get_ns();
	}
	if (error) {
		/* run83 forensics: 800 consecutive rc=-5 with no
		 * ioerror alert and no shutdown — name the imap daddr and the
		 * in-core cluster buffer's exact state so the silent-EIO source
		 * is attributable. */
		struct xfs_buf *fbp = NULL;

		if (xfs_buf_incore(mp->m_ddev_targp, ip->i_imap.im_blkno,
				   ip->i_imap.im_len, XBF_TRYLOCK, &fbp) == 0 &&
		    fbp) {
			mxfs_probe("mxfs: P-RELOAD-IMAPEIO ino=%llu rc=%d blkno=%lld len=%d berr=%d bflags=0x%x pin=%d has_bli=%d stale=%d done=%d fs_shut=%d log_shut=%d\n",
				(unsigned long long)ip->i_ino, error,
				(long long)ip->i_imap.im_blkno,
				ip->i_imap.im_len,
				fbp->b_error, fbp->b_flags,
				atomic_read(&fbp->b_pin_count),
				fbp->b_log_item ? 1 : 0,
				(fbp->b_flags & XBF_STALE) ? 1 : 0,
				(fbp->b_flags & XBF_DONE) ? 1 : 0,
				xfs_is_shutdown(mp) ? 1 : 0,
				xlog_is_shutdown(mp->m_log) ? 1 : 0);
			xfs_buf_relse(fbp);
		} else {
			mxfs_probe("mxfs: P-RELOAD-IMAPEIO ino=%llu rc=%d blkno=%lld len=%d NO-INCORE fs_shut=%d log_shut=%d\n",
				(unsigned long long)ip->i_ino, error,
				(long long)ip->i_imap.im_blkno,
				ip->i_imap.im_len,
				xfs_is_shutdown(mp) ? 1 : 0,
				xlog_is_shutdown(mp->m_log) ? 1 : 0);
		}
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: DLM inode reload imap_to_bp failed: ino=%llu rc=%d",
			(unsigned long long)ip->i_ino, error);
		ip->i_dlm_stale = false;
		return;
	}

	dip = xfs_buf_offset(bp, ip->i_imap.im_boffset);

	/*
	 * 0.89.0 (D-0977): AN EXPOSED SHELL'S INCARNATION IS IMMUTABLE.  A
	 * shell with open descriptors or live mappings names one incarnation
	 * to its users; if the platter's dinode is a DIFFERENT one (freed:
	 * mode 0 with the freed generation; reused: another generation, any
	 * mode), no adopt arm below may rebuild this shell's forks from it —
	 * the descriptor would then read or write the successor file's bytes
	 * (measured s62d: 4096 'G' through a held fd).  Poison instead: the
	 * gates refuse -ESTALE / SIGBUS, the revocation worker zaps the PTEs
	 * and discards the page cache (never flushes it: those pages were
	 * dirtied through a bmap whose blocks belong to another file now),
	 * and the shell retires at its last iput.  A shell this node is still
	 * authoring (dirty, pinned, in the AIL, unpublished) is ahead of the
	 * platter by design and is judged by the in-core-authoritative arms
	 * below, not here.
	 */
	/*
	 * 0.89.1 (D-0979): "exposed" means a descriptor that is USABLE — an
	 * open still inside its protecting acquire is counted for the mark
	 * but has not yet been handed an incarnation, and this reload, under
	 * that very acquire, is what decides which one it gets.  Measured
	 * s65b: B opened a file whose number the peer had reused since B last
	 * cached it; the two descriptors of that open counted as exposure of
	 * the OLD incarnation, the shell was poisoned, and a freshly opened,
	 * valid file read -ESTALE.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    VFS_I(ip)->i_mode != 0 &&
	    be32_to_cpu(dip->di_gen) != VFS_I(ip)->i_generation &&
	    mxfs_inode_exposed(ip) &&
	    !ip->i_dlm_unpublished && xfs_inode_clean(ip) &&
	    atomic_read(&ip->i_pincount) == 0) {
		pr_warn("mxfs: P977-RELOAD-EXPOSED-MISMATCH ino=%llu incore_gen=%u disk_gen=%u incore_mode=0%o disk_mode=0%o opens=%d inflight=%d mapped=%d dlm_mode=%u — the platter names another incarnation under live descriptors; poisoning the shell instead of adopting\n",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
			VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
			atomic_read(&ip->i_mxfs_open_n),
			atomic_read(&ip->i_mxfs_open_inflight),
			mapping_mapped(VFS_I(ip)->i_mapping) ? 1 : 0,
			ip->i_dlm_mode);
		xfs_buf_relse(bp);
		mxfs_incarn_poison(ip);
		return;
	}

	/*
	 * P31B-RELOAD-BUF DECISIVE INSTRUMENT (instrumented,
	 * FACE B disambiguation): the dir_reuse_coherency lookup-hole is an iget
	 * returning -ENOENT for a name whose inode shows LIVE on the coherent
	 * medium (P-IGET-ENOENT incore_mode=0 cached_disk_mode=0x81a4).  reload
	 * IS reached (it clears i_dlm_stale 1->0) yet in-core mode stays 0.  The
	 * question: does reload's buffer (dip) itself read mode==0 here (stale
	 * cluster buffer or peer-not-yet-durable) — vs reload reading 0x81a4 and a
	 * downstream bail keeping mode 0?  Log reload's buffer dinode AND a
	 * coherent plain-read at the same instant, for the in-core-FREE non-dir
	 * case only (bounded to reused/freed inodes), capped.
	 */
	if (VFS_I(ip)->i_mode == 0 && !S_ISDIR(be16_to_cpu(dip->di_mode)) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		static atomic_t p31b_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p31b_n) <= 1500) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t cl = BBTOB(ip->i_imap.im_len);
			void *ct = ((cl & 511) == 0 && cl) ?
				kmalloc(cl, GFP_NOFS) : NULL;
			uint16_t coh_mode = 0xffff;
			uint8_t coh_fmt = 0xff;
			uint32_t coh_gen = 0;

			if (ct && mxfs_pal_bdev_read_plain_bdev(
			    mp->m_ddev_targp->bt_bdev,
			    (uint64_t)ip->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset,
			    ct, cl) == 0) {
				struct xfs_dinode *cd = (struct xfs_dinode *)
					((char *)ct + ip->i_imap.im_boffset);
				coh_mode = be16_to_cpu(cd->di_mode);
				coh_fmt = cd->di_format;
				coh_gen = be32_to_cpu(cd->di_gen);
			}
			mxfs_probe("mxfs: P31B-RELOAD-BUF ino=0x%llx incore_gen=%u BUF[mode=0x%x fmt=%u gen=%u flags=0x%x] COH[mode=0x%x fmt=%u gen=%u] post_release=%d\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation,
				be16_to_cpu(dip->di_mode), dip->di_format,
				be32_to_cpu(dip->di_gen), bp->b_flags,
				coh_mode, coh_fmt, coh_gen, post_release ? 1 : 0);
			kfree(ct);
		}
	}

	/*
	 * P133-DINO-READSTALE (instrumented): the dabuf-HOLE shutdown shows
	 * the dir lookup using a dinode one growth behind the on-disk leaf.
	 * Two candidate producers: (A) a peer's stale write reverted the
	 * on-disk dinode (caught by P133-DIRINO-REVERT in xfs_buf.c), or
	 * (B) THIS reload was served a stale cached cluster buffer despite
	 * the stale-invalidate above.  Discriminate (B) directly: plain-read
	 * the coherent on-disk cluster and compare the dinode the buffer
	 * handed us.  Fires only on mismatch.  DIR inodes only.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) ||
	    S_ISDIR(be16_to_cpu(dip->di_mode))) {
		extern int	mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
		struct xfs_buftarg *p133_tp = mp->m_ddev_targp;
		uint32_t	p133_len = BBTOB(ip->i_imap.im_len);
		void		*p133_tmp;
		static atomic_t	p133_rsn = ATOMIC_INIT(0);

		p133_tmp = ((p133_len & 511) == 0 && p133_len) ?
			kmalloc(p133_len, GFP_NOFS) : NULL;
		if (p133_tmp && p133_tp && p133_tp->bt_bdev &&
		    mxfs_pal_bdev_read_plain_bdev(p133_tp->bt_bdev,
			(uint64_t)ip->i_imap.im_blkno + p133_tp->bt_sector_offset,
			p133_tmp, p133_len) == 0) {
			struct xfs_dinode *p133_dd =
				p133_tmp + ip->i_imap.im_boffset;
			/* < a864 > VARIANT-AGNOSTIC R-a/R-b probe.
			 * di_size/nx/fmt alone MISS the two observed dir_reuse@32
			 * corruptions: the bmbt case (same nx/fmt, but the broot's
			 * child pointers differ — one names a repurposed block) and
			 * the torn-shortform case (same fmt=LOCAL, but garbage sf
			 * bytes, namelen=0).  Also compare di_changecount and MEMCMP
			 * the whole data-fork region, so ANY divergence between the
			 * adopted buffer (dip) and the coherent cluster (p133_dd) is
			 * caught.  FIRE => the adopt served a STALE/TORN buffer while
			 * the coherent cluster differs (R-b, reader-side).  If a run
			 * still corrupts with NO fire, the coherent image itself is
			 * bad (R-a, writer-side) or the corruption is post-adopt. */
			{
				int	dsz = XFS_DFORK_DSIZE(dip, mp);
				int	dfdiff = (dsz > 0) ? memcmp(
					XFS_DFORK_PTR(dip, XFS_DATA_FORK),
					XFS_DFORK_PTR(p133_dd, XFS_DATA_FORK),
					dsz) : 0;
				uint64_t buf_chg =
					be64_to_cpu(dip->di_changecount);
				uint64_t coh_chg =
					be64_to_cpu(p133_dd->di_changecount);
				bool	fld = p133_dd->di_size != dip->di_size ||
					p133_dd->di_nextents != dip->di_nextents ||
					p133_dd->di_format != dip->di_format;

				if ((fld || dfdiff != 0 || buf_chg != coh_chg) &&
				    atomic_inc_return(&p133_rsn) <= 200) {
					uint8_t *bd = (uint8_t *)XFS_DFORK_PTR(
						dip, XFS_DATA_FORK);
					uint8_t *cd = (uint8_t *)XFS_DFORK_PTR(
						p133_dd, XFS_DATA_FORK);

					mxfs_probe("mxfs: P133-DINO-READSTALE ino=%llu buf[size=%lld nx=%u fmt=%u gen=%u chg=%llu] disk[size=%lld nx=%u fmt=%u gen=%u chg=%llu] fldiff=%d dforkdiff=%d bpflags=0x%x — %s\n",
						(unsigned long long)ip->i_ino,
						(long long)be64_to_cpu(dip->di_size),
						be32_to_cpu(dip->di_nextents),
						dip->di_format,
						be32_to_cpu(dip->di_gen),
						(unsigned long long)buf_chg,
						(long long)be64_to_cpu(p133_dd->di_size),
						be32_to_cpu(p133_dd->di_nextents),
						p133_dd->di_format,
						be32_to_cpu(p133_dd->di_gen),
						(unsigned long long)coh_chg,
						fld ? 1 : 0, dfdiff, bp->b_flags,
						(coh_chg > buf_chg || dfdiff != 0) ?
						"ADOPT-SERVED-STALE(R-b): coherent cluster newer/differs from adopted buffer" :
						"buf-not-behind-coherent (check R-a / writer-side)");
					mxfs_probe("mxfs: P133-DFORK-BYTES ino=%llu buf=[%02x %02x %02x %02x %02x %02x %02x %02x] coh=[%02x %02x %02x %02x %02x %02x %02x %02x]\n",
						(unsigned long long)ip->i_ino,
						bd[0], bd[1], bd[2], bd[3],
						bd[4], bd[5], bd[6], bd[7],
						cd[0], cd[1], cd[2], cd[3],
						cd[4], cd[5], cd[6], cd[7]);
				}
			}
		}
		kfree(p133_tmp);
	}

	mxfs_idbg(
		"mxfs: DLM reload ino=%llu disk_fmt=%u disk_size=%lld disk_mode=0x%x disk_nlink=%u disk_nblocks=%llu",
		(unsigned long long)ip->i_ino,
		dip->di_format,
		(long long)be64_to_cpu(dip->di_size),
		be16_to_cpu(dip->di_mode),
		be32_to_cpu(dip->di_nlink),
		(unsigned long long)be64_to_cpu(dip->di_nblocks));

	/*
	 * ALWAYS-ON: detect the self-loss mechanism.  If we already
	 * hold a NONZERO in-memory size for a regular file but the on-disk
	 * dinode we are about to reload from says di_size=0, this reload is
	 * about to CLOBBER our good size with a stale zero -> the file reads
	 * EMPTY afterwards (the "node loses its own files 11-20" residual).
	 * Means our own create's di_size update had not reached the on-disk
	 * inode cluster before a peer BAST forced this cluster's reload.
	 * Fires only on the bug; not instr-gated.
	 */
	/*
	 * FIX (proven via RELOAD-SIZE-DROP): if reloading this regular
	 * file would CLOBBER our nonzero in-memory size with a stale on-disk
	 * di_size=0 + nblocks=0 (the inode's allocation-time image, because our
	 * own create's di_size/nblocks update had not yet been iflushed to the
	 * cluster when a peer BAST forced this reload), DO NOT reload.  Our
	 * in-memory state is authoritative — each node writes only its own
	 * regular files, so disk can only legitimately differ by being NEWER,
	 * never by reverting a written file back to empty.  Keeping the
	 * in-memory inode preserves the file content (fixes "a node loses its
	 * own just-created files" in cache_coherency/rename_visibility); the
	 * dirty state reaches disk via the normal iflush.  The earlier
	 * pinned/in-AIL skip missed this because the create's change can sit in
	 * the CIL transiently with neither flag set at reload time, so the
	 * decisive test is the on-disk image itself.
	 */
	/*
	 * drop the nblocks==0 requirement.  The proven owner-self-
	 * clobber (P97, dlm_mode=EX) is a peer-read-induced BAST forcing this
	 * EX holder to downconvert+reload; the reload's FUA read pierces to
	 * the platter and can return a TORN image — di_size=0 while
	 * di_nblocks is already the written value (the size update reached the
	 * SCST write cache but is not yet destaged when the size field is
	 * read).  With the old nblocks==0 guard the skip MISSED that torn read,
	 * so the reload set our own in-core di_size to 0 and we then flushed 0
	 * back over the good on-disk size (the cross_write_read di_size=0
	 * empty-content root).  For a regular file, a peer never truncates our
	 * file to 0 (each node writes only its own files), so an on-disk
	 * di_size==0 while we hold a NONZERO in-memory size is ALWAYS a stale/
	 * torn read — keep the authoritative in-memory inode regardless of the
	 * on-disk nblocks.
	 */
	/*
	 * FIX (instrument step 2b — PROVEN via the inode 6291588 reuse
	 * timeline): the size-drop-skip protection is ONLY valid for the SAME
	 * incarnation.  Its premise ("a peer never truncates our file to 0")
	 * assumes the on-disk dinode is the very inode we hold in core.  Under
	 * inode-number REUSE that premise is false: a peer FREED our inode and
	 * REALLOCATED the number as a brand-new file (di_size=0 because it has
	 * no content yet, di_gen = a fresh value != our in-core generation).
	 * Keeping our stale prior incarnation here is the bug — we then go on
	 * to UNLINK/INACTIVATE that ghost (it has our old nlink/extent/unlinked
	 * state), double-freeing the peer's live inode's blocks (bnobt
	 * ltbno+ltlen>bno, xfs_alloc.c:2244) or corrupting the AGI unlinked
	 * list (xfs_iunlink_remove_inode line 632, P71-INSTR disk_dimode shows a
	 * LIVE peer file).  GATE the skip on di_gen == in-core generation: only
	 * a same-incarnation di_size=0 is the torn/own-clobber read we must
	 * defend against.  A different di_gen means genuine reuse — fall through
	 * to xfs_inode_from_disk below and adopt the peer's new incarnation so
	 * we never inactivate a number a peer owns live.
	 */
	/*
	 * FIX (instrument step 2b — PROVEN by the trunc_legal probe,
	 * ino=8388737/132, D-PEER-TRUNCATE-INVISIBLE-TO-PRIOR-HOLDER): the
	 * premise "a peer never truncates our file to 0" is a WORKLOAD
	 * assumption, not POSIX.  B's truncate -s 0 ran correctly under EX
	 * after a clean BAST handoff (P3-EFREE-Q freed the extent), and this
	 * skip then made A serve the OLD size and re-read the FREED extent
	 * through its kept stale extent map forever (23s+ verified; if the
	 * block is reallocated that read becomes a cross-file leak).
	 *
	 * The skip's legitimate target — a torn/lagging image of OUR OWN
	 * in-flight write (P97: BAST-forced downconvert reload mid-tenure;
	 * CIL-transient create) — only exists MID-TENURE.  Every
	 * post_release=true reload runs under a FRESH grant after our prior
	 * tenure's release drain (Invariant 1: drain_meta/alloc/inode +
	 * blkdev_flush BEFORE unlock), so our own writes are on the platter
	 * and a same-gen disk_size=0 is a peer's legitimate shrink: ADOPT it
	 * (fall through rebuilds size + extent map; the release already
	 * invalidated our pages).  Keep the skip for mid-tenure reloads,
	 * where the torn-own-image hazard is real and proven.
	 */
	if (S_ISREG(VFS_I(ip)->i_mode) && ip->i_disk_size > 0 &&
	    be64_to_cpu(dip->di_size) == 0 &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    !post_release) {
		mxfs_pal_log(MXFS_LOG_ERR,
			"mxfs: RELOAD-SIZE-DROP-SKIP ino=%llu mem_size=%lld disk_size=0 disk_nblocks=%llu gen=%u — keeping authoritative in-memory inode (same incarnation, mid-tenure)",
			(unsigned long long)ip->i_ino,
			(long long)ip->i_disk_size,
			(unsigned long long)be64_to_cpu(dip->di_nblocks),
			(unsigned)VFS_I(ip)->i_generation);
		xfs_buf_relse(bp);
		ip->i_dlm_stale = false;
		return;
	}
	if (S_ISREG(VFS_I(ip)->i_mode) && ip->i_disk_size > 0 &&
	    be64_to_cpu(dip->di_size) == 0 &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    post_release) {
		mxfs_probe_ratelimited(
			"mxfs: P96-RELOAD-PEER-SHRINK-ADOPT ino=%llu mem_size=%lld disk_size=0 disk_nblocks=%llu gen=%u — fresh tenure (post-release): same-gen size drop is a peer's shrink; adopting disk\n",
			(unsigned long long)ip->i_ino,
			(long long)ip->i_disk_size,
			(unsigned long long)be64_to_cpu(dip->di_nblocks),
			(unsigned)VFS_I(ip)->i_generation);
	}
	if (S_ISREG(VFS_I(ip)->i_mode) && ip->i_disk_size > 0 &&
	    be64_to_cpu(dip->di_size) == 0 &&
	    be32_to_cpu(dip->di_gen) != VFS_I(ip)->i_generation) {
		/* was an unratelimited MXFS_LOG_ERR — under inode-reuse churn it
		 * floods thousands/run (3727 at 4/tcp dir_reuse), which is harmless to a
		 * ring buffer but CATASTROPHIC to a 115200-baud serial console (blocks
		 * the CPU printk-by-printk).  Rate-limit it so a serial console can be
		 * used to capture real hung-task/lockup stacks. */
		mxfs_probe_ratelimited(
			"mxfs: P103-RELOAD-REUSE-ADOPT ino=%llu mem_size=%lld disk_size=0 incore_gen=%u disk_gen=%u disk_mode=0%o — adopting peer's reused incarnation (gen differs)\n",
			(unsigned long long)ip->i_ino,
			(long long)ip->i_disk_size,
			(unsigned)VFS_I(ip)->i_generation,
			(unsigned)be32_to_cpu(dip->di_gen),
			(unsigned)be16_to_cpu(dip->di_mode));
	}

	/*
	 * FIX (instrument step 2b — proven via P-RELOAD-TYPEFLIP +
	 * P90-PICK): a reload that FLIPS the inode TYPE (S_IFMT) is only
	 * legitimate when the on-disk inode is a STRICTLY NEWER incarnation,
	 * i.e. the number was freed and reused (which always bumps di_gen —
	 * mxfs increments the generation by +1 on reuse, confirmed by the
	 * off-by-one incore=949/disk=950 type-flips).  A type-flip with
	 * disk_gen <= incore_gen is therefore impossible in a correct FS: it
	 * is reading STALE or CORRUPT on-disk metadata —
	 *   - SAME gen (disk_gen == incore_gen, the node4 unlink_visibility
	 *     `Not a directory` case, ino=2097285): a peer flushed a stale
	 *     16KB inode-cluster buffer carrying an OLD REG incarnation of
	 *     this inode (same gen) over our committed DIR (P97
	 *     INODE-CLUSTER-CLOBBER).  Adopting it flips our live, in-use
	 *     directory to a regular file → every child path resolution
	 *     returns ENOTDIR (30 unlink_visibility failures on node4).
	 *   - OLDER gen (disk_gen < incore_gen): a torn/behind-disk read.
	 * In both cases our in-core inode (a validly-constructed, live
	 * directory with entries) is authoritative.  REFUSE the reload and
	 * keep it — exactly like RELOAD-SIZE-DROP-SKIP above.  Only a
	 * strictly newer disk_gen (genuine reuse) is allowed to flip the
	 * type, and that path falls through to xfs_inode_from_disk +
	 * xfs_setup_iops below.
	 */
	/*
	 * FIX (instrument step 2b — proven via P95-TYPEFLIP-RELOAD thrash,
	 * ino=14680194 fired 125×): XFS generations are RANDOM, not monotonic,
	 * so `disk_gen <= incore_gen` is NOT a reliable "stale disk" signal.
	 * When the caller passed an authoritative dirent ftype (just read from
	 * the parent dir block) and the on-disk inode's type MATCHES it, the
	 * disk inode and the dirent AGREE — that is GROUND TRUTH of a genuine
	 * type-flip (number freed and reused), regardless of the gen relation.
	 * Only the torn/stale-cluster case has disk+dirent DISAGREEING
	 * (the dirent still shows the OLD type while a stale cluster buffer
	 * carries a different mode), so the guard below still fires for it.
	 */
	/*
	 *  ROOT FIX (instrument step 2b — PROVEN, see below):
	 * gate this skip on the SAME INCARNATION, exactly as already did
	 * for RELOAD-SIZE-DROP-SKIP above and for exactly the same reason.
	 *
	 * The guard's legitimate target is a stale/torn cluster image of the inode
	 * WE hold — and the comment above names that case as
	 * `disk_gen == incore_gen`.  The `<=` admitted a DIFFERENT incarnation
	 * too, and since XFS generations are RANDOM (own note, two
	 * comments up) "disk_gen < incore_gen" is a coin flip on genuine reuse,
	 * not evidence of staleness.  When the coin came up wrong this node kept a
	 * DEAD incarnation and its release drain then PUBLISHED that corpse over
	 * the peer's live inode — durable namespace corruption, agreed by every
	 * node, and the true root of D-DIRENT-INODE-TYPE-MISMATCH.
	 *
	 * Captured, 32/caw, ino 10485888 (`node15.txt`):
	 *   test15  creates dir ino 10485888, gen 2697616535
	 *   test15  frees it (EVICT-RING-FLAG freed_gen=2697616536)
	 *   test15  reuses the number for a REGULAR FILE, new gen 2379993492
	 *   test30  RELOAD-TYPEFLIP-STALE-SKIP incore_mode=040755
	 *           disk_mode=0100644 incore_gen=2697616535 disk_gen=2379993492
	 *           expect_ft=0        <-- reads the CORRECT image and rejects it
	 *   test30  P170-CLWR publishes 10485888:40755:..6535 two seconds after
	 *           test15 published 10485888:100644:..3492
	 *   every node then reads dirent ftype=REG against a DIR inode, the P95B
	 *   resolver spins 201 rounds and gives up, and P207-COHERENT-TRUTH shows
	 *   the platter itself holding the pre-free image.
	 *
	 * Note expect_ft=0 (UNKNOWN): this reload came from a release/BAST path,
	 * not from a lookup, so dirent-agreement escape hatch cannot
	 * engage and the broken gen comparison was the ONLY discriminator.
	 *
	 * mxfs.typeflip_skip_same_incarn=0 restores the `<=` comparison as a
	 * same-build negative control.
	 */
	/*
	 * Exposure counter for the fix above: this is exactly the state in which
	 * the legacy `<=` kept a dead incarnation.  A nonzero count is the fix
	 * engaging; comparing it against the corruption rate is the A/B.
	 */
	/*
	 * NOT gated on the knob, deliberately: this must count the DANGEROUS
	 * SUBSET in BOTH arms of the A/B.  Gating it on the fix made the control
	 * arm unmeasurable — the arm that reproduces the corruption reported zero
	 * exposure, so a passing control could not be told apart from a control
	 * that never entered the state at all.
	 */
	if ((VFS_I(ip)->i_mode & S_IFMT) != 0 &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) != 0 &&
	    (VFS_I(ip)->i_mode & S_IFMT) !=
		    (be16_to_cpu(dip->di_mode) & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) != VFS_I(ip)->i_generation &&
	    be32_to_cpu(dip->di_gen) <= VFS_I(ip)->i_generation &&
	    !(expect_ftype != XFS_DIR3_FT_UNKNOWN &&
	      xfs_mode_to_ftype(be16_to_cpu(dip->di_mode)) == expect_ftype)) {
		static atomic_t	p208n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p208n) <= 600)
			pr_warn("mxfs: P208-TYPEFLIP-REUSE ino=%llu action=%s incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u expect_ft=%u dlm_mode=%d — DIFFERENT incarnation whose random gen happens to be lower; action=keep retains a DEAD incarnation and will publish it\n",
				(unsigned long long)ip->i_ino,
				mxfs_typeflip_skip_same_incarn ? "adopt" : "keep",
				VFS_I(ip)->i_mode,
				be16_to_cpu(dip->di_mode),
				VFS_I(ip)->i_generation,
				be32_to_cpu(dip->di_gen),
				expect_ftype, ip->i_dlm_mode);
	}
	if ((VFS_I(ip)->i_mode & S_IFMT) != 0 &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) != 0 &&
	    (VFS_I(ip)->i_mode & S_IFMT) !=
		    (be16_to_cpu(dip->di_mode) & S_IFMT) &&
	    (mxfs_typeflip_skip_same_incarn ?
		be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation :
		be32_to_cpu(dip->di_gen) <= VFS_I(ip)->i_generation) &&
	    !(expect_ftype != XFS_DIR3_FT_UNKNOWN &&
	      xfs_mode_to_ftype(be16_to_cpu(dip->di_mode)) == expect_ftype)) {
		mxfs_pal_log(MXFS_LOG_ERR,
			"mxfs: RELOAD-TYPEFLIP-STALE-SKIP ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u expect_ft=%u — keeping authoritative in-core inode (type-flip w/o newer gen = stale/corrupt disk)",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
			VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
			expect_ftype);
		xfs_buf_relse(bp);
		ip->i_dlm_stale = false;
		/* in-core judged LIVE (dirent disagrees with disk) —
		 * any prior dead-incarnation verdict is overturned. */
		ip->i_mxfs_dead_incarn_gen = 0;
		return;
	}
	if (expect_ftype != XFS_DIR3_FT_UNKNOWN &&
	    (VFS_I(ip)->i_mode & S_IFMT) !=
		    (be16_to_cpu(dip->di_mode) & S_IFMT) &&
	    xfs_mode_to_ftype(be16_to_cpu(dip->di_mode)) == expect_ftype &&
	    be32_to_cpu(dip->di_gen) <= VFS_I(ip)->i_generation) {
		mxfs_pal_log(MXFS_LOG_ERR,
			"mxfs: RELOAD-TYPEFLIP-DIRENT-OK ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u expect_ft=%u — disk+dirent agree, allowing genuine type-flip despite gen",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
			VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
			expect_ftype);
		/* (D3 ROOT FIX): record the dirent-validated verdict —
		 * our in-core object is a DEAD PRIOR INCARNATION; the disk's
		 * di_gen names the live one.  If this reload gets bailed
		 * before adopting (P34J race with an active release drain —
		 * the PROVEN ino-167 clobber sequence), the drain's durable
		 * stage and xfs_iflush consult this to refuse re-logging /
		 * flushing the corpse over the peer's live slot.  Cleared on
		 * successful adoption below. */
		ip->i_mxfs_dead_incarn_gen = be32_to_cpu(dip->di_gen);
	}

	/*
	 * FREED-REUSE DIR GUARD (instrumented — PROVEN via the
	 * run-2 fence_during_write cascade forensics: ino=8928577 reload with
	 * incore_gen=3555416468 vs disk_gen=65196620, P62 incore_fmt=1 disk_fmt=2,
	 * then P-RELOAD-IOPS-REWIRE new_mode=00 immediately preceding an
	 * xfs_create -> xfs_dabuf_map !HOLE_OK -> EFSCORRUPTED -> dirty
	 * xfs_trans_cancel -> FS SHUTDOWN -> the fence/fault/soak/tcp_dlm_scaling
	 * cascade).
	 *
	 * The on-disk slot reads FREE (di_mode S_IFMT==0) but with a di_gen that
	 * DIFFERS from our live in-core directory's i_generation — i.e. the inode
	 * number was freed and REUSED (a new incarnation), so the free image does
	 * NOT belong to the incarnation our in-flight create/remove is operating
	 * on.  The guard below only KEEPS a disk-free image when we are
	 * dirty / hold the grant; a CLEAN NL holder falls through and ADOPTS it,
	 * believing a peer legitimately freed THIS inode — but a gen MISMATCH
	 * proves it is NOT this inode.  Adopting it rewires our live in-core dir
	 * to the freed image's {di_format=EXTENTS, nx=0} state (P-RELOAD-IOPS-
	 * REWIRE), which the imminent dir-block map reads as a HOLE -> shutdown.
	 * Our in-core inode (the older, live incarnation in use) is authoritative
	 * for the operation in flight; KEEP it.  A genuine peer free of OUR
	 * incarnation carries the SAME di_gen (handled by below); only a
	 * different gen reaches here, and a different gen is never our inode.
	 */
	if ((be16_to_cpu(dip->di_mode) & S_IFMT) == 0 &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    be32_to_cpu(dip->di_gen) != VFS_I(ip)->i_generation) {
		/*
		 *  (design-consult design review decision matrix): the
		 * unconditional keep-alive here was WRONG-SIDED for a CLEAN
		 * shell.  Dirty (undestaged local provenance: the op in
		 * flight that protected) still keeps the in-core dir
		 * — the platter is behind us.  But a CLEAN shell with a
		 * freed different-incarnation disk image is a CORPSE (with
		 * FIX-1 the platter is truthful at grant transfer): keeping
		 * it alive let the whole fleet run round 1 of dir_reuse
		 * inside a 5-minutes-dead dir (ino 165, run 140939Z).
		 * POISON it: ops -ESTALE at entry, shell retired, re-iget
		 * instantiates the live incarnation.  Never in-place adopt
		 * across incarnations (icache is keyed by ino).
		 */
		bool p52_dirty = atomic_read(&ip->i_pincount) > 0 ||
			(ip->i_itemp &&
			 (ip->i_itemp->ili_fields ||
			  test_bit(XFS_LI_IN_AIL,
				   &ip->i_itemp->ili_item.li_flags)));

		if (p52_dirty) {
			mxfs_pal_log(MXFS_LOG_ERR,
				"mxfs: P52-RELOAD-FREEDREUSE-DIR-SKIP ino=%llu incore_mode=0%o incore_gen=%u disk_gen=%u dlm_mode=%u in_ail=%d — keeping live in-core dir (disk slot is a freed DIFFERENT incarnation; dirty provenance)",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_mode,
				(unsigned)VFS_I(ip)->i_generation,
				(unsigned)be32_to_cpu(dip->di_gen),
				ip->i_dlm_mode,
				(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags)) ? 1 : 0);
			xfs_buf_relse(bp);
			ip->i_dlm_stale = false;
			return;
		}
		/*
		 * 0.84.24 (a peer's mkdir under a directory the other node just
		 * recreated answered ESTALE, 2 nodes / TCP, measured 22:19:53 on
		 * the 2026-09-12 board): the verdict below is only sound when
		 * this read was taken under a fresh wire grant, i.e. after the
		 * previous holder's release drain.  The directory consumer
		 * refresh reloads BEFORE its acquire, and a freed image (mode 0,
		 * generation old+1) read that way is indistinguishable from the
		 * not-yet-destaged image of a peer's NEW incarnation of the same
		 * number — the creator's EX is deferred-published and undrained,
		 * and the parent's dirent naming the number is already visible.
		 * Poisoning on that read condemned a live directory (sticky, so
		 * the acquire that followed a millisecond later, BASTed the
		 * creator and read the true image, could no longer adopt it) and
		 * every create under it was refused before any transaction.
		 * Leave the shell stale instead: the caller's acquire reloads
		 * under its grant, and that reload is the one allowed to judge.
		 */
		if (!under_grant) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				"mxfs: P346-INCARN-DEFER ino=%llu src=reload incore_gen=%u disk_gen=%u disk_mode=0 — freed image read with no fresh grant; not judged (a peer's new incarnation may be undrained), left stale for the acquire's reload",
				(unsigned long long)ip->i_ino,
				(unsigned)VFS_I(ip)->i_generation,
				(unsigned)be32_to_cpu(dip->di_gen));
			xfs_buf_relse(bp);
			return;
		}
		mxfs_pal_log(MXFS_LOG_ERR,
			"mxfs: P34H-INCARN-POISON ino=%llu src=reload incore_gen=%u disk_gen=%u disk_mode=0 — clean shell, disk disowned this incarnation; poisoning (ESTALE)",
			(unsigned long long)ip->i_ino,
			(unsigned)VFS_I(ip)->i_generation,
			(unsigned)be32_to_cpu(dip->di_gen));
		mxfs_incarn_poison(ip);
		xfs_buf_relse(bp);
		/* leave i_dlm_stale set — the shell is condemned, never
		 * re-certified; retirement happens at op entry / iget. */
		return;
	}

	/*
	 * SELF-CLOBBER GUARD — PROVEN via the
	 * minimal cross-node mkdir reproducer (test1 `mkdir /mnt/shared/rx`,
	 * test2 cannot see rx):
	 *   P106-MKDIR new_ino=157  ->  P108-REACQUIRE ino=157 "on-disk slot
	 *   lost; forcing slow-path re-acquire"  ->  this reload reads the
	 *   on-disk cluster for 157, which is STILL FREE (di_mode=0) because
	 *   the create is only LOGGED, not yet checkpointed to the inode
	 *   cluster  ->  xfs_inode_from_disk clobbers the freshly-created
	 *   in-core dir to mode=0 (P-RELOAD-IOPS-REWIRE old=040000 new=00)
	 *   ->  rx vanishes even on the CREATOR, so the peer never sees it.
	 * The existing di_format==0 skip below misses this when the inode
	 * number was REUSED (rm+mkdir): the on-disk cluster keeps the prior
	 * incarnation's non-zero di_format while di_mode reads 0.
	 *
	 * Distinguish "we just created/modified this, not flushed" from "a
	 * peer genuinely freed it" by the in-core dirty state: a logged-not-
	 * checkpointed inode is pinned and/or in the AIL and/or carries dirty
	 * ili_fields.  If the on-disk image is FREE but our in-core inode is
	 * ALLOCATED and dirty, our image is newer — keep it.  (A clean in-core
	 * inode with a free on-disk image is a real peer-free → fall through
	 * and adopt it.)
	 */
	if ((be16_to_cpu(dip->di_mode) & S_IFMT) == 0 &&
	    (VFS_I(ip)->i_mode & S_IFMT) != 0) {
		struct xfs_inode_log_item *sc_iip = ip->i_itemp;
		bool sc_dirty = atomic_read(&ip->i_pincount) > 0;
		/*
		 * FACE B ROOT FIX (dir_reuse_coherency
		 * 2/tcp, instrumented — PROVEN via P31B-RELOAD-BUF + P-RELOAD-IOPS-REWIRE):
		 * the "dirty" heuristic is INSUFFICIENT.  By the verify phase
		 * a node's own just-created regular file is CHECKPOINTED (clean: no
		 * pin / no ili_fields / not in AIL), so sc_dirty=false and this guard
		 * fell through — the reload then ADOPTED the stale-free on-disk image
		 * (P-RELOAD-IOPS-REWIRE old_ifmt=0100000 new_mode=00), reverting the
		 * node's OWN live inode to FREE in-core, so iget of its own dirent
		 * returns -ENOENT (FACE B lookup_fail / P26-IGET-FAIL).  The correct
		 * "keep in-core" discriminator is DLM GRANT OWNERSHIP, not dirtiness:
		 * per the i_dlm_epoch invariant (xfs_inode.h), while i_dlm_mode != NL
		 * the on-disk grant is HELD, so NO peer can have modified or freed
		 * this inode — a disk image reading FREE while we hold the grant and
		 * our in-core is ALLOCATED is therefore provably STALE (our create's
		 * cluster write not yet destaged, or an intra-node stale-cluster
		 * flush).  Adopting it is always a self-clobber.  (Node-affine inode
		 * allocation,, already prevents a peer from owning this inode's
		 * cluster, so a held grant is authoritative.)  A genuine peer free
		 * REQUIRES the peer to acquire EX, which BASTs us to NL first — so
		 * i_dlm_mode==NL is the only state in which a disk-free is authoritative
		 * and we correctly fall through to adopt it (no resurrection regress).
		 */
		/*
		 * FIX-13 (PROVEN BY INSTRUMENT, run84 test3 @186.65):
		 * the cached i_dlm_mode is NOT sufficient evidence the grant is
		 * held — the no-inode BAST release removes the DLM entry while
		 * the (transiently un-igettable) in-core inode keeps its mode:
		 * the PHANTOM EX.  With the phantom, this guard kept a DEAD
		 * incarnation (disk_mode=0, disk_gen=incore_gen+1, pin=0,
		 * ili_fields=0) as "authoritative"; dd's O_TRUNC then freed the
		 * dead map's blocks (P3-SKIP-DBLFREE storm) -> defer corruption
		 * 0x8 -> node shutdown, every run at round ~6-9.  Verify the
		 * hold against the DLM table (the source of truth P108 already
		 * uses): a removed entry means NOT held, and a genuinely freed
		 * disk image must be adopted.
		 */
		bool sc_grant_held = (ip->i_dlm_mode != MXFS_LOCK_NL) &&
			((ip->i_dlm_routed_iclus ?
			  /* ICLUSTER: no per-inode slot — the cluster
			   * object's disk_mode is the hold truth; probing
			   * the per-inode table would false-negative and
			   * adopt a lagging disk image over live in-core
			   * state. */
			  mxfs_iclus_granted_mode(mp, ip->i_ino) :
			  mxfs_v5_dlm_inode_held_rawmode(mp->m_mxfs_dlm,
					ip->i_ino)) != MXFS_LOCK_NL);

		if (sc_iip) {
			if (sc_iip->ili_fields)
				sc_dirty = true;
			if (test_bit(XFS_LI_IN_AIL,
				     &sc_iip->ili_item.li_flags))
				sc_dirty = true;
		}
		/*
		 * ccloop-4dd7 ZOMBIE ARM (instrumented evidence, ino 1862 / ino
		 * 8388753 autopsies): "disk-free while in-core allocated" has
		 * TWO opposite causes and the held/dirty heuristics only
		 * discriminate one of them:
		 *  (a) OUR unpublished create of a reused ino — in-core is
		 *      authoritative.  After the reuse paths' generation
		 *      converge (reset4create ++ / P-RECYCLE-SANITIZE adopt),
		 *      this window has disk_gen == incore_gen; it is also
		 *      dirty until checkpointed.
		 *  (b) a PEER freed the incarnation we still cache (fresh EX
		 *      acquire on a freed ino succeeds trivially, so
		 *      grant-held does NOT imply liveness) — the peer's
		 *      xfs_inode_uninit bumped di_gen by exactly one, so
		 *      disk_gen == incore_gen + 1.  Keeping the zombie let an
		 *      O_TRUNC free the stale extent map = cross-node double
		 *      block free (P3-EFREE-Q agbno=226 on both nodes).
		 * A CLEAN inode with the +1 signature is (b): fall through and
		 * adopt the freed image (the truncate then no-ops on the empty
		 * map; dentry machinery re-resolves via i_dlm_stale).  Dirty
		 * still keeps — our own logged mods are never discarded.
		 */
		/*
		 * ccloop-4dd7 (ino 2097290 / P-DIFREE-DBL agno=1 agino=138
		 * autopsy): the gen+1 signature only covers peer-freed-WITHOUT-
		 * reuse (uninit's +1).  A peer that REALLOCATED the number
		 * (icreate stamps a fresh RANDOM generation) and then freed it
		 * leaves disk_gen unrelated to ours, so the +1 arm missed and
		 * the grant-held keep preserved the zombie: O_TRUNC then freed
		 * the stale map (cross-node extent double free) and rm double-
		 * freed the inobt bit (freecount 55 vs popcount 54 -> -117 on
		 * both nodes).  Grant-held is authority only across a
		 * CONTINUOUS hold; the DLM stamps EX grants with the handoff
		 * bit exactly when a DIFFERENT node held EX since we last did —
		 * and a peer free REQUIRES that EX.  Clean self + disk-free +
		 * handoff-stamped grant = peer-freed zombie: adopt.  (PR grants
		 * never carry the bit, so a PR-phase reload still keeps; the
		 * first EX-phase reload — which precedes any modification —
		 * adopts before harm.  Ops that raced the adopt clean-abort:
		 * proven P116-ZOMBIE-ADOPT ino=142 -> REMOVE-REVALIDATE-MISS,
		 * no shutdown.)  i_dlm_unpublished excluded: an unpublished
		 * reused create legitimately sits clean over the peer's freed
		 * disk image under a handoff-stamped grant.
		 */
		bool sc_handoff = genuine_handoff;

		if (!sc_handoff && !ip->i_dlm_routed_iclus && mp->m_mxfs_dlm) {
			uint32_t sc_hgg = 0;

			sc_handoff = mxfs_v5_dlm_inode_grant_handoff(
				mp->m_mxfs_dlm, ip->i_ino, &sc_hgg);
		}
		if (!sc_dirty && !ip->i_dlm_unpublished &&
		    (sc_handoff ||
		     be32_to_cpu(dip->di_gen) ==
		     VFS_I(ip)->i_generation + 1)) {
			mxfs_probe_ratelimited(
				"mxfs: P116-ZOMBIE-ADOPT ino=%llu incore_mode=0%o incore_gen=%u disk_gen=%u dlm_mode=%u held=%d handoff=%d — peer-freed incarnation; adopting freed image\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_mode,
				VFS_I(ip)->i_generation,
				be32_to_cpu(dip->di_gen),
				ip->i_dlm_mode, sc_grant_held ? 1 : 0,
				sc_handoff ? 1 : 0);
		} else if (sc_dirty || sc_grant_held) {
			pr_warn_ratelimited(
				"mxfs: P116-RELOAD-SELFCLOBBER-SKIP ino=%llu incore_mode=0%o disk_mode=0 pin=%d ili_fields=0x%x dlm_mode=%u held=%d incore_gen=%u disk_gen=%u — keeping authoritative in-core inode (stale-free on-disk image)\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_mode,
				atomic_read(&ip->i_pincount),
				sc_iip ? sc_iip->ili_fields : 0,
				ip->i_dlm_mode, sc_grant_held ? 1 : 0,
				VFS_I(ip)->i_generation,
				be32_to_cpu(dip->di_gen));
			xfs_buf_relse(bp);
			ip->i_dlm_stale = false;
			return;
		}
	}

	/*
	 * DIR-GROWTH REVERT GUARD — PROVEN ROOT of
	 * dir_reuse_coherency 2/tcp (instrument step 2b, P33-FROMDISK-DIRSHRINK
	 * ino=131 old_size=8192 new_size=4096 old_nx=3 SAME gen, comm=dd).
	 *
	 * A reload that ADOPTS a STRICTLY SMALLER data-fork size for the SAME
	 * incarnation of a DIRECTORY, while THIS node still carries the dir's
	 * growth as logged-but-not-checkpointed mods (pinned / ili_fields / in
	 * AIL), is REVERTING our own committed-not-yet-durable dir grow.  The
	 * on-disk dinode is one growth BEHIND (our size + extent-map update is
	 * in the CIL/log, not yet iflushed to the inode cluster) while the
	 * on-disk LEAF block already carries the higher data-block hash refs —
	 * adopting the small dinode drops the data block whose dirents the leaf
	 * still points at => the durable leaf-vs-data tear (P26-DSCAN-MISS:
	 * ~93 names readdir-listed but lookup-ENOENT, every round's verify).
	 *
	 * SOUNDNESS: a CLEAN (checkpointed) in-core dir cannot satisfy this —
	 * once our grow is checkpointed it is already ON DISK, so disk would
	 * not read smaller.  A genuine peer REMOVAL that shrinks the dir
	 * requires the peer to hold EX, which BASTs us to NL and DRAINS our
	 * mods first (Invariant 1); at that reacquire our mods are CLEAN, so
	 * this guard falls through and correctly adopts the peer's smaller dir
	 * (no resurrection).  Same incarnation only — a full rm+recreate bumps
	 * di_gen (genuine reuse) → fall through.  Mirrors the reg-file
	 * RELOAD-SIZE-DROP-SKIP above, for the directory grow case.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) == (VFS_I(ip)->i_mode & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation) {
		uint64_t dg_fl2 = be64_to_cpu(dip->di_flags2);
		uint64_t dg_disk_nx = (dg_fl2 & XFS_DIFLAG2_NREXT64) ?
			be64_to_cpu(dip->di_big_nextents) :
			be32_to_cpu(dip->di_nextents);
		uint64_t dg_mem_nx = (uint64_t)ip->i_df.if_nextents;
		bool dg_size_shrink =
			be64_to_cpu(dip->di_size) < (uint64_t)ip->i_disk_size;
		/*
		 * also catch the EXTENT-COUNT-only revert (FACE B daddr-
		 * 0x78 shutdown).  A block->leaf grown dir with ONE data block has
		 * size=4096 (unchanged) but nx=2 (data block 0 + leaf block);
		 * reverting to nx=1 drops the LEAF extent while block 0 on disk is
		 * already an XDD3 data block, so xfs_dir2_format later decides
		 * FMT_BLOCK and reads block 0 with the block verifier -> XDB3 vs
		 * XDD3 EFSCORRUPTED.  A size-only check misses this (4096==4096).
		 */
		bool dg_nx_shrink = (dg_mem_nx >= 2 && dg_disk_nx < dg_mem_nx);

		if (dg_size_shrink || dg_nx_shrink) {
			struct xfs_inode_log_item *dg_iip = ip->i_itemp;
			bool dg_inflight = atomic_read(&ip->i_pincount) > 0 ||
				(dg_iip && (dg_iip->ili_fields ||
					    test_bit(XFS_LI_IN_AIL,
						     &dg_iip->ili_item.li_flags)));

			/* on a genuine cross-node handoff our prior tenure
			 * was drained at release, so disk is authoritative even if
			 * our log item still shows pinned/in-AIL (committed-not-yet-
			 * checkpointed) — do NOT keep the stale in-core dir. */
			if (dg_inflight && !genuine_handoff) {
				mxfs_pal_log(MXFS_LOG_ERR,
					"mxfs: P33-DIRGROW-REVERT-SKIP ino=%llu mem_size=%lld disk_size=%lld mem_nx=%llu disk_nx=%llu sz_shrink=%d nx_shrink=%d pin=%d ili_fields=0x%x gen=%u — keeping authoritative in-core dir (our grow not yet destaged; disk one growth behind the leaf)",
					(unsigned long long)ip->i_ino,
					(long long)ip->i_disk_size,
					(long long)be64_to_cpu(dip->di_size),
					(unsigned long long)dg_mem_nx,
					(unsigned long long)dg_disk_nx,
					dg_size_shrink, dg_nx_shrink,
					atomic_read(&ip->i_pincount),
					dg_iip ? dg_iip->ili_fields : 0,
					(unsigned)VFS_I(ip)->i_generation);
				xfs_buf_relse(bp);
				ip->i_dlm_stale = false;
				return;
			}
		}
	}

	/*
	 * sess43 (ccloop 8ddb16a2) DIR FORMAT-REVERT GUARD — PROVEN ROOT of
	 * dir_reuse_coherency 2/tcp data loss (instrument step 2b; sess42
	 * non-perturbing P42-SFCONV capture, build B8C2149E): in a failing
	 * round, test1 ran xfs_dir2_sf_to_block TWICE for the SAME incarnation
	 * (ino=131, i_gen=2915315106, ~6s apart, no rm-rf between).  Between the
	 * two conversions the in-core dir REVERTED block->shortform, and the
	 * second xfs_dir2_sf_to_block re-allocated + re-initialised block0 via
	 * xfs_dir3_data_init, which ZEROES the block holding node1_f1..f14 ->
	 * those 14 dirents are durably lost (the sess36 datainit-zero root).
	 *
	 * The block->shortform revert is THIS reload adopting a SHORTFORM on-disk
	 * image (di_format==LOCAL) over an in-core dir already grown to BLOCK/leaf
	 * format (if_format!=LOCAL) for the SAME incarnation (di_gen == in-core
	 * generation).  The slow-path acquire reload (post_release, line ~9181)
	 * assumes "on-disk is a superset" — but block->shortform VIOLATES that
	 * superset: a directory never legitimately reverts block->shortform within
	 * one incarnation in a create-path workload (dir_reuse_coherency only adds
	 * entries within a round; the rm-rf that could shrink it bumps di_gen ->
	 * different incarnation, which this guard excludes).  A genuine peer
	 * removal that shrinks a dir back to shortform holds EX, which BASTs +
	 * drains us first, so we would re-read at NL with no in-core block fork to
	 * lose.  Therefore a same-incarnation block->shortform disk image is
	 * provably STALE (a peer's pre-conversion shortform flush, or a torn read)
	 * -> REFUSE it and keep the authoritative in-core BLOCK dir, so the second
	 * sf_to_block (and its block0 re-init) never happens.
	 *
	 * This is the format-revert sibling of P33-DIRGROW-REVERT-SKIP above
	 * (size/extent shrink), but unlike P33 it fires even when our conversion
	 * mods are CLEAN (checkpointed by the verify phase) — the exact clean-case
	 * the dg_inflight heuristic misses (proven: P42-SFCONV double-conversion
	 * fired in the verify window, when the first conversion was already
	 * checkpointed).  A type-flip (dir->reg) is handled by the
	 * RELOAD-TYPEFLIP-STALE-SKIP guard above; here both images are dirs.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) == (VFS_I(ip)->i_mode & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
	    dip->di_format == XFS_DINODE_FMT_LOCAL) {
		/*
		 * — SOUNDNESS GATE on P43 (PROVEN BY INSTRUMENT,
		 * cache_coherency uv: drop_caches on the outlier flips it 10->0, dir
		 * size 4096->6, i.e. the LUN IS the authoritative shortform and the
		 * in-core BLOCK dir is the stale one).  The original P43 fired
		 * UNCONDITIONALLY for any same-incarnation block->shortform, which is
		 * correct ONLY when THIS node is the authoritative holder of the dir.
		 * Its own comment states the discriminator: "a genuine peer removal
		 * that shrinks a dir back to shortform holds EX, which BASTs + drains
		 * us to NL first, so we would re-read at NL with no in-core block fork
		 * to lose."  That is EXACTLY the unlink/delete-path (cache_coherency
		 * uv): node2 deletes every dirent, the dir converts block->shortform,
		 * node2 destages it (dir_inode_durable) and bumps our dir gen via the
		 * eviction ring; we are at NL (BAST'd) with a CLEAN, stale in-core
		 * BLOCK fork.  The disk shortform is AUTHORITATIVE and we MUST adopt
		 * it — refusing it pins node2's just-deleted dirents forever (uv
		 * "none remain got=10").  Only KEEP the in-core block when we are
		 * authoritative: we have un-destaged dir mods (pinned/ili_fields/
		 * in-AIL) OR hold the dir EXCLUSIVELY (i_dlm_mode == EX — the dir_reuse
		 * create-path, where we own the grow and the disk shortform is a stale
		 * pre-conversion flush).  A PR (shared-read) holder is NOT
		 * authoritative: under PR this node cannot have made unshared writes
		 * (writes require EX), so a PR copy differing from the durable disk is
		 * STALE and MUST be adopted — exactly the uv re-acquire (held=1 mode=3
		 * in the trace: node2 took EX, shrank block->shortform, released; we
		 * re-acquired PR with a stale block copy).  The acquire path sets
		 * i_dlm_mode to the target BEFORE this reload, so a "mode != NL" gate
		 * wrongly flags the PR reader authoritative; gate on EX only.  Mirrors
		 * the P33/P116 soundness gates.
		 */
		struct xfs_inode_log_item *dfr_iip = ip->i_itemp;
		bool dfr_dirty = atomic_read(&ip->i_pincount) > 0 ||
			(dfr_iip && (dfr_iip->ili_fields ||
				     test_bit(XFS_LI_IN_AIL,
					      &dfr_iip->ili_item.li_flags)));
		bool dfr_grant_held = (ip->i_dlm_mode == MXFS_LOCK_EX);

		/* a genuine cross-node handoff means a peer held EX and
		 * committed this block->shortform shrink; our prior tenure drained
		 * at release, so disk is authoritative — adopt, do not keep stale. */
		if ((dfr_dirty || dfr_grant_held) && !genuine_handoff) {
			mxfs_pal_log(MXFS_LOG_ERR,
				"mxfs: P43-DIR-FMTREVERT-SKIP ino=%llu incore_fmt=%u incore_nx=%llu mem_size=%lld disk_fmt=LOCAL disk_size=%lld gen=%u dirty=%d held=%d(mode=%u) — keeping authoritative in-core BLOCK dir (block->shortform revert for same incarnation is stale; adopting it would re-init block0 and lose live dirents)",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				(long long)be64_to_cpu(dip->di_size),
				(unsigned)VFS_I(ip)->i_generation,
				dfr_dirty ? 1 : 0, dfr_grant_held ? 1 : 0,
				ip->i_dlm_mode);
			xfs_buf_relse(bp);
			ip->i_dlm_stale = false;
			return;
		}
		mxfs_probe_ratelimited(
			"mxfs: P43-ADOPT-PEER-SHRINK ino=%llu incore_fmt=%u mem_size=%lld disk_size=%lld gen=%u dir_gen=%llu loaded=%llu — clean + non-EX (PR/NL) passive cacher, adopting peer's durable block->shortform image\n",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			(long long)ip->i_disk_size,
			(long long)be64_to_cpu(dip->di_size),
			(unsigned)VFS_I(ip)->i_generation,
			(unsigned long long)ip->i_dlm_dir_gen,
			(unsigned long long)ip->i_dlm_dir_loaded_gen);
		/* fall through: adopt the authoritative on-disk shortform */
	}

	/*
	 * If the on-disk inode has format 0 (unwritten), the inode was
	 * just allocated and not yet committed.  Skip reload — the
	 * in-memory state from xfs_icreate is authoritative.
	 */
	if (dip->di_format == 0) {
		mxfs_idbg(
			"mxfs: DLM reload skip ino=%llu (unwritten on disk)",
			(unsigned long long)ip->i_ino);
		xfs_buf_relse(bp);
		ip->i_dlm_stale = false;
		return;
	}

	/*
	 * (instrumented, PROVEN: dir_reuse_coherency node1_f1 loss): within ONE
	 * dir incarnation (di_gen) all nodes converge to a SINGLE block0, but the
	 * convergence non-deterministically picks a peer's HIGHER-AG block0 instead
	 * of rank1's lower one (AG0, daddr=120) that durably holds node1_f1 — so
	 * node1_f1 (orphaned in the lower block0) is lost in those rounds.  Make
	 * convergence DETERMINISTIC: lowest block0 fsb wins.  On a block<->block
	 * same-incarnation reload, if the disk image's block0 is HIGHER than our
	 * in-core block0, OUR (lower) block0 is canonical → KEEP it (refuse the
	 * adopt); the peer holding the higher block0 will see disk lower and adopt
	 * it.  All nodes converge to the LOWEST block0 = rank1's = node1_f1's home.
	 * Peer dirents that lived only in the higher block0 are re-added by the
	 * create-path union-merge (mxfs_dir_merge).  Pure keep-stale (no free, no
	 * fork mutation).  Gated mxfs_dir_lower_block0_wins (default off). */
	if (mxfs_dir_lower_block0_wins &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) == (VFS_I(ip)->i_mode & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
	    !xfs_need_iread_extents(&ip->i_df) &&
	    dip->di_format == XFS_DINODE_FMT_EXTENTS &&
	    be32_to_cpu(dip->di_nextents) >= 1) {
		xfs_fsblock_t		incore_b0 = 0, disk_b0 = 0;
		struct xfs_iext_cursor	fc;
		struct xfs_bmbt_irec	fg;
		struct xfs_bmbt_rec	*drecs =
			(struct xfs_bmbt_rec *)XFS_DFORK_PTR(dip, XFS_DATA_FORK);
		uint32_t		dnx = be32_to_cpu(dip->di_nextents), di;

		for_each_xfs_iext(&ip->i_df, &fc, &fg) {
			if (fg.br_startoff == 0 &&
			    !isnullstartblock(fg.br_startblock)) {
				incore_b0 = fg.br_startblock;
				break;
			}
		}
		for (di = 0; di < dnx; di++) {
			struct xfs_bmbt_irec dg;

			xfs_bmbt_disk_get_all(&drecs[di], &dg);
			if (dg.br_startoff == 0) {
				disk_b0 = dg.br_startblock;
				break;
			}
		}
		if (incore_b0 && disk_b0 && disk_b0 > incore_b0) {
			pr_warn_ratelimited(
				"mxfs: P65-LOWERB0-KEEP ino=%llu incore_b0=%llu disk_b0=%llu gen=%u dlm_mode=%u — keeping lower (canonical) in-core block0; refusing higher disk block0\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)incore_b0,
				(unsigned long long)disk_b0,
				VFS_I(ip)->i_generation, ip->i_dlm_mode);
			xfs_buf_relse(bp);
			ip->i_dlm_stale = false;
			return;
		}
	}

	/*
	 * Hold the inode rwsem exclusively across fork destroy + repopulate.
	 * xfs_idestroy_fork sets if_data=NULL but leaves if_bytes unchanged;
	 * if xfsaild picks this inode for flush in that window, the
	 * shortform-dir verifier sees (if_data=NULL, if_bytes=6) and null-
	 * derefs in xfs_dir2_sf_verify.  xfsaild takes ILOCK_SHARED via
	 * xfs_iflush_cluster, so blocking writers on i_lock is the right
	 * barrier.  We can't go through xfs_ilock here — we're already
	 * inside mxfs_dlm_ilock_begin and would re-enter the MXFS hook.
	 * Raw down_write bypasses the hook and grabs only the rwsem.
	 *
	 * NON-BLOCKING acquire.  A plain down_write here DEADLOCKS
	 * PERMANENTLY when this reload runs from the path-walk d_revalidate
	 * context and another holder of ip->i_lock is parked (e.g. a thread
	 * holding ILOCK_SHARED across a CAW poll, or an I/O-completion path) —
	 * proven a `touch` wedged D-state forever in mxfs_drevalidate ->
	 * xfs_dir_lookup -> xfs_ilock -> mxfs_dlm_reload_inode -> down_write.
	 * Use a bounded trylock with cond_resched(); if we can't get it cleanly,
	 * BAIL without rebuilding: the stale cached cluster buffer was already
	 * invalidated above (XBF_DONE cleared), and i_dlm_stale is LEFT SET, so
	 * the next (uncontended) coordinated access re-reads — correctness is
	 * preserved, only this one access keeps the prior image.  Never wedge.
	 */
	{
		int		w_tries = 0;
		bool		got_w = false;

		/*
		 *  (D5 FIX, design-consult design): if the
		 * CALLING task is itself holding this inode's i_lock for READ
		 * (the readdir path takes ILOCK_SHARED across iteration and
		 * then triggers this reload), the write acquire below can
		 * NEVER succeed — the spin is a guaranteed 1000-iteration
		 * (~3.5 ms) waste, and the caller's retry loop turns each
		 * episode into ~201 spins ≈ 0.7 s of pure livelock (measured
		 * 800-5600 episodes/node/day, root ino 128 a frequent victim;
		 * 32-node pileups produced minute-scale stalls).  Bail out
		 * IMMEDIATELY instead: the buffer was already staled and
		 * i_dlm_stale stays set, so the next access from a context
		 * that does NOT hold the read lock performs the reload.  This
		 * is "serve stale for this call, reload right after" — the
		 * same outcome the spin reached 3.5 ms later, minus the burn.
		 */
		if (atomic_read(&ip->i_mxfs_ilk_rd_held) > 0 &&
		    ip->i_mxfs_ilk_rd_pid == current->pid) {
			mxfs_probe_ratelimited(
			    "mxfs: P173-RELOAD-SELFREAD ino=%llu rd_held=%d rd_last=%pS pid=%d comm=%s — caller holds ILOCK_SHARED; reload deferred (no impossible-lock spin)\n",
				(unsigned long long)ip->i_ino,
				atomic_read(&ip->i_mxfs_ilk_rd_held),
				(void *)ip->i_mxfs_ilk_rd_ret,
				current->pid, current->comm);
			xfs_buf_relse(bp);
			/* leave i_dlm_stale set → next lock-free access reloads */
			return;
		}

		/*
		 * (D5): the spin bound was 1000 (~3.5 ms of yielding).
		 * Measured cluster-wide: 100k+ bails per chain lap × 3.5 ms =
		 * ~350 CPU-seconds burned per lap achieving nothing.  A SHORT
		 * reader (lookup/stat) releases within a few tries; a LONG one
		 * (readdir iteration) will not release inside any spin we can
		 * afford — and for it the bail is the correct answer, since
		 * i_dlm_stale stays set and the next lock-free access reloads.
		 * 64 tries (~0.2 ms) keeps the short-holder win and drops the
		 * long-holder waste by ~16×.  Tunable for A/B.
		 */
		{
			extern int mxfs_reload_wtrylock_spin;
			int spin_cap = mxfs_reload_wtrylock_spin > 0 ?
				mxfs_reload_wtrylock_spin : 64;

		while (w_tries++ < spin_cap) {
			if (down_write_trylock(&ip->i_lock)) {
				/* raw down_write bypasses the
				 * xfs_ilock recorder — attribute it so a leak
				 * here is named by P132-ILOCK-STUCK (else it is
				 * misattributed to the prior xfs_lock_two_inodes). */
				mxfs_ilk_note_lock(ip, XFS_ILOCK_EXCL, _THIS_IP_);
				got_w = true;
				break;
			}
			cond_resched();
		}
		if (!got_w) {
			/* was pr_warn (uncapped) — 100k+ lines per chain
			 * lap cluster-wide, itself a measurable drag and a dmesg-
			 * ring flusher that buried other probes.  Ratelimited. */
			pr_warn_ratelimited("mxfs: DLM reload BAIL ino=%llu (i_lock contended; buffer staled, will retry) cnt=%ld rd_held=%d spin=%d wr_last=%pS pid=%d comm=%s rd_last=%pS pid=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				atomic_long_read(&ip->i_lock.count),
				atomic_read(&ip->i_mxfs_ilk_rd_held),
				spin_cap,
				(void *)ip->i_mxfs_ilk_wr_ret,
				ip->i_mxfs_ilk_wr_pid, ip->i_mxfs_ilk_wr_comm,
				(void *)ip->i_mxfs_ilk_rd_ret,
				ip->i_mxfs_ilk_rd_pid, ip->i_mxfs_ilk_rd_comm);
			xfs_buf_relse(bp);
			/* leave ip->i_dlm_stale set → next access retries reload */
			return;
		}
		}
	}

	/*
	 * ROOT FIX (instrumented, PROVEN): the shutdown that blocks
	 * cache_coherency (unlink_visibility) is xfs_iflush_cluster flushing an
	 * in-core inode whose SHORTFORM directory fork is inconsistent (count vs
	 * di_size), left HALF-DESTROYED by a failed reload: this path calls
	 * xfs_idestroy_fork(&ip->i_df) and THEN xfs_inode_from_disk(), whose
	 * first step is xfs_dinode_verify().  Under 4-node concurrent create into
	 * a shared shortform dir, the on-disk cluster buffer is being rewritten
	 * by peers; the wide window opened by the down_write_trylock spin above
	 * (cond_resched, up to 1000 iters) lets a concurrent re-read of the
	 * SHARED cluster buffer mutate dip's bytes between any early check and
	 * from_disk.  from_disk then sees a torn/inconsistent image, fails verify
	 * AFTER the fork was destroyed → in-core inode half-built → next
	 * xfsaild flush hits xfs_dir2_sf_verify → "Corruption of in-memory data
	 * ... xfs_iflush_cluster" → FS shutdown.
	 *
	 * Now that we hold i_lock EXCLUSIVE (the spin is over), take a STABLE,
	 * private snapshot of the on-disk inode and verify the SNAPSHOT.  On a
	 * torn read, re-stale + re-read from the platter a few times.  If it
	 * still fails, BAIL without destroying anything (keep the authoritative
	 * in-core inode, leave i_dlm_stale set to retry later).  Only a verified
	 * snapshot is fed to xfs_idestroy_fork + xfs_inode_from_disk, and the
	 * snapshot can't change under us — so the inode is never left half-built.
	 */
	{
		xfs_failaddr_t	fa;
		int		t = 0;

		snap = kmalloc(mp->m_sb.sb_inodesize, GFP_NOFS);
		if (!snap) {
			xfs_buf_relse(bp);
			up_write(&ip->i_lock);
			/* leave i_dlm_stale set → next access retries */
			return;
		}
		memcpy(snap, dip, mp->m_sb.sb_inodesize);
		/*
		 * ROOT FIX (instrument step 2b, PROVEN
		 * via the test10/test15 startoff=1 double-map timeline):
		 * when the P91 guard above REFUSED to invalidate the cached
		 * cluster buffer (it carries this node's logged-not-yet-
		 * checkpointed mods), dip points at a STALE image — the
		 * peer's just-committed dinode (e.g. a dir grow: nx=2 vs
		 * disk nx=3, P133-DINO-READSTALE) is invisible in it.
		 * Adopting it (a) rebuilds the in-core extent map one grow
		 * behind, so xfs_bmap_first_unused re-maps a dir offset the
		 * peer already mapped (the loser's committed block is
		 * ORPHANED = silent dirent loss), and (b) this node's next
		 * release-drain iflush writes the stale core back to disk,
		 * REVERTING the peer's grow durably.  The buffer must stay
		 * untouched (its co-resident uncheckpointed state is
		 * authoritative), but the INODE CORE source of truth is the
		 * platter: FUA-read the cluster privately and snapshot the
		 * peer's dinode from that instead.  On read failure or a
		 * verify failure of the fresh image, fall back to the old
		 * behavior (buffer snapshot + retry loop below).
		 */
		if (kept_protected) {
			uint32_t	clen = BBTOB(ip->i_imap.im_len);
			void		*fresh = ((clen & 511) == 0 && clen) ?
						kmalloc(clen, GFP_NOFS) : NULL;
			int		frc = -1;

			/*
			 * ROOT FIX (instrumented, PROVEN via
			 * the cw_ready/cm_verify barrier-victim timeline:
			 * P91-RELOAD-PROTECT=13 + P34D=13 on exactly the node
			 * whose own just-created shortform dirent durably
			 * vanished cluster-wide).  With fua_disable=1 the
			 * COHERENCE POINT of the cluster is the SCST target
			 * write CACHE: every completed buffer write (xfsaild
			 * iflush, release fence) is visible to a plain-bio
			 * read, but a SCSI READ-FUA pierces PAST the cache to
			 * the PLATTER, which lags until destage.  The old
			 * unconditional FUA read here therefore returned an
			 * image OLDER than this node's own last flush; adopting
			 * it reverted the in-core dir fork, dropping the just-
			 * committed dirent (barrier signal), and the next RMW
			 * made the loss durable — every observer then misses
			 * that node forever (the 120s barrier timeouts that
			 * blow posix_semantics(16) past 600s).  Read through
			 * the SAME coherence point the rest of the I/O path
			 * uses: plain bio when fua_disable=1, FUA otherwise.
			 */
			if (fresh && mp->m_ddev_targp &&
			    mp->m_ddev_targp->bt_bdev) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint64_t f_lba =
					(uint64_t)ip->i_imap.im_blkno +
					mp->m_ddev_targp->bt_sector_offset;

				if (mxfs_fua_disable)
					frc = mxfs_pal_bdev_read_plain_bdev(
						mp->m_ddev_targp->bt_bdev,
						f_lba, fresh, clen);
				else
					frc = mxfs_pal_scsi_read_fua_bdev(
						mp->m_ddev_targp->bt_bdev,
						f_lba, fresh, clen);
			}
			if (frc == 0) {
				struct xfs_dinode *fdip = (struct xfs_dinode *)
					((char *)fresh + ip->i_imap.im_boffset);
				bool fresh_free =
					(be16_to_cpu(fdip->di_mode) & S_IFMT) == 0;
				bool self_auth = false;

				/*
				 * CLASS-B ROOT FIX
				 * (instrumented — PROVEN via run29 t4 ledger, ino
				 * 8390566 "node4_f39": P107-PUBLISH acquire on
				 * the CREATOR's just-created REG file ran this
				 * reload; the FUA-fresh read returned the
				 * platter's PRE-create FREED image (our
				 * IALLOC cluster write was still in flight —
				 * P4C-IALLOC-WR 1ms earlier), P34D adopted it
				 * over the LIVE in-core inode
				 * (P-RELOAD-IOPS-REWIRE new_mode=00), and the
				 * next xfsaild iflush wrote mode=0 back over
				 * the valid dinode (P4C-IFREE-WR) — durably
				 * UN-creating the file while its dirent
				 * remains → permanent cluster-wide lookup
				 * ENOENT dangler.  Apply the P116-SELFCLOBBER
				 * discriminator (proven /) to the
				 * FUA-fresh image too: a fresh image reading
				 * FREE while our in-core inode is ALLOCATED
				 * and (dirty-in-log OR holding a non-NL DLM
				 * grant) is provably STALE — a genuine peer
				 * free requires BASTing us to NL and cannot
				 * leave us pinned/in-AIL with the grant held.
				 * Keep the protected cached buffer (snap
				 * already holds dip's memcpy) as the source.
				 */
				if (fresh_free &&
				    (VFS_I(ip)->i_mode & S_IFMT) != 0) {
					struct xfs_inode_log_item *fr_iip =
						ip->i_itemp;

					self_auth =
						atomic_read(&ip->i_pincount) > 0 ||
						ip->i_dlm_mode != MXFS_LOCK_NL;
					if (fr_iip &&
					    (fr_iip->ili_fields ||
					     test_bit(XFS_LI_IN_AIL,
						      &fr_iip->ili_item.li_flags)))
						self_auth = true;
				}
				if (!xfs_dinode_verify(mp, ip->i_ino, fdip) &&
				    fresh_free && self_auth) {
					pr_warn_ratelimited(
						"mxfs: P5F-FRESHSRC-SELFCLOBBER-SKIP ino=%llu incore_mode=0%o incore_gen=%u fresh_gen=%u pin=%d ili_fields=0x%x dlm_mode=%u — keeping protected cached buffer (fresh FREE image is stale for live in-core incarnation)\n",
						(unsigned long long)ip->i_ino,
						VFS_I(ip)->i_mode,
						(unsigned)VFS_I(ip)->i_generation,
						(unsigned)be32_to_cpu(fdip->di_gen),
						atomic_read(&ip->i_pincount),
						ip->i_itemp ?
							ip->i_itemp->ili_fields : 0,
						ip->i_dlm_mode);
				} else if (!xfs_dinode_verify(mp, ip->i_ino, fdip) &&
				    fresh_free &&
				    S_ISDIR(VFS_I(ip)->i_mode) &&
				    be32_to_cpu(fdip->di_gen) !=
					    VFS_I(ip)->i_generation) {
					/*
					 * (instrumented — PROVEN via run-4
					 * fence/rsync cascade: ino=8394205,
					 * fresh gen=1771427689 mode=0 vs in-core
					 * gen=1155044010 DIR).  The FUA-fresh
					 * on-disk slot reads FREE for a DIFFERENT
					 * incarnation (gen mismatch) — the number
					 * was freed and reused.  Adopting it into
					 * our live in-core directory rewires it to
					 * {di_format=EXTENTS, nx=0} (P-RELOAD-IOPS-
					 * REWIRE new_mode=00), which the imminent
					 * xfs_create/remove maps as a dir-block
					 * HOLE -> xfs_dabuf_map !HOLE_OK ->
					 * EFSCORRUPTED -> dirty xfs_trans_cancel ->
					 * FS SHUTDOWN cascade.  Keep the protected
					 * cached buffer (snap still holds the
					 * memcpy of dip from above) — it carries
					 * this node's authoritative incarnation.
					 * Companion to P52-RELOAD-FREEDREUSE-DIR-
					 * SKIP, which guards the non-FUA path.
					 */
					/*
					 *  (design-consult matrix):
					 * this branch is reached only when NOT
					 * self_auth (branch above catches
					 * dirty/granted) — i.e. a CLEAN shell
					 * whose number the disk has disowned.
					 * Keep-alive was wrong-sided: POISON.
					 */
					pr_warn_ratelimited(
						"mxfs: P34H-INCARN-POISON ino=%llu src=freshsrc-free incore_gen=%u fresh_gen=%u fresh_mode=0 — clean dir shell, FUA-fresh slot freed for a different incarnation; poisoning (ESTALE)\n",
						(unsigned long long)ip->i_ino,
						(unsigned)VFS_I(ip)->i_generation,
						(unsigned)be32_to_cpu(fdip->di_gen));
					mxfs_incarn_poison(ip);
				} else if (!xfs_dinode_verify(mp, ip->i_ino, fdip)) {
					/*
					 * run77 ROOT FIX (instrumented, captured
					 * live on test5 @302.783): this adopt ran ~4ms after
					 * OUR OWN dir grow committed (leaf split, nx 6->7,
					 * inode item still in AIL / ili_fields set) and
					 * adopted the platter's PRE-grow dinode (nx=6),
					 * REVERTING the in-flight committed grow (P133-DINO-
					 * READSTALE + P33-FROMDISK-DIRSHRINK fired) — the
					 * in-core da-btree then referenced logged leaf blocks
					 * the reverted fork no longer maps -> "Corruption
					 * detected" EFSCORRUPTED spiral -> the node lost the
					 * dir for 9 straight rounds.  If our in-core inode
					 * carries LOGGED-NOT-DESTAGED core changes (dirty
					 * ili_fields, inode item in AIL, or pinned), the
					 * platter is BY DEFINITION behind us — the fresh
					 * image is stale for us and must not be adopted.
					 * A genuine peer-ahead image is only possible when
					 * we are clean (our release fence destages before
					 * any peer tenure).  Keep the protected cached
					 * buffer snapshot (it carries our authoritative
					 * state).
					 */
					struct xfs_inode_log_item *sa_iip = ip->i_itemp;
					bool self_ahead =
						atomic_read(&ip->i_pincount) > 0 ||
						(sa_iip &&
						 (sa_iip->ili_fields ||
						  test_bit(XFS_LI_IN_AIL,
							   &sa_iip->ili_item.li_flags)));
					/*
					 * D-512 cycle-2 (design-consult ruling):
					 * dirty different-generation invariant
					 * arm.  self_ahead's "platter is behind
					 * us" reasoning is sound only for a
					 * lagging image of OUR incarnation (or
					 * the not-yet-destaged FREE image of a
					 * local create — the /P5F
					 * creator case, disk mode 0).  A
					 * VERIFYING, LIVE (mode != 0) dinode
					 * with a DIFFERENT di_gen is neither:
					 * the number was freed, reused and the
					 * new owner's init destaged — which is
					 * impossible while we hold dirty state
					 * under a granted tenure unless a
					 * serialization invariant already
					 * failed.  Our dirty pages/log items
					 * would flush G1 through a stale bmap
					 * into blocks the platter says belong
					 * to someone else.  Never keep, never
					 * adopt: poison (revocation worker zaps
					 * + DISCARDS), loud forensics, and
					 * fail-stop — shutdown withdraws this
					 * node from the DLM (D-409) so the
					 * tenure is disposed of via recovery,
					 * not served.
					 */
					if ((self_ahead && !fresh_free &&
					     be32_to_cpu(fdip->di_gen) !=
						    VFS_I(ip)->i_generation) ||
					    unlikely(mxfs_dbg_rel_fail(ip, 4))) {
						pr_err("mxfs: P-D512-DIRTY-MISMATCH ino=%llu incore_gen=%u incore_mode=0%o fresh_gen=%u fresh_mode=0%o pin=%d ili=0x%x in_ail=%d dlm_mode=%u — DIRTY shell vs live cross-incarnation platter image: reuse barrier violated; poisoning + fail-stop\n",
							(unsigned long long)ip->i_ino,
							(unsigned)VFS_I(ip)->i_generation,
							VFS_I(ip)->i_mode,
							(unsigned)be32_to_cpu(fdip->di_gen),
							(unsigned)be16_to_cpu(fdip->di_mode),
							atomic_read(&ip->i_pincount),
							sa_iip ? sa_iip->ili_fields : 0,
							sa_iip ? test_bit(XFS_LI_IN_AIL,
								&sa_iip->ili_item.li_flags) : 0,
							ip->i_dlm_mode);
						mxfs_incarn_poison(ip);
						xfs_force_shutdown(mp,
							SHUTDOWN_CORRUPT_INCORE);
					} else if (self_ahead) {
						mxfs_probe_ratelimited(
							"mxfs: P34E-FRESHSRC-SELFAHEAD-SKIP ino=%llu buf[size=%lld nx=%u] fresh[size=%lld nx=%u] pin=%d ili=0x%x in_ail=%d — undestaged local core mods; keeping cached (platter is behind us)\n",
							(unsigned long long)ip->i_ino,
							(long long)be64_to_cpu(dip->di_size),
							be32_to_cpu(dip->di_nextents),
							(long long)be64_to_cpu(fdip->di_size),
							be32_to_cpu(fdip->di_nextents),
							atomic_read(&ip->i_pincount),
							sa_iip ? sa_iip->ili_fields : 0,
							sa_iip ? test_bit(XFS_LI_IN_AIL,
								&sa_iip->ili_item.li_flags) : 0);
					} else if (be32_to_cpu(fdip->di_gen) !=
						   VFS_I(ip)->i_generation) {
						/*
						 *  (design-consult
						 * ruling): the P34G guard
						 * ("keep cached while we hold the
						 * grant") was WRONG-SIDED — it is
						 * only reachable when the shell is
						 * CLEAN (self_ahead above catches
						 * dirty), and a clean shell whose
						 * disk gen differs is a DEAD
						 * incarnation either way:
						 *  - disk NEWER (peer freed+reused
						 *    our number): keeping cached
						 *    serves the corpse;
						 *  - disk OLDER (our newer
						 *    incarnations never destaged —
						 *    pre-FIX-1 window): adopting
						 *    would time-travel the shell
						 *    backwards (the EEXIST /
						 *    iget-livelock family).
						 * Neither side may win in place:
						 * POISON the shell (ESTALE +
						 * retire + re-iget) so identity is
						 * re-established from the platter,
						 * which FIX-1 keeps truthful at
						 * grant boundaries.
						 */
						pr_warn_ratelimited(
							"mxfs: P34H-INCARN-POISON ino=%llu src=freshsrc incore_gen=%u fresh_gen=%u fresh_mode=0%o — clean shell vs cross-incarnation disk image; poisoning (ESTALE)\n",
							(unsigned long long)ip->i_ino,
							(unsigned)VFS_I(ip)->i_generation,
							(unsigned)be32_to_cpu(fdip->di_gen),
							(unsigned)be16_to_cpu(fdip->di_mode));
						mxfs_incarn_poison(ip);
					} else {
						mxfs_probe_ratelimited(
							"mxfs: P34D-RELOAD-FRESHSRC ino=%llu buf[size=%lld nx=%u] fresh[size=%lld nx=%u] src=%s — protected buffer; adopting coherent on-disk dinode\n",
							(unsigned long long)ip->i_ino,
							(long long)be64_to_cpu(dip->di_size),
							be32_to_cpu(dip->di_nextents),
							(long long)be64_to_cpu(fdip->di_size),
							be32_to_cpu(fdip->di_nextents),
							mxfs_fua_disable ? "plain" : "fua");
						memcpy(snap, fdip,
						       mp->m_sb.sb_inodesize);
					}
				}
			}
			kfree(fresh);
		}
		fa = xfs_dinode_verify(mp, ip->i_ino, snap);
		while (fa && t++ < 8) {
			struct xfs_buf	*rr = NULL;

			xfs_buf_relse(bp);
			bp = NULL;
			if (xfs_buf_incore(mp->m_ddev_targp,
					ip->i_imap.im_blkno, ip->i_imap.im_len,
					0, &rr) == 0) {
				xfs_buf_stale(rr);
				rr->b_flags &= ~XBF_DONE;
				xfs_buf_relse(rr);
			}
			cond_resched();
			error = xfs_imap_to_bp(mp, NULL, &ip->i_imap, &bp);
			if (error) {
				mxfs_pal_log(MXFS_LOG_DEBUG,
					"mxfs: RELOAD-VERIFY reread failed ino=%llu rc=%d",
					(unsigned long long)ip->i_ino, error);
				kfree(snap);
				up_write(&ip->i_lock);
				/* leave i_dlm_stale set → next access retries */
				return;
			}
			dip = xfs_buf_offset(bp, ip->i_imap.im_boffset);
			memcpy(snap, dip, mp->m_sb.sb_inodesize);
			fa = xfs_dinode_verify(mp, ip->i_ino, snap);
		}
		if (fa) {
			mxfs_probe_ratelimited(
				"mxfs: RELOAD-VERIFY-BAIL ino=%llu fa=%pS tries=%d — keeping authoritative in-core inode\n",
				(unsigned long long)ip->i_ino, fa, t);
			kfree(snap);
			xfs_buf_relse(bp);
			up_write(&ip->i_lock);
			/* leave i_dlm_stale set → next coordinated access retries */
			return;
		}
		if (t)
			mxfs_idbg(
				"mxfs: RELOAD-VERIFY recovered torn read ino=%llu after %d reread(s)",
				(unsigned long long)ip->i_ino, t);
		/*
		 * From here on, operate on the IMMUTABLE snapshot — a concurrent
		 * re-read of the shared cluster buffer can no longer change the
		 * bytes between verify and xfs_inode_from_disk.
		 */
		dip = snap;
	}

	/*
	 * DIR FORMAT-REVERT GUARD #2 — the SNAPSHOT
	 * (post-spin) site.  The early P43-DIR-FMTREVERT-SKIP guard above
	 * checks the LIVE cluster buffer (dip) BEFORE the down_write_trylock
	 * spin; but per the ROOT FIX a peer can rewrite the SHARED
	 * cluster buffer DURING that spin, so the early check can see
	 * disk_fmt=EXTENTS (matches in-core block → passes) while the stable
	 * snapshot taken AFTER the spin captures a SHORTFORM image.  That is
	 * exactly the residual that survived the early guard (drc_cap2 build
	 * 8E2F4890: 3 same-incarnation block0 double-conversions still slipped
	 * through — for each, P62-RELOAD-FORK-SHRINK incore_fmt=2→disk_fmt=1
	 * fired between the two P42-SFCONV, i.e. the destructive shrink ran on
	 * the snapshot path that the early dip check could not see).
	 *
	 * Re-check the format-revert on the IMMUTABLE snapshot, right before
	 * xfs_idestroy_fork: a same-incarnation block→shortform revert for a
	 * DIR (in-core if_format!=LOCAL, snapshot di_format==LOCAL, di_gen ==
	 * in-core generation) is provably STALE (a dir never legitimately
	 * reverts block→shortform within one incarnation in a create-path
	 * workload; the rm-rf that could shrink it bumps di_gen → a different
	 * incarnation this guard excludes; a genuine peer removal holds EX,
	 * BASTs+drains us to NL first).  BAIL, keeping the authoritative
	 * in-core BLOCK dir, so the second xfs_dir2_sf_to_block — and its
	 * xfs_dir3_data_init re-init of block0 that ZEROES the live dirents
	 * (node1_f1..f14) — never happens.  Cleanup mirrors RELOAD-VERIFY-BAIL
	 * above (kfree snap, relse bp, up_write); merge_ours is not yet
	 * allocated at this point.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) == (VFS_I(ip)->i_mode & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
	    dip->di_format == XFS_DINODE_FMT_LOCAL) {
		/* same SOUNDNESS GATE as the early P43 guard (see comment
		 * there).  Only keep the in-core BLOCK dir when THIS node is
		 * authoritative — un-destaged dir mods OR holds the dir EXCLUSIVELY
		 * (mode == EX).  A clean fork held at PR/NL is a passive stale cacher
		 * (PR cannot have unshared writes) that MUST adopt the peer's durable
		 * block->shortform (cache_coherency uv). */
		struct xfs_inode_log_item *dfr_iip = ip->i_itemp;
		bool dfr_dirty = atomic_read(&ip->i_pincount) > 0 ||
			(dfr_iip && (dfr_iip->ili_fields ||
				     test_bit(XFS_LI_IN_AIL,
					      &dfr_iip->ili_item.li_flags)));
		bool dfr_grant_held = (ip->i_dlm_mode == MXFS_LOCK_EX);

		/* a genuine cross-node handoff means a peer held EX and
		 * committed this block->shortform shrink; our prior tenure drained
		 * at release, so disk is authoritative — adopt, do not keep stale. */
		if ((dfr_dirty || dfr_grant_held) && !genuine_handoff) {
			mxfs_pal_log(MXFS_LOG_ERR,
				"mxfs: P43B-DIR-FMTREVERT-SNAP-SKIP ino=%llu incore_fmt=%u incore_nx=%llu mem_size=%lld disk_fmt=LOCAL disk_size=%lld gen=%u dirty=%d held=%d(mode=%u) — keeping authoritative in-core BLOCK dir (post-spin snapshot block->shortform revert for same incarnation is stale; adopting it would re-init block0 and lose live dirents)",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				(long long)be64_to_cpu(dip->di_size),
				(unsigned)VFS_I(ip)->i_generation,
				dfr_dirty ? 1 : 0, dfr_grant_held ? 1 : 0,
				ip->i_dlm_mode);
			kfree(snap);
			xfs_buf_relse(bp);
			up_write(&ip->i_lock);
			ip->i_dlm_stale = false;
			return;
		}
		mxfs_probe_ratelimited(
			"mxfs: P43B-ADOPT-PEER-SHRINK ino=%llu incore_fmt=%u mem_size=%lld disk_size=%lld gen=%u dir_gen=%llu loaded=%llu — clean + non-EX (PR/NL) passive cacher, adopting peer's durable block->shortform image (snapshot)\n",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			(long long)ip->i_disk_size,
			(long long)be64_to_cpu(dip->di_size),
			(unsigned)VFS_I(ip)->i_generation,
			(unsigned long long)ip->i_dlm_dir_gen,
			(unsigned long long)ip->i_dlm_dir_loaded_gen);
		/* fall through: adopt the authoritative on-disk shortform */
	}

	/* SELF-REVERT detector (always-on): if reloading a SHORTFORM dir
	 * would DROP entries our in-core fork has but the on-disk dinode lacks,
	 * we are about to CLOBBER our own just-committed dirents with a stale
	 * disk image (the last-committer lost-update).  Log in-core vs disk
	 * count + in_ail/pin so the timeline shows whether our change was
	 * un-durable (CIL/AIL) when the reload stomped it. */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    ip->i_df.if_data) {
		struct xfs_dir2_sf_hdr *cur_sfh = ip->i_df.if_data;
		uint8_t disk_cnt = (dip->di_format == XFS_DINODE_FMT_LOCAL)
			? ((struct xfs_dir2_sf_hdr *)
			   ((char *)dip + xfs_dinode_size(dip->di_version)))
			      ->count
			: 255;
		if (disk_cnt < cur_sfh->count) {
			/*
			 * + DECISIVE PROBE (instrumented): the plain-bio reload
			 * read (fua_disable=1) returned FEWER dir entries than our
			 * in-core fork.  Two opposite causes need opposite fixes:
			 *   (A) stale-cache read — the LUN actually holds the full
			 *       entry set, but our plain read served a stale image.
			 *   (B) stale-LUN image — the LUN genuinely lacks the
			 *       entries (the modifier has not destaged its inode
			 *       cluster, or a stale iflush clobbered it).
			 * Force a SCSI READ(16) FUA of THIS inode's cluster (pierces
			 * every cache layer) and re-parse the shortform count.  If
			 * fua_cnt >= incore  => (A) stale cache.  If fua_cnt == disk
			 * (still short) => (B) stale LUN.  Decides the fix class.
			 */
			int fua_cnt = -1;
			uint32_t clen = (uint32_t)ip->i_imap.im_len << BBSHIFT;
			void *cbuf = kmalloc(clen, GFP_NOFS);

			if (cbuf) {
				uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
					mp->m_ddev_targp->bt_sector_offset;
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *bdev,
					uint64_t lba_512, void *buf,
					uint32_t len);
				int rrc = mxfs_pal_scsi_read_fua_bdev(
					mp->m_ddev_targp->bt_bdev, lba, cbuf, clen);
				if (rrc == 0) {
					struct xfs_dinode *fdip = (struct xfs_dinode *)
						((char *)cbuf + ip->i_imap.im_boffset);
					if (fdip->di_format == XFS_DINODE_FMT_LOCAL)
						fua_cnt = ((struct xfs_dir2_sf_hdr *)
							((char *)fdip +
							 xfs_dinode_size(fdip->di_version)))->count;
					else
						fua_cnt = 250 + fdip->di_format;
				} else {
					fua_cnt = -100 + rrc;
				}
				kfree(cbuf);
			}
			mxfs_probe_ratelimited(
				"mxfs: P-SFDIR-REVERT ino=%llu incore_cnt=%u disk_cnt=%u fua_cnt=%d in_ail=%d pin=%d disk_gen=%u incore_gen=%u lastrel_flag=%u lastrel_age_ms=%lld lastrel_size=%llu realns=%llu\n",
				(unsigned long long)ip->i_ino,
				cur_sfh->count, disk_cnt, fua_cnt,
				ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags),
				atomic_read(&ip->i_pincount) > 0,
				be32_to_cpu(dip->di_gen),
				VFS_I(ip)->i_generation,
				ip->i_mxfs_lastrel_flag,
				ip->i_mxfs_lastrel_ns ?
					(long long)((ktime_get_real_ns() -
						     ip->i_mxfs_lastrel_ns) /
						    NSEC_PER_MSEC) : -1,
				(unsigned long long)ip->i_mxfs_lastrel_size,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * DECISIVE PROBE (instrumented) for the uniform zero_silent_loss
	 * shutdown: xfs_dabuf_map "bno 2 inode 131" HOLE at xfs_da_btree.c:2814,
	 * fired ~2ms AFTER a P34D-RELOAD-FRESHSRC on the SAME inode.  Hypothesis:
	 * the dir grew in-core (a new data block, if_nextents bumped) but that
	 * grow is still in the CIL and NOT yet serialized into the on-disk dinode
	 * (di_nextents lags), so when this reload runs xfs_idestroy_fork +
	 * xfs_inode_from_disk it SHRINKS the in-core extent map below this node's
	 * own dirty leaf/data blocks (which still reference the higher block) ->
	 * the leaf points at a now-unmapped offset -> HOLE -> shutdown.
	 * If in-core if_nextents > the adopted disk di_nextents here, the reload
	 * is reverting the data fork below this node's own uncommitted dir-grow.
	 * Fires for every multi-node DIR reload (low volume); rate-limited.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) && dip) {
		unsigned long long incore_nx = ip->i_df.if_nextents;
		unsigned int disk_nx = be32_to_cpu(dip->di_nextents);

		mxfs_probe_ratelimited(
			"mxfs: P62-RELOAD-FORK-SHRINK ino=%llu incore_fmt=%u incore_nx=%llu incore_size=%lld disk_fmt=%u disk_nx=%u disk_size=%lld shrink=%d in_ail=%d pin=%d incore_gen=%u disk_gen=%u post_release=%d self_created=%d pre_ms=%llu bp_ms=%llu tot_ms=%llu\n",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format, incore_nx,
			(long long)ip->i_disk_size,
			dip->di_format, disk_nx,
			(long long)be64_to_cpu(dip->di_size),
			(incore_nx > disk_nx) ? 1 : 0,
			ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags),
			atomic_read(&ip->i_pincount) > 0,
			VFS_I(ip)->i_generation,
			be32_to_cpu(dip->di_gen),
			post_release ? 1 : 0,
			ip->i_mxfs_self_created ? 1 : 0,
			/* phase split: pre_ms = everything before the
			 * dinode buffer read (grant/verify/evict work), bp_ms =
			 * the read itself, tot_ms = entry to here. */
			(unsigned long long)((rl_tpre - rl_t0) / 1000000ULL),
			(unsigned long long)((rl_tbp - rl_tpre) / 1000000ULL),
			(unsigned long long)((ktime_get_ns() - rl_t0) / 1000000ULL));

		/*
		 * DUAL-READ DISCRIMINATOR (instrumented).
		 * PROVEN sequence (cache_coherency@32 run 042532Z, test31 ino
		 * 4194436): reload at :21 read disk_nx=22 (fresh), the NEXT
		 * reload at :23 read disk_nx=18 — the "disk" answered an OLDER
		 * generation than this same node had already observed, the node
		 * adopted it and re-wrote stale (nr=18 leaf over nr=22) →
		 * leaf-vs-map torn platter → P14-DABUF-HOLE / bunmapi i!=1 →
		 * dirty trans_cancel → FS shutdown (the 0/32 victim family).
		 * Two candidate mechanisms need opposite fixes:
		 *   (R-a) platter/shared-cache truly regressed — a stale inode-
		 *         cluster WRITE landed between the reads (write-side gap;
		 *         P-DIRDW at mxfs_submit_partial_inode_write names it);
		 *   (R-b) the imap_to_bp read was served from a STALE CACHED
		 *         cluster buffer on THIS node (read-side gap: missing
		 *         handoff invalidation).
		 * On the suspicious direction only (disk < incore, the regression
		 * shape) re-read the SAME cluster with a raw plain-bdev read
		 * (bypasses the XFS buffer cache; hits the coherent SCST cache).
		 * raw==buffered => (R-a).  raw newer than buffered => (R-b).
		 * di_changecount is monotonic per inode — the unambiguous
		 * ordering witness.
		 */
		if (incore_nx > disk_nx) {
			static atomic_t p62dr = ATOMIC_INIT(0);

			if (atomic_inc_return(&p62dr) <= 200) {
				uint32_t clen =
					(uint32_t)ip->i_imap.im_len << BBSHIFT;
				void *cbuf = clen ? kmalloc(clen, GFP_NOFS) :
					NULL;
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);

				if (cbuf) {
					uint64_t lba =
						(uint64_t)ip->i_imap.im_blkno +
						mp->m_ddev_targp->bt_sector_offset;
					int rrc = mxfs_pal_bdev_read_plain_bdev(
						mp->m_ddev_targp->bt_bdev, lba,
						cbuf, clen);
					if (rrc == 0) {
						struct xfs_dinode *rdip =
							(struct xfs_dinode *)
							((char *)cbuf +
							 ip->i_imap.im_boffset);
						mxfs_probe("mxfs: P62-DUALREAD ino=%llu buffered_nx=%u buffered_chg=%llu raw_nx=%u raw_chg=%llu raw_fmt=%u raw_size=%lld verdict=%s\n",
							(unsigned long long)ip->i_ino,
							disk_nx,
							(unsigned long long)be64_to_cpu(dip->di_changecount),
							be32_to_cpu(rdip->di_nextents),
							(unsigned long long)be64_to_cpu(rdip->di_changecount),
							rdip->di_format,
							(long long)be64_to_cpu(rdip->di_size),
							(be64_to_cpu(rdip->di_changecount) >
							 be64_to_cpu(dip->di_changecount)) ?
							"STALE-BUFFERED-READ(R-b)" :
							"PLATTER-IS-OLD(R-a-or-legit)");
					} else {
						mxfs_probe("mxfs: P62-DUALREAD ino=%llu raw_read_rc=%d\n",
							(unsigned long long)ip->i_ino,
							rrc);
					}
					kfree(cbuf);
				}
			}
		}
	}

	/*
	 * snapshot the PRE-RELOAD in-core shortform fork so we can
	 * re-apply OUR delta after adopting disk (a reload must not revert our
	 * own committed-not-durable dirents — the proven write-side shortform
	 * resurrection root).  Only for pure-dirent churn (dir nlink unchanged
	 * on disk) on a shortform dir that already has a merge base.
	 */
	/*
	 *  (instrumented, PROVEN by this tree's own probe).
	 *
	 * The nlink-equality clause restricted the snapshot to "pure dirent
	 * churn" — but an unlanded mkdir is exactly the case where our nlink is
	 * AHEAD of the platter's, so the snapshot was skipped, no merge ran, and
	 * the adopt below REVERTED our committed create.  That is the P177 event
	 * verbatim, captured on the inode that lost it:
	 *
	 *   P177-OBLIGATION-DROPPED-AT-ADOPT ino=35651735 pending=16 durable=12
	 *     flush=12 mode=040755 identical=0
	 *     — reload adopted the platter over an UNLANDED committed change
	 *
	 * ino 35651735 is the parent of storm round 22, whose node17_1 was
	 * "NEVER PUBLISHED by any node" — its creator's own mkdir returned
	 * success and then vanished, dirent and link count together
	 * (tests/logs/sfstorm_20260728_135814).
	 *
	 * pending != durable is precisely "we hold a committed change that has
	 * not reached its home location", which is the state that makes our
	 * higher link count legitimate rather than a divergence.  Admit it, and
	 * only in the direction where we are ahead.
	 *
	 * NOT covered by the enforce lever: mxfs.pub_obligation_enforce gates
	 * the DRAIN's silent-success exit, and P176 fires 0 times in these runs
	 * — the obligation is dropped here, at the adopt.  Paired A/B measured
	 * enforce=1 vs 0 at 11 failing rounds each.
	 */
	if (mxfs_sf_merge && S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL && ip->i_df.if_data &&
	    ip->i_df.if_bytes > 0 && ip->i_dlm_dir_sf_base &&
	    dip->di_format == XFS_DINODE_FMT_LOCAL &&
	    (be32_to_cpu(dip->di_nlink) == VFS_I(ip)->i_nlink ||
	     (mxfs_reload_oblig_merge &&
	      ip->i_mxfs_pub_pending_seq != ip->i_mxfs_pub_durable_seq &&
	      VFS_I(ip)->i_nlink > be32_to_cpu(dip->di_nlink)))) {
		merge_ours = kmalloc(ip->i_df.if_bytes, GFP_NOFS);
		if (merge_ours) {
			memcpy(merge_ours, ip->i_df.if_data, ip->i_df.if_bytes);
			merge_ours_bytes = ip->i_df.if_bytes;
		}
	}

	/* we have passed every keep-stale guard and are committing to
	 * adopt the on-disk image — CONSUME the handoff for this grant episode so a
	 * later same-tenure reload (no new grant) does not re-adopt over our own
	 * fresh in-flight mods (resurrection).  Set here (not at detection) so a
	 * trylock-bailed retry above still re-triggered the handoff path. */
	if (genuine_handoff)
		ip->i_dlm_handoff_acted_gen = handoff_gg;
	/* (design review): record the epoch our base is now coherent with.  A
	 * later acquire only re-adopts when the master's epoch advances past this,
	 * so we never re-adopt the same handoff twice (no resurrection) yet never
	 * miss a real one (monotonic). */
	/* v0.6.0: CAW epochs can move BACKWARD across slot reclamation — stamp
	 * whatever value the current grant carries so the != gate re-arms
	 * correctly (a > -only stamp would leave valid_epoch permanently above
	 * a restarted counter and re-adopt on every acquire). */
	/*
	 * Option B (design review contract item 2) — the epoch/incarn stamp that
	 * lived HERE (pre-install) moved to the install-complete point below,
	 * behind the validity bit: stamping before xfs_inode_from_disk exposed
	 * a window where a concurrent ILOCK_SHARED lookup could trust a
	 * baseline whose base was about to be replaced.  (The old block also
	 * carried a missing-braces bug: the incarn stamp was OUTSIDE both
	 * epoch conditionals, so every reload reaching here stamped
	 * valid_incarn = live generation even when the epoch was not stamped —
	 * flipping "no baseline" into "live baseline of 0", the exact
	 * raw-compare feed of the captured P195 hit.)
	 *
	 * Committing to adopt: from here to xfs_inode_from_disk there is no
	 * bail, and the destroy tears the fork first — so the baseline can no
	 * longer vouch for the in-core base.  Clear it; the stamp re-arms it
	 * only after the install (or keep decision) is final.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode))
		mxfs_dir_base_invalidate(ip, 2);
	/* micro-revert lever: restore the pre-sess45 stamp TIMING (same
	 * values, commit point) for the amplifier A/B — see
	 * mxfs.reload_stamp_at_commit. */
	if (mxfs_reload_stamp_at_commit && S_ISDIR(VFS_I(ip)->i_mode) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		bool ecaw = mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm);
		uint32_t eep = dir_grant_epoch;

		if (!ecaw && ip->i_dlm_dir_valid_epoch > eep)
			eep = ip->i_dlm_dir_valid_epoch;
		if (mxfs_dir_adopt_at_acquire)
			mxfs_dir_base_stamp(ip, eep, dir_grant_gen_pre, 4);
		else if (ecaw ?
			 (dir_grant_epoch != ip->i_dlm_dir_valid_epoch) :
			 (dir_grant_epoch > ip->i_dlm_dir_valid_epoch)) {
			ip->i_dlm_dir_valid_epoch = dir_grant_epoch;
			ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;
		}
		b_stamped_early = true;
	}
	/* v0.6.5: the ONLY place i_dlm_dir_acq_epoch may advance — reaching
	 * here means every keep-stale guard fell through and the disk image
	 * IS adopted below (no bail between here and xfs_inode_from_disk).
	 * A guard early-return above leaves it lagging so the P65 gate
	 * re-fires on the next acquire (level-held until a real adopt). */
	ip->i_dlm_dir_acq_epoch = dir_grant_epoch;

	/*
	 * <ccloop sess49b, INVERTED sess2 a16ec5f2> A data-region HOLE in the
	 * on-disk dir extent map is NOT proof of a torn disk.  run7 8/tcp PROVED
	 * the legitimate case: a partially-completed rm -rf (one unlink ENOENT'd
	 * on a leaf-hash hole) leaves the SAME incarnation durably at e.g.
	 * nx=4 blocks {0,2,3}+leaf with block 1 punched by
	 * xfs_dir2_shrink_inode — a valid XFS state (readdir/lookup/addname all
	 * handle sparse data regions; bests[] carries NULLDATAOFF for holes).
	 * The former REFUSE-on-hole gate here made every node keep its in-core
	 * fork "until the owner heals the disk" — but in the legitimate case the
	 * nx=9 in-core holders are the STALE side (their map references blocks
	 * the rm already freed) and no heal can ever come: all 8 nodes spun on
	 * this gate for the rest of the run, the next round's creates landed in
	 * freed daddrs via the stale maps, and cold verify read 101/800.
	 * At acquire-time the drained disk image is cluster-canonical; shape
	 * alone must never override it.  ADOPT, and leave a ratelimited marker
	 * for timeline correlation.  (The mid-publish torn-disk window sess49b
	 * feared is closed on the publish side: release drains land leaf/data
	 * before the dinode, and the sess1 grant-epoch ordering fix keeps
	 * cross-node grows coherent.) */
	if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_format == XFS_DINODE_FMT_EXTENTS && mp->m_dir_geo &&
	    be16_to_cpu(dip->di_mode) != 0 &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation) {
		int dnx = (be64_to_cpu(dip->di_flags2) & XFS_DIFLAG2_NREXT64) ?
			(int)be64_to_cpu(dip->di_big_nextents) :
			(int)be32_to_cpu(dip->di_nextents);
		if (dnx > 1 && dnx <= 64) {
			char *drecs = (char *)dip +
				xfs_dinode_size(dip->di_version);
			xfs_fileoff_t dleaf = mp->m_dir_geo->leafblk;
			xfs_fileoff_t dprev = 0;
			bool d1st = true, dgap = false;
			int di;

			for (di = 0; di < dnx; di++) {
				struct xfs_bmbt_irec r;
				xfs_bmbt_disk_get_all(
					(struct xfs_bmbt_rec *)(drecs +
					   di * sizeof(struct xfs_bmbt_rec)),
					&r);
				if (r.br_startoff >= dleaf)
					break;	/* leaf/free region */
				if (!d1st && r.br_startoff > dprev) {
					dgap = true;
					break;
				}
				dprev = r.br_startoff + r.br_blockcount;
				d1st = false;
			}
			if (dgap)
				ip->i_mxfs_dir_hole_known = true;	/* 0.75.63: the flush-time detector must not call this adopted hole a tear */
			if (dgap)
				mxfs_probe_ratelimited(
					"mxfs: P-RELOAD-HOLEY-ADOPT ino=%llu disk_nx=%d incore_nx=%llu gen=%u dlm_mode=%u — disk dir map has a data-region hole (legit sparse state, e.g. partial rm); adopting disk\n",
					(unsigned long long)ip->i_ino, dnx,
					(unsigned long long)ip->i_df.if_nextents,
					VFS_I(ip)->i_generation, ip->i_dlm_mode);
		}
	}

	/*
	 * PROVEN BY INSTRUMENT 32-node dir EX-loop root fix:
	 * every cross-node EX handoff reloads this inode, and the
	 * xfs_idestroy_fork below unloads the in-core extent map even when the
	 * on-disk dinode is IDENTICAL to our in-core state (P62 fields all
	 * equal — nothing changed since our copy loaded).  The next
	 * xfs_ilock_data_map_shared then sees xfs_need_iread_extents and takes
	 * ILOCK_EXCL -> DLM EX just to re-read an extent map it already had ->
	 * BASTs every PR reader -> THEIR handoff-reload unloads THEIR forks ->
	 * their next lookup takes EX -> ... a self-sustaining cluster-wide EX
	 * rotation that turns the read-only cache_coherency@32 rename-verify
	 * into a ~630ms/op convoy (P138-WAIT mode=5 on a pure `cat` loop) and
	 * blows the 300s budget with zero real coherency work.
	 *
	 * di_changecount is bumped by EVERY logged modification of this inode
	 * (SB_I_VERSION), so disk changecount == in-core i_version, with the
	 * same di_gen incarnation, proves NO modification — a peer's OR our
	 * own — sits between our in-core state and the on-disk image: the
	 * adopt below would rebuild byte-identical state.  Skip ONLY the
	 * destructive statements (fork destroy, owner-evict, from_disk); every
	 * freshness stamp (loaded_gen below, acq_epoch/valid_epoch/handoff
	 * consumption above) still runs, so the epoch gates converge exactly
	 * as on a real adopt and no reload loop re-arms.  Any actual change —
	 * including our own committed-but-not-destaged mods (in-core i_version
	 * ahead of disk) — fails the equality and takes today's full adopt
	 * path unchanged.  A/B: reload_skip_identical=0 reverts.
	 */
	/*
	 * D-512 T8 kind-4: synthesize the dirty different-gen
	 * observation at a point every protective reload deterministically
	 * reaches (the freshsrc adopt chain's real arm needs a protected
	 * cached snapshot + live gen-mismatched fresh image — preconditions a
	 * healthy rig cannot produce; first T8 run proved the armed re-read
	 * short-circuits at P-RELOAD-IDENTICAL below without evaluating it).
	 * The RESPONSE is the real one and must mirror the real arm exactly:
	 * poison + fail-stop shutdown, node withdraws, never returns to
	 * service.
	 */
	if (unlikely(mxfs_dbg_rel_fail(ip, 4))) {
		pr_err("mxfs: P-D512-DIRTY-MISMATCH ino=%llu (SYNTHETIC T8 kind=4) — injected dirty cross-incarnation observation at protective reload; poisoning + fail-stop\n",
		       (unsigned long long)ip->i_ino);
		mxfs_incarn_poison(ip);
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
	}
	if (mxfs_reload_skip_identical && dip && dip->di_version >= 3 &&
	    be16_to_cpu(dip->di_mode) != 0 &&
	    be16_to_cpu(dip->di_mode) == VFS_I(ip)->i_mode &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    be64_to_cpu(dip->di_changecount) ==
			inode_peek_iversion(VFS_I(ip)) &&
	    /* (design-consult ruling F3): "identical" discharges the ledger,
	     * so it must also prove the field the unlink obligation is about. */
	    be32_to_cpu(dip->di_nlink) == VFS_I(ip)->i_nlink &&
	    dip->di_format == ip->i_df.if_format &&
	    be64_to_cpu(dip->di_size) == (uint64_t)ip->i_disk_size &&
	    ((be64_to_cpu(dip->di_flags2) & XFS_DIFLAG2_NREXT64) ?
	     be64_to_cpu(dip->di_big_nextents) :
	     (uint64_t)be32_to_cpu(dip->di_nextents)) ==
			(uint64_t)ip->i_df.if_nextents) {
		reload_identical = true;
		mxfs_probe_ratelimited(
			"mxfs: P-RELOAD-IDENTICAL ino=%llu cc=%llu gen=%u fmt=%u nx=%llu size=%lld — disk == in-core, keeping loaded fork (no destroy/adopt)\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)be64_to_cpu(dip->di_changecount),
			VFS_I(ip)->i_generation, ip->i_df.if_format,
			(unsigned long long)ip->i_df.if_nextents,
			(long long)ip->i_disk_size);
		/*
		 * ccloop-4dd7 P134 (instrumented, ino-1862 zombie autopsy): the
		 * "identical" verdict compared dip against IN-CORE state — but
		 * dip may itself be a STALE cached buffer image (the zombie
		 * O_TRUNC read gen-574-allocated here while ~100ms later the
		 * INACT guard's raw read saw gen-575-free).  Crosscheck the
		 * coherent medium: a differing plain-read means the reload was
		 * served a stale cluster buffer (reader-side hole) — vs the
		 * coherent image also matching (writer-side destage lag).
		 * Capped; fires only in the identical branch.
		 */
		if (mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
			static atomic_t p134_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p134_n) <= 2000) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t cl = BBTOB(ip->i_imap.im_len);
				void *ct = ((cl & 511) == 0 && cl) ?
					kmalloc(cl, GFP_NOFS) : NULL;

				if (ct && mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev,
					(uint64_t)ip->i_imap.im_blkno +
					mp->m_ddev_targp->bt_sector_offset,
					ct, cl) == 0) {
					struct xfs_dinode *cd =
						(struct xfs_dinode *)((char *)ct +
						ip->i_imap.im_boffset);

					/*
					 * (D-0941): the original crosscheck
					 * compared ONLY mode and gen — the two fields
					 * that do NOT change when a peer adds or removes
					 * dirents in a directory it already owns.  So for
					 * the whole class of defects this branch can cause
					 * (identical-verdict keeps a fork that still holds
					 * a peer's deleted names) the crosscheck was
					 * VACUOUS: it could never fire.  Compare the fields
					 * a dirent change actually moves — changecount,
					 * size, nextents, nlink — so a buffer image that is
					 * behind the coherent medium is named at the moment
					 * the "identical" verdict is issued on it.
					 */
					uint64_t bcc = be64_to_cpu(dip->di_changecount);
					uint64_t ccc = be64_to_cpu(cd->di_changecount);
					uint64_t bsz = be64_to_cpu(dip->di_size);
					uint64_t csz = be64_to_cpu(cd->di_size);
					uint64_t bnx = (be64_to_cpu(dip->di_flags2) &
						XFS_DIFLAG2_NREXT64) ?
						be64_to_cpu(dip->di_big_nextents) :
						be32_to_cpu(dip->di_nextents);
					uint64_t cnx = (be64_to_cpu(cd->di_flags2) &
						XFS_DIFLAG2_NREXT64) ?
						be64_to_cpu(cd->di_big_nextents) :
						be32_to_cpu(cd->di_nextents);

					if (cd->di_mode != dip->di_mode ||
					    cd->di_gen != dip->di_gen ||
					    ccc != bcc || csz != bsz || cnx != bnx ||
					    cd->di_nlink != dip->di_nlink)
						mxfs_probe("mxfs: P134-IDENTICAL-BUFSTALE ino=%llu isdir=%d BUF[mode=0%o gen=%u cc=%llu sz=%llu nx=%llu nlink=%u] COH[mode=0%o gen=%u cc=%llu sz=%llu nx=%llu nlink=%u] bflags=0x%x comm=%s — identical-verdict served a STALE cluster buffer\n",
							(unsigned long long)ip->i_ino,
							S_ISDIR(VFS_I(ip)->i_mode),
							be16_to_cpu(dip->di_mode),
							be32_to_cpu(dip->di_gen),
							(unsigned long long)bcc,
							(unsigned long long)bsz,
							(unsigned long long)bnx,
							be32_to_cpu(dip->di_nlink),
							be16_to_cpu(cd->di_mode),
							be32_to_cpu(cd->di_gen),
							(unsigned long long)ccc,
							(unsigned long long)csz,
							(unsigned long long)cnx,
							be32_to_cpu(cd->di_nlink),
							bp->b_flags, current->comm);
				}
				kfree(ct);
			}
		}
	}

	/*
	 * TIME-TRAVEL GUARD (instrumented, PROVEN run
	 * 052155Z): under the tenure floor the home cluster daddr legitimately
	 * LAGS the coherent cluster truth (P62-DUALREAD: 25 nodes read
	 * raw==buffered chg=649 at 05:25:39 while their in-core forks were
	 * already ahead), and this reload then ADOPTED the older image —
	 * the in-core extent map time-traveled backward while the dir's
	 * STRUCTURE blocks (leaf/free, read separately) stayed newer, so the
	 * next lookup/shrink tripped P14-DABUF-HOLE / bunmapi i!=1 -> dirty
	 * xfs_trans_cancel -> shutdown -> per-inode EIO death (victims
	 * test10/17/30, rename_visibility ino 52953221).  di_changecount is
	 * bumped by every logged modification (SB_I_VERSION), so a
	 * same-incarnation disk image with a STRICTLY LOWER changecount than
	 * our in-core i_version is provably a stale snapshot of state we have
	 * already moved past — adopting it can only destroy newer state.
	 * KEEP the in-core fork via the reload_identical skip (all freshness
	 * stamps still run, so the epoch gates converge and no reload loop
	 * re-arms).  A reused inode (di_gen differs), a freed slot (mode 0),
	 * a type flip, or a genuinely newer/equal disk image adopt exactly as
	 * before.
	 */
	if (!reload_identical && dip && dip->di_version >= 3 &&
	    be16_to_cpu(dip->di_mode) != 0 &&
	    (be16_to_cpu(dip->di_mode) & S_IFMT) ==
			(VFS_I(ip)->i_mode & S_IFMT) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    be64_to_cpu(dip->di_changecount) <
			inode_peek_iversion(VFS_I(ip))) {
		static atomic_t p3tt = ATOMIC_INIT(0);

		reload_identical = true;
		reload_kept_ahead = true;	/* in-core AHEAD, nothing landed */
		/*
		 *  — DECIDE WHETHER THIS REFUSAL IS THE LOSS.
		 *
		 * di_changecount only orders images along ONE serialization chain.
		 * The moment any node keeps its own fork instead of adopting a
		 * peer's published image, the two histories FORK and their
		 * changecounts stop being comparable — each side then bumps from
		 * its own base.  So this very guard can be the thing that turns a
		 * recoverable staleness into a permanent divergence: if the platter
		 * image carries names our in-core fork does not have, "keeping the
		 * fork" destroys those names the moment we publish.
		 *
		 * For a shortform directory both name sets are a few dozen bytes
		 * away, so print them and let the evidence settle it.  Fires only
		 * on a refusal (~175/run), so there is no hot-path cost.
		 */
		if (atomic_read(&p3tt) < 2000 &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    dip->di_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_data) {
			extern void mxfs_sf_disk_names(struct xfs_mount *,
					struct xfs_dinode *, char *, size_t);
			char p3in[160], p3dk[160];

			mxfs_sf_fmt_names(mp, ip->i_df.if_data, p3in,
					  sizeof(p3in));
			mxfs_sf_disk_names(mp, dip, p3dk, sizeof(p3dk));
			mxfs_probe("mxfs: P3-SFSETS ino=%llu disk_chg=%llu incore_chg=%llu disk_nlink=%u incore_nlink=%u incore=[%s] disk=[%s] comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)be64_to_cpu(dip->di_changecount),
				(unsigned long long)inode_peek_iversion(VFS_I(ip)),
				be32_to_cpu(dip->di_nlink),
				VFS_I(ip)->i_nlink, p3in, p3dk, current->comm,
				(unsigned long long)ktime_get_real_ns());
		}
		if (atomic_inc_return(&p3tt) <= 2000)
			pr_warn("mxfs: P3-REFUSE-OLDER-DISK ino=%llu disk_chg=%llu incore_chg=%llu disk_nx=%u incore_nx=%llu disk_fmt=%u incore_fmt=%u gen=%u dlm_mode=%u comm=%s — home image older than coherent in-core; keeping fork\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)be64_to_cpu(dip->di_changecount),
				(unsigned long long)inode_peek_iversion(VFS_I(ip)),
				be32_to_cpu(dip->di_nextents),
				(unsigned long long)ip->i_df.if_nextents,
				dip->di_format, ip->i_df.if_format,
				VFS_I(ip)->i_generation, ip->i_dlm_mode,
				current->comm);
	}

	/*
	 * 2026-07-16 DIRTY-DATA GUARD (instrumented, PROVEN live at fence@8/caw):
	 * a REGULAR FILE with un-destaged local data — delalloc blocks, dirty
	 * pagecache, or pages in writeback — must never have its data fork
	 * destroyed/rebuilt from an on-disk dinode.  The release fence
	 * destages data before any peer tenure, so local dirty data PROVES
	 * the platter is behind us; the log-item self_ahead checks (P34E) and
	 * the changecount time-travel guard (P3) both miss this state because
	 * a buffered write's tail lives only in pages + a delalloc extent
	 * (ili_fields=0, i_disk_size not yet advanced, di_changecount equal).
	 * Proven sequence (test3 ino=4196680, fdw own-file f6): BAST-drain
	 * flush destaged the write's FIRST page (disk size=4096 nx=2), head
	 * finished the tail into pagecache as delalloc, reacquire's reload
	 * adopted disk (P34D), xfs_idestroy_fork dropped the delalloc extent
	 * and xfs_inode_from_disk reverted i_size to 4096 — writeback then
	 * silently discarded the beyond-EOF dirty tail: durable loss of the
	 * node's own committed write (exp/got md5 mismatch, healed=0).
	 * Directories are exempt: their data lives in the buffer cache and
	 * the dir-specific guards above own that logic.
	 */
	if (!reload_identical && S_ISREG(VFS_I(ip)->i_mode)) {
		struct address_space *dd_map = VFS_I(ip)->i_mapping;
		bool dd_dirty = ip->i_delayed_blks > 0 ||
			(dd_map &&
			 (mapping_tagged(dd_map, PAGECACHE_TAG_DIRTY) ||
			  mapping_tagged(dd_map, PAGECACHE_TAG_WRITEBACK)));

		if (dd_dirty) {
			reload_identical = true;
			reload_kept_ahead = true;	/* platter behind us */
			mxfs_probe_ratelimited(
				"mxfs: P34F-RELOAD-DIRTYDATA-SKIP ino=%llu delayed_blks=%llu vfs_size=%lld disk_size=%lld incore_nx=%llu disk_nx=%u dlm_mode=%u comm=%s — un-destaged local file data; keeping in-core fork (platter is behind us)\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_delayed_blks,
				(long long)i_size_read(VFS_I(ip)),
				dip ? (long long)be64_to_cpu(dip->di_size) : -1,
				(unsigned long long)ip->i_df.if_nextents,
				dip ? be32_to_cpu(dip->di_nextents) : 0,
				ip->i_dlm_mode, current->comm);
		}
	}

	/*
	 *  — LAST-RESORT KEEP.
	 *
	 * Mechanism tally over 6 storm runs / 45 failing rounds
	 * (tests/sf_storm_ledger.py <run> -1):
	 *     NEVER-PUBLISHED       32
	 *     DROPPED-BY-PUBLISH     5
	 *     NO-PUBLISH-CAPTURED    8
	 * The dominant loss is NOT a stale publish clobbering peers.  It is a
	 * committed create that NO node ever published: the creator's mkdir
	 * returned success, and the name and its parent-link bump then vanished
	 * together.  On the captured victim the reload said so itself —
	 * P177-OBLIGATION-DROPPED-AT-ADOPT ino=35651735 pending=16 durable=12 —
	 * and then reconciled the counters and adopted anyway.
	 *
	 * The 3-way merge cannot rescue this case: a directory created moments
	 * ago has no captured merge BASE, so the snapshot is never taken (P183
	 * fired 0 times; only 28 of 2836 reloads merge at all).
	 *
	 * With no base there is no safe way to combine the two images, so take
	 * the one decision that cannot destroy committed work: KEEP the fork and
	 * leave i_dlm_stale set, so the adopt is retried once our change has
	 * landed.  The cost is bounded staleness on this one access — peers'
	 * newest names arrive on the next reload — and the obligation window is
	 * short (the drain's silent-success exit, P176, fires 0 times in these
	 * runs, i.e. obligations do get settled).  Trading temporary staleness
	 * for permanent loss is the right side of that trade; the reverse is
	 * what produced undeletable directories at nlink=1 and 4294967295.
	 *
	 * This is the same shape as the guards already here for dirty data
	 * (P34F) and for an older platter (P3) — it just uses the one predicate
	 * that expresses "committed but not yet at its home location", which is
	 * exactly what those two miss.
	 *
	 * ─────────────────────────────────────────────────────────────────────
	 *  — THE ABOVE IS UNBOUNDED, AND THAT IS THE
	 * DOMINANT CORRUPTION.  Measured byte-exact, test23 ino=44040339, one
	 * node, 11 ms (run sfstorm_20260728_161237):
	 *
	 *  3669.363720 P63-HANDOFF grant_gen=31 acted_gen=2 — cross-node EX
	 *              handoff; forcing disk-superset adopt
	 *  3669.364147 P184-RELOAD-KEEP-OBLIGATION pending=4 durable=3
	 *              nlink=5 disk_nlink=34 fmt=1   <== veto lands here
	 *  3669.365088 P146V-UNLANDED incore[nlink=5  size=53   fmt=LOCAL]
	 *                             disk  [nlink=34 size=4096 fmt=EXTENTS]
	 *  3669.370074 P32-IFLUSH-NXSHRINK — smaller dir extent map over larger
	 *  3669.370082 P-CCREGRESS cc_disk=35 cc_writing=7
	 *  3669.374764 P186-NLINK-REVERT out_nlink=5 seen_disk_nlink=34
	 *
	 * The obligation this guard protects was worth ONE committed mkdir.
	 * What keeping the fork then destroyed was 29 links and 29 names: the
	 * platter held a BLOCK-format directory with 32 entries, our fork was a
	 * three-entry SHORTFORM image from a tenure long past, and the release
	 * drain published it with full authority (relflush=1, grant held=1).
	 * All 15 surviving nlink reverts in that run have exactly this shape.
	 *
	 * "Keep the fork" is only defensible while we are genuinely AHEAD.  The
	 * predicate above says nothing about that — pending != durable is true
	 * whenever ANY change of ours is unlanded, including when the platter has
	 * since moved a whole tenure past us.  Bound it with the three facts that
	 * prove the platter is ahead, any one of which makes keeping the fork a
	 * pure regression:
	 *
	 *   - a LOWER link count than the platter (we cannot be ahead while
	 *     holding fewer children),
	 *   - a LOWER changecount than the platter on the same incarnation,
	 *   - a format REGRESSION (in-core LOCAL vs an on-disk non-LOCAL image —
	 *     shortform->block is one-way, so a block platter is proof of a
	 *     later tenure).
	 *
	 * When any of those holds, adopt: the peer's work is authoritative and
	 * P177 already records the obligation we drop.  Dropping one committed
	 * change is a defect that still needs its own fix at the release barrier
	 * (P188) — but it is not a licence to revert 29 of a peer's.
	 */
	if (mxfs_reload_oblig_keep && !reload_identical &&
	    S_ISDIR(VFS_I(ip)->i_mode) && dip &&
	    be16_to_cpu(dip->di_mode) != 0 &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
	    /* only defensible while we are provably AHEAD — see the
	     * P184/P186 root note above.  Any of these three means the platter
	     * moved past us and keeping the fork can only revert a peer. */
	    !(VFS_I(ip)->i_nlink < be32_to_cpu(dip->di_nlink)) &&
	    !(inode_peek_iversion(VFS_I(ip)) <
			be64_to_cpu(dip->di_changecount)) &&
	    !(ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	      dip->di_format != XFS_DINODE_FMT_LOCAL) &&
	    ip->i_mxfs_pub_pending_seq != ip->i_mxfs_pub_durable_seq) {
		static atomic_t p184n = ATOMIC_INIT(0);

		reload_identical = true;
		reload_kept_ahead = true;	/* obligation kept open */
		ip->i_dlm_stale = true; ip->i_dlm_stale_src = 26;
		/* same question as P3-SFSETS — a "keep our fork" verdict
		 * is only safe if the platter has nothing we lack.  Print both
		 * shortform name sets so a refusal that destroys a peer's names is
		 * visible at the decision, not three publishes later. */
		if (atomic_read(&p184n) < 4000 &&
		    dip && dip->di_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_data) {
			extern void mxfs_sf_disk_names(struct xfs_mount *,
					struct xfs_dinode *, char *, size_t);
			char k4in[160], k4dk[160];

			mxfs_sf_fmt_names(mp, ip->i_df.if_data, k4in,
					  sizeof(k4in));
			mxfs_sf_disk_names(mp, dip, k4dk, sizeof(k4dk));
			mxfs_probe("mxfs: P184-SFSETS ino=%llu incore=[%s] disk=[%s] incore_nlink=%u disk_nlink=%u comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino, k4in, k4dk,
				VFS_I(ip)->i_nlink,
				be32_to_cpu(dip->di_nlink), current->comm,
				(unsigned long long)ktime_get_real_ns());
		}
		if (atomic_inc_return(&p184n) <= 4000)
			pr_warn("mxfs: P184-RELOAD-KEEP-OBLIGATION ino=%llu pending=%llu durable=%llu flush=%llu nlink=%u disk_nlink=%u fmt=%d comm=%s — refusing to adopt the platter over an UNLANDED committed change; keeping fork, staying stale\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_mxfs_pub_pending_seq,
				(unsigned long long)ip->i_mxfs_pub_durable_seq,
				(unsigned long long)ip->i_mxfs_pub_flush_seq,
				VFS_I(ip)->i_nlink,
				dip ? be32_to_cpu(dip->di_nlink) : 0,
				ip->i_df.if_format, current->comm);
	}

	/*
	 *  — TORN-LOCAL-FORK ROOT FIX (instrument step 2b,
	 * PROVEN byte-exact, test13 ino=52953231, run sfstorm_20260728_151401):
	 *
	 *   151.405249  P34J-RELOAD-RACE-BAIL ino=52953231 demoter=1 epoch=5
	 *   151.405763  P181-FORK-TORN ino=52953231 site=trans_log_inode
	 *               if_bytes=100 mode=040755 dlm_mode=0
	 *   151.412737  P171-SFNULL x11506 -> xfs_dir2_sf_verify corruption
	 *               -> "Metadata I/O Error" -> FS SHUTDOWN + withdrawal
	 *
	 * The destroy USED TO RUN HERE, ~150 lines before xfs_inode_from_disk.
	 * xfs_idestroy_fork frees a LOCAL fork's if_data (-> NULL) and leaves
	 * if_format=LOCAL / if_bytes>0 untouched (it is written for teardown,
	 * where nothing re-reads those).  Between that point and the adopt sits
	 * the P34J pre-adopt TOCTOU bail — the ONLY `return` in the window —
	 * which discards the pre-drain snapshot and hands the inode back with a
	 * fork that is LOCAL, non-empty by if_bytes, and backed by NULL.  The
	 * inode is still a dirty AIL item, so the very next flush or the release
	 * drain's re-log arm emits a shortform directory image built from a NULL
	 * pointer: sf_verify rejects it and the mount dies.  Once torn, nothing
	 * repairs it — 11,506 P171-SFNULL in 28 s on the capture above.
	 *
	 * Fix the ORDER, not the symptom: a destroy is only safe when the
	 * repopulate that follows it cannot be skipped.  Do it immediately
	 * before xfs_inode_from_disk, so every early exit above leaves the
	 * previous, self-consistent fork in place (which is exactly what P34J's
	 * "let the caller retry against post-drain truth" already assumes).
	 * Nothing between the old and new position reads the destroyed state:
	 * xfs_idestroy_fork preserves if_nextents, and if_bytes/i_disk_size —
	 * the inputs to the shrink test below — are either preserved
	 * (LOCAL) or already zero for the formats it inspects.
	 */

	/* catch the REG<->DIR type FLIP.  If our in-core inode is a
	 * populated regular file (or any type) and this reload's source dinode
	 * carries a DIFFERENT S_IFMT, the reload is about to flip the in-core
	 * type — the exact mechanism behind `cat node1_after_1: Is a directory`
	 * after assert_file_exists already saw it as a regular file.  Logs the
	 * source buffer's freshness so we can tell stale-cached vs FUA-fresh. */
	if ((VFS_I(ip)->i_mode & S_IFMT) != 0 &&
	    be16_to_cpu(dip->di_mode) != 0 &&
	    (VFS_I(ip)->i_mode & S_IFMT) !=
		    (be16_to_cpu(dip->di_mode) & S_IFMT)) {
		mxfs_probe_ratelimited(
			"mxfs: P-RELOAD-TYPEFLIP ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u bp_flags=0x%x\n",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
			VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
			bp->b_flags);
	}

	/*
	 * (instrumented, design review architecture): purge owned dir blocks BEFORE
	 * adopting a shrinking / incarnation-changing on-disk image.  The post-
	 * adopt per-extent-map evict only reaches the NEW (smaller) map's daddrs,
	 * leaving the prior incarnation's leaf/data blocks orphaned-stale at
	 * reused daddrs => leaf-vs-data tear (drc leaf-hash lookup_fail).  Compare
	 * the about-to-adopt dip to our in-core; on di_gen change OR a strict
	 * shrink, owner-evict ALL cached dir blocks (by header owner, map-
	 * independent) so the post-adopt cold read rebuilds a coherent image.
	 * Dirs only; same-incarnation same-size reload pays nothing. */
	if (S_ISDIR(VFS_I(ip)->i_mode) && be16_to_cpu(dip->di_mode) != 0) {
		uint64_t d_fl2 = be64_to_cpu(dip->di_flags2);
		uint64_t d_nx = (d_fl2 & XFS_DIFLAG2_NREXT64) ?
			be64_to_cpu(dip->di_big_nextents) :
			be32_to_cpu(dip->di_nextents);
		uint64_t d_size = be64_to_cpu(dip->di_size);
		bool gen_change =
			be32_to_cpu(dip->di_gen) != VFS_I(ip)->i_generation;
		bool shrink = d_size < (uint64_t)ip->i_disk_size ||
			      d_nx < (uint64_t)ip->i_df.if_nextents;

		/*
		 * < > Also owner-evict on a genuine cross-node EX
		 * HANDOFF (not just shrink/gen-change).  PROVEN 8/tcp DISK-TORN root:
		 * after a peer's same-incarnation middle-block-free removal, our
		 * cached LEAF is stale (still references the freed block) but the
		 * read-time leaf invalidation is gated on the LOSSY TCP i_dlm_dir_gen
		 * (a fast-pathed EX re-acquire misses the bump), so the stale leaf is
		 * not re-read — and `mxfs_dir_ex_write_guard` (default ON) does NOT
		 * skip it because we DO hold EX, so xfsaild destages the stale leaf
		 * over the peer's durable leaf => leaf-vs-map tear => DABUF_MAP_HOLE.
		 * genuine_handoff is the RELIABLE (master grant-handoff) signal that a
		 * peer modified this dir since our base loaded; evicting ALL cached
		 * dir blocks here forces a cold, coherent re-read of the leaf/data
		 * from the platter before this tenure can flush a superseded image.
		 * Safe with the torn-disk reload gate above: a torn disk already
		 * bailed before reaching here, so this only fires on a good-disk
		 * adopt.  Gated on genuine_handoff so solo/unchanged dirs pay nothing
		 * (budget).  UNVERIFIED — test drc_reliab_iter.sh 8 >=5x before trust. */
		if (!reload_identical &&
		    (gen_change || shrink || genuine_handoff)) {
			mxfs_probe_ratelimited("mxfs: P68-PREEVICT ino=%llu gen_change=%d shrink=%d handoff=%d disk_gen=%u incore_gen=%u disk_sz=%llu incore_sz=%lld\n",
				(unsigned long long)ip->i_ino, gen_change, shrink,
				genuine_handoff ? 1 : 0,
				be32_to_cpu(dip->di_gen), VFS_I(ip)->i_generation,
				(unsigned long long)d_size, (long long)ip->i_disk_size);
			/* < > FULL evict (data+leaf) on handoff: leaf-only
			 * was MEASURED insufficient (re-admitted DISK-TORN/HOLE — the
			 * stale DATA blocks also feed the tear).  Full evict eliminates
			 * ALL corruption.  test6 readdir=0 is INDEPENDENT of evict scope
			 * (present with full, leaf-only, AND reload-gate-only) → a
			 * separate dir-data-block release-durability gap, not an
			 * evict artifact.  leaf_only param kept as a lever. */
			mxfs_dir_evict_owned_dir_blocks(ip, false);
		}
	}

	/*
	 *  pre-adopt TOCTOU recheck (pairs with the
	 * entry-side P34J demoter bail).  If a release drain started (or an
	 * epoch moved — any grant loss) since this reload sampled the
	 * platter, the snapshot in `dip`/`snap` may predate the drain's
	 * bwrite; adopting it would revert in-core behind a completed write
	 * (the round-4 node1_f1..f4 loss).  Discard and let the caller
	 * retry against post-drain truth.
	 */
	if (mxfs_foreign_demoter(ip) ||
	    READ_ONCE(ip->i_dlm_epoch) != r_entry_epoch) {
		/* H2: stamp the abandonment so P32E can report whether the
		 * flush it is fencing belongs to an inode whose reload was
		 * abandoned moments earlier (see i_mxfs_racebail_ns). */
		ip->i_mxfs_racebail_ns = ktime_get_ns();
		atomic64_inc(&mxfs_rb_total);
		mxfs_probe_ratelimited(
		    "mxfs: P34J-RELOAD-RACE-BAIL ino=%llu demoter=%d epoch=%lu entry_epoch=%lu — drain raced this reload; discarding pre-drain snapshot\n",
			(unsigned long long)ip->i_ino,
			mxfs_foreign_demoter(ip) ? 1 : 0,
			READ_ONCE(ip->i_dlm_epoch), r_entry_epoch);
		kfree(merge_ours);
		kfree(snap);
		if (bp)
			xfs_buf_relse(bp);
		up_write(&ip->i_lock);
		/* leave i_dlm_stale set — caller retries post-drain */
		return;
	}

	{
	umode_t old_ifmt = VFS_I(ip)->i_mode & S_IFMT;
	/* snapshot pre-adopt dir geometry so the owner-evict below fires
	 * only on the rare SHRINK / incarnation-change reload (P33-DIRSHRINK). */
	long long	p68_old_size = (long long)ip->i_disk_size;
	uint64_t	p68_old_nx = (uint64_t)ip->i_df.if_nextents;
	uint32_t	p68_old_incarn = VFS_I(ip)->i_generation;
	{
		extern unsigned long long mxfs_watch_ino;

		if (unlikely(mxfs_watch_ino) && ip->i_ino == mxfs_watch_ino)
			mxfs_probe("mxfs: PW-ADOPT ino=%llu incore_fmt=%d incore_nx=%llu incore_size=%lld -> disk_fmt=%d disk_nx=%u disk_size=%lld pin=%d in_ail=%d fields=0x%x last=0x%x dlm_mode=%d comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				dip->di_format,
				be32_to_cpu(dip->di_nextents),
				(long long)be64_to_cpu(dip->di_size),
				atomic_read(&ip->i_pincount),
				ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags) ? 1 : 0,
				ip->i_itemp ? ip->i_itemp->ili_fields : 0,
				ip->i_itemp ? ip->i_itemp->ili_last_fields : 0,
				ip->i_dlm_mode,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
	}
	/*
	 *  (P186): the platter image is in hand right
	 * here, at the one place every acquire passes through.  Record the
	 * highest di_nlink we have ever seen durable for THIS incarnation so
	 * the publish site can recognise an outgoing image that goes backward.
	 * Same-incarnation only — a reused inode number starts over.
	 */
	if (dip && be16_to_cpu(dip->di_mode) != 0 &&
	    S_ISDIR(VFS_I(ip)->i_mode)) {
		uint32_t d_gen = be32_to_cpu(dip->di_gen);
		uint32_t d_nl = be32_to_cpu(dip->di_nlink);

		if (ip->i_mxfs_disk_nlink_gen != d_gen) {
			ip->i_mxfs_disk_nlink_gen = d_gen;
			ip->i_mxfs_disk_nlink_seen = d_nl;
		} else if (d_nl > ip->i_mxfs_disk_nlink_seen) {
			ip->i_mxfs_disk_nlink_seen = d_nl;
		}
	}
	if (unlikely(mxfs_nlink_ledger) && S_ISDIR(VFS_I(ip)->i_mode))
		mxfs_probe("mxfs: P180-NLR ino=%llu incore=%u disk=%u identical=%d incore_cc=%llu disk_cc=%llu comm=%s realns=%llu\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_nlink,
			be32_to_cpu(dip->di_nlink), reload_identical ? 1 : 0,
			(unsigned long long)inode_peek_iversion(VFS_I(ip)),
			(unsigned long long)be64_to_cpu(dip->di_changecount),
			current->comm,
			(unsigned long long)ktime_get_real_ns());
	/* Destroy existing fork data before repopulating.
	 *
	 *  this MUST stay immediately adjacent to the
	 * xfs_inode_from_disk below — see the torn-LOCAL-fork root-fix note
	 * further up.  Anything that can return between the two leaves a
	 * LOCAL fork with if_bytes>0 and if_data==NULL, which is an
	 * unrepairable shortform directory that shuts the filesystem down. */
	if (!reload_identical) {
		xfs_idestroy_fork(&ip->i_df);
		/* (D-0535): zap, not destroy — if_bytes/if_format must
		 * not survive into an image that has no attr fork (see
		 * mxfs_dlm_reset_inode_for_create); xfs_inode_from_disk
		 * re-initialises a present fork from the dinode. */
		xfs_ifork_zap_attr(ip);
		if (ip->i_cowfp) {
			xfs_idestroy_fork(ip->i_cowfp);
			kmem_cache_free(xfs_ifork_cache, ip->i_cowfp);
			ip->i_cowfp = NULL;
		}
		/* a real adopt rebuilds the fork —
		 * any prior "leaf verified ENOENT-consistent" datascan state
		 * is void.  Re-arm one scan (see i_mxfs_dscan_clean_key). */
		ip->i_mxfs_dscan_clean_key = ~0ULL;
	}

	error = reload_identical ? 0 : xfs_inode_from_disk(ip, dip);
	if (error) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: DLM inode from_disk FAILED: ino=%llu rc=%d",
			(unsigned long long)ip->i_ino, error);
		/*
		 *  the destroy above already ran, so on
		 * a from_disk failure the fork is torn exactly like the P34J
		 * case was (LOCAL / if_bytes>0 / if_data==NULL).  from_disk has
		 * measured 0 failures in every storm run so far, but "rare" is
		 * not a disposition — leave the fork in the canonical empty
		 * state instead of a NULL-backed shortform, and keep
		 * i_dlm_stale set so the next access reloads for real.
		 */
		if (ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_bytes > 0 && !ip->i_df.if_data) {
			mxfs_probe("mxfs: P181R-FROMDISK-FAIL-TEAR ino=%llu if_bytes=%lld — from_disk failed after the fork destroy; resetting to empty EXTENTS rather than leaving a NULL-backed LOCAL fork\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_df.if_bytes);
			ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
			ip->i_df.if_bytes = 0;
			ip->i_df.if_nextents = 0;
		}
		ip->i_dlm_stale = true; ip->i_dlm_stale_src = 21;
		kfree(merge_ours);		/* drop unused snapshot */
		merge_ours = NULL;
	} else {
		/* (D3): adoption succeeded — in-core now IS the disk
		 * incarnation; clear any dead-incarnation verdict. */
		ip->i_mxfs_dead_incarn_gen = 0;
		/*
		 * (D3 residual): the in-core image was just REPLACED by
		 * the platter image, so by construction nothing in core is
		 * unlanded — the publication obligation is settled here, and if
		 * it is NOT settled we have just overwritten a committed change
		 * that never reached its home location.  That is the loss shape
		 * itself, so say so loudly and then reconcile the counters (a
		 * stale obligation left open across an adopt would otherwise
		 * make every later release drain re-log the adopted image
		 * forever).
		 */
		/*
		 * (design-consult ruling F3/F4).  Three distinct outcomes share
		 * this branch and only ONE of them may touch the ledger:
		 *
		 *  (a) reload_kept_ahead — the in-core was KEPT because it is
		 *      AHEAD of the platter (P3-REFUSE-OLDER-DISK / P34F / P184).
		 *      Nothing of ours landed; discharging here is laundering
		 *      (measured: P177 identical=1 pend=1 dur=0 closed a P119-
		 *      laundered unlink conversion, the AGI list then named a
		 *      LINKED dinode forever).  Leave the obligation OPEN — the
		 *      reldefer worker's converter (P245, now with the re-log
		 *      repair) and xfsaild's PR-held PUBOB flush (P55B) are its
		 *      writers; D-380's bounded episode still applies.
		 *  (b) reload_identical by PROOF (disk == in-core incl. changecount,
		 *      P-RELOAD-IDENTICAL) — the platter already carries every
		 *      committed change; discharge is honest.
		 *  (c) a REAL adopt (from_disk ran) — the in-core was replaced by
		 *      the platter image; by construction nothing in core is
		 *      unlanded.  Discharge (P177 says so loudly if it was open).
		 *      If the adopted image is a DIFFERENT INCARNATION (di_gen
		 *      moved / slot freed / type flipped) an armed PUBOB belongs to
		 *      the dead incarnation: its home conversion was superseded by
		 *      whoever freed+reused the number — cancel it (drop the flag
		 *      and list entry, "superseded"), never call it durable.
		 *      A real adopt is also the ONLY case that may strip this
		 *      node's freer authority (MXFS_IF_LOCAL_UNLINK /
		 *      ADOPTED_UNLINK): the clear used to run
		 *      unconditionally at reload ENTRY, so the reldefer
		 *      reload of our OWN live unlink (no adopt) stripped the flag
		 *      and xfs_inactive's B3 guard then skipped the ifree as
		 *      "torn-live-no-local-unlink" — the inode was never freed and
		 *      its AGI entry never removed (measured, INACT-SKIP-STALE).
		 */
		if (reload_kept_ahead) {
			if (ip->i_mxfs_pub_pending_seq !=
			    ip->i_mxfs_pub_durable_seq)
				mxfs_probe_ratelimited(
				    "mxfs: P177-KEPT-AHEAD-OBLIGATION-OPEN ino=%llu pending=%llu durable=%llu flush=%llu mode=0%o nlink=%u pubob=%d — in-core ahead of platter, reload kept it; ledger NOT discharged\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					VFS_I(ip)->i_mode, VFS_I(ip)->i_nlink,
					xfs_iflags_test(ip, MXFS_IF_PUBOB) ? 1 : 0);
		} else {
		if (!reload_identical) {
			bool new_incarn = dip &&
				(be32_to_cpu(dip->di_gen) != p68_old_incarn ||
				 be16_to_cpu(dip->di_mode) == 0 ||
				 (be16_to_cpu(dip->di_mode) & S_IFMT) != old_ifmt);

			xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK |
					     MXFS_IF_ADOPTED_UNLINK);
			if (new_incarn && xfs_iflags_test(ip, MXFS_IF_PUBOB)) {
				extern void mxfs_pubob_discharge(struct xfs_mount *,
								 struct xfs_inode *,
								 const char *);
				pr_warn_ratelimited(
				    "mxfs: P177-PUBOB-SUPERSEDED ino=%llu old_gen=%u disk_gen=%u disk_mode=0%o — obligation belonged to a dead incarnation; cancelled (not durable)\n",
					(unsigned long long)ip->i_ino,
					p68_old_incarn, be32_to_cpu(dip->di_gen),
					be16_to_cpu(dip->di_mode));
				mxfs_pubob_discharge(mp, ip, "superseded");
			}
		}
		if (ip->i_mxfs_pub_pending_seq != ip->i_mxfs_pub_durable_seq) {
			mxfs_probe_ratelimited(
			    "mxfs: P177-OBLIGATION-DROPPED-AT-ADOPT ino=%llu pending=%llu durable=%llu flush=%llu mode=0%o identical=%d — reload adopted the platter over an UNLANDED committed change\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_mxfs_pub_pending_seq,
				(unsigned long long)ip->i_mxfs_pub_durable_seq,
				(unsigned long long)ip->i_mxfs_pub_flush_seq,
				VFS_I(ip)->i_mode,
				reload_identical ? 1 : 0);
		}
		/* F3: adopt discharges the ledger, so it must stamp
		 * like a discharge (stamp first, wmb, durable second).  The
		 * adopted image came FROM the platter, but stamping the
		 * CURRENT epoch is the conservative direction: the ticket
		 * check then demands a flush after this adopt, never before. */
		WRITE_ONCE(ip->i_mxfs_pub_durable_fepoch,
			   (uint64_t)atomic64_read(&mp->m_mxfs_flush_epoch));
		smp_wmb();
		ip->i_mxfs_pub_durable_seq = ip->i_mxfs_pub_pending_seq;
		ip->i_mxfs_pub_flush_seq = ip->i_mxfs_pub_pending_seq;
		}
		/* < > tripwire: xfs_inode_from_disk must produce only
		 * REAL extents (disk never stores delalloc).  If a delalloc extent
		 * is present right after adopting disk, the in-core fork was
		 * corrupted before/around the reload (not by from_disk itself). */
		mxfs_dir_delalloc_tripwire(ip, "post_from_disk");
		/* P8-SFADOPT — resurrection tracer (gated
		 * dir_relverify): ledger the SF name set this reload just
		 * adopted from disk.  An owner-removed name reappearing here
		 * = the disk image was already polluted at adopt time. */
		if (mxfs_dir_relverify && S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			char p8nm[160];

			mxfs_sf_fmt_names(mp, ip->i_df.if_data, p8nm,
					  sizeof(p8nm));
			mxfs_probe("mxfs: P8-SFADOPT ino=%llu size=%lld post_release=%d handoff=%d names=[%s] realns=%llu\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_disk_size,
				post_release ? 1 : 0,
				genuine_handoff ? 1 : 0, p8nm,
				(unsigned long long)ktime_get_real_ns());
		}
		/*
		 * PROVEN ROOT FIX (instrumented, oops trace): xfs_idestroy_fork
		 * above frees a LOCAL data fork's if_data (→NULL) but LEAVES
		 * if_bytes and if_format=LOCAL stale (it never resets them).
		 * xfs_inode_from_disk EARLY-RETURNS 0 for a mode=0 (peer-FREED)
		 * disk inode (xfs_inode_buf.c: `if (!inode->i_mode) return 0;`)
		 * WITHOUT calling xfs_iformat_data_fork — so the fork is left
		 * format=LOCAL / if_bytes>0 / if_data=NULL.  This in-core inode is
		 * still a dirty AIL log item (ili_fields & XFS_ILOG_DDATA), so the
		 * next xfsaild flush hits xfs_iflush_fork's FMT_LOCAL branch and
		 * memcpy(cp, if_data==NULL, if_bytes) → NULL-deref OOPS that KILLS
		 * xfsaild while it holds the inode-cluster buffer lock → the lock
		 * leaks, IFLUSHING never clears, the BAST-release drain wedges, the
		 * peer's EX times out, and cache_coherency SIGKILLs at 900s.
		 * (PROVEN: dmesg memcpy_orig NULL-deref under xfs_iflush_fork ←
		 * xfs_iflush_cluster ← xfs_inode_item_push ← xfsaild; ino=131
		 * incore_mode=00; RDX=6=if_bytes; RSI=0=if_data; no from_disk-FAIL
		 * log because from_disk returned 0.)  Discarding the already-
		 * peer-freed fork is coherency-correct (the peer's free is
		 * authoritative — we just reloaded its committed image).  Reset the
		 * data fork to the canonical empty-EXTENTS state (same as
		 * mxfs_dlm_reset_inode_for_create) so a later flush copies nothing.
		 */
		if (!VFS_I(ip)->i_mode) {
			ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
			ip->i_df.if_data = NULL;
			ip->i_df.if_bytes = 0;
			ip->i_df.if_nextents = 0;
		}
		/*
		 * PROVEN ROOT FIX (instrument step 2b): an in-place reload
		 * that flips the inode TYPE (e.g. a peer freed inode N as a dir
		 * and reused N as a regular file — the rename_visibility Face-A
		 * `cat node1_after_1: Is a directory`) updates i_mode here but
		 * leaves i_op/i_fop/i_mapping->a_ops wired to the OLD type's
		 * operations.  xfs_setup_iops normally re-wires them, but it runs
		 * only on the XFS_INEW iget path (xfs_iget +1342) — this in-place
		 * reload returns a live cache-hit (inew=0), so it never fires.
		 * Result: the in-core inode is REG (P-VNLOOKUP/P-EVICT-RESULT
		 * mode=0100644) yet i_fop == xfs_dir_file_operations (P-DIROPEN
		 * fop_dir=1, same ip pointer) → cat's read hits generic_read_dir
		 * → -EISDIR.  Decisive proof: build 51A6A9DC, ino=131
		 * ip=ffff8e0a99f7cd80 fop_dir=1 inew=0 with final_mode=REG.
		 * FIX: when the reload changes S_IFMT, re-run xfs_setup_iops so
		 * the operation vtables match the new type.  Pure pointer writes,
		 * no I/O/alloc/locking (REG/DIR branches), safe in this context.
		 */
		/*
		 * 0.11.357: skip the rewire when the reload adopted a FREED
		 * image (mode 0) — xfs_setup_iops would route through
		 * init_special_inode(0) and log "bogus i_mode".  A freed
		 * shell has no namespace entry and cluster opens==0 (the
		 * peer only frees at opens==0), so its vtables are never
		 * dereferenced; leave the prior (self-consistent) ops in
		 * place.  If a later reload resurrects the inode, old_ifmt
		 * is captured per-reload, so the S_IFMT change fires the
		 * rewire then.
		 */
		if (VFS_I(ip)->i_mode &&
		    (VFS_I(ip)->i_mode & S_IFMT) != old_ifmt) {
			xfs_setup_iops(ip);
			mxfs_probe_ratelimited(
				"mxfs: P-RELOAD-IOPS-REWIRE ino=%llu old_ifmt=0%o new_mode=0%o\n",
				(unsigned long long)ip->i_ino,
				old_ifmt, VFS_I(ip)->i_mode);
		}
		/*
		 * v0.3.87: xfs_inode_from_disk populates xfs-private
		 * ip fields (i_disk_size, i_nblocks, i_df, etc.) and SOME VFS
		 * fields (i_mode, nlink, uid, gid, atime/mtime/ctime).  But it
		 * does NOT update inode->i_size — that's normally set by
		 * xfs_setup_inode at iget time only.  After a peer modifies
		 * the file size and we reload, our i_disk_size becomes
		 * correct but inode->i_size stays at the prior value.  vfs_read
		 * uses inode->i_size, so cat returns truncated/empty content.
		 *
		 * Sync VFS i_size to the freshly-loaded i_disk_size.  Also
		 * align iversion if v3 inodes (already done in
		 * xfs_inode_from_disk via inode_set_iversion_queried).
		 *
		 * Sess25 reproducer: T1 echo hello > /mnt/shared/foo +
		 * T1 sync; T2 cat /mnt/shared/foo returned empty (size=0).
		 * After this fix, T2 reads correct content.
		 */
		/* P-RELOAD-SIZESEVER (instrumented drc size=0):
		 * adopting a SMALLER disk size while we still have dirty/writeback
		 * pages or delalloc severs the pending append — writeback treats
		 * the pages as beyond-EOF and the eventual setfilesize clamps to
		 * the shrunken VFS i_size (silent no-op).  Detect exactly that. */
		if (S_ISREG(VFS_I(ip)->i_mode) &&
		    ip->i_disk_size < i_size_read(VFS_I(ip)) &&
		    (ip->i_delayed_blks ||
		     mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_DIRTY) ||
		     mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_WRITEBACK))) {
			static atomic_t p_szsev_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p_szsev_n) <= 300)
				mxfs_probe("mxfs: P-RELOAD-SIZESEVER ino=%llu vfs=%llu disk=%llu delayed=%llu dirty=%d wb=%d state=%u ident=%d keep=%d comm=%s\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)i_size_read(VFS_I(ip)),
					(unsigned long long)ip->i_disk_size,
					(unsigned long long)ip->i_delayed_blks,
					mapping_tagged(VFS_I(ip)->i_mapping,
						       PAGECACHE_TAG_DIRTY) ? 1 : 0,
					mapping_tagged(VFS_I(ip)->i_mapping,
						       PAGECACHE_TAG_WRITEBACK) ? 1 : 0,
					ip->i_dlm_state,
					reload_identical ? 1 : 0,
					mxfs_reload_size_keep, current->comm);
		}
		/* FIX (gated for the instrumented A/B): when the reload KEPT the
		 * in-core state (reload_identical — genuine-identical or the P34F
		 * dirty-data skip), i_disk_size was never overwritten from disk, so
		 * it still lags a pending append (setfilesize not yet committed).
		 * Re-syncing VFS i_size down to it severs the append: writeback
		 * discards the now-beyond-EOF dirty pages and the eventual
		 * xfs_setfilesize clamps to the shrunken VFS size (silent no-op)
		 * → durable size=0/nx=0 (drc@32 node5_f1 loss).  The sync
		 * is only needed when we actually ADOPTED a changed disk image. */
		if (!(mxfs_reload_size_keep && reload_identical))
			i_size_write(VFS_I(ip), ip->i_disk_size);

		/* in-core (shortform) fork now reflects the on-disk
		 * image at the current i_dlm_dir_gen.  Record it so a later
		 * cached-EX fast-path can detect a stale fork (gen advanced by
		 * a peer modify via the eviction ring) and reload before RMW. */
		ip->i_dlm_dir_loaded_gen = ip->i_dlm_dir_gen;

		/*
		 * we just adopted the on-disk image wholesale (theirs).
		 * Re-apply OUR pre-reload delta over it via the 3-way merge so a
		 * reload does not REVERT our own committed-not-durable dirents
		 * (the proven write-side resurrection root: a stale reload drops
		 * our entry, the next RMW makes the loss durable / a peer's
		 * removed entry survives).  merge_into captures base = disk
		 * itself.  i_lock is held EXCL here (reload took it).  If the
		 * merge did not run, bootstrap base = the adopted disk image.
		 */
		{
			bool mxfs_merged = false;

			/*
			 * (design-consult consult, PROVEN durable dirent
			 * RESURRECTION root): the 3-way merge re-applies OUR pre-reload
			 * delta (merge_ours vs base) over the adopted disk image so a
			 * reload doesn't drop our committed-not-yet-durable dirents.
			 * That is correct ONLY when we actually HAVE such a delta — i.e.
			 * the inode is DIRTY (uncommitted local dirent changes).  At a
			 * FRESH EX-ACQUIRE after a clean release+drain, the inode is
			 * CLEAN: it has NO valid local delta, and merge_ours is just our
			 * STALE PRIOR-TENURE image (entries the peer has since removed
			 * AND superseded).  Unioning it back RESURRECTS those entries
			 * durably (PROVEN k1: at re-acquire, P-SFDIR-REVERT incore_cnt=3
			 * disk_cnt=1 then merge UNIONs to 2 -> leftover n2_rN).  When
			 * CLEAN, ADOPT the disk image wholesale (disk is authoritative at
			 * the acquisition boundary: the previous EX owner published before
			 * release).  Pairs with the EX-tenure reload suppression in
			 * mxfs_dlm_dir_modify_reload_prelock.
			 */
			/* v0.6.5 (186320ae): ALSO merge when a destage was
			 * TENURE-REFUSED (i_dlm_icd_refused).  The refused change
			 * is committed but absent from disk, and the ili can
			 * ghost-retire clean — "clean => no local delta" is FALSE
			 * and the wholesale adopt would REVERT our committed
			 * rename/rm (PROVEN run 023605Z: test3 SRCDEL n3_r1->
			 * n3_r1.done, refuse, clean reload adopted [n3_r1 ...],
			 * ghost rode to round 50 -> "drained exp=0 got=1"). */
			/*
			 * "clean => no local delta" is FALSE while a
			 * publication obligation is outstanding — that is the
			 * whole reason the obligation counters exist
			 * (committed to the log, ili_fields==0, not in the
			 * AIL).  Without this the merge is skipped for exactly
			 * the inodes whose committed change the adopt is about
			 * to destroy.  Dossier at the snapshot gate above.
			 */
			if (merge_ours && S_ISDIR(VFS_I(ip)->i_mode) &&
			    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
			    ip->i_df.if_data &&
			    (!xfs_inode_clean(ip) || ip->i_dlm_icd_refused ||
			     (mxfs_reload_oblig_merge &&
			      ip->i_mxfs_pub_pending_seq !=
					ip->i_mxfs_pub_durable_seq)))
				mxfs_merged = mxfs_dir_sf_merge_into(ip,
					ip->i_dlm_dir_sf_base,
					(struct xfs_dir2_sf_hdr *)merge_ours,
					(struct xfs_dir2_sf_hdr *)ip->i_df.if_data,
					ip->i_df.if_bytes, &merge_own_dirs);
			/*
			 * The core came wholesale from the platter, so its
			 * di_nlink counts only the children the platter knows
			 * about.  Every subdirectory the merge just re-applied
			 * from our side is a child it does not count; restore
			 * those links or the parent ends up under-counting its
			 * children and later underflows on removal.
			 */
			if (mxfs_merged && merge_own_dirs > 0) {
				uint32_t nl_was = VFS_I(ip)->i_nlink;

				mxfs_set_nlink(ip, nl_was + merge_own_dirs);
				mxfs_probe_ratelimited(
					"mxfs: P183-RELMERGE-NLINK ino=%llu disk_nlink=%u readded_dirs=%d new_nlink=%u — restored links for subdirectories the merge re-applied over the adopted core\n",
					(unsigned long long)ip->i_ino,
					nl_was, merge_own_dirs,
					VFS_I(ip)->i_nlink);
			}
			if (!mxfs_merged &&
			    S_ISDIR(VFS_I(ip)->i_mode) &&
			    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
			    ip->i_df.if_data && ip->i_df.if_bytes > 0)
				mxfs_dir_sf_capture_base(ip, ip->i_df.if_data,
							 ip->i_df.if_bytes);
			/* DECISIVE PROBE (instrumented): after the reload adopts disk
			 * + optionally re-applies our delta, did the merge RESURRECT a
			 * peer-removed entry (post_cnt > disk_cnt)?  Logs merged/clean
			 * inputs so the timeline shows whether a DIRTY reload re-unioned
			 * a stale prior-tenure dirent (the tds leftover root). */
			if (S_ISDIR(VFS_I(ip)->i_mode) &&
			    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
			    ip->i_df.if_data && dip &&
			    dip->di_format == XFS_DINODE_FMT_LOCAL) {
				struct xfs_inode_log_item *m_iip = ip->i_itemp;
				uint8_t post_cnt = ((struct xfs_dir2_sf_hdr *)
					ip->i_df.if_data)->count;
				uint8_t disk_cnt = ((struct xfs_dir2_sf_hdr *)
					((char *)dip +
					 xfs_dinode_size(dip->di_version)))->count;
				char dnames[128];
				/* also log the PRE-RELOAD (ours) view.
				 * The fence n4_14 leak resurrects at the point
				 * a clean-adopt replaces a post-removal local
				 * fork with pre-removal disk: that shows here
				 * as ours_cnt < post_cnt (adopt RESTORED an
				 * entry we had removed) or ours_cnt > post_cnt
				 * (adopt DROPPED our committed add). */
				uint8_t ours_cnt = 255;
				char onames[128];

				onames[0] = '\0';
				if (merge_ours) {
					struct xfs_dir2_sf_hdr *osf =
						(struct xfs_dir2_sf_hdr *)merge_ours;
					struct xfs_dir2_sf_entry *oe =
						xfs_dir2_sf_firstentry(osf);
					int opos = 0, ok2;

					ours_cnt = osf->count;
					for (ok2 = 0; ok2 < osf->count &&
					     opos < (int)sizeof(onames) - 14; ok2++) {
						opos += scnprintf(onames + opos,
							sizeof(onames) - opos,
							"%.*s ",
							min_t(int, oe->namelen, 12),
							oe->name);
						oe = (void *)oe +
							xfs_dir2_sf_entsize(mp, osf,
								oe->namelen);
					}
				}

				mxfs_sf_disk_names(mp, dip, dnames, sizeof(dnames));
				mxfs_probe_ratelimited(
					"mxfs: P56-RELOAD-MERGE ino=%llu merged=%d clean=%d in_ail=%d ili=0x%x pin=%d post_cnt=%u disk_cnt=%u ours_cnt=%u resurrect=%d disk=[%s] ours=[%s]\n",
					(unsigned long long)ip->i_ino,
					mxfs_merged ? 1 : 0,
					xfs_inode_clean(ip) ? 1 : 0,
					(m_iip && test_bit(XFS_LI_IN_AIL,
						&m_iip->ili_item.li_flags)) ? 1 : 0,
					m_iip ? m_iip->ili_fields : 0,
					atomic_read(&ip->i_pincount),
					post_cnt, disk_cnt, ours_cnt,
					(post_cnt > disk_cnt) ? 1 : 0, dnames,
					onames);
			}
			kfree(merge_ours);
			merge_ours = NULL;
		}

		mxfs_idbg(
			"mxfs: DLM reload OK ino=%llu new_fmt=%u if_data=%px "
			"vfs_size=%lld",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			ip->i_df.if_data,
			(long long)i_size_read(VFS_I(ip)));

		/*
		 *  (P191) — DID THE ACQUIRE ACTUALLY
		 * CATCH UP?
		 *
		 * Every stale publish must be preceded by an acquire that left
		 * this node's in-core image behind the platter — that is the
		 * one precondition the whole defect family shares.  P186 asks
		 * the question at the publish, but it can only compare against
		 * a value THIS node happened to observe, so a node that never
		 * saw the newer image publishes a revert invisibly (the blind
		 * spot the design-consult review named).  Asking it here closes that:
		 * `dip` IS the platter, we have just finished deciding what to
		 * do with it, and a same-incarnation in-core link count still
		 * below it means the reload declined to catch up.
		 *
		 * `identical=` names the culprit: 1 means some guard set
		 * reload_identical (P3 changecount, P34F self-ahead/dirty-data,
		 * P184 obligation, or a genuine no-change verdict) and we kept
		 * our fork; 0 means the adopt ran and still came out behind,
		 * which would be a from_disk/merge defect instead.
		 *
		 * Free: no I/O, no lock, one comparison on a path that already
		 * holds both images, and nothing added to the release drain.
		 */
		if (S_ISDIR(VFS_I(ip)->i_mode) && dip &&
		    be16_to_cpu(dip->di_mode) != 0 &&
		    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
		    VFS_I(ip)->i_nlink < be32_to_cpu(dip->di_nlink)) {
			static atomic_t p191n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p191n) <= 8000)
				mxfs_probe("mxfs: P191-POSTRELOAD-BEHIND ino=%llu incore_nlink=%u disk_nlink=%u incore_chg=%llu disk_chg=%llu incore_fmt=%d disk_fmt=%d incore_sz=%lld disk_sz=%llu identical=%d pending=%llu durable=%llu dlm_mode=%u comm=%s realns=%llu — reload finished with the in-core image STILL behind the platter\n",
					(unsigned long long)ip->i_ino,
					VFS_I(ip)->i_nlink,
					be32_to_cpu(dip->di_nlink),
					(unsigned long long)inode_peek_iversion(VFS_I(ip)),
					(unsigned long long)be64_to_cpu(dip->di_changecount),
					ip->i_df.if_format, dip->di_format,
					(long long)ip->i_disk_size,
					(unsigned long long)be64_to_cpu(dip->di_size),
					reload_identical ? 1 : 0,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					ip->i_dlm_mode, current->comm,
					(unsigned long long)ktime_get_real_ns());
		}

		/* ALWAYS-ON lost-update detector: dump ALL shortform
		 * dirent names read from disk at each EX-acquire reload, so a
		 * cross-node timeline shows exactly where a peer's just-committed
		 * entry disappears (concurrent shortform-dir lost-update).
		 * run14d: gated mxfs.dirwr/mxfs.instr for ship. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_data) {
			struct xfs_dir2_sf_hdr *sfh = ip->i_df.if_data;
			struct xfs_dir2_sf_entry *e =
				xfs_dir2_sf_firstentry(sfh);
			char names[200];
			int  pos = 0, k;

			names[0] = '\0';
			for (k = 0; k < sfh->count && pos < (int)sizeof(names) - 12; k++) {
				int nl = min_t(int, e->namelen, 10);
				pos += scnprintf(names + pos, sizeof(names) - pos,
						 "%.*s ", nl, e->name);
				e = (void *)e +
				    xfs_dir2_sf_entsize(mp, sfh, e->namelen);
			}
			mxfs_pal_log(MXFS_LOG_DEBUG,
				"mxfs: P-SFDIR-RELOAD ino=%llu count=%u names=[%s] size=%lld realns=%llu",
				(unsigned long long)ip->i_ino, sfh->count, names,
				(long long)ip->i_disk_size,
				(unsigned long long)ktime_get_real_ns());
		} else if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			   S_ISDIR(VFS_I(ip)->i_mode)) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				"mxfs: P-SFDIR-RELOAD ino=%llu fmt=%u (NOT-LOCAL) size=%lld nx=%llu nlink=%u realns=%llu",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format,
				(long long)ip->i_disk_size,
				(unsigned long long)ip->i_df.if_nextents,
				VFS_I(ip)->i_nlink,
				(unsigned long long)ktime_get_real_ns());
		}

		/* Post-reload P6-INSTR: log what's actually in the dir now */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    ip->i_df.if_data && ip->i_disk_size > 6) {
			struct xfs_dir2_sf_hdr *sfh = ip->i_df.if_data;
			struct xfs_dir2_sf_entry *sfe =
				xfs_dir2_sf_firstentry(sfh);
			char name[32];
			int len = min_t(int, sfe->namelen, 31);

			memcpy(name, sfe->name, len);
			name[len] = '\0';
			mxfs_idbg(
				"mxfs: P6-INSTR reload-post ino=%llu "
				"mem_entries=%u first_entry=\"%s\" "
				"mem_size=%lld",
				(unsigned long long)ip->i_ino,
				sfh->count, name,
				(long long)ip->i_disk_size);
		}

		/* (instrumented): did this adopt SHRINK the dir data fork or
		 * adopt a DIFFERENT incarnation?  If so, the prior (larger)
		 * incarnation's leaf/data blocks at daddrs no longer in the new
		 * map are now orphaned-stale and the per-extent-map evict below
		 * cannot reach them -> leaf-vs-data tear.  Flag the owner-based
		 * evict (run after the map-walk so it catches exactly the
		 * orphans).  Dirs only; the common same-size/same-incarn reload
		 * pays nothing. */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ((long long)ip->i_disk_size < p68_old_size ||
		     (uint64_t)ip->i_df.if_nextents < p68_old_nx ||
		     VFS_I(ip)->i_generation != p68_old_incarn))
			p68_owner_evict = true;

		/*
		 * Option B (design review contract item 2) — INSTALL-COMPLETE STAMP.
		 * The adopt (or identical/P3 keep decision) is final: from_disk,
		 * type re-wiring and the shortform union-merge have all run, so
		 * the in-core base now IS the state the pre-read (epoch, gen)
		 * pair describes.  Stamp the baseline as one released unit.  The
		 * pre-read values are used deliberately: anything that moved
		 * mid-reload leaves the stamp behind, and the next authorization
		 * re-adopts (conservative direction — never claims coherence
		 * with state the installed base predates).  TCP keeps the
		 * monotonic-epoch guard (mirrors can transiently read 0 —
		 * /P44; a lower stamp would force spurious adopts).
		 * Knob-off arm: the pre-fix epoch/incarn stamp, minus the
		 * missing-braces bug this rework removed (see the commit-point
		 * comment above).
		 */
		if (!b_stamped_early && S_ISDIR(VFS_I(ip)->i_mode) &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			bool scaw = mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm);
			uint32_t sep = dir_grant_epoch;

			if (!scaw && ip->i_dlm_dir_valid_epoch > sep)
				sep = ip->i_dlm_dir_valid_epoch;
			if (mxfs_dir_adopt_at_acquire)
				mxfs_dir_base_stamp(ip, sep, dir_grant_gen_pre,
						    3);
			else if (scaw ?
				 (dir_grant_epoch != ip->i_dlm_dir_valid_epoch) :
				 (dir_grant_epoch > ip->i_dlm_dir_valid_epoch)) {
				ip->i_dlm_dir_valid_epoch = dir_grant_epoch;
				ip->i_dlm_dir_valid_incarn =
					VFS_I(ip)->i_generation;
			}
		}
	}
	}

	/* snapshot consumed by xfs_inode_from_disk; release it.  dip
	 * pointed at it, so don't dereference dip past this point. */
	if (snap) {
		kfree(snap);
		snap = NULL;
		dip = NULL;
	}

	/*
	 * Invalidate cached directory data blocks.  The inode cluster
	 * buffer was staled above, so the inode itself is re-read.
	 * But directory data blocks (block/leaf/node format) are
	 * separate buffers at different disk addresses.  If the other
	 * node modified the directory, our cached copy is stale.
	 * Read the in-core extent tree directly (it was just loaded by
	 * xfs_inode_from_disk) — simpler than xfs_bmapi_read and avoids
	 * the xfs_iread_extents path for BTREE-format inodes.
	 */
	/* P-H13b-INSTR: log directory format at reload time so we can
	 * tell whether the bug fires under LOCAL (inline) or EXTENTS format. */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		mxfs_idbg(
			"mxfs: P-H13b-INSTR ACQ-RELOAD-FMT ino=%llu fmt=%u disk_size=%lld",
			(unsigned long long)ip->i_ino,
			ip->i_df.if_format,
			(long long)ip->i_disk_size);
	}

	/*
	 * ROOT FIX (instrumented, PROVEN by signature 1 — `ir.loaded !=
	 * if_nextents` at xfs_bmap.c:1286 in lazy xfs_iread_extents, on the
	 * shared BTREE-format storm dir ino=131): the reload above destroyed the
	 * in-core iext tree (xfs_idestroy_fork) and adopted a fresh dinode (=bmbt
	 * ROOT, di_nextents=N), but NEVER invalidated this node's CACHED bmbt LEAF
	 * blocks.  For a BTREE fork, from_disk does NOT load the leaves
	 * (need_iread stays true), and the dir-DATA invalidation walk below
	 * iterates an EMPTY iext tree (zero extents) — so a stale cached leaf
	 * (N-1 records from before the peer's grow) survives.  The next
	 * xfs_iread_extents walks the fresh root into that stale leaf ->
	 * ir.loaded(N-1) != if_nextents(N) -> EFSCORRUPTED -> shutdown -> the
	 * whole-storm cascade (the zero_silent_loss count).  None of the reload
	 * CALLERS reliably evict bmbt blocks first (site 1510 evicts only DATA
	 * blocks), so do it HERE, inside every reload, so the lazy extent read
	 * always cold-fetches the peer's coherent leaves.  No-op for non-BTREE
	 * forks; leaves this node's own dirty/in-AIL/pinned leaves untouched
	 * (idiom).
	 *
	 * D-0973: for every BTREE data fork, not only a directory's.  A regular
	 * file's stale leaf survived this reload when it was directory-only:
	 * two nodes extending one sparse file with direct writes, one node's
	 * extent loads read its own pre-reload 15-record leaf against the
	 * peer's di_nextents (3620 of 3635 writes failed EFSCORRUPTED), and its
	 * inode flushes destaged that leaf over the peer's committed one while
	 * publishing the peer's count — a torn on-disk pair after each of its
	 * releases.  Nothing in either helper is specific to directories.
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    (S_ISDIR(VFS_I(ip)->i_mode) || mxfs_reload_evict_file_bmbt)) {
		mxfs_dir_evict_bmbt_blocks(ip);
		/* walk-miss-proof follow-up — evict the
		 * adopted root's children by exact daddr (see helper). */
		mxfs_dir_evict_bmbt_by_root(ip);
	}

	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format != XFS_DINODE_FMT_LOCAL) {
		struct xfs_bmbt_irec	irec;
		struct xfs_iext_cursor	icur;
		struct xfs_ifork	*ifp = &ip->i_df;

		/*
		 * H18 fix: walk ALL dir extents (not just first), and
		 * for each, walk dir blocks within the extent (each dir_block
		 * is mp->m_dir_geo->fsbcount FSBs).  Old code looked up bufs
		 * with XFS_FSB_TO_BB(mp, 1) = 1 FSB-worth of BBs, but the
		 * actual cached buf size is XFS_FSB_TO_BB(mp,
		 * mp->m_dir_geo->fsbcount).  Mismatch → xfs_buf_incore returns
		 * NULL → stale never fires → cached buf retains stale entries.
		 *
		 * H17 evidence: count BEFORE drop_caches=98, AFTER=100.  The
		 * dir3 buf in test1's cache had 98 entries, disk had 100;
		 * cache wasn't being invalidated on reload.  This walk fixes it.
		 */
		{
			unsigned int dir_blk_bb =
				XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);
			struct xfs_iext_cursor	icur2;
			struct xfs_bmbt_irec	got2;
			unsigned int		n_staled_h18 = 0;
			unsigned int		n_miss_h18 = 0;   /* not in cache */
			unsigned int		n_locked_h18 = 0; /* locked -> skipped */
			unsigned int		n_blocks_h18 = 0; /* total dir blocks walked */

			for_each_xfs_iext(ifp, &icur2, &got2) {
				xfs_daddr_t	d_start, d_end, d;

				if (got2.br_startblock == HOLESTARTBLOCK)
					continue;
				d_start = XFS_FSB_TO_DADDR(mp, got2.br_startblock);
				d_end = d_start +
					XFS_FSB_TO_BB(mp, got2.br_blockcount);
				for (d = d_start;
				     d + dir_blk_bb <= d_end;
				     d += dir_blk_bb) {
					struct xfs_buf	*dbp = NULL;
					n_blocks_h18++;
					if (xfs_buf_incore(mp->m_ddev_targp, d,
							   dir_blk_bb, 0,
							   &dbp) != 0 || !dbp) {
						/* not cached -> next read goes to disk
						 * naturally (no stale concern). */
						n_miss_h18++;
						continue;
					}
					/*
					 * trylock-skip: blocking xfs_buf_lock
					 * DEADLOCKS (lock inversion) and bounded-retry+msleep
					 * here regressed correctness (20/20).  Keep trylock;
					 * locked dir bufs stay cached — the residual block-dir
					 * Mode A acquire-side staleness (next session).  The
					 * n_locked_h18 / n_miss_h18 counts (gated) pin which
					 * failure mode dominates so the fix can target it.
					 */
					/*
					 * trylock-skip: blocking xfs_buf_lock DEADLOCKS
					 * even under the no-pin line-801 structure (sess37
					 * re-tested: repro hung) — a real lock inversion, not
					 * just independent I/O.  Bounded-retry+msleep also
					 * regressed.  Keep trylock; locked dir bufs stay
					 * cached = the residual block-dir Mode A staleness
					 * (P-H18 shows locked_skip=1 always).  Next: NOT a
					 * reload-time invalidation — use a read-time/lazy
					 * gen-counter FUA re-read, or release-side writeback
					 * drain so the buf isn't mid-write at acquire.
					 */
					/* FIX-15b: in this kernel
					 * xfs_buf_incore(flags=0) BLOCKING-locks the
					 * found buffer (get_map/find_lock), so the
					 * old `xfs_buf_trylock(dbp)` here was a
					 * SELF-trylock that always failed — the
					 * inline-stale arm was DEAD CODE and every
					 * cached block silently took the deferred
					 * stale_pending path (whose honor point then
					 * raced the first readdir = the rank1
					 * stale-serve).  We already HOLD the lock:
					 * decide inline.  FIX-11: never discard an
					 * UNDESTAGED buffer (committed dirents whose
					 * only copy is in-core — platter cannot be
					 * ahead of it under Invariant-1).  Use the
					 * DONE-clear form, NOT xfs_buf_stale (ghost/
					 * duplicate cache entry when an AIL BLI still
					 * refs the buffer — note). */
					if (mxfs_dir_buf_is_undestaged(dbp)) {
						mxfs_probe_ratelimited("mxfs: P5C-ACQSTALE-KEPT ino=%llu d=%llu lseq=%u wseq=%u pin=%d — undestaged, acquire-reload stale skipped\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)d,
							dbp->b_mxfs_logged_seq,
							dbp->b_mxfs_written_seq,
							atomic_read(&dbp->b_pin_count));
					} else {
						dbp->b_flags &= ~(XBF_DONE |
								  _XBF_FUA_FRESH);
						dbp->b_mxfs_dir_gen = 0;
						spin_lock(&dbp->b_lock);
						dbp->b_mxfs_stale_pending = false;
						spin_unlock(&dbp->b_lock);
						n_staled_h18++;
					}
					xfs_buf_relse(dbp);
				}
			}
			if (n_blocks_h18)
				mxfs_idbg("mxfs: P-H18-INSTR ACQ-RELOAD-STALE ino=%llu blocks=%u staled=%u locked_skip=%u miss=%u dir_blk_bb=%u\n",
					(unsigned long long)ip->i_ino,
					n_blocks_h18, n_staled_h18, n_locked_h18,
					n_miss_h18, dir_blk_bb);
		}

		/*
		 * P-H13-INSTR: read the on-disk dir3 buf NOW via direct
		 * SCSI READ(16) FUA, capturing the magic + first 8 bytes.  This
		 * is what the acquiring node sees on disk before any cached
		 * blocks come into play.  If this is missing peer's recently-
		 * committed entries, that's the leak point.
		 *
		 * gate the whole diagnostic behind mxfs.instr — it does
		 * a per-dir-reload FUA disk read + page alloc + 4KB scan, which
		 * is pure instrumentation cost on the lock hot path.
		 */
		if (mxfs_instr_enabled &&
		    xfs_iext_lookup_extent(ip, ifp, 0, &icur, &irec) &&
		    irec.br_startblock != HOLESTARTBLOCK) {
			void *page = (void *)__get_free_page(GFP_KERNEL);
			if (page) {
				/*
				 * FIX: XFS daddrs are relative to the XFS
				 * data region, which sits at bt_sector_offset on
				 * the underlying /dev/sda (the MXFS envelope places
				 * XFS at offset 100704256 = 196688 sectors).  The
				 * production read path (mxfs_buf_read_fua, xfs_log)
				 * adds bt_sector_offset; this diagnostic previously
				 * did NOT, so it read the journal/envelope region
				 * (zeros) and reported magic=0x0 — an ARTIFACT that
				 * misled /35 into a "disk reads zeros" theory.
				 * Add the offset so P-H16 reads the real dir block.
				 */
				uint64_t lba = (uint64_t)
					XFS_FSB_TO_DADDR(mp, irec.br_startblock)
					+ mp->m_ddev_targp->bt_sector_offset;
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *bdev,
					uint64_t lba_512,
					void *buf, uint32_t len);
				int rrc = mxfs_pal_scsi_read_fua_bdev(
					mp->m_ddev_targp->bt_bdev,
					lba, page, 4096);
				if (rrc == 0) {
					unsigned char *p = page;
					uint32_t magic =
						((uint32_t)p[0] << 24) |
						((uint32_t)p[1] << 16) |
						((uint32_t)p[2] << 8) |
						(uint32_t)p[3];
					/* P-H16-INSTR: scan the 4KB block for
					 * "node2_dir" substrings and log matches.  If
					 * disk has node2_dir1..50, we should find them
					 * all.  If a name is missing from disk → write
					 * bug.  If on disk but not visible → read/cache
					 * bug. */
					int j;
					int found_count = 0;
					int has_dir1 = 0, has_dir2 = 0;
					/* Generic dir-entry probe: count "modea_"
					 * substrings (repro_modea names) so we can
					 * tell whether the peer's just-committed dirent
					 * is on the disk home block at acquire time. */
					int modea_count = 0;
					for (j = 0; j < 4096 - 10; j++) {
						if (p[j]=='m' && p[j+1]=='o' &&
						    p[j+2]=='d' && p[j+3]=='e' &&
						    p[j+4]=='a' && p[j+5]=='_')
							modea_count++;
						if (p[j]=='n' && p[j+1]=='o' &&
						    p[j+2]=='d' && p[j+3]=='e' &&
						    p[j+4]=='2' && p[j+5]=='_' &&
						    p[j+6]=='d' && p[j+7]=='i' &&
						    p[j+8]=='r') {
							found_count++;
							if (p[j+9]=='1' && (p[j+10]<'0' || p[j+10]>'9'))
								has_dir1 = 1;
							if (p[j+9]=='2' && (p[j+10]<'0' || p[j+10]>'9'))
								has_dir2 = 1;
						}
					}
					mxfs_pal_log(MXFS_LOG_DEBUG,
						"mxfs: P-H16-INSTR ACQ-DISK-DIR3 ino=%llu lba=%llu magic=0x%x modea_count=%d found_node2=%d has_dir1=%d has_dir2=%d realns=%llu",
						(unsigned long long)ip->i_ino,
						(unsigned long long)lba,
						magic, modea_count, found_count, has_dir1, has_dir2,
						(unsigned long long)ktime_get_real_ns());
				}
				free_page((unsigned long)page);
			}
		}
	}

	/*
	 * (instrumented): the per-extent-map evict above only reaches daddrs
	 * the NEW (just-adopted) map names.  When this reload SHRANK the dir
	 * (P33-FROMDISK-DIRSHRINK) or adopted a DIFFERENT incarnation, the prior
	 * incarnation's leaf/data blocks at daddrs no longer mapped survive
	 * cached + stale and tear leaf-vs-data on the next lookup.  Drop them by
	 * OWNER so the next read cold-FUA-fetches the coherent image.  Only on
	 * the flagged rare reload (owner-walk is O(whole cache)). */
	if (p68_owner_evict)
		mxfs_dir_evict_owned_dir_blocks(ip, false);	/* shrink/incarnation: full evict */

	/*
	 * v0.3.88: invalidate VFS dcache for directory inodes.
	 * Sess25 confirmed Mode A (`xfs_dir_removename rc=-ENOENT`) at
	 * 15×256 iter-2: T2's reload picks up disk_size=6 (empty dir)
	 * but VFS dcache still has the previous entries (T2's prior
	 * "perf_t2"); rm hits dcache, iget(132), calls
	 * xfs_dir_removename(dp=128, "perf_t2"), dir is empty on disk →
	 * ENOENT.
	 *
	 * Drop all child dentries of this dir so the next lookup
	 * revalidates against the freshly-reloaded dir content.
	 *
	 * ccloop-4dd7 ROOT FIX (b55r3 pid 84017, live self-deadlock):
	 * this block MUST run AFTER the cluster buffer relse + up_write
	 * below, NOT here.  shrink_dcache_parent kills unused child
	 * dentries; a killed dentry holding the LAST reference iputs the
	 * child → evict → xfs_inode_mark_reclaimable → SYNCHRONOUS
	 * xfs_inactive (multinode policy, xfs_icache.c) — a full truncate/
	 * ifree with its own transactions — from INSIDE this reload.  The
	 * child shares the dir's inode cluster (small AGs: dir 131 +
	 * children all in the daddr-128 cluster), so its
	 * xfs_inode_item_precommit re-locks the cluster buffer THIS
	 * function still holds locked (bp, relse'd only at the tail) →
	 * b_sema self-deadlock.  Waiters convoy behind the parent i_rwsem
	 * (this kernel's do_rmdir dputs before inode_unlock), the dir sits
	 * in ISTATE_ACQUIRING forever, every peer BAST defers to an
	 * acquire-completion that never comes, and the peer's rmdir dies
	 * -110 with a dirty tx → cluster shutdown (the b54r1 184s family —
	 * same stack, root only visible once P-BUFLOCK-STUCK named the
	 * holder).  The in-transaction defer guard in
	 * xfs_inode_mark_reclaimable does not cover this context
	 * (journal_info is NULL during lookup revalidation).  The dir arm
	 * now runs at the function tail after both releases; the
	 * dcache/pagecache work needs neither ILOCK nor the buffer.  (The
	 * S_ISREG arm below stays here: invalidate_mapping_pages is
	 * non-blocking and cannot evict inodes.)
	 */
	if (S_ISREG(VFS_I(ip)->i_mode)) {
		/*
		 * FIX (di_size empty-content cross-node read): this reload
		 * just refreshed the regular file's metadata (di_size + extent
		 * map) from disk, but the DATA PAGE CACHE was NOT dropped — so a
		 * read served from a stale cached page returns the inode-number's
		 * PRIOR-lifecycle content (zeros after reuse) → `cat` of a peer's
		 * renamed file yields '' (rename_visibility / cross_write_read
		 * "Content preserved ... actual='').  P104+P105 proved the
		 * fail is a stale DATA PAGE (di_size>0, extent present, page-cache
		 * HIT so no iomap/disk read), NOT metadata.  Drop the data pages
		 * here so the next read re-fetches the owner's committed content
		 * from disk.  Only fires on a real cross-node reload, so no hot-path
		 * cost.
		 *
		 * DEADLOCK FIX (16-node cross_write_read wedge): the original
		 * invalidate_inode_pages2() does a BLOCKING folio_lock on every folio
		 * of the mapping.  This reload can be entered DEEP in the buffered-read
		 * path — xfs_file_buffered_read -> iomap_readahead -> read_pages (which
		 * has ALREADY allocated and LOCKED the readahead folios of THIS mapping)
		 * -> xfs_read_iomap_begin -> xfs_ilock -> mxfs_dlm_ilock_begin -> here
		 * (when a peer's EX BAST set i_dlm_stale after the top-of-read envelope
		 * already ran).  invalidate_inode_pages2 then blocks in folio_wait_bit
		 * trying to lock a folio THIS SAME TASK holds -> permanent self-deadlock
		 * (node14 md5sum hung 122s+, folio_wait_bit_common under
		 * invalidate_inode_pages2_range, dmesg P23-SLOWPATH stale=1).
		 *
		 * Use invalidate_mapping_pages() instead: it is NON-BLOCKING
		 * (folio_trylock) and SKIPS folios that are locked / dirty / under
		 * writeback.  The readahead folios the caller holds are trylock-skipped
		 * (no deadlock) AND they are being filled fresh from the disk extent the
		 * iomap just returned, so correctness holds.  Pre-existing CLEAN stale
		 * pages (the target) are unlocked and get dropped, so the next
		 * read re-fetches the owner's committed content.  Dirty local pages are
		 * skipped (never dropped) -> no data loss.
		 */
		invalidate_mapping_pages(VFS_I(ip)->i_mapping, 0, -1);
	}

	/*
	 * A COMPLETED reload.  If this inode carries a race-bail stamp, this is
	 * the retry that bail's comment promised — so account it and clear the
	 * stamp.  total - resolved is then the count of bails that nothing ever
	 * followed up on.  See the mxfs_rb_* declarations.
	 */
	if (ip->i_mxfs_racebail_ns) {
		u64 age_us = (ktime_get_ns() - ip->i_mxfs_racebail_ns) / 1000ULL;
		long long prev_max;

		atomic64_inc(&mxfs_rb_resolved);
		atomic64_add((long long)age_us, &mxfs_rb_sum_us);
		for (;;) {
			prev_max = atomic64_read(&mxfs_rb_max_us);
			if ((long long)age_us <= prev_max)
				break;
			if (atomic64_cmpxchg(&mxfs_rb_max_us, prev_max,
					     (long long)age_us) == prev_max)
				break;
		}
		ip->i_mxfs_racebail_ns = 0;
	}
	/* A real reload happened, so the skip streak is broken (see
	 * i_dlm_p6skip_n in xfs_inode.h). */
	ip->i_dlm_p6skip_n = 0;
	ip->i_dlm_stale = false;

	up_write(&ip->i_lock);

	xfs_buf_relse(bp);

	/*
	 * v0.3.88 dir dcache invalidation, relocated here (ccloop-4dd7
	 * ROOT FIX — see the comment at its old site above the
	 * S_ISREG arm): shrink_dcache_parent can iput the last reference
	 * on child inodes and run their SYNCHRONOUS inactivation right
	 * here, so it must not run while this function still holds the
	 * dir's inode-cluster buffer locked (the child shares that
	 * cluster; its precommit re-locks it → b_sema self-deadlock, the
	 * b54r1/b55r3 node-convoy + peer -110 shutdown).  After the
	 * relse/up_write above the child inactivation completes normally.
	 * Ordering is safe: the reloaded dir content is already published
	 * (i_dlm_stale cleared) and lookups revalidate via
	 * mxfs_drevalidate epochs; the shrink is cache hygiene, not a
	 * coherency fence.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		struct dentry *de = d_find_alias(VFS_I(ip));

		if (de) {
			shrink_dcache_parent(de);
			dput(de);
			mxfs_idbg(
				"mxfs: P41-INSTR ino=%llu dcache drained",
				(unsigned long long)ip->i_ino);
		}
		/* H19: drop the dir inode's page cache too.  XFS dir
		 * data normally lives in xfs_buf cache, but readdir / find
		 * iteration may also be affected by stale page-cache state.
		 * H17 drop_caches at the test level fixed the bug; this call
		 * is the equivalent at reload time for the specific dir. */
		invalidate_inode_pages2(VFS_I(ip)->i_mapping);
	}
}

void
mxfs_dlm_reset_inode_for_create(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct inode		*inode = VFS_I(ip);

	down_write(&ip->i_lock);
	mxfs_ilk_note_lock(ip, XFS_ILOCK_EXCL, _THIS_IP_);	/* attribute raw down_write */

	/*
	 *  instrumented hypothesis for the fence_during_write
	 * fdw-MISS data mismatch found at 16/caw (durable, does NOT heal via
	 * drop_caches -- ruling out a plain page-cache-staleness artifact
	 * fixable by a clean re-read).  This function resets EVERY XFS-level
	 * field (forks, mode, nlink, size, nblocks, diflags) for reuse by a
	 * brand-new file -- but this struct got here via the "NOT
	 * IRECLAIMABLE" cache-hit branch (xfs_iget_cache_hit), meaning it is
	 * STILL FULLY VFS-LIVE and has NEVER been through generic evict().
	 * Every OTHER inode-reuse path in the kernel (xfs_iget_recycle for
	 * IRECLAIMABLE structs, or a fresh xfs_inode_alloc after a clean
	 * __xfs_inode_free) gets its page cache cleared for free, because
	 * xfs_fs_evict_inode() unconditionally calls
	 * truncate_inode_pages_final() BEFORE the struct can ever become
	 * IRECLAIMABLE or be returned to the slab.  THIS path skips evict()
	 * entirely (that's its whole point -- avoid a disk re-read), so any
	 * page this node's PRIOR incarnation of this ino left behind in
	 * inode->i_mapping (dirty or clean) is silently still there when the
	 * new file is created here.  The new file's writes only dirty the
	 * pages they actually touch -- any stale page at an offset the new
	 * content never rewrites (a likely outcome for repeatedly-resized
	 * files like fence_during_write's fixed 40-file rotation) survives
	 * and can be read back, or win a writeback race, as if it were valid
	 * new content.  Diagnostic below records nrpages found at reset time
	 * (direct proof of the mechanism if nonzero); truncate_inode_pages()
	 * (not the non-blocking invalidate_mapping_pages() used elsewhere in
	 * this file for a same-thread self-deadlock-prone read path) is
	 * correct and safe HERE specifically because: (a) this struct is
	 * IRECLAIMABLE-excluded but i_count-idle -- no live fd/mmap holder
	 * can be racing a write into these pages (the prior incarnation's
	 * last closer already dropped to i_count==0, which is a precondition
	 * of reaching this "reset for reuse" branch at all); (b) we explicitly
	 * WANT dirty pages dropped too, not skipped -- they belong to a dead
	 * incarnation and must never reach disk under the new identity.
	 */
	{
		unsigned long nrpages = inode->i_mapping->nrpages;

		if (unlikely(nrpages)) {
			static atomic_t p143_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p143_n) <= 200)
				mxfs_probe("mxfs: P143-RESET-STALE-PAGES ino=0x%llx nrpages=%lu — dropping stale page cache from a prior incarnation before reuse\n",
					(unsigned long long)ip->i_ino, nrpages);
		}
		truncate_inode_pages(inode->i_mapping, 0);
	}

	xfs_idestroy_fork(&ip->i_df);
	/*
	 * (D-0535, chain 115 s473b on 0.64.22): xfs_idestroy_fork frees
	 * if_data but leaves if_bytes/if_format behind.  A shell whose PRIOR
	 * incarnation carried a shortform attr fork and was freed by a PEER
	 * (this node's xfs_ifree — the only upstream path that drops an attr
	 * fork in place, via xfs_ifork_zap_attr — never ran) arrived here with
	 * i_af.if_bytes=32 still set; the new incarnation's first attr add
	 * (the dirshard locator) then grew the fork FROM that phantom length
	 * (xfs_attr_shortform_create ASSERTs if_bytes==0, compiled out), the
	 * header said 32 bytes while the fork claimed more, and the release
	 * drain's flush verifier shut the creator down ('Metadata corruption
	 * detected at xfs_attr_shortform_verify ... attr fork').  Measure the
	 * inherited state, then ZAP the fork exactly as xfs_ifree does.
	 */
	if (ip->i_af.if_bytes || ip->i_af.if_data ||
	    ip->i_af.if_format == XFS_DINODE_FMT_LOCAL) {
		static atomic_t p_rstaf_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_rstaf_n) <= 400)
			mxfs_probe("mxfs: P-RESET-STALE-AF ino=%llu forkoff=%u af_format=%d af_bytes=%lld af_data=%d af_nextents=%llu — prior incarnation's attr fork state inherited at reuse; zapping\n",
				(unsigned long long)ip->i_ino,
				(unsigned)ip->i_forkoff, (int)ip->i_af.if_format,
				(long long)ip->i_af.if_bytes,
				ip->i_af.if_data ? 1 : 0,
				(unsigned long long)ip->i_af.if_nextents);
	}
	xfs_ifork_zap_attr(ip);
	if (ip->i_cowfp) {
		xfs_idestroy_fork(ip->i_cowfp);
		kmem_cache_free(xfs_ifork_cache, ip->i_cowfp);
		ip->i_cowfp = NULL;
	}

	inode->i_mode = 0;
	/* s_remove_count skew ledger — see P9-NLEDGE. */
	{
		static atomic_t p9rst_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p9rst_n) <= 4000)
			mxfs_probe("mxfs: P9-NLEDGE reset4create ino=%llu old=%u rmcnt=%ld acct=%d comm=%s\n",
				(unsigned long long)ip->i_ino, inode->i_nlink,
				atomic_long_read(&inode->i_sb->s_remove_count),
				xfs_iflags_test(ip, MXFS_IF_RMC_ACCT) ? 1 : 0,
				current->comm);
	}
	mxfs_set_nlink(ip, 0);
	ip->i_disk_size = 0;
	ip->i_nblocks = 0;
	ip->i_diflags = 0;
	ip->i_diflags2 = mp->m_ino_geo.new_diflags2;
	ip->i_forkoff = 0;
	ip->i_extsize = 0;
	if (xfs_has_v3inodes(mp))
		ip->i_cowextsize = 0;

	ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
	ip->i_df.if_data = NULL;
	ip->i_df.if_bytes = 0;
	ip->i_df.if_nextents = 0;

	/*
	 * ccloop-4dd7 GENERATION CONVERGE (instrumented evidence: P-CR62 disk_di_gen
	 * = incore+1 for every reused ino; ino 680 showed multi-cycle DRIFT of
	 * 8 figures between in-core and platter gens): this reset runs because
	 * a PEER (or a prior local life) freed the ino — the freed on-disk
	 * image carries the authoritative generation.  Destaging the new
	 * incarnation with a lower/unrelated gen REGRESSES the on-disk
	 * generation and blinds every gen-ordered staleness guard
	 * (P-RECYCLE-GATE, P116 zombie arm).  Adopt the platter gen when
	 * readable (sleeping context: we hold only i_lock write); fall back
	 * to a +1 bump.
	 */
	{
		uint32_t r4c_gen = 0;
		bool r4c_ok = false;

		if (mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev &&
		    ip->i_imap.im_len) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint32_t cl = BBTOB(ip->i_imap.im_len);
			void *ct = ((cl & 511) == 0 && cl) ?
				kmalloc(cl, GFP_NOFS) : NULL;

			if (ct && mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev,
				(uint64_t)ip->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset,
				ct, cl) == 0) {
				struct xfs_dinode *cd =
					(struct xfs_dinode *)((char *)ct +
					ip->i_imap.im_boffset);

				if (cd->di_magic ==
				    cpu_to_be16(XFS_DINODE_MAGIC)) {
					r4c_gen = be32_to_cpu(cd->di_gen);
					r4c_ok = true;
				}
			}
			kfree(ct);
		}
		VFS_I(ip)->i_generation = r4c_ok ? r4c_gen :
			VFS_I(ip)->i_generation + 1;
	}

	/*
	 * ccloop-4dd7: the local-unlink intent belongs to the PRIOR life —
	 * a leaked flag makes the next inactivation guard treat a stale
	 * copy as "rightfully ours to free" (the leak).  New life,
	 * clean slate.
	 */
	xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK | MXFS_IF_ADOPTED_UNLINK);

	/*
	 * Option B: NEW INCARNATION — the dir-base coherence baseline
	 * belongs to the prior life (xfs_inode.h's "reset at inode init/reuse"
	 * was only ever implemented for fresh slab allocs; recycled structs
	 * leaked the quadruple, which is why a reused dir with a leaked
	 * valid_epoch != 0 also SKIPPED the creator publish stamp).  Gated so
	 * the knob-off arm keeps the historical lifecycle for the A/B.
	 */
	if (mxfs_dir_adopt_at_acquire) {
		ip->i_dlm_dir_valid_epoch = 0;
		ip->i_dlm_dir_valid_incarn = 0;
		WRITE_ONCE(ip->i_dlm_base_valid, 0);
		ip->i_dlm_creator_base_state = MXFS_CBASE_UNSET;
	}

	ip->i_dlm_stale = false;

	up_write(&ip->i_lock);
}

/*
 * ROBUST shortform-dir coherency.  The shared LUN is a single-host LIO
 * fileio backstore over one coherent host page cache, so a plain disk read is
 * GROUND TRUTH across both nodes.  On a cached-EX fast-path modify of a SHARED
 * shortform dir, our in-core fork can be STALE if our cached i_dlm_mode==EX
 * outlived its actual DLM grant and a peer modified the dir — the mutual-
 * exclusion gap that neither the dg_shadow EX-EX detector nor the leaky
 * i_dlm_dir_gen/loaded_gen tracking can see (a peer modify while we cache EX
 * does NOT bump OUR gen; loaded_gen also lags whenever a reload bails).
 *
 * Defence that does not depend on the gen mechanism: if THIS inode's in-core
 * fork is CLEAN (no logged-not-checkpointed mods of our own to lose) and its
 * bytes differ from the coherent on-disk shortform image (same incarnation),
 * adopt disk via a reload before the RMW.  Clean ⇒ our committed state is
 * already durable on disk ⇒ disk is a superset ⇒ no loss.  Skipped for self-
 * created (peer-unreachable) dirs so the solo-rsync metadata path pays nothing.
 * Caller holds NO spinlock (post spin_unlock) and not ip->i_lock.
 */
/* Find a name in a shortform-dir image; returns the entry or NULL. */
struct xfs_dir2_sf_entry *
mxfs_sf_find(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *h,
	     const uint8_t *name, int namelen)
{
	struct xfs_dir2_sf_entry *e = xfs_dir2_sf_firstentry(h);
	int i;

	for (i = 0; i < h->count; i++) {
		if (e->namelen == namelen &&
		    memcmp(e->name, name, namelen) == 0)
			return e;
		e = xfs_dir2_sf_nextentry(mp, h, e);
	}
	return NULL;
}

/*
 * require the ACTUAL on-disk inode grant before honouring the
 * RELFLUSH publication token on a logged directory slot at NL.  Dossier at the
 * consuming site (pal/linux/xfs_buf.c, the P56-NL-LOGGED-DIR-SKIP branch):
 * the token was measured set while the grant was already gone (held=0), and
 * those writes are the ones that revert peers' committed dirents.
 */
int mxfs_reload_oblig_keep = 1;	/* default ON */
module_param_named(reload_oblig_keep, mxfs_reload_oblig_keep, int, 0644);
MODULE_PARM_DESC(reload_oblig_keep,
		 "A reload must not adopt the platter over a committed change that "
		 "has not reached its home location: keep the fork and stay stale "
		 "(1=on default)");
int mxfs_reload_oblig_merge = 1;	/* default ON */
module_param_named(reload_oblig_merge, mxfs_reload_oblig_merge, int, 0644);
MODULE_PARM_DESC(reload_oblig_merge,
		 "Let a reload 3-way-merge (instead of wholesale adopt) while a "
		 "publication obligation is outstanding, and restore the links of "
		 "the subdirectories it re-applies (1=on default)");
module_param_named(read_attr_probe, mxfs_read_attr_probe, int, 0644);
MODULE_PARM_DESC(read_attr_probe,
	"sess5: attribute cold (bio-issued) reads by class at the submit chokepoint; periodic dmesg + ratelimited stack for inode-real reads. 0=off");

/*
 * READ-STORM FIX (GFS2/design review prior-owner design,
 * DEFAULT-OFF pending coherency validation): in mxfs_dlm_reload_inode, the
 * inode-cluster stale+FUA-re-read (xfs_mxfs_dlm.c ~14417) assumes "a peer wrote
 * this inode".  For a reused inode this node freed+re-allocated ITSELF (the
 * dlm_scaling private-subdir create/rm loop; any single-writer inode), NO peer
 * held the EX grant since our last handoff, so the on-disk image cannot differ
 * from in-core — the stale + cache-bypassing FUA re-read is pure waste and, at
 * 32-node concurrency, saturates the shared iSCSI target (the read storm).
 * When on, skip the reload stale iff mxfs_v5_dlm_inode_grant_handoff reports NO
 * cross-node EX handoff since our acted gen (peer-reuse still stales → coherent).
 * MUST validate cache_coherency/strong_consistency/dir_reuse @4 and @16 before
 * defaulting on. 0=off (baseline: always stale).
 */
module_param_named(reload_skip_owned, mxfs_reload_skip_owned, int, 0644);
MODULE_PARM_DESC(reload_skip_owned,
	"sess5: skip reload_inode cluster-stale+FUA-reread when no cross-node EX handoff (self-reused inode, in-core authoritative). 0=off");

/*
 *  ROOT FIX for D-DIRENT-INODE-TYPE-MISMATCH.  The
 * RELOAD-TYPEFLIP-STALE-SKIP guard kept the in-core inode whenever
 * disk_gen <= incore_gen, but XFS generations are RANDOM, so on a genuine
 * inode-number reuse that comparison is a coin flip -- and when it came up
 * wrong the node kept a DEAD incarnation and its release drain published that
 * corpse over the peer's live inode.  1 = require the SAME incarnation
 * (disk_gen == incore_gen), which is what the guard's own documented target
 * case has; 0 = legacy <=, as a same-build negative control.
 */
int mxfs_typeflip_skip_same_incarn = 1;
EXPORT_SYMBOL(mxfs_typeflip_skip_same_incarn);
module_param_named(typeflip_skip_same_incarn, mxfs_typeflip_skip_same_incarn, int, 0644);
MODULE_PARM_DESC(typeflip_skip_same_incarn,
	"RELOAD-TYPEFLIP-STALE-SKIP requires disk_gen == incore_gen (same "
	"incarnation) before keeping the in-core inode over the platter.  "
	"1=on (default, correct), 0=legacy disk_gen <= incore_gen.");
