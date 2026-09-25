/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS -- private declarations shared by the files of the XFS-side DLM layer
 *
 * The includes, macros, types and cross-file declarations of the files that
 * implement the XFS side of MXFS cluster coordination (xfs_mxfs_*.c).  Each of
 * those files defines MXFS_TU_ID before including this header; it names the
 * file in the igrab/iput call-site records.  See docs/xfs-dlm-layout.md for
 * what each file holds.  Nothing outside those files includes this header;
 * the interface the rest of MXFS uses is xfs_mxfs_dlm.h.
 */
#ifndef __XFS_MXFS_DLM_PRIV_H__
#define __XFS_MXFS_DLM_PRIV_H__

/* this file's code site, decoded by MXFS_SITE_ARGS (xfs_mxfs_dlm.h) */
#define MXFS_SITE	(((unsigned int)MXFS_TU_ID << 16) | __LINE__)

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>	/* no-inode BAST dedup set */
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/iversion.h>	/* inode_peek_iversion (di_changecount epoch) */
#include <linux/sched/debug.h>	/* sched_show_task (stuck AG-holder dump) */
#include <linux/debugfs.h>	/* RECOVERY_BLOCKED_FENCE surface */
#include <linux/seq_file.h>

#include "xfs_platform.h"
#include "../pal/pal.h"	/* mxfs_pal_io_budget_* */
#include "../dlm/v5_mount.h"
#include "../dlm/disklock.h"	/* MXFS_EVICT_TYPE_* */
#include "../dlm/scsipr.h"	/* mxfs_fence_kind_name */
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_cksum.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_ag.h"
#include "xfs_btree.h"		/* 0.89.10: the alloc_witness_chunk inobt lookup */
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_log.h"
#include "xfs_inode_fork.h"
#include "xfs_inode_buf.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_inode_item.h"
#include "xfs_buf.h"
#include "xfs_buf_item.h"
#include "xfs_extfree_item.h"
#include "xfs_bit.h"
#include "../mxfs_clayer/yield_quantum.h"
#include "../mxfs_clayer/pinned_resource.h"
#include "xfs_dir2.h"
#include "libxfs/xfs_trans_space.h"
#include "libxfs/xfs_ialloc.h"	/* xfs_ialloc_read_agi (statfs perag sums) */
#include "libxfs/xfs_ialloc_btree.h"	/* XFS_INOBT_BLOCK_LEN (P-AGIFC release audit) */
#include "libxfs/xfs_inode_util.h"	/* xfs_iunlink (orphan adoption) */
#include "xfs_iwalk.h"		/* xfs_inobt_walk (orphan scan) */
#include "libxfs/xfs_dir2_priv.h"
#include "libxfs/xfs_da_format.h"
#include "libxfs/xfs_da_btree.h"
#include "libxfs/xfs_bmap.h"
#include "libxfs/xfs_bmap_btree.h"
#include "libxfs/xfs_defer.h"	/* trans-roll AG-grant migration walks
				 * t_dfops pendings (xfs_defer_pending + the
				 * defer_op_type externs) */
extern int mxfs_pub_defer_claim;	/* defined near the publish batch */
struct mxfs_release_cert;	/* defined in xfs_mxfs_dlm.h, included below */
#include "libxfs/xfs_alloc.h"	/* xfs_extent_free_item */
#include "libxfs/xfs_rmap.h"	/* xfs_rmap_intent */
#include "libxfs/xfs_refcount.h"	/* xfs_refcount_intent */
#include "xfs_log_priv.h"
#include "xfs_aops.h"	/* FIX-25: xfs_task_in_ioend */
#include "xfs_relmark_item.h"	/* clean-release marker on EX release */
#include "xfs_mxfs_dlm.h"

/*
 * (D-UNMOUNT-BUSY-INODES): attribute every igrab in this file to its
 * source line, so the reference that survives unmount can be named instead of
 * bisected.  See mxfs_igrab_tracked() in xfs_inode.h.
 */
#define igrab(vi) mxfs_igrab_tracked((vi), __LINE__, MXFS_TU_ID)
#define iput(vi) mxfs_iput_tracked((vi), __LINE__, MXFS_TU_ID)
/* the dead-holder budget: a frozen AG is a wait of milliseconds per extent */
#define MXFS_OBLF_WAIT_BUDGET_MS	120000u
/* 0.23.0: dialloc try-reserve counters live in libxfs/xfs_ialloc.c */
extern atomic64_t mxfs_resv_stat_try, mxfs_resv_stat_ok, mxfs_resv_stat_contended,
	mxfs_resv_stat_cool, mxfs_resv_stat_err, mxfs_resv_stat_exhaust,
	mxfs_resv_stat_recadv, mxfs_resv_stat_sweeps, mxfs_resv_stat_backoff_ms,
	mxfs_resv_stat_demand, mxfs_resv_stat_probe_ns, mxfs_resv_stat_probe_max_ns,
	mxfs_resv_stat_grow;

/*
 * — per-inode DLM transition ring for the watched inode.
 * Records EVERY i_dlm_mode / i_dlm_state assignment in this file (old->new,
 * source line, pid/comm, wall ns) when ip->i_ino == mxfs_watch_ino.  The r7
 * round-2 double-grant (two nodes in EX modify of the same dir block 80us
 * apart, same freespace slot -> durable one-name loss) is invisible to the
 * sampled P70/P71 probes: the grant-path transitions are silent in CACHED /
 * ACQUIRING states.  Dumped by mxfs_dlmtr_dump() from mxfs_dirdump (the drc
 * .mxfs_dirdump1 trigger) so the failing round's complete local lock history
 * is in the snapshot.  Lock-free ring; recording is a no-op unless watched.
 */
/*  a864 P72 stuck-DEMOTING orphan strike threshold before the
 * orphan-reclaim overrides a non-NULL i_dlm_demoter (a stuck inline bast_process).
 * ~31 waiters re-BAST ~1/s each while wedged, so 16 sustained swallows (~0.5s) is
 * a proven wedge — well past any transient live inline drain (clears demoter in
 * 1-2 BASTs) — yet far under the 360s wedge-cascade timeout. */
#define MXFS_P72_ORPHAN_STRIKES 16

/* every i_dlm_demoter claim stamps WHO/WHERE/WHEN so
 * a leaked demoter (set, task returned without clearing — the 25-min all-node
 * dir convoy on 12583041) is attributable from the P126/P72 swallow probes. */
/*
 * (D-BAST-IRELE-INACTIVE-SELF-WEDGE): record every demoter claim/clear
 * into the per-inode ring so a wedge can name WHICH source line, on WHICH
 * task, erased the claim the wedged thread was relying on.  See the ring's
 * declaration in xfs_inode.h for why a snapshot cannot answer that.
 */
extern int mxfs_demoter_legacy_clobber;
extern int mxfs_bast_irele_unclaim_inject;
extern int mxfs_bast_qfalse_inject;	/* P226 branch-coverage injector */
extern int mxfs_teardown_arm_gate;	/* D-DWORK-TEARDOWN-LASTREF fix gate */
extern int mxfs_rel_stale_inject;	/* teardown-strand injector (A/B) */
extern int mxfs_p6_midtenure_skip;
extern unsigned int mxfs_p6_honor_src_mask;
extern unsigned int mxfs_open_tracking;
extern int mxfs_evict_retain_pr;	/* clean-PR retention across evict */
/*
 * H4 instruments for the P6 mid-tenure skip (D-SILENT-MKDIR-LOSS lead).
 *
 * mxfs_p6_src_hist[src] — which i_dlm_stale_src's staleness this skip is
 * clearing.  The skip's premise ("dirtied under the current EX tenure, so the
 * platter has nothing to teach us") is only sound for staleness WE caused; if
 * the dominant sources are peer-driven (a peer BAST / publication), the skip is
 * discarding a peer's notification. mxfs.p6_epoch_override already honours
 * src==3 for exactly this reason — this says which OTHER sources need the same
 * treatment, and it is read straight off the counters rather than requiring a
 * losing window to be caught and scoped.
 *
 * mxfs_p6_repeat_ge8 — skips on an inode already skipped >=8 times with no real
 * reload in between: the staleness-livelock signature.
 */
#define MXFS_P6_SRC_N	32

#define MXFS_SET_DEMOTER(ip)						\
	do {								\
		struct task_struct *prev;				\
									\
		if (unlikely(mxfs_demoter_legacy_clobber)) {		\
			/* A/B ONLY: the pre-fix behaviour, an	\
			 * unconditional store that overwrites a live	\
			 * foreign claim.  Exists so the defects this	\
			 * caused can be re-armed on ONE build and	\
			 * measured against the fix.  NEVER ship on. */	\
			if ((ip)->i_dlm_demoter &&			\
			    (ip)->i_dlm_demoter != current) {		\
				/* The injected fault actually landed on a	\
				 * live foreign claim.  Record the victim so	\
				 * the demote-wait can report the precondition	\
				 * instead of us inferring it. */		\
				atomic64_inc(&mxfs_dem_legacy_steal);		\
				/* stamped scalar, not a deref of a	\
				 * reference-less task_struct* that dangles	\
				 * once the holder exits. */			\
				(ip)->i_dlm_clobber_victim_pid =		\
					(ip)->i_dlm_demoter_pid;		\
				(ip)->i_dlm_clobber_victim_line =		\
					(ip)->i_dlm_demoter_line;		\
			}							\
			(ip)->i_dlm_demoter = current;			\
			(ip)->i_dlm_demoter_depth = 1;			\
			(ip)->i_dlm_demoter_pid = current->pid;		\
			(ip)->i_dlm_demoter_line = MXFS_SITE;		\
			(ip)->i_dlm_demoter_set_ns = ktime_get_ns();	\
			mxfs_demev_rec((ip), 0, MXFS_SITE);		\
			break;						\
		}							\
		prev = cmpxchg(&(ip)->i_dlm_demoter, NULL, current);	\
									\
		if (prev == NULL || prev == current) {			\
			if (prev == NULL) {				\
				(ip)->i_dlm_demoter_depth = 1;		\
				atomic64_inc(&mxfs_dem_slot1);		\
			} else {					\
				(ip)->i_dlm_demoter_depth++;		\
				atomic64_inc(&mxfs_dem_slot1_nest);	\
			}						\
			(ip)->i_dlm_demoter_pid = current->pid;		\
			strscpy((ip)->i_dlm_demoter_comm, current->comm,\
				sizeof((ip)->i_dlm_demoter_comm));	\
			(ip)->i_dlm_demoter_set_ns = ktime_get_ns();	\
			(ip)->i_dlm_demoter_line = MXFS_SITE;		\
			mxfs_demev_rec((ip), 0, MXFS_SITE);		\
		} else if (cmpxchg(&(ip)->i_dlm_demoter2, NULL, current)	\
			   == NULL) {					\
			(ip)->i_dlm_demoter2_depth = 1;			\
			/* slot 2 had NO forensics, so a strand	\
			 * here reported slot 1's stale stamps.  Stamp it \
			 * identically. */				\
			(ip)->i_dlm_demoter2_pid = current->pid;	\
			strscpy((ip)->i_dlm_demoter2_comm, current->comm,\
				sizeof((ip)->i_dlm_demoter2_comm));	\
			(ip)->i_dlm_demoter2_set_ns = ktime_get_ns();	\
			(ip)->i_dlm_demoter2_line = MXFS_SITE;		\
			atomic64_inc(&mxfs_dem_slot2);			\
			mxfs_demev_rec((ip), 0, MXFS_SITE);		\
		} else if ((ip)->i_dlm_demoter2 == current) {		\
			(ip)->i_dlm_demoter2_depth++;			\
			(ip)->i_dlm_demoter2_pid = current->pid;	\
			strscpy((ip)->i_dlm_demoter2_comm, current->comm,\
				sizeof((ip)->i_dlm_demoter2_comm));	\
			(ip)->i_dlm_demoter2_set_ns = ktime_get_ns();	\
			(ip)->i_dlm_demoter2_line = MXFS_SITE;		\
			atomic64_inc(&mxfs_dem_slot2_nest);		\
			mxfs_demev_rec((ip), 0, MXFS_SITE);		\
		} else {						\
			static atomic_t p74n = ATOMIC_INIT(0);		\
									\
			atomic64_inc(&mxfs_dem_contest);		\
			mxfs_demev_rec((ip), 3, MXFS_SITE);		\
			if (atomic_inc_return(&p74n) <= 2000)		\
				pr_warn("mxfs: P74-DEMOTER-CONTEST ino=%llu holder_pid=%d holder_comm=%s holder_line=%u:%u age_ms=%llu me=%d comm=%s — concurrent release drain on one inode; claim NOT stolen (see D-BAST-IRELE-INACTIVE-SELF-WEDGE)\n", \
					(unsigned long long)(ip)->i_ino,\
					(ip)->i_dlm_demoter_pid,	\
					(ip)->i_dlm_demoter_comm,	\
					MXFS_SITE_ARGS((ip)->i_dlm_demoter_line), \
					(ip)->i_dlm_demoter_set_ns ?	\
					  (ktime_get_ns() -		\
					   (ip)->i_dlm_demoter_set_ns)	\
					  / 1000000ULL : 0,		\
					current->pid, current->comm);	\
		}							\
	} while (0)

/*
 * Only the owner releases, and only the outermost nesting level clears the
 * slot.  A non-owner's clear is recorded and ignored — that is precisely the
 * event that produced the wedge, so it stays visible rather than silent.
 */
#define MXFS_CLEAR_DEMOTER(ip)						\
	do {								\
		if (unlikely(mxfs_demoter_legacy_clobber)) {		\
			if ((ip)->i_dlm_demoter &&			\
			    (ip)->i_dlm_demoter != current)		\
				atomic64_inc(&mxfs_dem_legacy_clear_live); \
			mxfs_demev_rec((ip), 1, MXFS_SITE);		\
			(ip)->i_dlm_demoter = NULL;			\
			break;						\
		}							\
		if ((ip)->i_dlm_demoter == current) {			\
			if ((ip)->i_dlm_demoter_depth > 1) {		\
				(ip)->i_dlm_demoter_depth--;		\
				mxfs_demev_rec((ip), 4, MXFS_SITE);	\
			} else {					\
				(ip)->i_dlm_demoter_depth = 0;		\
				mxfs_demev_rec((ip), 1, MXFS_SITE);	\
				smp_store_release(&(ip)->i_dlm_demoter,	\
						  NULL);		\
			}						\
		} else if ((ip)->i_dlm_demoter2 == current) {		\
			if ((ip)->i_dlm_demoter2_depth > 1) {		\
				(ip)->i_dlm_demoter2_depth--;		\
				mxfs_demev_rec((ip), 4, MXFS_SITE);	\
			} else {					\
				(ip)->i_dlm_demoter2_depth = 0;		\
				mxfs_demev_rec((ip), 1, MXFS_SITE);	\
				smp_store_release(&(ip)->i_dlm_demoter2,\
						  NULL);		\
			}						\
		} else if (!(ip)->i_dlm_demoter && !(ip)->i_dlm_demoter2) {	\
			/* Nobody is draining this inode — a plain field reset	\
			 * (the DLM-state initializer).  Cannot strand anyone.	\
			 * Counted separately so foreign_clear stays a real	\
			 * assertion. */					\
			atomic64_inc(&mxfs_dem_clear_noclaim);			\
		} else {						\
			static atomic_t p76n = ATOMIC_INIT(0);		\
									\
			atomic64_inc(&mxfs_dem_foreign_clear);		\
			mxfs_demev_rec((ip), 5, MXFS_SITE);		\
			/* A clear by a task owning NEITHER slot.  Under the	\
			 * pre-fix macro this NULLed the slot outright — the	\
			 * clobber that stranded the owner's trailing irele.	\
			 * It is now ignored, but the RATE and the CALL SITE	\
			 * decide whether that is a benign unpaired defensive	\
			 * clear or a real cross-path collision, so name both	\
			 * rather than only counting. */			\
			/* print the STAMPED scalar, never		\
			 * (ip)->i_dlm_demoter->pid.  Both slots are bare	\
			 * task_struct pointers held WITHOUT a reference, so	\
			 * they dangle the moment the holder exits — which is	\
			 * exactly the state a stranded claim leaves behind	\
			 * (proven: demoter_pid gone from /proc while the claim	\
			 * was still set).  This deref was a live		\
			 * use-after-free read on a shipped path. */		\
			if (atomic_inc_return(&p76n) <= 400)			\
				pr_warn("mxfs: P76-DEMOTER-FOREIGN-CLEAR ino=%llu line=%u:%u me=%d comm=%s slot1_pid=%d slot1_set=%d slot2_set=%d — clear by non-owner; ignored\n", \
					(unsigned long long)(ip)->i_ino,	\
					MXFS_SITE_ARGS(MXFS_SITE), current->pid, current->comm, \
					(ip)->i_dlm_demoter_pid,		\
					!!(ip)->i_dlm_demoter,			\
					!!(ip)->i_dlm_demoter2);		\
		}							\
	} while (0)

#define MXFS_DLMTR_N 1024
struct mxfs_dlmtr_ent {
	u64	ns;
	u64	ino;
	u32	line;
	u32	pid;
	u8	om, nm, os, nst;
	u8	exh, prh;	/* P125 hunt: holder counts AFTER the event */
	char	comm[12];
};
extern unsigned long long mxfs_watch_ino;

/* P125 hunt (2026-07-25): record a HOLDER-COUNT event in the same ring —
 * the inc/dec sites mostly don't change mode/state, so without this the
 * ring can't show which begin lacked its end. */
#define MXFS_DLMTR_H(ip) \
	mxfs_dlmtr_rec((ip), (ip)->i_dlm_mode, (ip)->i_dlm_state, MXFS_SITE)

/* Forward declarations */
extern int mxfs_reg_release_durable;	/* defined below, used above */

/*
 * are ALL of this directory's DATA-fork block buffers durable on
 * disk?  A dir block buffer that still carries a dirty buffer-log-item, a
 * nonzero pin count (changes still in the CIL), a delwri-queue flag, or has
 * not completed its write (no XBF_DONE) has not reached the platter.
 * Releasing the dir inode's DLM lock while any dir block is non-durable lets
 * a peer FUA-read stale or torn dir content — the missing-dirent and
 * EFSBADCRC ("error 74") shutdowns seen under concurrent same-dir rename.
 *
 * The existing release-path drain loop only guarantees the DINODE itself is
 * clean (it breaks on the inode's in-AIL/pin state) and only pushes the
 * inode's own AG; a dir DATA block that xfsaild has not yet written — or one
 * allocated from a different AG — slips through.  This predicate lets the
 * caller keep draining until the dir's data blocks are genuinely durable.
 *
 * Caller must hold ip->i_lock (read) so the extent list is stable.
 * EXTENTS format only: LOCAL dirs live in the dinode (covered by the dinode
 * flush); BTREE-format dirs need xfs_iread_extents which can issue I/O, so
 * we conservatively report "durable" and fall back to the AG-AIL drain.
 */
/*
 * (instrumented): take ip->i_lock for read in the BAST drain WITHOUT
 * silently wedging the worker forever.  The 16-node create storm wedged
 * here (down_read blocked behind a queued writer on an i_lock with NO
 * live holder = leaked ILOCK; cluster then starved on our unreleased EX
 * bit until 120s-timeout force-shutdowns).  Keep waiting (correctness:
 * the drain must check/flush under i_lock) but after 5s dump the
 * last-locker forensics so the leaking call path is named, and re-log
 * every 30s.  Returns false only on FS shutdown (caller bails).
 */
/*
 * run74: BOUNDED.  The unbounded wait turned one corrupted
 * rwsem (P3B relsafe-without-hold reader underflow) into a 400s+ live cluster
 * convoy: the release worker spun here forever, so the dir EX was never
 * released and every peer EIO'd out.  All callers sit in the release /
 * durability pipeline where the designed degrade for "cannot drain" is
 * SHUTDOWN (Invariant 1: never unlock stale; fence + journal replay frees the
 * lock for peers).  After 180s (beyond the 120s CAW-poll worst-case legit
 * hold + margin) force shutdown and return false — callers already treat
 * false as "FS shut down", and now it is.
 */
#define MXFS_DRAIN_ILOCK_MAX_MS	180000

/* Deferred AG DLM unlock queue entry (definition hoisted from the
 * mxfs_ag_dlm_unlock_deferred section so early code can enumerate a
 * transaction's held-AG set). */
struct mxfs_pending_ag_unlock {
	struct list_head	list;
	struct xfs_perag	*pag;
};

extern uint32_t mxfs_dir3_data_fingerprint(struct xfs_mount *mp,
					   const void *addr,
					   uint32_t len, bool is_block,
					   uint32_t *fp_sum, uint32_t *fp_xor);
extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *, uint64_t,
					 void *, uint32_t);

extern int mxfs_dir_release_invalidate;	/* defined below (module_param) */
extern int mxfs_dir_relinval_clean;	/* defined below (module_param) */
extern int mxfs_dir_release_flush_all_done;	/* defined below */
extern int mxfs_dir_release_flush_leaf;		/* defined below */
extern int mxfs_dir_release_fua_write;	/* defined below (module_param) */
extern int mxfs_dir_tenure_evict;	/* defined below (module_param) */
extern int mxfs_pal_scsi_write_fua_bdev(struct block_device *, uint64_t,
					const void *, uint32_t);

/*
 * (D-0491) instrumented instrument: count this directory's cached data-fork
 * blocks that still carry committed content the LUN has not seen — undestaged
 * (logged_seq != written_seq or pinned) or still attached to a log item in the
 * AIL.  Caller holds ip->i_lock (read or write); nothing here sleeps on a
 * buffer lock (XBF_TRYLOCK; a block that is locked by someone else is counted
 * in *locked and not inspected).  Extent-format and extent-loaded btree-format
 * directories only; a directory whose extents are not in core reports -1.
 * Diagnostic only: no state changes.
 */
struct mxfs_dir_undest_census {
	int		undest;		/* undestaged cached blocks */
	int		inail;		/* blocks whose log item is in the AIL */
	int		locked;		/* cached but lock contended: not inspected */
	int		cached;		/* cached blocks inspected */
	xfs_daddr_t	first_daddr;	/* first undestaged block seen */
	uint64_t	first_lseq;
	uint64_t	first_wseq;
	int		first_has_bli;
	int		first_done;
};
#define MXFS_VERIFY_SITE_INC(v) WRITE_ONCE(v, READ_ONCE(v) + 1)

#define MXFS_REMSET_INVALID	0xFFFFFFFFu

/*
 * enumerate every cached metadata buffer OWNED by
 * dir ip — dir3 data/block/leaf/free, da3 node, and data-fork bmbt blocks —
 * via the per-AG buffer-cache walk (the mxfs_dir_bmbt_scan pattern).  The
 * extent-map snapshot the eviction fences used is impossible for a
 * BTREE-format dir (enumerating blocks via the bmbt trusts the very cache
 * being invalidated), so both fences silently bailed the moment the shared
 * storm dir grew past EXTENTS — every node then RMW'd dir blocks on stale
 * bases (PROVEN: DIR-STALE-SKIP buf_gen=0 inode_gen=365 with P-ACQ-DRAIN-*
 * and P-EVICT-* all 0x; quiet dirent loss + cluster-wide "corrupt dinode
 * 131 (btree extents)" both downstream).  Returns the number of buffers
 * collected, each with a hold taken; caller releases each via
 * xfs_buf_rele/xfs_buf_relse.  Sets *overflow if the cap truncated.
 */
#define MXFS_DIR_OWNED_MAX	64

struct mxfs_merge_ent {
	uint64_t	inum;
	uint8_t		ftype;
	uint8_t		namelen;
	unsigned char	name[255];
};

/*
 * (instrumented, PROVEN ROOT — dir logical-block0 DOUBLE-ALLOCATION):
 * dir_reuse_coherency 4/tcp durably loses exactly node1_f1 (rank1's FIRST
 * file), missing even on rank1 itself.  Mechanism: rank1 creates node1_f1
 * (shortform), converts sf->block allocating block0@daddr=120 (with node1_f1);
 * concurrently a peer converts ITS OWN stale shortform base (that never saw
 * node1_f1) to block0 in a different AG — the peer's extent map wins on disk.
 * rank1's NEXT create then post-release re-acquires and ADOPTS the peer's
 * winning block0 (which lacks node1_f1), dropping node1_f1 from rank1's
 * in-core dir.  node1_f2..f50 are added to the peer's block0 and survive;
 * node1_f1, created before the adopt, is orphaned in daddr=120 (not referenced
 * by the winning extent map) and lost forever.  The "post_release => disk is a
 * strict superset of our entries" invariant is FALSE here because the peer's
 * competing block0 allocation orphaned ours.  merge_ours only re-applies our
 * entries across a SHORTFORM<->SHORTFORM adopt, so it cannot restore node1_f1
 * across the SHORTFORM/BLOCK->BLOCK adopt.
 *
 * FIX (design review, additive replay — no extra DLM acquire, no orphan
 * free): track every dirent THIS node creates in this dir incarnation in a
 * small per-inode pending list; on every subsequent create, replay (re-add)
 * any pending name that is no longer resolvable in the (possibly just-adopted)
 * dir, using the create's OWN transaction + already-held dir EX grant.  This
 * re-adds node1_f1 into the winning block0 during node1_f2's create.  Replay
 * adds only the dirent (the child inode keeps its nlink from the original
 * create — the adopt replaced the dir fork, it never touched the child), is
 * idempotent (skips names already present), and is cleared on a parent
 * incarnation change (rm-rf+recreate) so a dead incarnation's names are never
 * resurrected.
 */
#define MXFS_PEND_NAME_MAX	40
#define MXFS_PEND_MAX_ENTS	96
/* MXFS_PEND_REPLAY_MAX is defined in xfs_mxfs_dlm.h (shared with xfs_create). */

struct mxfs_pend_ent {
	uint64_t	cino;
	uint32_t	cgen;
	uint8_t		ftype;
	uint8_t		namelen;
	char		name[MXFS_PEND_NAME_MAX];
};

/*
 * ACQUIRE-side DRAIN-then-EVICT (the proven Face B lost-update fix).
 *
 * The eager evict above (mxfs_dir_evict_data_blocks) SKIPS any dir data block
 * that is transiently PINNED — but that skip IS the lost-update window proven
 * by faceb_stress (build 8B1A4AD6): the "winning" node W slow-path acquires the
 * dir EX after peers have durably committed their dirents, yet W's cached dir
 * block (DIR-STALE-SKIP buf_gen=0 inode_gen=1 pin=1 dirty=0 in_ail=0
 * disk_differs=1) could NOT be refreshed because it was pinned by the async
 * CIL-unpin tail of W's OWN already-durable prior work.  The lazy read hook
 * skips it too (cannot clear XBF_DONE on a pinned buffer — corruption),
 * so W applies all its creates onto a STALE block and flushes it over the
 * peers' dirents = lost update.
 *
 * Coherency MUST be enforced at the DLM acquire boundary, not via lazy buffer
 * invalidation (design review).  We just won a fresh EX grant, so the peers'
 * dir is durable on the platter and our cached blocks are unambiguously stale.
 * We may NOT clear XBF_DONE while pinned, so we DRAIN the pin first: a single
 * synchronous log force unpins all of this node's committed-but-unpinned work
 * (which is ALREADY on the platter — these blocks are NOT dirty and NOT in the
 * AIL, only transiently pin-tailed; forcing does not re-write stale content),
 * then a bounded wait lets the async unpin workqueue settle.  Once a block is
 * genuinely clean we evict it so the caller's imminent read is a cache miss
 * that re-reads the peers' merged durable image.
 *
 * SAFETY: we ONLY drain pin-ONLY blocks (pinned && !dirty && !in_ail && DONE).
 * A dirty / in-AIL dir block carries un-written local content whose flush would
 * push it to disk and clobber the peer — those are left to the release-side
 * durability machinery and the lazy hook, exactly as before.
 *
 * To avoid sleeping under ip->i_lock (a writer could starve, and the DLM
 * acquire path is delicate), we snapshot the dir-block daddrs under i_lock,
 * release it, then force/drain/evict on the snapshot.  A dir with more data
 * blocks than the small snapshot array falls back to the non-draining evict
 * for the overflow (block- and small-leaf-format dirs — the contended case —
 * fit easily).
 */
/* 32 -> 64 — a dpn=100 x 16-node storm dir
 * (~1600 entries) runs ~20-30 data+leaf+free blocks plus bmbt children;
 * 32 truncated the sweep. */
#define MXFS_DIR_DRAIN_MAX 64

#define MXFS_CBS_EPOCH		0x1
#define MXFS_CBS_GRANTGEN	0x2

/*  — P192 extent-map predicate re-check after the
 * ILOCK acquire (see mxfs_ilock_map_recheck in xfs_inode.c).  0 = pre-fix
 * behaviour for A/B. */
extern int mxfs_ilock_map_recheck_enabled;

/*
 *  — FENCE-V1 dir-drain task registry (design-consult
 * blueprint, memory entry sess6-D).  The submit-side dir-block write fence in
 * xfs_buf_submit_ex suppresses any dir-metadata write whose owner dir's DLM
 * granted mode is < EX and that carries no log obligation — the proven
 * torn-write producer (sess6-C: 19 stale-image PR writes + 1 post-release NL
 * write interleaved with the real holder's leaf1->node split tore the block
 * on the LUN -> EUCLEAN -> 5/8-node shutdown cascade).  The release drain's
 * own publishes are the ONE sanctioned exception (Invariant 1: no unlock
 * without drain) — but ONLY for an EX-outgoing tenure: a PR tenure cannot
 * have committed dir mutations, so its drain has nothing legal to publish
 * (dir PR releases run the full drain — see skip_pr_drain — and their
 * undest-tracking false positives were exactly the 19 captured PR crime
 * writes).  Sanction is task-scoped like the FIX-26 wptask registry: callers
 * of mxfs_dlm_bast_process bracket the call with a stack entry (mode NL =
 * unsanctioned), and bast_process stamps the outgoing held mode once it is
 * known.  A drain write submitted while the physical grant is still EX never
 * consults this (gmode=EX passes the fence outright); the registry only
 * covers mode-transition tails, so an unbracketed caller fails SAFE.
 */
#define MXFS_DIRDRAIN_HASH_BITS	6

struct mxfs_dirdrain_task {
	struct hlist_node	node;
	struct task_struct	*task;
	uint8_t			mode;	/* outgoing held mode; only EX sanctions */
};

/*
 * — recovery-context task registry (incident474 hole b, design-consult
 * ruling).  Tasks doing victim recovery — foreign-slice replay and the
 * post-recovery cleanup sweeps — register here so the inode DLM acquire
 * path can tell them apart from ordinary threads:
 *
 *   - A recovery-context task whose acquire times out must NEVER escalate
 *     to its own shutdown: in incident474 the elected replayer's sweep
 *     blocked on an EX grant naming a still-unpurged fenced victim (whose
 *     purge was queued BEHIND the blocked sweep), timed out, and shut the
 *     last survivor down — completing the fleet-wide cascade.  It requeues
 *     and retries instead; progress arrives when the recovery machinery
 *     purges the dead holder's grants.
 *
 *   - A task in the REPLAY phase must never take an ordinary inode DLM
 *     lock at all: foreign-slice replay is buffer-level by design, and the
 *     b2 phase split (replay every pending slice before any lock-taking
 *     sweep) is only sound while that stays true.  The acquire path warns
 *     if it ever stops being true.
 */
#define MXFS_RECOV_PHASE_CLEANUP	1
#define MXFS_RECOV_PHASE_REPLAY		2

struct mxfs_recovtask {
	struct hlist_node	node;
	struct task_struct	*task;
	uint8_t			phase;
};

/*
 * FALLIBLE-ACQUIRE CONTEXT.
 *
 * xfs_ilock is void, so the inode-DLM hook it calls cannot hand an error back
 * to the caller, and for most callers that is right: there is no safe way to
 * continue without the cluster-wide grant, and no way to refuse.  A few
 * callers ARE different — they sit at a boundary where nothing is dirty, no
 * transaction is open, and the operation can be failed cleanly all the way
 * back to userspace.  Opening a file is one.
 *
 * Such a caller registers here for the duration of its acquire.  The hook
 * reads the registration to know that giving up is an option, and writes the
 * verdict back into it; the caller checks the verdict immediately after
 * xfs_ilock returns and fails the operation rather than proceeding without a
 * grant.  Nothing about the acquire changes for anyone who has not
 * registered, which is why this cannot quietly widen: a path that has not
 * been audited for a failed acquire never sees one.
 *
 * The verdict travels per TASK rather than on the inode, so two threads
 * acquiring the same inode cannot read each other's outcome.
 */
/*
 * 0.84.2: the registration names the INODE it covers.  A registered task
 * may take other inodes' locks inside the audited call (a cluster-covered
 * inode's routed conversion, a parent), and none of those has been audited
 * for a failed acquire; only the named one may give up, and only the named
 * one's verdict is read.  The verdict cannot be inherited by a later
 * registration on the same stack slot: enter clears it.
 */
struct mxfs_acqfallible {
	struct hlist_node	node;
	struct task_struct	*task;
	u64			ino;	/* the inode, or the AG number when ag */
	bool			ag;	/* 0.84.5: an AG acquire registered as a
				 * boundary (the untrusted iget's AG lock of
				 * an inode the task may already fail) */
	bool			gave_up;
	int			rc;	/* 0.84.5: the errno the give-up names (-EIO
				 * unless the arm that took it said otherwise) */
};

struct mxfs_f4_record {
	struct hlist_node	f4_node;
	uint64_t		f4_ino;		/* owner dir/bmbt ino; 0 = unknown (poison) */
	xfs_daddr_t		f4_daddr;
	unsigned int		f4_length;	/* BBs */
	u64			f4_gen;		/* latest committed gen */
	u8			f4_buffer_gone;	/* orphaned: buffer freed with record open */
	u8			f4_aborted;	/* saw a non-shutdown abort while open */
};

/*
 * step-5 F3 (ruling item A) — keyed inode-cluster write
 * accounting.  One entry per cluster daddr, created at the first counted
 * home-write submit and NEVER freed until unmount: freeing + recreating
 * would restart the generations a spanning release proof compares, so a
 * proof could alias "no writes since capture" with "entry recycled".
 * The release proof (mxfs_iclus_make_durable) waits on the CLUSTER'S OWN
 * inflight and generations only — never a device-wide aggregate.
 */
struct mxfs_icwr_entry {
	struct hlist_node	ie_node;
	xfs_daddr_t		ie_daddr;
	atomic_t		ie_inflight;	/* counted submits not yet completed */
	atomic64_t		ie_submit_gen;	/* bumped at every counted submit */
	atomic64_t		ie_complete_gen;/* bumped at every counted completion (incl. errors: conservative) */
};

struct mxfs_drain_watch {
	struct timer_list	timer;
	int			pid;
	u64			ino;
	u64			t0;
	int			site;
	int			fires;
	bool			armed;
};

/*
 * NO_INODE BAST release offload.  When a peer BASTs an inode
 * we no longer have in-core (reclaimed), the release path does a full
 * xfs_log_force(SYNC) + bounded AG-AIL drain + blkdev_issue_flush before the
 * on-disk DLM unlock (invariant #1 — protect a reclaimed DIR's dirty dir-data).
 * That heavy work used to run INLINE on the per-peer TCP recv thread
 * (peer.c:mxfs_peer_recv_fn dispatches msg_cb synchronously), so under
 * dir_reuse_coherency at 8 nodes — where rank1's rm -rf frees ~800 inodes/round
 * and every peer then reallocates those numbers and BASTs rank1 — the recv
 * thread serialized ~800 log-force+drain+flush sequences, stalling the entire
 * DLM message stream from that peer for ~60 s.  The deferred-publish EX of a
 * reused inode then timed out (rc=-110) and the test's post-create `sync`
 * blocked the full ~60 s/round (the budget rule slowness -> 300 s test-timeout FAIL).
 *
 * The in-core BAST path already runs async on m_mxfs_inode_bast_wq (WQ_UNBOUND,
 * multi-threaded); this offloads the NO_INODE path to the SAME wq so the recv
 * thread stays responsive and the heavy drains run concurrently.  Correctness
 * is unchanged: the drain still completes BEFORE the unlock inside the work fn.
 */
struct mxfs_noino_bast_work {
	struct work_struct	work;
	struct xfs_mount	*mp;
	uint64_t		ino;
	/* mkdir-storm ROOT: tenure anchor captured at BAST
	 * time.  The async release must NOT strip a lock this node
	 * RE-ACQUIRED between BAST arrival and work execution (proven live:
	 * test30's :17 no-inode release executed at :18.43x and cleared the
	 * EX its own mkdir won at :18.429 -> slot free -> test16 granted EX
	 * too -> double sf_to_block conversion -> node29/node30 dirents
	 * durably lost; 15,346 P135-HELD-MISS in one 3-min storm).  The
	 * release uses unlock_gen(rel_gen): -ESTALE = a newer local tenure
	 * owns the resource, skip (the peer re-BASTs the new tenure). */
	uint32_t		rel_gen;
};
struct mxfs_noino_inflight {
	struct hlist_node	hnode;
	struct xfs_mount	*mp;
	uint64_t		ino;
};

/*
 * — PROGRESS-BASED noino release fence.
 *
 * The 20260712T152205Z g1 collapse (posix_multi@32/caw): FIVE nodes hit
 * P-NOINO-RELFENCE-WEDGE within one second of each other and self-shut-
 * down mid-workload.  rank1's 3200-file `ls` fans one BAST per reclaimed
 * file inode to every peer; each peer's release fence gave the whole-AIL
 * push 5 tries x 2s and treated "target not reached in ~10s" as a wedge.
 * At 32 nodes the shared LUN drains one node's AIL at roughly 1/32 of
 * device bandwidth — the AIL was ADVANCING (test19 rode out repeated
 * try=4 storms un-wedged; the fleet calmed once the ls storm passed),
 * just slower than the patience.  Shutting down on SLOW converts a
 * transient convoy into simultaneous multi-node withdrawal; peers then
 * trip over the withdrawn nodes' un-landed platter state (test18:
 * xfs_imap_to_bp EFSBADCRC on an inode cluster whose platter still held
 * prior-tenant file data; test1: P56 write-verify SHUTDOWN 0x8) — the
 * very corruption class the fence exists to prevent.
 *
 * Policy now: keep issuing bounded pushes while the AIL min LSN is
 * MOVING (movement = the device is landing our items; the target stays
 * the entry snapshot, so concurrent foreground commits cannot livelock
 * the wait).  Declare a wedge ONLY when the min sits FROZEN across
 * MXFS_NOINO_STALL_TRIES consecutive bounded pushes (~10s of provable
 * zero progress = the genuine lost-completion class P3B fences), or at
 * the MXFS_NOINO_MAX_TRIES hard wall (~90s, deliberately under the
 * peer's 120s CAW acquire timeout so a true wedge still fences before
 * the BAST requester gives up).  Invariant #1 is untouched: we still
 * NEVER unlock undrained.
 */
#define MXFS_NOINO_MAX_TRIES	45
#define MXFS_NOINO_STALL_TRIES	8

struct mxfs_noino_lc_work {
	struct delayed_work	dw;
	struct xfs_mount	*mp;
	uint64_t		ino;
	uint8_t			mode;
	u64			first_ns;
	unsigned int		n;
	struct hlist_node	hnode;
};

/*
 * D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 component 3 (design-consult
 * ruling): poison-time revocation.  Setting MXFS_IF_INCARN_STALE gates NEW
 * operations, but cached folios of the dead incarnation stay readable
 * through resident PTEs (no fault, so no gate fires) and dirtyable through
 * writable PTEs until the next lookup happens to run the retire arm.  The
 * revocation must run when the poison publishes, not when a lookup next
 * notices.
 *
 * The poison sites sit under the reload path, which can run with the
 * poisoned inode's own IOLOCK/ILOCK held (e.g. write_iter -> DLM acquire ->
 * protective reload), so the revocation cannot run inline: it is deferred
 * to a workqueue.  The worker takes IOLOCK_EXCL + MMAPLOCK_EXCL — that
 * acquisition IS the drain: every gated data path holds one of them shared,
 * so ops admitted before the poison published have completed by the time
 * the worker owns both.  It then re-asserts the flag (so post-drain
 * admissions observe it under their shared lock), zaps every PTE (later
 * faults take the gated fault handler -> SIGBUS) and DISCARDS the
 * incarnation's page cache.  Discard, never flush: dirty pages here were
 * dirtied through a stale bmap whose blocks may already belong to another
 * live file (truncate_inode_pages waits out in-flight pre-poison writeback
 * but never submits new IO).  Finally it marks the shell DONTCACHE and
 * prunes aliases so the last iput evicts without waiting for a lookup.
 */
struct mxfs_incarn_revoke {
	struct work_struct	work;
	struct xfs_inode	*ip;	/* carries one inode reference */
};

#define MXFS_PUB_DRAIN_WORKERS	16
#define MXFS_PUB_DRAIN_INLINE	32	/* small backlog: drain inline */

struct mxfs_pub_drain_batch;

/* inodes one drain pass has already deferred; see mxfs_dlm_publish_drain_loop */
#define MXFS_PUB_SEEN_DEFER_MAX	128

struct mxfs_pub_drain_worker {
	struct work_struct	work;
	struct xfs_mount	*mp;
	xfs_ino_t		parent_ino;
	xfs_agnumber_t		agno;
	struct mxfs_pub_drain_batch *batch;
	unsigned int		published;
	/* the drain loop's scratch, here because the batch is heap-allocated
	 * and the loop's own stack frame was over 1 KB with it */
	xfs_ino_t		seen_defer[MXFS_PUB_SEEN_DEFER_MAX];
};

/*
 * — the publish drain batch is SELF-FREEING and
 * the caller's wait is BOUNDED.  ROOT (instrumented, measured live): the old
 * unbounded wait_for_completion ran on the ordered bast worker while the
 * drain workers' routed CLUSTER claims remote-waited on peer demotes —
 * demotes that run on the PEERS' bast workers.  Two nodes in this state
 * close a cross-node cycle (test5: publish wait 470s+ on iclus base
 * 10485952 [P-WAIT-EXTEND type=6 blockers=2] with its own AG5 release
 * work queued BEHIND the stuck head [P12 sched=1 page_ms=476s]; test7:
 * bast worker waiting on AG5 in covered-file delalloc writeback).  A
 * bounded wait breaks EVERY such cycle: one node's timeout unwedges its
 * queue, its queued demotes run, the peers' waits then complete in ms.
 * On timeout the workers keep running detached (the batch frees itself
 * on the last ref) and their claims land asynchronously — late, but the
 * claims themselves are still the correct action; the loud probe below
 * names each occurrence.  m_mxfs_pubdrain_active gates unmount teardown
 * against detached workers still referencing the mount.
 */
struct mxfs_pub_drain_batch {
	struct mxfs_pub_drain_worker w[MXFS_PUB_DRAIN_WORKERS];
	atomic_t		refs;		/* nworkers + the waiter */
	atomic_t		pending;	/* still-running workers */
	struct completion	done;
	unsigned int		nworkers;
};

#define MXFS_PUB_DRAIN_TIMEOUT_MS	5000

/* ─── deferred reap (D-CROSSNODE-OPEN-UNLINK orphan coordinator) ─── */

/*
 * An unlinked inode whose destructive inactivation found a PEER's
 * open-holder bit set stays durable on OUR unlinked bucket; this list just
 * drives retries.  Each retry is iget+irele: the irele re-enters evict →
 * xfs_inactive, where the B6 guard re-evaluates the open bits under a fresh
 * EX — the EX acquire itself BASTs cache-only peers into eviction (their
 * evict clears their bits), real openers keep theirs until last-close
 * eviction, and fencing strips dead nodes' bits, so retries converge.  A
 * successful ifree calls mxfs_defer_reap_done; a vanished/reincarnated ino
 * is dropped.  Entries lost to OUR crash/unmount are re-discovered by the
 * scoped bucket recovery at the next mount of this slot, whose iget/irele
 * path re-enters the same guard (recovery honors open bits for free).
 */
struct mxfs_reap_entry {
	struct list_head	l;
	uint64_t		ino;
	uint32_t		gen;
	/* Authority snapshot from defer time: this mount is the responsible
	 * freer (it ran the unlink, or adopted the orphan via its scoped
	 * bucket recovery), and the zombie lives in THIS bucket.  A fresh
	 * iget in the retry loop knows neither — MXFS_IF_LOCAL_UNLINK and
	 * i_unlinked_bucket lived on the long-evicted in-core copy — and the
	 * B4 no-authority guard then blocks the owner's own reap forever
	 * (measured: retries at 30s cadence, will_skip=1 b4_noauth=1).  The
	 * worker restores both onto the fresh copy after the generation
	 * match proves it is the same incarnation we deferred. */
	int16_t			bucket;
	/* retire-only entry — this node was an OPENER of a
	 * peer-unlinked file, not its responsible freer.  Its local dentry
	 * pins the zombie after last close (a cross-node unlink never
	 * d_deletes the opener's alias, and nothing re-looks the path up,
	 * so only memory pressure would ever evict — PROVEN leak: death-
	 * case victim ino=132 not re-issued across 400 creates).  The
	 * worker prunes the aliases and drops the entry; it must NOT
	 * restore LOCAL_UNLINK for these — false freer authority would
	 * arm the P2L-OWNFREE disk-free bypass on a non-unlinker. */
	uint8_t			kind;	/* MXFS_REAP_* */
	/* inactivation-certificate refusals seen for this zombie
	 * (P-INACT-CERT-REFUSED); MXFS_INACT_CERT_REFUSE_MAX escalates. */
	uint8_t			cert_refusals;
};

#define MXFS_REAP_OWN		0	/* this node ran the unlink (B6 defer) */
#define MXFS_REAP_RETIRE	1	/* opener-side alias retirement only */
#define MXFS_REAP_ADOPTED	2	/* survivor-sweep adopted freer */

#define MXFS_REAP_RETRY_MS	30000
#define MXFS_REAP_FIRST_MS	5000

/* ─── A-prime: mount-level typed iunlink write records ───────────
 *
 * The fossil di_next_unlinked producer (D-RSYNC-RENAME family; review-ruled
 * fix, memories TAIL7-TAIL11): a committed iunlink write can vanish from
 * every buffer/inode-scoped defense (reclaim + buffer teardown + fresh
 * cold fill), letting a stale platter image resurrect the pre-write chain
 * value under a current-gen dinode core.  These records survive at MOUNT
 * scope: inserted at iunlink-item precommit (the authoritative write),
 * retired when the covering cluster buffer's home write completes, and
 * consulted to overlay the committed value (+CRC recompute) onto any
 * freshly installed platter image of that cluster.  Only OUR OWN
 * committed values, keyed to the exact incarnation (gen) — shared-grain
 * safe per the lesson.
 */
struct mxfs_iunl_rec {
	struct list_head	l;
	uint64_t		ino;
	uint32_t		gen;
	uint32_t		next_agino;	/* committed value */
	xfs_daddr_t		daddr;		/* cluster buffer start */
	uint16_t		boffset;	/* byte offset in buffer */
	/* v5 (design-consult ruling, c3-391 inverted-P53 autopsy): records are
	 * AG-TENURE-SCOPED — valid only while this node holds the AG EX
	 * under which the value was committed.  Purged at every AG unlock
	 * (post-drain, so the value is durably home by Invariant #1); a
	 * record surviving into a later tenure can graft an abandoned past
	 * over a peer's newer same-gen chain value (nu has no ordering). */
	xfs_agnumber_t		agno;
	/* v2 (TAIL13): bio completion on this target stack means
	 * WRITE CACHE, not platter (the P143/mkfs precedent) — retiring
	 * there re-opened the window (383 fatal, zero store prints).  A
	 * record is droppable only once a device flush has happened AFTER
	 * its covering write completed: wr_epoch = flush epoch at write
	 * completion (0 = not yet written); drop when current flush epoch
	 * has ADVANCED past it. */
	uint64_t		wr_epoch;
};

/* ─── publication obligations ─────────────────────────────────────
 *
 * D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN, measured to the line: an AG
 * release may publish an unlinked-list CHAIN whose members' home dinodes
 * still read LINKED (the nlink=0 conversion has not been flushed), and the
 * head-only P86 audit cannot see mid-chain members (test22's death: member
 * agino 0x1a7, cached=0 nlink=1, killed the remove path 267s after its
 * unlink).  Per the design-consult ruling, correctness is per-inode OBLIGATIONS, not
 * a cluster-flush conversion rate: armed at xfs_iunlink (the entry's
 * creation), discharged when the conversion's covering write COMPLETES
 * (xfs_iflush_finish, via MXFS_IF_PUBOB_FLUSHED) or when the entry leaves
 * the list (xfs_iunlink_remove), and ENFORCED at every AG release: each
 * still-armed obligation for the AG is target-flushed and FUA-verified
 * before the unlock may publish.  No inode reference is held: an obligation
 * whose shell is gone (the inactivation-leak family) cannot be repaired and
 * counts as an unrepaired split — fail-closed, surfaced to the refuse-unlock
 * escalation, where self-shutdown is sound because our journal slice carries
 * the committed unlink and replay converts the dinode.
 */
struct mxfs_pubob {
	struct list_head	l;
	uint64_t		ino;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint32_t		gen;
	/*
	 * (D-0351, design-consult ruling ccmemory ccloop-c7ee71c6-sess427-GPT-
	 * ruling-free-publish-invariant-d0351): the obligation KIND.  An unlink
	 * obligation (UNLINK) owes "nlink=0 at home"; when that inode is then
	 * FREED by this node the obligation is not discharged at
	 * xfs_iunlink_remove but TRANSITIONS — continuously, with no gap the AG
	 * release could slip through — to FREE_PENDING (ifree in flight: the
	 * audit defers, never writes) and, at the ifree commit, to FREE (owes
	 * "mode=0 at gen" — the FREE-PUBLISH invariant: a peer may select this
	 * inode as free under a newly acquired AG grant only if that image is
	 * already durable).  `epoch` is the AG EX tenure (pag_mxfs_grant_epoch)
	 * the ifree committed under; xfsaild may write the free image only
	 * inside that same uninterrupted tenure (P55C), the release audit under
	 * its retiring token (pag_mxfs_rel_epoch).
	 */
	uint8_t			kind;
	/*
	 * (D-0351 chain, design-consult ruling ccmemory ccloop-c7ee71c6-sess430-
	 * GPT-ruling-free-foreign-chain): the number of times THIS node
	 * re-allocated the number (xfs_iget_recycle for a local create) while
	 * a FREE obligation on it was still open, every time under the SAME
	 * uninterrupted AG EX tenure (`epoch`).  While the new life is live the
	 * entry is CHAIN_LIVE — NOT actionable: the audit must never publish
	 * mode 0 over a live inode, nor poison it as foreign (s433: 634
	 * P-FREEOB-FOREIGN, one P32D-DEADINCARN-SKIP on a live file).  A later
	 * free of that life carries the chain forward (UNLINK -> FREE_PENDING
	 * -> FREE); a chained FREE's platter image at a gen other than gen-1
	 * is one of this node's own earlier lives (no peer can allocate the
	 * number without the AG EX, and the release audit publishes or fails
	 * closed before any unlock), so it is WRITTEN under the same tenure
	 * sanction as the exact predecessor — never neutralized as foreign.
	 */
	uint16_t		chain;
	uint64_t		epoch;
	/*
	 * (D-0524, design-consult ruling ccmemory ccloop-c7ee71c6-sess465-GPT-
	 * ruling-d0524-pubob-race-fix): the ENTRY is the single authority for
	 * every transition, and every decision about it is taken under
	 * m_mxfs_pubob_lock.  The lost update that killed test1 in chain 88:
	 * the ifree commit (FREE_PENDING -> FREE) and the write completion of
	 * the PRE-free unlink image (discharge -> re-mark FREE_PENDING) each
	 * read ip->i_mxfs_freeob outside the lock and wrote kind inside it, so
	 * the committed FREE was overwritten by FREE_PENDING and the release
	 * gate read 'ifree in flight' for 20 s, then shut the node down.
	 *
	 *   inflight      which image of this inode a submitted cluster-buffer
	 *                 write carries (published at copy-in, consumed once at
	 *                 completion, both under the lock).  A completion whose
	 *                 token no longer matches the entry's kind is STALE and
	 *                 changes nothing.
	 *   pred*         the exact state the entry had when the ifree began
	 *                 (FREE_PENDING is entered at xfs_inactive_ifree start),
	 *                 restored verbatim if the ifree definitely did not
	 *                 commit.  PRED_NONE = there was no entry.
	 *   pending_epoch the AG EX tenure the ifree began under; the commit and
	 *                 the gate's self-heal must see the same tenure.
	 */
	uint8_t			inflight;
	uint8_t			pred;
	uint16_t		pred_chain;
	uint32_t		pred_gen;
	uint64_t		pred_epoch;
	uint64_t		pending_epoch;
};
/* the obligation kinds themselves live in xfs_mxfs_dlm.h: the inode allocator
 * has to name them to decide whether a candidate's free is still unpublished */
#define MXFS_PUBOB_PRED_NONE	0xffu

#define MXFS_PUBOB_INFLIGHT_NONE	0u
#define MXFS_PUBOB_INFLIGHT_UNLINK	1u	/* nlink=0 conversion image */
#define MXFS_PUBOB_INFLIGHT_FREE	2u	/* committed mode=0 image */
#define MXFS_AG_YIELD_DOUBLE_THRESH 4	/* v0.3.147 N consecutive
					 * non-contended epochs before doubling
					 * the effective quantum back up. */

/*
 *  harness poke to dump the P172-WRTR write-
 * provenance ring (pal/linux/xfs_buf.c) after a detection — the ring is
 * memory-only (printk at the write path suppresses the D3 race), so the
 * harness writes 1 here on every node after a coherency FAIL and merges
 * the per-node dmesg dumps by daddr+realns.
 */
extern void mxfs_wrtr_dump(void);

/*
 * (design review audit C3) — OPEN-AT-NL closure.  An open served from the
 * dcache can complete on an inode whose DLM grant was idle-released or
 * close-demoted to NL: no grant means a peer's EX never BASTs us, so the
 * P90 publish never runs, the peer's B6 guard reads an empty bitmap, and
 * its unlink FREES a file this node has open (the exact D-CROSSNODE-OPEN-
 * UNLINK data loss, reachable in the default config via any
 * open→close→reopen cycle — close_release demotes the grant at close).
 *
 * Called after i_mxfs_open_n++ (order matters: the counter must be visible
 * before we establish/verify the grant, so a release firing at any later
 * point reads opens>0 at its P90 decision).  The ilock ride ensures the
 * grant through the battle-tested acquire path: an in-flight release either
 * defers to our held ilock (its P90 re-fires at ilock_end and sees us) or
 * completed first and the acquire claims a fresh grant.  If the file was
 * concurrently freed by a peer, the coherent acquire surfaces the stale/
 * freed incarnation through the existing reload guards instead of serving
 * freed extents.
 *
 * Failure to establish a grant = failure to protect: the open FAILS (-EIO).
 */
/* /PLAIN laps re-run the acquisition+admission protocol
 * bare; after that the admission gate arms (it defers releases that have
 * not yet reached their terminal store).  There is no exhaustion budget
 * any more — epoch-aware completion wait makes every lap wait
 * out the release pipeline it lost to, so the loop converges and
 * contention never becomes -EIO (design-consult ruling). */
#define MXFS_OPEN_PROTECT_PLAIN_RESTARTS	2

/*
 * (design review audit C4) — eager lazy-CLEAR at last close.  A bit published
 * under BAST (P90) used to persist until evict; with the inode cached and
 * nlink>0 that is hours, during which a peer's unlink of the file defers
 * its reclaim against a bit that no longer protects anything.  Clear it as
 * soon as the last local protected reference drops.  A concurrent reopen
 * is safe: C3 (mxfs_dlm_open_protect) guarantees the reopen holds a grant,
 * and grant-holdership protects independently of the bit.
 */
/*
 * 0.89.0 (D-0977), TCP: clear this node's open-holder mark by RELEASING.
 * The mark's only durable transitions are release transitions at the
 * resource master (publication inseparable from release, both ways), so a
 * last close at NL — the shell released its grant under a BAST while the
 * file was still open, which is exactly when the mark was set — takes a PR
 * grant through the ordinary acquire and queues its demote; the demote's
 * release runs the P90 decision and publishes the absolute state.  A shell
 * that still caches a grant only needs the demote.  Ordering against a
 * reopen is the grant's own: a release naming an older grant than the
 * record's is stale at the master and applies nothing, and the newer
 * grant's release publishes what is true then.
 *
 * Runs in a worker (the acquire can wait on the master and on a peer's
 * drain; close() must not).  Holds an inode reference across the ride.
 */
struct mxfs_open_clear_ride {
	struct work_struct	work;
	struct xfs_inode	*ip;
};

/*
 * v0.10.38 dir-EX-BAST sweep worker (see mxfs_dir_ex_bast_sweep param).
 * Walks the superblock's cached inodes once and queues the drain-free
 * demote for every idle REGULAR-file PR grant.  fs/drop_caches.c iteration
 * idiom: igrab under s_inode_list_lock, work outside it, iput of the
 * previous inode only after re-taking the list position.
 */
/* interactive session 2026-07-13 (2nd pass, instrumented): the need_resched()-gated
 * escape below is necessary but NOT sufficient.  A live 8/caw repro under
 * caw_fair_handoff=1 still hit a 750s+ softlockup with ZERO context switches
 * (rcu_preempt self-detected stall, csw/system=0) on a live vCPU register
 * capture — full call stack read straight off the stack (ret_from_fork_asm ->
 * ret_from_fork -> kthread -> worker_thread -> process_one_work), RIP
 * oscillating tightly between _raw_spin_lock and the pv queued-spin-unlock
 * callee-save thunk every sample.  need_resched() only fires when some OTHER
 * task wants THIS cpu; on an otherwise-idle cpu (3 of 4 vCPUs were HLT'd at
 * capture time) it can legitimately never become true, so the v1 escape never
 * engages no matter how long the walk runs.  A healthy node's whole inode
 * cache was only ~6666 entries at the time (/proc/sys/fs/inode-nr on a
 * healthy peer) — nowhere near enough to explain 750s even at the cost of a
 * genuine spin_lock/spin_unlock pair per entry — so an UNCONDITIONAL periodic
 * yield is required regardless of scheduler contention, plus a hard iteration
 * ceiling as a backstop against an actually-cyclic list (unproven but not
 * ruled out; list_for_each_entry has no other way to bound a cycle that
 * excludes the head). */
#define MXFS_PRSWEEP_YIELD_EVERY	2048
#define MXFS_PRSWEEP_VISIT_CAP		1000000

/*
 * — OVERHEAD-FREE in-kernel landing ring.  Per-write pr_warn +
 * dmesg-stream perturb timing badly (DRC_STREAM = ~4 min/round, masks the race)
 * and the kernel ring rotates over a 24-round run.  Instead record each dir3
 * data/leaf/block write COMPLETION into a fixed in-kernel ring with NO printk;
 * the test dumps it in ONE burst (echo 1 > .../parameters/dland_dump) the instant
 * it detects a readdir miss, so the failing round's COMPLETE landing order
 * survives in the fail snapshot.  Merge all nodes' P-DLAND by realns per daddr →
 * which content version of a (reused) daddr landed LAST = the smoking gun.
 */
#define MXFS_DLAND_RING 65536	/* 4096->65536 (power-of-2 for the mask).
				 * The 4096 ring rotated past the FAILING round's
				 * create wave in a 24-round run (the test continues
				 * past the fail, flooding the ring with later rounds'
				 * rm-rf teardown).  65536 (~1MB static) holds the
				 * whole run so the victim's create-wave trajectory
				 * survives to the on-fail dump. */
struct mxfs_dland_ent {
	u64	daddr;
	u64	owner;
	u64	realns;
	u32	incarn;
	u32	sum;
	int	cnt;
	char	comm[16];
	char	ops[12];
};

/*
 * sess-tcp: write-only trigger to dump the P-LKT lock-table event ring
 * post-mortem (after the tcp_dlm_scaling leftover is observed).  Write the
 * parent-dir inode number (0 = all) to /sys/module/mxfs/parameters/lktdump;
 * the ring is emitted to dmesg.  Dumping AFTER the race avoids the printk
 * perturbation that hides the double-grant when tracing live.
 */
extern void mxfs_dlm_lkt_dump(uint64_t want_ino);

/*
 * D-CLEAN-UNREF-INODE-LRU-STRAND (was D-DWORK-RUNTIME-PIN) fix.
 *
 * PROVEN by pin_census: bulk-created file inodes end i_count=0, i_state=0
 * (clean), on_lru=0 — invisible to drop_caches/shrinker forever; only
 * unmount's s_inodes walk frees them.  Mechanism: the inode was DIRTY at its
 * final iput (iput_final skips the LRU add for dirty inodes), and was later
 * cleaned outside fs-writeback's writeback_single_inode (mxfs drains/AIL
 * write the data+cluster directly), so inode_sync_complete's "clean and
 * unused → LRU" re-add never runs, and no VFS path ever revisits an
 * already-clean inode.  Upstream never strands because upstream inodes are
 * only cleaned BY writeback.  Each stranded inode also holds its cached
 * wire-EX slot with no reclaim trigger (demand-release still works — a peer
 * BAST finds the in-memory inode — but never-reaccessed files leak slots and
 * memory until unmount; measured 200/200 stranded per bulk-create batch).
 *
 * Repatriation sweep: every MXFS_LRU_SWEEP_MS walk s_inodes, igrab stranded
 * candidates (clean, unused, off-LRU), and iput them outside the list lock —
 * iput_final re-evaluates the now-clean inode and performs the LRU add
 * (inode_lru_list_add is not module-exported; igrab/iput is the portable
 * re-add idiom, same lock order as evict_inodes: s_inode_list_lock, then
 * i_lock inside).  Bounded batches so the lock hold stays short.
 */
#define MXFS_LRU_SWEEP_MS	30000
#define MXFS_LRU_SWEEP_BATCH	128

/*
 * — D-FOREIGN-REPLAY-UNGATED-IMAGES enforcement-gate prerequisites
 * (design-consult ruling, build-order step 1).  The tenure-release invariant
 * — "no new tenure becomes effective until the retiring tenure's dirty state
 * completed home-location writeback plus the required persistence barrier,
 * and only then does the resource go peer-claimable" — is UNMET today on
 * four audited fronts:
 *   F1 ICLUS make_durable gives up after a 250ms passive settle and
 *      releases anyway with the cluster buffer still dirty;
 *   F2 fua_disable=1 (default) turns every tenure-boundary flush_epoch into
 *      a no-op, so nothing covers loss of the shared target's volatile
 *      write cache — CAS may survive a cache loss that dropped the home
 *      write it was supposed to certify;
 *   F3 (proof landed sess256-258, telemetry-only) the release proof was
 *      check-then-CAS: an async xfsaild destage between the check and the
 *      CAS could promote durable_seq and certify a closed ledger without
 *      any flush covering it.  The completion-driven proof — keyed
 *      per-cluster write accounting (mxfs_icwr_*), durable-fepoch flush
 *      tickets, post-flush generation verify, pre-CAS tripwire — now
 *      RECORDS every such occurrence (proof_failed/ticket_stale/
 *      tripwires).  truth-up (audit of every failed-proof exit):
 *      the ICLUS class DOES defer under release_proof_enforce=1 since
 *      (mxfs_iclus_disk_release: proof_failed/tripwire/oblig_cas
 *      -> mxfs_iclus_release_defer; open-bit publish failure defers; a
 *      failed CAS never reopens admission; WEDGED is terminal).  The
 *      INODE class now matches (0.55.1):
 *      mxfs_relbar_close_or_defer defers (P228-RELBAR-TICKET-DEFER,
 *      DEMOTING, cause TICKET_STALE) on a flush-ticket proof failure
 *      instead of returning the non-defer value.  That exit is reachable
 *      only with fua_disable=0 (the ticket check passes trivially under
 *      fua_disable=1), a domain the mount-time validator refuses
 *      (D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516), so the deferral is
 *      verified only by the forced stage-10 fault until that domain is
 *      testable; F3_READY stays 0 until it is verified there;
 *   F4 a committed-never-submitted dir buffer has no obligation registry —
 *      m_mxfs_dir_wr_inflight fences submitted bios only, and the flush
 *      passes that would catch the rest can race relog/CIL.
 * A gate that trusts this unproven release predicate converts each unmet
 * barrier into silent false-ACCEPT/false-REJECT replay verdicts, so the
 * setter below FAILS CLOSED: enabling refuses with -EINVAL and one pr_err
 * per unmet prerequisite.  Readiness consts flip as build-order steps 4-7
 * land each barrier; readiness is a property of the BUILD, not of runtime
 * state.
 */
#define MXFS_RELGATE_F1_ICLUS_DEFERRED_RELEASE_READY	0
#define MXFS_RELGATE_F3_COMPLETION_PROOF_READY		0
#define MXFS_RELGATE_F4_OBLIGATION_REGISTRY_READY	0

/*
 * (D-FOREIGN-REPLAY-UNSTABLE-SLICE-READ-FALSE-TORN-527): foreign
 * slice snapshot stabilization knobs, consumed by
 * mxfs_xlog_slice_snapshot() in xfs_log_recover.c.
 */
extern int mxfs_fr_stab_interval_ms;
extern int mxfs_fr_stab_passes;
extern int mxfs_fr_stab_prefetch;
extern int mxfs_fr_stab_deadline_ms;

/* Ceiling on AG numbers the roll-migration bitmap can track.  An agno at or
 * above this (absurd for any test geometry; agcount here is 16) falls back
 * to the safe behavior: retain the grant across the roll. */
#define MXFS_MIGRATE_MAX_AGS	1024

/*
 * Inode-DLM bast deferral — symmetric to AG-side deferral above but for
 * inode-side bast_process (priority-3 dir-stale Mode A and "Free inode N
 * has blocks allocated").  See xfs_mxfs_dlm.h header comment.
 */
struct mxfs_pending_inode_unlock {
	struct list_head	list;
	struct xfs_inode	*ip;
};

/*
 * (design review step-4a review item 2/5): how many force/push/invalidate rounds
 * to spend trying to reach a genuinely empty cached view.  A buffer is only
 * retained when it still holds this node's un-destaged committed content, and
 * xfs_ail_push_all_sync returns when the AIL is empty, so one further round
 * normally suffices; the extras cover writeback still in flight (trylock fail)
 * and buffers racing towards free (b_hold==0).
 */
#define MXFS_INVAL_FLUSH_ROUNDS	5

/* ─── Mount init ─── */

/*
 * C8 — survivor sweep of a dead slot's AGI unlinked bucket (design review
 * acceptance invariant 8: "unreclaimed dead-slot bucket = unbounded
 * liveness defect, NOT an acceptable leak").
 *
 * Per-slot buckets (0.11.332) mean bucket index == owning node slot.  At
 * RUNTIME fence the dead slot is zeroed but never claimed, so no mount's
 * scoped recovery (own-bucket-only, P86) ever walks it — its zombies
 * (deferred open-unlink reaps, mid-flight unlinks) leak until an eventual
 * remount claims the slot.  The elected survivor (the same election that
 * ran the foreign-slice replay) adopts the bucket right after
 * recovery_complete: walk each AG's bucket, iget each chained inode,
 * restore ADOPTED authority (MXFS_IF_LOCAL_UNLINK + i_unlinked_bucket —
 * without it the B4 no-authority guard blocks every free, the exact trap
 * the reap worker documents), and irele into the normal inactivation
 * where B1-B6 decide free / defer / skip:
 *   - a live peer's open bit  -> B6 defers, reap-worker entry on THIS
 *     node retries until last-close (fencing already stripped the DEAD
 *     node's own bits in the purge CAS);
 *   - freed-elsewhere / reused -> B1/B2 skip;
 *   - plain orphan             -> freed under per-inode EX.
 * A concurrent future claimant of the slot walks the same bucket at its
 * mount; both walks free under per-inode EX with B1 disk-free skip, so
 * the race is benign.  next is captured BEFORE the irele and inodegc is
 * flushed between links (upstream xlog_recover_iunlink_bucket pattern) so
 * chain mutation never runs ahead of the walk.
 */
/*
 * — D-DESTAGE-TEAR-BUCKETLESS-ORPHAN fix (d), review-ruled design.
 *
 * MXFS destages cluster buffers eagerly (per-buffer, for coherency), so a
 * dying node can land SOME buffers of a committed transaction and not
 * others; the foreign-replay atomic skip (correctly) refuses to apply the
 * dead node's untagged transaction, so the log cannot repair the tear.
 * The unlink shape leaves the proven artifact: an allocated inode with
 * nlink==0 on NO unlinked bucket and no dirent — a permanent leak
 * (deterministic capture: ino=139 gen=3969932820, unlinker_death arm).
 *
 * Closure: after every dead-slot recovery (replay + bucket sweep), the
 * elected survivor scans the inobt for allocated nlink==0 inodes absent
 * from ALL 64 unlinked buckets of their AG and ADOPTS each: a durable
 * xfs_iunlink insert onto THIS node's slot bucket (small standalone
 * transaction), then the normal ADOPTED reap path frees it under the
 * existing authority gates (B6 defers while any peer holds it open).
 *
 * Authority (design-consult ruling): this is the recovery-domain authority class —
 * "under fenced recovery quiescence, an EX-holding survivor may adopt an
 * allocated, unreferenced, bucketless inode".  The live-unlinker race is
 * excluded by verifying UNDER THE INODE'S DLM EX: a live node mid-unlink
 * holds the inode EX, and its release drains its metadata buffers
 * (Invariant 1) — so once we hold EX, the platter reflects its completed
 * unlink INCLUDING the bucket insert, and membership sees it.  The
 * target's own membership cannot change while we hold its EX (insert and
 * remove both run under inode EX).  Adoption before free is deliberate:
 * an adopter crash leaves either the old orphan (rescanned at the next
 * recovery) or a normally-bucketed zombie (normal recovery) — never a
 * new unrecoverable state.
 */
#define MXFS_ORPHAN_MAX_CAND	4096

struct mxfs_orphan_scan_ctx {
	xfs_ino_t		*cand;
	unsigned int		n;
	bool			overflow;
};

/*
 * (ruling, D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356): the
 * closure classifier for the selective grant purge that follows a terminal
 * AG_MASK refusal.  Returns >0 only when the resource is PROVABLY outside
 * the quarantined AG domain; everything ambiguous stays frozen:
 *   - AG locks map by ag_number, inode/icluster locks by the AG their
 *     inode number decodes to (an inode cluster never spans AGs, and the
 *     ICLUSTER resource carries the cluster base ino);
 *   - JOURNAL/SUPER/EXTENT/unknown types are not AG-scoped or not provably
 *     classifiable — in closure, frozen (the refused slice's SB-counter
 *     obligations live behind SUPER, so freezing it is required, not just
 *     conservative);
 *   - an AG the uint64 mask cannot represent (>= 64) or an inode decoding
 *     past sb_agcount is unclassifiable garbage — frozen;
 *   - (D-0487): the ONE exception above the AG space is the SB
 *     summary key (mxfs_sb_summary_key: slot agcount+66 by construction).
 *     It is not an inode; it serializes the terminal SB write, which is a
 *     recount from uncached AGF/AGI headers and carries no logged state of
 *     its own.  After an AG-scoped refusal the refused AG's transactions are
 *     never applied, so the old headers are authoritative and the recount is
 *     safe; leaving the dead holder's grant frozen instead convoyed every
 *     unmounting peer on the 120 s lock timeout (leg Z: 7 dirty departures).
 *     Only AG-mask verdicts reach this classifier (the publisher gates on
 *     ag_mask != 0, the scrub callback returns 0 without one), so an FSWIDE
 *     refusal still keeps it frozen.
 */
struct mxfs_freplay_closure_arg {
	struct xfs_mount	*mp;
	uint64_t		ag_mask;
};

/*
 * (D-FOREIGN-REPLAY step 4a item 6) — MOUNT RECOVERY BARRIER.
 *
 * Mount step 4 KEEPS our previous incarnation's EX/PW bits in the CAW
 * table instead of purging them, because xlog_recover is about to replay
 * buffer images that were authored under exactly that authority, and the
 * recovery-side authority check reads those bits to decide which images it
 * may legally apply.  Mount step 6.5 likewise RECORDS, rather than purges,
 * the grants of peers that were already frozen when we arrived — those are
 * the authority manifests of journal slices nobody has replayed.  Something
 * has to resolve both sets afterwards, and this is it.
 *
 * WHERE IT RUNS, AND WHY THAT IS THE WHOLE POINT.
 *
 * ran this after xfs_mountfs returned.  That is a bootstrap
 * deadlock (design-consult ruling).  xfs_mountfs itself takes blocking
 * cluster locks: xfs_log_mount_finish replays intents and processes the
 * unlinked lists, and those bottom out in xfs_free_extent -> blocking AG
 * EX acquire.  The grants that can block those acquires are precisely the
 * ones this function releases — so their only release path was gated on
 * the completion of the very work they were blocking.
 *
 * It now runs from xfs_mountfs() the instant xfs_log_mount() returns:
 * our slice is recovered (so our retained bits have served their purpose
 * and the images that needed them are applied), the perags exist
 * (xfs_initialize_perag precedes xfs_log_mount), and nothing has yet taken
 * a cluster lock.
 *
 * WHAT IT MAY NOT DO THERE.  No log force, no xfs_ail_push_all_sync, no
 * inodegc flush, no iget, no transactions.  At this point the AIL holds
 * recovered INTENT items that xfs_log_mount_finish has not processed, and
 * pushing those never completes — upstream XFS refuses the same push for
 * the same reason.  Durability of the replay is instead carried by
 * xlog_recover's own pass-2 delwri submit-and-wait plus a device flush.
 *
 * Failure of most parts is not fatal to the mount: it means authority bits
 * leaked or a slice stayed unreplayed.  Both cost availability, not
 * integrity — an unreplayed slice keeps its grants frozen, which is the
 * safe direction (nothing may consume it).  Logged loudly; mount proceeds.
 *
 * THE ONE EXCEPTION, and why this function returns an error at all
 * (design review item 6A).  A peer we confirmed dead but could NOT
 * FENCE is left in the settle residue: we may not replay its slice, because
 * an unfenced node may still be writing, so its grants stay on disk.  If any
 * of those grants still names a resource, xfs_log_mount_finish — which runs
 * later inside this same xfs_mountfs — can block on it for the full CAW wait
 * timeout and then fail the mount.  That is the original bootstrap deadlock
 * wearing a timeout: the grant's only release path is a settle that runs
 * after the mount completes, and the mount cannot complete until the grant
 * is released.  We refuse to walk into it: retry the fence first (bounded,
 * in v5_settle_resolve), then census what the residue still owns, and fail
 * the mount cleanly if it owns anything.  A mount that fails in seconds with
 * a named cause beats one that stalls minutes and fails anyway.
 */

/*
 * item 6B: how many times step (c) re-drains the late-death record
 * before giving the remainder to the post-mount settle.  Each extra round
 * costs only the replay of slices that genuinely died during this mount —
 * the expensive part (the ~62 s dead-confirm) was already paid by the
 * heartbeat monitor in parallel, and each round strictly shrinks the set of
 * frozen grants xfs_log_mount_finish could stall on.  It is capped because
 * a cluster shedding a node every few seconds must not pin the mount here.
 */
#define MXFS_BARRIER_REPLAY_ROUNDS	4

/*
 * (design-consult ruling) — the admission gate's wait bound.  The budget rule
 * derivation, not a safety net: a WITHDRAWN stamp is noticed by a peer's
 * monitor within one poll interval (2 s), the fence pipeline
 * (intent + PREEMPT AND ABORT + certify) completes in ~1 s on this rig,
 * and an inline foreign-slice replay measures 1-3 s at 32/caw.  30 s
 * therefore covers a chain of ~5 sequential slice recoveries at 2x
 * slack; a recovery cut still dirty after that is not converging, and
 * the mount FAILS rather than going live over it.
 */
#define MXFS_BARRIER_ADMISSION_WAIT_MS	30000
#define MXFS_BARRIER_ADMISSION_POLL_MS	1000

#define MXFS_ICLUS_HASH_BITS	8
#define MXFS_ICLUS_HASH_SIZE	(1 << MXFS_ICLUS_HASH_BITS)

/*
 * ccloop 72513a13 sess4 REWORK — coverage-sweep, not refcounts.
 *
 * The first cut counted per-inode refs (ex_refs/pr_refs) and released the
 * disk grant when the last ref dropped under a pending BAST.  A session-4
 * audit found the count is structurally fragile: the per-inode machine has
 * half a dozen recovery paths that set i_dlm_mode = NL without transiting
 * a release call (P72 orphan escape, P106 phantom bail, unmount teardown,
 * single->multi transition wipe), the PR->EX upgrade is lock-lock-unlock
 * (two counts, one drop), and a nowait admit could count on one side only.
 * Any one imbalance either wedges the cluster (leak: never releases) or
 * split-brains it (steal: releases while a sibling still trusts its cached
 * mode).
 *
 * The rework derives the release decision from the SOURCE OF TRUTH instead:
 * a sweep of the covered in-core inodes.  A cluster's disk grant may be
 * released iff no covered in-core inode holds a granted i_dlm_mode or has a
 * slow-path acquire in flight (i_dlm_acq_inflight, the untrampleable
 * in-flight marker).  Exotic NL-transitions then CONVERGE by construction:
 * whatever path took the mode to NL, the next release_check or peer re-BAST
 * observes it and completes the release.  There is no counter to corrupt.
 *
 * Serialization: ic->busy excludes concurrent slow-path acquires and
 * release sweeps for one cluster.  Fast-path admits (disk_mode already
 * covers) are gated on !busy under ic->lock, and every admit window is
 * covered either by i_dlm_acq_inflight (ilock_begin, ilock_try bracket) or
 * by an already-granted i_dlm_mode, so a sweep can never miss an admit.
 */

struct mxfs_iclus {
	struct hlist_node	hnode;
	struct xfs_mount	*mp;
	uint64_t		base;		/* cluster base ino */
	spinlock_t		lock;
	uint8_t			disk_mode;	/* mode held on the disk slot */
	bool			busy;		/* acquire or release sweep in flight */
	bool			bast_pending;	/* peer waits on this cluster */
	uint64_t		grant_seq;	/* bumped on each NL->granted disk
						 * claim: the only window a peer
						 * could have held EX and
						 * modified covered inodes.
						 * Coherency clock for per-inode
						 * reload gating (seen_seq). */
	/*
	 * step 5.3(d) — durable-authority provenance for the CLUSTER
	 * grant.  auth_epoch is the ex_grant_epoch that the granting CAS
	 * itself stamped (mxfs_grant_result.grant_epoch), recorded under
	 * ic->lock in the same critical section that raised disk_mode, and
	 * ZEROED under the same lock wherever disk_mode falls back to NL.
	 *
	 * This is NOT the resource-keyed cache the ruling rejected.
	 * The rejected shape looked the epoch up by resource id long after
	 * the fact, so it could not tell one tenure from a later one.  Here
	 * ic IS the object that holds the grant: disk_mode > NL is true for
	 * exactly the interval between the CAS that set auth_epoch and the
	 * release that clears it, and both endpoints are serialised by
	 * ic->lock + ic->busy.  A reader that observes (disk_mode >= EX,
	 * auth_epoch) in ONE ic->lock section therefore has first-hand
	 * evidence of a continuously-held tenure, which is the property the
	 * ruling demanded and the hash bucket could not supply.
	 */
	uint64_t		auth_epoch;
	/*
	 * (design-consult ruling ccloop-c7ee71c6-sess448-GPT-ruling-iclus-
	 * relmark-certificate-and-sequencing): the slot's resource_lineage from
	 * the SAME grant image that stamped auth_epoch — installed, snapshotted
	 * and cleared together with it under ic->lock, so every routed inode's
	 * token carries the immutable tuple {INODE, base, lineage, epoch} the
	 * cluster's clean-release marker will certify.  Zero = non-proving.
	 *
	 * relmark_{lineage,epoch}: the IRREVOCABILITY record.  Set under
	 * ic->lock immediately before the marker is published (whether or not
	 * publication succeeds — "possibly marked" is treated as marked): a
	 * later grant image offering the same {lineage, epoch} is refused as
	 * authority (snapshot returns non-proving) on the fast-path admit and
	 * the CAS-established path alike.  Never cleared; a genuinely new
	 * tenure carries a new epoch (CAS-minted) and cannot match.
	 */
	uint64_t		auth_lineage;
	uint64_t		relmark_lineage;
	uint64_t		relmark_epoch;
	/* step 3: per-cluster release state (enum mxfs_release_state).
	 * Written only by the disk-release choke point (serialized by
	 * ic->busy); step 6: DEMOTING/WEDGED now close admission
	 * under mxfs_release_proof_enforce. */
	uint8_t			rel_state;
	wait_queue_head_t	wq;
	/*
	 * step-6 F1 (ruling): deferred-release episode.
	 * All under ic->lock.  defer_started_j != 0 marks an open episode;
	 * every completed release (any path) closes it and bumps
	 * release_epoch (the ruling's ABA guard — a stale worker firing
	 * into a NEW tenure sees DEMOTING false / episode closed and does
	 * nothing).  badness orders defer causes (8*publish-fail + 4*dirty
	 * + 2*proof + tripwire); a DECREASE is genuine progress and restamps
	 * last_progress_j.  Bounds: 60s without progress or 300s total →
	 * wedge (one-shot: pin the grant on disk, close admission forever,
	 * force-shutdown the mount).  no_retry is the teardown latch: set
	 * before cancel_delayed_work_sync so no retry can requeue after it.
	 */
	uint64_t		release_epoch;
	unsigned long		defer_started_j;
	unsigned long		last_progress_j;
	unsigned int		defer_badness;
	unsigned int		defer_tries;
	bool			wedge_shot;
	bool			no_retry;
	struct delayed_work	dwork;	/* retry worker, m_mxfs_inode_bast_wq */
};

/* Defined in one of the files above and used from another. */
extern atomic64_t mxfs_dlm_stat_agtry_localbusy;
extern atomic64_t mxfs_dlm_stat_ag_trydemoting;
extern atomic64_t mxfs_dlm_stat_latch_unlock;
extern atomic64_t mxfs_dlm_stat_latch_acq;
extern atomic64_t mxfs_dlm_stat_latch_acqnb;
extern atomic64_t mxfs_dlm_stat_handoff_n;
extern atomic64_t mxfs_dlm_stat_handoff_b2c_ms;
extern atomic64_t mxfs_dlm_stat_handoff_b2c_max;
extern atomic64_t mxfs_dlm_stat_handoff_b2c_gt50;
extern atomic64_t mxfs_dlm_stat_handoff_b2c_gt500;
extern atomic64_t mxfs_dlm_stat_handoff_c2r_ms;
extern atomic64_t mxfs_dlm_stat_handoff_c2r_max;
extern atomic64_t mxfs_dlm_stat_handoff_c2r_gt50;
extern atomic64_t mxfs_dlm_stat_handoff_c2r_gt500;
extern atomic64_t mxfs_dlm_stat_demote_wait_n;
extern atomic64_t mxfs_dlm_stat_demote_wait_ms;
extern atomic64_t mxfs_dlm_stat_demote_wait_max;
extern atomic64_t mxfs_dlm_stat_demote_wait_trans;
extern atomic64_t mxfs_dlm_stat_demote_wait_dirty;
extern atomic64_t mxfs_dlm_stat_postlatch_adopt;
extern atomic64_t mxfs_dlm_stat_handoff_q_gt500;
extern atomic64_t mxfs_dlm_stat_handoff_q_max;
extern atomic64_t mxfs_dlm_stat_handoff_wq_gt500;
extern atomic64_t mxfs_dlm_stat_handoff_wq_max;
extern atomic64_t mxfs_dlm_stat_handoff_e2a_gt500;
extern atomic64_t mxfs_dlm_stat_handoff_e2a_max;
extern atomic64_t mxfs_dlm_stat_handoff_a2c_gt500;
extern atomic64_t mxfs_dlm_stat_handoff_a2c_max;
extern atomic64_t mxfs_dlm_stat_handoff_rxheld;
extern atomic64_t mxfs_dlm_stat_stale_hint;
extern atomic64_t mxfs_noino_lifecycle_stat[XFS_ILC_NR];
extern atomic64_t mxfs_noino_lifecycle_requeued;
extern atomic64_t mxfs_noino_lifecycle_timeouts;
extern atomic64_t mxfs_dem_slot1;
extern atomic64_t mxfs_dem_slot1_nest;
extern atomic64_t mxfs_dem_slot2;
extern atomic64_t mxfs_dem_slot2_nest;
extern atomic64_t mxfs_dem_contest;
extern atomic64_t mxfs_dem_foreign_clear;
extern atomic64_t mxfs_dem_clear_noclaim;
extern atomic64_t mxfs_dem_init_inherit;
extern atomic64_t mxfs_dem_free_dirty;
extern atomic64_t mxfs_dem_legacy_steal;
extern atomic64_t mxfs_dem_legacy_clear_live;
extern atomic64_t mxfs_dem_wedge_precond;
extern atomic64_t mxfs_dem_inject_unclaim;
extern atomic64_t mxfs_rb_total;
extern atomic64_t mxfs_rb_resolved;
extern atomic64_t mxfs_rb_sum_us;
extern atomic64_t mxfs_rb_max_us;
extern atomic64_t mxfs_p6_skip_total;
extern atomic64_t mxfs_p6_skip_after_rb;
extern atomic64_t mxfs_p6_src_hist[MXFS_P6_SRC_N];
extern atomic64_t mxfs_p6_repeat_ge8;
extern atomic64_t mxfs_p6_repeat_max;
extern int mxfs_demoter_punt_reclaim;
extern atomic64_t mxfs_dem_punt_retain;
extern atomic64_t mxfs_dem_punt_reclaim_n;
extern atomic64_t mxfs_dem_punt_selfclear;
extern atomic64_t mxfs_dem_punt_owner_clear;
extern atomic64_t mxfs_dem_strand_n;
extern atomic64_t mxfs_dem_defer_set;
extern atomic64_t mxfs_dem_defer_clear;
extern atomic64_t mxfs_dem_drain_residue;
extern atomic64_t mxfs_auth_install_n;
extern atomic64_t mxfs_auth_install_advance_n;
extern atomic64_t mxfs_auth_revoke_n;
extern atomic64_t mxfs_auth_relbegin_n;
extern atomic64_t mxfs_auth_unpub_n;
extern atomic64_t mxfs_auth_backstop_n;
extern atomic64_t mxfs_auth_relclean_n;
extern atomic64_t mxfs_auth_publive_n;
extern atomic64_t mxfs_auth_phantom_n;
extern atomic64_t mxfs_auth_ref_novalid_n;
extern atomic64_t mxfs_auth_ref_nogres_n;
extern atomic64_t mxfs_auth_ref_status_n[MXFS_GAUTH_STATUS_MAX];
extern atomic64_t mxfs_auth_ref_stalegen_n;
extern atomic64_t mxfs_auth_ref_releasing_n;
extern atomic64_t mxfs_auth_ref_unpub_n;
extern atomic64_t mxfs_auth_ref_routing_n;
extern atomic64_t mxfs_auth_ref_reclaim_n;
extern atomic64_t mxfs_auth_nosnap_n;
extern atomic64_t mxfs_auth_try_n[MXFS_AUTH_TRY_MAX];
extern atomic64_t mxfs_relmark_iclus_unmarked;
extern atomic64_t mxfs_relmark_iclus_marked;
extern atomic64_t mxfs_relmark_iclus_failed;
extern atomic64_t mxfs_relmark_iclus_reinstall_refused;
extern atomic_t mxfs_bmbt_scan_stale_skip;
extern int mxfs_dir_owner_scan;
extern atomic_t mxfs_iflush_unread_clean_skip;
extern atomic_t mxfs_iflush_unread_local;
extern atomic_t mxfs_bmbt_evict_capped;
extern atomic_t mxfs_iflush_bmbt_capped;
extern atomic_t mxfs_iflush_bmbt_notdone_needs;
extern atomic_t mxfs_reg_bmbt_rel_flushed;
extern atomic_t mxfs_reg_bmbt_rel_wedge;
extern atomic_t mxfs_bmbt_rel_evicted;
extern atomic_t mxfs_bmbt_rel_busy;
extern atomic_t mxfs_bmbt_rel_localwork;
extern atomic_t mxfs_recov_tagged;
extern atomic_t mxfs_recov_queued;
extern atomic_t mxfs_recov_cache_hit;
extern atomic_t mxfs_recov_hit_in_recovery;
extern atomic_t mxfs_recov_bmbt_cached;
extern atomic_t mxfs_recov_dir_cached;
extern atomic_t mxfs_recov_agbt_cached;
extern atomic_t mxfs_recov_other_cached;
extern atomic_t mxfs_recov_evicted;
extern atomic_t mxfs_recov_busy;
extern atomic_t mxfs_recov_localwork;
extern atomic_t mxfs_bmbt_lookup_bad;
extern int mxfs_dir_relverify;
extern int mxfs_dir_zombie_retire;
extern int mxfs_dir_force_evict;
extern int mxfs_file_yield_on_demote;
extern int mxfs_dir_tenure_evict;
extern int mxfs_dir_release_invalidate;
extern int mxfs_dir_epoch_adopt;
extern int mxfs_dir_sf_rebase_merge;
extern atomic64_t mxfs_dirEX_serve_total;
extern atomic64_t mxfs_dirEX_phantom_total;
extern atomic64_t mxfs_dirEX_phantom_pinned;
extern atomic64_t mxfs_dirEX_phantom_selfcr;
extern atomic64_t mxfs_dirEX_phantom_unpub;
extern atomic64_t mxfs_dirEX_fastret_total;
extern atomic64_t mxfs_dirEX_fastret_stale;
extern atomic64_t mxfs_dirEX_demoter_bypass;
extern atomic64_t mxfs_dirEX_slowpath;
extern atomic64_t mxfs_dirEX_gg_armed;
extern atomic64_t mxfs_dirEX_gg_hgg0;
extern atomic64_t mxfs_dlm_stat_cache_hit;
extern atomic64_t mxfs_dlm_stat_cache_miss;
extern atomic64_t mxfs_dlm_stat_bast_immediate;
extern atomic64_t mxfs_dlm_stat_bast_deferred;
extern atomic64_t mxfs_dlm_stat_bast_no_inode;
extern atomic64_t mxfs_dlm_stat_ag_acquire;
extern atomic64_t mxfs_dlm_stat_ag_nested;
extern atomic64_t mxfs_dlm_stat_ag_release;
extern int mxfs_read_attr_probe;
extern atomic64_t mxfs_ex_epoch;
extern int mxfs_dir_ex_batch_grace_ms;
extern int mxfs_dir_sf_mht_ms;
extern int mxfs_dir_adopt_at_acquire;
extern atomic64_t mxfs_b_adopt_sentinel;
extern atomic64_t mxfs_b_adopt_epoch;
extern atomic64_t mxfs_b_adopt_gen;
extern atomic64_t mxfs_b_dirty_skip;
extern atomic64_t mxfs_b_p34j_defer;
extern atomic64_t mxfs_b_stamp_n;
extern atomic_t mxfs_p71_underflows;
extern atomic_t mxfs_noino_bast_reclaimable;
extern atomic_t mxfs_recycle_grant_cached;
extern atomic_t mxfs_recycle_grant_phantom;
extern atomic_t mxfs_demote_survivor;
extern atomic_t mxfs_end_unpaired_single;
extern atomic_t mxfs_rel_dio_waited;
extern atomic_t mxfs_rel_dio_wait_max_us;
extern atomic_t mxfs_rel_dio_defer;
extern atomic_t mxfs_dioend_admit;
extern atomic_t mxfs_rel_dio_inflight;
extern int mxfs_f4_gate;
extern atomic64_t mxfs_relbar_gate_defer;
extern int mxfs_noino_bast_dedup;
extern int mxfs_noino_lifecycle_requeue;
extern int mxfs_sf_merge;
extern atomic_t mxfs_sf_own_image_hits;
extern atomic_t mxfs_sf_own_image_recorded;
extern atomic_t mxfs_sf_release_base;
extern int mxfs_ag_yield_quantum;
extern int mxfs_ag_yield_adaptive;
extern int mxfs_diff_detail;
extern int mxfs_instr_enabled;
extern int mxfs_dirwr_enabled;
extern unsigned long long mxfs_watch_ino;
extern struct xfs_mount *mxfs_dbg_mp;
extern int mxfs_fua_disable;
extern struct mutex mxfs_fr_cfg_lock;
extern int mxfs_ag_bast_stall_iters;
extern int mxfs_target_cache_protected;
extern int mxfs_foreign_replay_token_enforce;
extern int mxfs_release_proof_enforce;
extern unsigned int mxfs_reldefer_noprogress_ms;
extern unsigned int mxfs_reldefer_total_ms;
extern atomic_t mxfs_freplay_work_inv;
extern atomic_t mxfs_dbg_iflush_pause_n;
extern atomic_t mxfs_dbg_ail_push_n;
extern int mxfs_icluster_dlm;
void mxfs_ag_demote_clear(struct xfs_perag *pag);
void mxfs_ag_bast_queue(struct xfs_mount *mp, struct xfs_perag *pag);
void mxfs_stat_max64(atomic64_t *v, s64 n);
void mxfs_pag_dlm_lock(struct xfs_perag *pag, int site);
void mxfs_pag_dlm_unlock(struct xfs_perag *pag, int site);
bool mxfs_bast_arm_queue( struct xfs_inode *ip);
bool mxfs_bast_arm_queue_delayed( struct xfs_inode *ip, unsigned long delay_j);
void mxfs_bastq_lat_probe( struct xfs_inode *ip, const char *who);
unsigned int mxfs_relab_backoff_ms( struct xfs_inode *ip, uint32_t now_gen);
void mxfs_demev_rec(struct xfs_inode *ip, uint8_t op, uint32_t line);
bool mxfs_is_demoter(const struct xfs_inode *ip);
bool mxfs_foreign_demoter(const struct xfs_inode *ip);
void mxfs_demoter_punt_reclaim_check(struct xfs_inode *ip, int site);
void mxfs_inode_authority_revoke_locked(struct xfs_inode *ip, u32 line);
void mxfs_inode_authority_begin_release_locked(struct xfs_inode *ip, u32 line);
void mxfs_inode_authority_check_published(struct xfs_inode *ip, u32 line);
void mxfs_inode_authority_phantom_loss_locked(struct xfs_inode *ip, u32 line);
void mxfs_inode_relmark_before_unlock( struct xfs_inode *ip, uint64_t rel_res, uint64_t rel_epoch, uint64_t rel_lineage, bool *marked, const char *who);
void mxfs_ag_relmark_before_unlock( struct xfs_perag *pag, const char *who);
void mxfs_relmark_site_counters( uint64_t *ino_marked, uint64_t *ino_failed, uint64_t *ag_marked, uint64_t *ag_failed, uint64_t *iclus_unmarked);
void mxfs_relmark_iclus_counters( uint64_t *marked, uint64_t *failed, uint64_t *reinstall_refused);
void mxfs_inode_authority_note_unpublished_locked(struct xfs_inode *ip, u32 line);
void mxfs_dlm_authority_install(struct xfs_inode *ip, const struct mxfs_grant_result *gres, uint64_t gen_snap, bool routed_iclus, u32 line);
void mxfs_inact_cert_evict_check_locked(struct xfs_inode *ip, u32 line);
void mxfs_dlmtr_rec(struct xfs_inode *ip, u8 om, u8 os, u32 line);
void mxfs_dlmtr_dump(void);
void mxfs_caw_orphan_forensic(struct xfs_inode *ip, int site);
bool mxfs_drain_ilock_read(struct xfs_inode *ip);
int mxfs_blkdev_flush_epoch(struct xfs_mount *mp);
int mxfs_blkdev_flush_durable(struct xfs_mount *mp);
bool mxfs_dir_bmbt_scan(struct xfs_inode *ip, bool flush);
void mxfs_fmt_trans_held_ags(char *buf, size_t sz);
bool mxfs_trans_retains_ag(struct xfs_perag *pag);
void mxfs_sf_fmt_names(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *sfp, char *buf, size_t sz);
void mxfs_exh_stamp_locked(struct xfs_inode *ip);
bool mxfs_dirop_durable_needed(struct xfs_mount *mp);
bool mxfs_dir_data_owner_scan(struct xfs_inode *ip, bool flush);
int mxfs_dir_noino_land_scan(struct xfs_mount *mp, uint64_t ino, bool land);
int mxfs_dir_evict_owned_data_blocks(struct xfs_inode *ip);
void mxfs_dir_evict_bmbt_blocks(struct xfs_inode *ip);
int mxfs_bmbt_tenure_end_evict(struct xfs_inode *ip, const char *why);
int mxfs_dbg_coherent_read(struct xfs_mount *mp, uint64_t lba_512, void *buf, uint32_t len);
uint64_t mxfs_sb_summary_key(struct xfs_mount *mp);
bool mxfs_sb_summary_key_is(struct xfs_mount *mp, uint64_t ino);
bool mxfs_dbg_p106_inject_take(uint64_t ino);
bool mxfs_dbg_ino_take(unsigned long long *knob, uint64_t ino);
void mxfs_dbg_sliced_sleep(int ms);
void mxfs_dbg_bast_pause(struct xfs_inode *ip);
void mxfs_dbg_bast_defer(struct xfs_inode *ip, const char *who);
bool mxfs_dbg_relog_force_armed(struct xfs_inode *ip);
bool mxfs_dbg_relog_force_take(struct xfs_inode *ip);
void mxfs_dir_evict_bmbt_by_root(struct xfs_inode *ip);
void mxfs_dir_platter_audit(struct xfs_inode *ip);
void mxfs_dir_bmbt_release_audit(struct xfs_inode *ip);
void mxfs_dir_data_release_verify(struct xfs_inode *ip);
bool mxfs_dir_data_durable(struct xfs_inode *ip);
void mxfs_sf_disk_names(struct xfs_mount *mp, struct xfs_dinode *dip, char *out, size_t outsz);
void mxfs_dir_dump_block_names(struct xfs_inode *ip, const char *tag);
void mxfs_dir_refresh_stale_data_blocks(struct xfs_inode *ip);
void mxfs_dir_flush_data_blocks(struct xfs_inode *ip);
int mxfs_dir_undest_census(struct xfs_inode *ip, struct mxfs_dir_undest_census *c);
void mxfs_dir_flush_data_blocks_relsafe(struct xfs_inode *ip);
bool mxfs_verify_throttle_elapsed(unsigned long stamp_j, unsigned int base_ms);
uint8_t mxfs_dlm_verify_rawmode(struct mxfs_v5_dlm *dlm, uint64_t ino, bool *sampled);
bool mxfs_dir_was_removed(struct xfs_inode *dp, xfs_ino_t ino);
bool mxfs_dir_remset_valid(struct xfs_inode *dp);
void mxfs_dir_stale_clean_data_blocks_relsafe(struct xfs_inode *ip);
void mxfs_ail_drain_inode_sync(struct xfs_inode *ip);
bool mxfs_inode_cluster_durable(struct xfs_inode *ip);
void __mxfs_dlm_dir_inode_durable(struct xfs_inode *dp);
void mxfs_dir_evict_owned_dir_blocks(struct xfs_inode *ip, bool leaf_only);
bool mxfs_file_yield_gate(const struct xfs_inode *ip, int mode);
bool mxfs_dir_evict_data_blocks(struct xfs_inode *ip);
void mxfs_dir_release_invalidate_data_blocks(struct xfs_inode *ip);
int mxfs_dir_stale_data_blocks(struct xfs_inode *ip);
int mxfs_dir_drain_evict_data_blocks(struct xfs_inode *ip);
int mxfs_ex_tenure_window_ms( const struct xfs_inode *ip);
void mxfs_dir_base_stamp( struct xfs_inode *ip, uint32_t ep, uint32_t gg, unsigned int site);
void mxfs_dir_base_invalidate( struct xfs_inode *ip, unsigned int site);
void mxfs_atomic_max(atomic_t *v, int n);
void mxfs_dlm_report_stats(void);
void mxfs_p71_hold(struct xfs_inode *ip, const char *site, int dex, int dpr);
void mxfs_dirdrain_enter(struct mxfs_dirdrain_task *e);
void mxfs_dirdrain_exit(struct mxfs_dirdrain_task *e);
void mxfs_dirdrain_set_mode(uint8_t mode);
void mxfs_recovtask_enter(struct mxfs_recovtask *e, uint8_t phase);
void mxfs_recovtask_exit(struct mxfs_recovtask *e);
void mxfs_recovtask_set_phase(uint8_t phase);
void mxfs_acqfall_enter(struct mxfs_acqfallible *e, u64 ino);
void mxfs_acqfall_exit(struct mxfs_acqfallible *e);
bool mxfs_acqfall_armed_for(u64 ino);
int mxfs_sb_summary_lock_fallible(struct xfs_mount *mp, uint64_t key, struct mxfs_grant_result *gres);
void mxfs_acqfall_give_up_rc(u64 ino, int rc);
void mxfs_acqfall_give_up(u64 ino);
bool mxfs_acqfall_taken(struct mxfs_acqfallible *e, int *rc);
int mxfs_ilock_fallible(struct xfs_inode *ip, uint flags);
int mxfs_readdir_refused(struct xfs_inode *dp, const char *stage, int rc);
int mxfs_lookup_refused(struct xfs_inode *dp, const char *stage, int rc);
uint8_t mxfs_task_recovery_phase(void);
struct mxfs_icwr_entry * mxfs_icwr_get(struct xfs_mount *mp, xfs_daddr_t daddr, bool create);
long mxfs_f4_open_for_dir(struct xfs_mount *mp, uint64_t dir_ino, int *unknown_out);
void mxfs_relbar_f4_census(struct xfs_inode *ip, long f4_open, int f4_unknown, const char *site);
void mxfs_dlm_relbar_check(struct xfs_inode *ip, const char *arm);
void mxfs_relbar_epoch_check(struct xfs_inode *ip);
void mxfs_rel_state_set(struct xfs_inode *ip, u8 state);
bool mxfs_relbar_close_or_defer(struct xfs_inode *ip, const char *arm, struct mxfs_release_cert *cert);
void mxfs_inode_relcert_finish(struct xfs_inode *ip, struct mxfs_release_cert *cert, int cas_result, uint64_t t0);
void mxfs_inode_relcert_defer(struct xfs_inode *ip, struct mxfs_release_cert *cert, uint64_t t0);
unsigned int mxfs_inode_defer_causes(struct xfs_inode *ip, const struct mxfs_release_cert *cert);
bool mxfs_inode_episode_expired_locked(struct xfs_inode *ip);
bool mxfs_inode_defer_arm(struct xfs_inode *ip, unsigned int causes);
void mxfs_inode_wedge(struct xfs_inode *ip, struct mxfs_release_cert *cert, bool teardown);
bool mxfs_dlm_relog_authorized( struct xfs_inode *ip, const char *site, uint32_t disk_gen);
void mxfs_dbg_rel_pause( struct xfs_inode *ip, unsigned int stage);
bool mxfs_dbg_rel_fail( struct xfs_inode *ip, unsigned int kind);
void mxfs_drain_watch_arm( struct mxfs_drain_watch *w, struct xfs_inode *ip, int site);
void mxfs_drain_watch_disarm( struct mxfs_drain_watch *w);
void mxfs_dlm_bast_process( struct xfs_inode *ip);
void mxfs_dlm_bast_work_fn( struct work_struct *work);
void mxfs_dlm_bast_dwork_fn( struct work_struct *work);
unsigned long mxfs_dlm_dir_tenure_keep_delay( struct xfs_inode *ip);
void mxfs_dlm_sf_tenure_arm( struct xfs_inode *ip, unsigned long delay_j);
bool mxfs_noino_inflight_try_add(struct xfs_mount *mp, uint64_t ino);
void mxfs_noino_inflight_remove(struct xfs_mount *mp, uint64_t ino);
bool mxfs_noino_inflight_contains(struct xfs_mount *mp, uint64_t ino);
void mxfs_release_coalesced_flush( struct xfs_mount *mp);
bool mxfs_noino_drain_fence( struct xfs_mount *mp, uint64_t ino, int landed);
void mxfs_dlm_noino_bast_work_fn( struct work_struct *work);
bool mxfs_noino_lifecycle_park( struct xfs_mount *mp, uint64_t ino, uint8_t requested_mode, enum xfs_ino_lifecycle lc);
void mxfs_dlm_bast_notify( void *data, uint64_t ino, uint8_t requested_mode);
void __mxfs_dlm_bast_notify( struct xfs_mount *mp, uint64_t ino, uint8_t requested_mode, bool allow_requeue);
void mxfs_ex_epoch_churn_check(struct xfs_inode *ip, int line);
void mxfs_dlm_reload_inode( struct xfs_inode *ip, uint8_t expect_ftype, bool post_release);
void mxfs_dlm_reload_inode_under( struct xfs_inode *ip, uint8_t expect_ftype, bool post_release, bool under_grant);
struct xfs_dir2_sf_entry * mxfs_sf_find(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *h, const uint8_t *name, int namelen);
void mxfs_dir_sf_capture_base(struct xfs_inode *ip, const void *img, uint32_t bytes);
void mxfs_dir_sf_release_base(struct xfs_inode *ip, bool held_ex);
bool mxfs_dir_sf_merge_into(struct xfs_inode *ip, struct xfs_dir2_sf_hdr *base, struct xfs_dir2_sf_hdr *ours, struct xfs_dir2_sf_hdr *theirs, uint32_t theirs_bytes, int *ours_only_dirs);
void mxfs_dir_sf_premerge_for_release(struct xfs_inode *ip);
void mxfs_dir_sf_refresh_if_disk_differs(struct xfs_inode *ip);
bool mxfs_iclus_routed(struct xfs_inode *ip);
bool mxfs_dlm_iclus_covered(struct xfs_inode *ip);
int mxfs_dlm_inode_lock_routed(struct xfs_inode *ip, uint8_t mode, uint64_t gen_snap);
void mxfs_dlm_ilock_begin( struct xfs_inode *ip, uint8_t mode);
void mxfs_dlm_ilock_end( struct xfs_inode *ip, uint8_t mode);
bool mxfs_dlm_unpublish_drop( struct xfs_inode *ip);
void mxfs_dlm_creator_baseline_query( struct xfs_inode *ip, unsigned int site);
void mxfs_dlm_publish_unpublished( struct xfs_mount *mp, xfs_ino_t parent_ino, xfs_agnumber_t agno);
void mxfs_reap_sched(struct xfs_mount *mp, unsigned int delay_ms, const char *why);
void mxfs_defer_reap_add_mode(struct xfs_mount *mp, uint64_t ino, uint32_t gen, int16_t bucket, uint8_t kind);
void mxfs_reap_worker(struct work_struct *work);
void mxfs_iunl_store_purge_ag(struct xfs_mount *mp, xfs_agnumber_t agno, const char *why);
bool mxfs_pubob_drop_ino(struct xfs_mount *mp, uint64_t ino);
struct mxfs_pubob *mxfs_pubob_find_locked(struct xfs_mount *mp, uint64_t ino);
void mxfs_pubob_discharge(struct xfs_mount *mp, struct xfs_inode *ip, const char *why);
void mxfs_ag_dlm_wait_demote( struct xfs_perag *pag);
bool mxfs_ag_handoff_closing( struct xfs_perag *pag);
void mxfs_ag_bcache_pin_census( struct xfs_perag *pag, unsigned int *pinned, unsigned int *inail);
void mxfs_freepub_claim_clear(struct xfs_inode *ip, const char *why);
void mxfs_ag_handoff_commit( struct xfs_perag *pag, const char *who, atomic64_t *stat);
bool mxfs_buf_has_uncheckpointed_mods(struct xfs_buf *bp);
bool mxfs_dir_buf_is_undestaged(struct xfs_buf *bp);
void mxfs_ag_meta_coldread_discard(struct xfs_perag *pag, bool fresh_peer);
int mxfs_ag_buf_disk_differs(struct xfs_buf *bp);
void mxfs_acq_fresh_durability_probe(struct xfs_perag *pag);
uint64_t mxfs_inode_disk_di_size(struct xfs_inode *ip, uint16_t *modep, uint32_t *genp);
void mxfs_dlm_evict_inode_cb(void *data, uint64_t ino, uint32_t gen, uint32_t type);
int __mxfs_ag_dlm_lock( struct xfs_mount *mp, struct xfs_perag *pag, bool nonblock, bool demand, bool resfree);
int mxfs_ag_dlm_lock( struct xfs_mount *mp, struct xfs_perag *pag);
int mxfs_ag_dlm_lock_resfree( struct xfs_mount *mp, struct xfs_perag *pag);
int mxfs_ag_dlm_trylock( struct xfs_mount *mp, struct xfs_perag *pag);
void mxfs_dlm_ag_drain_alloc_buflist( struct xfs_mount *mp, struct xfs_perag *pag);
void mxfs_dlm_ag_drain_alloc_buflist_nowait( struct xfs_mount *mp, struct xfs_perag *pag);
int mxfs_p87_read_home_dinode( struct xfs_perag *pag, xfs_agino_t agino, uint32_t *nlink, uint32_t *next_unl, uint32_t *gen, uint16_t *mode);
void mxfs_agifc_audit_coverage(const char *site);
void mxfs_agifc_release_audit( struct xfs_perag *pag, const char *site);
int mxfs_p86_agi_unlinked_publish_audit( struct xfs_perag *pag);
void mxfs_dlm_ag_drain_inode_buffers( struct xfs_perag *pag);
const char * mxfs_agmeta_name(struct xfs_buf *bp);
void mxfs_dlm_ag_drain_meta_buffers( struct xfs_perag *pag);
void mxfs_dlm_pr_sweep_trigger(struct xfs_mount *mp);
void mxfs_oblf_note( struct xfs_mount *mp, int slot, int state, uint32_t victim_node, uint64_t victim_epoch, uint32_t pub_seq, uint64_t ag_mask, bool fswide);
void mxfs_dlm_obl_cb( void *data, int slot, int state, uint32_t victim_node, uint64_t victim_epoch, uint32_t pub_seq, uint64_t ag_mask, bool fswide);
void mxfs_release_cert_emit(const struct mxfs_release_cert *rc);
bool mxfs_ag_strand_inject_hit(xfs_agnumber_t agno, const char *src);
void mxfs_ag_dlm_unlock( struct xfs_mount *mp, struct xfs_perag *pag);
bool mxfs_inode_dlm_defer_bast( struct xfs_trans *tp, struct xfs_inode *ip);
void mxfs_trans_drain_inode_unlocks( struct xfs_trans *tp);
void mxfs_dlm_ag_bast_notify( void *data, uint32_t agno, uint8_t mode);
void mxfs_pubob_unlock_census( struct xfs_perag *pag, const char *path);
void mxfs_ag_release_publish_gate( struct xfs_perag *pag, const char *path);
void mxfs_dlm_ag_bast_work_fn( struct work_struct *work);
unsigned int mxfs_dlm_invalidate_ag_meta( struct xfs_perag *pag, unsigned int *ag_preserved);
bool mxfs_buf_is_ag_metadata( struct xfs_buf *bp);
uint64_t mxfs_dir_buf_owner(struct xfs_buf *bp);
int mxfs_dlm_invalidate_cached_views( struct xfs_mount *mp);
int mxfs_dlm_peer_joined_flush( void *data);
int mxfs_dlm_join_prepare( void *data);
void mxfs_dlm_join_commit( void *data);
int mxfs_survivor_sweep_slot( struct xfs_mount *mp, unsigned int dead_slot);
int mxfs_own_bucket_rescan( struct xfs_mount *mp);
int mxfs_unclaimed_bucket_scan( struct xfs_mount *mp);
void mxfs_dlm_fence_notify( void *data, int reason);
int mxfs_dlm_quarantine_cb( void *data, int victim_slot, const struct mxfs_recov_outcome *oc);
int mxfs_freplay_classify_terminal( struct xfs_mount *mp, unsigned int slot);
int mxfs_dlm_quar_covers_cb( void *data, const struct mxfs_resource_id *res);
int mxfs_dlm_closure_classify_cb( void *data, const struct mxfs_resource_id *res, uint64_t ag_mask);
void mxfs_barrier_note_open_cases( struct xfs_mount *mp, uint64_t open, uint64_t *published);
int mxfs_freplay_park_census( struct xfs_mount *mp, unsigned int slot, struct mxfs_freplay_verdict *fv);
int mxfs_freplay_publish_refusal( struct xfs_mount *mp, unsigned int slot, struct mxfs_freplay_verdict *fv, int rrc);
void mxfs_dlm_foreign_replay_work_fn( struct work_struct *work);
void mxfs_dlm_dead_node_notify( void *data, uint32_t dead_slot);
void mxfs_dlm_clean_depart_notify( void *data, uint32_t slot);
void mxfs_dlm_stuck_work_fn( struct work_struct *work);
void mxfs_dlm_stuck_notify( void *data);
int mxfs_recovery_blocked_show( struct seq_file *m, void *data);
int mxfs_inode_authority_show( struct seq_file *m, void *data);
ssize_t mxfs_caw_pw_selftest_write( struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
ssize_t mxfs_caw_samenode_selftest_write( struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
ssize_t mxfs_inject_unheld_agmeta_dirty_write( struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
ssize_t mxfs_dbg_ail_push_write( struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
int mxfs_ailpin_stats_show( struct seq_file *m, void *data);
int mxfs_acquire_degraded_show( struct seq_file *m, void *data);
int mxfs_alloc_witness_open( struct inode *inode, struct file *file);
ssize_t mxfs_alloc_witness_write( struct file *file, const char __user *ubuf, size_t len, loff_t *ppos);
int mxfs_alloc_witness_chunk_open( struct inode *inode, struct file *file);
ssize_t mxfs_alloc_witness_chunk_write( struct file *file, const char __user *ubuf, size_t len, loff_t *ppos);
ssize_t mxfs_dbg_lu_reset_admit_write( struct file *file, const char __user *ubuf, size_t len, loff_t *ppos);
ssize_t mxfs_dbg_lu_reset_barrier_write( struct file *file, const char __user *ubuf, size_t len, loff_t *ppos);
ssize_t mxfs_dbg_lu_reset_fence_write( struct file *file, const char __user *ubuf, size_t len, loff_t *ppos);
bool mxfs_iclus_open_admit(struct xfs_mount *mp, uint64_t ino);
int mxfs_iclus_lock(struct xfs_mount *mp, uint64_t ino, uint8_t mode, struct mxfs_grant_result *gres);
int mxfs_iclus_unlock(struct xfs_mount *mp, uint64_t ino, uint8_t mode, bool is_free);
bool mxfs_iclus_try_admit(struct xfs_mount *mp, uint64_t ino, uint8_t mode);
uint8_t mxfs_iclus_granted_mode(struct xfs_mount *mp, uint64_t ino);
uint64_t mxfs_iclus_grant_seq(struct xfs_mount *mp, uint64_t ino);
void mxfs_iclus_bast_notify(void *data, uint64_t base_ino, uint8_t req_mode);

#endif /* __XFS_MXFS_DLM_PRIV_H__ */
