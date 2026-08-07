// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
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
#include "xfs_inode_item.h"
#include "xfs_quota.h"
#include "xfs_trace.h"
#include "xfs_icache.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_bmap_util.h"
#include "xfs_dquot_item.h"
#include "xfs_dquot.h"
#include "xfs_reflink.h"
#include "xfs_ialloc.h"
#include "xfs_ag.h"
#include "xfs_log_priv.h"
#include "xfs_health.h"
#include "xfs_da_format.h"
#include "xfs_dir2.h"
#include "xfs_metafile.h"
#include "xfs_mxfs_dlm.h"
#include "../dlm/v5_mount.h"

/* sess23: igrab() call-site attribution — see mxfs_igrab_tracked(). */
#define igrab(vi) mxfs_igrab_tracked((vi), __LINE__, 2)
#define iput(vi) mxfs_iput_tracked((vi), __LINE__, 2)
#include <mxfs/mxfs_dlm.h>

#include <linux/iversion.h>

/* Radix tree tags for incore inode tree. */

/* inode is to be reclaimed */
#define XFS_ICI_RECLAIM_TAG	0
/* Inode has speculative preallocations (posteof or cow) to clean. */
#define XFS_ICI_BLOCKGC_TAG	1

/*
 * The goal for walking incore inodes.  These can correspond with incore inode
 * radix tree tags when convenient.  Avoid existing XFS_IWALK namespace.
 */
enum xfs_icwalk_goal {
	/* Goals directly associated with tagged inodes. */
	XFS_ICWALK_BLOCKGC	= XFS_ICI_BLOCKGC_TAG,
	XFS_ICWALK_RECLAIM	= XFS_ICI_RECLAIM_TAG,
};

static int xfs_icwalk(struct xfs_mount *mp,
		enum xfs_icwalk_goal goal, struct xfs_icwalk *icw);
static int xfs_icwalk_ag(struct xfs_perag *pag,
		enum xfs_icwalk_goal goal, struct xfs_icwalk *icw);

/*
 * ccloopff21 sess1: record the task holding pag_ici_lock, mirroring
 * mxfs_ag_stamp_holder (xfs_mxfs_dlm.c) for pag_dlm_lock.  Diagnostic only —
 * chasing a soft lockup (kworker/u10, kworker/u11, bash all spinning
 * forever) that followed an XFS_ALL_IRECLAIM_FLAGS assert at line ~3210
 * during fence_during_write@8/caw.  Caller must already hold pag_ici_lock.
 */
static inline void
mxfs_ici_stamp_holder(struct xfs_perag *pag)
{
	pag->pag_ici_holder_pid = current->pid;
	strscpy(pag->pag_ici_holder_comm, current->comm,
		sizeof(pag->pag_ici_holder_comm));
	pag->pag_ici_held_since = jiffies;
}

/*
 * ccloop 703f15c3 sess1: the holder-stamp fields above were written on every
 * acquire but never consumed — no capture existed to name a stuck holder when
 * the lockup this diagnostic is chasing actually happens.  This is that
 * consumer: a spin_lock-equivalent (same non-blocking, non-preemptible
 * semantics — cpu_relax busy-wait, no scheduling) that additionally prints
 * the current holder's pid/comm/hold-time if the wait exceeds 5s.  Purely
 * diagnostic: identical locking behavior to spin_lock(), the only difference
 * is the stuck-holder print.
 */
void
mxfs_ici_lock(struct xfs_perag *pag)
{
	unsigned long	start = jiffies;

	while (!spin_trylock(&pag->pag_ici_lock)) {
		if (time_after(jiffies, start + HZ * 5)) {
			pr_warn_ratelimited(
				"mxfs: P-ICI-STUCK agno=%u waiting for pag_ici_lock held_by pid=%d comm=%s held_ms=%u\n",
				pag_agno(pag), pag->pag_ici_holder_pid,
				pag->pag_ici_holder_comm,
				jiffies_to_msecs(jiffies - pag->pag_ici_held_since));
			start = jiffies;
		}
		cpu_relax();
	}
	mxfs_ici_stamp_holder(pag);
}

/*
 * Private inode cache walk flags for struct xfs_icwalk.  Must not
 * coincide with XFS_ICWALK_FLAGS_VALID.
 */

/* Stop scanning after icw_scan_limit inodes. */
#define XFS_ICWALK_FLAG_SCAN_LIMIT	(1U << 28)

#define XFS_ICWALK_FLAG_RECLAIM_SICK	(1U << 27)
#define XFS_ICWALK_FLAG_UNION		(1U << 26) /* union filter algorithm */

#define XFS_ICWALK_PRIVATE_FLAGS	(XFS_ICWALK_FLAG_SCAN_LIMIT | \
					 XFS_ICWALK_FLAG_RECLAIM_SICK | \
					 XFS_ICWALK_FLAG_UNION)

/* Marks for the perag xarray */
#define XFS_PERAG_RECLAIM_MARK	XA_MARK_0
#define XFS_PERAG_BLOCKGC_MARK	XA_MARK_1

static inline xa_mark_t ici_tag_to_mark(unsigned int tag)
{
	if (tag == XFS_ICI_RECLAIM_TAG)
		return XFS_PERAG_RECLAIM_MARK;
	ASSERT(tag == XFS_ICI_BLOCKGC_TAG);
	return XFS_PERAG_BLOCKGC_MARK;
}

/*
 * ccloop c7ee71c6 sess23 — D-UNMOUNT-BUSY-INODES leak detector.
 *
 * Every allocated xfs_inode joins this list and leaves it in the RCU free
 * callback (the last instant before kmem_cache_free), so the list is an exact
 * mirror of the slab's live objects.  xfs_destroy_caches() consults it right
 * before kmem_cache_destroy(xfs_inode_cache), which is precisely where the
 * kernel reports "Slab cache still has objects" — so the survivor is named
 * with its full state instead of being an anonymous slab object.
 *
 * Cost is one spin_lock/list_add on alloc and one on free.  The list is
 * per-node (no cluster traffic) and inode alloc already takes several locks;
 * measured to be off the critical path.  mxfs.live_inode_track=0 disables it.
 */
DEFINE_SPINLOCK(mxfs_live_inodes_lock);
LIST_HEAD(mxfs_live_inodes);
int mxfs_live_inode_track = 1;
atomic64_t mxfs_live_inode_allocs = ATOMIC64_INIT(0);

/*
 * Report any xfs_inode still alive at module unload.  Called from
 * xfs_destroy_caches() immediately before kmem_cache_destroy(xfs_inode_cache).
 * By this point every superblock is gone, so anything here is a genuine leak:
 * a reference that was taken and never dropped.
 */
void
mxfs_report_leaked_inodes(void)
{
	struct xfs_inode	*ip;
	unsigned long		flags;
	int			n = 0;

	spin_lock_irqsave(&mxfs_live_inodes_lock, flags);
	list_for_each_entry(ip, &mxfs_live_inodes, i_mxfs_live_link) {
		struct inode *vip = VFS_I(ip);

		n++;
		if (n > 16)
			continue;
		pr_warn("mxfs: P202-LEAKED-INODE-AT-UNLOAD ino=%llu ip=%px icount=%d i_state=0x%lx mode=0%o nlink=%u iflags=0x%lx pincount=%d dlm_mode=%u dlm_state=%u ex_h=%u pr_h=%u pin=%u bast_pending=%d unpublished=%d stale_src=%u bastq_src=%u itemp=%d in_ail=%d age_ms=%u GRAB=file%u:line%u dwork_pending=%d dwork_timer=%d bwork_pending=%d unpub_linked=%d demoter=%d dentries=%d lru_linked=%d sblist_linked=%d hashed=%d wcount=%d iget_caller=%pS — xfs_inode still allocated at module unload; this is why kmem_cache_destroy(mxfs_inode) reports objects in use\n",
			(unsigned long long)ip->i_ino, ip,
			atomic_read(&vip->i_count), vip->i_state,
			vip->i_mode, vip->i_nlink, ip->i_flags,
			atomic_read(&ip->i_pincount),
			ip->i_dlm_mode, ip->i_dlm_state,
			ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
			ip->i_dlm_pin_count,
			ip->i_dlm_bast_pending ? 1 : 0,
			ip->i_dlm_unpublished ? 1 : 0,
			ip->i_dlm_stale_src, ip->i_dlm_bastq_src,
			ip->i_itemp ? 1 : 0,
			(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
			jiffies_to_msecs(jiffies - ip->i_mxfs_alloc_jiffies),
			ip->i_mxfs_grab_file, ip->i_mxfs_grab_line,
			delayed_work_pending(&ip->i_dlm_bast_dwork) ? 1 : 0,
			timer_pending(&ip->i_dlm_bast_dwork.timer) ? 1 : 0,
			work_pending(&ip->i_dlm_bast_work) ? 1 : 0,
			list_empty(&ip->i_dlm_unpub_link) ? 0 : 1,
			ip->i_dlm_demoter ? 1 : 0,
			hlist_empty(&vip->i_dentry) ? 0 : 1,
			list_empty(&vip->i_lru) ? 0 : 1,
			list_empty(&vip->i_sb_list) ? 0 : 1,
			hlist_unhashed(&vip->i_hash) ? 0 : 1,
			atomic_read(&vip->i_writecount),
			(void *)ip->i_mxfs_iget_ret);
		/*
		 * ccloop c7ee71c6 sess27 — P206-OWNERS, the OWNERSHIP question.
		 *
		 * Every pairing-based instrument has now failed here (global
		 * grab/release balance, the refcount-level table, and the
		 * final-tenure scoping added this session, which measured its
		 * own failure at tenure_grabs=499).  Per the RULE-5 GPT consult
		 * the right question is not "who incremented and never
		 * decremented" but "WHICH OWNER OBJECT still contains this
		 * inode".  drgn/crash/gdb and debug symbols are all absent from
		 * the test nodes, so the reverse-search has to be done from
		 * inside the module — which is fine for the VFS structures that
		 * pin an inode INVISIBLY and that nothing has ruled out yet.
		 *
		 * Each of these holds (or implies something holds) a reference:
		 *   fsnotify   an fsnotify mark connector pins the inode
		 *   flctx      a file_lock_context implies open file state
		 *   iprivate   fs/device private pointer (xfs uses it for RT
		 *              zones on S_ISREG; a DIRECTORY with it set is
		 *              anomalous)
		 *   nrpages    page cache still attached
		 *   readcount  files open read-only
		 *   dentries   printed as a COUNT, not the boolean above — a
		 *              hashed inode with one lingering alias reads as
		 *              "0 dentries" in the boolean and is invisible
		 */
		{
			int	nd = 0;
			struct dentry *de;

			hlist_for_each_entry(de, &vip->i_dentry, d_u.d_alias)
				nd++;
			pr_warn("mxfs: P206-OWNERS ino=%llu fsnotify=%d flctx=%d iprivate=%d nrpages=%lu readcount=%d dentry_count=%d i_state=0x%lx i_opflags=0x%x — which OWNER object still contains this inode\n",
				(unsigned long long)ip->i_ino,
				rcu_access_pointer(vip->i_fsnotify_marks) ? 1 : 0,
				vip->i_flctx ? 1 : 0,
				vip->i_private ? 1 : 0,
				vip->i_data.nrpages,
				atomic_read(&vip->i_readcount),
				nd, vip->i_state, (unsigned)vip->i_opflags);
		}
		/*
		 * sess26 P205-REFBAL — which HALF of the code holds the survivor.
		 *
		 * P203-LEVEL names the grab occupying each refcount level but is
		 * sound only under LIFO release order, so it cannot prove who
		 * leaked.  This does not depend on order at all:
		 *   net == icount  -> the survivor came through mxfs_igrab_tracked,
		 *                     i.e. an MXFS igrab site still holds it.
		 *   net == 0       -> every tracked grab was matched; the survivor
		 *                     is an UNTRACKED xfs_iget reference whose plain
		 *                     iput never came, which points at the
		 *                     lookup/VFS handoff rather than MXFS's own
		 *                     igrab sites.
		 * Anything in between means both, and the difference from icount is
		 * how many untracked references survive.
		 */
		pr_warn("mxfs: P205-REFBAL ino=%llu icount=%d tgrabs=%u tputs=%u net=%d verdict=%s\n",
			(unsigned long long)ip->i_ino,
			atomic_read(&vip->i_count),
			(unsigned int)ip->i_mxfs_tgrabs,
			(unsigned int)ip->i_mxfs_tputs,
			(int)ip->i_mxfs_tgrabs - (int)ip->i_mxfs_tputs,
			((int)ip->i_mxfs_tgrabs - (int)ip->i_mxfs_tputs) ==
				atomic_read(&vip->i_count) ? "BALANCED-XFS-SIDE (an XFS/MXFS grab is unreleased)" :
			((int)ip->i_mxfs_tgrabs - (int)ip->i_mxfs_tputs) == 0 ?
				"XFS-SIDE-BALANCED (survivor is a VFS-side ref: dentry/d_splice_alias path)" :
				"UNEXPLAINED (VFS igrab/iput outside both chokepoints)");
		/*
		 * Replay the reference-event ring oldest-first.  The grab with
		 * no matching release below it is the leak.  kind 1 = xfs_iget
		 * handed a ref to this caller, 0 = xfs_irele from this caller,
		 * 2/3 = igrab/iput inside a tagged MXFS file (printed as
		 * file:line, since those sites are macro-tagged not IP-tagged).
		 */
		/*
		 * sess25: the OUTSTANDING-GRAB STACK is the answer; the ring
		 * below is only corroborating history.  Anything still on this
		 * stack is a grab with no matching release — i.e. the leak
		 * itself, named by site.  A nonzero under= means a release was
		 * paired against a grab older than tracking, so the stack's
		 * pairing assumption failed and its contents must not be
		 * trusted for that inode.
		 */
		{
			int	k;

			/*
			 * sess27: the table is now scoped to the FINAL busy
			 * tenure (cleared at every i_count->0 in
			 * xfs_fs_drop_inode), so the LIFO objection that made
			 * the sess25/26 reading unsound no longer applies —
			 * there is only one tenure's worth of grabs in it.
			 *
			 * tenure_grabs=0 is a RESULT, not a missing
			 * measurement: no MXFS-tracked site opened the final
			 * tenure, so the surviving reference came from a VFS
			 * path (ihold/__iget) unhookable from a filesystem.
			 * zero_seq=0 instead means this inode NEVER passed
			 * through i_count==0 on our watch, which would
			 * contradict lru_linked=1 and indicts the instrument.
			 */
			pr_warn("mxfs: P203-GRABLEVELS ino=%llu icount=%d over=%u zero_seq=%u tenure_grabs=%u tenure_age_ms=%u lru_linked=%d verdict=%s — slot N names the grab that took i_count to N WITHIN THE FINAL TENURE; with icount=1 slot 1 IS the outstanding reference\n",
				(unsigned long long)ip->i_ino,
				atomic_read(&vip->i_count),
				ip->i_mxfs_grabst_over,
				ip->i_mxfs_zero_seq,
				ip->i_mxfs_tenure_grabs,
				ip->i_mxfs_zero_seq ?
				  jiffies_to_msecs(jiffies -
					ip->i_mxfs_zero_jiffies) : 0,
				list_empty(&vip->i_lru) ? 0 : 1,
				ip->i_mxfs_zero_seq == 0 ?
				  "NEVER-HIT-ZERO (instrument suspect: contradicts lru_linked)" :
				ip->i_mxfs_tenure_grabs == 0 ?
				  "VFS-SIDE (no MXFS-tracked grab opened the final tenure)" :
				  "MXFS-SIDE (a tracked grab opened the final tenure — see LEVEL[1])");
			for (k = 0; k < MXFS_GRABST_N; k++) {
				unsigned long who = ip->i_mxfs_grabst[k];

				if (!who)
					continue;
				/* kind 2 = igrab inside a tagged MXFS file
				 * (packed file:line); kind 1 = xfs_iget handing
				 * out a ref (a raw return address). */
				if (ip->i_mxfs_grabst_kind[k] == 2)
					pr_warn("mxfs:   P203-LEVEL[%d] site=file%lu:line%lu\n",
						k + 1, who >> 32,
						who & 0xffffffffUL);
				else
					pr_warn("mxfs:   P203-LEVEL[%d] %pS\n",
						k + 1, (void *)who);
			}
		}
		{
			int	k;

			for (k = 0; k < MXFS_REFEV_N; k++) {
				int	idx = (ip->i_mxfs_refev_head + k) %
						MXFS_REFEV_N;
				unsigned long	who = ip->i_mxfs_refev_ip[idx];
				unsigned char	kind = ip->i_mxfs_refev_kind[idx];

				if (!who)
					continue;
				if (kind >= 2)
					pr_warn("mxfs:   P202-REFEV[%d] %s site=file%lu:line%lu count_after=%u\n",
						k, kind == 2 ? "GRAB" : "RELE",
						who >> 32, who & 0xffffffffUL,
						ip->i_mxfs_refev_cnt[idx]);
				else
					pr_warn("mxfs:   P202-REFEV[%d] %s %pS count_after=%u\n",
						k, kind == 1 ? "IGET" : "IRELE",
						(void *)who,
						ip->i_mxfs_refev_cnt[idx]);
			}
		}
	}
	spin_unlock_irqrestore(&mxfs_live_inodes_lock, flags);

	/*
	 * ALWAYS print, including leaked=0.  A probe that is silent when clean
	 * cannot be told apart from a probe that never ran (or from a registry
	 * that was never populated), and this session has already been burned
	 * twice by counting probes that were not measuring what they seemed to.
	 * `tracked=` is the running total of allocations so a zero leak count
	 * comes with proof that the registry was live.
	 */
	pr_warn("mxfs: P202-LEAKED-INODE-TOTAL leaked=%d tracked_allocs=%llu track_enabled=%d (printed at most 16)\n",
		n, (unsigned long long)atomic64_read(&mxfs_live_inode_allocs),
		mxfs_live_inode_track);
}

/*
 * Allocate and initialise an xfs_inode.
 */
struct xfs_inode *
xfs_inode_alloc(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	struct xfs_inode	*ip;

	/*
	 * XXX: If this didn't occur in transactions, we could drop GFP_NOFAIL
	 * and return NULL here on ENOMEM.
	 */
	ip = alloc_inode_sb(mp->m_super, xfs_inode_cache, GFP_KERNEL | __GFP_NOFAIL);

	if (inode_init_always(mp->m_super, VFS_I(ip))) {
		kmem_cache_free(xfs_inode_cache, ip);
		return NULL;
	}

	/* VFS doesn't initialise i_mode or i_state on 6.8! */
	VFS_I(ip)->i_mode = 0;
	VFS_I(ip)->i_state = 0;
	mapping_set_folio_min_order(VFS_I(ip)->i_mapping,
				    M_IGEO(mp)->min_folio_order);

	XFS_STATS_INC(mp, vn_active);
	ASSERT(atomic_read(&ip->i_pincount) == 0);
	ASSERT(ip->i_ino == 0);

	/* initialise the xfs inode */
	ip->i_ino = ino;
	ip->i_mount = mp;
	memset(&ip->i_imap, 0, sizeof(struct xfs_imap));
	ip->i_cowfp = NULL;
	memset(&ip->i_af, 0, sizeof(ip->i_af));
	ip->i_af.if_format = XFS_DINODE_FMT_EXTENTS;
	memset(&ip->i_df, 0, sizeof(ip->i_df));
	ip->i_flags = 0;
	ip->i_delayed_blks = 0;
	ip->i_diflags2 = mp->m_ino_geo.new_diflags2;
	ip->i_nblocks = 0;
	ip->i_forkoff = 0;
	ip->i_sick = 0;
	ip->i_checked = 0;
	INIT_WORK(&ip->i_ioend_work, xfs_end_io);
	INIT_LIST_HEAD(&ip->i_ioend_list);
	spin_lock_init(&ip->i_ioend_lock);
	ip->i_next_unlinked = NULLAGINO;
	ip->i_prev_unlinked = 0;
	ip->i_unlinked_bucket = -1;
	atomic_set(&ip->i_mxfs_open_n, 0);
	ip->i_mxfs_open_pub = false;
	ip->i_mxfs_open_setting = false;

	/* MXFS DLM lock cache */
	mxfs_dlm_inode_init(ip);

	/* sess23: join the live registry (see mxfs_report_leaked_inodes). */
	INIT_LIST_HEAD(&ip->i_mxfs_live_link);
	ip->i_mxfs_alloc_jiffies = jiffies;
	if (mxfs_live_inode_track) {
		unsigned long	flags;

		spin_lock_irqsave(&mxfs_live_inodes_lock, flags);
		list_add(&ip->i_mxfs_live_link, &mxfs_live_inodes);
		spin_unlock_irqrestore(&mxfs_live_inodes_lock, flags);
		atomic64_inc(&mxfs_live_inode_allocs);
	}

	return ip;
}

STATIC void
xfs_inode_free_callback(
	struct rcu_head		*head)
{
	struct inode		*inode = container_of(head, struct inode, i_rcu);
	struct xfs_inode	*ip = XFS_I(inode);

	switch (VFS_I(ip)->i_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		xfs_idestroy_fork(&ip->i_df);
		break;
	}

	xfs_ifork_zap_attr(ip);

	/* sess14: free the 3-way shortform-merge base snapshot, if any. */
	if (ip->i_dlm_dir_sf_base) {
		kfree(ip->i_dlm_dir_sf_base);
		ip->i_dlm_dir_sf_base = NULL;
		ip->i_dlm_dir_sf_base_bytes = 0;
	}

	/* sess65: free the pending local-dirent replay list, if any. */
	if (ip->i_dlm_dir_pending) {
		kfree(ip->i_dlm_dir_pending);
		ip->i_dlm_dir_pending = NULL;
		ip->i_dlm_dir_pending_bytes = 0;
	}

	/* sess34: free the per-tenure drain-merge removed-set, if any. */
	if (ip->i_dlm_dir_removed) {
		kfree(ip->i_dlm_dir_removed);
		ip->i_dlm_dir_removed = NULL;
		ip->i_dlm_dir_removed_n = 0;
		ip->i_dlm_dir_removed_cap = 0;
	}

	if (ip->i_cowfp) {
		xfs_idestroy_fork(ip->i_cowfp);
		kmem_cache_free(xfs_ifork_cache, ip->i_cowfp);
	}
	if (ip->i_itemp) {
		ASSERT(!test_bit(XFS_LI_IN_AIL,
				 &ip->i_itemp->ili_item.li_flags));
		xfs_inode_item_destroy(ip);
		ip->i_itemp = NULL;
	}

	/*
	 * sess23: leave the live registry.  This is the last instant before the
	 * object returns to the slab, so the list stays an exact mirror of the
	 * cache's live objects.  list_del_init() (not list_del) so a double
	 * free would be visible rather than corrupting the list.
	 */
	if (!list_empty(&ip->i_mxfs_live_link)) {
		unsigned long	flags;

		spin_lock_irqsave(&mxfs_live_inodes_lock, flags);
		list_del_init(&ip->i_mxfs_live_link);
		spin_unlock_irqrestore(&mxfs_live_inodes_lock, flags);
	}

	/*
	 * sess29: the slab does NOT zero this object on the next allocation, so
	 * a demoter claim still set here is inherited by whatever inode lands on
	 * this memory next and makes mxfs_foreign_demoter() true for it from
	 * birth — a permanent strand nothing can own or clear.  Must be the last
	 * thing before the free.
	 */
	mxfs_dlm_inode_final_release(ip);

	kmem_cache_free(xfs_inode_cache, ip);
}

static void
__xfs_inode_free(
	struct xfs_inode	*ip)
{
	/* asserts to verify all state is correct here */
	ASSERT(atomic_read(&ip->i_pincount) == 0);
	ASSERT(!ip->i_itemp || list_empty(&ip->i_itemp->ili_item.li_bio_list));
	XFS_STATS_DEC(ip->i_mount, vn_active);

	call_rcu(&VFS_I(ip)->i_rcu, xfs_inode_free_callback);
}

void
xfs_inode_free(
	struct xfs_inode	*ip)
{
	ASSERT(!xfs_iflags_test(ip, XFS_IFLUSHING));

	/*
	 * sess5 shadow ledger — DISCARD-LEAK probe: freeing an inode whose
	 * nlink==0 state still holds a +1 in s_remove_count (flag set)
	 * means no __destroy_inode dec will ever run for it — the counter
	 * leaks +1 permanently (remount-ro -EBUSY forever).  Upstream shape:
	 * xfs_iget_cache_miss reads a FREED dinode (from_disk set_nlink(0)
	 * INCS), then xfs_iget_check_free_state fails the lookup and
	 * out_destroy lands here with no VFS destroy.  Rare upstream; COMMON
	 * under MXFS cross-node reuse (dirent visible while peer freed the
	 * ino).  Evidence first (capped print), rebalance fix after proof.
	 */
	if (VFS_I(ip)->i_nlink == 0 &&
	    xfs_iflags_test(ip, MXFS_IF_RMC_ACCT)) {
		static atomic_t p9dl_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p9dl_n) <= 30) {
			pr_alert("mxfs: P9-RMC-DISCARD-LEAK ino=%llu rmcnt=%ld last0=%pS comm=%s — freeing accounted-zero inode with no destroy dec (+1 leak)\n",
				(unsigned long long)ip->i_ino,
				atomic_long_read(&VFS_I(ip)->i_sb->s_remove_count),
				ip->i_rmc_last0_ra, current->comm);
			dump_stack();
		}
	}

	/*
	 * Because we use RCU freeing we need to ensure the inode always
	 * appears to be reclaimed with an invalid inode number when in the
	 * free state. The ip->i_flags_lock provides the barrier against lookup
	 * races.
	 */
	spin_lock(&ip->i_flags_lock);
	ip->i_flags = XFS_IRECLAIM;
	ip->i_ino = 0;
	spin_unlock(&ip->i_flags_lock);

	__xfs_inode_free(ip);
}

/*
 * Queue background inode reclaim work if there are reclaimable inodes and there
 * isn't reclaim work already scheduled or in progress.
 */
static void
xfs_reclaim_work_queue(
	struct xfs_mount        *mp)
{

	rcu_read_lock();
	if (xfs_group_marked(mp, XG_TYPE_AG, XFS_PERAG_RECLAIM_MARK)) {
		queue_delayed_work(mp->m_reclaim_workqueue, &mp->m_reclaim_work,
			msecs_to_jiffies(xfs_syncd_centisecs / 6 * 10));
	}
	rcu_read_unlock();
}

/*
 * Background scanning to trim preallocated space. This is queued based on the
 * 'speculative_prealloc_lifetime' tunable (5m by default).
 */
static inline void
xfs_blockgc_queue(
	struct xfs_perag	*pag)
{
	struct xfs_mount	*mp = pag_mount(pag);

	if (!xfs_is_blockgc_enabled(mp))
		return;

	rcu_read_lock();
	if (radix_tree_tagged(&pag->pag_ici_root, XFS_ICI_BLOCKGC_TAG))
		queue_delayed_work(mp->m_blockgc_wq, &pag->pag_blockgc_work,
				   secs_to_jiffies(xfs_blockgc_secs));
	rcu_read_unlock();
}

/* Set a tag on both the AG incore inode tree and the AG radix tree. */
static void
xfs_perag_set_inode_tag(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	unsigned int		tag)
{
	bool			was_tagged;

	lockdep_assert_held(&pag->pag_ici_lock);

	was_tagged = radix_tree_tagged(&pag->pag_ici_root, tag);
	radix_tree_tag_set(&pag->pag_ici_root, agino, tag);

	if (tag == XFS_ICI_RECLAIM_TAG)
		pag->pag_ici_reclaimable++;

	if (was_tagged)
		return;

	/* propagate the tag up into the pag xarray tree */
	xfs_group_set_mark(pag_group(pag), ici_tag_to_mark(tag));

	/* start background work */
	switch (tag) {
	case XFS_ICI_RECLAIM_TAG:
		xfs_reclaim_work_queue(pag_mount(pag));
		break;
	case XFS_ICI_BLOCKGC_TAG:
		xfs_blockgc_queue(pag);
		break;
	}

	trace_xfs_perag_set_inode_tag(pag, _RET_IP_);
}

/* Clear a tag on both the AG incore inode tree and the AG radix tree. */
static void
xfs_perag_clear_inode_tag(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	unsigned int		tag)
{
	lockdep_assert_held(&pag->pag_ici_lock);

	/*
	 * Reclaim can signal (with a null agino) that it cleared its own tag
	 * by removing the inode from the radix tree.
	 */
	if (agino != NULLAGINO)
		radix_tree_tag_clear(&pag->pag_ici_root, agino, tag);
	else
		ASSERT(tag == XFS_ICI_RECLAIM_TAG);

	if (tag == XFS_ICI_RECLAIM_TAG)
		pag->pag_ici_reclaimable--;

	if (radix_tree_tagged(&pag->pag_ici_root, tag))
		return;

	/* clear the tag from the pag xarray */
	xfs_group_clear_mark(pag_group(pag), ici_tag_to_mark(tag));
	trace_xfs_perag_clear_inode_tag(pag, _RET_IP_);
}

/*
 * Find the next AG after @pag, or the first AG if @pag is NULL.
 */
static struct xfs_perag *
xfs_perag_grab_next_tag(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	int			tag)
{
	return to_perag(xfs_group_grab_next_mark(mp,
			pag ? pag_group(pag) : NULL,
			ici_tag_to_mark(tag), XG_TYPE_AG));
}

/*
 * When we recycle a reclaimable inode, we need to re-initialise the VFS inode
 * part of the structure. This is made more complex by the fact we store
 * information about the on-disk values in the VFS inode and so we can't just
 * overwrite the values unconditionally. Hence we save the parameters we
 * need to retain across reinitialisation, and rewrite them into the VFS inode
 * after reinitialisation even if it fails.
 */
static int
xfs_reinit_inode(
	struct xfs_mount	*mp,
	struct inode		*inode)
{
	int			error;
	uint32_t		nlink = inode->i_nlink;
	uint32_t		generation = inode->i_generation;
	uint64_t		version = inode_peek_iversion(inode);
	umode_t			mode = inode->i_mode;
	dev_t			dev = inode->i_rdev;
	kuid_t			uid = inode->i_uid;
	kgid_t			gid = inode->i_gid;

	error = inode_init_always(mp->m_super, inode);

	/*
	 * sess9(a9a03929) RULE-4 s_remove_count skew ledger (see P9-NLEDGE in
	 * xfs_inode_buf.c).  inode_init_always RAW-writes __i_nlink=1 (no
	 * accounting), so recycling an nlink==0 corpse makes the set_nlink(0)
	 * below re-INCREMENT s_remove_count for a zero-state that was already
	 * accounted — a permanent +1 skew per recycle-at-zero.  Ledger it.
	 */
	if (nlink == 0) {
		static atomic_t p9rc_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p9rc_n) <= 4000)
			pr_warn("mxfs: P9-NLEDGE reinit0 ino=%llu rmcnt=%ld acct=%d comm=%s\n",
				(unsigned long long)XFS_I(inode)->i_ino,
				atomic_long_read(&inode->i_sb->s_remove_count),
				xfs_iflags_test(XFS_I(inode), MXFS_IF_RMC_ACCT) ? 1 : 0,
				current->comm);
	}
	/*
	 * sess5 shadow ledger: inode_init_always above RAW-wrote __i_nlink=1,
	 * so mxfs_set_nlink(0) below goes through clear_nlink and INCS
	 * s_remove_count — correct re-accounting, because the corpse's prior
	 * zero was dec'd by __destroy_inode at VFS eviction (which also
	 * cleared the flag).  A flag still SET here means the destroy-side
	 * dec never ran for this corpse — the double-inc anomaly.
	 */
	if (nlink == 0 && xfs_iflags_test(XFS_I(inode), MXFS_IF_RMC_ACCT)) {
		static atomic_t p9di_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p9di_n) <= 50) {
			pr_alert("mxfs: P9-RMC-REINIT0-STILL-ACCT ino=%llu rmcnt=%ld comm=%s — recycled corpse still flagged accounted (destroy dec missing?)\n",
				(unsigned long long)XFS_I(inode)->i_ino,
				atomic_long_read(&inode->i_sb->s_remove_count),
				current->comm);
			dump_stack();
		}
		/* raw 1 was just written; the accounted zero it replaced was
		 * unpaired — drop the stale flag so mxfs_set_nlink(0) below
		 * re-arms it against the clear_nlink inc it performs. */
		xfs_iflags_clear(XFS_I(inode), MXFS_IF_RMC_ACCT);
	}
	/*
	 * sess5 (b68r1 -45 flood): the corpse still carries I_FREEING|I_CLEAR
	 * here — xfs_iget_recycle stamps I_NEW only after we return — and
	 * mxfs_set_nlink's corpse-raw arm would swallow the re-accounting
	 * inc this restore must perform.  This inode is becoming LIVE again:
	 * re-open its VFS accounting before the nlink restore.
	 */
	inode->i_state = 0;
	mxfs_set_nlink(XFS_I(inode), nlink);
	inode->i_generation = generation;
	inode_set_iversion_queried(inode, version);
	inode->i_mode = mode;
	inode->i_rdev = dev;
	inode->i_uid = uid;
	inode->i_gid = gid;
	/* 6.8: inode_init_always doesn't reset i_state; clear stale flags */
	inode->i_state = 0;
	mapping_set_folio_min_order(inode->i_mapping,
				    M_IGEO(mp)->min_folio_order);
	return error;
}

/*
 * Carefully nudge an inode whose VFS state has been torn down back into a
 * usable state.  Drops the i_flags_lock and the rcu read lock.
 */
static int
xfs_iget_recycle(
	struct xfs_perag	*pag,
	struct xfs_inode	*ip,
	bool			deadshell_create)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct inode		*inode = VFS_I(ip);
	int			error;

	trace_xfs_iget_recycle(ip);

	/*
	 * ccloop cc87fed3 sess6: RULE 4 direct-evidence probe (Fable-guided,
	 * P135-PRSWEEP-CYCLE root cause hunt).  PROVEN via live capture
	 * (P139-RECYCLE-UNLINKED, 14 hits in one repro, always on a reused
	 * ino under directory churn + fault_netpartition, always via the
	 * CREATE path xfs_create -> xfs_icreate -> xfs_iget -> [cache-hit,
	 * IRECLAIMABLE, this function]): xfs_iget_recycle is regularly
	 * called on a struct inode whose i_sb_list is ALREADY empty (VFS's
	 * own evict() -> inode_sb_list_del() -> list_del_init() has already
	 * run on it), while still reachable via the per-AG radix tree (only
	 * removed near the very end of xfs_reclaim_inode's own teardown).
	 *
	 * TRIED AND REVERTED (sess6): auto-healing by calling
	 * inode_sb_list_add(inode) right here made things WORSE, not
	 * better -- re-validating with that fix live, P135's cycle length
	 * grew (visited=17 on the first hit, vs visited=2-3 pre-fix) and
	 * dir_reuse_coherency itself started timing out. Blindly re-linking
	 * an orphaned struct is not simply restoring a missing invariant --
	 * something about this specific struct/ino is ALREADY wrong by the
	 * time we get here (most likely: a DIFFERENT, newer struct inode
	 * object already legitimately owns this ino number via a fresh
	 * xfs_iget_cache_miss, and this one is a genuine zombie that must
	 * NOT be resurrected, only diagnosed). Left as diagnostic-only
	 * pending a correct fix; do not re-add the auto-heal without new
	 * proof it's safe.
	 */
	if (unlikely(list_empty(&inode->i_sb_list))) {
		static atomic_t p139_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p139_n) <= 200)
			pr_warn("mxfs: P139-RECYCLE-UNLINKED ino=0x%llx ip=%px pid=%d comm=%s — recycling an inode whose i_sb_list is ALREADY empty (already evicted by someone else)\n",
				(unsigned long long)ip->i_ino, ip, current->pid,
				current->comm);
	} else {
		/*
		 * ccloop cc87fed3 sess7: RULE 4 -- the P141-SETUP-DOUBLE-ADD
		 * evidence (xfs_setup_inode, pal/linux/xfs_iops.c) proves the
		 * actual corruption precursor is the OPPOSITE of what P139
		 * checks: xfs_fs_destroy_inode (the only site that sets
		 * XFS_IRECLAIMABLE) is called exclusively from generic VFS
		 * evict(), strictly AFTER inode_sb_list_del() already ran as
		 * part of that SAME evict() call -- so list_empty()==true at
		 * recycle entry is the universal, by-construction case, and
		 * P139 firing is expected/harmless.  This branch is the rare
		 * (should-be-impossible-by-construction) case: an
		 * IRECLAIMABLE inode whose i_sb_list is STILL linked.  This
		 * is the direct precursor to the later P141 double-add.  Full
		 * context here (CREATE flag, mode, nlink) to identify why.
		 */
		static atomic_t p142_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p142_n) <= 200)
			pr_warn("mxfs: P142-RECYCLE-STILL-LINKED ino=0x%llx ip=%px pid=%d comm=%s count=%d nlink=%u mode=0%o — recycling an IRECLAIMABLE inode whose i_sb_list is STILL LINKED (next=%px prev=%px)\n",
				(unsigned long long)ip->i_ino, ip, current->pid,
				current->comm, atomic_read(&inode->i_count),
				inode->i_nlink, inode->i_mode,
				inode->i_sb_list.next, inode->i_sb_list.prev);
	}

	ASSERT(!rwsem_is_locked(&inode->i_rwsem));
	error = xfs_reinit_inode(mp, inode);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);

	/*
	 * sess2 (a9a03929) STALE-BAST-ON-RECYCLE FIX (P2G/P2D proven): a
	 * recycled in-core inode is a NEW incarnation, but the DLM bast
	 * bookkeeping of the PREVIOUS incarnation (i_dlm_bast_pending +
	 * state=BAST, left behind after its unlink/inactivation released the
	 * slot) survives xfs_reinit_inode.  The MHT dwork then fires at the
	 * first quiescent sample after the fresh create and runs a FULL
	 * drain+release of the just-granted EX (P2D-DRAINWHY in_ail=1
	 * fields=0x1 on the create's own txn, ~7-14ms) — for every recycled
	 * file in the create wave (P2G dlm_state=2 at icreate on 59/84
	 * samples), and the next op re-acquires.  Clear the stale signal:
	 * the prior incarnation's tenure is over (its release already ran or
	 * the master granted us EX fresh — no waiter was ahead), and any
	 * bast for THIS incarnation can only arrive after the fresh grant,
	 * i.e. after this reset.  DEMOTING is left alone (an active demoter
	 * owns it).  The still-queued dwork bails on !i_dlm_bast_pending.
	 */
	spin_lock(&ip->i_dlm_lock);
	ip->i_dlm_bast_pending = false;
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_BAST)
		ip->i_dlm_state = (ip->i_dlm_mode == MXFS_LOCK_NL) ?
			MXFS_DLM_ISTATE_NONE : MXFS_DLM_ISTATE_CACHED;
	spin_unlock(&ip->i_dlm_lock);

	/*
	 * mxfs: a reclaimable inode in a cluster may have been FREED and
	 * REUSED by a peer for a different incarnation/type while it sat
	 * idle in our cache (we hold no DLM on an idle inode → no BAST
	 * invalidated it).  xfs_reinit_inode() PRESERVES the old mode/forks
	 * and does NOT re-read disk, so a plain recycle would resurrect the
	 * stale prior incarnation (wrong type/size/content).  When the
	 * inode was flagged stale (xfs_lookup's reuse-evict, or a prior
	 * BAST), re-read the current dinode from disk now: the inode is
	 * exclusively ours here (XFS_IRECLAIM set, no other users), so a
	 * full re-type is safe, and xfs_setup_existing_inode() — run by
	 * xfs_iget on XFS_INEW below — then wires the correct iops for the
	 * fresh mode.  Equivalent to a cache-miss read for content+type.
	 *
	 * GATED ON GENERATION MISMATCH: we only adopt the on-disk image when
	 * its di_gen differs from our preserved in-core generation — i.e. the
	 * number was genuinely re-allocated to a DIFFERENT incarnation.  When
	 * the generation matches, this is the SAME incarnation we cached (just
	 * reclaimed-then-reaccessed locally), so the in-core image is correct
	 * and may even be AHEAD of disk (a write not yet destaged); re-reading
	 * would clobber our good size with a stale disk-0 (the sess39
	 * RELOAD-SIZE-DROP regression).  So: reused (gen differs) → trust disk;
	 * same incarnation → keep in-core.  xfs_reinit_inode preserved
	 * i_generation, so the compare is valid.
	 */
	if (!error && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    /*
	     * ccloop-4dd7: a peer-freed dead shell may arrive with
	     * i_dlm_stale unset (the peer freed it without ever BASTing our
	     * per-inode DLM), so a deferred-deadshell CREATE forces the disk
	     * re-read regardless — the P-RECYCLE-SANITIZE / reject arms
	     * below resolve the shell from the platter verdict.
	     */
	    (ip->i_dlm_stale || deadshell_create)) {
		struct xfs_buf	*rbp = NULL;
		struct xfs_buf	*stale_bp = NULL;
		bool		p91_protected = false;
		void		*sr_tmp = NULL;

		if (xfs_buf_incore(mp->m_ddev_targp, ip->i_imap.im_blkno,
				   ip->i_imap.im_len, 0, &stale_bp) == 0) {
			/*
			 * sess91 ROOT FIX: never clear XBF_DONE on a cluster
			 * buffer that carries this node's logged-but-not-
			 * checkpointed modification to a co-resident inode —
			 * the re-read would clobber it (P90-FUA-OVER-LOGGED).
			 * See the matching guard in xfs_iget_cache_miss.
			 */
			if (mxfs_buf_has_uncheckpointed_mods(stale_bp)) {
				pr_warn_ratelimited(
				    "mxfs: P91-RECYCLE-PROTECT ino=0x%llx blkno=0x%llx flags=0x%x — keeping in-core authoritative cluster buffer\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_imap.im_blkno,
				    stale_bp->b_flags);
				p91_protected = true;
			} else {
				/* P20 forensic: every cluster invalidate is
				 * logged — a later re-read of this daddr pulls
				 * PLATTER content, which under publish-only
				 * dirsig may predate our committed state.
				 * sess38 run14d: gated for ship. */
				if (unlikely(mxfs_dirwr_enabled ||
					     mxfs_instr_enabled))
					pr_warn_ratelimited(
					    "mxfs: P20-CLUSTER-INVAL site=recycle ino=0x%llx blkno=0x%llx flags=0x%x comm=%s\n",
					    (unsigned long long)ip->i_ino,
					    (unsigned long long)ip->i_imap.im_blkno,
					    stale_bp->b_flags, current->comm);
				xfs_buf_stale(stale_bp);
				stale_bp->b_flags &= ~XBF_DONE;
			}
			xfs_buf_relse(stale_bp);
		}
		if (xfs_imap_to_bp(mp, NULL, &ip->i_imap, &rbp) == 0) {
			struct xfs_dinode *dip =
				xfs_buf_offset(rbp, ip->i_imap.im_boffset);

			/*
			 * sess5 ROOT FIX (b70r1 shutdown, RULE-4 proven): when
			 * the cluster buffer is P91-PROTECTED (carries our
			 * uncheckpointed mods to a co-resident inode), the
			 * xfs_imap_to_bp read above is a CACHE HIT on that
			 * kept buffer — for a deferred-deadshell CREATE the
			 * verdict then evaluates PRE-FREE bytes: b70r1 read
			 * gen=...547 mode=0100644 from the kept buffer while
			 * the PLATTER already held the peer's destaged free
			 * (gen=...548 mode=0, seen by this same node 360ms
			 * earlier) → the DISKLIVE reject misfired -117 → a
			 * dirty xfs_trans_cancel shutdown on a healthy FS.
			 * Side-read the platter into a private buffer (P9-ICD
			 * pattern; never touches the protected cluster buf)
			 * and give the VERDICT the real disk bytes.
			 */
			if (deadshell_create && p91_protected) {
				extern int mxfs_pal_bdev_read_plain_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t sr_len = BBTOB(ip->i_imap.im_len);

				sr_tmp = ((sr_len & 511) == 0 && sr_len) ?
					kmalloc(sr_len, GFP_NOFS) : NULL;
				if (sr_tmp &&
				    mxfs_pal_bdev_read_plain_bdev(
					mp->m_ddev_targp->bt_bdev,
					(uint64_t)ip->i_imap.im_blkno +
					mp->m_ddev_targp->bt_sector_offset,
					sr_tmp, sr_len) == 0) {
					struct xfs_dinode *sdip = sr_tmp +
						ip->i_imap.im_boffset;

					if (sdip->di_mode != dip->di_mode ||
					    sdip->di_gen != dip->di_gen)
						pr_warn("mxfs: P-CR63-SIDEREAD ino=%llu cached[mode=0%o gen=%u] platter[mode=0%o gen=%u] — protected cluster buf lagged the platter; verdict uses platter\n",
							(unsigned long long)ip->i_ino,
							be16_to_cpu(dip->di_mode),
							be32_to_cpu(dip->di_gen),
							be16_to_cpu(sdip->di_mode),
							be32_to_cpu(sdip->di_gen));
					dip = sdip;
				}
			}

			/* sess70: decisive always-on diagnostic for the
			 * INODE-REUSE type-confusion residual.  When a stale
			 * inode is recycled, log disk di_mode/di_gen vs the
			 * preserved in-core gen + the gate decision.  If the
			 * gen-gate SKIPS (disk gen == incore gen) while the
			 * type differs, the stale DIR mode is kept = the bug. */
			pr_warn_ratelimited(
				"mxfs: P-RECYCLE-GATE ino=%llu disk_mode=0%o disk_gen=%u incore_mode=0%o incore_gen=%u adopt=%d\n",
				(unsigned long long)ip->i_ino,
				be16_to_cpu(dip->di_mode),
				be32_to_cpu(dip->di_gen),
				VFS_I(ip)->i_mode,
				VFS_I(ip)->i_generation,
				(be16_to_cpu(dip->di_mode) != 0 &&
				 (s32)(be32_to_cpu(dip->di_gen) -
				       VFS_I(ip)->i_generation) > 0) ? 1 : 0);

			if (deadshell_create &&
			    be16_to_cpu(dip->di_mode) != 0) {
				/*
				 * ccloop-4dd7: dialloc handed out this ino as
				 * free (inobt under AG DLM) yet the platter
				 * dinode is LIVE — genuine cross-node
				 * incoherence (double-alloc territory), not
				 * the peer-freed shell we deferred for.  Fail
				 * the recycle (flows into the re-add-to-
				 * reclaim recovery below); the create errors
				 * loudly instead of clobbering a live inode.
				 */
				pr_warn("mxfs: P-CR63-DEFER-DISKLIVE ino=%llu disk_mode=0%o disk_gen=%u incore_gen=%u — deferred deadshell CREATE found LIVE platter image; failing recycle\n",
					(unsigned long long)ip->i_ino,
					be16_to_cpu(dip->di_mode),
					be32_to_cpu(dip->di_gen),
					VFS_I(ip)->i_generation);
				error = -EFSCORRUPTED;
			} else if (be16_to_cpu(dip->di_mode) != 0 &&
			    /*
			     * ccloop-4dd7 ORDERING GUARD (RULE-4 proven, ino
			     * 1862 autopsy: adopt=1 of disk_gen 3097500574 OVER
			     * newer incore_gen 3097500575 resurrected a freed
			     * incarnation's extent map).  di_gen only moves
			     * forward (xfs_inode_uninit ++), so adopt ONLY a
			     * strictly NEWER disk image; an equal or OLDER gen
			     * is a lagging platter/cached read of a prior
			     * incarnation — keep the in-core state.
			     */
			    (s32)(be32_to_cpu(dip->di_gen) -
				  VFS_I(ip)->i_generation) > 0) {
				xfs_idestroy_fork(&ip->i_df);
				if (xfs_inode_has_attr_fork(ip))
					xfs_idestroy_fork(&ip->i_af);
				if (ip->i_cowfp) {
					xfs_idestroy_fork(ip->i_cowfp);
					kmem_cache_free(xfs_ifork_cache,
							ip->i_cowfp);
					ip->i_cowfp = NULL;
				}
				if (xfs_inode_from_disk(ip, dip) == 0) {
					i_size_write(VFS_I(ip),
						     ip->i_disk_size);
					/* ccloop-4dd7: adopted a DIFFERENT
					 * incarnation — the old life's
					 * local-unlink intent must not leak
					 * onto it (sess37 flag-leak). */
					xfs_iflags_clear(ip,
						MXFS_IF_LOCAL_UNLINK);
					/*
					 * sess68 (RULE 4): we just adopted a
					 * DIFFERENT incarnation of this reused dir
					 * inode#.  The cluster buffer was staled
					 * above, but the prior incarnation's dir
					 * DATA/LEAF blocks (owner==ino, at daddrs
					 * the new map may REUSE) are still cached
					 * with stale content — the ABA that durably
					 * drops a peer's just-created dirent / tears
					 * leaf-vs-data on the recycled dir
					 * (dir_reuse_coherency).  The cluster-inval
					 * does NOT cover them.  Evict by OWNER so the
					 * next read cold-FUA-fetches the coherent
					 * image.  Safe here: inode is exclusively
					 * ours (XFS_IRECLAIM), ILOCK dropped at 393. */
					if (S_ISDIR(VFS_I(ip)->i_mode))
						mxfs_dir_evict_owned_dir_blocks(ip, false);
				}
			} else if (deadshell_create &&
				   be16_to_cpu(dip->di_mode) == 0 &&
				   VFS_I(ip)->i_mode != 0) {
				/*
				 * ccloop-4dd7 FIX: peer-freed dead shell — the
				 * platter image is FREE while the in-core shell
				 * still carries the dead incarnation (the
				 * authorized xfs_inode_uninit ran on the PEER;
				 * the local INACT-SKIP authority guard never
				 * zeroed our copy).  Emulate the missed local
				 * uninit in-core reset here, in the same
				 * exclusive context the adopt path already
				 * relies on (XFS_IRECLAIM set, sole owner):
				 * destroy the stale fork state (the peer's
				 * truncate freed those blocks on disk long ago)
				 * and mark the shell free, adopting the disk
				 * generation (the peer's uninit bumped it).  A
				 * CREATE then reuses the clean shell
				 * (xfs_inode_init); a plain lookup correctly
				 * sees a free inode.
				 */
				xfs_idestroy_fork(&ip->i_df);
				if (xfs_inode_has_attr_fork(ip))
					xfs_idestroy_fork(&ip->i_af);
				if (ip->i_cowfp) {
					xfs_idestroy_fork(ip->i_cowfp);
					kmem_cache_free(xfs_ifork_cache,
							ip->i_cowfp);
					ip->i_cowfp = NULL;
				}
				ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
				ip->i_df.if_bytes = 0;
				ip->i_df.if_data = NULL;
				ip->i_df.if_nextents = 0;
				VFS_I(ip)->i_mode = 0;
				ip->i_disk_size = 0;
				i_size_write(VFS_I(ip), 0);
				ip->i_nblocks = 0;
				ip->i_forkoff = 0;
				ip->i_diflags = 0;
				ip->i_diflags2 = mp->m_ino_geo.new_diflags2;
				VFS_I(ip)->i_generation =
					be32_to_cpu(dip->di_gen);
				/* ccloop-4dd7: prior-life intent must not leak
				 * into the new life (sess37 flag-leak). */
				xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK | MXFS_IF_ADOPTED_UNLINK);
				pr_warn_ratelimited(
				    "mxfs: P-RECYCLE-SANITIZE ino=%llu disk_gen=%u — peer-freed dead shell reset to free (missed local uninit emulated)\n",
				    (unsigned long long)ip->i_ino,
				    be32_to_cpu(dip->di_gen));
			}
			xfs_buf_relse(rbp);
		}
		kfree(sr_tmp);
		ip->i_dlm_stale = false;
	}

	if (error) {
		/*
		 * Re-initializing the inode failed, and we are in deep
		 * trouble.  Try to re-add it to the reclaim list.
		 */
		rcu_read_lock();
		spin_lock(&ip->i_flags_lock);
		ip->i_flags &= ~(XFS_INEW | XFS_IRECLAIM);
		ASSERT(ip->i_flags & XFS_IRECLAIMABLE);
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();

		trace_xfs_iget_recycle_fail(ip);
		return error;
	}

	mxfs_ici_lock(pag);
	spin_lock(&ip->i_flags_lock);

	/*
	 * Clear the per-lifetime state in the inode as we are now effectively
	 * a new inode and need to return to the initial state before reuse
	 * occurs.
	 */
	ip->i_flags &= ~XFS_IRECLAIM_RESET_FLAGS;
	ip->i_flags |= XFS_INEW;
	xfs_perag_clear_inode_tag(pag, XFS_INO_TO_AGINO(mp, ip->i_ino),
			XFS_ICI_RECLAIM_TAG);
	inode_state_assign_raw(inode, I_NEW);
	spin_unlock(&ip->i_flags_lock);
	spin_unlock(&pag->pag_ici_lock);

	return 0;
}

/*
 * If we are allocating a new inode, then check what was returned is
 * actually a free, empty inode. If we are not allocating an inode,
 * then check we didn't find a free inode.
 *
 * Returns:
 *	0		if the inode free state matches the lookup context
 *	-ENOENT		if the inode is free and we are not allocating
 *	-EFSCORRUPTED	if there is any state mismatch at all
 */
static int
xfs_iget_check_free_state(
	struct xfs_inode	*ip,
	int			flags)
{
	if (flags & XFS_IGET_CREATE) {
		/* should be a free inode */
		if (VFS_I(ip)->i_mode != 0) {
			xfs_warn(ip->i_mount,
"Corruption detected! Free inode 0x%llx not marked free! (mode 0x%x)",
				ip->i_ino, VFS_I(ip)->i_mode);
			{
				struct xfs_buf *_dbp = NULL;
				if (xfs_buf_incore(ip->i_mount->m_ddev_targp,
					ip->i_imap.im_blkno, ip->i_imap.im_len,
					0, &_dbp) == 0) {
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: P7-INSTR corruption-buf ino=0x%llx "
						"blkno=%llu bli=%px dq=%d li=%d "
						"flags=0x%x dlm_stale=%d",
						ip->i_ino,
						(unsigned long long)ip->i_imap.im_blkno,
						_dbp->b_log_item,
						!!(_dbp->b_flags & _XBF_DELWRI_Q),
						!list_empty_careful(&_dbp->b_li_list),
						_dbp->b_flags,
						ip->i_dlm_stale);
					{
						unsigned int isz = ip->i_mount->m_sb.sb_inodesize;
						unsigned int off = (ip->i_ino &
						   (ip->i_mount->m_sb.sb_inopblock - 1)) * isz;
						uint16_t *p = (uint16_t *)((char *)_dbp->b_addr + off);
						mxfs_pal_log(MXFS_LOG_WARN,
							"mxfs: P9-INSTR corruption-disk ino=0x%llx off=%u "
							"magic=0x%04x mode=0x%04x ver=0x%02x fmt=0x%02x "
							"nlink=0x%04x",
							ip->i_ino, off,
							be16_to_cpu(p[0]), be16_to_cpu(p[1]),
							((uint8_t *)p)[4], ((uint8_t *)p)[5],
							be16_to_cpu(*((uint16_t *)((char *)p + 6))));
					}
					xfs_buf_relse(_dbp);
				} else {
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: P7-INSTR corruption-buf ino=0x%llx "
						"blkno=%llu NOT-IN-CACHE dlm_stale=%d",
						ip->i_ino,
						(unsigned long long)ip->i_imap.im_blkno,
						ip->i_dlm_stale);
				}
			}
			xfs_agno_mark_sick(ip->i_mount,
					XFS_INO_TO_AGNO(ip->i_mount, ip->i_ino),
					XFS_SICK_AG_INOBT);
			return -EFSCORRUPTED;
		}

		if (ip->i_nblocks != 0) {
			xfs_warn(ip->i_mount,
"Corruption detected! Free inode 0x%llx has blocks allocated!",
				ip->i_ino);
			{
				struct xfs_buf *_dbp = NULL;
				if (xfs_buf_incore(ip->i_mount->m_ddev_targp,
					ip->i_imap.im_blkno, ip->i_imap.im_len,
					0, &_dbp) == 0) {
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: P16-INSTR has-blocks-buf ino=0x%llx "
						"blkno=%llu bli=%px dq=%d li=%d "
						"flags=0x%x dlm_stale=%d nblocks=%llu",
						ip->i_ino,
						(unsigned long long)ip->i_imap.im_blkno,
						_dbp->b_log_item,
						!!(_dbp->b_flags & _XBF_DELWRI_Q),
						!list_empty_careful(&_dbp->b_li_list),
						_dbp->b_flags,
						ip->i_dlm_stale,
						(unsigned long long)ip->i_nblocks);
					{
						unsigned int isz = ip->i_mount->m_sb.sb_inodesize;
						unsigned int off = (ip->i_ino &
						   (ip->i_mount->m_sb.sb_inopblock - 1)) * isz;
						struct xfs_dinode *dip =
							(struct xfs_dinode *)((char *)_dbp->b_addr + off);
						mxfs_pal_log(MXFS_LOG_WARN,
							"mxfs: P16-INSTR has-blocks-disk ino=0x%llx off=%u "
							"magic=0x%04x mode=0x%04x ver=0x%02x fmt=0x%02x "
							"nlink=%u nblocks=%llu size=%lld",
							ip->i_ino, off,
							be16_to_cpu(dip->di_magic),
							be16_to_cpu(dip->di_mode),
							dip->di_version, dip->di_format,
							be32_to_cpu(dip->di_nlink),
							(unsigned long long)be64_to_cpu(dip->di_nblocks),
							(long long)be64_to_cpu(dip->di_size));
					}
					xfs_buf_relse(_dbp);
				} else {
					mxfs_pal_log(MXFS_LOG_WARN,
						"mxfs: P16-INSTR has-blocks-buf ino=0x%llx "
						"blkno=%llu NOT-IN-CACHE dlm_stale=%d nblocks=%llu",
						ip->i_ino,
						(unsigned long long)ip->i_imap.im_blkno,
						ip->i_dlm_stale,
						(unsigned long long)ip->i_nblocks);
				}
			}
			xfs_agno_mark_sick(ip->i_mount,
					XFS_INO_TO_AGNO(ip->i_mount, ip->i_ino),
					XFS_SICK_AG_INOBT);
			return -EFSCORRUPTED;
		}
		return 0;
	}

	/* should be an allocated inode */
	if (VFS_I(ip)->i_mode == 0) {
		/*
		 * sess38 P-IGET-ENOENT: a peer-allocated inode reachable via a
		 * now-visible parent dirent reads as mode==0 here -> ENOENT
		 * (concurrent-mkdir loser sees the winner's child as missing).
		 * Distinguish: cached cluster buffer stale (cached_disk_mode==0)
		 * vs in-core ip not refreshed from a good buffer (cached!=0).
		 */
		/*
		 * sess40 DIAGNOSTIC (always-on, rate-limited, multi-node only):
		 * fires when a path resolved to this inode but its in-core mode
		 * reads 0 -> the caller sees ENOENT for a name that exists on a
		 * peer.  cached_disk_mode distinguishes a stale on-disk inode
		 * cluster (==0: creator's iflush hasn't reached the cluster we
		 * read) from an in-core inode never refreshed from a good buffer
		 * (!=0).  Cheap: only reached when in-core mode==0.
		 */
		/*
		 * sess127: UNGATED (was instr-gated, which hid the decisive
		 * evidence — instr=1 is a 100x slowdown that masks the race).
		 * Fires only on the mode==0 -> ENOENT error path, rate-limited.
		 */
		{
		if (ip->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
			struct xfs_buf	*_b = NULL;

			/*
			 * This probe does SLEEPING I/O (xfs_buf_incore + a FUA
			 * SCSI read).  xfs_iget_check_free_state runs from the
			 * cache-HIT path (xfs_iget_cache_hit) while holding BOTH
			 * rcu_read_lock() AND ip->i_flags_lock (a spinlock) —
			 * preempt_count==2.  Sleeping there is "scheduling while
			 * atomic": the forced schedule lets an RCU grace period
			 * reclaim/free this inode under us => use-after-free =>
			 * inobt / inode-cluster corruption + fs shutdown.
			 * PROVEN this run: BUG scheduling-while-atomic in
			 * mxfs-worker (preempt_count=2) via the bast_notify
			 * XFS_IGET_INCORE iget, followed by inobt record
			 * corruption in AG8 / xfs_inactive_ifree shutdown.
			 * Only run the sleeping probe when preemption is enabled
			 * (no spinlock / RCU read-side held).
			 */
			if (!in_atomic() &&
			    xfs_buf_incore(ip->i_mount->m_ddev_targp,
					   ip->i_imap.im_blkno, ip->i_imap.im_len,
					   0, &_b) == 0 && _b) {
				unsigned int isz = ip->i_mount->m_sb.sb_inodesize;
				unsigned int off = (ip->i_ino &
				   (ip->i_mount->m_sb.sb_inopblock - 1)) * isz;
				struct xfs_dinode *dip =
				   (struct xfs_dinode *)((char *)_b->b_addr + off);
				/*
				 * sess40: also FUA-read the cluster straight from the
				 * backing store (past the SCST write cache) to tell a
				 * DURABILITY gap (fua_mode==0: creator never flushed the
				 * dinode to the platter) from a CACHING/ordering gap
				 * (fua_mode!=0: disk has it, our cached buf is stale).
				 */
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *bdev, uint64_t lba_512,
					void *buf, uint32_t len);
				int fua_mode = -1;
				void *pg = (void *)__get_free_page(GFP_NOFS);
				if (pg) {
					uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
						ip->i_mount->m_ddev_targp->bt_sector_offset;
					if (mxfs_pal_scsi_read_fua_bdev(
						ip->i_mount->m_ddev_targp->bt_bdev,
						lba, pg, 4096) == 0)
						fua_mode = be16_to_cpu(
						   ((struct xfs_dinode *)((char *)pg + off))->di_mode);
					free_page((unsigned long)pg);
				}
				pr_warn_ratelimited(
					"mxfs: P-IGET-ENOENT ino=0x%llx incore_mode=0 cached_disk_mode=0x%x fua_disk_mode=0x%x flags=0x%lx iget_flags=0x%x reclaimable=%d dlm_stale=%d buf_flags=0x%x\n",
					ip->i_ino, be16_to_cpu(dip->di_mode), fua_mode,
					ip->i_flags, flags,
					(ip->i_flags & XFS_IRECLAIMABLE) ? 1 : 0,
					ip->i_dlm_stale, _b->b_flags);
				xfs_buf_relse(_b);
			} else {
				pr_warn_ratelimited(
					"mxfs: P-IGET-ENOENT ino=0x%llx incore_mode=0 buf=NOT-CACHED-or-ATOMIC iget_flags=0x%x reclaimable=%d dlm_stale=%d\n",
					ip->i_ino, flags,
					(ip->i_flags & XFS_IRECLAIMABLE) ? 1 : 0,
					ip->i_dlm_stale);
			}
			/* sess4(a16ec5f2) DECISIVE: run27 proved the dangler
			 * ENOENTs (dlm_stale=1, !IRECLAIMABLE, iget_flags=0)
			 * take NEITHER cache_hit reuse branch (P4S=0,
			 * P-REUSE-RELOAD=0).  Name the actual call path. */
			if (ip->i_dlm_stale &&
			    !(ip->i_flags & XFS_IRECLAIMABLE)) {
				static atomic_t p4st_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p4st_n) <= 3) {
					pr_warn("mxfs: P4ST-ENOENT-STACK ino=0x%llx iget_flags=0x%x\n",
						ip->i_ino, flags);
					dump_stack();
				}
			}
		} }
		return -ENOENT;
	}

	return 0;
}

/* Make all pending inactivation work start immediately. */
static bool
xfs_inodegc_queue_all(
	struct xfs_mount	*mp)
{
	struct xfs_inodegc	*gc;
	int			cpu;
	bool			ret = false;

	for_each_cpu(cpu, &mp->m_inodegc_cpumask) {
		gc = per_cpu_ptr(mp->m_inodegc, cpu);
		if (!llist_empty(&gc->list)) {
			mod_delayed_work_on(cpu, mp->m_inodegc_wq, &gc->work, 0);
			ret = true;
		}
	}

	return ret;
}

/* Wait for all queued work and collect errors */
static int
xfs_inodegc_wait_all(
	struct xfs_mount	*mp)
{
	int			cpu;
	int			error = 0;

	flush_workqueue(mp->m_inodegc_wq);
	for_each_cpu(cpu, &mp->m_inodegc_cpumask) {
		struct xfs_inodegc	*gc;

		gc = per_cpu_ptr(mp->m_inodegc, cpu);
		if (gc->error && !error)
			error = gc->error;
		gc->error = 0;
	}

	return error;
}

/*
 * Check the validity of the inode we just found it the cache
 */
static int
xfs_iget_cache_hit(
	struct xfs_perag	*pag,
	struct xfs_inode	*ip,
	xfs_ino_t		ino,
	int			flags,
	int			lock_flags) __releases(RCU)
{
	struct inode		*inode = VFS_I(ip);
	struct xfs_mount	*mp = ip->i_mount;
	int			error;
	/*
	 * ccloop-4dd7: CREATE cache-hit a peer-freed IRECLAIMABLE dead shell
	 * (nlink==0, in-core mode never zeroed because the sess47 authority
	 * guard skipped local destructive inactivation).  When set, skip the
	 * fatal xfs_iget_check_free_state (dialloc's inobt-free verdict under
	 * AG DLM is authoritative — this is NOT corruption) and let the
	 * IRECLAIMABLE recycle path resolve the shell from disk evidence
	 * (P-RECYCLE-SANITIZE emulates the missed local xfs_inode_uninit).
	 */
	bool			cr63_defer_deadshell = false;

	/*
	 * check for re-use of an inode within an RCU grace period due to the
	 * radix tree nodes not being updated yet. We monitor for this by
	 * setting the inode number to zero before freeing the inode structure.
	 * If the inode has been reallocated and set up, then the inode number
	 * will not match, so check for that, too.
	 */
	spin_lock(&ip->i_flags_lock);
	if (ip->i_ino != ino)
		goto out_skip;

	/*
	 * If we are racing with another cache hit that is currently
	 * instantiating this inode or currently recycling it out of
	 * reclaimable state, wait for the initialisation to complete
	 * before continuing.
	 *
	 * If we're racing with the inactivation worker we also want to wait.
	 * If we're creating a new file, it's possible that the worker
	 * previously marked the inode as free on disk but hasn't finished
	 * updating the incore state yet.  The AGI buffer will be dirty and
	 * locked to the icreate transaction, so a synchronous push of the
	 * inodegc workers would result in deadlock.  For a regular iget, the
	 * worker is running already, so we might as well wait.
	 *
	 * XXX(hch): eventually we should do something equivalent to
	 *	     wait_on_inode to wait for these flags to be cleared
	 *	     instead of polling for it.
	 */
	if (ip->i_flags & (XFS_INEW | XFS_IRECLAIM | XFS_INACTIVATING))
		goto out_skip;

	if (ip->i_flags & XFS_NEED_INACTIVE) {
		/* Unlinked inodes cannot be re-grabbed. */
		if (VFS_I(ip)->i_nlink == 0) {
			/* <ccloop sess3> Multi-node reused-inode CREATE race (PROVEN
			 * root of the dir_reuse->fault-test 2/tcp cascade): xfs_dialloc
			 * handed out this ino (FREE cluster-wide in the inobt) but our
			 * local in-core copy is still NEED_INACTIVE (nlink=0) from this
			 * node's own recent rm whose inactivation hasn't run.  Upstream
			 * ENOENT here fatally cancels an already-DIRTY xfs_create trans
			 * -> shutdown.  For a CREATE, flush inodegc + retry (-EAGAIN) so
			 * the pending inactivation completes and the inode recycles. */
			extern int mxfs_create_needinact_flush;
			if (mxfs_create_needinact_flush && (flags & XFS_IGET_CREATE) &&
			    ip->i_mount->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
				pr_warn_ratelimited(
				    "mxfs: P-CR3-NEEDINACT ino=0x%llx CREATE reused-while-NEED_INACTIVE -> inodegc_flush+EAGAIN (was fatal ENOENT)\n",
					ip->i_ino);
				goto out_inodegc_flush;
			}
			error = -ENOENT;
			goto out_error;
		}
		goto out_inodegc_flush;
	}

	/*
	 * MXFS multi-node CREATE: the caller (xfs_dialloc) picked this ino
	 * from inobt under AG DLM hold, so inobt-says-free is authoritative
	 * cluster-wide.  But our local cached struct may carry stale
	 * allocated content from this node's prior use of the inode — the
	 * peer freed it under their AG hold without ever BASTing our
	 * per-inode DLM, so i_dlm_stale stays false and reclaim never ran
	 * locally.  Reading from disk doesn't help: xfs_ifree never writes
	 * zeros to a freed slot, so the on-disk content is the last
	 * iflushed alloc'd state.  Single-node v3 XFS sidesteps this by
	 * skipping the disk read on CREATE in cache_miss (xfs_iget_cache_miss
	 * line ~771) — we mirror that for cache_hit by resetting in-memory
	 * state to free in place.  IRECLAIMABLE inodes are handled by the
	 * existing recycle path below.  The mode/nblocks check breaks the
	 * retry loop: after the reset, the inode looks free and the next
	 * pass falls through.
	 */
	if (ip->i_mount->m_mxfs_dlm && (flags & XFS_IGET_CREATE) &&
	    (VFS_I(ip)->i_mode != 0 || ip->i_nblocks != 0)) {
		/*
		 * P-CR63 (RULE 4, pve1 ino-489 dialloc -117 autopsy): dialloc
		 * picked this ino under AG DLM hold, so free-cluster-wide is
		 * authoritative — yet the cached in-core struct still shows
		 * allocated content.  Three sub-cases arrive here; name which
		 * (field reads only — safe under rcu + i_flags_lock):
		 *  - VFS-live shell -> reset-for-create + EAGAIN (rescued);
		 *  - igrab failure  -> mid-teardown window, FALLS THROUGH to
		 *    the fatal check_free_state (hole);
		 *  - IRECLAIMABLE   -> dead shell whose i_mode was never
		 *    zeroed (peer freed the ino; local ifree never ran —
		 *    sess47 guard skips destructive inactivation), FALLS
		 *    THROUGH to the fatal check_free_state (hole; the pve1
		 *    shutdown signature: mode=0x81a4 dlm_stale=1 platter-free).
		 */
		bool cr63_reclaimable = !!(ip->i_flags & XFS_IRECLAIMABLE);

		pr_warn_ratelimited("mxfs: P-CR63-SHELL ino=0x%llx mode=0%o nlink=%u nblk=%llu iflags=0x%lx istate=0x%lx reclaimable=%d dlm_mode=%u dlm_state=%u stale=%d src=%u comm=%s\n",
			(unsigned long long)ip->i_ino, VFS_I(ip)->i_mode,
			VFS_I(ip)->i_nlink,
			(unsigned long long)ip->i_nblocks,
			ip->i_flags, VFS_I(ip)->i_state,
			cr63_reclaimable ? 1 : 0,
			ip->i_dlm_mode, ip->i_dlm_state,
			ip->i_dlm_stale ? 1 : 0, ip->i_dlm_stale_src,
			current->comm);

		if (!cr63_reclaimable) {
			struct inode *inode_grabbed = igrab(inode);

			if (inode_grabbed) {
				spin_unlock(&ip->i_flags_lock);
				rcu_read_unlock();
				mxfs_dlm_reset_inode_for_create(ip);
				iput(inode_grabbed);
				return -EAGAIN;
			}
			pr_warn("mxfs: P-CR63-IGRAB-FAIL ino=0x%llx istate=0x%lx — mid-teardown shell falls through to check_free_state\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_state);
		} else if (VFS_I(ip)->i_nlink == 0) {
			/*
			 * ccloop-4dd7 FIX (RULE-4 proven chain, vmrig ino 139:
			 * P19-B3DEC will_skip=1 b4_noauth=1 → INACT-SKIP-STALE →
			 * P-CR63-DEADSHELL → false "Corruption detected!" −117 →
			 * dirty trans_cancel → cluster-wide shutdown): a PEER
			 * freed this ino.  The local unlink left nlink==0, but
			 * the authority guard rightly skipped local destructive
			 * inactivation, so — unlike a locally-freed shell — its
			 * in-core mode/forks were never reset by
			 * xfs_inode_uninit.  The shell is dead; defer the free-
			 * state verdict to the recycle path's disk re-read.
			 */
			cr63_defer_deadshell = true;
			pr_warn("mxfs: P-CR63-DEADSHELL-DEFER ino=0x%llx nlink=0 stale=%d — peer-freed dead shell; deferring free-state check to recycle disk evidence\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_stale ? 1 : 0);
		} else {
			pr_warn("mxfs: P-CR63-DEADSHELL ino=0x%llx nlink=%u — IRECLAIMABLE stale-mode LINKED shell falls through to check_free_state\n",
				(unsigned long long)ip->i_ino, VFS_I(ip)->i_nlink);
		}
	}

	/*
	 * sess38: reused-inode cross-node coherency.
	 *
	 * A cached inode that looks FREE (mode==0) here may have been
	 * re-allocated by a PEER since this node last saw it free (inode
	 * numbers are reused after rm + inactivation; the freed incarnation
	 * lingers in-core as mode==0).  xfs_iget_check_free_state() below
	 * would then return -ENOENT for a non-CREATE lookup and the caller
	 * (e.g. a concurrent same-name mkdir re-check) would conclude the
	 * name does not exist and allocate a SECOND inode for it
	 * (split-brain; observed on the shared barrier dirs).  Re-read the
	 * inode from disk ONCE so a peer's allocation becomes visible.
	 *
	 * Loop-free: mxfs_dlm_reload_inode() invalidates the inode's cluster
	 * buffer (clearing the stale _XBF_FUA_FRESH) and re-reads from disk.
	 * If a peer allocated it, the in-core mode becomes non-zero -> we
	 * return -EAGAIN and the retry's (mode==0) guard no longer fires, so
	 * the lookup proceeds normally.  If it is genuinely free on disk,
	 * mode stays 0 and we fall through to check_free_state -> -ENOENT
	 * (no retry).  Only for multi-node, non-CREATE, non-reclaimable
	 * inodes we can pin via igrab; reclaimable freed inodes hit the
	 * recycle path and are left to a future fix.
	 */
	if (ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm) &&
	    !(flags & (XFS_IGET_CREATE | XFS_IGET_INCORE)) &&
	    !(ip->i_flags & XFS_IRECLAIMABLE) &&
	    VFS_I(ip)->i_mode == 0) {
		struct inode *inode_grabbed = igrab(inode);

		/*
		 * sess4(a16ec5f2) FIX B1 (RULE 4, run23 P-IGET-ENOENT proof:
		 * incore_mode=0 fua_disk_mode=0x81a4 flags=0x0 — disk VALID,
		 * live stale shell): if igrab fails the VFS inode is mid-
		 * teardown (the reader's own drop_caches races this lookup).
		 * Falling through returned -ENOENT for a name whose reallocated
		 * dinode is already durable — the persistent lookup_fail
		 * dangler.  Do what every other igrab-failure path here does:
		 * skip + retry; the retry finds the shell gone (cache miss)
		 * and reads the valid dinode fresh.
		 */
		if (!inode_grabbed)
			goto out_skip;

		if (inode_grabbed) {
			extern int mxfs_reuse_dlm;
			spin_unlock(&ip->i_flags_lock);
			rcu_read_unlock();
			mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
			/*
			 * sess40: if the cheap reload still reads free, the peer
			 * creator may not have flushed yet (Type-A).  Acquire the
			 * inode DLM PR to BAST the holder and force its flush, then
			 * reload again.  Gated by reuse_dlm (expensive); the
			 * rename_visibility subdir create-race needs it.
			 */
			if (mxfs_reuse_dlm && VFS_I(ip)->i_mode == 0) {
				mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
				mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
				mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
			}
			error = (VFS_I(ip)->i_mode != 0) ? -EAGAIN : -ENOENT;
			/* sess4(a16ec5f2): name the live-shell reload outcome —
			 * run25 shows disk-valid (0x81a4) inos ENOENTing with
			 * this branch armed; is it entered, and does the reload
			 * adopt? */
			{
				static atomic_t p4s_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p4s_n) <= 20000)
					pr_warn("mxfs: P4S-LIVESHELL-RELOAD ino=0x%llx post_mode=0%o err=%d dlm_stale=%d realns=%llu\n",
						ip->i_ino, VFS_I(ip)->i_mode,
						error, ip->i_dlm_stale,
						(unsigned long long)ktime_get_real_ns());
			}
			iput(inode_grabbed);
			return error;
		}
	}

	/*
	 * sess40: IRECLAIMABLE reused-inode cross-node coherency (the gap the
	 * sess38 fix above left open).  A locally-freed inode incarnation sits
	 * in-core as IRECLAIMABLE mode==0; a PEER then reuses that inode number
	 * for a new file/dir.  Because we hold no DLM lock on an idle freed
	 * inode, the peer's allocation never BASTs us, so the peer never flushes
	 * its new dinode to the platter — and check_free_state() below would
	 * return -ENOENT for the now-visible name (the persistent missing-dirent
	 * / EACCES that blocks cache_coherency; proven via P-IGET-ENOENT:
	 * incore_mode=0 fua_disk_mode=0 flags=IRECLAIMABLE dlm_stale=1).
	 *
	 * Unlike the non-reclaimable path above (a reload-from-disk suffices
	 * because a prior BAST already flushed the peer), here we must ACQUIRE
	 * the inode DLM lock first: the PR acquire BASTs the peer holder, which
	 * drains+flushes the new dinode to the backing store; only then does a
	 * reload read the real mode.  Pin the struct against reclaim with
	 * XFS_IRECLAIM (as the recycle path does), do the DLM-coordinated
	 * reload, then -EAGAIN.  Gated on i_dlm_stale, which reload clears, so
	 * the retry cannot re-enter this block — it falls through to
	 * check_free_state (mode!=0 -> recycle+return; still 0 -> genuine
	 * ENOENT).  Bounded, no loop.
	 */
	{ extern int mxfs_reuse_reload; if (mxfs_reuse_reload &&
	    ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm) &&
	    !(flags & (XFS_IGET_CREATE | XFS_IGET_INCORE)) &&
	    (ip->i_flags & XFS_IRECLAIMABLE) &&
	    !(ip->i_flags & XFS_IRECLAIM) &&
	    ip->i_dlm_stale &&
	    VFS_I(ip)->i_mode == 0) {
		ip->i_flags |= XFS_IRECLAIM;	/* block reclaim during reload */
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();

		/*
		 * sess40 perf: try the cheap reload-from-disk FIRST (no DLM
		 * round-trip).  Two observed sub-types of the reused-inode race:
		 *  - Type B (common): the peer's new dinode is ALREADY on disk
		 *    (fua_disk_mode!=0) and only our in-core struct is stale — a
		 *    plain reload reads the real mode, no BAST needed.
		 *  - Type A: disk still reads free (peer hasn't flushed) — only
		 *    then pay the DLM PR acquire, which BASTs the peer holder and
		 *    forces its drain+flush, and reload again.
		 * Avoids a DLM round-trip on every reused-inode iget under churn.
		 */
		mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
		{ extern int mxfs_reuse_dlm;
		if (mxfs_reuse_dlm && VFS_I(ip)->i_mode == 0) {
			/*
			 * sess40: the Type-A DLM PR round-trip (BAST the peer to
			 * force its flush) is needed only when the creator hasn't
			 * flushed yet.  It is EXPENSIVE per iget and over-fires on
			 * the unlink verify-gone phase (~480 deleted-file igets ->
			 * timeout).  Default OFF (cheap-only): rely on the cheap
			 * reload + the creator's eventual flush (tests have
			 * barriers/sleeps).  Toggle mxfs.reuse_dlm=1 to force it.
			 */
			mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
			mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
			mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
		} }

		/* sess4(a16ec5f2): UN-GATED (was instr-only, invisible in dirwr
		 * runs) — the r10 dangler autopsy needs this branch's outcome:
		 * did the cheap reload adopt the peer's valid dinode? */
		{
			static atomic_t p4rr_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p4rr_n) <= 20000)
				pr_warn("mxfs: P-REUSE-RELOAD ino=0x%llx post_mode=0%o dlm_mode=%u stale=%d realns=%llu\n",
					ip->i_ino, VFS_I(ip)->i_mode,
					ip->i_dlm_mode, ip->i_dlm_stale,
					(unsigned long long)ktime_get_real_ns());
		}

		spin_lock(&ip->i_flags_lock);
		ip->i_flags &= ~XFS_IRECLAIM;
		spin_unlock(&ip->i_flags_lock);
		return -EAGAIN;
	} }

	/*
	 * Check the inode free state is valid. This also detects lookup
	 * racing with unlinks.
	 *
	 * ccloop-4dd7: skipped for a peer-freed dead shell on a multi-node
	 * CREATE (see cr63_defer_deadshell above) — the recycle path below
	 * resolves the shell from disk evidence instead.
	 */
	if (!cr63_defer_deadshell) {
		error = xfs_iget_check_free_state(ip, flags);
		if (error)
			goto out_error;
	}

	/* Skip inodes that have no vfs state. */
	if ((flags & XFS_IGET_INCORE) &&
	    (ip->i_flags & XFS_IRECLAIMABLE))
		goto out_skip;

	/* The inode fits the selection criteria; process it. */
	if (ip->i_flags & XFS_IRECLAIMABLE) {
		/*
		 * We need to make it look like the inode is being reclaimed to
		 * prevent the actual reclaim workers from stomping over us
		 * while we recycle the inode.  We can't clear the radix tree
		 * tag yet as it requires pag_ici_lock to be held exclusive.
		 */
		if (!xfs_ilock_nowait(ip, XFS_ILOCK_EXCL))
			goto out_skip;
		ip->i_flags |= XFS_IRECLAIM;
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();

		error = xfs_iget_recycle(pag, ip, cr63_defer_deadshell);
		if (error)
			return error;
	} else {
		/* If the VFS inode is being torn down, pause and try again. */
		if (!igrab(inode))
			goto out_skip;

		/* We've got a live one. */
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();
		trace_xfs_iget_hit(ip);
	}

	/*
	 * sess45 P99: cache-HIT return of a regular file with in-core
	 * di_size==0.  If the medium has di_size!=0, this is a STALE CACHE
	 * HIT — the node holds a cached in-core inode it never refreshed (it
	 * holds no DLM on a peer's inode, so no BAST set i_dlm_stale) and
	 * returns the stale size.  That is the di_size=0 cross_write_read root.
	 */
	{ extern int mxfs_instr_enabled;
	  extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *, uint16_t *);
	  if (unlikely(mxfs_instr_enabled) &&
	      mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	      !(flags & XFS_IGET_INCORE) &&
	      S_ISREG(VFS_I(ip)->i_mode) && ip->i_disk_size == 0) {
		uint64_t dsz = mxfs_inode_disk_di_size(ip, NULL);
		pr_warn_ratelimited("mxfs: P99-IGET-HIT ino=%llu incore_size=0 disk_di_size=%lld dlm_mode=%u stale=%d (disk!=0 => STALE CACHE HIT)\n",
			(unsigned long long)ino, (long long)dsz,
			ip->i_dlm_mode, ip->i_dlm_stale);
	  } }

	if (lock_flags != 0)
		xfs_ilock(ip, lock_flags);

	if (!(flags & XFS_IGET_INCORE))
		xfs_iflags_clear(ip, XFS_ISTALE);
	XFS_STATS_INC(mp, xs_ig_found);

	return 0;

out_skip:
	trace_xfs_iget_skip(ip);
	XFS_STATS_INC(mp, xs_ig_frecycle);
	error = -EAGAIN;
out_error:
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();
	return error;

out_inodegc_flush:
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();
	/*
	 * Do not wait for the workers, because the caller could hold an AGI
	 * buffer lock.  We're just going to sleep in a loop anyway.
	 */
	if (xfs_is_inodegc_enabled(mp))
		xfs_inodegc_queue_all(mp);
	return -EAGAIN;
}

/*
 * sess19(ccloop): does the in-core cluster buffer show the inode at the given
 * byte offset as ALLOCATED (valid dinode magic + nonzero mode)?  Used to skip
 * the sess38 per-inode cluster re-stale when the cached image already proves
 * the inode exists (the sess38 ENOENT risk is strictly the cached-FREE case).
 * Conservative: any uncertainty (no b_addr, bad magic) returns false → stale.
 */
static bool
mxfs_dinode_cached_allocated(
	struct xfs_buf	*bp,
	int		boffset)
{
	struct xfs_dinode	*dip;

	if (!bp->b_addr)
		return false;
	dip = xfs_buf_offset(bp, boffset);
	return dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	       dip->di_mode != 0;
}

STATIC int
xfs_iget_cache_miss(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	xfs_trans_t		*tp,
	xfs_ino_t		ino,
	struct xfs_inode	**ipp,
	int			flags,
	int			lock_flags)
{
	struct xfs_inode	*ip;
	int			error;
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ino);
	bool			dlm_acquired = false;
	uint8_t			dlm_mode = MXFS_LOCK_NL;

	ip = xfs_inode_alloc(mp, ino);
	if (!ip)
		return -ENOMEM;

	error = xfs_imap(pag, tp, ip->i_ino, &ip->i_imap, flags);
	if (error)
		goto out_destroy;

	/*
	 * MXFS: acquire DLM lock before reading the inode from disk.
	 *
	 * xfs_ilock_nowait (called below at the tail of this function)
	 * skips the DLM hook for XFS_ILOCK — the comment there is correct
	 * for xfsaild/reclaim, but this path is process context and MUST
	 * cross-node-serialize with the node that last modified the inode.
	 * Without this, a freshly-created inode's cluster buffer on the
	 * remote node may not be flushed when we read it, and xfs_imap_to_bp
	 * below trips xfs_inode_buf_verify on all-zero data → FS shutdown.
	 *
	 * For XFS_IGET_CREATE we're the allocating node — there is no
	 * on-disk data to reload, so clear stale before acquiring so
	 * ilock_begin's reload path is skipped.  We hold DLM EX so any
	 * reader on another node will BAST us and we'll flush on release.
	 *
	 * Track whether we acquired so error paths below can release via
	 * mxfs_dlm_ilock_end — otherwise the holder count leaks and the
	 * lock never drops.  Particularly important for radix_tree_preload's
	 * -EAGAIN retry path: every retry re-enters this function, and a
	 * leak per retry accumulates into a stuck lock.
	 */
	if (mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    (lock_flags & (XFS_ILOCK_EXCL | XFS_ILOCK_SHARED))) {
		dlm_mode = (lock_flags & XFS_ILOCK_EXCL) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;

		if (flags & XFS_IGET_CREATE) {
			ip->i_dlm_stale = false;
			/*
			 * sess44 deferred-publish: this is the allocating node
			 * for a brand-new inode that no peer can see yet.  Grant
			 * the DLM lock LOCALLY (EX, cached) with NO disk CAW —
			 * the dominant rsync_paired cost is one CAW round-trip
			 * per new inode here.  We publish lazily (acquire a real
			 * slot) only when a peer BASTs a directory/AG that could
			 * lead them to this inode (mxfs_dlm_publish_unpublished),
			 * or drop it silently on local eviction.
			 */
			mxfs_dlm_grant_local_new(ip, dlm_mode);
		} else {
			mxfs_dlm_ilock_begin(ip, dlm_mode);
		}
		dlm_acquired = true;
	}

	/*
	 * For version 5 superblocks, if we are initialising a new inode, we
	 * simply build the new inode core with a random generation number.
	 *
	 * For version 4 (and older) superblocks, log recovery is dependent on
	 * the i_flushiter field being initialised from the current on-disk
	 * value and hence we must also read the inode off disk even when
	 * initializing new inodes.
	 */
	if (xfs_has_v3inodes(mp) && (flags & XFS_IGET_CREATE)) {
		VFS_I(ip)->i_generation = get_random_u32();
	} else {
		struct xfs_buf		*bp;

		/*
		 * MXFS: if we just acquired the DLM lock above, another node
		 * may have been holding EX and has flushed updated data to
		 * this inode's cluster LBA.  Our local buffer cache can still
		 * hold the pre-flush copy of the cluster (XBF_DONE set), and
		 * xfs_imap_to_bp would happily return it, causing
		 * xfs_inode_buf_verify to trip on a stale-but-valid or
		 * stale-and-corrupt buffer → fs shutdown.
		 *
		 * Stripped in 0.2.3 as "redundant given per-AG drain", but
		 * v0.2.3 perf testing (heavy dd + concurrent allocation)
		 * showed inode-0 verify failures and a defer_finish corruption
		 * shutdown that returned with this block restored.  The
		 * per-AG drain covers freshly-allocated cluster buffers, but
		 * NOT cached cluster buffers that survive across DLM grants
		 * with stale contents under cache-pressure workloads.
		 */
		/*
		 * sess38: invalidate a stale cached cluster buffer for EVERY
		 * multi-node cache-miss read, not only when we acquired the DLM
		 * above.  xfs_lookup() igets with lock_flags=0 (no ILOCK), so
		 * dlm_acquired is false there — yet the cluster buffer may be
		 * cached from when this inode was FREE (mode=0) and flagged
		 * _XBF_FUA_FRESH, which makes the FUA gate skip the re-read.
		 * A peer then allocates the inode (writes mode!=0 to disk), but
		 * our iget returns the stale mode=0 copy → xfs_iget_check_free_
		 * state() returns -ENOENT and a stat/lookup of a peer-created
		 * name fails (the concurrent-mkdir loser sees the winner's child
		 * as missing).  Staling the buffer clears XBF_DONE|_XBF_FUA_FRESH
		 * so xfs_imap_to_bp below re-reads it FUA-fresh from disk.
		 * xfs_buf_incore is a no-op (returns nothing) when the buffer is
		 * not cached — a true cache miss — so this only costs anything in
		 * the stale-cached case it is meant to fix.
		 */
		if (dlm_acquired ||
		    (mp->m_mxfs_dlm &&
		     !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))) {
			struct xfs_buf	*stale_bp = NULL;

			if (xfs_buf_incore(mp->m_ddev_targp, ip->i_imap.im_blkno,
					   ip->i_imap.im_len, 0,
					   &stale_bp) == 0) {
				/*
				 * sess91 ROOT FIX (confirmed sess90
				 * P90-FUA-OVER-LOGGED, FIRED 7× on the shutdown
				 * node, ops=xfs_inode daddr=128): this cluster
				 * buffer may carry THIS node's logged-but-not-
				 * checkpointed modification to a CO-RESIDENT inode
				 * in the same cluster (b_li_list non-empty / pinned
				 * / in-AIL).  Staling it clears XBF_DONE so
				 * xfs_imap_to_bp FUA-re-reads the on-disk image,
				 * DMA-clobbering that uncheckpointed change with
				 * stale disk content → the lost-update family
				 * (di_size→0, bnobt lost-removal → double-free
				 * shutdown).  The peer-allocation-visibility case
				 * sess38 fixed only arises on a CLEAN cluster
				 * buffer (no local logged change — inode alloc is
				 * node-affine per AG, so a peer never allocates
				 * into a cluster we have logged changes in), so it
				 * is safe to skip the invalidate when in-core is
				 * authoritative.  Mirrors the AG-meta hook's
				 * sess42/sess43 protection.
				 */
				if (mxfs_buf_has_uncheckpointed_mods(stale_bp)) {
					pr_warn_ratelimited(
					    "mxfs: P91-CLUSTER-PROTECT ino=0x%llx blkno=0x%llx pin=%d li_empty=%d has_bli=%d flags=0x%x comm=%s — keeping in-core authoritative cluster buffer (would-be clobber averted)\n",
					    (unsigned long long)ino,
					    (unsigned long long)ip->i_imap.im_blkno,
					    xfs_buf_ispinned(stale_bp) ? 1 : 0,
					    list_empty(&stale_bp->b_li_list) ? 1 : 0,
					    stale_bp->b_log_item ? 1 : 0,
					    stale_bp->b_flags, current->comm);
				} else if (mxfs_inode_cluster_owned_skip &&
					   (stale_bp->b_flags & XBF_DONE) &&
					   mxfs_dinode_cached_allocated(stale_bp,
						ip->i_imap.im_boffset)) {
					/*
					 * sess19(ccloop) PERF (the precise inverse of the
					 * sess38 bug): the sess38 invalidation exists ONLY
					 * to catch a peer's fresh ALLOCATION of an inode our
					 * cache still shows FREE (mode=0 → check_free_state
					 * ENOENT).  When the cached cluster already shows
					 * THIS inode ALLOCATED (di_magic ok, di_mode!=0), the
					 * sess38 ENOENT cannot occur — existence is coherent.
					 * (A dir entry resolving to this ino implies the ino
					 * is allocated on disk; dir staleness is handled by
					 * the separate dir_gen path.)  Content coherency is
					 * unaffected: it is refreshed at ilock time by the
					 * inode-DLM reload (mxfs_dlm_reload_inode), not here.
					 * So skip the redundant re-stale that would re-FUA-
					 * read the whole 32-inode cluster — the per-inode
					 * cluster-stale thrash that made a read-only 800-entry
					 * verify (and rm-rf) FUA-read each cluster ~32×.
					 * Only the mode=0 cached-free case (the genuine
					 * sess38 risk) still falls through to the stale below.
					 */
					atomic64_inc(&mxfs_fua_inode_owned_skip);
				} else {
					/* P20 forensic — see recycle-site twin.
					 * sess38 run14d: gated for ship. */
					if (unlikely(mxfs_dirwr_enabled ||
						     mxfs_instr_enabled))
						pr_warn_ratelimited(
						    "mxfs: P20-CLUSTER-INVAL site=iget-miss ino=0x%llx blkno=0x%llx flags=0x%x comm=%s\n",
						    (unsigned long long)ino,
						    (unsigned long long)ip->i_imap.im_blkno,
						    stale_bp->b_flags, current->comm);
					atomic64_inc(&mxfs_iget_cluster_staled);
					xfs_buf_stale(stale_bp);
				}
				xfs_buf_relse(stale_bp);
			}
		}

		error = xfs_imap_to_bp(mp, tp, &ip->i_imap, &bp);
		if (error)
			goto out_release_dlm;

		error = xfs_inode_from_disk(ip,
				xfs_buf_offset(bp, ip->i_imap.im_boffset));
		if (!error)
			xfs_buf_set_ref(bp, XFS_INO_REF);
		else
			xfs_inode_mark_sick(ip, XFS_SICK_INO_CORE);
		/*
		 * sess79 RULE-4 DECISIVE PROBE: inode_from_disk failed
		 * verification (e.g. xfs_dir2_sf_verify !ino_ok inode=0) on a
		 * multi-node mount.  The sess38 stale-invalidate above already
		 * forced this buffer FUA-fresh, so a TORN/in-flight peer write
		 * is the only way a fresh read sees a half-written shortform dir.
		 * FUA-re-read the cluster block straight from the medium and
		 * compare to the buffer we just verified.  differs==1 => the
		 * first (cached) read was stale/torn and disk is now newer
		 * (READ-coherency / torn-read); differs==0 => disk itself carries
		 * the corrupt inode=0 (durable WRITE / double-alloc clobber).
		 * One FUA read on the rare corruption path only.
		 */
		if (error && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			extern int mxfs_ag_buf_disk_differs(struct xfs_buf *);
			int s79_dd = mxfs_ag_buf_disk_differs(bp);
			pr_warn("mxfs: P-SFV-FAIL ino=0x%llx err=%d disk_differs=%d blkno=0x%llx boff=%u flags=0x%x (differs=1 => torn/stale READ; differs=0 => DURABLE on-disk corruption)\n",
				(unsigned long long)ino, error, s79_dd,
				(unsigned long long)ip->i_imap.im_blkno,
				(unsigned)ip->i_imap.im_boffset,
				bp->b_flags);
		}
		xfs_trans_brelse(tp, bp);

		/*
		 * sess45 P99: cache-MISS read of a regular file that landed
		 * di_size==0.  FUA-read the medium NOW (separate from the buffer
		 * we just read through the cache) to tell durability (disk==0 =>
		 * writer not destaged) from a stale buffer read (disk!=0 => the
		 * v0.4.9 invalidate+FUA-reread did NOT pierce to current data).
		 */
		{ extern int mxfs_instr_enabled;
		  extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *, uint16_t *);
		  if (unlikely(mxfs_instr_enabled) && !error &&
		      mp->m_mxfs_dlm &&
		      !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		      S_ISREG(VFS_I(ip)->i_mode) && ip->i_disk_size == 0) {
			uint64_t dsz = mxfs_inode_disk_di_size(ip, NULL);
			pr_warn_ratelimited("mxfs: P99-IGET-MISS ino=%llu incore_size=0 disk_di_size=%lld dlm_acq=%d stale=%d (disk!=0 => reread missed current; disk==0 => writer not durable)\n",
				(unsigned long long)ino, (long long)dsz,
				dlm_acquired, ip->i_dlm_stale);
		  } }

		/*
		 * sess-tcp ROOT FIX: extend the sess127 durable-before-visible
		 * coordination to the dinode-VERIFY-FAIL case.  On the
		 * TCP/write-through (LIO/tcm_loop) stack the creator's freshly
		 * allocated child inode cluster is often not yet durable on the
		 * medium when a peer first reads it, so xfs_inode_from_disk fails
		 * xfs_dinode_verify (-EFSCORRUPTED, "Structure needs cleaning")
		 * instead of the mode==0/-ENOENT the write-back-cache (SCST) path
		 * produces — which bypassed the PR-reload recovery below and
		 * returned EFSCORRUPTED to userspace on the FIRST read (it
		 * self-healed only on a later access).  xfs_inode_from_disk bails
		 * at the verifier BEFORE mutating any fork state, so ip is still
		 * pristine here and a coordinated reload is safe.  Do the same
		 * PR acquire (BASTs the creator's deferred-publish EX -> its
		 * release flushes the dinode durable) + reload; if the inode now
		 * reads a valid mode the creator flush succeeded and we proceed.
		 * Confined to the anomaly path (multi-node, no tp, non-CREATE).
		 */
		if (error && !tp && !dlm_acquired &&
		    !(flags & XFS_IGET_CREATE) &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
			mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
			mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
			if (VFS_I(ip)->i_mode != 0)
				error = 0;
			pr_warn_ratelimited(
				"mxfs: P-TCP-VERIFY-COORD ino=0x%llx post_mode=0%o err=%d (verify-fail -> coordinated creator flush)\n",
				(unsigned long long)ino, VFS_I(ip)->i_mode,
				error);
		}

		if (error)
			goto out_release_dlm;
	}

	trace_xfs_iget_miss(ip);

	/*
	 * Check the inode free state is valid. This also detects lookup
	 * racing with unlinks.
	 */
	error = xfs_iget_check_free_state(ip, flags);

	/*
	 * sess127 ROOT FIX (RULE 4 PROVEN via repro_uv_create_race.sh +
	 * ungated P-IGET-ENOENT: fua_disk_mode=0x0 on every loser):
	 * durable-before-visible gap for NEWLY CREATED inodes.  The creator
	 * commits dirent + new dinode in ONE transaction; its parent-dir
	 * BAST release flushes the PARENT durable (so we can see the
	 * dirent), but the new CHILD dinode stays unflushed in the
	 * creator's AIL — and per sess44 deferred-publish the creator's EX
	 * on the child is LOCAL (no CAW slot), so nothing ever BASTs it to
	 * flush.  xfs_lookup igets with lock_flags=0, so no DLM acquire
	 * happens on this path at all: we read the on-platter FREE image
	 * and fail ENOENT for a name that provably exists (mkdir -p race
	 * loser cannot use the winner's dir = POSIX violation; reader
	 * counts miss peers' fresh files; downstream inobt double-free).
	 *
	 * Recovery: ONE coordinated PR acquire on the child inode.  The
	 * acquire contends with the creator's (published-on-dir-BAST) EX,
	 * BASTing it; the creator's release path (sess38 writer-flush
	 * durability wait) makes the dinode durable before granting; the
	 * reload then reads the real mode and we proceed.  If the inode is
	 * GENUINELY free (lookup racing a real unlink), the acquire is
	 * uncontended (~1 CAW round-trip), the reload still reads free,
	 * and we return the legitimate ENOENT.  Cost is confined to the
	 * anomaly path: reaching here at all requires a dirent that
	 * resolved to an inode whose dinode reads free.
	 * Gated: multi-node, no transaction context (no CAW poll with a
	 * dirty tp), non-CREATE, and we didn't already coordinate above.
	 */
	if (error == -ENOENT && !tp && !dlm_acquired &&
	    !(flags & XFS_IGET_CREATE) &&
	    VFS_I(ip)->i_mode == 0 &&
	    mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
		mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
		mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
		pr_warn_ratelimited(
			"mxfs: P127-IGET-COORD ino=0x%llx post_mode=0%o (0=>genuinely free; !=0=>creator flush forced)\n",
			(unsigned long long)ino, VFS_I(ip)->i_mode);
		error = xfs_iget_check_free_state(ip, flags);
	}

	if (error)
		goto out_release_dlm;

	/*
	 * Preload the radix tree so we can insert safely under the
	 * write spinlock. Note that we cannot sleep inside the preload
	 * region.
	 */
	if (radix_tree_preload(GFP_KERNEL | __GFP_NOLOCKDEP)) {
		error = -EAGAIN;
		goto out_release_dlm;
	}

	/*
	 * Because the inode hasn't been added to the radix-tree yet it can't
	 * be found by another thread, so we can do the non-sleeping lock here.
	 */
	if (lock_flags) {
		if (!xfs_ilock_nowait(ip, lock_flags))
			BUG();
	}

	/*
	 * These values must be set before inserting the inode into the radix
	 * tree as the moment it is inserted a concurrent lookup (allowed by the
	 * RCU locking mechanism) can find it and that lookup must see that this
	 * is an inode currently under construction (i.e. that XFS_INEW is set).
	 * The ip->i_flags_lock that protects the XFS_INEW flag forms the
	 * memory barrier that ensures this detection works correctly at lookup
	 * time.
	 */
	if (flags & XFS_IGET_DONTCACHE)
		d_mark_dontcache(VFS_I(ip));
	ip->i_udquot = NULL;
	ip->i_gdquot = NULL;
	ip->i_pdquot = NULL;
	xfs_iflags_set(ip, XFS_INEW);
	/*
	 * sess118: XFS_IGET_CREATE means THIS node is allocating a brand-new
	 * inode incarnation.  Mark it so the xfs_iflush resurrection guard knows
	 * its first on-disk write is legitimate (the on-disk slot still holds the
	 * chunk-init/prior-free image, so disk_gen != incore_gen is expected and
	 * must NOT be mistaken for a peer-resurrection ghost).  Cleared on the
	 * first flush that stamps our gen onto the home block.  See
	 * MXFS_IF_FIRST_FLUSH in xfs_inode.h.
	 */
	if (flags & XFS_IGET_CREATE)
		xfs_iflags_set(ip, MXFS_IF_FIRST_FLUSH);

	/* insert the new inode */
	mxfs_ici_lock(pag);
	error = radix_tree_insert(&pag->pag_ici_root, agino, ip);
	if (unlikely(error)) {
		WARN_ON(error != -EEXIST);
		XFS_STATS_INC(mp, xs_ig_dup);
		error = -EAGAIN;
		goto out_preload_end;
	}
	spin_unlock(&pag->pag_ici_lock);
	radix_tree_preload_end();

	*ipp = ip;
	return 0;

out_preload_end:
	spin_unlock(&pag->pag_ici_lock);
	radix_tree_preload_end();
	if (lock_flags)
		xfs_iunlock(ip, lock_flags);
	/* xfs_iunlock called mxfs_dlm_ilock_end for us — skip release below */
	dlm_acquired = false;
out_release_dlm:
	/*
	 * Error paths that took the DLM lock via mxfs_dlm_ilock_begin above
	 * but never went through xfs_iunlock must release the holder
	 * themselves, otherwise ip->i_dlm_ex_holders/pr_holders leaks and
	 * the cached lock never drops — blocking remote nodes' BAST-driven
	 * acquires with a 120s timeout.
	 */
	if (dlm_acquired)
		mxfs_dlm_ilock_end(ip, dlm_mode);
out_destroy:
	/*
	 * sess44 deferred-publish: a failed XFS_IGET_CREATE may have linked ip
	 * onto mp->m_mxfs_unpub_list via mxfs_dlm_grant_local_new.  Remove it
	 * before freeing or the list holds a dangling pointer.  No-op if the
	 * inode was never granted locally.
	 */
	if (mp->m_mxfs_dlm)
		mxfs_dlm_unpublish_drop(ip);
	/*
	 * sess6 (ccloop 8ba7ae5c) ROOT FIX of the recycled-inode BAST-work
	 * panics (test26 radix_tree_tag_set ino=0, test5 agino=0xb7): the
	 * mxfs_dlm_ilock_begin coordination above runs on this NOT-YET-
	 * INSERTED inode, and a peer BAST during that window arms
	 * i_dlm_bast_work / i_dlm_bast_dwork against it (igrab'd).  The
	 * direct free below bypasses VFS refcounts — upstream-safe only
	 * because an uninserted inode can never escape this function; the
	 * DLM arms violate that.  Reap both works synchronously so nothing
	 * can fire on the freed object (their igrab counts are inert here:
	 * xfs_inode_free ignores i_count).  No re-arm is possible after
	 * this point: the inode is not in the radix tree, so bast_notify's
	 * INCORE iget cannot reach it, and only this thread holds the
	 * pointer.
	 */
	if (mp->m_mxfs_dlm) {
		cancel_work_sync(&ip->i_dlm_bast_work);
		cancel_delayed_work_sync(&ip->i_dlm_bast_dwork);
	}
	__destroy_inode(VFS_I(ip));
	xfs_inode_free(ip);
	return error;
}

/*
 * Look up an inode by number in the given file system.  The inode is looked up
 * in the cache held in each AG.  If the inode is found in the cache, initialise
 * the vfs inode if necessary.
 *
 * If it is not in core, read it in from the file system's device, add it to the
 * cache and initialise the vfs inode.
 *
 * The inode is locked according to the value of the lock_flags parameter.
 * Inode lookup is only done during metadata operations and not as part of the
 * data IO path. Hence we only allow locking of the XFS_ILOCK during lookup.
 */
int
xfs_iget(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_ino_t		ino,
	uint			flags,
	uint			lock_flags,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*ip;
	struct xfs_perag	*pag;
	xfs_agino_t		agino;
	int			error;

	ASSERT((lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED)) == 0);

	/* reject inode numbers outside existing AGs */
	if (!xfs_verify_ino(mp, ino))
		return -EINVAL;

	XFS_STATS_INC(mp, xs_ig_attempts);

	/* get the perag structure and ensure that it's inode capable */
	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
	agino = XFS_INO_TO_AGINO(mp, ino);

again:
	error = 0;
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);

	if (ip) {
		error = xfs_iget_cache_hit(pag, ip, ino, flags, lock_flags);
		if (error)
			goto out_error_or_again;
		/*
		 * sess128 ROOT FIX: a CREATE satisfied from the inode cache is
		 * a REUSED incarnation carrying the prior incarnation's DLM
		 * fields (phantom EX, unpub flag clear — the prior slot was
		 * released at xfs_inactive).  Re-arm deferred-publish so
		 * xfs_create's publish-on-create acquires a real on-disk slot
		 * and peers' acquires of the reused number BAST us (forcing
		 * the new dinode durable) instead of granting clean against an
		 * empty slot and reading size=0.  See
		 * mxfs_dlm_rearm_unpublished.
		 */
		if ((flags & XFS_IGET_CREATE) && mp->m_mxfs_dlm)
			mxfs_dlm_rearm_unpublished(ip);
	} else {
		rcu_read_unlock();
		if (flags & XFS_IGET_INCORE) {
			error = -ENODATA;
			goto out_error_or_again;
		}
		XFS_STATS_INC(mp, xs_ig_missed);

		error = xfs_iget_cache_miss(mp, pag, tp, ino, &ip,
							flags, lock_flags);
		if (error)
			goto out_error_or_again;
	}
	xfs_perag_put(pag);

	*ipp = ip;

	/*
	 * If we have a real type for an on-disk inode, we can setup the inode
	 * now.	 If it's a new inode being created, xfs_init_new_inode will
	 * handle it.
	 */
	if (xfs_iflags_test(ip, XFS_INEW) && VFS_I(ip)->i_mode != 0)
		xfs_setup_existing_inode(ip);
	/* sess23: attribute the reference this call is handing to its caller. */
	ip->i_mxfs_iget_ret = _RET_IP_;
	/* sess26 P205-REFBAL: xfs_iget hands the caller a reference that is NOT
	 * an mxfs_igrab_tracked grab.  Count it, or the balance is asymmetric in
	 * the other direction (releases via xfs_irele would drive net negative). */
	if (ip->i_mxfs_tgrabs < 0xffff)
		ip->i_mxfs_tgrabs++;
	mxfs_refev_rec(ip, _RET_IP_, 1);
	return 0;

out_error_or_again:
	if (!(flags & (XFS_IGET_INCORE | XFS_IGET_NORETRY)) &&
	    error == -EAGAIN) {
		delay(1);
		goto again;
	}
	xfs_perag_put(pag);
	return error;
}

/*
 * Get a metadata inode.
 *
 * The metafile type must match the file mode exactly, and for files in the
 * metadata directory tree, it must match the inode's metatype exactly.
 */
int
xfs_trans_metafile_iget(
	struct xfs_trans	*tp,
	xfs_ino_t		ino,
	enum xfs_metafile_type	metafile_type,
	struct xfs_inode	**ipp)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_inode	*ip;
	umode_t			mode;
	int			error;

	error = xfs_iget(mp, tp, ino, 0, 0, &ip);
	if (error == -EFSCORRUPTED || error == -EINVAL)
		goto whine;
	if (error)
		return error;

	if (VFS_I(ip)->i_nlink == 0)
		goto bad_rele;

	if (metafile_type == XFS_METAFILE_DIR)
		mode = S_IFDIR;
	else
		mode = S_IFREG;
	if (inode_wrong_type(VFS_I(ip), mode))
		goto bad_rele;
	if (xfs_has_metadir(mp)) {
		if (!xfs_is_metadir_inode(ip))
			goto bad_rele;
		if (metafile_type != ip->i_metatype)
			goto bad_rele;
	}

	*ipp = ip;
	return 0;
bad_rele:
	xfs_irele(ip);
whine:
	xfs_err(mp, "metadata inode 0x%llx type %u is corrupt", ino,
			metafile_type);
	xfs_fs_mark_sick(mp, XFS_SICK_FS_METADIR);
	return -EFSCORRUPTED;
}

/* Grab a metadata file if the caller doesn't already have a transaction. */
int
xfs_metafile_iget(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	enum xfs_metafile_type	metafile_type,
	struct xfs_inode	**ipp)
{
	struct xfs_trans	*tp;
	int			error;

	tp = xfs_trans_alloc_empty(mp);
	error = xfs_trans_metafile_iget(tp, ino, metafile_type, ipp);
	xfs_trans_cancel(tp);
	return error;
}

/*
 * Grab the inode for reclaim exclusively.
 *
 * We have found this inode via a lookup under RCU, so the inode may have
 * already been freed, or it may be in the process of being recycled by
 * xfs_iget(). In both cases, the inode will have XFS_IRECLAIM set. If the inode
 * has been fully recycled by the time we get the i_flags_lock, XFS_IRECLAIMABLE
 * will not be set. Hence we need to check for both these flag conditions to
 * avoid inodes that are no longer reclaim candidates.
 *
 * Note: checking for other state flags here, under the i_flags_lock or not, is
 * racy and should be avoided. Those races should be resolved only after we have
 * ensured that we are able to reclaim this inode and the world can see that we
 * are going to reclaim it.
 *
 * Return true if we grabbed it, false otherwise.
 */
static bool
xfs_reclaim_igrab(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	ASSERT(rcu_read_lock_held());

	spin_lock(&ip->i_flags_lock);
	if (!__xfs_iflags_test(ip, XFS_IRECLAIMABLE) ||
	    __xfs_iflags_test(ip, XFS_IRECLAIM)) {
		/* not a reclaim candidate. */
		spin_unlock(&ip->i_flags_lock);
		return false;
	}

	/* Don't reclaim a sick inode unless the caller asked for it. */
	if (ip->i_sick &&
	    (!icw || !(icw->icw_flags & XFS_ICWALK_FLAG_RECLAIM_SICK))) {
		spin_unlock(&ip->i_flags_lock);
		return false;
	}

	__xfs_iflags_set(ip, XFS_IRECLAIM);
	spin_unlock(&ip->i_flags_lock);
	return true;
}

/*
 * Inode reclaim is non-blocking, so the default action if progress cannot be
 * made is to "requeue" the inode for reclaim by unlocking it and clearing the
 * XFS_IRECLAIM flag.  If we are in a shutdown state, we don't care about
 * blocking anymore and hence we can wait for the inode to be able to reclaim
 * it.
 *
 * We do no IO here - if callers require inodes to be cleaned they must push the
 * AIL first to trigger writeback of dirty inodes.  This enables writeback to be
 * done in the background in a non-blocking manner, and enables memory reclaim
 * to make progress without blocking.
 */
static void
xfs_reclaim_inode(
	struct xfs_inode	*ip,
	struct xfs_perag	*pag)
{
	xfs_ino_t		ino = ip->i_ino; /* for radix_tree_delete */

	if (!xfs_ilock_nowait(ip, XFS_ILOCK_EXCL))
		goto out;
	if (xfs_iflags_test_and_set(ip, XFS_IFLUSHING))
		goto out_iunlock;

	/*
	 * Check for log shutdown because aborting the inode can move the log
	 * tail and corrupt in memory state. This is fine if the log is shut
	 * down, but if the log is still active and only the mount is shut down
	 * then the in-memory log tail movement caused by the abort can be
	 * incorrectly propagated to disk.
	 */
	if (xlog_is_shutdown(ip->i_mount->m_log)) {
		xfs_iunpin_wait(ip);
		/*
		 * Avoid a ABBA deadlock on the inode cluster buffer vs
		 * concurrent xfs_ifree_cluster() trying to mark the inode
		 * stale. We don't need the inode locked to run the flush abort
		 * code, but the flush abort needs to lock the cluster buffer.
		 */
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		xfs_iflush_shutdown_abort(ip);
		xfs_ilock(ip, XFS_ILOCK_EXCL);
		goto reclaim;
	}
	if (xfs_ipincount(ip))
		goto out_clear_flush;
	if (!xfs_inode_clean(ip))
		goto out_clear_flush;

	xfs_iflags_clear(ip, XFS_IFLUSHING);
reclaim:
	trace_xfs_inode_reclaiming(ip);

	/*
	 * ccloop cc87fed3 sess6: RULE 4 audit trail (Fable-guided, P135
	 * root cause hunt) -- every REAL eviction commit, so a later
	 * P135/P139 corruption report's ino/ptr can be cross-referenced
	 * against exactly when and by whom it was actually reclaimed.
	 */
	/* sess9 (72513a13) CAPPED — see P82-ADD comment (printk-storm DoS). */
	{
		static atomic_t p140_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p140_n) <= 300)
			pr_warn("mxfs: P140-RECLAIM-COMMIT ino=0x%llx ip=%px pid=%d comm=%s\n",
				(unsigned long long)ino, VFS_I(ip),
				current->pid, current->comm);
	}

	/* MXFS: release any cached DLM lock before i_ino is zeroed */
	mxfs_dlm_evict(ip);

	/*
	 * Because we use RCU freeing we need to ensure the inode always appears
	 * to be reclaimed with an invalid inode number when in the free state.
	 * We do this as early as possible under the ILOCK so that
	 * xfs_iflush_cluster() and xfs_ifree_cluster() can be guaranteed to
	 * detect races with us here. By doing this, we guarantee that once
	 * xfs_iflush_cluster() or xfs_ifree_cluster() has locked XFS_ILOCK that
	 * it will see either a valid inode that will serialise correctly, or it
	 * will see an invalid inode that it can skip.
	 */
	spin_lock(&ip->i_flags_lock);
	ip->i_flags = XFS_IRECLAIM;
	ip->i_ino = 0;
	ip->i_sick = 0;
	ip->i_checked = 0;
	spin_unlock(&ip->i_flags_lock);

	ASSERT(!ip->i_itemp || ip->i_itemp->ili_item.li_buf == NULL);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);

	XFS_STATS_INC(ip->i_mount, xs_ig_reclaims);
	/*
	 * Remove the inode from the per-AG radix tree.
	 *
	 * Because radix_tree_delete won't complain even if the item was never
	 * added to the tree assert that it's been there before to catch
	 * problems with the inode life time early on.
	 */
	mxfs_ici_lock(pag);
	if (!radix_tree_delete(&pag->pag_ici_root,
				XFS_INO_TO_AGINO(ip->i_mount, ino)))
		ASSERT(0);
	xfs_perag_clear_inode_tag(pag, NULLAGINO, XFS_ICI_RECLAIM_TAG);
	spin_unlock(&pag->pag_ici_lock);

	/*
	 * Here we do an (almost) spurious inode lock in order to coordinate
	 * with inode cache radix tree lookups.  This is because the lookup
	 * can reference the inodes in the cache without taking references.
	 *
	 * We make that OK here by ensuring that we wait until the inode is
	 * unlocked after the lookup before we go ahead and free it.
	 */
	xfs_ilock(ip, XFS_ILOCK_EXCL);
	ASSERT(!ip->i_udquot && !ip->i_gdquot && !ip->i_pdquot);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	ASSERT(xfs_inode_clean(ip));

	__xfs_inode_free(ip);
	return;

out_clear_flush:
	xfs_iflags_clear(ip, XFS_IFLUSHING);
out_iunlock:
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
out:
	xfs_iflags_clear(ip, XFS_IRECLAIM);
}

/* Reclaim sick inodes if we're unmounting or the fs went down. */
static inline bool
xfs_want_reclaim_sick(
	struct xfs_mount	*mp)
{
	return xfs_is_unmounting(mp) || xfs_has_norecovery(mp) ||
	       xfs_is_shutdown(mp);
}

void
xfs_reclaim_inodes(
	struct xfs_mount	*mp)
{
	struct xfs_icwalk	icw = {
		.icw_flags	= 0,
	};

	if (xfs_want_reclaim_sick(mp))
		icw.icw_flags |= XFS_ICWALK_FLAG_RECLAIM_SICK;

	while (xfs_group_marked(mp, XG_TYPE_AG, XFS_PERAG_RECLAIM_MARK)) {
		xfs_ail_push_all_sync(mp->m_ail);
		xfs_icwalk(mp, XFS_ICWALK_RECLAIM, &icw);
	}
}

/*
 * The shrinker infrastructure determines how many inodes we should scan for
 * reclaim. We want as many clean inodes ready to reclaim as possible, so we
 * push the AIL here. We also want to proactively free up memory if we can to
 * minimise the amount of work memory reclaim has to do so we kick the
 * background reclaim if it isn't already scheduled.
 */
long
xfs_reclaim_inodes_nr(
	struct xfs_mount	*mp,
	unsigned long		nr_to_scan)
{
	struct xfs_icwalk	icw = {
		.icw_flags	= XFS_ICWALK_FLAG_SCAN_LIMIT,
		.icw_scan_limit	= min_t(unsigned long, LONG_MAX, nr_to_scan),
	};

	if (xfs_want_reclaim_sick(mp))
		icw.icw_flags |= XFS_ICWALK_FLAG_RECLAIM_SICK;

	/* kick background reclaimer and push the AIL */
	xfs_reclaim_work_queue(mp);
	xfs_ail_push_all(mp->m_ail);

	xfs_icwalk(mp, XFS_ICWALK_RECLAIM, &icw);
	return 0;
}

/*
 * Return the number of reclaimable inodes in the filesystem for
 * the shrinker to determine how much to reclaim.
 */
long
xfs_reclaim_inodes_count(
	struct xfs_mount	*mp)
{
	XA_STATE		(xas, &mp->m_groups[XG_TYPE_AG].xa, 0);
	long			reclaimable = 0;
	struct xfs_perag	*pag;

	rcu_read_lock();
	xas_for_each_marked(&xas, pag, ULONG_MAX, XFS_PERAG_RECLAIM_MARK) {
		trace_xfs_reclaim_inodes_count(pag, _THIS_IP_);
		reclaimable += pag->pag_ici_reclaimable;
	}
	rcu_read_unlock();

	return reclaimable;
}

STATIC bool
xfs_icwalk_match_id(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	if ((icw->icw_flags & XFS_ICWALK_FLAG_UID) &&
	    !uid_eq(VFS_I(ip)->i_uid, icw->icw_uid))
		return false;

	if ((icw->icw_flags & XFS_ICWALK_FLAG_GID) &&
	    !gid_eq(VFS_I(ip)->i_gid, icw->icw_gid))
		return false;

	if ((icw->icw_flags & XFS_ICWALK_FLAG_PRID) &&
	    ip->i_projid != icw->icw_prid)
		return false;

	return true;
}

/*
 * A union-based inode filtering algorithm. Process the inode if any of the
 * criteria match. This is for global/internal scans only.
 */
STATIC bool
xfs_icwalk_match_id_union(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	if ((icw->icw_flags & XFS_ICWALK_FLAG_UID) &&
	    uid_eq(VFS_I(ip)->i_uid, icw->icw_uid))
		return true;

	if ((icw->icw_flags & XFS_ICWALK_FLAG_GID) &&
	    gid_eq(VFS_I(ip)->i_gid, icw->icw_gid))
		return true;

	if ((icw->icw_flags & XFS_ICWALK_FLAG_PRID) &&
	    ip->i_projid == icw->icw_prid)
		return true;

	return false;
}

/*
 * Is this inode @ip eligible for eof/cow block reclamation, given some
 * filtering parameters @icw?  The inode is eligible if @icw is null or
 * if the predicate functions match.
 */
static bool
xfs_icwalk_match(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	bool			match;

	if (!icw)
		return true;

	if (icw->icw_flags & XFS_ICWALK_FLAG_UNION)
		match = xfs_icwalk_match_id_union(ip, icw);
	else
		match = xfs_icwalk_match_id(ip, icw);
	if (!match)
		return false;

	/* skip the inode if the file size is too small */
	if ((icw->icw_flags & XFS_ICWALK_FLAG_MINFILESIZE) &&
	    XFS_ISIZE(ip) < icw->icw_min_file_size)
		return false;

	return true;
}

/*
 * This is a fast pass over the inode cache to try to get reclaim moving on as
 * many inodes as possible in a short period of time. It kicks itself every few
 * seconds, as well as being kicked by the inode cache shrinker when memory
 * goes low.
 */
void
xfs_reclaim_worker(
	struct work_struct *work)
{
	struct xfs_mount *mp = container_of(to_delayed_work(work),
					struct xfs_mount, m_reclaim_work);

	xfs_icwalk(mp, XFS_ICWALK_RECLAIM, NULL);
	xfs_reclaim_work_queue(mp);
}

STATIC int
xfs_inode_free_eofblocks(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw,
	unsigned int		*lockflags)
{
	bool			wait;

	wait = icw && (icw->icw_flags & XFS_ICWALK_FLAG_SYNC);

	if (!xfs_iflags_test(ip, XFS_IEOFBLOCKS))
		return 0;

	/*
	 * If the mapping is dirty the operation can block and wait for some
	 * time. Unless we are waiting, skip it.
	 */
	if (!wait && mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_DIRTY))
		return 0;

	if (!xfs_icwalk_match(ip, icw))
		return 0;

	/*
	 * If the caller is waiting, return -EAGAIN to keep the background
	 * scanner moving and revisit the inode in a subsequent pass.
	 */
	if (!xfs_ilock_nowait(ip, XFS_IOLOCK_EXCL)) {
		if (wait)
			return -EAGAIN;
		return 0;
	}
	*lockflags |= XFS_IOLOCK_EXCL;

	if (xfs_can_free_eofblocks(ip))
		return xfs_free_eofblocks(ip);

	/* inode could be preallocated */
	trace_xfs_inode_free_eofblocks_invalid(ip);
	xfs_inode_clear_eofblocks_tag(ip);
	return 0;
}

static void
xfs_blockgc_set_iflag(
	struct xfs_inode	*ip,
	unsigned long		iflag)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_perag	*pag;

	ASSERT((iflag & ~(XFS_IEOFBLOCKS | XFS_ICOWBLOCKS)) == 0);

	/*
	 * Don't bother locking the AG and looking up in the radix trees
	 * if we already know that we have the tag set.
	 */
	if (ip->i_flags & iflag)
		return;
	spin_lock(&ip->i_flags_lock);
	ip->i_flags |= iflag;
	spin_unlock(&ip->i_flags_lock);

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
	mxfs_ici_lock(pag);

	xfs_perag_set_inode_tag(pag, XFS_INO_TO_AGINO(mp, ip->i_ino),
			XFS_ICI_BLOCKGC_TAG);

	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

void
xfs_inode_set_eofblocks_tag(
	xfs_inode_t	*ip)
{
	trace_xfs_inode_set_eofblocks_tag(ip);
	return xfs_blockgc_set_iflag(ip, XFS_IEOFBLOCKS);
}

static void
xfs_blockgc_clear_iflag(
	struct xfs_inode	*ip,
	unsigned long		iflag)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_perag	*pag;
	bool			clear_tag;

	ASSERT((iflag & ~(XFS_IEOFBLOCKS | XFS_ICOWBLOCKS)) == 0);

	spin_lock(&ip->i_flags_lock);
	ip->i_flags &= ~iflag;
	clear_tag = (ip->i_flags & (XFS_IEOFBLOCKS | XFS_ICOWBLOCKS)) == 0;
	spin_unlock(&ip->i_flags_lock);

	if (!clear_tag)
		return;

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
	mxfs_ici_lock(pag);

	xfs_perag_clear_inode_tag(pag, XFS_INO_TO_AGINO(mp, ip->i_ino),
			XFS_ICI_BLOCKGC_TAG);

	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

void
xfs_inode_clear_eofblocks_tag(
	xfs_inode_t	*ip)
{
	trace_xfs_inode_clear_eofblocks_tag(ip);
	return xfs_blockgc_clear_iflag(ip, XFS_IEOFBLOCKS);
}

/*
 * Prepare to free COW fork blocks from an inode.
 */
static bool
xfs_prep_free_cowblocks(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	bool			sync;

	sync = icw && (icw->icw_flags & XFS_ICWALK_FLAG_SYNC);

	/*
	 * Just clear the tag if we have an empty cow fork or none at all. It's
	 * possible the inode was fully unshared since it was originally tagged.
	 */
	if (!xfs_inode_has_cow_data(ip)) {
		trace_xfs_inode_free_cowblocks_invalid(ip);
		xfs_inode_clear_cowblocks_tag(ip);
		return false;
	}

	/*
	 * A cowblocks trim of an inode can have a significant effect on
	 * fragmentation even when a reasonable COW extent size hint is set.
	 * Therefore, we prefer to not process cowblocks unless they are clean
	 * and idle. We can never process a cowblocks inode that is dirty or has
	 * in-flight I/O under any circumstances, because outstanding writeback
	 * or dio expects targeted COW fork blocks exist through write
	 * completion where they can be remapped into the data fork.
	 *
	 * Therefore, the heuristic used here is to never process inodes
	 * currently opened for write from background (i.e. non-sync) scans. For
	 * sync scans, use the pagecache/dio state of the inode to ensure we
	 * never free COW fork blocks out from under pending I/O.
	 */
	if (!sync && inode_is_open_for_write(VFS_I(ip)))
		return false;
	return xfs_can_free_cowblocks(ip);
}

/*
 * Automatic CoW Reservation Freeing
 *
 * These functions automatically garbage collect leftover CoW reservations
 * that were made on behalf of a cowextsize hint when we start to run out
 * of quota or when the reservations sit around for too long.  If the file
 * has dirty pages or is undergoing writeback, its CoW reservations will
 * be retained.
 *
 * The actual garbage collection piggybacks off the same code that runs
 * the speculative EOF preallocation garbage collector.
 */
STATIC int
xfs_inode_free_cowblocks(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw,
	unsigned int		*lockflags)
{
	bool			wait;
	int			ret = 0;

	wait = icw && (icw->icw_flags & XFS_ICWALK_FLAG_SYNC);

	if (!xfs_iflags_test(ip, XFS_ICOWBLOCKS))
		return 0;

	if (!xfs_prep_free_cowblocks(ip, icw))
		return 0;

	if (!xfs_icwalk_match(ip, icw))
		return 0;

	/*
	 * If the caller is waiting, return -EAGAIN to keep the background
	 * scanner moving and revisit the inode in a subsequent pass.
	 */
	if (!(*lockflags & XFS_IOLOCK_EXCL) &&
	    !xfs_ilock_nowait(ip, XFS_IOLOCK_EXCL)) {
		if (wait)
			return -EAGAIN;
		return 0;
	}
	*lockflags |= XFS_IOLOCK_EXCL;

	if (!xfs_ilock_nowait(ip, XFS_MMAPLOCK_EXCL)) {
		if (wait)
			return -EAGAIN;
		return 0;
	}
	*lockflags |= XFS_MMAPLOCK_EXCL;

	/*
	 * Check again, nobody else should be able to dirty blocks or change
	 * the reflink iflag now that we have the first two locks held.
	 */
	if (xfs_prep_free_cowblocks(ip, icw))
		ret = xfs_reflink_cancel_cow_range(ip, 0, NULLFILEOFF, false);
	return ret;
}

void
xfs_inode_set_cowblocks_tag(
	xfs_inode_t	*ip)
{
	trace_xfs_inode_set_cowblocks_tag(ip);
	return xfs_blockgc_set_iflag(ip, XFS_ICOWBLOCKS);
}

void
xfs_inode_clear_cowblocks_tag(
	xfs_inode_t	*ip)
{
	trace_xfs_inode_clear_cowblocks_tag(ip);
	return xfs_blockgc_clear_iflag(ip, XFS_ICOWBLOCKS);
}

/* Disable post-EOF and CoW block auto-reclamation. */
void
xfs_blockgc_stop(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;

	if (!xfs_clear_blockgc_enabled(mp))
		return;

	while ((pag = xfs_perag_next(mp, pag)))
		cancel_delayed_work_sync(&pag->pag_blockgc_work);
	trace_xfs_blockgc_stop(mp, __return_address);
}

/* Enable post-EOF and CoW block auto-reclamation. */
void
xfs_blockgc_start(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;

	if (xfs_set_blockgc_enabled(mp))
		return;

	trace_xfs_blockgc_start(mp, __return_address);
	while ((pag = xfs_perag_grab_next_tag(mp, pag, XFS_ICI_BLOCKGC_TAG)))
		xfs_blockgc_queue(pag);
}

/* Don't try to run block gc on an inode that's in any of these states. */
#define XFS_BLOCKGC_NOGRAB_IFLAGS	(XFS_INEW | \
					 XFS_NEED_INACTIVE | \
					 XFS_INACTIVATING | \
					 XFS_IRECLAIMABLE | \
					 XFS_IRECLAIM)
/*
 * Decide if the given @ip is eligible for garbage collection of speculative
 * preallocations, and grab it if so.  Returns true if it's ready to go or
 * false if we should just ignore it.
 */
static bool
xfs_blockgc_igrab(
	struct xfs_inode	*ip)
{
	struct inode		*inode = VFS_I(ip);

	ASSERT(rcu_read_lock_held());

	/* Check for stale RCU freed inode */
	spin_lock(&ip->i_flags_lock);
	if (!ip->i_ino)
		goto out_unlock_noent;

	if (ip->i_flags & XFS_BLOCKGC_NOGRAB_IFLAGS)
		goto out_unlock_noent;
	spin_unlock(&ip->i_flags_lock);

	/* nothing to sync during shutdown */
	if (xfs_is_shutdown(ip->i_mount))
		return false;

	/* If we can't grab the inode, it must on it's way to reclaim. */
	if (!igrab(inode))
		return false;

	/* inode is valid */
	return true;

out_unlock_noent:
	spin_unlock(&ip->i_flags_lock);
	return false;
}

/* Scan one incore inode for block preallocations that we can remove. */
static int
xfs_blockgc_scan_inode(
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	unsigned int		lockflags = 0;
	int			error;

	error = xfs_inode_free_eofblocks(ip, icw, &lockflags);
	if (error)
		goto unlock;

	error = xfs_inode_free_cowblocks(ip, icw, &lockflags);
unlock:
	if (lockflags)
		xfs_iunlock(ip, lockflags);
	xfs_irele(ip);
	return error;
}

/* Background worker that trims preallocated space. */
void
xfs_blockgc_worker(
	struct work_struct	*work)
{
	struct xfs_perag	*pag = container_of(to_delayed_work(work),
					struct xfs_perag, pag_blockgc_work);
	struct xfs_mount	*mp = pag_mount(pag);
	int			error;

	trace_xfs_blockgc_worker(mp, __return_address);

	error = xfs_icwalk_ag(pag, XFS_ICWALK_BLOCKGC, NULL);
	if (error)
		xfs_info(mp, "AG %u preallocation gc worker failed, err=%d",
				pag_agno(pag), error);
	xfs_blockgc_queue(pag);
}

/*
 * Try to free space in the filesystem by purging inactive inodes, eofblocks
 * and cowblocks.
 */
int
xfs_blockgc_free_space(
	struct xfs_mount	*mp,
	struct xfs_icwalk	*icw)
{
	int			error;

	trace_xfs_blockgc_free_space(mp, icw, _RET_IP_);

	error = xfs_icwalk(mp, XFS_ICWALK_BLOCKGC, icw);
	if (error)
		return error;

	return xfs_inodegc_flush(mp);
}

/*
 * Reclaim all the free space that we can by scheduling the background blockgc
 * and inodegc workers immediately and waiting for them all to clear.
 */
int
xfs_blockgc_flush_all(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;

	trace_xfs_blockgc_flush_all(mp, __return_address);

	/*
	 * For each blockgc worker, move its queue time up to now.  If it wasn't
	 * queued, it will not be requeued.  Then flush whatever is left.
	 */
	while ((pag = xfs_perag_grab_next_tag(mp, pag, XFS_ICI_BLOCKGC_TAG)))
		mod_delayed_work(mp->m_blockgc_wq, &pag->pag_blockgc_work, 0);

	while ((pag = xfs_perag_grab_next_tag(mp, pag, XFS_ICI_BLOCKGC_TAG)))
		flush_delayed_work(&pag->pag_blockgc_work);

	return xfs_inodegc_flush(mp);
}

/*
 * Run cow/eofblocks scans on the supplied dquots.  We don't know exactly which
 * quota caused an allocation failure, so we make a best effort by including
 * each quota under low free space conditions (less than 1% free space) in the
 * scan.
 *
 * Callers must not hold any inode's ILOCK.  If requesting a synchronous scan
 * (XFS_ICWALK_FLAG_SYNC), the caller also must not hold any inode's IOLOCK or
 * MMAPLOCK.
 */
int
xfs_blockgc_free_dquots(
	struct xfs_mount	*mp,
	struct xfs_dquot	*udqp,
	struct xfs_dquot	*gdqp,
	struct xfs_dquot	*pdqp,
	unsigned int		iwalk_flags)
{
	struct xfs_icwalk	icw = {0};
	bool			do_work = false;

	if (!udqp && !gdqp && !pdqp)
		return 0;

	/*
	 * Run a scan to free blocks using the union filter to cover all
	 * applicable quotas in a single scan.
	 */
	icw.icw_flags = XFS_ICWALK_FLAG_UNION | iwalk_flags;

	if (XFS_IS_UQUOTA_ENFORCED(mp) && udqp && xfs_dquot_lowsp(udqp)) {
		icw.icw_uid = make_kuid(mp->m_super->s_user_ns, udqp->q_id);
		icw.icw_flags |= XFS_ICWALK_FLAG_UID;
		do_work = true;
	}

	if (XFS_IS_UQUOTA_ENFORCED(mp) && gdqp && xfs_dquot_lowsp(gdqp)) {
		icw.icw_gid = make_kgid(mp->m_super->s_user_ns, gdqp->q_id);
		icw.icw_flags |= XFS_ICWALK_FLAG_GID;
		do_work = true;
	}

	if (XFS_IS_PQUOTA_ENFORCED(mp) && pdqp && xfs_dquot_lowsp(pdqp)) {
		icw.icw_prid = pdqp->q_id;
		icw.icw_flags |= XFS_ICWALK_FLAG_PRID;
		do_work = true;
	}

	if (!do_work)
		return 0;

	return xfs_blockgc_free_space(mp, &icw);
}

/* Run cow/eofblocks scans on the quotas attached to the inode. */
int
xfs_blockgc_free_quota(
	struct xfs_inode	*ip,
	unsigned int		iwalk_flags)
{
	return xfs_blockgc_free_dquots(ip->i_mount,
			xfs_inode_dquot(ip, XFS_DQTYPE_USER),
			xfs_inode_dquot(ip, XFS_DQTYPE_GROUP),
			xfs_inode_dquot(ip, XFS_DQTYPE_PROJ), iwalk_flags);
}

/* XFS Inode Cache Walking Code */

/*
 * The inode lookup is done in batches to keep the amount of lock traffic and
 * radix tree lookups to a minimum. The batch size is a trade off between
 * lookup reduction and stack usage. This is in the reclaim path, so we can't
 * be too greedy.
 */
#define XFS_LOOKUP_BATCH	32


/*
 * Decide if we want to grab this inode in anticipation of doing work towards
 * the goal.
 */
static inline bool
xfs_icwalk_igrab(
	enum xfs_icwalk_goal	goal,
	struct xfs_inode	*ip,
	struct xfs_icwalk	*icw)
{
	switch (goal) {
	case XFS_ICWALK_BLOCKGC:
		return xfs_blockgc_igrab(ip);
	case XFS_ICWALK_RECLAIM:
		return xfs_reclaim_igrab(ip, icw);
	default:
		return false;
	}
}

/*
 * Process an inode.  Each processing function must handle any state changes
 * made by the icwalk igrab function.  Return -EAGAIN to skip an inode.
 */
static inline int
xfs_icwalk_process_inode(
	enum xfs_icwalk_goal	goal,
	struct xfs_inode	*ip,
	struct xfs_perag	*pag,
	struct xfs_icwalk	*icw)
{
	int			error = 0;

	switch (goal) {
	case XFS_ICWALK_BLOCKGC:
		error = xfs_blockgc_scan_inode(ip, icw);
		break;
	case XFS_ICWALK_RECLAIM:
		xfs_reclaim_inode(ip, pag);
		break;
	}
	return error;
}

/*
 * For a given per-AG structure @pag and a goal, grab qualifying inodes and
 * process them in some manner.
 */
static int
xfs_icwalk_ag(
	struct xfs_perag	*pag,
	enum xfs_icwalk_goal	goal,
	struct xfs_icwalk	*icw)
{
	struct xfs_mount	*mp = pag_mount(pag);
	uint32_t		first_index;
	int			last_error = 0;
	int			skipped;
	bool			done;
	int			nr_found;

restart:
	done = false;
	skipped = 0;
	if (goal == XFS_ICWALK_RECLAIM)
		first_index = READ_ONCE(pag->pag_ici_reclaim_cursor);
	else
		first_index = 0;
	nr_found = 0;
	do {
		struct xfs_inode *batch[XFS_LOOKUP_BATCH];
		int		error = 0;
		int		i;

		rcu_read_lock();

		nr_found = radix_tree_gang_lookup_tag(&pag->pag_ici_root,
				(void **) batch, first_index,
				XFS_LOOKUP_BATCH, goal);
		if (!nr_found) {
			done = true;
			rcu_read_unlock();
			break;
		}

		/*
		 * Grab the inodes before we drop the lock. if we found
		 * nothing, nr == 0 and the loop will be skipped.
		 */
		for (i = 0; i < nr_found; i++) {
			struct xfs_inode *ip = batch[i];

			if (done || !xfs_icwalk_igrab(goal, ip, icw))
				batch[i] = NULL;

			/*
			 * Update the index for the next lookup. Catch
			 * overflows into the next AG range which can occur if
			 * we have inodes in the last block of the AG and we
			 * are currently pointing to the last inode.
			 *
			 * Because we may see inodes that are from the wrong AG
			 * due to RCU freeing and reallocation, only update the
			 * index if it lies in this AG. It was a race that lead
			 * us to see this inode, so another lookup from the
			 * same index will not find it again.
			 */
			if (XFS_INO_TO_AGNO(mp, ip->i_ino) != pag_agno(pag))
				continue;
			first_index = XFS_INO_TO_AGINO(mp, ip->i_ino + 1);
			if (first_index < XFS_INO_TO_AGINO(mp, ip->i_ino))
				done = true;
		}

		/* unlock now we've grabbed the inodes. */
		rcu_read_unlock();

		for (i = 0; i < nr_found; i++) {
			if (!batch[i])
				continue;
			error = xfs_icwalk_process_inode(goal, batch[i], pag,
					icw);
			if (error == -EAGAIN) {
				skipped++;
				continue;
			}
			if (error && last_error != -EFSCORRUPTED)
				last_error = error;
		}

		/* bail out if the filesystem is corrupted.  */
		if (error == -EFSCORRUPTED)
			break;

		cond_resched();

		if (icw && (icw->icw_flags & XFS_ICWALK_FLAG_SCAN_LIMIT)) {
			icw->icw_scan_limit -= XFS_LOOKUP_BATCH;
			if (icw->icw_scan_limit <= 0)
				break;
		}
	} while (nr_found && !done);

	if (goal == XFS_ICWALK_RECLAIM) {
		if (done)
			first_index = 0;
		WRITE_ONCE(pag->pag_ici_reclaim_cursor, first_index);
	}

	if (skipped) {
		delay(1);
		goto restart;
	}
	return last_error;
}

/* Walk all incore inodes to achieve a given goal. */
static int
xfs_icwalk(
	struct xfs_mount	*mp,
	enum xfs_icwalk_goal	goal,
	struct xfs_icwalk	*icw)
{
	struct xfs_perag	*pag = NULL;
	int			error = 0;
	int			last_error = 0;

	while ((pag = xfs_perag_grab_next_tag(mp, pag, goal))) {
		error = xfs_icwalk_ag(pag, goal, icw);
		if (error) {
			last_error = error;
			if (error == -EFSCORRUPTED) {
				xfs_perag_rele(pag);
				break;
			}
		}
	}
	return last_error;
	BUILD_BUG_ON(XFS_ICWALK_PRIVATE_FLAGS & XFS_ICWALK_FLAGS_VALID);
}

#ifdef DEBUG
static void
xfs_check_delalloc(
	struct xfs_inode	*ip,
	int			whichfork)
{
	struct xfs_ifork	*ifp = xfs_ifork_ptr(ip, whichfork);
	struct xfs_bmbt_irec	got;
	struct xfs_iext_cursor	icur;

	if (!ifp || !xfs_iext_lookup_extent(ip, ifp, 0, &icur, &got))
		return;
	do {
		if (isnullstartblock(got.br_startblock)) {
			xfs_warn(ip->i_mount,
	"ino %llx %s fork has delalloc extent at [0x%llx:0x%llx]",
				ip->i_ino,
				whichfork == XFS_DATA_FORK ? "data" : "cow",
				got.br_startoff, got.br_blockcount);
		}
	} while (xfs_iext_next_extent(ifp, &icur, &got));
}
#else
#define xfs_check_delalloc(ip, whichfork)	do { } while (0)
#endif

/* Schedule the inode for reclaim. */
static void
xfs_inodegc_set_reclaimable(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_perag	*pag;

	if (!xfs_is_shutdown(mp) && ip->i_delayed_blks) {
		xfs_check_delalloc(ip, XFS_DATA_FORK);
		xfs_check_delalloc(ip, XFS_COW_FORK);
		ASSERT(0);
	}

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
	mxfs_ici_lock(pag);
	spin_lock(&ip->i_flags_lock);

	trace_xfs_inode_set_reclaimable(ip);
	ip->i_flags &= ~(XFS_NEED_INACTIVE | XFS_INACTIVATING);
	ip->i_flags |= XFS_IRECLAIMABLE;
	xfs_perag_set_inode_tag(pag, XFS_INO_TO_AGINO(mp, ip->i_ino),
			XFS_ICI_RECLAIM_TAG);

	spin_unlock(&ip->i_flags_lock);
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

/*
 * Free all speculative preallocations and possibly even the inode itself.
 * This is the last chance to make changes to an otherwise unreferenced file
 * before incore reclamation happens.
 */
static int
xfs_inodegc_inactivate(
	struct xfs_inode	*ip)
{
	int			error;

	trace_xfs_inode_inactivating(ip);
	error = xfs_inactive(ip);
	xfs_inodegc_set_reclaimable(ip);
	return error;

}

void
xfs_inodegc_worker(
	struct work_struct	*work)
{
	struct xfs_inodegc	*gc = container_of(to_delayed_work(work),
						struct xfs_inodegc, work);
	struct llist_node	*node = llist_del_all(&gc->list);
	struct xfs_inode	*ip, *n;
	struct xfs_mount	*mp = gc->mp;
	unsigned int		nofs_flag;

	/*
	 * Clear the cpu mask bit and ensure that we have seen the latest
	 * update of the gc structure associated with this CPU. This matches
	 * with the release semantics used when setting the cpumask bit in
	 * xfs_inodegc_queue.
	 */
	cpumask_clear_cpu(gc->cpu, &mp->m_inodegc_cpumask);
	smp_mb__after_atomic();

	WRITE_ONCE(gc->items, 0);

	if (!node)
		return;

	/*
	 * We can allocate memory here while doing writeback on behalf of
	 * memory reclaim.  To avoid memory allocation deadlocks set the
	 * task-wide nofs context for the following operations.
	 */
	nofs_flag = memalloc_nofs_save();

	ip = llist_entry(node, struct xfs_inode, i_gclist);
	trace_xfs_inodegc_worker(mp, READ_ONCE(gc->shrinker_hits));

	WRITE_ONCE(gc->shrinker_hits, 0);
	llist_for_each_entry_safe(ip, n, node, i_gclist) {
		int	error;

		xfs_iflags_set(ip, XFS_INACTIVATING);
		error = xfs_inodegc_inactivate(ip);
		if (error && !gc->error)
			gc->error = error;
	}

	memalloc_nofs_restore(nofs_flag);
}

/*
 * Expedite all pending inodegc work to run immediately. This does not wait for
 * completion of the work.
 */
void
xfs_inodegc_push(
	struct xfs_mount	*mp)
{
	if (!xfs_is_inodegc_enabled(mp))
		return;
	trace_xfs_inodegc_push(mp, __return_address);
	xfs_inodegc_queue_all(mp);
}

/*
 * Force all currently queued inode inactivation work to run immediately and
 * wait for the work to finish.
 */
int
xfs_inodegc_flush(
	struct xfs_mount	*mp)
{
	xfs_inodegc_push(mp);
	trace_xfs_inodegc_flush(mp, __return_address);
	return xfs_inodegc_wait_all(mp);
}

/*
 * Flush all the pending work and then disable the inode inactivation background
 * workers and wait for them to stop.  Caller must hold sb->s_umount to
 * coordinate changes in the inodegc_enabled state.
 */
void
xfs_inodegc_stop(
	struct xfs_mount	*mp)
{
	bool			rerun;

	if (!xfs_clear_inodegc_enabled(mp))
		return;

	/*
	 * Drain all pending inodegc work, including inodes that could be
	 * queued by racing xfs_inodegc_queue or xfs_inodegc_shrinker_scan
	 * threads that sample the inodegc state just prior to us clearing it.
	 * The inodegc flag state prevents new threads from queuing more
	 * inodes, so we queue pending work items and flush the workqueue until
	 * all inodegc lists are empty.  IOWs, we cannot use drain_workqueue
	 * here because it does not allow other unserialized mechanisms to
	 * reschedule inodegc work while this draining is in progress.
	 */
	xfs_inodegc_queue_all(mp);
	do {
		flush_workqueue(mp->m_inodegc_wq);
		rerun = xfs_inodegc_queue_all(mp);
	} while (rerun);

	trace_xfs_inodegc_stop(mp, __return_address);
}

/*
 * Enable the inode inactivation background workers and schedule deferred inode
 * inactivation work if there is any.  Caller must hold sb->s_umount to
 * coordinate changes in the inodegc_enabled state.
 */
void
xfs_inodegc_start(
	struct xfs_mount	*mp)
{
	if (xfs_set_inodegc_enabled(mp))
		return;

	trace_xfs_inodegc_start(mp, __return_address);
	xfs_inodegc_queue_all(mp);
}

#ifdef CONFIG_XFS_RT
static inline bool
xfs_inodegc_want_queue_rt_file(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;

	if (!XFS_IS_REALTIME_INODE(ip) || xfs_has_zoned(mp))
		return false;

	if (xfs_compare_freecounter(mp, XC_FREE_RTEXTENTS,
				mp->m_low_rtexts[XFS_LOWSP_5_PCNT],
				XFS_FDBLOCKS_BATCH) < 0)
		return true;

	return false;
}
#else
# define xfs_inodegc_want_queue_rt_file(ip)	(false)
#endif /* CONFIG_XFS_RT */

/*
 * Schedule the inactivation worker when:
 *
 *  - We've accumulated more than one inode cluster buffer's worth of inodes.
 *  - There is less than 5% free space left.
 *  - Any of the quotas for this inode are near an enforcement limit.
 */
static inline bool
xfs_inodegc_want_queue_work(
	struct xfs_inode	*ip,
	unsigned int		items)
{
	struct xfs_mount	*mp = ip->i_mount;

	if (items > mp->m_ino_geo.inodes_per_cluster)
		return true;

	if (xfs_compare_freecounter(mp, XC_FREE_BLOCKS,
				mp->m_low_space[XFS_LOWSP_5_PCNT],
				XFS_FDBLOCKS_BATCH) < 0)
		return true;

	if (xfs_inodegc_want_queue_rt_file(ip))
		return true;

	if (xfs_inode_near_dquot_enforcement(ip, XFS_DQTYPE_USER))
		return true;

	if (xfs_inode_near_dquot_enforcement(ip, XFS_DQTYPE_GROUP))
		return true;

	if (xfs_inode_near_dquot_enforcement(ip, XFS_DQTYPE_PROJ))
		return true;

	return false;
}

/*
 * Upper bound on the number of inodes in each AG that can be queued for
 * inactivation at any given time, to avoid monopolizing the workqueue.
 */
#define XFS_INODEGC_MAX_BACKLOG		(4 * XFS_INODES_PER_CHUNK)

/*
 * Make the frontend wait for inactivations when:
 *
 *  - Memory shrinkers queued the inactivation worker and it hasn't finished.
 *  - The queue depth exceeds the maximum allowable percpu backlog.
 *
 * Note: If we are in a NOFS context here (e.g. current thread is running a
 * transaction) the we don't want to block here as inodegc progress may require
 * filesystem resources we hold to make progress and that could result in a
 * deadlock. Hence we skip out of here if we are in a scoped NOFS context.
 */
static inline bool
xfs_inodegc_want_flush_work(
	struct xfs_inode	*ip,
	unsigned int		items,
	unsigned int		shrinker_hits)
{
	if (current->flags & PF_MEMALLOC_NOFS)
		return false;

	if (shrinker_hits > 0)
		return true;

	if (items > XFS_INODEGC_MAX_BACKLOG)
		return true;

	return false;
}

/*
 * Queue a background inactivation worker if there are inodes that need to be
 * inactivated and higher level xfs code hasn't disabled the background
 * workers.
 */
static void
xfs_inodegc_queue(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_inodegc	*gc;
	int			items;
	unsigned int		shrinker_hits;
	unsigned int		cpu_nr;
	unsigned long		queue_delay = 1;

	trace_xfs_inode_set_need_inactive(ip);
	spin_lock(&ip->i_flags_lock);
	ip->i_flags |= XFS_NEED_INACTIVE;
	spin_unlock(&ip->i_flags_lock);

	cpu_nr = get_cpu();
	gc = this_cpu_ptr(mp->m_inodegc);
	llist_add(&ip->i_gclist, &gc->list);
	items = READ_ONCE(gc->items);
	WRITE_ONCE(gc->items, items + 1);
	shrinker_hits = READ_ONCE(gc->shrinker_hits);

	/*
	 * Ensure the list add is always seen by anyone who finds the cpumask
	 * bit set. This effectively gives the cpumask bit set operation
	 * release ordering semantics.
	 */
	smp_mb__before_atomic();
	if (!cpumask_test_cpu(cpu_nr, &mp->m_inodegc_cpumask))
		cpumask_test_and_set_cpu(cpu_nr, &mp->m_inodegc_cpumask);

	/*
	 * We queue the work while holding the current CPU so that the work
	 * is scheduled to run on this CPU.
	 */
	if (!xfs_is_inodegc_enabled(mp)) {
		put_cpu();
		return;
	}

	if (xfs_inodegc_want_queue_work(ip, items))
		queue_delay = 0;

	trace_xfs_inodegc_queue(mp, __return_address);
	mod_delayed_work_on(current_cpu(), mp->m_inodegc_wq, &gc->work,
			queue_delay);
	put_cpu();

	if (xfs_inodegc_want_flush_work(ip, items, shrinker_hits)) {
		trace_xfs_inodegc_throttle(mp, __return_address);
		flush_delayed_work(&gc->work);
	}
}

/*
 * We set the inode flag atomically with the radix tree tag.  Once we get tag
 * lookups on the radix tree, this inode flag can go away.
 *
 * We always use background reclaim here because even if the inode is clean, it
 * still may be under IO and hence we have wait for IO completion to occur
 * before we can reclaim the inode. The background reclaim path handles this
 * more efficiently than we can here, so simply let background reclaim tear down
 * all inodes.
 */
void
xfs_inode_mark_reclaimable(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			need_inactive;

	XFS_STATS_INC(mp, vn_reclaim);

	/*
	 * ccloop cc87fed3 sess6: sweep-pin tripwire (RULE 4 direct-evidence
	 * probe for the P135-PRSWEEP-CYCLE self-loop hang).
	 * mxfs_dlm_pr_sweep_work_fn (xfs_mxfs_dlm.c) records here which
	 * inode it currently holds a live igrab() reference on.  That
	 * reference SHOULD make it impossible for the inode to reach this
	 * function (i_count hit 0, real eviction starting) before pr_sweep's
	 * own iput() runs.  If this fires, it is direct proof some OTHER
	 * code path over-released a reference it did not hold — same bug
	 * FAMILY as the already-fixed BUG3 (raw ihold() vs igrab()), but a
	 * different, not-yet-found call site.  Checked before the earliest
	 * branch so it catches both the sync-inactive and inodegc-queue
	 * paths below.
	 */
	if (unlikely(READ_ONCE(mp->m_mxfs_pr_sweep_pinned) == VFS_I(ip))) {
		pr_warn("mxfs: P136-SWEEPPIN-TRIPWIRE ino=0x%llx ip=%px pid=%d comm=%s — inode entering real eviction while pr_sweep still believes it holds a live igrab() pin on it\n",
			(unsigned long long)ip->i_ino, ip, current->pid,
			current->comm);
		dump_stack();
	}

	/*
	 * We should never get here with any of the reclaim flags already set.
	 *
	 * ccloopff21 sess1: this assert fired live during fence_during_write@
	 * 8/caw (0.10.74) immediately preceding a permanent 3-CPU soft lockup
	 * on the node.  Root cause of the double-entry is unproven — log the
	 * ino/pid/comm/raw-flags so the next reproduction gives a definitive
	 * cross-reference against the "P25-INSTR sync-inactive[-DONE]" pair
	 * for the same ino (mid-flight re-entrancy vs. a stale leaked flag).
	 */
	if (unlikely(xfs_iflags_test(ip, XFS_ALL_IRECLAIM_FLAGS))) {
		pr_warn("mxfs: P-DBLRECLAIM ino=0x%llx pid=%d comm=%s flags=0x%lx\n",
			(unsigned long long)ip->i_ino, current->pid, current->comm,
			(unsigned long)ip->i_flags);
	}
	ASSERT_ALWAYS(!xfs_iflags_test(ip, XFS_ALL_IRECLAIM_FLAGS));

	need_inactive = xfs_inode_needs_inactive(ip);
	if (need_inactive) {
		/*
		 * MXFS multi-node: run inactivation synchronously rather than
		 * queueing it to the inodegc worker.  Async inactivation lets
		 * the unlinked inode sit in the AGI bucket past the unlink
		 * syscall return.  A subsequent dialloc on the same node, or a
		 * peer ACQ-FRESH, may pick the same inode number from inobt
		 * (because the inobt allocation bit was cleared in the
		 * unlink trans) while the AGI bucket head still points at it.
		 * Both nodes then attempt xfs_iunlink_insert for the same ino,
		 * tripping the next_agino==agino corruption check captured at
		 * v0.3.59 stress (MX-INSTR agi-recycle ino=0x83 bucket=3
		 * agno=0 — both nodes simultaneously).  Single-node behaviour
		 * (inodegc queue) is preserved.
		 */
		/*
		 * RE-ENTRANCY GUARD (sess41 ccloop): synchronous inactivation
		 * starts its own transaction and locks the AGI buffer
		 * (xfs_inactive -> xfs_ifree -> xfs_difree -> xfs_read_agi).
		 * If we reach here nested inside an active transaction that
		 * already holds the AGI buffer locked, the inline inactivation
		 * self-deadlocks on the AGI buffer semaphore (xfs_buf_lock,
		 * never released).  The concrete trigger is
		 * xfs_iunlink_reload_next(), which does xfs_irele() of a
		 * reloaded unlinked zombie WHILE xfs_iunlink holds the AGI
		 * ("Caller must hold the AGI" -- xfs_inode.c).  XFS repurposes
		 * current->journal_info to point at the outermost active trans
		 * (xfs_trans.c); when it is non-NULL we are inside a trans and
		 * MUST NOT inactivate inline.  Defer to the inodegc worker
		 * (upstream behaviour) -- it runs after the AGI is dropped.
		 * The AGI-bucket recycle-race protection still applies to the
		 * top-level unlink-syscall path, where the unlink transaction
		 * has already committed (journal_info == NULL) before the final
		 * iput/evict that lands here.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    current->journal_info == NULL) {
			int error;

			/*
			 * ccloop cc87fed3 sess4: added ip=/pid=/comm= (RULE 4 —
			 * BUG3 hunt).  Prior instances of this print gave no way
			 * to tell whether two "sync-inactive" firings for the
			 * same ino within one dmesg-second are (a) the SAME
			 * struct xfs_inode entered twice — genuine re-entrancy —
			 * or (b) two DIFFERENT incarnations from a legitimately
			 * fast inode-number recycle.  ip= disambiguates (a) vs
			 * (b) directly; pid=/comm= identifies the driving thread
			 * (needed to confirm/refute whether the crashing task's
			 * OWN call chain is what reaches here, vs a foreign
			 * thread racing it).
			 */
			/* sess9 (72513a13) CAPPED — see P82-ADD (printk DoS). */
			{
				static atomic_t p25a_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p25a_n) <= 300)
					pr_warn("mxfs: P25-INSTR sync-inactive ino=0x%llx nlink=%u mode=0x%x ip=%px pid=%d comm=%s\n",
						(unsigned long long)ip->i_ino,
						VFS_I(ip)->i_nlink,
						VFS_I(ip)->i_mode, ip,
						current->pid, current->comm);
			}

			spin_lock(&ip->i_flags_lock);
			ip->i_flags |= XFS_NEED_INACTIVE;
			spin_unlock(&ip->i_flags_lock);

			error = xfs_inactive(ip);
			(void)error;	/* errors logged inside; mark reclaimable */
			xfs_inodegc_set_reclaimable(ip);

			{
				static atomic_t p25b_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p25b_n) <= 300)
					pr_warn("mxfs: P25-INSTR sync-inactive-DONE ino=0x%llx rc=%d ip=%px pid=%d comm=%s\n",
						(unsigned long long)ip->i_ino,
						error, ip,
						current->pid, current->comm);
			}
			return;
		}
		xfs_inodegc_queue(ip);
		return;
	}

	/* Going straight to reclaim, so drop the dquots. */
	xfs_qm_dqdetach(ip);
	xfs_inodegc_set_reclaimable(ip);
}

/*
 * Register a phony shrinker so that we can run background inodegc sooner when
 * there's memory pressure.  Inactivation does not itself free any memory but
 * it does make inodes reclaimable, which eventually frees memory.
 *
 * The count function, seek value, and batch value are crafted to trigger the
 * scan function during the second round of scanning.  Hopefully this means
 * that we reclaimed enough memory that initiating metadata transactions won't
 * make things worse.
 */
#define XFS_INODEGC_SHRINKER_COUNT	(1UL << DEF_PRIORITY)
#define XFS_INODEGC_SHRINKER_BATCH	((XFS_INODEGC_SHRINKER_COUNT / 2) + 1)

static unsigned long
xfs_inodegc_shrinker_count(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct xfs_mount	*mp = shrink->private_data;
	struct xfs_inodegc	*gc;
	int			cpu;

	if (!xfs_is_inodegc_enabled(mp))
		return 0;

	for_each_cpu(cpu, &mp->m_inodegc_cpumask) {
		gc = per_cpu_ptr(mp->m_inodegc, cpu);
		if (!llist_empty(&gc->list))
			return XFS_INODEGC_SHRINKER_COUNT;
	}

	return 0;
}

static unsigned long
xfs_inodegc_shrinker_scan(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct xfs_mount	*mp = shrink->private_data;
	struct xfs_inodegc	*gc;
	int			cpu;
	bool			no_items = true;

	if (!xfs_is_inodegc_enabled(mp))
		return SHRINK_STOP;

	trace_xfs_inodegc_shrinker_scan(mp, sc, __return_address);

	for_each_cpu(cpu, &mp->m_inodegc_cpumask) {
		gc = per_cpu_ptr(mp->m_inodegc, cpu);
		if (!llist_empty(&gc->list)) {
			unsigned int	h = READ_ONCE(gc->shrinker_hits);

			WRITE_ONCE(gc->shrinker_hits, h + 1);
			mod_delayed_work_on(cpu, mp->m_inodegc_wq, &gc->work, 0);
			no_items = false;
		}
	}

	/*
	 * If there are no inodes to inactivate, we don't want the shrinker
	 * to think there's deferred work to call us back about.
	 */
	if (no_items)
		return LONG_MAX;

	return SHRINK_STOP;
}

/* Register a shrinker so we can accelerate inodegc and throttle queuing. */
int
xfs_inodegc_register_shrinker(
	struct xfs_mount	*mp)
{
	mp->m_inodegc_shrinker = shrinker_alloc(SHRINKER_NONSLAB,
						"xfs-inodegc:%s",
						mp->m_super->s_id);
	if (!mp->m_inodegc_shrinker)
		return -ENOMEM;

	mp->m_inodegc_shrinker->count_objects = xfs_inodegc_shrinker_count;
	mp->m_inodegc_shrinker->scan_objects = xfs_inodegc_shrinker_scan;
	mp->m_inodegc_shrinker->seeks = 0;
	mp->m_inodegc_shrinker->batch = XFS_INODEGC_SHRINKER_BATCH;
	mp->m_inodegc_shrinker->private_data = mp;

	shrinker_register(mp->m_inodegc_shrinker);

	return 0;
}
