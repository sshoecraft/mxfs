// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>

#include "xfs_platform.h"
#include <linux/hashtable.h>	/* sess37 CREATEINT task registry */
#include "../dlm/v5_mount.h"
#include "xfs_mxfs_dlm.h"
#include "../mxfs_clayer/pinned_resource.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_dir2.h"
#include "libxfs/xfs_dir2_priv.h"
#include "xfs_attr.h"
#include "xfs_bit.h"
#include "xfs_trans_space.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_inode_item.h"
#include "xfs_iunlink_item.h"
#include "xfs_ialloc.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_quota.h"
#include "xfs_filestream.h"
#include "xfs_trace.h"
#include "xfs_icache.h"
#include "xfs_symlink.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_bmap_btree.h"
#include "xfs_reflink.h"
#include "xfs_ag.h"
#include "xfs_log_priv.h"
#include "xfs_health.h"
#include <linux/sched/debug.h>	/* sched_show_task — P129 probe */
#include "xfs_pnfs.h"
#include "xfs_parent.h"
#include "xfs_xattr.h"
#include "xfs_inode_util.h"
#include "xfs_metafile.h"

struct kmem_cache *xfs_inode_cache;

/*
 * ccloop c7ee71c6 sess21 — P192: RE-CHECK THE EXTENT-MAP PREDICATE UNDER THE
 * LOCK WE JUST TOOK.
 *
 * ROOT (proven, 32/caw soak, WARNING at include/linux/rwsem.h:85 in
 * xfs_assert_ilocked, 3 of 4 nodes):
 *
 *     openat -> xfs_vn_lookup -> xfs_lookup -> xfs_dir_lookup
 *       -> xfs_dir_lookup_args -> xfs_dir2_format
 *          -> xfs_bmap_last_offset -> xfs_bmap_last_extent
 *             -> xfs_iread_extents  ->  xfs_assert_ilocked(ip, XFS_ILOCK_EXCL)
 *
 * xfs_ilock_{data,attr}_map_shared decide SHARED-vs-EXCL by testing
 * xfs_need_iread_extents() BEFORE calling xfs_ilock().  Upstream that is
 * sound: nothing can unload a fork without already holding ILOCK_EXCL, so the
 * predicate cannot change under you.
 *
 * MXFS BREAKS THAT INVARIANT.  xfs_ilock() recurses into the MXFS DLM acquire
 * hook, and that hook can run mxfs_dlm_reload_inode() to adopt a
 * peer-committed on-disk image (see the sess115 comment in xfs_dir_lookup,
 * which documents the same recursion for a different consequence).  A reload
 * resets the fork, so the predicate we evaluated a moment ago is stale by the
 * time xfs_ilock() returns — and it is not even a rare cross-CPU race, it is
 * the very call we make next that invalidates it.  We then proceed holding
 * only SHARED into a path that requires EXCL: the assertion fires, and worse,
 * two SHARED holders can race to populate the same in-core extent map.
 *
 * Fix: re-evaluate the predicate AFTER the acquire.  If the fork now needs an
 * iread and we only got SHARED, drop and retake at EXCL.  Taking EXCL when it
 * turns out not to be needed is merely heavier, never incorrect, so a single
 * retry is sufficient — no unbounded loop.
 *
 * mxfs.ilock_map_recheck=0 restores the pre-fix behaviour for A/B.
 */
int mxfs_ilock_map_recheck_enabled = 1;

static uint
mxfs_ilock_map_recheck(
	struct xfs_inode	*ip,
	struct xfs_ifork	*ifp,
	uint			lock_mode,
	const char		*which)
{
	uint			new_mode;

	if (!mxfs_ilock_map_recheck_enabled)
		return lock_mode;
	/* Only the SHARED outcome is at risk; EXCL already satisfies the
	 * assertion no matter what the reload did. */
	if (!(lock_mode & XFS_ILOCK_SHARED))
		return lock_mode;
	if (likely(!xfs_need_iread_extents(ifp)))
		return lock_mode;

	{
		static atomic_t p192_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p192_n) <= 2000)
			pr_warn_ratelimited(
				"mxfs: P192-ILOCK-MAP-RACE ino=%llu fork=%s fmt=%d nextents=%llu comm=%s — fork needed an iread AFTER xfs_ilock returned SHARED (DLM acquire hook reloaded the inode); upgrading to EXCL\n",
				(unsigned long long)ip->i_ino, which,
				ifp->if_format,
				(unsigned long long)ifp->if_nextents,
				current->comm);
	}

	/* sess38 leak-C fix: preserve ALL mxfs policy bits across the base-mode
	 * replacement, not just PRIREAD.  Dropping CREATEINT here regressed the
	 * reacquire to wire PR (PRIREAD) right after the EX was granted. */
	new_mode = XFS_ILOCK_EXCL |
		   (lock_mode & (XFS_ILOCK_MXFS_PRIREAD |
				 XFS_ILOCK_MXFS_CREATEINT));
	if (unlikely((lock_mode & XFS_ILOCK_MXFS_CREATEINT) &&
		     mxfs_instr_enabled))
		pr_warn_ratelimited("mxfs: P-CI-C recheck-under-arm ino=%llu (CREATEINT preserved across relock)\n",
			(unsigned long long)ip->i_ino);
	xfs_iunlock(ip, lock_mode);
	xfs_ilock(ip, new_mode);
	return new_mode;
}

/*
 * sess37 CREATE-INTENT registry (FIX-26 task-registry pattern): xfs_lookup
 * brackets its xfs_dir_lookup call when the VFS lookup carries create
 * intent; xfs_ilock_data_map_shared consults it ONCE per dir lookup (not
 * per ilock) and tags the dir ILOCK with XFS_ILOCK_MXFS_CREATEINT so the
 * cluster mode is EX from the lookup on.  Stack-resident entries, keyed by
 * task — lookups never nest per task, so one entry per task suffices.
 */
struct mxfs_createint_ent {
	struct hlist_node	node;
	struct task_struct	*task;
	xfs_ino_t		dirino;
};
#define MXFS_CREATEINT_HASH_BITS 6
static DEFINE_SPINLOCK(mxfs_createint_lock);
static DEFINE_HASHTABLE(mxfs_createint_hash, MXFS_CREATEINT_HASH_BITS);

static void
mxfs_createint_enter(struct mxfs_createint_ent *ent, xfs_ino_t dirino)
{
	ent->task = current;
	ent->dirino = dirino;
	spin_lock(&mxfs_createint_lock);
	hash_add(mxfs_createint_hash, &ent->node, (unsigned long)current);
	spin_unlock(&mxfs_createint_lock);
}

static void
mxfs_createint_exit(struct mxfs_createint_ent *ent)
{
	spin_lock(&mxfs_createint_lock);
	hash_del(&ent->node);
	spin_unlock(&mxfs_createint_lock);
}

static bool
mxfs_createint_active(xfs_ino_t dirino)
{
	struct mxfs_createint_ent *e;
	bool hit = false;

	spin_lock(&mxfs_createint_lock);
	hash_for_each_possible(mxfs_createint_hash, e, node,
			       (unsigned long)current) {
		if (e->task == current && e->dirino == dirino) {
			hit = true;
			break;
		}
	}
	spin_unlock(&mxfs_createint_lock);
	return hit;
}

/*
 * sess38 (GPT design review): single gate+consult used by EVERY lock-mode
 * computation inside the armed window — xfs_ilock_data_map_shared AND
 * mxfs_dlm_dir_consumer_refresh (leak A: its direct ILOCK_SHARED bypassed
 * the consult, taking a wire-PR tenure right before the create's EX and
 * preserving the EDEADLK/drain cycle CREATEINT exists to kill).
 */
bool
mxfs_createint_dir_armed(
	struct xfs_inode	*ip)
{
	extern int mxfs_create_intent_ex;

	return unlikely(mxfs_create_intent_ex &&
			ip->i_mount->m_mxfs_dlm &&
			S_ISDIR(VFS_I(ip)->i_mode)) &&
	       mxfs_createint_active(ip->i_ino);
}


/*
 * These two are wrapper routines around the xfs_ilock() routine used to
 * centralize some grungy code.  They are used in places that wish to lock the
 * inode solely for reading the extents.  The reason these places can't just
 * call xfs_ilock(ip, XFS_ILOCK_SHARED) is that the inode lock also guards to
 * bringing in of the extents from disk for a file in b-tree format.  If the
 * inode is in b-tree format, then we need to lock the inode exclusively until
 * the extents are read in.  Locking it exclusively all the time would limit
 * our parallelism unnecessarily, though.  What we do instead is check to see
 * if the extents have been read in yet, and only lock the inode exclusively
 * if they have not.
 *
 * The functions return a value which should be given to the corresponding
 * xfs_iunlock() call.
 */
uint
xfs_ilock_data_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;
	/* sess38 leak-B fix: consult ONCE, apply the tag AFTER the base mode
	 * is final.  The old order set CREATEINT on SHARED and the need_iread
	 * branch's `lock_mode = XFS_ILOCK_EXCL` wiped it, regressing every
	 * fresh-adopt create-intent lookup to wire PR (PRIREAD) — preserving
	 * the per-visit PR->EDEADLK->drain->EX cycle CREATEINT exists to kill. */
	bool			ci = mxfs_createint_dir_armed(ip);

	if (xfs_need_iread_extents(&ip->i_df)) {
		lock_mode = XFS_ILOCK_EXCL;
		/*
		 * sess1 (ccloop 46efd8b6) iread-PR (RULE-4 PROVEN root of the
		 * 32/caw cache_coherency verify collapse): this EXCL exists
		 * only to serialize the in-core extent-map load; cluster-wide
		 * a PR grant fully protects it (no peer can modify under our
		 * PR, and the disk image is Invariant-1 consistent).  Tag the
		 * acquire so xfs_ilock/xfs_iunlock take/release the DLM lock
		 * at PR instead of EX.  Without this, every real fork adopt
		 * turns the NEXT lookup into a cluster EX: at 32 nodes the
		 * post-rename verify had 12+ nodes requesting EX against 31
		 * PR-cycling readers -> 3x120s starvation -> rc=-110 -> FS
		 * shutdown (measured, build 6CE7E022).  A/B: iread_pr=0.
		 */
		if (mxfs_iread_pr && ip->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
			lock_mode |= XFS_ILOCK_MXFS_PRIREAD;
		if (unlikely(ci && mxfs_instr_enabled))
			pr_warn_ratelimited("mxfs: P-CI-B iread-under-arm ino=%llu (CREATEINT preserved over PRIREAD)\n",
				(unsigned long long)ip->i_ino);
	}
	if (unlikely(ci))
		lock_mode |= XFS_ILOCK_MXFS_CREATEINT;
	xfs_ilock(ip, lock_mode);
	lock_mode = mxfs_ilock_map_recheck(ip, &ip->i_df, lock_mode, "data");
	return lock_mode;
}

uint
xfs_ilock_attr_map_shared(
	struct xfs_inode	*ip)
{
	uint			lock_mode = XFS_ILOCK_SHARED;

	if (xfs_inode_has_attr_fork(ip) && xfs_need_iread_extents(&ip->i_af)) {
		lock_mode = XFS_ILOCK_EXCL;
		/* sess1 (ccloop 46efd8b6) iread-PR — same as the data-fork
		 * variant above: attr-fork extent load needs only cluster PR. */
		if (mxfs_iread_pr && ip->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
			lock_mode |= XFS_ILOCK_MXFS_PRIREAD;
	}
	xfs_ilock(ip, lock_mode);
	lock_mode = mxfs_ilock_map_recheck(ip, &ip->i_af, lock_mode, "attr");
	return lock_mode;
}

/*
 * You can't set both SHARED and EXCL for the same lock,
 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_MMAPLOCK_SHARED,
 * XFS_MMAPLOCK_EXCL, XFS_ILOCK_SHARED, XFS_ILOCK_EXCL are valid values
 * to set in lock_flags.
 */
static inline void
xfs_lock_flags_assert(
	uint		lock_flags)
{
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
		(XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL)) !=
		(XFS_MMAPLOCK_SHARED | XFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
		(XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	/* sess1 (ccloop 46efd8b6): XFS_ILOCK_MXFS_PRIREAD rides outside
	 * XFS_LOCK_MASK and is valid only alongside ILOCK_EXCL. */
	ASSERT(!(lock_flags & XFS_ILOCK_MXFS_PRIREAD) ||
	       (lock_flags & XFS_ILOCK_EXCL));
	/* sess37: CREATEINT rides outside the mask too; valid only with an
	 * ILOCK (shared or excl) — it upgrades the CLUSTER mode, never the
	 * local lock. */
	ASSERT(!(lock_flags & XFS_ILOCK_MXFS_CREATEINT) ||
	       (lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_SUBCLASS_MASK |
			       XFS_ILOCK_MXFS_PRIREAD |
			       XFS_ILOCK_MXFS_CREATEINT)) == 0);
	ASSERT(lock_flags != 0);
}

/*
 * In addition to i_rwsem in the VFS inode, the xfs inode contains 2
 * multi-reader locks: invalidate_lock and the i_lock.  This routine allows
 * various combinations of the locks to be obtained.
 *
 * The 3 locks should always be ordered so that the IO lock is obtained first,
 * the mmap lock second and the ilock last in order to prevent deadlock.
 *
 * Basic locking order:
 *
 * i_rwsem -> invalidate_lock -> page_lock -> i_ilock
 *
 * mmap_lock locking order:
 *
 * i_rwsem -> page lock -> mmap_lock
 * mmap_lock -> invalidate_lock -> page_lock
 *
 * The difference in mmap_lock locking order mean that we cannot hold the
 * invalidate_lock over syscall based read(2)/write(2) based IO. These IO paths
 * can fault in pages during copy in/out (for buffered IO) or require the
 * mmap_lock in get_user_pages() to map the user pages into the kernel address
 * space for direct IO. Similarly the i_rwsem cannot be taken inside a page
 * fault because page faults already hold the mmap_lock.
 *
 * Hence to serialise fully against both syscall and mmap based IO, we need to
 * take both the i_rwsem and the invalidate_lock. These locks should *only* be
 * both taken in places where we need to invalidate the page cache in a race
 * free manner (e.g. truncate, hole punch and other extent manipulation
 * functions).
 */
/* sess73 (RULE 4): forensic dump for a wedged ip->i_lock acquire — names the
 * last writer/reader/unlock call sites + outstanding SHARED-hold count + raw
 * rwsem count, so the leaking storm path that stranded the lock is identified
 * from the victim's context.  Ratelimited by the caller's 5s/30s gate. */
static void
mxfs_ilk_dump_stuck(struct xfs_inode *ip, uint lock_flags, unsigned int waited_ms)
{
	pr_warn("mxfs: P73-ILOCK-STUCK ino=%llu want=%s waited_ms=%u rd_held=%d cnt=%ld wr_last=%pS wr_pid=%d wr_comm=%s rd_last=%pS rd_pid=%d rd_comm=%s un_last=%pS\n",
		(unsigned long long)ip->i_ino,
		(lock_flags & XFS_ILOCK_EXCL) ? "EX" : "SH",
		waited_ms,
		atomic_read(&ip->i_mxfs_ilk_rd_held),
		atomic_long_read(&ip->i_lock.count),
		(void *)ip->i_mxfs_ilk_wr_ret,
		ip->i_mxfs_ilk_wr_pid, ip->i_mxfs_ilk_wr_comm,
		(void *)ip->i_mxfs_ilk_rd_ret,
		ip->i_mxfs_ilk_rd_pid, ip->i_mxfs_ilk_rd_comm,
		(void *)ip->i_mxfs_ilk_un_ret);
}
void
xfs_ilock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock(ip, lock_flags, _RET_IP_);

	xfs_lock_flags_assert(lock_flags);

	/*
	 * ccloop-4dd7 sess4 (b61r6 holder-stack proof, RULE 4): the IOLOCK
	 * i_rwsem must be taken BEFORE the DLM admission, not after.  The old
	 * "distributed lock before local semaphore" order let every queued
	 * writer of a contended file hold a PHANTOM DLM EX admission while
	 * parked on the rwsem (P36-EXH-STACK: bash in
	 * xfs_file_buffered_write -> xfs_ilock -> rwsem_down_write_slowpath
	 * with the ino-135 admission held 184s).  VFS-entered paths (setattr,
	 * truncate) take i_rwsem first and their DLM ILOCK admission second,
	 * so the two orders deadlock locally the moment a peer BAST closes
	 * the fast path: rwsem holder waits DLM (slow path behind demote),
	 * demote waits ex_holders==0, ex_holders includes the parked rwsem
	 * waiters' admissions -> 3-party wedge -> both nodes -110 after 184s
	 * (b58r1/b61r6 dual-shutdown family).  With rwsem-first the global
	 * order is i_rwsem -> DLM everywhere, parked waiters hold nothing,
	 * and the demote drains.  Safe: flushers (iflush/xfsaild) take ILOCK,
	 * never i_rwsem, so a cross-node DLM wait under i_rwsem blocks only
	 * same-file ops that would queue anyway.
	 */
	if (lock_flags & XFS_IOLOCK_EXCL) {
		down_write_nested(&VFS_I(ip)->i_rwsem,
				  XFS_IOLOCK_DEP(lock_flags));
	} else if (lock_flags & XFS_IOLOCK_SHARED) {
		down_read_nested(&VFS_I(ip)->i_rwsem,
				 XFS_IOLOCK_DEP(lock_flags));
	}

	/* MXFS DLM: acquire cached distributed lock (after the IOLOCK rwsem,
	 * before the mmap/ilock semaphores) */
	if (ip->i_mount->m_mxfs_dlm &&
	    (lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED |
			   XFS_ILOCK_EXCL | XFS_ILOCK_SHARED))) {
		uint8_t mode = (lock_flags & (XFS_IOLOCK_EXCL | XFS_ILOCK_EXCL)) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;
		/* sess1 (ccloop 46efd8b6) iread-PR: an ILOCK_EXCL tagged
		 * PRIREAD serializes only the local extent-map load — the
		 * cluster needs PR, not EX (see xfs_ilock_data_map_shared).
		 * Never demote a combined IOLOCK_EXCL request. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_PRIREAD) &&
		    !(lock_flags & XFS_IOLOCK_EXCL))
			mode = MXFS_LOCK_PR;
		/* sess37 CREATEINT: create-intent dir lookup wants the cluster
		 * at EX from the lookup on (kills the per-create PR->EDEADLK->
		 * drain->EX cycle).  Wins over PRIREAD by ordering. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_CREATEINT))
			mode = MXFS_LOCK_EX;
		/*
		 * sess45 P100: capture the call path that takes a WRITE lock on
		 * a regular-file inode living in a PEER's affine AG.  A node
		 * should only need to write inodes in its own affine AG; taking
		 * EX on a peer's file is what lets it flush a stale di_size and
		 * clobber the peer (P97).  dump_stack once per ratelimit window.
		 */
		{ extern int mxfs_instr_enabled;
		  static atomic_t p100_dumped = ATOMIC_INIT(0);
		  struct xfs_mount *p100mp = ip->i_mount;
		  if (unlikely(mxfs_instr_enabled) && mode == MXFS_LOCK_EX &&
		      S_ISREG(VFS_I(ip)->i_mode) && p100mp->m_maxagi &&
		      !mxfs_v5_dlm_is_single_node(p100mp->m_mxfs_dlm) &&
		      XFS_INO_TO_AGNO(p100mp, ip->i_ino) !=
		        (p100mp->m_mxfs_node_slot % p100mp->m_maxagi)) {
			pr_warn_ratelimited("mxfs: P100 EX-on-peer-file ino=%llu ino_ag=%u node_slot=%u lock_flags=0x%x\n",
				(unsigned long long)ip->i_ino,
				XFS_INO_TO_AGNO(p100mp, ip->i_ino),
				p100mp->m_mxfs_node_slot, lock_flags);
			if (atomic_inc_return(&p100_dumped) <= 3)
				dump_stack();
		  } }
		mxfs_dlm_ilock_begin(ip, mode);
	}

	if (lock_flags & XFS_MMAPLOCK_EXCL) {
		down_write_nested(&VFS_I(ip)->i_mapping->invalidate_lock,
				  XFS_MMAPLOCK_DEP(lock_flags));
	} else if (lock_flags & XFS_MMAPLOCK_SHARED) {
		down_read_nested(&VFS_I(ip)->i_mapping->invalidate_lock,
				 XFS_MMAPLOCK_DEP(lock_flags));
	}

	/*
	 * sess73 diagnostic busy-spin ILOCK acquire REVERTED (sess-tcp): the
	 * trylock+cond_resched spin was a "revert after capture" diagnostic that
	 * severely distorts lock timing and starves peers — restored to the
	 * standard sleeping nested acquire so 2-node timing is trustworthy.
	 */
	if (lock_flags & XFS_ILOCK_EXCL)
		down_write_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
	else if (lock_flags & XFS_ILOCK_SHARED)
		down_read_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));

	mxfs_ilk_note_lock(ip, lock_flags, _RET_IP_);
	/* sess33 writer-quiescence census — open-coded (NOT in note_lock:
	 * the raw forensic note_lock callers must stay uncounted).  A write
	 * rwsem has exactly one holder, so the post-inc value is 1. */
	if (lock_flags & XFS_ILOCK_EXCL)
		WARN_ON_ONCE(atomic_inc_return(&ip->i_mxfs_ilk_wr_held) != 1);
}

/*
 * This is just like xfs_ilock(), except that the caller
 * is guaranteed not to sleep.  It returns 1 if it gets
 * the requested locks and 0 otherwise.  If the IO lock is
 * obtained but the inode lock cannot be, then the IO lock
 * is dropped before returning.
 *
 * ip -- the inode being locked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be locked.  See the comment for xfs_ilock() for a list
 *	 of valid values.
 */
/* sess132 (RULE 4): ILOCK last-locker forensics — the 16-node create-storm
 * wedge is a bast_process drain blocked forever on i_lock with NO live
 * holder (leaked ILOCK).  Record every ILOCK take/release with the caller
 * IP so the stuck-drain probe (P132-ILOCK-STUCK in xfs_mxfs_dlm.c) can name
 * the leaking call path.  SHARED holds also keep an outstanding counter. */
void
mxfs_ilk_note_lock(
	struct xfs_inode	*ip,
	uint			lock_flags,
	unsigned long		ret_ip)
{
	if (lock_flags & XFS_ILOCK_EXCL) {
		ip->i_mxfs_ilk_wr_ret = ret_ip;
		ip->i_mxfs_ilk_wr_pid = current->pid;
		memcpy(ip->i_mxfs_ilk_wr_comm, current->comm,
		       sizeof(ip->i_mxfs_ilk_wr_comm));
	} else if (lock_flags & XFS_ILOCK_SHARED) {
		atomic_inc(&ip->i_mxfs_ilk_rd_held);
		ip->i_mxfs_ilk_rd_ret = ret_ip;
		ip->i_mxfs_ilk_rd_pid = current->pid;
		memcpy(ip->i_mxfs_ilk_rd_comm, current->comm,
		       sizeof(ip->i_mxfs_ilk_rd_comm));
	}
}

void
mxfs_ilk_note_unlock(
	struct xfs_inode	*ip,
	uint			lock_flags,
	unsigned long		ret_ip)
{
	if (lock_flags & XFS_ILOCK_SHARED)
		atomic_dec(&ip->i_mxfs_ilk_rd_held);
	else if (lock_flags & XFS_ILOCK_EXCL)
		/* sess33 writer-quiescence census.  Both callers (xfs_iunlock,
		 * mxfs_iunlock_rwsems_raw) release xfs_ilock-taken locks, so
		 * inc/dec pair; the raw reload releases bypass this helper and
		 * stay uncounted, matching their uncounted raw takes.  The dec
		 * runs in the mutator's thread AFTER its commit's CIL insert
		 * (program order), so a relbar waiter observing 0 may trust
		 * log_force to capture everything the holder stamped.
		 * atomic_dec_return is fully ordered — the pend++/CIL stores
		 * are visible before the 0.  Underflow would mean an unpaired
		 * release — scream once. */
		WARN_ON_ONCE(atomic_dec_return(&ip->i_mxfs_ilk_wr_held) < 0);
	if (lock_flags & (XFS_ILOCK_EXCL | XFS_ILOCK_SHARED))
		ip->i_mxfs_ilk_un_ret = ret_ip;
}

int
xfs_ilock_nowait(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock_nowait(ip, lock_flags, _RET_IP_);

	xfs_lock_flags_assert(lock_flags);

	/*
	 * ccloop-4dd7 sess4: rwsem-first here too (mirrors xfs_ilock's b61r6
	 * inversion fix) — even the transient trylock-admission window keeps
	 * the global i_rwsem -> DLM order.
	 */
	if (lock_flags & XFS_IOLOCK_EXCL) {
		if (!down_write_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	} else if (lock_flags & XFS_IOLOCK_SHARED) {
		if (!down_read_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	}

	/*
	 * MXFS DLM: try non-blocking distributed lock (after the IOLOCK
	 * rwsem).  Only for IOLOCK — ILOCK nowait callers (xfsaild, reclaim)
	 * run in atomic context where DLM CAW I/O cannot sleep.
	 */
	if (ip->i_mount->m_mxfs_dlm &&
	    (lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED))) {
		uint8_t mode = (lock_flags & XFS_IOLOCK_EXCL) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;
		if (!mxfs_dlm_ilock_try(ip, mode))
			goto out_undo_iolock_rwsem;
	}

	if (lock_flags & XFS_MMAPLOCK_EXCL) {
		if (!down_write_trylock(&VFS_I(ip)->i_mapping->invalidate_lock))
			goto out_undo_dlm;
	} else if (lock_flags & XFS_MMAPLOCK_SHARED) {
		if (!down_read_trylock(&VFS_I(ip)->i_mapping->invalidate_lock))
			goto out_undo_dlm;
	}

	if (lock_flags & XFS_ILOCK_EXCL) {
		if (!down_write_trylock(&ip->i_lock))
			goto out_undo_mmaplock;
	} else if (lock_flags & XFS_ILOCK_SHARED) {
		if (!down_read_trylock(&ip->i_lock))
			goto out_undo_mmaplock;
	}
	mxfs_ilk_note_lock(ip, lock_flags, _RET_IP_);
	/* sess33 writer-quiescence census (see xfs_ilock) */
	if (lock_flags & XFS_ILOCK_EXCL)
		WARN_ON_ONCE(atomic_inc_return(&ip->i_mxfs_ilk_wr_held) != 1);
	return 1;

out_undo_mmaplock:
	if (lock_flags & XFS_MMAPLOCK_EXCL)
		up_write(&VFS_I(ip)->i_mapping->invalidate_lock);
	else if (lock_flags & XFS_MMAPLOCK_SHARED)
		up_read(&VFS_I(ip)->i_mapping->invalidate_lock);
out_undo_dlm:
	/* MXFS DLM: undo holder count (keep lock cached) — IOLOCK only */
	if (ip->i_mount->m_mxfs_dlm &&
	    (lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED))) {
		uint8_t mode = (lock_flags & XFS_IOLOCK_EXCL) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;
		mxfs_dlm_ilock_end(ip, mode);
	}
out_undo_iolock_rwsem:
	if (lock_flags & XFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);
out:
	return 0;
}

/*
 * xfs_iunlock() is used to drop the inode locks acquired with
 * xfs_ilock() and xfs_ilock_nowait().  The caller must pass
 * in the flags given to xfs_ilock() or xfs_ilock_nowait() so
 * that we know which locks to drop.
 *
 * ip -- the inode being unlocked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be unlocked.  See the comment for xfs_ilock() for a list
 *	 of valid values for this parameter.
 *
 */
void
xfs_iunlock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	xfs_lock_flags_assert(lock_flags);

	if (lock_flags & XFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);

	if (lock_flags & XFS_MMAPLOCK_EXCL)
		up_write(&VFS_I(ip)->i_mapping->invalidate_lock);
	else if (lock_flags & XFS_MMAPLOCK_SHARED)
		up_read(&VFS_I(ip)->i_mapping->invalidate_lock);

	mxfs_ilk_note_unlock(ip, lock_flags, _RET_IP_);
	if (lock_flags & XFS_ILOCK_EXCL)
		up_write(&ip->i_lock);
	else if (lock_flags & XFS_ILOCK_SHARED)
		up_read(&ip->i_lock);

	/* MXFS DLM: decrement holders, process deferred BAST if last */
	if (ip->i_mount->m_mxfs_dlm &&
	    (lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED |
			   XFS_ILOCK_EXCL | XFS_ILOCK_SHARED))) {
		uint8_t mode = (lock_flags & (XFS_IOLOCK_EXCL | XFS_ILOCK_EXCL)) ?
			MXFS_LOCK_EX : MXFS_LOCK_PR;
		/* sess1 (ccloop 46efd8b6) iread-PR: mirror xfs_ilock's mapping
		 * so the PR holder count taken at begin is the one released. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_PRIREAD) &&
		    !(lock_flags & XFS_IOLOCK_EXCL))
			mode = MXFS_LOCK_PR;
		/* sess37 CREATEINT: mirror xfs_ilock so the EX holder count
		 * taken at begin is the one released.  Wins over PRIREAD. */
		if (unlikely(lock_flags & XFS_ILOCK_MXFS_CREATEINT))
			mode = MXFS_LOCK_EX;
		mxfs_dlm_ilock_end(ip, mode);
	}

	trace_xfs_iunlock(ip, lock_flags, _RET_IP_);
}

/*
 * give up write locks.  the i/o lock cannot be held nested
 * if it is being demoted.
 */
void
xfs_ilock_demote(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	ASSERT(lock_flags & (XFS_IOLOCK_EXCL|XFS_MMAPLOCK_EXCL|XFS_ILOCK_EXCL));
	ASSERT((lock_flags &
		~(XFS_IOLOCK_EXCL|XFS_MMAPLOCK_EXCL|XFS_ILOCK_EXCL)) == 0);

	if (lock_flags & XFS_ILOCK_EXCL) {
		downgrade_write(&ip->i_lock);
		/* sess33 writer-quiescence census: EXCL became SHARED (no
		 * in-tree ILOCK demote callers today — insurance).  Adjust
		 * AFTER the downgrade: the brief overshoot only makes a
		 * relbar waiter wait a touch longer (safe direction); a
		 * pre-downgrade dec could publish 0 while still write-held.
		 * NOTE for future demote users: demoting between a
		 * xfs_trans_log_inode stamp and CIL insertion would defeat
		 * the wr_held==0 inference — don't. */
		WARN_ON_ONCE(atomic_dec_return(&ip->i_mxfs_ilk_wr_held) < 0);
		atomic_inc(&ip->i_mxfs_ilk_rd_held);
	}
	if (lock_flags & XFS_MMAPLOCK_EXCL)
		downgrade_write(&VFS_I(ip)->i_mapping->invalidate_lock);
	if (lock_flags & XFS_IOLOCK_EXCL) {
		downgrade_write(&VFS_I(ip)->i_rwsem);
		/* MXFS DLM: adjust holder counts (EX→PR) */
		if (ip->i_mount->m_mxfs_dlm)
			mxfs_dlm_ilock_demote(ip);
	}

	trace_xfs_ilock_demote(ip, lock_flags, _RET_IP_);
}

void
xfs_assert_ilocked(
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	/*
	 * Sometimes we assert the ILOCK is held exclusively, but we're in
	 * a workqueue, so lockdep doesn't know we're the owner.
	 */
	if (lock_flags & XFS_ILOCK_SHARED)
		rwsem_assert_held(&ip->i_lock);
	else if (lock_flags & XFS_ILOCK_EXCL)
		rwsem_assert_held_write_nolockdep(&ip->i_lock);

	if (lock_flags & XFS_MMAPLOCK_SHARED)
		rwsem_assert_held(&VFS_I(ip)->i_mapping->invalidate_lock);
	else if (lock_flags & XFS_MMAPLOCK_EXCL)
		rwsem_assert_held_write(&VFS_I(ip)->i_mapping->invalidate_lock);

	if (lock_flags & XFS_IOLOCK_SHARED)
		rwsem_assert_held(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_EXCL)
		rwsem_assert_held_write(&VFS_I(ip)->i_rwsem);
}

/*
 * xfs_lockdep_subclass_ok() is only used in an ASSERT, so is only called when
 * DEBUG or XFS_WARN is set. And MAX_LOCKDEP_SUBCLASSES is then only defined
 * when CONFIG_LOCKDEP is set. Hence the complex define below to avoid build
 * errors and warnings.
 */
#if (defined(DEBUG) || defined(XFS_WARN)) && defined(CONFIG_LOCKDEP)
static bool
xfs_lockdep_subclass_ok(
	int subclass)
{
	return subclass < MAX_LOCKDEP_SUBCLASSES;
}
#else
#define xfs_lockdep_subclass_ok(subclass)	(true)
#endif

/*
 * Bump the subclass so xfs_lock_inodes() acquires each lock with a different
 * value. This can be called for any type of inode lock combination, including
 * parent locking. Care must be taken to ensure we don't overrun the subclass
 * storage fields in the class mask we build.
 */
static inline uint
xfs_lock_inumorder(
	uint	lock_mode,
	uint	subclass)
{
	uint	class = 0;

	ASSERT(!(lock_mode & XFS_ILOCK_PARENT));
	ASSERT(xfs_lockdep_subclass_ok(subclass));

	if (lock_mode & (XFS_IOLOCK_SHARED|XFS_IOLOCK_EXCL)) {
		ASSERT(subclass <= XFS_IOLOCK_MAX_SUBCLASS);
		class += subclass << XFS_IOLOCK_SHIFT;
	}

	if (lock_mode & (XFS_MMAPLOCK_SHARED|XFS_MMAPLOCK_EXCL)) {
		ASSERT(subclass <= XFS_MMAPLOCK_MAX_SUBCLASS);
		class += subclass << XFS_MMAPLOCK_SHIFT;
	}

	if (lock_mode & (XFS_ILOCK_SHARED|XFS_ILOCK_EXCL)) {
		ASSERT(subclass <= XFS_ILOCK_MAX_SUBCLASS);
		class += subclass << XFS_ILOCK_SHIFT;
	}

	return (lock_mode & ~XFS_LOCK_SUBCLASS_MASK) | class;
}

/*
 * sess16 FIX-L3 (a9a03929) helpers for the set-lock functions below.
 *
 * mxfs_setlock_dlm_mode: the exact lock_flags -> DLM mode mapping xfs_ilock
 * uses, so a Phase-A pre-acquire is indistinguishable from the begin that
 * xfs_ilock itself would have issued.  Returns 0 when the flags carry no
 * DLM-relevant lock.
 *
 * mxfs_iunlock_rwsems_raw: release ONLY the local rwsems that
 * xfs_ilock_nowait took — NOT the DLM hold.  Used by set-lock backoff so a
 * Phase-A grant survives the retry (an ilock_end at zero holders fires the
 * pending peer BAST inline and forfeits the grant — the 2/tcp L1 ping-pong
 * livelock).
 */
static uint8_t
mxfs_setlock_dlm_mode(
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	if (!ip->i_mount->m_mxfs_dlm)
		return 0;
	if (!(lock_flags & (XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED |
			    XFS_ILOCK_EXCL | XFS_ILOCK_SHARED)))
		return 0;
	return (lock_flags & (XFS_IOLOCK_EXCL | XFS_ILOCK_EXCL)) ?
		MXFS_LOCK_EX : MXFS_LOCK_PR;
}

static void
mxfs_iunlock_rwsems_raw(
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	mxfs_ilk_note_unlock(ip, lock_flags, _RET_IP_);
	if (lock_flags & XFS_ILOCK_EXCL)
		up_write(&ip->i_lock);
	else if (lock_flags & XFS_ILOCK_SHARED)
		up_read(&ip->i_lock);
	if (lock_flags & XFS_MMAPLOCK_EXCL)
		up_write(&VFS_I(ip)->i_mapping->invalidate_lock);
	else if (lock_flags & XFS_MMAPLOCK_SHARED)
		up_read(&VFS_I(ip)->i_mapping->invalidate_lock);
	if (lock_flags & XFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);
}

/*
 * The following routine will lock n inodes in exclusive mode.  We assume the
 * caller calls us with the inodes in i_ino order.
 *
 * We need to detect deadlock where an inode that we lock is in the AIL and we
 * start waiting for another inode that is locked by a thread in a long running
 * transaction (such as truncate). This can result in deadlock since the long
 * running trans might need to wait for the inode we just locked in order to
 * push the tail and free space in the log.
 *
 * xfs_lock_inodes() can only be used to lock one type of lock at a time -
 * the iolock, the mmaplock or the ilock, but not more than one at a time. If we
 * lock more than one at a time, lockdep will report false positives saying we
 * have violated locking orders.
 */
void
xfs_lock_inodes(
	struct xfs_inode	**ips,
	int			inodes,
	uint			lock_mode)
{
	int			attempts = 0;
	uint			i;
	int			j;
	bool			try_lock;
	bool			dlm_pre[5] = { false, false, false, false, false };
	struct xfs_log_item	*lp;

	/*
	 * Currently supports between 2 and 5 inodes with exclusive locking.  We
	 * support an arbitrary depth of locking here, but absolute limits on
	 * inodes depend on the type of locking and the limits placed by
	 * lockdep annotations in xfs_lock_inumorder.  These are all checked by
	 * the asserts.
	 */
	ASSERT(ips && inodes >= 2 && inodes <= 5);
	ASSERT(lock_mode & (XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL |
			    XFS_ILOCK_EXCL));
	ASSERT(!(lock_mode & (XFS_IOLOCK_SHARED | XFS_MMAPLOCK_SHARED |
			      XFS_ILOCK_SHARED)));
	ASSERT(!(lock_mode & XFS_MMAPLOCK_EXCL) ||
		inodes <= XFS_MMAPLOCK_MAX_SUBCLASS + 1);
	ASSERT(!(lock_mode & XFS_ILOCK_EXCL) ||
		inodes <= XFS_ILOCK_MAX_SUBCLASS + 1);

	if (lock_mode & XFS_IOLOCK_EXCL) {
		ASSERT(!(lock_mode & (XFS_MMAPLOCK_EXCL | XFS_ILOCK_EXCL)));
	} else if (lock_mode & XFS_MMAPLOCK_EXCL)
		ASSERT(!(lock_mode & XFS_ILOCK_EXCL));

	/*
	 * sess16 FIX-L3 (a9a03929, k1 2/tcp tds wedge) — Phase A: acquire
	 * EVERY set member's cross-node DLM grant FIRST, in ascending-ino
	 * order (the exact order and mode xfs_ilock would have used), and
	 * HOLD each until the caller's xfs_iunlock.  The GFS2 pattern: every
	 * blocking cross-node wait happens while we hold NO rwsems, so all
	 * inodes stay flushable and peer AG BAST drains never stall behind
	 * us (captured k1 wedge: rename blocked in the dir PR->EX conversion
	 * with the child's ILOCK held -> iflush_cluster ILOCK_SHARED-nowait
	 * skip -> P67-AG-BAST-STALL loop -> peer starved 60s+ on AG-4).
	 * Ascending includes NON-dirs: the L2 dirs-first variant made every
	 * remove hold the shared dir's EX across its cross-node CHILD
	 * acquire, convoying all peers' creates (8/tcp L1: drc round-12
	 * create phase 200s+ -> budget timeout 0/8).  Ascending-all matches
	 * the historical per-xfs_ilock acquisition order, minus the rwsems.
	 * Phase B below takes rwsems via nowait-only (xfs_ilock would
	 * double-hold the DLM), balanced by the caller's xfs_iunlock ->
	 * mxfs_dlm_ilock_end exactly once per inode.  Do NOT rework this as
	 * begin+end-then-retry: with zero holders the pending peer BAST
	 * fires inline in ilock_end and forfeits the grant instantly, so
	 * contending nodes ping-pong the grant without ever completing a
	 * set (2/tcp L1: rm 184s rc=-110 -> shutdown cascade).
	 */
	for (i = 0; i < (uint)inodes; i++) {
		uint8_t pre_mode;

		if (i && (ips[i] == ips[i - 1]))
			continue;
		pre_mode = mxfs_setlock_dlm_mode(ips[i], lock_mode);
		if (!pre_mode)
			continue;
		mxfs_dlm_ilock_begin(ips[i], pre_mode);
		dlm_pre[i] = true;
	}

again:
	try_lock = false;
	i = 0;
	for (; i < inodes; i++) {
		ASSERT(ips[i]);

		if (i && (ips[i] == ips[i - 1]))	/* Already locked */
			continue;

		/*
		 * If try_lock is not set yet, make sure all locked inodes are
		 * not in the AIL.  If any are, set try_lock to be used later.
		 */
		if (!try_lock) {
			for (j = (i - 1); j >= 0 && !try_lock; j--) {
				lp = &ips[j]->i_itemp->ili_item;
				if (lp && test_bit(XFS_LI_IN_AIL, &lp->li_flags))
					try_lock = true;
			}
		}

		/*
		 * If any of the previous locks we have locked is in the AIL,
		 * we must TRY to get the second and subsequent locks. If
		 * we can't get any, we must release all we have
		 * and try again.
		 */
		if (!try_lock) {
			/*
			 * sess16 FIX-L3: Phase-A members take their rwsems via
			 * the nowait arm below — xfs_ilock would add a SECOND
			 * DLM hold on top of Phase A's (the caller's single
			 * iunlock would leak it).  Blocking xfs_ilock remains
			 * only for the no-DLM configuration.
			 */
			if (!dlm_pre[i]) {
				xfs_ilock(ips[i], xfs_lock_inumorder(lock_mode, i));
				continue;
			}
			try_lock = true;
		}

		/* try_lock means we have an inode locked that is in the AIL,
		 * or ips[i] carries a Phase-A DLM hold (rwsem-only from here
		 * on — sess16 FIX-L3). */
		/*
		 * sess58 (ccloop 8ddb16a2) RULE-4 PROVEN FIX (xfs_rename / comm=mv
		 * half of the durable dirent RESURRECTION; companion to the
		 * xfs_lock_two_inodes fix).  xfs_ilock_nowait for ILOCK acquires ONLY
		 * the rwsem, NOT the DLM grant (the IOLOCK-only atomic carve-out), so
		 * a DIR locked here would be modified + committed at its STALE cached
		 * DLM mode (NL/PR, ex_holders==0) — no EX authority -> flush-skipped
		 * (P119-NONEX-FLUSH-SKIP) -> peer reads stale -> dirent RESURRECTS
		 * (TDS-LEFTOVER, PROVEN run3 ino=25701712 comm=mv).  Acquire the dir's
		 * DLM grant explicitly (DIR-only; process context; ips[] is ascending
		 * ino so no DLM ABBA; an inode-DLM release drains only ips[i]).
		 * Released on the unlock-retry path; otherwise balanced by the
		 * caller's xfs_iunlock(ips[i]) -> mxfs_dlm_ilock_end.
		 */
		{
			bool ipi_dir = (lock_mode & XFS_ILOCK_EXCL) &&
				       S_ISDIR(VFS_I(ips[i])->i_mode);

			/*
			 * sess58 lesson retained: xfs_ilock_nowait takes ONLY
			 * the rwsem.  A dir modified at a stale cached mode
			 * loses its commits to the P119-NONEX flush skip, so
			 * every member reaching here must already carry DLM
			 * authority — Phase A holds it (dlm_pre, FIX-L3 all
			 * members).
			 */
			ASSERT(!ipi_dir || dlm_pre[i]);
			if (xfs_ilock_nowait(ips[i],
					     xfs_lock_inumorder(lock_mode, i)))
				continue;
		}

		/*
		 * Unlock all previous guys and try again.  xfs_iunlock will try
		 * to push the tail if the inode is in the AIL.  Phase-A members
		 * release only the RAW rwsems — their DLM hold persists so the
		 * grant cannot be forfeited mid-set (sess16 FIX-L3).
		 */
		attempts++;
		for (j = i - 1; j >= 0; j--) {
			/*
			 * Check to see if we've already unlocked this one.  Not
			 * the first one going back, and the inode ptr is the
			 * same.
			 */
			if (j != (i - 1) && ips[j] == ips[j + 1])
				continue;

			if (dlm_pre[j])
				mxfs_iunlock_rwsems_raw(ips[j], lock_mode);
			else
				xfs_iunlock(ips[j], lock_mode);
		}

		if ((attempts % 5) == 0) {
			delay(1); /* Don't just spin the CPU */
		}
		goto again;
	}
}

/*
 * xfs_lock_two_inodes() can only be used to lock ilock. The iolock and
 * mmaplock must be double-locked separately since we use i_rwsem and
 * invalidate_lock for that. We now support taking one lock EXCL and the
 * other SHARED.
 */
void
xfs_lock_two_inodes(
	struct xfs_inode	*ip0,
	uint			ip0_mode,
	struct xfs_inode	*ip1,
	uint			ip1_mode)
{
	int			attempts = 0;
	bool			pre0 = false;
	bool			pre1 = false;
	struct xfs_log_item	*lp;

	ASSERT(hweight32(ip0_mode) == 1);
	ASSERT(hweight32(ip1_mode) == 1);
	ASSERT(!(ip0_mode & (XFS_IOLOCK_SHARED|XFS_IOLOCK_EXCL)));
	ASSERT(!(ip1_mode & (XFS_IOLOCK_SHARED|XFS_IOLOCK_EXCL)));
	ASSERT(!(ip0_mode & (XFS_MMAPLOCK_SHARED|XFS_MMAPLOCK_EXCL)));
	ASSERT(!(ip1_mode & (XFS_MMAPLOCK_SHARED|XFS_MMAPLOCK_EXCL)));
	ASSERT(ip0->i_ino != ip1->i_ino);

	if (ip0->i_ino > ip1->i_ino) {
		swap(ip0, ip1);
		swap(ip0_mode, ip1_mode);
	}

	/*
	 * sess16 FIX-L3 (a9a03929) — Phase A: BOTH inodes' cross-node DLM
	 * grants FIRST, ascending, in the exact mode xfs_ilock would use,
	 * HELD until the caller's xfs_iunlock.  Any blocking cross-node wait
	 * happens with NO rwsems held, so both inodes stay flushable and
	 * peer AG BAST drains never stall behind this thread (the captured
	 * k1 2/tcp tds wedge: dir PR->EX conversion blocked inside this
	 * function with the other inode's ILOCK held -> iflush_cluster
	 * ILOCK-nowait skip -> AG-4 drain stalled 60s+ -> peer allocation
	 * starved).  Ascending-ALL, not dirs-first: the L2 dirs-first
	 * variant held the shared dir's EX across the cross-node CHILD
	 * acquire and convoyed every peer (8/tcp drc create collapse).
	 * See xfs_lock_inodes.
	 */
	{
		uint8_t m0 = mxfs_setlock_dlm_mode(ip0, ip0_mode);
		uint8_t m1 = mxfs_setlock_dlm_mode(ip1, ip1_mode);
		int abba_laps = 0;

		/*
		 * ccloop-4dd7 sess2 ABBA breaker (RULE-4 PROVEN, 184s cycle):
		 * with cached-grant retention, each node's task fast-paths its
		 * OWN held inode here and cross-node-waits on the other's —
		 * test2's rm held the shared dir (m0) wanting the peer's file
		 * (m1) while test1 symmetrically held the file wanting the
		 * dir; both BASTs deferred behind the "active holder", both
		 * holders blocked -> 184s -> -110 -> forced shutdown.  Bound
		 * the SECOND acquire (~3s); on timeout drop the first
		 * grant-hold (its deferred BAST then fires within ms, feeding
		 * the peer), back off with jitter, and retry both in order.
		 * After 32 laps fall back to the historical unbounded acquire
		 * (its escalation path is still the backstop).
		 */
dlm_two_again:
		if (m0 && !pre0) {
			mxfs_dlm_ilock_begin(ip0, m0);
			pre0 = true;
		}
		if (m1 && !pre1) {
			if (m0 && abba_laps < 32) {
				ip1->i_dlm_tries_rc = 0;
				ip1->i_dlm_tries = 3;
				ip1->i_dlm_tries_owner = current;
				mxfs_dlm_ilock_begin(ip1, m1);
				ip1->i_dlm_tries_owner = NULL;
				ip1->i_dlm_tries = 0;
				if (ip1->i_dlm_tries_rc == -ETIMEDOUT) {
					mxfs_dlm_ilock_end(ip0, m0);
					pre0 = false;
					abba_laps++;
					pr_warn_ratelimited(
					    "mxfs: P-ABBA-BACKOFF ino0=%llu ino1=%llu lap=%d comm=%s — second-inode DLM contended; dropped first, backing off\n",
						(unsigned long long)ip0->i_ino,
						(unsigned long long)ip1->i_ino,
						abba_laps, current->comm);
					msleep(8 + get_random_u32_below(24) +
					       min(abba_laps * 8, 120));
					goto dlm_two_again;
				}
			} else {
				mxfs_dlm_ilock_begin(ip1, m1);
			}
			pre1 = true;
		}
	}

 again:
	if (pre0) {
		/* rwsem only — xfs_ilock would double-hold the DLM grant */
		while (!xfs_ilock_nowait(ip0, xfs_lock_inumorder(ip0_mode, 0))) {
			if ((++attempts % 5) == 0)
				delay(1); /* Don't just spin the CPU */
		}
	} else {
		xfs_ilock(ip0, xfs_lock_inumorder(ip0_mode, 0));
	}

	/*
	 * If the first lock we have locked is in the AIL, we must TRY to get
	 * the second lock. If we can't get it, we must release the first one
	 * and try again.
	 */
	lp = &ip0->i_itemp->ili_item;
	{
		/*
		 * sess58 (ccloop 8ddb16a2) RULE-4 PROVEN FIX for the tcp_dlm_scaling
		 * durable dirent RESURRECTION.  CAPTURED (P58-DIRPIN-NONEX stack ->
		 * xfs_inode_item_pin <- xfs_trans_commit <- xfs_remove): when ip0 is
		 * in the AIL we take ip1 via xfs_ilock_nowait — but xfs_ilock_nowait
		 * for ILOCK acquires ONLY the rwsem, NOT the DLM grant (it is the
		 * IOLOCK-only atomic xfsaild/reclaim carve-out).  So when ip1 is the
		 * parent DIRECTORY (by ascending-ino ordering under inode reuse) it was
		 * modified + committed at its STALE cached DLM mode (NL/PR,
		 * ex_holders==0) — NO exclusive authority -> the committed dir change
		 * is later flush-skipped (P119-NONEX-FLUSH-SKIP, mode=0) -> the peer
		 * reads stale disk -> the dirent RESURRECTS (TDS-LEFTOVER).  Restrict
		 * the explicit DLM acquire to DIRECTORIES (the resurrection domain;
		 * a child file's nlink/mode change is not a cross-node dirent RMW), so
		 * the common file-child path is untouched.  Process context (always),
		 * ascending ino (ip0<ip1, no DLM ABBA), inode-DLM release drains only
		 * ip1 (no v0.3.148 AG-drain wedge).  Balanced by xfs_iunlock(ip1).
		 *
		 * sess16 FIX-L3 (a9a03929, k1 2/tcp tds wedge): BOTH inodes'
		 * DLM grants are Phase-A pre-held above (pre0/pre1) — a
		 * pre-held ip1 takes ONLY its rwsem here (nowait; xfs_ilock
		 * would double-hold), and backoff releases pre-held rwsems
		 * RAW so the DLM hold persists (an ilock_end at zero holders
		 * fires the pending peer BAST inline and forfeits the grant —
		 * the 2/tcp L1 ping-pong livelock).  The middle arm below is
		 * reachable only in the no-DLM configuration (pre1 false).
		 */
		bool ip1_dir = S_ISDIR(VFS_I(ip1)->i_mode);
		uint8_t ip1_dlm = (ip1_mode & XFS_ILOCK_EXCL) ?
				MXFS_LOCK_EX : MXFS_LOCK_PR;

		if (pre1) {
			if (!xfs_ilock_nowait(ip1,
					      xfs_lock_inumorder(ip1_mode, 1))) {
				if (pre0)
					mxfs_iunlock_rwsems_raw(ip0, ip0_mode);
				else
					xfs_iunlock(ip0, ip0_mode);
				if ((++attempts % 5) == 0)
					delay(1); /* Don't just spin the CPU */
				goto again;
			}
		} else if ((lp && test_bit(XFS_LI_IN_AIL, &lp->li_flags)) ||
			   ip1_dir) {
			if (ip1_dir)
				mxfs_dlm_ilock_begin(ip1, ip1_dlm);
			if (!xfs_ilock_nowait(ip1,
					      xfs_lock_inumorder(ip1_mode, 1))) {
				if (ip1_dir)
					mxfs_dlm_ilock_end(ip1, ip1_dlm);
				if (pre0)
					mxfs_iunlock_rwsems_raw(ip0, ip0_mode);
				else
					xfs_iunlock(ip0, ip0_mode);
				if ((++attempts % 5) == 0)
					delay(1); /* Don't just spin the CPU */
				goto again;
			}
		} else {
			xfs_ilock(ip1, xfs_lock_inumorder(ip1_mode, 1));
		}
	}
}

/*
 * Lookups up an inode from "name". If ci_name is not NULL, then a CI match
 * is allowed, otherwise it has to be an exact match. If a CI match is found,
 * ci_name->name will point to a the actual name (caller must free) or
 * will be set to NULL if an exact match is found.
 */
int
xfs_lookup(
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	struct xfs_inode	**ipp,
	struct xfs_name		*ci_name,
	bool			create_intent)
{
	struct mxfs_createint_ent createint_ent;
	bool			createint_armed = false;

	xfs_ino_t		inum;
	int			error;
	uint8_t			dirent_ftype = XFS_DIR3_FT_UNKNOWN;
	int			evict_tries = 0;
	extern int		mxfs_icluster_dlm;
	int			igetmiss_tries = 0;
	int			gcwait_tries = 0;
	/* sess42 (ccloop c7ee71c6) P-LKERR tripwire, GPT-designed: the sess41
	 * matrix failure was a SILENT lookup error on the non-creating node
	 * (rm's path walk EIO'd with zero kernel lines; ls/stat probes EIO;
	 * self-healed after ~2 cases).  Every non-ENOENT error leaving this
	 * function on a multi-node mount now names its originating stage and
	 * the parent's identity/DLM/fork state so the next natural occurrence
	 * is self-diagnosing.  1=xfs_dir_lookup 2=iget ladder 3=post-iget. */
	int			lk_stage = 0;

	trace_xfs_lookup(dp, name);

	if (xfs_is_shutdown(dp->i_mount))
		return -EIO;
	if (xfs_ifork_zapped(dp, XFS_DATA_FORK))
		return -EIO;

	/*
	 * ccloop c7ee71c6 sess3 (Phase A): this dir shell is a POISONED dead
	 * incarnation (P34H-INCARN-POISON) — nothing it serves is real.  Fail
	 * the op with -ESTALE (synchronously visible; the VFS lookup retry
	 * re-resolves the PATH, and pruning the dead dentries here makes that
	 * re-resolution do a real lookup in the live parent).  Entry context:
	 * no ILOCK/i_lock held, so d_prune_aliases is safe.
	 */
	if (dp->i_mount->m_mxfs_dlm &&
	    xfs_iflags_test(dp, MXFS_IF_INCARN_STALE)) {
		d_prune_aliases(VFS_I(dp));
		return -ESTALE;
	}

	/*
	 * sess10(a9a03929): magic diagnostic name — dump this dir's per-block
	 * in-core vs platter dirent counts (P10-DIRDUMP) and return ENOENT
	 * WITHOUT touching the dir's DLM/coherency state (no
	 * consumer_refresh, no xfs_dir_lookup).  The dir_reuse test probes
	 * ".mxfs_dirdump1"/"2" the moment a readdir returns short.
	 */
	if (unlikely(name->len >= 13 &&
		     memcmp(name->name, ".mxfs_dirdump", 13) == 0)) {
		extern void mxfs_dirdump(struct xfs_inode *, const char *);

		mxfs_dirdump(dp, (name->len > 13 && name->name[13] == '2') ?
				 "rdmiss-post" : "rdmiss");
		return -ENOENT;
	}

	/*
	 * sess97: consumer-side eager dir-block refresh BEFORE the lookup reads
	 * the dir blocks.  If a peer modified this dir since our last refresh,
	 * drop all clean cached dir DATA blocks so xfs_dir_lookup refetches the
	 * peer's durable committed image instead of a stale-stamped cached block
	 * (the unlink/create-visibility residual).  No-op single-node / unchanged
	 * dir / shortform.
	 */
	if (create_intent && dp->i_mount->m_mxfs_dlm) {
		mxfs_createint_enter(&createint_ent, dp->i_ino);
		createint_armed = true;
		/* sess38 (GPT discriminator): the cached grant mode AT ARM
		 * ENTRY tells a residual EDEADLK's origin apart — a PR taken
		 * INSIDE the armed window (leaks A/B/C, fixable by tagging)
		 * vs a PR already cached from an earlier PLAIN lookup on this
		 * dir (path-walk/revalidate; needs a different fix). */
		if (unlikely(mxfs_instr_enabled))
			pr_warn_ratelimited("mxfs: P-CI-ARM ino=%llu cached_dlm_mode=%u\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_mode);
	}
	mxfs_dlm_dir_consumer_refresh(dp);

	error = xfs_dir_lookup(NULL, dp, name, &inum, ci_name, &dirent_ftype);
	/* sess37 CREATEINT: the dir ILOCK inside xfs_dir_lookup was the tag's
	 * one consumer; disarm immediately (iget below must not inherit it). */
	if (createint_armed) {
		mxfs_createint_exit(&createint_ent);
		createint_armed = false;
	}

	/*
	 * sess127 (RULE 4, ungated, miss-only): the unlink_visibility loser's
	 * P-SFDIR-RELOAD shows the parent's in-core shortform WITH the child
	 * entry, yet a real lookup 3ms later returns ENOENT.  Dump the in-core
	 * shortform content AT THE MISS so we can tell (A) content reverted
	 * between reload and lookup (count drops; chase the reverter) from
	 * (B) content present but xfs_dir_lookup misses it (lookup-side bug).
	 * Fires only on multi-node ENOENT misses — low volume.
	 */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
	    error == -ENOENT && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		    dp->i_df.if_data) {
			struct xfs_dir2_sf_hdr *sfh = dp->i_df.if_data;
			struct xfs_dir2_sf_entry *e =
				xfs_dir2_sf_firstentry(sfh);
			char names[200];
			int  pos = 0, k;

			names[0] = '\0';
			for (k = 0; k < sfh->count &&
				    pos < (int)sizeof(names) - 12; k++) {
				int nl = min_t(int, e->namelen, 10);

				pos += scnprintf(names + pos,
						 sizeof(names) - pos,
						 "%.*s ", nl, e->name);
				e = (void *)e + xfs_dir2_sf_entsize(
					dp->i_mount, sfh, e->namelen);
			}
			pr_warn("mxfs: P127-DIRMISS dp=%llu name=%.*s sfcount=%u names=[%s] size=%lld stale=%d gen=%u loaded_gen=%u dlm_mode=%u evgen=%u realns=%llu\n",
				(unsigned long long)dp->i_ino,
				name->len, (const char *)name->name,
				sfh->count, names,
				(long long)dp->i_disk_size, dp->i_dlm_stale,
				dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
				dp->i_dlm_mode, dp->i_dlm_dir_evicted_gen,
				(unsigned long long)ktime_get_real_ns());
		} else {
			pr_warn("mxfs: P127-DIRMISS dp=%llu name=%.*s fmt=%u (NOT-LOCAL) size=%lld stale=%d gen=%u loaded_gen=%u dlm_mode=%u evgen=%u realns=%llu\n",
				(unsigned long long)dp->i_ino,
				name->len, (const char *)name->name,
				dp->i_df.if_format,
				(long long)dp->i_disk_size, dp->i_dlm_stale,
				dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
				dp->i_dlm_mode, dp->i_dlm_dir_evicted_gen,
				(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * sess45 DIR-MISS discriminator (instr-gated): on a multi-node lookup
	 * miss, FUA-read the parent dir inode's on-disk di_size and compare to
	 * our in-core di_size.  disk > incore  => our cached dir inode is STALE
	 * (a peer added the name and grew the dir; fix = force dir reload on
	 * read).  disk == incore => the peer's dir update is NOT durable on the
	 * medium yet (fix = durable-before-visible on the writer's release).
	 * Decides the dirent-visibility fix direction.
	 */
	{ extern int mxfs_instr_enabled;
	  if (unlikely(mxfs_instr_enabled) && error == -ENOENT &&
	      dp->i_mount->m_mxfs_dlm &&
	      !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *, uint16_t *, uint32_t *);
		uint64_t ddsz = mxfs_inode_disk_di_size(dp, NULL, NULL);
		pr_warn_ratelimited("mxfs: DIR-MISS name=%.*s dp_ino=%llu incore_dirsize=%lld disk_dirsize=%lld stale=%d fmt=%u (disk>incore=>STALE-DIR; equal=>NOT-DURABLE)\n",
			name->len, (const char *)name->name,
			(unsigned long long)dp->i_ino,
			(long long)dp->i_disk_size, (long long)ddsz,
			dp->i_dlm_stale, dp->i_df.if_format);
	  } }
	/*
	 * sess45: a lookup-miss retry under the dir ILOCK_SHARED was tried here
	 * to fix dirent-visibility (peer's freshly-created name invisible) but
	 * did NOT help (5-run 3/5, == baseline) — the miss is durable-before-
	 * visible (the peer's dirent isn't flushed to the medium when we read,
	 * and the dir-DLM acquire fast-paths / the BAST-flush chain races), not a
	 * stale-cache the acquire can refresh.  Reverted (it also added a dir-DLM
	 * acquire to every ENOENT path).  The real fix is dir-block durable-
	 * before-visible on dir-DLM release.
	 */
	{
		/* sess38 P-LOOKUP (gated): correlate EEXIST-loser stat->ENOENT
		 * with parent staleness/format.  rc=-2 (ENOENT) on a name a
		 * peer just created => stale parent on this node. */
		extern int mxfs_instr_enabled;
		if (unlikely(mxfs_instr_enabled) && dp->i_mount->m_mxfs_dlm)
			pr_warn("mxfs: P-LOOKUP dp_ino=%llu name=%.*s rc=%d inum=%llu dp_stale=%d dp_fmt=%u dp_size=%lld\n",
				(unsigned long long)dp->i_ino,
				name->len, (const char *)name->name,
				error,
				(unsigned long long)(error ? 0 : inum),
				dp->i_dlm_stale, dp->i_df.if_format,
				(long long)dp->i_disk_size);
	}
	if (error) {
		lk_stage = 1;
		goto out_unlock;
	}

retry_iget:
	lk_stage = 2;
	error = xfs_iget(dp->i_mount, NULL, inum, 0, 0, ipp);
	if (error) {
#ifdef __KERNEL__
		/* sess12(a9a03929) FIX-B: a dirent-resolved inum that igets
		 * -ENOENT on a multi-node mount is (r11-proven) usually a
		 * sticky-stale CACHED inode-cluster buffer serving the old
		 * FREE image — peers iget the same inum fine.  Invalidate the
		 * cluster buf and retry (bounded); see
		 * mxfs_dlm_iget_miss_reload.
		 *
		 * sess13 FIX-D: when the invalidate can't act (no cached buf,
		 * or the failure is a dead in-core shell / not-yet-published
		 * fresh create), NUDGE: PR-acquire the ino's DLM by number —
		 * BASTs the creator into publishing (iflush + mirror) — then
		 * retry.  Bounded ~360ms worst-case on a genuinely dangling
		 * dirent; converges in ~1-2 tries on the create-race (the
		 * creator's drain is ~7ms).  See the helper's proof comment. */
		if ((error == -ENOENT || error == -EFSCORRUPTED) &&
		    igetmiss_tries < (mxfs_icluster_dlm ? 24 : 8)) {
			/* ICLUSTER (ccloop 72513a13 sess4): the 8-lap
			 * (~360ms) budget was tuned for ~7ms per-inode
			 * drains; a cluster handoff drains up to a whole
			 * inode cluster (fan-out + make_durable, observed
			 * ~seconds under 16-node load).  The recovery chain
			 * provably converges (live dissection: both views
			 * agree post-window) — the tail just needs laps. */
			extern int mxfs_dlm_iget_miss_reload(
				struct xfs_mount *, xfs_ino_t);
			extern int mxfs_dlm_iget_shell_reload(
				struct xfs_mount *, xfs_ino_t);
			extern int mxfs_dlm_iget_visibility_nudge(
				struct xfs_mount *, xfs_ino_t);
			int	acted;

			/* sess13 FIX-D v2: dead-shell reload first (the
			 * proven blocker: iget cache-hits a mode-0 prior-
			 * incarnation shell and ENOENTs before any buffer or
			 * mirror logic; the reload resurrects it via the
			 * normal grant+mirror path). */
			acted = mxfs_dlm_iget_shell_reload(dp->i_mount, inum);
			if (!acted)
				acted = mxfs_dlm_iget_miss_reload(dp->i_mount,
								  inum);
			if (!acted)
				acted = mxfs_dlm_iget_visibility_nudge(
						dp->i_mount, inum);
			else if (igetmiss_tries >= 1)
				/* ICLUSTER (ccloop 72513a13 sess4, 16-node
				 * cache_coherency root): the local buffer
				 * invalidation "acts" every lap but cannot
				 * converge when the CREATOR hasn't flushed —
				 * there is no per-inode mirror under cluster
				 * granularity, so only a BAST (the nudge's
				 * PR acquire) forces the creator's dinode to
				 * the platter.  Proven: 76× P26-IGET-FAIL
				 * with P13-VISNUDGE=0 — the nudge was
				 * short-circuited by acted!=0 on all 8 laps. */
				(void)mxfs_dlm_iget_visibility_nudge(
						dp->i_mount, inum);
			/* daf50d34 sess3: acted==2 = a LOCAL mid-teardown
			 * shell of a prior incarnation of this (reused) ino
			 * is blocking the iget.  That teardown is guaranteed
			 * to finish (evict/inodegc always completes), so wait
			 * it out on its own budget instead of burning the
			 * shared 8-try nudge budget: 8s worst-case, 20ms
			 * steps.  Giving up early here made a mkdir on a
			 * live cross-node dirent fail ENOENT (mkdir_storm
			 * round-3 "node1 missing" HIT: 8×GCFLUSH ≈ 360ms
			 * vs a ~5s 18-inode inodegc backlog). */
			if (acted == 2 && gcwait_tries < 400) {
				gcwait_tries++;
				msleep(20);
				goto retry_iget;
			}
			if (acted) {
				igetmiss_tries++;
				msleep(igetmiss_tries * 10);
				goto retry_iget;
			}
		}
		/* sess26 (ccloop 8ddb16a2): the dir lookup SUCCEEDED (found the
		 * dirent + inum) but the iget FAILED — the dirent references a
		 * stale/freed inode (the dir_reuse_coherency lookup_fail residual
		 * with rebuild OFF: leaf/data find the name, iget -ENOENT because
		 * the on-disk inode is free).  Capture inum+err so a cross-node
		 * timeline shows whether the dirent points to a freed prior-
		 * incarnation inode (stale dir DATA block) vs an undurable alloc. */
		if (dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			/* sess14: detection-triggered P172-WRTR ring dump
			 * (hard-throttled inside; see pal/linux/xfs_buf.c) */
			extern void mxfs_wrtr_dump_auto(void);

			pr_warn_ratelimited("mxfs: P26-IGET-FAIL dp=%llu name=\"%.*s\" inum=%llu err=%d ftype=%u\n",
					(unsigned long long)dp->i_ino,
					name->len, (const char *)name->name,
					(unsigned long long)inum, error,
					dirent_ftype);
			mxfs_wrtr_dump_auto();
		}
#endif
		goto out_free_name;
	}
	lk_stage = 3;

	/*
	 * sess56: VFS staleness trap (Gemini design Part 2).
	 *
	 * The disklock eviction-ring consumer (mxfs_dlm_evict_inode_cb) flags
	 * an in-core inode XFS_ISTALE_CAW when a PEER reported having freed that
	 * inode number — meaning our passively-cached (NL, no DLM grant) copy is
	 * a stale prior incarnation the peer may have since reused with the SAME
	 * type but different contents (the `actual=''` empty-read failures the
	 * ftype check below cannot catch).  Evict it here, in the safe ->lookup
	 * context (we hold dp->i_rwsem, NOT the child ILOCK — so no AIL-drain
	 * wedge): drop lingering positive dentries + our ref so the inode becomes
	 * reclaimable, then re-iget — which cache-misses and re-reads the current
	 * dinode (the gen-gated recycle/miss re-read).  Bounded retry; if the
	 * inode is still referenced and can't be pruned we fall through with what
	 * we have.  The flag is cleared on recycle (XFS_IRECLAIM_RESET_FLAGS).
	 */
	/*
	 * ccloop c7ee71c6 sess3 (Phase A): a POISONED shell needs no disk
	 * re-verify — a protective-grant reload already proved the disk
	 * disowned this incarnation (P34H-INCARN-POISON).  Retire it here in
	 * the safe ->lookup context (same discipline as the ISTALE_CAW trap
	 * below): prune the dead-name dentries, drop our ref so it becomes
	 * reclaimable, re-iget the live incarnation from disk.  The flag
	 * resets on recycle (XFS_IRECLAIM_RESET_FLAGS).  Bounded: if the
	 * corpse stays referenced (open FDs) we fall through — op-entry
	 * checks then fail its ops with -ESTALE rather than serving it.
	 */
	if (xfs_iflags_test(*ipp, MXFS_IF_INCARN_STALE) &&
	    dp->i_mount->m_mxfs_dlm &&
	    evict_tries++ < 4) {
		struct inode	*vi = VFS_I(*ipp);

		pr_warn_ratelimited(
			"mxfs: P34H-POISON-EVICT ino=%llu gen=%u try=%d — retiring poisoned shell for re-iget\n",
			(unsigned long long)(*ipp)->i_ino,
			VFS_I(*ipp)->i_generation, evict_tries);
		(*ipp)->i_dlm_stale = true; (*ipp)->i_dlm_stale_src = 15;
		d_prune_aliases(vi);
		xfs_irele(*ipp);
		*ipp = NULL;
		goto retry_iget;
	}

	if (xfs_iflags_test(*ipp, XFS_ISTALE_CAW) &&
	    dp->i_mount->m_mxfs_dlm &&
	    evict_tries++ < 4) {
		struct inode	*vi = VFS_I(*ipp);
		uint16_t	s91_dmode = 0;
		uint32_t	s91_dgen = 0;
		extern uint64_t	mxfs_inode_disk_di_size(struct xfs_inode *,
						uint16_t *, uint32_t *);

		/*
		 * sess91 ROOT FIX (PROVEN by P91-STALEFLAG-DISK): the INODE_FREE
		 * eviction-ring handler (mxfs_dlm_evict_inode_cb) sets
		 * XFS_ISTALE_CAW when a peer frees an inode number, but the flag
		 * has NO other clear site in the tree.  A heavily-referenced LIVE
		 * shared directory (.mxfs_barriers) cannot be pruned/reclaimed, so
		 * after the number is legitimately reused for the CURRENT
		 * incarnation the flag persists forever → d_revalidate returns
		 * INVALID on every access → 291x path-walk thrash → 120s barrier
		 * timeouts (unlink/cross_write_read FAIL).
		 *
		 * FUA-read the on-disk dinode (lockless, no child ILOCK held
		 * here).  If the on-disk incarnation MATCHES our cached one (same
		 * di_mode AND di_gen) the inode is genuinely current — the flag is
		 * a false positive from an old INODE_FREE.  Clear it (the missing
		 * clear site) and KEEP this inode: the dir lookup just above
		 * already returned the fresh dirent, so rename/unlink content
		 * stays visible (unlike clearing in d_revalidate, which dropped
		 * the dir-content re-read trigger and regressed rename).  Only
		 * when the disk incarnation DIFFERS (genuine free/realloc) do we
		 * evict + re-iget the fresh incarnation, as before.
		 */
		(void)mxfs_inode_disk_di_size(*ipp, &s91_dmode, &s91_dgen);
		if (s91_dmode != 0 &&
		    s91_dmode == (VFS_I(*ipp)->i_mode & 0xFFFF) &&
		    s91_dgen == (uint32_t)VFS_I(*ipp)->i_generation) {
			pr_warn_ratelimited(
				"mxfs: P91-CAW-FALSEPOS-CLEAR ino=%llu gen=%u dmode=0%o — current incarnation, clearing stuck ISTALE_CAW\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, s91_dmode);
			(*ipp)->i_dlm_stale = false;
			xfs_iflags_clear(*ipp, XFS_ISTALE_CAW);
			/* fall through — keep this current inode */
		} else if (s91_dmode != 0 &&
			   (VFS_I(*ipp)->i_mode & S_IFMT) ==
				   (s91_dmode & S_IFMT)) {
			/*
			 * sess95 FIX (Gemini-confirmed, RULE 4 step 2b): SAME-TYPE
			 * inode-number REUSE.  The cached inode is a valid
			 * incarnation of the SAME type (dir->dir / reg->reg) but a
			 * STALE generation — a peer freed inode `inum` and reused
			 * it for a fresh same-type incarnation (disk_gen !=
			 * incore_gen).  EVICTION cannot fix this when the inode is
			 * REFERENCED (a live FD/dentry from the running test):
			 * xfs_irele does not drop the last ref, the inode never
			 * becomes reclaimable, and retry_iget cache-HITs the same
			 * stale inode forever (PROVEN this session: P-EVICT-RESULT
			 * inew=0 gen=<stale> tries=5; node3 saw NONE of peers'
			 * renamed dir entries because its rename_visibility dir
			 * inode kept the stale gen → stale dir-fork → old dir
			 * blocks).
			 *
			 * Do an IN-PLACE reload instead: mxfs_dlm_reload_inode
			 * invalidates this inode's cluster buffer AND its dir DATA
			 * blocks (clears XBF_DONE so the fua_disable=1 plain-bio
			 * read re-fetches from the coherent SCST cache), then
			 * repopulates the inode — i_generation and the dir-fork —
			 * from the fresh on-disk incarnation.  The next dir read
			 * then sees the peer's current entries.  No i_op/i_fop swap
			 * is needed for a same-type reload, so reloading a LIVE
			 * referenced inode is safe (the sess45 in-place-reload
			 * deadlock concern was specific to type-FLIP iops rewiring,
			 * which still goes through clean eviction below).  With
			 * fua_disable=1 this is the ONLY path that refreshes a
			 * referenced, gen-stale directory.
			 */
			pr_warn_ratelimited(
				"mxfs: P95-SAMETYPE-RELOAD ino=%llu incore_gen=%u disk_gen=%u dmode=0%o try=%d\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, s91_dgen, s91_dmode,
				evict_tries);

			/*
			 * sess10 (ccloop c7ee71c6) ROOT FIX, same-type arm —
			 * cc rv empty-content (run 003359Z test1: 8 reused
			 * node5_after_* inos, single-shot reload BAILED on all
			 * 8, lookup returned the stale pre-write size=0 shells
			 * while 15 cold-iget peers read the platter fine).
			 * Same mechanism as the P95B typeflip wait below: a
			 * lookup must not return an inode whose reload it just
			 * armed but which silently bailed.  Bounded blocking
			 * retry until the reload actually lands (contract:
			 * mxfs_dlm_reload_inode clears i_dlm_stale on success,
			 * leaves it set on any bail).  No locks held here.
			 */
			{
				int p95c = 0;

				while (p95c++ < 200 &&
				       !xfs_is_shutdown(dp->i_mount)) {
					(*ipp)->i_dlm_stale = true;	/* arm in-place reload */
					(*ipp)->i_dlm_stale_src = 14;
					/* same-type reload — never hits the
					 * typeflip guard */
					mxfs_dlm_reload_inode(*ipp,
						XFS_DIR3_FT_UNKNOWN, false);
					if (!(*ipp)->i_dlm_stale)
						break;
					msleep(10);
				}
				if (p95c > 1 || (*ipp)->i_dlm_stale)
					pr_warn_ratelimited(
						"mxfs: P95C-SAMETYPE-WAIT ino=%llu resolved=%d rounds=%d gen=%u\n",
						(unsigned long long)(*ipp)->i_ino,
						(*ipp)->i_dlm_stale ? 0 : 1,
						p95c,
						VFS_I(*ipp)->i_generation);
			}
			/* Only clear the stuck ISTALE_CAW flag when the reload
			 * actually refreshed us; otherwise leave it so the next
			 * access retries. */
			if (!(*ipp)->i_dlm_stale)
				xfs_iflags_clear(*ipp, XFS_ISTALE_CAW);
			/* fall through — keep this now-reloaded inode */
		} else {
			pr_warn_ratelimited(
				"mxfs: ISTALE-CAW-EVICT ino=%llu gen=%u dmode=0%o dgen=%u try=%d\n",
				(unsigned long long)(*ipp)->i_ino,
				vi->i_generation, s91_dmode, s91_dgen,
				evict_tries);

			(*ipp)->i_dlm_stale = true;	/* force disk re-read on recycle */ (*ipp)->i_dlm_stale_src = 15;
			d_prune_aliases(vi);		/* drop stale-name dentries */
			xfs_irele(*ipp);		/* drop our ref → reclaimable */
			*ipp = NULL;
			goto retry_iget;
		}
	}

	/*
	 * mxfs: cross-node inode-number REUSE coherency (proven sess45,
	 * acted on sess48).
	 *
	 * A peer may have freed inode `inum` and reused the number for a
	 * NEW incarnation of a DIFFERENT type (the churned barrier/test
	 * dirs: a regular file's number reused for a directory, or vice
	 * versa).  This node still holds a LIVE cached in-core inode of the
	 * OLD type (mode!=0, not reclaimable), pinned by a lingering
	 * positive dentry from the prior name — we hold no DLM grant on a
	 * passively-cached inode, so the peer's free/realloc never BAST'd
	 * us.  xfs_iget cache-HITs that stale inode → lookups of the reused
	 * name see the WRONG type (ENOTDIR on a now-directory, EISDIR on a
	 * now-file) → the catastrophic unlink_visibility/barrier failures.
	 *
	 * The dir block we just read carries the CURRENT on-disk ftype for
	 * this name (dirent_ftype, zero extra I/O).  If it disagrees with
	 * our cached inode's actual type, the cached inode is a stale prior
	 * incarnation.  Force it out: drop the lingering positive dentries
	 * (d_prune_aliases) and our own reference so the inode becomes
	 * reclaimable, flag it stale so the recycle/miss path re-reads the
	 * current dinode from disk, then re-iget — which now returns the
	 * correct-type incarnation.  In-place reload+iops-swap on a LIVE
	 * inode deadlocks/races (sess45); eviction + clean re-instantiation
	 * is the safe path.  Bounded retry: if a dentry can't be pruned
	 * (in use) we fall through with what we have rather than spin.
	 */
	if (xfs_has_ftype(dp->i_mount) &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    dirent_ftype != XFS_DIR3_FT_UNKNOWN &&
	    dirent_ftype < XFS_DIR3_FT_MAX &&
	    VFS_I(*ipp)->i_mode != 0 &&
	    xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) != dirent_ftype &&
	    evict_tries++ < 4) {
		struct inode	*vi = VFS_I(*ipp);

		pr_warn_ratelimited(
			"mxfs: INODE-REUSE-EVICT ino=%llu incore_ftype=%u dirent_ftype=%u name=%.*s try=%d\n",
			(unsigned long long)(*ipp)->i_ino,
			xfs_mode_to_ftype(VFS_I(*ipp)->i_mode),
			dirent_ftype, name->len, (const char *)name->name,
			evict_tries);

		/*
		 * sess49: FORCE the peer that created the new incarnation to
		 * flush its dinode NOW, rather than waiting (up to a 120s barrier
		 * timeout) for its lazy iflush.  A PR acquire BASTs the creator's
		 * sticky-cached EX grant -> it drains+iflushes the new dinode
		 * before downconverting, so the gen-gated recycle re-read below
		 * sees the fresh incarnation on the NEXT iget instead of looping
		 * 4x on the stale disk image.  i_dlm_stale is still clear here, so
		 * this does NOT trigger an in-place reload of the wrong-type stale
		 * inode (which deadlocks — sess45); we use only the BAST/flush
		 * side effect, then evict + re-instantiate cleanly.
		 */
		{ extern void mxfs_dlm_force_peer_flush(struct xfs_inode *);
		  mxfs_dlm_force_peer_flush(*ipp); }

		(*ipp)->i_dlm_stale = true;	/* force disk re-read on recycle */ (*ipp)->i_dlm_stale_src = 16;
		d_prune_aliases(vi);		/* drop stale-name dentries */
		xfs_irele(*ipp);		/* drop our ref → reclaimable */
		*ipp = NULL;
		goto retry_iget;
	}

	/*
	 * sess95 FIX2 (Gemini-confirmed, RULE 4 step 2b): TYPE-FLIP reuse where
	 * eviction FAILED because the inode is REFERENCED.  The ftype-mismatch
	 * eviction above (INODE-REUSE-EVICT) loops up to 4x without progress
	 * when a live dentry/FD holds the wrong-type inode: xfs_irele never
	 * makes it reclaimable, retry_iget cache-HITs the same stale inode.
	 * PROVEN this session: the reused barrier directory uv_delete (ino 136,
	 * a regular file reused as a DIR) showed incore_ftype=1 dirent_ftype=2
	 * try=1..4 on node2/3/4 — they kept the stale FILE incarnation, could
	 * not use uv_delete as a directory, so barrier_signal failed and the
	 * uv_delete barrier timed out 0/4 on every peer (146s unlink_visibility
	 * failure).  Eviction cannot fix a referenced inode (same root as the
	 * P95 same-type case in xfs_lookup's ISTALE_CAW block).
	 *
	 * Do an IN-PLACE reload as the fallback: mxfs_dlm_reload_inode now
	 * rewires i_op/i_fop on an S_IFMT change (sess72/90 P-RELOAD-IOPS-
	 * REWIRE) and only ADOPTS a strictly-newer disk_gen type-flip (genuine
	 * reuse; the typeflip guard rejects stale/torn reads with disk_gen <=
	 * incore_gen).  It uses down_write_trylock + bail (no deadlock — the
	 * sess45 in-place-reload concern was a plain down_write, since fixed),
	 * and invalidates the inode-cluster buffer so the fua_disable=1 read
	 * re-fetches the fresh incarnation.  After reload, i_mode/ftype match
	 * the dirent and the reused directory is usable.  Reached only when the
	 * eviction loop above was tried (evict_tries>0) yet the type still
	 * mismatches → the inode is referenced and un-evictable.
	 */
	if (xfs_has_ftype(dp->i_mount) &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	    *ipp &&
	    evict_tries > 0 &&
	    dirent_ftype != XFS_DIR3_FT_UNKNOWN &&
	    dirent_ftype < XFS_DIR3_FT_MAX &&
	    VFS_I(*ipp)->i_mode != 0 &&
	    xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) != dirent_ftype) {
		/*
		 * sess10 (ccloop c7ee71c6) ROOT FIX — cc uv lost-create /
		 * ENOTDIR window (RULE 4, two live captures: 233839Z test16
		 * ino=27263107, 001124Z test6 ino=18874507).  A single reload
		 * attempt here silently LOSES to trylock/drain-race bails
		 * (P34J-RELOAD-RACE-BAIL) under the reuse storm, and the
		 * lookup then hands the WRONG-TYPE stale shell to the VFS:
		 * every walk into the name fails ENOTDIR for ~1s (until an
		 * async reload finally lands the flip), so open(O_CREAT)
		 * fails and the create is silently lost (`echo >` unchecked).
		 * The dirent ftype we just read under the parent's grant is
		 * ground truth (disk+dirent agree per the TYPEFLIP-DIRENT-OK
		 * guard) — so do NOT return until the in-core inode matches
		 * it.  Bounded blocking retry: no locks are held here (see
		 * function-entry comment), each round re-arms the reload and
		 * sleeps 10ms; converges in 1-3 rounds once the contending
		 * holders cycle.  Cap 200 (2s) then fall through as before
		 * (no worse than the old single-shot behavior).
		 */
		int p95w = 0;

		pr_warn_ratelimited(
			"mxfs: P95-TYPEFLIP-RELOAD ino=%llu incore_ftype=%u dirent_ftype=%u name=%.*s tries=%d\n",
			(unsigned long long)(*ipp)->i_ino,
			xfs_mode_to_ftype(VFS_I(*ipp)->i_mode),
			dirent_ftype, name->len, (const char *)name->name,
			evict_tries);

		/* BAST the creator to flush the fresh dinode, then reload it. */
		{ extern void mxfs_dlm_force_peer_flush(struct xfs_inode *);
		  mxfs_dlm_force_peer_flush(*ipp); }
		/*
		 * ccloop c7ee71c6 sess22 — TEST-ONLY: force the resolver to give
		 * up immediately, so the P201 give-up path can be EXERCISED.
		 * Type flips are common (165 waits in one 32-node run) but the
		 * unresolved outcome is not reproducible on demand, and RULE 6
		 * will not accept a fix whose path has never run.  With this set,
		 * every flip that reaches here takes the unresolved branch.
		 */
		{ extern int mxfs_typeflip_force_unresolved;
		  if (unlikely(mxfs_typeflip_force_unresolved))
			p95w = 200; }
		while (p95w++ < 200 &&
		       !xfs_is_shutdown(dp->i_mount) &&
		       VFS_I(*ipp)->i_mode != 0 &&
		       xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) != dirent_ftype) {
			(*ipp)->i_dlm_stale = true;
			(*ipp)->i_dlm_stale_src = 17;
			mxfs_dlm_reload_inode(*ipp, dirent_ftype, false);
			if (VFS_I(*ipp)->i_mode == 0 ||
			    xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) ==
				dirent_ftype)
				break;
			if ((p95w & 15) == 0) {
				extern void mxfs_dlm_force_peer_flush(
					struct xfs_inode *);
				mxfs_dlm_force_peer_flush(*ipp);
			}
			msleep(10);
		}
		{
			bool p95_ok = (VFS_I(*ipp)->i_mode != 0 &&
				       xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) ==
						dirent_ftype);

			pr_warn_ratelimited(
				"mxfs: P95B-TYPEFLIP-WAIT ino=%llu resolved=%d rounds=%d final_ftype=%u dirent_ftype=%u name=%.*s\n",
				(unsigned long long)(*ipp)->i_ino,
				p95_ok ? 1 : 0,
				p95w,
				VFS_I(*ipp)->i_mode ?
					xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) : 0,
				dirent_ftype, name->len,
				(const char *)name->name);

			/*
			 * ccloop c7ee71c6 sess22 — DO NOT PUBLISH A MISMATCHED
			 * BINDING (D-DIRENT-INODE-TYPE-MISMATCH).
			 *
			 * The comment above says the loop "falls through as
			 * before (no worse than the old single-shot behavior)"
			 * when it gives up.  Falling through means handing the
			 * VFS an inode whose type CONTRADICTS the dirent this
			 * very function just read under the parent's grant —
			 * and that dirent is ground truth (disk+dirent agree
			 * per the TYPEFLIP-DIRENT-OK guard).  It is not "no
			 * worse": it is how the mismatch becomes DURABLE and
			 * agreed by every node.
			 *
			 * PROVEN (32/caw, after a storm on an aged mount):
			 *   P95B-TYPEFLIP-WAIT ino=60823425 resolved=0
			 *       rounds=201 final_ftype=2 dirent_ftype=1
			 *       name=node5.txt
			 * and userspace then permanently sees
			 *   node5.txt  type=directory ino=60823425 size=6
			 *              nlink=2 mode=755
			 * where an 18-byte regular file belongs, on ALL 32
			 * nodes.  Cluster census that run: 165 waits, 109
			 * resolved, 56 gave up — every one of the 56 on this
			 * same inode and name.
			 *
			 * There is no correct inode to return here.  The only
			 * honest answer is that this handle is stale: -ESTALE
			 * is exactly the "revalidate and retry" contract, and a
			 * reported failure is strictly better than durable
			 * silent namespace corruption.  Drop our reference and
			 * leave *ipp NULL — xfs_lookup must not return an inode
			 * alongside an error.
			 *
			 * This does NOT root the reuse race that produces the
			 * flip; it stops the flip from being published.  The
			 * root (what lets a REG dirent be created against a
			 * live DIR inode) is still open.
			 */
			extern int mxfs_typeflip_fail_unresolved;

			if (!p95_ok && mxfs_typeflip_fail_unresolved) {
				static atomic_t p201_n = ATOMIC_INIT(0);
				/*
				 * ccloop c7ee71c6 sess27 — WHICH SIDE IS ACTUALLY
				 * STALE.  Every previous verdict here read the
				 * child's "disk" mode through the buffer cache,
				 * i.e. through exactly the path under suspicion.
				 * This reads the COHERENT platter image with a
				 * plain bio (the image a peer sees), so the three
				 * outcomes are distinguishable:
				 *   coh_mode == a REG file  -> the platter agrees
				 *     with the dirent and our in-core DIR is a
				 *     dead incarnation we refused to drop;
				 *   coh_mode == a DIR with coh_gen == incore_gen
				 *     -> the dirent is the corrupt side (the
				 *     sess22 reading);
				 *   coh_mode == 0 -> the number is FREE on the
				 *     platter and the dirent is dangling.
				 * Sleeping is allowed here: the resolver loop
				 * above msleep()s and holds no buffer locks.
				 */
				extern uint16_t mxfs_dbg_disk_di_mode_coherent(
					struct xfs_mount *, xfs_ino_t,
					uint32_t *);
				uint32_t	coh_gen = 0;
				uint16_t	coh_mode =
					mxfs_dbg_disk_di_mode_coherent(
						dp->i_mount, (*ipp)->i_ino,
						&coh_gen);

				if (atomic_inc_return(&p201_n) <= 2000)
					pr_warn("mxfs: P207-COHERENT-TRUTH ino=%llu coh_mode=0%o coh_gen=%u incore_mode=0%o incore_gen=%u dirent_ft=%u dlm_mode=%d dlm_state=%d name=%.*s\n",
						(unsigned long long)(*ipp)->i_ino,
						(unsigned)coh_mode, coh_gen,
						VFS_I(*ipp)->i_mode,
						VFS_I(*ipp)->i_generation,
						dirent_ftype,
						(*ipp)->i_dlm_mode,
						(*ipp)->i_dlm_state,
						name->len,
						(const char *)name->name);

				if (atomic_read(&p201_n) <= 2000)
					/*
					 * sess22: include the PARENT's coherency
					 * state.  The dirent's ftype comes from
					 * the parent's directory BLOCK, and the
					 * evidence says the dirent is the corrupt
					 * side (disk_mode=040755 with
					 * disk_gen==incore_gen for the child, i.e.
					 * the inode really IS a directory).  So
					 * the question is whether OUR copy of the
					 * parent's block is stale — a stale block
					 * still holding a pre-free REG dirent for
					 * an inode number a peer has since reused
					 * as a directory would explain it exactly.
					 * dir_valid_epoch vs the master dir_epoch
					 * is the existing staleness signal for
					 * that; print both plus the gens.
					 */
					pr_warn("mxfs: P201-TYPEFLIP-UNRESOLVED-FAIL ino=%llu incore_ftype=%u dirent_ftype=%u incore_mode=0%o incore_gen=%u pino=%llu p_fmt=%d p_valid_epoch=%u p_dir_gen=%llu p_loaded_gen=%u p_stale=%d name=%.*s comm=%s — type flip UNRESOLVED after %d rounds; failing the lookup with -ESTALE rather than publishing a dirent/inode type mismatch\n",
						(unsigned long long)(*ipp)->i_ino,
						VFS_I(*ipp)->i_mode ?
						  xfs_mode_to_ftype(VFS_I(*ipp)->i_mode) : 0,
						dirent_ftype,
						VFS_I(*ipp)->i_mode,
						VFS_I(*ipp)->i_generation,
						(unsigned long long)dp->i_ino,
						dp->i_df.if_format,
						dp->i_dlm_dir_valid_epoch,
						(unsigned long long)dp->i_dlm_dir_gen,
						dp->i_dlm_dir_loaded_gen,
						dp->i_dlm_stale ? 1 : 0,
						name->len,
						(const char *)name->name,
						current->comm, p95w);
				xfs_irele(*ipp);
				*ipp = NULL;
				return -ESTALE;
			}
		}
	}

	/* sess70: decisive — when we evicted at least once, log the FINAL
	 * inode the retry delivered.  If incore_ftype still != dirent_ftype
	 * the loop must have hit the try<4 cap (it didn't, only try=1 seen)
	 * or fell through; if it MATCHES yet userspace still sees a dir, the
	 * bug is in the dcache/dentry, not the inode. */
	if (evict_tries > 0 && *ipp &&
	    dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		struct inode *vi2 = VFS_I(*ipp);
		extern const struct file_operations xfs_dir_file_operations;
		pr_warn_ratelimited(
			"mxfs: P-EVICT-RESULT ino=%llu ip=%px final_mode=0%o final_ftype=%u dirent_ftype=%u gen=%u inew=%d fop_dir=%d tries=%d name=%.*s\n",
			(unsigned long long)(*ipp)->i_ino, *ipp,
			vi2->i_mode,
			vi2->i_mode ? xfs_mode_to_ftype(vi2->i_mode) : 0,
			dirent_ftype, vi2->i_generation,
			(vi2->i_state & I_NEW) ? 1 : 0,
			(vi2->i_fop == &xfs_dir_file_operations) ? 1 : 0,
			evict_tries, name->len, (const char *)name->name);
	}

	/*
	 * sess45: cross-node INODE-NUMBER REUSE coherency (dir<->file).
	 *
	 * A peer may have freed inode `inum` (e.g. a churned barrier dir) and
	 * THIS node still holds a stale cached in-core inode for it with the
	 * OLD type, kept alive by a lingering positive dentry (the peer's
	 * unlink wasn't observed).  When `inum` is reused as a different type,
	 * our cache-hit returns the stale-type inode → open/read sees the
	 * wrong type (e.g. EISDIR on a regular file).  The local free→reclaim→
	 * realloc ordering that makes single-node reuse safe does NOT hold
	 * cross-node, and we hold no DLM grant on a passively-cached inode so
	 * no BAST invalidates it.
	 *
	 * Detect it: FUA-read the on-disk inode's mode; if its TYPE differs
	 * from our in-core VFS i_mode type, our cached inode is a stale prior
	 * incarnation.  Correct it in place under ILOCK_EXCL: reload from disk
	 * (updates mode, forks, size) and re-run xfs_setup_iops so i_op/i_fop/
	 * a_ops match the NEW type (the same re-init the recycle path does).
	 * Gated to multi-node + a real type mismatch, so it costs nothing in
	 * the common case.
	 */
	/*
	 * sess45: cross-node inode-reuse (dir<->file) detection.  Detection is
	 * proven correct (INODE-REUSE-FIX fires with incore dir vs disk file),
	 * but doing the in-place reload+xfs_setup_iops HERE under ILOCK_EXCL
	 * DEADLOCKS (stat stuck in D-state) — reload's buffer I/O / DLM under
	 * the held lock during a path-walk lookup is unsafe.  The safe fix
	 * (drop the stale dentry aliases so the inode reclaims, then recycle-
	 * re-instantiate) is deferred; detection-only here for diagnosis.
	 */
	/*
	 * sess51: detection-only di_size probe for same-type reused-inode
	 * CONTENT empty-read (cross_write_read / rename actual='').  An active
	 * eviction here (gen-mismatch + FUA re-read) was TRIED and REVERTED:
	 * (1) the discriminator fired 0x — the empty-read is NOT "in-core
	 *     di_size==0 + disk di_size>0 + disk_gen!=in-core gen", so either
	 *     the writer's data is not durable (disk also 0) or the stale read
	 *     comes from a dcache hit that never reaches xfs_lookup; and
	 * (2) the FUA probe on every grant-less empty reg-file lookup perturbs
	 *     the hot barrier-marker path (markers are empty files) -> brought
	 *     the ~120s barrier stall back (passed 2->1).  Gate behind instr.
	 */
	if (dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		extern int mxfs_instr_enabled;

		if (unlikely(mxfs_instr_enabled)) {
			extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);
			uint16_t	disk_mode = 0;
			uint32_t	disk_gen = 0;
			uint64_t	dsz = mxfs_inode_disk_di_size(*ipp,
							&disk_mode, &disk_gen);

			if (dsz != (uint64_t)-1 && disk_mode != 0 &&
			    S_ISREG(VFS_I(*ipp)->i_mode) &&
			    XFS_ISIZE(*ipp) == 0)
				pr_warn_ratelimited("mxfs: INODE-REUSE-DETECT ino=%llu incore_gen=%u disk_gen=%u disk_size=%lld dlm_mode=%u name=%.*s\n",
					(unsigned long long)(*ipp)->i_ino,
					(unsigned)VFS_I(*ipp)->i_generation,
					(unsigned)disk_gen, (long long)dsz,
					(*ipp)->i_dlm_mode, name->len,
					(const char *)name->name);
		}
	}

	/*
	 * Fail if a directory entry in the regular directory tree points to
	 * a metadata file.
	 */
	if (XFS_IS_CORRUPT(dp->i_mount, xfs_is_metadir_inode(*ipp))) {
		xfs_fs_mark_sick(dp->i_mount, XFS_SICK_FS_METADIR);
		error = -EFSCORRUPTED;
		goto out_irele;
	}

	return 0;

out_irele:
	xfs_irele(*ipp);
out_free_name:
	if (ci_name)
		kfree(ci_name->name);
out_unlock:
	*ipp = NULL;
	/* sess42 P-LKERR tripwire — see declaration comment.  Racy unlocked
	 * reads are fine for diagnostics; never blocks, never acquires. */
	if (unlikely(error && error != -ENOENT) && dp->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm))
		pr_warn_ratelimited(
			"mxfs: P-LKERR dp=%llu name=\"%.*s\" stage=%d err=%d inum=%llu dpgen=%u fmt=%u nx=%llu sz=%lld stale=%d ssrc=%d dmode=%u dstate=%u dgen=%u lgen=%u sick=0x%x iflags=0x%lx comm=%s realns=%llu\n",
			(unsigned long long)dp->i_ino,
			name->len, (const char *)name->name,
			lk_stage, error,
			(unsigned long long)(lk_stage >= 2 ? inum : 0),
			VFS_I(dp)->i_generation,
			dp->i_df.if_format,
			(unsigned long long)dp->i_df.if_nextents,
			(long long)dp->i_disk_size,
			dp->i_dlm_stale, dp->i_dlm_stale_src,
			dp->i_dlm_mode, dp->i_dlm_state,
			dp->i_dlm_dir_gen, dp->i_dlm_dir_loaded_gen,
			READ_ONCE(dp->i_sick), dp->i_flags,
			current->comm,
			(unsigned long long)ktime_get_real_ns());
	return error;
}

/*
 * Initialise a newly allocated inode and return the in-core inode to the
 * caller locked exclusively.
 *
 * Caller is responsible for unlocking the inode manually upon return
 */
int
xfs_icreate(
	struct xfs_trans	*tp,
	xfs_ino_t		ino,
	const struct xfs_icreate_args *args,
	struct xfs_inode	**ipp)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_inode	*ip = NULL;
	int			error;

	/*
	 * Get the in-core inode with the lock held exclusively to prevent
	 * others from looking at until we're done.
	 */
	error = xfs_iget(mp, tp, ino, XFS_IGET_CREATE, XFS_ILOCK_EXCL, &ip);
	if (error)
		return error;

	ASSERT(ip != NULL);
	xfs_trans_ijoin(tp, ip, 0);
	xfs_inode_init(tp, args, ip);

	/*
	 * sess28 (ccloop) ROOT FIX for dir_reuse_coherency 2/tcp inode-revert:
	 * a newly-allocated inode MUST get a fresh generation.  xfs_iget assigns a
	 * random gen on the cache-MISS create path (xfs_icache.c, the
	 * xfs_has_v3inodes branch), but the cache-HIT/recycle path PRESERVES the
	 * stale in-core gen (xfs_reinit_inode).  Under MXFS multi-node a freed inode
	 * lingers in our cache (held EX, never reclaimed), so re-allocating it
	 * cache-HITs the stale struct whose gen is BEHIND the disk's free-bumped gen
	 * (a peer freed the prior incarnation, bumping the on-disk di_gen, which our
	 * idle cache never observed).  xfsaild's resurrection-skip guard then sees
	 * disk_gen > incore_gen and DROPS this create's inode flush
	 * (P25-RESURRECT-SKIP) -> the new file's inode never reaches the platter ->
	 * a reader's dirent->iget finds a free inode (P26-IGET-FAIL).  Assigning a
	 * fresh gen here (the cache-HIT analogue of the cache-MISS randomize) makes
	 * the new incarnation's gen independent of the stale predecessor, so its
	 * flush is never mistaken for a stale resurrection.
	 */
	if (xfs_has_v3inodes(mp)) {
		VFS_I(ip)->i_generation = get_random_u32();
		xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	}

	/* v0.5.4: stamp before the dirent can publish — no peer BAST can
	 * exist for this incarnation yet, so the bast_notify clear cannot
	 * race this store (see i_mxfs_self_created in xfs_inode.h). */
	ip->i_mxfs_self_created = true;

	/* now that we have an i_mode we can setup the inode structure */
	xfs_setup_inode(ip);

	*ipp = ip;
	return 0;
}

/* Return dquots for the ids that will be assigned to a new file. */
int
xfs_icreate_dqalloc(
	const struct xfs_icreate_args	*args,
	struct xfs_dquot		**udqpp,
	struct xfs_dquot		**gdqpp,
	struct xfs_dquot		**pdqpp)
{
	struct inode			*dir = VFS_I(args->pip);
	kuid_t				uid = GLOBAL_ROOT_UID;
	kgid_t				gid = GLOBAL_ROOT_GID;
	prid_t				prid = 0;
	unsigned int			flags = XFS_QMOPT_QUOTALL;

	if (args->idmap) {
		/*
		 * The uid/gid computation code must match what the VFS uses to
		 * assign i_[ug]id.  INHERIT adjusts the gid computation for
		 * setgid/grpid systems.
		 */
		uid = mapped_fsuid(args->idmap, i_user_ns(dir));
		gid = mapped_fsgid(args->idmap, i_user_ns(dir));
		prid = xfs_get_initial_prid(args->pip);
		flags |= XFS_QMOPT_INHERIT;
	}

	*udqpp = *gdqpp = *pdqpp = NULL;

	return xfs_qm_vop_dqalloc(args->pip, uid, gid, prid, flags, udqpp,
			gdqpp, pdqpp);
}

int
xfs_create(
	const struct xfs_icreate_args *args,
	struct xfs_name		*name,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*dp = args->pip;
	struct xfs_dir_update	du = {
		.dp		= dp,
		.name		= name,
	};
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_trans	*tp = NULL;
	struct xfs_dquot	*udqp;
	struct xfs_dquot	*gdqp;
	struct xfs_dquot	*pdqp;
	struct xfs_trans_res	*tres;
	xfs_ino_t		ino;
	bool			unlock_dp_on_error = false;
	bool			is_dir = S_ISDIR(args->mode);
	/* sess55: pin dp's DLM EX across the ILOCK-dropped create-durability flush
	 * (computed once at iunlock, reused at the durable call ~85 lines later). */
	bool			mxfs_create_dp_durable = false;
	uint			resblks;
	int			error;
	/* sess132 (RULE 4): per-mkdir phase decomposition for the 16-node
	 * same-dir create-storm throughput blocker.  Always-on for DIR
	 * creates on multi-node mounts only (mkdir is rare outside the
	 * storm; ~80 lines per criterion run). */
	u64			p132_t0 = 0, p132_tpre = 0, p132_tcommit = 0;
	u64			p132_tdirsig = 0, p132_tpub = 0;

	trace_xfs_create(dp, name);
	if (mp->m_mxfs_dlm && is_dir)
		p132_t0 = ktime_get_ns();

	/* sess35 H40: log ALL xfs_create entries with parent ino + name.
	 * Helps verify the cascading Mode A theory — if test2's
	 * "concurrent_mkdir" create has parent != 131, both nodes
	 * created different .mxfs_test inodes. */
	if (mp->m_mxfs_dlm) {
		char nm[32];
		int ln = name->len < 31 ? name->len : 31;
		memcpy(nm, name->name, ln);
		nm[ln] = '\0';
		mxfs_idbg("mxfs: H40-XFS-CREATE parent_ino=%llu name=\"%s\"\n",
			(unsigned long long)dp->i_ino, nm);
	}

	if (xfs_is_shutdown(mp))
		return -EIO;
	if (xfs_ifork_zapped(dp, XFS_DATA_FORK))
		return -EIO;

	/* ccloop c7ee71c6 sess3 (Phase A): creating inside a POISONED dead
	 * dir incarnation forges parallel universes (the 140939Z corpse-dir
	 * round).  -ESTALE + prune so the path re-resolves the live parent.
	 * Entry context — no locks held yet. */
	if (mp->m_mxfs_dlm && xfs_iflags_test(dp, MXFS_IF_INCARN_STALE)) {
		d_prune_aliases(VFS_I(dp));
		return -ESTALE;
	}

	/* Make sure that we have allocated dquot(s) on disk. */
	error = xfs_icreate_dqalloc(args, &udqp, &gdqp, &pdqp);
	if (error)
		return error;

	if (is_dir) {
		resblks = xfs_mkdir_space_res(mp, name->len);
		tres = &M_RES(mp)->tr_mkdir;
		/*
		 * sess18: when forcing new multinode dirs to block format
		 * (mxfs.dir_force_block), reserve the extra dir DATA block + bmap
		 * blocks the immediate sf->block conversion (xfs_dir2_sf_to_block
		 * → xfs_dir2_grow_inode) allocates.  A fresh mkdir otherwise leaves
		 * the dir shortform (no data block), so the base reservation does
		 * not cover the conversion.  No-op when dir_force_block=0.
		 */
		if (mxfs_dir_force_block && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
			resblks += XFS_DAENTER_SPACE_RES(mp, XFS_DATA_FORK) + 1;
	} else {
		resblks = xfs_create_space_res(mp, name->len);
		tres = &M_RES(mp)->tr_create;
	}

	/*
	 * sess18: reserve block headroom for the in-transaction block-dir peer
	 * union-merge (mxfs_dir_merge_peer_into_tp, wired just before
	 * xfs_dir_create_child).  Gated by mxfs.dir_merge (default off → baseline
	 * reservation unchanged).  Bounded to MXFS_DIR_MERGE_MAX extra dirent
	 * inserts; the merge re-adds the peer's missing entries onto the same few
	 * dir DATA/leaf blocks, whose re-logging coalesces within one trans, so
	 * tr_create's permanent log reservation covers it.
	 */
	if (mxfs_dir_merge_enabled)
		resblks += MXFS_DIR_MERGE_MAX *
			   XFS_DIRENTER_SPACE_RES(mp, MAXNAMELEN - 1);

	/* sess65: headroom for pending-dirent replay (re-add our own dirents a
	 * stale-block0 adopt dropped — the dir_reuse node1_f1 fix).  Bounded to
	 * MXFS_PEND_REPLAY_MAX extra inserts; multi-node dir creates only. */
	if (!is_dir && mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		resblks += MXFS_PEND_REPLAY_MAX *
			   XFS_DIRENTER_SPACE_RES(mp, MAXNAMELEN - 1);

	error = xfs_parent_start(mp, &du.ppargs);
	if (error)
		goto out_release_dquots;

	/*
	 * sess13 (MODE B fix): adopt a peer-stale SHORTFORM parent-dir base
	 * BEFORE taking dp ILOCK_EXCL, so the create's existence-check + dirent
	 * add RMW the peer's durable image (not a stale inline-dirent base that
	 * would resurrect a peer's removed entries).  No-op once ILOCK is held.
	 */
	mxfs_dlm_dir_modify_reload_prelock(dp);

	/*
	 * sess18: the sess17 pre-lock block-dir merge (mxfs_dir_merge_peer_blocks)
	 * is REMOVED here — it took an EXTRA dir-EX DLM acquire on the hot dir
	 * inode (its own transaction/ILOCK at pre-lock), which under 2-node
	 * contention TIMES OUT (rc=-110) → mxfs_dlm_ilock_begin force-shutdown.
	 * The union-merge now runs as mxfs_dir_merge_peer_into_tp() folded into
	 * THIS create's transaction + already-held grant (just before
	 * xfs_dir_create_child), so it adds no DLM acquire.
	 */

	/*
	 * Initially assume that the file does not exist and
	 * reserve the resources for that case.  If that is not
	 * the case we'll drop the one we have and get a more
	 * appropriate transaction later.
	 */
	error = xfs_trans_alloc_icreate(mp, tres, udqp, gdqp, pdqp, resblks,
			&tp);
	if (error == -ENOSPC) {
		/* flush outstanding delalloc blocks and retry */
		xfs_flush_inodes(mp);
		error = xfs_trans_alloc_icreate(mp, tres, udqp, gdqp, pdqp,
				resblks, &tp);
	}
	if (error)
		goto out_parent;

	/*
	 * v0.3.148 sess33: do NOT hold dp ILOCK across xfs_dialloc.
	 *
	 * xfs_dialloc allocates a new inode in some AG (chosen by
	 * affinity) by acquiring AG-DLM.  Under MXFS multi-node, the
	 * AG-DLM acquire is a CAW poll that can block up to 120s waiting
	 * for the peer to release the cached grant.  The peer's
	 * bast_work_fn drains the AG's AIL via xfs_ail_push_ag_sync,
	 * which calls iop_push on each item — and iop_push for inode
	 * log items needs ILOCK_SHARED on the inode.  If dp's inode
	 * happens to live in the AG being drained (a frequent case for
	 * the rsync workload — the destination directory's inode is
	 * actively dirty in target AG), peer's iop_push trylock fails
	 * because we hold ILOCK_EXCL.  Mirror cycle on the peer.  Both
	 * nodes wedge.  Sess33 P67-INSTR captured this exactly:
	 * `buf=2 inode=1 pinned=0` per stalled AG.
	 *
	 * The fix: drop dp ILOCK across xfs_dialloc.  xfs_dialloc only
	 * reads dp via args->pip (i_ino, i_mount fields, no lock needed)
	 * for AG affinity, then operates on AG metadata (AGI, inobt) for
	 * the chosen AG.  It does not read or modify dp's directory
	 * tree.  dp is not ijoin'd to the trans until line 784, after
	 * xfs_dialloc returns, so the trans roll inside xfs_dialloc
	 * cannot accidentally release dp via trans commit either.
	 *
	 * Re-acquire ILOCK before xfs_icreate (which doesn't strictly
	 * need dp ILOCK, but xfs_dir_create_child below DOES, so we
	 * must hold it before line 786).
	 */
	/*
	 * sess11(a9a03929) RULE-4 PROVEN cross-node ABBA (fence suite-3
	 * double shutdown, run 20260703T230150Z): with the first dp lock
	 * taken only AFTER xfs_dialloc (below at the re-acquire), a create
	 * orders AG-EX -> dir-EX (dialloc's AG grant rides the trans until
	 * commit via t_mxfs_ag_unlocks) while rm/unlink orders dir-EX ->
	 * AG-EX (Approach-A defers the dir BAST to trans_free; defer_finish
	 * then wants the file's AG).  Under hot-dir churn the two meet:
	 * t2's rm held dir-166 EX + burned its FULL 60-retry AG-0 budget
	 * (P36-RETRY 59..1 -> "DLM AG lock failed: ag=0 rc=-110" ->
	 * xfs_defer_finish_noroll -EFSCORRUPTED shutdown) while the
	 * create side held AG-0-until-commit and re-BASTed 166 in vain —
	 * BOTH transes dirty, so neither the sess5 P5D clean-trans breaker
	 * nor the deferred-BAST honor could yield.  t3 repeated it 68s
	 * later; netpartition + tcp_dlm_scaling inherited dead FSes.
	 *
	 * Fix the ORDER, not the symptom: take dp's DLM EX BEFORE
	 * xfs_dialloc and keep the GRANT (not the rwsem) pinned across the
	 * alloc, so every dirtying path agrees on dir -> AG.  The v0.3.148
	 * rwsem drop is preserved verbatim (peer xfsaild iop_push trylocks
	 * the rwsem, not the DLM pin), so the sess33 AIL mirror-wedge
	 * cannot return.  A peer wanting the dir now simply waits out this
	 * create's bounded tenure (BASTs defer against i_dlm_pin_count;
	 * mxfs_inode_unpin at the re-lock hands deferral to the Approach-A
	 * trans hook), instead of entering an unbreakable dirty-dirty cycle.
	 */
	xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
	mxfs_inode_pin(dp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
	error = xfs_dialloc(&tp, args, &ino);
	/* sess-tcp (RULE 4): split dialloc vs icreate as the err=1/ino=0 source
	 * on the first multi-node create.  Fires only when dialloc misbehaves. */
	if (unlikely(error || ino == 0 || ino == NULLFSINO))
		pr_warn("mxfs: P-DIALLOC dp=%llu err=%d ino=%llu single=%d\n",
			(unsigned long long)dp->i_ino, error,
			(unsigned long long)ino,
			mp->m_mxfs_dlm ? mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) : -1);
	if (!error) {
		xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
		/* sess11: dialloc window over — the rwsem hold resumes BAST
		 * deferral duty (Approach-A / holder gates); drop the pin. */
		mxfs_inode_unpin(dp);
		unlock_dp_on_error = true;

		/*
		 * sess-pve DEBUG fault injection (default off).  xfs_dialloc above
		 * logged + mxfs_ag_meta_track'd the AGI/inobt/finobt for this AG, so
		 * the transaction is now dirty with tracked AG-meta buffers.  Force a
		 * DIRTY xfs_trans_cancel here — the exact signature of the natural
		 * stale-inode dialloc corruption — so the AGI umount-wedge
		 * shutdown-abort reclaim (mxfs_ag_meta_reclaim_abort) fires
		 * DETERMINISTICALLY (the natural cross-node race is too narrow to
		 * re-hit).  One-shot: `mxfs.dbg_dialloc_shutdown=1` arms it; the
		 * cmpxchg consumes the arm so exactly one create fires.  Gated to
		 * multi-node mounts (single-node does not track AG-meta).
		 */
		if (unlikely(mxfs_dbg_dialloc_shutdown) && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    cmpxchg(&mxfs_dbg_dialloc_shutdown, 1, 0) == 1) {
			pr_warn("mxfs: P-DBG-DIALLOC-SHUTDOWN ino=%llu agno=%llu trans_dirty=%d comm=%s — injecting dirty trans_cancel to exercise AGI umount-wedge reclaim\n",
				(unsigned long long)ino,
				(unsigned long long)XFS_INO_TO_AGNO(mp, ino),
				(tp->t_flags & XFS_TRANS_DIRTY) ? 1 : 0,
				current->comm);
			error = -EFSCORRUPTED;
			goto out_trans_cancel;
		}

		/*
		 * sess104: MODIFY-side acquire cold-read for create (mirror of the
		 * xfs_remove/xfs_rename fix).  dp ILOCK_EXCL is held.  Drop our
		 * stale cached dir DATA blocks if a peer modified dp since our last
		 * refresh, so BOTH the EEXIST re-validate below AND the eventual
		 * xfs_dir_create_child RMW read the peer's DURABLE committed image.
		 * Without this, adding our new dirent from a stale base clobbers a
		 * peer's already-committed dirents (durable lost-update).
		 */
		mxfs_dlm_dir_modify_refresh(dp);

		/*
		 * sess61: mxfs_dir_modify_adopt_disk_format() was REFUTED — the
		 * staleness is CONTENT-level in the dir DATA buffer (dirty bufgen=0
		 * block0 materialized on a stale base), NOT the inode fork
		 * format/nextents/size (which is never behind disk under EX).  The
		 * format/count compare never fires.  Call DISABLED; the real fix is
		 * a tenure-cookie invariant at block0 materialization (GPT case A) or
		 * a DLM double-grant fix (case B) — verify A/B first.  See ccmemory
		 * sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard.
		 */
		/* sess62: mxfs_dir_modify_adopt_disk_format REFUTED AGAIN (at the
		 * time).  At the converting create the in-core dir is LOCAL
		 * (shortform) but DISK is ALSO LOCAL (P62-CRCONV: 27 LOCAL creates,
		 * P61-ADOPT-DISK fired 0).  The loss is CONTENT-level: the
		 * converter's in-core shortform base is missing an entry a peer
		 * already published to disk shortform, so sf->block drops it.  The
		 * ORIGINAL format-only compare (LOCAL-vs-non-LOCAL, or nextents/size
		 * growth on a non-LOCAL fork) cannot see a LOCAL-vs-LOCAL content
		 * gap.  P62-CRCONV stays gated behind mxfs.instr for diagnosis. */
		if (unlikely(mxfs_instr_enabled) &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(dp)->i_mode) && dp->i_ino != mp->m_sb.sb_rootino)
			pr_warn("mxfs: P62-CRCONV dp=%llu incore_fmt=%d dlm_mode=%u gen=%u name=\"%.*s\" comm=%s\n",
				(unsigned long long)dp->i_ino,
				dp->i_df.if_format, dp->i_dlm_mode,
				VFS_I(dp)->i_generation,
				name->len, name->name, current->comm);
		/*
		 * ccloop cc87fed3 sess8: RE-ENABLED.  mxfs_dir_modify_adopt_disk_format
		 * (xfs_mxfs_dlm.c) now ALSO catches the LOCAL/LOCAL content-level gap
		 * sess62 identified but never closed (di_size growth compared on the
		 * SAME FUA read the format check already does -- no extra I/O beyond
		 * the read itself).  Gate the read on i_dlm_dir_gen>0 (a peer has
		 * touched this dir since we last synced, bumped by the async
		 * DIR_MODIFY evict-ring notification independent of our own EX
		 * acquire) so a node-private / never-shared dir never pays the FUA
		 * cost -- bounds this to exactly the dirs that need it, addressing
		 * sess62's RULE-0 perf objection to the unconditional call.
		 */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    dp->i_dlm_dir_gen > 0)
			mxfs_dir_modify_adopt_disk_format(dp,
					XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);

		/* sess105 (RULE 4): PROVE the directory-inode divergence.  The
		 * rename_visibility loser's before-files are NEVER created into the
		 * live shared dir block (its mv then fails "No such file").  Log the
		 * PARENT dir inode each create targets so a cross-node merge shows
		 * whether the loser creates into a DIFFERENT (orphaned/stale) parent
		 * inode than its peers for the same path (concurrent-mkdir / stale
		 * dentry divergence). sess38 run14d: gated mxfs.dirwr/
		 * mxfs.instr for ship (fires per multi-node create). */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
			pr_warn_ratelimited(
				"mxfs: P105-CREATE-PARENT dp=%llu name=\"%.*s\" realns=%llu\n",
				(unsigned long long)dp->i_ino,
				name->len, name->name,
				(unsigned long long)ktime_get_real_ns());

		/*
		 * MXFS Mode A fix (sess37 robust): re-validate non-existence of
		 * @name NOW, under dp's cross-node EX DLM (just acquired by the
		 * xfs_ilock above; its reload refreshed dp's directory from
		 * disk).  This single acquire is held continuously through
		 * xfs_trans_commit below, and holders>0 defers any peer BAST, so
		 * no peer can modify dp between this check and our commit — fully
		 * closing the lookup->create race (no gap-1, no double-acquire /
		 * CAW issue, no pin needed).
		 *
		 * xfs_dialloc already dirtied the tp, so we cannot xfs_trans_cancel
		 * on EEXIST (that force-shuts-down the FS).  Instead, if the peer
		 * won the race, turn our pending create into a tmpfile-style
		 * orphan: xfs_icreate the dialloc'd inode with XFS_ICREATE_TMPFILE
		 * (nlink=0, no parent link) + xfs_iunlink, commit cleanly, and let
		 * inactivation free it.  Returns -EEXIST (correct POSIX; mkdir -p
		 * treats it as success — xfs_iops d_drops the loser's stale
		 * negative dentry so its next lookup sees the peer's entry).
		 */
		if (mp->m_mxfs_dlm) {
			xfs_ino_t	existing_ino;
			int		lrc;

			lrc = xfs_dir_lookup_locked(tp, dp, name, &existing_ino);
			/* sess106 (RULE 4): PROVE the directory-inode divergence.
			 * The rename_visibility loser created its files into a
			 * PRIVATE dir inode (ino=135) while peers used a different
			 * one (ino=8388737): a peer's mkdir of the same name did NOT
			 * see the first creator's just-committed dirent in the parent
			 * (.mxfs_test) -> allocated a competing inode -> the parent
			 * block lost-update orphaned the first inode.  Log every mkdir
			 * existence-check: parent + name + whether we FOUND an existing
			 * inode (converge) or are about to CREATE a new one (diverge).
			 * S_ISDIR gate keeps it low-volume (mkdirs only). */
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			    S_ISDIR(args->mode))
				pr_warn("mxfs: P106-MKDIR parent=%llu name=\"%.*s\" lookup_rc=%d existing_ino=%llu new_ino=%llu realns=%llu\n",
					(unsigned long long)dp->i_ino,
					name->len, name->name, lrc,
					(unsigned long long)(lrc == 0 ? existing_ino : 0),
					(unsigned long long)ino,
					(unsigned long long)ktime_get_real_ns());
			if (lrc == 0) {
				struct xfs_icreate_args orphan = *args;

				/*
				 * sess127 (RULE 4 PROVEN — corrects sess126): do NOT set
				 * dp->i_dlm_stale here.  sess126's Phase-1 fix set it on the
				 * premise that the loser's cached parent dir doesn't reflect
				 * the winner's child — but that premise is FALSE.  To reach
				 * this branch we acquired dp ILOCK_EXCL just above, which
				 * forced the winner to release its dp lock and reloaded dp
				 * fresh FROM the durable peer-committed image: the reload
				 * (P-SFDIR-RELOAD) already shows the winner's child entry.
				 * The parent IS coherent.  Setting i_dlm_stale=true instead
				 * RE-INTRODUCED the sess91 stuck-stale d_revalidate thrash:
				 * PROVEN (sess127 dmesg) — d_revalidate(parent) then returned
				 * INVALID on every path-walk (8× P-DREVAL-STALEFLAG, ZERO
				 * P-VNLOOKUP) because the flag never cleared (no reload fired
				 * to clear it), so ALL 30 `echo > dir/file` walks died at the
				 * PARENT component with ENOENT and never even reached the
				 * child lookup.  Coherency for this race is instead provided
				 * by (a) this EX reload making the parent fresh and (b) the
				 * Phase-2 fix excluding DIRECTORY dentries from d_revalidate's
				 * affine fast-path (pal/linux/xfs_super.c), so the child
				 * lookup does a coordinated re-resolve.  Keep a low-volume
				 * probe to confirm the loser branch + that dp is fresh.
				 */
				pr_warn("mxfs: P127-EEXIST-LOSER dp=%llu name=\"%.*s\" winner_ino=%llu dp_stale=%d dp_fmt=%d realns=%llu\n",
					(unsigned long long)dp->i_ino,
					name->len, name->name,
					(unsigned long long)existing_ino,
					dp->i_dlm_stale, dp->i_df.if_format,
					(unsigned long long)ktime_get_real_ns());

				/* Free the allocated inode as a regular-file orphan
				 * (simplest path to inactivation/free). */
				orphan.flags |= XFS_ICREATE_TMPFILE;
				orphan.mode = S_IFREG | 0600;
				error = xfs_icreate(tp, ino, &orphan, &du.ip);
				if (!error)
					error = xfs_iunlink(tp, du.ip);
				/* mxfs (sess19): THIS node created this nlink==0
				 * orphan and owns its eventual free — record local
				 * intent so the clustered inactivation guard does not
				 * mistake it for a torn/stale peer inode and skip the
				 * free (which would leak it on the AGI unlinked list).
				 */
				if (!error)
					xfs_iflags_set(du.ip, MXFS_IF_LOCAL_UNLINK);
				if (!error) {
					error = xfs_trans_commit(tp);
					xfs_iunlock(du.ip, XFS_ILOCK_EXCL);
					xfs_finish_inode_setup(du.ip);
					xfs_irele(du.ip);
					du.ip = NULL;
					xfs_iunlock(dp, XFS_ILOCK_EXCL);
					unlock_dp_on_error = false;
					xfs_qm_dqrele(udqp);
					xfs_qm_dqrele(gdqp);
					xfs_qm_dqrele(pdqp);
					xfs_parent_finish(mp, du.ppargs);
					return error ? error : -EEXIST;
				}
				/* orphan setup failed (rare) — fall to error path. */
				goto out_trans_cancel;
			} else if (lrc != -ENOENT) {
				error = lrc;
				goto out_trans_cancel;
			}
		}

		error = xfs_icreate(tp, ino, args, &du.ip);
	}
	if (error) {
		/*
		 * If dialloc failed, we never re-acquired dp ILOCK above.
		 * out_trans_cancel still expects unlock_dp_on_error to be
		 * accurate; it remains false here, consistent with our
		 * not-holding state.
		 */
		/* sess11: balance the pre-dialloc dir-DLM pin.  Only when the
		 * re-lock (which unpins on the success path) never ran —
		 * unlock_dp_on_error doubles as the exact "re-locked" flag,
		 * so this also stays balanced for icreate-stage failures. */
		if (!unlock_dp_on_error)
			mxfs_inode_unpin(dp);
		/* v0.3.146 sess32 P-INSTR: identify q=8 corruption error path. */
		pr_warn("mxfs: P-CREATE-ERR1 dialloc/icreate err=%d t_dfops_empty=%d dp_ino=%llu\n",
			error,
			list_empty(&tp->t_dfops),
			(unsigned long long)dp->i_ino);
		/* sess62 P-CR62: the dialloc'd inode `ino` failed xfs_icreate
		 * (xfs_iget) with EFSCORRUPTED but no free-state probe (P7/P9/
		 * P16) fired => not the in-core-mode!=0 check.  Decide whether
		 * dialloc handed out an inode that is LIVE on disk (double-
		 * allocation: a peer/this node already owns it) vs genuinely
		 * free-on-disk (in-core cached-struct staleness).  Read the
		 * on-disk dinode mode+gen of the very inode we tried to create. */
		if (mp->m_mxfs_dlm) {
			extern uint16_t mxfs_dbg_disk_di_mode(struct xfs_mount *,
				xfs_ino_t, uint32_t *);
			uint32_t cr62_dgen = 0;
			uint16_t cr62_dm = mxfs_dbg_disk_di_mode(mp, ino, &cr62_dgen);
			struct xfs_inode *cr62_ip = NULL;
			(void)xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &cr62_ip);
			pr_warn("mxfs: P-CR62 new_ino=%llu agno=%llu err=%d disk_di_mode=0%o disk_di_gen=%u incore=%s incore_mode=0%o incore_nblk=%llu verdict=%s\n",
				(unsigned long long)ino,
				(unsigned long long)XFS_INO_TO_AGNO(mp, ino),
				error, (unsigned)cr62_dm, cr62_dgen,
				cr62_ip ? "HIT" : "MISS",
				cr62_ip ? (unsigned)VFS_I(cr62_ip)->i_mode : 0,
				cr62_ip ? (unsigned long long)cr62_ip->i_nblocks : 0ULL,
				cr62_dm == 0xFFFF ? "disk-read-err/badmagic" :
				cr62_dm != 0 ? "DISK-LIVE=>double-alloc(inobt-stale)" :
				"DISK-FREE=>incore-struct-stale");
			if (cr62_ip)
				xfs_irele(cr62_ip);
		}
		goto out_trans_cancel;
	}

	/*
	 * Now we join the directory inode to the transaction.  We do not do it
	 * earlier because xfs_dialloc might commit the previous transaction
	 * (and release all the locks).  An error from here on will result in
	 * the transaction cancel unlocking dp so don't do it explicitly in the
	 * error path.
	 */
	xfs_trans_ijoin(tp, dp, 0);

	/*
	 * sess18: block-dir peer union-merge, folded into THIS create's
	 * transaction (dp ILOCK_EXCL held + just ijoin'd, dir-EX grant already
	 * cached — NO extra DLM acquire, unlike refuted merge v1/v2).  Re-adds up
	 * to MXFS_DIR_MERGE_MAX peer dirents missing from our (possibly
	 * kept-stale/undestaged) in-core dir so xfs_dir_create_child below RMWs a
	 * UNION base instead of durably clobbering the peer's committed entries
	 * (the write-side durable lost-update — P17-CLOBBER-DROP).  Reservation
	 * headroom was added at trans-alloc.  Gated by mxfs.dir_merge.
	 */
	mxfs_dir_merge_peer_into_tp(tp, dp, MXFS_DIR_MERGE_MAX);

	/* sess31: cheap per-block reconcile of any dir DATA block the acquire-evict
	 * had to KEEP stale (in-AIL undestaged) — FUA-fold the peer's missing
	 * dirents in before xfs_dir_create_child RMWs + destages the stale base over
	 * them (the dir_reuse single-dirent loss).  Folded into THIS transaction
	 * (dp ILOCK_EXCL + dir-EX held); gated by mxfs.dir_stale_reconcile. */
	mxfs_dir_reconcile_stale_data_blocks(tp, dp);

	/* sess65: re-add any of OUR own recently-created dirents that a stale
	 * block0 adopt dropped from this dir (the node1_f1 double-block0 orphan),
	 * folded into THIS create's transaction + already-held dir EX grant — no
	 * extra DLM acquire.  Idempotent (skips names already present). */
	if (!is_dir)
		mxfs_dir_pending_replay(tp, dp, resblks);

	error = xfs_dir_create_child(tp, resblks, &du);
	if (error) {
		/* v0.3.146 sess32 P-INSTR: identify q=8 corruption error path. */
		pr_warn("mxfs: P-CREATE-ERR2 dir_create_child err=%d t_dfops_empty=%d dp_ino=%llu new_ino=%llu\n",
			error,
			list_empty(&tp->t_dfops),
			(unsigned long long)dp->i_ino,
			(unsigned long long)(du.ip ? du.ip->i_ino : 0));
		goto out_trans_cancel;
	}

	/* sess32 (GPT A-vs-B probe): our dirent is now in the in-core dir block,
	 * before commit.  Probe whether the base we RMW'd already LACKS a peer's
	 * durable dirent (mechanism A = stale base) vs is a superset (B = later
	 * writeback ABA).  Read-only, gated dir_postrmw_probe. */
	mxfs_dir_postrmw_probe(dp);

	/*
	 * sess18: force a freshly-created multinode directory to BLOCK format
	 * immediately, within this mkdir transaction, so it NEVER lives in
	 * shortform on the shared LUN.  This eliminates the shortform->block
	 * format-transition race that is the PROVEN root of the 2/tcp durable
	 * dirent lost-update (two nodes racing the sf->block conversion of a
	 * fresh shared dir; one keeps a stale shortform base and durably writes
	 * it over the peer's block image).  du.ip is the new dir (shortform with
	 * .,..), ILOCK_EXCL held, tp active; the extra dir-data block was
	 * reserved in resblks above.  Gated by mxfs.dir_force_block (default off).
	 */
	if (du.ip && mxfs_dir_should_force_block(du.ip)) {
		struct xfs_da_args bargs = {
			.geo	= mp->m_dir_geo,
			.dp	= du.ip,
			.trans	= tp,
			.owner	= du.ip->i_ino,
			.total	= resblks,
		};

		error = xfs_dir2_sf_to_block(&bargs);
		if (error) {
			pr_warn("mxfs: P18-FORCEBLOCK ino=%llu sf_to_block err=%d\n",
				(unsigned long long)du.ip->i_ino, error);
			goto out_trans_cancel;
		}
	}

	/*
	 * v0.5.6 (sess29 ccloop 14d31183): record which directory names this
	 * unpublished inode so the BAST-side publish drain can scope itself
	 * to the released dir's own children (see i_mxfs_unpub_parent in
	 * xfs_inode.h).  Covers fresh (grant_local_new) and reused
	 * (rearm_unpublished) creates — create/mkdir/mknod all land here.
	 * Plain store: a racing drain reading the pre-store 0 over-publishes,
	 * never under-publishes.
	 */
	if (du.ip)
		du.ip->i_mxfs_unpub_parent = dp->i_ino;

	/* sess65: remember this local create so we can REPLAY it if a later
	 * stale-block0 adopt drops it from this dir (the node1_f1 orphan fix).
	 * Reg-file creates only (the dir_reuse workload; dirs use other paths). */
	if (!is_dir && du.ip)
		mxfs_dir_pending_add(dp, name, du.ip);

	/* sess28 (ccloop): record (name -> new inum + gen) so a reader's
	 * P26-IGET-FAIL inum can be correlated: same inum => node's CURRENT
	 * inode was reverted to free; different inum => stale dir-block dirent. */
	{
		extern int mxfs_iwr_enabled;
		if (unlikely(mxfs_iwr_enabled) && du.ip && dp->i_mount->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm))
			pr_warn_ratelimited(
				"mxfs: P28-CREATE dp=%llu name=\"%.*s\" inum=%llu gen=%u\n",
				(unsigned long long)dp->i_ino,
				name->len, (const char *)name->name,
				(unsigned long long)du.ip->i_ino,
				VFS_I(du.ip)->i_generation);
	}

	/*
	 * If this is a synchronous mount, make sure that the
	 * create transaction goes to disk before returning to
	 * the user.
	 */
	if (xfs_has_wsync(mp) || xfs_has_dirsync(mp))
		xfs_trans_set_sync(tp);

	/*
	 * Attach the dquot(s) to the inodes and modify them incore.
	 * These ids of the inode couldn't have changed since the new
	 * inode has been locked ever since it was created.
	 */
	xfs_qm_vop_create_dqattach(tp, du.ip, udqp, gdqp, pdqp);

	/*
	 * v0.5.4 (sess24 ccloop 14d31183): asynchronous publish-on-mkdir,
	 * queued BEFORE the commit so the worker's ~1 ms CAW slot claim
	 * overlaps the commit + parent durable-signal (~2-3 ms) below.  The
	 * first userspace EX op on a fresh dir arrives ~60 µs after mkdir
	 * returns (ftrace/dmesg-proven: rsync's per-dir utimensat), so a
	 * post-create queue always loses the race and the sess107
	 * unpublished-dir-EX backstop in mxfs_dlm_ilock_begin claims the
	 * slot synchronously inside xfs_vn_setattr (~1.5 ms each, ≈ +1
	 * s/node on a 2-node parallel rsync).  du.ip is already on
	 * m_mxfs_unpub_list (grant_local_new during icreate) with i_mode
	 * set.  If the create aborts after the worker claims, eviction's
	 * normal release path frees the slot (the unpub flag was already
	 * cleared by the claim).  Files stay on the deferred-publish list
	 * exactly as before (see the v0.5.2 note below); the backstop
	 * remains the synchronous fallback if an EX-modify still wins.
	 */
	if (du.ip && S_ISDIR(VFS_I(du.ip)->i_mode) &&
	    du.ip->i_mxfs_reused_create &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    mp->m_mxfs_inode_bast_wq && mxfs_publish_dirs) {
		/* P24 RULE-4 probe (capped): publish state at queue time. */
		{
			static atomic_t p24q_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p24q_n) <= 50)
				pr_warn("mxfs: P24-QUEUE ino=%llu mode=%o unpub=%d listed=%d\n",
					(unsigned long long)du.ip->i_ino,
					VFS_I(du.ip)->i_mode,
					du.ip->i_dlm_unpublished ? 1 : 0,
					!list_empty(&du.ip->i_dlm_unpub_link));
		}
		queue_work(mp->m_mxfs_inode_bast_wq, &mp->m_mxfs_publish_work);
	}

	if (p132_t0)
		p132_tpre = ktime_get_ns();
	error = xfs_trans_commit(tp);
	if (error)
		goto out_release_inode;
	if (p132_t0)
		p132_tcommit = ktime_get_ns();

	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	/*
	 * sess97: PUBLISH-BEFORE-NOTIFY — flush the parent dir's modified data
	 * blocks to the shared LUN while dp ILOCK_EXCL is still held, so the
	 * next acquirer (or our own next modify) re-reads the fresh dirent
	 * instead of clobbering from a pinned-stale buffer.  See the long note
	 * in xfs_remove.  (Distinct from the REVERTED sess38 child-AG push,
	 * which flushed the new inode's cluster, not the parent dir block.)
	 */
	mxfs_dlm_dir_durable_signal(dp);
	if (p132_t0)
		p132_tdirsig = ktime_get_ns();

	/*
	 * v0.5.2: publish-on-create (NEWARCH Phase 1.4, a synchronous
	 * mxfs_dlm_publish_inode(du.ip) here) is REMOVED.  It cost one
	 * on-disk CAW slot read+write per created file — the dominant term
	 * of the solo-rsync slowdown (10/13 stack samples in
	 * mxfs_dlm_publish_inode → mxfs_dlm_caw_lock → read_slot under
	 * xfs_create; ~3ms × 8714 files ≈ 25s of a 32s run).
	 *
	 * The sess107 window it closed (peer acquires the new inode's empty
	 * slot cleanly, never BASTs us, dual-EX lost update) is closed
	 * instead by the BAST-side drains: every path a peer can take to
	 * reach this inode transits a lock WE currently hold — the parent
	 * dir's DLM lock (we hold EX for this create; lookup/readdir BASTs
	 * it) or the AG locks (inobt/bulkstat) — and all three BAST paths
	 * (inode release, AG bast_work, and the no-inode orphan release)
	 * call mxfs_dlm_publish_unpublished() BEFORE releasing, so the
	 * inode has a real slot before any peer can resolve its number.
	 * du.ip stays staged on m_mxfs_unpub_list (grant_local_new) until
	 * contention actually arrives; solo/idle-peer creates never touch
	 * the slot table.
	 *
	 * sess32 NOTE: a synchronous-publish-of-dirs fix attempt here was
	 * REVERTED — the dir_reuse_coherency loss is NOT a cross-node dual-EX
	 * gap (REFUTED by tests/drc_single_node.sh: a SINGLE writer in the
	 * 2-node cluster still loses the dir / shuts down at ~round 6), so
	 * publishing does not address the root and it destabilized create.
	 */
	if (p132_t0)
		p132_tpub = ktime_get_ns();

	*ipp = du.ip;
	xfs_iunlock(du.ip, XFS_ILOCK_EXCL);
	/*
	 * sess55 (ccloop 8ddb16a2; GPT-5.5 design #3 "add create") — pin dp's
	 * DLM-EX grant across the ILOCK-dropped create-durability flush below
	 * (mirror of xfs_remove/xfs_rename).  Without the pin a concurrent peer
	 * BAST demotes dp EX->PR->NL in the window between this iunlock and the
	 * mxfs_dlm_dir_inode_durable(dp) call further down, so the durable flush
	 * runs at NL and the P119 non-EX guard DISCARDS the just-added dirent ->
	 * the new entry never reaches the platter -> this node's own later reload
	 * (P34D-RELOAD-FRESHSRC) FUA-reads the stale on-disk dinode and REVERTS the
	 * create (PROVEN sess55 tcp_dlm_scaling: RENAME-REVALIDATE-MISS
	 * name="n1_rNN" lookup_rc=-2 -> churn loop broke at round 94).  Bump the
	 * extra EX holder while we still hold dp ILOCK_EXCL (proves EX), drop
	 * ILOCK, and release the pin AFTER the flush (mxfs_dlm_ilock_end fires any
	 * deferred BAST via the sanctioned RELFLUSH drain).  Evaluate the durable
	 * gate ONCE here and reuse it so pin/unpin are exactly paired. */
	/* sess14 (ccloop c7ee71c6) D2: runtime lever for the per-dirop
	 * synchronous parent-durability barrier — A/B-proven 7.6× per-op
	 * collapse once a dir has ANY peer contact (0.36 → 2.74 ms/op after
	 * one peer ls, permanent).  Default 1 (legacy behavior); 0 relies on
	 * the demote-drain flush + destage_kick for peer visibility. */
	{
		extern int mxfs_dirop_sync_barrier;

		mxfs_create_dp_durable = du.ip && mxfs_dirop_sync_barrier &&
			(!dp->i_mxfs_self_created || dp->i_dlm_dir_gen > 0);
	}
	if (mxfs_create_dp_durable)
		mxfs_dlm_dir_hold_ex(dp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);

	/*
	 * sess13 (ccloop 4eef1f39): PROACTIVE shortform-parent durability.
	 * The new dirent for du.ip lives INLINE in dp's shortform dinode; the
	 * publish-before-notify above (mxfs_dlm_dir_durable_signal) flushes only
	 * dp's DATA-fork blocks, which a shortform dir has none of.  Under CAW a
	 * peer's cold read of dp's inode cluster does NOT BAST us, so without this
	 * the new child is invisible to peers until the next async iflush and
	 * every peer create under it fails ENOENT (proven test_unlink_visibility
	 * root).  Now that dp's ILOCK is dropped, make dp's inode cluster
	 * platter-durable so peers see the child immediately.  No-op for
	 * non-shortform parents and single-node mounts.
	 *
	 * Gated to DIRECTORY creation (mkdir): the proven failure is a peer
	 * unable to RESOLVE a freshly-created child directory (and thus unable to
	 * create anything under it).  Regular-file dirent visibility already works
	 * via the existing block-dir publish path (cross_visibility passes without
	 * this), and flushing on every file create runs a per-create
	 * log_force(SYNC) that serializes the concurrent-create storm and starves
	 * CAW EX acquires into -ETIMEDOUT shutdown.  mkdir is comparatively rare,
	 * so the targeted flush is affordable.
	 */
	/*
	 * sess115 (ccloop 4eef1f39) — DISABLED.  RULE 4: the P112-IFLUSH-CALLER
	 * probe named THIS call (mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_-
	 * durable) as the site that sets XFS_IFLUSHING on the hot SHARED parent
	 * inode cluster (e.g. the mount root ino=128) and then abandons the flush,
	 * LEAKING the cluster-buffer lock.  Every mkdir into a shared shortform
	 * parent fires this synchronous iflush_cluster+bwrite on the parent's
	 * cluster, racing concurrent creators on the SAME cluster + xfsaild + the
	 * sess85 release-path flush → an inode left IFLUSHING/in_ail with the
	 * buffer locked off-list → mxfs_ail_drain_inode_sync (BAST release drain)
	 * spins forever (P113-DRAIN-WEDGE) → SESS50-STARVE → criterion SIGKILL.
	 * sess108 (BEFORE this create-path flush was added in sess13) had
	 * cross_visibility 4/4 with only rename wedging; this addition regressed
	 * cluster stability.  Parent-dirent visibility is the chokepoint's job: a
	 * peer that resolves the parent acquires its DLM lock, BASTs the owner, who
	 * drains+flushes the cluster on release (the sess85 mxfs_inode_cluster_-
	 * durable in bast_process is RETAINED).  Removing only the create-time
	 * proactive flush eliminates the leak without losing the release-side
	 * durability barrier.
	 */
	/* sess115: RE-ENABLED after fixing the IFLUSHING/buffer-lock leak in
	 * mxfs_inode_cluster_durable (manual xfs_bwrite on an alloc-buflist-
	 * trapped shared cluster → native delwri submit / AG-drain).  The
	 * create-path durability is NEEDED (A/B: removing it regressed
	 * unlink_visibility 1→30 fails); the leak — not the flush — was the
	 * wedge.  See mxfs_inode_cluster_durable sess115 comment. */
	/* v0.5.4 (sess23 ccloop 14d31183, RULE 4 ftrace-proven): the per-mkdir
	 * parent barrier below cost 1.2-1.6 s of the ~5.5 s 2-node parallel
	 * rsync wall (~700 mkdirs x ~1.8 ms log_force(SYNC)+cluster flush each)
	 * while being a no-op for every one of those parents: rsync's tree is
	 * node-private, so dp was created by this node seconds earlier and no
	 * peer can cold-read it un-coordinated (peers descend through a shared
	 * ancestor whose barrier DID fire, or take dp's DLM lock — a BAST that
	 * clears the flag ahead of the retained release-path flush).  Skip the
	 * barrier for self-created parents (stamped in xfs_icreate); any
	 * inode igot from disk or ever BAST'd keeps it. */
	/*
	 * sess49 (ccloop 14d31183, RULE 4 PROVEN — 16-node cross_write_read /
	 * repro_dirent_capture.sh durable dirent loss): the old gate required the
	 * CHILD to be a DIRECTORY, so a REGULAR-FILE create into a shared
	 * shortform parent skipped the proactive parent-durability flush.  Proven
	 * consequence: 16 nodes each `echo > sharedir/f_N` race to add their
	 * dirent to ONE shortform parent dinode; the LAST committer is never
	 * BAST'd (peers only PR-read during verify), so its add stays CIL/AIL-
	 * resident and is NEVER destaged to the in-place dinode — a peer's RMW or
	 * the committer's own later reload then reads the stale on-disk dinode
	 * (count=N-1) and the entry vanishes from EVERY node (P127-DIRMISS
	 * sfcount=15 missing f_10).  concurrent_mkdir PASSES at 16 nodes precisely
	 * because mkdir DID hit this flush; file-create did not.  Extend the flush
	 * to ANY child type.  The flush helper itself no-ops unless the PARENT is a
	 * shortform dir, and the !i_mxfs_self_created gate still skips rsync's
	 * node-private self-created parents (the v0.5.4 perf carve-out) — a shared
	 * parent created by a peer is exactly the lost-update surface and must be
	 * made durable per create.
	 */
	/* sess48: also fire for a CONTENDED dir (i_dlm_dir_gen>0 => a peer has
	 * modified it) even if self-created — the uv dir is created by mkdir -p
	 * on one node (self_created there) yet is shared, and as deletes shrink it
	 * back to shortform the final dirents live inline in the dinode; without
	 * this its shortform state never destages and a peer cold-reads the stale
	 * block-format inode (uv "got=N").  gen==0 node-private rsync dirs still
	 * skip (the v0.5.4 perf carve-out). */
	if (mxfs_create_dp_durable) {
		mxfs_dlm_dir_inode_durable(dp);
		mxfs_dlm_ilock_end(dp, MXFS_LOCK_EX);	/* drop EX-pin; fire deferred BAST */
	}
	/* ccloop c7ee71c6 sess2: queue the fresh dinode's destage (coalesced
	 * background kick) so a peer's iget of this — possibly reused — ino
	 * reads the NEW incarnation from disk within ~ms instead of spinning
	 * on the stale/free predecessor (VISNUDGE convergence). */
	mxfs_destage_kick(mp);

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) && p132_t0) {
		u64 p132_end = ktime_get_ns();
		pr_warn("mxfs: P132-CREATE ino=%llu parent=%llu pre_ms=%llu commit_ms=%llu dirsig_ms=%llu pub_ms=%llu pdur_ms=%llu total_ms=%llu\n",
			du.ip ? (unsigned long long)du.ip->i_ino : 0ULL,
			(unsigned long long)dp->i_ino,
			(p132_tpre - p132_t0) / NSEC_PER_MSEC,
			(p132_tcommit - p132_tpre) / NSEC_PER_MSEC,
			(p132_tdirsig - p132_tcommit) / NSEC_PER_MSEC,
			(p132_tpub - p132_tdirsig) / NSEC_PER_MSEC,
			(p132_end - p132_tpub) / NSEC_PER_MSEC,
			(p132_end - p132_t0) / NSEC_PER_MSEC);
	}

	xfs_parent_finish(mp, du.ppargs);

	/*
	 * sess38: cross-AG new-inode durability.
	 *
	 * The new inode and the parent dirent that points to it are committed
	 * together, but they can live in DIFFERENT AGs (dialloc affinity).
	 * The parent dir's lock is released lazily and only flushed to disk on
	 * its next BAST — and that flush pushes only the PARENT's AG.  A peer
	 * that follows the now-visible parent dirent to the new inode would
	 * then iget it from disk before the child's AG was ever written,
	 * reading an unallocated/stale inode (observed: concurrent same-name
	 * mkdir loser sees the winner's child dir as empty / unresolvable).
	 *
	 * dp's DLM grant is still held cached here (xfs_iunlock dropped only
	 * the local ILOCK), so the dirent is not yet peer-visible — a peer
	 * must BAST dp first, which is a network round-trip away.  Push the
	 * child's AG to disk now so the inode is durable before any peer can
	 * reach it.  Only needed when the child is in a different AG than the
	 * parent (same-AG is covered by the parent's own BAST flush) and only
	 * in multi-node mounts (gated off for single-node performance).
	 */
	/*
	 * sess38: the post-commit cross-AG / parent-AG durability push was
	 * REVERTED — it was slow (a sync flush per create) AND did not fix
	 * the barrier-dir split-brain (the split persists with it on), so
	 * the split is NOT a writer-durability problem.  The split is an
	 * inode-REUSE coherency issue (a freed inode incarnation cached
	 * in-core as mode=0 → iget cache-HIT returns stale → split), which
	 * the xfs_iget_cache_miss stale-buffer fix does not cover (that
	 * path is cache-MISS only).  Left to the iget/reuse path instead.
	 */

	/*
	 * v0.3.78 P30-INSTR: dump fresh-inode state right after create.  A
	 * newly-created inode should have nblocks==0 and an empty bmap.  If
	 * non-zero, the create's xfs_iget pulled stale dinode content from
	 * disk (a previous incarnation of this inode number had data and
	 * the on-disk dinode wasn't fully cleared by inactive_ifree).
	 * Sess22 v0.3.77 finding: perf_t2 ino=0x83 bmap had extents at
	 * sb=12536 and sb=105976 that T2 never alloc'd, suggesting bmap
	 * corruption from inode reuse.
	 */
	if (mp->m_mxfs_dlm && du.ip) {
		struct xfs_inode *p30_ip = du.ip;
		struct xfs_ifork *p30_dfp = &p30_ip->i_df;

		if (p30_ip->i_nblocks != 0 ||
		    (p30_dfp->if_format == XFS_DINODE_FMT_EXTENTS &&
		     p30_dfp->if_nextents != 0) ||
		    p30_dfp->if_format == XFS_DINODE_FMT_BTREE) {
			mxfs_idbg("mxfs: P30-INSTR fresh-create-DIRTY ino=0x%llx nblocks=%llu fmt=%d nextents=%lld disk_size=%lld\n",
				(unsigned long long)p30_ip->i_ino,
				(unsigned long long)p30_ip->i_nblocks,
				p30_dfp->if_format,
				(long long)p30_dfp->if_nextents,
				(long long)p30_ip->i_disk_size);
		}
	}
	return 0;

 out_trans_cancel:
	/* <ccloop sess3> CASCADE PROBE: pin the exact error xfs_create cancels on
	 * (the inode-reuse EAGAIN cascade shuts down via a DIRTY trans_cancel).
	 * Log error + the dir + whether the trans is dirty (dirty cancel = fatal). */
	pr_warn("mxfs: P-CR3-CANCEL error=%d dp_ino=%llu dialloc_ino=%llu new_ino=%llu trans_dirty=%d comm=%s\n",
		error, (unsigned long long)dp->i_ino,
		(unsigned long long)ino,
		(unsigned long long)(du.ip ? du.ip->i_ino : 0),
		(tp->t_flags & XFS_TRANS_DIRTY) ? 1 : 0, current->comm);
	xfs_trans_cancel(tp);
 out_release_inode:
	/*
	 * Wait until after the current transaction is aborted to finish the
	 * setup of the inode and release the inode.  This prevents recursive
	 * transactions and deadlocks from xfs_inactive.
	 */
	if (du.ip) {
		xfs_iunlock(du.ip, XFS_ILOCK_EXCL);
		xfs_finish_inode_setup(du.ip);
		xfs_irele(du.ip);
	}
 out_parent:
	xfs_parent_finish(mp, du.ppargs);
 out_release_dquots:
	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	if (unlock_dp_on_error)
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
	return error;
}

int
xfs_create_tmpfile(
	const struct xfs_icreate_args *args,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*dp = args->pip;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_inode	*ip = NULL;
	struct xfs_trans	*tp = NULL;
	struct xfs_dquot	*udqp;
	struct xfs_dquot	*gdqp;
	struct xfs_dquot	*pdqp;
	struct xfs_trans_res	*tres;
	xfs_ino_t		ino;
	uint			resblks;
	int			error;

	ASSERT(args->flags & XFS_ICREATE_TMPFILE);

	if (xfs_is_shutdown(mp))
		return -EIO;

	/* Make sure that we have allocated dquot(s) on disk. */
	error = xfs_icreate_dqalloc(args, &udqp, &gdqp, &pdqp);
	if (error)
		return error;

	resblks = XFS_IALLOC_SPACE_RES(mp);
	tres = &M_RES(mp)->tr_create_tmpfile;

	error = xfs_trans_alloc_icreate(mp, tres, udqp, gdqp, pdqp, resblks,
			&tp);
	if (error)
		goto out_release_dquots;

	error = xfs_dialloc(&tp, args, &ino);
	if (!error)
		error = xfs_icreate(tp, ino, args, &ip);
	if (error)
		goto out_trans_cancel;

	if (xfs_has_wsync(mp))
		xfs_trans_set_sync(tp);

	/*
	 * Attach the dquot(s) to the inodes and modify them incore.
	 * These ids of the inode couldn't have changed since the new
	 * inode has been locked ever since it was created.
	 */
	xfs_qm_vop_create_dqattach(tp, ip, udqp, gdqp, pdqp);

	error = xfs_iunlink(tp, ip);
	if (error)
		goto out_trans_cancel;

	/* mxfs (sess19): THIS node created this O_TMPFILE nlink==0 inode and owns
	 * its eventual free — record local-unlink intent so the clustered
	 * inactivation guard frees it rather than treating it as a torn/stale
	 * peer inode (which would leak it on the AGI unlinked list). */
	xfs_iflags_set(ip, MXFS_IF_LOCAL_UNLINK);

	error = xfs_trans_commit(tp);
	if (error)
		goto out_release_inode;

	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	*ipp = ip;
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return 0;

 out_trans_cancel:
	xfs_trans_cancel(tp);
 out_release_inode:
	/*
	 * Wait until after the current transaction is aborted to finish the
	 * setup of the inode and release the inode.  This prevents recursive
	 * transactions and deadlocks from xfs_inactive.
	 */
	if (ip) {
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		xfs_finish_inode_setup(ip);
		xfs_irele(ip);
	}
 out_release_dquots:
	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	return error;
}

static inline int
xfs_projid_differ(
	struct xfs_inode	*tdp,
	struct xfs_inode	*sip)
{
	/*
	 * If we are using project inheritance, we only allow hard link/renames
	 * creation in our tree when the project IDs are the same; else
	 * the tree quota mechanism could be circumvented.
	 */
	if (unlikely((tdp->i_diflags & XFS_DIFLAG_PROJINHERIT) &&
		     tdp->i_projid != sip->i_projid)) {
		/*
		 * Project quota setup skips special files which can
		 * leave inodes in a PROJINHERIT directory without a
		 * project ID set. We need to allow links to be made
		 * to these "project-less" inodes because userspace
		 * expects them to succeed after project ID setup,
		 * but everything else should be rejected.
		 */
		if (!special_file(VFS_I(sip)->i_mode) ||
		    sip->i_projid != 0) {
			return -EXDEV;
		}
	}

	return 0;
}

int
xfs_link(
	struct xfs_inode	*tdp,
	struct xfs_inode	*sip,
	struct xfs_name		*target_name)
{
	struct xfs_dir_update	du = {
		.dp		= tdp,
		.name		= target_name,
		.ip		= sip,
	};
	struct xfs_mount	*mp = tdp->i_mount;
	struct xfs_trans	*tp;
	int			error, nospace_error = 0;
	int			resblks;

	trace_xfs_link(tdp, target_name);

	ASSERT(!S_ISDIR(VFS_I(sip)->i_mode));

	if (xfs_is_shutdown(mp))
		return -EIO;
	if (xfs_ifork_zapped(tdp, XFS_DATA_FORK))
		return -EIO;

	/*
	 * v0.5.6 (sess29 ccloop 14d31183): a hardlink gives this inode a
	 * SECOND parent dir, which the single i_mxfs_unpub_parent scope
	 * cannot represent — a peer could then reach the inode through tdp's
	 * release without the scoped drain publishing it (the sess107
	 * empty-slot hole).  Force a synchronous publish (acquire-then-clear,
	 * ~1.5 ms, no locks held yet) before the link becomes visible.
	 * No-op when already published; hardlinks of just-created files are
	 * rare so this is off the hot path.
	 */
	if (sip->i_dlm_unpublished)
		mxfs_dlm_publish_inode(sip);

	error = xfs_qm_dqattach(sip);
	if (error)
		goto std_return;

	error = xfs_qm_dqattach(tdp);
	if (error)
		goto std_return;

	error = xfs_parent_start(mp, &du.ppargs);
	if (error)
		goto std_return;

	resblks = xfs_link_space_res(mp, target_name->len);
	error = xfs_trans_alloc_dir(tdp, &M_RES(mp)->tr_link, sip, &resblks,
			&tp, &nospace_error);
	if (error)
		goto out_parent;

	/*
	 * We don't allow reservationless or quotaless hardlinking when parent
	 * pointers are enabled because we can't back out if the xattrs must
	 * grow.
	 */
	if (du.ppargs && nospace_error) {
		error = nospace_error;
		goto error_return;
	}

	error = xfs_projid_differ(tdp, sip);
	if (error)
		goto error_return;

	/*
	 * ccloop c7ee71c6 sess27 — same producer as P206-RENAME-FTYPE-STALE.
	 * xfs_vn_link snapshots the dirent ftype from inode->i_mode before
	 * xfs_trans_alloc_dir takes the ILOCKs, and the acquire can reload sip
	 * and change its type.  Both locks are held here, so this is the last
	 * point at which the value written is still correctable.
	 */
	{
		unsigned char	live_ft = xfs_mode_to_ftype(VFS_I(sip)->i_mode);

		if (target_name->type != XFS_DIR3_FT_UNKNOWN &&
		    live_ft != XFS_DIR3_FT_UNKNOWN &&
		    target_name->type != live_ft) {
			static atomic_t	p206ln = ATOMIC_INIT(0);

			if (atomic_inc_return(&p206ln) <= 400)
				pr_warn("mxfs: P206-LINK-FTYPE-STALE sip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d dlm_mode=%d tdp=%llu reval=%d comm=%s — dirent ftype snapshotted before the ILOCK contradicts the inode's post-reload type\n",
					(unsigned long long)sip->i_ino,
					target_name->len,
					(const char *)target_name->name,
					(unsigned)target_name->type,
					(unsigned)live_ft,
					(unsigned)VFS_I(sip)->i_mode,
					(unsigned)VFS_I(sip)->i_generation,
					sip->i_dlm_stale ? 1 : 0,
					sip->i_dlm_mode,
					(unsigned long long)tdp->i_ino,
					mxfs_rename_ftype_revalidate,
					current->comm);
			if (mxfs_rename_ftype_revalidate)
				target_name->type = live_ft;
		}
	}

	error = xfs_dir_add_child(tp, resblks, &du);
	if (error)
		goto error_return;

	/*
	 * If this is a synchronous mount, make sure that the
	 * link transaction goes to disk before returning to
	 * the user.
	 */
	if (xfs_has_wsync(mp) || xfs_has_dirsync(mp))
		xfs_trans_set_sync(tp);

	error = xfs_trans_commit(tp);
	xfs_iunlock(tdp, XFS_ILOCK_EXCL);
	xfs_iunlock(sip, XFS_ILOCK_EXCL);
	xfs_parent_finish(mp, du.ppargs);
	return error;

 error_return:
	xfs_trans_cancel(tp);
	xfs_iunlock(tdp, XFS_ILOCK_EXCL);
	xfs_iunlock(sip, XFS_ILOCK_EXCL);
 out_parent:
	xfs_parent_finish(mp, du.ppargs);
 std_return:
	if (error == -ENOSPC && nospace_error)
		error = nospace_error;
	return error;
}

/* Clear the reflink flag and the cowblocks tag if possible. */
static void
xfs_itruncate_clear_reflink_flags(
	struct xfs_inode	*ip)
{
	struct xfs_ifork	*dfork;
	struct xfs_ifork	*cfork;

	if (!xfs_is_reflink_inode(ip))
		return;
	dfork = xfs_ifork_ptr(ip, XFS_DATA_FORK);
	cfork = xfs_ifork_ptr(ip, XFS_COW_FORK);
	if (dfork->if_bytes == 0 && cfork->if_bytes == 0)
		ip->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;
	if (cfork->if_bytes == 0)
		xfs_inode_clear_cowblocks_tag(ip);
}

/*
 * Free up the underlying blocks past new_size.  The new size must be smaller
 * than the current size.  This routine can be used both for the attribute and
 * data fork, and does not modify the inode size, which is left to the caller.
 *
 * The transaction passed to this routine must have made a permanent log
 * reservation of at least XFS_ITRUNCATE_LOG_RES.  This routine may commit the
 * given transaction and start new ones, so make sure everything involved in
 * the transaction is tidy before calling here.  Some transaction will be
 * returned to the caller to be committed.  The incoming transaction must
 * already include the inode, and both inode locks must be held exclusively.
 * The inode must also be "held" within the transaction.  On return the inode
 * will be "held" within the returned transaction.  This routine does NOT
 * require any disk space to be reserved for it within the transaction.
 *
 * If we get an error, we must return with the inode locked and linked into the
 * current transaction. This keeps things simple for the higher level code,
 * because it always knows that the inode is locked and held in the transaction
 * that returns to it whether errors occur or not.  We don't mark the inode
 * dirty on error so that transactions can be easily aborted if possible.
 */
int
xfs_itruncate_extents_flags(
	struct xfs_trans	**tpp,
	struct xfs_inode	*ip,
	int			whichfork,
	xfs_fsize_t		new_size,
	int			flags)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp = *tpp;
	xfs_fileoff_t		first_unmap_block;
	int			error = 0;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	if (icount_read(VFS_I(ip)))
		xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);
	ASSERT(new_size <= XFS_ISIZE(ip));
	ASSERT(tp->t_flags & XFS_TRANS_PERM_LOG_RES);
	ASSERT(ip->i_itemp != NULL);
	ASSERT(ip->i_itemp->ili_lock_flags == 0);
	ASSERT(!XFS_NOT_DQATTACHED(mp, ip));

	trace_xfs_itruncate_extents_start(ip, new_size);

	flags |= xfs_bmapi_aflag(whichfork);

	/*
	 * Since it is possible for space to become allocated beyond
	 * the end of the file (in a crash where the space is allocated
	 * but the inode size is not yet updated), simply remove any
	 * blocks which show up between the new EOF and the maximum
	 * possible file size.
	 *
	 * We have to free all the blocks to the bmbt maximum offset, even if
	 * the page cache can't scale that far.
	 */
	first_unmap_block = XFS_B_TO_FSB(mp, (xfs_ufsize_t)new_size);
	if (!xfs_verify_fileoff(mp, first_unmap_block)) {
		WARN_ON_ONCE(first_unmap_block > XFS_MAX_FILEOFF);
		return 0;
	}

	/* sess47: record the inode being truncated/inactivated so the AG bnobt
	 * double-free site (xfs_alloc.c:2244) can FUA-probe whether this inode
	 * is still allocated on disk (stale-inode double-free vs lost-removal). */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern uint64_t mxfs_dbg_inactive_ino;
		extern uint32_t mxfs_dbg_inactive_gen;
		mxfs_dbg_inactive_ino = ip->i_ino;
		mxfs_dbg_inactive_gen = VFS_I(ip)->i_generation;
	}

	error = xfs_bunmapi_range(&tp, ip, flags, first_unmap_block,
			XFS_MAX_FILEOFF);
	if (error)
		goto out;

	if (whichfork == XFS_DATA_FORK) {
		/* Remove all pending CoW reservations. */
		error = xfs_reflink_cancel_cow_blocks(ip, &tp,
				first_unmap_block, XFS_MAX_FILEOFF, true);
		if (error)
			goto out;

		xfs_itruncate_clear_reflink_flags(ip);
	}

	/*
	 * Always re-log the inode so that our permanent transaction can keep
	 * on rolling it forward in the log.
	 */
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);

	trace_xfs_itruncate_extents_end(ip, new_size);

out:
	*tpp = tp;
	return error;
}

/*
 * Mark all the buffers attached to this directory stale.  In theory we should
 * never be freeing a directory with any blocks at all, but this covers the
 * case where we've recovered a directory swap with a "temporary" directory
 * created by online repair and now need to dump it.
 */
STATIC void
xfs_inactive_dir(
	struct xfs_inode	*dp)
{
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo = mp->m_dir_geo;
	struct xfs_ifork	*ifp = xfs_ifork_ptr(dp, XFS_DATA_FORK);
	xfs_fileoff_t		off;

	/*
	 * Invalidate each directory block.  All directory blocks are of
	 * fsbcount length and alignment, so we only need to walk those same
	 * offsets.  We hold the only reference to this inode, so we must wait
	 * for the buffer locks.
	 */
	for_each_xfs_iext(ifp, &icur, &got) {
		for (off = round_up(got.br_startoff, geo->fsbcount);
		     off < got.br_startoff + got.br_blockcount;
		     off += geo->fsbcount) {
			struct xfs_buf	*bp = NULL;
			xfs_fsblock_t	fsbno;
			int		error;

			fsbno = (off - got.br_startoff) + got.br_startblock;
			error = xfs_buf_incore(mp->m_ddev_targp,
					XFS_FSB_TO_DADDR(mp, fsbno),
					XFS_FSB_TO_BB(mp, geo->fsbcount),
					XBF_LIVESCAN, &bp);
			if (error)
				continue;

			xfs_buf_stale(bp);
			xfs_buf_relse(bp);
		}
	}
}

/*
 * xfs_inactive_truncate
 *
 * Called to perform a truncate when an inode becomes unlinked.
 */
STATIC int
xfs_inactive_truncate(
	struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error) {
		ASSERT(xfs_is_shutdown(mp));
		return error;
	}
	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, 0);

	/*
	 * Log the inode size first to prevent stale data exposure in the event
	 * of a system crash before the truncate completes. See the related
	 * comment in xfs_vn_setattr_size() for details.
	 */
	ip->i_disk_size = 0;
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);

	error = xfs_itruncate_extents(&tp, ip, XFS_DATA_FORK, 0);
	if (error)
		goto error_trans_cancel;

	ASSERT(ip->i_df.if_nextents == 0);

	error = xfs_trans_commit(tp);
	if (error)
		goto error_unlock;

	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return 0;

error_trans_cancel:
	xfs_trans_cancel(tp);
error_unlock:
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return error;
}

/*
 * sess47 — D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN preflight helpers.
 *
 * A defer-reaped zombie whose in-core shell was reclaimed between the
 * open-defer and the reap retry re-enters destructive inactivation as a
 * fresh iget: i_prev_unlinked==0 (chain state gone; only the bucket was
 * restored from the reap entry).  Upstream never sees this — its three
 * unlinked-iget surfaces (bulkstat, quotacheck, NFS fh) reload at iget,
 * and single-node lifetime rules keep every other unlinked inode in-core
 * through its ifree.  Without repair, xfs_iunlink_remove_inode's mid-list
 * branch does xfs_iunlink_lookup(prev==0) -> NULL -> silent -EFSCORRUPTED
 * AFTER xfs_difree dirtied the transaction -> ifree -117 -> forced
 * shutdown + withdrawal (probes P-UNLREM-INCOMPLETE / P-UNLREM-NOPREV;
 * deterministic repro tests/reap_midlist_repro.sh).
 *
 * The preflight (GPT-reviewed design, sess47) runs BEFORE xfs_ifree,
 * under the AG DLM with the transaction still clean: walk the recorded
 * slot bucket to find this agino's predecessor and PIN it — a reference
 * held across the ifree — so the remove cannot lose it to a concurrent
 * reclaim.  A plain reload-and-irele is NOT enough: a still-peer-open
 * neighbor's inodegc defers without ever blocking on our held AG DLM and
 * can be reclaimed again inside the window.  Pinning is nonblocking: an
 * in-core predecessor mid-evict (I_FREEING — inodegc owns it, and its
 * destructive arm may be blocked on the AG DLM we hold) must not be
 * waited on (lifecycle ABBA through xfs_iget's I_FREEING wait), so that
 * case fails the pass with -EAGAIN: the tx cancels clean, the zombie
 * stays durable on its bucket, and the reap entry retries at cadence.
 */
static int
mxfs_iunlink_pin_member(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*mip;
	int			error;

	*ipp = NULL;
	rcu_read_lock();
	mip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (mip && mip->i_ino &&
	    !xfs_iflags_test(mip, XFS_IRECLAIMABLE | XFS_IRECLAIM)) {
		/* VFS-visible: live zombie or mid-evict.  igrab decides
		 * atomically under i_lock; failure means I_FREEING and
		 * waiting for it (as xfs_iget would) can deadlock through
		 * our held AG DLM. */
		bool got = igrab(VFS_I(mip)) != NULL;

		rcu_read_unlock();
		if (!got)
			return -EAGAIN;
		*ipp = mip;
		return 0;
	}
	rcu_read_unlock();
	/* Absent, RCU-limbo, or reclaimable shell: xfs_iget loads fresh or
	 * recycles without an I_FREEING wait (evict already finished for a
	 * reclaimable shell), so no deadlock through the held AG DLM. */
	error = xfs_iget(mp, tp, xfs_agino_to_ino(pag, agino),
			 XFS_IGET_UNTRUSTED, 0, &mip);
	if (error)
		return error;
	*ipp = mip;
	return 0;
}

static int
mxfs_ifree_unlinked_preflight(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_inode	*ip,
	struct xfs_inode	**pinp)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_buf		*agibp = NULL;
	struct xfs_agi		*agi;
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	xfs_agino_t		prev_agino = NULLAGINO;
	xfs_agino_t		next_agino;
	long			hops = 0;
	short			bucket;
	int			error;

	*pinp = NULL;

	if (ip->i_unlinked_bucket >= 0) {
		bucket = ip->i_unlinked_bucket;
	} else {
		/* No recorded membership to walk — every reap-driven entry
		 * restores the bucket, so this is an unexpected surface.
		 * Fail closed: skip this pass, stay durable, retry later. */
		pr_warn("mxfs: P-UNLPRE-NOBUCKET ino=%llu agino=0x%x prev=0x%x nlink=%u\n",
			(unsigned long long)ip->i_ino, agino,
			ip->i_prev_unlinked, VFS_I(ip)->i_nlink);
		return -EAGAIN;
	}

	error = xfs_read_agi(pag, tp, 0, &agibp);
	if (error)
		return error;
	agi = agibp->b_addr;

	next_agino = be32_to_cpu(agi->agi_unlinked[bucket]);
	while (next_agino != NULLAGINO && next_agino != agino) {
		struct xfs_inode	*mip;
		xfs_agino_t		hop = next_agino;
		bool			incore = false;

		if (++hops > 100000) {
			pr_warn("mxfs: P-UNLPRE-LOOP ino=%llu bucket=%d hops=%ld — cycle in unlinked chain\n",
				(unsigned long long)ip->i_ino, (int)bucket,
				hops);
			error = -EFSCORRUPTED;
			goto out;
		}

		/* Raw probe, NOT xfs_iunlink_lookup: a RECLAIMABLE shell is
		 * a legitimate hop here (its unlinked fields froze at evict
		 * and the chain cannot change under the held AGI + AG DLM),
		 * which the helper's contract disallows. */
		rcu_read_lock();
		mip = radix_tree_lookup(&pag->pag_ici_root, hop);
		if (mip && mip->i_ino) {
			next_agino = mip->i_next_unlinked;
			incore = true;
		}
		rcu_read_unlock();
		if (incore) {
			prev_agino = hop;
			continue;
		}
		/* Reclaimed member: instantiate it to read its next pointer
		 * (a fresh load carries di_next_unlinked).  If it turns out
		 * to be the predecessor, keep the reference. */
		error = mxfs_iunlink_pin_member(mp, tp, pag, hop, &mip);
		if (error)
			goto out;
		mip->i_prev_unlinked = prev_agino;
		mip->i_unlinked_bucket = bucket;
		next_agino = mip->i_next_unlinked;
		prev_agino = hop;
		if (next_agino == agino)
			*pinp = mip;
		else
			xfs_irele(mip);
	}

	if (next_agino != agino) {
		/* Walked the recorded bucket to its end without finding our
		 * entry.  Under the held AG DLM + slot-partitioned buckets
		 * only a completed free can have consumed it (the mid-list
		 * sibling of the bucket-empty revalidation verdict) — but
		 * this variant has never been observed, so stay loud and
		 * fail closed rather than freeing. */
		pr_warn("mxfs: P-UNLPRE-NOTFOUND ino=%llu agino=0x%x bucket=%d head=0x%x hops=%ld\n",
			(unsigned long long)ip->i_ino, agino, (int)bucket,
			be32_to_cpu(agi->agi_unlinked[bucket]), hops);
		error = -EFSCORRUPTED;
		goto out;
	}

	if (prev_agino != NULLAGINO && !*pinp) {
		error = mxfs_iunlink_pin_member(mp, tp, pag, prev_agino, pinp);
		if (error)
			goto out;
	}
	if (*pinp && (*pinp)->i_next_unlinked != agino) {
		/* The pinned predecessor's own next does not point at us —
		 * stale beyond in-place repair.  Fail closed. */
		pr_warn("mxfs: P-UNLPRE-PREVMISMATCH ino=%llu agino=0x%x prev=0x%x prev_next=0x%x bucket=%d\n",
			(unsigned long long)ip->i_ino, agino, prev_agino,
			(*pinp)->i_next_unlinked, (int)bucket);
		xfs_irele(*pinp);
		*pinp = NULL;
		error = -EFSCORRUPTED;
		goto out;
	}

	ip->i_prev_unlinked = prev_agino;
	pr_warn_ratelimited("mxfs: P-UNLPRE-RECOVERED ino=%llu agino=0x%x bucket=%d prev=0x%x pinned=%d hops=%ld\n",
		(unsigned long long)ip->i_ino, agino, (int)bucket,
		prev_agino, *pinp ? 1 : 0, hops);
	error = 0;
out:
	xfs_trans_brelse(tp, agibp);
	return error;
}

/*
 * xfs_inactive_ifree()
 *
 * Perform the inode free when an inode is unlinked.
 */
STATIC int
xfs_inactive_ifree(
	struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	struct xfs_perag	*pag = NULL;
	struct xfs_inode	*mxfs_pflt_pin = NULL;
	int			error;
	int			lock_error;

	/*
	 * We try to use a per-AG reservation for any block needed by the finobt
	 * tree, but as the finobt feature predates the per-AG reservation
	 * support a degraded file system might not have enough space for the
	 * reservation at mount time.  In that case try to dip into the reserved
	 * pool and pray.
	 *
	 * Send a warning if the reservation does happen to fail, as the inode
	 * now remains allocated and sits on the unlinked list until the fs is
	 * repaired.
	 */
	if (unlikely(mp->m_finobt_nores)) {
		error = xfs_trans_alloc(mp, &M_RES(mp)->tr_ifree,
				XFS_IFREE_SPACE_RES(mp), 0, XFS_TRANS_RESERVE,
				&tp);
	} else {
		error = xfs_trans_alloc(mp, &M_RES(mp)->tr_ifree, 0, 0, 0, &tp);
	}
	if (error) {
		if (error == -ENOSPC) {
			xfs_warn_ratelimited(mp,
			"Failed to remove inode(s) from unlinked list. "
			"Please free space, unmount and run xfs_repair.");
		} else {
			ASSERT(xfs_is_shutdown(mp));
		}
		return error;
	}

	/*
	 * MXFS: acquire per-AG DLM lock around the entire inode-free
	 * transaction (alloc → log → commit → flush → release).  Without
	 * this, a peer freshly allocating from this AG can read stale
	 * inobt/finobt and trip xfs_ialloc.c:2333.  And without the
	 * post-commit synchronous flush below, the peer can read a stale
	 * dinode (mode != 0) and trip xfs_dialloc_ag's "Free inode not
	 * marked free!" check.
	 */
	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
	if (pag) {
		lock_error = mxfs_ag_dlm_lock(mp, pag);
		if (lock_error) {
			xfs_perag_put(pag);
			pag = NULL;
			xfs_trans_cancel(tp);
			return lock_error;
		}
	}

	/*
	 * We do not hold the inode locked across the entire rolling transaction
	 * here. We only need to hold it for the first transaction that
	 * xfs_ifree() builds, which may mark the inode XFS_ISTALE if the
	 * underlying cluster buffer is freed. Relogging an XFS_ISTALE inode
	 * here breaks the relationship between cluster buffer invalidation and
	 * stale inode invalidation on cluster buffer item journal commit
	 * completion, and can result in leaving dirty stale inodes hanging
	 * around in memory.
	 *
	 * We have no need for serialising this inode operation against other
	 * operations - we freed the inode and hence reallocation is required
	 * and that will serialise on reallocating the space the deferops need
	 * to free. Hence we can unlock the inode on the first commit of
	 * the transaction rather than roll it right through the deferops. This
	 * avoids relogging the XFS_ISTALE inode.
	 *
	 * We check that xfs_ifree() hasn't grown an internal transaction roll
	 * by asserting that the inode is still locked when it returns.
	 */
	xfs_ilock(ip, XFS_ILOCK_EXCL);

	/*
	 * mxfs (ccloop-4dd7 sess2, ino 10485889 autopsy): the EX re-acquire
	 * inside the xfs_ilock above can find this inode PEER-FREED.  The
	 * inactivation entry guard read a LIVE dinode, but a BAST forced our
	 * EX out during the truncate phase and the peer's rm of the same
	 * (stale-resolved) name completed the whole free — dinode mode 0,
	 * inobt bit set, AGI bucket entry removed.  The reload on this fresh
	 * acquire adopts the freed image (P116-ZOMBIE-ADOPT → in-core mode
	 * 0).  Proceeding re-frees the inobt bit (P-DIFREE-DBL freecount
	 * skew) and walks an empty AGI bucket (P71 agi-unlinked-garbage →
	 * -EFSCORRUPTED shutdown).  Everything our ifree would do is already
	 * durably done by the peer: cancel the still-clean transaction and
	 * forget our in-core unlinked membership (the disk list no longer
	 * contains us — same "not on list" epilogue as
	 * xfs_iunlink_remove_inode).
	 */
	{
		bool ifr_skip = (VFS_I(ip)->i_mode & S_IFMT) == 0;
		const char *ifr_why = "adopted-free-image";

		/*
		 * Second arm (ino 8388737 autopsy, round-2 v0.11.50): a peer's
		 * CONCURRENT free of the same double-removed ino can be fully
		 * committed but not yet destaged to the dinode cluster (the
		 * bounded ifree drain defers it), so the reload still shows a
		 * LIVE mode — but the AGI bucket remove IS visible here: we
		 * hold the AG DLM (acquired above), and AG-meta destages
		 * before any AG handoff (Invariant 1).  If we believe we are
		 * on the unlinked list while the coherent on-disk bucket is
		 * EMPTY, the peer's ifree consumed the entry — proceeding
		 * difrees an already-freed bit and then trips the P71
		 * empty-bucket -EFSCORRUPTED with the transaction dirty.
		 * (A non-empty bucket missing our agino mid-list is not
		 * covered — not yet observed; the churn's buckets are
		 * depth-1.)
		 *
		 * ccloop-4dd7 sess4 (b59r1 ino 136 autopsy): gate widened —
		 * xfs_inode_on_unlinked_list() DROPPED from the condition.
		 * An ADOPTED mirror never went through local xfs_iunlink, so
		 * its in-core membership is unset (prev=0, next=NULLAGINO
		 * adopted straight from the dinode) and the old gate skipped
		 * this check — the ifree then walked the empty bucket inside
		 * xfs_iunlink_remove (P71 agi-unlinked-garbage, 11ms after
		 * this node's own rm freed the same agino) → -117 → META_IO
		 * shutdown.  In multinode, an EMPTY bucket at ifree time for
		 * an nlink=0 inode always means the unlink entry was already
		 * consumed by the completed free (ours or a peer's): every
		 * legitimately-unlinked inode is reachable in its bucket
		 * until exactly one ifree removes it.  Skipping is therefore
		 * always the right disposition; the tx is still clean here.
		 */
		if (!ifr_skip && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    pag) {
			struct xfs_buf	*ck_agibp = NULL;

			if (!xfs_read_agi(pag, tp, 0, &ck_agibp)) {
				struct xfs_agi	*ck_agi = ck_agibp->b_addr;
				xfs_agino_t	ck_agino =
					XFS_INO_TO_AGINO(mp, ip->i_ino);
				int		ck_differs =
					mxfs_ag_buf_disk_differs(ck_agibp);
				/*
				 * sess47 TAIL3: differs alone does not say
				 * WHICH side is stale.  If WE own a pending
				 * delta on this AGI (dirty bli / pinned /
				 * delwri / uncheckpointed), the in-core image
				 * is AHEAD and is the truth — deciding on
				 * disk would un-see our own just-inserted
				 * entry and mis-skip a legitimate free.  Only
				 * a CLEAN-but-divergent AGI means the in-core
				 * image is a prior-tenure fossil (the test32
				 * shutdown shape) and disk is the truth.
				 */
				if (ck_differs &&
				    ((ck_agibp->b_flags & _XBF_DELWRI_Q) ||
				     xfs_buf_ispinned(ck_agibp) ||
				     (ck_agibp->b_log_item &&
				      test_bit(XFS_LI_DIRTY,
					&ck_agibp->b_log_item->bli_item.li_flags)) ||
				     mxfs_buf_has_uncheckpointed_mods(ck_agibp)))
					ck_differs = 0;

				/*
				 * sess47 (test32 ring, t=20454): this check
				 * decided on a STALE prior-tenure in-core AGI
				 * (bucket looked non-empty), then the remove's
				 * coherent read saw it EMPTY -> P71 -117
				 * shutdown (agi_disk_differs=1 at failure).
				 * When the in-core image diverges from disk,
				 * the DISK side is the cluster-coherent truth
				 * under the AG EX we hold — decide on it.
				 */
				if (ck_differs) {
					static atomic_t pifr_n = ATOMIC_INIT(0);

					if (atomic_inc_return(&pifr_n) <= 100)
					pr_warn("mxfs: P-IFR-AGI-STALE ino=%llu agno=%u bucket=%d incore_head=0x%x disk_head=0x%x agi_gen=%llu — clean-but-divergent AGI; revalidating on the disk-side image\n",
						(unsigned long long)ip->i_ino,
						pag_agno(pag),
						(int)(ip->i_unlinked_bucket >= 0 ?
						  ip->i_unlinked_bucket :
						  (int16_t)(ck_agino %
						    XFS_AGI_UNLINKED_BUCKETS)),
						be32_to_cpu(ck_agi->agi_unlinked[
						  ip->i_unlinked_bucket >= 0 ?
						  ip->i_unlinked_bucket :
						  (short)(ck_agino %
						    XFS_AGI_UNLINKED_BUCKETS)]),
						mxfs_agi_disk_bucket_head(ck_agibp,
						  ip->i_unlinked_bucket >= 0 ?
						  ip->i_unlinked_bucket :
						  (int)(ck_agino %
						    XFS_AGI_UNLINKED_BUCKETS)),
						(unsigned long long)ck_agibp->b_mxfs_ag_gen);
				}
				/* mxfs sess40: check the bucket OUR entry
				 * actually lives in (slot-partitioned). */
				short		ck_bucket =
					ip->i_unlinked_bucket >= 0 ?
					(short)ip->i_unlinked_bucket :
					(short)(ck_agino %
						XFS_AGI_UNLINKED_BUCKETS);

				if ((ck_differs ?
				     mxfs_agi_disk_bucket_head(ck_agibp,
							       ck_bucket) :
				     be32_to_cpu(
					ck_agi->agi_unlinked[ck_bucket])) ==
				    NULLAGINO) {
					int	fb, found = -1;

					/*
					 * 0.11.360 instrumentation (D-OUTAGE-
					 * REMOUNT-MUTUAL-IFREE-SKIP-STRAND):
					 * the agino%64 fallback above is an
					 * upstream-ism — MXFS parks entries on
					 * the UNLINKER'S SLOT bucket, so an
					 * adopted mirror (i_unlinked_bucket
					 * unset) can compute the wrong bucket,
					 * read it empty, and skip forever on
					 * every node.  Scan all 64 heads for
					 * our agino to prove/refute before
					 * trusting the empty read.
					 */
					for (fb = 0;
					     fb < XFS_AGI_UNLINKED_BUCKETS;
					     fb++) {
						xfs_agino_t fb_head = ck_differs ?
						    mxfs_agi_disk_bucket_head(
							ck_agibp, fb) :
						    be32_to_cpu(
						    ck_agi->agi_unlinked[fb]);

						if (fb_head == ck_agino) {
							found = fb;
							break;
						}
					}
					if (found >= 0) {
						pr_warn("mxfs: P-IFR-BUCKET-MISMATCH ino=%llu computed=%d actual_head_at=%d ub=%d — entry IS listed; proceeding with free on the real bucket\n",
							(unsigned long long)ip->i_ino,
							ck_bucket, found,
							(int)ip->i_unlinked_bucket);
						ip->i_unlinked_bucket =
							(int16_t)found;
					} else {
						ifr_skip = true;
						ifr_why = "bucket-empty-peer-freeing";
					}
				}
				xfs_trans_brelse(tp, ck_agibp);
			}
		}
		if (ifr_skip) {
			pr_warn_ratelimited(
			    "mxfs: IFREE-REVALIDATE-SKIP ino=%llu gen=%u mode=0%o prev_unlinked=0x%x next_unlinked=0x%x why=%s — peer freed during inactivation; clean skip, no double-free\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation, VFS_I(ip)->i_mode,
				ip->i_prev_unlinked, ip->i_next_unlinked,
				ifr_why);
			ip->i_next_unlinked = NULLAGINO;
			ip->i_prev_unlinked = 0;
			ip->i_unlinked_bucket = -1;
			xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK | MXFS_IF_ADOPTED_UNLINK);
			xfs_trans_cancel(tp);
			xfs_iunlock(ip, XFS_ILOCK_EXCL);
			error = 0;
			goto out_unlock_ag;
		}
	}
	/*
	 * sess47 preflight (see mxfs_ifree_unlinked_preflight above): a
	 * reclaimed-and-reaped zombie re-enters here with no in-core chain
	 * state.  Rebuild it and pin the predecessor BEFORE xfs_ifree can
	 * dirty the transaction — the mid-list unlinked remove must not be
	 * able to fail on a vanished neighbor after difree.  Any preflight
	 * failure is a clean skip: tx still clean, zombie stays durable on
	 * its bucket, the reap entry retries at cadence.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    pag && xfs_inode_unlinked_incomplete(ip)) {
		error = mxfs_ifree_unlinked_preflight(tp, pag, ip,
						      &mxfs_pflt_pin);
		if (error) {
			pr_warn("mxfs: P-UNLPRE-SKIP ino=%llu rc=%d — deferring free; zombie durable, reap retries\n",
				(unsigned long long)ip->i_ino, error);
			xfs_trans_cancel(tp);
			xfs_iunlock(ip, XFS_ILOCK_EXCL);
			error = 0;
			goto out_unlock_ag;
		}
	}

	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	error = xfs_ifree(tp, ip);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	if (error == -ESTALE) {
		/*
		 * Adopted-peer-free (ccloop-4dd7 sess3, round-5 ino 134):
		 * xfs_difree found the inobt bit for this inode already set
		 * under the held AG DLM — a peer (or an earlier pass)
		 * completed the whole free and this is a second inactivation
		 * of a mirror that adopted nlink=0 from disk.  difree aborts
		 * before its first modification, so the transaction is still
		 * clean; cancel releases the ijoin'd ILOCK.  Forget our
		 * in-core unlinked membership (the disk list no longer
		 * contains us) and succeed so the shell just reclaims.
		 */
		pr_warn_ratelimited(
		    "mxfs: IFREE-REVALIDATE-SKIP ino=%llu gen=%u mode=0%o prev_unlinked=0x%x next_unlinked=0x%x why=inobt-already-free — peer freed during inactivation; clean skip, no double-free\n",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_generation, VFS_I(ip)->i_mode,
			ip->i_prev_unlinked, ip->i_next_unlinked);
		ip->i_next_unlinked = NULLAGINO;
		ip->i_prev_unlinked = 0;
		ip->i_unlinked_bucket = -1;
		xfs_iflags_clear(ip, MXFS_IF_LOCAL_UNLINK | MXFS_IF_ADOPTED_UNLINK);
		xfs_trans_cancel(tp);
		error = 0;
		goto out_unlock_ag;
	}
	if (error) {
		/*
		 * If we fail to free the inode, shut down.  The cancel
		 * might do that, we need to make sure.  Otherwise the
		 * inode might be lost for a long time or forever.
		 */
		if (!xfs_is_shutdown(mp)) {
			xfs_notice(mp, "%s: xfs_ifree returned error %d",
				__func__, error);
			xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		}
		xfs_trans_cancel(tp);
		goto out_unlock_ag;
	}

	/*
	 * Credit the quota account(s). The inode is gone.
	 */
	xfs_trans_mod_dquot_byino(tp, ip, XFS_TRANS_DQ_ICOUNT, -1);

	error = xfs_trans_commit(tp);
	/* The ifree is committed: this incarnation is genuinely dead by OUR
	 * hand.  The free-aware DLM release sites key on this flag, not on
	 * nlink==0 (which is also true for a cached copy of a peer's live
	 * open-unlinked inode). */
	if (!error) {
		xfs_iflags_set(ip, MXFS_IF_FREE_COMMITTED);
		/* sess40: retire any deferred-reap entry for this ino. */
		if (mp->m_mxfs_dlm)
			mxfs_defer_reap_done(mp, ip->i_ino);
	}

	/*
	 * MXFS: before releasing the AG DLM lock, ensure both the AG-meta
	 * btrees AND the dinode cluster buffer (which now carries mode=0
	 * for the freed inode) are durable on disk.  v0.2.5's deferred-
	 * release covers AG-meta via b_iodone but not the inode buffer.
	 * Without this, a peer that acquires the AG and allocates the just-
	 * freed inode reads the stale dinode and trips the "Free inode
	 * 0x%x not marked free! (mode 0x%x)" corruption check.
	 *
	 * xfs_log_force(SYNC) drains CIL → on-disk log; the targeted drain
	 * waits for THIS inode's log item to leave the AIL (its cluster
	 * buffer written home); blkdev_issue_flush forces the block layer.
	 *
	 * sess129 (RULE 4 PROVEN): this MUST be a targeted per-inode drain,
	 * NOT xfs_ail_push_all_sync.  The whole-AIL wait deadlocked
	 * test_many_files single-node: a creator (xfs_create) holds the
	 * parent dir's ILOCK_EXCL across xfs_icreate→xfs_iget, and iget
	 * retry-loops on -EAGAIN when the dialloc'd inode number's prior
	 * incarnation is still NEED_INACTIVE — waiting on these inodegc
	 * workers.  The workers in turn waited here for the WHOLE AIL,
	 * which contains the parent dir's dirty inode item, whose flush
	 * needs the parent's ILOCK_SHARED (P129-CLSKIP ILOCK_NOWAIT_FAIL
	 * owner=the creator).  ABBA: creator→inodegc→parent-ILOCK→creator.
	 * Only THIS inode's dinode (mode=0) and the AG meta need to be
	 * durable before the AG DLM release — and this inode's ILOCK is
	 * free here (released at xfs_trans_commit), so the targeted drain
	 * always makes progress.  AG-meta durability for a peer handoff is
	 * enforced by the Phase-2 BAST drain pipeline (invariant #1).
	 */
	/*
	 * ccloop c7ee71c6 sess2 (RULE 4, P137/P133/ftrace-attributed): this
	 * eager per-ifree durability chain (log_force(SYNC) + pin-settle +
	 * targeted AIL drain + blkdev flush) dates to v0.2.5, when the
	 * deferred AG release covered AG-meta via b_iodone but NOT the inode
	 * cluster buffer.  Since the Phase-2 BAST drain pipeline gained
	 * drain_inode_buffers (invariant #1: meta + alloc-buflist + INODE
	 * buffers + blkdev_flush before every mxfs_v5_dlm_ag_unlock), every
	 * cross-node path that could observe the freed dinode routes through
	 * a draining handoff: peer allocation of the freed ino needs the AG
	 * (Phase-2 drains this cluster buffer then), and peer iget-by-number
	 * needs the ino's inode-DLM (whose release path drains that inode).
	 * The eager chain is therefore redundant cross-node work charged to
	 * EVERY unlink syscall (sync-inactivation): measured 17-33ms/unlink
	 * on the tcp/LIO rig (force 9-16ms + drain 7-27ms + flush 2-7ms
	 * serializing on the shared target), collapsing dlm_scaling to
	 * ~10 ops/s/node at 8-16 nodes (needs 33+).  The AGI-bucket recycle
	 * race that motivated SYNC inactivation is unaffected — it needs the
	 * difree TRANSACTION committed before unlink returns (still true),
	 * not the dinode durable on the platter.  mxfs.ifree_eager_durable=1
	 * restores the old behavior for A/B.
	 */
	if (pag && !error && mxfs_ifree_eager_durable) {
		u64 p137_s = ktime_get_ns();
		u64 p137_force_ns, p137_drain_ns, p137_flush_ns;

		xfs_log_force(mp, XFS_LOG_SYNC);
		/*
		 * v0.5.6: settle the async CIL→AIL insertion (drain contract)
		 * by its REAL condition instead of a blind msleep(10).  The
		 * inode item's pin is dropped by iop_unpin AFTER
		 * xfs_trans_committed_bulk has inserted the item into the AIL,
		 * so pincount==0 ⇒ the CIL→AIL handoff is complete and the
		 * drain below cannot see a premature !in_ail (the sess29 Mode
		 * A race the msleep guarded against).  P137 timing proved the
		 * msleep(10) + second log force cost ~12ms of the ~25ms
		 * per-unlink inactivation (native XFS: <1ms total) — the
		 * cleanup `rm` storms that blow the 600s phase budget are
		 * thousands of these.  Bounded: a wedged log falls back to
		 * one more sync force after ~2s and proceeds to the drain,
		 * which has its own rescue + wedge logging.
		 */
		{
			int p137_settle = 0;

			while (xfs_ipincount(ip) > 0 && p137_settle++ < 4000)
				usleep_range(250, 500);
			if (xfs_ipincount(ip) > 0)
				xfs_log_force(mp, XFS_LOG_SYNC);
		}
		p137_force_ns = ktime_get_ns() - p137_s;
		p137_s = ktime_get_ns();
		/*
		 * sess-tcp BOUNDED: do NOT hold the AG as an active DLM holder
		 * for a wedge duration here.  A freed inode's cluster buffer can
		 * stay orphaned in the AIL for ~60s while xfsaild is starved by a
		 * concurrent same-dir create storm; the old unbounded drain then
		 * deferred a peer's AG BAST for the whole wedge, timing out the
		 * peer's xfs_dialloc (-110) and stalling concurrent create.  Bound
		 * the synchronous wait to mxfs_ifree_drain_ms (healthy case
		 * ~1-3ms); cross-node dinode (mode=0) durability on an actual peer
		 * AG handoff is guaranteed by the Phase-2 BAST drain pipeline
		 * (invariant #1).  PROVEN: P137-IFREE-TIME drain_us=62569.
		 */
		{
			extern bool mxfs_ail_drain_inode_sync_bounded(
				struct xfs_inode *, unsigned int);
			extern int mxfs_ifree_drain_ms;

			if (!mxfs_ail_drain_inode_sync_bounded(ip,
					(unsigned int)mxfs_ifree_drain_ms))
				pr_warn_ratelimited(
				    "mxfs: P-IFREE-DRAIN-BOUND ino=%llu not durable in %dms — deferring to BAST drain pipeline\n",
					(unsigned long long)ip->i_ino,
					mxfs_ifree_drain_ms);
		}
		p137_drain_ns = ktime_get_ns() - p137_s;
		p137_s = ktime_get_ns();
		xfs_buftarg_wait(mp->m_ddev_targp);
		blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
		p137_flush_ns = ktime_get_ns() - p137_s;
		if (p137_force_ns + p137_drain_ns + p137_flush_ns >
		    10 * NSEC_PER_MSEC)
			pr_warn_ratelimited(
			    "mxfs: P137-IFREE-TIME ino=%llu force_us=%llu drain_us=%llu flush_us=%llu\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)(p137_force_ns / 1000),
				(unsigned long long)(p137_drain_ns / 1000),
				(unsigned long long)(p137_flush_ns / 1000));
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P9-INSTR ifree DONE ino=%llu agno=%u flushed",
			(unsigned long long)ip->i_ino, pag_agno(pag));
	}
	/* ccloop c7ee71c6 sess2: with the eager chain off, hand the freed
	 * cluster's destage to the coalesced background kick (~2ms batch)
	 * so a reused ino's disk dinode converges promptly for peer iget. */
	if (pag && !error && !mxfs_ifree_eager_durable)
		mxfs_destage_kick(mp);

out_unlock_ag:
	if (pag) {
		mxfs_ag_dlm_unlock(mp, pag);
		xfs_perag_put(pag);
	}
	/* sess47: release the preflight's predecessor pin only after the AG
	 * DLM is dropped — its irele may re-drive that inode's inodegc,
	 * whose destructive arm wants this AG. */
	if (mxfs_pflt_pin)
		xfs_irele(mxfs_pflt_pin);
	return error;
}

/*
 * Returns true if we need to update the on-disk metadata before we can free
 * the memory used by this inode.  Updates include freeing post-eof
 * preallocations; freeing COW staging extents; and marking the inode free in
 * the inobt if it is on the unlinked list.
 */
bool
xfs_inode_needs_inactive(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_ifork	*cow_ifp = xfs_ifork_ptr(ip, XFS_COW_FORK);

	/*
	 * If the inode is already free, then there can be nothing
	 * to clean up here.
	 */
	if (VFS_I(ip)->i_mode == 0)
		return false;

	/*
	 * If this is a read-only mount, don't do this (would generate I/O)
	 * unless we're in log recovery and cleaning the iunlinked list.
	 */
	if (xfs_is_readonly(mp) && !xlog_recovery_needed(mp->m_log))
		return false;

	/* If the log isn't running, push inodes straight to reclaim. */
	if (xfs_is_shutdown(mp) || xfs_has_norecovery(mp))
		return false;

	/* Metadata inodes require explicit resource cleanup. */
	if (xfs_is_internal_inode(ip))
		return false;

	/* Want to clean out the cow blocks if there are any. */
	if (cow_ifp && cow_ifp->if_bytes > 0)
		return true;

	/* Unlinked files must be freed. */
	if (VFS_I(ip)->i_nlink == 0)
		return true;

	/*
	 * This file isn't being freed, so check if there are post-eof blocks
	 * to free.
	 *
	 * Note: don't bother with iolock here since lockdep complains about
	 * acquiring it in reclaim context. We have the only reference to the
	 * inode at this point anyways.
	 */
	return xfs_can_free_eofblocks(ip);
}

/*
 * Save health status somewhere, if we're dumping an inode with uncorrected
 * errors and online repair isn't running.
 */
static inline void
xfs_inactive_health(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_perag	*pag;
	unsigned int		sick;
	unsigned int		checked;

	xfs_inode_measure_sickness(ip, &sick, &checked);
	if (!sick)
		return;

	trace_xfs_inode_unfixed_corruption(ip, sick);

	if (sick & XFS_SICK_INO_FORGET)
		return;

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));
	if (!pag) {
		/* There had better still be a perag structure! */
		ASSERT(0);
		return;
	}

	xfs_ag_mark_sick(pag, XFS_SICK_AG_INODES);
	xfs_perag_put(pag);
}

/*
 * xfs_inactive
 *
 * This is called when the vnode reference count for the vnode
 * goes to zero.  If the file has been unlinked, then it must
 * now be truncated.  Also, we clear all of the read-ahead state
 * kept for the inode here since the file is now closed.
 */
int
xfs_inactive(
	xfs_inode_t	*ip)
{
	struct xfs_mount	*mp;
	int			error = 0;
	int			truncate = 0;
	bool			mxfs_inact_dlm_locked = false;
	bool			mxfs_inact_via_iclus = false;
	/*
	 * v0.5.6 P137 stage timer (always-on, ratelimited, reported only
	 * when the whole inactivation exceeds 15ms): the cluster-phase
	 * cleanup `rm` was measured at ~53ms per cross-node unlink on a
	 * QUIET cluster (native XFS: <1ms) — these stamps attribute the
	 * cost to dlm-acquire / FUA reads / truncate / ifree so the fix
	 * lands on the proven term, not a guessed one.
	 */
	u64			p137_t0 = ktime_get_ns();
	u64			p137_dlm_ns = 0;
	u64			p137_fua_ns = 0;
	u64			p137_trunc_ns = 0;
	u64			p137_ifree_ns = 0;

	/*
	 * If the inode is already free, then there can be nothing
	 * to clean up here.
	 */
	if (VFS_I(ip)->i_mode == 0) {
		ASSERT(ip->i_df.if_broot_bytes == 0);
		goto out;
	}

	mp = ip->i_mount;
	ASSERT(!xfs_iflags_test(ip, XFS_IRECOVERY));

	/*
	 * sess47 CLUSTERED DOUBLE-FREE GUARD (PROVEN root of the AG bnobt
	 * "ltbno+ltlen>bno" corruption).  A node can instantiate a PEER's inode
	 * grant-less (readdir / lookup / stat of a shared directory) and later
	 * observe nlink==0 after the owner unlinks it; the stale in-core inode
	 * still carries the peer's data-fork extent map.  When this node drops
	 * its last reference, xfs_inactive would truncate that stale extent map
	 * and free the peer's ALREADY-FREED blocks a second time -> AG free-space
	 * btree double-free -> EFSCORRUPTED shutdown (sess47 P47-INACT proved
	 * disk_di_mode==0 at the failure: the inode is already free on disk).
	 *
	 * Only the owning node (which still has the inode allocated on disk)
	 * must run destructive inactivation.  If the inode is already FREE on
	 * disk, the owner has freed it; there is nothing for us to clean up, so
	 * reclaim the in-core inode WITHOUT touching the shared on-disk metadata.
	 * Gated multi-node + nlink==0; one FUA dinode read per inactivated
	 * unlinked inode (inactivation is not a hot path).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    VFS_I(ip)->i_nlink == 0) {
		extern uint16_t mxfs_dbg_disk_di_mode(struct xfs_mount *,
						      uint64_t, uint32_t *);
		extern uint32_t mxfs_dbg_disk_di_nlink_coherent(struct xfs_mount *,
						      uint64_t);
		extern int mxfs_v5_dlm_inode_lock(struct mxfs_v5_dlm *,
						  uint64_t, uint8_t,
						  struct mxfs_grant_result *);
		uint32_t mxfs_dgen = 0;
		uint16_t mxfs_dmode;
		uint32_t mxfs_igen = VFS_I(ip)->i_generation;
		uint32_t mxfs_coh_nlink;

		/*
		 * sess78 TOCTOU CLOSURE (Gemini RULE-5 design; see
		 * notes/sess78_inactive_toctou_fix.md).  The disk-state check
		 * below is a point-in-time read.  Under concurrent multi-node
		 * rsync TWO nodes can both hold this inode in-core with
		 * nlink==0 and both race into destructive inactivation: the
		 * loser's read saw the inode still LIVE (di_mode!=0, gen
		 * matched) at check time, the winner freed+reused it during the
		 * window, and the loser double-freed its blocks -> bnobt
		 * ltbno+ltlen>bno shutdown (proven P47-INACT verdict DISK-FREE,
		 * disk_di_gen==incore_gen+1; sess77 pinned-drain fix never
		 * fires here, P73-FIX=0).
		 *
		 * Acquire the per-inode DLM EX grant (cluster-wide mutual
		 * exclusion on this inode number) BEFORE the disk read and hold
		 * it across truncate+ifree.  This serializes the racing nodes:
		 * the winner frees under EX; transferring EX to the loser
		 * forces the winner's flush, so the loser's disk read THEN sees
		 * di_mode==0 and skips.  Exactly one node performs the free.
		 *
		 * Use the LOW-LEVEL lock (NOT mxfs_dlm_ilock_begin): we must
		 * not reload/mutate the VFS struct inode mid-eviction
		 * (I_FREEING) — a peer may have reused the ino as a different
		 * type, and reloading would corrupt teardown / trip VFS
		 * asserts.  We only need cluster mutex + a raw FUA disk read.
		 * No XFS ILOCK is held here (inodegc worker context), so
		 * DLM-then-ILOCK is the correct order and cannot deadlock vs
		 * the documented ILOCK-across-CAW-poll holders.  Released at
		 * the single out: label below.
		 */
		{
			u64 p137_s = ktime_get_ns();
			int mxfs_lkrc;
			extern bool mxfs_dlm_iclus_covered(struct xfs_inode *);
			extern int mxfs_iclus_lock(struct xfs_mount *,
						   uint64_t, uint8_t,
						   struct mxfs_grant_result *);

			/*
			 * ICLUSTER (ccloop 72513a13 sess4): for cluster-routed
			 * files the cluster EX IS the cluster-wide mutual
			 * exclusion on this ino — and the raw per-inode claim
			 * DEADLOCKS against it (proven 8/cawd: A guard-holds
			 * per-inode X wanting cluster C for ifree; B retains C
			 * and cannot release because B's own in-core X awaits
			 * this same guard — 270s+ P-WAIT-EXTEND wedge).  One
			 * resource, one order.  VFS i_mode is still valid on
			 * an I_FREEING inode, so the routed predicate is
			 * stable here.
			 */
			mxfs_inact_via_iclus = mxfs_dlm_iclus_covered(ip);
			mxfs_lkrc = mxfs_inact_via_iclus ?
				mxfs_iclus_lock(mp, ip->i_ino, MXFS_LOCK_EX,
						NULL) :
				mxfs_v5_dlm_inode_lock(mp->m_mxfs_dlm,
						       ip->i_ino,
						       MXFS_LOCK_EX, NULL);
			if (mxfs_lkrc == -EDEADLK) {
				/*
				 * sess2 (ccloop a9a03929) IUNLINK-LEAK FIX — PROVEN by
				 * run48: INACT-SKIP-STALE ino=12583085 local_unlink=1
				 * dlm_mode=3.  A peer's transient PR pull in the
				 * unlink→iput window demoted our EX; this one-shot
				 * re-acquire then hit the sess12 blocked-upgrade
				 * contract (-EDEADLK = keep lower grant; CALLER must
				 * drop it and re-acquire fresh), and B5 skipped the
				 * RIGHTFUL freer's ifree — leaking the inode on its
				 * AGI unlinked bucket.  The next same-bucket iunlink
				 * insert walked to the leaked head, reload-iget read
				 * nlink!=0 (the ifree never ran) → -EFSCORRUPTED →
				 * dirty trans cancel → shutdown (run48 t1 @179.9s,
				 * agno=6 bucket=45).
				 *
				 * Honor the contract the way the P109 ilock path does,
				 * via the P60 inline-demote precedent (proven safe on
				 * an I_FREEING inode: no igrab, i_dlm_demoter tag makes
				 * bast_process re-entrant-safe): drop our lower grant
				 * through bast_process (gen-aware, table-synced), then
				 * re-acquire EX from clean NL — which cannot return
				 * -EDEADLK.  Tag self-demote only when no peer BAST is
				 * pending so a genuine handoff keeps its durability
				 * drain (we hold PR here, so the self-demote drop is
				 * clean/read-only anyway).
				 */
				int mxfs_upg_try;

				for (mxfs_upg_try = 0; mxfs_upg_try < 3;
				     mxfs_upg_try++) {
					spin_lock(&ip->i_dlm_lock);
					if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE)
						ip->i_dlm_self_demote = true;
					ip->i_dlm_state = MXFS_DLM_ISTATE_BAST;
					spin_unlock(&ip->i_dlm_lock);
					wake_up_all(&ip->i_dlm_wait);
					/* sess25: owned/nestable claim — a raw
					 * store here can overwrite a live
					 * foreign claim and the raw clear then
					 * strands its owner
					 * (D-BAST-IRELE-INACTIVE-SELF-WEDGE). */
					mxfs_dlm_claim_demoter(ip);
					mxfs_dlm_bast_process(ip);
					mxfs_dlm_release_demoter(ip);
					mxfs_lkrc = mxfs_inact_via_iclus ?
						mxfs_iclus_lock(mp, ip->i_ino,
								MXFS_LOCK_EX,
								NULL) :
						mxfs_v5_dlm_inode_lock(
							mp->m_mxfs_dlm,
							ip->i_ino,
							MXFS_LOCK_EX, NULL);
					/* ICLUSTER: a sibling's still-draining
					 * grant re-EDEADLKs the cluster
					 * upgrade transiently; the fan-out we
					 * just armed clears it in ms. */
					if (mxfs_lkrc != -EDEADLK)
						break;
					msleep(25);
				}
				pr_warn("mxfs: P2I-INACT-UPG ino=%llu demote+reacquire rc=%d tries=%d (one-shot was -EDEADLK)\n",
					(unsigned long long)ip->i_ino,
					mxfs_lkrc, mxfs_upg_try + 1);
			}
			if (mxfs_lkrc == 0)
				mxfs_inact_dlm_locked = true;
			/*
			 * sess6 (ccloop 72513a13) RULE-4 PROVEN root of the
			 * dlm_fairness churn shutdowns ("Free inode N has
			 * blocks allocated", 8/cawd create+mv+rm):  an idle
			 * demote in the droplink->inactivation gap left
			 * i_dlm_mode=NL, so EVERY AIL flush of the truncate/
			 * ifree transactions below was discarded by the P119
			 * non-EX guard (marks clean without writing) — the
			 * ifree-end bounded drain then vacuously "succeeded"
			 * and the platter kept the PRE-FREE dinode.  The next
			 * local realloc's recycle-gate adopted that stale
			 * allocated image (nx=1) over the freed in-core state,
			 * resurrecting a freed extent -> frankenstein dinode
			 * (mode=0 nblocks=1) -> -EFSCORRUPTED -> shutdown
			 * (proven live: P70-BP strip @58.634 -> P19-B3DEC
			 * dlm_mode=0 -> P119-NONEX-FLUSH-SKIP @58.638 ->
			 * P-RECYCLE-GATE adopt=1 of disk_gen 186 over newer
			 * in-core gen 187 -> corruption @61.684, test8).
			 *
			 * We hold the cluster-wide exclusion here (cluster EX
			 * for routed inodes, per-inode EX otherwise), so this
			 * node IS authoritative for the dinode until the
			 * INACT-EXREL unlock at out: — exactly what
			 * MXFS_IF_DLM_RELFLUSH asserts.  Set it so the
			 * freeing transactions' flushes actually write, and
			 * the ifree-end drain+blkdev_flush destages mode=0
			 * BEFORE the release.  Cleared alongside the release.
			 */
			if (mxfs_inact_dlm_locked)
				xfs_iflags_set(ip, MXFS_IF_DLM_RELFLUSH);
			p137_dlm_ns = ktime_get_ns() - p137_s;

			p137_s = ktime_get_ns();
			/*
			 * sess10 (ccloop c7ee71c6) RULE-0 FIX — dlm_scaling@32
			 * NO_TERMINAL_RECORD (~15-19 ops/s vs floor 30): after
			 * the sess7 nlink-read skip below, the mode/gen read
			 * was the LAST raw target round-trip on this hot path
			 * and it alone is the whole cost (P137 fua_us p50=46ms
			 * p90=123ms at 32 nodes; plain-bio vs SCSI-FUA made no
			 * difference — it is queue-wait behind the cluster's
			 * O_DSYNC writes, not FUA semantics).  Under
			 * LOCAL_UNLINK **and** a successful fresh EX
			 * (mxfs_inact_dlm_locked) this node is authoritative
			 * for the dinode: any disk view may lag our OWN
			 * not-yet-destaged writes, so the B-guards it feeds
			 * must not act on it anyway — B1 (dmode==0) would
			 * false-skip on a lagging pre-create image and LEAK;
			 * B2's number-reuse premise cannot hold while we hold
			 * EX on the number.  Same sentinel discipline as the
			 * nlink skip: 0xFFFF means "unknown" — B1 (==0) and
			 * B2 (!=0xFFFF) are both inert on it.  Non-local or
			 * EX-less inactivations (stale cached shells — the
			 * cases the guards exist for) still pay the read.
			 */
			if (xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) &&
			    mxfs_inact_dlm_locked) {
				mxfs_dmode = 0xFFFF;
				mxfs_dgen = 0;
			} else {
				mxfs_dmode = mxfs_dbg_disk_di_mode(mp,
							ip->i_ino, &mxfs_dgen);
				/*
				 * sess47 finding-B discriminator (RULE 4):
				 * when the raw read says LIVE for a foreign
				 * zombie (no local-unlink authority), compare
				 * against the coherent read.  A divergence
				 * here is the missing proof that the raw mode
				 * read can serve a stale pre-free image and
				 * wave a peer-freed inode into destructive
				 * inactivation (test32 chain, finding B).
				 * Extra round-trip only on this rare
				 * foreign-zombie path, and only while the
				 * raw verdict is LIVE.
				 */
				if (mxfs_dmode != 0 && mxfs_dmode != 0xFFFF) {
					extern uint16_t
					mxfs_dbg_disk_di_mode_coherent(
						struct xfs_mount *, uint64_t,
						uint32_t *);
					uint32_t bcg = 0;
					uint16_t bcm =
					    mxfs_dbg_disk_di_mode_coherent(mp,
						ip->i_ino, &bcg);

					if (bcm != mxfs_dmode ||
					    bcg != mxfs_dgen) {
						static atomic_t pbmd_n =
							ATOMIC_INIT(0);

						if (atomic_inc_return(&pbmd_n) <= 60)
							pr_warn("mxfs: P-B-MODE-DIVERGE ino=%llu raw_mode=0%o raw_gen=%u coh_mode=0%o coh_gen=%u — authority guard raw disk-mode read diverges from coherent read\n",
								(unsigned long long)ip->i_ino,
								mxfs_dmode, mxfs_dgen,
								bcm, bcg);
						/* Coherent side is the truth
						 * the guards must judge. */
						mxfs_dmode = bcm;
						mxfs_dgen = bcg;
					}
				}
			}
			/*
			 * sess7 (c7ee71c6): the coherent-nlink read feeds ONLY
			 * the B3/B4 guards below, both gated !local_unlink —
			 * under a LOCAL unlink its value reaches nothing but
			 * the P19 print.  Skipping it halves the raw target
			 * round-trips this hot path pays per unlink (P137
			 * fua_us 17-47ms under 16-way contention = the
			 * dlm_scaling@16 rate-floor FAIL).  0xFFFFFFFF is the
			 * probes' own "unknown" sentinel: B3/B4 already treat
			 * it as do-not-skip.
			 */
			mxfs_coh_nlink =
				xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) ?
				0xFFFFFFFF :
				mxfs_dbg_disk_di_nlink_coherent(mp,
							   ip->i_ino);
			p137_fua_ns = ktime_get_ns() - p137_s;
		}

		/*
		 * di_mode==0  => the inode is already FREE on disk (a peer
		 *                unlinked+freed it); nothing for us to clean up.
		 * gen mismatch => the on-disk inode is a DIFFERENT incarnation
		 *                (the inode number was reused by a peer); our
		 *                in-core copy is a stale prior incarnation whose
		 *                extent map points at blocks the new owner (or
		 *                the free space) holds.  Either way, freeing this
		 *                inode's blocks here is a double-free.  Reclaim
		 *                the in-core inode WITHOUT touching shared disk
		 *                metadata.  (mode!=0 && gen matches => it is our
		 *                live inode being legitimately inactivated.)
		 */
		/*
		 * B1 (disk-free): di_mode==0 => the inode is FREE on disk; freeing
		 *   its blocks again is unconditionally a double-free.  Safe to skip
		 *   regardless of grant state.
		 * B2 (reused): di_mode!=0 but di_gen != in-core gen => the on-disk
		 *   inode is a DIFFERENT incarnation (peer reused the inode number).
		 *   Only skip when we are GRANT-LESS (i_dlm_mode==NL): a stale cached
		 *   peer/old incarnation we instantiated via readdir/lookup.  A node's
		 *   OWN inode is held at PR/EX while it owns it, so this never
		 *   false-skips a legitimate local inactivation (which would leak the
		 *   inode + leave it on the AGI unlinked list — sess47 risk).
		 */
		/*
		 * B3 (sess19 ccloop, Gemini RULE-5): the killer case B1/B2 both
		 * MISS — disk_mode!=0 AND disk_gen==incore_gen, yet this is NOT our
		 * inode to free.  Proven by the latest shutdown: test1 held a
		 * cached in-core inode for a PEER's still-LIVE file (same gen, mode
		 * 0100644) but with a TORN/STALE in-core nlink==0 (torn reload /
		 * NL-cached eviction).  B2's gen check cannot catch a same-gen torn
		 * reload, so the guard fell into the "our live inode" branch and
		 * freed a block the peer's on-disk inode still owns -> bnobt
		 * ltbno+ltlen>bno shutdown (P47-INACT DISK-LIVE-same-gen=>
		 * A-lost-removal + P81-DEXT disk_claims_freed=1).
		 *
		 * disk_nlink is NOT a sound discriminator (FUA reads hit the stale
		 * platter; a not-yet-flushed legitimate local unlink reads nlink>0).
		 * LOCAL INTENT is: MXFS_IF_LOCAL_UNLINK is set ONLY when THIS node
		 * drove the link count to 0 via a user remove/rename-over/rmdir
		 * (xfs_droplink) or created an O_TMPFILE/orphan it owns.  If the
		 * flag is CLEAR while in-core nlink==0, our nlink==0 did not come
		 * from a local removal -> it is a torn/stale copy of a peer's inode
		 * -> skip the destructive free.
		 */
		{
		bool mxfs_local_unlink = xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK);
		/* sess41 C8: adopted (survivor-sweep) freer authority — see
		 * MXFS_IF_ADOPTED_UNLINK.  Grants B3/B4 authority, never the
		 * P2L-OWNFREE bypass. */
		bool mxfs_adopted_unlink =
			xfs_iflags_test(ip, MXFS_IF_ADOPTED_UNLINK);
		/*
		 * ccloop cc87fed3 sess4 (RULE 4 — BUG3 hunt, fence_during_write@
		 * 8/caw): B2's own comment above says "Only skip when we are
		 * GRANT-LESS (i_dlm_mode==NL)" but the check below never
		 * implemented that qualifier.  A same-session attempt to ADD
		 * that check (matching B4/B5's `!= MXFS_LOCK_EX` pattern) was
		 * REJECTED after two independent model consults (GPT-5.6,
		 * Fable/Opus): live captures show this firing with
		 * ip->i_dlm_mode==EX AND mxfs_inact_dlm_locked=1 (a FRESH
		 * low-level per-inode EX re-acquire, taken specifically to
		 * close the disk-read TOCTOU window, succeeded immediately
		 * before the mismatched read) — i.e. the disk read is
		 * TOCTOU-safe, not racy, so a genuine post-lock gen mismatch is
		 * the STRONGEST possible evidence this in-core struct is a
		 * stale incarnation whose number a peer already reused, not a
		 * false positive.  The DLM lock is keyed by inode NUMBER only,
		 * not (number, generation) — holding EX proves exclusion on the
		 * number, never proves this struct is the CURRENT incarnation.
		 * Requiring i_dlm_mode==NL to skip would make B2 proceed to
		 * destructive free in EXACTLY the case its own post-lock read
		 * just proved unsafe — trading an intermittent crash (this
		 * skip leaks an AGI bucket entry, loud via P2L-INACT-LEAK) for
		 * intermittent SILENT DISK CORRUPTION (freeing a peer's live
		 * blocks).  DO NOT add the i_dlm_mode gate here.  Left as
		 * unconditional-on-genmismatch (original, safe) behavior.
		 * Keeping a loud, capped WARN below so a future session has
		 * forensic signal without re-deriving this — the real question
		 * is HOW this node's OWN just-created-then-unlinked file (see
		 * mxfs_local_unlink/dlm_locked below) ends up with a stale
		 * generation despite holding EX; the durable fix is making the
		 * DLM lock incarnation-aware (carry generation in the resource
		 * name or LVB), not touching this gate.
		 */
		bool mxfs_b2_reused = mxfs_dmode != 0xFFFF &&
			mxfs_dgen != mxfs_igen;

		if (unlikely(mxfs_b2_reused && ip->i_dlm_mode != MXFS_LOCK_NL)) {
			/* sess9: 3000→300 — printk-storm DoS (see P82-ADD). */
			static atomic_t p2lex_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p2lex_n) <= 300)
				pr_warn("mxfs: P2L-EX-GENMIS ino=%llu incore_gen=%u disk_gen=%u dlm_mode=%u dlm_locked=%d local_unlink=%d ip=%px pid=%d comm=%s — gen-mismatch B2-skip fired while holding a non-NL grant (forensic only, NOT proceeding destructively — see comment above)\n",
					(unsigned long long)ip->i_ino,
					mxfs_igen, mxfs_dgen, ip->i_dlm_mode,
					mxfs_inact_dlm_locked ? 1 : 0,
					mxfs_local_unlink ? 1 : 0,
					ip, current->pid, current->comm);
		}

		/*
		 * B3 (sess19): torn/stale in-core copy of a peer's STILL-LINKED
		 * live inode.  Skip the destructive free ONLY when BOTH:
		 *   (a) we have no local-unlink intent (flag CLEAR — our nlink==0
		 *       did not come from a local remove/rename/tmpfile), AND
		 *   (b) the on-disk inode is still LINKED in the COHERENT cluster
		 *       view (coherent di_nlink > 0 — a peer references it).
		 * Requiring (b) prevents false-skipping a genuinely-unlinked inode
		 * pending free (coherent nlink==0), including the survivor journal-
		 * replay cleanup of a dead peer's unlinked inodes (flag CLEAR but
		 * MUST be freed).  A read error (0xFFFFFFFF) is treated as "unknown"
		 * -> do NOT skip on B3 (fall back to B1/B2 only).
		 */
		bool mxfs_b3_torn_live = !(mxfs_local_unlink ||
					   mxfs_adopted_unlink) &&
			mxfs_coh_nlink != 0xFFFFFFFF && mxfs_coh_nlink > 0;

		/*
		 * B4 (sess-tcp fast-repro, 2-node create+unlink/rename storm):
		 * B1/B2/B3 all MISS — disk_mode!=0, disk_gen==incore_gen,
		 * coh_nlink==0, yet this node neither unlinked the inode
		 * (local_unlink=0) nor holds the inode EXCLUSIVELY
		 * (i_dlm_mode != EX — observed at NL *and* PR).  To destructively
		 * free an inode a node must EITHER have driven its link count to
		 * zero locally (MXFS_IF_LOCAL_UNLINK set) OR hold it EX (the
		 * authority a real xfs_ifree acquires).  A node holding only
		 * NL/PR with no local-unlink intent has NO AUTHORITY: our in-core
		 * copy is a stale cached incarnation (instantiated via
		 * readdir/lookup of the shared dir, then driven to nlink==0 by a
		 * peer-coherent reload) of a file the PEER unlinked.  That peer
		 * (holding EX, local_unlink=1) frees it during its own
		 * inactivation.  Proceeding to xfs_ifree here frees blocks the
		 * peer's on-disk inode still owns -> inobt -117 double-free ->
		 * FS shutdown (the 90-session stale-INODE family).
		 *
		 * Gate on !xlog_recovery_needed: during MOUNT-TIME log recovery
		 * the survivor/this-node MUST walk the AGI iunlink list and free
		 * a dead peer's orphaned inodes (also local_unlink=0, non-EX,
		 * coh_nlink==0 by construction) — must NOT skip then.  Outside
		 * recovery there is no legitimate reason for a non-EX,
		 * non-locally-unlinked node to free a coh_nlink==0 inode.
		 * coh_nlink read error (0xFFFFFFFF) => unknown => do NOT skip.
		 */
		bool mxfs_b4_no_authority = !(mxfs_local_unlink ||
					      mxfs_adopted_unlink) &&
			ip->i_dlm_mode != MXFS_LOCK_EX &&
			mxfs_coh_nlink == 0 &&
			!xlog_recovery_needed(mp->m_log);

		/*
		 * B5 (sess26 ccloop 8ddb16a2): the per-inode EX grant acquire
		 * above FAILED (mxfs_inact_dlm_locked==false — observed -EDEADLK
		 * rc=-35: we hold only NL/PR on this ino and cannot upgrade to
		 * EX).  A node that LEGITIMATELY unlinked this inode holds it EX,
		 * so that acquire returns 0; -EDEADLK therefore proves our in-core
		 * copy is a STALE cached incarnation of an inode a peer owns/freed.
		 * The disk-state reads above were then taken WITHOUT the cluster
		 * mutex and can be stale (FUA hit a not-yet-destaged platter), so
		 * B1's disk-free test MISSES and the loser double-frees the peer's
		 * blocks -> bnobt ltbno+ltlen>bno shutdown (PROVEN: ino 1956 freed
		 * at t=64s, reused, then ifree'd AGAIN at t=86s each time preceded
		 * by "DLM inode lock failed mode=5 rc=-35"; P47-INACT DISK-FREE +
		 * P81-DEXT incore-extent-stale fire at the bnobt free-point AFTER
		 * this guard let it through).  When we could not get EX and have no
		 * local-unlink intent (outside log recovery), skip the destructive
		 * free — the real owner frees it under its own EX.
		 *
		 * sess37 TOCTOU-CLOSURE EXTENSION (PROVEN: P47-INACT inact_ino=2099107
		 * disk_di_mode=0 disk_di_gen=incore_gen+1 — a stale gen-G cached inode
		 * the peer freed+reused to gen G+1; this node double-freed block 297 in
		 * agno=1 -> ltbno+ltlen>bno shutdown).  The original B5 required
		 * !mxfs_local_unlink, but MXFS_IF_LOCAL_UNLINK LEAKS across inode-number
		 * REUSE: it was set when THIS node unlinked the gen-G incarnation in a
		 * PRIOR round, and (because the stale copy was never reloaded —
		 * sess19's clear-on-reload didn't run) it still reads 1 for the dead
		 * incarnation.  With local_unlink=1 the old B5 fell through, the racy
		 * (mutex-less) disk read at CHECK time saw the inode still gen-G/live
		 * (B1/B2 missed), and the peer freed+reused it in the post-check window
		 * -> double-free.  When the per-inode EX acquire FAILED we have NO
		 * cluster authority over this inode-number regardless of a (possibly
		 * leaked) local-unlink flag, and our disk read cannot be trusted; the
		 * real owner (who holds EX) performs the free.  Drop the !local_unlink
		 * requirement.  SAFE for a node's OWN live files: it acquires EX
		 * cleanly (mxfs_inact_dlm_locked=true) so B5 never fires for them; B5
		 * fires only when a PEER holds EX (is reusing the number) = exactly the
		 * stale-copy case that must be skipped.  Gated outside log recovery so
		 * the survivor still frees a dead peer's orphaned iunlink inodes.
		 */
		/*
		 * sess41 (GPT audit C2): the log-recovery exemption is GONE.
		 * It existed so the survivor could free a dead peer's
		 * orphaned iunlink inodes, but those frees acquire the inode
		 * EX cleanly (a dead owner cannot contend, and live peers'
		 * open bits never block an EX grant — they only defer the
		 * free via B6, which REQUIRES the EX to run).  When the EX
		 * acquire FAILS during recovery we have no cluster authority
		 * and B6 cannot check open bits: proceeding could free an
		 * inode a live peer holds open.  Recovery does not justify
		 * bypassing mutual exclusion; the zombie stays on its bucket
		 * for the reaper / next mount to re-drive (fail-safe leak,
		 * loud via P2L-INACT-LEAK when local intent exists).
		 */
		bool mxfs_b5_nolock = !mxfs_inact_dlm_locked &&
			ip->i_dlm_mode != MXFS_LOCK_EX;

		/*
		 * sess19 (ccloop 4eef1f39) RULE-4 instrumentation: log the B3
		 * decision INPUTS unconditionally for every multi-node nlink==0
		 * inactivation, so a shutdown's pre-free state is captured even
		 * when the guard does NOT skip (the failing case).  P19-B3DEC.
		 */
		/* sess4(a9a03929): capped, NOT ratelimited — run68's decisive
		 * B-decision (ifree of the about-to-be-reused inum) was
		 * ratelimit-suppressed in the rm-rf storm. */
		{
		/* sess9: 8000→300 — printk-storm DoS (see P82-ADD). */
		static atomic_t p19_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p19_n) <= 300)
		pr_warn("mxfs: P19-B3DEC ino=%llu agno=%u incore_gen=%u disk_mode=0%o disk_gen=%u coh_nlink=%d local_unlink=%d dlm_mode=%u dlm_locked=%d will_skip=%d (b1_diskfree=%d b2_genmis_raw=%d b2_reused=%d b3_tornlive=%d b4_noauth=%d b5_nolock=%d) ip=%px pid=%d comm=%s\n",
			(unsigned long long)ip->i_ino,
			(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
			mxfs_igen, (unsigned)mxfs_dmode, mxfs_dgen,
			(int)mxfs_coh_nlink, mxfs_local_unlink ? 1 : 0,
			ip->i_dlm_mode, mxfs_inact_dlm_locked ? 1 : 0,
			(mxfs_dmode == 0 ||
			 mxfs_b2_reused ||
			 mxfs_b3_torn_live || mxfs_b4_no_authority ||
			 mxfs_b5_nolock) ? 1 : 0,
			mxfs_dmode == 0 ? 1 : 0,
			(mxfs_dmode != 0xFFFF && mxfs_dgen != mxfs_igen) ? 1 : 0,
			mxfs_b2_reused ? 1 : 0,
			mxfs_b3_torn_live ? 1 : 0,
			mxfs_b4_no_authority ? 1 : 0,
			mxfs_b5_nolock ? 1 : 0,
			ip, current->pid, current->comm);
		}

		/*
		 * ccloop-4dd7 OWN-FREE BYPASS (RULE-4 proven, ino 680 autopsy):
		 * a REUSED ino whose new life was created and unlinked before
		 * its cluster image ever destaged reads DISK-FREE (the prior
		 * life's freed image) with a foreign gen at its inactivation —
		 * b1/b2 then misclassify the RIGHTFUL freer's own unpublished
		 * life as a peer-free and skip, leaking the ino in the inobt
		 * AND stranding/racing its AGI bucket entry (the P2L storm →
		 * empty-bucket -117 at a peer's legitimate free).  With
		 * local-unlink intent AND the inode DLM EX held, the in-core
		 * life is authoritative and this node IS the authorized freer:
		 * proceed with the normal free (difree frees the inobt
		 * allocation; the truncate frees in-core-mapped blocks;
		 * iunlink_remove pulls our own insert).  Only the disk-FREE
		 * arm is bypassed — a disk-LIVE image still skips via b2/b3
		 * (a published foreign incarnation is never ours to free).
		 */
		if (mxfs_dmode == 0 && mxfs_local_unlink &&
		    mxfs_inact_dlm_locked) {
			static atomic_t p2lof_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p2lof_n) <= 300)
				pr_warn("mxfs: P2L-OWNFREE ino=%llu agno=%u incore_gen=%u disk_gen=%u — disk-free is our unpublished life; proceeding with authorized free (no skip/leak)\n",
					(unsigned long long)ip->i_ino,
					(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
					mxfs_igen, mxfs_dgen);
		} else if (mxfs_dmode == 0 ||
		    mxfs_b2_reused ||
		    mxfs_b3_torn_live || mxfs_b4_no_authority ||
		    mxfs_b5_nolock) {
			const char *mxfs_reason = mxfs_dmode == 0 ? "disk-free" :
				mxfs_b2_reused ?
				"gen-mismatch" :
				mxfs_b3_torn_live ? "torn-live-no-local-unlink" :
				mxfs_b4_no_authority ?
				"no-authority-unlocked-not-unlinked" :
				"ex-lock-unavailable-stale-copy";
			/*
			 * sess2 (a9a03929): a skip WITH local-unlink intent means the
			 * rightful freer is bailing — that leaks the inode on its AGI
			 * unlinked bucket (nobody else will free it; peers' B4/B5 skip
			 * too) and poisons the next same-bucket insert.  Post-fix
			 * (P2I demote+reacquire above) this must be ZERO; log it
			 * UNRATELIMITED so any residual leak is visible in one run.
			 */
			/* sess9 (72513a13): CAP 300 (was deliberately unlimited).
			 * At drc@32/tcp this fired 2001×/145s — the P2I
			 * demote+reacquire fix is NOT holding there (REAL leak
			 * regression, open front) — and the print volume itself
			 * became a DLM-service DoS (see P82-ADD).  300 samples
			 * still make any residual leak unmissable per run. */
			static atomic_t p2ll_n = ATOMIC_INIT(0);
			if (mxfs_local_unlink &&
			    atomic_inc_return(&p2ll_n) <= 300)
				pr_warn("mxfs: P2L-INACT-LEAK ino=%llu agno=%u agino=0x%x bucket=%d dlm_mode=%u dlm_locked=%d reason=%s — RIGHTFUL FREER SKIPPING (AGI bucket entry leaked) ip=%px pid=%d comm=%s\n",
					(unsigned long long)ip->i_ino,
					(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
					XFS_INO_TO_AGINO(mp, ip->i_ino),
					(int)(XFS_INO_TO_AGINO(mp, ip->i_ino) % XFS_AGI_UNLINKED_BUCKETS),
					ip->i_dlm_mode,
					mxfs_inact_dlm_locked ? 1 : 0,
					mxfs_reason, ip, current->pid, current->comm);
			pr_warn_ratelimited("mxfs: INACT-SKIP-STALE ino=%llu agno=%u incore_mode=0%o incore_gen=%u disk_mode=0%o disk_gen=%u coh_nlink=%d dlm_mode=%u local_unlink=%d reason=%s — skipping destructive inactivation to avoid double-free ip=%px pid=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
				(unsigned)VFS_I(ip)->i_mode, mxfs_igen,
				(unsigned)mxfs_dmode, mxfs_dgen,
				(int)mxfs_coh_nlink, ip->i_dlm_mode,
				mxfs_local_unlink ? 1 : 0, mxfs_reason,
				ip, current->pid, current->comm);
			/*
			 * ccloop-4dd7 UNLEAK (RULE-4 proven: the P2L-INACT-LEAK
			 * storm poisons the shared AGI bucket — a later
			 * xfs_iunlink walking it reaches the leaked entry's
			 * freed/reused ino and returns -EFSCORRUPTED out of a
			 * DIRTY remove transaction = the "droplink rc=-117"
			 * cluster-wide shutdown).  The skip above is correct for
			 * the BLOCK/chunk free — but when local_unlink is set
			 * OUR OWN remove transaction inserted this ino on the
			 * shared AGI unlinked bucket, and nobody else will ever
			 * remove that entry (the peer's free removed only its
			 * own insert of the prior life).  Pull our entry here in
			 * a small standalone transaction so the bucket stays
			 * walkable.  Gated on holding the inode DLM EX
			 * (mxfs_inact_dlm_locked): with EX no peer can own the
			 * reused number right now, so the bucket entry for this
			 * agino is provably OURS — never a peer's insert for a
			 * new incarnation.  Failure leaves today's (loud) leak.
			 */
			if (mxfs_local_unlink && mxfs_inact_dlm_locked &&
			    !xfs_is_shutdown(mp)) {
				struct xfs_trans	*ultp = NULL;
				struct xfs_perag	*ulpag = NULL;
				int			ulerr;

				ulerr = xfs_trans_alloc(mp,
						&M_RES(mp)->tr_ifree, 0, 0, 0,
						&ultp);
				if (!ulerr) {
					ulpag = xfs_perag_get(mp,
						XFS_INO_TO_AGNO(mp, ip->i_ino));
					if (ulpag &&
					    !mxfs_ag_dlm_lock(mp, ulpag)) {
						xfs_ilock(ip, XFS_ILOCK_EXCL);
						xfs_trans_ijoin(ultp, ip,
								XFS_ILOCK_EXCL);
						ulerr = xfs_iunlink_remove(
							ultp, ulpag, ip);
						if (!ulerr) {
							ulerr = xfs_trans_commit(ultp);
							if (!ulerr)
								xfs_iflags_clear(ip,
								    MXFS_IF_LOCAL_UNLINK);
						} else {
							xfs_trans_cancel(ultp);
						}
						mxfs_ag_dlm_unlock(mp, ulpag);
					} else {
						xfs_trans_cancel(ultp);
						ulerr = -EAGAIN;
					}
					if (ulpag)
						xfs_perag_put(ulpag);
				}
				pr_warn("mxfs: P2L-UNLEAK ino=%llu agno=%u agino=0x%x bucket=%d rc=%d — %s our AGI unlinked-list insert at inactivation skip\n",
					(unsigned long long)ip->i_ino,
					(unsigned)XFS_INO_TO_AGNO(mp, ip->i_ino),
					XFS_INO_TO_AGINO(mp, ip->i_ino),
					(int)(XFS_INO_TO_AGINO(mp, ip->i_ino) %
					      XFS_AGI_UNLINKED_BUCKETS),
					ulerr,
					ulerr ? "FAILED to remove (leaked as before)" :
						"removed");
			}
			goto out;
		}
		}
	}

	xfs_inactive_health(ip);

	/*
	 * If this is a read-only mount, don't do this (would generate I/O)
	 * unless we're in log recovery and cleaning the iunlinked list.
	 */
	if (xfs_is_readonly(mp) && !xlog_recovery_needed(mp->m_log))
		goto out;

	/* Metadata inodes require explicit resource cleanup. */
	if (xfs_is_internal_inode(ip))
		goto out;

	/* Try to clean out the cow blocks if there are any. */
	if (xfs_inode_has_cow_data(ip)) {
		error = xfs_reflink_cancel_cow_range(ip, 0, NULLFILEOFF, true);
		if (error)
			goto out;
	}

	if (VFS_I(ip)->i_nlink != 0) {
		/*
		 * Note: don't bother with iolock here since lockdep complains
		 * about acquiring it in reclaim context. We have the only
		 * reference to the inode at this point anyways.
		 */
		if (xfs_can_free_eofblocks(ip))
			error = xfs_free_eofblocks(ip);

		goto out;
	}

	/*
	 * B6 — sess40 OPEN-DEFER (D-CROSSNODE-OPEN-UNLINK-DATA-LOSS / GPT
	 * orphan-coordinator).  nlink==0 and we are about to run the WHOLE
	 * destructive inactivation (truncate frees data extents, then ifree).
	 * A PEER with the inode's open-holder bit set may have live fds,
	 * mappings, or writeback against those extents — POSIX requires the
	 * data to survive until the last close ANYWHERE.  Defer: leave the
	 * zombie durable on OUR unlinked bucket, record it for the periodic
	 * reaper, and free nothing now.  The query is valid because we hold
	 * the per-inode DLM EX (mxfs_inact_dlm_locked) — the acquire
	 * re-established the live slot, inheriting idle-gap open bits.  Peers
	 * that merely CACHE the inode clear their bits at evict (our EX
	 * acquire BASTed them); real openers keep theirs until last-close
	 * eviction, and fencing strips dead nodes' bits — so the reaper's
	 * retries converge.  Runs AFTER the B1-B5 authority guards: if we
	 * should not free at all, those verdicts win.
	 */
	if (({ extern unsigned int mxfs_open_tracking; mxfs_open_tracking; }) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    mxfs_inact_dlm_locked) {
		uint64_t mxfs_oh = 0;
		int mxfs_oh_rc;
		uint64_t mxfs_self = mxfs_v5_dlm_node_bit(mp->m_mxfs_dlm);

		if (mxfs_dlm_iclus_covered(ip)) {
			/* sess46: ROUTED inode — we hold the CLUSTER EX, not
			 * a per-inode claim, so the per-inode read's
			 * "no slot under held EX = failure" contract is
			 * wrong here (a never-opened routed file correctly
			 * has no record).  The probe distinguishes provable
			 * absence (clean chain walk → free may proceed) from
			 * unreadable/garbage (defer, fail closed), and reads
			 * bits across live, tombstone-carried and duplicate
			 * records.  Linearized by publication-before-release
			 * on every publisher + our held cluster EX. */
			bool mxfs_oh_auth = false;

			mxfs_oh_rc = mxfs_v5_dlm_inode_open_probe(
					mp->m_mxfs_dlm, ip->i_ino,
					&mxfs_oh, &mxfs_oh_auth);
		} else {
			mxfs_oh_rc = mxfs_v5_dlm_inode_open_holders(
					mp->m_mxfs_dlm, ip->i_ino, &mxfs_oh);
		}

		/*
		 * sess41 (GPT audit C5): FAIL CLOSED.  We hold the inode EX,
		 * so the bitmap read must succeed; an unreadable bitmap is
		 * indistinguishable from "a peer holds this open" and the
		 * only safe verdict is defer.  -EOPNOTSUPP (transport without
		 * open tracking — TCP until the C9 increment) proceeds:
		 * that exposure is ledgered, and deferring EVERY free on such
		 * a transport would leak every unlinked inode.
		 */
		if (mxfs_oh_rc && mxfs_oh_rc != -EOPNOTSUPP) {
			pr_warn_ratelimited(
			    "mxfs: P87-OPEN-DEFER-ERR ino=%llu gen=%u rc=%d — open bitmap unreadable under EX; failing CLOSED (deferring free)\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation, mxfs_oh_rc);
			mxfs_defer_reap_add(mp, ip->i_ino,
					    VFS_I(ip)->i_generation,
					    ip->i_unlinked_bucket);
			goto out;
		}
		if (mxfs_oh & ~mxfs_self) {
			pr_warn_ratelimited(
			    "mxfs: P87-OPEN-DEFER ino=%llu gen=%u open_holders=0x%llx self=0x%llx bucket=%d — peer holds this unlinked inode open; deferring destructive inactivation\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_generation,
				(unsigned long long)mxfs_oh,
				(unsigned long long)mxfs_self,
				(int)ip->i_unlinked_bucket);
			mxfs_defer_reap_add(mp, ip->i_ino,
					    VFS_I(ip)->i_generation,
					    ip->i_unlinked_bucket);
			goto out;
		}
	}

	if (S_ISREG(VFS_I(ip)->i_mode) &&
	    (ip->i_disk_size != 0 || XFS_ISIZE(ip) != 0 ||
	     xfs_inode_has_filedata(ip)))
		truncate = 1;

	if (xfs_iflags_test(ip, XFS_IQUOTAUNCHECKED)) {
		/*
		 * If this inode is being inactivated during a quotacheck and
		 * has not yet been scanned by quotacheck, we /must/ remove
		 * the dquots from the inode before inactivation changes the
		 * block and inode counts.  Most probably this is a result of
		 * reloading the incore iunlinked list to purge unrecovered
		 * unlinked inodes.
		 */
		xfs_qm_dqdetach(ip);
	} else {
		error = xfs_qm_dqattach(ip);
		if (error)
			goto out;
	}

	if (S_ISDIR(VFS_I(ip)->i_mode) && ip->i_df.if_nextents > 0) {
		xfs_inactive_dir(ip);
		truncate = 1;
	}

	if (S_ISLNK(VFS_I(ip)->i_mode))
		error = xfs_inactive_symlink(ip);
	else if (truncate) {
		u64 p137_s = ktime_get_ns();

		error = xfs_inactive_truncate(ip);
		p137_trunc_ns = ktime_get_ns() - p137_s;
	}
	if (error)
		goto out;

	/*
	 * If there are attributes associated with the file then blow them away
	 * now.  The code calls a routine that recursively deconstructs the
	 * attribute fork. If also blows away the in-core attribute fork.
	 */
	if (xfs_inode_has_attr_fork(ip)) {
		error = xfs_attr_inactive(ip);
		if (error)
			goto out;
	}

	ASSERT(ip->i_forkoff == 0);

	/*
	 * Free the inode.
	 */
	{
		u64 p137_s = ktime_get_ns();

		error = xfs_inactive_ifree(ip);
		p137_ifree_ns = ktime_get_ns() - p137_s;
	}

out:
	if (ktime_get_ns() - p137_t0 > 15 * NSEC_PER_MSEC)
		pr_warn_ratelimited(
		    "mxfs: P137-INACT-TIME ino=%llu total_us=%llu dlm_us=%llu fua_us=%llu trunc_us=%llu ifree_us=%llu\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)((ktime_get_ns() - p137_t0) / 1000),
			(unsigned long long)(p137_dlm_ns / 1000),
			(unsigned long long)(p137_fua_ns / 1000),
			(unsigned long long)(p137_trunc_ns / 1000),
			(unsigned long long)(p137_ifree_ns / 1000));
	/*
	 * sess78: release the per-inode DLM EX grant taken to serialize
	 * clustered destructive inactivation (idempotent — caw_unlock is a
	 * no-op if not held).  Done before dquot detach; no XFS ILOCK held.
	 */
	if (mxfs_inact_dlm_locked &&
	    mxfs_inact_defer_unlock && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    (atomic_read(&ip->i_pincount) > 0 ||
	     (ip->i_itemp &&
	      (ip->i_itemp->ili_fields ||
	       test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags))))) {
		/*
		 * ccloop c7ee71c6 sess3 FIX-1 (RULE 4, PROVEN via
		 * run_dir_reuse_coherency_20260725T140939Z ino 165): the freed
		 * dinode (mode=0) is still only in the CIL/AIL — the platter
		 * still carries the PRIOR alive incarnation.  Publishing the
		 * on-disk slot now lets a peer acquire+reload and certify the
		 * corpse as alive (test2 held PR on the rmdir'ed dir for 297s;
		 * the fleet then ran a whole round inside the dead universe).
		 * Invariant #1 for the inode's own cluster: never hand the
		 * slot over before the free is on the platter.  DEFER: keep
		 * the grant CACHED; release happens via a peer BAST
		 * (bast_process durable loop, extended to freed inodes) or
		 * via reclaim/evict (reclaim implies flushed; evict does the
		 * free-aware tombstone unlock).  Common already-destaged
		 * frees still unlock immediately below.
		 */
		pr_warn_ratelimited(
		    "mxfs: P128-INACT-DEFER ino=%llu pin=%d ili=0x%x in_ail=%d — freed dinode undestaged; keeping grant cached\n",
			(unsigned long long)ip->i_ino,
			atomic_read(&ip->i_pincount),
			ip->i_itemp ? ip->i_itemp->ili_fields : 0,
			(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
				&ip->i_itemp->ili_item.li_flags)) ? 1 : 0);
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
	} else if (mxfs_inact_dlm_locked) {
		extern void mxfs_v5_dlm_inode_unlock_free(struct mxfs_v5_dlm *,
							  uint64_t);
		extern void mxfs_v5_dlm_inode_unlock(struct mxfs_v5_dlm *,
						     uint64_t);
		extern int mxfs_iclus_unlock(struct xfs_mount *, uint64_t,
					     uint8_t, bool);
		/*
		 * ccloop cc87fed3 sess7/sess8: use the free-aware unlock so
		 * CAW piggybacks a dir_epoch/last_ex_slot clear onto its own
		 * tombstone CAS (zero extra I/O) so the NEXT node to reuse
		 * this ino number doesn't inherit a stale cross-node-handoff
		 * signal from this now-dead incarnation (dlm_scaling@32
		 * op-rate fix).  Also handled at the mxfs_dlm_evict site
		 * (xfs_mxfs_dlm.c) for any freed inode whose release didn't
		 * take this synchronous inactivation-lock path.
		 *
		 * sess40 (D-AGI-UNLINKED tombstone-semantics): the old gate
		 * here was "we're past the nlink!=0 bail, so a genuine free
		 * is guaranteed" — FALSE for the guard-skip exits
		 * (INACT-SKIP-STALE / B2-B5 / IFREE-REVALIDATE-SKIP), which
		 * goto out with nlink==0 and NO free.  The deterministic
		 * AGI-bucket reproducer caught this path free-tombstoning
		 * the slot of a LIVE peer inode this node had merely
		 * reloaded.  Only a committed ifree may publish free
		 * semantics; a skipped inactivation releases plainly.
		 */
		{
		bool mxfs_freed = xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED);

		if (mxfs_inact_via_iclus)
			/* ICLUSTER release_check: is_free piggybacks the
			 * tombstone CAS iff this call performs the cluster
			 * release (pending BAST + clean sweep). */
			(void)mxfs_iclus_unlock(mp, ip->i_ino, MXFS_LOCK_EX,
						mxfs_freed);
		else if (mxfs_freed)
			mxfs_v5_dlm_inode_unlock_free(mp->m_mxfs_dlm,
						      ip->i_ino);
		else
			mxfs_v5_dlm_inode_unlock(mp->m_mxfs_dlm, ip->i_ino);
		}

		/*
		 * sess40 open tracking — clear at inactivation exit.  We are
		 * past the last local iput (VFS evict truncated the pages) so
		 * this node provably has no protected activity left; waiting
		 * for xfs_reclaim (memory pressure) leaves a peer's deferred
		 * reap stuck behind our stale bit for minutes (measured: the
		 * openunlink probe's reaper retried forever while the closer's
		 * zombie sat RECLAIMABLE).  Applies to every nlink==0 exit —
		 * guard-skips, B6 defers, and plain paths — except a committed
		 * free, whose unlock_free already zeroed the whole field.
		 */
		if (ip->i_mxfs_open_pub && VFS_I(ip)->i_nlink == 0 &&
		    !xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED) &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			mxfs_v5_dlm_inode_open_clear(mp->m_mxfs_dlm,
						     ip->i_ino);
			ip->i_mxfs_open_pub = false;
		}
		/*
		 * sess128 RULE-4 probe: the ON-DISK slot for this ino is now
		 * released, but in-core i_dlm_mode/i_dlm_unpublished are left
		 * as-is.  If this in-core inode is later RECYCLED for a new
		 * local create, publish-on-create bails (unpub flag clear) and
		 * the create runs on a phantom EX with no slot.  Pair with
		 * P128-PUBLISH-BAIL on the same ino.
		 */
		pr_warn_ratelimited(
		    "mxfs: P128-INACT-EXREL ino=%llu dlm_mode=%u unpub=%d freed=%d\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_mode,
			ip->i_dlm_unpublished ? 1 : 0,
			xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED) ? 1 : 0);
		/* sess6 (ccloop 72513a13): close the sanctioned inactivation
		 * flush window opened at the DLM acquire above. */
		xfs_iflags_clear(ip, MXFS_IF_DLM_RELFLUSH);
	}

	/*
	 * We're done making metadata updates for this inode, so we can release
	 * the attached dquots.
	 */
	xfs_qm_dqdetach(ip);
	return error;
}

/*
 * Find an inode on the unlinked list. This does not take references to the
 * inode as we have existence guarantees by holding the AGI buffer lock and that
 * only unlinked, referenced inodes can be on the unlinked inode list.  If we
 * don't find the inode in cache, then let the caller handle the situation.
 */
struct xfs_inode *
xfs_iunlink_lookup(
	struct xfs_perag	*pag,
	xfs_agino_t		agino)
{
	struct xfs_inode	*ip;

	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (!ip) {
		/* Caller can handle inode not being in memory. */
		rcu_read_unlock();
		return NULL;
	}

	/*
	 * Inode in RCU freeing limbo should not happen.  Warn about this and
	 * let the caller handle the failure.
	 */
	if (WARN_ON_ONCE(!ip->i_ino)) {
		rcu_read_unlock();
		return NULL;
	}
	ASSERT(!xfs_iflags_test(ip, XFS_IRECLAIMABLE | XFS_IRECLAIM));
	rcu_read_unlock();
	return ip;
}

/*
 * Load the inode @next_agino into the cache and set its prev_unlinked pointer
 * to @prev_agino.  Caller must hold the AGI to synchronize with other changes
 * to the unlinked list.
 */
int
xfs_iunlink_reload_next(
	struct xfs_trans	*tp,
	struct xfs_buf		*agibp,
	xfs_agino_t		prev_agino,
	xfs_agino_t		next_agino,
	short			bucket)
{
	struct xfs_perag	*pag = agibp->b_pag;
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_inode	*next_ip = NULL;
	int			error;

	ASSERT(next_agino != NULLAGINO);

#ifdef DEBUG
	rcu_read_lock();
	next_ip = radix_tree_lookup(&pag->pag_ici_root, next_agino);
	ASSERT(next_ip == NULL);
	rcu_read_unlock();
#endif

	xfs_info_ratelimited(mp,
 "Found unrecovered unlinked inode 0x%x in AG 0x%x.  Initiating recovery.",
			next_agino, pag_agno(pag));
	/* sess38 D-AGI-UNLINKED canary detail (unconditional — this reload is
	 * the rare precursor of the cross-node stale-stitch shutdown): under
	 * multi-node, next_agino here is typically a PEER's in-flight unlinked
	 * inode our cache never saw.  Log the stitch parameters + AG tenure
	 * gen so the fleet-wide merge orders this against both nodes' P82/P83
	 * records. */
	if (mp->m_mxfs_dlm)
		pr_warn("mxfs: P83-UNL-RELOAD agno=%u prev_agino=0x%x next_agino=0x%x agi_gen=%llu node_slot=%u realns=%llu\n",
			pag_agno(pag), prev_agino, next_agino,
			(unsigned long long)agibp->b_mxfs_ag_gen,
			mp->m_mxfs_node_slot,
			(unsigned long long)ktime_get_real_ns());

	/*
	 * Use an untrusted lookup just to be cautious in case the AGI has been
	 * corrupted and now points at a free inode.  That shouldn't happen,
	 * but we'd rather shut down now since we're already running in a weird
	 * situation.
	 */
	error = xfs_iget(mp, tp, xfs_agino_to_ino(pag, next_agino),
			XFS_IGET_UNTRUSTED, 0, &next_ip);
	if (error) {
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		return error;
	}

	/* If this is not an unlinked inode, something is very wrong. */
	if (VFS_I(next_ip)->i_nlink != 0) {
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		error = -EFSCORRUPTED;
		goto rele;
	}

	next_ip->i_prev_unlinked = prev_agino;
	next_ip->i_unlinked_bucket = bucket;
	trace_xfs_iunlink_reload_next(next_ip);
rele:
	ASSERT(!(inode_state_read_once(VFS_I(next_ip)) & I_DONTCACHE));
	if (xfs_is_quotacheck_running(mp) && next_ip)
		xfs_iflags_set(next_ip, XFS_IQUOTAUNCHECKED);
	xfs_irele(next_ip);
	return error;
}

/*
 * Look up the inode number specified and if it is not already marked XFS_ISTALE
 * mark it stale. We should only find clean inodes in this lookup that aren't
 * already stale.
 */
static void
xfs_ifree_mark_inode_stale(
	struct xfs_perag	*pag,
	struct xfs_inode	*free_ip,
	xfs_ino_t		inum)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_inode_log_item *iip;
	struct xfs_inode	*ip;

retry:
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, XFS_INO_TO_AGINO(mp, inum));

	/* Inode not in memory, nothing to do */
	if (!ip) {
		rcu_read_unlock();
		return;
	}

	/*
	 * because this is an RCU protected lookup, we could find a recently
	 * freed or even reallocated inode during the lookup. We need to check
	 * under the i_flags_lock for a valid inode here. Skip it if it is not
	 * valid, the wrong inode or stale.
	 */
	spin_lock(&ip->i_flags_lock);
	if (ip->i_ino != inum || __xfs_iflags_test(ip, XFS_ISTALE))
		goto out_iflags_unlock;

	/*
	 * Don't try to lock/unlock the current inode, but we _cannot_ skip the
	 * other inodes that we did not find in the list attached to the buffer
	 * and are not already marked stale. If we can't lock it, back off and
	 * retry.
	 */
	if (ip != free_ip) {
		if (!xfs_ilock_nowait(ip, XFS_ILOCK_EXCL)) {
			spin_unlock(&ip->i_flags_lock);
			rcu_read_unlock();
			delay(1);
			goto retry;
		}
	}
	ip->i_flags |= XFS_ISTALE;

	/*
	 * If the inode is flushing, it is already attached to the buffer.  All
	 * we needed to do here is mark the inode stale so buffer IO completion
	 * will remove it from the AIL.
	 */
	iip = ip->i_itemp;
	if (__xfs_iflags_test(ip, XFS_IFLUSHING)) {
		ASSERT(!list_empty(&iip->ili_item.li_bio_list));
		ASSERT(iip->ili_last_fields || xlog_is_shutdown(mp->m_log));
		goto out_iunlock;
	}

	/*
	 * Inodes not attached to the buffer can be released immediately.
	 * Everything else has to go through xfs_iflush_abort() on journal
	 * commit as the flock synchronises removal of the inode from the
	 * cluster buffer against inode reclaim.
	 */
	if (!iip || list_empty(&iip->ili_item.li_bio_list))
		goto out_iunlock;

	__xfs_iflags_set(ip, XFS_IFLUSHING);
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();

	/* we have a dirty inode in memory that has not yet been flushed. */
	spin_lock(&iip->ili_lock);
	iip->ili_last_fields = iip->ili_fields;
	iip->ili_fields = 0;
	spin_unlock(&iip->ili_lock);
	ASSERT(iip->ili_last_fields);

	if (ip != free_ip)
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return;

out_iunlock:
	if (ip != free_ip)
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
out_iflags_unlock:
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();
}

/*
 * A big issue when freeing the inode cluster is that we _cannot_ skip any
 * inodes that are in memory - they all must be marked stale and attached to
 * the cluster buffer.
 */
static int
xfs_ifree_cluster(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_inode	*free_ip,
	struct xfs_icluster	*xic)
{
	struct xfs_mount	*mp = free_ip->i_mount;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	struct xfs_buf		*bp;
	xfs_daddr_t		blkno;
	xfs_ino_t		inum = xic->first_ino;
	int			nbufs;
	int			i, j;
	int			ioffset;
	int			error;

	nbufs = igeo->ialloc_blks / igeo->blocks_per_cluster;

	for (j = 0; j < nbufs; j++, inum += igeo->inodes_per_cluster) {
		/*
		 * The allocation bitmap tells us which inodes of the chunk were
		 * physically allocated. Skip the cluster if an inode falls into
		 * a sparse region.
		 */
		ioffset = inum - xic->first_ino;
		if ((xic->alloc & XFS_INOBT_MASK(ioffset)) == 0) {
			ASSERT(ioffset % igeo->inodes_per_cluster == 0);
			continue;
		}

		blkno = XFS_AGB_TO_DADDR(mp, XFS_INO_TO_AGNO(mp, inum),
					 XFS_INO_TO_AGBNO(mp, inum));

		/*
		 * We obtain and lock the backing buffer first in the process
		 * here to ensure dirty inodes attached to the buffer remain in
		 * the flushing state while we mark them stale.
		 *
		 * If we scan the in-memory inodes first, then buffer IO can
		 * complete before we get a lock on it, and hence we may fail
		 * to mark all the active inodes on the buffer stale.
		 */
		error = xfs_trans_get_buf(tp, mp->m_ddev_targp, blkno,
				mp->m_bsize * igeo->blocks_per_cluster, 0, &bp);
		if (error)
			return error;

		/*
		 * This buffer may not have been correctly initialised as we
		 * didn't read it from disk. That's not important because we are
		 * only using to mark the buffer as stale in the log, and to
		 * attach stale cached inodes on it.
		 *
		 * For the inode that triggered the cluster freeing, this
		 * attachment may occur in xfs_inode_item_precommit() after we
		 * have marked this buffer stale.  If this buffer was not in
		 * memory before xfs_ifree_cluster() started, it will not be
		 * marked XBF_DONE and this will cause problems later in
		 * xfs_inode_item_precommit() when we trip over a (stale, !done)
		 * buffer to attached to the transaction.
		 *
		 * Hence we have to mark the buffer as XFS_DONE here. This is
		 * safe because we are also marking the buffer as XBF_STALE and
		 * XFS_BLI_STALE. That means it will never be dispatched for
		 * IO and it won't be unlocked until the cluster freeing has
		 * been committed to the journal and the buffer unpinned. If it
		 * is written, we want to know about it, and we want it to
		 * fail. We can acheive this by adding a write verifier to the
		 * buffer.
		 */
		bp->b_flags |= XBF_DONE;
		bp->b_ops = &xfs_inode_buf_ops;

		/*
		 * Now we need to set all the cached clean inodes as XFS_ISTALE,
		 * too. This requires lookups, and will skip inodes that we've
		 * already marked XFS_ISTALE.
		 */
		for (i = 0; i < igeo->inodes_per_cluster; i++)
			xfs_ifree_mark_inode_stale(pag, free_ip, inum + i);

		xfs_trans_stale_inode_buf(tp, bp);
		xfs_trans_binval(tp, bp);
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: P9-INSTR ifree_cluster STALE blkno=%llu first_ino=%llu",
			(unsigned long long)blkno,
			(unsigned long long)inum);
	}
	return 0;
}

/*
 * This is called to return an inode to the inode free list.  The inode should
 * already be truncated to 0 length and have no pages associated with it.  This
 * routine also assumes that the inode is already a part of the transaction.
 *
 * The on-disk copy of the inode will have been added to the list of unlinked
 * inodes in the AGI. We need to remove the inode from that list atomically with
 * respect to freeing it here.
 */
int
xfs_ifree(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_perag	*pag;
	struct xfs_icluster	xic = { 0 };
	struct xfs_inode_log_item *iip = ip->i_itemp;
	int			error;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	ASSERT(VFS_I(ip)->i_nlink == 0);
	ASSERT(ip->i_df.if_nextents == 0);
	ASSERT(ip->i_disk_size == 0 || !S_ISREG(VFS_I(ip)->i_mode));
	ASSERT(ip->i_nblocks == 0);

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));

	error = xfs_inode_uninit(tp, pag, ip, &xic);
	if (error)
		goto out;

	if (xfs_iflags_test(ip, XFS_IPRESERVE_DM_FIELDS))
		xfs_iflags_clear(ip, XFS_IPRESERVE_DM_FIELDS);

	/* Don't attempt to replay owner changes for a deleted inode */
	spin_lock(&iip->ili_lock);
	iip->ili_fields &= ~(XFS_ILOG_AOWNER | XFS_ILOG_DOWNER);
	spin_unlock(&iip->ili_lock);

	if (xic.deleted)
		error = xfs_ifree_cluster(tp, pag, ip, &xic);

	/*
	 * sess55: publish an inode-eviction hint into the disklock heartbeat
	 * ring so passively NL-caching peers drop any stale cached copy of this
	 * inode number before it is reused as a different type/incarnation (the
	 * cross_visibility "Is a directory" / invisible-file coherency failures).
	 * Success path only — the number is now free on disk.  No-op single-node.
	 */
	if (!error) {
		extern void mxfs_dlm_note_inode_freed(struct xfs_mount *,
						      uint64_t, uint32_t);
		mxfs_dlm_note_inode_freed(mp, ip->i_ino,
					  VFS_I(ip)->i_generation);
	}
	/* sess4(a16ec5f2) IFREE ledger — pairs with P4X-UNLINK: names when
	 * each inode number went free and by whom (run22 dangler autopsy). */
	{
		extern int mxfs_dirwr_enabled;

		if (unlikely(mxfs_dirwr_enabled) && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			static atomic_t p4i_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p4i_n) <= 200000)
				pr_warn("mxfs: P4I-IFREE ino=%llu err=%d gen=%u cluster_deleted=%d comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino, error,
					VFS_I(ip)->i_generation,
					xic.deleted ? 1 : 0, current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
	}
out:
	xfs_perag_put(pag);
	return error;
}

/*
 * This is called to unpin an inode.  The caller must have the inode locked
 * in at least shared mode so that the buffer cannot be subsequently pinned
 * once someone is waiting for it to be unpinned.
 */
static void
xfs_iunpin(
	struct xfs_inode	*ip)
{
	struct xfs_inode_log_item *iip = ip->i_itemp;
	xfs_csn_t		seq = 0;

	trace_xfs_inode_unpin_nowait(ip, _RET_IP_);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL | XFS_ILOCK_SHARED);

	spin_lock(&iip->ili_lock);
	seq = iip->ili_commit_seq;
	spin_unlock(&iip->ili_lock);
	if (!seq)
		return;

	/* Give the log a push to start the unpinning I/O */
	xfs_log_force_seq(ip->i_mount, seq, 0, NULL);

}

static void
__xfs_iunpin_wait(
	struct xfs_inode	*ip)
{
	wait_queue_head_t *wq = bit_waitqueue(&ip->i_flags, __XFS_IPINNED_BIT);
	DEFINE_WAIT_BIT(wait, &ip->i_flags, __XFS_IPINNED_BIT);

	xfs_iunpin(ip);

	do {
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		if (xfs_ipincount(ip))
			io_schedule();
	} while (xfs_ipincount(ip));
	finish_wait(wq, &wait.wq_entry);
}

void
xfs_iunpin_wait(
	struct xfs_inode	*ip)
{
	if (xfs_ipincount(ip))
		__xfs_iunpin_wait(ip);
}

/*
 * Removing an inode from the namespace involves removing the directory entry
 * and dropping the link count on the inode. Removing the directory entry can
 * result in locking an AGF (directory blocks were freed) and removing a link
 * count can result in placing the inode on an unlinked list which results in
 * locking an AGI.
 *
 * The big problem here is that we have an ordering constraint on AGF and AGI
 * locking - inode allocation locks the AGI, then can allocate a new extent for
 * new inodes, locking the AGF after the AGI. Similarly, freeing the inode
 * removes the inode from the unlinked list, requiring that we lock the AGI
 * first, and then freeing the inode can result in an inode chunk being freed
 * and hence freeing disk space requiring that we lock an AGF.
 *
 * Hence the ordering that is imposed by other parts of the code is AGI before
 * AGF. This means we cannot remove the directory entry before we drop the inode
 * reference count and put it on the unlinked list as this results in a lock
 * order of AGF then AGI, and this can deadlock against inode allocation and
 * freeing. Therefore we must drop the link counts before we remove the
 * directory entry.
 *
 * This is still safe from a transactional point of view - it is not until we
 * get to xfs_defer_finish() that we have the possibility of multiple
 * transactions in this operation. Hence as long as we remove the directory
 * entry and drop the link count in the first transaction of the remove
 * operation, there are no transactional constraints on the ordering here.
 */
int
xfs_remove(
	struct xfs_inode	*dp,
	struct xfs_name		*name,
	struct xfs_inode	*ip)
{
	struct xfs_dir_update	du = {
		.dp		= dp,
		.name		= name,
		.ip		= ip,
	};
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_trans	*tp = NULL;
	int			is_dir = S_ISDIR(VFS_I(ip)->i_mode);
	int			dontcare;
	int                     error = 0;
	uint			resblks;
	/* sess13 FIX-C: bounded clean-trans retries for the post-lock child-AG
	 * acquire below (replaces the sess58 pre-lock hold — see comment there). */
	int			p13_tries = 0;
	/* P133 (ccloop c7ee71c6 sess2, RULE 4): stage timing for the tcp
	 * dlm_scaling unlink-pace collapse.  instr/dirwr-gated, capped. */
	u64			p133_t0 = 0, p133_tcommit = 0, p133_tdur = 0;
	bool			p133_durable = false;

	trace_xfs_remove(dp, name);

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		p133_t0 = ktime_get_ns();

	if (xfs_is_shutdown(mp))
		return -EIO;
	if (xfs_ifork_zapped(dp, XFS_DATA_FORK))
		return -EIO;

	/* ccloop c7ee71c6 sess3 (Phase A): never mutate a POISONED dead dir
	 * incarnation.  -ESTALE + prune; entry context, no locks held. */
	if (mp->m_mxfs_dlm && xfs_iflags_test(dp, MXFS_IF_INCARN_STALE)) {
		d_prune_aliases(VFS_I(dp));
		return -ESTALE;
	}

	error = xfs_qm_dqattach(dp);
	if (error)
		goto std_return;

	error = xfs_qm_dqattach(ip);
	if (error)
		goto std_return;

	error = xfs_parent_start(mp, &du.ppargs);
	if (error)
		goto std_return;

p13_retry:
	/*
	 * sess13 (MODE B fix): refresh a peer-stale SHORTFORM dir base BEFORE we
	 * take dp's ILOCK_EXCL in xfs_trans_alloc_dir — once ILOCK_EXCL is held
	 * mxfs_dlm_reload_inode can't run (needs i_lock EXCL) and the post-lock
	 * mxfs_dlm_dir_modify_refresh is a no-op for shortform (no data blocks).
	 */
	mxfs_dlm_dir_modify_reload_prelock(dp);

	/*
	 * We try to get the real space reservation first, allowing for
	 * directory btree deletion(s) implying possible bmap insert(s).  If we
	 * can't get the space reservation then we use 0 instead, and avoid the
	 * bmap btree insert(s) in the directory code by, if the bmap insert
	 * tries to happen, instead trimming the LAST block from the directory.
	 *
	 * Ignore EDQUOT and ENOSPC being returned via nospace_error because
	 * the directory code can handle a reservationless update and we don't
	 * want to prevent a user from trying to free space by deleting things.
	 */
	resblks = xfs_remove_space_res(mp, name->len);
	error = xfs_trans_alloc_dir(dp, &M_RES(mp)->tr_remove, ip, &resblks,
			&tp, &dontcare);
	if (error) {
		ASSERT(error != -ENOSPC);
		goto out_parent;
	}

	/*
	 * sess13 FIX-C (RULE-4 PROVEN, ladder-r16 P12-HOLDERTASK/P36-STACK):
	 * the sess58 pre-lock child-AG hold PARKED this task holding AG-EX
	 * while waiting for the dir's inode DLM lock inside
	 * xfs_trans_alloc_dir -> xfs_lock_two_inodes (captured stack: rm holds
	 * AG-0, blocked at mxfs_dlm_lock_retries on the hot dir).  A peer rm
	 * holding that dir in defer_finish then starves ~60s acquiring our AG
	 * -> rc=-110 -> dirty-cancel shutdown (the fence/netpartition/
	 * tcp_dlm_scaling triple-FAIL).  The pre-acquire didn't remove the
	 * hold-and-wait edge, it inverted it.
	 *
	 * Acquire the child's AG HERE instead: entry locks are already held,
	 * the transaction is still CLEAN, so an acquire timeout degrades to a
	 * clean cancel + bounded retry (never a shutdown), and NO task ever
	 * holds an AG grant while parked on an entry lock.  Release is
	 * deferred to commit/cancel (t_mxfs_ag_unlocks), which drives the
	 * drain-before-release exactly like the rename preacquire; the
	 * in-trans iunlink/difree acquires nest on the fast path as before.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		error = mxfs_trans_preacquire_inode_ags(tp, &ip, 1);
		if (error) {
			xfs_trans_cancel(tp);
			xfs_iunlock(ip, XFS_ILOCK_EXCL);
			xfs_iunlock(dp, XFS_ILOCK_EXCL);
			if (++p13_tries < 3) {
				pr_warn_ratelimited(
				    "mxfs: P13-CLEANRETRY remove dp=%llu ip=%llu try=%d rc=%d\n",
				    (unsigned long long)dp->i_ino,
				    (unsigned long long)ip->i_ino,
				    p13_tries, error);
				goto p13_retry;
			}
			goto out_parent;
		}
	}

	/*
	 * sess82: cross-node defensive re-validation BEFORE the transaction is
	 * dirtied.  Under concurrent multi-node modify of a SHARED directory a
	 * peer's RMW can durably erase our just-committed dirent from the on-disk
	 * dir block (the dir-block lost-update).  When that happens, the stock
	 * path dirties the transaction (xfs_droplink(ip) logs the inode) and only
	 * THEN calls xfs_dir_removename, which returns -ENOENT — forcing
	 * xfs_trans_cancel on a DIRTY transaction = "Corruption of in-memory data"
	 * FILESYSTEM SHUTDOWN (which also kills unrelated tests on this node).
	 * Re-read the dirent here, under the already-held dir ILOCK_EXCL + EX DLM
	 * (lock-free helper; FUA-fresh disk block), and if it is gone (or now
	 * points to a different inode), abort the still-CLEAN transaction — the
	 * unlink degrades to a benign -ENOENT ("rm: No such file") instead of a
	 * node-killing shutdown.  The underlying lost-update is a separate fix;
	 * this just stops it from being catastrophic.
	 */
	/*
	 * sess103: MODIFY-side acquire cold-read (the missing half of the
	 * sess98 PAIR — sess97 only added it to the READ path xfs_lookup).
	 * Before this transaction RMWs the shared dir block, drop our stale
	 * cached dir DATA blocks if a peer modified the dir since our last
	 * refresh, so xfs_dir_remove_child reads the peer's DURABLE committed
	 * image.  Without this, removing our own dirent from a stale base
	 * resurrected the peer's already-deleted dirents (all-nodes-agree
	 * durable lost-update in unlink_visibility).  Caller holds ILOCK_EXCL.
	 */
	mxfs_dlm_dir_modify_refresh(dp);

	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		xfs_ino_t	cur_ino = 0;
		int		lerr = xfs_dir_lookup_locked(tp, dp, name, &cur_ino);

		if (lerr == -ENOENT || (lerr == 0 && cur_ino != ip->i_ino)) {
			pr_warn_ratelimited(
			    "mxfs: REMOVE-REVALIDATE-MISS dp=%llu ip=%llu name=\"%.*s\" lookup_rc=%d cur_ino=%llu (clean-abort, no shutdown)\n",
			    (unsigned long long)dp->i_ino,
			    (unsigned long long)ip->i_ino,
			    name->len, (const char *)name->name, lerr,
			    (unsigned long long)cur_ino);
			error = -ENOENT;
			goto out_trans_cancel;
		}
	}

	error = xfs_dir_remove_child(tp, resblks, &du);
	if (error)
		goto out_trans_cancel;

	/*
	 * If this is a synchronous mount, make sure that the
	 * remove transaction goes to disk before returning to
	 * the user.
	 */
	if (xfs_has_wsync(mp) || xfs_has_dirsync(mp))
		xfs_trans_set_sync(tp);

	error = xfs_trans_commit(tp);
	if (error)
		goto out_unlock;
	if (unlikely(p133_t0))
		p133_tcommit = ktime_get_ns();

	/*
	 * sess97: PUBLISH-BEFORE-NOTIFY (dir-block lost-update fix).
	 *
	 * PROVEN root (sess96, RULE 4): under 4-node concurrent rename/unlink of
	 * a SHARED directory, a node's NEXT modify works from its own
	 * pinned-stale dir buffer (DIR-STALE-SKIP at xfs_da_btree.c:3001 — the
	 * read-time gen-invalidation CANNOT re-read a PINNED buffer, so it keeps
	 * the stale local copy, RMWs it, and on checkpoint durably clobbers a
	 * peer's committed dirent).  The buffer is pinned by THIS node's own
	 * prior committed-not-checkpointed dir op.
	 *
	 * Fix it on the WRITE side (both ask_gemini ×2 and ask_gpt converge
	 * here; acquire/read-side refresh is FATAL — it clobbers the peer):
	 * right after our commit, with dp ILOCK_EXCL + the dir EX DLM lock still
	 * held (so no peer can be concurrently modifying and our buffer holds
	 * ONLY our own just-committed change — it cannot be missing a peer's
	 * entry), force the dir's CIL to the log and xfs_buf_wait_unpin + write
	 * the modified dir DATA blocks to the shared LUN.  This UNPINS the
	 * buffer, so at our NEXT acquire the read-time invalidation takes the
	 * re-read branch (xfs_da_btree.c:2999) instead of the pinned SKIP — the
	 * fix is self-reinforcing.  Differs from the sess96 release-side flush
	 * (REVERTED): that ran at BAST handoff where the buffer could already be
	 * stale from a failed pinned re-read; at commit it is always fresh.
	 */
	mxfs_dlm_dir_durable_signal(dp);

	if (is_dir && xfs_inode_is_filestream(ip))
		xfs_filestream_deassociate(ip);

	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	/*
	 * sess9: make the SHORTFORM parent's just-committed REMOVAL durable on
	 * its on-disk inode cluster (mirror xfs_create's add-side flush at the
	 * end of this file).  Without it, the removal is only logged/AIL-resident
	 * while mxfs_dlm_dir_durable_signal (v0.5.1 PUBLISH-ONLY) notifies peers;
	 * an eviction-ring consumer / peer reload then cold-reads the STALE
	 * on-disk cluster (dirent still present) and durably RESURRECTS it (the
	 * dlm_fairness / tcp_dlm_scaling "shared dir drained got=N" + crash_-
	 * consistency leftover).  ILOCK is dropped (required by the helper); the
	 * helper no-ops unless the parent is a multi-node shortform dir, and the
	 * !self_created gate keeps rsync's node-private dirs free (the v0.5.4
	 * perf carve-out, identical to the create path).
	 */
	/* sess48: also fire for a CONTENDED dir (gen>0) even if self-created —
	 * see the matching note in xfs_create.  This is the uv shortform-delete
	 * durability gap: node2's last 10 deletes happen after the block->sf
	 * conversion, so the data-block publish (durable_signal) no-ops and only
	 * this inode-cluster flush makes node2's removal visible to node1. */
	/*
	 * sess54 (ccloop 8ddb16a2) PROVEN FIX: pin dp's DLM-EX grant across the
	 * ILOCK-dropped durable flush.  Decide the durable gate and bump the extra
	 * holder WHILE we still hold dp ILOCK_EXCL (so we provably hold EX and
	 * bast_process — which needs holders==0 — cannot release us).  Then drop
	 * ILOCK (the flush co-acquires i_lock SHARED), flush, and drop the extra
	 * holder, which fires any deferred BAST through the sanctioned RELFLUSH
	 * drain.  Without the pin, a concurrent peer BAST demotes us mid-flush and
	 * the P119 non-EX guard discards this removal (P119-NONEX-FLUSH-SKIP
	 * comm=rm) -> stale on-disk dirent survives -> durable resurrection.
	 */
	{
		extern int mxfs_dirop_sync_barrier;	/* sess14 D2 lever */
		bool dp_durable = mxfs_dirop_sync_barrier &&
			(!dp->i_mxfs_self_created || dp->i_dlm_dir_gen > 0);

		p133_durable = dp_durable;
		if (dp_durable)
			mxfs_dlm_dir_hold_ex(dp);
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
		if (dp_durable) {
			mxfs_dlm_dir_inode_durable(dp);
			mxfs_dlm_ilock_end(dp, MXFS_LOCK_EX);
		}
	}
	if (unlikely(p133_t0)) {
		static atomic_t p133_n = ATOMIC_INIT(0);

		p133_tdur = ktime_get_ns();
		if (atomic_inc_return(&p133_n) <= 2000)
			pr_warn("mxfs: P133-REMOVE ino=%llu parent=%llu durable=%d self_created=%d dgen=%llu pfmt=%d commit_ms=%llu pdur_ms=%llu\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)dp->i_ino,
				p133_durable ? 1 : 0,
				dp->i_mxfs_self_created ? 1 : 0,
				(unsigned long long)dp->i_dlm_dir_gen,
				dp->i_df.if_format,
				(p133_tcommit - p133_t0) / NSEC_PER_MSEC,
				(p133_tdur - p133_tcommit) / NSEC_PER_MSEC);
	}
	xfs_parent_finish(mp, du.ppargs);
	/* sess4(a16ec5f2): route through std_return so the P4X-UNLINK ledger
	 * records SUCCESSFUL removes too (it only saw error exits before). */
	error = 0;
	goto std_return;

 out_trans_cancel:
	xfs_trans_cancel(tp);
 out_unlock:
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
 out_parent:
	xfs_parent_finish(mp, du.ppargs);
 std_return:
	/* sess4(a16ec5f2) UNLINK ledger (RULE 4): run22's dangling-dirent
	 * autopsy (dirent durable, dinode free on disk, P29 chain shows the
	 * removal NEVER left this node in any submitted image) needs the
	 * remove-side event stream P51-MOD provides for adds: who unlinked
	 * what, when, with what outcome. */
	{
		extern int mxfs_dirwr_enabled;

		if (unlikely(mxfs_dirwr_enabled) && dp->i_ino <= 256 &&
		    mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			static atomic_t p4x_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p4x_n) <= 200000)
				pr_warn("mxfs: P4X-UNLINK pino=%llu name=[%.*s] cino=%llu err=%d nlink=%u comm=%s realns=%llu\n",
					(unsigned long long)dp->i_ino,
					name->len, name->name,
					(unsigned long long)ip->i_ino, error,
					VFS_I(ip)->i_nlink, current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
	}
	return error;
}

static inline void
xfs_iunlock_rename(
	struct xfs_inode	**i_tab,
	int			num_inodes)
{
	int			i;

	for (i = num_inodes - 1; i >= 0; i--) {
		/* Skip duplicate inodes if src and target dps are the same */
		if (!i_tab[i] || (i > 0 && i_tab[i] == i_tab[i - 1]))
			continue;
		xfs_iunlock(i_tab[i], XFS_ILOCK_EXCL);
	}
}

/*
 * Enter all inodes for a rename transaction into a sorted array.
 */
#define __XFS_SORT_INODES	5
STATIC void
xfs_sort_for_rename(
	struct xfs_inode	*dp1,	/* in: old (source) directory inode */
	struct xfs_inode	*dp2,	/* in: new (target) directory inode */
	struct xfs_inode	*ip1,	/* in: inode of old entry */
	struct xfs_inode	*ip2,	/* in: inode of new entry */
	struct xfs_inode	*wip,	/* in: whiteout inode */
	struct xfs_inode	**i_tab,/* out: sorted array of inodes */
	int			*num_inodes)  /* in/out: inodes in array */
{
	int			i;

	ASSERT(*num_inodes == __XFS_SORT_INODES);
	memset(i_tab, 0, *num_inodes * sizeof(struct xfs_inode *));

	/*
	 * i_tab contains a list of pointers to inodes.  We initialize
	 * the table here & we'll sort it.  We will then use it to
	 * order the acquisition of the inode locks.
	 *
	 * Note that the table may contain duplicates.  e.g., dp1 == dp2.
	 */
	i = 0;
	i_tab[i++] = dp1;
	i_tab[i++] = dp2;
	i_tab[i++] = ip1;
	if (ip2)
		i_tab[i++] = ip2;
	if (wip)
		i_tab[i++] = wip;
	*num_inodes = i;

	xfs_sort_inodes(i_tab, *num_inodes);
}

void
xfs_sort_inodes(
	struct xfs_inode	**i_tab,
	unsigned int		num_inodes)
{
	int			i, j;

	ASSERT(num_inodes <= __XFS_SORT_INODES);

	/*
	 * Sort the elements via bubble sort.  (Remember, there are at
	 * most 5 elements to sort, so this is adequate.)
	 */
	for (i = 0; i < num_inodes; i++) {
		for (j = 1; j < num_inodes; j++) {
			if (i_tab[j]->i_ino < i_tab[j-1]->i_ino)
				swap(i_tab[j], i_tab[j - 1]);
		}
	}
}

/*
 * xfs_rename_alloc_whiteout()
 *
 * Return a referenced, unlinked, unlocked inode that can be used as a
 * whiteout in a rename transaction. We use a tmpfile inode here so that if we
 * crash between allocating the inode and linking it into the rename transaction
 * recovery will free the inode and we won't leak it.
 */
static int
xfs_rename_alloc_whiteout(
	struct mnt_idmap	*idmap,
	struct xfs_name		*src_name,
	struct xfs_inode	*dp,
	struct xfs_inode	**wip)
{
	struct xfs_icreate_args	args = {
		.idmap		= idmap,
		.pip		= dp,
		.mode		= S_IFCHR | WHITEOUT_MODE,
		.flags		= XFS_ICREATE_TMPFILE,
	};
	struct xfs_inode	*tmpfile;
	struct qstr		name;
	int			error;

	error = xfs_create_tmpfile(&args, &tmpfile);
	if (error)
		return error;

	name.name = src_name->name;
	name.len = src_name->len;
	error = xfs_inode_init_security(VFS_I(tmpfile), VFS_I(dp), &name);
	if (error) {
		xfs_finish_inode_setup(tmpfile);
		xfs_irele(tmpfile);
		return error;
	}

	/*
	 * Prepare the tmpfile inode as if it were created through the VFS.
	 * Complete the inode setup and flag it as linkable.  nlink is already
	 * zero, so we can skip the drop_nlink.
	 */
	xfs_setup_iops(tmpfile);
	xfs_finish_inode_setup(tmpfile);
	inode_state_set_raw(VFS_I(tmpfile), I_LINKABLE);

	*wip = tmpfile;
	return 0;
}

/*
 * xfs_rename
 */
int
xfs_rename(
	struct mnt_idmap	*idmap,
	struct xfs_inode	*src_dp,
	struct xfs_name		*src_name,
	struct xfs_inode	*src_ip,
	struct xfs_inode	*target_dp,
	struct xfs_name		*target_name,
	struct xfs_inode	*target_ip,
	unsigned int		flags)
{
	struct xfs_dir_update	du_src = {
		.dp		= src_dp,
		.name		= src_name,
		.ip		= src_ip,
	};
	struct xfs_dir_update	du_tgt = {
		.dp		= target_dp,
		.name		= target_name,
		.ip		= target_ip,
	};
	struct xfs_dir_update	du_wip = { };
	struct xfs_mount	*mp = src_dp->i_mount;
	struct xfs_trans	*tp;
	struct xfs_inode	*inodes[__XFS_SORT_INODES];
	int			i;
	int			num_inodes = __XFS_SORT_INODES;
	bool			new_parent = (src_dp != target_dp);
	bool			src_is_directory = S_ISDIR(VFS_I(src_ip)->i_mode);
	int			spaceres;
	bool			retried = false;
	int			error, nospace_error = 0;

	trace_xfs_rename(src_dp, target_dp, src_name, target_name);

	/* sess45 P217 cookie (D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361):
	 * src-dir image identity captured at the pre-dirty preflight; logged
	 * with the failure on any dirty cancel so a below-locks image swap
	 * (revalidate saw the name, helper later missed it) is measured, not
	 * inferred.  Zero cost off the error path. */
	u64	p217_src_iv = 0;
	u32	p217_src_bytes = 0, p217_src_ve = 0;
	u64	p217_src_dgen = 0;
	s8	p217_src_fmt = -1;
	bool	p217_armed = false;

	if ((flags & RENAME_EXCHANGE) && !target_ip)
		return -EINVAL;

	/* ccloop c7ee71c6 sess3 (Phase A): refuse renames touching a
	 * POISONED dead dir incarnation (either side).  -ESTALE + prune;
	 * entry context, no locks/txn held yet. */
	if (mp->m_mxfs_dlm) {
		if (xfs_iflags_test(src_dp, MXFS_IF_INCARN_STALE)) {
			d_prune_aliases(VFS_I(src_dp));
			return -ESTALE;
		}
		if (xfs_iflags_test(target_dp, MXFS_IF_INCARN_STALE)) {
			d_prune_aliases(VFS_I(target_dp));
			return -ESTALE;
		}
	}

	/*
	 * v0.5.6 (sess29 ccloop 14d31183): a CROSS-directory rename moves a
	 * still-unpublished inode out from under its recorded
	 * i_mxfs_unpub_parent, so the scoped BAST publish drain of the NEW
	 * parent would miss it — a peer could reach it through target_dp's
	 * release and acquire its empty CAW slot cleanly (the sess107 hole).
	 * Force a synchronous publish before any dirent moves (no locks/txn
	 * held yet; no-op when already published).  Same-dir renames (the
	 * rsync temp-file → final-name hot path) keep their parent and skip
	 * this.  RENAME_EXCHANGE moves target_ip into src_dp, so cover it
	 * too.  A RENAME_WHITEOUT wip is created with parent 0 (in scope of
	 * every drain) and needs nothing here.
	 */
	if (src_dp != target_dp) {
		if (src_ip->i_dlm_unpublished)
			mxfs_dlm_publish_inode(src_ip);
		if (target_ip && target_ip->i_dlm_unpublished)
			mxfs_dlm_publish_inode(target_ip);
	}

	/*
	 * If we are doing a whiteout operation, allocate the whiteout inode
	 * we will be placing at the target and ensure the type is set
	 * appropriately.
	 */
	if (flags & RENAME_WHITEOUT) {
		error = xfs_rename_alloc_whiteout(idmap, src_name, target_dp,
				&du_wip.ip);
		if (error)
			return error;

		/* setup target dirent info as whiteout */
		src_name->type = XFS_DIR3_FT_CHRDEV;
	}

	xfs_sort_for_rename(src_dp, target_dp, src_ip, target_ip, du_wip.ip,
			inodes, &num_inodes);

	error = xfs_parent_start(mp, &du_src.ppargs);
	if (error)
		goto out_release_wip;

	if (du_wip.ip) {
		error = xfs_parent_start(mp, &du_wip.ppargs);
		if (error)
			goto out_src_ppargs;
	}

	if (target_ip) {
		error = xfs_parent_start(mp, &du_tgt.ppargs);
		if (error)
			goto out_wip_ppargs;
	}

	/*
	 * sess13 (MODE B fix): refresh peer-stale SHORTFORM src/target dir bases
	 * BEFORE the rename takes their ILOCK_EXCL.  The .done-add of a rename was
	 * the proven P58-STALE-BASE-ADD resurrection site — once ILOCK_EXCL is
	 * held mxfs_dlm_reload_inode can't run and the post-lock data-block
	 * refresh is a no-op for shortform dirs.
	 */
	mxfs_dlm_dir_modify_reload_prelock(src_dp);
	if (target_dp && target_dp != src_dp)
		mxfs_dlm_dir_modify_reload_prelock(target_dp);

retry:
	nospace_error = 0;
	spaceres = xfs_rename_space_res(mp, src_name->len, target_ip != NULL,
			target_name->len, du_wip.ip != NULL);
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_rename, spaceres, 0, 0, &tp);
	if (error == -ENOSPC) {
		nospace_error = error;
		spaceres = 0;
		error = xfs_trans_alloc(mp, &M_RES(mp)->tr_rename, 0, 0, 0,
				&tp);
	}
	if (error)
		goto out_tgt_ppargs;

	/*
	 * We don't allow reservationless renaming when parent pointers are
	 * enabled because we can't back out if the xattrs must grow.
	 */
	if (du_src.ppargs && nospace_error) {
		error = nospace_error;
		xfs_trans_cancel(tp);
		goto out_tgt_ppargs;
	}

	/*
	 * Attach the dquots to the inodes
	 */
	error = xfs_qm_vop_rename_dqattach(inodes);
	if (error) {
		xfs_trans_cancel(tp);
		goto out_tgt_ppargs;
	}

	/*
	 * Lock all the participating inodes. Depending upon whether
	 * the target_name exists in the target directory, and
	 * whether the target directory is the same as the source
	 * directory, we can lock from 2 to 5 inodes.
	 */
	xfs_lock_inodes(inodes, num_inodes, XFS_ILOCK_EXCL);

	/*
	 * Join all the inodes to the transaction.
	 */
	xfs_trans_ijoin(tp, src_dp, 0);
	if (new_parent)
		xfs_trans_ijoin(tp, target_dp, 0);
	xfs_trans_ijoin(tp, src_ip, 0);
	if (target_ip)
		xfs_trans_ijoin(tp, target_ip, 0);
	if (du_wip.ip)
		xfs_trans_ijoin(tp, du_wip.ip, 0);

	/*
	 * MXFS sess77 (repositioned sess13 FIX-C): acquire the per-AG DLM
	 * grants for every participating inode's AG, ascending, so the deep
	 * allocator/defer acquires below nest on the fast path and never
	 * block cross-node with the transaction DIRTY (120s timeout -> dirty
	 * cancel -> shutdown).  The transaction is still clean here, so a
	 * (rare) acquire failure is a clean cancel with no shutdown.
	 *
	 * sess13 FIX-C: this call used to sit BEFORE xfs_lock_inodes, which
	 * parked this task holding AG grants while waiting for entry-lock DLM
	 * grants — the exact hold-and-wait edge (mirror of the xfs_remove
	 * sess58 pre-lock hold, see the P12-HOLDERTASK stack there) that
	 * starved peers' defer_finish AG acquires into rc=-110 shutdowns.
	 * Entry locks FIRST, then AG grants under a still-clean transaction.
	 */
	error = mxfs_trans_preacquire_inode_ags(tp, inodes, num_inodes);
	if (error)
		goto out_trans_cancel;

	error = xfs_projid_differ(target_dp, src_ip);
	if (error)
		goto out_trans_cancel;

	/*
	 * sess104: MODIFY-side acquire cold-read for rename (mirror of the
	 * xfs_remove fix at line ~2839).  Both src_dp and target_dp ILOCKs are
	 * held EXCL here.  Before this transaction RMWs either shared dir block
	 * (xfs_dir_rename_children / xfs_dir_exchange_children below), drop our
	 * stale cached dir DATA blocks if a peer modified the dir since our last
	 * refresh, so the rename reads the peer's DURABLE committed image.
	 * Without this, adding our renamed dirent (or removing the old name)
	 * from a stale base resurrected/clobbered the peer's already-committed
	 * dirents -> all-nodes-agree durable lost-update (one node's renamed
	 * files invisible to every node in rename_visibility).
	 */
	mxfs_dlm_dir_modify_refresh(src_dp);
	if (new_parent)
		mxfs_dlm_dir_modify_refresh(target_dp);

	/*
	 * sess8 (2/tcp): pre-dirty source/target-name revalidation — the rename
	 * mirror of the xfs_remove guard at ~3481.  PROVEN (build E8BF16B2,
	 * 2-node tcp dlm_fairness in the cumulative full suite): under concurrent
	 * multi-node modify of a SHARED directory a peer's RMW can durably erase
	 * the SOURCE dirent we are about to rename.  xfs_dir_rename_children
	 * creates the TARGET name first (xfs_dir_createname/replace — this DIRTIES
	 * the transaction) and only THEN removes the SOURCE name
	 * (xfs_dir_removename), which returns -ENOENT when the source dirent is
	 * gone -> xfs_dir_rename_children returns error -> xfs_rename runs
	 * xfs_trans_cancel on a DIRTY transaction = "Corruption of in-memory data
	 * (0x8) ... xfs_trans_cancel at xfs_rename+0x90b" FILESYSTEM SHUTDOWN,
	 * which also kills every unrelated test on this node (the full-suite
	 * cascade).  Re-read the names here, under the already-held dir
	 * ILOCK_EXCL + EX DLM (FUA-fresh disk block, transaction still CLEAN), and
	 * if the source is gone / now points to a different inode (or, for
	 * RENAME_EXCHANGE, the target moved) abort the clean transaction: the
	 * rename degrades to a benign -ENOENT instead of a node-killing shutdown.
	 * The underlying durable lost-update is a separate fix; this stops it from
	 * being catastrophic.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		xfs_ino_t	cur_src = 0;
		int		serr = xfs_dir_lookup_locked(tp, src_dp,
							     src_name, &cur_src);

		if (serr == -ENOENT ||
		    (serr == 0 && cur_src != src_ip->i_ino)) {
			pr_warn_ratelimited(
			    "mxfs: RENAME-REVALIDATE-MISS src_dp=%llu src_ip=%llu name=\"%.*s\" lookup_rc=%d cur_ino=%llu (clean-abort, no shutdown)\n",
			    (unsigned long long)src_dp->i_ino,
			    (unsigned long long)src_ip->i_ino,
			    src_name->len, (const char *)src_name->name, serr,
			    (unsigned long long)cur_src);
			error = -ENOENT;
			goto out_trans_cancel;
		}

		if ((flags & RENAME_EXCHANGE) && target_ip) {
			xfs_ino_t	cur_tgt = 0;
			int		terr = xfs_dir_lookup_locked(tp,
						target_dp, target_name,
						&cur_tgt);

			if (terr == -ENOENT ||
			    (terr == 0 && cur_tgt != target_ip->i_ino)) {
				pr_warn_ratelimited(
				    "mxfs: RENAME-REVALIDATE-MISS-TGT target_dp=%llu target_ip=%llu name=\"%.*s\" lookup_rc=%d cur_ino=%llu (clean-abort, no shutdown)\n",
				    (unsigned long long)target_dp->i_ino,
				    (unsigned long long)target_ip->i_ino,
				    target_name->len,
				    (const char *)target_name->name, terr,
				    (unsigned long long)cur_tgt);
				error = -ENOENT;
				goto out_trans_cancel;
			}
		}

		/*
		 * sess45 (D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361, GPT
		 * RULE-5 ruling) — FULL target-expectation preflight for the
		 * NON-exchange case, which the guard above left unguarded and
		 * which is the classic rsync temp->existing-final rename:
		 * xfs_dir_rename_children dirties the transaction (target
		 * replace / timestamps) BEFORE it can discover the target
		 * dirent no longer matches the VFS snapshot, and a helper
		 * -ENOENT then cancels a DIRTY transaction = 0x8 forced
		 * shutdown (17 of 32 nodes at once under rsync_paired).
		 *
		 * Both polarities are checked: a VFS-known target that
		 * vanished or now names a DIFFERENT inode, and a VFS-absent
		 * target that a peer has meanwhile created (the symmetric
		 * createname -EEXIST hazard).  The correct degrade is a
		 * RESTART, not user-visible ENOENT: a vanished target should
		 * let the rename SUCCEED as a plain rename after re-walk.
		 * -ESTALE is exactly that contract — do_renameat2's
		 * retry_estale re-walks BOTH names with LOOKUP_REVAL and
		 * retries the whole operation on fresh dentries, and MXFS
		 * already returns -ESTALE for cross-node dentry staleness
		 * elsewhere.  Transaction is still clean here (asserted), so
		 * the abort is benign; wip was allocated in its OWN earlier
		 * transaction and is disposed by the shared unwind.
		 */
		if (!(flags & RENAME_EXCHANGE)) {
			xfs_ino_t	cur_tgt = 0;
			int		terr = xfs_dir_lookup_locked(tp,
						target_dp, target_name,
						&cur_tgt);
			bool		mismatch;

			if (target_ip)
				mismatch = (terr == -ENOENT ||
					    (terr == 0 &&
					     cur_tgt != target_ip->i_ino));
			else
				mismatch = (terr == 0);
			if (mismatch) {
				static atomic_t p217r = ATOMIC_INIT(0);

				if (atomic_inc_return(&p217r) <= 2000)
					pr_warn("mxfs: P217-RENAME-TGT-PREFLIGHT target_dp=%llu vfs_tgt=%llu name=\"%.*s\" lookup_rc=%d cur_ino=%llu dirty=%d — target expectation stale under held locks; -ESTALE restart (retry_estale re-walk), no shutdown\n",
						(unsigned long long)target_dp->i_ino,
						(unsigned long long)(target_ip ?
							target_ip->i_ino : 0),
						target_name->len,
						(const char *)target_name->name,
						terr,
						(unsigned long long)cur_tgt,
						(tp->t_flags & XFS_TRANS_DIRTY) ?
							1 : 0);
				WARN_ON_ONCE(tp->t_flags & XFS_TRANS_DIRTY);
				error = -ESTALE;
				goto out_trans_cancel;
			}
		}

		/* sess45 P217 cookie: the preflight just proved the names
		 * coherent with the held-lock image — snapshot that image's
		 * identity for the dirty-cancel probe. */
		p217_src_iv = inode_peek_iversion(VFS_I(src_dp));
		p217_src_bytes = src_dp->i_df.if_bytes;
		p217_src_ve = src_dp->i_dlm_dir_valid_epoch;
		p217_src_dgen = src_dp->i_dlm_dir_gen;
		p217_src_fmt = src_dp->i_df.if_format;
		p217_armed = true;
	}

	/*
	 * ccloop c7ee71c6 sess27 — D-DIRENT-INODE-TYPE-MISMATCH PRODUCER PROBE
	 * (P206-RENAME-FTYPE-STALE), with the candidate fix behind
	 * mxfs.rename_ftype_revalidate so one build can measure both arms.
	 *
	 * xfs_vn_rename computes the NEW dirent's ftype from
	 * d_inode(odentry)->i_mode and passes it in as target_name->type —
	 * BEFORE xfs_rename takes a single inode lock.  Upstream XFS is safe
	 * there because a live inode's S_IFMT never changes.  In MXFS it can:
	 * the xfs_lock_inodes above reloads a stale inode from the platter
	 * (xfs_inode_from_disk + xfs_setup_iops), and the whole type-flip
	 * machinery exists precisely because an inode number can come back as a
	 * different type once a peer freed and reallocated it.  So the pre-lock
	 * snapshot can already be wrong by the time xfs_dir_rename_children
	 * writes it — producing a dirent whose ftype contradicts the inode it
	 * names, which is exactly the captured signature (dirent REG, inode DIR,
	 * SAME incarnation — i.e. not the lookup racing a reuse).
	 *
	 * src_is_directory is snapshotted from the same pre-lock read and drives
	 * the AGI-read loop and the parent-nlink handling below, so it is
	 * corrected on the same evidence.
	 */
	{
		unsigned char	live_ft =
			xfs_mode_to_ftype(VFS_I(src_ip)->i_mode);

		if (target_name->type != XFS_DIR3_FT_UNKNOWN &&
		    live_ft != XFS_DIR3_FT_UNKNOWN &&
		    target_name->type != live_ft) {
			static atomic_t	p206n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p206n) <= 400)
				pr_warn("mxfs: P206-RENAME-FTYPE-STALE src_ip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d dlm_mode=%d src_is_directory=%d src_dp=%llu target_dp=%llu reval=%d comm=%s — dirent ftype snapshotted before the ILOCK contradicts the inode's post-reload type\n",
					(unsigned long long)src_ip->i_ino,
					target_name->len,
					(const char *)target_name->name,
					(unsigned)target_name->type,
					(unsigned)live_ft,
					(unsigned)VFS_I(src_ip)->i_mode,
					(unsigned)VFS_I(src_ip)->i_generation,
					src_ip->i_dlm_stale ? 1 : 0,
					src_ip->i_dlm_mode,
					src_is_directory ? 1 : 0,
					(unsigned long long)src_dp->i_ino,
					(unsigned long long)target_dp->i_ino,
					mxfs_rename_ftype_revalidate,
					current->comm);
			if (mxfs_rename_ftype_revalidate) {
				target_name->type = live_ft;
				src_is_directory =
					S_ISDIR(VFS_I(src_ip)->i_mode);
			}
		}

		/*
		 * RENAME_EXCHANGE additionally writes src_name with the TARGET
		 * inode's type, snapshotted from the same pre-lock read.
		 */
		if ((flags & RENAME_EXCHANGE) && target_ip) {
			unsigned char	live_sft =
				xfs_mode_to_ftype(VFS_I(target_ip)->i_mode);

			if (src_name->type != XFS_DIR3_FT_UNKNOWN &&
			    live_sft != XFS_DIR3_FT_UNKNOWN &&
			    src_name->type != live_sft) {
				static atomic_t	p206xn = ATOMIC_INIT(0);

				if (atomic_inc_return(&p206xn) <= 400)
					pr_warn("mxfs: P206-EXCHANGE-FTYPE-STALE target_ip=%llu name=\"%.*s\" write_ft=%u live_ft=%u live_mode=0%o gen=%u stale=%d reval=%d comm=%s\n",
						(unsigned long long)target_ip->i_ino,
						src_name->len,
						(const char *)src_name->name,
						(unsigned)src_name->type,
						(unsigned)live_sft,
						(unsigned)VFS_I(target_ip)->i_mode,
						(unsigned)VFS_I(target_ip)->i_generation,
						target_ip->i_dlm_stale ? 1 : 0,
						mxfs_rename_ftype_revalidate,
						current->comm);
				if (mxfs_rename_ftype_revalidate)
					src_name->type = live_sft;
			}
		}
	}

	/* RENAME_EXCHANGE is unique from here on. */
	if (flags & RENAME_EXCHANGE) {
		error = xfs_dir_exchange_children(tp, &du_src, &du_tgt,
				spaceres);
		if (error)
			goto out_trans_cancel;
		goto out_commit;
	}

	/*
	 * Try to reserve quota to handle an expansion of the target directory.
	 * We'll allow the rename to continue in reservationless mode if we hit
	 * a space usage constraint.  If we trigger reservationless mode, save
	 * the errno if there isn't any free space in the target directory.
	 */
	if (spaceres != 0) {
		error = xfs_trans_reserve_quota_nblks(tp, target_dp, spaceres,
				0, false);
		if (error == -EDQUOT || error == -ENOSPC) {
			if (!retried) {
				xfs_trans_cancel(tp);
				xfs_iunlock_rename(inodes, num_inodes);
				xfs_blockgc_free_quota(target_dp, 0);
				retried = true;
				goto retry;
			}

			nospace_error = error;
			spaceres = 0;
			error = 0;
		}
		if (error)
			goto out_trans_cancel;
	}

	/*
	 * We don't allow quotaless renaming when parent pointers are enabled
	 * because we can't back out if the xattrs must grow.
	 */
	if (du_src.ppargs && nospace_error) {
		error = nospace_error;
		goto out_trans_cancel;
	}

	/*
	 * Lock the AGI buffers we need to handle bumping the nlink of the
	 * whiteout inode off the unlinked list and to handle dropping the
	 * nlink of the target inode.  Per locking order rules, do this in
	 * increasing AG order and before directory block allocation tries to
	 * grab AGFs because we grab AGIs before AGFs.
	 *
	 * The (vfs) caller must ensure that if src is a directory then
	 * target_ip is either null or an empty directory.
	 */
	for (i = 0; i < num_inodes && inodes[i] != NULL; i++) {
		if (inodes[i] == du_wip.ip ||
		    (inodes[i] == target_ip &&
		     (VFS_I(target_ip)->i_nlink == 1 || src_is_directory))) {
			struct xfs_perag	*pag;
			struct xfs_buf		*bp;

			pag = xfs_perag_get(mp,
					XFS_INO_TO_AGNO(mp, inodes[i]->i_ino));
			error = xfs_read_agi(pag, tp, 0, &bp);
			xfs_perag_put(pag);
			if (error)
				goto out_trans_cancel;
		}
	}

	error = xfs_dir_rename_children(tp, &du_src, &du_tgt, spaceres,
			&du_wip);
	if (error)
		goto out_trans_cancel;

	if (du_wip.ip) {
		/*
		 * Now we have a real link, clear the "I'm a tmpfile" state
		 * flag from the inode so it doesn't accidentally get misused in
		 * future.
		 */
		inode_state_clear_raw(VFS_I(du_wip.ip), I_LINKABLE);
	}

out_commit:
	/*
	 * If this is a synchronous mount, make sure that the rename
	 * transaction goes to disk before returning to the user.
	 */
	if (xfs_has_wsync(tp->t_mountp) || xfs_has_dirsync(tp->t_mountp))
		xfs_trans_set_sync(tp);

	error = xfs_trans_commit(tp);
	nospace_error = 0;

	/*
	 * sess97: PUBLISH-BEFORE-NOTIFY — rename is the worst lost-update case
	 * (it touches src_dp via removename and target_dp via createname/replace).
	 * With both dir ILOCKs still held (released below by xfs_iunlock_rename),
	 * flush each modified dir's data blocks to the shared LUN so the next
	 * acquirer re-reads fresh.  See the long note in xfs_remove.
	 */
	if (!error) {
		mxfs_dlm_dir_durable_signal(src_dp);
		if (target_dp != src_dp)
			mxfs_dlm_dir_durable_signal(target_dp);
	}
	goto out_unlock;

out_trans_cancel:
	/*
	 * sess45 P217-RENAME-DIRTYCANCEL (GPT item: "instrument the exact first
	 * failing helper").  Any cancel arriving DIRTY is the 0x8 shutdown about
	 * to happen — name the errno the helper chain returned and compare the
	 * src-dir image identity against the preflight cookie: same-iversion
	 * with a changed byte-count/format = the image was swapped BELOW the
	 * held ILOCK_EXCL+EX (the producer class); advanced iversion = our own
	 * transaction chain mutated it before failing (helper-order class).
	 */
	if (unlikely((tp->t_flags & XFS_TRANS_DIRTY) &&
		     mp->m_mxfs_dlm &&
		     !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))) {
		static atomic_t p217n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p217n) <= 400)
			pr_warn("mxfs: P217-RENAME-DIRTYCANCEL rc=%d src_dp=%llu tgt_dp=%llu src=\"%.*s\" tgt=\"%.*s\" armed=%d pre[iv=%llu bytes=%u fmt=%d dgen=%llu ve=%u] now[iv=%llu bytes=%u fmt=%d dgen=%llu ve=%u] exch=%d wip=%d comm=%s — dirty cancel imminent (0x8 shutdown); cookie names the class\n",
				error,
				(unsigned long long)src_dp->i_ino,
				(unsigned long long)target_dp->i_ino,
				src_name->len, (const char *)src_name->name,
				target_name->len,
				(const char *)target_name->name,
				p217_armed ? 1 : 0,
				(unsigned long long)p217_src_iv,
				p217_src_bytes, p217_src_fmt,
				(unsigned long long)p217_src_dgen,
				p217_src_ve,
				(unsigned long long)inode_peek_iversion(VFS_I(src_dp)),
				src_dp->i_df.if_bytes,
				src_dp->i_df.if_format,
				(unsigned long long)src_dp->i_dlm_dir_gen,
				src_dp->i_dlm_dir_valid_epoch,
				(flags & RENAME_EXCHANGE) ? 1 : 0,
				du_wip.ip ? 1 : 0, current->comm);
	}
	xfs_trans_cancel(tp);
out_unlock:
	/*
	 * sess9: make each SHORTFORM rename-dir's just-committed change durable
	 * on its on-disk inode cluster (mirror xfs_create / xfs_remove).  Rename
	 * is the worst lost-update case: the source-dir's REMOVAL of the old name
	 * must be destaged, else a peer / eviction-ring re-read cold-reads the
	 * stale cluster and durably RESURRECTS the renamed-away dirent (the
	 * dlm_fairness `mv n_rX n_rX.done` leftover).  ILOCK dropped below;
	 * success path only; !self_created keeps rsync's node-private dirs free.
	 *
	 * sess54 (ccloop 8ddb16a2) PROVEN FIX: pin each dir's DLM-EX grant across
	 * the ILOCK-dropped durable flush.  The `mv` source-name removal was being
	 * discarded by the P119 non-EX guard (P119-NONEX-FLUSH-SKIP comm=mv) when a
	 * concurrent peer BAST demoted us in the window between xfs_iunlock_rename
	 * and the flush -> the source name survived on disk -> durable resurrection
	 * (tcp_dlm_scaling "drained got=N", leftover = base names n2_rN).  Bump the
	 * extra EX holder WHILE we still hold ILOCK_EXCL (so bast_process, which
	 * needs holders==0, cannot release us), drop ILOCK, flush, then drop the
	 * holder (fires any deferred BAST through the sanctioned RELFLUSH drain).
	 */
	{
		extern int mxfs_dirop_sync_barrier;	/* sess14 D2 lever */
		bool src_pin = !error && src_dp && mxfs_dirop_sync_barrier &&
			(!src_dp->i_mxfs_self_created || src_dp->i_dlm_dir_gen > 0);
		bool tgt_pin = !error && target_dp && target_dp != src_dp &&
			mxfs_dirop_sync_barrier &&
			(!target_dp->i_mxfs_self_created ||
			 target_dp->i_dlm_dir_gen > 0);

		if (src_pin)
			mxfs_dlm_dir_hold_ex(src_dp);
		if (tgt_pin)
			mxfs_dlm_dir_hold_ex(target_dp);
		xfs_iunlock_rename(inodes, num_inodes);
		if (src_pin) {
			mxfs_dlm_dir_inode_durable(src_dp);
			mxfs_dlm_ilock_end(src_dp, MXFS_LOCK_EX);
		}
		if (tgt_pin) {
			mxfs_dlm_dir_inode_durable(target_dp);
			mxfs_dlm_ilock_end(target_dp, MXFS_LOCK_EX);
		}
	}
out_tgt_ppargs:
	xfs_parent_finish(mp, du_tgt.ppargs);
out_wip_ppargs:
	xfs_parent_finish(mp, du_wip.ppargs);
out_src_ppargs:
	xfs_parent_finish(mp, du_src.ppargs);
out_release_wip:
	if (du_wip.ip)
		xfs_irele(du_wip.ip);
	if (error == -ENOSPC && nospace_error)
		error = nospace_error;
	return error;
}

static int
xfs_iflush(
	struct xfs_inode	*ip,
	struct xfs_buf		*bp)
{
	struct xfs_inode_log_item *iip = ip->i_itemp;
	struct xfs_dinode	*dip;
	struct xfs_mount	*mp = ip->i_mount;
	int			error;
	/*
	 * sess18 (ccloop c7ee71c6) D3 residual, wiring step 2 (completion):
	 * snapshot the publication obligation BEFORE the copy-in below, so the
	 * value can only under-state what the outgoing image actually carries.
	 * Stamped into i_mxfs_pub_flush_seq on the success path only, and
	 * promoted to i_mxfs_pub_durable_seq by xfs_iflush_finish when the
	 * buffer write COMPLETES without error.  See xfs_inode.h.
	 */
	uint64_t		pub_seq_at_copyin = ip->i_mxfs_pub_pending_seq;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL | XFS_ILOCK_SHARED);
	ASSERT(xfs_iflags_test(ip, XFS_IFLUSHING));
	ASSERT(ip->i_df.if_format != XFS_DINODE_FMT_BTREE ||
	       ip->i_df.if_nextents > XFS_IFORK_MAXEXT(ip, XFS_DATA_FORK));
	ASSERT(iip->ili_item.li_buf == bp);

	dip = xfs_buf_offset(bp, ip->i_imap.im_boffset);

	/*
	 * sess102 RULE-4 DETECTOR (P-IRESURRECT): the bnobt double-free
	 * (`ltbno+ltlen>bno` xfs_alloc.c:2244 shutdown, ~13-session blocker)
	 * is downstream of an INODE RESURRECTION: a node holds a stale in-core
	 * inode (live, owns a block) that a PEER has freed on disk (di_mode=0,
	 * block returned to the bnobt); this node then re-dirties the stale
	 * inode (atime/etc.), xfs_iflush copies the in-core LIVE image OVER the
	 * peer-zeroed on-disk inode (resurrecting it), and a later free of its
	 * block double-frees a block the bnobt already reclaimed.  Evidence:
	 * P47-INACT DISK-LIVE-same-gen=>A-lost-removal + P81-DEXT
	 * disk_claims_freed=1.  This detector logs EVERY multi-node iflush where
	 * the on-disk inode (read via the coherent SCST cache under fua_disable=1)
	 * DISAGREES with the in-core inode about mode/gen/nlink, plus the lock
	 * state needed to distinguish a legitimate new-inode first-flush
	 * (di_mode=0 + INEW + i_dlm_mode=EX) from a peer-free resurrection.
	 * Counter-capped (not ratelimited) so the decisive line is never dropped.
	 * NO behavior change yet — observe the real signature, THEN guard.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC)) {
		struct inode *vinode = VFS_I(ip);
		uint16_t disk_mode = be16_to_cpu(dip->di_mode);
		uint32_t disk_gen = be32_to_cpu(dip->di_gen);
		uint32_t disk_nlink = be32_to_cpu(dip->di_nlink);

		if (disk_mode != vinode->i_mode || disk_gen != vinode->i_generation ||
		    disk_nlink != vinode->i_nlink) {
			static atomic_t irn = ATOMIC_INIT(0);
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			    atomic_inc_return(&irn) <= 4000)
				pr_warn("mxfs: P-IRESURRECT ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u inew=%d istale_caw=%d dlm_mode=%u dlm_state=%u comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino,
					vinode->i_mode, disk_mode,
					vinode->i_generation, disk_gen,
					vinode->i_nlink, disk_nlink,
					xfs_iflags_test(ip, XFS_INEW) ? 1 : 0,
					xfs_iflags_test(ip, XFS_ISTALE_CAW) ? 1 : 0,
					ip->i_dlm_mode, ip->i_dlm_state,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
		}
	}

	/*
	 * We don't flush the inode if any of the following checks fail, but we
	 * do still update the log item and attach to the backing buffer as if
	 * the flush happened. This is a formality to facilitate predictable
	 * error handling as the caller will shutdown and fail the buffer.
	 */
	error = -EFSCORRUPTED;
	if (dip->di_magic != cpu_to_be16(XFS_DINODE_MAGIC) ||
	    XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_1)) {
		xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
			"%s: Bad inode %llu magic number 0x%x, ptr "PTR_FMT,
			__func__, ip->i_ino, be16_to_cpu(dip->di_magic), dip);
		/*
		 * P20-IFLUSH-FORENSIC (RULE 4): a bad-magic cluster buffer at
		 * flush time is either (a) an in-core clobber (something
		 * re-read/DMA'd over the live buffer: disk_differs=0 means the
		 * platter holds the SAME garbage → the buffer content came
		 * FROM the platter, i.e. an invalidate+re-read pulled foreign
		 * bytes; disk_differs=1 means in-core was corrupted after the
		 * last read) or (b) a wrong-daddr mapping (double-allocated
		 * cluster).  One FUA read on the corruption path only.
		 */
		if (mp->m_mxfs_dlm) {
			extern int mxfs_ag_buf_disk_differs(struct xfs_buf *);
			pr_warn("mxfs: P20-IFLUSH-FORENSIC ino=%llu daddr=%llu len=%d bflags=0x%x li_empty=%d pin=%d disk_differs=%d imap_blk=%llu boff=%u\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)xfs_buf_daddr(bp),
				bp->b_length, bp->b_flags,
				list_empty(&bp->b_li_list) ? 1 : 0,
				xfs_buf_ispinned(bp),
				mxfs_ag_buf_disk_differs(bp),
				(unsigned long long)ip->i_imap.im_blkno,
				(unsigned)ip->i_imap.im_boffset);
		}
		goto flush_out;
	}
	if (ip->i_df.if_format == XFS_DINODE_FMT_META_BTREE) {
		if (!S_ISREG(VFS_I(ip)->i_mode) ||
		    !(ip->i_diflags2 & XFS_DIFLAG2_METADATA)) {
			xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
				"%s: Bad %s meta btree inode %Lu, ptr "PTR_FMT,
				__func__, xfs_metafile_type_str(ip->i_metatype),
				ip->i_ino, ip);
			goto flush_out;
		}
	} else if (S_ISREG(VFS_I(ip)->i_mode)) {
		if ((ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
		     ip->i_df.if_format != XFS_DINODE_FMT_BTREE) ||
		    XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_3)) {
			xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
				"%s: Bad regular inode %llu, ptr "PTR_FMT,
				__func__, ip->i_ino, ip);
			goto flush_out;
		}
	} else if (S_ISDIR(VFS_I(ip)->i_mode)) {
		if ((ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
		     ip->i_df.if_format != XFS_DINODE_FMT_BTREE &&
		     ip->i_df.if_format != XFS_DINODE_FMT_LOCAL) ||
		    XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_4)) {
			xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
				"%s: Bad directory inode %llu, ptr "PTR_FMT,
				__func__, ip->i_ino, ip);
			goto flush_out;
		}
	}
	if (ip->i_df.if_nextents + xfs_ifork_nextents(&ip->i_af) >
	    ip->i_nblocks || XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_5)) {
		xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
			"%s: detected corrupt incore inode %llu, "
			"total extents = %llu nblocks = %lld, ptr "PTR_FMT,
			__func__, ip->i_ino,
			ip->i_df.if_nextents + xfs_ifork_nextents(&ip->i_af),
			ip->i_nblocks, ip);
		goto flush_out;
	}
	if (ip->i_forkoff > mp->m_sb.sb_inodesize ||
	    XFS_TEST_ERROR(mp, XFS_ERRTAG_IFLUSH_6)) {
		xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
			"%s: bad inode %llu, forkoff 0x%x, ptr "PTR_FMT,
			__func__, ip->i_ino, ip->i_forkoff, ip);
		goto flush_out;
	}

	if (xfs_inode_has_attr_fork(ip) &&
	    ip->i_af.if_format == XFS_DINODE_FMT_META_BTREE) {
		xfs_alert_tag(mp, XFS_PTAG_IFLUSH,
			"%s: meta btree in inode %Lu attr fork, ptr "PTR_FMT,
			__func__, ip->i_ino, ip);
		goto flush_out;
	}

	/*
	 * Inode item log recovery for v2 inodes are dependent on the flushiter
	 * count for correct sequencing.  We bump the flush iteration count so
	 * we can detect flushes which postdate a log record during recovery.
	 * This is redundant as we now log every change and hence this can't
	 * happen but we need to still do it to ensure backwards compatibility
	 * with old kernels that predate logging all inode changes.
	 */
	if (!xfs_has_v3inodes(mp))
		ip->i_flushiter++;

	/*
	 * If there are inline format data / attr forks attached to this inode,
	 * make sure they are not corrupt.
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    xfs_ifork_verify_local_data(ip)) {
		/*
		 * sess22 (ccloop 8ddb16a2) TORN-SHORTFORM-DIR FLUSH BARRIER (RULE 4,
		 * PROVEN clean-slate primary root).  Under dir-inode REUSE churn
		 * (dir_reuse_coherency: rm-rf of a leaf dir down-converts
		 * leaf->block->shortform, then the next mkdir reuses the inode#),
		 * xfsaild catches ino N's in-core LOCAL data fork in a TRANSIENT TORN
		 * state — observed sf hdr count=1 but entry[0].namelen=0, with the
		 * in-core if_format flipping EXTENTS<->LOCAL across consecutive flushes
		 * (the P78-FMT-TORN-FIX storm) as the down-conversion races the async
		 * cluster flush.  Upstream treats a verify failure at flush as FATAL
		 * (xfs_dir2_sf_verify -> SHUTDOWN_CORRUPT_INCORE -> the round-2
		 * readdir=0 cluster-down) because in single-node XFS it can only mean
		 * real in-memory corruption.  In a clustered FS it is a transient
		 * coherency artifact and the LAST VALID on-disk image (write-verifier
		 * passed) is authoritative.  NEVER publish metadata that fails its own
		 * verifier to the shared LUN: skip this flush cleanly (error=0) and
		 * taint XFS_ISTALE_CAW so the next access DLM-cold-reloads the coherent
		 * on-disk shortform.  Multi-node DIRs only; single-node / non-dir keep
		 * upstream fatal semantics.  The skip preserves this inode's on-disk
		 * slot in the cluster buffer (we never copied in-core->disk for it).
		 */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(ip)->i_mode)) {
			static atomic_t sftorn = ATOMIC_INIT(0);

			if (atomic_inc_return(&sftorn) <= 200) {
				unsigned char *d = ip->i_df.if_data;

				pr_warn("mxfs: P22-SFTORN-SKIP ino=%llu if_bytes=%lld dlm_mode=%u inew=%d istale_caw=%d dirty_seq=%llu ex_grant_seq=%llu ili_fields=0x%x flushiter=%d hdr=[%02x %02x %02x %02x %02x %02x %02x %02x] comm=%s\n",
					(unsigned long long)ip->i_ino,
					(long long)ip->i_df.if_bytes,
					(unsigned)ip->i_dlm_mode,
					xfs_iflags_test(ip, XFS_INEW) ? 1 : 0,
					xfs_iflags_test(ip, XFS_ISTALE_CAW) ? 1 : 0,
					(unsigned long long)ip->i_mxfs_dirty_seq,
					(unsigned long long)ip->i_mxfs_ex_grant_seq,
					iip->ili_fields, ip->i_flushiter,
					d ? d[0] : 0, d ? d[1] : 0, d ? d[2] : 0,
					d ? d[3] : 0, d ? d[4] : 0, d ? d[5] : 0,
					d ? d[6] : 0, d ? d[7] : 0,
					current->comm);
			}
			xfs_iflags_set(ip, XFS_ISTALE_CAW);
			/*
			 * sess3 (ccloop a16ec5f2) ROOT FIX — run13/run15 PROVEN
			 * durable-loss chain: routing this skip through flush_out
			 * CONSUMED ili_fields (moved to ili_last_fields, cleared)
			 * with NOTHING copied into the buffer, so the next cluster
			 * write completion removed the inode from the AIL and the
			 * committed dir contraction (leaf->block->SF, which had
			 * already queued its block frees durably) was silently
			 * dropped from writeback FOREVER.  The acquire-time reload
			 * then saw a clean ILI and adopted the stale on-disk
			 * EXTENTS map whose blocks the bnobt had already freed ->
			 * a file re-allocated the dir's still-mapped block0 ->
			 * urandom over live dir data -> CRC error 74 -> cluster
			 * wide shutdown (run15 t=5273.32-.62: BLOCK2SF + P3-EFREE-Q
			 * agbno=15, SFTORN-SKIP ili_fields=0x3, fence+reload see
			 * fields=0x0, PW-ADOPT discards fmt=1, P-DBLALLOC realloc
			 * of agbno=15, error 74 at daddr 0x78).  Return -EAGAIN
			 * WITHOUT touching the ILI so the inode stays dirty in the
			 * AIL and the flush retries once the transient conversion
			 * tear settles (the caller skips this inode this round).
			 */
			return -EAGAIN;
		}
		goto flush_out;
	}
	/*
	 * sess14(a9a03929) SF-DIR SIZE-DESYNC TRIPWIRE (RULE 4 instrument +
	 * guard).  The local-data verify above runs against if_bytes, but the
	 * on-disk image this flush is about to serialize carries di_size =
	 * i_disk_size.  If the two desynced (candidate producer: a reload
	 * whose xfs_inode_from_disk failed AFTER xfs_idestroy_fork reset the
	 * fork, leaving i_disk_size from the old life), the in-core verify
	 * passes while the PUBLISHED payload walks count entries past its
	 * size — exactly the durable frankenstein that wedged test4's AIL for
	 * 184s and convoyed the whole cluster (gap-run tds, ino 0xa00083:
	 * count=7, six valid entries, zeroed tail; 13,783 verifier rejects on
	 * reload).  NEVER publish it: same contract as the P22 skip — taint
	 * ISTALE_CAW, -EAGAIN without consuming the ILI (nothing has been
	 * copied into the buffer yet), retry after the next modify resyncs.
	 * The capped print names the producer's residue for the post-mortem.
	 */
	if (S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    (xfs_fsize_t)ip->i_df.if_bytes != ip->i_disk_size) {
		static atomic_t p14n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p14n) <= 200)
			pr_warn("mxfs: P14-SFSIZE-DESYNC ino=%llu if_bytes=%lld disk_size=%lld ili_fields=0x%x dlm_mode=%u istale_caw=%d comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino,
				(long long)ip->i_df.if_bytes,
				(long long)ip->i_disk_size,
				iip->ili_fields, (unsigned)ip->i_dlm_mode,
				xfs_iflags_test(ip, XFS_ISTALE_CAW) ? 1 : 0,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		return -EAGAIN;
	}
	if (xfs_inode_has_attr_fork(ip) &&
	    ip->i_af.if_format == XFS_DINODE_FMT_LOCAL &&
	    xfs_ifork_verify_local_attr(ip))
		goto flush_out;

	/*
	 * sess118 RULE-4 GUARD (the sess102 P-IRESURRECT detector, now acting):
	 * do NOT resurrect a peer-reincarnated inode.  If the on-disk dinode is a
	 * DIFFERENT incarnation than our in-core inode (disk di_gen != in-core
	 * i_generation), the disk copy is the authoritative newer life (a peer
	 * freed our inode and re-allocated that inode number, bumping the gen).
	 * Our in-core image is a stale ghost; copying it over the disk would
	 * RESURRECT the dead inode, double-allocating its blocks/inode-record and
	 * later faulting xfs_dialloc with EFSCORRUPTED (badmagic) -> FS shutdown
	 * (PROVEN sess118: P-IRESURRECT comm=xfsaild incore_mode=0100644
	 * disk_mode=0 disk_gen!=incore_gen, fired immediately before the
	 * xfs_dialloc -117 create shutdown in cache_coherency/unlink_visibility).
	 *
	 * Skip the content copy (preserving the peer's durable on-disk inode that
	 * is already in this buffer) and complete the flush bookkeeping with
	 * error=0 so the AIL releases our stale item without a write and xfsaild
	 * does not loop.
	 *
	 * DISCRIMINATOR = disk di_gen STRICTLY GREATER than in-core i_generation.
	 * XFS bumps di_gen on every (re)allocation, so disk_gen > incore_gen means
	 * the on-disk inode is a LATER incarnation than ours -> a peer advanced it
	 * past us -> our in-core is the stale ghost -> skip.  The inverse cases all
	 * flush normally: our own modifications/frees (disk_gen == incore_gen) and
	 * a freshly-created inode's first flush (incore_gen > disk_gen, because WE
	 * just bumped the gen on allocation and the on-disk slot still holds the
	 * old/zero gen).  Earlier attempts using `!=` or a disk_mode==0 test were
	 * REFUTED (sess118): they skipped legitimate new-inode first flushes
	 * (disk_gen=0, INEW already cleared by the async xfsaild flush) -> the new
	 * file was never persisted -> cross_visibility "cannot see" + AIL stall.
	 * !INEW + valid magic are kept as belt-and-suspenders.
	 */
	{
		/*
		 * sess55 (ccloop 8ddb16a2; GPT-5.5 RULE-5 design #4) — CO-RESIDENT
		 * COMMITTED-CHANGE FLUSH.  The sess119/sess17b guards below DISCARD any
		 * non-EX dirty inode on the theory "non-EX -> clean-or-ghost, never a
		 * pending legit write" (invariant #1 drains before release).  RULE-4
		 * PROVEN FALSE for a CO-RESIDENT (tcp_dlm_scaling "drained got=1"):
		 * when this node flushes dir A's 4 KiB inode cluster (release flush or
		 * mxfs_inode_cluster_durable), the cluster also holds a DIFFERENT dir B
		 * that this node modified+committed under a prior EX tenure and then
		 * DEMOTED to PR (the demote's drain flushed A's cluster, not B's own).
		 * B reaches xfs_iflush still in_ail at i_dlm_mode=PR; P119 marks it
		 * CLEAN without writing -> B's committed dirent removal is LOST -> the
		 * stale on-disk dirent survives -> leak (PROVEN sess54/55 stack: P119
		 * ino=B i_dlm_mode=3 in_ail=1 exh=0 comm=rm, a co-resident of the
		 * EX-pinned op dir).  The EX-pin (mxfs_dlm_dir_hold_ex) only covers the
		 * OP's own dir, never arbitrary co-residents.
		 *
		 * Safe to FLUSH (not discard) B's committed change while we still hold
		 * PR: PR<->EX are mutually exclusive across nodes, so while we hold PR
		 * NO peer holds EX and NO peer is mid-write -> our in-core image (the
		 * committed change, in_ail) is authoritative and clobbers nothing.
		 * Gate tightly: PR (NOT NL — NL holds nothing), same incarnation (disk
		 * di_gen == in-core i_generation), LIVE on disk (di_mode != 0) and SAME
		 * type (S_IFMT) so a peer-reincarnation/ghost still discards; dir only
		 * (the proven leak; reg-file coherency tests pass).  When set, skip the
		 * P119 + P17B discards below and flush normally; the P25 resurrect guard
		 * needs disk di_mode==0 and so is already mutually exclusive. */
		bool mxfs_cores_commit_flush =
			mp->m_mxfs_dlm &&
			!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
			S_ISDIR(VFS_I(ip)->i_mode) &&
			ip->i_dlm_mode == MXFS_LOCK_PR &&
			dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
			be16_to_cpu(dip->di_mode) != 0 &&
			(be16_to_cpu(dip->di_mode) & S_IFMT) ==
				(VFS_I(ip)->i_mode & S_IFMT) &&
			be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
			ip->i_itemp &&
			test_bit(XFS_LI_IN_AIL,
				 &ip->i_itemp->ili_item.li_flags);
		if (mxfs_cores_commit_flush) {
			static atomic_t ccf = ATOMIC_INIT(0);
			if (atomic_inc_return(&ccf) <= 4000)
				pr_warn("mxfs: P55-CORESIDENT-COMMIT-FLUSH ino=%llu i_dlm_mode=%u mode=0%o gen=%u in_ail=1 comm=%s — flushing PR-held committed change (not discarding)\n",
					(unsigned long long)ip->i_ino,
					(unsigned)ip->i_dlm_mode,
					VFS_I(ip)->i_mode,
					VFS_I(ip)->i_generation,
					current->comm);
		}
		/*
		 * sess119 (Gemini RULE-5 validated) — DLM-OWNERSHIP DISCRIMINATOR.
		 *
		 * The ONLY architecturally correct test for "may THIS node write
		 * this inode to the shared LUN" is DLM lock ownership: a node may
		 * flush a dirty inode ONLY while it holds the inode's DLM lock in
		 * EX.  If we do not hold EX, the in-core image is not
		 * authoritative:
		 *   - a peer forced us off EX (and architectural invariant #1
		 *     guarantees our drain pipeline flushed any genuinely-dirty
		 *     state BEFORE the downgrade — so a non-EX inode reaching here
		 *     is clean-or-ghost, never a pending legit write), or
		 *   - this is a stale ghost left in the AIL after a peer
		 *     freed/reallocated the inode number.
		 * Writing it would either RESURRECT a peer-freed inode (sess118
		 * corruption: xfs_dialloc badmagic -> EFSCORRUPTED -> shutdown) or
		 * CLOBBER a peer's live incarnation (the cross_visibility barrier
		 * lost-update: ino=133 .mxfs_test/test_rename_visibility, a LIVE
		 * dir this node owns, was being skipped by the old gen heuristic).
		 *
		 * This REPLACES the di_gen comparison used sess44-118.  XFS bumps
		 * i_generation on free (xfs_inode_util.c:803) and randomizes it at
		 * chunk-init (get_random_u32), so cross-node di_gen values live in
		 * independent numeric domains and are NOT comparable: every
		 * gen-comparison discriminator had a ~50% peer-clobber hole.  The
		 * EX check has none — a freshly-created inode is granted EX
		 * LOCALLY (i_dlm_mode=EX, possibly i_dlm_unpublished) so its first
		 * flush passes; inode locks only ever use NL/PR/EX, and EX is the
		 * sole write mode, so "!= EX" == "not authoritative to write".
		 * Skip cleanly (error=0) and mark stale for DLM cold-reload.
		 */
	/*
	 * ccloop c7ee71c6 sess3 (RULE 4, PROVEN via P-SFDIR-REVERT ino=152
	 * fua_cnt=0 + P146-RELDUR flushed=1 wrote=0): bast_process NLs
	 * i_dlm_mode hundreds of lines BEFORE it sets the RELFLUSH sanction,
	 * and the destage kick cycles xfsaild every ~10ms into that gap.  A
	 * concurrent iflush in the gap hit this skip, which completes as
	 * "flushed" WITHOUT copying the dinode — the AIL item retires while
	 * the cluster buffer/LUN keep the PRIOR-incarnation bytes, the
	 * release loop then sees clean+not-in-AIL and trusts "durable", and
	 * the creator's own reload adopts the stale platter (round-4
	 * node1_f1 loss).  i_dlm_demoter is non-NULL for the entire
	 * bast_process, so treat an active demote as sanctioned: the drain
	 * fence still orders the write before the unlock, and no peer can
	 * hold the grant while we are the demoter, so writing our state
	 * cannot clobber a peer.  ICLUSTER-routed inodes keep the skip
	 * (cluster grants cover foreign inodes; continuity argument does
	 * not hold per-inode there).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	    ip->i_dlm_mode != MXFS_LOCK_EX &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    (ip->i_dlm_routed_iclus || ip->i_dlm_demoter == NULL) &&
	    !mxfs_cores_commit_flush) {
		static atomic_t irsk = ATOMIC_INIT(0);
		if (atomic_inc_return(&irsk) <= 4000)
			pr_warn("mxfs: P119-NONEX-FLUSH-SKIP ino=%llu i_dlm_mode=%u incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u exh=%d prh=%d in_ail=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				(unsigned)ip->i_dlm_mode,
				VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
				VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
				VFS_I(ip)->i_nlink, be32_to_cpu(dip->di_nlink),
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					&ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
				current->comm);
		/* sess54 RULE-4: one-shot stack dump for a DIR skip so we can name the
		 * exact caller whose committed dir change is being discarded (the
		 * residual tcp_dlm_scaling leftover after the create/remove/rename
		 * EX-pin fix). */
		if (S_ISDIR(VFS_I(ip)->i_mode)) {
			static atomic_t p119stk = ATOMIC_INIT(0);
			if (atomic_inc_return(&p119stk) <= 3)
				dump_stack();
		}
		/* Mark in-core stale for DLM cold-reload on next access. */
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		error = 0;
		goto flush_out;
	}

	/*
	 * sess17b (ccloop 4eef1f39, Gemini DLM-epoch LINEAGE guard) — closes the
	 * sess119 hole.  We hold EX here, but holding EX is NOT sufficient: a node
	 * can hold (or re-take) EX on an inode NUMBER whose in-core image is a stale
	 * FREED ghost from a PREVIOUS tenure while a peer has reallocated that number
	 * to a LIVE file on disk.  Flushing the ghost (mode=0/di_size=0) over the
	 * peer's live on-disk inode silently destroys the file's content/dirent
	 * (the rename_visibility + cross_write_read empty-content failures) or, in
	 * the inverse direction, resurrects a peer-freed inode (bnobt double-alloc).
	 * Both showed dlm_mode=EX in the P-IRESURRECT detector, so the EX check
	 * above lets them through.
	 *
	 * DISCRIMINATOR (lock-continuity, NOT gen comparison which is refuted):
	 * i_mxfs_dirty_seq is the EX epoch under which this in-core state was last
	 * logged; i_mxfs_ex_grant_seq is the epoch of the EX tenure we hold NOW.
	 * If they differ, we yielded EX and re-took it between dirtying and
	 * flushing — a window in which a peer may have freed/reused the on-disk
	 * inode — so the dirty image is not authoritative for the shared LUN.
	 * (Invariant #1 flushes genuinely-dirty state BEFORE any EX release, so a
	 * mismatch here is always a stale ghost, never a pending legit write.)
	 * A legitimate local delete or new-inode first flush runs within the SAME
	 * continuous EX tenure -> dirty_seq == ex_grant_seq -> flushes normally.
	 * Skip cleanly (error=0) and taint for DLM cold-reload.  Bypassed by the
	 * sanctioned release flush (MXFS_IF_DLM_RELFLUSH) which is current-tenure.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    ip->i_mxfs_dirty_seq != ip->i_mxfs_ex_grant_seq &&
	    /* c7ee71c6 sess3: active demote == sanctioned (see P119 above) */
	    (ip->i_dlm_routed_iclus || ip->i_dlm_demoter == NULL) &&
	    !mxfs_cores_commit_flush) {
		static atomic_t epsk = ATOMIC_INIT(0);
		if (atomic_inc_return(&epsk) <= 4000)
			pr_warn("mxfs: P17B-EPOCH-GHOST-SKIP ino=%llu incore_mode=0%o disk_mode=0%o dirty_seq=%llu ex_grant_seq=%llu incore_nlink=%u disk_nlink=%u comm=%s\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
				(unsigned long long)ip->i_mxfs_dirty_seq,
				(unsigned long long)ip->i_mxfs_ex_grant_seq,
				VFS_I(ip)->i_nlink, be32_to_cpu(dip->di_nlink),
				current->comm);
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		error = 0;
		goto flush_out;
	}
	}

	/*
	 * sess25 (ccloop) RESURRECTION GUARD (RULE 4, PROVEN dir_reuse_coherency
	 * 2/tcp root): xfsaild flushes a stale-live in-core inode whose COHERENT
	 * on-disk copy a PEER already FREED (disk mode=0 nlink=0, di_gen bumped
	 * past ours).  ~201 such flushes per run (P-IRESURRECT, P119+P17B both 0x)
	 * RESURRECT the freed inode -> its data block, already freed+reallocated to
	 * the reused dir's LEAF, is double-claimed -> the dir leaf daddr holds .md5
	 * FILE data -> EFSBADCRC / lookup-fail.  The sess119 P119 (i_dlm_mode==EX)
	 * and sess17b P17B (dirty_seq==ex_grant_seq) guards MISS these: the peer
	 * freed our UNPUBLISHED inode without BASTing us, so i_dlm_mode is a STALE
	 * EX and dirty_seq==ex_grant_seq.  Reliable signal = the coherent on-disk
	 * inode (dip, the cluster buffer re-read at acquire/flush) is FREE and a
	 * SMALL-DELTA-LATER incarnation: di_mode==0 && di_nlink==0 &&
	 * 1 <= (u32)(disk_gen - incore_gen) <= MXFS_RESURRECT_GEN_WINDOW.  XFS
	 * increments i_generation by exactly 1 on each free (xfs_inode_util.c), so a
	 * resurrection lagging N peer-frees has disk_gen = incore_gen + N with N
	 * SMALL (the inode NUMBER is reused at most a few dozen times across the
	 * test's rm-rf rounds).  We must NOT use disk_gen > incore_gen (sess25 v1
	 * REGRESSION, readdir=0 EVERY round incl round 1) NOR == incore_gen+1 (v2,
	 * never matched the real dirwr=0 timing where N>1): a freshly chunk-
	 * allocated inode's disk slot carries a chunk-init RANDOM gen (get_random_u32)
	 * independent of our in-core gen, so `>` fires ~50% on LEGIT new-inode first
	 * flushes -> never persisted -> readdir=0 (sess119 "cross-node random gens
	 * are incomparable").  A BOUNDED window separates the two cleanly: a free-
	 * bump lag is a small positive delta (1..WINDOW); a chunk-init random gen
	 * lands in [1,WINDOW] only WINDOW/2^32 of the time (negligible at WINDOW=64);
	 * a reuse-alloc / our-own-newest has disk<=incore so (u32) delta wraps huge
	 * and is excluded.  Residual: a chunk-REINIT resurrection (gen fully re-
	 * randomized, delta huge) slips through — revisit with an inobt-allocation
	 * check if it still corrupts.  A local self-free has in-core mode==0 so the
	 * i_mode!=0 guard excludes it.  Skip cleanly (error=0) + taint for DLM cold-
	 * reload; bypassed by the sanctioned release flush.  WINDOW is the runtime-
	 * tunable mxfs.resurrect_gen_window (default 64, 0=disable the guard).
	 */
	{ extern int mxfs_resurrect_gen_window;
	u32 mxfs_rgw_delta = (u32)(be32_to_cpu(dip->di_gen) -
				   VFS_I(ip)->i_generation);
	if (mxfs_resurrect_gen_window > 0 &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    be16_to_cpu(dip->di_mode) == 0 && be32_to_cpu(dip->di_nlink) == 0 &&
	    VFS_I(ip)->i_mode != 0 &&
	    mxfs_rgw_delta >= 1 &&
	    mxfs_rgw_delta <= (u32)mxfs_resurrect_gen_window) {
		static atomic_t rsrk = ATOMIC_INIT(0);
		if (atomic_inc_return(&rsrk) <= 4000)
			pr_warn("mxfs: P25-RESURRECT-SKIP ino=%llu incore_mode=0%o disk_mode=0%o incore_gen=%u disk_gen=%u incore_nlink=%u disk_nlink=%u i_dlm_mode=%u comm=%s\n",
				(unsigned long long)ip->i_ino,
				VFS_I(ip)->i_mode, be16_to_cpu(dip->di_mode),
				VFS_I(ip)->i_generation, be32_to_cpu(dip->di_gen),
				VFS_I(ip)->i_nlink, be32_to_cpu(dip->di_nlink),
				(unsigned)ip->i_dlm_mode, current->comm);
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		error = 0;
		goto flush_out;
	}
	}

	/*
	 * sess74 (ccloop 14d31183) WRITE-BOUNDARY TORN-DINODE BARRIER (RULE 4 +
	 * Gemini design): the PROVEN deepest root of zero_silent_loss is that the
	 * dir inode's in-core if_nextents (the count copied into di_nextents by
	 * xfs_inode_to_disk below) DISAGREES with the actual number of extents in
	 * the in-core iext tree (sess60: di_nextents=14 vs 13-record leaf; sess65:
	 * iext tree=16 vs if_nextents=15).  In upstream XFS these CANNOT diverge;
	 * one of mxfs's DLM reload/reconcile paths injected the skew (e.g. a stale
	 * dirty bmbt leaf surviving acquire-eviction so lazy xfs_iread_extents
	 * builds the tree from it while if_nextents took the fresh dinode value, or
	 * the P70 `ifp->if_nextents = disk_nx` band-aid).  Packing di_nextents=N
	 * over an extent set of M!=N records writes a TORN dinode to the shared
	 * LUN; a reloading peer trips xfs_iformat_extents / xfs_iread_bmbt_block
	 * (over/under-count) -> EFSCORRUPTED -> xfs_trans_cancel-dirty CORRUPT_INCORE
	 * shutdown -> SCSI-PR reservation storm -> cluster-wide EIO -> the 1600
	 * silent dirent loss.  We hold the ILOCK here (iext tree frozen and
	 * authoritative), so count the REAL extents and reconcile if_nextents to
	 * them BEFORE force-destaging leaves and BEFORE the dinode pack — the
	 * dinode is then INTERNALLY CONSISTENT (di_nextents == records written) and
	 * no torn pair ever reaches disk.  One-shot stack dump on the first skew so
	 * the producing reload path is named.  DIR forks, multi-node, extents
	 * loaded (need_iread=0 => tree is authoritative) only.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     ip->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
	    !xfs_need_iread_extents(&ip->i_df)) {
		struct xfs_iext_cursor	rcur;
		struct xfs_bmbt_irec	rrec;
		xfs_extnum_t		real = 0;

		for_each_xfs_iext(&ip->i_df, &rcur, &rrec)
			real++;

		if (real != ip->i_df.if_nextents) {
			static atomic_t p74skew = ATOMIC_INIT(0);

			pr_warn_ratelimited(
				"mxfs: P74-IFNEXT-SKEW ino=%llu if_nextents=%llu real_iext=%llu fmt=%d comm=%s — reconciling to real count (torn-dinode barrier)\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_df.if_nextents,
				(unsigned long long)real,
				ip->i_df.if_format, current->comm);
			if (atomic_inc_return(&p74skew) == 1)
				dump_stack();
			ip->i_df.if_nextents = real;
		}
	}

	/*
	 * sess78 (ccloop 14d31183) FORMAT/LITERAL-AREA TORN-DINODE BARRIER
	 * (RULE 4; sess77 PROVEN durable on-disk root).  xfs_inode_to_disk()
	 * below writes di_format UNCONDITIONALLY from the in-core if_format, but
	 * xfs_iflush_fork() only REWRITES the dinode literal area when the
	 * matching data-fork log flag (DEXT/DBROOT/DDATA) is set in ili_fields.
	 * A forced relflush (MXFS_IF_DLM_RELFLUSH) — or any flush whose
	 * ili_fields carries CORE but not the data-fork bit while the in-core
	 * fork has just crossed LOCAL->EXTENTS/BTREE — therefore publishes
	 * di_format=EXTENTS/BTREE over a literal area that STILL HOLDS the old
	 * shortform/local bytes.  A reloading peer reads di_format=EXTENTS with
	 * shortform dir bytes in di_u, decodes the "node7.." dirent bytes as a
	 * bmbt extent record -> xfs_bmap_validate_extent_raw "Bmap BTree record
	 * corruption" / xfs_iformat_extents -> EFSCORRUPTED -> DLM from_disk
	 * FAILED -> force_shutdown -> SCSI-PR storm -> posix_multi16 >600s
	 * (sess77: durable torn dir-inode ino 0x1c001b2 on a barrier dir).
	 *
	 * We hold the ILOCK (fork frozen + authoritative) and — having passed
	 * the sess119 EX discriminator and P17B epoch-ghost guard above — this
	 * is a current-tenure authoritative flush.  For a multi-node DIR whose
	 * fork is loaded (!need_iread => iext tree / broot is the truth) and
	 * non-empty, FORCE the matching data-fork bit so xfs_iflush_fork
	 * rewrites the literal area to MATCH the di_format we are about to
	 * publish.  The on-disk dinode is then internally consistent (format
	 * matches content); no torn (format,literal) pair ever reaches the
	 * shared LUN.  Idempotent when the fork was already coherent.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    iip && S_ISDIR(VFS_I(ip)->i_mode) &&
	    !xfs_need_iread_extents(&ip->i_df)) {
		uint		want = 0;

		if (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS &&
		    ip->i_df.if_nextents > 0)
			want = XFS_ILOG_DEXT;
		else if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
			 ip->i_df.if_broot && ip->i_df.if_broot_bytes > 0)
			want = XFS_ILOG_DBROOT;
		else if (ip->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
			 ip->i_df.if_data && ip->i_df.if_bytes > 0)
			want = XFS_ILOG_DDATA;

		if (want && !(iip->ili_fields & want)) {
			static atomic_t p78 = ATOMIC_INIT(0);

			if (atomic_inc_return(&p78) <= 400)
				pr_warn("mxfs: P78-FMT-TORN-FIX ino=%llu newfmt=%d ondisk_fmt=%d nextents=%llu ili_fields=0x%x forcing=0x%x comm=%s\n",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format, dip->di_format,
					(unsigned long long)ip->i_df.if_nextents,
					iip->ili_fields, want, current->comm);
			iip->ili_fields |= want;
		}
	}

	/*
	 * sess62 WRITER-SIDE ORDERING FIX (zero_silent_loss): for a BTREE-format
	 * data fork in a multi-node mount, land every un-durable bmbt leaf owned
	 * by this inode to disk BEFORE we copy di_nextents into the on-disk
	 * dinode.  We hold the ILOCK here, so in-core di_nextents is frozen and
	 * the leaves we flush match exactly the di_nextents about to be written —
	 * a reloading peer can no longer read di=N over a leaf still at N-1.  No-op
	 * for non-BTREE forks and single-node mounts.  See
	 * mxfs_iflush_force_bmbt_durable() in xfs_mxfs_dlm.c.
	 */
	if (mp->m_mxfs_dlm) {
		extern void mxfs_iflush_force_bmbt_durable(struct xfs_inode *);
		mxfs_iflush_force_bmbt_durable(ip);
	}

	/*
	 * sess32 (ccloop 8ddb16a2) RULE-4 (a)-discriminator (GPT-5.5 2nd consult):
	 * dir_reuse_coherency ends with the dir's LEAF index referencing more
	 * entries than the DATA fork holds (di_nextents reverted nx=2->1 while the
	 * leaf persisted).  Catch the durable extent-map REVERT in the act: a
	 * DIRECTORY iflush about to write a SMALLER in-core data-fork extent count
	 * over a LARGER on-disk one.  If this fires, GPT root (a) (stale iflush
	 * reverting the parent dinode extent map) is CONFIRMED and the fix is to
	 * FENCE it (skip the shrinking flush unless authoritative).  Log-only,
	 * multinode dir, capped.  dip here is the cluster buffer being overwritten,
	 * so be32(dip->di_nextents) is the value we are about to clobber.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	    (xfs_extnum_t)be32_to_cpu(dip->di_nextents) > ip->i_df.if_nextents) {
		static atomic_t p32nx = ATOMIC_INIT(0);
		if (atomic_inc_return(&p32nx) <= 2000)
			pr_warn("mxfs: P32-IFLUSH-NXSHRINK ino=%llu incore_nx=%llu disk_nx=%u incore_size=%lld disk_size=%lld relflush=%d dlm_mode=%u dirty_seq=%llu ex_gseq=%llu comm=%s — about to write SMALLER dir extent map over a larger on-disk one (extent-map revert)\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_df.if_nextents,
				be32_to_cpu(dip->di_nextents),
				(long long)ip->i_disk_size,
				(long long)be64_to_cpu(dip->di_size),
				xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
				ip->i_dlm_mode,
				(unsigned long long)ip->i_mxfs_dirty_seq,
				(unsigned long long)ip->i_mxfs_ex_grant_seq,
				current->comm);
	}

	/*
	 * sess16(ccloop) P32F-NXSHRINK-FENCE (RULE 4 ENFORCEMENT of the P32 probe
	 * above): the dir_reuse_coherency mht=50 SHUTDOWN.  A node that served EX on
	 * the FAST PATH never ran the slow-path reload, so its in-core dir data-fork
	 * extent map is STALE (smaller than the peer-grown on-disk image); an rm then
	 * flushes that smaller map over the larger durable one of the SAME
	 * incarnation -> extent-map revert -> leaf-vs-data tear -> EFSCORRUPTED.
	 * Discriminator (RELIABLE, level-triggered): the master's current dir_epoch
	 * EXCEEDS i_dlm_dir_valid_epoch iff a peer modified this dir since our base
	 * last adopted -> the shrink is a stale revert, not our own legit shrink
	 * (a self-shrink has valid_epoch == current).  Skip the flush (mark stale,
	 * no I/O); the next EX (re)acquire reloads + adopts the disk superset.  Same
	 * safe skip idiom as P65/P67 (XFS_ISTALE_CAW + error=0 + goto flush_out).
	 */
	{
		extern int mxfs_dir_nxshrink_fence;
		extern uint32_t mxfs_v5_dlm_inode_dir_epoch(
			struct mxfs_v5_dlm *, uint64_t);

		if (mxfs_dir_nxshrink_fence &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_ino != mp->m_sb.sb_rootino &&
		    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
		    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
		    (xfs_extnum_t)be32_to_cpu(dip->di_nextents) >
			ip->i_df.if_nextents) {
			uint32_t cur_ep = mxfs_v5_dlm_inode_dir_epoch(
				mp->m_mxfs_dlm, ip->i_ino);

			/* sess28: incarnation-qualified.  A raw `>` here fenced
			 * EVERY flush of a freshly created directory whose inode
			 * NUMBER carried a previous incarnation's epoch — the
			 * proven D-SILENT-MKDIR-LOSS path.  The fence's own
			 * safety premise ("our changes were landed by our
			 * release drain before the peer could acquire") is false
			 * for an incarnation that has never been released. */
			if (mxfs_dir_epoch_superseded(ip, cur_ep)) {
				pr_warn_ratelimited(
				    "mxfs: P32F-NXSHRINK-FENCE ino=%llu incore_nx=%llu disk_nx=%u valid_epoch=%u cur_epoch=%u dlm_mode=%u comm=%s — skip stale extent-map revert; reload on next acquire\n",
				    (unsigned long long)ip->i_ino,
				    (unsigned long long)ip->i_df.if_nextents,
				    be32_to_cpu(dip->di_nextents),
				    ip->i_dlm_dir_valid_epoch, cur_ep,
				    ip->i_dlm_mode, current->comm);
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				ip->i_dlm_stale = true; ip->i_dlm_stale_src = 18;
				error = 0;
				goto flush_out;
			}
		}
	}

	/*
	 * sess14 (ccloop c7ee71c6) D3 ROOT FIX arm 2 — dead-incarnation flush
	 * fence.  A dirent-validated reload (RELOAD-TYPEFLIP-DIRENT-OK) marked
	 * this in-core object a DEAD PRIOR INCARNATION of a reused ino, and
	 * the cluster buffer we are about to modify still carries the newer
	 * live incarnation (di_gen matches the recorded verdict).  Copying our
	 * corpse over it is the PROVEN 22/32-node rename loss (ino 167: stale
	 * storm-dir dinode written over the peer's current file by the release
	 * drain's iflush_cluster, ring #4008/#4009 + stack capture).  Arm 1
	 * kills the drain's phantom-retire re-log (P146D); this arm refuses
	 * any OTHER path (xfsaild BLI push, direct reclaim flush) that reaches
	 * iflush with genuinely-dirty ili_fields on a dead incarnation.  Same
	 * safe skip idiom as P32F above.
	 */
	/* sess14+GPT: WRITE-POISON — the marker alone forbids the flush (gen
	 * matching is ABA-fragile; a corpse never regains write authority by
	 * coincidence).  Cleared only by a successful serialized adoption. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    ip->i_mxfs_dead_incarn_gen) {
		pr_warn_ratelimited(
		    "mxfs: P32D-DEADINCARN-SKIP ino=%llu incore_gen=%u disk_gen=%u incore_mode=0%o dlm_mode=%u comm=%s — refusing flush of dead prior incarnation over live slot\n",
			(unsigned long long)ip->i_ino,
			VFS_I(ip)->i_generation,
			be32_to_cpu(dip->di_gen),
			VFS_I(ip)->i_mode, ip->i_dlm_mode, current->comm);
		xfs_iflags_set(ip, XFS_ISTALE_CAW);
		ip->i_dlm_stale = true; ip->i_dlm_stale_src = 24;
		error = 0;
		goto flush_out;
	}

	/*
	 * sess14 (ccloop c7ee71c6) D3 ROOT FIX arm 3 — dir EPOCH flush fence
	 * (generalizes the P32F nx-shrink arm above to EVERY dir flush shape,
	 * including SHORTFORM).  PROVEN (fdw ghost-dirent n5_8, 17:03:41):
	 * test5 under EX removed the SF dirent and landed the post-remove fork
	 * (write=[n17_6 n26_12 n4_9]); 166ms later test8 — and then test24 —
	 * flushed their RETAINED pre-remove image at dlm_mode=0 (xfsaild
	 * pushing a zombie AIL item after release), durably resurrecting the
	 * dirent; every later tenure re-adopted the corpse from disk and the
	 * name became a cluster-wide P26-IGET-FAIL err=-2 ghost.  Predicate:
	 * a SAME-incarnation dir whose master dir_epoch EXCEEDS our
	 * valid_epoch — a peer has held EX since our copy was valid, so the
	 * disk is (or may be) a successor of our image: writing ours can only
	 * revert it.  Our own real changes were landed by our release drain
	 * (data_durable) before the peer could acquire, so nothing of ours is
	 * lost by skipping; the item completes on the unmodified buffer.
	 */
	{
		extern int mxfs_dir_epoch_flush_fence;
		extern uint32_t mxfs_v5_dlm_inode_dir_epoch(
			struct mxfs_v5_dlm *, uint64_t);
		extern bool mxfs_dir_epoch_superseded(struct xfs_inode *,
						      uint32_t);

		if (mxfs_dir_epoch_flush_fence &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_ino != mp->m_sb.sb_rootino &&
		    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
		    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation) {
			uint32_t cur_ep = mxfs_v5_dlm_inode_dir_epoch(
				mp->m_mxfs_dlm, ip->i_ino);

			if (cur_ep > ip->i_dlm_dir_valid_epoch) {
				pr_warn_ratelimited(
				    "mxfs: P32E-DIREPOCH-FENCE ino=%llu fmt=%d valid_epoch=%u cur_epoch=%u dlm_mode=%u comm=%s racebail_age_ms=%lld — skip stale dir flush (peer superseded since our copy); reload on next acquire\n",
				    (unsigned long long)ip->i_ino,
				    ip->i_df.if_format,
				    ip->i_dlm_dir_valid_epoch, cur_ep,
				    ip->i_dlm_mode, current->comm,
				    ip->i_mxfs_racebail_ns ?
					(long long)((ktime_get_ns() -
					   ip->i_mxfs_racebail_ns) / 1000000ULL)
					: -1LL);
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				ip->i_dlm_stale = true;
				ip->i_dlm_stale_src = 25;
				error = 0;
				goto flush_out;
			}
		}
	}

	/*
	 * sess-tcp (GPT fence design, [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]):
	 * the dir_reuse_coherency loss is node2 serializing a STALE in-core dir
	 * INODE FORK (block0 -> freed prior-incarnation daddr 112) over the
	 * canonical dinode (block0 -> 120).  DECISIVE QUESTION for the fence: does
	 * the stale flush happen (a) UNDER EX during release-drain (fork never
	 * reloaded) or (b) in NL/PR via background xfsaild (a node that does NOT own
	 * the dir writing its fork)?  Case (b) is fenceable by a simple
	 * "mode==EX required" guard; case (a) needs the epoch/reload fix.  Log every
	 * multi-node DIRECTORY fork flush that happens while NOT holding EX — if this
	 * fires for ino=131 in a failing run, the NL/PR xfsaild flush hole is real.
	 * Log-only (capped); enforcement (skip the flush) is the next step.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     ip->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
	    !xfs_need_iread_extents(&ip->i_df)) {
		static atomic_t p_fen = ATOMIC_INIT(0);
		xfs_fsblock_t		b0 = 0;
		struct xfs_iext_cursor	c0;
		struct xfs_bmbt_irec	g0;

		for_each_xfs_iext(&ip->i_df, &c0, &g0) {
			if (g0.br_startoff == 0 &&
			    !isnullstartblock(g0.br_startblock)) {
				b0 = g0.br_startblock;
				break;
			}
		}
		/* node1's canonical block0 is fsb=15 (P-GROW0). A flush here with
		 * block0 at a DIFFERENT fsb under EX = the stale-fork serialization
		 * that overwrites the canonical dinode (dir_reuse loss). */
		if (atomic_inc_return(&p_fen) <= 500000)
			pr_warn("mxfs: P-DIRIFLUSH ino=%llu dlm_mode=%u incore_blk0_fsb=%llu incore_nx=%llu disk_nx=%u dir_gen=%llu loaded_gen=%u relflush=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode,
				(unsigned long long)b0,
				(unsigned long long)ip->i_df.if_nextents,
				(dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC)) ?
					be32_to_cpu(dip->di_nextents) : 0xffffffff,
				(unsigned long long)ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen,
				xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
				current->comm);
	}

	/*
	 * sess67 (RULE 4 ENFORCEMENT — the "next step" the prior P-DIRIFLUSH
	 * probe deferred): a node that does NOT hold the dir's DLM in EX must not
	 * publish the dir inode's data fork.  P-DIRIFLUSH PROVED ino=131 is flushed
	 * with dlm_mode=0 (NL) by nodes that have released EX; that stray xfsaild
	 * flush writes a STALE in-core extent map over the current EX owner's
	 * authoritative map (the extent-map flip-flop, sess65), orphaning a logical
	 * dir block's daddr -> the dirents in it become unreachable on every node
	 * (dir_reuse_coherency 4/tcp durable single-entry loss; P67-POSTREAD-REREAD
	 * never fired => not a data-block content stale-RMW).  Only the EX owner, or
	 * the release-drain RELFLUSH (which runs while transitioning out of EX and
	 * MUST make our committed work durable before unlock), may publish the dir
	 * inode.  Skip any other dir-inode flush cleanly (mark stale, no I/O) so a
	 * later EX (re)acquire reloads + adopts the canonical image.  Mirrors the
	 * block0 fence's safe skip (XFS_ISTALE_CAW + error=0 + goto flush_out).
	 */
	{
		extern int mxfs_dir_iflush_owner_fence;

		if (mxfs_dir_iflush_owner_fence &&
		    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_ino != mp->m_sb.sb_rootino &&
		    ip->i_dlm_mode != MXFS_LOCK_EX &&
		    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
		    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
		     ip->i_df.if_format == XFS_DINODE_FMT_BTREE)) {
			pr_warn_ratelimited(
			    "mxfs: P67-IFLUSH-OWNER-FENCE ino=%llu dlm_mode=%u fmt=%u nx=%llu — non-EX/non-RELFLUSH dir-inode flush; skip to keep owner's canonical extent map\n",
			    (unsigned long long)ip->i_ino, ip->i_dlm_mode,
			    ip->i_df.if_format,
			    (unsigned long long)ip->i_df.if_nextents);
			xfs_iflags_set(ip, XFS_ISTALE_CAW);
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 19;
			error = 0;
			goto flush_out;
		}
	}

	/*
	 * sess65 (GPT-5.5 "first-published wins" iflush FENCE): the
	 * dir_reuse_coherency node1_f1 loss is the dir INODE's data-fork
	 * extent[0] (logical block0 -> physical block) DIVERGING across nodes for
	 * the SAME incarnation — two nodes each converted shortform->block and
	 * allocated their OWN block0 (rank1 -> daddr=120/AG0 holding node1_f1, a
	 * peer -> a higher-AG block0), and whichever iflush of this dinode lands
	 * LAST wins, orphaning the other block0.  PROVEN: node1_f1 is durably
	 * present in block0=120 on every write (never content-clobbered); it is
	 * lost only in rounds where a peer's higher block0 wins inode-131's
	 * extent[0].  FENCE: if our in-core block0 daddr is HIGHER than the disk's
	 * current block0 for the SAME incarnation (di_gen match), our extent map
	 * is a divergent late allocation — SKIP this flush so we do not clobber the
	 * canonical (lower) block0.  Deterministic lowest-block0-daddr-wins
	 * convergence; node1_f1 lives in the lowest (AG0) block0, so it is
	 * preserved.  A pure fence (no free, no fork mutation) — the node reloads
	 * and adopts the canonical block0 on its next acquire/cold-read.  Gated on
	 * mxfs_dir_iflush_fence (default off) for isolation. */
	if (mxfs_dir_iflush_fence &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    !xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
	    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     ip->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
	    !xfs_need_iread_extents(&ip->i_df) &&
	    dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
	    be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation &&
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
		if (incore_b0 && disk_b0 && incore_b0 > disk_b0) {
			pr_warn_ratelimited(
				"mxfs: P65-IFLUSH-FENCE ino=%llu incore_b0=%llu disk_b0=%llu gen=%u dlm_mode=%u comm=%s — divergent (higher) dir block0; skip flush to keep canonical lower block0\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)incore_b0,
				(unsigned long long)disk_b0,
				VFS_I(ip)->i_generation, ip->i_dlm_mode,
				current->comm);
			xfs_iflags_set(ip, XFS_ISTALE_CAW);
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 20;
			error = 0;
			goto flush_out;
		}
	}

	/*
	 * <ccloop sess49b> DATA-REGION GAP FENCE (RULE 4, PROVEN DISK-TORN root):
	 * the 8/tcp DABUF_MAP_HOLE shutdown is a durable dir dinode whose data-fork
	 * extent map SKIPS a logical block (e.g. [off0, off4, leaf] — blocks 1,2,3
	 * absent) while the leaf hash index references the missing blocks
	 * (P-HOLE-DISK DISK_MAPS_WANT=0).  A create-only dir NEVER legitimately has
	 * a hole between its data blocks, so an in-core fork with such a gap is a
	 * divergent/torn map produced by cross-node grow interference.  Flushing it
	 * writes the tear durably and shuts a peer down.  FENCE: if this is a
	 * multi-node DIRECTORY whose in-core data fork has a gap in the data region
	 * (offsets below the leaf region), DO NOT serialize it to disk — mark stale
	 * and skip, so the EX owner with the contiguous map publishes the canonical
	 * image (mirrors the P65-IFLUSH-FENCE block0-divergence skip just above). */
	if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     ip->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
	    !xfs_need_iread_extents(&ip->i_df) && mp->m_dir_geo) {
		struct xfs_bmbt_irec	gr;
		struct xfs_iext_cursor	gc;
		xfs_fileoff_t		leafoff = mp->m_dir_geo->leafblk;
		xfs_fileoff_t		prev_end = 0;
		bool			gfirst = true, ghole = false;

		for (xfs_iext_first(&ip->i_df, &gc);
		     xfs_iext_get_extent(&ip->i_df, &gc, &gr);
		     xfs_iext_next(&ip->i_df, &gc)) {
			if (gr.br_startoff >= leafoff)
				break;	/* leaf/free region — past the data region */
			if (!gfirst && gr.br_startoff > prev_end) {
				ghole = true;
				break;
			}
			prev_end = gr.br_startoff + gr.br_blockcount;
			gfirst = false;
		}
		if (ghole) {
			/* <ccloop sess49b> DETECTOR-ONLY (enforcement reverted): the
			 * gap is the PROVEN DISK-TORN root (a divergent cross-node grow
			 * left this node's in-core dir map with a hole between data
			 * blocks).  Skipping the flush here merely defers the tear: the
			 * gapped in-core fork then survives into xfs_dir2_leaf_addname
			 * which writes a leaf entry against the hole -> kernel OOPS
			 * (worse than the controlled DABUF_MAP_HOLE shutdown).  The real
			 * fix is upstream — prevent the divergent grow / heal the gapped
			 * fork BEFORE addname uses it.  Detect + log only for now. */
			pr_warn_ratelimited(
				"mxfs: P-IFLUSH-GAP-DETECT ino=%llu nextents=%llu disize=%lld gen=%u dlm_mode=%u comm=%s — in-core dir data fork has a HOLE between data blocks (divergent-grow torn map; DABUF_MAP_HOLE / leaf-addname-oops source)\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				VFS_I(ip)->i_generation, ip->i_dlm_mode,
				current->comm);
		}
	}

	/*
	 * Copy the dirty parts of the inode into the on-disk inode.  We always
	 * copy out the core of the inode, because if the inode is dirty at all
	 * the core must be.
	 */
	{
		extern unsigned long long mxfs_watch_ino;

		if (unlikely(mxfs_watch_ino) && ip->i_ino == mxfs_watch_ino)
			pr_warn("mxfs: PW-IFLUSH ino=%llu fmt=%d nx=%llu size=%lld nlink=%u pin=%d in_ail=%d fields=0x%x last=0x%x lsn=0x%llx daddr=%lld comm=%s realns=%llu\n",
				(unsigned long long)ip->i_ino,
				ip->i_df.if_format,
				(unsigned long long)ip->i_df.if_nextents,
				(long long)ip->i_disk_size,
				VFS_I(ip)->i_nlink,
				atomic_read(&ip->i_pincount),
				test_bit(XFS_LI_IN_AIL, &iip->ili_item.li_flags) ? 1 : 0,
				iip->ili_fields, iip->ili_last_fields,
				(unsigned long long)iip->ili_item.li_lsn,
				(long long)bp->b_maps[0].bm_bn,
				current->comm,
				(unsigned long long)ktime_get_real_ns());
	}
	xfs_inode_to_disk(ip, dip, iip->ili_item.li_lsn);

	/* Wrap, we never let the log put out DI_MAX_FLUSH */
	if (!xfs_has_v3inodes(mp)) {
		if (ip->i_flushiter == DI_MAX_FLUSH)
			ip->i_flushiter = 0;
	}

	xfs_iflush_fork(ip, dip, iip, XFS_DATA_FORK);
	if (xfs_inode_has_attr_fork(ip))
		xfs_iflush_fork(ip, dip, iip, XFS_ATTR_FORK);

	/*
	 * Sess29 v0.3.120: P64-INSTR — capture iflush'd content for SF dirs.
	 * Compare with P55-INSTR (post-bast_process disk read) to verify
	 * iflush serializes the expected (post-modification) ip state.
	 *
	 * Hypothesis 2 from sess29 state.md: iflush might serialize stale
	 * pre-modification state, explaining Mode A.  P64 captures what
	 * iflush actually writes to the buf for cross-correlation.
	 */
	/* sess8 (a9a03929) P8-SFIFLUSH — platter ledger (gated dir_relverify):
	 * dip now holds the exact image the cluster buffer will write.  For a
	 * multi-node SF dir, ledger the full name set: the FIRST flush whose
	 * set contains a name after its owner's P8-SFRM removed it is the
	 * resurrection creator (a stale-base RMW being made durable). */
	if (({ extern int mxfs_dir_relverify; mxfs_dir_relverify; }) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    dip->di_format == XFS_DINODE_FMT_LOCAL && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern void mxfs_sf_fmt_names(struct xfs_mount *,
				struct xfs_dir2_sf_hdr *, char *, size_t);
		char p8nm[160];

		mxfs_sf_fmt_names(mp, (struct xfs_dir2_sf_hdr *)
				  XFS_DFORK_DPTR(dip), p8nm, sizeof(p8nm));
		pr_warn("mxfs: P8-SFIFLUSH ino=%llu size=%lld daddr=%lld in_ail=%d names=[%s] comm=%s realns=%llu\n",
			(unsigned long long)ip->i_ino,
			(long long)be64_to_cpu(dip->di_size),
			(long long)bp->b_maps[0].bm_bn,
			test_bit(XFS_LI_IN_AIL, &iip->ili_item.li_flags) ? 1 : 0,
			p8nm, current->comm,
			(unsigned long long)ktime_get_real_ns());
	}

	if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm) {
		uint8_t fmt = dip->di_format;
		int64_t disk_size = (int64_t)be64_to_cpu(dip->di_size);
		char p64_first[32] = "";
		if (fmt == XFS_DINODE_FMT_LOCAL && disk_size > 6) {
			char *ondisk = (char *)dip + sizeof(struct xfs_dinode);
			struct xfs_dir2_sf_hdr *sfh =
				(struct xfs_dir2_sf_hdr *)ondisk;
			struct xfs_dir2_sf_entry *sfe =
				xfs_dir2_sf_firstentry(sfh);
			int len = min_t(int, sfe->namelen, 31);
			memcpy(p64_first, sfe->name, len);
			p64_first[len] = '\0';
		}
		mxfs_idbg("mxfs: P64-INSTR ino=%llu IFLUSH-DIR fmt=%u disk_size=%lld first=\"%s\" realns=%llu\n",
			(unsigned long long)ip->i_ino, fmt,
			(long long)disk_size, p64_first,
			(unsigned long long)ktime_get_real_ns());
	}

	/*
	 * sess50 (run14d) PRODUCER PROBE — cross_write_read torn dir dinode.
	 * A directory flushed in EXTENTS format whose FIRST data-fork extent
	 * record does not decode to a valid filesystem block was copied from an
	 * in-core fork that is mid-LOCAL->EXTENTS-conversion torn (di_format
	 * EXTENTS in the core but the literal still holds stale shortform dir
	 * bytes, e.g. "data_node…").  Such a dinode PASSES the structural write
	 * verifier (xfs_dinode_verify decodes di_nextents vs forkoff only) but
	 * FAILS every reader's xfs_iformat_extents -> EUCLEAN -> FS shutdown
	 * (PROVEN sess50: ino=444 .mxfs_test/cross_write_read, 16-node).  Catch
	 * the producing flush + its call stack here, at the in-core->disk copy.
	 */
	{
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		if (S_ISDIR(VFS_I(ip)->i_mode) && mp->m_mxfs_dlm &&
		    (mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    dip->di_format == XFS_DINODE_FMT_EXTENTS &&
		    be64_to_cpu(dip->di_big_nextents) >= 1) {
			struct xfs_bmbt_rec *frp = (struct xfs_bmbt_rec *)
				XFS_DFORK_PTR(dip, XFS_DATA_FORK);
			struct xfs_bmbt_irec irec;

			xfs_bmbt_disk_get_all(frp, &irec);
			if (!xfs_verify_fsbext(mp, irec.br_startblock,
					       irec.br_blockcount)) {
				unsigned char *fb = (unsigned char *)frp;

				pr_warn("mxfs: P-IFLUSH-DIRTORN ino=%llu nx=%llu forkoff=%u startblk=0x%llx cnt=0x%llx first16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x comm=%s pid=%d realns=%llu — torn LOCAL->EXTENTS dir dinode about to be written; stack:\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)be64_to_cpu(dip->di_big_nextents),
					dip->di_forkoff,
					(unsigned long long)irec.br_startblock,
					(unsigned long long)irec.br_blockcount,
					fb[0], fb[1], fb[2], fb[3], fb[4], fb[5],
					fb[6], fb[7], fb[8], fb[9], fb[10], fb[11],
					fb[12], fb[13], fb[14], fb[15],
					current->comm, current->pid,
					(unsigned long long)ktime_get_real_ns());
				dump_stack();
			}
		}
	}

	/*
	 * We've recorded everything logged in the inode, so we'd like to clear
	 * the ili_fields bits so we don't log and flush things unnecessarily.
	 * However, we can't stop logging all this information until the data
	 * we've copied into the disk buffer is written to disk.  If we did we
	 * might overwrite the copy of the inode in the log with all the data
	 * after re-logging only part of it, and in the face of a crash we
	 * wouldn't have all the data we need to recover.
	 *
	 * What we do is move the bits to the ili_last_fields field.  When
	 * logging the inode, these bits are moved back to the ili_fields field.
	 * In the xfs_buf_inode_iodone() routine we clear ili_last_fields, since
	 * we know that the information those bits represent is permanently on
	 * disk.  As long as the flush completes before the inode is logged
	 * again, then both ili_fields and ili_last_fields will be cleared.
	 */
	error = 0;
	/*
	 * sess18: success path only — this image is now in the cluster buffer
	 * and carries every committed change up to pub_seq_at_copyin.  The
	 * obligation is NOT discharged yet (the buffer has not been written);
	 * xfs_iflush_finish does that from the write completion.
	 */
	ip->i_mxfs_pub_flush_seq = pub_seq_at_copyin;
	/* sess35 P241: a fresh copy-in supersedes any prior overlay of this
	 * inode's slot — the staged image is current again, so a later
	 * discharge is honest.  Disarm the blind-discharge tripwire. */
	xfs_iflags_clear(ip, MXFS_IF_CLMERGE_HIT);
	/* sess34 P240 (Gemini 2c chain-of-custody): pair every sanctioned-
	 * release copy-in with its BUFFER IDENTITY, so a later overlay trace
	 * (P239) proves whether the condemning merge ran on the SAME buffer
	 * instance (theory i: flag sub-window) or a DIFFERENT one (theory ii:
	 * instance replacement — the run64 blindness family).  RELFLUSH-gated:
	 * a few lines per dirty-at-release file, nothing on hot paths. */
	if (unlikely(xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH)))
		pr_warn_ratelimited(
		    "mxfs: P240-COPYIN-ID ino=%llu bp=%px flush=%llu pend=%llu dur=%llu comm=%s realns=%llu\n",
			(unsigned long long)ip->i_ino, bp,
			(unsigned long long)ip->i_mxfs_pub_flush_seq,
			(unsigned long long)ip->i_mxfs_pub_pending_seq,
			(unsigned long long)ip->i_mxfs_pub_durable_seq,
			current->comm,
			(unsigned long long)ktime_get_real_ns());
	/*
	 * ccloop c7ee71c6 sess30 — record WHICH TENURE these bytes were staged
	 * under.  The buffer is submitted later (xfsaild), and the grant can be
	 * lost in between; the cluster-write site compares this against the live
	 * i_dlm_epoch to see whether it is publishing a dead tenure's image.
	 * Success path only: a skipped flush staged nothing.
	 *
	 * sess31: the release path stores mode=NL and epoch++ as two plain
	 * stores under i_dlm_lock (xfs_mxfs_dlm.c ~14513-14516); a lockless
	 * two-field read here can interleave them and stamp {old epoch, NL} —
	 * the measured class-Y P219 shape.  A double-read of the epoch around
	 * the mode read makes the pair coherent without taking i_dlm_lock
	 * (this path can run inside drain contexts whose lock state varies).
	 */
	{
		unsigned long se;
		u8 sm;
		int tries = 0;

		do {
			se = READ_ONCE(ip->i_dlm_epoch);
			sm = READ_ONCE(ip->i_dlm_mode);
		} while (READ_ONCE(ip->i_dlm_epoch) != se && ++tries < 8);
		ip->i_mxfs_pub_stage_epoch = se;
		ip->i_mxfs_pub_stage_mode = sm;
	}
	ip->i_mxfs_pub_stage_ns = ktime_get_real_ns();
flush_out:
	spin_lock(&iip->ili_lock);
	iip->ili_last_fields = iip->ili_fields;
	iip->ili_fields = 0;
	set_bit(XFS_LI_FLUSHING, &iip->ili_item.li_flags);
	spin_unlock(&iip->ili_lock);

	/*
	 * Store the current LSN of the inode so that we can tell whether the
	 * item has moved in the AIL from xfs_buf_inode_iodone().
	 */
	xfs_trans_ail_copy_lsn(mp->m_ail, &iip->ili_flush_lsn,
				&iip->ili_item.li_lsn);

	/* generate the checksum. */
	xfs_dinode_calc_crc(mp, dip);
	if (error)
		xfs_inode_mark_sick(ip, XFS_SICK_INO_CORE);
	return error;
}

/*
 * sess61: cross-inode CLUSTER-BUFFER false-sharing fix (PROVEN root cause).
 *
 * A directory inode and an adjacent regular-file inode can live in the SAME
 * inode-cluster buffer (up to 64 inodes/cluster).  MXFS grants DLM locks
 * per-INODE but the buffer cache is per-CLUSTER.  When peers modify the DIR
 * inode under its EX DLM (made platter-durable before EX->NL via the
 * drain-before-unlock barrier + sess39 dir-data durability barrier), THIS
 * node's cached copy of the cluster buffer is never refreshed for the dir
 * slot: we hold NL on the dir, and the per-inode BAST only forces a re-read on
 * the next READ -- but a dirty co-resident CHILD pins the buffer resident and
 * the next access is a WRITE.  When xfsaild flushes the dirty child via
 * xfs_iflush_cluster, it writes the WHOLE cluster, carrying this node's STALE
 * dir slot back to disk and REVERTING the peers' committed dir entries
 * (PROVEN sess61: P-DIRFLUSH ino=4194434 count=4 written by test4, then count=2
 * written by test2 ~248ms later -> node1.txt/node4.txt LOST on disk).
 *
 * FIX: before the cluster buffer is submitted, FUA-read the CURRENT on-disk
 * cluster and OVERLAY the on-disk image of every FOREIGN directory inode (a
 * S_ISDIR dinode we are NOT flushing this round) so the durable peer-committed
 * dir is written back instead of our stale cached copy.
 *
 * Scope = directories only.  Dir writes are durable-before-visible here, so the
 * FUA read returns the committed dir, not a stale-in-cache value.  Regular-file
 * di_size does NOT have that guarantee (sess44 attempt-2 read a not-yet-durable
 * di_size=0 and re-wrote 0), so regular files are deliberately NOT merged.
 *
 * Safety (per Gemini architectural review, sess61):
 *  - Only FOREIGN slots are touched.  Inodes we are flushing or own-ahead stay
 *    attached as inode log items (XFS_IFLUSHING) in b_li_list until buffer I/O
 *    completes, so they are excluded by the `flushing` mask and never overlaid.
 *  - If the buffer carries a DIRTY xfs_buf_log_item (e.g. di_next_unlinked
 *    buf-logged under the AGI lock), the merge is SKIPPED entirely -- overlaying
 *    a buf-logged region with a pre-update disk read would corrupt the unlinked
 *    list / AGI hash bucket.
 *  - CRC-safe: we copy the peer's FULL dinode incl. di_lsn, so the per-inode
 *    write verifier recomputes a valid CRC.
 *  - di_lsn is NOT comparable across nodes (per-node journal slices), so the
 *    NL-vs-disk authority rule (Invariant #1: durable-before-NL) is what makes
 *    the overlay correct, not an LSN compare.
 */
/*
 * sess34 (c7ee71c6) D-CRASH-COLDREAD-STALE-SPLIT FIX-1 — LEDGER HONESTY AT
 * THE OVERLAY.  PROVEN incident (crash_consistency 20260731T131837Z, ino
 * 18876678 slot 6 of daddr 18841320): xfs_iflush copied the cc=6 O_SYNC
 * image into the cluster buffer (i_mxfs_pub_flush_seq -> pend), the merge
 * below then RESTORED the platter's cc=4 image over that slot, and the
 * buffer's completion discharged durable = flush for bytes that were merged
 * away and never reached the wire.  The release tail's close_or_defer then
 * read pend == durable (honestly closed, blind-closed in fact) and handed
 * the tenure to peers with the acknowledged O_SYNC append existing nowhere
 * but in this node's soon-to-be-reloaded core — permanent cluster-wide loss
 * of fsync'd data.
 *
 * Same shape and same cure as the P56 partial-write skip (pal/linux/
 * xfs_buf.c): dropping a staged image from the actual I/O REQUIRES rolling
 * the flush watermark back so the buffer-wide completion's discharge is a
 * no-op for this inode and the obligation stays open until its bytes really
 * land.  MXFS_IF_PUB_SKIPPED re-arms the item so retry paths keep it.
 */
static void
mxfs_clmerge_ledger_rollback(struct xfs_inode *oip, int slot, const char *arm,
			     struct xfs_buf *mrb_bp, u64 mrb_pcc, u32 mrb_pgen)
{
	u64 mrb_f, mrb_d;

	if (!oip)
		return;
	/* sess34 P239 (Gemini 2c): UNCONDITIONAL identity trace for every
	 * overlay of a slot carrying an in-flight copy-in claim — pairs with
	 * P240 (copy-in side) by ino + bp pointer to settle theory (i)
	 * flag-sub-window vs theory (ii) buffer-instance replacement.  The
	 * behavioral rollback below stays RELFLUSH-gated.
	 *
	 * sess34b CLASSIFIER (consult #3): pcc (the PLATTER slot's
	 * changecount from the merge's own coherent read) vs icc (in-core
	 * iversion) decides whether this condemnation protects a PEER's
	 * newer image (pcc ahead of our landed knowledge = true staleness;
	 * fatal-tripwire class per Gemini once proven the only class) or
	 * reverts OUR OWN newer state while no peer ever wrote (icc > pcc
	 * with the wire grant never having left = provenance FALSE
	 * POSITIVE from in-core epoch churn — the mask predicate, not the
	 * data, is stale; making the tripwire fatal on this class would
	 * shut down healthy nodes).  Classify before enforcing (RULE 4). */
	if (READ_ONCE(oip->i_mxfs_pub_flush_seq) !=
	    READ_ONCE(oip->i_mxfs_pub_durable_seq)) {
		/* sess35 CLASS DISCRIMINATORS (RULE 4, classifier round 2):
		 *  gen/pgen — in-core vs platter incarnation.  gen==pgen with
		 *    icc>pcc = the overlay reverts OUR OWN same-incarnation
		 *    newer state (defect class); gen!=pgen = peer freed+
		 *    recreated the ino and our in-core is a dead incarnation
		 *    (overlay is the designed correction, in-core void).
		 *  ds/gs — dirty_seq vs ex_grant_seq at condemnation: gs
		 *    ahead of ds under a held EX names mid-tenure epoch
		 *    churn (see P242 at the bump sites).
		 *  fields — non-zero means the item is re-logged and the
		 *    in-core state WILL be copied in again (self-healing);
		 *    zero means the coming iodone detaches it clean (P241).
		 */
		pr_warn_ratelimited(
		    "mxfs: P239-OVERLAY-ID ino=%llu slot=%d arm=%s bp=%px relflush=%d dlm_mode=%u flush=%llu dur=%llu pend=%llu pcc=%llu icc=%llu gen=%u pgen=%u ds=%llu gs=%llu fields=0x%x comm=%s realns=%llu\n",
			(unsigned long long)oip->i_ino, slot, arm, mrb_bp,
			xfs_iflags_test(oip, MXFS_IF_DLM_RELFLUSH) ? 1 : 0,
			(unsigned)oip->i_dlm_mode,
			(unsigned long long)oip->i_mxfs_pub_flush_seq,
			(unsigned long long)oip->i_mxfs_pub_durable_seq,
			(unsigned long long)oip->i_mxfs_pub_pending_seq,
			(unsigned long long)mrb_pcc,
			(unsigned long long)inode_peek_iversion(VFS_I(oip)),
			VFS_I(oip)->i_generation, mrb_pgen,
			(unsigned long long)oip->i_mxfs_dirty_seq,
			(unsigned long long)oip->i_mxfs_ex_grant_seq,
			oip->i_itemp ? READ_ONCE(oip->i_itemp->ili_fields) : 0,
			current->comm,
			(unsigned long long)ktime_get_real_ns());
		/* P241 arm: mark the slot so the buffer-wide completion's
		 * durable discharge over this merged-away image is traced. */
		xfs_iflags_set(oip, MXFS_IF_CLMERGE_HIT);
	}
	/*
	 * sess34 REFINEMENT (RULE 4 — the unconditional first cut was a
	 * PROVEN LIVELOCK ENGINE, caught same session on its first board:
	 * test32 ino 62914705 looped copy-in(flush 6->7) -> overlay ->
	 * rollback(7->6) -> re-arm -> re-push, 50 capped P238 + 1926
	 * P187 in minutes, immortal dirty item, no-inode release fence
	 * P-NOINO-RELFENCE-WEDGE -> node shutdown).  The copy-in gate and
	 * the merge mask use DIFFERENT authority predicates; for a slot
	 * in that gap (copy-in allowed, mask condemns — e.g. revoked
	 * provenance / pipe-relog forms) the overlay is the DESIGNED
	 * correction and the in-core change is void: the pre-existing
	 * complete-clean resolution (dur = flush at iodone) is correct
	 * for it, and keeping it dirty can never converge.
	 *
	 * Roll back + re-arm inside the sanctioned-release window
	 * (MXFS_IF_DLM_RELFLUSH): there the staged image is a release
	 * OBLIGATION — condemning it without rolling the ledger back is
	 * the blind-close that lost the 20260731 O_SYNC append — and the
	 * window is short + pipeline-paced, so no condemn loop can
	 * sustain (the loop ino above had RELFLUSH clear).
	 *
	 * sess35 FIX-C (Gemini P1, paired with FIX-B3): ALSO roll back for a
	 * SAME-INCARNATION condemnation of our own strictly-newer state
	 * (mode EX, gen == platter gen, in-core iversion > platter
	 * changecount, not ISTALE): the P239/P241 capture (ino 58729920)
	 * proved the complete-clean resolution blind-discharges exactly this
	 * class and leaves the in-core state as the sole copy of
	 * acknowledged data.  Livelock safety (the 293 lesson): the 293 loop
	 * class had REVOKED authority (gen mismatch / authority gap) —
	 * excluded here by the gen equality + EX check; and FIX-B3 protects
	 * the re-staged image on the next push (stage_epoch == current
	 * tenure), so the condemn/rollback pair cannot recur on the same
	 * state.
	 */
	{
		bool mrb_rel = xfs_iflags_test(oip, MXFS_IF_DLM_RELFLUSH);
		bool mrb_own = oip->i_dlm_mode == MXFS_LOCK_EX &&
			!xfs_iflags_test(oip, XFS_ISTALE) &&
			VFS_I(oip)->i_generation == mrb_pgen &&
			inode_peek_iversion(VFS_I(oip)) > mrb_pcc;

		if (!mrb_rel && !mrb_own)
			return;
		mrb_f = READ_ONCE(oip->i_mxfs_pub_flush_seq);
		mrb_d = READ_ONCE(oip->i_mxfs_pub_durable_seq);
		if (mrb_f == mrb_d)
			return;
		oip->i_mxfs_pub_flush_seq = mrb_d;
		xfs_iflags_set(oip, MXFS_IF_PUB_SKIPPED);
		pr_warn_ratelimited(
		    "mxfs: P238-CLMERGE-LEDGER-ROLLBACK ino=%llu slot=%d arm=%s cls=%s flush=%llu->%llu pend=%llu — overlay replaced a staged image; rolled the flush watermark back so the completion cannot discharge merged-away bytes\n",
			(unsigned long long)oip->i_ino, slot, arm,
			mrb_rel ? "relflush" : "samegen-own",
			(unsigned long long)mrb_f, (unsigned long long)mrb_d,
			(unsigned long long)READ_ONCE(oip->i_mxfs_pub_pending_seq));
	}
}

static void
mxfs_iflush_cluster_merge_dirs(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_log_item	*lip;
	void			*scratch;
	uint64_t		flushing = 0;
	uint64_t		authorit = 0;	/* c7ee71c6 sess3: same-tenure provenance — exempt from DEADINCARN overlay */
	uint64_t		curstage = 0;	/* sess35 FIX-B3: live staged image produced under the CURRENT tenure */
	/* sess34 (c7ee71c6) D-CRASH-COLDREAD-STALE-SPLIT FIX-1: attached
	 * in-core inode per slot, so an overlay can roll the publication
	 * ledger back for the image it just replaced (see the overlay
	 * sites below).  b_li_list attachment is exactly the population
	 * with a live copy-in claim. */
	struct xfs_inode	*slot_ip[64] = { NULL };
	unsigned int		inodelog;
	unsigned int		inodesize;
	unsigned int		len;
	uint64_t		lba_512;
	int			ni, i;
	bool			foreign_dir = false;
	xfs_agnumber_t		agno = 0;
	xfs_agino_t		first_agino = 0;

	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	/*
	 * sess113 (Gemini RULE-5, PROVEN ROOT): this merge does a SYNCHRONOUS
	 * forced SCSI FUA read (mxfs_pal_scsi_read_fua_bdev) while xfsaild holds
	 * the inode-CLUSTER buffer lock (b_lock_ip = xfs_inode_item_push trylock).
	 * On the SCST target a forced-FUA read can stall/error (scsi_eh active) —
	 * that is the cache_coherency release-path DRAIN WEDGE: ino=128's cluster
	 * buffer left locked + IFLUSHING + in_ail with no live holder, peer EX
	 * times out -> shutdown.  When fua_disable=1 (the module DEFAULT since
	 * sess94), reads already route through the coherent shared cache, so this
	 * FUA-overlay is BOTH unnecessary AND the thing that wedges the flush.
	 * Skip it entirely under fua_disable.
	 *
	 * sess134 REVISED: skipping the merge under fua_disable left the
	 * P133-DIRINO-REVERT clobber open — an xfsaild push of a cluster
	 * buffer carrying a PRIOR-tenure dir-dinode image (this node's flush
	 * authority since revoked) overwrote a peer's durable dir growth
	 * (size/nextents shrank -> dabuf-map HOLE -> 12-node shutdown,
	 * p134b).  The overlay IS needed under fua_disable; only the forced-
	 * FUA wedge risk is not.  Use a plain bdev read (the shared cache is
	 * coherent under fua_disable — the same read the P133 probe used to
	 * SEE the newer disk image) instead of the forced SCSI FUA read.
	 */
	if (bp->b_map_count != 1)
		return;

	inodelog = mp->m_sb.sb_inodelog;
	inodesize = mp->m_sb.sb_inodesize;
	len = BBTOB(bp->b_length);
	ni = len >> inodelog;
	if (ni <= 0 || ni > 64)
		return;

	/*
	 * Slots being flushed this round -- or own-ahead (XFS_IFLUSHING items
	 * stay attached until buffer I/O completes) -- must NOT be overlaid.
	 */
	list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
		struct xfs_inode_log_item *iip;
		struct xfs_inode	*ip;
		int			slot;

		if (lip->li_type != XFS_LI_INODE)
			continue;
		iip = (struct xfs_inode_log_item *)lip;
		ip = iip->ili_inode;
		if (!ip)
			continue;
		/* sess34 FIX-1: record every attached inode by slot (before any
		 * of the protection-mask decisions below skip it) — the overlay
		 * ledger-rollback needs the inode even for slots the mask does
		 * NOT protect; a mask miss is precisely the hazard. */
		slot = ip->i_imap.im_boffset >> inodelog;
		if (slot >= 0 && slot < ni && slot < 64)
			slot_ip[slot] = ip;
		/*
		 * sess35 FIX-B3 (c7ee71c6, Gemini priority-1 design): the mask
		 * predicate below trusts the ITEM's provenance (dirty_seq vs
		 * ex_grant_seq) — but commits that legitimately slip into a
		 * closing tenure (FIX-25 ioend conversions; P220/P242 measured
		 * the leak) carry the OLD tenure's dirty_seq, while the copy-in
		 * that staged them ran under the CURRENT tenure and was
		 * sanctioned by the copy-in gate.  The STAGING tenure is the
		 * authority token for the BUFFER image: stage_epoch ==
		 * i_dlm_epoch (coherent pair, stamped at xfs_iflush) with the
		 * grant EX and a live claim (flush != durable) means THIS
		 * node's current tenure produced the staged image.  Mark it;
		 * the overlay loop protects it after verifying the platter is
		 * the same incarnation and not ahead (peer-continuity guards).
		 * PROVEN victim: ino 58729920 — staged flush 7->9 under T2,
		 * ds=311 vs gs=312 -> condemned, blind-discharged, in-core
		 * left sole copy (P239/P241 capture, 20260731).
		 */
		if (slot >= 0 && slot < ni && slot < 64 &&
		    ip->i_dlm_mode == MXFS_LOCK_EX &&
		    ip->i_mxfs_pub_stage_mode == MXFS_LOCK_EX &&
		    READ_ONCE(ip->i_mxfs_pub_stage_epoch) ==
		    READ_ONCE(ip->i_dlm_epoch) &&
		    READ_ONCE(ip->i_mxfs_pub_flush_seq) !=
		    READ_ONCE(ip->i_mxfs_pub_durable_seq))
			curstage |= (1ULL << slot);
		/*
		 * sess134: an attached inode whose flush AUTHORITY is revoked
		 * (the P119 non-EX skip / sess17b epoch skip above refused its
		 * copy-in) leaves only a prior-tenure image in the buffer; the
		 * durable disk slot is the authority.  Leave its flushing bit
		 * clear so the overlay below restores it (PROVEN clobber:
		 * P133-DIRINO-REVERT on ino=131, p134b storm).  An EX-held
		 * same-tenure inode that merely could not flush this round
		 * (pinned/trylock-fail) keeps its bit — its buffer image is
		 * this node's own authoritative prior flush.
		 */
		/*
		 * sess55 (ccloop 8ddb16a2) — mirror of the xfs_iflush P55 co-resident
		 * committed-change exception.  An attached DIR we hold at PR with a
		 * pending committed change (in_ail) has an AUTHORITATIVE buffer image:
		 * xfs_iflush (P55) copied our committed dirent REMOVAL into the buffer
		 * this round.  PR<->EX exclusivity guarantees no peer wrote (or freed/
		 * realloc'd) the on-disk slot since we took PR, so disk is STALE and the
		 * buffer wins; PR-hold => same incarnation (no ghost risk).  KEEP the
		 * flushing bit so the overlay below does NOT copy the stale disk image
		 * back over our removal (PROVEN sess55: without this the merge overlaid
		 * disk AFTER P55's flush and RESURRECTED node2's renamed-away n2_rNN ->
		 * tcp_dlm_scaling "drained got=N").  Precedes the sess134 revoke. */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    ip->i_dlm_mode == MXFS_LOCK_PR &&
		    ip->i_itemp &&
		    test_bit(XFS_LI_IN_AIL, &ip->i_itemp->ili_item.li_flags)) {
			slot = ip->i_imap.im_boffset >> inodelog;
			if (slot >= 0 && slot < ni) {
				flushing |= (1ULL << slot);
				/* PR-hold => same incarnation (documented
				 * above) — full authority incl. gen. */
				authorit |= (1ULL << slot);
			}
			continue;
		}
		if (!xfs_iflags_test(ip, MXFS_IF_DLM_RELFLUSH) &&
		    (ip->i_dlm_mode != MXFS_LOCK_EX ||
		     ip->i_mxfs_dirty_seq != ip->i_mxfs_ex_grant_seq))
			continue;
		slot = ip->i_imap.im_boffset >> inodelog;
		if (slot >= 0 && slot < ni) {
			flushing |= (1ULL << slot);
			/*
			 * ccloop c7ee71c6 sess3 (RULE 4, PROVEN via
			 * P-CLMERGE-DEADINCARN @15:30:34 == the round-4
			 * node1_f1..f6 loss instant): same-tenure dirty
			 * provenance (dirty_seq == ex_grant_seq) means THIS
			 * node produced the buffer image under a continuously
			 * held grant — including a brand-new incarnation
			 * (mkdir reusing a freed ino) whose platter slot still
			 * carries the PRIOR incarnation because the free/create
			 * are deferred-destage now (eager=0).  Such a slot is
			 * authoritative even on a di_gen mismatch: the
			 * DEADINCARN overlay below must NOT resurrect the
			 * platter's dead incarnation over it (that re-wrote
			 * gen 3691193945 over fresh 456508100 and reverted the
			 * creator).  A genuine dead-shell ghost (evict-ring
			 * overflow family) was dirtied under a PRIOR tenure —
			 * seqs differ — so it never gets this bit and stays
			 * protected by the overlay.
			 */
			if (ip->i_mxfs_dirty_seq == ip->i_mxfs_ex_grant_seq)
				authorit |= (1ULL << slot);
		}
	}

	/*
	 * Any FOREIGN inode (not flushed this round) at risk of a stale-buffer
	 * revert?  sess62: this is no longer dir-only.  A regular-file inode
	 * co-resident with a foreign dir gets reverted ALLOCATED->FREE by the
	 * same false-sharing flush (PROVEN: cross_visibility node1.txt ino=132
	 * disk_mode=0 while in-core mode=0100644 -> dirent present, stat ENOENT).
	 * Trigger the FUA-merge whenever there is any foreign ALLOCATED inode
	 * (dir or regular) in the buffer: its durable on-disk image is the
	 * authority and our cached copy may be stale.
	 */
	for (i = 0; i < ni; i++) {
		struct xfs_dinode *dip;

		if (flushing & (1ULL << i))
			continue;
		dip = xfs_buf_offset(bp, i << inodelog);
		if (be16_to_cpu(dip->di_magic) != XFS_DINODE_MAGIC)
			continue;
		if (be16_to_cpu(dip->di_mode) != 0) {
			foreign_dir = true;
			break;
		}
	}
	if (!foreign_dir)
		return;

	/*
	 * sess44 (ccloop 8ddb16a2): a dirty buf-log-item means a buf-logged range
	 * is pending + not durable.  The ONLY field buf-logged on an inode-CLUSTER
	 * buffer is di_next_unlinked (updated in-place under the AGI lock during
	 * iunlink; inode CORE changes go through the inode log item, NOT the buf
	 * log).  The old code SKIPPED the whole overlay here — but that left the
	 * cross-node stale co-resident-slot CLOBBER window OPEN precisely during the
	 * inactivation/iunlink churn that wedges the 2/tcp suite (PROVEN sess44: a
	 * peer's dir/inode slot overwritten with this node's stale image -> later
	 * xfs_iget verify-fail on the cluster -> shutdown; repro = dlm_fairness +
	 * rsync_paired + crash_consistency on one prep).  Do NOT skip.
	 *
	 * sess48: the sess44 companion rule — "PRESERVE each overlaid slot's
	 * BUFFER di_next_unlinked when the buf is dirty" — is GONE, replaced
	 * by the mount iunlink store overlay after the merge loop.  The flag
	 * was buffer-level, so it (a) skipped exactly when the iunlink write
	 * was checkpointed (BLI detached ⇒ fossil installed in-core — the
	 * PROVEN P53 producer, 390-c1 WRSITE bli=0 specimens), (b) could
	 * restore OUR stale value over a FOREIGN slot's fresher disk image,
	 * and (c) restored without a CRC recompute — di_next_unlinked IS
	 * inside the di_crc region (upstream xfs_iunlink_update_dinode
	 * recomputes after every store).
	 */
	scratch = kmalloc(len, GFP_NOFS);
	if (!scratch)
		return;

	lba_512 = bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	if (mxfs_fua_disable) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
				uint64_t, void *, uint32_t);

		if (mxfs_pal_bdev_read_plain_bdev(bp->b_target->bt_bdev,
						  lba_512, scratch, len) != 0) {
			kfree(scratch);
			return;
		}
	} else if (mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev, lba_512,
					scratch, len) != 0) {
		kfree(scratch);
		return;
	}

	if (bp->b_pag) {
		agno = pag_agno(bp->b_pag);
		first_agino = XFS_AGB_TO_AGINO(mp,
				xfs_daddr_to_agbno(mp, xfs_buf_daddr(bp)));
	}

	for (i = 0; i < ni; i++) {
		struct xfs_dinode *dbuf, *ddisk;
		uint16_t	bmode, dmode;
		bool		buf_alloc, disk_alloc;

		dbuf  = xfs_buf_offset(bp, i << inodelog);
		ddisk = (struct xfs_dinode *)((char *)scratch + (i << inodelog));
		if (flushing & (1ULL << i)) {
			/*
			 * sess-tcp INCARNATION FENCE (PROVEN dir_reuse_coherency root,
			 * [[sess-tcp-SEED-ROOT-ino131-free-lost-to-evict-ring-overflow]]).
			 * Normally an EX-held / own-flush slot is authoritative and left
			 * untouched.  EXCEPT a DIRECTORY slot whose in-core incarnation
			 * (di_gen) DIFFERS from the durable on-disk one: the dir inode#
			 * was freed+recreated by a peer (rm-rf + mkdir each round) and
			 * this node never reloaded the new incarnation (the INODE_FREE
			 * evict-ring hint is unreliable for the dir), so its in-core
			 * extent map is a DEAD prior incarnation pointing block0 at a
			 * freed daddr.  Writing it reverts the peer's fresh dir inode
			 * (block0 daddr divergence -> getdents reads block0 at the stale
			 * daddr -> readdir short, lookup_fail=0).  Overlay the canonical
			 * on-disk image so the dead incarnation can never win.  SAFE:
			 * only DIRECTORIES, and only on a real di_gen MISMATCH -- rank1 is
			 * the sole dir creator so this node's dir incarnation is never
			 * AHEAD of disk; legitimate same-incarnation growth (di_gen ==)
			 * is never reverted (that case keeps the sess85/sess62 rules).
			 */
			if (!(be16_to_cpu(ddisk->di_magic) == XFS_DINODE_MAGIC &&
			      be16_to_cpu(dbuf->di_magic) == XFS_DINODE_MAGIC &&
			      S_ISDIR(be16_to_cpu(ddisk->di_mode)) &&
			      S_ISDIR(be16_to_cpu(dbuf->di_mode)) &&
			      be32_to_cpu(dbuf->di_gen) != be32_to_cpu(ddisk->di_gen)))
				continue;
			/*
			 * ccloop c7ee71c6 sess3 (RULE 4 PROVEN — see the
			 * authorit mask above): a same-tenure sanctioned flush
			 * of a NEW incarnation legitimately has buf_gen !=
			 * disk_gen while the deferred-destage platter lags.
			 * The "never AHEAD of disk" premise of this arm died
			 * with eager=0.  Never overlay an authoritative slot.
			 */
			if (authorit & (1ULL << i)) {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P-CLMERGE-AUTH-KEEP slot=%d buf_gen=%u disk_gen=%u — same-tenure new incarnation; buffer wins (platter lags)",
				    i, be32_to_cpu(dbuf->di_gen),
				    be32_to_cpu(ddisk->di_gen));
				continue;
			}
			{
				uint32_t mxfs_pre_gen = be32_to_cpu(dbuf->di_gen);

				memcpy(dbuf, ddisk, inodesize);
				mxfs_clmerge_ledger_rollback(
					i < 64 ? slot_ip[i] : NULL, i,
					"deadincarn", bp,
					(u64)be64_to_cpu(ddisk->di_changecount),
					be32_to_cpu(ddisk->di_gen));
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P-CLMERGE-DEADINCARN slot=%d pre_buf_gen=%u disk_gen=%u — overlaid dead prior-incarnation dir slot with canonical disk image",
				    i, mxfs_pre_gen,
				    be32_to_cpu(ddisk->di_gen));
			}
			continue;
		}

		/*
		 * sess35 FIX-B3 (Gemini P1): a slot whose LIVE staged image was
		 * produced under the CURRENT EX tenure is this node's own
		 * authoritative staging even when the item's dirty_seq predates
		 * the tenure (leaked-commit class, P242).  Protect it — but
		 * only with peer-continuity proven from the coherent disk read:
		 * same incarnation (di_gen equal) AND the platter is not ahead
		 * (its changecount <= the staged image's).  A platter that is
		 * ahead means a peer published since our knowledge (missed
		 * handoff / instance skew) — fall through to the restore arms,
		 * where the FIX-C rollback keeps the ledger honest.
		 */
		if ((curstage & (1ULL << i)) &&
		    be16_to_cpu(dbuf->di_magic) == XFS_DINODE_MAGIC &&
		    be16_to_cpu(ddisk->di_magic) == XFS_DINODE_MAGIC &&
		    dbuf->di_gen == ddisk->di_gen &&
		    be64_to_cpu(ddisk->di_changecount) <=
		    be64_to_cpu(dbuf->di_changecount)) {
			pr_warn_ratelimited(
			    "mxfs: P243-CURSTAGE-KEEP ino=%llu slot=%d gen=%u dcc=%llu bcc=%llu flush=%llu dur=%llu — current-tenure staged image kept (leaked-commit provenance would have condemned it)\n",
				(unsigned long long)(i < 64 && slot_ip[i] ?
					slot_ip[i]->i_ino : 0), i,
				be32_to_cpu(dbuf->di_gen),
				(unsigned long long)be64_to_cpu(ddisk->di_changecount),
				(unsigned long long)be64_to_cpu(dbuf->di_changecount),
				(unsigned long long)(i < 64 && slot_ip[i] ?
					slot_ip[i]->i_mxfs_pub_flush_seq : 0),
				(unsigned long long)(i < 64 && slot_ip[i] ?
					slot_ip[i]->i_mxfs_pub_durable_seq : 0));
			continue;
		}

		/*
		 * sess62: the durable on-disk image of a FOREIGN slot (one we
		 * are not flushing this round) is authoritative -- we hold NL
		 * and have no pending change for it, so a clean cached copy
		 * cannot legitimately be ahead of disk (Invariant #1:
		 * durable-before-NL).  Overlay disk->buffer so this node's
		 * stale cache cannot revert a peer's committed state.
		 *
		 * The disk slot must carry a valid dinode (don't overlay
		 * garbage onto a formatted slot).  A genuinely-free disk slot
		 * still has DINODE_MAGIC with di_mode==0.
		 */
		if (be16_to_cpu(ddisk->di_magic) != XFS_DINODE_MAGIC)
			continue;

		bmode = (be16_to_cpu(dbuf->di_magic) == XFS_DINODE_MAGIC)
			? be16_to_cpu(dbuf->di_mode) : 0;
		dmode = be16_to_cpu(ddisk->di_mode);
		buf_alloc  = (bmode != 0);
		disk_alloc = (dmode != 0);

		/*
		 * NEVER zero an allocated buffer slot to free: disk-free while
		 * buffer-allocated is the inode-reuse / eviction direction,
		 * handled elsewhere (sess48) and never safe to force here.
		 */
		if (!disk_alloc && buf_alloc)
			continue;

		if (memcmp(dbuf, ddisk, inodesize) == 0)
			continue;

		/*
		 * sess85 FIX (PROVEN cross_visibility shortform self-revert): for
		 * a SHORTFORM (FMT_LOCAL) directory the dirents live inline in the
		 * dinode, so the dirent count is sfh->count.  NEVER overlay a dir
		 * slot whose BUFFER image has MORE dirents than the on-disk image:
		 * a buffer that is AHEAD of disk holds this node's own
		 * just-committed dirent adds whose in-place dinode write is still
		 * in the SCST write cache (not yet destaged to the platter), so
		 * the FUA read of the platter returns the STALE smaller image.
		 * Overlaying it CLOBBERS our committed entries (PROVEN: test4 adds
		 * node4.txt → buffer count=4 (P-DIRFLUSH own=1), then a co-resident
		 * child flush FUA-reads stale platter count=3 and this overlay
		 * reverts it → node4.txt durably lost from every node).  When the
		 * buffer is BEHIND disk (peer committed entries we are stale on),
		 * overlaying disk is correct (sess62) and still happens.
		 */
		if (be16_to_cpu(dbuf->di_magic) == XFS_DINODE_MAGIC &&
		    S_ISDIR(bmode) &&
		    XFS_DFORK_FORMAT(dbuf, XFS_DATA_FORK) == XFS_DINODE_FMT_LOCAL &&
		    XFS_DFORK_FORMAT(ddisk, XFS_DATA_FORK) == XFS_DINODE_FMT_LOCAL) {
			struct xfs_dir2_sf_hdr *bsf =
				(struct xfs_dir2_sf_hdr *)XFS_DFORK_DPTR(dbuf);
			struct xfs_dir2_sf_hdr *dsf =
				(struct xfs_dir2_sf_hdr *)XFS_DFORK_DPTR(ddisk);

			if (bsf->count > dsf->count) {
				mxfs_pal_log(MXFS_LOG_WARN,
				    "mxfs: P-CLMERGE-DIRAHEAD ino=%llu slot=%d buf_cnt=%u disk_cnt=%u realns=%llu",
				    (unsigned long long)(bp->b_pag ?
					XFS_AGINO_TO_INO(mp, agno, first_agino + i)
					: 0),
				    i, bsf->count, dsf->count,
				    (unsigned long long)ktime_get_real_ns());
				continue;
			}
		}

		memcpy(dbuf, ddisk, inodesize);
		mxfs_clmerge_ledger_rollback(i < 64 ? slot_ip[i] : NULL, i,
					     "restore", bp,
					     (u64)be64_to_cpu(ddisk->di_changecount),
					     be32_to_cpu(ddisk->di_gen));
		if (bp->b_pag)
			mxfs_pal_log(MXFS_LOG_WARN,
			    "mxfs: P-CLMERGE restored ino=%llu slot=%d bmode=0%o dmode=0%o realns=%llu",
			    (unsigned long long)XFS_AGINO_TO_INO(mp, agno,
				first_agino + i),
			    i, bmode, dmode,
			    (unsigned long long)ktime_get_real_ns());
	}

	/*
	 * sess48 install site 5 — PROVEN in-core fossil reverter (RULE 4):
	 * the memcpys above install fresh platter images per-slot, and the
	 * old blanket bli_dirty save/restore of di_next_unlinked skipped
	 * exactly when the covering iunlink write was checkpointed (BLI
	 * detached ⇒ bli_dirty=0), installing the platter's pre-write chain
	 * value in-core; xfsaild then destaged the fossil (the 390-c1
	 * P-IUNLSTORE-WRSITE bli=0 comm=xfsaild specimens).  When it DID
	 * fire it also restored without a CRC recompute and could revert a
	 * FOREIGN slot's fresher disk value.  The mount store holds the
	 * exact per-slot truth the flag approximated: live same-incarnation
	 * record → overlay the committed value (+CRC); otherwise the disk
	 * image stands (peer slots, retired values, dead incarnations).
	 */
	{
		extern int mxfs_iunl_store_overlay(struct xfs_mount *,
				xfs_daddr_t, int, void *, unsigned int);

		if (bp->b_addr && bp->b_map_count == 1)
			mxfs_iunl_store_overlay(mp, xfs_buf_daddr(bp),
						bp->b_length, bp->b_addr,
						BBTOB(bp->b_length));
	}

	kfree(scratch);
}

/*
 * Non-blocking flush of dirty inode metadata into the backing buffer.
 *
 * The caller must have a reference to the inode and hold the cluster buffer
 * locked. The function will walk across all the inodes on the cluster buffer it
 * can find and lock without blocking, and flush them to the cluster buffer.
 *
 * On successful flushing of at least one inode, the caller must write out the
 * buffer and release it. If no inodes are flushed, -EAGAIN will be returned and
 * the caller needs to release the buffer. On failure, the filesystem will be
 * shut down, the buffer will have been unlocked and released, and EFSCORRUPTED
 * will be returned.
 */
int
xfs_iflush_cluster(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_log_item	*lip, *n;
	struct xfs_inode	*ip;
	struct xfs_inode_log_item *iip;
	int			clcount = 0;
	int			error = 0;

	/*
	 * We must use the safe variant here as on shutdown xfs_iflush_abort()
	 * will remove itself from the list.
	 */
	list_for_each_entry_safe(lip, n, &bp->b_li_list, li_bio_list) {
		iip = (struct xfs_inode_log_item *)lip;
		ip = iip->ili_inode;

		/*
		 * Quick and dirty check to avoid locks if possible.
		 */
		if (__xfs_iflags_test(ip, XFS_IRECLAIM | XFS_IFLUSHING)) {
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=RECLAIM_OR_FLUSHING iflags=0x%lx\n",
					(unsigned long long)ip->i_ino, ip->i_flags);
			continue;
		}
		if (xfs_ipincount(ip)) {
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=PINNED ipin=%d\n",
					(unsigned long long)ip->i_ino, xfs_ipincount(ip));
			continue;
		}

		/*
		 * The inode is still attached to the buffer, which means it is
		 * dirty but reclaim might try to grab it. Check carefully for
		 * that, and grab the ilock while still holding the i_flags_lock
		 * to guarantee reclaim will not be able to reclaim this inode
		 * once we drop the i_flags_lock.
		 */
		spin_lock(&ip->i_flags_lock);
		ASSERT(!__xfs_iflags_test(ip, XFS_ISTALE));
		if (__xfs_iflags_test(ip, XFS_IRECLAIM | XFS_IFLUSHING)) {
			spin_unlock(&ip->i_flags_lock);
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=RECLAIM_OR_FLUSHING2 iflags=0x%lx\n",
					(unsigned long long)ip->i_ino, ip->i_flags);
			continue;
		}

		/*
		 * ILOCK will pin the inode against reclaim and prevent
		 * concurrent transactions modifying the inode while we are
		 * flushing the inode. If we get the lock, set the flushing
		 * state before we drop the i_flags_lock.
		 */
		if (!xfs_ilock_nowait(ip, XFS_ILOCK_SHARED)) {
			spin_unlock(&ip->i_flags_lock);
			if (atomic_read(&mxfs_ailstuck_probe)) {
				/* rwsem owner: task ptr with flag bits in the
				 * low 3 bits (RWSEM_READER_OWNED etc). */
				struct task_struct *otsk = (struct task_struct *)
					(atomic_long_read(&ip->i_lock.owner) & ~0x7UL);
				static atomic_t odumps = ATOMIC_INIT(0);

				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=ILOCK_NOWAIT_FAIL count=%ld owner=%px ocomm=%s opid=%d\n",
					(unsigned long long)ip->i_ino,
					atomic_long_read(&ip->i_lock.count),
					otsk,
					otsk ? otsk->comm : "-",
					otsk ? task_pid_nr(otsk) : -1);
				if (otsk && atomic_inc_return(&odumps) <= 3)
					sched_show_task(otsk);
			}
			continue;
		}
		__xfs_iflags_set(ip, XFS_IFLUSHING);
		spin_unlock(&ip->i_flags_lock);

		/*
		 * sess112 LEAKER-CAPTURE (safe, no lock manipulation): the
		 * cache_coherency drain wedge is the root-dir inode (sb_rootino,
		 * ino=128) left IFLUSHING with its cluster buffer locked+DONE but
		 * never written.  IFLUSHING is set HERE; record which caller of
		 * xfs_iflush_cluster set it so the next repro names the path that
		 * abandons the flush (the one whose bwrite/relse never runs).
		 * Rate-limited, root-dir only -> negligible noise.
		 */
		if (ip->i_ino == mp->m_sb.sb_rootino)
			pr_warn_ratelimited(
			    "mxfs: P112-IFLUSH-CALLER ino=%llu set IFLUSHING caller=%pS %pS\n",
			    (unsigned long long)ip->i_ino,
			    __builtin_return_address(0),
			    __builtin_return_address(1));

		/*
		 * Abort flushing this inode if we are shut down because the
		 * inode may not currently be in the AIL. This can occur when
		 * log I/O failure unpins the inode without inserting into the
		 * AIL, leaving a dirty/unpinned inode attached to the buffer
		 * that otherwise looks like it should be flushed.
		 */
		if (xlog_is_shutdown(mp->m_log)) {
			xfs_iunpin_wait(ip);
			xfs_iflush_abort(ip);
			/*
			 * sess16 (ccloop 4eef1f39) DEADLOCK FIX — release the
			 * flush ILOCK with the RAW semaphore, NOT xfs_iunlock.
			 * The matching xfs_ilock_nowait(XFS_ILOCK_SHARED) above
			 * is atomic-context and DELIBERATELY skips the MXFS DLM
			 * (mxfs_dlm_ilock_try is IOLOCK-only — ILOCK CAW would
			 * sleep), so this flush took NO DLM holder reference.
			 * xfs_iunlock, however, unconditionally calls
			 * mxfs_dlm_ilock_end, which on a pending peer BAST runs
			 * mxfs_dlm_bast_process INLINE — a synchronous AIL drain
			 * (mxfs_ail_drain_inode_sync) that waits for THIS inode's
			 * cluster buffer to be written.  But xfsaild is holding
			 * that very buffer locked across xfs_iflush_cluster ->
			 * the drain can never complete -> xfsaild self-deadlock
			 * (P113-DRAIN-WEDGE, proven: ino stuck in_ail ~600s,
			 * holder=xfs_inode_item_push, lb_flags=XBF_DONE).  The
			 * legitimate BAST firer is the async inode-bast wq
			 * (no-holder path) or a REAL DLM holder's xfs_iunlock,
			 * never this spurious nowait release.  Symmetric un-take.
			 */
			atomic_dec(&ip->i_mxfs_ilk_rd_held);
			up_read(&ip->i_lock);
			error = -EIO;
			continue;
		}

		/* don't block waiting on a log force to unpin dirty inodes */
		if (xfs_ipincount(ip)) {
			xfs_iflags_clear(ip, XFS_IFLUSHING);
			/* sess16 deadlock fix — raw un-take (see above). */
			atomic_dec(&ip->i_mxfs_ilk_rd_held);
			up_read(&ip->i_lock);
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=PINNED2 ipin=%d\n",
					(unsigned long long)ip->i_ino, xfs_ipincount(ip));
			continue;
		}

		if (!xfs_inode_clean(ip)) {
			error = xfs_iflush(ip, bp);
			/*
			 * sess3 (ccloop a16ec5f2): -EAGAIN = transient torn
			 * shortform dir fork (mid down-conversion) — skip this
			 * inode THIS round, leaving its ILI dirty in the AIL so
			 * the flush retries after the conversion settles.  Not
			 * an error: must not shut down or fail the buffer.
			 */
			if (error == -EAGAIN) {
				xfs_iflags_clear(ip, XFS_IFLUSHING);
				/* raw un-take (see sess16 deadlock fix above) */
				atomic_dec(&ip->i_mxfs_ilk_rd_held);
				up_read(&ip->i_lock);
				error = 0;
				continue;
			}
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=IFLUSH_RAN err=%d ili_fields=0x%x\n",
					(unsigned long long)ip->i_ino, error,
					iip->ili_fields);
		} else {
			xfs_iflags_clear(ip, XFS_IFLUSHING);
			if (atomic_read(&mxfs_ailstuck_probe))
				pr_warn_ratelimited("mxfs: P129-CLSKIP ino=%llu why=CLEAN ili_fields=0x%x\n",
					(unsigned long long)ip->i_ino, iip->ili_fields);
		}
		/* sess16 deadlock fix — raw un-take of the nowait flush ILOCK
		 * (no DLM ref was taken); xfs_iunlock here would run the inline
		 * BAST drain in xfsaild while it holds bp -> self-deadlock. */
		atomic_dec(&ip->i_mxfs_ilk_rd_held);
		up_read(&ip->i_lock);
		if (error)
			break;
		clcount++;
	}

	if (error) {
		/*
		 * Shutdown first so we kill the log before we release this
		 * buffer. If it is an INODE_ALLOC buffer and pins the tail
		 * of the log, failing it before the _log_ is shut down can
		 * result in the log tail being moved forward in the journal
		 * on disk because log writes can still be taking place. Hence
		 * unpinning the tail will allow the ICREATE intent to be
		 * removed from the log an recovery will fail with uninitialised
		 * inode cluster buffers.
		 */
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		bp->b_flags |= XBF_ASYNC;
		xfs_buf_ioend_fail(bp);
		return error;
	}

	if (!clcount)
		return -EAGAIN;

	/*
	 * sess61: before this cluster buffer is written, restore any FOREIGN
	 * directory inode's region from the durable on-disk image so a flush
	 * driven by a co-resident dirty CHILD cannot revert a peer's committed
	 * dir entries (PROVEN cross-inode cluster-buffer false-sharing).  This
	 * is the SAFE site noted below (buffer locked but not yet I/O-owned).
	 */
	mxfs_iflush_cluster_merge_dirs(bp);

	/*
	 * sess44 FIX ATTEMPT 2 (build 977C5A3E) REVERTED: the inode-cluster
	 * merge HERE (FUA-read disk cluster + restore peer inode regions not in
	 * b_li_list) did NOT hang (confirms this is a SAFE site, unlike
	 * xfs_buf_submit — buffer not yet I/O-owned, fast 10s) BUT did NOT fix
	 * di_size=0 (still actual=0).  WHY: the merge's FUA-read of the PEER's
	 * inode can return a NOT-YET-DURABLE stale value (di_size=0) — the same
	 * read-vs-destage race as the bnobt (peer's inode write in the SCST
	 * write cache, not on the medium yet) — so restoring it just re-writes
	 * 0.  ⇒ the inode-cluster fix needs the peer's inode to be PLATTER-
	 * DURABLE before this node reads it (on inode-DLM release the peer must
	 * make its inode durable), AND/OR a per-cluster-gen so this node only
	 * reads when the peer's change is committed+durable.  This is the SAME
	 * deep coherency problem as the bnobt (a node reads a stale peer value).
	 * The READ side (node B sees node A's file as 0) and the WRITE side
	 * (node B clobbers node A's inode) are TWO faces of one root: cross-node
	 * inode-cluster coherency without durable-before-visible ordering.
	 */
	XFS_STATS_INC(mp, xs_icluster_flushcnt);
	XFS_STATS_ADD(mp, xs_icluster_flushinode, clcount);
	return 0;

}

/* Release an inode. */
void
xfs_irele(
	struct xfs_inode	*ip)
{
	trace_xfs_irele(ip, _RET_IP_);
	/* sess23: every XFS-side release lands in the reference-event ring. */
	mxfs_refev_rec(ip, _RET_IP_, 0);
	/*
	 * sess26 P205-REFBAL: MXFS releases with xfs_irele(), NOT iput(), so
	 * counting only mxfs_iput_tracked made the balance meaningless -- a real
	 * capture read tgrabs=61 tputs=1 net=60 against icount=1 and the probe
	 * confidently announced the wrong verdict.  Count here too; this is the
	 * single XFS-side release chokepoint.  Before iput(): it may free the
	 * inode and touching ip after would be a use-after-free.
	 */
	if (ip->i_mxfs_tputs < 0xffff)
		ip->i_mxfs_tputs++;
	iput(VFS_I(ip));
}

/*
 * Ensure all commited transactions touching the inode are written to the log.
 */
int
xfs_log_force_inode(
	struct xfs_inode	*ip)
{
	struct xfs_inode_log_item *iip = ip->i_itemp;
	xfs_csn_t		seq = 0;

	if (!iip)
		return 0;

	spin_lock(&iip->ili_lock);
	seq = iip->ili_commit_seq;
	spin_unlock(&iip->ili_lock);

	if (!seq)
		return 0;
	return xfs_log_force_seq(ip->i_mount, seq, XFS_LOG_SYNC, NULL);
}

/*
 * Grab the exclusive iolock for a data copy from src to dest, making sure to
 * abide vfs locking order (lowest pointer value goes first) and breaking the
 * layout leases before proceeding.  The loop is needed because we cannot call
 * the blocking break_layout() with the iolocks held, and therefore have to
 * back out both locks.
 */
static int
xfs_iolock_two_inodes_and_break_layout(
	struct inode		*src,
	struct inode		*dest)
{
	int			error;

	if (src > dest)
		swap(src, dest);

retry:
	/* Wait to break both inodes' layouts before we start locking. */
	error = break_layout(src, true);
	if (error)
		return error;
	if (src != dest) {
		error = break_layout(dest, true);
		if (error)
			return error;
	}

	/* Lock one inode and make sure nobody got in and leased it. */
	inode_lock(src);
	error = break_layout(src, false);
	if (error) {
		inode_unlock(src);
		if (error == -EWOULDBLOCK)
			goto retry;
		return error;
	}

	if (src == dest)
		return 0;

	/* Lock the other inode and make sure nobody got in and leased it. */
	inode_lock_nested(dest, I_MUTEX_NONDIR2);
	error = break_layout(dest, false);
	if (error) {
		inode_unlock(src);
		inode_unlock(dest);
		if (error == -EWOULDBLOCK)
			goto retry;
		return error;
	}

	return 0;
}

static int
xfs_mmaplock_two_inodes_and_break_dax_layout(
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	int			error;

	if (ip1->i_ino > ip2->i_ino)
		swap(ip1, ip2);

again:
	/* Lock the first inode */
	xfs_ilock(ip1, XFS_MMAPLOCK_EXCL);
	error = xfs_break_dax_layouts(VFS_I(ip1));
	if (error) {
		xfs_iunlock(ip1, XFS_MMAPLOCK_EXCL);
		return error;
	}

	if (ip1 == ip2)
		return 0;

	/* Nested lock the second inode */
	xfs_ilock(ip2, xfs_lock_inumorder(XFS_MMAPLOCK_EXCL, 1));
	/*
	 * We cannot use xfs_break_dax_layouts() directly here because it may
	 * need to unlock & lock the XFS_MMAPLOCK_EXCL which is not suitable
	 * for this nested lock case.
	 */
	error = dax_break_layout(VFS_I(ip2), 0, -1, NULL);
	if (error) {
		xfs_iunlock(ip2, XFS_MMAPLOCK_EXCL);
		xfs_iunlock(ip1, XFS_MMAPLOCK_EXCL);
		goto again;
	}

	return 0;
}

/*
 * Lock two inodes so that userspace cannot initiate I/O via file syscalls or
 * mmap activity.
 */
int
xfs_ilock2_io_mmap(
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	int			ret;

	ret = xfs_iolock_two_inodes_and_break_layout(VFS_I(ip1), VFS_I(ip2));
	if (ret)
		return ret;

	if (IS_DAX(VFS_I(ip1)) && IS_DAX(VFS_I(ip2))) {
		ret = xfs_mmaplock_two_inodes_and_break_dax_layout(ip1, ip2);
		if (ret) {
			inode_unlock(VFS_I(ip2));
			if (ip1 != ip2)
				inode_unlock(VFS_I(ip1));
			return ret;
		}
	} else
		filemap_invalidate_lock_two(VFS_I(ip1)->i_mapping,
					    VFS_I(ip2)->i_mapping);

	return 0;
}

/* Unlock both inodes to allow IO and mmap activity. */
void
xfs_iunlock2_io_mmap(
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	if (IS_DAX(VFS_I(ip1)) && IS_DAX(VFS_I(ip2))) {
		xfs_iunlock(ip2, XFS_MMAPLOCK_EXCL);
		if (ip1 != ip2)
			xfs_iunlock(ip1, XFS_MMAPLOCK_EXCL);
	} else
		filemap_invalidate_unlock_two(VFS_I(ip1)->i_mapping,
					      VFS_I(ip2)->i_mapping);

	inode_unlock(VFS_I(ip2));
	if (ip1 != ip2)
		inode_unlock(VFS_I(ip1));
}

/* Drop the MMAPLOCK and the IOLOCK after a remap completes. */
void
xfs_iunlock2_remapping(
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	xfs_iflags_clear(ip1, XFS_IREMAPPING);

	if (ip1 != ip2)
		xfs_iunlock(ip1, XFS_MMAPLOCK_SHARED);
	xfs_iunlock(ip2, XFS_MMAPLOCK_EXCL);

	if (ip1 != ip2)
		inode_unlock_shared(VFS_I(ip1));
	inode_unlock(VFS_I(ip2));
}

/*
 * Reload the incore inode list for this inode.  Caller should ensure that
 * the link count cannot change, either by taking ILOCK_SHARED or otherwise
 * preventing other threads from executing.
 */
int
xfs_inode_reload_unlinked_bucket(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	struct xfs_perag	*pag;
	xfs_agnumber_t		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	xfs_agino_t		prev_agino, next_agino;
	unsigned int		bucket;
	bool			foundit = false;
	int			error;

	/* Grab the first inode in the list */
	pag = xfs_perag_get(mp, agno);
	error = xfs_ialloc_read_agi(pag, tp, 0, &agibp);
	xfs_perag_put(pag);
	if (error)
		return error;

	/*
	 * We've taken ILOCK_SHARED and the AGI buffer lock to stabilize the
	 * incore unlinked list pointers for this inode.  Check once more to
	 * see if we raced with anyone else to reload the unlinked list.
	 */
	if (!xfs_inode_unlinked_incomplete(ip)) {
		foundit = true;
		goto out_agibp;
	}

	/*
	 * mxfs sess40 (D-AGI-UNLINKED F1): a cached FOREIGN zombie — nlink==0
	 * with no local-unlink intent and no recorded bucket membership — is a
	 * peer's live open-unlinked inode observed via lookup/adoption.  It is
	 * not on any of OUR lists and its bucket is not ours to walk or mutate
	 * (quotacheck/bulkstat arm of the defect).  Report success with no
	 * reload; the owner maintains its own list.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    ip->i_unlinked_bucket < 0 &&
	    !xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK)) {
		pr_warn_ratelimited(
		    "mxfs: P85-UNL-FOREIGN-RELOAD-SKIP ino=%llu agino=0x%x — foreign cached zombie; not walking a peer's bucket\n",
			(unsigned long long)ip->i_ino, agino);
		foundit = true;
		goto out_agibp;
	}

	/* mxfs sess40: walk the bucket this inode's entry actually lives in
	 * (recorded at insert; slot-partitioned in multi-node mode). */
	if (ip->i_unlinked_bucket >= 0)
		bucket = ip->i_unlinked_bucket;
	else
		bucket = agino % XFS_AGI_UNLINKED_BUCKETS;
	agi = agibp->b_addr;

	trace_xfs_inode_reload_unlinked_bucket(ip);

	xfs_info_ratelimited(mp,
 "Found unrecovered unlinked inode 0x%x in AG 0x%x.  Initiating list recovery.",
			agino, agno);

	prev_agino = NULLAGINO;
	next_agino = be32_to_cpu(agi->agi_unlinked[bucket]);
	while (next_agino != NULLAGINO) {
		struct xfs_inode	*next_ip = NULL;

		/* Found this caller's inode, set its backlink. */
		if (next_agino == agino) {
			next_ip = ip;
			next_ip->i_prev_unlinked = prev_agino;
			next_ip->i_unlinked_bucket = (short)bucket;
			foundit = true;
			goto next_inode;
		}

		/* Try in-memory lookup first. */
		next_ip = xfs_iunlink_lookup(pag, next_agino);
		if (next_ip)
			goto next_inode;

		/* Inode not in memory, try reloading it. */
		error = xfs_iunlink_reload_next(tp, agibp, prev_agino,
				next_agino, (short)bucket);
		if (error)
			break;

		/* Grab the reloaded inode. */
		next_ip = xfs_iunlink_lookup(pag, next_agino);
		if (!next_ip) {
			/* No incore inode at all?  We reloaded it... */
			ASSERT(next_ip != NULL);
			error = -EFSCORRUPTED;
			break;
		}

next_inode:
		prev_agino = next_agino;
		next_agino = next_ip->i_next_unlinked;
	}

out_agibp:
	xfs_trans_brelse(tp, agibp);
	/* Should have found this inode somewhere in the iunlinked bucket. */
	if (!error && !foundit)
		error = -EFSCORRUPTED;
	return error;
}

/* Decide if this inode is missing its unlinked list and reload it. */
int
xfs_inode_reload_unlinked(
	struct xfs_inode	*ip)
{
	struct xfs_trans	*tp;
	int			error = 0;

	tp = xfs_trans_alloc_empty(ip->i_mount);
	xfs_ilock(ip, XFS_ILOCK_SHARED);
	if (xfs_inode_unlinked_incomplete(ip))
		error = xfs_inode_reload_unlinked_bucket(tp, ip);
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
	xfs_trans_cancel(tp);

	return error;
}

/* Has this inode fork been zapped by repair? */
bool
xfs_ifork_zapped(
	const struct xfs_inode	*ip,
	int			whichfork)
{
	unsigned int		datamask = 0;

	switch (whichfork) {
	case XFS_DATA_FORK:
		switch (ip->i_vnode.i_mode & S_IFMT) {
		case S_IFDIR:
			datamask = XFS_SICK_INO_DIR_ZAPPED;
			break;
		case S_IFLNK:
			datamask = XFS_SICK_INO_SYMLINK_ZAPPED;
			break;
		}
		return ip->i_sick & (XFS_SICK_INO_BMBTD_ZAPPED | datamask);
	case XFS_ATTR_FORK:
		return ip->i_sick & XFS_SICK_INO_BMBTA_ZAPPED;
	default:
		return false;
	}
}

/* Compute the number of data and realtime blocks used by a file. */
void
xfs_inode_count_blocks(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	xfs_filblks_t		*dblocks,
	xfs_filblks_t		*rblocks)
{
	struct xfs_ifork	*ifp = xfs_ifork_ptr(ip, XFS_DATA_FORK);

	*rblocks = 0;
	if (XFS_IS_REALTIME_INODE(ip))
		xfs_bmap_count_leaves(ifp, rblocks);
	*dblocks = ip->i_nblocks - *rblocks;
}

static void
xfs_wait_dax_page(
	struct inode		*inode)
{
	struct xfs_inode        *ip = XFS_I(inode);

	xfs_iunlock(ip, XFS_MMAPLOCK_EXCL);
	schedule();
	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
}

int
xfs_break_dax_layouts(
	struct inode		*inode)
{
	xfs_assert_ilocked(XFS_I(inode), XFS_MMAPLOCK_EXCL);

	return dax_break_layout_inode(inode, xfs_wait_dax_page);
}

int
xfs_break_layouts(
	struct inode		*inode,
	uint			*iolock,
	enum layout_break_reason reason)
{
	bool			retry;
	int			error;

	xfs_assert_ilocked(XFS_I(inode), XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL);

	do {
		retry = false;
		switch (reason) {
		case BREAK_UNMAP:
			error = xfs_break_dax_layouts(inode);
			if (error)
				break;
			fallthrough;
		case BREAK_WRITE:
			error = xfs_break_leased_layouts(inode, iolock, &retry);
			break;
		default:
			WARN_ON_ONCE(1);
			error = -EINVAL;
		}
	} while (error == 0 && retry);

	return error;
}

/* Returns the size of fundamental allocation unit for a file, in bytes. */
unsigned int
xfs_inode_alloc_unitsize(
	struct xfs_inode	*ip)
{
	unsigned int		blocks = 1;

	if (XFS_IS_REALTIME_INODE(ip))
		blocks = ip->i_mount->m_sb.sb_rextsize;

	return XFS_FSB_TO_B(ip->i_mount, blocks);
}

/* Should we always be using copy on write for file writes? */
bool
xfs_is_always_cow_inode(
	const struct xfs_inode	*ip)
{
	return xfs_is_zoned_inode(ip) ||
		(ip->i_mount->m_always_cow && xfs_has_reflink(ip->i_mount));
}
